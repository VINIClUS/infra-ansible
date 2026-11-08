import importlib.util
import pytest


def api():
    assert importlib.util.find_spec("tools.samba_ad.domain_source"), "signed source verifier missing"
    from tools.samba_ad import domain_source
    return domain_source


def test_debian_control_rejects_duplicate_and_malformed_fields():
    d = api()
    for text in ["Package: samba\nPackage: evil\n", "missing colon", " orphan continuation"]:
        with pytest.raises(ValueError): d.paragraphs(text)
    assert d.paragraphs("Package: samba\nVersion: 4.25.1\n\n") == [{"Package": "samba", "Version": "4.25.1"}]


def test_signed_release_hash_cannot_authorize_other_packages():
    d = api()
    packages = b"Package: samba\nVersion: 4.25.1\n"
    digest = d.hashlib.sha256(packages).hexdigest()
    assert d.release_packages({"SHA256": "\n " + digest + " " + str(len(packages)) + " main/binary-amd64/Packages"}, packages)
    for data in [packages + b"injection", b""]:
        with pytest.raises(ValueError): d.release_packages({"SHA256": "\n " + digest + " " + str(len(packages)) + " main/binary-amd64/Packages"}, data)


def test_pins_require_coherent_samba_ldb_python_stack():
    d = api()
    import json
    from pathlib import Path
    rows = json.loads((Path(__file__).parent / "fixtures/samba_ad_vendor_runtime.json").read_text())
    pins = {row["Package"]: row["Version"] for row in rows}
    d.validate_pins(pins)
    with pytest.raises(ValueError): d.validate_pins(dict(pins, **{"python3-ldb": "2:2.10.0"}))
    with pytest.raises(ValueError): d.validate_pins({"samba": pins["samba"]})


def test_real_gpgv_signature_and_signed_package_hashes(tmp_path):
    import datetime
    import email.utils
    import os
    import subprocess
    d = api()
    home = tmp_path / "gnupg"; home.mkdir(mode=0o700)
    root = tmp_path / "source"; root.mkdir(mode=0o700)
    (root / "packages").mkdir(mode=0o700)
    env = dict(os.environ, GNUPGHOME=str(home))
    def gpg(*args, data=None):
        result = subprocess.run(["gpg", "--batch", *args], input=data, capture_output=True, env=env)
        assert result.returncode == 0, "test-only GPG fixture failed"
        return result.stdout
    gpg("--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "S4 test fixture <fixture@example.invalid>", "ed25519", "sign", "0")
    public = gpg("--export")
    fingerprint = next(line.split(":")[9] for line in gpg("--with-colons", "--list-keys").decode().splitlines() if line.startswith("fpr:"))
    import json
    from pathlib import Path
    rows = json.loads((Path(__file__).parent / "fixtures/samba_ad_vendor_runtime.json").read_text())
    pins = {row["Package"]: row["Version"] for row in rows}
    archive = b"synthetic archive contents - no installation"
    paragraphs = []
    for package, version in pins.items():
        filename = package + ".deb"; (root / "packages" / filename).write_bytes(archive)
        row = next(row for row in rows if row["Package"] == package)
        headers = "".join(f"{key}: {value}\n" for key, value in row.items())
        paragraphs.append(headers + f"Filename: pool/{filename}\nSize: {len(archive)}\nSHA256: {d.hashlib.sha256(archive).hexdigest()}\n")
    packages = "\n".join(paragraphs).encode()
    date = email.utils.format_datetime(datetime.datetime.now(datetime.timezone.utc))
    old_date = email.utils.format_datetime(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30))
    release = f"Suite: trixie\nDate: {old_date}\nSHA256:\n {d.hashlib.sha256(packages).hexdigest()} {len(packages)} main/binary-amd64/Packages\n".encode()
    signed = gpg("--armor", "--clearsign", data=release)
    for name, data in [("InRelease", signed), ("Packages", packages), ("keyring.gpg", public)]: (root / name).write_bytes(data)
    for item in root.rglob("*"):
        if item.is_file(): item.chmod(0o600)
    source = {"verified_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "directory": str(root), "fingerprint": fingerprint, "packages": pins,
              "inrelease_sha256": d.hashlib.sha256(signed).hexdigest(), "packages_sha256": d.hashlib.sha256(packages).hexdigest(), "key_sha256": d.hashlib.sha256(public).hexdigest()}
    assert len(d.verified_archives(source)) == len(rows)
    (root / "packages" / "samba.deb").write_bytes(b"tampered archive")
    with pytest.raises(ValueError): d.verified_archives(source)
