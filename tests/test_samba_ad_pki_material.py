"""Offline ceremony and destination CSR use only temporary test identities."""
import importlib.util
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import pytest

from test_samba_ad_ca_substrate import ca_request
from test_samba_ad_pki import ROOT, NOW

PASSWORD = b"test-only-passphrase-not-operational"


def module(name):
    p = ROOT / "tools/samba_ad" / (name + ".py")
    assert p.is_file(), "PKI material ceremony missing"
    spec = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


class Offline:
    def identity(self): return {"uid": 1000, "hostname": "operator.example.invalid"}
    def now(self): return NOW


def root_request(directory):
    return {"schema": "samba-ad-root/v1", "enabled": True, "apply": True, "action": "create_root",
            "directory": str(directory), "expected_uid": 1000, "expected_hostname": "operator.example.invalid",
            "subject": "TEST ONLY ROOT", "key_bits": 3072, "validity_days": 365,
            "csr_file": None, "root_sha256": None}


def test_offline_root_is_encrypted_and_reexecution_never_replaces_it(tmp_path):
    m = module("pki_root"); r = root_request(tmp_path)
    assert m.run(r, PASSWORD, Offline(), check=False)["state"] == "root_created"
    key_path = tmp_path / "root.key.pem"
    assert key_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(TypeError): serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=PASSWORD)
    public = x509.load_pem_x509_certificate((tmp_path / "root.pem").read_bytes())
    public.verify_directly_issued_by(public)
    assert public.public_key().public_numbers() == key.public_key().public_numbers()
    before = key_path.read_bytes()
    with pytest.raises(ValueError, match="suppressed"): m.run(r, PASSWORD, Offline(), check=False)
    assert key_path.read_bytes() == before


def test_offline_check_and_wrong_operator_cannot_generate_material(tmp_path):
    m = module("pki_root"); r = root_request(tmp_path)
    assert m.run(r, None, Offline(), check=True)["state"] == "planned"
    assert not list(tmp_path.iterdir())
    r["expected_hostname"] = "ca.ad.example.invalid"
    with pytest.raises(ValueError): m.run(r, PASSWORD, Offline(), check=False)
    assert not list(tmp_path.iterdir())


def test_destination_generates_csr_only_and_offline_signer_returns_public_intermediate(tmp_path):
    root_dir = tmp_path / "offline"; root_dir.mkdir(mode=0o700)
    ca_dir = tmp_path / "ca"; ca_dir.mkdir(mode=0o700)
    root = module("pki_root"); root.run(root_request(root_dir), PASSWORD, Offline(), check=False)
    guest = ca_request()
    ca = guest["resource"]
    target = {"fqdn": ca["name"], "address": ca["address"].split("/")[0], "mac": ca["mac"],
              "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "machine_id": "a" * 32, "interface": "eth0"}
    payload = {"schema": "samba-ad-ca-csr/v1", "enabled": True, "apply": True, "guest_request": guest,
               "target": target, "directory": str(ca_dir), "subject": "TEST ONLY ISSUER", "key_bits": 3072}
    class Host:
        def inspect(self, _): return target | {"uid": 0, "virtualization": "kvm", "addresses": [target["address"]]}
    material = module("pki_material")
    assert material.prepare(payload, PASSWORD, Host(), check=True)["state"] == "planned"
    assert not list(ca_dir.iterdir())
    assert material.prepare(payload, PASSWORD, Host(), check=False)["state"] == "csr_created"
    assert not (ca_dir / "root.key.pem").exists()
    root_cert = x509.load_pem_x509_certificate((root_dir / "root.pem").read_bytes())
    sign = root_request(root_dir)
    sign.update(action="sign_intermediate", subject="TEST ONLY ISSUER", validity_days=90,
                csr_file=str(ca_dir / "intermediate.csr.pem"), root_sha256=root_cert.fingerprint(hashes.SHA256()).hex())
    assert root.run(sign, PASSWORD, Offline(), check=False)["state"] == "intermediate_signed"
    issuer = x509.load_pem_x509_certificate((root_dir / "intermediate.pem").read_bytes())
    issuer.verify_directly_issued_by(root_cert)
    assert issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    assert not (root_dir / "intermediate.key.pem").exists()
    dest_key = serialization.load_pem_private_key((ca_dir / "intermediate.key.pem").read_bytes(), password=PASSWORD)
    assert dest_key.public_key().public_numbers() == issuer.public_key().public_numbers()


def test_material_directory_in_git_or_symlink_is_refused(tmp_path):
    m = module("pki_root")
    actual = tmp_path / "actual"; actual.mkdir(mode=0o700)
    alias = tmp_path / "alias"; alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError): m.run(root_request(alias), PASSWORD, Offline(), check=False)
    (tmp_path / ".git").mkdir()
    with pytest.raises(ValueError): m.run(root_request(actual), PASSWORD, Offline(), check=False)
    assert not list(actual.iterdir())
