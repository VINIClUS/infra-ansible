"""Verify already staged, signed vendor packages before installation or use.

Acquisition is an explicit operator step over S1's approved egress; this module
never configures a repository or resolves dependencies from a different origin.
"""
from __future__ import annotations

import datetime
import email.utils
import hashlib
import io
from pathlib import Path
import re
import subprocess
import tarfile

from tools.samba_ad.domain import CANDIDATE_KEY_SHA256, CANDIDATE_PRIMARY, command, require
from tools.samba_ad.pki_files import secure_directory, secure_file


def paragraphs(text):
    result, row, previous = [], {}, None
    for line in text.splitlines() + [""]:
        if not line:
            if row: result.append(row)
            row, previous = {}, None
        elif line.startswith((" ", "\t")):
            require(previous is not None)
            row[previous] += "\n" + line
        else:
            require(":" in line)
            name, value = line.split(":", 1)
            require(re.fullmatch(r"[A-Za-z0-9-]+", name) and name not in row)
            row[name] = value.strip(); previous = name
    return result


def validate_pins(pins):
    samba = {"samba", "samba-ad-dc", "python3-samba"}
    ldb = {"libldb2", "python3-ldb"}
    require(samba | ldb <= set(pins))
    require(len({pins[p] for p in samba}) == 1 and len({pins[p] for p in ldb}) == 1)
    require(all("4.25.1" in v for v in pins.values()))
    require(all("2.11.0+samba4.25.1" in pins[p] for p in ldb))


def release_packages(release, packages):
    expected = f"{hashlib.sha256(packages).hexdigest()} {len(packages)} main/binary-amd64/Packages"
    require(any(" ".join(line.split()) == expected for line in release.get("SHA256", "").splitlines()))
    return True


def verified_archives(source):
    """A key pin alone is insufficient: verify the exact signed metadata tree."""
    validate_pins(source["packages"])
    root = secure_directory(source["directory"], exact=True)
    data = {}
    for name, pin in [("InRelease", "inrelease_sha256"), ("Packages", "packages_sha256"), ("keyring.gpg", "key_sha256")]:
        path = secure_file(root / name, secret=False)
        data[name] = path.read_bytes()
        require(hashlib.sha256(data[name]).hexdigest() == source[pin])
    result = subprocess.run(["gpgv", "--status-fd", "2", "--keyring", str(root / "keyring.gpg"),
                             "--output", "-", str(root / "InRelease")],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode == 0)
    statuses = result.stderr.decode().splitlines()
    valid = [line.split() for line in statuses if line.startswith("[GNUPG:] VALIDSIG ")]
    require(len(valid) == 1 and source["fingerprint"].upper() in [valid[0][2], valid[0][-1]])
    release_rows = paragraphs(result.stdout.decode()); require(len(release_rows) == 1)
    release = release_rows[0]
    require(release.get("Suite") == "trixie" or release.get("Codename") == "trixie")
    issued = email.utils.parsedate_to_datetime(release["Date"])
    now = datetime.datetime.now(datetime.timezone.utc)
    # Publication date is not a provider expiry. This repository may publish an
    # immutable Release for weeks and has no Valid-Until in the observed metadata.
    require(issued <= now + datetime.timedelta(minutes=5))
    verified = datetime.datetime.fromisoformat(source["verified_utc"].replace("Z", "+00:00"))
    require(verified.utcoffset() == datetime.timedelta(0)
            and -datetime.timedelta(minutes=5) <= now - verified <= datetime.timedelta(hours=24))
    if "Valid-Until" in release:
        require(now < email.utils.parsedate_to_datetime(release["Valid-Until"]))
    release_packages(release, data["Packages"])
    rows = paragraphs(data["Packages"].decode())
    archives = []
    for name, version in sorted(source["packages"].items()):
        found = [row for row in rows if row.get("Package") == name and row.get("Version") == version
                 and row.get("Architecture") in ["amd64", "all"]]
        require(len(found) == 1)
        row = found[0]
        require(re.fullmatch(r"[a-zA-Z0-9_+./~:-]+\.deb", row["Filename"]) and ".." not in row["Filename"])
        archive = secure_file(root / "packages" / Path(row["Filename"]).name, secret=False)
        require(archive.stat().st_size == int(row["Size"]))
        require(hashlib.sha256(archive.read_bytes()).hexdigest() == row["SHA256"])
        archives.append((name, version, archive))
    return archives


def verify_installed(source):
    """Check installed versions and package payload, including Samba/LDB .so files."""
    for name, version, archive in verified_archives(source):
        installed = command(["dpkg-query", "--show", "--showformat=${db:Status-Status} ${Version}", name]).decode()
        require(installed == "installed " + version)
        payload = command(["dpkg-deb", "--fsys-tarfile", str(archive)])
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tar:
            for member in tar:
                parts = Path(member.name).parts
                require(".." not in parts and not Path(member.name).is_absolute())
                relative = member.name.removeprefix("./")
                # Package conffiles are intentionally managed separately by S4.
                if not relative.startswith(("usr/bin/", "usr/sbin/", "usr/lib/", "usr/libexec/")): continue
                path = Path("/") / relative
                if member.isfile():
                    expected = tar.extractfile(member).read()
                    require(secure_file(path, secret=False).read_bytes() == expected)
                elif member.issym():
                    require(path.is_symlink() and str(path.readlink()) == member.linkname)
                else:
                    require(member.isdir())


def install(source):
    """Install only a pre-reviewed complete offline set; never run apt resolution.

    A pre-existing policy-rc.d must deny automatic service starts. This helper
    neither replaces that policy nor removes a policy owned by another project.
    """
    require(source["fingerprint"] == CANDIDATE_PRIMARY and source["key_sha256"] == CANDIDATE_KEY_SHA256)
    archives = verified_archives(source)
    policy = secure_file("/usr/sbin/policy-rc.d", secret=False)
    require(policy.stat().st_mode & 0o111)
    result = subprocess.run([str(policy), "samba-ad-dc", "start"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(result.returncode == 101)
    command(["dpkg", "--install"] + [str(a) for _, _, a in archives])
    verify_installed(source)
