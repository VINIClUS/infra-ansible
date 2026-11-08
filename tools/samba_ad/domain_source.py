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

SAMBA_RUNTIME = set("samba samba-ad-dc samba-ad-provision samba-common samba-common-bin samba-dsdb-modules samba-libs winbind libwbclient0 python3-samba".split())
SUPPORT_RUNTIME = set("libldb2 python3-ldb libtalloc2 python3-talloc libtdb1 python3-tdb libtevent0t64".split())
MANAGED_CONFFILES = {"etc/samba/smb.conf"}
DENY_ALL_POLICY = b"#!/bin/sh\nexit 101\n"


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
    require(isinstance(pins, dict) and SAMBA_RUNTIME | SUPPORT_RUNTIME <= set(pins))
    require(len({pins[p] for p in SAMBA_RUNTIME}) == 1)
    require("4.25.1" in pins["samba"])
    require(pins["libldb2"] == pins["python3-ldb"] and "2.11.0+samba4.25.1" in pins["libldb2"])
    require(pins["libtalloc2"] == pins["python3-talloc"] and pins["libtdb1"] == pins["python3-tdb"])


def terms(value):
    """Binary Depends grammar; unknown architecture/profile syntax fails closed."""
    groups = []
    if not value: return groups
    for group in value.split(","):
        choices = []
        for alternative in group.split("|"):
            match = re.fullmatch(r"\s*([a-z0-9][a-z0-9+.-]+)(?::(?:any|native|amd64))?(?:\s+\((<<|<=|=|>=|>>)\s+([^\s()]+)\))?\s*", alternative)
            require(match is not None)
            choices.append((match[1], match[2], match[3]))
        groups.append(choices)
    return groups


def version_matches(version, operator, required):
    if operator is None: return True
    result = subprocess.run(["dpkg", "--compare-versions", version, operator, required],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode in [0, 1])
    return result.returncode == 0


def dependency_plan(rows, pins):
    """Resolve the vendor closure from authenticated Depends/Pre-Depends/Provides.

    Only binary packages in this signed index are vendor candidates. Distribution
    constraints remain separate and do not inherit Samba's version namespace.
    """
    validate_pins(pins)
    by_name = {}
    providers = {}
    for row in rows:
        if row.get("Architecture") not in ["amd64", "all"]: continue
        name = row["Package"]
        require(name not in by_name)
        by_name[name] = row
        for group in terms(row.get("Provides", "")):
            require(len(group) == 1 and group[0][1] in [None, "="])
            virtual, _, provided = group[0]
            providers.setdefault(virtual, []).append((name, provided))
    vendor, base, pending = {}, [], ["samba-ad-dc", "samba-ad-provision"]
    while pending:
        name = pending.pop()
        if name in vendor: continue
        require(name in pins and name in by_name and by_name[name]["Version"] == pins[name])
        row = by_name[name]; vendor[name] = row
        for group in terms(row.get("Pre-Depends", "")) + terms(row.get("Depends", "")):
            candidates = []
            vendor_edge = False
            for dep, operator, required in group:
                if dep in by_name:
                    vendor_edge = True
                    if dep in pins and version_matches(pins[dep], operator, required): candidates.append(dep)
                for provider, version in providers.get(dep, []):
                    vendor_edge = True
                    if provider in pins and (operator is None or version is not None and version_matches(version, operator, required)):
                        candidates.append(provider)
            if vendor_edge:
                require(candidates)
                pending.append(sorted(set(candidates))[0])
            else:
                base.append(group)
    require(set(vendor) == set(pins))
    return {"vendor": vendor, "base": base}


def verify_base_dependencies(source):
    packages = secure_file(Path(source["directory"]) / "Packages").read_bytes()
    require(hashlib.sha256(packages).hexdigest() == source["packages_sha256"])
    plan = dependency_plan(paragraphs(packages.decode()), source["packages"])
    installed = {}
    for group in plan["base"]:
        satisfied = False
        for name, operator, required in group:
            if name not in installed:
                result = subprocess.run(["dpkg-query", "--show", "--showformat=${db:Status-Status} ${Version}", name],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                require(result.returncode in [0, 1])
                text = result.stdout.decode()
                installed[name] = text.removeprefix("installed ") if result.returncode == 0 and text.startswith("installed ") else None
            version = installed[name]
            if version is not None and version_matches(version, operator, required): satisfied = True
        require(satisfied)


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
    dependency_plan(rows, source["packages"])
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
    """Verify the entire immutable payload, including schema/LDIF provisioning data."""
    archives = verified_archives(source)
    verify_base_dependencies(source)
    for name, version, archive in archives:
        installed = command(["dpkg-query", "--show", "--showformat=${db:Status-Status} ${Version}", name]).decode()
        require(installed == "installed " + version)
        payload = command(["dpkg-deb", "--fsys-tarfile", str(archive)])
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tar:
            for member in tar:
                parts = Path(member.name).parts
                require(".." not in parts and not Path(member.name).is_absolute())
                relative = member.name.removeprefix("./")
                if relative in MANAGED_CONFFILES: continue
                if relative in ["", "."]: continue
                # Debian's usrmerge aliases are canonical system directories,
                # not a license to follow arbitrary package-path symlinks.
                first, separator, rest = relative.partition("/")
                if first in ["bin", "sbin", "lib", "lib64"]: relative = "usr/" + first + (separator + rest if separator else "")
                path = Path("/") / relative
                if member.isfile() or member.islnk():
                    if member.islnk(): require(not Path(member.linkname).is_absolute() and ".." not in Path(member.linkname).parts)
                    expected = tar.extractfile(member).read()
                    require(secure_file(path, secret=False).read_bytes() == expected)
                elif member.issym():
                    secure_directory(path.parent)
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
    verify_base_dependencies(source)
    policy = secure_file("/usr/sbin/policy-rc.d", secret=False)
    require(policy.stat().st_mode & 0o111 and policy.read_bytes() == DENY_ALL_POLICY)
    for service in ["samba", "samba-ad-dc", "smbd", "nmbd", "winbind"]:
        for action in ["start", "stop", "restart", "reload", "force-reload", "try-restart", "reload-or-restart", "try-reload-or-restart"]:
            result = subprocess.run([str(policy), service, action], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            require(result.returncode == 101)
    command(["dpkg", "--install"] + [str(a) for _, _, a in archives])
    verify_installed(source)
