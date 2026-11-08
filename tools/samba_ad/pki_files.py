"""Protected local PKI file operations. No key generation or transport."""
import os
from pathlib import Path
import stat
import uuid

from tools.samba_ad.pki import require
from tools.samba_ad.pki_contract import path


def future_directory(directory, owner_uid=None):
    """Readonly validation of every existing ancestor, including dangling links."""
    p = Path(path(str(directory)))
    require(p.resolve() == p)
    for parent in [p, *p.parents]:
        require(not parent.is_symlink())
        if not parent.exists():
            continue
        s = parent.stat()
        owners = {0, os.geteuid()}
        if parent == p and owner_uid is not None:
            owners.add(owner_uid)
        require(parent.is_dir() and s.st_uid in owners and not (parent / ".git").exists())
        require(not s.st_mode & 0o022 or (parent == Path("/tmp") and s.st_uid == 0 and s.st_mode & stat.S_ISVTX))
    return p


def role_paths(profile=None):
    """Guard the role's fixed destinations before Ansible can chmod/copy them."""
    library = Path("/usr/libexec/samba-ad-pki")
    directories = [library, library / "tools", library / "tools/samba_ad",
                   Path("/etc/samba-ad-pki"), Path("/etc/samba-ad-pki/profiles"),
                   Path("/etc/samba-ad-pki/requests"), Path("/etc/systemd/system")]
    for directory in directories:
        future_directory(directory)
    files = [library / "frontend.js", library / "tools/__init__.py",
             library / "tools/samba_ad/__init__.py"]
    files += [library / "tools/samba_ad" / (name + ".py") for name in
              ["compatibility", "ca_substrate", "pki", "pki_contract", "pki_files", "pki_runtime", "pki_material", "pki_ca"]]
    if profile is not None:
        files += [Path("/etc/samba-ad-pki/requests") / (profile + ".json")]
        files += [Path("/etc/systemd/system") / ("samba-ad-pki-" + profile + "." + suffix)
                  for suffix in ["service", "timer"]]
    for filename in files:
        if filename.exists() or filename.is_symlink():
            secure_file(filename)


def secure_directory(directory, exact=False):
    p = Path(path(str(directory)))
    require(p.resolve() == p and p.is_dir())
    for parent in [p, *p.parents]:
        s = parent.stat()
        require(s.st_uid in [0, os.geteuid()] and not (parent / ".git").exists())
        require(not s.st_mode & 0o022 or (parent == Path("/tmp") and s.st_uid == 0 and s.st_mode & stat.S_ISVTX))
    if exact:
        require(stat.S_IMODE(p.stat().st_mode) == 0o700 and p.stat().st_uid == os.geteuid())
    return p


def secure_file(filename, secret=False):
    p = Path(path(str(filename)))
    secure_directory(p.parent)
    require(p.resolve() == p)
    s = p.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid in [0, os.geteuid()] and not s.st_mode & 0o022)
    require(not secret or not s.st_mode & 0o077)
    return p


def sync_dir(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def exclusive_file(p, value):
    secure_directory(p.parent)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(value); out.flush(); os.fsync(out.fileno())
    sync_dir(p.parent)


def atomic_file(p, value):
    temp = p.parent / (".write-" + uuid.uuid4().hex)
    exclusive_file(temp, value)
    os.replace(temp, p)
    sync_dir(p.parent)
