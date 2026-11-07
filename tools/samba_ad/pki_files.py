"""Protected local PKI file operations. No key generation or transport."""
import os
from pathlib import Path
import stat
import uuid

from tools.samba_ad.pki import require
from tools.samba_ad.pki_contract import path


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
