"""Own only the two fixed persistent files for the additional S1 router NIC.

Sent with python -c to the guest; also embedded in the canonical revert.sh.
No device events are triggered. Only installation/removal reloads udev metadata.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

NETWORK = Path("/etc/systemd/network/05-samba-ad-identity.network")
LINK = Path("/etc/systemd/network/05-samba-ad-identity.link")
SYS_CLASS_NET = Path("/sys/class/net")
OWNER = (0, 0)


def require(ok):
    if not ok:
        raise ValueError("S1 persistent NIC policy ownership/state mismatch")


def expected_files(request, network):
    mac, name = request["mac"].lower(), request["interface"]
    require(re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac))
    require(re.fullmatch(r"eth[1-9]", name))
    require(isinstance(network, str) and network.startswith("# samba-ad-s1:"))
    link = ("# samba-ad-s1: own additional interface naming only\n[Match]\n"
            f"MACAddress={mac}\nDriver=virtio_net\n[Link]\nNamePolicy=\nName={name}\n")
    return {NETWORK: network.encode(), LINK: link.encode()}


def owned(path, expected):
    """Read no symlinks/special files; validate metadata and exact content."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and (before.st_uid, before.st_gid) == OWNER
            and stat.S_IMODE(before.st_mode) == 0o644 and before.st_size == len(expected))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
        require(hashlib.sha256(stream.read()).digest() == hashlib.sha256(expected).digest())
    after = path.lstat()
    require((after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink)
            == (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink))
    return before


def verify(request, network, phase):
    require(phase in ("absent", "verify"))
    for path, content in expected_files(request, network).items():
        present = owned(path, content) is not None
        require(present == (phase == "verify"))


def command(argv):
    subprocess.run(argv, capture_output=True, text=True, check=True, timeout=20)


def install(request, network):
    verify(request, network, "absent")
    for path, content in expected_files(request, network).items():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    verify(request, network, "verify")
    # systemd.link(5): reload configuration before the new device event. This
    # changes metadata only; never trigger legacy devices or reload networkd here.
    command(["udevadm", "control", "--reload"])


def rollback(request, network):
    files = expected_files(request, network)
    present = {path: owned(path, content) for path, content in files.items()}
    if not any(present.values()):
        return
    # Validate both files before any down/unlink, including partial installation.
    # Never infer a kernel/PCI name or down another interface that shares a MAC.
    iface = request["interface"]
    address = SYS_CLASS_NET / iface / "address"
    if address.exists():
        require(address.read_text().strip().lower() == request["mac"].lower())
        command(["networkctl", "down", iface])
    for path, prior in present.items():
        if prior is not None:
            current = owned(path, files[path])
            require(current is not None and (current.st_dev, current.st_ino) == (prior.st_dev, prior.st_ino))
    for path, prior in present.items():
        if prior is not None:
            path.unlink()
    if present[NETWORK] is not None:
        command(["networkctl", "reload"])
    if present[LINK] is not None:
        command(["udevadm", "control", "--reload"])


def main():
    try:
        data = json.load(sys.stdin)
        operation = data["operation"]
        require(operation in ("absent", "verify", "install", "rollback"))
        if operation in ("absent", "verify"):
            verify(data["request"], data["network"], operation)
        else:
            {"install": install, "rollback": rollback}[operation](data["request"], data["network"])
        print('{"verified":true}')
        return 0
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError):
        print("S1 persistent NIC policy failed; values suppressed; no drift repair", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
