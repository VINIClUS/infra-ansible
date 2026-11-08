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
import tempfile

NETWORK = Path("/etc/systemd/network/05-samba-ad-identity.network")
LINK = Path("/etc/systemd/network/05-samba-ad-identity.link")
SYS_CLASS_NET = Path("/sys/class/net")
OWNER = (0, 0)
PENDING = Path("/root/samba-ad-s1-network/policy-pending.json")


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


def _fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _stage(path, content, mode=0o644):
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), *OWNER)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        return staged
    except BaseException:
        try:
            staged.unlink()
        except FileNotFoundError:
            pass
        raise


def _pending_owned():
    """Read the protected reload journal, refusing foreign or malformed state."""
    try:
        before = PENDING.lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and (before.st_uid, before.st_gid) == OWNER
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_size <= 4096)
    fd = os.open(PENDING, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
        raw = stream.read()
    after = PENDING.lstat()
    require((after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink)
            == (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink))
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("invalid protected NIC reload journal")
    require(isinstance(state, dict) and set(state) == {"required", "completed"})
    required, completed = state["required"], state["completed"]
    require(isinstance(required, list) and isinstance(completed, list))
    require(set(required) in ({"network"}, {"link"}, {"network", "link"}))
    require(set(completed).issubset(set(required)) and len(set(required)) == len(required)
            and len(set(completed)) == len(completed))
    return {"required": set(required), "completed": set(completed)}


def _write_pending(required, completed):
    required, completed = set(required), set(completed)
    require(required in ({"network"}, {"link"}, {"network", "link"}))
    require(completed.issubset(required))
    current = _pending_owned()
    payload = json.dumps({"required": sorted(required), "completed": sorted(completed)},
                         sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    staged = _stage(PENDING, payload, mode=0o600)
    try:
        if current is None:
            os.link(staged, PENDING, follow_symlinks=False)
            staged.unlink()
        else:
            os.replace(staged, PENDING)
        _fsync_directory(PENDING.parent)
    finally:
        try:
            staged.unlink()
        except FileNotFoundError:
            pass
    _pending_owned()


def _clear_pending():
    if _pending_owned() is None:
        return
    PENDING.unlink()
    _fsync_directory(PENDING.parent)


def verify(request, network, phase):
    require(phase in ("absent", "verify"))
    require(_pending_owned() is None)
    for path, content in expected_files(request, network).items():
        present = owned(path, content) is not None
        require(present == (phase == "verify"))


def command(argv):
    subprocess.run(argv, capture_output=True, text=True, check=True, timeout=20)


def install(request, network):
    verify(request, network, "absent")
    staged = []
    try:
        for path, content in expected_files(request, network).items():
            staged.append((path, _stage(path, content)))
        for path, temporary in staged:
            # Hard-linking a complete, fsynced inode is atomic and no-clobber;
            # unlike rename it cannot replace a competing destination.
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
            _fsync_directory(path.parent)
    finally:
        for _, temporary in staged:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    verify(request, network, "verify")
    # systemd.link(5): reload configuration before the new device event. This
    # changes metadata only; never trigger legacy devices or reload networkd here.
    command(["udevadm", "control", "--reload"])


def rollback(request, network):
    files = expected_files(request, network)
    pending = _pending_owned()
    present = {path: owned(path, content) for path, content in files.items()}
    if pending is None and not any(present.values()):
        return
    names = {"network": NETWORK, "link": LINK}
    if pending is None:
        pending = {"required": {name for name, path in names.items() if present[path]},
                   "completed": set()}
    else:
        require(all(not present[path] or name in pending["required"]
                     for name, path in names.items()))
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
    if _pending_owned() is None:
        _write_pending(pending["required"], pending["completed"])
    for path, prior in present.items():
        if prior is not None:
            path.unlink()
    if any(prior is not None for prior in present.values()):
        _fsync_directory(NETWORK.parent)
    errors = []
    reloads = {
        "network": ["networkctl", "reload"],
        "link": ["udevadm", "control", "--reload"],
    }
    for name in ("network", "link"):
        if name not in pending["required"] or name in pending["completed"]:
            continue
        try:
            command(reloads[name])
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(error)
            continue
        pending["completed"].add(name)
        try:
            _write_pending(pending["required"], pending["completed"])
        except (OSError, ValueError) as error:
            errors.append(error)
    if errors:
        raise errors[0]
    require(pending["completed"] == pending["required"])
    _clear_pending()


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
