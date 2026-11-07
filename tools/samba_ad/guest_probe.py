"""Guest-only first proof. No installation, Samba, network or host fallback.

security.NTACL uses an opaque sentinel: this proves protected namespace access,
not the validity of a Samba descriptor. POSIX ACL encoding follows Linux UAPI
posix_acl{,_xattr}.h (version 2, little endian).
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys


def require(value):
    if not value:
        raise ValueError("guest proof precondition")


def identity():
    require(os.path.realpath("/var/lib") == "/var/lib")
    parent = os.stat("/var/lib", follow_symlinks=False)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_mode & 0o022 == 0)
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        point = before.split()[4]
        if "/var/lib" == point or "/var/lib".startswith(point.rstrip("/") + "/"):
            mounts.append((len(point), after.split()[0]))
    require(bool(mounts))
    return {"hostname": os.uname().nodename, "euid": os.geteuid(),
            "namespaces": {n: os.readlink("/proc/self/ns/" + n) for n in ["user", "mnt", "pid"]},
            "uid_map": " ".join(Path("/proc/self/uid_map").read_text().split()),
            "apparmor": Path("/proc/self/attr/current").read_text().strip(),
            "filesystem": max(mounts)[1], "parent_dev": parent.st_dev, "parent_ino": parent.st_ino,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "cgroup": Path("/proc/1/cgroup").read_text().strip()}


def validate_identity(expected, actual):
    require(set(expected) == {"run_id", "guest", "host_namespaces"})
    require(isinstance(expected["run_id"], str) and re.fullmatch(r"[a-f0-9]{32}", expected["run_id"]))
    require(actual == expected["guest"] and actual["euid"] == 0)
    require(actual["hostname"].endswith(".lab.ad.test"))
    require(actual["filesystem"] in ["ext4", "xfs", "zfs", "btrfs"])
    require("unconfined" not in actual["apparmor"] and actual["apparmor"].endswith("(enforce)"))
    for ns in ["user", "mnt", "pid"]:
        require(re.fullmatch(ns + r":\[[0-9]+\]", actual["namespaces"][ns]))
        require(actual["namespaces"][ns] != expected["host_namespaces"][ns])
    mapping = [int(v) for v in actual["uid_map"].split()]
    require(len(mapping) == 3 and mapping[0] == 0 and mapping[1] > 0 and mapping[2] >= 65535)
    require(bool(actual["cgroup"]) and bool(actual["boot_id"]))


class NativeOps:
    identity = staticmethod(identity)

    def create(self, run_id, parent):
        directory = os.open("/var/lib", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            require((info.st_dev, info.st_ino) == (parent["parent_dev"], parent["parent_ino"]))
            name = ".samba-ad-s2-" + run_id
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_RDWR, 0o600, dir_fd=directory)
        except BaseException:
            os.close(directory)
            raise
        return {"fd": fd, "dir": directory, "name": name, "inode": os.fstat(fd)}

    def ntacl(self, handle):
        value = b"samba-ad-s2-protected-namespace-v1"
        os.setxattr(handle["fd"], "security.NTACL", value, os.XATTR_CREATE)
        require(os.getxattr(handle["fd"], "security.NTACL") == value)

    def acl(self, handle):
        undefined = 0xffffffff
        entries = [(1, 6, undefined), (2, 4, 65534), (4, 0, undefined), (16, 4, undefined), (32, 0, undefined)]
        value = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)
        os.setxattr(handle["fd"], "system.posix_acl_access", value)
        require(os.getxattr(handle["fd"], "system.posix_acl_access") == value)
        os.write(handle["fd"], b"s2")
        for uid, allowed in [(65534, True), (65533, False)]:
            pid = os.fork()
            if pid == 0:
                try:
                    os.setgroups([]); os.setgid(uid); os.setuid(uid)
                    try:
                        fd = os.open(handle["name"], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=handle["dir"])
                    except PermissionError:
                        os._exit(0 if not allowed else 1)
                    data = os.read(fd, 2); os.close(fd)
                    os._exit(0 if allowed and data == b"s2" else 1)
                except BaseException:
                    os._exit(2)
            _, status = os.waitpid(pid, 0)
            require(os.waitstatus_to_exitcode(status) == 0)

    def cleanup(self, handle):
        try:
            entry = os.stat(handle["name"], dir_fd=handle["dir"], follow_symlinks=False)
            original = handle["inode"]
            require(stat.S_ISREG(entry.st_mode) and (entry.st_dev, entry.st_ino) ==
                    (original.st_dev, original.st_ino))
            os.unlink(handle["name"], dir_fd=handle["dir"])
        finally:
            os.close(handle["fd"]); os.close(handle["dir"])


def run_probe(expected: dict, ops=None) -> dict:
    ops = NativeOps() if ops is None else ops
    result = {"schema": "samba-ad-s2-probe/v1", "run_id": expected.get("run_id"),
              "status": "operational_error", "checks": [], "cleanup": "not_created"}
    handle = None
    protected = {errno.EPERM, errno.EACCES, errno.EOPNOTSUPP}
    try:
        validate_identity(expected, ops.identity())
        handle = ops.create(expected["run_id"], expected["guest"])
        for name, operation in [("security_ntacl", ops.ntacl), ("posix_acl", ops.acl)]:
            check = {"name": name, "status": "operational_error", "attempts": []}
            result["checks"].append(check)
            try:
                operation(handle)
            except OSError as first:
                check["attempts"].append(errno.errorcode.get(first.errno, "UNKNOWN"))
                if first.errno not in protected:
                    raise
                try:
                    operation(handle)
                except OSError as second:
                    check["attempts"].append(errno.errorcode.get(second.errno, "UNKNOWN"))
                    if second.errno == first.errno:
                        check["status"] = "incompatible"
                        result["status"] = "incompatible"
                        break
                require(False)  # A transient failure is not a reproduced limitation.
            else:
                check["status"] = "passed"
        else:
            result["status"] = "passed"
    except (OSError, ValueError, KeyError, TypeError):
        result["status"] = "operational_error"
    finally:
        if handle is not None:
            try:
                ops.cleanup(handle)
                result["cleanup"] = "complete"
            except (OSError, ValueError):
                result["cleanup"] = "incomplete"
                result["status"] = "operational_error"
    return result


def main():
    try:
        result = run_probe(json.load(sys.stdin))
        print(json.dumps(result))
        return {"passed": 0, "incompatible": 3, "operational_error": 2}[result["status"]]
    except (ValueError, TypeError, KeyError, OSError):
        print("S2 guest proof failed; values suppressed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
