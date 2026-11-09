"""Package-free, guest-only QEMU substrate measurements. Never provision AD.

Loaded with the reviewed s2_protected module by the explicit QGA runner.
Audit measures live kernel status, not production log delivery or audit rules.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

import s2_protected as protected

CHECKS = ["security_ntacl", "posix_acl", "systemd", "clock", "audit", "isolation", "network"]
require = protected.require


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
    return {"hostname": os.uname().nodename, "euid": os.geteuid(), "filesystem": max(mounts)[1],
            "parent_dev": parent.st_dev, "parent_ino": parent.st_ino,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "product_uuid": Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower(),
            "kernel": os.uname().release}


def validate_identity(expected, actual):
    require(set(expected) == {"run_id", "nonce", "host_boot_id", "resource", "guest"})
    for key in ["run_id", "nonce"]:
        require(isinstance(expected[key], str) and re.fullmatch(r"[a-f0-9]{32}", expected[key]))
    require(set(actual) == {"hostname", "euid", "filesystem", "parent_dev", "parent_ino",
                            "boot_id", "product_uuid", "kernel"})
    require(actual == expected["guest"] and actual["euid"] == 0)
    require(expected["resource"]["kind"] == "qemu")
    require(actual["hostname"] == expected["resource"]["name"] and actual["hostname"].endswith(".lab.ad.test"))
    require(actual["filesystem"] in ["ext4", "xfs", "zfs", "btrfs"])
    require(isinstance(actual["product_uuid"], str) and actual["product_uuid"] == str(uuid.UUID(actual["product_uuid"])))
    require(uuid.UUID(actual["product_uuid"]).int != 0)
    for boot in [actual["boot_id"], expected["host_boot_id"]]:
        require(isinstance(boot, str) and re.fullmatch(r"[a-f0-9-]{32,36}", boot))
    require(actual["boot_id"] != expected["host_boot_id"] and bool(actual["kernel"]))
    require(all(type(actual[k]) is int and actual[k] >= 0 for k in ["parent_dev", "parent_ino"]))


def audit_status(data):
    require(len(data) >= 32)
    _, enabled, failure, pid, rate_limit, backlog_limit, lost, backlog = struct.unpack("=8I", data[:32])
    require(enabled in [1, 2] and failure in [1, 2] and pid > 0 and lost == 0 and backlog_limit > 0)
    return dict(enabled=enabled, failure=failure, listener_pid=pid, rate_limit=rate_limit,
                backlog_limit=backlog_limit, lost=lost, backlog=backlog)


def kernel_audit():
    # Linux UAPI linux/audit.h AUDIT_GET=1000; no rule or audit state mutation.
    sequence = int.from_bytes(os.urandom(4), "little") or 1
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 9) as channel:  # NETLINK_AUDIT
        channel.settimeout(3)
        channel.bind((0, 0))
        channel.sendto(struct.pack("=IHHII", 16, 1000, 1, sequence, channel.getsockname()[0]), (0, 0))
        data, address = channel.recvfrom(4096)
    require(address[0] == 0 and len(data) >= 48)
    length, kind, _, received, _ = struct.unpack("=IHHII", data[:16])
    require(48 <= length <= len(data) and kind == 1000 and received == sequence)
    return audit_status(data[16:length])


def network_status(links, routes, resource):
    require(isinstance(links, list) and isinstance(routes, list))
    require(all(isinstance(item, dict) for item in links + routes))
    physical = [link for link in links if link.get("ifname") != "lo"]
    require(len(physical) == 1)
    nic = physical[0]
    require(nic.get("address", "").lower() == resource["mac"].lower() and nic.get("mtu") == resource["mtu"])
    require({"UP", "LOWER_UP"} <= set(nic.get("flags", [])))
    require(isinstance(nic.get("addr_info"), list) and all(isinstance(a, dict) for a in nic["addr_info"]))
    addresses = [str(ipaddress.IPv4Interface(str(a["local"]) + "/" + str(a["prefixlen"])))
                 for a in nic.get("addr_info", []) if a.get("family") == "inet"]
    require(addresses == [resource["address"]])
    require(all(a.get("scope") == "link" for a in nic.get("addr_info", []) if a.get("family") == "inet6"))
    defaults = [route for route in routes if route.get("dst") == "default"]
    require(len(defaults) == 1 and defaults[0].get("gateway") == resource["gateway"]
            and defaults[0].get("dev") == nic["ifname"] and not defaults[0].get("multipath"))
    return {"interface": nic["ifname"], "address": addresses[0], "mac": nic["address"],
            "mtu": nic["mtu"], "gateway": resource["gateway"]}


def command(argv, allowed=(0,)):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=5, check=False)
    require(result.returncode in allowed and not result.stderr.strip() and len(result.stdout) <= 65536)
    return result


class NativeOps(protected.NativeOps):
    identity = staticmethod(identity)

    def measure(self, name, resource):
        if name == "systemd":
            require(Path("/proc/1/comm").read_text().strip() == "systemd")
            state = command(["/usr/bin/systemctl", "is-system-running"]).stdout.strip()
            require(state == "running")
            return {"pid1": "systemd", "state": state}
        if name == "clock":
            synced = command(["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"]).stdout.strip()
            require(synced == "yes")
            return {"ntp_synchronized": True, "realtime_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns()}
        if name == "audit":
            return kernel_audit()
        if name == "isolation":
            vm = command(["/usr/bin/systemd-detect-virt", "--vm"]).stdout.strip()
            container = command(["/usr/bin/systemd-detect-virt", "--container"], (1,)).stdout.strip()
            require(vm in ["qemu", "kvm"] and container == "none")
            return {"vm": vm, "container": container, "kernel": os.uname().release}
        if name == "network":
            links = json.loads(command(["/usr/sbin/ip", "-j", "address", "show"]).stdout)
            routes = json.loads(command(["/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all"]).stdout)
            return network_status(links, routes, resource)
        require(False)


def run_probe(expected, ops=None):
    ops = NativeOps() if ops is None else ops
    result = {"schema": "samba-ad-s2-qemu-probe/v1", "run_id": expected.get("run_id"),
              "nonce": expected.get("nonce"), "status": "operational_error", "checks": [],
              "cleanup": "not_created", "measurements": {}}
    handle = None
    try:
        validate_identity(expected, ops.identity())
        handle = ops.create(expected["run_id"], expected["guest"])
        for name in CHECKS:
            result["checks"].append({"name": name, "status": "operational_error", "attempts": []})
            if name == "security_ntacl": ops.ntacl(handle)
            elif name == "posix_acl": ops.acl(handle)
            else: result["measurements"][name] = ops.measure(name, expected["resource"])
            result["checks"][-1]["status"] = "passed"
        validate_identity(expected, ops.identity())
        result["status"] = "passed"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        pass
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
        return 0 if result["status"] == "passed" else 2
    except (OSError, ValueError, KeyError, TypeError):
        print("S2 QEMU guest probe failed; values suppressed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
