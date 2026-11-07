"""Validate the complete synthetic tables in a fresh unprivileged net namespace.

Only test setup: create the two EMPTY fixture ipsets via Linux's installed UAPI,
then iptables-restore --test for both families. No ipset CLI/package is needed.
The ipset members/bridge/path proof is covered separately by readback unit tests.
Never call from production; the worker refuses the original network namespace.
"""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys


def attribute(kind, value):
    length = 4 + len(value)
    return struct.pack("HH", length, kind) + value + b"\0" * ((-length) % 4)


def create_fixture_set(name, family):
    # linux/netfilter/{nfnetlink.h,ipset/ip_set.h}: subsystem=6, CREATE=2,
    # protocol=7; nested DATA attrs HASHSIZE=18, MAXELEM=19 (network byte order).
    attrs = (attribute(1, b"\x07") + attribute(2, name.encode() + b"\0")
             + attribute(3, b"hash:net\0") + attribute(4, b"\0") + attribute(5, bytes([family])))
    data = attribute(18 | 0x4000, struct.pack("!I", 64)) + attribute(19 | 0x4000, struct.pack("!I", 64))
    payload = struct.pack("BBH", family, 0, 0) + attrs + attribute(7 | 0x8000, data)
    message = struct.pack("IHHII", 16 + len(payload), (6 << 8) | 2, 1 | 4 | 0x200, 1, 0) + payload
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as sock:
        sock.settimeout(5); sock.bind((0, 0)); sock.sendto(message, (0, 0))
        reply = sock.recv(65536)
        error = struct.unpack_from("i", reply, 16)[0]
        if error:
            raise OSError("isolated fixture ipset create error " + str(error))


def main():
    if sys.argv[1:2] != ["--inside"]:
        descriptor = os.open("/proc/self/ns/net", os.O_RDONLY)
        try:
            return subprocess.run(["unshare", "--user", "--map-root-user", "--net", sys.executable,
                                   str(Path(__file__).resolve()), "--inside", str(descriptor)],
                                  pass_fds=(descriptor,), check=False).returncode
        finally:
            os.close(descriptor)
    # An inherited namespace FD avoids reading a parent process across userns.
    # Refuse the original namespace before any netlink writes.
    descriptor = int(sys.argv[2])
    if not os.readlink(f"/proc/self/fd/{descriptor}").startswith("net:["):
        raise RuntimeError("fixture worker requires its original network namespace FD")
    if os.stat("/proc/self/ns/net").st_ino == os.fstat(descriptor).st_ino:
        raise RuntimeError("fixture worker must run in a different network namespace")
    data = json.loads(Path(__file__).with_name("pve-runtime.json").read_text())
    create_fixture_set("PVEFW-800080-ipfilter-net0-v4", socket.AF_INET)
    create_fixture_set("PVEFW-800080-ipfilter-net0-v6", socket.AF_INET6)
    for family, program in [("ipv4", "iptables-restore"), ("ipv6", "ip6tables-restore")]:
        result = subprocess.run([program, "--test"], input=data[family], text=True, capture_output=True, check=False)
        if result.returncode:
            print(result.stderr, file=sys.stderr)
            return result.returncode
    print("both complete synthetic tables validated in isolated namespace")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
