"""Readonly router guest identity/network proof shared by add and verify.

The optional --reconfigure validates the fresh snapshot before touching only the
new, MAC/PCI/ifindex-identified device. Input and output are JSON, never secrets.
"""
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys


def require(ok, field):
    if not ok:
        raise ValueError("S1 router guest state: " + field)


def command(argv):
    p = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=20)
    require(p.returncode == 0, "read/reconfigure command failed; output suppressed")
    return p.stdout


def capture():
    command(["systemctl", "is-active", "--quiet", "systemd-networkd"])
    links = json.loads(command(["ip", "-j", "-d", "link", "show"]))
    for link in links:
        device = Path("/sys/class/net") / link["ifname"] / "device"
        link["device"] = str(device.resolve()) if device.exists() else None
        link["driver"] = (device / "driver").resolve().name if (device / "driver").exists() else None
    return {"links": links, "addresses": json.loads(command(["ip", "-j", "address", "show"])),
            "routes4": json.loads(command(["ip", "-j", "-4", "route", "show", "table", "all"])),
            "routes6": json.loads(command(["ip", "-j", "-6", "route", "show", "table", "all"]))}


def canonical(records):
    return sorted(json.dumps(record, sort_keys=True, separators=(",", ":")) for record in records)


def links(records, exclude):
    keys = ["ifname", "ifindex", "address", "mtu", "operstate", "link_type", "master", "link_index", "device", "driver"]
    return canonical([{**{key: item.get(key) for key in keys}, "flags": sorted(item.get("flags", []))}
                      for item in records if item["ifname"] != exclude])


def addresses(records, exclude):
    keys = ["family", "local", "prefixlen", "scope", "broadcast", "label"]
    return canonical([{"ifname": item["ifname"], "addresses": canonical([
        {key: address.get(key) for key in keys} for address in item.get("addr_info", [])])}
        for item in records if item["ifname"] != exclude])


def routes(records, exclude):
    return canonical([{key: value for key, value in item.items() if key not in ["expires", "cache"]}
                      for item in records if item.get("dev") != exclude])


def validate(r, observed, baseline, phase):
    name, mac = r["interface"], r["mac"].lower()
    require(re.fullmatch(r"eth[1-9]", name) and re.fullmatch(r"02(?::[0-9a-f]{2}){5}", mac), "new interface identity")
    require(phase in ["absent", "preconfigure", "verify"], "phase")
    target = ipaddress.IPv4Interface(r["address"])
    require(not any(link["ifname"] == name or link.get("address", "").lower() == mac
                    for link in baseline["links"]), "baseline already owns name/MAC")
    require(not any(a.get("local") == str(target.ip) for i in baseline["addresses"]
                    for a in i.get("addr_info", [])), "baseline already owns address")
    require(links(observed["links"], name) == links(baseline["links"], name), "old interfaces drift")
    require(addresses(observed["addresses"], name) == addresses(baseline["addresses"], name), "old addresses drift")
    for family in ["routes4", "routes6"]:
        require(routes(observed[family], name) == routes(baseline[family], name), "old routes drift")
        for route in observed[family]:
            if route.get("dev") == name:
                dst = route.get("dst", "default")
                require(dst != "default" and not route.get("gateway") and family == "routes4"
                        and ipaddress.ip_network(dst if "/" in dst else dst + "/32").subnet_of(target.network),
                        "unexpected route on new device")
    matches = [link for link in observed["links"] if link["ifname"] == name]
    if phase == "absent":
        require(not matches and not any(link.get("address", "").lower() == mac for link in observed["links"]),
                "new name/MAC is occupied")
        return
    require(len(matches) == 1, "new interface absent or ambiguous")
    link = matches[0]
    require(link.get("address", "").lower() == mac and link.get("link_type") == "ether"
            and link.get("driver") == "virtio_net" and isinstance(link.get("device"), str)
            and link["device"].startswith("/sys/devices/pci") and type(link.get("ifindex")) is int
            and link["ifindex"] not in {old["ifindex"] for old in baseline["links"]}, "wrong MAC/device/index")
    require(sum(item.get("address", "").lower() == mac for item in observed["links"]) == 1, "duplicate MAC")
    if phase == "verify":
        connected = [route for route in observed["routes4"]
                     if route.get("dev") == name and route.get("type", "unicast") == "unicast"
                     and route.get("table", "main") in ["main", 254]
                     and route.get("protocol") in ["kernel", 2] and route.get("scope") in ["link", 253]
                     and not route.get("gateway") and route.get("dst") == str(target.network)]
        require(len(connected) == 1, "connected route missing/ambiguous in main table")
        require(link.get("mtu") == r["mtu"] and link.get("operstate") == "UP"
                and {"UP", "LOWER_UP"} <= set(link.get("flags", [])), "link/MTU drift")
        ips = [a for item in observed["addresses"] if item["ifname"] == name for a in item.get("addr_info", [])]
        require(len(ips) == 1 and ips[0].get("family") == "inet" and ips[0].get("local") == str(target.ip)
                and ips[0].get("prefixlen") == target.network.prefixlen, "address/prefix drift")


def main():
    try:
        if "--snapshot" in sys.argv:
            print(json.dumps(capture()))
            return 0
        data = json.load(sys.stdin)
        if "--reconfigure" in sys.argv:
            state = capture()
            validate(data["request"], state, data["baseline"], "preconfigure")
            # No command is reached for a name/MAC/device mismatch.
            command(["networkctl", "reload"])
            validate(data["request"], capture(), data["baseline"], "preconfigure")
            command(["networkctl", "reconfigure", data["request"]["interface"]])
        else:
            state = capture() if "--verify-live" in sys.argv else data["observed"]
            validate(data["request"], state, data["baseline"], data["phase"])
        print('{"verified":true}')
        return 0
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError):
        print("S1 router guest state failed; values suppressed; no automatic drift repair", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
