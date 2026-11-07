"""Add or revert one QEMU router NIC; preserve every preexisting NIC.
JSON stdin, explicit config digest; --plan reads only, --revert removes only our exact NIC.
"""
import ipaddress
import json
import re
import subprocess
import sys


def require(ok, field):
    if not ok:
        raise ValueError("S1 router precondition: " + field)


def nic_text(r):
    return f'virtio={r["mac"]},bridge={r["bridge"]},firewall=0,mtu={r["mtu"]}'


def network_text(r):
    return (f'# samba-ad-s1: own additional interface only\n[Match]\nMACAddress={r["mac"]}\n'
            f'Name={r["interface"]}\n[Link]\nMTUBytes={r["mtu"]}\n[Network]\n'
            f'Address={r["address"]}\nDHCP=no\nIPv6AcceptRA=no\nLinkLocalAddressing=no\n')


def pairs(s):
    return dict(x.split("=", 1) for x in s.split(",") if "=" in x)


def plan(r, config, pending, reverting=False):
    require(set(r) == {"node", "vmid", "name", "smbios1", "expected_digest", "nic", "mac", "bridge", "mtu",
                       "interface", "address", "existing_nics"}, "request fields")
    require(type(r["vmid"]) is int and 100 <= r["vmid"] <= 999999999, "VMID")
    require(isinstance(r["node"], str) and re.fullmatch(r"[a-z0-9-]+", r["node"]), "node")
    require(re.fullmatch(r"net[1-9]", r["nic"]) and r["interface"] == "eth" + r["nic"][3:], "additional NIC")
    require(re.fullmatch(r"02(?::[0-9A-F]{2}){5}", r["mac"])
            and re.fullmatch(r"[a-z][a-z0-9]{1,7}", r["bridge"]), "network identity")
    require(type(r["mtu"]) is int and 1280 <= r["mtu"] <= 1450, "MTU")
    addr = ipaddress.IPv4Interface(r["address"])
    require(addr.network.prefixlen >= 24 and addr.ip not in [addr.network.network_address, addr.network.broadcast_address], "address")
    require(config.get("name") == r["name"] and config.get("smbios1") == r["smbios1"]
            and config.get("ostype") == "l26" and not config.get("template") and not config.get("lock"), "router identity")
    require(isinstance(r["expected_digest"], str) and re.fullmatch(r"[a-f0-9]{40}", r["expected_digest"]), "expected digest")
    require(reverting or config.get("digest") == r["expected_digest"], "stale digest")
    require(not any("pending" in x or x.get("delete") for x in pending), "pending changes")
    existing = {k: v for k, v in config.items() if re.fullmatch(r"net[0-9]+", k) and k != r["nic"]}
    require(existing == r["existing_nics"] and "net0" in existing and r["nic"] not in r["existing_nics"], "existing interfaces")
    for value in existing.values():
        require(r["mac"].lower() not in value.lower() and pairs(value).get("bridge") != r["bridge"], "duplicate network")
    current = config.get(r["nic"])
    require(current is None or pairs(current) == pairs(nic_text(r)), "occupied NIC slot")
    return {"action": "verify" if current else "add",
            "params": {"digest": config["digest"], r["nic"]: nic_text(r)}, "network": network_text(r)}


def api(method, path, **params):
    argv = ["pvesh", method, path, "--output-format", "json"]
    for k, value in params.items():
        argv += ["--" + k, str(value)]
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)
    require(result.returncode == 0, "PVE command failed; output suppressed")
    return json.loads(result.stdout) if result.stdout.strip() else None


def main():
    try:
        r = json.load(sys.stdin)
        # Validate node/VMID before using them in an API path.
        require(type(r.get("vmid")) is int and isinstance(r.get("node"), str)
                and re.fullmatch(r"[a-z0-9-]+", r["node"]), "identity")
        path = f'/nodes/{r["node"]}/qemu/{r["vmid"]}'
        config = api("get", path + "/config")
        result = plan(r, config, api("get", path + "/pending"), reverting="--revert" in sys.argv)
        require(api("get", path + "/status/current").get("status") == "running", "running router")
        if "--revert" in sys.argv:
            if result["action"] == "verify":
                api("set", path + "/config", digest=config["digest"], delete=r["nic"])
                require(r["nic"] not in api("get", path + "/config"), "remove readback")
            print(json.dumps({"changed": result["action"] == "verify"}))
            return 0
        changed = result["action"] == "add"
        if "--plan" not in sys.argv and changed:
            api("set", path + "/config", **result["params"])
            after = api("get", path + "/config")
            r["expected_digest"] = after["digest"]
            require(plan(r, after, api("get", path + "/pending"))["action"] == "verify", "NIC readback")
        print(json.dumps({"changed": changed, "action": result["action"], "network": result["network"]}))
        return 0
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError):
        print("S1 router failed; values suppressed; dead-man/recovery remain required", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
