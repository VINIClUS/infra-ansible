"""Add or revert one QEMU router NIC; preserve every preexisting NIC.
JSON stdin, explicit config digest; --plan reads only, --revert removes only our exact NIC.
"""
import ipaddress
import json
import re
import subprocess
import sys
import socket


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
    changes = [x for x in pending if "pending" in x or x.get("delete")]
    require(not changes or (reverting and all(x.get("key") == r["nic"]
            and isinstance(x.get("pending"), str) and pairs(x["pending"]) == pairs(nic_text(r))
            and not x.get("delete") for x in changes)), "pending changes")
    existing = {k: v for k, v in config.items() if re.fullmatch(r"net[0-9]+", k) and k != r["nic"]}
    require(existing == r["existing_nics"] and "net0" in existing and r["nic"] not in r["existing_nics"], "existing interfaces")
    for value in existing.values():
        require(r["mac"].lower() not in value.lower() and pairs(value).get("bridge") != r["bridge"], "duplicate network")
    current = config.get(r["nic"])
    if reverting and current is None and changes:
        current = changes[0]["pending"]
    require(current is None or pairs(current) == pairs(nic_text(r)), "occupied NIC slot")
    return {"action": "verify" if current else "add",
            "params": {"digest": config["digest"], r["nic"]: nic_text(r)}, "network": network_text(r)}


class CommandFailure(ValueError):
    """Only fixed categories and numeric status may escape command boundaries."""

    def __init__(self, category, returncode):
        super().__init__(category)
        self.category = category
        self.returncode = returncode


def checked_run(argv, timeout):
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    if result.returncode != 0:
        raise CommandFailure("command_failed", result.returncode)
    return result


def response_json(stdout, expected, item_key=None):
    try:
        result = json.loads(stdout)
    except ValueError:
        raise CommandFailure("invalid_json", 0) from None
    if type(result) is not expected or (expected is list and any(type(x) is not dict for x in result)):
        raise CommandFailure("invalid_response", 0)
    if item_key and any(type(x.get(item_key)) is not str or not x[item_key] for x in result):
        raise CommandFailure("invalid_response", 0)
    return result


def api(method, path, **params):
    require(method in ("get", "set"), "API method")
    argv = ["pvesh", method, path, "--output-format", "json"]
    for k, value in params.items():
        argv += ["--" + k, str(value)]
    result = checked_run(argv, timeout=60)
    # Synchronous PUT config returns null but its worker prints informational text.
    # Its success is established by the subsequent readbacks, never by that text.
    if method == "set":
        return None
    pending = path.endswith("/pending")
    return response_json(result.stdout, list if pending else dict, "key" if pending else None)


def host_nic_present(r):
    require(socket.gethostname().split(".")[0] == r["node"], "local PVE node identity")
    result = checked_run(["ip", "-j", "link", "show"], timeout=15)
    return any(link.get("ifname") == "tap" + str(r["vmid"]) + "i" + r["nic"][3:]
               for link in response_json(result.stdout, list, "ifname"))


def qga_preflight(r):
    """Prove the existing local PVE -> QGA root channel without guest IP access."""
    require(socket.gethostname().split(".")[0] == r["node"], "local PVE node identity")
    checked_run(["qm", "guest", "cmd", str(r["vmid"]), "ping"], timeout=15)
    execution = checked_run(["qm", "guest", "exec", str(r["vmid"]), "--timeout", "10", "--", "/usr/bin/id", "-u"],
                            timeout=20)
    result = response_json(execution.stdout, dict)
    require(isinstance(result, dict) and result.get("exited") == 1
            and type(result.get("exitcode")) is int and result["exitcode"] == 0
            and isinstance(result.get("out-data"), str) and result["out-data"].strip() == "0"
            and not result.get("out-truncated") and not result.get("err-data"), "QGA root proof incomplete")


def main():
    reverting = "--revert" in sys.argv
    readonly = "--plan" in sys.argv
    diagnostic = {
        "schema": 1, "operation": "revert" if reverting else "plan" if readonly else "apply",
        "success": False, "phase": "request", "category": "unknown", "command_rc": None,
        "mutation_attempted": False, "readback": "not_started", "state": "unknown",
    }
    try:
        r = json.load(sys.stdin)
        qga = "--qga-preflight" in sys.argv
        require(not qga or ("--plan" in sys.argv and "--revert" not in sys.argv), "QGA preflight is readonly")
        # Validate node/VMID before using them in an API path.
        require(isinstance(r, dict) and type(r.get("vmid")) is int and isinstance(r.get("node"), str)
                and re.fullmatch(r"[a-z0-9-]+", r["node"]), "identity")
        path = f'/nodes/{r["node"]}/qemu/{r["vmid"]}'
        diagnostic["phase"] = "config"
        config = api("get", path + "/config", current=1)
        diagnostic["phase"] = "pending"
        pending = api("get", path + "/pending")
        diagnostic["phase"] = "preconditions"
        result = plan(r, config, pending, reverting=reverting)
        diagnostic["phase"] = "status"
        require(api("get", path + "/status/current").get("status") == "running", "running router")
        if qga:
            diagnostic["phase"] = "qga"
            qga_preflight(r)
        if reverting:
            if result["action"] == "verify":
                diagnostic.update(phase="write", mutation_attempted=True)
                api("set", path + "/config", digest=config["digest"], delete=r["nic"])
            diagnostic.update(phase="readback_pending", readback="incomplete")
            pending = api("get", path + "/pending")
            require(not any("pending" in x or x.get("delete") for x in pending), "remove still pending; reviewed recovery required")
            diagnostic["phase"] = "readback_config"
            after = api("get", path + "/config", current=1)
            require(r["nic"] not in after, "active remove readback")
            require(plan(r, after, pending, reverting=True)["action"] == "add", "recovery config readback")
            diagnostic["phase"] = "readback_tap"
            require(not host_nic_present(r), "effective host NIC remains; reviewed recovery required")
            diagnostic.update(success=True, phase="complete", category="ok", readback="verified", state="absent")
            print(json.dumps({"changed": result["action"] == "verify", "diagnostic": diagnostic}))
            return 0
        changed = result["action"] == "add"
        if not readonly:
            if changed:
                diagnostic.update(phase="write", mutation_attempted=True)
                api("set", path + "/config", **result["params"])
            diagnostic.update(phase="readback_config", readback="incomplete")
            after = api("get", path + "/config", current=1)
            r["expected_digest"] = after["digest"]
            diagnostic["phase"] = "readback_pending"
            require(plan(r, after, api("get", path + "/pending"))["action"] == "verify", "NIC readback")
            diagnostic["phase"] = "readback_tap"
            require(host_nic_present(r), "effective host NIC absent; reviewed recovery required")
            diagnostic.update(success=True, phase="complete", category="ok", readback="verified", state="present")
            print(json.dumps({"changed": changed, "diagnostic": diagnostic}))
        else:
            print(json.dumps({"changed": changed, "action": result["action"], "network": result["network"], "qga_management_verified": qga}))
        return 0
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as error:
        if isinstance(error, CommandFailure):
            diagnostic.update(category=error.category, command_rc=error.returncode)
        elif isinstance(error, subprocess.TimeoutExpired):
            diagnostic["category"] = "timeout"
        elif isinstance(error, OSError):
            diagnostic["category"] = "os_error"
        elif isinstance(error, json.JSONDecodeError):
            diagnostic["category"] = "invalid_json"
        else:
            diagnostic["category"] = "precondition"
        print(json.dumps({"changed": None if diagnostic["mutation_attempted"] else False, "diagnostic": diagnostic}))
        print("S1 router failed; values suppressed; dead-man/recovery remain required", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
