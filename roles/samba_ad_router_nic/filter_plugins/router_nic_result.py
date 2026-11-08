"""Publish only closed, validated NIC diagnostics from no_log command results."""
from collections.abc import Mapping
import json


def command_result(result):
    """A guest recovery command's rc is not proof of restored network state."""
    rc = result.get("rc") if isinstance(result, Mapping) else None
    if not isinstance(rc, int) or isinstance(rc, bool) or not -255 <= rc <= 255:
        rc = None
    attempted = None
    if isinstance(result, Mapping):
        if not result or result.get("skipped") is True:
            attempted = False
        elif rc is not None:
            attempted = True
    return {"attempted": attempted, "helper_rc": rc, "state": "unknown"}


def nic_result(result, operation):
    command = command_result(result)
    safe = dict(command, operation=operation if operation in ("apply", "revert") else "unknown",
                success=False, phase="unknown", category="invalid_result", command_rc=None,
                mutation_attempted=None, readback="unknown")
    if safe["operation"] == "unknown" or command["attempted"] is not True:
        return safe
    stdout = result.get("stdout")
    if not isinstance(stdout, str) or len(stdout) > 4096:
        return safe
    try:
        payload = json.loads(stdout)
    except (ValueError, RecursionError):
        return safe
    if type(payload) is not dict or set(payload) != {"changed", "diagnostic"}:
        return safe
    d = payload["diagnostic"]
    fields = {"schema", "operation", "success", "phase", "category", "command_rc",
              "mutation_attempted", "readback", "state"}
    if type(d) is not dict or set(d) != fields:
        return safe
    enums = {
        "operation": {operation},
        "phase": {"request", "config", "pending", "preconditions", "status", "qga", "write",
                  "readback_config", "readback_pending", "readback_tap", "complete"},
        "category": {"ok", "unknown", "command_failed", "invalid_json", "invalid_response",
                     "precondition", "timeout", "os_error"},
        "readback": {"not_started", "incomplete", "verified"},
        "state": {"unknown", "present", "absent"},
    }
    if any(type(d[k]) is not str or d[k] not in allowed for k, allowed in enums.items()):
        return safe
    if (type(d["schema"]) is not int or d["schema"] != 1
            or type(d["success"]) is not bool or type(d["mutation_attempted"]) is not bool):
        return safe
    rc = d["command_rc"]
    if rc is not None and (type(rc) is not int or not -255 <= rc <= 255):
        return safe
    if d["success"]:
        if (command["helper_rc"] != 0 or d["phase"] != "complete" or d["category"] != "ok"
                or d["readback"] != "verified" or d["state"] != ("absent" if operation == "revert" else "present")
                or rc is not None or type(payload["changed"]) is not bool
                or payload["changed"] != d["mutation_attempted"]):
            return safe
    elif (command["helper_rc"] == 0 or d["phase"] == "complete" or d["category"] == "ok"
          or d["state"] != "unknown" or d["readback"] == "verified"
          or (d["mutation_attempted"] and payload["changed"] is not None)
          or (not d["mutation_attempted"] and payload["changed"] is not False)):
        return safe
    # Reconstruct from validated primitive values only; never echo arbitrary command fields.
    return dict(command, **{k: d[k] for k in fields if k != "schema"})


class FilterModule:
    def filters(self):
        return {"samba_ad_router_nic_result": nic_result,
                "samba_ad_router_command_result": command_result}
