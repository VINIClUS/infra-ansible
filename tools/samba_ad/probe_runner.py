"""First LXC proof only. Explicit dependencies are loaded from reviewed sources.

Never installs Samba, creates another guest or performs lifecycle cleanup.
Persist the returned report before explicitly invoking S1 stop/absent.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import s2_guest as guest
import s2_compatibility as evidence


def checked_snapshot(value):
    evidence.fields(value, "hostname euid namespaces uid_map apparmor filesystem parent_dev parent_ino boot_id cgroup")
    evidence.fields(value["namespaces"], "user mnt pid cgroup")
    for key in ["hostname", "uid_map", "apparmor", "filesystem", "boot_id", "cgroup"]:
        evidence.require(isinstance(value[key], str) and bool(value[key]))
    evidence.require(all(type(value[key]) is int and value[key] >= 0 for key in ["euid", "parent_dev", "parent_ino"]))
    for ns, identity in value["namespaces"].items():
        evidence.require(isinstance(identity, str) and re.fullmatch(ns + r":\[[0-9]+\]", identity))
    return copy.deepcopy(value)


def checked_capture(value):
    evidence.fields(value, "guest host_namespaces host_anchor")
    checked_snapshot(value["guest"])
    evidence.fields(value["host_namespaces"], "user mnt pid cgroup")
    for ns, identity in value["host_namespaces"].items():
        evidence.require(isinstance(identity, str) and re.fullmatch(ns + r":\[[0-9]+\]", identity))
    anchor = value["host_anchor"]
    evidence.fields(anchor, "vmid init_pid starttime nspid cgroup")
    evidence.require(type(anchor["vmid"]) is int and 100 <= anchor["vmid"] <= 999999999)
    evidence.require(type(anchor["init_pid"]) is int and anchor["init_pid"] > 1)
    evidence.require(isinstance(anchor["starttime"], str) and anchor["starttime"].isdigit())
    evidence.require(isinstance(anchor["nspid"], list) and len(anchor["nspid"]) >= 2
                     and all(type(pid) is int and pid > 0 for pid in anchor["nspid"])
                     and anchor["nspid"][0] == anchor["init_pid"] and anchor["nspid"][-1] == 1)
    evidence.require(isinstance(anchor["cgroup"], str) and bool(anchor["cgroup"]))
    return copy.deepcopy(value)


def checked_result(report, rc, value):
    """Do not attach wire data until the complete first-proof protocol is valid."""
    evidence.fields(value, "schema run_id status checks cleanup")
    evidence.require(type(rc) is int and rc in [0, 2, 3])
    status = {0: "passed", 2: "operational_error", 3: "incompatible"}[rc]
    evidence.require(value["schema"] == "samba-ad-s2-probe/v1" and value["run_id"] == report["run_id"])
    evidence.require(value["status"] == status and (rc == 2 or value["cleanup"] == "complete"))
    evidence.require(isinstance(value["checks"], list) and len(value["checks"]) <= 2)
    error_names = set(errno.errorcode.values()) | {"UNKNOWN", "ENOTSUP"}
    for check in value["checks"]:
        evidence.fields(check, "name status attempts")
        evidence.require(check["name"] in ["security_ntacl", "posix_acl"])
        evidence.require(check["status"] in ["passed", "incompatible", "operational_error"])
        evidence.require(isinstance(check["attempts"], list) and
                         all(isinstance(v, str) and v in error_names for v in check["attempts"]))
    names = [c["name"] for c in value["checks"]]
    evidence.require(names == ["security_ntacl", "posix_acl"][:len(names)])
    candidate = copy.deepcopy(report)
    candidate["checks"] = [dict(c, subject="probe") for c in value["checks"]]
    candidate["cleanup"]["probe"]["file"] = value["cleanup"]
    evidence.validate_report(candidate)  # Validates checks/cleanup without storing the response in observations.
    if rc == 0:
        evidence.require(len(names) == 2 and all(c["status"] == "passed" for c in value["checks"]))
    if rc == 3:
        evidence.require(bool(names) and value["checks"][-1]["status"] == "incompatible"
                         and all(c["status"] == "passed" for c in value["checks"][:-1]))
    return {"schema": "samba-ad-s2-probe/v1", "run_id": report["run_id"], "status": status,
            "checks": copy.deepcopy(value["checks"]), "cleanup": value["cleanup"]}


class PctTransport:
    def __init__(self, api):
        self.api = api

    def command(self, r, source, data=None):
        result = subprocess.run(["pct", "exec", str(r["resource"]["vmid"]), "--", "python3", "-c", source],
                                input=json.dumps(data) if data is not None else "", capture_output=True,
                                text=True, timeout=45, check=False)
        decoded = json.loads(result.stdout)
        evidence.require(isinstance(decoded, dict))
        return result.returncode, decoded

    def init_anchor(self, vmid, expected_pid=None):
        """Host-view membership belongs to the PID authoritatively resolved by pct."""
        raw = self.api.run(["pct", "pid", str(vmid)]).strip()
        evidence.require(re.fullmatch(r"[1-9][0-9]*", raw))
        evidence.require(expected_pid is None or raw == str(expected_pid))
        proc = Path("/proc") / raw
        namespaces = {n: os.readlink(proc / "ns" / n) for n in ["user", "mnt", "pid", "cgroup"]}
        records = [line.split()[1:] for line in (proc / "status").read_text().splitlines()
                   if line.startswith("NSpid:")]
        evidence.require(len(records) == 1 and len(records[0]) >= 2 and all(v.isdigit() for v in records[0]))
        nspid = [int(v) for v in records[0]]
        evidence.require(nspid[0] == int(raw) and nspid[-1] == 1)
        stat_line = (proc / "stat").read_text()
        evidence.require(stat_line.split(" ", 1)[0] == raw)
        tail = stat_line.rsplit(")", 1)
        evidence.require(len(tail) == 2 and len(tail[1].split()) >= 20)
        starttime = tail[1].split()[19]
        evidence.require(starttime.isdigit())
        cgroup = (proc / "cgroup").read_text().strip()
        evidence.require(bool(cgroup))
        for record in cgroup.splitlines():
            parts = record.split(":", 2)
            evidence.require(len(parts) == 3 and parts[0].isdigit() and parts[2].startswith("/"))
        return proc, namespaces, {"vmid": vmid, "init_pid": int(raw), "starttime": starttime,
                                  "nspid": nspid, "cgroup": cgroup}

    def capture(self, r, source, filesystem):
        vmid = r["resource"]["vmid"]
        proc, namespaces, anchor = self.init_anchor(vmid)
        host_namespaces = {n: os.readlink("/proc/self/ns/" + n) for n in namespaces}
        evidence.require(all(namespaces[n] != host_namespaces[n] for n in namespaces))
        program = "import json; ns={'__name__':'snapshot'}; exec(" + repr(source) + ",ns); print(json.dumps(ns['identity']()))"
        rc, observed = self.command(r, program)
        evidence.require(rc == 0)
        observed = checked_snapshot(observed)
        parent = (proc / "root/var/lib").stat()
        expected = dict(observed, hostname=r["resource"]["name"], euid=0, namespaces=namespaces,
                        uid_map=" ".join((proc / "uid_map").read_text().split()),
                        apparmor=(proc / "attr/current").read_text().strip(), filesystem=filesystem,
                        parent_dev=parent.st_dev, parent_ino=parent.st_ino,
                        boot_id=(proc / "root/proc/sys/kernel/random/boot_id").read_text().strip())
        # cgroup path stays guest-view. Reading a guest procfs from the PVE does
        # not enter its cgroup namespace; inode identities are view-independent.
        evidence.require(observed == expected and bool(observed["cgroup"]))
        _, after_namespaces, after_anchor = self.init_anchor(vmid, anchor["init_pid"])
        evidence.require(namespaces == after_namespaces and anchor == after_anchor)
        return {"guest": expected, "host_namespaces": host_namespaces, "host_anchor": anchor}

    def execute(self, r, source, expectation):
        return self.command(r, source, expectation)


def run(payload: dict, api, transport, probe_source: str) -> dict:
    for key in ["enabled", "apply", "check"]:
        evidence.require(type(payload.get(key)) is bool)
    if not payload["enabled"]:
        return {"state": "disabled"}
    evidence.fields(payload, "enabled apply check limit inventory_host node_hostname hosts_count tags request provenance run_id")
    evidence.require(payload["limit"] == payload["inventory_host"] and bool(payload["limit"]))
    evidence.require(type(payload["hosts_count"]) is int and payload["hosts_count"] == 1)
    evidence.require(payload["tags"] == ["samba_ad_compatibility"])
    r = copy.deepcopy(payload["request"])
    evidence.require(r["resource"]["node"] == payload["node_hostname"])
    evidence.require(r["scope"] == "lab" and r["resource"]["kind"] == "lxc" and r["action"] == "present")
    evidence.require(guest.digest(r["expected_digest"]))
    r.update(enabled=True, apply=False, boot=True)
    guest.validate(r)
    provenance = payload["provenance"]
    evidence.fields(provenance, "public_revision private_revision s1_audit_sha256 filesystem policy_sha256")
    for key in ["public_revision", "private_revision"]: evidence.hex_value(provenance[key], 40)
    evidence.hex_value(provenance["s1_audit_sha256"], 64)
    evidence.require(provenance["policy_sha256"] == evidence.sha(r["firewall"]))
    evidence.require(provenance["filesystem"] in ["ext4", "xfs", "zfs", "btrfs"])
    template = api.get(f'/nodes/{r["template"]["node"]}/lxc/{r["template"]["vmid"]}/config', current=1)
    evidence.require(template.get("template") == 1 and template.get("digest") == r["template"]["digest"])
    evidence.require(guest.reconcile(r, api, check=True)["state"] == "verified")
    if payload["check"] or not payload["apply"]:
        return {"state": "preflight"}
    evidence.hex_value(payload["run_id"], 32)
    fingerprint = {"nodes": {}, "templates": [dict(node=r["template"]["node"], kind="lxc",
                    vmid=r["template"]["vmid"], digest=r["template"]["digest"])],
                   "filesystem": provenance["filesystem"], "isolation": "lxc-unprivileged-apparmor",
                   "policy_sha256": provenance["policy_sha256"]}
    for node in {r["resource"]["node"], r["template"]["node"]}:
        state = api.get(f"/nodes/{node}/status")
        evidence.require(state["memory"]["total"] - state["memory"]["used"] >= 2 * guest.GIB)
        fingerprint["nodes"][node] = {"kernel": state["kversion"], "pve": state["pveversion"]}
    expectation = checked_capture(transport.capture(r, probe_source, provenance["filesystem"]))
    expectation["run_id"] = payload["run_id"]
    report = {"schema": "samba-ad-s2/v1", "run_id": expectation["run_id"],
              "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "public_revision": provenance["public_revision"], "private_revision": provenance["private_revision"],
              "helper_sha256": hashlib.sha256(probe_source.encode()).hexdigest(),
              "s1_audit_sha256": provenance["s1_audit_sha256"],
              "subjects": [{"key": "probe", "node": r["resource"]["node"], "kind": "lxc",
                            "spec_sha256": guest.spec_hash(r), "config_digest": r["expected_digest"],
                            "boot_id": expectation["guest"]["boot_id"], "template_digest": r["template"]["digest"],
                            "template": dict(node=r["template"]["node"], kind=r["resource"]["kind"],
                                             vmid=r["template"]["vmid"], digest=r["template"]["digest"])}],
              "checks": [], "cleanup": {"probe": {"file": "not_created", "guest": "pending"}},
              "selection": None, "qualification": "pending",
              "platform_fingerprint": fingerprint,
              "observations": {"probe": {"before": expectation, "after": None, "result": None}}}
    evidence.validate_report(report)  # Validate provenance before any mutating guest command.
    status = "operational_error"
    try:
        rc, response = transport.execute(r, probe_source, expectation)
        result = checked_result(report, rc, response)
        report["observations"]["probe"]["result"] = result
        report["cleanup"]["probe"]["file"] = result["cleanup"]
        report["checks"] = [dict(check, subject="probe") for check in result["checks"]]
        after = checked_capture(transport.capture(r, probe_source, provenance["filesystem"]))
        evidence.require(after["guest"] == expectation["guest"] and after["host_namespaces"] == expectation["host_namespaces"])
        evidence.require(after["host_anchor"] == expectation["host_anchor"])
        report["observations"]["probe"]["after"] = after
        evidence.require(guest.reconcile(r, api, check=True)["state"] == "verified")
        status = result["status"]
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        report["checks"] = [{"name": "security_ntacl", "subject": "probe", "status": "operational_error", "attempts": []}]
        if report["cleanup"]["probe"]["file"] != "complete": report["cleanup"]["probe"]["file"] = "incomplete"
    if status == "operational_error" and not any(c["status"] == "operational_error" for c in report["checks"]):
        report["checks"] = [{"name": "security_ntacl", "subject": "probe", "status": "operational_error", "attempts": []}]
    report["selection"] = evidence.select_platform(report)
    return {"state": "measured", "status": status, "report": report}


def main():
    try:
        payload = json.load(sys.stdin)
        api = guest.Pvesh()
        result = run(payload["operation"], api, PctTransport(api), payload["probe_source"])
        print(json.dumps(result))
        return {"passed": 0, "incompatible": 3, "operational_error": 2}.get(result.get("status"), 0)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        print("S2 preflight/transport failed; values suppressed; no host fallback", file=sys.stderr)
        return 2
