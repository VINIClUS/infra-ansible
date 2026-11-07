"""First LXC proof only. Explicit dependencies are loaded from reviewed sources.

Never installs Samba, creates another guest or performs lifecycle cleanup.
Persist the returned report before explicitly invoking S1 stop/absent.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

import s2_guest as guest
import s2_compatibility as evidence


class PctTransport:
    def __init__(self, api):
        self.api = api

    def command(self, r, source, data=None):
        result = subprocess.run(["pct", "exec", str(r["resource"]["vmid"]), "--", "python3", "-c", source],
                                input=json.dumps(data) if data is not None else "", capture_output=True,
                                text=True, timeout=45, check=False)
        return result.returncode, json.loads(result.stdout)

    def capture(self, r, source, filesystem):
        vmid = r["resource"]["vmid"]
        raw = self.api.run(["pct", "pid", str(vmid)]).strip()
        evidence.require(re.fullmatch(r"[1-9][0-9]*", raw))
        proc = Path("/proc") / raw
        program = "import json; ns={'__name__':'snapshot'}; exec(" + repr(source) + ",ns); print(json.dumps(ns['identity']()))"
        rc, observed = self.command(r, program)
        evidence.require(rc == 0)
        parent = (proc / "root/var/lib").stat()
        observed.update(hostname=r["resource"]["name"], euid=0,
                        namespaces={n: os.readlink(proc / "ns" / n) for n in ["user", "mnt", "pid"]},
                        uid_map=" ".join((proc / "uid_map").read_text().split()),
                        apparmor=(proc / "attr/current").read_text().strip(), filesystem=filesystem,
                        parent_dev=parent.st_dev, parent_ino=parent.st_ino,
                        boot_id=(proc / "root/proc/sys/kernel/random/boot_id").read_text().strip(),
                        cgroup=(proc / "root/proc/1/cgroup").read_text().strip())
        return {"guest": observed,
                "host_namespaces": {n: os.readlink("/proc/self/ns/" + n) for n in ["user", "mnt", "pid"]}}

    def execute(self, r, source, expectation):
        return self.command(r, source, expectation)


def run(payload: dict, api, transport, probe_source: str) -> dict:
    for key in ["enabled", "apply", "check"]:
        evidence.require(type(payload.get(key)) is bool)
    if not payload["enabled"]:
        return {"state": "disabled"}
    evidence.fields(payload, "enabled apply check limit inventory_host node_hostname hosts_count tags request provenance")
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
    fingerprint = {"nodes": {}, "templates": [dict(node=r["template"]["node"], kind="lxc",
                    vmid=r["template"]["vmid"], digest=r["template"]["digest"])],
                   "filesystem": provenance["filesystem"], "isolation": "lxc-unprivileged-apparmor",
                   "policy_sha256": provenance["policy_sha256"]}
    for node in {r["resource"]["node"], r["template"]["node"]}:
        state = api.get(f"/nodes/{node}/status")
        evidence.require(state["memory"]["total"] - state["memory"]["used"] >= 2 * guest.GIB)
        fingerprint["nodes"][node] = {"kernel": state["kversion"], "pve": state["pveversion"]}
    expectation = transport.capture(r, probe_source, provenance["filesystem"])
    expectation["run_id"] = uuid.uuid4().hex
    report = {"schema": "samba-ad-s2/v1", "run_id": expectation["run_id"],
              "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "public_revision": provenance["public_revision"], "private_revision": provenance["private_revision"],
              "helper_sha256": hashlib.sha256(probe_source.encode()).hexdigest(),
              "s1_audit_sha256": provenance["s1_audit_sha256"],
              "subjects": [{"key": "probe", "node": r["resource"]["node"], "kind": "lxc",
                            "spec_sha256": guest.spec_hash(r), "config_digest": r["expected_digest"],
                            "boot_id": expectation["guest"]["boot_id"], "template_digest": r["template"]["digest"]}],
              "checks": [], "cleanup": {"probe": {"file": "not_created", "guest": "pending"}},
              "selection": None, "qualification": "pending",
              "platform_fingerprint": fingerprint,
              "observations": {"probe": {"before": expectation, "after": None, "result": None}}}
    evidence.validate_report(report)  # Validate provenance before any mutating guest command.
    status = "operational_error"
    try:
        rc, result = transport.execute(r, probe_source, expectation)
        report["observations"]["probe"]["result"] = result
        evidence.fields(result, "schema run_id status checks cleanup")
        evidence.require(result["schema"] == "samba-ad-s2-probe/v1" and result["run_id"] == expectation["run_id"])
        evidence.require(rc in [0, 2, 3] and result["status"] == {0: "passed", 2: "operational_error", 3: "incompatible"}[rc])
        evidence.require(rc == 2 or result["cleanup"] == "complete")
        report["cleanup"]["probe"]["file"] = result["cleanup"]
        report["checks"] = [dict(check, subject="probe") for check in result["checks"]]
        evidence.validate_report(report)
        if rc == 0:
            evidence.require([c["name"] for c in report["checks"]] == ["security_ntacl", "posix_acl"])
            evidence.require(all(c["status"] == "passed" for c in report["checks"]))
        if rc == 3:
            evidence.require(any(c["status"] == "incompatible" for c in report["checks"]))
        after = transport.capture(r, probe_source, provenance["filesystem"])
        report["observations"]["probe"]["after"] = after
        evidence.require(after["guest"] == expectation["guest"] and after["host_namespaces"] == expectation["host_namespaces"])
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
