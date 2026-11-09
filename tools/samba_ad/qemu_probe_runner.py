"""Explicit, bounded QGA measurements and read-only aggregation; no lifecycle.

Original reports must be durable before stop/absent. Aggregate only after S1
cleanup and fresh guest/firewall/storage absence readbacks for every generation.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid

try:
    import s2_guest as guest
    import s2_compatibility as evidence
    import s2_probe_runner as lxc_probe
except ImportError:
    import guest
    import compatibility as evidence
    import probe_runner as lxc_probe

CHECKS = ["security_ntacl", "posix_acl", "systemd", "clock", "audit", "isolation", "network"]


def decode_qga(value):
    evidence.require(isinstance(value, dict) and type(value.get("exited")) is int and value["exited"] == 1)
    evidence.require(type(value.get("exitcode")) is int and value["exitcode"] in [0, 2])
    evidence.require(not value.get("out-truncated") and not value.get("err-truncated")
                     and not value.get("err-data") and not value.get("signal"))
    evidence.require(isinstance(value.get("out-data"), str) and len(value["out-data"]) <= 131072)
    decoded = json.loads(value["out-data"])
    evidence.require(isinstance(decoded, dict))
    return value["exitcode"], decoded


def clock_window(start, end, monotonic_elapsed, observed):
    evidence.require(type(observed) is int and type(start) is int and type(end) is int)
    evidence.require(type(monotonic_elapsed) is int)
    evidence.require(0 <= monotonic_elapsed <= 40_000_000_000)
    evidence.require(abs(end - start - monotonic_elapsed) <= 1_000_000_000)
    evidence.require(start - 2_000_000_000 <= observed <= end + 2_000_000_000)


def checked_capture(value, r, filesystem):
    evidence.fields(value, "guest qga host_boot_id clock")
    current = value["guest"]
    evidence.fields(current, "hostname euid filesystem parent_dev parent_ino boot_id product_uuid kernel")
    evidence.require(current["hostname"] == r["resource"]["name"] and type(current["euid"]) is int and current["euid"] == 0)
    evidence.require(current["filesystem"] == filesystem and isinstance(current["kernel"], str) and bool(current["kernel"]))
    evidence.require(all(type(current[k]) is int and current[k] >= 0 for k in ["parent_dev", "parent_ino"]))
    evidence.require(isinstance(current["product_uuid"], str) and str(uuid.UUID(current["product_uuid"])) == current["product_uuid"]
                     and uuid.UUID(current["product_uuid"]).int != 0)
    evidence.require(current["boot_id"] != value["host_boot_id"])
    for boot in [current["boot_id"], value["host_boot_id"]]:
        evidence.require(isinstance(boot, str) and 32 <= len(boot) <= 36 and uuid.UUID(boot).int != 0)
    expected = {"node": r["resource"]["node"], "vmid": r["resource"]["vmid"],
                "config_digest": r["expected_digest"], "template_digest": r["template"]["digest"],
                "spec_sha256": guest.spec_hash(r), "uuid": current["product_uuid"]}
    evidence.require(value["qga"] == expected)
    evidence.fields(value["clock"], "host_start_ns host_end_ns elapsed_ns guest_ns nonce")
    clock = value["clock"]
    evidence.hex_value(clock["nonce"], 32)
    clock_window(clock["host_start_ns"], clock["host_end_ns"], clock["elapsed_ns"], clock["guest_ns"])
    return copy.deepcopy(value)


class QgaTransport:
    def __init__(self, api):
        self.api = api

    def command(self, r, source, data):
        evidence.require(os.uname().nodename.split(".")[0] == r["resource"]["node"])
        encoded = json.dumps(data)
        evidence.require(len(encoded.encode()) < 1048576)
        result = subprocess.run(["qm", "guest", "exec", str(r["resource"]["vmid"]),
                                 "--pass-stdin", "1", "--synchronous", "1", "--timeout", "30", "--",
                                 "/usr/bin/python3", "-c", source], input=encoded,
                                capture_output=True, text=True, timeout=40, check=False)
        evidence.require(result.returncode == 0 and not result.stderr.strip() and len(result.stdout) <= 262144)
        return decode_qga(json.loads(result.stdout))

    def capture(self, r, source, filesystem):
        path = f'/nodes/{r["resource"]["node"]}/qemu/{r["resource"]["vmid"]}/config'
        config = self.api.get(path, current=1)
        evidence.require(config.get("digest") == r["expected_digest"])
        agent = str(config.get("agent", ""))
        evidence.require(agent == "1" or guest.pairs(agent).get("enabled") == "1")
        evidence.require(isinstance(config.get("smbios1"), str))
        product_uuid = str(uuid.UUID(guest.pairs(config.get("smbios1", "")).get("uuid", "")))
        evidence.require(uuid.UUID(product_uuid).int != 0)
        ping = subprocess.run(["qm", "guest", "cmd", str(r["resource"]["vmid"]), "ping"],
                              capture_output=True, text=True, timeout=10, check=False)
        evidence.require(ping.returncode == 0 and not ping.stderr.strip())
        nonce = secrets.token_hex(16)
        program = ("import json,sys,time; ns={'__name__':'snapshot'}; exec(" + repr(source)
                   + ",ns); request=json.load(sys.stdin); print(json.dumps({'nonce':request['nonce'],"
                     "'guest':ns['identity'](),'realtime_ns':time.time_ns()}))")
        start, mono = time.time_ns(), time.monotonic_ns()
        rc, observed = self.command(r, program, {"nonce": nonce})
        end, elapsed = time.time_ns(), time.monotonic_ns() - mono
        evidence.fields(observed, "nonce guest realtime_ns")
        evidence.require(rc == 0 and observed["nonce"] == nonce)
        evidence.require(observed["guest"].get("product_uuid") == product_uuid)
        evidence.require(self.api.get(path, current=1) == config)
        frame = {"guest": observed["guest"],
                 "qga": {"node": r["resource"]["node"], "vmid": r["resource"]["vmid"],
                         "config_digest": r["expected_digest"], "template_digest": r["template"]["digest"],
                         "spec_sha256": guest.spec_hash(r), "uuid": product_uuid},
                 "host_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                 "clock": {"host_start_ns": start, "host_end_ns": end, "elapsed_ns": elapsed,
                           "guest_ns": observed["realtime_ns"], "nonce": nonce}}
        return checked_capture(frame, r, filesystem)

    def execute(self, r, source, expectation):
        start, mono = time.time_ns(), time.monotonic_ns()
        rc, result = self.command(r, source, expectation)
        end, elapsed = time.time_ns(), time.monotonic_ns() - mono
        evidence.require(isinstance(result.get("measurements"), dict))
        clock = result["measurements"].get("clock")
        if clock is not None:
            evidence.require(isinstance(clock, dict))
            clock_window(start, end, elapsed, clock.get("realtime_ns"))
        return rc, result


def checked_result(report, nonce, rc, value):
    evidence.fields(value, "schema run_id nonce status checks cleanup measurements")
    evidence.require(rc in [0, 2] and type(rc) is int)
    evidence.require(value["schema"] == "samba-ad-s2-qemu-probe/v1"
                     and value["run_id"] == report["run_id"] and value["nonce"] == nonce)
    evidence.require(value["status"] == ("passed" if rc == 0 else "operational_error"))
    evidence.require(isinstance(value["checks"], list) and len(value["checks"]) <= len(CHECKS))
    names = []
    for check in value["checks"]:
        evidence.fields(check, "name status attempts")
        evidence.require(check["status"] in ["passed", "operational_error"] and check["attempts"] == [])
        names.append(check["name"])
    evidence.require(names == CHECKS[:len(names)])
    passed = {c["name"] for c in value["checks"] if c["status"] == "passed"}
    measurements = value["measurements"]
    evidence.require(isinstance(measurements, dict) and set(measurements) == passed - set(CHECKS[:2]))
    evidence.require(all(isinstance(item, dict) and bool(item) for item in measurements.values()))
    if rc == 0:
        evidence.require(passed == set(CHECKS) and value["cleanup"] == "complete")
    candidate = copy.deepcopy(report)
    candidate["checks"] = [dict(c, subject="probe") for c in value["checks"]]
    candidate["cleanup"]["probe"]["file"] = value["cleanup"]
    evidence.validate_report(candidate)
    return copy.deepcopy(value)


def run(payload, api, transport, probe_source):
    for key in ["enabled", "apply", "check"]:
        evidence.require(type(payload.get(key)) is bool)
    if not payload["enabled"]: return {"state": "disabled"}
    evidence.fields(payload, "enabled apply check limit inventory_host node_hostname hosts_count tags request provenance run_id")
    evidence.require(payload["limit"] == payload["inventory_host"] and bool(payload["limit"]))
    evidence.require(type(payload["hosts_count"]) is int and payload["hosts_count"] == 1)
    evidence.require(payload["tags"] == ["samba_ad_compatibility"])
    r = copy.deepcopy(payload["request"])
    evidence.require(r["resource"]["node"] == payload["node_hostname"] and r["resource"]["kind"] == "qemu")
    evidence.require(r["scope"] == "lab" and r["action"] == "present" and guest.digest(r["expected_digest"]))
    r.update(enabled=True, apply=False, boot=True)
    guest.validate(r)
    provenance = payload["provenance"]
    evidence.fields(provenance, "public_revision private_revision s1_audit_sha256 filesystem policy_sha256")
    for key in ["public_revision", "private_revision"]: evidence.hex_value(provenance[key], 40)
    evidence.hex_value(provenance["s1_audit_sha256"], 64)
    evidence.require(provenance["filesystem"] in ["ext4", "xfs", "zfs", "btrfs"])
    evidence.require(provenance["policy_sha256"] == evidence.sha(r["firewall"]))
    reference = dict(node=r["template"]["node"], kind="qemu", vmid=r["template"]["vmid"], digest=r["template"]["digest"])
    template = api.get(f'/nodes/{reference["node"]}/qemu/{reference["vmid"]}/config', current=1)
    evidence.require(template.get("template") == 1 and template.get("digest") == reference["digest"])
    evidence.require(guest.reconcile(r, api, check=True)["state"] == "verified")
    if payload["check"] or not payload["apply"]: return {"state": "preflight"}
    evidence.hex_value(payload["run_id"], 32)
    fingerprint = {"nodes": {}, "templates": [reference], "filesystem": provenance["filesystem"],
                   "isolation": "qemu-no-passthrough", "policy_sha256": provenance["policy_sha256"]}
    for node in {r["resource"]["node"], r["template"]["node"]}:
        state = api.get(f"/nodes/{node}/status")
        evidence.require(state["memory"]["total"] - state["memory"]["used"] >= 2 * guest.GIB)
        fingerprint["nodes"][node] = {"kernel": state["kversion"], "pve": state["pveversion"]}
    before = checked_capture(transport.capture(r, probe_source, provenance["filesystem"]), r, provenance["filesystem"])
    report = {"schema": "samba-ad-s2/v1", "run_id": payload["run_id"],
              "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "public_revision": provenance["public_revision"], "private_revision": provenance["private_revision"],
              "helper_sha256": hashlib.sha256(probe_source.encode()).hexdigest(), "s1_audit_sha256": provenance["s1_audit_sha256"],
              "subjects": [{"key": "probe", "node": r["resource"]["node"], "kind": "qemu", "spec_sha256": guest.spec_hash(r),
                            "config_digest": r["expected_digest"], "boot_id": before["guest"]["boot_id"],
                            "template_digest": reference["digest"], "template": reference}],
              "checks": [], "cleanup": {"probe": {"file": "not_created", "guest": "pending"}},
              "selection": None, "qualification": "pending", "platform_fingerprint": fingerprint,
              "observations": {"probe": {"before": before, "after": None, "result": None}}}
    evidence.validate_report(report)
    status = "operational_error"
    try:
        expectation = {"run_id": payload["run_id"], "nonce": secrets.token_hex(16), "guest": before["guest"],
                       "host_boot_id": before["host_boot_id"], "resource": r["resource"]}
        # Preserve the sent expectation independently of the returned nonce/result.
        report["observations"]["probe"]["before"]["probe_request"] = copy.deepcopy(expectation)
        rc, response = transport.execute(r, probe_source, expectation)
        result = checked_result(report, expectation["nonce"], rc, response)
        report["observations"]["probe"]["result"] = result
        report["checks"] = [dict(c, subject="probe") for c in result["checks"]]
        report["cleanup"]["probe"]["file"] = result["cleanup"]
        after = checked_capture(transport.capture(r, probe_source, provenance["filesystem"]), r, provenance["filesystem"])
        evidence.require(all(after[k] == before[k] for k in ["guest", "qga", "host_boot_id"]))
        report["observations"]["probe"]["after"] = after
        evidence.require(guest.reconcile(r, api, check=True)["state"] == "verified")
        status = result["status"]
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        if report["cleanup"]["probe"]["file"] != "complete": report["cleanup"]["probe"]["file"] = "incomplete"
    if status != "passed":
        # Retain measurements in observations; invalidate qualification after any drift/error.
        report["checks"] = [{"name": "isolation", "subject": "probe", "status": "operational_error", "attempts": []}]
    return {"state": "measured", "status": status, "report": evidence.validate_report(report)}


def checked_measurements(result, r, before, after):
    """Validate recorded QEMU summaries without rerunning native measurements."""
    for name, value in result["measurements"].items():
        if name == "systemd":
            evidence.fields(value, "pid1 state")
            evidence.require(value == {"pid1": "systemd", "state": "running"})
        elif name == "clock":
            evidence.fields(value, "ntp_synchronized realtime_ns monotonic_ns")
            evidence.require(value["ntp_synchronized"] is True)
            evidence.require(all(type(value[k]) is int and value[k] >= 0
                                 for k in ["realtime_ns", "monotonic_ns"]))
            evidence.require(before["clock"]["host_start_ns"] - 2_000_000_000 <= value["realtime_ns"]
                             <= after["clock"]["host_end_ns"] + 2_000_000_000)
        elif name == "audit":
            evidence.fields(value, "enabled failure listener_pid rate_limit backlog_limit lost backlog")
            evidence.require(all(type(v) is int and v >= 0 for v in value.values()))
            evidence.require(value["enabled"] in [1, 2] and value["failure"] in [1, 2]
                             and value["listener_pid"] > 0 and value["backlog_limit"] > 0 and value["lost"] == 0)
        elif name == "isolation":
            evidence.fields(value, "vm container kernel")
            evidence.require(value["vm"] in ["qemu", "kvm"] and value["container"] == "none"
                             and value["kernel"] == before["guest"]["kernel"])
        elif name == "network":
            evidence.fields(value, "interface address mac mtu gateway")
            evidence.require(isinstance(value["interface"], str) and bool(value["interface"])
                             and value["interface"] != "lo" and type(value["mtu"]) is int)
            evidence.require(isinstance(value["mac"], str) and value["mac"].lower() == r["resource"]["mac"].lower())
            evidence.require(all(value[k] == r["resource"][k] for k in ["address", "mtu", "gateway"]))


def checked_source_trace(source, r):
    """Bind a closed source protocol to its original report and S1 generation."""
    subject = source["subjects"][0]
    evidence.require(subject["key"] == "probe")
    trace = source["observations"]["probe"]
    before, after, value = trace["before"], trace["after"], trace["result"]
    evidence.require(isinstance(after, dict) and isinstance(value, dict))
    fingerprint = source["platform_fingerprint"]
    kind = subject["kind"]
    evidence.require(fingerprint["policy_sha256"] == evidence.sha(r["firewall"]))
    evidence.require(set(fingerprint["nodes"]) == {r["resource"]["node"], r["template"]["node"]})
    evidence.require(fingerprint["templates"] == [subject["template"]])
    evidence.require(fingerprint["isolation"] == ("qemu-no-passthrough" if kind == "qemu"
                                                else "lxc-unprivileged-apparmor"))
    if kind == "qemu":
        evidence.fields(before, "guest qga host_boot_id clock probe_request")
        capture = {k: v for k, v in before.items() if k != "probe_request"}
        checked_capture(capture, r, fingerprint["filesystem"])
        checked_capture(after, r, fingerprint["filesystem"])
        evidence.require(all(before[k] == after[k] for k in ["guest", "qga", "host_boot_id"]))
        expectation = before["probe_request"]
        evidence.fields(expectation, "run_id nonce guest host_boot_id resource")
        evidence.hex_value(expectation["nonce"], 32)
        evidence.require(expectation == {"run_id": source["run_id"], "nonce": expectation["nonce"],
                                         "guest": before["guest"], "host_boot_id": before["host_boot_id"],
                                         "resource": r["resource"]})
        evidence.require(value.get("status") in ["passed", "operational_error"])
        result = checked_result(source, expectation["nonce"], 0 if value["status"] == "passed" else 2, value)
        checked_measurements(result, r, before, after)
    else:
        evidence.fields(before, "guest host_namespaces host_anchor run_id")
        evidence.require(before["run_id"] == source["run_id"])
        capture = {k: v for k, v in before.items() if k != "run_id"}
        lxc_probe.checked_capture(capture)
        lxc_probe.checked_capture(after)
        evidence.require(capture == after and before["host_anchor"]["vmid"] == r["resource"]["vmid"])
        current = before["guest"]
        evidence.require(current["hostname"] == r["resource"]["name"] and current["euid"] == 0
                         and current["filesystem"] == fingerprint["filesystem"])
        evidence.require(all(current["namespaces"][n] != before["host_namespaces"][n]
                             for n in current["namespaces"]))
        mapping = current["uid_map"].split()
        evidence.require(len(mapping) == 3 and all(v.isdigit() for v in mapping))
        evidence.require(int(mapping[0]) == 0 and int(mapping[1]) > 0 and int(mapping[2]) >= 65535)
        evidence.require("unconfined" not in current["apparmor"] and current["apparmor"].endswith("(enforce)"))
        evidence.require(value.get("status") in ["passed", "incompatible", "operational_error"])
        result = lxc_probe.checked_result(source, {"passed": 0, "operational_error": 2, "incompatible": 3}[value["status"]], value)
    evidence.require(before["guest"]["boot_id"] == subject["boot_id"])
    evidence.require(result["cleanup"] == source["cleanup"]["probe"]["file"] == "complete")
    checks = [dict(check, subject="probe") for check in result["checks"]]
    if result["status"] == "operational_error":
        evidence.require(all(check["status"] != "incompatible" for check in checks))
        # The runners invalidate successful partial checks on operational failure.
        if kind == "qemu" or not any(check["status"] == "operational_error" for check in checks):
            checks = [{"name": "isolation" if kind == "qemu" else "security_ntacl", "subject": "probe",
                       "status": "operational_error", "attempts": []}]
    evidence.require(source["checks"] == checks)
    return checks


def aggregate(reports, requests, api, header):
    evidence.fields(header, "run_id public_revision private_revision")
    evidence.hex_value(header["run_id"], 32)
    for field in ["public_revision", "private_revision"]: evidence.hex_value(header[field], 40)
    evidence.require(isinstance(reports, list) and 2 <= len(reports) <= 16 and len(requests) == len(reports))
    combined = copy.deepcopy(reports[0])
    combined.update(**header, created_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    subjects=[], checks=[], cleanup={}, observations={}, selection=None, qualification="pending")
    fingerprint = combined["platform_fingerprint"]
    fingerprint.update(nodes={}, templates=[], isolation="qemu-no-passthrough")
    hashes = set()
    for index, (source, request) in enumerate(zip(reports, requests)):
        evidence.validate_report(source)
        evidence.require(len(source["subjects"]) == 1 and evidence.sha(source) not in hashes)
        hashes.add(evidence.sha(source))
        subject = source["subjects"][0]
        old_key, key = subject["key"], "source" + str(index)
        evidence.require(source["qualification"] == "pending" and source["selection"] == evidence.select_platform(source))
        evidence.require(source["cleanup"][old_key]["file"] == "complete")
        trace = source["observations"][old_key]
        r = copy.deepcopy(request)
        r.update(enabled=True, apply=False, action="absent")
        guest.validate(r)
        evidence.require(r["scope"] == "lab" and guest.spec_hash(r) == subject["spec_sha256"])
        evidence.require(r["expected_digest"] == subject["config_digest"] and r["resource"]["node"] == subject["node"]
                         and r["resource"]["kind"] == subject["kind"])
        evidence.require(subject["template"] == dict(node=r["template"]["node"], kind=r["resource"]["kind"],
                                                      vmid=r["template"]["vmid"], digest=r["template"]["digest"]))
        checks = checked_source_trace(source, r)
        # Readback only: reconcile(absent, check=True) can describe a planned deletion.
        # Use the absence verifier directly so a stopped but still present guest fails.
        api.cleanup_readback(r, [])
        other = source["platform_fingerprint"]
        for field in ["filesystem", "policy_sha256"]: evidence.require(other[field] == fingerprint[field])
        for node, version in other["nodes"].items():
            evidence.require(node not in fingerprint["nodes"] or fingerprint["nodes"][node] == version)
            live = api.get(f"/nodes/{node}/status")
            evidence.require(version == {"kernel": live["kversion"], "pve": live["pveversion"]})
            fingerprint["nodes"][node] = copy.deepcopy(version)
        for template in other["templates"]:
            live = api.get(f'/nodes/{template["node"]}/{template["kind"]}/{template["vmid"]}/config', current=1)
            evidence.require(live.get("template") == 1 and live.get("digest") == template["digest"])
            if template not in fingerprint["templates"]: fingerprint["templates"].append(copy.deepcopy(template))
        combined["subjects"].append(dict(subject, key=key))
        combined["checks"].extend(dict(c, subject=key) for c in checks)
        combined["cleanup"][key] = {"file": "complete", "guest": "complete"}
        combined["observations"][key] = {"before": {"source_report": copy.deepcopy(source),
                                                    "source_report_sha256": evidence.sha(source), "absence_readback": True},
                                          "after": copy.deepcopy(trace["after"]), "result": copy.deepcopy(trace["result"])}
    evidence.require(any(s["kind"] == "lxc" for s in combined["subjects"])
                     and any(s["kind"] == "qemu" for s in combined["subjects"]))
    combined["helper_sha256"] = evidence.sha([r["helper_sha256"] for r in reports])
    combined["s1_audit_sha256"] = evidence.sha([r["s1_audit_sha256"] for r in reports])
    combined["selection"] = evidence.select_platform(combined)
    combined["qualification"] = evidence.qualification(combined)
    return evidence.validate_report(combined)


def aggregate_operation(payload, api):
    evidence.fields(payload, "enabled apply check reports requests directory provenance")
    for key in ["enabled", "apply", "check"]: evidence.require(type(payload[key]) is bool)
    if not payload["enabled"]: return {"state": "disabled"}
    prepared = None
    if payload["apply"] and not payload["check"]:
        prepared = evidence.prepare_report(payload["directory"])
    evidence.fields(payload["provenance"], "public_revision private_revision")
    header = dict(payload["provenance"], run_id=prepared["run_id"] if prepared else secrets.token_hex(16))
    report = aggregate(payload["reports"], payload["requests"], api, header)
    if prepared is None: return {"state": "preflight"}
    persisted = evidence.write_report(payload["directory"], report, prepared)
    return {"state": "aggregated", "evidence": persisted, "selection": report["selection"],
            "qualification": report["qualification"]}


def main():
    try:
        payload = json.load(sys.stdin)
        api = guest.Pvesh()
        if payload.get("mode") == "aggregate":
            evidence.fields(payload, "mode operation")
            result = aggregate_operation(payload["operation"], api)
        else:
            evidence.fields(payload, "operation probe_source")
            result = run(payload["operation"], api, QgaTransport(api), payload["probe_source"])
        print(json.dumps(result))
        return 0 if result.get("status") in [None, "passed"] else 2
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        print("S2 QEMU preflight/transport failed; values suppressed; no host fallback", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
