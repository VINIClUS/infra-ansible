"""Strict, offline S2 contracts. Trust root: reviewed immutable private config.

Hashes bind artifacts; they do not authenticate an operator's assertion of review.
No public operational pin, approval flag, infrastructure access or lab runner.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MINIMUM = {"security_ntacl", "posix_acl", "systemd", "clock", "audit", "isolation", "network"}
LXC_FULL = MINIMUM | {"samba_systemd", "sysvol", "replication"}


def require(value):
    if not value:
        raise ValueError("S2 evidence precondition failed (values suppressed)")


def fields(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys.split()))


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def hex_value(value, size):
    require(isinstance(value, str) and re.fullmatch("[a-f0-9]{" + str(size) + "}", value)
            and value != "0" * size)


def validate_report(report: dict) -> dict:
    fields(report, "schema run_id created_utc public_revision private_revision helper_sha256 s1_audit_sha256 "
                   "subjects checks cleanup selection qualification platform_fingerprint observations")
    require(report["schema"] == "samba-ad-s2/v1")
    hex_value(report["run_id"], 32)
    datetime.strptime(report["created_utc"], "%Y-%m-%dT%H:%M:%SZ")
    for key in ["public_revision", "private_revision"]: hex_value(report[key], 40)
    for key in ["helper_sha256", "s1_audit_sha256"]: hex_value(report[key], 64)
    require(isinstance(report["subjects"], list) and bool(report["subjects"]))
    subjects = {}
    for subject in report["subjects"]:
        fields(subject, "key node kind spec_sha256 config_digest boot_id template_digest")
        require(isinstance(subject["key"], str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", subject["key"]))
        require(subject["key"] not in subjects and subject["kind"] in ["lxc", "qemu"])
        require(isinstance(subject["node"], str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,63}", subject["node"]))
        hex_value(subject["spec_sha256"], 64)
        for key in ["config_digest", "template_digest"]: hex_value(subject[key], 40)
        require(isinstance(subject["boot_id"], str) and re.fullmatch(r"[a-f0-9-]{32,36}", subject["boot_id"]))
        subjects[subject["key"]] = subject
    require(isinstance(report["cleanup"], dict) and set(report["cleanup"]) == set(subjects))
    for cleanup in report["cleanup"].values():
        fields(cleanup, "file guest")
        require(cleanup["file"] in ["complete", "incomplete", "not_created"])
        require(cleanup["guest"] in ["complete", "pending"])
    require(isinstance(report["observations"], dict) and set(report["observations"]) == set(subjects))
    for trace in report["observations"].values():
        fields(trace, "before after result")
        require(isinstance(trace["before"], dict) and bool(trace["before"]))
        require(all(trace[k] is None or isinstance(trace[k], dict) for k in ["after", "result"]))
    require(isinstance(report["checks"], list))
    seen = set()
    for check in report["checks"]:
        fields(check, "name subject status attempts")
        require(check["name"] in LXC_FULL and check["subject"] in subjects)
        pair = (check["subject"], check["name"])
        require(pair not in seen); seen.add(pair)
        require(check["status"] in ["passed", "incompatible", "operational_error", "not_run"])
        require(isinstance(check["attempts"], list) and len(check["attempts"]) <= 2)
        require(all(isinstance(v, str) and re.fullmatch(r"[A-Z_]{1,32}", v) for v in check["attempts"]))
        if check["status"] == "passed": require(not check["attempts"])
        if check["status"] == "incompatible":
            require(len(check["attempts"]) == 2 and check["attempts"][0] == check["attempts"][1]
                    and check["attempts"][0] in ["EPERM", "EACCES", "EOPNOTSUPP", "ENOTSUP"])
    fingerprint = report["platform_fingerprint"]
    fields(fingerprint, "nodes templates filesystem isolation policy_sha256")
    require(isinstance(fingerprint["nodes"], dict) and bool(fingerprint["nodes"]))
    for node, version in fingerprint["nodes"].items():
        require(isinstance(node, str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,63}", node))
        fields(version, "kernel pve")
        require(all(isinstance(v, str) and 0 < len(v) <= 256 for v in version.values()))
    require(all(s["node"] in fingerprint["nodes"] for s in subjects.values()))
    require(isinstance(fingerprint["templates"], list) and bool(fingerprint["templates"]))
    for template in fingerprint["templates"]:
        fields(template, "node kind vmid digest")
        require(template["node"] in fingerprint["nodes"] and template["kind"] in ["lxc", "qemu"])
        require(type(template["vmid"]) is int and 100 <= template["vmid"] <= 999999999)
        hex_value(template["digest"], 40)
    require(fingerprint["filesystem"] in ["ext4", "xfs", "zfs", "btrfs"])
    require(fingerprint["isolation"] in ["lxc-unprivileged-apparmor", "qemu-no-passthrough"])
    hex_value(fingerprint["policy_sha256"], 64)
    require(report["selection"] in [None, "lxc", "qemu"])
    require(report["qualification"] in ["pending", "lxc_lab_full", "qemu_substrate"])
    return report


def qualified_nodes(report, kind, required):
    nodes = set()
    for subject in report["subjects"]:
        if subject["kind"] != kind:
            continue
        passed = {c["name"] for c in report["checks"] if c["subject"] == subject["key"] and c["status"] == "passed"}
        cleanup = report["cleanup"][subject["key"]]
        if required <= passed and cleanup == {"file": "complete", "guest": "complete"}:
            nodes.add(subject["node"])
    return nodes


def select_platform(report: dict) -> str | None:
    validate_report(report)
    if any(v["file"] != "complete" for v in report["cleanup"].values()) or any(
            c["status"] in ["operational_error", "not_run"] for c in report["checks"]):
        return None
    kinds = {s["key"]: s["kind"] for s in report["subjects"]}
    incompatible = [c for c in report["checks"] if c["status"] == "incompatible"]
    if any(kinds[c["subject"]] == "qemu" for c in incompatible):
        return None
    if incompatible:
        return "qemu"
    if len(qualified_nodes(report, "lxc", LXC_FULL)) >= 2:
        return "lxc"
    return None


def qualification(report: dict) -> str:
    selected = select_platform(report)
    if any(v["guest"] != "complete" for v in report["cleanup"].values()): return "pending"
    if selected == "lxc": return "lxc_lab_full"
    if selected == "qemu" and len(qualified_nodes(report, "qemu", MINIMUM)) >= 2: return "qemu_substrate"
    return "pending"


def validate_bundle(envelope: dict, target: dict) -> dict:
    fields(envelope, "sha256 data")
    hex_value(envelope["sha256"], 64)
    data = envelope["data"]
    require(sha(data) == envelope["sha256"])
    fields(data, "schema pin choice report audit")
    require(data["schema"] == "samba-ad-s2-bundle/v1")
    pin, choice, report, audit = [data[k] for k in ["pin", "choice", "report", "audit"]]
    fields(pin, "schema report_sha256 choice_sha256 audit_sha256 provenance")
    require(type(pin["schema"]) is int and pin["schema"] == 1)
    for key, item in [("report_sha256", report), ("choice_sha256", choice), ("audit_sha256", audit)]:
        hex_value(pin[key], 64); require(pin[key] == sha(item))
    provenance = pin["provenance"]
    fields(provenance, "reviewed_config_revision path review_ref")
    hex_value(provenance["reviewed_config_revision"], 40)
    require(provenance["path"] == "inventories/prod/contracts/samba-ad-s2-choice.yml")
    require(isinstance(provenance["review_ref"], str) and
            re.fullmatch(r"git:[a-f0-9]{40}:[a-zA-Z0-9_./-]+", provenance["review_ref"]))
    require(".." not in provenance["review_ref"])
    validate_report(report)
    selected = select_platform(report); qualified = qualification(report)
    require(selected is not None and qualified != "pending")
    require(report["selection"] == selected and report["qualification"] == qualified)
    require(all(trace["after"] and trace["result"] for trace in report["observations"].values()))
    fields(choice, "schema platform qualification target_role target_sha256 report_sha256 fingerprint_sha256")
    require(type(choice["schema"]) is int and choice["schema"] == 1)
    require(choice["platform"] == selected and choice["qualification"] == qualified)
    require(choice["report_sha256"] == pin["report_sha256"])
    fingerprint = report["platform_fingerprint"]
    require(choice["fingerprint_sha256"] == sha(fingerprint))
    require(choice["target_sha256"] == sha({k: target[k] for k in ["owner", "scope", "resource", "template", "firewall"]}))
    require(target["scope"] == "production" and target["resource"]["kind"] == selected)
    require(not target["resource"]["name"].endswith(".lab.ad.test"))
    require(choice["target_role"] in ["dc01", "dc02"] and
            target["resource"]["name"].split(".")[0] == choice["target_role"])
    require((target["resource"]["cores"], target["resource"]["memory_mib"], target["resource"]["disk_gib"]) == (2, 4096, 64))
    require(target["resource"]["node"] in qualified_nodes(report, selected, LXC_FULL if selected == "lxc" else MINIMUM))
    template = dict(target["template"])
    template = {k: template[k] for k in ["node", "vmid", "digest"]} | {"kind": selected}
    require(template in fingerprint["templates"])
    require(fingerprint["isolation"] == ("lxc-unprivileged-apparmor" if selected == "lxc" else "qemu-no-passthrough"))
    fields(audit, "schema scope decision report_sha256 choice_sha256 public_revision private_revision review_ref")
    require(type(audit["schema"]) is int and audit["schema"] == 1 and audit["scope"] == "S2-state")
    require(audit["decision"] == "accept" and audit["review_ref"] == provenance["review_ref"])
    for key in ["report_sha256", "choice_sha256"]: require(audit[key] == pin[key])
    for key in ["public_revision", "private_revision"]: require(audit[key] == report[key])
    return fingerprint


def write_report(directory: str, report: dict) -> dict:
    """Exclusive durable write to a pre-existing, private operator directory."""
    validate_report(report)
    path = Path(directory)
    require(path.is_absolute() and path.resolve() == path)
    parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid())
        fd = os.open(report["run_id"] + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "w") as output:
            json.dump(report, output, sort_keys=True, separators=(",", ":"))
            output.flush(); os.fsync(output.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)
    return {"sha256": sha(report)}
