"""Evidence contracts use synthetic data; no valid operational pin is shipped."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from test_samba_ad_guest import module as guest_module, request


def module():
    path = Path(__file__).resolve().parents[1] / "tools/samba_ad/compatibility.py"
    assert path.is_file(), "strict S2 evidence consumer missing"
    spec = importlib.util.spec_from_file_location("s2_contract", path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def sha(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def report():
    return {"schema": "samba-ad-s2/v1", "run_id": "a" * 32, "created_utc": "2026-11-07T12:00:00Z",
            "public_revision": "a" * 40, "private_revision": "b" * 40,
            "helper_sha256": "c" * 64, "s1_audit_sha256": "d" * 64,
            "subjects": [{"key": "probe", "node": "node-b", "kind": "lxc", "spec_sha256": "e" * 64,
                          "config_digest": "f" * 40, "boot_id": "b" * 32, "template_digest": "a" * 40,
                          "template": {"node": "node-a", "kind": "lxc", "vmid": 7900, "digest": "a" * 40}}],
            "checks": [{"name": "security_ntacl", "subject": "probe", "status": "incompatible",
                        "attempts": ["EPERM", "EPERM"]}],
            "cleanup": {"probe": {"file": "complete", "guest": "complete"}},
            "selection": "qemu", "qualification": "pending",
            "observations": {"probe": {"before": {"synthetic": "test-only"},
                                       "after": {"synthetic": "test-only"}, "result": {"synthetic": "test-only"}}},
            "platform_fingerprint": {"nodes": {"node-a": {"kernel": "test-kernel", "pve": "test-pve"},
                                               "node-b": {"kernel": "test-kernel", "pve": "test-pve"}},
                                     "templates": [{"node": "node-a", "kind": "lxc", "vmid": 7900,
                                                    "digest": "a" * 40}],
                                     "filesystem": "ext4", "isolation": "qemu-no-passthrough",
                                     "policy_sha256": "e" * 64}}


def bundle():
    r = request(); r["scope"] = "production"; r["resource"]["kind"] = "qemu"
    r["resource"]["name"] = "dc01.ad.example.invalid"; r["template"]["disk"] = "scsi0"
    r["template"]["vmid"] = 7901
    evidence = report()
    vm_template = {"node": "node-a", "kind": "qemu", "vmid": 7901, "digest": "a" * 40}
    evidence["platform_fingerprint"]["templates"].append(vm_template)
    for i, node in enumerate(["node-a", "node-b"]):
        key = "vm" + str(i)
        evidence["subjects"].append(dict(evidence["subjects"][0], key=key, node=node, kind="qemu",
                                         template=copy.deepcopy(vm_template)))
        evidence["cleanup"][key] = {"file": "complete", "guest": "complete"}
        evidence["observations"][key] = copy.deepcopy(evidence["observations"]["probe"])
        for name in ["security_ntacl", "posix_acl", "systemd", "clock", "audit", "isolation", "network"]:
            evidence["checks"].append({"name": name, "subject": key, "status": "passed", "attempts": []})
    evidence["qualification"] = "qemu_substrate"
    target = sha({k: r[k] for k in ["owner", "scope", "resource", "template", "firewall"]})
    choice = {"schema": 1, "platform": "qemu", "qualification": "qemu_substrate", "target_role": "dc01",
              "target_sha256": target, "report_sha256": sha(evidence),
              "fingerprint_sha256": sha(evidence["platform_fingerprint"])}
    audit = {"schema": 1, "scope": "S2-state", "decision": "accept", "report_sha256": sha(evidence),
             "choice_sha256": sha(choice), "public_revision": "a" * 40, "private_revision": "b" * 40,
             "review_ref": "git:" + "c" * 40 + ":reviews/s2-state.json"}
    pin = {"schema": 1, "report_sha256": sha(evidence), "choice_sha256": sha(choice), "audit_sha256": sha(audit),
           "provenance": {"reviewed_config_revision": "d" * 40,
                          "path": "inventories/prod/contracts/samba-ad-s2-choice.yml", "review_ref": audit["review_ref"]}}
    data = {"schema": "samba-ad-s2-bundle/v1", "pin": pin, "choice": choice, "report": evidence, "audit": audit}
    r["compatibility"] = {"sha256": sha(data), "data": data}
    return r


def reseal(r):
    """Rehash synthetic artifacts so semantic tests pass the outer integrity gate."""
    data = r["compatibility"]["data"]
    data["choice"]["report_sha256"] = sha(data["report"])
    data["choice"]["fingerprint_sha256"] = sha(data["report"]["platform_fingerprint"])
    data["audit"]["report_sha256"] = sha(data["report"])
    data["audit"]["choice_sha256"] = sha(data["choice"])
    for key in ["report", "choice", "audit"]: data["pin"][key + "_sha256"] = sha(data[key])
    r["compatibility"]["sha256"] = sha(data)


def test_protected_failure_selects_vm_but_does_not_qualify_it():
    m = module(); evidence = report()
    assert m.select_platform(evidence) == "qemu"
    assert m.qualification(evidence) == "pending"


def test_first_positive_probe_never_selects_lxc():
    m = module(); evidence = report()
    evidence["checks"][0].update(status="passed", attempts=[])
    evidence["selection"] = None
    assert m.select_platform(evidence) is None


@pytest.mark.parametrize("change", ["operational", "transient", "cleanup", "guest_cleanup", "unknown", "second_host"])
def test_incomplete_or_operational_report_cannot_qualify(change):
    m = module(); r = bundle(); evidence = r["compatibility"]["data"]["report"]
    if change == "operational": evidence["checks"][0]["status"] = "operational_error"
    if change == "transient": evidence["checks"][0]["attempts"] = ["EPERM"]
    if change == "cleanup": evidence["cleanup"]["probe"]["file"] = "incomplete"
    if change == "guest_cleanup": evidence["cleanup"]["probe"]["guest"] = "pending"
    if change == "unknown": evidence["checks"][0]["name"] = "custom_approval"
    if change == "second_host": evidence["subjects"][-1]["node"] = "node-a"
    reseal(r)
    with pytest.raises(ValueError): m.validate_bundle(r["compatibility"], r)


def test_bundle_accepts_only_complete_bound_evidence(monkeypatch):
    m = module(); r = bundle()
    assert m.validate_bundle(r["compatibility"], r)["isolation"] == "qemu-no-passthrough"
    monkeypatch.setitem(sys.modules, "s2_compatibility", m)
    guest_module().validate(r)
    assert "production" in guest_module().desired_config(r)["tags"].split(";")


def test_live_platform_drift_stops_production_before_any_mutation(monkeypatch):
    from test_samba_ad_guest import Fake
    m = module(); r = bundle(); api = Fake()
    monkeypatch.setitem(sys.modules, "s2_compatibility", m)
    with pytest.raises(ValueError): guest_module().reconcile(r, api)
    assert all(method == "get" for method, _, _ in api.calls)


def test_consistent_bundle_cannot_label_lab_identity_as_production():
    m = module(); r = bundle(); r["resource"]["name"] = "dc01.lab.ad.test"
    r["compatibility"]["data"]["choice"]["target_sha256"] = sha(
        {k: r[k] for k in ["owner", "scope", "resource", "template", "firewall"]})
    reseal(r)
    with pytest.raises(ValueError): m.validate_bundle(r["compatibility"], r)


@pytest.mark.parametrize("change", ["missing", "hash", "audit", "target", "kind", "template", "boolean", "provenance"])
def test_production_rejects_unpinned_or_mismatched_s2(change):
    m = module(); r = bundle(); env = r["compatibility"]
    if change == "missing": r["compatibility"] = None
    if change == "hash": env["sha256"] = "0" * 64
    if change == "audit": env["data"]["audit"]["decision"] = "pending"
    if change == "target": r["resource"]["vmid"] += 1
    if change == "kind": r["resource"]["kind"] = "lxc"
    if change == "template": r["template"]["digest"] = "b" * 40
    if change == "boolean": env["data"]["allow_production"] = True
    if change == "provenance": env["data"]["pin"]["provenance"]["reviewed_config_revision"] = ""
    if change in ["audit", "boolean", "provenance"]: reseal(r)
    with pytest.raises((ValueError, TypeError)): m.validate_bundle(r["compatibility"], r)


def test_write_report_is_exclusive_private_and_cannot_replace_a_run(tmp_path):
    m = module(); tmp_path.chmod(0o700); evidence = report()
    result = m.write_report(str(tmp_path), evidence)
    path = tmp_path / (evidence["run_id"] + ".json")
    assert json.loads(path.read_text()) == evidence
    assert path.stat().st_mode & 0o777 == 0o600
    assert result == {"sha256": sha(evidence)}
    with pytest.raises(FileExistsError): m.write_report(str(tmp_path), evidence)
    assert json.loads(path.read_text()) == evidence


def test_write_report_rejects_shared_or_symlink_directory(tmp_path):
    m = module(); tmp_path.chmod(0o755)
    with pytest.raises(ValueError): m.write_report(str(tmp_path), report())
    assert not list(tmp_path.glob("*.json"))
    target = tmp_path / "private"; target.mkdir(mode=0o700)
    link = tmp_path / "alias"; link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError): m.write_report(str(link), report())


def test_lxc_selection_requires_all_checks_on_two_physical_nodes():
    m = module(); evidence = report(); original = evidence["subjects"][0]
    evidence["subjects"].append(dict(original, key="second", node="node-a"))
    evidence["cleanup"]["second"] = {"file": "complete", "guest": "complete"}
    evidence["observations"]["second"] = copy.deepcopy(evidence["observations"]["probe"])
    evidence["platform_fingerprint"]["isolation"] = "lxc-unprivileged-apparmor"
    evidence["platform_fingerprint"]["templates"][0]["kind"] = "lxc"
    evidence["checks"] = [{"name": name, "subject": key, "status": "passed", "attempts": []}
                          for key in ["probe", "second"]
                          for name in ["security_ntacl", "posix_acl", "systemd", "clock", "audit", "isolation",
                                       "network", "samba_systemd", "sysvol", "replication"]]
    assert m.select_platform(evidence) == "lxc" and m.qualification(evidence) == "lxc_lab_full"
    evidence["checks"].pop()
    assert m.select_platform(evidence) is None and m.qualification(evidence) == "pending"


def bind_subject_template(subject, template):
    subject["template_digest"] = template["digest"]
    subject["template"] = copy.deepcopy(template)


def test_subject_template_digest_outside_fingerprint_is_invalid_even_when_resealed():
    m = module(); r = bundle(); report_data = r["compatibility"]["data"]["report"]
    template = {k: r["template"][k] for k in ["node", "vmid", "digest"]} | {"kind": "qemu"}
    template["digest"] = "c" * 40
    bind_subject_template(report_data["subjects"][-1], template)
    reseal(r)
    with pytest.raises(ValueError): m.validate_report(report_data)
    with pytest.raises(ValueError): m.validate_bundle(r["compatibility"], r)


@pytest.mark.parametrize("difference", ["digest", "vmid", "node"])
def test_template_list_does_not_qualify_an_untested_placement_template_pair(difference):
    m = module(); r = bundle(); data = r["compatibility"]["data"]; evidence = data["report"]
    approved_target = data["choice"]["target_sha256"]
    template_b = {k: r["template"][k] for k in ["node", "vmid", "digest"]} | {"kind": "qemu"}
    template_b[difference] = {"digest": "b" * 40, "vmid": 7902, "node": "node-b"}[difference]
    evidence["platform_fingerprint"]["templates"].append(template_b)
    bind_subject_template(evidence["subjects"][-1], template_b)
    reseal(r)
    assert data["choice"]["target_sha256"] == approved_target
    with pytest.raises(ValueError): m.validate_bundle(r["compatibility"], r)


def test_mixed_templates_require_an_actual_subject_for_the_approved_target_pair():
    m = module(); r = bundle(); data = r["compatibility"]["data"]; evidence = data["report"]
    approved_target = data["choice"]["target_sha256"]
    template_a = {k: r["template"][k] for k in ["node", "vmid", "digest"]} | {"kind": "qemu"}
    template_b = dict(template_a, vmid=7902, digest="b" * 40)
    evidence["platform_fingerprint"]["templates"].append(template_b)
    bind_subject_template(evidence["subjects"][-1], template_b)
    tested_a = copy.deepcopy(evidence["subjects"][-1]); tested_a["key"] = "vm2"
    bind_subject_template(tested_a, template_a)
    evidence["subjects"].append(tested_a)
    evidence["cleanup"]["vm2"] = {"file": "complete", "guest": "complete"}
    evidence["observations"]["vm2"] = copy.deepcopy(evidence["observations"]["vm1"])
    evidence["checks"] += [dict(c, subject="vm2") for c in evidence["checks"] if c["subject"] == "vm1"]
    reseal(r)
    assert data["choice"]["target_sha256"] == approved_target
    assert m.validate_bundle(r["compatibility"], r)["isolation"] == "qemu-no-passthrough"
