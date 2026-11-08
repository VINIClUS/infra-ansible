"""CA evidence is synthetic and purpose-bound; never qualifies DCs."""
import importlib.util
from pathlib import Path

import pytest
import yaml

from test_samba_ad_guest import module as guest_module, request
from test_samba_ad_compatibility import module as evidence_module

ROOT = Path(__file__).resolve().parents[1]


def module():
    path = ROOT / "tools/samba_ad/ca_substrate.py"
    assert path.is_file(), "CA-specific evidence consumer missing"
    spec = importlib.util.spec_from_file_location("ca_substrate", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ca_request():
    m = yaml.safe_load((ROOT / "contracts/samba_ad/example.yml").read_text())
    ca = m["resources"]["ca"]
    r = request()
    r.update(scope="production")
    r["resource"] = {key: ca[key] for key in ["vmid", "node", "kind", "mac", "bridge", "storage",
                                              "cores", "memory_mib", "disk_gib"]}
    r["resource"].update(name=ca["fqdn"], address=ca["address"] + "/25",
                         gateway=m["network"]["gateway"], mtu=m["network"]["mtu"])
    r["template"] = {key: ca["template"][key] for key in ["node", "vmid", "storage"]}
    r["template"].update(digest="a" * 40, disk="scsi0")
    e = evidence_module()
    template = {key: r["template"][key] for key in ["node", "vmid", "digest"]} | {"kind": "qemu"}
    report = {"schema": "samba-ad-s2/v1", "run_id": "a" * 32, "created_utc": "2026-11-07T12:00:00Z",
              "public_revision": "a" * 40, "private_revision": "b" * 40, "helper_sha256": "c" * 64,
              "s1_audit_sha256": "d" * 64,
              "subjects": [{"key": "ca_probe", "node": ca["node"], "kind": "qemu",
                            "spec_sha256": "e" * 64, "config_digest": "f" * 40, "boot_id": "b" * 32,
                            "template_digest": "a" * 40, "template": template}],
              "checks": [{"name": name, "subject": "ca_probe", "status": "passed", "attempts": []}
                         for name in ["posix_acl", "systemd", "clock", "audit", "isolation", "network"]],
              "cleanup": {"ca_probe": {"file": "complete", "guest": "complete"}},
              "observations": {"ca_probe": {"before": {"synthetic": True}, "after": {"synthetic": True},
                                              "result": {"synthetic": True}}},
              "selection": None, "qualification": "pending",
              "platform_fingerprint": {"nodes": {node: {"kernel": "test-kernel", "pve": "test-pve"}
                                                   for node in {ca["node"], template["node"]}},
                                       "templates": [template], "filesystem": "ext4",
                                       "isolation": "qemu-no-passthrough", "policy_sha256": e.sha(r["firewall"])}}
    review = "git:" + "c" * 40 + ":reviews/ca-substrate.json"
    data = {"schema": "samba-ad-ca-substrate-bundle/v1", "purpose": "ca", "manifest": m, "report": report,
            "target_sha256": guest_module().spec_hash(r),
            "prerequisites": {key: {"sha256": "d" * 64, "review_ref": review}
                              for key in ["s1_state", "s2_state"]},
            "provenance": {"reviewed_config_revision": "d" * 40,
                           "path": "inventories/prod/contracts/samba-ad-ca-substrate.yml", "review_ref": review},
            "audit": {"schema": 1, "scope": "S3-ca-substrate", "decision": "accept", "review_ref": review,
                      "public_revision": "a" * 40, "private_revision": "b" * 40}}
    r["compatibility"] = {"sha256": "", "data": data}
    reseal(r)
    return r


def reseal(r):
    e = evidence_module()
    data = r["compatibility"]["data"]
    for key in ["manifest", "report", "prerequisites"]:
        data["audit"][key + "_sha256"] = e.sha(data[key])
    data["audit"]["target_sha256"] = data["target_sha256"]
    r["compatibility"]["sha256"] = e.sha(data)


def test_ca_single_qualified_placement_does_not_claim_dc_qualification():
    r = ca_request()
    assert module().validate_ca_bundle(r["compatibility"], r) == r["compatibility"]["data"]["report"]["platform_fingerprint"]
    assert evidence_module().qualification(r["compatibility"]["data"]["report"]) == "pending"


@pytest.mark.parametrize("change", ["kind", "sizing", "role", "template", "node", "policy", "cleanup",
                                     "missing_gate", "review", "manifest", "pending_check"])
def test_ca_rejects_semantic_drift_even_after_consistent_rehash(change):
    r = ca_request()
    d = r["compatibility"]["data"]
    if change == "kind": r["resource"]["kind"] = "lxc"
    if change == "sizing": r["resource"]["memory_mib"] = 4096
    if change == "role": r["resource"]["name"] = "dc01.ad.example.invalid"
    if change == "template": r["template"]["digest"] = "b" * 40
    if change == "node": r["resource"]["node"] = "node-b"
    if change == "policy": d["report"]["platform_fingerprint"]["policy_sha256"] = "f" * 64
    if change == "cleanup": d["report"]["cleanup"]["ca_probe"]["guest"] = "pending"
    if change == "missing_gate": del d["prerequisites"]["s2_state"]
    if change == "review": d["audit"]["review_ref"] = "git:" + "a" * 40 + ":other.json"
    if change == "manifest": d["manifest"]["resources"]["ca"]["vmid"] += 1
    if change == "pending_check": d["report"]["checks"][0]["status"] = "not_run"
    # Updating the target hash also cannot turn an unqualified target into an approved one.
    d["target_sha256"] = guest_module().spec_hash(r)
    reseal(r)
    with pytest.raises(ValueError, match="suppressed"):
        module().validate_ca_bundle(r["compatibility"], r)


def test_guest_dispatch_accepts_ca_only_through_typed_bundle(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "s3_ca_substrate", module())
    r = ca_request()
    guest_module().validate(r)
    dcs = evidence_module()
    with pytest.raises(ValueError): dcs.validate_bundle(r["compatibility"], r)
    r["compatibility"]["data"]["schema"] = "unknown"
    with pytest.raises(ValueError): guest_module().validate(r)
