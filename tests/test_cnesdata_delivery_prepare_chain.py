"""Operational deploy after the observer-bootstrap deploy, through the real private payload flow."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.cnesdata_delivery import contract as c


class FakeS3:
    def __init__(self, state_raw, state_object):
        self.objects, self.state = {}, (state_raw, state_object)

    def put(self, key, raw):
        self.objects[key] = raw

    def get(self, bucket, key, maximum=None):
        return self.objects[key], {}

    def get_state(self):
        return self.state


def _publish(s3, governance, owner, step, files):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"]}
    prefix = lr.namespace(governance, {"source_sha": owner["source_sha"], "step": step}, run)
    for name, raw in files.items():
        s3.put(prefix + name, raw)
    index = {"version": 1, "source_sha": owner["source_sha"], "run_id": run["id"], "run_attempt": run["run_attempt"],
             "step": step, "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
             "files": [{"name": n, "sha256": c.sha(r), "size": len(r)} for n, r in sorted(files.items())],
             "application_purpose": "promotion", "context_kind": governance["context_kind"],
             "caller_binding_sha256": "e" * 64}
    return {"index.json": c.canonical(index)}


def _case(tmp_path, monkeypatch, *, historical, window_on_bootstrap):
    from fixtures.cnesdata_delivery_lifecycle import mode_source_case
    from test_cnesdata_application_gate import _phase_a_carrier_case
    from test_cnesdata_delivery_lifecycle import held
    from tools.cnesdata_delivery import iam_boundary, lifecycle_contract as lc, lifecycle_runtime as lr, session_owner
    carrier, _ = _phase_a_carrier_case()
    original = lc.phase_a_originals(carrier)
    store, _, _ = held()
    store.value.update(application_purpose="promotion", context_kind=lc.APPLICATION_CONTEXTS["promotion"],
                       caller_binding_sha256="e" * 64)
    owner = lc.owner_binding(store.value)
    moved = c.canonical({"lineage": "fixture", "serial": 2, "resources": [{"address": "observer"}]})
    moved_object = {"version_id": "after-bootstrap"}
    anchor = original["raw"]["checkpoint.json"]
    bootstrap = c.canonical({"owner": owner, "state": c.state_identity(moved), "state_object": moved_object,
                             "phase_a_originals": carrier, "previous_checkpoint_sha256": c.sha(anchor)})
    governance = {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "evidence", "account_id": "111122223333",
                  "context_kind": owner["context_kind"], "source_closure": {}, "cost": {}, "lifecycle_predecessor": {},
                  "predecessor_read": {"protocol": "legacy-infra"},
                  "lifecycle_steps": {"operational-audit": {"role": "audit", "job_name": "audit"}},
                  "baseline": {"toolchain": {"opentofu": {"binary_sha256": ""}, "lock_sha256": ""},
                               "cost_context": {}, "cost_evidence": {}, "cost_manifest": {}, "source_manifest_sha256": "9" * 64,
                               "backend": {"configuration": {"type": "s3", "workspace": "default"}}}}
    s3 = FakeS3(moved, moved_object)
    sent = {"bootstrap": bootstrap, "approval": b"{}"}
    public = {"checkpoint": _publish(s3, governance, owner, "bootstrap-deploy", {"checkpoint.json": anchor if historical else bootstrap,
                                                                               "inputs.json": b"{}", "plan.bin": b"p", "plan.json": b"{}"}),
              "approval": _publish(s3, governance, owner, "operational-audit", {"approval.json": sent["approval"]})}
    step = {"role": "deploy", "purpose": "application-prepare", "mode": "operational", "direction": "advance",
            "input_jobs": {"checkpoint": {"name": "d", "step": "bootstrap-deploy"}, "approval": {"name": "a", "step": "operational-audit"}}}
    if historical:
        step["historical_entry"] = True
    window = {"admitted_at": 1000, "deadline": 1900, "sequence": 0 if historical else 1,
              "checkpoint_sha256": c.sha(bootstrap if window_on_bootstrap else anchor)}
    store.value["lifecycle"] = {**window, "stage": "application-prepare",
                                "predecessor_sha256": c.sha(c.canonical(carrier["origin"]))}
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "product/infra/opentofu/env/prod"
    (root / ".terraform").mkdir(parents=True)
    (root / ".terraform.lock.hcl").write_bytes(b"lock")
    (root / ".terraform/terraform.tfstate").write_bytes(c.canonical({"backend": {"type": "s3", "config": {}}}))
    tofu = tmp_path / "tofu"
    tofu.write_bytes(b"tofu")
    governance["baseline"]["toolchain"] = {"opentofu": {"binary_sha256": c.sha(b"tofu")}, "lock_sha256": c.sha(b"lock")}
    request = {"source_sha": owner["source_sha"], "application_purpose": "promotion", "caller_binding_sha256": "e" * 64}
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"]}
    monkeypatch.setattr(lr, "admission", lambda role: (governance, request, step, None, run, public))
    monkeypatch.setattr(lr, "AWS", lambda _: s3)
    monkeypatch.setattr(lr, "S3LeaseStore", lambda _: store)
    monkeypatch.setattr(session_owner, "authenticate_lifecycle", lambda *args: SimpleNamespace(
        application_fragment={"application_role_arn": original["envelope"]["plan"]["phase_a_inputs"]["canary_trusted_principal_arn"]}))
    monkeypatch.setattr(session_owner, "verify_managed", lambda *args: None)
    monkeypatch.setenv("AWS_CREDENTIAL_EXPIRATION", "2030-01-01T00:00:00Z")
    monkeypatch.setattr(lr, "authenticate_predecessor", lambda *args: copy.deepcopy(carrier["origin"]))
    monkeypatch.setattr(lr, "keeper_transport", lambda **kwargs: {"phase_a_originals": copy.deepcopy(carrier)})
    monkeypatch.setattr(lr, "historical_checkpoint", lambda aws, gov, ref, record, raw=None: raw)
    monkeypatch.setattr(lr.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=owner["source_sha"]))
    monkeypatch.setattr(lr, "authenticate_infrastructure_closure", lambda *args: None)
    monkeypatch.setattr(iam_boundary, "authenticate_sources", lambda *args: {})
    monkeypatch.setattr(lr.shutil, "which", lambda _: str(tofu))

    class Guard:
        pass
    Guard.window = store.value["lifecycle"]
    Guard.check = lambda self, *args: None
    monkeypatch.setattr(lr, "LifecycleWatchdog", lambda *args: Guard())
    return lr


@pytest.mark.parametrize("historical", [True, False])
def test_deploy_operacional_apos_bootstrap_admite_checkpoint_predecessor_encadeado(tmp_path, monkeypatch, historical):
    lr = _case(tmp_path, monkeypatch, historical=historical, window_on_bootstrap=False)
    try:
        lr.execute("deploy")
    except ValueError as error:
        assert "real predecessor checkpoint" not in str(error)


def test_deploy_operacional_passa_do_checkpoint_predecessor_quando_a_janela_avanca(tmp_path, monkeypatch):
    lr = _case(tmp_path, monkeypatch, historical=False, window_on_bootstrap=True)
    with pytest.raises(ValueError, match="closed object fields"):
        lr.execute("deploy")
