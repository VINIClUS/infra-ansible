"""P40 merge-main item 11: the application-prepare chain over the real private payload flow (bootstrap, then operational)."""
import copy
from types import SimpleNamespace

import pytest

from test_cnesdata_delivery_prepare_chain import FakeS3, _publish
from tools.cnesdata_delivery import contract as c

STEPS = {"operational-audit": {"role": "audit", "purpose": "application-prepare", "mode": "operational", "job_name": "a"},
         "operational-plan": {"role": "plan", "purpose": "application-prepare", "mode": "operational", "job_name": "p"},
         "bootstrap-plan": {"role": "plan", "purpose": "application-prepare", "mode": "observer-bootstrap", "job_name": "bp"},
         "bootstrap-deploy": {"role": "deploy", "purpose": "application-prepare", "mode": "observer-bootstrap", "job_name": "d"}}


def _case(tmp_path, monkeypatch, *, role, mode, inputs, steps=None, anchor_state=False):
    from test_cnesdata_application_gate import _phase_a_carrier_case
    from test_cnesdata_delivery_lifecycle import held
    from tools.cnesdata_delivery import iam_boundary, lifecycle_contract as lc, lifecycle_runtime as lr, plan_inputs, session_owner
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
                             "purpose": "application-prepare", "phase_a_originals": carrier,
                             "previous_checkpoint_sha256": c.sha(anchor)})
    governance = {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "evidence", "account_id": "111122223333",
                  "context_kind": owner["context_kind"], "source_closure": {}, "cost": {}, "lifecycle_predecessor": {},
                  "predecessor_read": {"protocol": "legacy-infra"}, "lifecycle_steps": copy.deepcopy(STEPS) | (steps or {}),
                  "baseline": {"toolchain": {"opentofu": {"binary_sha256": ""}, "lock_sha256": ""},
                               "cost_context": {}, "cost_evidence": {}, "cost_manifest": {}, "source_manifest_sha256": "9" * 64,
                               "backend": {"configuration": {"type": "s3", "workspace": "default"}}}}
    s3 = FakeS3(moved, moved_object)
    if anchor_state:
        anchored = c.loads(anchor, canonical=True)
        s3 = FakeS3(b"anchor-state", anchored["state_object"])
        identity = c.state_identity
        monkeypatch.setattr(c, "state_identity", lambda raw: anchored["state_after"] if raw == b"anchor-state" else identity(raw))
    files = {"bootstrap-deploy": {"checkpoint.json": bootstrap, "approval.json": b"{}"},
             "operational-plan": {"checkpoint.json": bootstrap, "inputs.json": b"{}", "plan.bin": b"p", "plan.json": b"{}"},
             "bootstrap-plan": {"checkpoint.json": anchor, "inputs.json": b"{}", "plan.bin": b"p", "plan.json": b"{}"},
             "operational-audit": {"approval.json": b"{}"}}
    public = {name: _publish(s3, governance, owner, producer, files[producer]) for name, producer in inputs.items()}
    step = {"role": role, "purpose": "application-prepare", "mode": mode, "direction": "advance",
            "input_jobs": {name: {"name": STEPS[producer]["job_name"], "step": producer} for name, producer in inputs.items()}}
    window = {"admitted_at": 1000, "deadline": 1900, "sequence": 0, "checkpoint_sha256": c.sha(anchor)}
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

    def attach(role, payload, origins, **context):
        if role == "plan":
            payload["inputs.json"], origins["inputs.json"] = b"{}", "plan-inputs-" + context["request"].get("step", "")
    monkeypatch.setattr(plan_inputs, "attach", attach)

    class Guard:
        pass
    Guard.window = store.value["lifecycle"]
    Guard.check = lambda self, *args: None
    monkeypatch.setattr(lr, "LifecycleWatchdog", lambda *args: Guard())
    return lr


OPERATIONAL = [("plan", {"checkpoint": "bootstrap-deploy"}, "operational plan requires activation transport"),
               ("audit", {"plan": "operational-plan"}, "closed object fields"),
               ("deploy", {"plan": "operational-plan", "approval": "operational-audit"}, "closed object fields")]


@pytest.mark.parametrize("role, inputs, later", OPERATIONAL, ids=[r for r, _, _ in OPERATIONAL])
def test_cadeia_operacional_passa_da_checagem_do_predecessor_sobre_o_checkpoint_do_bootstrap(tmp_path, monkeypatch, role, inputs, later):
    lr = _case(tmp_path, monkeypatch, role=role, mode="operational", inputs=inputs)
    with pytest.raises(ValueError, match=later):
        lr.execute(role)


@pytest.mark.parametrize("change", [{"mode": "observer-bootstrap"}, {"purpose": "phase-b"}], ids=["outro-modo", "outro-proposito"])
@pytest.mark.parametrize("role, inputs", [(r, i) for r, i, _ in OPERATIONAL[1:]], ids=["audit", "deploy"])
def test_origem_do_checkpoint_em_plano_de_outro_modo_ou_proposito_e_recusada(tmp_path, monkeypatch, role, inputs, change):
    lr = _case(tmp_path, monkeypatch, role=role, mode="operational", inputs=inputs,
               steps={"operational-plan": STEPS["operational-plan"] | change})
    with pytest.raises(ValueError, match="real predecessor checkpoint"):
        lr.execute(role)


def test_audit_do_bootstrap_le_o_checkpoint_ancora_republicado_pelo_plano_historico(tmp_path, monkeypatch):
    lr = _case(tmp_path, monkeypatch, role="audit", mode="observer-bootstrap", inputs={"plan": "bootstrap-plan"},
               steps={"bootstrap-plan": STEPS["bootstrap-plan"] | {"historical_entry": True}}, anchor_state=True)
    with pytest.raises(ValueError) as caught:
        lr.execute("audit")
    assert "real predecessor checkpoint" not in str(caught.value)
