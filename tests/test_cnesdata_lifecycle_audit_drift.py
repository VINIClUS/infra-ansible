"""X6: o audit do lifecycle deriva a matriz de drift do próprio propósito do plano salvo e do estado anterior."""
import hashlib
import json
from pathlib import Path

import pytest

from test_cnesdata_delivery_lifecycle import ReadbackAWS, ReadbackGuard, change
from tools.cnesdata_delivery import contract as c, drift_catalog, drift_handoff, lifecycle_runtime as lr
from tools.cnesdata_delivery.producers import governance_assembly

S6 = Path(__file__).parent / "fixtures" / "cnesdata_lifecycle_steps_s6.json"
S6_SHA256 = "5c991344a10da55f68fa70e8c52eeff30e47fee6e59ef8f76dc6be3435091bc4"
SOURCE = "a" * 40
ROLE = "module.runtime_iam.aws_iam_role.fence[0]"
POLICY = "module.runtime_iam.aws_iam_role_policy.fence[0]"
MACHINE = "module.processing.aws_sfn_state_machine.processor[0]"
ROLE_ATTRIBUTES = {"name": "cnesdata-prod-fence", "arn": "arn:aws:iam::111122223333:role/cnesdata-prod-fence"}
POLICY_BEFORE = {"name": "fence", "role": "cnesdata-prod-fence", "policy": '{"Statement":[],"Version":"2012-10-17"}'}
POLICY_AFTER = POLICY_BEFORE | {"policy": '{"Statement":[{"Action":"s3:GetObject","Effect":"Allow","Resource":"*"}],'
                                          '"Version":"2012-10-17"}'}
OWNER = {"owner_sha256": "b" * 64, "generation": 3, "source_sha": SOURCE}


def iam_plan():
    return {"resource_changes": [change(ROLE, ROLE_ATTRIBUTES, ROLE_ATTRIBUTES, ["no-op"]),
                                 change(POLICY, POLICY_BEFORE, POLICY_AFTER, ["update"])]}


def instance(kind, attributes):
    return {"mode": "managed", "module": "module.runtime_iam", "type": kind, "name": "fence",
            "instances": [{"index_key": 0, "attributes": attributes}]}


def iam_state(policy=POLICY_BEFORE):
    return {"version": 4, "serial": 1, "resources": [instance("aws_iam_role", ROLE_ATTRIBUTES),
                                                     instance("aws_iam_role_policy", policy)]}


def audit_steps():
    raw = S6.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == S6_SHA256
    return {name: step for name, step in json.loads(raw).items() if step["role"] == "audit"}


def test_cada_audit_do_catalogo_s6_recebe_a_matriz_do_proprio_proposito():
    steps = audit_steps()
    assert len(steps) == 5
    assert {step["purpose"] for step in steps.values()} == {"application-prepare", "phase-b", "phase-c-recovery",
                                                            "phase-c-audit"}
    rows = {(ROLE, "name"), (ROLE, "arn"), (POLICY, "name"), (POLICY, "role"), (POLICY, "policy")}
    for step in steps.values():
        matrix, readbacks = drift_handoff.lifecycle(iam_plan(), iam_state(), SOURCE, step["purpose"])
        assert (matrix["matrix_version"], matrix["source_sha"], matrix["purpose"]) == (2, SOURCE, step["purpose"])
        assert matrix["absent"] == []
        assert {(row["address"], row["attribute"]) for row in matrix["before"]} == rows
        assert all(spec["absent"] is False for stage in ("before", "after") for spec in readbacks[stage])


def observed(call, policy):
    if call["operation"] == "get_role":
        return {"Role": {"RoleName": ROLE_ATTRIBUTES["name"], "Arn": ROLE_ATTRIBUTES["arn"]}}
    return {"PolicyName": policy["name"], "RoleName": policy["role"], "PolicyDocument": policy["policy"]}


@pytest.mark.parametrize("stage", ["before", "after"])
def test_cobertura_do_deploy_passa_com_a_matriz_derivada(stage):
    plan = iam_plan()
    matrix, readbacks = drift_handoff.lifecycle(plan, iam_state(), SOURCE, "phase-b")
    state = c.loads(c.canonical(iam_state(POLICY_AFTER)), state=True) if stage == "after" else None
    calls = lr.readback_calls(plan, readbacks[stage], stage, state)
    policy = POLICY_AFTER if stage == "after" else POLICY_BEFORE
    reports = lr.readbacks(ReadbackAWS([observed(call, policy) for call in calls]), calls, ReadbackGuard())
    c.drift_coverage(plan, reports, matrix, SOURCE, "phase-b", stage, state=state, specs=calls,
                     envelope=drift_catalog.LIFECYCLE_ENVELOPE)


def phase_b_case():
    before = {"definition": '{"TaskDefinition":"unit:1"}', "role_arn": "role",
              "arn": "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod-processor"}
    after = before | {"definition": '{"TaskDefinition":"unit:2"}'}
    plan = {"resource_changes": [change(MACHINE, before, after, ["update"])]}
    state = {"version": 4, "serial": 1, "resources": [
        {"mode": "managed", "module": "module.processing", "type": "aws_sfn_state_machine", "name": "processor",
         "instances": [{"index_key": 0, "attributes": before}]}]}
    payload = {"plan.bin": b"binary-plan", "plan.json": c.canonical(plan), "inputs.json": b'{"x":1}\n',
               "checkpoint.json": b'{"c":1}\n'}
    return {"governance": {"source_sha": SOURCE}, "step": {"purpose": "phase-b", "direction": "advance",
            "mode": "established"}, "owner": OWNER, "payload": payload, "before_raw": c.canonical(state)}


def test_build_approval_deriva_a_matriz_do_plano_salvo_sem_matriz_na_governanca():
    case = phase_b_case()
    approval = lr.build_approval(**case)
    plan = c.loads(case["payload"]["plan.json"], state=True)
    matrix, readbacks = drift_handoff.lifecycle(plan, c.loads(case["before_raw"], state=True), SOURCE, "phase-b")
    assert (approval["drift_matrix"], approval["readbacks"]) == (matrix, readbacks)
    assert approval["drift_matrix"]["purpose"] == "phase-b"
    assert {row["address"] for row in matrix["before"]} == {MACHINE}


def test_derivacao_recusa_plano_com_delete_sem_create():
    plan = {"resource_changes": [change(POLICY, POLICY_BEFORE, None, ["delete"])]}
    state = {"version": 4, "serial": 1, "resources": [instance("aws_iam_role_policy", POLICY_BEFORE)]}
    with pytest.raises(ValueError, match="delete without create refused"):
        drift_handoff.lifecycle(plan, state, SOURCE, "phase-b")


def test_derivacao_recusa_estado_coberto_diferente_do_plano():
    state = iam_state()
    state["resources"].append(instance("aws_iam_role", ROLE_ATTRIBUTES) | {"name": "other"})
    with pytest.raises(ValueError, match="state covered instances differ from the plan"):
        drift_handoff.lifecycle(iam_plan(), state, SOURCE, "phase-b")


def test_derivacao_recusa_proposito_fora_do_lifecycle():
    with pytest.raises(ValueError, match="lifecycle step purpose"):
        drift_handoff.lifecycle(iam_plan(), iam_state(), SOURCE, "phase-a")


@pytest.mark.parametrize("key", ["drift_matrix", "readbacks"])
def test_escrita_do_lifecycle_recusa_matriz_inline(key):
    document = {"product_inputs": {"shared_outputs": {"a": 1}}, "report_hmac_key": "5a" * 32,
                "lifecycle_enabled": True, key: {}}
    with pytest.raises(ValueError, match="inline drift matrix refused"):
        governance_assembly.crosscheck(document, {"shared_outputs_sha256": c.sha(c.canonical({"a": 1}))})


@pytest.mark.parametrize("key", ["drift_matrix", "readbacks"])
def test_admissao_do_lifecycle_recusa_matriz_inline(monkeypatch, key):
    monkeypatch.setenv("CNESDATA_DELIVERY_GOVERNANCE", c.canonical({key: {}}).decode())
    with pytest.raises(ValueError, match="inline drift matrix refused"):
        lr.admission("audit")
