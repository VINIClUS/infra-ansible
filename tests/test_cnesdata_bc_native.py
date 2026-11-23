"""Native mock plans are grammar/structure fixtures of B and C, not a domain capability."""
import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import drift_catalog as dc
from tools.cnesdata_delivery import lifecycle_contract as lc

SCHEDULE = 'module.schedulers.aws_scheduler_schedule.mode["{}"]'
RUN = 'module.schedulers.aws_iam_role_policy.run["{}"]'
ADVANCE = [("b_initial", "phase-b", "initial", {lc.STATE_MACHINE, lc.API_POLICY}),
           ("b_established", "phase-b", "established", {lc.STATE_MACHINE}),
           ("c_recovery_initial", "phase-c-recovery", "initial", lc.scheduler_closure("recovery") | {RUN.format("recovery")}),
           ("c_recovery_established", "phase-c-recovery", "established", {SCHEDULE.format("recovery"), RUN.format("recovery")}),
           ("c_audit_initial", "phase-c-audit", "initial", lc.scheduler_closure("audit") | {RUN.format("audit")}),
           ("c_audit_established", "phase-c-audit", "established", {SCHEDULE.format("audit"), RUN.format("audit")})]
INVERSE = [("b_inverse", "b_initial", "phase-b"), ("c_recovery_inverse", "c_recovery_initial", "phase-c-recovery"),
           ("c_audit_inverse", "c_audit_initial", "phase-c-audit")]


@pytest.fixture(scope="module")
def plans():
    from fixtures.cnesdata_delivery_bc_native import bc_native_plans
    return bc_native_plans()


def _changed(plan):
    return [row for row in plan["resource_changes"] if row["mode"] == "managed"
            and row["change"]["actions"] not in (["no-op"], ["read"])]


def _delta(plan, purpose, direction, mode, original=None, created=None):
    before = {row["address"]: row["change"]["before"] for row in plan["resource_changes"]
              if row["mode"] == "managed" and row["change"]["before"] is not None}
    return {"purpose": purpose, "direction": direction, "mode": mode, "before": before, "original": original or {},
            "created": created or {}, "expected_changes_sha256": c.sha(c.canonical(_changed(plan)))}


@pytest.mark.parametrize("name,purpose,mode,addresses", ADVANCE)
def test_plano_nativo_de_avanco_de_b_e_c_passa_no_oraculo_com_o_conjunto_exato(plans, name, purpose, mode, addresses):
    plan = plans[name]
    assert {row["address"] for row in lc.validate_delta(plan, _delta(plan, purpose, "advance", mode))} == addresses


def _inverse(plans, name, advance):
    plan, forward = plans[name], plans[advance]
    original = {row["address"]: row["change"]["before"] for row in _changed(forward) if row["change"]["actions"] == ["update"]}
    created = {row["address"]: row["change"]["before"] for row in _changed(plan) if row["change"]["actions"] == ["delete"]}
    return plan, forward, original, created


@pytest.mark.parametrize("name,advance,purpose", INVERSE)
def test_plano_nativo_inverso_apaga_so_o_que_o_avanco_criou_e_restaura_o_original(plans, name, advance, purpose):
    plan, forward, original, created = _inverse(plans, name, advance)
    changes = lc.validate_delta(plan, _delta(plan, purpose, "converge", "initial", original, created))
    deleted = {row["address"] for row in changes if row["change"]["actions"] == ["delete"]}
    assert deleted == {row["address"] for row in _changed(forward) if row["change"]["actions"] == ["create"]}
    assert {row["address"] for row in changes} - deleted == set(original)


@pytest.mark.parametrize("name,advance,purpose", INVERSE)
@pytest.mark.parametrize("mutation,message", [
    ("created", "delete requires original absence and own exact create"),
    ("original", "original resource restoration required"),
    ("advance", "delete requires original absence and own exact create"),
    ("established", "delete requires original absence and own exact create|unapproved phase resource"),
])
def test_plano_nativo_inverso_recusa_custodia_incompleta(plans, name, advance, purpose, mutation, message):
    plan, _, original, created = _inverse(plans, name, advance)
    direction, mode = "converge", "initial"
    if mutation == "created":
        created = {}
    if mutation == "original":
        original = {}
    if mutation == "advance":
        direction = "advance"
    if mutation == "established":
        mode = "established"
    with pytest.raises(ValueError, match=message):
        lc.validate_delta(plan, _delta(plan, purpose, direction, mode, original, created))


def test_catalogo_do_lifecycle_cobre_exatamente_o_inventario_dos_planos_nativos(plans):
    inventory = set()
    for plan in plans.values():
        changed = _changed(plan)
        dc.LIFECYCLE_ENVELOPE.required(plan, {row["address"]: row["change"]["after"] or row["change"]["before"]
                                              for row in changed})
        inventory |= {row["type"] for row in changed}
    assert inventory == {"aws_sfn_state_machine", "aws_iam_role_policy", "aws_scheduler_schedule",
                         "aws_scheduler_schedule_group", "aws_cloudwatch_event_rule", "aws_cloudwatch_metric_alarm"}
    assert inventory <= set(lc.COMPUTED_OUTPUTS)
    assert dc.LIFECYCLE_ENVELOPE.supported - inventory == {
        "aws_iam_role", "aws_s3_bucket_lifecycle_configuration", "aws_cloudfront_response_headers_policy"}
