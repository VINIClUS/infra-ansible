"""P16b follow-up item 7: unit, phase-c-recovery and phase-c-audit in one keeper with unit-start open, the observed
origin over the unit-start step receipts and the real phase-c element child under the exported runtime."""
from types import SimpleNamespace

from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401

from test_cnesdata_mode_session_sts import RESOURCES
from test_cnesdata_mode_stages import _c_files, _fake_broker, _host_unit, _record, _stage_open_stages
from test_cnesdata_mode_unit_dispatch_broker import _readbacks
from test_cnesdata_phase_c_element import _product, _runtime
from test_cnesdata_phase_c_routes import REV, _after, _machine, _task
from test_cnesdata_stage_events import B_REFERENCE, MACHINE_ARN
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery import lifecycle_runtime as lr
from tools.cnesdata_delivery import mode_broker as mb

CAPABILITY, SOURCE, ELEMENT = ag.mode_capability, ag.mode_input_source, lr.phase_c_element
STEPS = ("unit-execution", "unit-task", "unit-output", "unit-task", "unit-output")
READBACKS = _readbacks()
ENVIRONMENT = [{"name": "AWS_STATE_MACHINE_ARN", "value": MACHINE_ARN}]


def _rows(mode):
    rows = []
    for row in _after(mode):
        if row["operation"] == "describe_state_machine":
            row = _machine(stateMachineArn=MACHINE_ARN)
        if row["operation"] == "describe_task_definition":
            arn = row["observed"]["taskDefinition"]["taskDefinitionArn"]
            row = _task(next(key for key, value in REV.items() if value == arn), environment=ENVIRONMENT)
        rows.append(row)
    return rows


def _install(monkeypatch, world):
    fake_source, fake_capability = ag.mode_input_source, ag.mode_capability
    seen = SimpleNamespace(authorities=[], effects=[], elements=[])

    def source(**kwargs):
        if kwargs["operation"] not in ("unit-start", "unit-observe"):
            return fake_source(**kwargs)
        world.mode.sources.append((kwargs["operation"], list(kwargs["names"]), kwargs["window"]["stage"]))
        assert "readbacks" in kwargs["names"]
        names = [name for name in kwargs["names"] if name != "readbacks"]
        return SOURCE(**kwargs | {"names": names}) | {"readbacks": READBACKS}

    def authority(context, owner, window):
        record = world.keeper.lease.check()
        assert type(context) is ag.ModeContext and context.activation_sha256 == c.sha(world.activation)
        assert owner == lc.owner_binding(record) and window == record["lifecycle"]
        seen.authorities.append(window["stage"])
        return SimpleNamespace(scope={"resources": RESOURCES})

    def capability(*, journal, keeper, guard, context):
        real = CAPABILITY if journal._request["operation"] == "unit-start" else fake_capability
        return real(journal=journal, keeper=keeper, guard=guard, context=context)

    def effect(*, journal, keeper, context):
        seen.effects.append(journal._request["operation"])
        world.mode.capabilities.append(journal)
        return _fake_broker("ModeBroker", journal, keeper)

    def element(sources, *, product, runtime, run=None):
        raw = ELEMENT(sources, product=product, runtime=runtime, run=run)
        seen.elements.append((sources.purpose, raw))
        return raw
    monkeypatch.setattr(ag, "mode_input_source", source)
    monkeypatch.setattr(ag, "mode_capability", capability)
    monkeypatch.setattr(mb, "_prepared_authority", authority)
    monkeypatch.setattr(mb, "mode_effect_capability", effect)
    monkeypatch.setattr(lr, "phase_c_element", element)
    return seen


def _receipts(world):
    (start,) = [item for item in world.keeper._contexts
                if type(item) is ag.AdapterJournal and item._request["operation"] == "unit-start"]
    return start, [(entry["kind"], c.loads(start._observation_bytes[entry["sha256"]], canonical=True))
                   for entry in start._observations]


def test_unit_recovery_e_audit_rodam_com_o_unit_start_aberto_e_o_elemento_real_do_phase_c(monkeypatch, tmp_path):
    stage = {"product": _product(tmp_path), "phase_c_runtime": _runtime(),
             "b_readbacks": [_machine(stateMachineArn=MACHINE_ARN)]}
    world, run_host = _host_unit(monkeypatch, steps={"unit-start": STEPS}, stage=stage)
    seen, opened = _install(monkeypatch, world), _stage_open_stages(monkeypatch, world)
    run_host()
    assert _record(world)["stage"] == "phase-c-recovery" and opened == ["phase-c-recovery"]
    recovery = _c_files(world, "phase-c-recovery", checkpoint={"readbacks": _rows("recovery")})
    world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))
    assert _record(world)["stage"] == "phase-c-audit" and opened == ["phase-c-recovery", "phase-c-audit"]
    state = {"lineage": "original-lineage", "serial": 10, "state_sha256": "5" * 64}
    audit = _c_files(world, "phase-c-audit", checkpoint={"readbacks": _rows("audit"), "state": state})
    world.handlers["phase-c-audit"](world.keeper, dict(B_REFERENCE))
    after = _record(world)
    assert after["stage"] == "final" and after["checkpoint_sha256"] == c.sha(audit["checkpoint.json"])
    assert world.store.get()[0]["status"] == "held" and opened == ["phase-c-recovery", "phase-c-audit"]
    assert [call[0] for call in world.mode.calls] == [
        "unit-record", "unit-seed", "unit-start", "unit-observe", "recovery-record", "recovery-seed", "recovery-start",
        "recovery-observe", "audit-record", "audit-start", "audit-observe"]
    start, receipts = _receipts(world)
    assert [kind for kind, _ in receipts] == [*STEPS, "mode-result"] and start._failed is False
    observed = {"execution": receipts[0][1], "tasks": [receipts[1][1], receipts[3][1]],
                "outputs": [receipts[2][1], receipts[4][1]]}
    inputs = {call[0]: call[3] for call in world.mode.calls}
    assert inputs["unit-observe"]["observed"] == c.canonical(observed)
    assert inputs["unit-observe"]["readbacks"] == inputs["unit-start"]["readbacks"] == READBACKS
    assert inputs["unit-start"]["previous"] == b"null\n" and seen.effects == ["unit-start"]
    assert seen.authorities == ["unit"]
    assert [purpose for purpose, _ in seen.elements] == ["phase-c-recovery", "phase-c-audit"]
    assert world.keeper.phase_c_elements == dict(seen.elements)
    routes = {purpose: c.loads(raw, canonical=True)["routes"] for purpose, raw in seen.elements}
    assert routes == {"phase-c-recovery": REV | {"audit": None}, "phase-c-audit": REV}
    assert c.loads(dict(seen.elements)["phase-c-audit"], canonical=True)["before"]["serial"] == 9
    assert recovery["checkpoint.json"] != audit["checkpoint.json"]
