"""P16b ruling 6 item 2: the C handler builds the phase-c element after the C deploy publication and before mode()."""
import pytest

from test_cnesdata_mode_stages import _c_files, _record, _through_unit
from test_cnesdata_stage_events import B_REFERENCE, _ready_journal
from tools.cnesdata_delivery import contract as c


def _recovery(world):
    _c_files(world, "phase-c-recovery")
    world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))


def _moment(world, purpose):
    (moments,) = [moments for name, moments in world.mode.moments if name == purpose][-1:]
    return moments


def test_recovery_constroi_o_elemento_com_as_fontes_autenticadas_antes_do_modo(monkeypatch):
    world = _through_unit(monkeypatch)
    files = _c_files(world, "phase-c-recovery")
    world.events.clear()
    world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))
    ((sources, product, runtime, run),) = world.mode.elements
    b_checkpoint = world.b_files["checkpoint.json"]
    assert sources.purpose == "phase-c-recovery" and sources.published == files
    assert sources.before_raw == sources.phase_b_raw == b_checkpoint
    assert sources.close_raw == world.close_raw == world.mode.calls[-1][3]["close-drain"]
    assert c.sha(sources.close_raw) == c.loads(_ready_journal(world)._inputs["phase-b"], canonical=True)["close_drain_sha256"]
    moments = _moment(world, "phase-c-recovery")
    assert sources.observed_at == moments["job_completed_at"] != moments["artifact_created_at"]
    assert c.instant(sources.observed_at) < world.mode.publications[-1][3]
    assert (product, runtime, run) == ("product", world.phase_c_runtime, None)
    assert world.keeper.phase_c_elements == {"phase-c-recovery": c.canonical({"fixture_element": "phase-c-recovery"})}
    events = [event for event in world.events if event[0] in ("element", "child")]
    assert events[:2] == [("element", "phase-c-recovery"), ("child", "recovery-record")]


def test_audit_rele_o_b_pela_cadeia_cas_e_o_recovery_pelo_checkpoint_da_janela(monkeypatch):
    world = _through_unit(monkeypatch)
    _recovery(world)
    recovery = world.c_files["phase-c-recovery"]
    files = _c_files(world, "phase-c-audit")
    world.mode.publications.clear()
    reads = len(world.phase_b)
    world.handlers["phase-c-audit"](world.keeper, dict(B_REFERENCE))
    assert [publication[0] for publication in world.mode.publications] == ["phase-c-audit", "phase-c-recovery"]
    assert len(world.phase_b) == reads + 1
    sources = world.mode.elements[-1][0]
    assert sources.purpose == "phase-c-audit" and sources.published == files
    assert sources.before_raw == recovery["checkpoint.json"]
    assert sources.phase_b_raw == world.b_files["checkpoint.json"] != recovery["checkpoint.json"]
    assert sources.close_raw == world.close_raw
    assert sources.observed_at == _moment(world, "phase-c-audit")["job_completed_at"]
    assert set(world.keeper.phase_c_elements) == {"phase-c-recovery", "phase-c-audit"}
    assert _record(world)["stage"] == "final"


def _refused(world, purpose, message):
    before, calls, elements = _record(world), len(world.mode.calls), len(world.mode.elements)
    with pytest.raises(ValueError, match=f"^{message}$"):
        world.handlers[purpose](world.keeper, dict(B_REFERENCE))
    assert len(world.mode.calls) == calls and len(world.mode.elements) == elements
    assert _record(world) == before and world.store.get()[0]["status"] == "held"


def test_recovery_recusa_b_relido_fora_do_checkpoint_da_janela(monkeypatch):
    world = _through_unit(monkeypatch)
    _c_files(world, "phase-c-recovery")
    world.b_files["checkpoint.json"] = c.canonical(world.b_checkpoint | {"plan_sha256": "8" * 64})
    _refused(world, "phase-c-recovery", "phase_c=phase_b_binding")
    assert world.keeper.phase_c_elements == {}


def test_audit_recusa_b_relido_diferente_do_que_a_janela_do_recovery_fixou(monkeypatch):
    world = _through_unit(monkeypatch)
    _recovery(world)
    _c_files(world, "phase-c-audit")
    world.b_files["checkpoint.json"] = c.canonical(world.b_checkpoint | {"plan_sha256": "8" * 64})
    _refused(world, "phase-c-audit", "phase_c=phase_b_binding")


def test_audit_recusa_checkpoint_do_recovery_relido_fora_da_janela(monkeypatch):
    world = _through_unit(monkeypatch)
    _recovery(world)
    _c_files(world, "phase-c-audit")
    recovery = c.loads(world.c_files["phase-c-recovery"]["checkpoint.json"], canonical=True)
    world.c_files["phase-c-recovery"] = dict(world.c_files["phase-c-recovery"]) | {
        "checkpoint.json": c.canonical(recovery | {"plan_sha256": "8" * 64})}
    _refused(world, "phase-c-audit", "phase_c=before_binding")


def test_audit_recusa_janela_do_recovery_fora_da_cadeia_cas_do_keeper(monkeypatch):
    world = _through_unit(monkeypatch)
    _recovery(world)
    _c_files(world, "phase-c-audit")
    recovery = _record(world)["sequence"] - 1
    events = world.keeper.lease.checkpoints
    assert [event["sequence"] for event in events].count(recovery) == 1
    events[:] = [event for event in events if event["sequence"] != recovery]
    _refused(world, "phase-c-audit", "phase_c=phase_b_chain")


def test_filho_recusado_no_recovery_nao_chega_ao_modo_e_o_audit_nao_abre(monkeypatch):
    world = _through_unit(monkeypatch)
    _c_files(world, "phase-c-recovery")
    world.mode.element_refusal = "phase_c=element_child"
    before, contexts, calls = _record(world), len(world.keeper._contexts), len(world.mode.calls)
    with pytest.raises(ValueError, match="^phase_c=element_child$"):
        world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))
    assert len(world.mode.calls) == calls
    assert _record(world) == before and _record(world)["stage"] == "phase-c-recovery"
    assert len(world.keeper._contexts) == contexts and world.keeper.phase_c_elements == {}
    assert world.store.get()[0]["status"] == "held"
    world.mode.element_refusal = None
    _c_files(world, "phase-c-audit")
    _refused(world, "phase-c-audit", "phase_c=recovery_element")
