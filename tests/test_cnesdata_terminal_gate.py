"""P17: terminal sequences of the keeper (final, recovery, failed prepare), restoration, publication and release."""
import ast
import copy
import inspect
import io
import re
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
TERMINAL_OPERATIONS = ("reopen", "terminal-readback", "rollback-api-static")
RESTORATION_KEYS = ("unit", "recovery", "audit", "api", "static", "first_static_absent")
MEMBER_IDENTITY = ("dispatch_id", "request_sha256", "generation", "initial_state", "execution_ref", "resolution")


def _reusable_lists():
    result = {}
    for path in sorted(WORKFLOWS.glob("reusable-cnesdata-*.yml")):
        found = re.findall(r"files = (\[[^\]]*\])", path.read_text())
        if found:
            result[path.name] = [eval(value, {}) for value in found]
    return result


def _observer_lists():
    text = (WORKFLOWS / "reusable-cnesdata-observer.yml").read_text()
    return [re.findall(r'"([^"]+)"', block) for block in re.findall(r"const modules = \[(.*?)\];", text, re.S)]


PRODUCT_TERMINAL_ORIGIN = {
    "commit": "1d0054c87501de3bbc5f55cfa618b4f54124c55f",
    "scripts/promotion/_adapter_abi.py": "c485be2e93de45b2093fa74fbe6a60397b6a14067bfa917343a4a4a272748cee",
    "scripts/promotion/_api_static_records.py": "f2844355df3c95914a832867c3d4bbebf846cbdf9defbbd8ac477b02d9140f7c",
    "scripts/promotion/promote_api.py": "6d4bdc5f13b3d66d534d3edc09c0f8cb7eaec02104bd545087ef05f0407331eb",
    "scripts/promotion/promote_terminal.py": "53269609b9b25cdfaf9709582cb68e2c15e8e5de0407bf307be3b2da297494fb",
    "tests/production/delivery/reopen_sdk_vector.json": "86e9d493ebbdd1aedcb4c422416dbcf06d28b9e925dc934966cff7718b35b99f"}
VENDORED_TERMINAL_SHA256 = "9c6b02236f4f3243c8555580c50e0c1dbbab02ad29d4d196a0a246dffb491844"


def _product_terminal_abi():
    """Vendored from CnesData 1d0054c8 (P17c): _adapter_abi INPUTS, STAGES, OBSERVATIONS, ROUTING_FIELDS and
    TERMINAL_READBACK_FIELDS of the terminal operations, promote_api._require_request (the input set is exact at
    every stage), promote_terminal ROUTE_MODES, ROLLBACK_FIELDS, REQUIRED_INPUTS and FORBIDDEN_INPUTS of
    terminal-readback (names whose input is not null), and _api_static_records.ROLLBACK_SCHEMA."""
    inputs = {"rollback-api-static": {"static-plan", "inventory", "publication", "host-recovery-receipt", "recovery-decision"},
              "reopen": {"activation", "routing", "canaries", "membership"},
              "terminal-readback": {"routing", "membership", "host-receipt", "static-receipt", "decision"}}
    stages = {"rollback-api-static": {"recovery"}, "reopen": {"final", "recovery"},
              "terminal-readback": {"application-prepare", "final", "recovery"}}
    observations = {"rollback-api-static": "rollback", "reopen": "routing", "terminal-readback": "terminal"}
    optional = {"routing", "host-receipt", "static-receipt", "decision"}
    required = {"application-prepare": set(), "final": {"routing", "host-receipt", "static-receipt"},
                "recovery": {"routing", "decision"}}
    forbidden = {"application-prepare": optional, "final": {"decision"}, "recovery": set()}
    return {"inputs": inputs, "stages": stages, "observations": observations,
            "routing_fields": {"version", "kind", "fence", "routes_match"},
            "readback_fields": {"version", "kind", "members", "quiescent", "state_clean", "pending", "unknown", "observed_at"},
            "route_modes": ("unit", "recovery", "audit"),
            "rollback_fields": {"schema", "plan_sha256", "restored", "residual", "invalidation_id"},
            "rollback_schema": "cnesdata.static-rollback/v1", "optional": optional, "required": required,
            "forbidden": forbidden}


PRODUCT = _product_terminal_abi()


def _product_admission(world):
    for operation, stage, _, inputs in world.terminal.calls:
        assert set(inputs) == PRODUCT["inputs"][operation] and stage in PRODUCT["stages"][operation], (operation, stage)


def _product_stage_rule(readback, stage):
    present = {name for name in PRODUCT["optional"] if readback[name] != b"null"}
    assert set(readback) == PRODUCT["inputs"]["terminal-readback"]
    assert PRODUCT["required"][stage] <= present and not present & PRODUCT["forbidden"][stage]


def test_copia_vendorizada_do_abi_terminal_so_muda_junto_com_a_origem_registrada():
    """infra-ansible CI cannot import CnesData: a refresh of the vendored tables updates its origin and this digest."""
    assert set(PRODUCT_TERMINAL_ORIGIN) == {"commit", "scripts/promotion/_adapter_abi.py",
                                            "scripts/promotion/_api_static_records.py", "scripts/promotion/promote_api.py",
                                            "scripts/promotion/promote_terminal.py",
                                            "tests/production/delivery/reopen_sdk_vector.json"}
    assert c.sha(inspect.getsource(_product_terminal_abi).encode()) == VENDORED_TERMINAL_SHA256


@pytest.mark.parametrize("operation", sorted(PRODUCT["inputs"]))
def test_tabelas_terminais_do_keeper_batem_com_o_abi_do_produto_em_cada_estagio(operation):
    assert lc.ADAPTER_STAGES[operation] == PRODUCT["stages"][operation]
    assert lc.ADAPTER_OBSERVATIONS[operation] == PRODUCT["observations"][operation]
    for stage in sorted(PRODUCT["stages"][operation]):
        assert set(lc.ADAPTER_INPUTS[operation].split()) == PRODUCT["inputs"][operation], stage


def test_formatos_terminais_do_keeper_batem_com_o_produto():
    from tools.cnesdata_delivery import application_gate as ag, terminal_gate as tg
    assert set(ag.ROUTING_FIELDS.split()) == PRODUCT["routing_fields"]
    assert set(ag.TERMINAL_READBACK_FIELDS.split()) == PRODUCT["readback_fields"]
    assert set(tg.ROLLBACK_FIELDS.split()) == PRODUCT["rollback_fields"] and tg.ROLLBACK_SCHEMA == PRODUCT["rollback_schema"]
    assert tg.MODES == PRODUCT["route_modes"]


def test_listas_dos_reusables_cobrem_os_modulos_do_pyboot():
    assert "terminal_gate.py" in lc.APPLICATION_PYBOOT
    assert "tools/cnesdata_delivery/terminal_gate.py" in lc.APPLICATION_CLOSURE_PATHS
    lists = _reusable_lists()
    assert len(lists) == 4 and all(len(values) in {1, 2} for values in lists.values())
    for name, values in lists.items():
        for files in values:
            assert "terminal_gate.py" in files and len(files) == len(set(files)), name
    observer = _observer_lists()
    assert len(observer) == 2
    for modules in observer:
        assert "terminal_gate.py" in modules and len(modules) == len(set(modules))
        python = [name for name in modules if name.endswith(".py")]
        assert python == sorted(python)


def test_terminal_gate_importa_o_gate_e_o_gate_so_o_importa_em_tempo_de_chamada():
    gate = ast.parse((ROOT / "tools/cnesdata_delivery/application_gate.py").read_text())
    top = [node for node in gate.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert not any("terminal_gate" in ast.unparse(node) for node in top)
    assert any("terminal_gate" in ast.unparse(node) for node in ast.walk(gate) if isinstance(node, ast.ImportFrom))
    source = (ROOT / "tools/cnesdata_delivery/terminal_gate.py").read_text()
    assert "boto3" not in source and "urllib" not in source


def _prepare_window(**changes):
    return {"sequence": 0, "preparation_deadline": 1900, "close": None, "fixed_deadline": None, "input_deadline": None,
            "stage": "application-prepare", "admitted_at": 1000, "deadline": 1900, "decision": None,
            "checkpoint_sha256": "a" * 64} | changes


def _assessment(kind, **changes):
    value = {"kind": kind, "fence": "OPEN" if kind == "accepted-open" else "CLOSED",
             "accepted_modes": ["unit", "recovery", "audit"] if kind == "accepted-open" else [],
             "routes_match": True, "state_clean": True, "quiescent": True, "pending": [], "unknown": [], "observed_at": 100}
    if kind != "accepted-open":
        value["restoration"] = {key: key != "first_static_absent" for key in RESTORATION_KEYS}
    return value | changes


def test_failed_prepare_dispensa_routing_e_aceita_fence_e_routes_match_nulos():
    from tools.cnesdata_delivery import application_gate as ag
    assert ag._terminal_required("failed-prepare-quiescent", _prepare_window()) == {"restoration", "quiescence"}
    value = _assessment("failed-prepare-quiescent", fence=None, routes_match=None)
    assert lc.terminal_result(value, now=110, deadline=200) == "failed"


@pytest.mark.parametrize("change", [{"fence": "CLOSED"}, {"routes_match": True}, {"fence": "OPEN", "routes_match": True},
                                    {"fence": "CLOSED", "routes_match": False}])
def test_failed_prepare_so_aceita_os_dois_nulos_juntos(change):
    with pytest.raises(ValueError):
        lc.terminal_result(_assessment("failed-prepare-quiescent", fence=None, routes_match=None) | change, now=110,
                           deadline=200)


@pytest.mark.parametrize("kind", ["accepted-open", "failed-closed-quiescent"])
@pytest.mark.parametrize("change", [{"fence": None, "routes_match": None}, {"routes_match": None}, {"fence": None}])
def test_fence_e_routes_match_nulos_recusam_nos_outros_tipos(kind, change):
    with pytest.raises(ValueError):
        lc.terminal_result(_assessment(kind) | change, now=110, deadline=200)


def test_failed_prepare_monta_a_avaliacao_sem_validador_de_routing():
    from test_cnesdata_application_gate import _prepare_stage_keeper
    keeper, store = _prepare_stage_keeper()
    readback = _readback([])
    keeper.attach(_journal([("terminal", readback)]))
    keeper._terminal_validators.clear()
    from tools.cnesdata_delivery import application_gate as ag, terminal_gate as tg
    keeper.register_terminal_validator("quiescence", ag.quiescence_terminal_validator(keeper.uncertainty), label="q")
    keeper.register_terminal_validator("restoration", tg.restoration_validator(keeper), label="r")
    window = store.get()[0]["lifecycle"]
    proof = keeper._terminal_proof({"kind": "failed-prepare-quiescent", "checkpoint_raw": keeper.predecessor["raw"],
                                    "sources": {"quiescence": {"terminal": c.sha(readback)},
                                                "restoration": {"terminal": c.sha(readback)}}},
                                   lc.owner_binding(store.get()[0]), window)
    assert proof["assessment"]["fence"] is None and proof["assessment"]["routes_match"] is None
    assert set(proof["inputs"]) == {"quiescence", "restoration"}


@pytest.mark.parametrize("kind, field", [("accepted-open", "fixed_deadline"), ("failed-closed-quiescent", "fixed_deadline"),
                                         ("failed-prepare-quiescent", "preparation_deadline")])
def test_limite_da_publicacao_e_f_ou_o_prazo_de_preparacao(kind, field):
    from tools.cnesdata_delivery import terminal_gate as tg
    window = {"close": 1000, "fixed_deadline": 2800, "preparation_deadline": 1900, "stage": "final", "decision": None}
    if kind == "failed-closed-quiescent":
        window |= {"stage": "recovery", "decision": {"choice_at": 1100, "deadline": 1520, "checkpoint_sha256": "9" * 64}}
    if kind == "failed-prepare-quiescent":
        window |= {"close": None, "fixed_deadline": None, "stage": "application-prepare"}
    assert tg.publication_limit(kind, window) == window[field]


@pytest.mark.parametrize("kind, window", [("accepted-open", {"close": None, "fixed_deadline": None, "preparation_deadline": 1900,
                                                             "stage": "application-prepare", "decision": None}),
                                          ("failed-prepare-quiescent", {"close": 1000, "fixed_deadline": 2800,
                                                                        "preparation_deadline": 1900, "stage": "final",
                                                                        "decision": None})])
def test_limite_da_publicacao_recusa_tipo_fora_da_janela(kind, window):
    from tools.cnesdata_delivery import terminal_gate as tg
    with pytest.raises(ValueError, match="terminal publication window"):
        tg.publication_limit(kind, window)


def test_guarda_da_publicacao_usa_o_limite_f_e_recusa_depois_dele():
    from test_cnesdata_application_gate import _accepted_terminal_case, _terminal_reference
    from tools.cnesdata_delivery import terminal_gate as tg
    keeper, store = _accepted_terminal_case()
    keeper.finish(_terminal_reference(keeper))
    record, etag = store.get()
    now = {"value": 1000}
    keeper.clock = keeper.monotonic = lambda: now["value"]
    guard = tg.publication_guard(keeper, "accepted-open", credential_limit=9000)
    assert guard.limit == record["lifecycle"]["fixed_deadline"] == 2800 and guard.record == record and guard.etag == etag
    guard.check(20)
    now["value"] = 2800 - 37
    with pytest.raises(ValueError, match="released publication"):
        guard.check()


def _journal(observations, *, operation=None, inputs=None):
    from test_cnesdata_application_gate import _journal_with
    journal = _journal_with(observations=observations)
    journal._request = {"operation": operation or "terminal-readback", "owner": {"owner_sha256": "a" * 64}}
    journal._inputs = inputs or {}
    return journal


def _readback(members, **changes):
    return c.canonical({"version": 1, "kind": "terminal", "members": members, "quiescent": True, "state_clean": True,
                        "pending": [], "unknown": [], "observed_at": c.utc(1000)} | changes)


def _rollback(**changes):
    from tools.cnesdata_delivery import terminal_gate as tg
    return c.canonical({"schema": tg.ROLLBACK_SCHEMA, "plan_sha256": "9" * 64, "restored": [], "residual": False,
                        "invalidation_id": None} | changes)


def _decision(choice_at=1100, deadline=1520, fixed=2800):
    return {"version": 1, "operation_id": "5" * 64, "binding_sha256": "6" * 64, "generation": 2, "choice_at": c.utc(choice_at),
            "choice_monotonic_ms": 5, "clock_boot_id": "8" * 64, "fixed_deadline": c.utc(fixed),
            "recovery_deadline": c.utc(deadline), "allocated_seconds": deadline - choice_at, "convergence_budget_seconds": 300,
            "finalization_budget_seconds": 60, "uncertainty_budget_seconds": 60, "checkpoint_sha256": "7" * 64}


def _handoff(status, decision, **changes):
    from tools.cnesdata_delivery import application_gate as ag
    value = {field: None for field in ag.HOST_HANDOFF_FIELDS.split()} | {
        "version": 1, "kind": "host-handoff", "caller": {"repository": "VINIClUS/CnesData"}, "producer_sha": "d" * 40,
        "status": status, "closed_ready_sha256": "8" * 64, "recovery_decision": decision,
        "recovery_proof_sha256": c.sha(c.canonical(decision)) if decision is not None else None}
    return c.canonical(value | changes)


def _recovery_window():
    return {"sequence": 4, "preparation_deadline": 1900, "close": 1000, "fixed_deadline": 2800, "input_deadline": 3000,
            "stage": "recovery", "admitted_at": 1100, "deadline": 1400, "checkpoint_sha256": "a" * 64,
            "decision": {"choice_at": 1100, "deadline": 1520, "checkpoint_sha256": "7" * 64}}


def _restoration(keeper, source, window, observations):
    from tools.cnesdata_delivery import terminal_gate as tg
    return tg.restoration_validator(keeper)(source, owner={"owner_sha256": "a" * 64}, window=window, observations=observations)


def test_restoration_do_failed_prepare_vem_do_estado_sem_fence_nem_publicacao():
    from test_cnesdata_application_gate import _prepare_stage_keeper
    keeper, _ = _prepare_stage_keeper()
    readback = _readback([])
    keeper.attach(_journal([("terminal", readback)]))
    source = {"terminal": c.sha(readback)}
    result = _restoration(keeper, source, _prepare_window(), {c.sha(readback): readback})
    assert result == {"sha256": c.sha(c.canonical(source)),
                      "facts": {"unit": True, "recovery": True, "audit": True, "api": True, "static": True,
                                "first_static_absent": False}}


@pytest.mark.parametrize("operation, fact", [("publish-static", "static"), ("unit-seed", "unit"),
                                             ("recovery-start", "recovery"), ("audit-observe", "audit")])
def test_restoration_reporta_o_que_a_lease_chegou_a_mudar_como_nao_restaurado(operation, fact):
    from test_cnesdata_application_gate import _prepare_stage_keeper
    keeper, _ = _prepare_stage_keeper()
    readback = _readback([])
    keeper.attach(_journal([("terminal", readback)]))
    keeper.attach(_journal([], operation=operation))
    result = _restoration(keeper, {"terminal": c.sha(readback)}, _prepare_window(), {c.sha(readback): readback})
    assert result["facts"][fact] is False
    assert all(value is (key != "first_static_absent") for key, value in result["facts"].items() if key != fact)


@pytest.mark.parametrize("change", [{"close": 1000}, {"stage": "final"}, {"decision": {"choice_at": 1}}])
def test_restoration_do_prepare_recusa_janela_que_nao_e_a_do_prepare(change):
    from test_cnesdata_application_gate import _prepare_stage_keeper
    keeper, _ = _prepare_stage_keeper()
    readback = _readback([])
    with pytest.raises(ValueError, match="terminal restoration"):
        _restoration(keeper, {"terminal": c.sha(readback)}, _prepare_window(**change), {c.sha(readback): readback})


def _recovery_restoration_case(*, rollback=None, handoff=None):
    from test_cnesdata_application_gate import _accepted_terminal_case
    keeper, _ = _accepted_terminal_case()
    raw = _rollback() if rollback is None else rollback
    keeper.attach(_journal([("rollback", raw)], operation="rollback-api-static"))
    keeper.host_recovery = _handoff("rolled_back", _decision()) if handoff is None else handoff
    source = {"rollback": c.sha(raw), "host-recovery": c.sha(keeper.host_recovery)}
    return keeper, source, {c.sha(raw): raw}


def test_restoration_do_failed_closed_exige_rollback_sem_residuo_e_host_rolled_back_amarrado_a_decisao():
    keeper, source, observations = _recovery_restoration_case()
    result = _restoration(keeper, source, _recovery_window(), observations)
    assert result == {"sha256": c.sha(c.canonical(source)),
                      "facts": {"unit": True, "recovery": True, "audit": True, "api": True, "static": True,
                                "first_static_absent": False}}


@pytest.mark.parametrize("case, fact", [("residual", "static"), ("not-rolled-back", "api")])
def test_restoration_do_failed_closed_reporta_o_que_o_rollback_nao_provou(case, fact):
    rollback = _rollback(residual=True) if case == "residual" else None
    handoff = _handoff("accepted", _decision()) if case == "not-rolled-back" else None
    keeper, source, observations = _recovery_restoration_case(rollback=rollback, handoff=handoff)
    assert _restoration(keeper, source, _recovery_window(), observations)["facts"][fact] is False


@pytest.mark.parametrize("mutation", ["foreign-decision", "proof", "schema", "restored-type", "extra-field", "source-digest",
                                      "absent-host", "missing-role", "window"])
def test_restoration_do_failed_closed_recusa_fonte_fora_do_contrato(mutation):
    decision = _decision(choice_at=1101) if mutation == "foreign-decision" else _decision()
    handoff = _handoff("rolled_back", decision, **({"recovery_proof_sha256": "0" * 64} if mutation == "proof" else {}))
    rollback = {"schema": _rollback(schema="other/v1"), "restored-type": _rollback(restored={}),
                "extra-field": _rollback(extra=1)}.get(mutation)
    keeper, source, observations = _recovery_restoration_case(rollback=rollback, handoff=handoff)
    window = _recovery_window()
    if mutation == "source-digest": source["host-recovery"] = "0" * 64
    if mutation == "absent-host": keeper.host_recovery = None
    if mutation == "missing-role": source.pop("rollback")
    if mutation == "window": window["decision"] = None
    with pytest.raises(ValueError):
        _restoration(keeper, source, window, observations)


@pytest.mark.parametrize("stage", ["unit", "application-prepare", "phase-c-audit"])
def test_routing_so_vale_nos_estagios_final_e_recovery(stage):
    from test_cnesdata_application_gate import _validate
    with pytest.raises(ValueError, match="terminal routing stage"):
        _validate("routing", window={"stage": stage})


@pytest.mark.parametrize("pending", [["intent"], [{"kind": "sdk-call", "reference_sha256": "f" * 64}],
                                     [{"kind": "permit-held", "reference_sha256": "F" * 64}],
                                     [{"kind": "member-unresolved", "reference_sha256": "f" * 64, "extra": 1}]])
def test_quiescence_recusa_pending_fora_da_forma_do_produto(pending):
    from test_cnesdata_application_gate import _synthetic_terminal_vectors, _validate
    from tools.cnesdata_delivery import application_gate as ag
    vectors = _synthetic_terminal_vectors(terminal=lambda value: value.update(quiescent=False, pending=pending))
    with pytest.raises(ValueError):
        _validate("quiescence", vectors, validator=ag.quiescence_terminal_validator(lambda: []))


@pytest.mark.parametrize("quiescent, pending", [(True, [{"kind": "permit-held", "reference_sha256": "f" * 64}]), (False, [])])
def test_quiescence_recusa_quiescent_que_contradiz_pending(quiescent, pending):
    from test_cnesdata_application_gate import _synthetic_terminal_vectors, _validate
    from tools.cnesdata_delivery import application_gate as ag
    vectors = _synthetic_terminal_vectors(terminal=lambda value: value.update(quiescent=quiescent, pending=pending))
    with pytest.raises(ValueError, match="terminal quiescence facts"):
        _validate("quiescence", vectors, validator=ag.quiescence_terminal_validator(lambda: []))


def test_registro_de_producao_fecha_os_tres_tipos_terminais_com_rotulos_de_origem():
    from tools.cnesdata_delivery import application_gate as ag
    assert {kind: label for kind, (label, _) in ag.TERMINAL_VALIDATORS.items()} == {
        "routing": "product-reopen", "static": "product-publication", "membership": "product-membership",
        "quiescence": "product-terminal-readback", "host": "infra-host-handoff", "decision": "infra-recovery-decision",
        "restoration": "keeper-restoration", "unit": "product-mode-unit", "recovery": "product-mode-recovery",
        "audit": "product-mode-audit"}
    windows = {"accepted-open": {"stage": "final", "decision": None},
               "failed-closed-quiescent": {"stage": "recovery", "decision": {"choice_at": 1}},
               "failed-prepare-quiescent": {"stage": "application-prepare", "decision": None, "close": None}}
    for kind, window in windows.items():
        assert ag._terminal_required(kind, window) <= set(ag.TERMINAL_VALIDATORS)
    assert "SYNTHETIC" not in (ROOT / "tools/cnesdata_delivery/application_gate.py").read_text()


def test_eventos_do_keeper_incluem_o_host_recovery_que_dispara_o_rollback():
    from tools.cnesdata_delivery import application_gate as ag
    assert ag.KEEPER_EVENTS == ("observer-bootstrap", "prepared", "phase-b", "host", "phase-c-recovery", "phase-c-audit",
                                "host-recovery")
    assert lc.OPERATION_TRIGGERS == {"inventory": ("application-prepare", "observer-bootstrap"),
                                     "rollback-api-static": ("recovery", "host-recovery")}
    assert "recovery" not in lc.STAGE_TRIGGERS


def test_keeper_loop_recebe_o_terminal_e_devolve_o_resultado():
    import inspect
    from tools.cnesdata_delivery import application_gate as ag
    assert list(inspect.signature(ag.keeper_loop).parameters) == ["keeper", "next_event", "handlers", "terminal", "poll",
                                                                  "sleep"]


class _Terminal:
    def __init__(self, result=None, error=None):
        self.calls, self.result, self.error = [], result, error

    def final(self, keeper):
        self.calls.append(("final", keeper.lease.check()["lifecycle"]["stage"]))
        return self.result

    def prepare_failure(self, keeper, error):
        self.calls.append(("prepare_failure", str(error)))
        if self.error is not None:
            raise self.error
        return self.result


def _loop_handlers(ag, **handlers):
    base = {name: (lambda *a, _name=name: pytest.fail(_name + " unexpected")) for name in ag.KEEPER_EVENTS}
    return base | handlers


def test_keeper_loop_devolve_o_resultado_do_terminal_ao_chegar_no_final():
    from test_cnesdata_application_gate import _accepted_terminal_case
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store = _accepted_terminal_case()
    assert store.get()[0]["lifecycle"]["stage"] == "final"
    terminal = _Terminal(result={"kind": "accepted-open"})
    outcome = ag.keeper_loop(keeper, next_event=lambda window: pytest.fail("final needs no caller event"),
                             handlers=_loop_handlers(ag), terminal=terminal, sleep=lambda seconds: None)
    assert outcome == {"kind": "accepted-open"} and terminal.calls == [("final", "final")]


def test_keeper_loop_devolve_o_resultado_de_um_handler_terminal():
    from test_cnesdata_application_gate import _keeper_loop_case
    ag, keeper, store, run, seen, handled, slept = _keeper_loop_case()
    terminal = _Terminal()
    outcome = ag.keeper_loop(keeper, next_event=lambda window: {"kind": "host-recovery", "reference": {"job_id": 1}},
                             handlers=_loop_handlers(ag, **{"host-recovery": lambda current, reference: {"closed": reference}}),
                             terminal=terminal, sleep=lambda seconds: None)
    assert outcome == {"closed": {"job_id": 1}} and terminal.calls == []


def test_keeper_loop_fecha_failed_prepare_numa_recusa_antes_do_close():
    from test_cnesdata_application_gate import _keeper_loop_case
    ag, keeper, store, run, seen, handled, slept = _keeper_loop_case()
    terminal = _Terminal(result={"kind": "failed-prepare-quiescent"})

    def prepared(current, reference):
        raise ValueError("prepared refused")
    outcome = ag.keeper_loop(keeper, next_event=lambda window: {"kind": "prepared", "reference": {}},
                             handlers=_loop_handlers(ag, prepared=prepared), terminal=terminal, sleep=lambda seconds: None)
    assert outcome == {"kind": "failed-prepare-quiescent"} and terminal.calls == [("prepare_failure", "prepared refused")]


def test_keeper_loop_fecha_failed_prepare_quando_o_produtor_de_eventos_recusa_antes_do_close():
    from test_cnesdata_application_gate import _keeper_loop_case
    ag, keeper, store, run, seen, handled, slept = _keeper_loop_case()
    terminal = _Terminal(result={"kind": "failed-prepare-quiescent"})

    def next_event(window):
        raise ValueError("stage deadline elapsed stage=application-prepare")
    outcome = ag.keeper_loop(keeper, next_event=next_event, handlers=_loop_handlers(ag), terminal=terminal,
                             sleep=lambda seconds: None)
    assert outcome["kind"] == "failed-prepare-quiescent"
    assert terminal.calls == [("prepare_failure", "stage deadline elapsed stage=application-prepare")]


def test_keeper_loop_propaga_a_recusa_depois_do_close_com_o_lease_retido():
    from test_cnesdata_application_gate import _keeper_loop_case
    ag, keeper, store, run, seen, handled, slept = _keeper_loop_case()
    terminal = _Terminal(result={"kind": "failed-prepare-quiescent"})

    def prepared(current, reference):
        record = current.lease.check()["lifecycle"]
        current.lease.checkpoint(record | {"sequence": 1, "close": 1000, "fixed_deadline": 2800, "input_deadline": 4000,
                                           "stage": "phase-b", "admitted_at": 1000, "deadline": 1360,
                                           "checkpoint_sha256": "e" * 64})
        raise ValueError("refused after close")
    with pytest.raises(ValueError, match="^refused after close$"):
        ag.keeper_loop(keeper, next_event=lambda window: {"kind": "prepared", "reference": {}},
                       handlers=_loop_handlers(ag, prepared=prepared), terminal=terminal, sleep=lambda seconds: None)
    assert terminal.calls == [] and store.get()[0]["status"] == "held"


def test_keeper_loop_mantem_a_recusa_original_quando_o_failed_prepare_nao_fecha():
    from test_cnesdata_application_gate import _keeper_loop_case
    ag, keeper, store, run, seen, handled, slept = _keeper_loop_case()
    terminal = _Terminal(error=ValueError("terminal readback refused"))

    def prepared(current, reference):
        raise ValueError("prepared refused")
    with pytest.raises(ValueError, match="^terminal readback refused$") as caught:
        ag.keeper_loop(keeper, next_event=lambda window: {"kind": "prepared", "reference": {}},
                       handlers=_loop_handlers(ag, prepared=prepared), terminal=terminal, sleep=lambda seconds: None)
    assert str(caught.value.__context__) == "prepared refused" and store.get()[0]["status"] == "held"


@pytest.mark.parametrize("status, code", [("accepted", None), ("failed", "terminal promotion_status=failed kind=failed-prepare-quiescent")])
def test_main_execute_sai_com_erro_so_quando_a_promocao_falha(monkeypatch, status, code):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime, session_owner
    monkeypatch.setattr(lifecycle_runtime, "admission", lambda name: ({}, {}, {}, None, {}, {}))
    monkeypatch.setattr(ag, "verify_source_closure", lambda *args: None)
    monkeypatch.setattr(session_owner, "application_fragment", lambda *args: None)
    kind = "accepted-open" if status == "accepted" else "failed-prepare-quiescent"
    monkeypatch.setattr(ag, "execute", lambda admitted: {"kind": kind, "promotion_status": status, "receipt": {"id": 1}})
    if code is None:
        assert ag.main(["execute"]) == {"kind": kind, "promotion_status": status, "receipt": {"id": 1}}
        return
    with pytest.raises(SystemExit) as caught:
        ag.main(["execute"])
    assert caught.value.code == code


def _shared_state(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag
    state = {}
    real = ag.stage_handlers
    monkeypatch.setattr(ag, "stage_handlers", lambda **kwargs: real(**kwargs, state=state))
    return state


class _Evidence:
    def __init__(self, keeper):
        self.keeper, self.objects = keeper, {}

    def put(self, bucket, key, raw):
        assert bucket == "evidence" and "/terminal/" in key and key not in self.objects
        self.objects[key] = raw

    def get(self, bucket, key, *, maximum=None):
        if key.endswith("/keeper/checkpoint.json"):
            return self.keeper.transport_raw, "original-keeper-etag"
        return self.objects[key], "etag"


def _product_observation(world, journal):
    operation, stage = journal._request["operation"], journal._request["stage"]["stage"]
    inputs = journal._inputs
    if operation == "reopen":
        value = {"version": 1, "kind": "routing", "fence": "OPEN" if stage == "final" else "CLOSED", "routes_match": True}
    elif operation == "rollback-api-static":
        from tools.cnesdata_delivery import terminal_gate as tg
        value = {"schema": tg.ROLLBACK_SCHEMA, "plan_sha256": c.sha(inputs["static-plan"]), "restored": [],
                 "residual": False, "invalidation_id": None}
    else:
        members = c.loads(inputs["membership"], canonical=True)["members"]
        value = {"version": 1, "kind": "terminal", "members": [{key: item[key] for key in MEMBER_IDENTITY} for item in members],
                 "quiescent": True, "state_clean": True, "pending": [], "unknown": [],
                 "observed_at": c.utc(int(world.clock.value))}
    return c.canonical(value | world.terminal.changes.get(operation, {}))


def _terminal_fakes(monkeypatch, world, state, **changes):
    from test_cnesdata_stage_events import RUN
    from tools.cnesdata_delivery import application_gate as ag, terminal_gate as tg
    world.terminal = SimpleNamespace(calls=[], capabilities=[], sources=[], raws={}, changes=changes)
    previous = ag.invoke_adapter

    def invoke_adapter(**kwargs):
        journal = kwargs["journal"]
        operation = journal._request["operation"]
        if operation not in TERMINAL_OPERATIONS:
            return previous(**kwargs)
        world.terminal.calls.append((operation, journal._request["stage"]["stage"], kwargs["timeout"], dict(journal._inputs)))
        raw = _product_observation(world, journal)
        world.terminal.raws[operation] = raw
        journal._observations.append({"kind": lc.ADAPTER_OBSERVATIONS[operation], "sha256": c.sha(raw), "size": len(raw)})
        journal._observation_bytes[c.sha(raw)] = raw
        world.clock.value += 2
    monkeypatch.setattr(ag, "invoke_adapter", invoke_adapter)

    def capability(*, journal, keeper, guard, context):
        assert guard is journal._guard and type(context) is tg.TerminalContext and context.state is state
        world.terminal.capabilities.append(journal._request["operation"])
        return SimpleNamespace(aws="operation-client", evidence=[], session=SimpleNamespace(client="c", evidence="e"))
    monkeypatch.setattr(tg, "terminal_capability", capability)

    def source(*, keeper, owner, window, operation, names):
        world.terminal.sources.append((operation, list(names), window["stage"]))
        return {name: c.canonical({"unit": "u", "recovery": "r", "audit": "a"}) for name in names}
    monkeypatch.setattr(tg, "terminal_input_source", source)
    world.keeper._terminal_validators = {}
    ag.register_terminal_validators(world.keeper, ag.TERMINAL_VALIDATORS)
    world.evidence = _Evidence(world.keeper)
    world.keeper.evidence_aws = world.evidence
    release = {field: "r-" + field for field in ag.RELEASE_FIELDS.split()}
    governance = world.governance | {"state_bucket": "state", "release": release}
    world.steps = tg.TerminalSteps(keeper=world.keeper, api=world.api, governance=governance, run=dict(RUN), state=state,
                                   product="product", credential_limit=6000, clock=world.clock, authority="authority",
                                   operation_session="operation-session")
    world.loop_handlers = dict(world.handlers) | {"host-recovery": world.steps.host_recovery}
    return world


def _accepted_world(monkeypatch, **changes):
    from test_cnesdata_mode_stages import _c_files, _through_unit
    from test_cnesdata_stage_events import B_REFERENCE
    state = _shared_state(monkeypatch)
    world = _through_unit(monkeypatch)
    custody = {"phase_a_originals": world.keeper.phase_a_originals}
    for purpose in ("phase-c-recovery", "phase-c-audit"):
        _c_files(world, purpose, checkpoint=custody)
        world.handlers[purpose](world.keeper, dict(B_REFERENCE))
    return _terminal_fakes(monkeypatch, world, state, **changes), state


def _loop(world):
    from tools.cnesdata_delivery import application_gate as ag
    return ag.keeper_loop(world.keeper, next_event=world.next_event, handlers=world.loop_handlers, terminal=world.steps,
                          sleep=lambda seconds: None)


def test_ponta_a_ponta_fecha_accepted_open_e_libera_o_lease(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag
    world, state = _accepted_world(monkeypatch)
    assert world.store.get()[0]["lifecycle"]["stage"] == "final"
    world.next_event = lambda window: pytest.fail("final closes on the internal terminal-readback")
    outcome = _loop(world)
    record = world.store.get()[0]
    assert outcome["kind"] == "accepted-open" and outcome["promotion_status"] == "accepted" and record["status"] == "released"
    assert [call[:2] for call in world.terminal.calls] == [("reopen", "final"), ("terminal-readback", "final")]
    assert world.terminal.capabilities == ["reopen", "terminal-readback"]
    assert world.terminal.sources == [("reopen", ["routing"], "final")]
    reopen, readback = (call[3] for call in world.terminal.calls)
    assert set(reopen) == {"activation", "routing", "canaries", "membership"} and reopen["activation"] == state["activation"]
    assert [item["kind"] for item in c.loads(reopen["canaries"], canonical=True)] == ["unit", "recovery", "audit"]
    assert readback["decision"] == b"null" and readback["routing"] == world.terminal.raws["reopen"]
    _product_stage_rule(readback, "final")
    _product_admission(world)
    assert c.loads(readback["static-receipt"], canonical=True)["schema"] == "cnesdata.static-publication/v1"
    assert c.loads(readback["host-receipt"], canonical=True)["status"] == "accepted"
    files = {key.rsplit("/", 1)[1]: raw for key, raw in world.evidence.objects.items()}
    assert set(files) == {"terminal.json", "checkpoint.json", "lease.json"}
    result = ag.verify_terminal_bundle(files, record)
    assert result["terminal"]["promotion_status"] == "accepted" and result["terminal"]["assessment"]["fence"] == "OPEN"
    assert result["checkpoint"]["inputs"].keys() == {"unit", "recovery", "audit", "host", "static", "routing", "membership",
                                                     "quiescence"}
    assert world.uploads[-1][0] == "lifecycle-terminal" and outcome["receipt"] == {"id": 501, "digest": "sha256:" + "a" * 64}


def test_ponta_a_ponta_recusa_accepted_open_com_rotas_divergentes_e_mantem_o_lease(monkeypatch):
    world, _ = _accepted_world(monkeypatch, reopen={"fence": "CLOSED", "routes_match": False})
    world.next_event = lambda window: pytest.fail("no event at final")
    with pytest.raises(ValueError, match="^terminal uncertainty/drift/expiry$"):
        _loop(world)
    assert world.store.get()[0]["status"] == "held" and world.evidence.objects == {}


def _recovery_world(monkeypatch, *, rolled_back=None, **changes):
    from test_cnesdata_stage_events import B_REFERENCE, HOST_REFERENCE, _prepared_world
    from tools.cnesdata_delivery import application_gate as ag
    state = _shared_state(monkeypatch)
    world = _prepared_world(monkeypatch)
    world.b_checkpoint["phase_a_originals"] = world.keeper.phase_a_originals
    world.b_files["checkpoint.json"] = c.canonical(world.b_checkpoint)
    world.handlers["phase-b"](world.keeper, dict(B_REFERENCE))
    world.clock.value = 1200
    world.keeper.tick()
    window = world.store.get()[0]["lifecycle"]
    world.decision = _decision(choice_at=1200, deadline=min(window["fixed_deadline"], 1620), fixed=window["fixed_deadline"])
    ready = c.sha(world.ready_raw)
    first = _handoff("recovery_required", world.decision, closed_ready_sha256=ready)
    second = (_handoff("rolled_back", world.decision, closed_ready_sha256=ready) if rolled_back is None
              else rolled_back(ready, world.decision))
    world.handoff_raws = (first, second)
    world.handoffs = []

    def authenticate_host_handoff(api, owner, *, guard, **names):
        world.handoffs.append(names)
        return second if names else first
    monkeypatch.setattr(ag, "authenticate_host_handoff", authenticate_host_handoff)
    world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    return _terminal_fakes(monkeypatch, world, state, **changes), state


def test_host_recovery_required_com_decisao_entra_no_estagio_recovery_sem_publicar_o_estatico(monkeypatch):
    from tools.cnesdata_delivery import terminal_gate as tg
    world, state = _recovery_world(monkeypatch)
    window = world.store.get()[0]["lifecycle"]
    choice, deadline = 1200, int(c.instant(world.decision["recovery_deadline"]))
    assert window["stage"] == "recovery" and window["decision"] == {"choice_at": choice, "deadline": deadline,
                                                                     "checkpoint_sha256": "7" * 64}
    assert window["deadline"] == min(deadline - 120, choice + 300) and window["admitted_at"] == world.clock.value
    assert "publish-static" not in tg._operations(world.keeper) and world.store.get()[0]["status"] == "held"
    assert state["recovery-decision"] == c.canonical(world.decision)


@pytest.mark.parametrize("handoff", [
    lambda ready, decision: _handoff("rolled_back", None, closed_ready_sha256=ready),
    lambda ready, decision: _handoff("recovery_required", None, closed_ready_sha256=ready),
    lambda ready, decision: _handoff("recovery_required", decision, closed_ready_sha256="0" * 64),
    lambda ready, decision: _handoff("recovery_required", decision, closed_ready_sha256=ready, recovery_proof_sha256="0" * 64),
    lambda ready, decision: _handoff("recovery_required", decision | {"recovery_deadline": c.utc(9999)},
                                     closed_ready_sha256=ready),
    lambda ready, decision: _handoff("recovery_required", _later_f(decision), closed_ready_sha256=ready)],
    ids=["rolled-back-null", "required-null", "closed-ready", "proof", "recovery-deadline", "fixed-deadline"])
def test_host_sem_decisao_amarrada_fica_retido_no_estagio_api(monkeypatch, handoff):
    from test_cnesdata_stage_events import B_REFERENCE, HOST_REFERENCE, _prepared_world
    from tools.cnesdata_delivery import application_gate as ag
    _shared_state(monkeypatch)
    world = _prepared_world(monkeypatch)
    world.handlers["phase-b"](world.keeper, dict(B_REFERENCE))
    world.clock.value = 1200
    window = world.store.get()[0]["lifecycle"]
    raw = handoff(c.sha(world.ready_raw), _decision(choice_at=1200, deadline=min(window["fixed_deadline"], 1620),
                                                    fixed=window["fixed_deadline"]))
    monkeypatch.setattr(ag, "authenticate_host_handoff", lambda api, owner, *, guard, **names: raw)
    before = world.store.get()
    with pytest.raises(ValueError):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert world.store.get()[0]["lifecycle"] == before[0]["lifecycle"] and world.store.get()[0]["status"] == "held"


def test_host_recovery_required_com_incerteza_do_keeper_fica_retido_no_estagio_api(monkeypatch):
    from test_cnesdata_stage_events import B_REFERENCE, HOST_REFERENCE, _prepared_world
    from tools.cnesdata_delivery import application_gate as ag
    _shared_state(monkeypatch)
    world = _prepared_world(monkeypatch)
    world.handlers["phase-b"](world.keeper, dict(B_REFERENCE))
    world.clock.value = 1200
    window = world.store.get()[0]["lifecycle"]
    decision = _decision(choice_at=1200, deadline=min(window["fixed_deadline"], 1620), fixed=window["fixed_deadline"])
    raw = _handoff("recovery_required", decision, closed_ready_sha256=c.sha(world.ready_raw))
    monkeypatch.setattr(ag, "authenticate_host_handoff", lambda api, owner, *, guard, **names: raw)
    world.keeper._contexts.append(SimpleNamespace(_request={"operation": "rollout"}, _observations=[], _observation_bytes={},
                                                  _failed=False, _inflight=None, unknown=[],
                                                  pending=[{"kind": "sdk-call", "reference_sha256": "f" * 64}]))
    before = world.store.get()
    with pytest.raises(ValueError, match="^host handoff with unresolved keeper uncertainty$"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert world.store.get() == before and before[0]["lifecycle"]["stage"] == "api"


def test_ponta_a_ponta_fecha_failed_closed_quiescent_e_libera_o_lease(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag, terminal_gate as tg
    world, state = _recovery_world(monkeypatch)
    events = [{"kind": "host-recovery", "reference": {"job_id": 95}}]
    world.next_event = lambda window: events.pop(0)
    outcome = _loop(world)
    record = world.store.get()[0]
    assert outcome["kind"] == "failed-closed-quiescent" and outcome["promotion_status"] == "failed"
    assert record["status"] == "released" and record["lifecycle"]["stage"] == "recovery"
    assert world.handoffs == [{}, {"job": tg.HOST_RECOVERY_JOB, "artifact": tg.HOST_RECOVERY_ARTIFACT}, {}]
    assert [call[:2] for call in world.terminal.calls] == [("rollback-api-static", "recovery"), ("reopen", "recovery"),
                                                         ("terminal-readback", "recovery")]
    rollback, reopen, readback = (call[3] for call in world.terminal.calls)
    assert rollback["recovery-decision"] == readback["decision"] == state["recovery-decision"]
    assert rollback["host-recovery-receipt"] == world.handoff_raws[0] == state["host-recovery-receipt"]
    assert rollback["publication"] == b"null" and set(reopen) == {"activation", "routing", "canaries", "membership"}
    assert reopen["canaries"] == b"null" and reopen["membership"] == readback["membership"]
    assert reopen["activation"] == state["activation"] and world.terminal.sources == []
    assert reopen["routing"] == c.canonical({mode: state["revisions"][mode] for mode in ("unit", "recovery", "audit")})
    assert readback["static-receipt"] == world.terminal.raws["rollback-api-static"]
    _product_stage_rule(readback, "recovery")
    _product_admission(world)
    assert readback["routing"] == world.terminal.raws["reopen"] and readback["host-receipt"] == world.handoff_raws[1]
    files = {key.rsplit("/", 1)[1]: raw for key, raw in world.evidence.objects.items()}
    result = ag.verify_terminal_bundle(files, record)
    assert result["terminal"]["promotion_status"] == "failed" and result["terminal"]["assessment"]["fence"] == "CLOSED"
    assert result["terminal"]["assessment"]["restoration"] == {"unit": True, "recovery": True, "audit": True, "api": True,
                                                               "static": True, "first_static_absent": False}
    assert set(result["checkpoint"]["inputs"]) == {"decision", "restoration", "routing", "membership", "quiescence"}


def _later_f(decision):
    return decision | {"fixed_deadline": c.utc(int(c.instant(decision["fixed_deadline"])) + 100)}


BOUND = "^host-recovery rolled_back bound to the keeper decision$"


@pytest.mark.parametrize("rolled_back, message", [
    (lambda ready, decision: _handoff("recovery_required", _decision(choice_at=1200, deadline=1620, fixed=1620),
                                      closed_ready_sha256=ready), "^host recovery decision binding$"),
    (lambda ready, decision: _handoff("rolled_back", _decision(choice_at=1199), closed_ready_sha256=ready),
     "^host recovery decision binding$"),
    (lambda ready, decision: _handoff("rolled_back", None, closed_ready_sha256=ready), "^closed object fields$"),
    (lambda ready, decision: _handoff("rolled_back", decision, closed_ready_sha256="9" * 64), BOUND),
    (lambda ready, decision: _handoff("rolled_back", decision | {"checkpoint_sha256": "4" * 64}, closed_ready_sha256=ready),
     BOUND),
    (lambda ready, decision: _handoff("rolled_back", _later_f(decision), closed_ready_sha256=ready),
     "^host recovery decision binding$")],
    ids=["recovery-required", "choice-at", "decision-null", "closed-ready", "checkpoint-sha256", "fixed-deadline"])
def test_host_recovery_sem_rolled_back_amarrado_a_decisao_mantem_o_lease(monkeypatch, rolled_back, message):
    world, _ = _recovery_world(monkeypatch, rolled_back=rolled_back)
    world.next_event = lambda window: {"kind": "host-recovery", "reference": {"job_id": 95}}
    with pytest.raises(ValueError, match=message):
        _loop(world)
    assert world.store.get()[0]["status"] == "held" and world.terminal.calls == [] and world.evidence.objects == {}


@pytest.mark.parametrize("attempt", [
    {"_observations": [{"kind": "publication", "sha256": "1" * 64, "size": 1}]},
    {"_inflight": {"kind": "sdk-call"}},
    {"pending": [{"kind": "sdk-call", "reference_sha256": "f" * 64}]},
    {"unknown": [{"kind": "sdk-call", "reference_sha256": "e" * 64}]}])
def test_host_recovery_recusa_publication_nula_com_tentativa_de_publish_static_no_journal(monkeypatch, attempt):
    world, _ = _recovery_world(monkeypatch)
    journal = SimpleNamespace(_request={"operation": "publish-static"}, _observations=[], _observation_bytes={},
                              _failed=False, _inflight=None, pending=[], unknown=[])
    world.keeper._contexts.append(SimpleNamespace(**vars(journal) | attempt))
    world.next_event = lambda window: {"kind": "host-recovery", "reference": {"job_id": 95}}
    with pytest.raises(ValueError, match="^rollback publication null with a publish-static attempt$"):
        _loop(world)
    assert world.handoffs == [{}] and world.terminal.calls == [] and world.terminal.capabilities == []
    assert world.store.get()[0]["status"] == "held" and world.evidence.objects == {}


def test_falha_da_publicacao_depois_do_release_propaga_a_recusa_original(monkeypatch):
    world, _ = _recovery_world(monkeypatch)
    world.next_event = lambda window: {"kind": "host-recovery", "reference": {"job_id": 95}}

    def refused(bucket, key, raw):
        raise ValueError("evidence put refused")
    world.evidence.put = refused
    with pytest.raises(ValueError, match="^evidence put refused$"):
        _loop(world)
    assert world.store.get()[0]["status"] == "released" and world.evidence.objects == {}


def test_recovery_sem_host_recovery_ate_o_prazo_do_estagio_para_com_o_lease_retido(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag
    world, _ = _recovery_world(monkeypatch)
    deadline = world.store.get()[0]["lifecycle"]["deadline"]
    polled = []
    world.next_event = lambda window: polled.append(world.clock.value)

    def sleep(seconds):
        world.clock.value += seconds
        if world.clock.value > deadline + 60:
            pytest.fail("keeper loop kept polling past the recovery stage deadline")

    with pytest.raises(ValueError, match="^recovery stage deadline elapsed without host-recovery$"):
        ag.keeper_loop(world.keeper, next_event=world.next_event, handlers=world.loop_handlers, terminal=world.steps,
                       sleep=sleep)
    assert polled and max(polled) < deadline <= world.clock.value
    assert world.store.get()[0]["status"] == "held" and world.store.get()[0]["lifecycle"]["stage"] == "recovery"
    assert world.handoffs == [{}] and world.terminal.calls == [] and world.evidence.objects == {}


@pytest.mark.parametrize(("stage", "extra", "accepted"), [
    ("recovery", {}, False),
    ("recovery", {"canaries": b"null"}, False),
    ("recovery", {"canaries": b"null", "membership": b"{}"}, True),
    ("final", {}, False),
    ("final", {"canaries": b"[]", "membership": b"{}"}, True)])
def test_contrato_do_reopen_exige_os_quatro_insumos_do_produto_em_final_e_recovery(monkeypatch, stage, extra, accepted):
    from tools.cnesdata_delivery import application_gate as ag
    world, state = _recovery_world(monkeypatch)
    record = world.store.get()[0]
    owner, window = lc.owner_binding(record), record["lifecycle"] | {"stage": stage}
    inputs = {"activation": state["activation"], "routing": c.canonical({"unit": "u", "recovery": "r", "audit": "a"})} | extra
    raw = ag._operation_request("reopen", owner=owner, window=window, inputs=inputs)
    if accepted:
        lc.validate_adapter_request(raw, operation="reopen", owner=owner, window=window, inputs=inputs,
                                    activation_sha256=c.sha(state["activation"]))
        return
    with pytest.raises(ValueError):
        lc.validate_adapter_request(raw, operation="reopen", owner=owner, window=window, inputs=inputs,
                                    activation_sha256=c.sha(state["activation"]))


@pytest.mark.parametrize("extra", [{}, {"canaries": b"null"}, {"membership": b"{}"}])
def test_reopen_do_recovery_recusa_insumos_incompletos_antes_do_journal(monkeypatch, extra):
    from tools.cnesdata_delivery import terminal_gate as tg
    world, state = _recovery_world(monkeypatch)
    before = list(world.keeper._contexts)
    inputs = {"activation": state["activation"], "routing": c.canonical({"unit": "u", "recovery": "r", "audit": "a"})} | extra
    with pytest.raises(ValueError):
        tg.run_terminal_operation(world.keeper, "reopen", inputs=inputs, activation=state["activation"],
                                  invoke=lambda **kwargs: pytest.fail("no child"), credential_limit=6000, clock=world.clock)
    assert world.keeper._contexts == before and world.terminal.capabilities == []


def test_ponta_a_ponta_fecha_failed_prepare_quiescent_e_libera_o_lease(monkeypatch):
    from test_cnesdata_stage_events import PREPARED_REFERENCE, _stage_world
    from tools.cnesdata_delivery import application_gate as ag
    state = _shared_state(monkeypatch)
    world = _stage_world(monkeypatch, manifest={"activation_sha256": "0" * 64})
    _terminal_fakes(monkeypatch, world, state)
    world.next_event = lambda window: {"kind": "prepared", "reference": dict(PREPARED_REFERENCE)}
    outcome = _loop(world)
    record = world.store.get()[0]
    assert outcome["kind"] == "failed-prepare-quiescent" and outcome["promotion_status"] == "failed"
    assert record["status"] == "released" and record["lifecycle"]["sequence"] == 1
    assert [call[:2] for call in world.terminal.calls] == [("terminal-readback", "application-prepare")]
    (readback,) = (call[3] for call in world.terminal.calls)
    assert {name: raw for name, raw in readback.items() if name != "membership"} == {
        name: b"null" for name in ("routing", "host-receipt", "static-receipt", "decision")}
    assert c.loads(readback["membership"], canonical=True) == {"frozen_membership_sha256": c.sha(c.canonical([])), "members": []}
    _product_stage_rule(readback, "application-prepare")
    _product_admission(world)
    files = {key.rsplit("/", 1)[1]: raw for key, raw in world.evidence.objects.items()}
    result = ag.verify_terminal_bundle(files, record)
    assert result["terminal"]["assessment"]["fence"] is None and result["terminal"]["assessment"]["routes_match"] is None
    assert set(result["checkpoint"]["inputs"]) == {"restoration", "quiescence"}


def test_failed_prepare_com_journal_incerto_mantem_o_lease_retido(monkeypatch):
    from test_cnesdata_stage_events import PREPARED_REFERENCE, _stage_world
    state = _shared_state(monkeypatch)
    world = _stage_world(monkeypatch, pending=True)
    _terminal_fakes(monkeypatch, world, state)
    world.next_event = lambda window: {"kind": "prepared", "reference": dict(PREPARED_REFERENCE)}
    with pytest.raises(ValueError, match="^close-drain single observation without uncertainty$"):
        _loop(world)
    assert world.store.get()[0]["status"] == "held" and world.evidence.objects == {}


def test_failed_prepare_recusa_janela_do_prepare_fora_da_sequencia_zero(monkeypatch):
    from test_cnesdata_stage_events import _stage_world
    state = _shared_state(monkeypatch)
    world = _stage_world(monkeypatch)
    _terminal_fakes(monkeypatch, world, state)
    value, etag = world.store.get()
    assert value["lifecycle"]["stage"] == "application-prepare" and value["lifecycle"]["close"] is None
    world.keeper.lease.etag = world.store.put(value | {"lifecycle": value["lifecycle"] | {"sequence": 1}}, etag)
    with pytest.raises(ValueError, match="^failed prepare window$"):
        world.steps.prepare_failure(world.keeper, ValueError("prepared refused"))
    assert world.terminal.calls == [] and world.store.get()[0]["status"] == "held" and world.evidence.objects == {}


def _successor(world, *, mutation=None):
    """The published terminal read back as the next run reads it: public index, private bytes, then the CAS acquire."""
    from tools.cnesdata_delivery import application_gate as ag
    from tools.cnesdata_delivery.coordination_lease import Lease
    record = world.store.get()[0]
    owner = lc.owner_binding(record)
    name, members = world.uploads[-1]
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("index.json", members["index.json"])
    raw_zip = out.getvalue()
    governance = world.steps.governance | {"gate_shas": {"application": "a" * 40},
                                           "lifecycle_terminal_job": "application / execute"}
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"], "head_sha": owner["source_sha"], "status": "completed",
           "conclusion": "success", "head_branch": "main", "event": "workflow_dispatch",
           "repository": {"full_name": c.REPOSITORY}, "path": ".github/workflows/promote-production.yml",
           "referenced_workflows": [{"path": "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-application-gate.yml@"
                                     + "a" * 40, "sha": "a" * 40, "ref": "refs/heads/main"}]}
    job = {"id": 9, "run_id": owner["run_id"], "run_attempt": owner["run_attempt"], "head_sha": owner["source_sha"],
           "name": "application / execute", "status": "completed", "conclusion": "success",
           "started_at": c.utc(900), "completed_at": c.utc(9000)}
    metadata = {"id": 4, "name": name, "digest": "sha256:" + c.sha(raw_zip),
                "workflow_run": {"id": owner["run_id"], "head_sha": owner["source_sha"]}, "expired": False,
                "expires_at": c.utc(9000000000), "created_at": c.utc(1001)}

    class API:
        def read(self, path, **kwargs):
            if path.endswith("/zip"): return raw_zip
            if "/artifacts/" in path: return metadata
            if "artifacts?" in path: return {"total_count": 1, "artifacts": [metadata]}
            if "jobs?" in path: return {"total_count": 1, "jobs": [job]}
            if "/jobs/" in path: return job
            return run
    if mutation is not None:
        key = next(key for key in world.evidence.objects if key.endswith("/lease.json"))
        evidence = c.loads(world.evidence.objects[key], canonical=True)
        mutation(evidence)
        world.evidence.objects[key] = c.canonical(evidence)
        index = c.loads(members["index.json"], canonical=True)
        for entry in index["files"]:
            if entry["name"] == "lease.json":
                entry.update(sha256=c.sha(world.evidence.objects[key]), size=len(world.evidence.objects[key]))
        members = {"index.json": c.canonical(index)}
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as archive:
            archive.writestr("index.json", members["index.json"])
        raw_zip = out.getvalue()
        metadata["digest"] = "sha256:" + c.sha(raw_zip)
    binding = {key: record[key] for key in ("repository", "source_sha", "session_sha256", "release_sha256", "lifecycle_version",
                                            "application_purpose", "context_kind", "caller_binding_sha256")}
    binding |= {"run_id": owner["run_id"] + 1, "run_attempt": 1}
    seen = []

    def previous_success(previous):
        seen.append(ag.previous_terminal(world.evidence, API(), governance, previous))
        return True
    return Lease(world.store, binding, previous_success=previous_success, clock=lambda: 9000), seen


def test_acquire_seguinte_autentica_o_terminal_aceito_lido_de_volta(monkeypatch):
    world, _ = _accepted_world(monkeypatch)
    world.next_event = lambda window: pytest.fail("no event at final")
    _loop(world)
    released = world.store.get()[0]
    lease, seen = _successor(world)
    lease.acquire()
    (result,) = seen
    assert result["terminal"]["promotion_status"] == "accepted" and result["checkpoint"]["owner"] == lc.owner_binding(released)
    record = world.store.get()[0]
    assert record["status"] == "held" and record["generation"] == released["generation"] + 1


def test_acquire_seguinte_recusa_o_terminal_falho_sem_recuperacao_revisada(monkeypatch):
    world, _ = _recovery_world(monkeypatch)
    events = [{"kind": "host-recovery", "reference": {"job_id": 95}}]
    world.next_event = lambda window: events.pop(0)
    _loop(world)
    before = world.store.get()
    lease, _ = _successor(world)
    with pytest.raises(ValueError, match="failed terminal requires exact reviewed recovery acceptance"):
        lease.acquire()
    assert world.store.get() == before


def _swap_checkpoints(evidence):
    first, second = evidence["checkpoints"][-3], evidence["checkpoints"][-2]
    for field in ("previous_etag_sha256", "etag_sha256"):
        first[field], second[field] = second[field], first[field]


def _fork_checkpoint(evidence):
    evidence["checkpoints"][-1]["previous_etag_sha256"] = evidence["checkpoints"][-2]["previous_etag_sha256"]


@pytest.mark.parametrize("mutation", [_swap_checkpoints, _fork_checkpoint])
def test_cadeia_de_etag_fora_de_ordem_recusa_o_acquire_seguinte(monkeypatch, mutation):
    world, _ = _accepted_world(monkeypatch)
    world.next_event = lambda window: pytest.fail("no event at final")
    _loop(world)
    before = world.store.get()
    lease, _ = _successor(world, mutation=mutation)
    with pytest.raises(ValueError, match="^CAS "):
        lease.acquire()
    assert world.store.get() == before


def test_stage_event_source_emite_host_recovery_no_estagio_recovery():
    from test_cnesdata_stage_events import _GitHub, _Guard, RUN
    from tools.cnesdata_delivery import application_gate as ag, terminal_gate as tg
    api = _GitHub(tg.HOST_RECOVERY_JOB, "host-recovery")
    keeper = SimpleNamespace(static_inventory=b"settled")
    source = ag.stage_event_source(api=api, governance={}, run=dict(RUN), owner={}, guard=_Guard(), keeper=keeper,
                                   clock=lambda: 1300)
    event = source(_recovery_window() | {"deadline": 1400})
    assert event == {"kind": "host-recovery", "reference": {"job_id": api.reference["job_id"]}}


@pytest.mark.parametrize("window", [_recovery_window() | {"decision": None},
                                    {**_recovery_window(), "stage": "api", "decision": {"choice_at": 1100}}])
def test_stage_event_source_so_aceita_decisao_no_estagio_recovery(window):
    from test_cnesdata_stage_events import _GitHub, _Guard, RUN
    from tools.cnesdata_delivery import application_gate as ag, terminal_gate as tg
    api = _GitHub(tg.HOST_RECOVERY_JOB, "host-recovery")
    source = ag.stage_event_source(api=api, governance={}, run=dict(RUN), owner={}, guard=_Guard(),
                                   keeper=SimpleNamespace(static_inventory=b"settled"), clock=lambda: 1300)
    with pytest.raises(ValueError, match="stage trigger not connected"):
        source(window)
    assert api.reads == []


def test_execute_devolve_o_resultado_do_loop_com_o_host_recovery_e_o_terminal(monkeypatch):
    from test_cnesdata_application_gate import _execute_case
    from tools.cnesdata_delivery import application_gate as ag, terminal_gate as tg
    ag_mod, admitted, calls, world = _execute_case(monkeypatch)
    loops = []

    def loop(keeper, **kwargs):
        loops.append(kwargs)
        return {"kind": "accepted-open", "promotion_status": "accepted", "receipt": {"id": 1}}
    monkeypatch.setattr(ag, "keeper_loop", loop)
    validators = {"quiescence": ("q", object()), "routing": ("r", object())}
    outcome = ag.execute(admitted, validators=validators, event_source=lambda **kwargs: "next-event", product="product")
    assert outcome == {"kind": "accepted-open", "promotion_status": "accepted", "receipt": {"id": 1}}
    (kwargs,) = loops
    assert set(kwargs["handlers"]) == {"prepared", "phase-b", "host", "host-recovery"}
    assert type(kwargs["terminal"]) is tg.TerminalSteps and kwargs["handlers"]["host-recovery"] == kwargs["terminal"].host_recovery
    handler_kwargs = next(kw for name, _, kw in calls if name == "handlers")
    assert handler_kwargs["state"] is kwargs["terminal"].state
    context = kwargs["terminal"].context
    assert type(context) is tg.TerminalContext and context.state is handler_kwargs["state"]
    assert context.authority is handler_kwargs["authority"] and context.operation_session is handler_kwargs["operation_session"]
    assert (context.governance, context.credential_limit) == (handler_kwargs["governance"], handler_kwargs["credential_limit"])


def test_operacoes_terminais_rodam_sob_o_journal_do_keeper_com_a_capability_antes_do_child(monkeypatch):
    world, _ = _accepted_world(monkeypatch)
    order = []
    from tools.cnesdata_delivery import application_gate as ag, terminal_gate as tg
    invoke, capability = ag.invoke_adapter, tg.terminal_capability
    monkeypatch.setattr(ag, "invoke_adapter", lambda **kwargs: order.append("child") or invoke(**kwargs))
    monkeypatch.setattr(tg, "terminal_capability", lambda **kwargs: order.append("capability") or capability(**kwargs))
    world.next_event = lambda window: pytest.fail("no event at final")
    _loop(world)
    assert order == ["capability", "child", "capability", "child"]


@pytest.mark.parametrize("revisions", [
    {"unit": "u", "recovery": "r"},
    {"unit": "u", "recovery": "r", "audit": "a", "extra": "x"},
    {"unit": "u", "recovery": None, "audit": "a"}])
def test_routing_do_recovery_recusa_revisoes_fora_da_projecao_fechada(monkeypatch, revisions):
    world, state = _recovery_world(monkeypatch)
    state["revisions"] = revisions
    world.next_event = lambda window: {"kind": "host-recovery", "reference": {"job_id": 95}}
    with pytest.raises(ValueError, match="^terminal recovery routing revisions$"):
        _loop(world)
    assert world.terminal.calls == [] and world.terminal.sources == [] and world.handoffs == [{}]
    assert world.store.get()[0]["status"] == "held" and world.evidence.objects == {}


def test_operacao_terminal_exige_uma_observacao_e_nenhuma_incerteza(monkeypatch):
    world, _ = _accepted_world(monkeypatch, **{"terminal-readback": {}})
    from tools.cnesdata_delivery import application_gate as ag
    invoke = ag.invoke_adapter

    def twice(**kwargs):
        invoke(**kwargs)
        journal = kwargs["journal"]
        if journal._request["operation"] == "reopen":
            journal._observations.append(copy.deepcopy(journal._observations[-1]))
    monkeypatch.setattr(ag, "invoke_adapter", twice)
    world.next_event = lambda window: pytest.fail("no event at final")
    with pytest.raises(ValueError, match="reopen single observation without uncertainty"):
        _loop(world)
    assert world.store.get()[0]["status"] == "held"
