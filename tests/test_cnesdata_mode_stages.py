"""P16: mode adapter operations, DD-4 unit/recovery/audit validators and the post-static stage triggers."""
import inspect
import json

import pytest

from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

PRODUCT_MODE_ORIGIN = {
    "commit": "06849119a24e33e2b847a9d3d1bab2d76a8cf2fa",
    "scripts/promotion/_adapter_abi.py": "1b0fd24e1e77776db0ccb4a99a513b37d8403c063730512fed51206454903386",
    "scripts/promotion/promote_api.py": "b13f4c2d7cf1e3e207bb98c4eca871ed9c5445b4ee38131f6ac2e6ceac49ae5f",
    "scripts/promotion/promote_mode.py": "34e1db60928ee96480a9164a384ff070df74eed4f886e7f597a3c2af49888515",
    "scripts/promotion/promote_mode_effects.py": "d08e4b73fa9a317f82e3fb4edebe55ab9fb803cab23cd6443bd2e6ce2bc19b48",
    "scripts/promotion/promote_mode_record.py": "743814d1ad84669d597a692bd8194ec350496e98a83e8cdfc6410189fb57aa7c"}
VENDORED_MODE_SHA256 = "f64ff5b13871f32de0f9c443ff73480d6b6f1cdfabbacca499a2aaf5e013eadb"
MODES = ("unit", "recovery", "audit")
MODE_STAGE = {"unit": "unit", "recovery": "phase-c-recovery", "audit": "phase-c-audit"}
MODE_WINDOWS = {"unit": (1720, 1900), "phase-c-recovery": (1900, 2230), "phase-c-audit": (2230, 2560)}


def _product_mode_abi():
    """Vendored from CnesData P16c 06849119: _adapter_abi MODE_OPERATIONS, MODE_INPUTS, MODE_OBSERVATIONS,
    MODE_OBSERVATION_FIELDS, MODE_EFFECT_CALLS/STEPS/METHODS, the promote_api handler module of each operation
    (promote_mode, promote_mode_effects, promote_mode_record), promote_mode_effects.SDK_OPERATIONS and
    promote_mode._observation."""
    operations = {
        "unit-seed": ("unit", "unit"), "unit-start": ("unit", "unit"), "unit-observe": ("unit", "unit"),
        "recovery-seed": ("recovery", "phase-c-recovery"), "recovery-start": ("recovery", "phase-c-recovery"),
        "recovery-observe": ("recovery", "phase-c-recovery"),
        "audit-start": ("audit", "phase-c-audit"), "audit-observe": ("audit", "phase-c-audit"),
        "unit-record": ("unit", "unit"), "recovery-record": ("recovery", "phase-c-recovery"),
        "audit-record": ("audit", "phase-c-audit")}
    scheduled = frozenset({"activation", "network", "close-drain", "phase-b", "phase-c", "mode-result", "readbacks"})
    seed = frozenset({"record", "mode-start", "fixture-manifest", "fixture-cnes-local", "fixture-cnes-nacional"})
    start = frozenset({"record", "readbacks", "previous", "mode-seed", "mode-start"})
    record = frozenset({"activation", "close-drain", "fixture-manifest", "mode-input"})
    inputs = {"unit-seed": seed, "recovery-seed": seed, "unit-start": start, "recovery-start": start,
              "audit-start": start | {"audit-event-ids"},
              "unit-observe": frozenset({"activation", "close-drain", "record", "mode-result", "readbacks", "observed"}),
              "recovery-observe": scheduled, "audit-observe": scheduled | {"recovery-result", "recovery-readbacks"},
              "unit-record": record, "recovery-record": record, "audit-record": record | {"mode-seed"}}
    artifacts = {"seed": "mode-seed", "start": "mode-result", "record": "mode-record"}
    observations = {name: artifacts.get(name.rsplit("-", 1)[1], "mode") for name in operations}
    fields = frozenset({"version", "kind", "accepted", "checks", "commitments"})
    handlers = {name: "promote_mode" if name.endswith("-observe") else "promote_mode_record" if name.endswith("-record")
                else "promote_mode_effects" for name in operations}
    seed_calls = frozenset({("mode_seed", "dynamodb", "put_item"), ("mode_seed", "dynamodb", "get_item"),
                            ("mode_seed", "s3", "put_object"), ("mode_seed", "s3", "get_object")})
    calls = {"unit-seed": seed_calls, "recovery-seed": seed_calls, "unit-start": frozenset(),
             "recovery-start": frozenset({("mode_dispatch", "ecs", "run_task"), ("mode_dispatch", "ecs", "describe_tasks")}),
             "audit-start": frozenset({("mode_audit_launch", "ecs", "run_task"),
                                       ("mode_audit_launch", "ecs", "describe_tasks")})}
    steps = {"unit-seed": frozenset(), "recovery-seed": frozenset(),
             "unit-start": frozenset({"unit-execution", "unit-task", "unit-output"}),
             "recovery-start": frozenset({"recovery-task"}), "audit-start": frozenset({"audit-task"})}
    methods = {"unit-seed": frozenset(), "recovery-seed": frozenset(),
               "unit-start": frozenset({"dispatch_unit", "mode_readbacks"}),
               "recovery-start": frozenset({"ledger_admit_effect", "ledger_mark_unknown", "ledger_settle", "mode_readbacks"}),
               "audit-start": frozenset({"mode_readbacks"})}
    sdk = {"dynamodb:PutItem": ("dynamodb", "put_item"), "dynamodb:GetItem": ("dynamodb", "get_item"),
           "s3:PutObject": ("s3", "put_object"), "s3:GetObject": ("s3", "get_object"),
           "ecs:RunTask": ("ecs", "run_task"), "ecs:DescribeTasks": ("ecs", "describe_tasks")}

    def canonical(value):
        return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")

    def observation(kind, checks, request, originals):
        commitments = {"owner": request["owner"]["owner_sha256"]}
        commitments |= {name: c.sha(raw) for name, raw in originals.items()}
        return canonical({"version": 1, "kind": kind, "accepted": not checks, "checks": sorted(checks),
                          "commitments": commitments})
    return {"operations": operations, "inputs": inputs, "observations": observations, "fields": fields,
            "observation": observation, "handlers": handlers, "calls": calls, "steps": steps, "methods": methods,
            "sdk": sdk}


PRODUCT = _product_mode_abi()


def test_copia_vendorizada_do_abi_de_modo_so_muda_junto_com_a_origem_registrada():
    """infra-ansible CI cannot import CnesData: a refresh of the vendored tables updates its origin and this digest."""
    assert set(PRODUCT_MODE_ORIGIN) == {"commit", "scripts/promotion/_adapter_abi.py", "scripts/promotion/promote_api.py",
                                        "scripts/promotion/promote_mode.py", "scripts/promotion/promote_mode_effects.py",
                                        "scripts/promotion/promote_mode_record.py"}
    assert c.sha(inspect.getsource(_product_mode_abi).encode()) == VENDORED_MODE_SHA256


@pytest.mark.parametrize("operation", sorted(PRODUCT["operations"]))
def test_tabelas_de_adapter_do_keeper_batem_com_o_abi_de_modo_do_produto(operation):
    assert set(lc.ADAPTER_INPUTS[operation].split()) == PRODUCT["inputs"][operation]
    assert lc.ADAPTER_STAGES[operation] == {PRODUCT["operations"][operation][1]}
    assert lc.ADAPTER_OBSERVATIONS[operation] == PRODUCT["observations"][operation]


def test_as_onze_operacoes_de_modo_do_produto_tem_handler_e_tabelas_completas_no_keeper():
    mode = {name for name in lc.ADAPTER_INPUTS if name in PRODUCT["operations"]}
    assert mode == set(PRODUCT["operations"]) == set(PRODUCT["handlers"]) and len(mode) == 11
    assert {name for name, module in PRODUCT["handlers"].items() if module == "promote_mode_record"} == {
        "unit-record", "recovery-record", "audit-record"}
    assert {name for name, module in PRODUCT["handlers"].items() if module == "promote_mode_effects"} == set(PRODUCT["calls"])
    assert set(PRODUCT["calls"]) == set(PRODUCT["steps"]) == set(PRODUCT["methods"])
    assert all(name in lc.ADAPTER_STAGES and name in lc.ADAPTER_OBSERVATIONS for name in mode)


@pytest.mark.parametrize("operation", sorted(PRODUCT["calls"]))
def test_chamadas_sdk_de_cada_efeito_do_produto_usam_so_a_sessao_de_promotion_do_keeper(operation):
    _, alias, context, _ = lc.MODE_SESSION_OPERATIONS[operation]
    assert context == "promotion"
    assert {call[0] for call in PRODUCT["calls"][operation]} <= {alias}
    assert {call[1:] for call in PRODUCT["calls"][operation]} <= set(PRODUCT["sdk"].values())


def test_oito_sessoes_de_promotion_sao_as_operacoes_de_modo_do_produto_com_sdk_e_os_records_puros_nao_tem_sessao():
    from fixtures.cnesdata_delivery_lifecycle import MODE_SESSION_VECTORS
    promotion = {name: phase for name, (_, _, context, phase) in lc.MODE_SESSION_OPERATIONS.items() if context == "promotion"}
    assert promotion == {name: mode for name, (mode, _) in PRODUCT["operations"].items() if not name.endswith("-record")}
    assert len(promotion) == 8 and not {name for name in lc.MODE_SESSION_OPERATIONS if name.endswith("-record")}
    vectors = {vector["operation"]: vector for vector in MODE_SESSION_VECTORS if vector["operation"] in promotion}
    assert set(vectors) == set(promotion)
    for name, vector in vectors.items():
        assert lc.mode_session(vector["binding"], "promotion")["session_name"] == vector["session_name"]
        assert vector["binding"]["phase"] == promotion[name]


def _mode_case(operation, *, stage=None):
    from test_cnesdata_application_gate import _adapter_case
    request, owner, window, _ = _adapter_case("closed-ready")
    start, deadline = MODE_WINDOWS[stage or PRODUCT["operations"][operation][1]]
    window.update(stage=stage or PRODUCT["operations"][operation][1], admitted_at=start, deadline=deadline)
    inputs = {name: c.canonical({"fixture_only": name}) for name in sorted(PRODUCT["inputs"][operation])}
    request |= {"operation": operation,
                "stage": {key: value for key, value in window.items() if key not in lc.application_identity(owner)},
                "inputs": {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in inputs.items()}}
    return request, owner, window, inputs


def _validate_request(request, owner, window, inputs):
    return lc.validate_adapter_request(c.canonical(request), operation=request["operation"], owner=owner, window=window,
                                       inputs=inputs, activation_sha256=request["activation_sha256"])


@pytest.mark.parametrize("operation", sorted(PRODUCT["operations"]))
def test_request_de_modo_e_aceito_so_no_estagio_do_proprio_modo(operation):
    request, owner, window, inputs = _mode_case(operation)
    assert _validate_request(request, owner, window, inputs) == request
    other = next(stage for stage in MODE_WINDOWS if stage != window["stage"])
    request, owner, window, inputs = _mode_case(operation, stage=other)
    with pytest.raises(ValueError, match="^adapter original stage$"):
        _validate_request(request, owner, window, inputs)


def _mode_journal(mode, *, checks=(), change=None):
    from tools.cnesdata_delivery.application_gate import AdapterJournal
    request, owner, window, inputs = _mode_case(mode + "-observe")

    class Guard:
        def check(self, seconds=0):
            return None
    journal = AdapterJournal(c.canonical(request), operation=request["operation"], owner=owner, window=window,
                             inputs=inputs, activation_sha256=request["activation_sha256"], guard=Guard())
    raw = PRODUCT["observation"](mode, list(checks), request, inputs)
    if change is not None:
        value = json.loads(raw)
        change(value)
        raw = c.canonical(value)
    journal.observe("mode", raw)
    return journal, owner, raw


def _keeper(*journals):
    from test_cnesdata_application_gate import _accepted_terminal_case
    keeper, _ = _accepted_terminal_case()
    for journal in journals:
        keeper.attach(journal)
    return keeper


def _mode_validator(keeper, mode):
    from tools.cnesdata_delivery import application_gate as ag
    return ag.TERMINAL_VALIDATORS[mode][1](keeper)


@pytest.mark.parametrize("mode", MODES)
def test_validador_de_modo_aceita_so_a_observacao_original_do_journal_do_observe(mode):
    journal, owner, raw = _mode_journal(mode)
    source = {"mode": c.sha(raw)}
    result = _mode_validator(_keeper(journal), mode)(source, owner=owner, window={"stage": "final"}, observations={})
    assert result == {"sha256": c.sha(c.canonical(source)), "facts": {"accepted": True}}


@pytest.mark.parametrize("mode", MODES)
def test_validador_de_modo_reporta_a_recusa_do_produto_sem_inventar_aceite(mode):
    journal, owner, raw = _mode_journal(mode, checks=["canary=schema"])
    result = _mode_validator(_keeper(journal), mode)({"mode": c.sha(raw)}, owner=owner, window={}, observations={})
    assert result["facts"] == {"accepted": False}


def test_cada_modo_le_o_proprio_journal_embora_os_tres_observes_tenham_o_mesmo_kind():
    found = {mode: _mode_journal(mode) for mode in MODES}
    keeper = _keeper(*(journal for journal, _, _ in found.values()))
    latest = keeper._latest_observation_bytes()
    assert [c.sha(raw) for _, _, raw in found.values() if c.sha(raw) in latest] == [c.sha(found["audit"][2])]
    for mode, (_, owner, raw) in found.items():
        facts = _mode_validator(keeper, mode)({"mode": c.sha(raw)}, owner=owner, window={}, observations=latest)["facts"]
        assert facts == {"accepted": True}


def _drop_input(value):
    value["commitments"].pop("readbacks")


MUTATIONS = {
    "extra-field": (lambda v: v.update(freeze=True), "^closed object fields$"),
    "missing-field": (lambda v: v.pop("checks"), "^closed object fields$"),
    "version-bool": (lambda v: v.update(version=True), "^terminal source kind=unit$"),
    "version-2": (lambda v: v.update(version=2), "^terminal source kind=unit$"),
    "other-mode": (lambda v: v.update(kind="recovery"), "^terminal source kind=unit$"),
    "accepted-with-checks": (lambda v: v.update(checks=["canary=schema"]), "^terminal mode verdict$"),
    "refused-without-checks": (lambda v: v.update(accepted=False), "^terminal mode verdict$"),
    "accepted-type": (lambda v: v.update(accepted="true", checks=[]), "^terminal mode verdict$"),
    "checks-unsorted": (lambda v: v.update(accepted=False, checks=["b", "a"]), "^terminal mode verdict$"),
    "checks-type": (lambda v: v.update(accepted=False, checks=[1]), "^terminal mode verdict$"),
    "commitment-input": (lambda v: v["commitments"].update(readbacks="0" * 64), "^terminal mode commitments$"),
    "commitment-missing": (_drop_input, "^terminal mode commitments$"),
    "commitment-extra": (lambda v: v["commitments"].update(foreign="0" * 64), "^terminal mode commitments$"),
    "commitment-owner": (lambda v: v["commitments"].update(owner="0" * 64), "^terminal mode commitments$"),
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_validador_de_modo_recusa_observacao_fora_da_forma_ou_dos_compromissos(mutation):
    change, message = MUTATIONS[mutation]
    journal, owner, raw = _mode_journal("unit", change=change)
    with pytest.raises(ValueError, match=message):
        _mode_validator(_keeper(journal), "unit")({"mode": c.sha(raw)}, owner=owner, window={}, observations={})


@pytest.mark.parametrize("case", ["no-journal", "two-journals", "other-bytes", "source-fields", "owner"])
def test_validador_de_modo_recusa_fonte_que_nao_e_o_original_unico_do_journal(case):
    journal, owner, raw = _mode_journal("unit")
    journals, source = [journal], {"mode": c.sha(raw)}
    if case == "no-journal":
        journals = [_mode_journal("recovery")[0]]
    if case == "two-journals":
        journals.append(_mode_journal("unit", checks=["canary=schema"])[0])
    if case == "other-bytes":
        source = {"mode": c.sha(raw + b" ")}
    if case == "source-fields":
        source |= {"extra": c.sha(raw)}
    if case == "owner":
        owner = owner | {"owner_sha256": "0" * 64}
    message = {"no-journal": "^terminal mode journal mode=unit$", "two-journals": "^terminal mode journal mode=unit$",
               "other-bytes": "^terminal mode source$", "source-fields": "^closed object fields$",
               "owner": "^terminal mode owner$"}[case]
    with pytest.raises(ValueError, match=message):
        _mode_validator(_keeper(*journals), "unit")(source, owner=owner, window={}, observations={})


def test_registro_de_producao_tem_os_validadores_de_modo_com_rotulo_do_produto():
    from tools.cnesdata_delivery import application_gate as ag
    assert {kind: ag.TERMINAL_VALIDATORS[kind][0] for kind in MODES} == {kind: "product-mode-" + kind for kind in MODES}
    assert {kind: ag.TERMINAL_SOURCE_ROLES[kind] for kind in MODES} == dict.fromkeys(MODES, "mode")


def _unit_window(**changes):
    from test_cnesdata_stage_events import _api
    static = lc.static_window(_api(), now=1350)
    return static | {"sequence": static["sequence"] + 1, "stage": "unit", "admitted_at": 1500,
                     "deadline": min(static["fixed_deadline"], 1500 + static["windows"]["stages"]["unit"])} | changes


def _recovery_window():
    return lc.mode_stage_window(_unit_window(), "phase-c-recovery", now=1600)


def _audit_window():
    return lc.mode_stage_window(_recovery_window(), "phase-c-audit", now=1800, checkpoint_sha256="8" * 64)


def test_tabela_de_gatilhos_tem_as_tres_linhas_do_dd3_depois_do_unit():
    assert {stage: lc.STAGE_TRIGGERS[stage] for stage in ("unit", "phase-c-recovery", "phase-c-audit")} == {
        "unit": ("unit", "phase-c-recovery"), "phase-c-recovery": ("phase-c-recovery", "phase-c-audit"),
        "phase-c-audit": ("phase-c-audit", "final")}
    assert lc.STAGE_TRIGGERS["static"] == ("publish-static", "unit") and "final" not in lc.STAGE_TRIGGERS


def test_janela_do_c_recovery_segue_o_unit_aceito_sem_mudar_o_checkpoint():
    unit = _unit_window()
    current = lc.mode_stage_window(dict(unit), "phase-c-recovery", now=1600.9)
    assert current == unit | {"sequence": unit["sequence"] + 1, "stage": "phase-c-recovery", "admitted_at": 1600,
                              "deadline": min(unit["fixed_deadline"], 1600 + unit["windows"]["stages"]["phase-c-recovery"])}
    lc.checkpoint_transition(unit, current)
    lc.phase_capacity(current, now=1600, credential_deadline=9000, operation_seconds=20)


@pytest.mark.parametrize("stage, previous, now", [("phase-c-audit", _recovery_window, 1800), ("final", _audit_window, 1990)])
def test_janelas_do_c_audit_e_do_final_levam_o_checkpoint_do_deploy_c_do_estagio_anterior(stage, previous, now):
    before = previous()
    current = lc.mode_stage_window(dict(before), stage, now=now, checkpoint_sha256="7" * 64)
    assert current == before | {"sequence": before["sequence"] + 1, "stage": stage, "admitted_at": now,
                                "checkpoint_sha256": "7" * 64,
                                "deadline": min(before["fixed_deadline"], now + before["windows"]["stages"][stage])}
    lc.checkpoint_transition(before, current)


def test_prazo_da_janela_de_modo_vem_do_vetor_governado_e_nao_de_constante():
    from test_cnesdata_application_gate import WINDOWS
    unit = _unit_window(windows=WINDOWS, fixed_deadline=9999)
    assert lc.mode_stage_window(unit, "phase-c-recovery", now=1600)["deadline"] == 1600 + 330
    assert lc.mode_stage_window(_unit_window(fixed_deadline=1700), "phase-c-recovery", now=1600)["deadline"] == 1700


@pytest.mark.parametrize("case, message", [
    ("stage-static", "^mode stage window stage=static$"), ("stage-recovery", "^mode stage window stage=recovery$"),
    ("skip", "^phase-c-audit follows the closed phase-c-recovery stage$"),
    ("open", "^phase-c-recovery follows the closed unit stage$"),
    ("decision", "^phase-c-recovery follows the closed unit stage$"),
    ("retreat", "^phase-c-recovery follows the closed unit stage$"),
    ("recovery-checkpoint", "^phase-c-recovery checkpoint$"), ("audit-no-checkpoint", "^phase-c-audit checkpoint$"),
    ("final-no-checkpoint", "^final checkpoint$"), ("checkpoint-digest", "^digest$")])
def test_janela_de_modo_recusa_salto_retrocesso_ou_checkpoint_fora_da_regra(case, message):
    unit = _unit_window()
    calls = {"stage-static": (unit, "static", {}), "stage-recovery": (unit, "recovery", {}),
             "skip": (unit, "phase-c-audit", {"checkpoint_sha256": "7" * 64}),
             "open": (unit | {"close": None}, "phase-c-recovery", {}),
             "decision": (unit | {"decision": {"choice_at": 1550}}, "phase-c-recovery", {}),
             "retreat": (unit | {"admitted_at": 1601}, "phase-c-recovery", {}),
             "recovery-checkpoint": (unit, "phase-c-recovery", {"checkpoint_sha256": "7" * 64}),
             "audit-no-checkpoint": (_recovery_window(), "phase-c-audit", {}),
             "final-no-checkpoint": (_audit_window(), "final", {}),
             "checkpoint-digest": (_recovery_window(), "phase-c-audit", {"checkpoint_sha256": "x"})}
    previous, stage, extra = calls[case]
    with pytest.raises(ValueError, match=message):
        lc.mode_stage_window(previous, stage, now=max(1600, _unit_window()["admitted_at"] if case == "retreat"
                                                      else previous["admitted_at"]), **extra)


C_STEPS = {}
for _purpose in ("phase-c-recovery", "phase-c-audit"):
    _common = {"purpose": _purpose, "direction": "advance", "mode": "initial"}
    C_STEPS |= {f"{_purpose}-plan": _common | {"role": "plan", "job_name": f"{_purpose}-plan / execute"},
                f"{_purpose}-audit": _common | {"role": "audit", "job_name": f"{_purpose}-audit / audit"},
                f"{_purpose}-deploy": _common | {"role": "deploy", "job_name": f"{_purpose} / execute"}}


def _c_governance(change=None):
    from test_cnesdata_stage_events import GOVERNANCE
    steps = dict(GOVERNANCE["lifecycle_steps"]) | {name: dict(step) for name, step in C_STEPS.items()}
    if change is not None:
        change(steps)
    return {"lifecycle_steps": steps}


def _c_source(api, governance):
    from types import SimpleNamespace

    from test_cnesdata_stage_events import OWNER, RUN, _Guard
    from tools.cnesdata_delivery import application_gate as ag
    return ag.stage_event_source(api=api, governance=governance, run=dict(RUN), owner=dict(OWNER), guard=_Guard(),
                                 keeper=SimpleNamespace(static_inventory=b"settled"), clock=lambda: 1300)


@pytest.mark.parametrize("stage", ["phase-c-recovery", "phase-c-audit"])
def test_evento_externo_do_c_e_o_deploy_advance_do_catalogo_com_a_publicacao_do_proprio_run(stage):
    from test_cnesdata_stage_events import _GitHub, _window
    api = _GitHub(f"{stage} / execute", f"{stage}-deploy")
    assert _c_source(api, _c_governance())(_window(stage)) == {"kind": stage, "reference": api.reference}


@pytest.mark.parametrize("change", ["absent", "two", "converge-only"])
def test_evento_do_c_recusa_catalogo_sem_um_unico_deploy_advance(change):
    from test_cnesdata_stage_events import _GitHub, _window

    def mutate(steps):
        deploy = steps.pop("phase-c-recovery-deploy")
        if change == "two":
            steps["phase-c-recovery-deploy"], steps["phase-c-recovery-again"] = deploy, dict(deploy)
        if change == "converge-only":
            steps["phase-c-recovery-converge"] = deploy | {"direction": "converge"}
    api = _GitHub("phase-c-recovery / execute", "phase-c-recovery-deploy")
    with pytest.raises(ValueError, match="^unique protected phase-c-recovery advance step$"):
        _c_source(api, _c_governance(mutate))(_window("phase-c-recovery"))
    assert api.reads == []


def test_gatilho_interno_do_unit_nao_e_evento_do_produtor():
    from test_cnesdata_stage_events import _GitHub, _window
    api = _GitHub("phase-c-recovery / execute", "phase-c-recovery-deploy")
    with pytest.raises(ValueError, match="^stage trigger not connected stage=unit$"):
        _c_source(api, _c_governance())(_window("unit"))
    assert api.reads == []


def test_eventos_do_keeper_sao_os_externos_da_tabela_de_gatilhos():
    from tools.cnesdata_delivery import application_gate as ag
    assert ag.KEEPER_EVENTS == ("observer-bootstrap", "prepared", "phase-b", "host", "phase-c-recovery", "phase-c-audit",
                                "host-recovery")
    assert {event for event, _ in lc.STAGE_TRIGGERS.values()} - set(ag.KEEPER_EVENTS) == {"publish-static", "unit"}


def _mode_world(monkeypatch, *, checks=None, capability=None, observations=1, pending=False, fail=False, late=False,
                brokers=None, steps=None, host=True):
    """The stage-events world through the host handler and its publish-static (P15 fakes) into the unit window, plus mode
    fakes: source, capability, child. With host, the unit mode run the host starts is recorded and the world stays in the
    unit window; without it, the caller runs the host with the real unit mode run over these fakes."""
    from types import SimpleNamespace

    from test_cnesdata_stage_events import HOST_REFERENCE
    from test_cnesdata_static_stage import _static_world
    from tools.cnesdata_delivery import application_gate as ag
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    real_stage = ag.mode_stage
    world = _static_world(monkeypatch, static={"unit": "stub" if host else "real"})
    if host:
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
        monkeypatch.setattr(ag, "mode_stage", real_stage)
    inner = ag.invoke_adapter
    world.mode = SimpleNamespace(calls=[], sources=[], capabilities=[], dropped=[], checks=checks or {},
                                 capability=capability, observations=observations, pending=pending, publications=[],
                                 fail=fail, late=late, brokers=brokers or {}, contexts=[], steps=steps or {},
                                 source_contexts=[])

    def invoke_adapter(**kwargs):
        journal = kwargs["journal"]
        operation = journal._request["operation"]
        if operation not in PRODUCT["operations"]:
            return inner(**kwargs)
        world.events.append(("child", operation))
        world.mode.calls.append((operation, kwargs["timeout"], world.clock.value, dict(journal._inputs)))
        if world.mode.fail is True or world.mode.fail == operation:
            raise ValueError("fixture child failed")
        kind = lc.ADAPTER_OBSERVATIONS[operation]
        mode = PRODUCT["operations"][operation][0]
        raw = (PRODUCT["observation"](mode, world.mode.checks.get(mode, []), journal._request, journal._inputs)
               if kind == "mode" else _record_observation(mode, journal._request) if kind == "mode-record"
               else c.canonical({"fixture_child": operation}))
        for step in world.mode.steps.get(operation, ()):
            body = c.canonical({"fixture_step": step, "ordinal": len(journal._observations)})
            journal._observations.append({"kind": step, "sha256": c.sha(body), "size": len(body)})
            journal._observation_bytes[c.sha(body)] = body
        for _ in range(world.mode.observations):
            journal._observations.append({"kind": kind, "sha256": c.sha(raw), "size": len(raw)})
        journal._observation_bytes[c.sha(raw)] = raw
        journal._pending = [{"kind": "sdk-call", "reference_sha256": "f" * 64}] if world.mode.pending else []
        world.clock.value += 5
        if world.mode.late and operation.endswith("-observe"):
            deadline = lc.terminal_deadline(_record(world))
            while world.clock.value < deadline:
                world.clock.value = min(deadline, world.clock.value + 25)
                world.keeper.tick()
    monkeypatch.setattr(ag, "invoke_adapter", invoke_adapter)

    def mode_input_source(*, keeper, owner, window, operation, names, context):
        assert type(context) is ag.ModeContext or context is None
        world.mode.source_contexts.append(context)
        world.events.append(("source", operation))
        world.mode.sources.append((operation, list(names), window["stage"]))
        return {name: c.canonical({"fixture_original": name, "operation": operation}) for name in names}
    monkeypatch.setattr(ag, "mode_input_source", mode_input_source)

    def mode_capability(*, journal, keeper, guard, context):
        assert guard is journal._guard
        world.mode.contexts.append(context)
        world.events.append(("capability", journal._request["operation"]))
        world.mode.capabilities.append(journal)
        if world.mode.capability is not None:
            journal._failed = True
            raise ValueError(world.mode.capability)
        operation = journal._request["operation"]
        if operation.endswith("-record") and operation not in world.mode.brokers:
            return None
        kind = world.mode.brokers.get(operation, "FenceReadBroker" if operation.endswith("-observe") else "ModeBroker")
        broker = _fake_broker(kind, journal, keeper)
        world.mode.dropped.append(broker)
        return broker
    monkeypatch.setattr(ag, "mode_capability", mode_capability)

    def deploy_publication(api, aws, governance, request, run, owner, guard, now, purpose):
        world.mode.publications.append((purpose, owner, type(guard).__name__, now))
        moments = {"artifact_created_at": c.utc(now - 30), "job_completed_at": c.utc(now - 20)}
        world.mode.moments.append((purpose, moments))
        return world.c_files[purpose], moments
    monkeypatch.setattr(ag, "_deploy_publication", deploy_publication)

    def phase_c_element(sources, *, product, runtime, run=None):
        world.events.append(("element", sources.purpose))
        world.mode.elements.append((sources, product, runtime, run))
        if world.mode.element_refusal is not None:
            raise ValueError(world.mode.element_refusal)
        return c.canonical({"fixture_element": sources.purpose})
    monkeypatch.setattr(lr, "phase_c_element", phase_c_element)
    world.mode.moments, world.mode.elements, world.mode.element_refusal = [], [], None
    world.c_files = {}
    return world


def _record_text(mode, request):
    return c.canonical({"activation_sha256": request["activation_sha256"], "fixture_record": mode, "mode": mode,
                        "owner_sha256": request["owner"]["owner_sha256"], "phase": mode}).decode()


def _record_observation(mode, request, **changes):
    ids = [f"reconciliation.published:fixture:{mode}-{index}" for index in (1, 2)] if mode == "audit" else None
    return c.canonical({"version": 1, "kind": "mode-record", "record": _record_text(mode, request),
                        "audit_event_ids": ids} | changes)


def _fake_broker(kind, journal, keeper):
    """A broker of the admitted mode type (or a look-alike) attached to the journal and keeper, with fake clients."""
    from types import SimpleNamespace

    from tools.cnesdata_delivery import mode_broker as mb
    cls = getattr(mb, kind) if kind in ("ModeBroker", "FenceReadBroker") else None
    broker = cls.__new__(cls) if cls is not None else SimpleNamespace()
    broker.aws, broker.journal = "operation-client", journal
    broker.evidence = [SimpleNamespace(_aws="ledger-client", uncertainty=[])]
    broker.session = SimpleNamespace(client="c", evidence="e")
    if kind == "ModeBroker":
        broker.read_session = SimpleNamespace(client="rc", evidence="re")
    journal._broker = broker
    if cls is not None:
        keeper.attach(broker)
    return broker


def _record(world):
    return world.store.get()[0]["lifecycle"]


def _enter_unit(world, at=1250):
    assert _record(world)["stage"] == "unit"
    world.clock.value = max(world.clock.value, at)
    world.keeper.tick()


def _known(world):
    return {"activation": world.activation, "close-drain": world.close_raw}


def _unit_stage(world, **extra):
    from tools.cnesdata_delivery import application_gate as ag

    def invoke(*, journal, timeout):
        return ag.invoke_adapter(journal=journal, timeout=timeout)
    def capability(**kwargs):
        return ag.mode_capability(**kwargs, context=None)
    return ag.mode_stage(world.keeper, "unit", known=_known(world) | extra, invoke=invoke, capability=capability,
                         credential_limit=6000, clock=world.clock)


def test_estagio_unit_roda_seed_start_observe_encadeados_e_avanca_com_o_unit_aceito(monkeypatch):
    world = _mode_world(monkeypatch)
    _enter_unit(world)
    before = _record(world)
    _unit_stage(world)
    operations = [call[0] for call in world.mode.calls]
    assert operations == ["unit-record", "unit-seed", "unit-start", "unit-observe"]
    assert [event for event in world.events if type(event) is tuple] == [
        (step, operation) for operation in operations for step in ("source", "capability", "child")]
    record, seed, start, observe = (call[3] for call in world.mode.calls)
    seed_raw = c.canonical({"fixture_child": "unit-seed"})
    text = _record_text("unit", world.mode.capabilities[0]._request).encode()
    assert seed["record"] == start["record"] == observe["record"] == text
    assert start["mode-seed"] == seed_raw and observe["mode-result"] == c.canonical({"fixture_child": "unit-start"})
    assert observe["activation"] == record["activation"] == world.activation
    assert observe["close-drain"] == record["close-drain"] == world.close_raw
    assert [(operation, names) for operation, names, _ in world.mode.sources] == [
        ("unit-record", ["fixture-manifest", "mode-input"]),
        ("unit-seed", sorted(PRODUCT["inputs"]["unit-seed"] - {"record"})),
        ("unit-start", sorted(PRODUCT["inputs"]["unit-start"] - {"mode-seed", "record"})),
        ("unit-observe", ["observed", "readbacks"])]
    for operation, timeout, now, _ in world.mode.calls:
        assert timeout == before["deadline"] - now - 38
    assert len(world.mode.dropped) == 3 and all(broker.aws is None for broker in world.mode.dropped)
    after = _record(world)
    assert after == before | {"sequence": before["sequence"] + 1, "stage": "phase-c-recovery", "admitted_at": world.clock.value,
                              "deadline": world.clock.value + before["windows"]["stages"]["phase-c-recovery"]}
    assert world.store.get()[0]["status"] == "held" and world.keeper.uncertainty() == []


def _host_unit(monkeypatch, **flags):
    from test_cnesdata_stage_events import HOST_REFERENCE
    world = _mode_world(monkeypatch, host=False, **flags)
    world.puts = []
    put = world.store.put
    world.store.put = lambda value, etag: world.puts.append(value["lifecycle"]) or put(value, etag)
    return world, lambda: world.handlers["host"](world.keeper, dict(HOST_REFERENCE))


def _stages(lifecycles):
    stages = [item["stage"] for item in lifecycles]
    return [stage for index, stage in enumerate(stages) if index == 0 or stages[index - 1] != stage]


def test_host_roda_o_modo_unit_na_janela_unit_e_o_unit_aceito_abre_a_janela_phase_c_recovery(monkeypatch):
    """Ruling 4 item 6: the internal DD-3 transition unit -> phase-c-recovery under STAGE_TRIGGERS, through the real host
    handler and the real mode_stage, with only the mode boundaries faked."""
    world, host = _host_unit(monkeypatch)
    host()
    assert lc.STAGE_TRIGGERS["unit"] == ("unit", "phase-c-recovery")
    assert _stages(world.puts)[-3:] == ["static", "unit", "phase-c-recovery"]
    unit = next(item for item in world.puts if item["stage"] == "unit")
    operations = [call[0] for call in world.mode.calls]
    assert operations == ["unit-record", "unit-seed", "unit-start", "unit-observe"]
    assert [event for event in world.events if type(event) is tuple] == [
        (step, operation) for operation in operations for step in ("source", "capability", "child")]
    assert {stage for _, _, stage in world.mode.sources} == {"unit"}
    assert [journal._request["stage"] for journal in world.mode.capabilities] == [
        {key: unit[key] for key in lc.ADAPTER_STAGE_FIELDS.split()}] * 4
    for _, timeout, now, _ in world.mode.calls:
        assert timeout == unit["deadline"] - now - 38
    assert world.mode.calls[0][3]["activation"] == world.activation and world.mode.calls[0][3]["close-drain"] == world.close_raw
    assert len(world.mode.dropped) == 3 and all(broker.aws is None for broker in world.mode.dropped)
    assert _record(world) == unit | {"sequence": unit["sequence"] + 1, "stage": "phase-c-recovery",
                                     "admitted_at": world.clock.value,
                                     "deadline": world.clock.value + unit["windows"]["stages"]["phase-c-recovery"]}
    assert world.store.get()[0]["status"] == "held" and world.keeper.uncertainty() == []


@pytest.mark.parametrize("flags, message, last", [
    ({"checks": {"unit": ["canary=schema"]}}, "unit mode accepted", "unit-observe"),
    ({"fail": "unit-seed"}, "fixture child failed", "unit-seed"),
    ({"capability": "mode broker refused"}, "mode broker refused", None),
    ({"late": True}, "unit stage deadline elapsed", "unit-observe")], ids=["recusado", "child", "capability", "lapso"])
def test_host_mantem_o_lease_retido_sem_checkpoint_de_janela_quando_o_modo_unit_e_recusado(monkeypatch, flags, message,
                                                                                            last):
    world, host = _host_unit(monkeypatch, **flags)
    with pytest.raises(ValueError, match=f"^{message}$"):
        host()
    unit = next(item for item in world.puts if item["stage"] == "unit")
    assert _stages(world.puts)[-2:] == ["static", "unit"] and _record(world) == unit
    assert world.store.get()[0]["status"] == "held"
    assert (world.mode.calls[-1][0] if world.mode.calls else None) == last


def test_docstring_dos_handlers_descreve_o_modo_unit_rodado_na_janela_unit():
    from tools.cnesdata_delivery import application_gate as ag
    doc = " ".join(ag.stage_handlers.__doc__.split())
    assert "nothing runs it" not in doc and "the unit stage ends it" not in doc
    assert "the unit window (internal, DD-3) and in it the unit mode run (record, seed, start, observe)" in doc
    assert "its acceptance opens the phase-c-recovery window (internal, DD-3); a refusal or a lapse ends held" in doc


def test_estagio_unit_recusa_unit_que_o_produto_nao_aceitou_e_mantem_o_lease(monkeypatch):
    world = _mode_world(monkeypatch, checks={"unit": ["canary=schema"]})
    _enter_unit(world)
    before = _record(world)
    with pytest.raises(ValueError, match="^unit mode accepted$"):
        _unit_stage(world)
    assert _record(world) == before and world.store.get()[0]["status"] == "held"


def test_operacao_de_modo_nunca_roda_o_child_quando_a_capability_recusa(monkeypatch):
    world = _mode_world(monkeypatch, capability="mode broker refused")
    _enter_unit(world)
    before = _record(world)
    with pytest.raises(ValueError, match="^mode broker refused$"):
        _unit_stage(world)
    assert world.mode.calls == [] and _record(world) == before
    assert {"kind": "context-failed"} in world.keeper.uncertainty()


@pytest.mark.parametrize("stage", ["unit", "phase-c-recovery"])
def test_estagio_de_modo_recusa_avancar_quando_o_prazo_do_vetor_governado_vence_depois_do_observe(monkeypatch, stage):
    from test_cnesdata_stage_events import B_REFERENCE
    world = _mode_world(monkeypatch)
    _enter_unit(world)
    if stage == "phase-c-recovery":
        _unit_stage(world)
        _c_files(world, stage)
    world.mode.late = True
    before = _record(world)
    assert lc.governed_windows(before["windows"])["stages"][stage] == before["deadline"] - before["admitted_at"]
    assert lc.terminal_deadline(before) == min(before["fixed_deadline"], before["admitted_at"] + before["windows"]["stages"][stage])
    with pytest.raises(ValueError, match=f"^{stage} stage deadline elapsed$"):
        if stage == "unit":
            _unit_stage(world)
        else:
            world.handlers[stage](world.keeper, dict(B_REFERENCE))
    assert world.mode.calls[-1][0] == ("unit" if stage == "unit" else "recovery") + "-observe"
    assert world.clock.value == lc.terminal_deadline(before)
    assert _record(world) == before and world.store.get()[0]["status"] == "held"


def test_cada_operacao_de_modo_registra_inicio_e_fim_medidos_no_journal(monkeypatch):
    """Ruling 2 C4: start and stop of every mode operation, so a refused attempt still yields measured durations."""
    world = _mode_world(monkeypatch)
    _enter_unit(world)
    _unit_stage(world)
    assert [journal._timings for journal in world.mode.capabilities] == [
        [{"kind": "operation", "operation": operation, "started_at": now, "ended_at": now + 5}]
        for operation, _, now, _ in world.mode.calls]


def test_operacao_de_modo_recusada_ainda_registra_o_tempo_medido(monkeypatch):
    world = _mode_world(monkeypatch, fail="unit-seed")
    _enter_unit(world)
    with pytest.raises(ValueError, match="^fixture child failed$"):
        _unit_stage(world)
    _, now = world.mode.calls[-1][0], world.mode.calls[-1][2]
    assert world.mode.capabilities[-1]._timings == [
        {"kind": "operation", "operation": "unit-seed", "started_at": now, "ended_at": now}]


def test_operacao_de_modo_registra_o_tempo_quando_a_capability_recusa(monkeypatch):
    world = _mode_world(monkeypatch, capability="mode broker refused")
    _enter_unit(world)
    now = world.clock.value
    with pytest.raises(ValueError, match="^mode broker refused$"):
        _unit_stage(world)
    assert world.mode.capabilities[-1]._timings == [
        {"kind": "operation", "operation": "unit-record", "started_at": now, "ended_at": now}]


def test_operacao_de_modo_descarta_os_clientes_do_broker_quando_o_child_falha(monkeypatch):
    world = _mode_world(monkeypatch, fail="unit-seed")
    _enter_unit(world)
    before = _record(world)
    with pytest.raises(ValueError, match="^fixture child failed$"):
        _unit_stage(world)
    assert [call[0] for call in world.mode.calls] == ["unit-record", "unit-seed"]
    broker, = world.mode.dropped
    assert (broker.aws, broker.session.client, broker.session.evidence) == (None, None, None)
    assert (broker.read_session.client, broker.read_session.evidence) == (None, None)
    assert [ledger._aws for ledger in broker.evidence] == [None]
    assert _record(world) == before and world.store.get()[0]["status"] == "held"


@pytest.mark.parametrize("operation, kind", [("unit-seed", "FenceReadBroker"), ("unit-seed", "look-alike"),
                                             ("unit-start", "FenceReadBroker"), ("unit-observe", "ModeBroker"),
                                             ("unit-observe", "look-alike"), ("unit-record", "ModeBroker"),
                                             ("unit-record", "FenceReadBroker"), ("unit-record", "look-alike")])
def test_operacao_de_modo_exige_o_broker_da_propria_classe_admitido_antes_do_child(monkeypatch, operation, kind):
    world = _mode_world(monkeypatch, brokers={operation: kind})
    _enter_unit(world)
    before = _record(world)
    with pytest.raises(ValueError, match="^mode broker admitted before adapter$"):
        _unit_stage(world)
    assert operation not in [call[0] for call in world.mode.calls]
    assert world.mode.dropped[-1].aws is None and world.mode.dropped[-1].session.client is None
    assert _record(world) == before and world.store.get()[0]["status"] == "held"


def test_operacao_de_modo_recusa_broker_admitido_que_nao_e_o_devolvido_pela_capability(monkeypatch):
    from types import SimpleNamespace
    world = _mode_world(monkeypatch)
    _enter_unit(world)
    from tools.cnesdata_delivery import application_gate as ag
    real = ag.mode_capability

    def swapped(*, journal, keeper, guard, context):
        real(journal=journal, keeper=keeper, guard=guard, context=context)
        return SimpleNamespace(aws="other", evidence=[], session=SimpleNamespace(client="x", evidence="y"))
    monkeypatch.setattr(ag, "mode_capability", swapped)
    with pytest.raises(ValueError, match="^mode broker admitted before adapter$"):
        _unit_stage(world)
    assert world.mode.calls == []


def test_passos_intermediarios_do_keeper_sao_os_do_abi_de_modo_do_produto():
    assert lc.ADAPTER_STEPS == {name: steps for name, steps in PRODUCT["steps"].items() if steps}
    assert lc.MODE_SINGLE_STEPS == frozenset({"unit-execution", "recovery-task", "audit-task"})


@pytest.mark.parametrize("operation, kind", [("unit-start", "unit-task"), ("unit-start", "unit-output")])
def test_journal_aceita_o_passo_intermediario_da_propria_operacao(operation, kind):
    journal = _start_journal(operation)
    raw = c.canonical({"step": kind})
    assert journal.observe(kind, raw) == c.sha(raw)
    assert journal.observations == [{"kind": kind, "sha256": c.sha(raw), "size": len(raw)}]


@pytest.mark.parametrize("operation, kind", [("unit-start", "recovery-task"), ("recovery-start", "unit-task"),
                                             ("audit-start", "recovery-task"), ("unit-seed", "unit-task"),
                                             ("unit-observe", "unit-execution"), ("unit-start", "mode-record")])
def test_journal_recusa_passo_intermediario_de_outra_operacao(operation, kind):
    journal = _start_journal(operation)
    with pytest.raises(ValueError, match="^adapter operation observation$"):
        journal.observe(kind, c.canonical({"step": kind}))


def _start_journal(operation):
    from tools.cnesdata_delivery.application_gate import AdapterJournal
    request, owner, window, inputs = _mode_case(operation)

    class Guard:
        def check(self, seconds=0):
            return None
    return AdapterJournal(c.canonical(request), operation=operation, owner=owner, window=window, inputs=inputs,
                          activation_sha256=request["activation_sha256"], guard=Guard())


def _result(journal):
    request = journal._request
    return c.canonical({"abi_version": lc.ADAPTER_ABI_VERSION, "operation": request["operation"],
                        "owner_sha256": request["owner"]["owner_sha256"], "generation": request["owner"]["generation"],
                        "checkpoint_sha256": request["checkpoint_sha256"], "observations": journal.observations,
                        "call_receipts_sha256": c.sha(c.canonical([])), "pending": [], "unknown": []})


def test_resultado_do_adapter_aceita_os_passos_registrados_e_recusa_passo_de_outra_operacao():
    journal = _start_journal("unit-start")
    journal.observe("unit-task", c.canonical({"step": 1}))
    journal.observe("mode-result", c.canonical({"result": 1}))
    raw = _result(journal)
    assert lc.validate_adapter_result(raw, request=journal._request, observations=journal.observations, call_receipts=[],
                                      pending=[], unknown=[]) == c.loads(raw, canonical=True)
    foreign = [{"kind": "recovery-task", "sha256": "1" * 64, "size": 3}]
    value = c.loads(raw, canonical=True) | {"observations": foreign}
    with pytest.raises(ValueError, match="^adapter operation observation$"):
        lc.validate_adapter_result(c.canonical(value), request=journal._request, observations=foreign, call_receipts=[],
                                   pending=[], unknown=[])


def test_unit_start_admite_execucao_tarefas_e_saidas_com_um_resultado(monkeypatch):
    world = _mode_world(monkeypatch, steps={"unit-start": ("unit-execution", "unit-task", "unit-task", "unit-output",
                                                           "unit-output")})
    _enter_unit(world)
    _unit_stage(world)
    assert _record(world)["stage"] == "phase-c-recovery"


@pytest.mark.parametrize("operation, steps", [("unit-start", ("unit-execution", "unit-execution")),
                                              ("unit-start", ("recovery-task",)), ("unit-seed", ("unit-task",)),
                                              ("unit-observe", ("unit-output",)), ("unit-start", ("mode-seed",))])
def test_operacao_de_modo_recusa_passo_fora_da_cardinalidade_ou_de_outra_operacao(monkeypatch, operation, steps):
    world = _mode_world(monkeypatch, steps={operation: steps})
    _enter_unit(world)
    before = _record(world)
    with pytest.raises(ValueError, match=f"^{operation} step observations$"):
        _unit_stage(world)
    assert _record(world) == before and world.store.get()[0]["status"] == "held"


@pytest.mark.parametrize("flags", [{"observations": 2}, {"observations": 0}, {"pending": True}])
def test_operacao_de_modo_exige_uma_observacao_e_nenhuma_incerteza(monkeypatch, flags):
    world = _mode_world(monkeypatch, **flags)
    _enter_unit(world)
    before = _record(world)
    with pytest.raises(ValueError, match="^unit-record single observation without uncertainty$"):
        _unit_stage(world)
    assert _record(world) == before and world.store.get()[0]["status"] == "held"


def test_operacao_de_modo_recusa_sem_capacidade_na_janela_antes_do_child(monkeypatch):
    world = _mode_world(monkeypatch)
    _enter_unit(world)
    window = _record(world)
    world.clock.value = window["deadline"] - 38
    with pytest.raises(ValueError, match="^unit-record capacity seconds=0$"):
        _unit_stage(world)
    assert world.mode.calls == [] and _record(world) == window


@pytest.mark.parametrize("operation", ["unit-seed", "unit-start", "recovery-seed", "recovery-start", "audit-start"])
def test_producao_recusa_o_modo_sem_fonte_dos_originais_e_o_efeito_sem_contexto_do_estagio(operation):
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag
    message = "^mode_unit_start=p16d_pending$" if operation == "unit-start" else "^mode_inputs=source_unconnected$"
    with pytest.raises(ValueError, match=message):
        ag.mode_input_source(keeper=None, owner={}, window={}, operation=operation, names=["record"])
    journal = SimpleNamespace(_failed=False, _request={"operation": operation})
    message = "^mode_unit_start=p16d_pending$" if operation == "unit-start" else "^mode effect original context$"
    with pytest.raises(ValueError, match=message):
        ag.mode_capability(journal=journal, keeper=None, guard=None, context=None)
    assert journal._failed is True


@pytest.mark.parametrize("operation", ["unit-observe", "recovery-observe", "audit-observe"])
def test_capability_de_producao_do_observe_e_a_do_fence_preparado_com_o_contexto_do_handler(monkeypatch, operation):
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag
    from tools.cnesdata_delivery import mode_broker as mb
    calls = []
    monkeypatch.setattr(mb, "fence_observe_capability", lambda **kwargs: calls.append(kwargs) or "fence-read-broker")
    context = ag.ModeContext(governance="g", authority="a", prepared="p", credential_limit=6000, operation_session="o",
                             clock="k", aws="evidence", activation_sha256="1" * 64, product="product")
    journal = SimpleNamespace(_failed=False, _request={"operation": operation})
    assert ag.mode_capability(journal=journal, keeper="keeper", guard="guard", context=context) == "fence-read-broker"
    assert calls == [{"governance": "g", "authority": "a", "journal": journal, "keeper": "keeper", "prepared": "p",
                      "credential_limit": 6000, "operation_session": "o", "clock": "k"}]
    assert journal._failed is False


def test_modos_rodam_o_record_puro_antes_do_seed_e_o_audit_record_antes_do_start():
    from tools.cnesdata_delivery import application_gate as ag
    assert ag.MODE_RUNS == {"unit": ("unit-record", "unit-seed", "unit-start", "unit-observe"),
                            "recovery": ("recovery-record", "recovery-seed", "recovery-start", "recovery-observe"),
                            "audit": ("audit-record", "audit-start", "audit-observe")}


def _record_inputs(mode, raw, request):
    from tools.cnesdata_delivery import mode_broker as mb
    return mb.mode_record_inputs(raw, mode=mode, owner_sha256=request["owner"]["owner_sha256"],
                                 activation_sha256=request["activation_sha256"])


@pytest.mark.parametrize("mode", MODES)
def test_observacao_mode_record_vira_o_texto_exato_do_record_e_os_ids_canonicos_do_audit(mode):
    request = _mode_case(mode + "-record")[0]
    raw = _record_observation(mode, request)
    expected = {"record": _record_text(mode, request).encode()}
    if mode == "audit":
        expected["audit-event-ids"] = c.canonical(json.loads(raw)["audit_event_ids"])
    assert _record_inputs(mode, raw, request) == expected


RECORD_SHAPES = [("unit", {"version": 2}), ("unit", {"version": True}), ("unit", {"kind": "mode"}),
                 ("unit", {"record": None}), ("unit", {"audit_event_ids": ["x"]}), ("recovery", {"audit_event_ids": []}),
                 ("audit", {"audit_event_ids": None}), ("audit", {"audit_event_ids": []}),
                 ("audit", {"audit_event_ids": [1]}), ("audit", {"audit_event_ids": ["x"] * 9}),
                 ("audit", {"audit_event_ids": ["x" * 257]})]


@pytest.mark.parametrize("mode, change", RECORD_SHAPES)
def test_observacao_mode_record_fora_da_forma_fechada_recusa(mode, change):
    request = _mode_case(mode + "-record")[0]
    with pytest.raises(ValueError, match="^mode record observation$"):
        _record_inputs(mode, _record_observation(mode, request, **change), request)


def test_observacao_mode_record_com_campo_a_mais_ou_bytes_nao_canonicos_recusa():
    request = _mode_case("unit-record")[0]
    with pytest.raises(ValueError, match="^closed object fields$"):
        _record_inputs("unit", _record_observation("unit", request, extra=1), request)
    raw = _record_observation("unit", request)
    with pytest.raises(ValueError, match="^noncanonical JSON bytes$"):
        _record_inputs("unit", raw[:-1] + b" \n", request)
    with pytest.raises(ValueError, match="^noncanonical JSON bytes$"):
        _record_inputs("unit", _record_observation("unit", request, record='{"phase": "unit"}\n'), request)


RECORD_BINDINGS = [("unit", {"phase": "recovery"}), ("recovery", {"mode": "unit"}), ("audit", {"owner_sha256": "0" * 64}),
                   ("unit", {"activation_sha256": "0" * 64}), ("recovery", {"phase": None})]


@pytest.mark.parametrize("mode, change", RECORD_BINDINGS)
def test_record_de_outro_modo_owner_ou_ativacao_recusa(mode, change):
    request = _mode_case(mode + "-record")[0]
    text = c.canonical(json.loads(_record_text(mode, request)) | change).decode()
    with pytest.raises(ValueError, match="^mode record binding$"):
        _record_inputs(mode, _record_observation(mode, request, record=text), request)


@pytest.mark.parametrize("operation", ["unit-record", "recovery-record", "audit-record"])
def test_capability_de_producao_do_record_puro_nao_admite_broker_nem_falha_o_journal(operation):
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag
    journal = SimpleNamespace(_failed=False, _request={"operation": operation})
    assert ag.mode_capability(journal=journal, keeper=None, guard=None, context=None) is None
    assert journal._failed is False and not hasattr(journal, "_broker")
    assert ag._mode_broker_class(operation) is type(None)


def test_frame_call_numa_operacao_record_recusa_sem_broker_admitido():
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag
    frame = c.canonical({"kind": "call", "role": "mode_seed", "service": "dynamodb", "operation": "get_item",
                         "parameters": {}})
    with pytest.raises(ValueError, match="^adapter protected SDK admission absent$"):
        ag._adapter_message(frame, SimpleNamespace(_broker=None, _request={"operation": "unit-record"}))


def test_estagio_unit_recusa_record_de_outro_modo_antes_do_seed(monkeypatch):
    world = _mode_world(monkeypatch)
    _enter_unit(world)
    before = _record(world)
    from tools.cnesdata_delivery import application_gate as ag
    original = ag.invoke_adapter

    def invoke(**kwargs):
        original(**kwargs)
        journal = kwargs["journal"]
        if journal._request["operation"] == "unit-record":
            raw = _record_observation("recovery", journal._request, audit_event_ids=None)
            journal._observations[:] = [{"kind": "mode-record", "sha256": c.sha(raw), "size": len(raw)}]
            journal._observation_bytes[c.sha(raw)] = raw
    monkeypatch.setattr(ag, "invoke_adapter", invoke)
    with pytest.raises(ValueError, match="^mode record binding$"):
        _unit_stage(world)
    assert [call[0] for call in world.mode.calls] == ["unit-record"]
    assert _record(world) == before and world.store.get()[0]["status"] == "held"


def _lease_journal(operation, *, observations=(), inputs=None):
    from tools.cnesdata_delivery.application_gate import AdapterJournal
    request, owner, window, original = _mode_case(operation)
    if inputs is not None:
        original = original | inputs
        request["inputs"] = {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in original.items()}

    class Guard:
        def check(self, seconds=0):
            return None
    journal = AdapterJournal(c.canonical(request), operation=operation, owner=owner, window=window, inputs=original,
                             activation_sha256=request["activation_sha256"], guard=Guard())
    for kind, raw in observations:
        journal.observe(kind, raw)
    return journal


def _source(operation, names, *journals):
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag
    window = _mode_case(operation)[2]
    return ag.mode_input_source(keeper=SimpleNamespace(_contexts=list(journals)), owner={}, window=window,
                                operation=operation, names=names), window


@pytest.mark.parametrize("operation", ["unit-seed", "unit-start", "recovery-seed", "recovery-start", "audit-start"])
def test_mode_start_e_do_keeper_com_o_instante_de_abertura_da_janela_e_o_frozen_que_o_produto_aceita(monkeypatch,
                                                                                                    operation):
    from tools.cnesdata_delivery import mode_broker
    monkeypatch.setattr(mode_broker, "MODE_UNIT_START_OPEN", True)
    inputs, window = _source(operation, ["mode-start"])
    assert inputs == {"mode-start": c.canonical({"version": 1, "kind": "mode-start", "frozen": operation == "audit-start",
                                                 "started_at": c.utc(window["admitted_at"])})}


@pytest.mark.parametrize("operation", ["unit-start", "recovery-start", "audit-start"])
def test_previous_e_sempre_nulo_e_um_segundo_start_no_lease_recusa_reentrada(monkeypatch, operation):
    from tools.cnesdata_delivery import mode_broker
    monkeypatch.setattr(mode_broker, "MODE_UNIT_START_OPEN", True)
    assert _source(operation, ["previous"], _lease_journal(operation.replace("-start", "-observe")))[0] == {
        "previous": b"null\n"}
    with pytest.raises(ValueError, match="^mode reentry unavailable$"):
        _source(operation, ["previous"], _lease_journal(operation))


@pytest.mark.parametrize("operation", ["audit-record", "audit-start"])
def test_mode_seed_do_audit_e_a_observacao_do_recovery_seed_deste_lease(operation):
    seed = c.canonical({"fixture_seed": "recovery"})
    journal = _lease_journal("recovery-seed", observations=[("mode-seed", seed)])
    assert _source(operation, ["mode-seed"], journal)[0] == {"mode-seed": seed}
    for journals in ((), (journal, _lease_journal("recovery-seed", observations=[("mode-seed", seed)])),
                     (_lease_journal("recovery-seed"),)):
        with pytest.raises(ValueError, match="^mode-seed original$"):
            _source(operation, ["mode-seed"], *journals)


def test_recovery_readbacks_do_audit_observe_sao_os_readbacks_ligados_ao_recovery_start_deste_lease():
    readbacks = c.canonical({"fixture_readbacks": "recovery"})
    journal = _lease_journal("recovery-start", inputs={"readbacks": readbacks})
    assert _source("audit-observe", ["recovery-readbacks"], journal)[0] == {"recovery-readbacks": readbacks}
    with pytest.raises(ValueError, match="^recovery-readbacks original$"):
        _source("audit-observe", ["recovery-readbacks"])


@pytest.mark.parametrize("operation, names", [("unit-seed", ["mode-start", "mode-input"]),
                                              ("unit-seed", ["readbacks"]), ("unit-observe", ["network"]),
                                              ("recovery-start", ["network"]), ("unit-seed", ["mode-seed"]),
                                              ("recovery-start", ["fixture-manifest"]),
                                              ("unit-observe", ["recovery-readbacks"]), ("recovery-start", ["mode-seed"])])
def test_origem_ainda_nao_conectada_recusa_sem_derivar_nenhuma_outra(operation, names):
    with pytest.raises(ValueError, match="^mode_inputs=source_unconnected$"):
        _source(operation, names)


def _c_files(world, purpose, **changes):
    window = _record(world)
    checkpoint = {"state": {"lineage": "original-lineage", "serial": 9, "state_sha256": "4" * 64},
                  "state_object": {"status": "present", "version_id": "v9", "etag_sha256": "3" * 64},
                  "owner": world.owner, "purpose": purpose, "plan_sha256": "2" * 64, "readbacks": []} | changes.get("checkpoint", {})
    approval = {"checkpoint_sha256": window["checkpoint_sha256"], "plan_sha256": "2" * 64, "purpose": purpose,
                "direction": "advance"} | changes.get("approval", {})
    world.c_files[purpose] = {"checkpoint.json": c.canonical(checkpoint), "approval.json": c.canonical(approval),
                              "apply-output.bin": f"Apply complete! {purpose}\n".encode()}
    return world.c_files[purpose]


def _through_unit(monkeypatch, **flags):
    world = _mode_world(monkeypatch, **flags)
    _enter_unit(world)
    _unit_stage(world)
    return world


def test_handler_do_c_recovery_autentica_o_deploy_roda_o_modo_e_avanca_com_o_checkpoint_do_deploy(monkeypatch):
    from test_cnesdata_stage_events import B_REFERENCE
    world = _through_unit(monkeypatch)
    files = _c_files(world, "phase-c-recovery")
    before = _record(world)
    world.mode.calls.clear()
    world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))
    (purpose, owner, guard, _), = world.mode.publications
    assert (purpose, owner, guard) == ("phase-c-recovery", world.owner, "KeeperGuard")
    assert [call[0] for call in world.mode.calls] == ["recovery-record", "recovery-seed", "recovery-start",
                                                      "recovery-observe"]
    text = _record_text("recovery", world.mode.capabilities[-1]._request).encode()
    assert all(call[3]["record"] == text for call in world.mode.calls[1:3])
    observe = world.mode.calls[-1][3]
    from test_cnesdata_stage_events import _ready_journal
    assert observe["phase-b"] == _ready_journal(world)._inputs["phase-b"]
    assert observe["activation"] == world.activation and observe["close-drain"] == world.close_raw
    after = _record(world)
    assert after == before | {"sequence": before["sequence"] + 1, "stage": "phase-c-audit", "admitted_at": world.clock.value,
                              "checkpoint_sha256": c.sha(files["checkpoint.json"]),
                              "deadline": world.clock.value + before["windows"]["stages"]["phase-c-audit"]}


def test_handler_do_c_audit_leva_o_resultado_do_recovery_e_avanca_para_o_final(monkeypatch):
    from test_cnesdata_stage_events import B_REFERENCE
    world = _through_unit(monkeypatch)
    _c_files(world, "phase-c-recovery")
    world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))
    recovery_result = c.canonical({"fixture_child": "recovery-start"})
    files = _c_files(world, "phase-c-audit")
    before = _record(world)
    world.mode.calls.clear()
    world.handlers["phase-c-audit"](world.keeper, dict(B_REFERENCE))
    assert [call[0] for call in world.mode.calls] == ["audit-record", "audit-start", "audit-observe"]
    assert world.mode.calls[-1][3]["recovery-result"] == recovery_result
    request = world.mode.capabilities[-1]._request
    assert world.mode.calls[1][3]["record"] == _record_text("audit", request).encode()
    assert world.mode.calls[1][3]["audit-event-ids"] == c.canonical(json.loads(_record_observation("audit", request))[
        "audit_event_ids"])
    after = _record(world)
    assert after == before | {"sequence": before["sequence"] + 1, "stage": "final", "admitted_at": world.clock.value,
                              "checkpoint_sha256": c.sha(files["checkpoint.json"]),
                              "deadline": min(before["fixed_deadline"], world.clock.value + before["windows"]["stages"]["final"])}
    assert world.store.get()[0]["status"] == "held"


@pytest.mark.parametrize("purpose", ["phase-c-recovery", "phase-c-audit"])
def test_handler_c_de_producao_recusa_o_seed_sem_pacote_de_modo_sem_child_e_com_o_lease_retido(monkeypatch, purpose):
    from test_cnesdata_stage_events import B_REFERENCE
    from tools.cnesdata_delivery import application_gate as ag
    production = ag.mode_capability
    world = _through_unit(monkeypatch)
    if purpose == "phase-c-audit":
        _c_files(world, "phase-c-recovery")
        world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))
    _c_files(world, purpose)
    monkeypatch.setattr(ag, "mode_capability", production)
    before = _record(world)
    world.mode.calls.clear()
    with pytest.raises(ValueError, match="^mode prepared authority package$"):
        world.handlers[purpose](world.keeper, dict(B_REFERENCE))
    assert [call[0] for call in world.mode.calls] == [purpose.removeprefix("phase-c-") + "-record"]
    assert _record(world) == before
    assert world.store.get()[0]["status"] == "held"
    assert {"kind": "context-failed"} in world.keeper.uncertainty()


@pytest.mark.parametrize("purpose", ["phase-c-recovery", "phase-c-audit"])
def test_handler_c_de_producao_sem_nada_falsificado_recusa_primeiro_a_fonte_dos_originais(monkeypatch, purpose):
    from test_cnesdata_stage_events import B_REFERENCE
    from tools.cnesdata_delivery import application_gate as ag
    production = {"mode_capability": ag.mode_capability, "mode_input_source": ag.mode_input_source}
    world = _through_unit(monkeypatch)
    if purpose == "phase-c-audit":
        _c_files(world, "phase-c-recovery")
        world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))
    _c_files(world, purpose)
    for name, function in production.items():
        monkeypatch.setattr(ag, name, function)
    before, contexts = _record(world), len(world.keeper._contexts)
    world.mode.calls.clear()
    with pytest.raises(ValueError, match="^mode fixture original$"):
        world.handlers[purpose](world.keeper, dict(B_REFERENCE))
    assert world.mode.calls == [] and _record(world) == before and len(world.keeper._contexts) == contexts
    assert world.store.get()[0]["status"] == "held"


def test_capability_de_modo_e_injetada_pelo_handler_e_nao_tem_padrao():
    import inspect
    from tools.cnesdata_delivery import application_gate as ag
    for function in (ag.run_mode_operation, ag.mode_stage):
        parameter = inspect.signature(function).parameters["capability"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY and parameter.default is inspect.Parameter.empty
    assert list(inspect.signature(ag.mode_capability).parameters) == ["journal", "keeper", "guard", "context"]
    assert ag.ModeContext._fields == ("governance", "authority", "prepared", "credential_limit", "operation_session", "clock",
                                      "aws", "activation_sha256", "product")


def test_handler_do_c_entrega_ao_capability_o_contexto_do_keeper_e_o_fence_preparado(monkeypatch):
    from test_cnesdata_stage_events import B_REFERENCE
    world = _through_unit(monkeypatch)
    _c_files(world, "phase-c-recovery")
    world.mode.contexts.clear()
    world.mode.source_contexts.clear()
    world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))
    contexts = world.mode.contexts
    assert len(contexts) == 4 and all(context is contexts[0] for context in contexts)
    context = contexts[0]
    assert (context.governance, context.authority, context.credential_limit) == (world.governance, world.authority, 6000)
    assert context.operation_session is world.operation_session and context.clock is world.clock
    assert type(context.prepared).__name__ == "PreparedFence"
    assert world.mode.source_contexts and all(item is context for item in world.mode.source_contexts)
    assert context.aws is world.aws and context.activation_sha256 == c.sha(world.activation) and context.product == "product"


C_REFUSALS = {
    "approval-checkpoint": {"approval": {"checkpoint_sha256": "5" * 64}},
    "approval-plan": {"approval": {"plan_sha256": "5" * 64}},
    "purpose": {"checkpoint": {"purpose": "phase-b"}},
    "owner": {"checkpoint": {"owner": {"generation": 99}}},
}


@pytest.mark.parametrize("mutation", sorted(C_REFUSALS))
def test_handler_do_c_recusa_deploy_que_nao_e_filho_do_checkpoint_do_keeper(monkeypatch, mutation):
    from test_cnesdata_stage_events import B_REFERENCE
    world = _through_unit(monkeypatch)
    _c_files(world, "phase-c-recovery", **C_REFUSALS[mutation])
    before = _record(world)
    world.mode.calls.clear()
    with pytest.raises(ValueError, match="^phase-c-recovery checkpoint ancestry$"):
        world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))
    assert world.mode.calls == [] and _record(world) == before


def test_handler_do_c_recusa_modo_nao_aceito_sem_avancar(monkeypatch):
    from test_cnesdata_stage_events import B_REFERENCE
    world = _through_unit(monkeypatch)
    world.mode.checks["recovery"] = ["phase_c=evidence"]
    _c_files(world, "phase-c-recovery")
    before = _record(world)
    with pytest.raises(ValueError, match="^recovery mode accepted$"):
        world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))
    assert _record(world) == before and world.store.get()[0]["status"] == "held"


def test_handler_do_c_recusa_keeper_que_nao_rodou_o_closed_ready(monkeypatch):
    from test_cnesdata_stage_events import B_REFERENCE, _stage_world
    world = _stage_world(monkeypatch)
    with pytest.raises(ValueError, match="^phase-c-recovery follows the closed-ready run of this keeper$"):
        world.handlers["phase-c-recovery"](world.keeper, dict(B_REFERENCE))


def test_handlers_do_keeper_sao_exatamente_os_eventos_externos(monkeypatch):
    from test_cnesdata_stage_events import _stage_world
    from tools.cnesdata_delivery import application_gate as ag
    world = _stage_world(monkeypatch)
    assert set(world.handlers) == set(ag.KEEPER_EVENTS) - {"host-recovery"}
    assert all(callable(item) for item in world.handlers.values())
