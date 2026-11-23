"""Janelas de estágio e prazo fixo vindos da governança, dentro dos limites do código (E2)."""
import copy

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

INITIAL = {"phase-b": 360, "api": 180, "static": 180, "unit": 180,
           "phase-c-recovery": 330, "phase-c-audit": 330, "final": 90}
BOUNDS = {"phase-b": (360, 720), "api": (180, 360), "static": (180, 360), "unit": (120, 360),
          "phase-c-recovery": (240, 660), "phase-c-audit": (240, 660), "final": (60, 180)}
GUARD, INIT, PLAN, SHOW, APPLY = 20, 45, 120, 20, 120


def governance(stages=None, fixed=None):
    stages = dict(INITIAL if stages is None else stages)
    return {"stage_windows": stages, "fixed_deadline_seconds": sum(stages.values()) + 420 if fixed is None else fixed}


def vector(stages=None):
    return lc.stage_windows(governance(stages))


def test_valores_iniciais_da_governanca_viram_o_vetor_canonico():
    assert lc.stage_windows(governance()) == {"stages": INITIAL, "fixed_deadline_seconds": 2070}
    assert list(lc.stage_windows(governance())["stages"]) == list(lc.STAGES)


def test_limites_do_codigo_sao_a_tabela_fixada():
    assert lc.STAGES == BOUNDS
    assert (lc.FINAL_RESERVE, lc.STAGE_SUM_CEILING) == (420, 1830)


@pytest.mark.parametrize("missing", ["stage_windows", "fixed_deadline_seconds"])
def test_governanca_sem_as_chaves_e_recusada(missing):
    value = governance()
    value.pop(missing)
    with pytest.raises(ValueError, match=f"governance key={missing}"):
        lc.stage_windows(value)


@pytest.mark.parametrize("stages", [{k: v for k, v in INITIAL.items() if k != "final"}, INITIAL | {"recovery": 60}])
def test_conjunto_de_estagios_da_governanca_e_fechado(stages):
    with pytest.raises(ValueError, match="stage_windows keys"):
        lc.stage_windows(governance(stages, fixed=2070))


@pytest.mark.parametrize("stage", list(BOUNDS))
@pytest.mark.parametrize("edge", ["below", "above"])
def test_janela_fora_dos_limites_do_estagio_e_recusada(stage, edge):
    low, high = BOUNDS[stage]
    value = low - 1 if edge == "below" else high + 1
    stages = {name: low_ for name, (low_, _) in BOUNDS.items()} | {stage: value}
    with pytest.raises(ValueError, match=f"stage window stage={stage} value={value} min={low} max={high}"):
        lc.stage_windows(governance(stages))


@pytest.mark.parametrize("value", [True, 360.0, "360", None])
def test_janela_que_nao_e_inteiro_e_recusada(value):
    with pytest.raises(ValueError, match="stage window stage=phase-b"):
        lc.stage_windows(governance(INITIAL | {"phase-b": value}, fixed=2070))


def test_soma_acima_do_teto_e_recusada_e_no_teto_e_aceita():
    at_ceiling = INITIAL | {"phase-b": 540}
    assert sum(at_ceiling.values()) == 1830
    assert lc.stage_windows(governance(at_ceiling))["fixed_deadline_seconds"] == 2250
    above = INITIAL | {"phase-b": 541}
    with pytest.raises(ValueError, match="stage windows sum=1831 ceiling=1830"):
        lc.stage_windows(governance(above))


@pytest.mark.parametrize("fixed", [2069, 2071, 1800, True, 2070.0])
def test_prazo_fixo_inconsistente_com_a_soma_e_a_reserva_e_recusado(fixed):
    with pytest.raises(ValueError, match="fixed_deadline_seconds"):
        lc.stage_windows(governance(fixed=fixed))


def _job_head():
    return [("creds", 3, GUARD), ("preflight", 3, GUARD), ("tofu init", 8, INIT)]


def _rx2_c_stage():
    """R-X2 seção 3, caso típico: plan -> audit -> deploy -> mode run, timeouts declarados do código."""
    return (_job_head() + [("job1 tofu plan", 25, PLAN), ("job1 tofu show", 3, SHOW), ("job1 publish", 5, GUARD),
                           ("handoff to audit", 8, None)]
            + _job_head() + [("job2 tofu show", 3, SHOW), ("job2 readbacks", 10, GUARD), ("job2 publish", 5, GUARD),
                             ("handoff to deploy", 8, None)]
            + _job_head() + [("job3 tofu show", 3, SHOW), ("job3 readbacks-before", 10, GUARD),
                             ("job3 tofu show 2", 3, SHOW), ("job3 state+verify", 3, GUARD),
                             ("job3 tofu apply", 25, APPLY), ("job3 readbacks-after", 10, GUARD),
                             ("job3 publish", 5, GUARD), ("keeper observe", 7, None)]
            + [("mode seed", 5, None), ("mode run", 60, None), ("mode accept", 5, None), ("keeper observe", 7, None)])


def _c_window(c_seconds):
    windows = vector(INITIAL | {"phase-c-recovery": c_seconds})
    close = 50_000
    order = list(lc.STAGES)
    admitted = close + sum(windows["stages"][name] for name in order[:order.index("phase-c-recovery")])
    return {"sequence": 6, "preparation_deadline": close - 1, "close": close,
            "fixed_deadline": close + windows["fixed_deadline_seconds"], "input_deadline": close + 10**6,
            "stage": "phase-c-recovery", "admitted_at": admitted, "deadline": admitted + c_seconds,
            "decision": None, "checkpoint_sha256": "a" * 64, "windows": windows}


def _replay(window):
    now, admitted = window["admitted_at"], []
    for name, duration, declared in _rx2_c_stage():
        try:
            lc.phase_capacity(window, now=now, credential_deadline=now + 10**6,
                              operation_seconds=duration if declared is None else declared)
        except ValueError:
            return admitted, name
        admitted.append(name)
        now += duration
    return admitted, None


def test_estagio_c_com_330_s_admite_plan_audit_deploy_e_mode_run_no_caso_tipico_do_rx2():
    admitted, refused = _replay(_c_window(330))
    assert refused is None and admitted[-4:] == ["mode seed", "mode run", "mode accept", "keeper observe"]


def test_estagio_c_com_240_s_recusa_o_apply_no_caso_tipico_do_rx2():
    admitted, refused = _replay(_c_window(240))
    assert refused == "job3 tofu apply" and "mode run" not in admitted


def _close_drain(close, windows, expires):
    return {"version": 2, "kind": "close-drain", "common": {}, "fence": {"changed_at": c.utc(close)},
            "close_confirmed_at": c.utc(close), "drain_observed_at": c.utc(close + 5),
            "frozen_membership_sha256": "7" * 64, "members": [], "proofs": [], "permit": None,
            "input_expirations": [{"kind": "envelope", "object_sha256": "9" * 64, "expires_at": c.utc(expires)}],
            "fixed_deadline": c.utc(min(close + windows["fixed_deadline_seconds"], expires)), "decision": None,
            "windows": windows}


def _prepared(windows, noon):
    return {"sequence": 0, "preparation_deadline": noon + 600, "close": None, "fixed_deadline": None,
            "input_deadline": None, "stage": "application-prepare", "admitted_at": noon - 300, "deadline": noon + 600,
            "decision": None, "checkpoint_sha256": "a" * 64, "predecessor_sha256": "e" * 64,
            "application_purpose": "promotion", "context_kind": "promotion", "caller_binding_sha256": "c" * 64,
            "windows": windows}


@pytest.mark.parametrize("stages", [INITIAL, INITIAL | {"phase-b": 400, "api": 240}, INITIAL | {"phase-b": 540}])
def test_consumidores_derivam_todo_prazo_da_janela_governada(stages):
    windows, noon = vector(stages), 1_000_000
    previous = _prepared(windows, noon)
    lc.checkpoint_transition(None, previous)
    closed = lc.close_window(previous, c.canonical(_close_drain(noon, windows, noon + 10**5)), checkpoint_sha256="f" * 64,
                             infra_bound=noon + 10**5, now=noon)
    assert closed["fixed_deadline"] == noon + windows["fixed_deadline_seconds"]
    assert closed["deadline"] == noon + stages["phase-b"] and closed["windows"] == windows
    lc.checkpoint_transition(previous, closed)
    lc.phase_capacity(closed, now=noon, credential_deadline=noon + 10**5, operation_seconds=20)
    admitted = noon + stages["phase-b"] - 40
    api = lc.api_window(closed, checkpoint_sha256="b" * 64, now=admitted)
    assert api["deadline"] == admitted + stages["api"]
    lc.checkpoint_transition(closed, api)
    lc.phase_capacity(api, now=admitted, credential_deadline=noon + 10**5, operation_seconds=stages["api"] - 38)
    with pytest.raises(ValueError, match="phase remaining capacity"):
        lc.phase_capacity(api, now=admitted, credential_deadline=noon + 10**5, operation_seconds=stages["api"] - 37)


def test_prazo_fixo_segue_a_governanca_e_o_input_deadline_continua_limitando():
    windows, noon = vector(INITIAL | {"api": 240}), 1_000_000
    assert windows["fixed_deadline_seconds"] == 2130
    early = lc.close_window(_prepared(windows, noon), c.canonical(_close_drain(noon, windows, noon + 2000)),
                            checkpoint_sha256="f" * 64, infra_bound=noon + 2000, now=noon)
    assert early["fixed_deadline"] == noon + 2000


def test_close_drain_com_janelas_diferentes_das_do_keeper_e_recusado():
    windows, noon = vector(), 1_000_000
    other = vector(INITIAL | {"api": 240})
    with pytest.raises(ValueError, match="close-drain windows"):
        lc.close_window(_prepared(windows, noon), c.canonical(_close_drain(noon, other, noon + 10**5)),
                        checkpoint_sha256="f" * 64, infra_bound=noon + 10**5, now=noon)
    legacy = _close_drain(noon, windows, noon + 10**5) | {"version": 1}
    legacy.pop("windows")
    with pytest.raises(ValueError):
        lc.close_window(_prepared(windows, noon), c.canonical(legacy), checkpoint_sha256="f" * 64,
                        infra_bound=noon + 10**5, now=noon)


def test_checkpoint_sem_janelas_ou_com_janelas_trocadas_e_recusado():
    windows, noon = vector(), 1_000_000
    previous = _prepared(windows, noon)
    bare = {key: value for key, value in previous.items() if key != "windows"}
    with pytest.raises(ValueError):
        lc.checkpoint_transition(None, bare)
    swapped = previous | {"sequence": 1, "windows": vector(INITIAL | {"api": 240})}
    with pytest.raises(ValueError, match="original stage windows"):
        lc.checkpoint_transition(previous, swapped)
    out_of_bounds = previous | {"windows": {"stages": INITIAL | {"final": 30}, "fixed_deadline_seconds": 2010}}
    with pytest.raises(ValueError, match="stage window stage=final"):
        lc.checkpoint_transition(None, out_of_bounds)


def test_timeout_do_adapter_pos_fence_e_prazo_menos_agora_menos_38():
    windows, noon = vector(), 1_000_000
    window = {"sequence": 2, "preparation_deadline": noon - 1, "close": noon, "fixed_deadline": noon + 2070,
              "input_deadline": noon + 10**5, "stage": "api", "admitted_at": noon + 360, "deadline": noon + 540,
              "decision": None, "checkpoint_sha256": "a" * 64, "windows": windows}
    now = noon + 400
    seconds = lc.adapter_seconds(window, now=now, credential_deadline=now + 10**5, operation="closed-ready")
    assert seconds == window["deadline"] - now - 38
    lc.phase_capacity(window, now=now, credential_deadline=now + 10**5, operation_seconds=seconds)
    with pytest.raises(ValueError):
        lc.phase_capacity(window, now=now, credential_deadline=now + 10**5, operation_seconds=seconds + 1)
    assert lc.adapter_seconds(window, now=now, credential_deadline=now + 200, operation="closed-ready") == 200 - 121


def test_timeout_do_close_drain_pre_fence_continua_prazo_menos_agora_menos_158():
    windows, noon = vector(), 1_000_000
    window = _prepared(windows, noon)
    now = noon
    assert lc.adapter_seconds(window, now=now, credential_deadline=now + 10**5,
                              operation="close-drain") == window["preparation_deadline"] - now - 158


def test_adapter_recusa_capacidade_esgotada():
    windows, noon = vector(), 1_000_000
    window = _prepared(windows, noon)
    with pytest.raises(ValueError, match="close-drain capacity seconds=0"):
        lc.adapter_seconds(window, now=window["preparation_deadline"] - 158, credential_deadline=noon + 10**5,
                           operation="close-drain")


def test_estagio_do_request_do_adapter_carrega_as_janelas_na_abi3():
    assert "windows" in lc.ADAPTER_STAGE_FIELDS.split()
    assert lc.ADAPTER_ABI_VERSION == 3


def test_janelas_recusam_vetor_com_campo_extra_ou_ausente():
    value = copy.deepcopy(vector())
    with pytest.raises(ValueError):
        lc.governed_windows(value | {"extra": 1})
    value.pop("fixed_deadline_seconds")
    with pytest.raises(ValueError):
        lc.governed_windows(value)


def test_teto_da_soma_cabe_na_credencial_e_no_timeout_do_job_do_application():
    import inspect
    from pathlib import Path

    import yaml

    from tools.cnesdata_delivery.lifecycle_runtime import oidc_credentials
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/reusable-cnesdata-application-gate.yml"
    job_timeout = yaml.safe_load(workflow.read_text())["jobs"]["execute"]["timeout-minutes"] * 60
    credential = inspect.signature(oidc_credentials).parameters["duration"].default
    worst_close_after_acquire = 900 - 158
    fixed = lc.STAGE_SUM_CEILING + lc.FINAL_RESERVE
    assert worst_close_after_acquire + fixed + 120 < credential
    assert job_timeout - worst_close_after_acquire - fixed >= 300


def _host():
    import importlib
    return importlib.import_module("tools.cnesdata_delivery.host_gate")


def test_host_gate_usa_os_mesmos_limites_do_lifecycle():
    g = _host()
    assert g.STAGE_WINDOW_BOUNDS == lc.STAGES
    assert (g.STAGE_SUM_CEILING, g.FINAL_RESERVE) == (lc.STAGE_SUM_CEILING, lc.FINAL_RESERVE)


def _host_case(stages):
    from test_personal_platform_dispatcher import closed_ready_fixture
    g, clock, gov, api, responses, close, phase, ready, pack = closed_ready_fixture()
    windows = vector(stages)
    order = list(lc.STAGES)
    assert close["version"] == 2
    close["windows"] = windows
    close["fixed_deadline"] = g.utc(min(660 + windows["fixed_deadline_seconds"], 3600))
    ready["stage"]["deadline"] = g.utc(960 + stages["api"])
    ready["stage"]["later_seconds"] = sum(stages[name] for name in order[order.index("api") + 1:])
    return g, clock, gov, api, close, ready, pack


@pytest.mark.parametrize("stages", [INITIAL, INITIAL | {"api": 240, "phase-b": 300 + 60}])
def test_host_gate_admite_closed_ready_com_as_janelas_governadas_do_close_drain(stages):
    g, clock, gov, api, close, ready, pack = _host_case(stages)
    pack()
    window = g.admit_physical_action(gov["binding"], gov, api, clock).window(clock)
    assert window.fixed_deadline == min(660 + sum(stages.values()) + 420, 3600)
    assert window.stage_deadline == 960 + stages["api"]


HOST_REFUSALS = {
    "later": "^original API admission budget$",
    "deadline": "^original API admission budget$",
    "fixed": "^original fixed deadline$",
    "bounds": "^stage window stage=final value=30 min=60 max=180$",
    "sum": "^stage windows sum=1831 ceiling=1830$",
    "fixed-seconds": "^fixed_deadline_seconds value=2131 expected=2130$",
    "close-drain-v1-com-janelas": "^canonical original ClosedReady$",
    "close-drain-v2-sem-janelas": "^closed object fields$",
}


@pytest.mark.parametrize("mutation", list(HOST_REFUSALS))
def test_host_gate_recusa_closed_ready_fora_das_janelas_governadas(mutation):
    g, clock, gov, api, close, ready, pack = _host_case(INITIAL | {"api": 240})
    windows = close["windows"]
    if mutation == "later":
        ready["stage"]["later_seconds"] = 840
    elif mutation == "deadline":
        ready["stage"]["deadline"] = g.utc(960 + 241)
    elif mutation == "fixed":
        close["fixed_deadline"] = g.utc(660 + 1800)
    elif mutation == "bounds":
        windows["stages"]["final"] = 30
        windows["fixed_deadline_seconds"] -= 60
    elif mutation == "sum":
        windows["stages"]["phase-b"] = 481
        windows["fixed_deadline_seconds"] += 121
    elif mutation == "fixed-seconds":
        windows["fixed_deadline_seconds"] += 1
    elif mutation == "close-drain-v1-com-janelas":
        close["version"] = 1
    elif mutation == "close-drain-v2-sem-janelas":
        close.pop("windows")
    if mutation in {"bounds", "sum", "fixed-seconds"}:
        order = list(lc.STAGES)
        close["fixed_deadline"] = g.utc(min(660 + windows["fixed_deadline_seconds"], 3600))
        ready["stage"]["later_seconds"] = sum(windows["stages"][name] for name in order[order.index("api") + 1:])
    pack()
    with pytest.raises(ValueError, match=HOST_REFUSALS[mutation]):
        g.admit_physical_action(gov["binding"], gov, api, clock)


def test_sessao_da_fence_no_estagio_api_usa_a_janela_api_governada(monkeypatch):
    from test_cnesdata_application_gate import _fence_sdk_boundary_case
    ag, args, calls, native = _fence_sdk_boundary_case(monkeypatch)
    stage = args["journal"]._request["stage"]
    windows = vector(INITIAL | {"api": 240})
    stage.update(windows=windows, fixed_deadline=stage["close"] + windows["fixed_deadline_seconds"],
                 deadline=stage["admitted_at"] + 240)
    session = ag._assume_fence_session(**args)
    assert session.deadline == stage["admitted_at"] + 240
    stage.update(deadline=stage["admitted_at"] + 180)
    with pytest.raises(ValueError, match="API/credential window"):
        ag._assume_fence_session(**args)


def test_sessao_avaliada_da_fence_expira_com_a_janela_api_governada(monkeypatch):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    from tools.cnesdata_delivery import session_owner, session_policy
    monkeypatch.setattr(session_owner, "application_identity_document", lambda governance, fragment: {})
    monkeypatch.setattr(session_policy, "application_request", lambda *args, **kwargs: {"Policy": "{}"})
    pin = {"frozen_until": c.utc(5000), "document": {}, "document_sha256": "1" * 64}
    fragment = {"enabled_until": c.utc(5000)}
    owner = {"source_sha": "a" * 40, "run_id": 1, "run_attempt": 1}
    table = "arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control"
    prefix = "arn:aws:states:us-east-2:111122223333:execution:cnesdata-prod:"
    documents = lr.fence_evaluation_documents(governance={}, pin=pin, fragment=fragment, owner=owner,
                                              role={"session_name": "s", "policy": {}}, control_table_arn=table,
                                              execution_prefix=prefix, observed_at=1000, api_seconds=240)
    assert documents["fence_session"] == session_policy.fence_session_policy(control_table_arn=table, execution_prefix=prefix,
                                                                             deadline=1240)


INITIAL_RENDER = {"stage_windows": INITIAL, "fixed_deadline_seconds": 2070}


def test_cli_do_dono_renderiza_os_valores_iniciais_por_padrao(capsys):
    from tools.cnesdata_delivery.producers import governance_assembly
    assert governance_assembly.main(["stage-windows"]) == 0
    assert c.loads(capsys.readouterr().out.encode()) == INITIAL_RENDER


def test_cli_do_dono_renderiza_janela_recalibrada_e_recusa_fora_dos_limites(capsys):
    from tools.cnesdata_delivery.producers import governance_assembly
    assert governance_assembly.main(["stage-windows", "--window", "unit=240"]) == 0
    rendered = c.loads(capsys.readouterr().out.encode())
    assert rendered["stage_windows"]["unit"] == 240 and rendered["fixed_deadline_seconds"] == 2130
    assert governance_assembly.main(["stage-windows", "--window", "final=30"]) == 1
    seen = capsys.readouterr()
    assert seen.out == "" and "refused reason=stage window stage=final value=30 min=60 max=180" in seen.err
    assert governance_assembly.main(["stage-windows", "--window", "recovery=60"]) == 1
    assert "refused reason=stage window stage=recovery" in capsys.readouterr().err


def test_cli_do_dono_valida_as_chaves_novas_no_cruzamento():
    from tools.cnesdata_delivery.producers import governance_assembly
    assert {"stage_windows", "fixed_deadline_seconds"} <= governance_assembly.GOVERNANCE_KEYS
    base = {"product_inputs": {"shared_outputs": {"a": 1}}, "report_hmac_key": "5a" * 32}
    commitments = {"shared_outputs_sha256": c.sha(c.canonical({"a": 1}))}
    governance_assembly.crosscheck(base | {"role": "application"} | INITIAL_RENDER, commitments)
    with pytest.raises(ValueError, match="governance key=stage_windows"):
        governance_assembly.crosscheck(base | {"role": "application"}, commitments)
    with pytest.raises(ValueError, match="fixed_deadline_seconds"):
        governance_assembly.crosscheck(base | {"role": "application"} | INITIAL_RENDER | {"fixed_deadline_seconds": 1800},
                                       commitments)
    with pytest.raises(ValueError, match="stage windows outside application governance role=plan"):
        governance_assembly.crosscheck(base | {"role": "plan"} | INITIAL_RENDER, commitments)


def test_governanca_completa_do_application_com_janelas_cabe_no_teto_da_cli(monkeypatch, tmp_path):
    from test_cnesdata_application_gate import _application_entry_case
    from tools.cnesdata_delivery.producers import governance_assembly
    gov, *_ = _application_entry_case(monkeypatch, tmp_path)
    assert lc.stage_windows(gov) == {"stages": INITIAL, "fixed_deadline_seconds": 2070}
    assert len(governance_assembly.render(gov)) <= governance_assembly.CLI_CEILING
