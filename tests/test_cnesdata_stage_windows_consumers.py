"""Consumidores das janelas governadas presos ao vetor da governança, nunca à tabela de mínimos (P36)."""
import time

import pytest

from test_cnesdata_stage_windows import INITIAL, _close_drain, _prepared, vector
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

MINIMUM = {"phase-b": 360, "api": 180, "static": 180, "unit": 120,
           "phase-c-recovery": 240, "phase-c-audit": 240, "final": 60}
E2_API_240 = INITIAL | {"api": 240}
MINIMUM_API_240 = MINIMUM | {"api": 240}


def _api_stage(stages, *, input_deadline=None):
    windows, noon = vector(stages), 1_000_000
    expires = noon + 10**5 if input_deadline is None else input_deadline
    closed = lc.close_window(_prepared(windows, noon), c.canonical(_close_drain(noon, windows, expires)),
                             checkpoint_sha256="f" * 64, infra_bound=expires, now=noon)
    admitted = noon + stages["phase-b"]
    return lc.api_window(closed, checkpoint_sha256="b" * 64, now=admitted), admitted


def test_keeper_acquire_grava_as_janelas_da_governanca_e_o_close_window_segue_com_elas(monkeypatch, tmp_path):
    from test_cnesdata_application_gate import _current_caller, _legacy_history_fixture, _phase_a_release_sha256
    from tools.cnesdata_delivery.application_gate import Keeper, authenticated_previous
    chain, aws, api, store, _, _ = _legacy_history_fixture(monkeypatch, tmp_path)
    governed = vector(E2_API_240)
    chain.gov.update(stage_windows=governed["stages"], fixed_deadline_seconds=governed["fixed_deadline_seconds"])
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": _phase_a_release_sha256(), "session_sha256": "d" * 64, "lifecycle_version": 1}
    binding |= _current_caller(chain.gov, binding)
    keeper = Keeper(store, binding, lambda value: authenticated_previous(aws, api, chain.gov, value), api=api,
                    governance=chain.gov)
    keeper.acquire(preparation_deadline=int(time.time()) + 900)
    record = store.get()[0]["lifecycle"]
    assert record["windows"] == governed
    close = record["admitted_at"] + 10
    closed = lc.close_window(record, c.canonical(_close_drain(close, governed, close + 10**5)), checkpoint_sha256="f" * 64,
                             infra_bound=close + 10**5, now=close)
    assert (closed["fixed_deadline"], closed["deadline"]) == (close + 2130, close + 360)
    api_stage = lc.api_window(closed, checkpoint_sha256="b" * 64, now=close + 300)
    assert api_stage["deadline"] == close + 300 + 240


def test_estagio_static_expira_com_a_janela_static_governada():
    stages = INITIAL | {"static": 240}
    api_stage, admitted = _api_stage(stages)
    static = lc.static_window(api_stage, now=admitted + 100)
    lc.checkpoint_transition(api_stage, static)
    assert static["deadline"] == admitted + 100 + 240


def test_reserva_dos_estagios_seguintes_vem_do_vetor_governado_com_f_cortado_pelo_input_deadline():
    noon = 1_000_000
    later = sum(E2_API_240[name] for name in ("static", "unit", "phase-c-recovery", "phase-c-audit", "final"))
    assert later == lc.later_seconds(vector(E2_API_240), "api") == 1110
    api_stage, admitted = _api_stage(E2_API_240)
    assert api_stage["fixed_deadline"] - admitted == 240 + later + lc.FINAL_RESERVE
    lc.phase_capacity(api_stage, now=admitted, credential_deadline=admitted + 10**5, operation_seconds=20)
    clipped, admitted = _api_stage(E2_API_240, input_deadline=noon + 2129)
    assert clipped["fixed_deadline"] - admitted == 1769 > 240 + lc.later_seconds(vector(MINIMUM), "api") + lc.FINAL_RESERVE
    with pytest.raises(ValueError, match="^phase remaining capacity$"):
        lc.phase_capacity(clipped, now=admitted, credential_deadline=admitted + 10**5, operation_seconds=20)


@pytest.mark.parametrize(("floor_offset", "admitted"), [(0, True), (-1, False)], ids=["no-piso", "um-segundo-abaixo"])
def test_sessao_da_fence_exige_o_piso_governado_api_mais_seguintes_mais_reserva(monkeypatch, floor_offset, admitted):
    from test_cnesdata_application_gate import _fence_sdk_boundary_case
    ag, args, _, _ = _fence_sdk_boundary_case(monkeypatch)
    stage = args["journal"]._request["stage"]
    windows = vector(E2_API_240)
    floor = 240 + lc.later_seconds(windows, "api") + lc.FINAL_RESERVE
    assert floor == 1770
    fixed = stage["admitted_at"] + floor + floor_offset
    stage.update(windows=windows, fixed_deadline=fixed, input_deadline=fixed, deadline=stage["admitted_at"] + 240)
    if admitted:
        assert ag._assume_fence_session(**args).deadline == stage["admitted_at"] + 240
    else:
        with pytest.raises(ValueError, match="^fence original API/credential window$"):
            ag._assume_fence_session(**args)


def test_avaliacao_preparada_da_fence_usa_a_janela_api_governada(monkeypatch):
    from test_cnesdata_application_gate import _fence_prepare_package_case
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    from tools.cnesdata_delivery.session_policy import fence_session_policy
    kwargs, _, _ = _fence_prepare_package_case(monkeypatch, windows=vector(MINIMUM_API_240))
    files = lr.fence_prepare_package(**kwargs)
    observed = c.loads(files["fence-prepared.json"], canonical=True)["preparation"]["observed_at"]
    evaluation = c.loads(files["fence-evaluation.json"], canonical=True)
    cases = {case["case_id"]: case for case in evaluation["cases"]}
    frozen = c.instant(cases["freeze-expired"]["context"]["aws:CurrentTime"])
    assert observed + 240 < frozen

    def session(api):
        return c.sha(c.canonical(fence_session_policy(control_table_arn=cases["get-fence"]["resource"],
                                                      execution_prefix=cases["probe-own"]["resource"][:-16],
                                                      deadline=int(min(observed + api, frozen)))))
    assert evaluation["documents"]["fence_session"] == session(240) != session(180)


def test_capability_do_closed_ready_reconstroi_a_sessao_preparada_com_a_janela_api_governada(monkeypatch):
    from test_cnesdata_application_gate import _closed_ready_capability_case
    windows = vector(MINIMUM_API_240)
    ag, args, sts_calls, keeper, journal = _closed_ready_capability_case(monkeypatch, windows=windows)
    stage = journal._request["stage"]
    assert stage["windows"] == windows and stage["deadline"] == stage["admitted_at"] + 240
    broker = ag.closed_ready_capability(**args)
    assert type(broker) is ag.ClosedReadyBroker and len(sts_calls) == 1 and keeper.uncertainty() == []
    assert args["operation_session"].calls == [("closed-ready", "promotion-fence-r1", stage)]


@pytest.mark.parametrize("role", ["application", "plan"])
def test_admissao_do_application_recusa_governanca_sem_as_janelas_antes_do_github(monkeypatch, role):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    governance = {"activation_enabled": True, "lifecycle_enabled": True, "lifecycle_authority": "infra-ansible#55/6755178450",
                  "lifecycle_steps_sha256": "d" * 64, "source_closure_sha256": "e" * 64}
    request = c.canonical({"schema_version": 1, "repository": c.REPOSITORY, "source_sha": "b" * 40, "step": "keeper",
                           "payloads": {}, "application_purpose": "promotion", "caller_binding_sha256": "c" * 64})
    for key, value in {"CNESDATA_DELIVERY_GOVERNANCE": c.canonical(governance).decode(), "REQUEST_DESCRIPTOR": request.decode(),
                       "REQUEST_DESCRIPTOR_SHA256": c.sha(request), "EXPECTED_SOURCE_SHA": "b" * 40,
                       "PURPOSE": "application-prepare", "GITHUB_RUN_ID": "44", "GITHUB_RUN_ATTEMPT": "2"}.items():
        monkeypatch.setenv(key, value)
    reached = []
    monkeypatch.setattr(lr, "GitHub", lambda: reached.append("github") or pytest.fail("admission reached GitHub"))
    monkeypatch.setattr(lr, "source_admission", lambda *args: pytest.fail("admission reached source admission"))
    if role == "application":
        with pytest.raises(ValueError, match="^governance key=stage_windows absent$"):
            lr.admission(role)
        assert reached == []
    else:
        with pytest.raises(pytest.fail.Exception, match="admission reached GitHub"):
            lr.admission(role)


def test_validador_de_membership_recusa_close_drain_com_janelas_fora_dos_limites():
    from test_cnesdata_application_gate import _synthetic_terminal_vectors, _validate
    out_of_bounds = {"stages": MINIMUM | {"final": 30}, "fixed_deadline_seconds": 1770}
    vectors = _synthetic_terminal_vectors(**{"close-drain": lambda value: value.update(windows=out_of_bounds)})
    with pytest.raises(ValueError, match="^stage window stage=final value=30 min=60 max=180$"):
        _validate("membership", vectors)


def test_request_do_adapter_com_abi_anterior_e_recusado():
    from test_cnesdata_application_gate import _adapter_case
    request, owner, window, inputs = _adapter_case("closed-ready")
    args = {"operation": "closed-ready", "owner": owner, "window": window, "inputs": inputs,
            "activation_sha256": request["activation_sha256"]}
    assert lc.validate_adapter_request(c.canonical(request), **args) == request
    with pytest.raises(ValueError, match="^closed adapter ABI/operation$"):
        lc.validate_adapter_request(c.canonical(request | {"abi_version": 2}), **args)


@pytest.mark.parametrize(("seconds", "accepted"), [(1799, False), (1800, True), (2250, True), (2251, False)])
def test_janela_do_host_so_aceita_prazo_fixo_entre_a_soma_minima_e_o_teto_mais_reserva(seconds, accepted):
    from test_personal_platform_dispatcher import runtime
    from test_personal_platform_lease import Clock
    g = runtime()
    if accepted:
        window = g.Window(Clock(), close_confirmed_at=1000, fixed_seconds=seconds, input_deadlines=[9000])
        assert window.fixed_deadline == 1000 + seconds
    else:
        with pytest.raises(ValueError, match=f"^promotion fixed_deadline_seconds value={seconds}$"):
            g.Window(Clock(), close_confirmed_at=1000, fixed_seconds=seconds, input_deadlines=[9000])


@pytest.mark.parametrize(("fixed", "accepted"), [(1009, True), (1008, False)], ids=["no-prazo", "um-segundo-depois"])
def test_reopen_do_host_recusa_verificacao_lida_depois_do_prazo_fixo(tmp_path, fixed, accepted):
    """SYNTHETIC: the window clock is held at 900 apart from the lease clock.

    With one shared clock window.guard already refuses 36 s before F, so only a separate
    window clock reaches the reopen observed <= F check on the lease clock.
    """
    from test_personal_platform_deployer import operation
    from test_personal_platform_lease import Clock
    g, clock, op = operation(tmp_path, "deploy")
    op.close()
    op.confirm_closed(lambda _: clock.advance(2))
    op.closed_ready("e" * 64)
    held = Clock()
    held.t = held.m = 900
    window = g.Window(held, close_confirmed_at=1002, fixed_seconds=1800, input_deadlines=[fixed])
    release = op.record["binding"]["release"]
    routes = {name: release[name + "_revision"] for name in ("unit", "recovery", "audit")}
    reopen = (window, lambda: clock.advance(3), lambda _: clock.advance(4), lambda: routes)
    if accepted:
        op.reopen(*reopen)
        assert op.record["reopen_verified_at"] == g.utc(1009) == g.utc(window.fixed_deadline)
    else:
        with pytest.raises(ValueError, match="^reopen outside fence window$"):
            op.reopen(*reopen)
        assert op.record["reopen_verified_at"] is None


@pytest.mark.parametrize(("verified", "accepted"), [(2800, True), (2801, False)], ids=["no-prazo", "um-segundo-depois"])
def test_resposta_do_host_recusa_reopen_verificado_depois_do_prazo_fixo(tmp_path, verified, accepted):
    """SYNTHETIC: receipt edited so reopen_verified_at lies beyond observed_at, commitments recomputed.

    A sealed receipt keeps reopen_verified_at <= observed_at <= now <= F; only the
    accept_response reopen bound <= F refuses a receipt that breaks that order.
    """
    from test_personal_platform_deployer import operation
    from test_personal_platform_dispatcher import H
    g, clock, op = operation(tmp_path)
    op.transition("VERIFIED")
    op.transition("ACCEPTED")
    raw = op.seal(H, g.Window(clock, close_confirmed_at=1000, fixed_seconds=1800, input_deadlines=[4600]),
                  lambda: {"checked_processes": [], "all_absent_or_send_disabled": True})
    value = g.host_json(raw)
    value["receipt"].update(close_confirmed_at=g.utc(1000), open_requested_at=g.utc(1000),
                            open_responded_at=g.utc(1000), reopen_verified_at=g.utc(verified))
    value["receipt_readback_witness"]["receipt_sha256"] = g.sha(g.canonical(value["receipt"]))
    arguments = {"binding": op.record["binding"], "channel_nonce": H, "now": 1001, "fixed_deadline": 2800}
    if accepted:
        assert g.accept_response(g.canonical(value), **arguments)["receipt"]["reopen_verified_at"] == g.utc(2800)
    else:
        with pytest.raises(ValueError, match="^actual reopen window$"):
            g.accept_response(g.canonical(value), **arguments)
