"""P40 merge-main round: keeper wiring, ordering, presence check and mode-aware binding."""
import pytest


def test_saida_registrada_nao_mascara_o_erro_original_sem_leitor_da_api():
    from tools.cnesdata_delivery import application_gate as gate

    @gate._exit_logged
    def falha(admitted):
        raise ValueError("original")

    with pytest.raises(ValueError, match="^original$"):
        falha(())


def test_saida_registrada_le_a_taxa_do_leitor_da_api_quando_existe():
    from tools.cnesdata_delivery import application_gate as gate

    class Api:
        rate = {"limit": 5000, "used": 7, "remaining": 4993}

    @gate._exit_logged
    def ok(admitted):
        return "feito"

    assert ok((None, None, None, Api())) == "feito"


def _binding(plan_sha):
    return {"release_id": "r0123", "run_id": 44, "run_attempt": 2, "generation": 3, "product_source_sha": "b" * 40,
            "shared_source_sha": "c" * 40, "static_plan_sha256": plan_sha}


def _carrier(mode, plan_sha):
    from tools.cnesdata_delivery import contract as c
    return c.canonical({"static_promotion": {"mode": mode, "binding": _binding(plan_sha)}})


def test_binding_de_bootstrap_com_hash_do_plano_e_recusado():
    from tools.cnesdata_delivery import static_inputs as si
    with pytest.raises(ValueError, match="^static_binding=carrier_plan_sha256$"):
        si.carrier_binding(_carrier("observer-bootstrap", "a" * 64))


def test_binding_operacional_com_hash_nulo_e_recusado():
    from tools.cnesdata_delivery import static_inputs as si
    with pytest.raises(ValueError, match="^static_binding=carrier_plan_sha256$"):
        si.carrier_binding(_carrier("operational", None))


def test_binding_de_modo_desconhecido_e_recusado():
    from tools.cnesdata_delivery import static_inputs as si
    with pytest.raises(ValueError, match="^static_binding=carrier_mode$"):
        si.carrier_binding(_carrier("other", None))


def test_binding_de_bootstrap_nulo_e_operacional_com_hash_sao_aceitos():
    from tools.cnesdata_delivery import static_inputs as si
    assert si.carrier_binding(_carrier("observer-bootstrap", None))["static_plan_sha256"] is None
    assert si.carrier_binding(_carrier("operational", "a" * 64))["static_plan_sha256"] == "a" * 64


def _prepare_proof(keeper, store, raw):
    from test_cnesdata_terminal_gate import _journal, _readback
    from tools.cnesdata_delivery import application_gate as ag, contract as c, lifecycle_contract as lc, terminal_gate as tg
    readback = _readback([])
    keeper.attach(_journal([("terminal", readback)]))
    keeper._terminal_validators.clear()
    keeper.register_terminal_validator("quiescence", ag.quiescence_terminal_validator(keeper.uncertainty), label="q")
    keeper.register_terminal_validator("restoration", tg.restoration_validator(keeper), label="r")
    sources = {"quiescence": {"terminal": c.sha(readback)}, "restoration": {"terminal": c.sha(readback)}}
    return {"kind": "failed-prepare-quiescent", "checkpoint_raw": raw, "sources": sources}


def test_falha_de_prepare_depois_do_deploy_bootstrap_fecha_sobre_o_bruto_do_predecessor():
    from test_cnesdata_application_gate import _prepare_stage_keeper
    from tools.cnesdata_delivery import contract as c
    keeper, store = _prepare_stage_keeper()
    window = store.get()[0]["lifecycle"]
    assert window["sequence"] == 0 and window["checkpoint_sha256"] == c.sha(keeper.predecessor["raw"])
    files = keeper.finish(_prepare_proof(keeper, store, keeper.predecessor["raw"]))
    assert c.loads(files["terminal.json"], canonical=True)["coordination_status"] == "quiescent-released"


def test_checkpoint_do_deploy_bootstrap_nao_substitui_o_bruto_do_predecessor_no_fechamento():
    from test_cnesdata_application_gate import _prepare_stage_keeper
    from tools.cnesdata_delivery import contract as c
    keeper, store = _prepare_stage_keeper()
    hop = c.loads(keeper.predecessor["raw"], canonical=True) | {"previous_checkpoint_sha256": c.sha(keeper.predecessor["raw"]),
                                                                  "purpose": "application-prepare"}
    with pytest.raises(ValueError, match="original terminal checkpoint bytes"):
        keeper.finish(_prepare_proof(keeper, store, c.canonical(hop)))


class CountingApi:
    def __init__(self, listing):
        self.reads, self.listing = [], listing

    def read(self, path, raw=False):
        self.reads.append(path)
        return self.listing(path, raw)


def test_leitor_do_plano_faz_exatamente_as_leituras_declaradas_no_modelo():
    from tools.cnesdata_delivery import contract as c, plan_inputs, stage_wait
    from tools.cnesdata_delivery.application_gate import KeeperGuard
    from tools.cnesdata_delivery.provenance import unzip
    del KeeperGuard, unzip
    name = plan_inputs.artifact_name("phase-b-plan", 7, 1)
    item = {"id": 5, "name": name, "digest": "sha256:" + "d" * 64, "created_at": "2026-11-26T10:00:20Z"}

    def listing(path, raw):
        if path.endswith("/jobs?per_page=100&page=1"):
            return {"total_count": 1, "jobs": [{"name": "plan", "status": "in_progress", "started_at": "2026-11-26T10:00:00Z"}]}
        if path.endswith("artifacts?per_page=100&page=1"):
            return {"total_count": 1, "artifacts": [item]}
        if path.endswith("/zip"):
            return b"zip"
        return {"id": 5, "name": name, "digest": item["digest"], "workflow_run": {"id": 7}, "expired": False,
                "expires_at": "2026-12-26T10:00:00Z"}
    api = CountingApi(listing)
    run = {"id": 7, "run_attempt": 1}
    guard = type("G", (), {"check": lambda self, seconds=0: None})()
    started = plan_inputs._consumer_started(api, run, {"job_name": "plan"}, guard)
    found, _ = plan_inputs._publication(api, run, "phase-b-plan", started, c.instant("2026-11-26T10:01:00Z"))
    try:
        plan_inputs._public_index(api, run, found, name, c.instant("2026-11-26T10:01:00Z"))
    except ValueError:
        pass
    assert len(api.reads) == stage_wait.P40_READER_READS == 4


def test_o_modelo_conta_as_leituras_do_p40_no_termo_do_keeper_e_no_de_admissao_dos_planos():
    from tools.cnesdata_delivery import stage_wait
    from test_cnesdata_rest_model import _model
    components = _model()["components"]
    assert components["plan_inputs_keeper"] == sum(stage_wait.P40_KEEPER_STAGE_READS.values())
    assert components["plan_inputs_reader"] == stage_wait.P40_READER_READS * sum(stage_wait.P40_PLAN_JOBS.values())
    assert stage_wait.P40_POINT_READS == components["plan_inputs_keeper"] + components["plan_inputs_reader"]


def test_pior_hora_governada_com_as_leituras_do_p40_cabe_nos_dois_limiares():
    from tools.cnesdata_delivery import stage_wait
    from test_cnesdata_rest_model import CONDITION_2
    measured = stage_wait.governed_worst(stage_wait.MEASURED_HIT_RATES)["worst_rolling_hour"]
    condition_2 = stage_wait.governed_worst(CONDITION_2)["worst_rolling_hour"]
    assert measured <= stage_wait.REST_BUDGET and condition_2 <= stage_wait.REST_BUDGET_NO_JOBS_CREDIT


def _wait_inputs(api, clock, started=1000, ceiling=300, producers=None):
    from test_cnesdata_payload_wait import PRODUCER, RUN
    from tools.cnesdata_delivery import stage_wait
    stage_wait.wait_for_payloads(api, RUN, producers=[PRODUCER] if producers is None else producers, ceiling=ceiling,
                                 plan_inputs=("cnesdata-plan-inputs-p-4242-1", started), clock=clock, sleep=clock.sleep)


def _inputs(created):
    from tools.cnesdata_delivery import contract as c
    return {"id": 11, "name": "cnesdata-plan-inputs-p-4242-1", "digest": "sha256:" + "b" * 64, "created_at": c.utc(created)}


def test_espera_so_retorna_com_o_plan_inputs_criado_depois_do_inicio_do_job_de_plano():
    from test_cnesdata_payload_wait import ARTIFACT, DONE, Clock, Rounds
    clock, api = Clock(), Rounds(([DONE], [ARTIFACT]), ([DONE], [ARTIFACT, _inputs(1000)]), ([DONE], [ARTIFACT, _inputs(1004)]))
    _wait_inputs(api, clock)
    assert clock.now == 1010 and api.log.count("artifacts") == 3


def test_espera_com_plan_inputs_nao_faz_listagem_extra_por_sondagem():
    from test_cnesdata_payload_wait import ARTIFACT, DONE, Clock, Rounds
    api = Rounds(([DONE], [ARTIFACT, _inputs(1004)]))
    _wait_inputs(api, Clock())
    assert api.log == ["artifacts", "jobs"]


def test_espera_sem_produtores_retorna_so_com_o_plan_inputs_e_nao_le_jobs():
    from test_cnesdata_payload_wait import Clock, Rounds
    api = Rounds(([], []), ([], [_inputs(1004)]))
    _wait_inputs(api, Clock(), producers=[])
    assert api.log == ["artifacts", "artifacts"]


def test_espera_recusa_plan_inputs_duplicado_na_listagem():
    from test_cnesdata_payload_wait import ARTIFACT, DONE, Clock, Rounds
    api = Rounds(([DONE], [ARTIFACT, _inputs(1004), dict(_inputs(1005), id=12)]))
    with pytest.raises(ValueError, match="unique plan-inputs publication"):
        _wait_inputs(api, Clock())


def test_espera_atinge_o_teto_quando_o_plan_inputs_e_anterior_ao_inicio_do_job():
    from test_cnesdata_payload_wait import ARTIFACT, DONE, Clock, Rounds
    api = Rounds(([DONE], [ARTIFACT, _inputs(990)]))
    with pytest.raises(ValueError, match="stage_wait=ceiling payloads"):
        _wait_inputs(api, Clock(), ceiling=20)


def _vec():
    import json
    import pathlib
    return json.loads((pathlib.Path(__file__).parent / "fixtures/cnesdata_plan_inputs_p25_vector.json").read_text())


def _static_args(vector):
    return {"binding": vector["binding"], "application_promotion": vector["application_promotion"],
            "enabled_until": vector["enabled_until"]}


def test_composicao_do_plano_bootstrap_reproduz_o_vetor_do_produto():
    from tools.cnesdata_delivery import plan_inputs
    vector = _vec()
    raw = plan_inputs.compose("observer-bootstrap-plan", vector["base"], _static_args(vector), {})
    assert raw == bytes.fromhex(vector["bootstrap_inputs_hex"])


def test_composicao_do_plano_operacional_une_plano_inventory_e_mode_canary():
    from tools.cnesdata_delivery import plan_inputs
    vector = _vec()
    canary = {"context": "x"}
    extras = {"plan": bytes.fromhex(vector["plan_hex"]), "inventory": bytes.fromhex(vector["inventory_hex"]), "mode_canary": canary}
    raw = plan_inputs.compose("application-prepare-operational-plan", vector["base"], _static_args(vector), extras)
    assert raw == plan_inputs.inputs_bytes(vector["base"], vector["static_promotion"], canary)


@pytest.mark.parametrize("step", ["phase-b-plan", "phase-c-recovery-plan", "phase-c-audit-plan"])
def test_composicao_dos_demais_planos_e_so_a_base_com_as_duas_chaves_nulas(step):
    from tools.cnesdata_delivery import contract as c, plan_inputs
    vector = _vec()
    raw = plan_inputs.compose(step, vector["base"], None, {})
    assert c.loads(raw, canonical=True) == vector["base"] | {"static_promotion": None, "mode_canary": None}


@pytest.mark.parametrize("step, extras", [
    ("application-prepare-operational-plan", {"plan": b"{}", "inventory": b"{}"}),
    ("observer-bootstrap-plan", {"plan": b"{}"}), ("phase-b-plan", {"mode_canary": {}}),
], ids=["operacional-sem-canary", "bootstrap-com-plano", "outro-com-canary"])
def test_composicao_recusa_fontes_fora_do_papel_do_plano(step, extras):
    from tools.cnesdata_delivery import plan_inputs
    vector = _vec()
    with pytest.raises(ValueError, match="^plan_inputs=compose$"):
        plan_inputs.compose(step, vector["base"], _static_args(vector), extras)


SOURCE40 = "b" * 40
CANDIDATE = "candidate-" + SOURCE40 + "-3-1"
PHASE_A = {"image_digest": "sha256:" + "1" * 64, "processor_active_unit_task_definition_arn": "arn:a",
           "processor_retained_unit_task_definition_arns": [], "canary_storage_enabled": True,
           "canary_release_id": "r1", "canary_trusted_principal_arn": "arn:p"}
FRAGMENT = {"enabled_until": "2026-11-26T00:00:00Z", "evidence": {"bucket_arn": "arn:aws:s3:::evidence", "prefix": "p/"},
            "application_role_arn": "arn:r"}


def _world(monkeypatch, stage, plan_step):
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as gate, lifecycle_contract as lc, plan_inputs, session_owner
    window = {"stage": stage, "sequence": 0}
    record = {"lifecycle": window, "run_id": 4242, "run_attempt": 1, "generation": 3, "source_sha": SOURCE40}
    keeper = SimpleNamespace(lease=SimpleNamespace(check=lambda: record), phase_a_originals={"carrier": 1})
    governance = {"product_inputs": {"shared_outputs": {"account_id": "111122223333"}}, "gate_shas": {"application": "c" * 40},
                  "lifecycle_steps": {plan_step: {"role": "plan", "purpose": stage, "direction": "advance", "job_name": "plan job",
                                                  "mode": "observer-bootstrap"}}}
    published = []
    monkeypatch.setattr(lc, "owner_binding", lambda value: {"run_id": 4242, "run_attempt": 1, "generation": 3, "source_sha": SOURCE40})
    monkeypatch.setattr(lc, "phase_a_originals", lambda carrier: {"envelope": {"plan": {"phase_a_inputs": PHASE_A}}})
    monkeypatch.setattr(session_owner, "application_fragment", lambda governance, now: FRAGMENT)
    monkeypatch.setattr(plan_inputs, "publish_plan_inputs", lambda **kwargs: published.append(kwargs) or {"id": 1})
    monkeypatch.setattr(gate, "KeeperGuard", lambda current: SimpleNamespace(check=lambda seconds=0: None))
    return gate, keeper, governance, published


def test_abertura_de_estagio_publica_os_inputs_do_plano_antes_do_marcador(monkeypatch):
    from tools.cnesdata_delivery import stage_wait
    gate, keeper, governance, published = _world(monkeypatch, "phase-b", "phase-b-plan")
    order = []
    monkeypatch.setattr(gate, "_publish_plan_inputs", lambda *args: order.append("inputs"))
    monkeypatch.setattr(stage_wait, "publish_stage_open", lambda **kwargs: order.append("marker"))
    gate._publish_stage_open(keeper, None, {}, governance, 9000, lambda: 1000.0)
    assert order == ["inputs", "marker"]


def test_falha_na_publicacao_dos_inputs_impede_o_marcador_de_abertura(monkeypatch):
    from tools.cnesdata_delivery import stage_wait
    gate, keeper, governance, published = _world(monkeypatch, "phase-b", "phase-b-plan")
    order = []

    def refuse(*args):
        raise ValueError("plan_inputs=consumer_not_in_progress")
    monkeypatch.setattr(gate, "_publish_plan_inputs", refuse)
    monkeypatch.setattr(stage_wait, "publish_stage_open", lambda **kwargs: order.append("marker"))
    with pytest.raises(ValueError, match="plan_inputs=consumer_not_in_progress"):
        gate._publish_stage_open(keeper, None, {}, governance, 9000, lambda: 1000.0)
    assert order == []


def test_abertura_do_phase_b_publica_so_a_base_com_as_duas_chaves_nulas(monkeypatch):
    from tools.cnesdata_delivery import contract as c
    gate, keeper, governance, published = _world(monkeypatch, "phase-b", "phase-b-plan")
    gate._publish_plan_inputs(keeper, None, {"id": 4242, "run_attempt": 1}, governance, 9000, lambda: 1000.0)
    (call,) = published
    assert call["plan_step"] == "phase-b-plan" and call["phase_a_inputs"] == PHASE_A and call["credential_limit"] == 9000
    assert c.loads(call["raw"], canonical=True) == governance["product_inputs"] | PHASE_A | {"static_promotion": None, "mode_canary": None}


def test_abertura_do_application_prepare_publica_o_bootstrap_com_binding_do_candidato(monkeypatch):
    from tools.cnesdata_delivery import contract as c, static_inputs as si
    gate, keeper, governance, published = _world(monkeypatch, "application-prepare", "observer-bootstrap-plan")
    monkeypatch.setattr(gate, "_static_candidate", lambda *args: {"release_id": CANDIDATE})
    gate._publish_plan_inputs(keeper, None, {"id": 4242, "run_attempt": 1}, governance, 9000, lambda: 1000.0)
    (call,) = published
    value = c.loads(call["raw"], canonical=True)
    promotion = value["static_promotion"]
    assert call["plan_step"] == "observer-bootstrap-plan" and value["mode_canary"] is None
    assert promotion["mode"] == "observer-bootstrap" and promotion["binding"]["static_plan_sha256"] is None
    assert promotion["binding"]["release_id"] == si.binding_release_id(CANDIDATE)
    assert promotion["application_promotion"] == {"enabled_until": FRAGMENT["enabled_until"], "evidence": FRAGMENT["evidence"]}
    assert promotion["binding"]["shared_source_sha"] == "c" * 40 and promotion["binding"]["product_source_sha"] == SOURCE40


def test_inventory_liquidada_publica_os_inputs_do_plano_operacional(monkeypatch):
    from tools.cnesdata_delivery import contract as c, plan_inputs
    vector = _vec()
    gate, keeper, governance, published = _world(monkeypatch, "application-prepare", "application-prepare-operational-plan")
    governance["lifecycle_steps"]["application-prepare-operational-plan"].pop("mode")
    monkeypatch.setattr(gate, "_static_candidate", lambda *args: {"release_id": CANDIDATE})
    monkeypatch.setattr(gate, "_caller_artifact", lambda *args, **kwargs: {"static-plan.json": bytes.fromhex(vector["plan_hex"])})
    monkeypatch.setattr(plan_inputs, "mode_canary_source", lambda **kwargs: {"context": "x"})
    inventory = bytes.fromhex(vector["inventory_hex"])
    gate._publish_operational_plan_inputs(keeper, None, {"id": 4242, "run_attempt": 1}, governance, (inventory, 9000), lambda: 1000.0)
    (call,) = published
    value = c.loads(call["raw"], canonical=True)
    assert call["plan_step"] == "application-prepare-operational-plan" and value["mode_canary"] == {"context": "x"}
    assert value["static_promotion"]["mode"] == "operational"
    assert value["static_promotion"]["binding"]["static_plan_sha256"] == c.sha(bytes.fromhex(vector["plan_hex"]))
