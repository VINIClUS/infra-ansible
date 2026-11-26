"""P35 fix round 2: the pinned REST budget model over the real constants (one GITHUB_TOKEN bucket per repository)."""
import math
import pathlib
import re

import pytest

from tools.cnesdata_delivery import stage_wait

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / "tools/cnesdata_delivery/application_gate.py").read_text(encoding="utf-8")
REFERENCE = {"phase-b": 720, "api": 240, "static": 180, "unit": 120, "phase-c-recovery": 240, "phase-c-audit": 240, "final": 60}
MEASURED = {"jobs": 0.141, "artifacts": 0.929}
CONDITION_2 = {"jobs": 0.0, "artifacts": 0.8}


GOVERNED_WORST = {"phase-b": 720, "api": 180, "static": 180, "unit": 180, "phase-c-recovery": 240, "phase-c-audit": 240, "final": 60}
EXACT = {
    "measured": 2295.158, "condition_2": 3392.0, "vectors": 2827,
    "measured_components": {"keeper": 714.48, "marker_waiters": 392.616, "payload_waiters": 441.2, "admission": 615.0,
                            "probes": 71.862, "own_job": 15.0, "non_consumers": 25.0, "residual": 20},
    "governed_measured": (2337.758, GOVERNED_WORST, 1500), "governed_condition_2": (3512.0, GOVERNED_WORST, 1500),
}


def _model(rates=None, **options):
    return stage_wait.rest_model(rates, windows=REFERENCE, **options)


def _keeper_loop_poll_default():
    import ast
    (function,) = [n for n in ast.parse(SOURCE).body if isinstance(n, ast.FunctionDef) and n.name == "keeper_loop"]
    defaults = dict(zip((a.arg for a in function.args.kwonlyargs), function.args.kw_defaults))
    return ast.literal_eval(defaults["poll"])


def test_poll_do_keeper_no_modelo_e_o_default_de_keeper_loop():
    assert _keeper_loop_poll_default() == stage_wait.KEEPER_POLL_SECONDS
    assert stage_wait.KEEPER_POLL_SECONDS == stage_wait.POLL_SECONDS == 5


def test_o_modelo_conta_o_keeper_com_uma_listagem_de_jobs_por_sondagem_mais_as_leituras_dos_handlers():
    model = _model()
    stages = len(stage_wait.WINDOW_ORDER) + 1
    expected = math.ceil(model["run_seconds"] / stage_wait.KEEPER_POLL_SECONDS) + stages * stage_wait.HANDLER_READS_PER_STAGE
    assert model["components"]["keeper"] == expected


def test_modelo_sem_o_termo_do_keeper_zera_so_o_keeper():
    with_keeper, without = _model(), _model(include_keeper=False)
    assert without["components"]["keeper"] == 0
    assert {k: v for k, v in with_keeper["components"].items() if k != "keeper"} == \
        {k: v for k, v in without["components"].items() if k != "keeper"}
    assert with_keeper["worst_rolling_hour"] > without["worst_rolling_hour"]


def test_304_so_zera_a_leitura_na_taxa_de_acerto_medida_da_listagem():
    full = _model()["components"]
    hits = _model({"jobs": 1.0, "artifacts": 1.0})["components"]
    assert hits["marker_waiters"] == sum(stage_wait.G_JOBS.values()) * stage_wait.MARKER_HIT_READS
    assert hits["keeper"] == len(stage_wait.WINDOW_ORDER) * stage_wait.HANDLER_READS_PER_STAGE + stage_wait.HANDLER_READS_PER_STAGE
    assert hits["admission"] == full["admission"]
    half = _model({"artifacts": 0.5})["components"]["marker_waiters"]
    assert hits["marker_waiters"] < half < full["marker_waiters"]


def test_o_pior_intervalo_de_uma_hora_nao_passa_do_total_da_corrida_nem_e_menor_que_uma_componente():
    model = _model()
    assert 0 < model["worst_rolling_hour"] <= sum(model["components"].values())
    assert model["worst_rolling_hour"] >= model["components"]["probes"]


def test_corrida_do_modelo_cobre_a_reserva_de_preparacao_e_as_sete_janelas_do_codigo():
    model = _model()
    assert model["run_seconds"] == stage_wait.PREPARATION_ALLOWANCE_SECONDS + sum(REFERENCE.values())
    assert sum(stage_wait.G_JOBS.values()) == 15


def test_cauda_do_produtor_soma_upload_passos_pos_e_defasagem_de_conclusao():
    assert stage_wait.PRODUCER_TAIL_SECONDS == (stage_wait.UPLOAD_READBACK_SECONDS + stage_wait.POST_STEP_ALLOWANCE_SECONDS
                                                + stage_wait.COMPLETION_LAG_SECONDS) == 40 + 60 + 60


def test_execute_e_o_ultimo_passo_do_job_produtor_nos_tres_gates_de_infra():
    import yaml
    root = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows"
    for role in ("plan", "deploy", "audit"):
        workflow = yaml.safe_load((root / f"reusable-cnesdata-infra-{role}-gate.yml").read_text(encoding="utf-8"))
        (job,) = [value for value in workflow["jobs"].values() if "steps" in value]
        assert job["steps"][-1]["run"].endswith(" execute")


def test_jobs_listing_dos_consumidores_so_e_cobrada_pela_cauda_do_produtor():
    consumers = sum(stage_wait.PAYLOAD_CONSUMERS.values())
    polls = lambda seconds: math.ceil(seconds / stage_wait.POLL_SECONDS)
    per_consumer_tail = polls(stage_wait.PRODUCER_TAIL_SECONDS)
    only_jobs = _model({"artifacts": 1.0})["components"]["payload_waiters"]
    fixed = consumers * stage_wait.PRODUCERS_READS
    assert only_jobs == fixed + consumers * per_consumer_tail
    only_artifacts = _model({"jobs": 1.0})["components"]["payload_waiters"]
    assert only_artifacts > only_jobs


def test_leituras_contadas_dos_fixtures_sao_as_constantes_do_modelo():
    assert (stage_wait.ADMISSION_PREFLIGHT_READS, stage_wait.ADMISSION_FULL_READS) == (9, 9)
    assert stage_wait.PRODUCERS_READS == 3 and stage_wait.MARKER_HIT_READS == 3
    assert stage_wait.PAYLOAD_READS_PER_ADMISSION == 2 + stage_wait.LIFECYCLE_ARTIFACT_READS == 6


def test_leituras_do_lifecycle_artifact_sao_as_chamadas_api_read_da_funcao():
    import ast
    source = (pathlib.Path(__file__).resolve().parents[1] / "tools/cnesdata_delivery/provenance.py").read_text(encoding="utf-8")
    (function,) = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "lifecycle_artifact"]
    calls = [n for n in ast.walk(function) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "read" and getattr(n.func.value, "id", "") == "api"]
    assert len(calls) == stage_wait.LIFECYCLE_ARTIFACT_READS == 4


def test_sondas_do_cnesdata_entram_com_as_constantes_que_o_p35c_entrega():
    assert (stage_wait.PROBE_POLL_SECONDS, stage_wait.PROBE_ARTIFACT_READS_PER_POLL, stage_wait.PROBE_JOBS_READS_PER_MINUTE) == (5, 1, 1)
    probes = _model()["components"]["probes"]
    assert probes > 0
    assert _model({"artifacts": 1.0, "jobs": 1.0})["components"]["probes"] == 0


def test_limite_assumido_e_orcamento_da_regra_dos_60_por_cento():
    assert stage_wait.ASSUMED_RATE_LIMIT == 5000
    assert stage_wait.REST_BUDGET == 3000 == 60 * stage_wait.ASSUMED_RATE_LIMIT // 100
    assert stage_wait.REST_BUDGET_NO_JOBS_CREDIT == 4500 == 90 * stage_wait.ASSUMED_RATE_LIMIT // 100


def test_upload_readback_e_o_limite_de_codigo_de_duas_leituras_limitadas():
    import inspect
    from tools.cnesdata_delivery import aws_boundary
    timeout = inspect.signature(aws_boundary.bounded).parameters["timeout"].default
    assert stage_wait.UPLOAD_READBACK_SECONDS == 2 * timeout == 40


def test_taxas_medidas_e_hora_sao_as_do_run_45702629690():
    assert stage_wait.MEASURED_HIT_RATES == {"jobs": 0.141, "artifacts": 0.929}
    assert stage_wait.HOUR_SECONDS == 3600


def test_leituras_fora_do_modelo_entram_por_termos_nomeados_e_contados():
    components = _model()["components"]
    assert (stage_wait.OWN_JOB_READS_PER_G_JOB, stage_wait.NON_CONSUMER_PAYLOAD_READS, stage_wait.UNMODELED_RESIDUAL_READS) == (1, 5, 20)
    assert components["own_job"] == sum(stage_wait.G_JOBS.values()) * stage_wait.OWN_JOB_READS_PER_G_JOB == 15
    non_consumers = sum(stage_wait.G_JOBS.values()) - sum(stage_wait.PAYLOAD_CONSUMERS.values())
    assert components["non_consumers"] == non_consumers * stage_wait.NON_CONSUMER_PAYLOAD_READS == 25
    assert components["residual"] == stage_wait.UNMODELED_RESIDUAL_READS


def test_saida_exata_do_modelo_nas_taxas_medidas_e_na_condicao_2_no_vetor_de_referencia():
    assert _model(MEASURED)["worst_rolling_hour"] == pytest.approx(EXACT["measured"], abs=1e-3)
    assert _model(CONDITION_2)["worst_rolling_hour"] == pytest.approx(EXACT["condition_2"], abs=1e-3)


def test_sondas_e_cauda_exatas_no_vetor_de_referencia():
    assert _model(MEASURED)["components"] == pytest.approx(EXACT["measured_components"], abs=1e-3)


def test_ordem_das_janelas_do_modelo_e_a_dos_estagios_governados():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert tuple(lc.STAGES) == stage_wait.WINDOW_ORDER


def test_vetor_governado_pior_e_aceito_pelo_contrato_e_limita_todo_vetor_da_grade():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    worst = stage_wait.governed_worst(MEASURED)
    windows = worst["windows"]
    lc.governed_windows({"stages": windows, "fixed_deadline_seconds": sum(windows.values()) + lc.FINAL_RESERVE})
    assert worst["vectors"] == EXACT["vectors"]
    assert worst["worst_rolling_hour"] >= _model(MEASURED)["worst_rolling_hour"]
    assert worst["worst_rolling_hour"] >= stage_wait.rest_model(MEASURED, windows={n: lo for n, (lo, hi) in lc.STAGES.items()})["worst_rolling_hour"]


def test_pior_hora_governada_exata_nas_duas_condicoes_inclusive_com_marcador_de_preparacao_tardio():
    measured = stage_wait.governed_worst(MEASURED)
    condition_2 = stage_wait.governed_worst(CONDITION_2)
    for found, key in ((measured, "governed_measured"), (condition_2, "governed_condition_2")):
        hour, windows, prepare_open = EXACT[key]
        assert found["worst_rolling_hour"] == pytest.approx(hour, abs=1e-3)
        assert (found["windows"], found["prepare_open"]) == (windows, prepare_open)
    assert measured["prepare_open"] == condition_2["prepare_open"] == stage_wait.LATE_PREPARE_OPEN_SECONDS


def test_o_espaco_governado_segue_as_constantes_do_lifecycle_contract(monkeypatch):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    full = stage_wait.governed_worst(MEASURED)["vectors"]
    monkeypatch.setattr(lc, "STAGE_SUM_CEILING", 1500)
    stage_wait._governed_worst.cache_clear()
    try:
        assert 0 < stage_wait.governed_worst(MEASURED)["vectors"] < full
        monkeypatch.setattr(lc, "STAGES", {**lc.STAGES, "phase-b": (360, 420)})
        stage_wait._governed_worst.cache_clear()
        assert max(stage_wait.governed_worst(MEASURED)["windows"]["phase-b"], 0) <= 420
    finally:
        monkeypatch.undo()
        stage_wait._governed_worst.cache_clear()


def test_pior_hora_governada_cabe_nos_dois_orcamentos():
    assert stage_wait.governed_worst(stage_wait.MEASURED_HIT_RATES)["worst_rolling_hour"] <= stage_wait.REST_BUDGET
    assert stage_wait.governed_worst(CONDITION_2)["worst_rolling_hour"] <= stage_wait.REST_BUDGET_NO_JOBS_CREDIT


def test_folga_para_as_41_leituras_pontuais_do_p40_nos_dois_limiares():
    assert stage_wait.P40_POINT_READS == 41
    measured = stage_wait.governed_worst(stage_wait.MEASURED_HIT_RATES)["worst_rolling_hour"]
    condition_2 = stage_wait.governed_worst(CONDITION_2)["worst_rolling_hour"]
    assert measured + stage_wait.P40_POINT_READS <= stage_wait.REST_BUDGET
    assert condition_2 + stage_wait.P40_POINT_READS <= stage_wait.REST_BUDGET_NO_JOBS_CREDIT
