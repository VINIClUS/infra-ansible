"""P35 fix round 2: the pinned REST budget model over the real constants (one GITHUB_TOKEN bucket per repository)."""
import math
import pathlib
import re

from tools.cnesdata_delivery import stage_wait

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / "tools/cnesdata_delivery/application_gate.py").read_text(encoding="utf-8")


def test_poll_do_keeper_no_modelo_e_o_default_de_keeper_loop():
    assert re.search(r"def keeper_loop\(keeper, \*, next_event, handlers, terminal, poll=(\d+), sleep=time.sleep\)", SOURCE).group(1) \
        == str(stage_wait.KEEPER_POLL_SECONDS)
    assert stage_wait.KEEPER_POLL_SECONDS == stage_wait.POLL_SECONDS == 5


def test_o_modelo_conta_o_keeper_com_uma_listagem_de_jobs_por_sondagem_mais_as_leituras_dos_handlers():
    model = stage_wait.rest_model()
    stages = len(stage_wait.WINDOW_ORDER) + 1
    expected = math.ceil(model["run_seconds"] / stage_wait.KEEPER_POLL_SECONDS) + stages * stage_wait.HANDLER_READS_PER_STAGE
    assert model["components"]["keeper"] == expected


def test_modelo_sem_o_termo_do_keeper_zera_so_o_keeper():
    with_keeper, without = stage_wait.rest_model(), stage_wait.rest_model(include_keeper=False)
    assert without["components"]["keeper"] == 0
    assert {k: v for k, v in with_keeper["components"].items() if k != "keeper"} == \
        {k: v for k, v in without["components"].items() if k != "keeper"}
    assert with_keeper["worst_rolling_hour"] > without["worst_rolling_hour"]


def test_304_so_zera_a_leitura_na_taxa_de_acerto_medida_da_listagem():
    full = stage_wait.rest_model()["components"]
    hits = stage_wait.rest_model({"jobs": 1.0, "artifacts": 1.0})["components"]
    assert hits["marker_waiters"] == sum(stage_wait.G_JOBS.values()) * stage_wait.MARKER_HIT_READS
    assert hits["keeper"] == len(stage_wait.WINDOW_ORDER) * stage_wait.HANDLER_READS_PER_STAGE + stage_wait.HANDLER_READS_PER_STAGE
    assert hits["admission"] == full["admission"]
    half = stage_wait.rest_model({"artifacts": 0.5})["components"]["marker_waiters"]
    assert hits["marker_waiters"] < half < full["marker_waiters"]


def test_o_pior_intervalo_de_uma_hora_nao_passa_do_total_da_corrida_nem_e_menor_que_uma_componente():
    model = stage_wait.rest_model()
    assert 0 < model["worst_rolling_hour"] <= sum(model["components"].values())
    assert model["worst_rolling_hour"] >= model["components"]["probes"]


def test_corrida_do_modelo_cobre_a_reserva_de_preparacao_e_as_sete_janelas_do_codigo():
    model = stage_wait.rest_model()
    assert model["run_seconds"] == stage_wait.PREPARATION_ALLOWANCE_SECONDS + 7 * stage_wait.CODE_BOUND_WINDOW_SECONDS
    assert sum(stage_wait.G_JOBS.values()) == 15


def test_cauda_do_produtor_soma_upload_passos_pos_e_defasagem_de_conclusao():
    assert stage_wait.PRODUCER_TAIL_SECONDS == (stage_wait.UPLOAD_READBACK_SECONDS + stage_wait.POST_STEP_ALLOWANCE_SECONDS
                                                + stage_wait.COMPLETION_LAG_SECONDS) == 30 + 60 + 60


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
    windows = stage_wait.PREPARATION_ALLOWANCE_SECONDS + 3 * stage_wait.CODE_BOUND_WINDOW_SECONDS
    per_consumer_tail = polls(stage_wait.PRODUCER_TAIL_SECONDS)
    only_jobs = stage_wait.rest_model({"artifacts": 1.0})["components"]["payload_waiters"]
    fixed = consumers * stage_wait.PRODUCERS_READS
    assert only_jobs == fixed + consumers * per_consumer_tail
    only_artifacts = stage_wait.rest_model({"jobs": 1.0})["components"]["payload_waiters"]
    assert only_artifacts > only_jobs and windows > 0


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
    probes = stage_wait.rest_model()["components"]["probes"]
    assert probes > 0
    assert stage_wait.rest_model({"artifacts": 1.0, "jobs": 1.0})["components"]["probes"] == 0


def test_limite_assumido_e_orcamento_da_regra_dos_60_por_cento():
    assert stage_wait.ASSUMED_RATE_LIMIT == 5000
    assert stage_wait.REST_BUDGET == 3000 == 60 * stage_wait.ASSUMED_RATE_LIMIT // 100
    assert stage_wait.REST_BUDGET_NO_JOBS_CREDIT == 4500 == 90 * stage_wait.ASSUMED_RATE_LIMIT // 100


def test_pior_hora_cabe_no_orcamento_com_as_taxas_de_304_medidas():
    assert stage_wait.rest_model(stage_wait.MEASURED_HIT_RATES)["worst_rolling_hour"] <= stage_wait.REST_BUDGET


def test_pior_hora_cabe_em_90_por_cento_sem_credito_de_304_nos_jobs_e_com_artefatos_a_0_8():
    model = stage_wait.rest_model({"jobs": 0.0, "artifacts": 0.8})
    assert model["worst_rolling_hour"] <= stage_wait.REST_BUDGET_NO_JOBS_CREDIT
