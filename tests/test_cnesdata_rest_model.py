"""P35 fix round 2: the pinned REST budget model over the real constants (one GITHUB_TOKEN bucket per repository)."""
import math
import pathlib
import re

from tools.cnesdata_delivery import stage_wait

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / "tools/cnesdata_delivery/application_gate.py").read_text(encoding="utf-8")


def test_poll_do_keeper_no_modelo_e_o_default_de_keeper_loop():
    assert re.search(r"def keeper_loop\(keeper, \*, next_event, handlers, poll=(\d+), sleep=time.sleep\)", SOURCE).group(1) \
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
    assert hits["probes"] == full["probes"] and hits["admission"] == full["admission"]
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
