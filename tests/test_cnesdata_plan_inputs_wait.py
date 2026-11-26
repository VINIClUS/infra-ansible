"""P40 Codex fix 1: bounded guarded wait before the operational plan inputs are published."""
from types import SimpleNamespace

import pytest

from tools.cnesdata_delivery import lifecycle_contract as lc, stage_wait

RUN = {"id": 4242, "run_attempt": 1}
STEP = {"role": "plan", "job_name": "operational plan"}
GOVERNANCE = {"lifecycle_steps": {"application-prepare-operational-plan": STEP}}
START = 1000.0


def _job(name, status, conclusion=None):
    return {"name": name, "status": status, "conclusion": conclusion}


class Jobs:
    def __init__(self, script):
        self.script, self.reads = list(script), 0

    def read_conditional(self, path):
        assert path.endswith("/jobs?per_page=100&page=1")
        self.reads += 1
        jobs = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        return {"total_count": len(jobs), "jobs": jobs}

    read = read_conditional


class Clock:
    def __init__(self):
        self.now, self.sleeps = START, []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def _gate(monkeypatch, deadline=START + 3600):
    from tools.cnesdata_delivery import application_gate as gate
    ticks = []
    keeper = SimpleNamespace(lease=SimpleNamespace(check=lambda: {"lifecycle": {"close": None, "preparation_deadline": deadline}}))
    monkeypatch.setattr(gate, "KeeperGuard", lambda current: SimpleNamespace(check=lambda seconds=0: ticks.append(1)))
    monkeypatch.setattr(lc, "terminal_deadline", lambda window: window["preparation_deadline"])
    return gate, keeper, ticks


def _wait(gate, keeper, api, clock):
    return gate._await_operational_inputs(keeper, api, RUN, GOVERNANCE, (clock, clock.sleep))


PROBE_DONE = _job("static-inventory", "completed", "success")
PROBE_RUNNING = _job("static-inventory", "in_progress")
CONSUMER_RUNNING = _job("operational plan", "in_progress")
CONSUMER_QUEUED = _job("operational plan", "queued")


def test_publica_depois_que_a_sonda_de_inventario_termina(monkeypatch):
    gate, keeper, ticks = _gate(monkeypatch)
    clock = Clock()
    api = Jobs([[PROBE_RUNNING, CONSUMER_RUNNING], [PROBE_RUNNING, CONSUMER_RUNNING], [PROBE_DONE, CONSUMER_RUNNING]])
    _wait(gate, keeper, api, clock)
    assert clock.sleeps == [stage_wait.POLL_SECONDS] * 2 and ticks


def test_recusa_com_motivo_quando_a_sonda_nunca_termina(monkeypatch):
    gate, keeper, _ = _gate(monkeypatch, deadline=START + 900 + 30)
    clock = Clock()
    with pytest.raises(ValueError, match="^operational_inputs=static_inventory_timeout$"):
        _wait(gate, keeper, Jobs([[PROBE_RUNNING, CONSUMER_RUNNING]]), clock)
    assert clock.now >= START + 30


def test_aguarda_o_consumidor_iniciar(monkeypatch):
    gate, keeper, _ = _gate(monkeypatch)
    clock = Clock()
    api = Jobs([[PROBE_DONE, CONSUMER_QUEUED], [PROBE_DONE], [PROBE_DONE, CONSUMER_RUNNING]])
    _wait(gate, keeper, api, clock)
    assert len(clock.sleeps) == 2


def test_recusa_com_motivo_quando_o_consumidor_nao_inicia(monkeypatch):
    gate, keeper, _ = _gate(monkeypatch, deadline=START + 900 + 30)
    with pytest.raises(ValueError, match="^operational_inputs=consumer_not_started$"):
        _wait(gate, keeper, Jobs([[PROBE_DONE, CONSUMER_QUEUED]]), Clock())


def test_sonda_concluida_sem_sucesso_recusa_sem_esperar(monkeypatch):
    gate, keeper, _ = _gate(monkeypatch)
    clock = Clock()
    with pytest.raises(ValueError, match="^operational_inputs=static_inventory_failed$"):
        _wait(gate, keeper, Jobs([[_job("static-inventory", "completed", "failure"), CONSUMER_RUNNING]]), clock)
    assert clock.sleeps == []


def test_sem_espera_quando_ja_pronto_a_leitura_e_unica_por_listagem(monkeypatch):
    gate, keeper, _ = _gate(monkeypatch)
    clock, api = Clock(), Jobs([[PROBE_DONE, CONSUMER_RUNNING]])
    _wait(gate, keeper, api, clock)
    assert clock.sleeps == [] and api.reads == stage_wait.P40_WAIT_READS_PER_POLL == 1


def test_orcamento_da_espera_cabe_nos_dois_limiares():
    assert stage_wait.P40_WAIT_SECONDS == stage_wait.PREPARATION_ALLOWANCE_SECONDS - stage_wait.CEILING_MARGIN_SECONDS
    assert stage_wait.governed_worst(stage_wait.MEASURED_HIT_RATES)["worst_rolling_hour"] <= stage_wait.REST_BUDGET
    assert stage_wait.governed_worst({"jobs": 0.0, "artifacts": 0.8})["worst_rolling_hour"] <= stage_wait.REST_BUDGET_NO_JOBS_CREDIT
    windows = {"phase-b": 720, "api": 240, "static": 180, "unit": 120, "phase-c-recovery": 240, "phase-c-audit": 240, "final": 60}
    with_wait = stage_wait.rest_model(windows=windows)["components"]["keeper"]
    assert with_wait - stage_wait.rest_model(windows=windows, include_keeper=False)["components"]["keeper"] > \
        stage_wait.P40_WAIT_SECONDS // stage_wait.POLL_SECONDS
