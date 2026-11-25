"""P35: pre-approved in-window jobs wait for their stage without credentials (E1, DD-2 extension)."""
import io
import json
import zipfile

import pytest

from tools.cnesdata_delivery import contract as c

RUN = {"id": 4242, "run_attempt": 1, "head_sha": "b" * 40}
ROOT = f"repos/{c.REPOSITORY}/actions"
JOBS = ROOT + "/runs/4242/attempts/1/jobs?per_page=100&page=1"
ARTIFACTS = ROOT + "/runs/4242/artifacts?per_page=100&page=1"
NAME = "cnesdata-stage-open-phase-b-4242-1"
INDEX = {"version": 1, "owner_sha256": "4" * 64, "generation": 7, "run_attempt": 1, "stage": "phase-b",
         "sequence": 3, "checkpoint_sha256": "f" * 64, "admitted_at": 1000, "deadline": 1360}
OWN = {"id": 91, "name": "phase-b-plan / execute", "status": "in_progress", "runner_name": "GitHub Actions 9",
       "started_at": c.utc(1000), "conclusion": None}
WINDOWS = {"stages": {"phase-b": 360, "api": 180, "static": 180, "unit": 120, "phase-c-recovery": 240,
                      "phase-c-audit": 240, "final": 60}, "fixed_deadline_seconds": 1800}


def _zip(index):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("index.json", c.canonical(index))
    return buffer.getvalue()


class Api:
    def __init__(self, *, index=INDEX, created=1010, count=1, jobs=(OWN,)):
        self.reads = []
        self.index, self.created, self.count, self.jobs = index, created, count, list(jobs)

    def read(self, path, raw=False):
        self.reads.append(path)
        archive = _zip(self.index)
        digest = "sha256:" + c.sha(archive)
        if path == JOBS:
            return {"total_count": len(self.jobs), "jobs": self.jobs}
        if path == ARTIFACTS:
            items = [{"id": 500 + n, "name": NAME, "digest": digest, "created_at": c.utc(self.created),
                      "expired": False, "workflow_run": {"id": 4242, "head_sha": "b" * 40}}
                     for n in range(self.count)]
            return {"total_count": len(items), "artifacts": items}
        if path.endswith("/zip"):
            return archive
        return {"id": int(path.rsplit("/", 1)[-1]), "name": NAME, "digest": digest, "created_at": c.utc(self.created),
                "expired": False, "expires_at": c.utc(9999999), "workflow_run": {"id": 4242, "head_sha": "b" * 40}}


class Clock:
    def __init__(self, now=1020):
        self.now = now

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _wait(api, *, stage="phase-b", clock=None, windows=WINDOWS):
    from tools.cnesdata_delivery import stage_wait
    clock = clock or Clock()
    return stage_wait.wait_for_stage(api, RUN, job=OWN, stage=stage, windows=windows, clock=clock, sleep=clock.sleep)


def test_constantes_do_wait_sao_as_do_ruling():
    from tools.cnesdata_delivery import stage_wait
    assert (stage_wait.POLL_SECONDS, stage_wait.TIMEOUT_MINUTES) == (5, 90)
    assert stage_wait.MAX_WAIT_SECONDS == 90 * 60 - 15 * 60
    assert stage_wait.STAGES_WITH_EXTERNAL_FIRST_JOB == ("application-prepare", "phase-b", "phase-c-recovery", "phase-c-audit")
    assert stage_wait.stage_open_name("phase-b", 4242, 1) == NAME


def test_marcador_valido_devolve_o_indice_fechado():
    assert _wait(Api()) == INDEX


@pytest.mark.parametrize("stage", ["api", "static", "unit", "final", "x"])
def test_estagio_sem_primeiro_job_externo_e_recusado(stage):
    with pytest.raises(ValueError, match="stage_wait=stage"):
        _wait(Api(), stage=stage)


def test_dois_marcadores_sao_recusados_na_hora_sem_esperar():
    clock = Clock()
    with pytest.raises(ValueError, match="unique stage-open marker"):
        _wait(Api(count=2), clock=clock)
    assert clock.now == 1020


@pytest.mark.parametrize("change", [{"stage": "api"}, {"run_attempt": 2}, {"version": 2}, {"extra": 1},
                                    {"owner_sha256": "x"}, {"generation": 0}, {"deadline": 1000}])
def test_indice_de_outro_estagio_tentativa_ou_forma_e_recusado(change):
    with pytest.raises(ValueError, match="stage-open"):
        _wait(Api(index=INDEX | change))


def test_marcador_criado_antes_do_inicio_do_proprio_job_e_recusado():
    with pytest.raises(ValueError, match="stage-open marker interval"):
        _wait(Api(created=999))


def test_marcador_do_futuro_e_recusado():
    with pytest.raises(ValueError, match="stage-open marker interval"):
        _wait(Api(created=5000), clock=Clock(1020))


def test_sem_marcador_espera_pelo_intervalo_e_falha_fechado_no_teto():
    from tools.cnesdata_delivery import stage_wait
    clock = Clock()
    api = Api(count=0)
    with pytest.raises(ValueError, match="stage_wait=ceiling stage=phase-b"):
        _wait(api, clock=clock)
    assert clock.now - 1020 >= stage_wait.wait_ceiling("phase-b", WINDOWS)
    assert clock.now - 1020 <= stage_wait.wait_ceiling("phase-b", WINDOWS) + stage_wait.POLL_SECONDS


def test_marcador_que_aparece_depois_e_aceito_antes_do_teto():
    api = Api(count=0)
    clock = Clock()
    original = clock.sleep

    def sleep(seconds):
        original(seconds)
        if clock.now >= 1050:
            api.count = 1

    from tools.cnesdata_delivery import stage_wait
    assert stage_wait.wait_for_stage(api, RUN, job=OWN, stage="phase-b", windows=WINDOWS, clock=clock,
                                     sleep=sleep) == INDEX


def test_zip_com_digest_diferente_e_recusado():
    api = Api()
    original = api.read

    def read(path, raw=False):
        value = original(path, raw)
        return value + b"x" if path.endswith("/zip") else value

    api.read = read
    with pytest.raises(ValueError, match="stage-open marker archive bytes"):
        _wait(api)


def test_teto_nunca_passa_do_timeout_menos_a_margem_e_cresce_com_o_estagio():
    from tools.cnesdata_delivery import stage_wait
    values = [stage_wait.wait_ceiling(stage, WINDOWS) for stage in stage_wait.STAGES_WITH_EXTERNAL_FIRST_JOB[1:]]
    assert values == sorted(values) and values[0] > 0
    assert all(value <= stage_wait.MAX_WAIT_SECONDS for value in values)
    maximum = {"stages": {name: high for name, high in zip(WINDOWS["stages"], (720, 360, 360, 360, 660, 660, 180))},
               "fixed_deadline_seconds": 3300}
    assert all(stage_wait.wait_ceiling(stage, maximum) <= stage_wait.MAX_WAIT_SECONDS
               for stage in stage_wait.STAGES_WITH_EXTERNAL_FIRST_JOB)


def test_job_proprio_e_o_unico_em_andamento_com_o_nome_do_runner():
    from tools.cnesdata_delivery import stage_wait
    other = OWN | {"id": 92, "runner_name": "other"}
    assert stage_wait.own_job(Api(jobs=[other, OWN]), RUN, "GitHub Actions 9") == OWN
    with pytest.raises(ValueError, match="own in-progress job"):
        stage_wait.own_job(Api(jobs=[other]), RUN, "GitHub Actions 9")
    with pytest.raises(ValueError, match="own in-progress job"):
        stage_wait.own_job(Api(jobs=[OWN, OWN | {"id": 93}]), RUN, "GitHub Actions 9")


def test_linha_de_tempo_e_uma_linha_chave_valor():
    from tools.cnesdata_delivery import stage_wait
    assert stage_wait.timing_line("phase-b", setup_seconds=41, wait_seconds=12) == \
        "stage_wait stage=phase-b setup_seconds=41 wait_seconds=12"


def test_modulo_nao_importa_aws_nem_boto():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "tools/cnesdata_delivery/stage_wait.py").read_text()
    assert "boto3" not in source and "AWS_" not in source and "sts" not in source.lower().split("def publish_stage_open")[0]


import pathlib

import yaml

from tools.cnesdata_delivery import stage_wait

WORKFLOWS = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"
INFRA_GATES = ("plan", "audit", "deploy")


def _steps(role):
    document = yaml.safe_load((WORKFLOWS / f"reusable-cnesdata-infra-{role}-gate.yml").read_text())
    job = document["jobs"]["execute"]
    return job, [step.get("name") for step in job["steps"]]


@pytest.mark.parametrize("role", INFRA_GATES)
def test_espera_do_estagio_roda_antes_das_credenciais_e_depois_do_setup(role):
    _, names = _steps(role)
    wait = names.index("Wait for the stage-open marker without credentials")
    assert names.index("Install checksum-locked protected runtime") < wait
    assert wait + 1 == names.index("Repeat source gate then request exact OIDC role")


@pytest.mark.parametrize("role", INFRA_GATES)
def test_gates_de_infra_usam_timeout_de_90_minutos(role):
    job, _ = _steps(role)
    assert job["timeout-minutes"] == stage_wait.TIMEOUT_MINUTES


def test_teto_da_espera_cabe_no_timeout_com_folga_de_15_minutos():
    assert stage_wait.MAX_WAIT_SECONDS <= (stage_wait.TIMEOUT_MINUTES - 15) * 60


GOVERNANCE = {"lifecycle_steps": {
    "phase-b-plan": {"role": "plan", "purpose": "phase-b", "direction": "advance", "job_name": "phase-b-plan / execute"},
    "phase-b-advance": {"role": "deploy", "purpose": "phase-b", "direction": "advance", "job_name": "phase-b / execute"},
    "keeper": {"role": "plan", "purpose": "application-prepare", "direction": "advance", "mode": "observer-bootstrap",
               "job_name": "bootstrap-plan / execute"},
    "operational-plan": {"role": "plan", "purpose": "application-prepare", "direction": "advance", "mode": "operational",
                         "job_name": "operational-plan / execute"}}}
OWNER = {"owner_sha256": "4" * 64, "generation": 7, "run_id": 4242, "run_attempt": 1}
WINDOW = {"stage": "phase-b", "sequence": 3, "checkpoint_sha256": "f" * 64, "admitted_at": 1000, "deadline": 1360}


@pytest.mark.parametrize("stage, job", [("phase-b", "phase-b-plan / execute"), ("application-prepare", "bootstrap-plan / execute")])
def test_primeiro_job_do_estagio_vem_do_passo_plan_governado(stage, job):
    assert stage_wait.first_job_name(GOVERNANCE, stage) == job


def test_estagio_sem_primeiro_job_unico_e_recusado():
    with pytest.raises(ValueError, match="stage-open first job"):
        stage_wait.first_job_name({"lifecycle_steps": {}}, "phase-b")


class Uploads:
    def __init__(self):
        self.calls = []

    def __call__(self, keeper, api, run, *, name, files, guard, credential_limit, clock):
        self.calls.append((name, files))
        return {"receipt": True}


def _publish(monkeypatch, api, window=WINDOW):
    from tools.cnesdata_delivery import application_gate as gate
    uploads = Uploads()
    monkeypatch.setattr(gate, "_upload_keeper_artifact", uploads)
    guard = type("Guard", (), {"check": lambda self, seconds=0: None})()
    return uploads, lambda: stage_wait.publish_stage_open(
        keeper=object(), guard=guard, api=api, run=RUN, owner=OWNER, window=window, first_job="phase-b-plan / execute",
        credential_limit=9999)


def test_marcador_so_e_publicado_com_o_primeiro_job_em_andamento(monkeypatch):
    uploads, publish = _publish(monkeypatch, Api())
    assert publish() == {"receipt": True}
    (name, files), = uploads.calls
    assert name == NAME and set(files) == {"index.json"}
    assert c.loads(files["index.json"], canonical=True) == INDEX


@pytest.mark.parametrize("jobs", [(), (dict(OWN, status="queued"),), (dict(OWN, status="completed", conclusion="success"),)])
def test_marcador_sem_primeiro_job_em_andamento_nao_e_publicado(monkeypatch, jobs):
    uploads, publish = _publish(monkeypatch, Api(jobs=jobs))
    with pytest.raises(ValueError, match="first job in progress"):
        publish()
    assert uploads.calls == []


def test_marcador_de_estagio_sem_primeiro_job_externo_nao_e_publicado(monkeypatch):
    uploads, publish = _publish(monkeypatch, Api(), window=WINDOW | {"stage": "api"})
    with pytest.raises(ValueError, match="stage_wait=stage"):
        publish()
    assert uploads.calls == []
