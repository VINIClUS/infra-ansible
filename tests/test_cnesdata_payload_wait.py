"""P35 fix round 1: the credential-free payload wait and payload_references share one publication predicate."""
import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_runtime as lr
from tools.cnesdata_delivery import stage_wait

ROOT = f"repos/{c.REPOSITORY}/actions"
RUN = {"id": 4242, "run_attempt": 1, "head_sha": "b" * 40}
JOBS = ROOT + "/runs/4242/attempts/1/jobs?per_page=100&page=1"
ARTIFACTS = ROOT + "/runs/4242/artifacts?per_page=100&page=1"
PRODUCER = {"name": "operational-plan / execute", "step": "prepared"}
DONE = {"id": 77, "name": PRODUCER["name"], "status": "completed", "conclusion": "success",
        "started_at": c.utc(1000), "completed_at": c.utc(1100)}
RUNNING = dict(DONE, status="in_progress", conclusion=None, completed_at=None)
ARTIFACT = {"id": 9, "name": "lifecycle-prepared", "digest": "sha256:" + "a" * 64, "created_at": c.utc(1050)}


class Rounds:
    def __init__(self, *rounds):
        self.rounds, self.reads = list(rounds), 0

    def read(self, path, raw=False):
        jobs, artifacts = self.rounds[min(self.reads // 2, len(self.rounds) - 1)]
        self.reads += 1
        if path == JOBS:
            return {"total_count": len(jobs), "jobs": list(jobs)}
        assert path == ARTIFACTS
        return {"total_count": len(artifacts), "artifacts": list(artifacts)}


class Clock:
    def __init__(self, now=1000):
        self.now = now

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _wait(api, clock, ceiling=300, producers=(PRODUCER,)):
    stage_wait.wait_for_payloads(api, RUN, producers=list(producers), ceiling=ceiling, clock=clock, sleep=clock.sleep)


def test_espera_nao_retorna_com_o_artefato_listado_e_o_produtor_em_andamento():
    clock = Clock()
    _wait(Rounds(([RUNNING], [ARTIFACT]), ([RUNNING], [ARTIFACT]), ([DONE], [ARTIFACT])), clock)
    assert clock.now == 1010


def test_espera_retorna_quando_o_produtor_conclui_com_sucesso_e_artefato_no_intervalo():
    clock = Clock()
    _wait(Rounds(([DONE], [ARTIFACT])), clock)
    assert clock.now == 1000


def test_espera_continua_enquanto_o_job_do_produtor_nao_existe():
    clock = Clock()
    _wait(Rounds(([], []), ([RUNNING], []), ([DONE], [ARTIFACT])), clock)
    assert clock.now == 1010


@pytest.mark.parametrize("round_", [
    ([dict(DONE, conclusion="failure")], [ARTIFACT]),
    ([DONE], []),
    ([DONE], [ARTIFACT, dict(ARTIFACT, id=10)]),
    ([DONE], [dict(ARTIFACT, created_at=c.utc(999))]),
    ([DONE], [dict(ARTIFACT, created_at=c.utc(1101))]),
    ([DONE, dict(DONE, id=78)], [ARTIFACT]),
])
def test_espera_recusa_de_imediato_o_que_a_admissao_recusaria(round_):
    clock = Clock()
    with pytest.raises(ValueError):
        _wait(Rounds(round_), clock)
    assert clock.now == 1000


def test_produtor_que_nao_conclui_expira_no_teto_da_espera():
    clock = Clock()
    with pytest.raises(ValueError, match="stage_wait=ceiling"):
        _wait(Rounds(([RUNNING], [ARTIFACT])), clock, ceiling=60)
    assert 1060 <= clock.now <= 1065


def test_espera_exige_todos_os_produtores():
    other = {"name": "other / execute", "step": "audited"}
    done_other = dict(DONE, id=78, name=other["name"])
    art_other = dict(ARTIFACT, id=10, name="lifecycle-audited")
    clock = Clock()
    _wait(Rounds(([DONE], [ARTIFACT]), ([DONE, done_other], [ARTIFACT, art_other])), clock, producers=[PRODUCER, other])
    assert clock.now == 1005


CASES = [
    ([DONE], [ARTIFACT]),
    ([RUNNING], [ARTIFACT]),
    ([], [ARTIFACT]),
    ([dict(DONE, conclusion="failure")], [ARTIFACT]),
    ([DONE], []),
    ([DONE], [ARTIFACT, dict(ARTIFACT, id=10)]),
    ([DONE], [dict(ARTIFACT, created_at=c.utc(1000))]),
    ([DONE], [dict(ARTIFACT, created_at=c.utc(1100))]),
    ([DONE], [dict(ARTIFACT, created_at=c.utc(1099))]),
]


def _admits(round_):
    try:
        lr.payload_references(Rounds(round_), RUN, {"plan": {"step": "prepared"}}, {"plan": PRODUCER})
    except ValueError:
        return False
    return True


def _wait_returns(round_):
    clock = Clock()
    try:
        _wait(Rounds(round_), clock, ceiling=10)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("round_", CASES)
def test_espera_e_payload_references_decidem_igual_pelo_mesmo_predicado(round_):
    assert _wait_returns(round_) == _admits(round_)


@pytest.mark.parametrize("round_", CASES)
def test_predicado_unico_aceita_so_o_que_a_admissao_aceita(round_):
    jobs, artifacts = round_
    try:
        found = stage_wait.payload_publication(jobs[0], artifacts, "prepared") if len(jobs) == 1 else None
    except ValueError:
        found = "refused"
    assert (found not in (None, "refused")) == _admits(round_)


@pytest.mark.parametrize("created, accepted", [(1000, False), (1001, True), (1099, True), (1100, False)])
def test_predicado_unico_exige_o_artefato_estritamente_dentro_do_intervalo(created, accepted):
    item = dict(ARTIFACT, created_at=c.utc(created))
    if accepted:
        assert stage_wait.payload_publication(DONE, [item], "prepared") == item
    else:
        with pytest.raises(ValueError, match="unique payload publication in job interval"):
            stage_wait.payload_publication(DONE, [item], "prepared")


@pytest.mark.parametrize("job", [None, RUNNING, dict(RUNNING, status="queued")])
def test_predicado_unico_devolve_none_enquanto_o_produtor_nao_concluiu(job):
    assert stage_wait.payload_publication(job, [ARTIFACT], "prepared") is None
