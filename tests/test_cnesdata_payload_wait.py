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
    """One round per artifacts poll; the jobs listing of that poll is the same round. Plain reads of listings refuse."""
    def __init__(self, *rounds):
        self.rounds, self.polls, self.log = list(rounds), 0, []

    def read(self, path, raw=False):
        raise AssertionError(f"polled listing read without a conditional GET: {path}")

    def read_conditional(self, path):
        self.log.append("jobs" if path == JOBS else "artifacts")
        if path == ARTIFACTS:
            self.polls += 1
        jobs, artifacts, *total = self.rounds[min(self.polls, len(self.rounds)) - 1]
        if path == JOBS:
            return {"total_count": len(jobs), "jobs": list(jobs)}
        assert path == ARTIFACTS
        return {"total_count": total[0] if total else len(artifacts), "artifacts": list(artifacts)}


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
    ([DONE], [ARTIFACT, dict(ARTIFACT, id=10)]),
    ([DONE], [ARTIFACT], 2),
    ([DONE], [dict(ARTIFACT, created_at=c.utc(999))]),
    ([DONE], [dict(ARTIFACT, created_at=c.utc(1101))]),
    ([DONE, dict(DONE, id=78)], [ARTIFACT]),
])
def test_espera_recusa_de_imediato_o_que_a_admissao_recusaria(round_):
    clock = Clock()
    with pytest.raises(ValueError):
        _wait(Rounds(round_), clock)
    assert clock.now == 1000


def test_sem_artefato_do_produtor_a_espera_continua_ate_o_teto_sem_ler_a_listagem_de_jobs():
    api, clock = Rounds(([DONE], [])), Clock()
    with pytest.raises(ValueError, match="stage_wait=ceiling"):
        _wait(api, clock, ceiling=30)
    assert set(api.log) == {"artifacts"}


def test_listagem_de_jobs_so_e_lida_depois_que_todos_os_artefatos_dos_produtores_aparecem():
    other = {"name": "other / execute", "step": "audited"}
    api, clock = Rounds(([], [ARTIFACT]), ([DONE], [ARTIFACT]),
                        ([DONE, dict(DONE, id=78, name=other["name"])], [ARTIFACT, dict(ARTIFACT, id=10, name="lifecycle-audited")])), Clock()
    _wait(api, clock, producers=[PRODUCER, other])
    assert api.log == ["artifacts", "artifacts", "artifacts", "jobs"]


def test_uma_so_listagem_de_jobs_por_sondagem_para_todos_os_produtores():
    producers = [{"name": f"p{n} / execute", "step": f"s{n}"} for n in range(3)]
    jobs = [dict(DONE, id=80 + n, name=producers[n]["name"]) for n in range(3)]
    arts = [dict(ARTIFACT, id=20 + n, name=f"lifecycle-s{n}") for n in range(3)]
    api, clock = Rounds((jobs, arts)), Clock()
    _wait(api, clock, producers=producers)
    assert api.log.count("jobs") == 1 and api.log.count("artifacts") == 1


def test_dois_jobs_com_o_nome_do_produtor_sao_recusados():
    clock = Clock()
    with pytest.raises(ValueError, match="unique payload producer job"):
        _wait(Rounds(([DONE, dict(DONE, id=78)], [ARTIFACT])), clock)


def test_listagem_de_jobs_truncada_e_recusada():
    class Truncated(Rounds):
        def read_conditional(self, path):
            value = super().read_conditional(path)
            return value | {"total_count": 2} if path == JOBS else value
    with pytest.raises(ValueError, match="complete payload publication inventory"):
        _wait(Truncated(([DONE], [ARTIFACT])), Clock())


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
    ([DONE], [ARTIFACT], 2),
    ([DONE], [dict(ARTIFACT, created_at=c.utc(1000))]),
    ([DONE], [dict(ARTIFACT, created_at=c.utc(1100))]),
    ([DONE], [dict(ARTIFACT, created_at=c.utc(1099))]),
]


class Plain:
    """The post-credential admission read: one-shot, never conditional."""
    def __init__(self, round_):
        self.jobs, self.artifacts, *total = round_
        self.total = total[0] if total else len(self.artifacts)

    def read(self, path, raw=False):
        if path == JOBS:
            return {"total_count": len(self.jobs), "jobs": list(self.jobs)}
        assert path == ARTIFACTS
        return {"total_count": self.total, "artifacts": list(self.artifacts)}


def _admits(round_):
    try:
        lr.payload_references(Plain(round_), RUN, {"plan": {"step": "prepared"}}, {"plan": PRODUCER})
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


@pytest.mark.parametrize("round_", [case for case in CASES if len(case) == 2])
def test_predicado_unico_aceita_so_o_que_a_admissao_aceita(round_):
    jobs, artifacts, *_ = round_
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
