"""P35 Q2: lifecycle request payloads are producer step names, never artifact ids."""
import importlib

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_runtime as lr

ROOT = f"repos/{c.REPOSITORY}/actions"
RUN = {"id": 4242, "run_attempt": 1, "head_sha": "b" * 40}
JOBS = ROOT + "/runs/4242/attempts/1/jobs?per_page=100&page=1"
ARTIFACTS = ROOT + "/runs/4242/artifacts?per_page=100&page=1"
PRODUCER = {"name": "operational-plan / execute", "step": "prepared"}
JOB = {"id": 77, "name": PRODUCER["name"], "status": "completed", "conclusion": "success",
       "started_at": c.utc(1000), "completed_at": c.utc(1100)}
ARTIFACT = {"id": 9, "name": "lifecycle-prepared", "digest": "sha256:" + "a" * 64, "created_at": c.utc(1050)}


class Api:
    def __init__(self, jobs=(JOB,), artifacts=(ARTIFACT,)):
        self.jobs, self.artifacts = list(jobs), list(artifacts)

    def read(self, path, raw=False):
        if path == JOBS:
            return {"total_count": len(self.jobs), "jobs": self.jobs}
        assert path == ARTIFACTS
        return {"total_count": len(self.artifacts), "artifacts": self.artifacts}


def _refs(api=None, payloads=None):
    return lr.payload_references(api or Api(), RUN, payloads if payloads is not None else {"plan": {"step": "prepared"}},
                                 {"plan": PRODUCER})


def test_payload_por_nome_resolve_job_e_artefato_do_proprio_run():
    assert _refs() == {"plan": {"job_id": 77, "artifact_id": 9, "artifact_digest": "sha256:" + "a" * 64}}


@pytest.mark.parametrize("payloads", [
    {"plan": {"artifact_id": 9, "artifact_digest": "sha256:" + "a" * 64, "job_id": 77}},
    {"plan": {"step": "prepared", "artifact_id": 9}},
    {"plan": {"step": "other"}},
    {"plan": {}},
    {},
    {"plan": {"step": "prepared"}, "extra": {"step": "prepared"}},
])
def test_forma_antiga_com_ids_ou_fora_do_inventario_e_recusada(payloads):
    with pytest.raises(ValueError):
        _refs(payloads=payloads)


@pytest.mark.parametrize("api", [
    Api(jobs=()),
    Api(jobs=(JOB, dict(JOB, id=78))),
    Api(jobs=(dict(JOB, status="in_progress", conclusion=None),)),
    Api(jobs=(dict(JOB, conclusion="failure"),)),
    Api(artifacts=()),
    Api(artifacts=(ARTIFACT, dict(ARTIFACT, id=10))),
    Api(artifacts=(dict(ARTIFACT, created_at=c.utc(999)),)),
    Api(artifacts=(dict(ARTIFACT, created_at=c.utc(1101)),)),
])
def test_produtor_ausente_ambiguo_ou_fora_do_intervalo_e_recusado(api):
    with pytest.raises(ValueError):
        _refs(api)


def test_descritor_do_produtor_so_aceita_nomes():
    application = importlib.import_module("tools.cnesdata_delivery.producers.application")
    raw, _ = application.descriptor("c" * 64, source_sha="b" * 40, step="keeper", purpose="promotion",
                                    payloads={"plan": {"step": "prepared"}})
    assert c.loads(raw, canonical=True)["payloads"] == {"plan": {"step": "prepared"}}
    with pytest.raises(ValueError):
        application.descriptor("c" * 64, source_sha="b" * 40, step="keeper", purpose="promotion",
                               payloads={"plan": {"artifact_id": 1, "artifact_digest": "sha256:" + "1" * 64, "job_id": 2}})


def test_vetor_fixa_o_descritor_com_nomes():
    import json
    import pathlib
    vector = json.loads((pathlib.Path(__file__).parent / "fixtures" / "cnesdata_lifecycle_request_names_vector.json").read_text())
    application = importlib.import_module("tools.cnesdata_delivery.producers.application")
    raw, digest = application.descriptor("c" * 64, source_sha="b" * 40, step="keeper", purpose="promotion",
                                         payloads={"plan": {"step": "prepared"}, "audit": {"step": "audited"}})
    assert raw.decode() == vector["descriptor_canonical_utf8"]
    assert digest == vector["descriptor_sha256"]


OWNER = {"owner_sha256": "4" * 64, "generation": 7}


def _env(**extra):
    return {"PURPOSE": "phase-b", "STAGE_OPEN_OWNER_SHA256": "4" * 64, "STAGE_OPEN_GENERATION": "7", **extra}


def test_dono_do_lease_igual_ao_do_marcador_e_aceito():
    lr.bind_stage_open_owner(OWNER, _env())


@pytest.mark.parametrize("environ", [
    _env(STAGE_OPEN_OWNER_SHA256="5" * 64),
    _env(STAGE_OPEN_GENERATION="8"),
    {"PURPOSE": "phase-b"},
])
def test_dono_ou_geracao_diferente_do_marcador_e_recusado(environ):
    with pytest.raises(ValueError, match="stage-open owner"):
        lr.bind_stage_open_owner(OWNER, environ)


def test_proposito_sem_marcador_nao_exige_dono():
    lr.bind_stage_open_owner(OWNER, {"PURPOSE": "static-maintenance"})
