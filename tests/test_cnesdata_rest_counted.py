"""P35 fix round 2: the model's read constants are counted from the fixtures, not estimated."""
import os

from test_cnesdata_delivery_governance_hydration import admission_case
from test_cnesdata_payload_wait import DONE, ARTIFACT, JOBS, ARTIFACTS, PRODUCER, RUN
from test_cnesdata_stage_wait import Api, _wait
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_runtime as lr
from tools.cnesdata_delivery import stage_wait


def _counted(reads, call):
    before = len(reads)
    call()
    return len(reads) - before


def test_admissao_de_preflight_le_o_numero_contado_de_vezes(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    module, _, _, reads = admission_case(monkeypatch)
    assert _counted(reads, lambda: module.admission("plan", resolve_payloads=False)) == stage_wait.ADMISSION_PREFLIGHT_READS


def test_admissao_completa_sem_payloads_le_o_numero_contado_de_vezes(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    module, _, _, reads = admission_case(monkeypatch)
    assert _counted(reads, lambda: module.admission("plan")) == stage_wait.ADMISSION_FULL_READS


def test_produtores_da_espera_leem_o_numero_contado_de_vezes(monkeypatch, tmp_path):
    import json
    monkeypatch.chdir(tmp_path)
    module, governance, _, reads = admission_case(monkeypatch)
    request = c.loads(os.environ["REQUEST_DESCRIPTOR"].encode(), canonical=True)
    count = _counted(reads, lambda: stage_wait._producers(module.GitHub(), {}, json.loads(os.environ["CNESDATA_DELIVERY_GOVERNANCE"]), request))
    assert count == stage_wait.PRODUCERS_READS


def test_acerto_do_marcador_le_listagem_metadados_e_zip():
    api = Api()
    _wait(api)
    assert len(api.reads) == stage_wait.MARKER_HIT_READS


def test_resolucao_de_um_payload_le_duas_listagens():
    reads = []

    class Counting:
        def read(self, path, raw=False):
            reads.append(path)
            if path == JOBS:
                return {"total_count": 1, "jobs": [DONE]}
            assert path == ARTIFACTS
            return {"total_count": 1, "artifacts": [ARTIFACT]}
    lr.payload_references(Counting(), RUN, {"plan": {"step": "prepared"}}, {"plan": PRODUCER})
    assert len(reads) == 2 == stage_wait.PAYLOAD_READS_PER_ADMISSION - stage_wait.LIFECYCLE_ARTIFACT_READS
