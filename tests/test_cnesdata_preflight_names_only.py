"""P35 fix round 1: preflight validates payload names only; the post-credential admission stays the authority (E1)."""
import copy
import os

import pytest

from tools.cnesdata_delivery import contract as c


def _case(monkeypatch, producer_status, conclusion=None):
    from test_cnesdata_application_gate import _application_caller_fixture
    from test_cnesdata_delivery_governance_hydration import admission_case
    _, _, _, step, _, _ = _application_caller_fixture(monkeypatch, "promotion", "plan")
    step.pop("caller_job")
    base = dict(step, role="plan", purpose="application-prepare", input_jobs={}, mode="observer-bootstrap",
                direction="advance")
    producer = dict(copy.deepcopy(base), job_name="producer-plan / execute")
    consumer = dict(copy.deepcopy(base), input_jobs={"plan": {"name": "producer-plan / execute", "step": "producer"}})
    lr, _, _, _ = admission_case(monkeypatch, steps={"keeper": consumer, "producer": producer})
    request = c.loads(os.environ["REQUEST_DESCRIPTOR"].encode(), canonical=True)
    request["payloads"] = {"plan": {"step": "producer"}}
    raw = c.canonical(request)
    monkeypatch.setenv("REQUEST_DESCRIPTOR", raw.decode())
    monkeypatch.setenv("REQUEST_DESCRIPTOR_SHA256", c.sha(raw))
    inner = lr.GitHub
    seen = []

    class E1(inner):
        def read(self, path, **kwargs):
            if path.endswith("/runs/44/attempts/2/jobs?per_page=100&page=1"):
                listing = copy.deepcopy(super().read(path, **kwargs))
                finished = producer_status == "completed"
                listing["jobs"].append({"id": 501, "name": "producer-plan / execute", "status": producer_status,
                                        "conclusion": conclusion, "started_at": c.utc(1000),
                                        "completed_at": c.utc(1100) if finished else None,
                                        "run_id": 44, "run_attempt": 2, "head_sha": "0" * 40})
                listing["total_count"] = len(listing["jobs"])
                seen.append("jobs")
                return listing
            if path.endswith("/runs/44/artifacts?per_page=100&page=1"):
                seen.append("artifacts")
                return {"total_count": 1, "artifacts": [{"id": 777, "name": "lifecycle-producer",
                                                         "digest": "sha256:" + "7" * 64, "created_at": c.utc(1050)}]}
            return super().read(path, **kwargs)
    monkeypatch.setattr(lr, "GitHub", E1)
    fetched = []
    monkeypatch.setattr(lr, "lifecycle_artifact", lambda api, reference, now, **kw: fetched.append(reference) or {})
    return lr, seen, fetched


@pytest.mark.parametrize("status", ["in_progress", "queued"])
def test_preflight_do_consumidor_passa_com_o_produtor_ainda_nao_concluido(monkeypatch, tmp_path, status):
    monkeypatch.chdir(tmp_path)
    lr, seen, fetched = _case(monkeypatch, status)
    lr.main("plan", "preflight")
    assert fetched == []


def test_preflight_do_consumidor_nao_le_o_estado_do_produtor(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    lr, seen, fetched = _case(monkeypatch, "completed", "success")
    lr.main("plan", "preflight")
    assert "artifacts" not in seen and fetched == []


@pytest.mark.parametrize("payloads", [{"plan": {"step": "other"}}, {"plan": {}}, {}, {"plan": {"step": "producer", "x": 1}},
                                      {"plan": {"step": "producer"}, "extra": {"step": "producer"}}])
def test_preflight_ainda_recusa_nomes_fora_do_inventario_governado(monkeypatch, tmp_path, payloads):
    monkeypatch.chdir(tmp_path)
    lr, _, _ = _case(monkeypatch, "in_progress")
    request = c.loads(os.environ["REQUEST_DESCRIPTOR"].encode(), canonical=True) | {"payloads": payloads}
    raw = c.canonical(request)
    monkeypatch.setenv("REQUEST_DESCRIPTOR", raw.decode())
    monkeypatch.setenv("REQUEST_DESCRIPTOR_SHA256", c.sha(raw))
    with pytest.raises(ValueError):
        lr.main("plan", "preflight")


def test_admissao_pos_credencial_ainda_recusa_produtor_em_andamento(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    lr, _, _ = _case(monkeypatch, "in_progress")
    with pytest.raises(ValueError, match="completed payload producer"):
        lr.admission("plan")


def test_admissao_pos_credencial_resolve_o_payload_do_produtor_concluido(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    lr, _, fetched = _case(monkeypatch, "completed", "success")
    lr.admission("plan")
    assert fetched == [{"job_id": 501, "artifact_id": 777, "artifact_digest": "sha256:" + "7" * 64}]
