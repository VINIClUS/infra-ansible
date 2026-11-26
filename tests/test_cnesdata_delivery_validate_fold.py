"""DD-6 (i), design C: o job validate foi dobrado em execute nos reusables plan e deploy."""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = ("plan", "deploy")
GATE = {"plan": "plan_gate", "deploy": "apply_gate"}


def load(role):
    path = ROOT / ".github/workflows" / f"reusable-cnesdata-infra-{role}-gate.yml"
    return yaml.safe_load(path.read_text())


def index_of(steps, suffix):
    found = [i for i, step in enumerate(steps) if step.get("run", "").endswith(suffix)]
    assert len(found) == 1
    return found[0]


@pytest.mark.parametrize("role", ROLES)
def test_reusable_tem_um_unico_job_execute_com_ambiente_production(role):
    workflow = load(role)
    assert set(workflow["jobs"]) == {"execute"}
    assert workflow["jobs"]["execute"]["environment"] == "production"
    assert "needs" not in workflow["jobs"]["execute"]


@pytest.mark.parametrize("role", ROLES)
def test_reusable_nao_tem_job_validate_nem_referencia_a_ele(role):
    path = ROOT / ".github/workflows" / f"reusable-cnesdata-infra-{role}-gate.yml"
    text = path.read_text()
    assert "validate" not in load(role)["jobs"]
    assert re.search(r"needs\.validate|jobs\.validate|needs:\s*validate", text) is None


@pytest.mark.parametrize("role", ROLES)
def test_oidc_existe_somente_no_job_com_environment(role):
    workflow = load(role)
    assert workflow["permissions"] == {}
    for name, job in workflow["jobs"].items():
        grants = job.get("permissions", {})
        if grants.get("id-token") == "write":
            assert job.get("environment") == "production", name
    assert workflow["jobs"]["execute"]["permissions"]["id-token"] == "write"


@pytest.mark.parametrize("role", ROLES)
def test_prova_de_admissao_vem_antes_do_primeiro_passo_de_credencial(role):
    steps = load(role)["jobs"]["execute"]["steps"]
    gate = GATE[role]
    preflight = index_of(steps, f"{gate} preflight")
    credentials = index_of(steps, f"{gate} credentials")
    execute = index_of(steps, f"{gate} execute")
    assert steps[0]["name"] == "Load actual immutable producer from authenticated run"
    assert 0 < preflight < credentials < execute
    assert not any("credentials" in step.get("run", "") for step in steps[:credentials])


@pytest.mark.parametrize("role", ROLES)
def test_execute_preserva_pins_checksums_timeout_e_interface(role):
    workflow = load(role)
    job = workflow["jobs"]["execute"]
    assert job["timeout-minutes"] == 90
    for step in job["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
    runtime = next(s["run"] for s in job["steps"] if s["name"].startswith("Install checksum-locked"))
    assert runtime.count("sha256sum -c -") == 2
    assert set(job["outputs"]) == {"evidence_run_id", "evidence_artifact_id",
                                   "evidence_artifact_digest", "evidence_status"}
    call = workflow["on"]["workflow_call"]
    assert set(call["outputs"]) == set(job["outputs"])
    assert all(v["value"].startswith("${{ jobs.execute.outputs.") for v in call["outputs"].values())
    assert set(call["inputs"]) == {
        "request_descriptor", "request_descriptor_sha256", "contract_repository", "contract_source_sha",
        "contract_path", "contract_sha256", "expected_source_sha", "purpose"}
    assert set(call["secrets"]) == {"CNESDATA_DELIVERY_GOVERNANCE"}
