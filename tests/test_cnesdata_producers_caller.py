"""Caller cnesdata-producers.yml do observador, cujo merge e K (P33)."""
import subprocess
from pathlib import Path

import yaml

from fixtures.cnesdata_producers import OWNER
from test_cnesdata_producers_assembler import CALLER_K
from tools.cnesdata_delivery.producers import release_guard

ROOT = Path(__file__).resolve().parents[1]
X_STAR = "2a61ad885b435c4e40ee3eab8bf43b5e3c58f828"
REUSABLE = ".github/workflows/reusable-cnesdata-observer.yml"


def _caller():
    return yaml.safe_load((ROOT / OWNER["workflow_path"]).read_text())


def _job():
    jobs = _caller()["jobs"]
    assert len(jobs) == 1
    return next(iter(jobs.values()))


def _reusable_at_x_star():
    done = subprocess.run(["git", "-C", str(ROOT), "cat-file", "blob", f"{X_STAR}:{REUSABLE}"], capture_output=True,
                          check=True)
    return yaml.safe_load(done.stdout.decode())


def _last_caller_commit():
    done = subprocess.run(["git", "-C", str(ROOT), "log", "-1", "--format=%H", "--", OWNER["workflow_path"]],
                          capture_output=True, text=True, check=True)
    return done.stdout.strip()


def test_caller_cita_o_x_star_literal_no_uses_e_no_input():
    job = _job()
    assert job["uses"] == f"{release_guard.OBSERVER}@{X_STAR}"
    assert job["with"]["x_star"] == X_STAR


def test_with_e_secrets_conferem_com_o_workflow_call_do_reusable_em_x_star():
    call, job = _reusable_at_x_star()["on"]["workflow_call"], _job()
    assert set(job["with"]) == set(call["inputs"])
    assert set(job["secrets"]) == set(call["secrets"])
    assert all(job["secrets"][name] == "${{ secrets." + name + " }}" for name in call["secrets"])


def test_inputs_do_dispatch_sao_os_publicos_do_reusable_sem_o_x_star():
    caller, job = _caller(), _job()
    assert set(caller["on"]) == {"workflow_dispatch"}
    inputs = caller["on"]["workflow_dispatch"]["inputs"]
    assert set(inputs) == set(job["with"]) - {"x_star"}
    assert all(job["with"][name] == "${{ inputs." + name + " }}" for name in inputs)


def test_descricao_do_role_no_dispatch_e_a_do_reusable_em_x_star():
    dispatch = _caller()["on"]["workflow_dispatch"]["inputs"]["role"]
    called = _reusable_at_x_star()["on"]["workflow_call"]["inputs"]["role"]
    assert dispatch["description"] == called["description"]
    assert dispatch["description"] == "Delivery role, plan, audit, deploy or application (lifecycle owner cycle)"


def test_permissoes_sao_a_uniao_das_dos_jobs_do_reusable_e_nada_mais():
    reusable, caller, job = _reusable_at_x_star(), _caller(), _job()
    union = {}
    for item in reusable["jobs"].values():
        union |= item["permissions"]
    assert caller["permissions"] == {}
    assert job["permissions"] == union == {"actions": "read", "contents": "read", "id-token": "write"}


def test_environment_do_observador_vem_do_job_observe_do_reusable_e_nao_do_caller():
    job = _job()
    assert "environment" not in job and "runs-on" not in job
    assert _reusable_at_x_star()["jobs"]["observe"]["environment"] == "cnesdata-observer"
    assert "self-hosted" not in (ROOT / OWNER["workflow_path"]).read_text()


def test_identidade_do_caller_e_a_do_owner_producer_e_do_caller_k():
    assert OWNER["workflow_path"] == CALLER_K["workflow_path"] == release_guard.CALLER
    assert OWNER["repository"] == CALLER_K["repository"]
    assert _job()["uses"].startswith(OWNER["repository"] + "/.github/workflows/")


def test_guarda_do_dono_aceita_x_star_ate_o_commit_do_caller():
    release_guard.check(ROOT, X_STAR, _last_caller_commit())
