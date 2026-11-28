"""X7: host gate deriva o caller da execução viva e aceita a emissão real do keeper."""

import copy
import json
import os
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from test_personal_platform_dispatcher import (
    H,
    SHA,
    authenticated_fixture,
    closed_ready_fixture,
    runtime,
)

PREFIX = "repos/VINIClUS/CnesData/"
S6 = "f5bd7a95f1e6f591b2ceecf305863102bd95af50"
NOW = "2029-12-31T23:03:00Z"
SELECTORS = {
    "plan_evidence_id",
    "plan_evidence_digest",
    "plan_run_id",
    "artifact_id",
    "artifact_digest",
}


def listing(workflow):
    return (
        PREFIX
        + f"actions/workflows/{workflow}/runs?branch=main&event=workflow_dispatch"
        + f"&status=in_progress&head_sha={SHA}&per_page=100"
    )


def keeper_close(g, close):
    from tools.cnesdata_delivery import application_gate as ag
    from tools.cnesdata_delivery import contract as c
    from tools.cnesdata_delivery.session_owner import Authority

    pin = {
        "role_arn": "cnesdata-prod-ops",
        "frozen_until": c.utc(7000),
    }
    fragment = {
        "application_role_arn": "cnesdata-prod-app",
        "enabled_until": c.utc(6000),
    }
    authority = Authority(pin, 5000.0, None, fragment, "3" * 64)
    api = SimpleNamespace(
        expiries={(c.REPOSITORY, 81): 6500.0}, digests={(c.REPOSITORY, 81): "2" * 64}
    )
    keeper = json.loads(ag.close_expirations(authority, api))
    receipt = {
        "closed_membership_sha256": close["frozen_membership_sha256"],
        "expires_at": g.utc(3000),
    }
    envelope = {
        "kind": "envelope",
        "object_sha256": g.sha(g.canonical(receipt)),
        "expires_at": g.utc(3000),
    }
    entries = sorted([*keeper, envelope], key=lambda e: (e["kind"], e["object_sha256"]))
    close["input_expirations"] = entries
    close["fixed_deadline"] = g.utc(
        min(
            660 + close["windows"]["fixed_deadline_seconds"],
            *(g.instant(e["expires_at"]) for e in entries),
        )
    )
    return keeper


def rerun(responses, attempt=2, total=1):
    live = copy.deepcopy(responses[PREFIX + "actions/runs/11/attempts/1"])
    live["run_attempt"] = attempt
    responses[PREFIX + f"actions/runs/11/attempts/{attempt}"] = live
    responses[listing("deploy.yml")] = {
        "total_count": total,
        "workflow_runs": [live] * total,
    }


class Overlay:
    clock = None

    def __init__(self, api, extra):
        self.api, self.extra = api, extra

    def read(self, path, **kwargs):
        if path in self.extra:
            return copy.deepcopy(self.extra[path])
        return self.api.read(path, **kwargs)


def runner_env(monkeypatch, value, attempt):
    platform = value["binding"]["platform"]
    for key, item in {
        "PLAN_EVIDENCE_ID": platform["evidence_id"],
        "PLAN_EVIDENCE_DIGEST": platform["evidence_sha256"],
        "PLAN_RUN_ID": "12",
        "ARTIFACT_ID": "20",
        "ARTIFACT_DIGEST": value["binding"]["ci_artifact"]["artifact_digest"],
        "GITHUB_REPOSITORY": "VINIClUS/CnesData",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": SHA,
        "GITHUB_RUN_ID": "11",
        "GITHUB_RUN_ATTEMPT": str(attempt),
    }.items():
        monkeypatch.setenv(key, item)


def test_admite_close_drain_com_expiracoes_reais_do_keeper():
    g, clock, gov, api, _, close, _, _, pack = closed_ready_fixture()
    keeper = keeper_close(g, close)
    assert {e["kind"] for e in keeper} == {"credential", "platform", "artifact"}
    pack()
    admission = g.admit_physical_action(gov["binding"], gov, api, clock)
    assert admission.window(clock).fixed_deadline == 2730


@pytest.mark.parametrize(
    ("expiry", "reason"),
    [(1000, "original stage deadline"), (2000, "original API admission budget")],
)
def test_recusa_expiry_proprio_do_host_antes_do_estagio_ou_do_orcamento(expiry, reason):
    g, clock, gov, api, _, close, _, _, pack = closed_ready_fixture()
    keeper_close(g, close)
    cost = next(e for e in gov["binding"]["expires"] if e["name"] == "cost")
    cost["expires_at"] = g.utc(expiry)
    pack()
    with pytest.raises(ValueError, match=reason):
        g.admit_physical_action(gov["binding"], gov, api, clock)


def test_host_deriva_o_caller_da_execucao_viva_e_nao_do_secret(tmp_path, monkeypatch):
    g = runtime()
    request, gov, api, responses = authenticated_fixture(tmp_path, monkeypatch)
    gov["binding"]["caller"].update(run_id=1, run_attempt=1)
    original = copy.deepcopy(gov)
    rerun(responses)
    b, _ = g.authenticate_request(request, gov, api, g.instant(NOW))
    assert (b["caller"]["run_id"], b["caller"]["run_attempt"]) == (11, 2)
    assert gov == original


@pytest.mark.parametrize("total", [0, 2])
def test_host_recusa_sem_uma_unica_execucao_viva(tmp_path, monkeypatch, total):
    g = runtime()
    request, gov, api, responses = authenticated_fixture(tmp_path, monkeypatch)
    rerun(responses, attempt=1, total=total)
    with pytest.raises(ValueError, match="live caller"):
        g.authenticate_request(request, gov, api, g.instant(NOW))


@pytest.mark.parametrize("field", ["source_sha256", "expires_at"])
def test_host_confere_o_expiry_do_envelope_com_os_bytes_autenticados(
    tmp_path, monkeypatch, field
):
    g = runtime()
    request, gov, api, _ = authenticated_fixture(tmp_path, monkeypatch)
    entry = next(e for e in gov["binding"]["expires"] if e["name"] == "envelope")
    entry[field] = H if field == "source_sha256" else "2029-12-31T23:59:00Z"
    with pytest.raises(ValueError, match="original envelope expiry"):
        g.authenticate_request(request, gov, api, g.instant(NOW))


@pytest.mark.parametrize(("env_attempt", "ok"), [(2, True), (1, False)])
def test_runner_usa_a_tentativa_viva_e_recusa_ambiente_de_outra(
    tmp_path, monkeypatch, env_attempt, ok
):
    from test_personal_platform_host_path import NOW as HOST_NOW
    from test_personal_platform_host_path import build, governed

    g, hp, seen, static, _, api = governed(tmp_path, monkeypatch)
    value = g.host_json(build(hp, static, seen, run_id=11, attempt=1))
    live = copy.deepcopy(api.read(PREFIX + "actions/runs/11/attempts/1"))
    live["run_attempt"] = 2
    overlay = Overlay(
        api,
        {
            PREFIX + "actions/runs/11/attempts/2": live,
            listing("promote-production.yml"): {"total_count": 1, "workflow_runs": [live]},
        },
    )
    monkeypatch.setattr(g, "GitHub", lambda token, clock=None: overlay)
    monkeypatch.setattr(g.time, "time", lambda: g.instant(HOST_NOW))
    runner_env(monkeypatch, value, env_attempt)
    if ok:
        request = g.runner_request(value, bytearray(b"fixture-token"))
        assert request.binding["caller"]["run_attempt"] == 2
    else:
        with pytest.raises(ValueError, match="actual caller environment"):
            g.runner_request(value, bytearray(b"fixture-token"))


@pytest.mark.skipif(
    not os.environ.get("CNESDATA_TEST_PRODUCT_CHECKOUT"),
    reason="external_target_absent: set CNESDATA_TEST_PRODUCT_CHECKOUT to a CnesData clone",
)
def test_caller_real_do_s6_nao_carrega_execucao_e_o_host_deriva_a_viva():
    g = runtime()
    raw = subprocess.run(
        [
            "git",
            "-C",
            os.environ["CNESDATA_TEST_PRODUCT_CHECKOUT"],
            "show",
            S6 + ":.github/workflows/promote-production.yml",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    ).stdout
    jobs = yaml.safe_load(raw)["jobs"]
    host = jobs["host-gate"]
    assert set(host["with"]) == SELECTORS
    assert set(host["secrets"]) == {"host_governance"}
    assert "closed-ready" in jobs and "closed-ready" in host["needs"]
    caller = {
        "repository": "VINIClUS/CnesData",
        "source_sha": SHA,
        "ref": "refs/heads/main",
        "workflow_path": ".github/workflows/promote-production.yml",
        "workflow_sha": SHA,
        "run_id": 1,
        "run_attempt": 1,
    }
    run = {"id": 4242, "run_attempt": 2, "path": caller["workflow_path"]}
    routes = {listing("promote-production.yml"): {"total_count": 1, "workflow_runs": [run]}}
    live = g.live_caller(caller, SimpleNamespace(read=lambda path, **_: routes[path]))
    assert (live["run_id"], live["run_attempt"]) == (4242, 2)
    assert {k: v for k, v in live.items() if k not in {"run_id", "run_attempt"}} == {
        k: v for k, v in caller.items() if k not in {"run_id", "run_attempt"}
    }
