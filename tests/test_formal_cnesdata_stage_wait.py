"""F4 conformance of the stage wait: each safety mutant must be caught by the oracle, the baseline must pass it."""
import ast
import pathlib
import types

import pytest
import yaml

from test_cnesdata_stage_wait import INDEX, OWN, RUN, WINDOWS, Api, Clock
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

ROOT = pathlib.Path(__file__).resolve().parents[1]
WAIT_SOURCE = (ROOT / "tools/cnesdata_delivery/stage_wait.py").read_text(encoding="utf-8")
RUNTIME_SOURCE = (ROOT / "tools/cnesdata_delivery/lifecycle_runtime.py").read_text(encoding="utf-8")
GATE_WORKFLOW = (ROOT / ".github/workflows/reusable-cnesdata-infra-plan-gate.yml").read_text(encoding="utf-8")
CREDENTIALS = "Repeat source gate then request exact OIDC role"
WAIT_STEP = "Wait for the stage-open marker without credentials"


def _module(replace=None):
    source = WAIT_SOURCE
    if replace:
        old, new = replace
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    module = types.ModuleType("stage_wait_mutant")
    exec(compile(source, "stage_wait_mutant", "exec"), module.__dict__)
    return module


def _bind(replace=None):
    function = next(node for node in ast.parse(RUNTIME_SOURCE).body
                    if isinstance(node, ast.FunctionDef) and node.name == "bind_stage_open_owner")
    source = ast.get_source_segment(RUNTIME_SOURCE, function)
    if replace:
        assert source.count(replace[0]) == 1, replace[0]
        source = source.replace(*replace)
    namespace = {"c": c}
    exec(source, namespace)
    return namespace["bind_stage_open_owner"]


def _refuses(call):
    try:
        call()
    except ValueError:
        return True
    return False


def _clock():
    clock = Clock()
    return clock, clock.sleep


def oracle_ceiling(module):
    stages = module.STAGES_WITH_EXTERNAL_FIRST_JOB
    maximum = {"stages": {name: high for name, (_, high) in lc.STAGES.items()}, "fixed_deadline_seconds": 1830}
    bounded = all(module.wait_ceiling(stage, maximum) <= module.MAX_WAIT_SECONDS for stage in stages)
    covers = all(module.wait_ceiling(stage, WINDOWS) <= module.PREPARATION_ALLOWANCE_SECONDS
                 + sum(WINDOWS["stages"][name] for name in module.WINDOW_ORDER[:module.WINDOW_ORDER.index(stage) + 1])
                 for stage in stages if stage != "application-prepare")
    return bounded and covers and module.MAX_WAIT_SECONDS <= (module.TIMEOUT_MINUTES - 15) * 60


def oracle_unique_marker(module):
    clock, sleep = _clock()
    return _refuses(lambda: module.wait_for_stage(Api(count=2), RUN, job=OWN, stage="phase-b", windows=WINDOWS,
                                                  clock=clock, sleep=sleep))


def oracle_owner_bound(bind):
    owner = {"owner_sha256": INDEX["owner_sha256"], "generation": INDEX["generation"]}
    env = {"PURPOSE": "phase-b", "STAGE_OPEN_OWNER_SHA256": INDEX["owner_sha256"],
           "STAGE_OPEN_GENERATION": str(INDEX["generation"])}
    return (not _refuses(lambda: bind(owner, env))
            and _refuses(lambda: bind(owner, env | {"STAGE_OPEN_OWNER_SHA256": "5" * 64}))
            and _refuses(lambda: bind(owner, env | {"STAGE_OPEN_GENERATION": "8"})))


def oracle_first_job_running(module, monkeypatch):
    from tools.cnesdata_delivery import application_gate as gate
    uploads = []
    monkeypatch.setattr(gate, "_upload_keeper_artifact", lambda *args, **kwargs: uploads.append(kwargs))
    guard = type("Guard", (), {"check": lambda self, seconds=0: None})()
    window = {key: INDEX[key] for key in ("stage", "sequence", "checkpoint_sha256", "admitted_at", "deadline")}
    owner = {"owner_sha256": INDEX["owner_sha256"], "generation": 7, "run_id": 4242, "run_attempt": 1}
    queued = Api(jobs=(dict(OWN, status="queued"),))
    refused = _refuses(lambda: module.publish_stage_open(keeper=object(), guard=guard, api=queued, run=RUN, owner=owner,
                                                         window=window, first_job=OWN["name"], credential_limit=9999))
    return refused and uploads == []


def oracle_order(text):
    names = [step.get("name") for step in yaml.safe_load(text)["jobs"]["execute"]["steps"]]
    return names.index(WAIT_STEP) < names.index(CREDENTIALS)


def test_linha_de_base_satisfaz_todos_os_oraculos(monkeypatch):
    module = _module()
    assert oracle_ceiling(module) and oracle_unique_marker(module) and oracle_owner_bound(_bind())
    assert oracle_first_job_running(module, monkeypatch) and oracle_order(GATE_WORKFLOW)


def test_mutante_credenciais_antes_da_checagem_e_pego():
    swapped = GATE_WORKFLOW.replace(WAIT_STEP, "Moved").replace(CREDENTIALS, WAIT_STEP).replace("Moved", CREDENTIALS)
    assert swapped != GATE_WORKFLOW and not oracle_order(swapped)


@pytest.mark.parametrize("old, new", [
    ('== owner["owner_sha256"]', "== environ.get('STAGE_OPEN_OWNER_SHA256')"),
    ('== str(owner["generation"])', "== environ.get('STAGE_OPEN_GENERATION')"),
])
def test_mutante_outro_dono_ou_geracao_aceito_e_pego(old, new):
    assert not oracle_owner_bound(_bind((old, new)))


def test_mutante_teto_acima_do_prazo_do_estagio_e_pego():
    module = _module(("PREPARATION_ALLOWANCE_SECONDS + sum(windows", "PREPARATION_ALLOWANCE_SECONDS + 10**6 + sum(windows"))
    assert not oracle_ceiling(module)


def test_mutante_teto_acima_do_timeout_do_job_e_pego():
    assert not oracle_ceiling(_module(("CEILING_MARGIN_SECONDS = 900", "CEILING_MARGIN_SECONDS = 0")))


def test_mutante_dois_artefatos_aceitos_e_pego():
    module = _module(('c.require(len(found) <= 1, "unique stage-open marker")', "found = found[:1]"))
    assert not oracle_unique_marker(module)


def test_mutante_marcador_sem_primeiro_job_em_andamento_e_pego(monkeypatch):
    module = _module(('job["status"] == "in_progress", "stage-open first job', 'True, "stage-open first job'))
    assert not oracle_first_job_running(module, monkeypatch)
