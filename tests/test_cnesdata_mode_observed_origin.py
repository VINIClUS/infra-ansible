"""P16b follow-up item 4 (ack 1 answer 1): unit-observe's observed, built from this lease's single unit-start journal."""
import json

import pytest

from test_cnesdata_mode_prepared_authority import _world
from test_cnesdata_mode_prepared_origins import _context, _source
from test_cnesdata_mode_stages import _lease_journal
from tools.cnesdata_delivery import contract as c

VECTOR = json.loads(open(__file__.rsplit("/", 1)[0] + "/fixtures/cnesdata_mode_canary_frames_vector.json").read())
SECTION = VECTOR["unit_observe"]
CASE = {case["name"]: case for case in SECTION["cases"]}["aceito-pascal"]
EXECUTION = CASE["execution"]["response"]
TASKS = CASE["describe_tasks"]["response"]["tasks"]
OUTPUTS = SECTION["outputs"]


def _prepared(monkeypatch):
    prepared, arguments, _, _ = _world(monkeypatch)
    cluster = c.loads(prepared["mode-input.json"], canonical=True)["mode_canary"]["resources"]["cluster_arn"]
    return prepared, arguments, cluster


def _readbacks(cluster):
    definition = SECTION["definition"].replace(json.dumps(SECTION["cluster_arn"]), json.dumps(cluster))
    return c.canonical(SECTION["readbacks"] | {"state_machine": SECTION["readbacks"]["state_machine"]
                                               | {"definition": definition}})


def _append(journal, kind, value):
    raw = c.canonical(value)
    journal._observation_bytes[c.sha(raw)] = raw
    journal._observations.append({"kind": kind, "sha256": c.sha(raw), "size": len(raw)})


def _start(readbacks, steps=None):
    journal = _lease_journal("unit-start", inputs={"readbacks": readbacks})
    order = steps if steps is not None else [("unit-execution", EXECUTION), ("unit-task", TASKS[0]),
                                             ("unit-output", OUTPUTS[0]), ("unit-task", TASKS[1]),
                                             ("unit-output", OUTPUTS[1]), ("mode-result", {"result": 1})]
    for kind, value in order:
        _append(journal, kind, value)
    return journal


def _observed(prepared, arguments, *journals, context=True):
    from types import SimpleNamespace
    return _source("unit-observe", ["observed"], context=_context(prepared, arguments) if context else None,
                   owner=arguments["owner"], keeper=SimpleNamespace(_contexts=list(journals)), prepared=arguments["window"])


def test_observed_do_unit_observe_e_o_texto_dos_recibos_do_unit_start_na_ordem_do_journal(monkeypatch):
    prepared, arguments, cluster = _prepared(monkeypatch)
    observed = _observed(prepared, arguments, _start(_readbacks(cluster)))
    assert observed == {"observed": c.canonical({"execution": EXECUTION, "tasks": TASKS, "outputs": OUTPUTS})}
    assert set(c.loads(observed["observed"], canonical=True)) == {"execution", "tasks", "outputs"}


def test_observed_sem_tasks_e_a_execucao_com_listas_vazias(monkeypatch):
    prepared, arguments, cluster = _prepared(monkeypatch)
    failed = {key: value for key, value in EXECUTION.items() if key != "output"} | {"status": "FAILED"}
    observed = _observed(prepared, arguments, _start(_readbacks(cluster), [("unit-execution", failed)]))
    assert observed == {"observed": c.canonical({"execution": failed, "tasks": [], "outputs": []})}


def _failed(journal):
    journal._failed = True
    return journal


def _unknown(journal):
    journal._unknown.append({"kind": "unknown"})
    return journal


@pytest.mark.parametrize("journals", [
    lambda readbacks: [], lambda readbacks: [_start(readbacks), _start(readbacks)],
    lambda readbacks: [_failed(_start(readbacks))], lambda readbacks: [_unknown(_start(readbacks))],
    lambda readbacks: [_start(readbacks, [("unit-task", TASKS[0])])],
    lambda readbacks: [_start(readbacks, [("unit-execution", EXECUTION), ("unit-execution", EXECUTION)])]],
    ids=["sem-journal", "dois-journals", "journal-falho", "journal-incerto", "sem-execucao", "duas-execucoes"])
def test_observed_recusa_fora_do_unico_journal_do_unit_start_com_uma_execucao(monkeypatch, journals):
    prepared, arguments, cluster = _prepared(monkeypatch)
    with pytest.raises(ValueError, match="^observed original$"):
        _observed(prepared, arguments, *journals(_readbacks(cluster)))


@pytest.mark.parametrize("readbacks", [lambda cluster: _readbacks(cluster + "-other"),
                                       lambda cluster: _readbacks(cluster.replace(":cluster/", ":service/")),
                                       lambda cluster: c.canonical({"fixture_only": "readbacks"})],
                         ids=["outro-cluster", "servico-com-conta", "readback-sem-maquina"])
def test_observed_reconfere_o_cluster_do_readback_com_o_dos_recursos_preparados(monkeypatch, readbacks):
    """Third of the three cluster checks: pure, over the unit-start readbacks bytes and the prepared resources."""
    prepared, arguments, cluster = _prepared(monkeypatch)
    with pytest.raises(ValueError, match="^mode unit cluster$"):
        _observed(prepared, arguments, _start(readbacks(cluster)))


def test_observed_sem_contexto_do_estagio_recusa(monkeypatch):
    prepared, arguments, cluster = _prepared(monkeypatch)
    with pytest.raises(ValueError, match="^mode prepared origin context$"):
        _observed(prepared, arguments, _start(_readbacks(cluster)), context=False)


@pytest.mark.parametrize("operation", ["recovery-observe", "audit-observe", "unit-seed"])
def test_observed_e_so_do_unit_observe(monkeypatch, operation):
    prepared, arguments, cluster = _prepared(monkeypatch)
    from types import SimpleNamespace
    with pytest.raises(ValueError, match="^mode_inputs=source_unconnected$"):
        _source(operation, ["observed"], context=_context(prepared, arguments), owner=arguments["owner"],
                keeper=SimpleNamespace(_contexts=[_start(_readbacks(cluster))]), prepared=arguments["window"])
