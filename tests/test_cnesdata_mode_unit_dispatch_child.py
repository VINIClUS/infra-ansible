"""P16b Falta 4 (c-1125-p16b-repin item 2): Context.dispatch_unit of the adapter child and its dispatch-unit IPC kind."""
import pytest

from test_cnesdata_mode_child_context import CATCH, _forged, _invoke, _product, _seed_broker
from test_cnesdata_mode_unit_dispatch_broker import OWNER, RUN_ID, TENANT_ID, _binding, _names, _world
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c

DISPATCH = r'''
class Binding:
    def __init__(self, **fields):
        self.__dict__.update(fields)
def execute_shared_operation(operation, request, context):
    observed = context.dispatch_unit(Binding(**FIELDS))
    return canonical({'status': observed['execution']['status'], 'tasks': observed['tasks'],
                      'outputs': observed['outputs'], 'keys': sorted(observed)})
'''


def _code(**changes):
    fields = _binding() | {"run_ids": (RUN_ID,)} | changes
    return DISPATCH.replace("FIELDS", repr(fields))


def test_filho_real_despacha_o_unit_pelo_kind_do_keeper_e_recebe_a_observacao(tmp_path, monkeypatch):
    product, source, manifest = _product(tmp_path, _code())
    broker, journal, table, _ = _world(monkeypatch, source=source)
    result = _invoke(monkeypatch, product, source, manifest, journal)
    assert result == {"status": "SUCCEEDED", "tasks": broker.unit_observed["tasks"], "outputs": broker.unit_observed["outputs"],
                      "keys": ["execution", "failures", "outputs", "tasks"]}
    assert len(result["tasks"]) == len(result["outputs"]) == 2
    assert _names(table).count("start_execution") == 1 and broker.uncertainty == []


def test_filho_real_com_binding_de_outro_run_recusa_no_keeper_sem_chamada(tmp_path, monkeypatch):
    product, source, manifest = _product(tmp_path, _code(run_ids=("unit-" + "b" * 16,)))
    _, journal, table, _ = _world(monkeypatch, source=source)
    with pytest.raises(ValueError, match="^mode unit dispatch binding$"):
        _invoke(monkeypatch, product, source, manifest, journal)
    assert table.calls == []


@pytest.mark.parametrize("reply", [{"execution": {}, "tasks": []}, {"execution": {}, "tasks": [], "outputs": []},
                                   {"execution": {}, "failures": [], "outputs": [], "tasks": [], "x": 1}],
                         ids=["dois-campos", "tres-campos", "cinco-campos"])
def test_filho_recusa_resposta_do_dispatch_fora_do_contrato(tmp_path, monkeypatch, reply):
    binding = ("__import__('types').SimpleNamespace(tenant_id='t', run_ids=('r',), owner_sha256='o', record_sha256='s', "
               "phase='unit', context_kind='promotion')")
    product, source, manifest = _product(tmp_path, CATCH.replace("CALL", f"context.dispatch_unit({binding})"))
    journal, _ = _seed_broker(monkeypatch, source)
    _forged(monkeypatch, {"dispatch-unit": reply})
    with pytest.raises(ValueError, match="^adapter complete result frame$"):
        _invoke(monkeypatch, product, source, manifest, journal)


def test_kind_do_dispatch_exige_o_broker_de_modo(monkeypatch):
    journal, _ = _seed_broker(monkeypatch, None)
    journal._broker = None
    with pytest.raises(ValueError, match="^mode method outside table$"):
        ag._adapter_message(c.canonical({"kind": "dispatch-unit", "binding": _binding()}), journal)


def test_kind_do_dispatch_fora_do_unit_start_recusa_no_broker(monkeypatch):
    journal, native = _seed_broker(monkeypatch, None)
    with pytest.raises(ValueError, match="^mode method outside table$"):
        ag._adapter_message(c.canonical({"kind": "dispatch-unit", "binding": _binding()}), journal)
    assert native == []


def test_kind_do_dispatch_entrega_a_resposta_do_broker(monkeypatch):
    broker, journal, table, plan = _world(monkeypatch)
    reply, result = ag._adapter_message(c.canonical({"kind": "dispatch-unit", "binding": _binding()}), journal)
    assert result is None and reply["execution"]["executionArn"] == plan.execution
    assert (TENANT_ID, OWNER) == (plan.locator.tenant_id, plan.locator.owner_sha256)
