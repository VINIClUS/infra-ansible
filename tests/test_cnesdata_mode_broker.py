"""P16b: mode SDK broker, fence-read broker, mode readbacks and their keeper seam."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

REUSABLE_LISTS = {"application-gate": 1, "infra-audit-gate": 1, "infra-deploy-gate": 1, "infra-plan-gate": 1, "observer": 2}
UNKNOWN = {"kind": "sdk-call", "reference_sha256": "a" * 64}


def _mode_broker_module():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _broker(kind, journal, *, uncertainty=()):
    cls = getattr(_mode_broker_module(), kind)
    broker = cls.__new__(cls)
    broker.journal, broker.calls = journal, []
    broker.evidence = [SimpleNamespace(uncertainty=list(uncertainty), _aws="ledger-client")]
    broker.call = lambda **kwargs: broker.calls.append(kwargs) or {"kind": "sdk-result", "value": {"ok": True}}
    journal._broker = broker
    return broker


def test_brokers_admitidos_sao_os_dois_do_p15_mais_os_dois_de_modo_na_ordem_exata():
    mb = _mode_broker_module()
    assert ag._brokers() == (ag.ClosedReadyBroker, ag.StaticBroker, mb.ModeBroker, mb.FenceReadBroker)
    assert ag.BROKERS == (ag.ClosedReadyBroker, ag.StaticBroker)


def test_mode_broker_entra_no_pyboot_e_nas_cinco_listas_dos_reusables():
    assert "mode_broker.py" in lc.APPLICATION_PYBOOT
    assert "tools/cnesdata_delivery/mode_broker.py" in lc.APPLICATION_CLOSURE_PATHS
    root = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    for name, count in REUSABLE_LISTS.items():
        assert (root / f"reusable-cnesdata-{name}.yml").read_text().count('"mode_broker.py"') == count, name


@pytest.mark.parametrize("kind", ["ModeBroker", "FenceReadBroker"])
def test_frame_call_vai_para_o_broker_de_modo_admitido_no_journal(kind):
    journal = SimpleNamespace()
    broker = _broker(kind, journal)
    frame = c.canonical({"kind": "call", "role": "r", "service": "s", "operation": "o", "parameters": {"k": 1}})
    assert ag._adapter_message(frame, journal) == ({"kind": "sdk-result", "value": {"ok": True}}, None)
    assert broker.calls == [{"role": "r", "service": "s", "operation": "o", "parameters": {"k": 1}}]


def test_frame_call_recusa_broker_que_so_imita_o_broker_de_modo():
    journal = SimpleNamespace(_broker=SimpleNamespace(call=lambda **kwargs: {"kind": "sdk-result", "value": {}}))
    frame = c.canonical({"kind": "call", "role": "r", "service": "s", "operation": "o", "parameters": {}})
    with pytest.raises(ValueError, match="^adapter protected SDK admission absent$"):
        ag._adapter_message(frame, journal)


@pytest.mark.parametrize("kind", ["ModeBroker", "FenceReadBroker"])
def test_keeper_anexa_o_broker_de_modo_e_a_incerteza_do_ledger_segura_o_lease(kind):
    from test_cnesdata_mode_stages import _keeper, _mode_journal
    journal, _, _ = _mode_journal("unit")
    keeper = _keeper(journal)
    broker = _broker(kind, journal, uncertainty=[UNKNOWN])
    keeper.attach(broker)
    assert ag._journal_of(broker) is journal
    assert UNKNOWN in keeper.uncertainty()
    assert ag._mode_journal(keeper, "unit") is journal
