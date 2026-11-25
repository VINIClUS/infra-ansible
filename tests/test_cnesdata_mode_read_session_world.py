"""P16b standing item: one world where the read session minted on the lease is admitted by ModeBroker(reads=) of the
start journal that run_mode_operation builds from the same lease."""
import copy

import pytest

from test_cnesdata_mode_effect_broker import _Evidence
from test_cnesdata_mode_readback_session import _case, _mb
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

INPUTS = {name: c.canonical({"fixture_input": name}) for name in lc.ADAPTER_INPUTS["unit-start"].split()}


class _Stop(Exception):
    pass


def _run(world, args, reads, admitted):
    def capability(*, journal, keeper, guard):
        start = _mb()._ModeSession(None, "d" * 64, reads.scope, reads.deadline, c.sha(c.canonical(journal._request)), None,
                                   code="ux", alias="mode_dispatch")
        broker = _mb().ModeBroker(_Evidence(), args["governance"], journal, start, prepared_sha256="3" * 64,
                                  credential_limit=args["credential_limit"], clock=args["clock"], reads=reads)
        admitted.append((journal, broker))
        return broker

    def invoke(*, journal, timeout):
        raise _Stop()
    with pytest.raises(_Stop):
        ag.run_mode_operation(world.keeper, "unit-start", inputs=dict(INPUTS), activation=world.activation, invoke=invoke,
                              capability=capability, credential_limit=args["credential_limit"], clock=args["clock"])


def test_sessao_de_leitura_cunhada_no_lease_e_admitida_pelo_broker_do_start_do_mesmo_lease(monkeypatch):
    args, world, (owner, window), _, _ = _case(monkeypatch)
    reads = _mb().assume_readback_session(**args)
    admitted = []
    _run(world, args, reads, admitted)
    journal, broker = admitted[0]
    assert broker.reads is reads and journal._broker is broker
    assert journal._request["owner"] | journal._identity == owner | lc.application_identity(owner, required=True)
    assert reads.request_binding == c.sha(c.canonical(_mb().mode_readback_request(
        journal._request["owner"] | journal._identity, journal._request["stage"], "unit")))
    assert journal._request["stage"] == {key: window[key] for key in lc.ADAPTER_STAGE_FIELDS.split()}


@pytest.mark.parametrize("field", ["sequence", "checkpoint_sha256"])
def test_janela_que_avanca_entre_a_cunhagem_e_o_start_recusa_a_sessao_de_leitura(monkeypatch, field):
    args, world, _, _, _ = _case(monkeypatch)
    reads = _mb().assume_readback_session(**args)
    real = world.keeper.lease.check

    def moved():
        record = copy.deepcopy(real())
        window = record["lifecycle"]
        window[field] = window[field] + 1 if field == "sequence" else "9" * 64
        return record
    monkeypatch.setattr(world.keeper.lease, "check", moved)
    with pytest.raises(ValueError, match="^mode readback original context$"):
        _run(world, args, reads, [])
