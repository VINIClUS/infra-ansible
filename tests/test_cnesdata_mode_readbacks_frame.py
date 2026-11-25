"""P16b c-1124-p16b-next item 2: the mode-readbacks frame of the start operations, read on the stage observe session."""
import json

import pytest

from test_cnesdata_mode_child_context import _invoke, _product
from test_cnesdata_mode_effect_broker import _Evidence, _frame, _metadata, _mb
from test_cnesdata_mode_readback import _responses
from test_cnesdata_mode_readback_context import _Client
from test_cnesdata_mode_run_task import REVISIONS, _readbacks
from test_cnesdata_mode_session_sts import RESOURCES, _case, _journal
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

FRAME = c.canonical({"kind": "mode-readbacks"})


def _reads(journal, mode, client, code=None, binding=None):
    owner = journal._request["owner"] | journal._identity
    request = _mb().mode_readback_request(owner, journal._request["stage"], mode)
    return _mb()._ModeSession(client, "e" * 64, {"resources": RESOURCES}, journal._request["stage"]["deadline"],
                              binding or c.sha(c.canonical(request)), None,
                              code=code or lc.MODE_SESSION_OPERATIONS[mode + "-observe"][0], alias="mode_observe")


def _broker(monkeypatch, mode="recovery", reads=True, source=None, **client):
    operation = mode + "-start"
    args, _, _ = _case(monkeypatch, operation, source=source)
    inputs = {"readbacks": _mb().mode_readback_bytes(mode, RESOURCES, _responses(mode))} if mode != "unit" else {}
    if mode != "unit":
        inputs["record"] = c.canonical({"revisions": dict(REVISIONS)})
    args["journal"], _ = _journal(operation, inputs, source)
    session = _mb().assume_mode_session(**args)
    native = _Client(mode, **client)
    extra = {"reads": _reads(args["journal"], mode, native)} if reads else {}
    broker = _mb().ModeBroker(_Evidence(), args["governance"], args["journal"], session, prepared_sha256="3" * 64,
                              credential_limit=args["credential_limit"], clock=args["clock"], **extra)
    return broker, args["journal"], native


def _product_text(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


@pytest.mark.parametrize("mode", ["unit", "recovery", "audit"])
def test_mode_readbacks_le_o_conjunto_na_sessao_de_observe_com_recibo_no_journal_do_start(monkeypatch, mode):
    broker, journal, native = _broker(monkeypatch, mode)
    reply, result = ag._adapter_message(FRAME, journal)
    expected = _mb().mode_readback_bytes(mode, RESOURCES, _responses(mode))
    assert result is None and _product_text(reply) == expected
    assert native.calls == [(call["service"], call["operation"], call["parameters"])
                            for call in _mb().mode_readback_calls(mode, RESOURCES)]
    assert len(journal.call_receipts) == len(native.calls) and broker.uncertainty == []
    assert all(receipt["role_session_sha256"] == "e" * 64 for receipt in journal.call_receipts)
    assert [entry["call"]["role"] for entry in journal._settled_calls()] == ["mode_observe"] * len(native.calls)


def test_rota_antes_e_depois_sem_deriva_tem_o_mesmo_sha_do_produto(monkeypatch):
    broker, journal, _ = _broker(monkeypatch)
    reply, _ = ag._adapter_message(FRAME, journal)
    assert c.sha(_product_text(reply)) == c.sha(journal._inputs["readbacks"])


def test_frame_sem_sessao_de_leitura_recusa(monkeypatch):
    broker, journal, native = _broker(monkeypatch, reads=False)
    with pytest.raises(ValueError, match="^mode method outside table$"):
        ag._adapter_message(FRAME, journal)
    assert native.calls == []


def test_frame_em_operacao_sem_o_metodo_recusa(monkeypatch):
    from test_cnesdata_mode_effect_broker import _broker as _seed_broker
    _, journal, _, native = _seed_broker(monkeypatch)
    with pytest.raises(ValueError, match="^mode method outside table$"):
        ag._adapter_message(FRAME, journal)
    assert native == []


def test_frame_sem_mode_broker_recusa():
    from test_cnesdata_mode_stages import _lease_journal
    with pytest.raises(ValueError, match="^mode method outside table$"):
        ag._adapter_message(FRAME, _lease_journal("recovery-start"))


def test_frame_com_campo_extra_recusa(monkeypatch):
    broker, journal, native = _broker(monkeypatch)
    with pytest.raises(ValueError):
        ag._adapter_message(c.canonical({"kind": "mode-readbacks", "mode": "audit"}), journal)
    assert native.calls == []


@pytest.mark.parametrize("change", ["codigo", "binding", "alias"])
def test_sessao_de_leitura_de_outro_codigo_binding_ou_alias_recusa_na_construcao(monkeypatch, change):
    args, _, _ = _case(monkeypatch, "recovery-start")
    session = _mb().assume_mode_session(**args)
    reads = _reads(args["journal"], "recovery", _Client("recovery"), code="uo" if change == "codigo" else None,
                   binding="9" * 64 if change == "binding" else None)
    if change == "alias":
        reads.alias = "mode_seed"
    with pytest.raises(ValueError, match="^mode readback original context$"):
        _mb().ModeBroker(_Evidence(), args["governance"], args["journal"], session, prepared_sha256="3" * 64,
                         credential_limit=args["credential_limit"], clock=args["clock"], reads=reads)


def test_leitura_com_resultado_desconhecido_envenena(monkeypatch):
    broker, journal, native = _broker(monkeypatch, fail=2)
    with pytest.raises(ValueError, match="^mode native SDK outcome unknown$"):
        ag._adapter_message(FRAME, journal)
    assert journal._failed and journal.unknown and broker.uncertainty


def test_chamada_direta_do_filho_com_alias_de_observe_recusa(monkeypatch):
    broker, journal, native = _broker(monkeypatch)
    parameters = _mb().mode_readback_calls("recovery", RESOURCES)[0]["parameters"]
    with pytest.raises(ValueError, match="^mode call alias$"):
        ag._adapter_message(_frame("stepfunctions", "describe_state_machine", parameters, "mode_observe"), journal)
    assert native.calls == []


def test_journal_admite_a_leitura_de_observe_so_nas_operacoes_de_start():
    from test_cnesdata_mode_stages import _lease_journal
    call = _mb().mode_readback_calls("recovery", RESOURCES)[0]
    native = c.canonical({"role": "mode_observe", "service": call["service"], "operation": call["operation"],
                          "parameters": call["parameters"]})
    assert _lease_journal("recovery-start").begin_sdk_call(native, role_session_sha256="4" * 64)
    with pytest.raises(ValueError, match="^closed SDK journal operation$"):
        _lease_journal("recovery-seed").begin_sdk_call(native, role_session_sha256="4" * 64)


READBACKS = r'''
def execute_shared_operation(operation, request, context):
    return canonical(context.mode_readbacks())
'''


def test_filho_real_recebe_o_documento_de_readbacks(tmp_path, monkeypatch):
    product, source, manifest = _product(tmp_path, READBACKS)
    broker, journal, native = _broker(monkeypatch, source=source)
    result = _invoke(monkeypatch, product, source, manifest, journal)
    assert _product_text(result) == journal._inputs["readbacks"] and len(native.calls) == 4
