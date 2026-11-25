"""P16b c-1124-p16b-next item 1: the recovery-start ledger frames on the vendored builders under the rx session."""
import datetime
import json
import re

import pytest

from test_cnesdata_mode_effect_broker import _Evidence, _frame, _metadata, _mb
from test_cnesdata_mode_ledger import CASES
from test_cnesdata_mode_run_task import _readbacks
from test_cnesdata_mode_session_sts import START, _case, _journal
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c

CASE = CASES["ledger-admit"]
NOW = START + 30
SHIFT = NOW - int(datetime.datetime.fromisoformat(CASE["now"].replace("Z", "+00:00")).timestamp())
EFFECT = {"effect_kind": "run-recovery", "request_sha256": "1" * 64, "target_sha256": "2" * 64}


def _shifted(text):
    def move(match):
        moment = datetime.datetime.fromisoformat(match.group(0).replace("Z", "+00:00"))
        return (moment + datetime.timedelta(seconds=SHIFT)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return re.sub(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", move, text)


RECORD = _shifted(CASE["record"])
CONTROL = _shifted(CASE["control"])


class _Native(Exception):
    def __init__(self, response):
        super().__init__("native")
        self.response = response


class _Dynamo:
    """Native DynamoDB fake with the product conditions and full response metadata."""

    def __init__(self, items, forced=(), error=None):
        self.items, self.forced, self.error, self.calls = dict(items), list(forced), error, []

    def _admits(self, put):
        key = (put["Item"]["pk"]["S"], put["Item"]["sk"]["S"])
        if put["ConditionExpression"] == "attribute_not_exists(pk)":
            return key not in self.items
        return self.items.get(key) == put["ExpressionAttributeValues"][":old"]["S"]

    def __call__(self, service, name, **parameters):
        self.calls.append((name, parameters))
        if name == "get_item":
            key = (parameters["Key"]["pk"]["S"], parameters["Key"]["sk"]["S"])
            item = {"pk": parameters["Key"]["pk"], "sk": parameters["Key"]["sk"], "payload": {"S": self.items[key]}}
            return ({"Item": item} if key in self.items else {}) | {"ResponseMetadata": _metadata()}
        if self.error is not None:
            raise self.error
        puts = [item["Put"] for item in parameters["TransactItems"]] if name == "transact_write_items" else [parameters]
        codes = self.forced.pop(0) if self.forced else ["None" if self._admits(put) else "ConditionalCheckFailed" for put in puts]
        if any(code != "None" for code in codes):
            code = "TransactionCanceledException" if name == "transact_write_items" else "ConditionalCheckFailedException"
            raise _Native({"Error": {"Code": code}, "ResponseMetadata": _metadata(400)}
                          | ({"CancellationReasons": [{"Code": item} for item in codes]} if name == "transact_write_items" else {}))
        for put in puts:
            self.items[(put["Item"]["pk"]["S"], put["Item"]["sk"]["S"])] = put["Item"]["payload"]["S"]
        return {"ResponseMetadata": _metadata()}


def _frames():
    return _mb().product_frames()


def _keys(effect_id):
    frames = _frames()
    record = json.loads(RECORD)
    pk = frames.tenant_partition("prod-canary-" + record["canary_id"])
    return (pk, frames.control_key(record["owner_sha256"])), (pk, frames.ticket_key(record["owner_sha256"], effect_id))


def _effect_id(kind="run-recovery", request="1" * 64):
    return _frames().effect_id(c.sha(RECORD.encode()), kind, request)


def _ledger_broker(monkeypatch, operation="recovery-start", items=None, record=RECORD, **dynamo):
    args, _, _ = _case(monkeypatch, operation)
    inputs = {"record": record.encode()} | ({"readbacks": c.canonical(_readbacks(operation.split("-")[0]))}
                                            if operation in ("recovery-start", "audit-start") else {})
    args["journal"], _ = _journal(operation, inputs)
    session = _mb().assume_mode_session(**args)
    control, _ = _keys(_effect_id())
    table = _Dynamo({control: CONTROL} if items is None else items, **dynamo)
    session.client.call = table
    broker = _mb().ModeBroker(_Evidence(), args["governance"], args["journal"], session, prepared_sha256="3" * 64,
                              credential_limit=args["credential_limit"], clock=args["clock"])
    return broker, args["journal"], table


def _send(journal, kind, **fields):
    return ag._adapter_message(c.canonical({"kind": kind} | fields), journal)


def _admit(journal, **changes):
    return _send(journal, "ledger-admit", **(EFFECT | {"admitted_at": c.utc(NOW)} | changes))


def _expected_admission(control_text=CONTROL, ticket_text=None):
    frames = _frames()
    record = frames.ModeCanaryRecord.from_mapping(json.loads(RECORD))
    binding = frames.ModeCanaryBinding("prod-canary-" + record.canary_id, record.run_ids, record.owner_sha256,
                                       c.sha(RECORD.encode()), record.phase, record.context_kind)
    state = frames.LedgerState(binding, record, control_text, ticket_text)
    now = datetime.datetime.fromtimestamp(NOW, datetime.timezone.utc)
    return frames.admission("cnesdata-prod-control-plane", state, frames.ledger_effect(**{
        "kind": EFFECT["effect_kind"], "request_sha256": EFFECT["request_sha256"], "target_sha256": EFFECT["target_sha256"]}), now)


def test_ledger_admit_le_forte_e_grava_uma_vez_a_transacao_do_produto(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch)
    reply, result = _admit(journal)
    control, ticket = _keys(_effect_id())
    expected = _expected_admission()
    assert result is None and reply == {"effect_id": _effect_id()} == {"effect_id": expected.effect_id}
    assert [name for name, _ in table.calls] == ["get_item", "get_item", "transact_write_items"]
    assert [(call["Key"]["pk"]["S"], call["Key"]["sk"]["S"]) for _, call in table.calls[:2]] == [control, ticket]
    assert all(call["ConsistentRead"] is True for _, call in table.calls[:2])
    assert table.calls[2][1] == {"TransactItems": expected.items}
    assert len(journal.call_receipts) == 3 and broker.uncertainty == [] and ticket in table.items


def test_ledger_admit_reentrada_com_o_mesmo_efeito_nao_grava_de_novo(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch)
    _admit(journal)
    writes = [name for name, _ in table.calls].count("transact_write_items")
    reply, _ = _admit(journal)
    assert reply == {"effect_id": _effect_id()} and [name for name, _ in table.calls].count("transact_write_items") == writes


def test_cancelamento_definitivo_relido_e_reconstruido_sem_incerteza(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch, forced=[["None", "TransactionConflict"]])
    reply, _ = _admit(journal)
    assert reply == {"effect_id": _effect_id()}
    assert [name for name, _ in table.calls] == ["get_item", "get_item", "transact_write_items"] * 2
    assert broker.uncertainty == [] and not journal._failed


def test_cancelamento_com_motivo_fora_do_conjunto_recusa_sem_nova_tentativa(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch, forced=[["None", "ValidationError"]])
    with pytest.raises(ValueError, match="^ledger_cancel reason=ValidationError$"):
        _admit(journal)
    assert [name for name, _ in table.calls].count("transact_write_items") == 1 and broker.uncertainty == []


def test_escrita_do_ledger_com_resultado_desconhecido_envenena(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch, error=RuntimeError("timeout"))
    with pytest.raises(ValueError, match="^mode native SDK outcome unknown$"):
        _admit(journal)
    assert broker.uncertainty and journal._failed and journal.unknown


def test_conflito_de_ticket_recusa_pela_regra_do_produto(monkeypatch):
    control, ticket = _keys(_effect_id())
    other = json.loads(_shifted(CASES["ticket-conflict"]["ticket"]))
    broker, journal, table = _ledger_broker(monkeypatch, items={control: CONTROL, ticket: json.dumps(other)})
    with pytest.raises(ValueError, match="^reason=ticket_conflict field=tenant_id$"):
        _admit(journal)
    assert [name for name, _ in table.calls] == ["get_item", "get_item"]


def _pending(journal, table):
    _admit(journal)
    return _keys(_effect_id())[1]


def test_ledger_unknown_troca_o_ticket_pendente_por_unknown(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch)
    ticket = _pending(journal, table)
    reply, _ = _send(journal, "ledger-unknown", effect_id=_effect_id())
    assert reply == {} and table.calls[-1][0] == "put_item"
    assert json.loads(table.items[ticket])["state"] == "UNKNOWN" and json.loads(table.items[ticket])["receipt_sha256"] is None


def test_ledger_settle_so_com_recibo_de_uma_observacao_de_tarefa_desta_operacao(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch)
    ticket = _pending(journal, table)
    calls = len(table.calls)
    with pytest.raises(ValueError, match="^mode ledger settle receipt$"):
        _send(journal, "ledger-settle", effect_id=_effect_id(), receipt_sha256="9" * 64)
    assert len(table.calls) == calls
    body = b'{"lastStatus":"STOPPED"}\n'
    receipt = journal.observe("recovery-task", body)
    reply, _ = _send(journal, "ledger-settle", effect_id=_effect_id(), receipt_sha256=receipt)
    assert reply == {} and json.loads(table.items[ticket])["state"] == "SETTLED"
    assert json.loads(table.items[ticket])["receipt_sha256"] == receipt


@pytest.mark.parametrize("operation, kind", [("audit-start", "ledger-admit"), ("unit-start", "ledger-unknown"),
                                             ("unit-seed", "ledger-settle")])
def test_frame_do_ledger_fora_dos_metodos_da_operacao_recusa(monkeypatch, operation, kind):
    broker, journal, table = _ledger_broker(monkeypatch, operation)
    fields = (EFFECT | {"admitted_at": c.utc(NOW)} if kind == "ledger-admit"
              else {"effect_id": _effect_id()} | ({"receipt_sha256": "9" * 64} if kind == "ledger-settle" else {}))
    with pytest.raises(ValueError, match="^mode method outside table$"):
        _send(journal, kind, **fields)
    assert table.calls == []


@pytest.mark.parametrize("changes", [{"extra": 1}, {"request_sha256": "x" * 64}, {"admitted_at": "2026-11-23 11:55:30"},
                                     {"admitted_at": c.utc(NOW + 6)}, {"admitted_at": c.utc(NOW - 6)},
                                     {"effect_kind": 7}],
                         ids=["campo-extra", "digest", "carimbo", "futuro", "passado", "tipo"])
def test_frame_do_ledger_fora_da_forma_recusa_antes_do_io(monkeypatch, changes):
    broker, journal, table = _ledger_broker(monkeypatch)
    with pytest.raises(ValueError, match="^mode ledger frame$"):
        _admit(journal, **changes)
    assert table.calls == []


@pytest.mark.parametrize("effect_id", ["g" * 64, "a" * 63, 7])
def test_transicao_com_effect_id_fora_da_forma_recusa_antes_do_io(monkeypatch, effect_id):
    broker, journal, table = _ledger_broker(monkeypatch)
    with pytest.raises(ValueError, match="^mode ledger frame$"):
        _send(journal, "ledger-unknown", effect_id=effect_id)
    assert table.calls == []


def test_record_de_outro_owner_no_journal_recusa_antes_do_io(monkeypatch):
    other = json.loads(RECORD) | {"owner_sha256": "b" * 64,
                                  "run_ids": ["recovery-a-bbbbbbbbbbbbbbbb", "recovery-b-bbbbbbbbbbbbbbbb"]}
    broker, journal, table = _ledger_broker(monkeypatch, record=json.dumps(other, sort_keys=True, separators=(",", ":")))
    with pytest.raises(ValueError, match="^mode ledger record$"):
        _admit(journal)
    assert table.calls == []


def test_chamada_direta_do_filho_ao_dynamodb_no_recovery_start_recusa(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch)
    control, _ = _keys(_effect_id())
    parameters = {"TableName": "cnesdata-prod-control-plane", "Key": {"pk": {"S": control[0]}, "sk": {"S": control[1]}},
                  "ConsistentRead": True}
    with pytest.raises(ValueError, match="^mode call outside table$"):
        ag._adapter_message(_frame("dynamodb", "get_item", parameters, "mode_dispatch"), journal)
    assert table.calls == []
