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
            item = {"pk": parameters["Key"]["pk"], "sk": parameters["Key"]["sk"], "payload": {"S": self.items.get(key)}}
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


def _expected_admission(control_text=CONTROL, ticket_text=None, now=NOW):
    frames = _frames()
    record = frames.ModeCanaryRecord.from_mapping(json.loads(RECORD))
    binding = frames.ModeCanaryBinding("prod-canary-" + record.canary_id, record.run_ids, record.owner_sha256,
                                       c.sha(RECORD.encode()), record.phase, record.context_kind)
    state = frames.LedgerState(binding, record, control_text, ticket_text)
    moment = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    return frames.admission("cnesdata-prod-control-plane", state, frames.ledger_effect(**{
        "kind": EFFECT["effect_kind"], "request_sha256": EFFECT["request_sha256"], "target_sha256": EFFECT["target_sha256"]}), moment)


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
    case = CASES["ticket-conflict"]
    control, ticket = _keys(_effect_id(case["effect"]["kind"]))
    items = {control: _shifted(case["control"]), ticket: _shifted(case["ticket"])}
    broker, journal, table = _ledger_broker(monkeypatch, items=items)
    with pytest.raises(ValueError, match="^reason=ticket_conflict field=tenant_id$"):
        _admit(journal, effect_kind=case["effect"]["kind"])
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


def test_frame_do_ledger_sem_mode_broker_no_journal_recusa(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch)
    journal._broker = None
    with pytest.raises(ValueError, match="^mode method outside table$"):
        _admit(journal)
    assert table.calls == []


def test_frame_fora_da_janela_da_sessao_recusa_antes_do_io(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch)
    late = broker.session.deadline - 20
    broker.clock = lambda: late
    with pytest.raises(ValueError, match="^mode finite SDK request/window$"):
        _admit(journal, admitted_at=c.utc(late))
    assert table.calls == [] and broker.aws.events == []


def test_frame_com_guard_perdido_recusa_antes_da_reserva(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch)

    def lost(seconds=0):
        raise ValueError("lease lost")
    monkeypatch.setattr(journal._guard, "check", lost)
    with pytest.raises(ValueError, match="^lease lost$"):
        _admit(journal)
    assert table.calls == [] and broker.aws.events == []


def test_record_de_outro_tenant_recusa_antes_do_io(monkeypatch):
    other = json.loads(RECORD) | {"canary_id": "f" * 32}
    broker, journal, table = _ledger_broker(monkeypatch, record=json.dumps(other, sort_keys=True, separators=(",", ":")))
    with pytest.raises(ValueError, match="^mode ledger record$"):
        _admit(journal)
    assert table.calls == []


def test_record_de_outra_fase_recusa_antes_do_io(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch, record=_shifted(CASES["dispatch-unit"]["record"]))
    with pytest.raises(ValueError, match="^mode ledger record$"):
        _admit(journal)
    assert table.calls == []


def test_settle_com_recibo_da_observacao_final_recusa(monkeypatch):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    broker, journal, table = _ledger_broker(monkeypatch)
    _pending(journal, table)
    calls = len(table.calls)
    receipt = journal.observe(lc.ADAPTER_OBSERVATIONS["recovery-start"], b'{"lastStatus":"STOPPED"}\n')
    with pytest.raises(ValueError, match="^mode ledger settle receipt$"):
        _send(journal, "ledger-settle", effect_id=_effect_id(), receipt_sha256=receipt)
    assert len(table.calls) == calls


def test_admissao_usa_o_carimbo_do_produto_e_nao_o_relogio_do_keeper(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch)
    _admit(journal, admitted_at=c.utc(NOW - 3))
    assert table.calls[2][1] == {"TransactItems": _expected_admission(now=NOW - 3).items}
    assert table.calls[2][1] != {"TransactItems": _expected_admission().items}


class _Skewed(_Dynamo):
    def __call__(self, service, name, **parameters):
        reply = super().__call__(service, name, **parameters)
        if name == "get_item" and "Item" in reply:
            reply["Item"]["sk"] = {"S": reply["Item"]["sk"]["S"] + "-other"}
        return reply


def test_leitura_do_ledger_com_item_de_outra_chave_recusa(monkeypatch):
    broker, journal, table = _ledger_broker(monkeypatch)
    skewed = _Skewed(table.items)
    broker.session.client.call = skewed
    with pytest.raises(ValueError, match="^mode ledger read$"):
        _admit(journal)
    assert [name for name, _ in skewed.calls] == ["get_item"]


def _frame_scope(broker):
    control, ticket = _keys(_effect_id())
    keys = {"canary_id": json.loads(RECORD)["canary_id"], "owner_sha256": json.loads(RECORD)["owner_sha256"],
            "run_ids": json.loads(RECORD)["run_ids"], "dispatch_id": None}
    return broker._call_scope() | {"frame": {"name": "ledger-admit", "binding": keys}}, control, ticket


def _get(key, role="mode_dispatch", consistent=True):
    return {"role": role, "service": "dynamodb", "operation": "get_item", "parameters": {
        "TableName": "cnesdata-prod-control-plane", "Key": {"pk": {"S": key[0]}, "sk": {"S": key[1]}},
        "ConsistentRead": consistent}}


@pytest.mark.parametrize("case", ["fraca", "fora-do-c1", "papel", "operacao", "put-fora-do-c1"])
def test_validador_das_chamadas_do_frame_recusa_fora_do_c1_e_da_tabela(monkeypatch, case):
    broker, journal, table = _ledger_broker(monkeypatch)
    scope, control, ticket = _frame_scope(broker)
    foreign = (control[0], "PROD_CANARY_CONTROL#" + "b" * 64)
    native = {"fraca": _get(control, consistent=False), "fora-do-c1": _get(foreign), "papel": _get(control, "mode_seed"),
              "operacao": _get(control), "put-fora-do-c1": {
                  "role": "mode_dispatch", "service": "dynamodb", "operation": "put_item", "parameters": {
                      "TableName": "cnesdata-prod-control-plane", "ConditionExpression": "attribute_not_exists(pk)",
                      "Item": {"pk": {"S": foreign[0]}, "sk": {"S": foreign[1]}, "entity": {"S": "x"},
                               "payload": {"S": "{}"}}}}}[case]
    operation = "audit-start" if case == "operacao" else "recovery-start"
    assert _mb().validate_mode_frame_call("recovery-start", scope["frame"], _get(control), scope)
    with pytest.raises(ValueError, match="^(mode dynamodb call|mode key outside frame|mode frame call outside table)$"):
        _mb().validate_mode_frame_call(operation, scope["frame"], native, scope)
    with pytest.raises(ValueError):
        _mb().ModeEvidence._native(journal if operation == "recovery-start" else _foreign_journal(), c.canonical(native),
                                   scope, broker.governance)


def _foreign_journal():
    from test_cnesdata_mode_session_sts import _journal
    return _journal("audit-start")[0]


def _journal_call(journal, native):
    ticket = journal.begin_sdk_call(c.canonical(native), role_session_sha256="4" * 64)
    return ticket


@pytest.mark.parametrize("response", [
    {"Error": {"Code": "ValidationException"}},
    {"Error": {"Code": "TransactionCanceledException"}, "CancellationReasons": [{"Code": "ConditionalCheckFailed"}]},
    {"Error": {"Code": "ConditionalCheckFailedException"}, "CancellationReasons": []},
], ids=["erro-qualquer", "cancelamento-de-outra-operacao", "sem-motivos"])
def test_journal_so_aceita_o_cancelamento_definitivo_da_propria_escrita_do_frame(monkeypatch, response):
    import time
    from email.utils import formatdate
    broker, journal, table = _ledger_broker(monkeypatch)
    journal._broker = None
    control, _ = _keys(_effect_id())
    put = {"role": "mode_dispatch", "service": "dynamodb", "operation": "put_item", "parameters": {
        "TableName": "cnesdata-prod-control-plane", "ConditionExpression": "attribute_not_exists(pk)",
        "Item": {"pk": {"S": control[0]}, "sk": {"S": control[1]}, "entity": {"S": "x"}, "payload": {"S": "{}"}}}}
    ticket = _journal_call(journal, put)
    with pytest.raises(ValueError, match="^SDK response already sanitized before journal$"):
        journal.complete_sdk_call(ticket, c.canonical(response), request_id="native-id",
                                  server_date=formatdate(time.time(), usegmt=True))
    definite = {"Error": {"Code": "ConditionalCheckFailedException"}, "CancellationReasons": [{"Code": "ConditionalCheckFailed"}]}
    _, clean, _ = _ledger_broker(monkeypatch)
    clean._broker = None
    ticket = _journal_call(clean, put)
    receipt = clean.complete_sdk_call(ticket, c.canonical(definite), request_id="native-id",
                                      server_date=formatdate(time.time(), usegmt=True))
    assert receipt["response_sha256"] == c.sha(c.canonical(definite))


def test_run_task_depois_do_ledger_admit_segue_a_tabela_da_operacao(monkeypatch):
    from test_cnesdata_mode_effect_ecs import _run, _task
    from test_cnesdata_mode_run_task import REVISIONS
    record = json.dumps(json.loads(RECORD) | {"revisions": dict(REVISIONS)}, sort_keys=True, separators=(",", ":"))
    control = _keys(_effect_id())[0]
    broker, journal, table = _ledger_broker(monkeypatch, record=record, items={control: CONTROL})

    def sdk(service, name, **parameters):
        if service == "dynamodb":
            return table(service, name, **parameters)
        return {"tasks": [_task("recovery", "PROVISIONING")], "failures": [], "ResponseMetadata": _metadata()}
    broker.session.client.call = sdk
    reply, _ = _admit(journal)
    assert set(reply) == {"effect_id"}
    run, _ = _run(journal)
    assert run["kind"] == "sdk-result" and run["value"]["tasks"][0]["lastStatus"] == "PROVISIONING"
