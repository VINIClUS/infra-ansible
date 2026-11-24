"""P16b ruling 3 item 2: ledger writes over the vendored product builders, rebuild on a definite cancel, poison on unknown."""
import datetime
import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VECTOR = json.loads((ROOT / "tests" / "fixtures" / "cnesdata_mode_canary_frames_vector.json").read_bytes())
CASES = {case["name"]: case for case in VECTOR["cases"]}
TABLE = VECTOR["table"]


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


class _NativeError(Exception):
    def __init__(self, response=None):
        super().__init__("native")
        if response is not None:
            self.response = response


def _cancel(operation, codes, status=400):
    code = "TransactionCanceledException" if operation == "transact_write_items" else "ConditionalCheckFailedException"
    response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}
    return _NativeError(response | ({"CancellationReasons": [{"Code": item} for item in codes]}
                                    if operation == "transact_write_items" else {}))


class _Table:
    """Native DynamoDB fake with the product conditions: insert-only and payload swap, all-or-nothing transactions."""

    def __init__(self, items, *, interfere=(), forced=(), error=None):
        self.items, self.reads, self.writes = dict(items), [], []
        self.interfere, self.forced, self.error = list(interfere), list(forced), error

    def read(self, keys):
        self.reads.append(list(keys))
        return {key: self.items.get(key) for key in keys}

    @staticmethod
    def _puts(operation, request):
        return [item["Put"] for item in request["TransactItems"]] if operation == "transact_write_items" else [request]

    def _admits(self, put):
        key = (put["Item"]["pk"]["S"], put["Item"]["sk"]["S"])
        if put["ConditionExpression"] == "attribute_not_exists(pk)":
            return key not in self.items
        return self.items.get(key) == put["ExpressionAttributeValues"][":old"]["S"]

    def apply(self, operation, request):
        puts = self._puts(operation, request)
        codes = ["None" if self._admits(put) else "ConditionalCheckFailed" for put in puts]
        if any(code != "None" for code in codes):
            return codes
        for put in puts:
            self.items[(put["Item"]["pk"]["S"], put["Item"]["sk"]["S"])] = put["Item"]["payload"]["S"]
        return None

    def native(self, operation, request):
        self.writes.append((operation, request))
        if self.interfere:
            self.interfere.pop(0)(self)
        if self.error is not None:
            raise self.error
        forced = self.forced.pop(0) if self.forced else None
        codes = forced or self.apply(operation, request)
        if codes is not None:
            raise _cancel(operation, codes)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def execute(self, operation, request):
        try:
            self.native(operation, request)
        except _NativeError as error:
            projected = _mb().ledger_cancel_response(operation, error)
            if projected is None:
                raise
            return projected
        return {}


class _Ledger:
    def __init__(self, case_name):
        frames = _mb().product_frames()
        case = CASES[case_name]
        self.frames, self.case = frames, case
        self.record = frames.ModeCanaryRecord.from_mapping(json.loads(case["record"]))
        self.binding = frames.ModeCanaryBinding(f"prod-canary-{self.record.canary_id}", self.record.run_ids,
                                                self.record.owner_sha256, hashlib.sha256(case["record"].encode()).hexdigest(),
                                                self.record.phase, self.record.context_kind)
        self.pk = frames.tenant_partition(self.binding.tenant_id)
        self.control = (self.pk, frames.control_key(self.binding.owner_sha256))
        self.c1 = {"canary_id": self.record.canary_id, "owner_sha256": self.record.owner_sha256,
                   "run_ids": list(self.record.run_ids), "dispatch_id": None}

    def ticket(self, effect):
        identifier = self.frames.effect_id(self.binding.record_sha256, effect.kind, effect.request_sha256)
        return (self.pk, self.frames.ticket_key(self.binding.owner_sha256, identifier))

    def admission(self, effect, now=None):
        now = now or datetime.datetime.fromisoformat(self.case["now"])
        ticket = self.ticket(effect)

        def build(texts):
            state = self.frames.LedgerState(self.binding, self.record, texts[self.control], texts[ticket])
            plan = self.frames.admission(TABLE, state, effect, now)
            return None if plan.items is None else ("transact_write_items", {"TransactItems": plan.items})
        return [self.control, ticket], build

    def transition(self, change):
        identifier = json.loads(self.case["ticket"])["effect_id"]
        ticket = (self.pk, self.frames.ticket_key(self.binding.owner_sha256, identifier))

        def build(texts):
            item = self.frames.transition(TABLE, self.binding, texts[ticket], change)
            return None if item is None else ("put_item", item)
        return ticket, build

    def effect(self, request_sha256=None):
        value = self.case["effect"]
        return self.frames.ledger_effect(value["kind"], request_sha256 or value["request_sha256"], value["target_sha256"])

    def write(self, frame, table, reads, build):
        return _mb().ledger_write(frame, table=TABLE, binding=self.c1, reads=reads, read=table.read, build=build,
                                  execute=table.execute)


def _admit(**flags):
    ledger = _Ledger("ledger-admit")
    reads, build = ledger.admission(ledger.effect())
    table = _Table({ledger.control: ledger.case["control"]}, **flags)
    return ledger, table, reads, build


def test_ledger_admit_grava_uma_vez_a_transacao_exata_do_produto_quando_nada_cancela():
    ledger, table, reads, build = _admit()
    assert ledger.write("ledger-admit", table, reads, build) == 1
    assert table.writes == [("transact_write_items", {"TransactItems": ledger.case["result"]["items"]})]
    assert table.reads == [reads]
    assert table.items[reads[1]] == ledger.case["result"]["items"][0]["Put"]["Item"]["payload"]["S"]


def test_ledger_releia_e_nao_grava_de_novo_quando_o_cancelamento_mostra_o_mesmo_efeito_ja_admitido():
    """The product re-entry rule: after a cancel the ticket exists with the same kind and request, so no second write."""
    ledger, _, reads, build = _admit()

    def concurrent(table):
        assert table.apply("transact_write_items", {"TransactItems": ledger.case["result"]["items"]}) is None
    table = _Table({ledger.control: ledger.case["control"]}, interfere=[concurrent])
    assert ledger.write("ledger-admit", table, reads, build) == 1
    assert len(table.writes) == 1 and table.reads == [reads, reads]


def test_ledger_reconstroi_sobre_o_control_relido_quando_outro_efeito_trocou_o_control():
    ledger, _, reads, build = _admit()
    other_reads, other_build = ledger.admission(ledger.effect("4" * 64))

    def concurrent(table):
        texts = table.read(other_reads)
        table.reads.pop()
        assert table.apply(*other_build(texts)) is None
    table = _Table({ledger.control: ledger.case["control"]}, interfere=[concurrent])
    assert ledger.write("ledger-admit", table, reads, build) == 2
    first, second = (request["TransactItems"][1]["Put"] for _, request in table.writes)
    assert first["ExpressionAttributeValues"][":old"]["S"] == ledger.case["control"]
    assert second["ExpressionAttributeValues"][":old"]["S"] != ledger.case["control"]
    assert table.reads == [reads, reads] and reads[1] in table.items


@pytest.mark.parametrize("codes", [["None", "TransactionConflict"], ["TransactionConflict", "None"],
                                   ["ConditionalCheckFailed", "None"]])
def test_ledger_reconstroi_apos_cancelamento_com_motivos_do_conjunto_permitido(codes):
    ledger, table, reads, build = _admit(forced=[codes])
    assert ledger.write("ledger-admit", table, reads, build) == 2
    assert table.reads == [reads, reads] and table.writes[0] == table.writes[1]


def test_ledger_recusa_ledger_contended_ao_esgotar_o_teto_vendorizado_com_uma_escrita_por_tentativa():
    frames = _mb().product_frames()
    ledger, table, reads, build = _admit(forced=[["None", "TransactionConflict"]] * 5)
    with pytest.raises(ValueError, match=f"^ledger_contended attempts={frames.ATTEMPTS}$"):
        ledger.write("ledger-admit", table, reads, build)
    assert len(table.writes) == len(table.reads) == frames.ATTEMPTS == VECTOR["attempts"] == 3
    assert reads[1] not in table.items


@pytest.mark.parametrize("codes, reason", [
    (["None", "ThrottlingError"], "ThrottlingError"), (["ValidationError", "None"], "ValidationError"),
    (["ItemCollectionSizeLimitExceeded", "None"], "ItemCollectionSizeLimitExceeded"),
    (["TransactionConflict", "ProvisionedThroughputExceeded"], "ProvisionedThroughputExceeded")])
def test_ledger_recusa_sem_nova_tentativa_quando_algum_motivo_do_cancelamento_fica_fora_do_conjunto(codes, reason):
    ledger, table, reads, build = _admit(forced=[codes])
    with pytest.raises(ValueError, match=f"^ledger_cancel reason={reason}$"):
        ledger.write("ledger-admit", table, reads, build)
    assert len(table.writes) == len(table.reads) == 1


@pytest.mark.parametrize("error", [_NativeError(), _NativeError({"Error": {"Code": "TransactionCanceledException"},
                                                                 "ResponseMetadata": {"HTTPStatusCode": 400}}),
                                   _NativeError({"Error": {"Code": "InternalServerError"},
                                                 "ResponseMetadata": {"HTTPStatusCode": 500}})],
                         ids=["timeout", "sem-motivos", "erro-interno"])
def test_ledger_nao_tenta_de_novo_quando_o_resultado_e_desconhecido(error):
    ledger, table, reads, build = _admit(error=error)
    with pytest.raises(_NativeError):
        ledger.write("ledger-admit", table, reads, build)
    assert len(table.writes) == len(table.reads) == 1


@pytest.mark.parametrize("frame", ["ledger-unknown", "ledger-settle", "unit-seed"])
def test_ledger_recusa_chave_fora_do_frame_antes_de_qualquer_leitura_ou_escrita(frame):
    ledger, table, reads, build = _admit()
    with pytest.raises(ValueError, match="^mode key outside frame$"):
        ledger.write(frame, table, reads, build)
    assert table.reads == table.writes == []


def test_ledger_recusa_item_escrito_fora_do_frame_antes_da_escrita():
    ledger, table, reads, build = _admit()
    record_key = (ledger.pk, f"PROD_CANARY#{ledger.binding.owner_sha256}#{ledger.binding.phase}")

    def foreign(texts):
        operation, request = build(texts)
        put = json.loads(json.dumps(request["TransactItems"][0]))
        put["Put"]["Item"]["sk"]["S"] = record_key[1]
        return operation, {"TransactItems": [*request["TransactItems"], put]}
    with pytest.raises(ValueError, match="^mode key outside frame$"):
        ledger.write("ledger-admit", table, reads, foreign)
    assert table.writes == []


@pytest.mark.parametrize("change", ["update", "table", "operation", "extra"])
def test_ledger_recusa_requisicao_fora_da_forma_dos_formatos_do_produto(change):
    ledger, table, reads, build = _admit()

    def changed(texts):
        operation, request = build(texts)
        items = json.loads(json.dumps(request["TransactItems"]))
        if change == "update":
            items[1] = {"Update": items[1]["Put"]}
        if change == "table":
            items[1]["Put"]["TableName"] = "other-table"
        if change == "operation":
            return "batch_write_item", {"TransactItems": items}
        extra = {"ClientRequestToken": "x"} if change == "extra" else {}
        return operation, {"TransactItems": items} | extra
    with pytest.raises(ValueError, match="^mode ledger request shape$"):
        ledger.write("ledger-admit", table, reads, changed)
    assert table.writes == []


@pytest.mark.parametrize("frame, case", [("ledger-settle", "ledger-settle"), ("ledger-unknown", "ledger-unknown")])
def test_transicao_do_ticket_grava_o_put_item_exato_do_produto(frame, case):
    ledger = _Ledger(case)
    read, build = ledger.transition(tuple(ledger.case["change"]))
    table = _Table({read: ledger.case["ticket"]})
    assert ledger.write(frame, table, [read], build) == 1
    assert table.writes == [("put_item", ledger.case["result"])]


def test_transicao_releia_e_para_quando_o_put_cancelado_mostra_o_ticket_ja_liquidado_com_o_mesmo_recibo():
    ledger = _Ledger("ledger-settle")
    read, build = ledger.transition(tuple(ledger.case["change"]))

    def concurrent(table):
        assert table.apply("put_item", ledger.case["result"]) is None
    table = _Table({read: ledger.case["ticket"]}, interfere=[concurrent])
    assert ledger.write("ledger-settle", table, [read], build) == 1
    assert table.reads == [[read], [read]]


def test_transicao_recusa_pelo_produto_quando_o_ticket_relido_foi_liquidado_com_outro_recibo():
    ledger = _Ledger("ledger-settle")
    read, build = ledger.transition(tuple(ledger.case["change"]))
    other = json.loads(ledger.case["result"]["Item"]["payload"]["S"]) | {"receipt_sha256": "5" * 64}

    def concurrent(table):
        table.items[read] = ledger.frames.canonical_text(other)
    table = _Table({read: ledger.case["ticket"]}, interfere=[concurrent])
    with pytest.raises(ledger.frames.SyntheticContextRequired, match="ticket_settled"):
        ledger.write("ledger-settle", table, [read], build)
    assert len(table.writes) == 1


@pytest.mark.parametrize("operation, codes, expected", [
    ("transact_write_items", ["None", "ConditionalCheckFailed"], ["None", "ConditionalCheckFailed"]),
    ("transact_write_items", ["TransactionConflict"], ["TransactionConflict"]),
    ("put_item", None, ["ConditionalCheckFailed"])])
def test_cancelamento_definitivo_vira_a_resposta_recibada_com_os_codigos_do_cancelamento(operation, codes, expected):
    error = _cancel(operation, codes or [])
    projected = _mb().ledger_cancel_response(operation, error)
    code = "TransactionCanceledException" if operation == "transact_write_items" else "ConditionalCheckFailedException"
    assert projected == {"Error": {"Code": code}, "CancellationReasons": [{"Code": item} for item in expected]}
    assert _mb().ledger_cancel_codes(projected) == tuple(expected)


@pytest.mark.parametrize("operation, error", [
    ("transact_write_items", _NativeError()),
    ("transact_write_items", _cancel("transact_write_items", [])),
    ("transact_write_items", _cancel("transact_write_items", ["None"], status=500)),
    ("transact_write_items", _NativeError({"Error": {"Code": "TransactionCanceledException"},
                                           "CancellationReasons": [{"Message": "x"}],
                                           "ResponseMetadata": {"HTTPStatusCode": 400}})),
    ("transact_write_items", _cancel("put_item", [])),
    ("put_item", _cancel("transact_write_items", ["ConditionalCheckFailed"])),
    ("put_item", _NativeError({"Error": {"Code": "ProvisionedThroughputExceededException"},
                               "ResponseMetadata": {"HTTPStatusCode": 400}})),
    ("get_item", _cancel("put_item", [])),
], ids=["sem-resposta", "sem-motivos", "status-500", "motivo-sem-codigo", "codigo-do-put-na-transacao",
        "codigo-da-transacao-no-put", "outro-codigo", "leitura"])
def test_erro_sem_cancelamento_definitivo_e_desconhecido(operation, error):
    assert _mb().ledger_cancel_response(operation, error) is None


def test_resposta_sem_erro_e_a_escrita_aplicada():
    assert _mb().ledger_cancel_codes({}) is None


@pytest.mark.parametrize("response", [{"Error": {"Code": "TransactionCanceledException"}},
                                      {"Error": {"Code": "X"}, "CancellationReasons": [{"Code": "None"}]},
                                      {"Error": {"Code": "TransactionCanceledException"}, "CancellationReasons": []},
                                      {"Item": {}}])
def test_resposta_recibada_fora_da_forma_recusa(response):
    with pytest.raises(ValueError, match="^mode ledger response$"):
        _mb().ledger_cancel_codes(response)
