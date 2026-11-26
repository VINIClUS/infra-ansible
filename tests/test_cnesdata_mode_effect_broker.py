"""P16b c-1124-p16b-next item 1: ModeBroker.call, the closed per-operation SDK table on the mc-* session."""
import base64
import time
from email.utils import formatdate

import pytest

from test_cnesdata_mode_session_sts import OWNER, RESOURCES, _case
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

TABLE = RESOURCES["table_arn"].rsplit("/", 1)[1]
BUCKET = RESOURCES["data_bucket_arn"].removeprefix("arn:aws:s3:::")
TENANT = "TENANT#" + RESOURCES["scope"]["tenant_id"].encode().hex()
RECORD = (TENANT, f"PROD_CANARY#{OWNER}#unit")
CONTROL = (TENANT, f"PROD_CANARY_CONTROL#{OWNER}")
RAW = RESOURCES["scope"]["raw_object_keys"][0]
BODY = b"PAR1-fixture-bytes"


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


class _Evidence:
    def __init__(self):
        self.objects, self.events = {}, []

    def get(self, bucket, key, *, maximum, absent=False):
        return self.objects.get(key), "etag"

    def put(self, bucket, key, raw):
        assert key not in self.objects
        self.events.append(key.rsplit("-", 1)[1])
        self.objects[key] = raw


class _Body:
    def __init__(self, raw):
        self.raw = raw

    def read(self, size=-1):
        chunk, self.raw = (self.raw, b"") if size < 0 else (self.raw[:size], self.raw[size:])
        return chunk


class _Native(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.response = {"Error": {"Code": code}, "ResponseMetadata": _metadata(status)}


def _metadata(status=200):
    return {"RequestId": "native-id", "HTTPStatusCode": status, "HTTPHeaders": {"date": formatdate(time.time(), usegmt=True)}}


def _broker(monkeypatch, operation="unit-seed", error=None):
    args, _, _ = _case(monkeypatch, operation)
    session = _mb().assume_mode_session(**args)
    evidence, native = _Evidence(), []

    def sdk(service, name, **parameters):
        native.append((service, name, parameters))
        if error is not None:
            raise error
        if name == "get_item":
            return {"Item": {"pk": parameters["Key"]["pk"], "sk": parameters["Key"]["sk"], "payload": {"S": "{}"}},
                    "ResponseMetadata": _metadata()}
        if name == "get_object":
            return {"Body": _Body(BODY), "ContentLength": len(BODY), "ResponseMetadata": _metadata()}
        return {"ETag": '"etag"', "ResponseMetadata": _metadata()}
    session.client.call = sdk
    broker = _mb().ModeBroker(evidence, args["governance"], args["journal"], session, prepared_sha256="3" * 64,
                              credential_limit=args["credential_limit"], clock=args["clock"])
    return broker, args["journal"], evidence, native


def _frame(service, operation, parameters, role="mode_seed"):
    return c.canonical({"kind": "call", "role": role, "service": service, "operation": operation, "parameters": parameters})


def _put_item(key=RECORD, **extra):
    return {"TableName": TABLE, "Item": {"pk": {"S": key[0]}, "sk": {"S": key[1]}, "payload": {"S": "{}"}},
            "ConditionExpression": "attribute_not_exists(pk)"} | extra


def _get_item(key=RECORD, **extra):
    return {"TableName": TABLE, "Key": {"pk": {"S": key[0]}, "sk": {"S": key[1]}}, "ConsistentRead": True} | extra


def _put_object(key=RAW, **extra):
    return {"Bucket": BUCKET, "Key": key, "Body": {"bytes": base64.b64encode(BODY).decode()}, "IfNoneMatch": "*"} | extra


def test_tabelas_de_chamadas_e_metodos_do_keeper_sao_as_do_produto():
    from test_cnesdata_mode_stages import PRODUCT
    assert lc.MODE_EFFECT_CALLS == PRODUCT["calls"] and lc.MODE_EFFECT_METHODS == PRODUCT["methods"]
    assert set(lc.MODE_EFFECT_CALLS) == set(_mb().MODE_EFFECTS)


def test_put_item_do_seed_tem_evidencia_duravel_e_resposta_vazia(monkeypatch):
    broker, journal, evidence, native = _broker(monkeypatch)
    reply, result = ag._adapter_message(_frame("dynamodb", "put_item", _put_item()), journal)
    assert result is None and reply == {"kind": "sdk-result", "value": {}}
    assert native == [("dynamodb", "put_item", _put_item())]
    assert evidence.events == ["intent.json", "response.json", "receipt.json"] and len(journal.call_receipts) == 1
    assert all("/unit-seed/" in key for key in evidence.objects) and broker.uncertainty == []


def test_get_item_forte_do_seed_devolve_o_item(monkeypatch):
    _, journal, _, native = _broker(monkeypatch, "recovery-seed")
    reply, _ = ag._adapter_message(_frame("dynamodb", "get_item", _get_item(CONTROL)), journal)
    assert reply == {"kind": "sdk-result", "value": {"Item": {"pk": {"S": CONTROL[0]}, "sk": {"S": CONTROL[1]},
                                                              "payload": {"S": "{}"}}}}
    assert native == [("dynamodb", "get_item", _get_item(CONTROL))]


def test_objeto_cru_vai_em_bytes_ao_sdk_e_volta_em_bytes_no_fio(monkeypatch):
    _, journal, _, native = _broker(monkeypatch)
    reply, _ = ag._adapter_message(_frame("s3", "put_object", _put_object()), journal)
    assert reply == {"kind": "sdk-result", "value": {}}
    reply, _ = ag._adapter_message(_frame("s3", "get_object", {"Bucket": BUCKET, "Key": RAW}), journal)
    assert reply == {"kind": "sdk-result", "value": {"Body": {"bytes": base64.b64encode(BODY).decode()}}}
    assert native == [("s3", "put_object", {"Bucket": BUCKET, "Key": RAW, "Body": BODY, "IfNoneMatch": "*"}),
                      ("s3", "get_object", {"Bucket": BUCKET, "Key": RAW})]


@pytest.mark.parametrize("service, operation, parameters, code, status", [
    ("dynamodb", "put_item", _put_item(), "ConditionalCheckFailedException", 400),
    ("s3", "put_object", _put_object(), "PreconditionFailed", 412)], ids=["item-existente", "objeto-existente"])
def test_insert_only_existente_e_resultado_definitivo_com_recibo(monkeypatch, service, operation, parameters, code, status):
    broker, journal, evidence, native = _broker(monkeypatch, error=_Native(code, status))
    reply, _ = ag._adapter_message(_frame(service, operation, parameters), journal)
    assert reply == {"kind": "sdk-error", "code": code} and len(native) == 1
    assert evidence.events == ["intent.json", "response.json", "receipt.json"] and broker.uncertainty == []
    assert journal.unknown == [] and not journal._failed


@pytest.mark.parametrize("service, operation, parameters, error", [
    ("dynamodb", "put_item", _put_item(), RuntimeError("timeout")),
    ("dynamodb", "get_item", _get_item(), _Native("ConditionalCheckFailedException", 400)),
    ("s3", "put_object", _put_object(), _Native("ConditionalRequestConflict", 409)),
    ("dynamodb", "put_item", _put_item(), _Native("ConditionalCheckFailedException", 500))],
    ids=["timeout", "condicional-em-leitura", "conflito-s3", "status-errado"])
def test_resultado_nativo_desconhecido_envenena_sem_retry(monkeypatch, service, operation, parameters, error):
    broker, journal, _, native = _broker(monkeypatch, error=error)
    with pytest.raises(ValueError, match="^mode native SDK (outcome unknown|authenticated status)$"):
        ag._adapter_message(_frame(service, operation, parameters), journal)
    assert len(native) == 1 and broker.uncertainty and journal._failed and journal.unknown


def _other_owner(key):
    return key[0], key[1].replace(OWNER, "b" * 64)


REFUSALS = {
    "alias": (("dynamodb", "put_item", _put_item(), "mode_dispatch"), "^mode call alias$"),
    "fora-da-tabela": (("ecs", "run_task", {"cluster": RESOURCES["cluster_arn"]}, "mode_seed"), "^mode call outside table$"),
    "outro-owner": (("dynamodb", "put_item", _put_item(_other_owner(RECORD)), "mode_seed"), "^mode key outside frame$"),
    "record-de-outra-fase": (("dynamodb", "put_item", _put_item((TENANT, f"PROD_CANARY#{OWNER}#recovery")), "mode_seed"),
                             "^mode key outside frame$"),
    "tabela": (("dynamodb", "put_item", _put_item(TableName="cnesdata-prod-other"), "mode_seed"), "^mode dynamodb call$"),
    "sem-condicao": (("dynamodb", "put_item", {"TableName": TABLE, "Item": _put_item()["Item"]}, "mode_seed"),
                     "^mode dynamodb call$"),
    "condicao-outra": (("dynamodb", "put_item", _put_item(ConditionExpression="attribute_exists(pk)"), "mode_seed"),
                       "^mode dynamodb call$"),
    "leitura-fraca": (("dynamodb", "get_item", _get_item(ConsistentRead=False), "mode_seed"), "^mode dynamodb call$"),
    "campo-extra": (("dynamodb", "get_item", _get_item(ProjectionExpression="pk"), "mode_seed"), "^mode dynamodb call$"),
    "bucket": (("s3", "put_object", _put_object(Bucket="cnesdata-prod-other"), "mode_seed"), "^mode s3 call$"),
    "chave-de-saida": (("s3", "get_object", {"Bucket": BUCKET, "Key": RESOURCES["scope"]["output_object_keys"][0]}, "mode_seed"),
                       "^mode s3 call$"),
    "sem-if-none-match": (("s3", "put_object", {key: value for key, value in _put_object().items() if key != "IfNoneMatch"},
                           "mode_seed"), "^mode s3 call$"),
    "corpo-cru": (("s3", "put_object", _put_object(Body="PAR1"), "mode_seed"), "^mode s3 call$"),
    "if-none-match-outro": (("s3", "put_object", _put_object(IfNoneMatch='"etag"'), "mode_seed"), "^mode s3 call$"),
}


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_seed_recusa_chamada_fora_da_tabela_antes_de_qualquer_io(monkeypatch, case):
    (service, operation, parameters, role), message = REFUSALS[case]
    broker, journal, evidence, native = _broker(monkeypatch)
    with pytest.raises(ValueError, match=message):
        ag._adapter_message(_frame(service, operation, parameters, role), journal)
    assert native == [] and evidence.objects == {} and journal.call_receipts == [] and broker.uncertainty == []


def test_controle_so_e_escrito_pelo_unit_seed(monkeypatch):
    _, journal, evidence, native = _broker(monkeypatch, "recovery-seed")
    with pytest.raises(ValueError, match="^mode key outside frame$"):
        ag._adapter_message(_frame("dynamodb", "put_item", _put_item(CONTROL)), journal)
    assert native == [] and evidence.objects == {}


@pytest.mark.parametrize("service, operation, parameters", [
    ("dynamodb", "get_item", _get_item()), ("states", "start_execution", {"stateMachineArn": RESOURCES["machine_arn"]}),
    ("ecs", "describe_tasks", {"cluster": RESOURCES["cluster_arn"], "tasks": []})])
def test_unit_start_nao_tem_chamada_direta(monkeypatch, service, operation, parameters):
    _, journal, evidence, native = _broker(monkeypatch, "unit-start")
    with pytest.raises(ValueError, match="^mode call outside table$"):
        ag._adapter_message(_frame(service, operation, parameters, "mode_dispatch"), journal)
    assert native == [] and evidence.objects == {}


def test_broker_de_modo_so_sobre_a_sessao_mc_de_um_journal_sem_broker(monkeypatch):
    broker, journal, evidence, _ = _broker(monkeypatch)
    with pytest.raises(ValueError, match="^one original admitted mode broker$"):
        _mb().ModeBroker(evidence, broker.governance, journal, broker.session, prepared_sha256="3" * 64,
                         credential_limit=broker.credential_limit, clock=broker.clock)
    journal._broker = None
    with pytest.raises(ValueError, match="^one original admitted mode broker$"):
        _mb().ModeBroker(evidence, broker.governance, journal, object(), prepared_sha256="3" * 64,
                         credential_limit=broker.credential_limit, clock=broker.clock)


def test_broker_de_modo_e_admitido_pelo_frame_e_os_clientes_sao_descartados(monkeypatch):
    broker, journal, _, _ = _broker(monkeypatch)
    assert journal._broker is broker and type(broker) in ag._brokers()
    ag._adapter_message(_frame("dynamodb", "put_item", _put_item()), journal)
    ag._drop_operation_clients(broker)
    assert (broker.aws, broker.session.client, broker.session.evidence) == (None, None, None)
    assert all(ledger._aws is None for ledger in broker.evidence)


def test_janela_da_sessao_vencida_recusa_antes_da_reserva(monkeypatch):
    broker, journal, evidence, native = _broker(monkeypatch)
    broker.clock = lambda: broker.session.deadline - 20
    with pytest.raises(ValueError, match="^mode finite SDK request/window$"):
        ag._adapter_message(_frame("dynamodb", "put_item", _put_item()), journal)
    assert native == [] and evidence.objects == {}


def test_evidencia_de_modo_revalida_a_chamada_antes_de_qualquer_gravacao(monkeypatch):
    broker, journal, evidence, _ = _broker(monkeypatch)
    raw = c.canonical({"role": "mode_dispatch", "service": "dynamodb", "operation": "put_item", "parameters": _put_item()})
    with pytest.raises(ValueError, match="^mode call alias$"):
        _mb().ModeEvidence(evidence, broker.governance, journal, raw, prepared_sha256="3" * 64,
                           role_session_sha256=broker.session.commitment, scope=broker.scope)
    assert evidence.objects == {}


def test_resposta_do_get_item_com_campo_alem_do_item_envenena(monkeypatch):
    broker, journal, _, native = _broker(monkeypatch)

    def sdk(service, name, **parameters):
        native.append((service, name, parameters))
        return {"Item": {"pk": parameters["Key"]["pk"]}, "ConsumedCapacity": {"TableName": TABLE}, "ResponseMetadata": _metadata()}
    broker.session.client.call = sdk
    with pytest.raises(ValueError, match="^finite native DynamoDB response$"):
        ag._adapter_message(_frame("dynamodb", "get_item", _get_item()), journal)
    assert len(native) == 1 and broker.uncertainty and journal._failed


def test_journal_do_efeito_so_aceita_o_erro_definitivo_da_propria_chamada(monkeypatch):
    broker, journal, _, _ = _broker(monkeypatch)
    raw = c.canonical({"role": "mode_seed", "service": "dynamodb", "operation": "put_item", "parameters": _put_item()})
    ticket = journal.begin_sdk_call(raw, role_session_sha256=broker.session.commitment)
    with pytest.raises(ValueError, match="^SDK response already sanitized before journal$"):
        journal.complete_sdk_call(ticket, c.canonical({"Error": {"Code": "PreconditionFailed"}}), request_id="native-id",
                                  server_date=formatdate(time.time(), usegmt=True))
