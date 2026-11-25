"""P16b c-1124-p16b-next item 1: the child Context of the mode effects, through the real adapter child."""
import base64
import subprocess

import pytest

from test_cnesdata_mode_effect_broker import BODY, BUCKET, RAW, RECORD, _Body, _Evidence, _get_item, _metadata, _mb
from test_cnesdata_mode_ledger_frames import EFFECT, NOW, _effect_id, _ledger_broker
from test_cnesdata_mode_session_sts import _case
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c

STUB = '''class ClientError(Exception):
    def __init__(self, error_response, operation_name):
        super().__init__(operation_name)
        self.response, self.operation_name = error_response, operation_name
'''
HEADER = r'''import json
from botocore.exceptions import ClientError
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
'''


class _Error(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.response = {"Error": {"Code": code}, "ResponseMetadata": _metadata(status)}


def _product(tmp_path, body):
    product = tmp_path / "product"
    files = {"scripts/promotion/promote_api.py": HEADER + body, "botocore/__init__.py": "",
             "botocore/exceptions.py": STUB}
    for name, text in files.items():
        (product / name).parent.mkdir(parents=True, exist_ok=True)
        (product / name).write_text(text)

    def git(*args):
        return subprocess.run(["git", *args], cwd=product, check=True, capture_output=True).stdout.decode().strip()
    git("init", "-q")
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "mode child fixture")
    source = git("rev-parse", "HEAD")
    manifest = {"version": 1, "source_sha": source, "files": {name: c.sha((product / name).read_bytes()) for name in files}}
    return product, source, manifest


def _invoke(monkeypatch, product, source, manifest, journal):
    monkeypatch.setattr(journal, "validate_result", lambda raw: raw)
    raw = ag.invoke_adapter(product=product, source=source, manifest=manifest,
                            manifest_sha256=c.sha(c.canonical(manifest)), journal=journal, timeout=10)
    return c.loads(raw, canonical=True)


def _seed_broker(monkeypatch, source, failures=None):
    args, _, _ = _case(monkeypatch, "unit-seed", source=source)
    session = _mb().assume_mode_session(**args)
    native = []

    def sdk(service, name, **parameters):
        native.append((service, name, parameters))
        if (failures or {}).get(name):
            raise failures[name]
        if name == "get_item":
            return {"Item": {"pk": parameters["Key"]["pk"], "sk": parameters["Key"]["sk"], "payload": {"S": "{}"}},
                    "ResponseMetadata": _metadata()}
        if name == "get_object":
            return {"Body": _Body(BODY), "ContentLength": len(BODY), "ResponseMetadata": _metadata()}
        return {"ETag": '"etag"', "ResponseMetadata": _metadata()}
    session.client.call = sdk
    _mb().ModeBroker(_Evidence(), args["governance"], args["journal"], session, prepared_sha256="3" * 64,
                     credential_limit=args["credential_limit"], clock=args["clock"])
    return args["journal"], native


SEED = r'''
def execute_shared_operation(operation, request, context):
    item = {'TableName': TABLE, 'Item': {'pk': {'S': PK}, 'sk': {'S': SK}, 'payload': {'S': '{}'}},
            'ConditionExpression': 'attribute_not_exists(pk)'}
    out = {}
    try:
        context.call('mode_seed', 'dynamodb', 'put_item', item)
    except ClientError as error:
        out['item_error'] = [error.response, error.operation_name]
    context.call('mode_seed', 's3', 'put_object', {'Bucket': BUCKET, 'Key': KEY, 'Body': RAWBODY, 'IfNoneMatch': '*'})
    body = context.call('mode_seed', 's3', 'get_object', {'Bucket': BUCKET, 'Key': KEY})['Body']
    out['body'] = [type(body).__name__, body.decode()]
    return canonical(out)
'''


def _seed_code():
    from test_cnesdata_mode_effect_broker import TABLE
    return (SEED.replace("TABLE", repr(TABLE)).replace("PK", repr(RECORD[0])).replace("SK", repr(RECORD[1]))
            .replace("BUCKET", repr(BUCKET)).replace("KEY", repr(RAW)).replace("RAWBODY", repr(BODY)))


def test_filho_real_do_seed_manda_bytes_no_fio_e_recebe_o_codigo_definitivo(tmp_path, monkeypatch):
    product, source, manifest = _product(tmp_path, _seed_code())
    journal, native = _seed_broker(monkeypatch, source,
                                   {"put_item": _Error("ConditionalCheckFailedException", 400)})
    result = _invoke(monkeypatch, product, source, manifest, journal)
    assert result == {"item_error": [{"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem"],
                      "body": ["bytes", BODY.decode()]}
    assert [(service, name) for service, name, _ in native] == [
        ("dynamodb", "put_item"), ("s3", "put_object"), ("s3", "get_object")]
    assert native[1][2]["Body"] == BODY and len(journal.call_receipts) == 3


def test_filho_real_recebe_precondition_failed_do_put_object(tmp_path, monkeypatch):
    code = _seed_code().replace("    context.call('mode_seed', 's3', 'put_object'",
                                "    try:\n        context.call('mode_seed', 's3', 'put_object'").replace(
        "'IfNoneMatch': '*'})\n", "'IfNoneMatch': '*'})\n    except ClientError as error:\n"
        "        out['object_error'] = [error.response, error.operation_name]\n")
    product, source, manifest = _product(tmp_path, code)
    journal, _ = _seed_broker(monkeypatch, source, {"put_object": _Error("PreconditionFailed", 412)})
    result = _invoke(monkeypatch, product, source, manifest, journal)
    assert result["object_error"] == [{"Error": {"Code": "PreconditionFailed"}}, "PutObject"]


def _forged(monkeypatch, replies):
    original = ag._adapter_message

    def message(frame, journal):
        value = c.loads(frame, canonical=True)
        key = value.get("operation", value["kind"])
        return (replies[key], None) if key in replies else original(frame, journal)
    monkeypatch.setattr(ag, "_adapter_message", message)


CATCH = r'''
def execute_shared_operation(operation, request, context):
    try:
        CALL
    except ClientError as error:
        return canonical({'code': error.response['Error']['Code']})
    except AttributeError:
        return canonical({'method': 'absent'})
    return canonical({'returned': True})
'''


@pytest.mark.parametrize(("operation", "call", "reply"), [
    ("put_item", "context.call('mode_seed', 'dynamodb', 'put_item', {})", {"kind": "sdk-error", "code": "ExecutionDoesNotExist"}),
    ("put_item", "context.call('mode_seed', 'dynamodb', 'put_item', {})", {"kind": "sdk-error", "code": "PreconditionFailed"}),
    ("put_object", "context.call('mode_seed', 's3', 'put_object', {})", {"kind": "sdk-error", "code": "ConditionalCheckFailedException"}),
    ("get_item", "context.call('mode_seed', 'dynamodb', 'get_item', {})", {"kind": "sdk-error", "code": "ConditionalCheckFailedException"}),
    ("get_object", "context.call('mode_seed', 's3', 'get_object', {})", {"kind": "sdk-result", "value": {"Body": "UEFSMQ=="}}),
    ("get_object", "context.call('mode_seed', 's3', 'get_object', {})", {"kind": "sdk-result", "value": {"Body": {"bytes": "UEFSMQ==", "x": 1}}}),
    ("get_object", "context.call('mode_seed', 's3', 'get_object', {})", {"kind": "sdk-result", "value": {"Body": {"bytes": "não"}}}),
    ("ledger-admit", "context.ledger_admit_effect('run-recovery', '1' * 64, '2' * 64, '2026-01-01T00:00:00Z')", {"effect_id": "a" * 64, "x": 1}),
    ("ledger-admit", "context.ledger_admit_effect('run-recovery', '1' * 64, '2' * 64, '2026-01-01T00:00:00Z')", {}),
    ("ledger-unknown", "context.ledger_mark_unknown('a' * 64)", {"effect_id": "a" * 64}),
    ("ledger-settle", "context.ledger_settle('a' * 64, 'b' * 64)", {"settled": True}),
])
def test_filho_recusa_resposta_fora_do_contrato_do_metodo(tmp_path, monkeypatch, operation, call, reply):
    product, source, manifest = _product(tmp_path, CATCH.replace("CALL", call))
    journal, _ = _seed_broker(monkeypatch, source)
    _forged(monkeypatch, {operation: reply})
    with pytest.raises(ValueError, match="^adapter complete result frame$"):
        _invoke(monkeypatch, product, source, manifest, journal)


LEDGER = r'''
def execute_shared_operation(operation, request, context):
    effect = context.ledger_admit_effect(KIND, REQUEST, TARGET, ADMITTED)
    again = context.ledger_admit_effect(KIND, REQUEST, TARGET, ADMITTED)
    unknown = context.ledger_mark_unknown(effect)
    return canonical({'effect_id': effect, 'again': again, 'unknown': unknown})
'''


def _ledger_code(body=LEDGER):
    return (body.replace("KIND", repr(EFFECT["effect_kind"])).replace("REQUEST", repr(EFFECT["request_sha256"]))
            .replace("TARGET", repr(EFFECT["target_sha256"])).replace("ADMITTED", repr(c.utc(NOW))))


def test_filho_real_admite_o_efeito_e_marca_unknown_pelos_frames_do_keeper(tmp_path, monkeypatch):
    product, source, manifest = _product(tmp_path, _ledger_code())
    broker, journal, table = _ledger_broker(monkeypatch, source=source)
    result = _invoke(monkeypatch, product, source, manifest, journal)
    assert result == {"effect_id": _effect_id(), "again": _effect_id(), "unknown": None}
    assert [name for name, _ in table.calls].count("transact_write_items") == 1
    assert [name for name, _ in table.calls].count("put_item") == 1 and broker.uncertainty == []


def test_filho_real_settle_sem_recibo_desta_operacao_recusa_no_keeper(tmp_path, monkeypatch):
    body = LEDGER.replace("    unknown = context.ledger_mark_unknown(effect)\n",
                          "    unknown = context.ledger_settle(effect, '9' * 64)\n")
    product, source, manifest = _product(tmp_path, _ledger_code(body))
    _, journal, table = _ledger_broker(monkeypatch, source=source)
    with pytest.raises(ValueError, match="^mode ledger settle receipt$"):
        _invoke(monkeypatch, product, source, manifest, journal)
    assert [name for name, _ in table.calls].count("put_item") == 0
