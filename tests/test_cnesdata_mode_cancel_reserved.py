"""P16b ruling 4 item 10: cancel_reserved is not a keeper operation; the ux broker refuses it before any SDK call."""
import json
import pathlib

import pytest

from test_cnesdata_mode_ledger import TABLE, _Table
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.iam_boundary import effective_iam

ROLES = json.loads((pathlib.Path(__file__).resolve().parent / "fixtures" / "cnesdata_mode_roles.json").read_text())
RESOURCES = ROLES["fields"]["resources"]
OWNER = "a" * 64
CANARY = "0123456789abcdef0123456789abcdef"
UNIT_RUN = "unit-" + OWNER[:16]
TENANT = "TENANT#" + ("prod-canary-" + CANARY).encode().hex()
SEMAPHORE = ("ENV#prod#SEMAPHORE", "UNIT")
DISPATCH = (TENANT + "#RUN#" + UNIT_RUN.encode().hex(), "DISPATCH#ACTIVE")
BINDING = {"canary_id": CANARY, "owner_sha256": OWNER, "run_ids": [UNIT_RUN], "dispatch_id": "1a2b3c4d5e6f7a8b"}
DEADLINE = int(c.instant(ROLES["fields"]["enabled_until"])) - 600


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _cancel_transaction(_texts):
    """Labelled shape of CnesData P16c 06849119 packages/cnes_infra/src/cnes_infra/control_plane/
    dynamodb_dispatch_start.py:59-113 cancel_reserved (sha256 c25d18a7...): a ConditionCheck on the unit SEMAPHORE
    plus the Put of the RESERVED dispatch turned TERMINAL CANCELED."""
    check = {"ConditionCheck": {"TableName": TABLE, "Key": {"pk": {"S": SEMAPHORE[0]}, "sk": {"S": SEMAPHORE[1]}},
                                "ConditionExpression": "#v0 = :v0", "ExpressionAttributeNames": {"#v0": "start_state"},
                                "ExpressionAttributeValues": {":v0": {"S": "RESERVED"}}}}
    put = {"Put": {"TableName": TABLE, "Item": {"pk": {"S": DISPATCH[0]}, "sk": {"S": DISPATCH[1]},
                                                "entity": {"S": "DISPATCH"}, "payload": {"S": "{}"}},
                   "ConditionExpression": "payload = :old", "ExpressionAttributeValues": {":old": {"S": "{}"}}}}
    return "transact_write_items", {"TransactItems": [check, put]}


def _write(frame, reads, table, build=_cancel_transaction):
    built = []

    def recorded(texts):
        built.append(texts)
        return build(texts)
    with pytest.raises(ValueError) as refused:
        _mb().ledger_write(frame, table=TABLE, binding=BINDING if frame == "dispatch-unit" else BINDING | {"dispatch_id": None},
                           reads=reads, read=table.read, build=recorded, execute=table.execute)
    return str(refused.value), built


@pytest.mark.parametrize("frame", ["cancel-reserved", "cancel_reserved", "dispatch-unit-cancel"])
def test_frame_cancel_reserved_e_recusado_antes_de_qualquer_leitura_mesmo_sem_chaves_de_leitura(frame):
    table = _Table({})
    message, built = _write(frame, [], table)
    assert message == "mode key outside frame"
    assert table.reads == table.writes == [] and built == []


def test_frame_cancel_reserved_com_as_leituras_do_produto_e_recusado_antes_de_ler():
    table = _Table({})
    message, built = _write("cancel-reserved", [DISPATCH, SEMAPHORE], table)
    assert message == "mode key outside frame" and table.reads == table.writes == [] and built == []


def test_dispatch_unit_nao_le_o_semaforo_que_o_cancel_reserved_confere():
    table = _Table({})
    message, built = _write("dispatch-unit", [SEMAPHORE], table)
    assert message == "mode key outside frame" and table.reads == table.writes == [] and built == []


def test_dispatch_unit_recusa_a_transacao_do_cancel_reserved_antes_da_escrita():
    table = _Table({})
    message, built = _write("dispatch-unit", [], table)
    assert message == "mode ledger request shape" and table.writes == [] and len(built) == 1


def test_nenhum_frame_do_ux_nem_do_vetor_tem_cancelamento():
    from tools.cnesdata_delivery.session_policy import MODE_SESSION_FRAMES
    assert MODE_SESSION_FRAMES["unit-start"] == ("dispatch-unit",)
    assert not any("cancel" in frame for frame in _mb().MODE_KEY_FRAMES)
    vector = json.loads((pathlib.Path(__file__).resolve().parent / "fixtures" / "cnesdata_mode_canary_frames_vector.json").read_text())
    assert not any("cancel" in case["name"] or "ConditionCheck" in json.dumps(case.get("result")) for case in vector["cases"])


def test_conditioncheck_no_semaforo_fica_fora_do_papel_e_da_sessao_ux_sem_mudanca_de_iam():
    """mode-canary.tf:68 grants SEMAPHORE GetItem and UpdateItem only; ux keeps neither."""
    from tools.cnesdata_delivery.session_policy import mode_session_policy
    role = ROLES["roles"]["mode_dispatch"]["policy"]["PolicyDocument"]
    session = mode_session_policy("unit-start", resources=RESOURCES, owner_sha256=OWNER, deadline=DEADLINE)
    context = {"aws:CurrentTime": c.utc(DEADLINE - 300),
               "dynamodb:LeadingKeys": [SEMAPHORE[0]]}
    table = RESOURCES["table_arn"]
    assert not effective_iam(role, [role], "dynamodb:ConditionCheckItem", table, context)
    assert not effective_iam(role, [session], "dynamodb:ConditionCheckItem", table, context)
    assert effective_iam(role, [role], "dynamodb:UpdateItem", table, context)
    assert not effective_iam(role, [session], "dynamodb:UpdateItem", table, context)
    assert lc.MODE_SESSION_OPERATIONS["unit-start"][:2] == ("ux", "mode_dispatch")
