"""P16b Q1b (c-1125-p16b-repin item 2, ruling 7): ModeBroker.dispatch_unit, the unit-start sequence journaled on ux with
C1 per request, the dispatch-unit frame, B3 on a fresh clock, the exact StartExecution and the bounded wait on uw."""
import copy
import datetime
import json
import re
from types import SimpleNamespace

import pytest

from test_cnesdata_mode_effect_broker import _Evidence, _metadata
from test_cnesdata_mode_session_sts import OWNER, RESOURCES, START, _case, _journal
from test_cnesdata_mode_unit_dispatch import CASES as DISPATCH
from tools.cnesdata_delivery import contract as c

VECTOR = json.loads(open(__file__.rsplit("/", 1)[0] + "/fixtures/cnesdata_mode_canary_frames_vector.json").read())
FRAME = next(case for case in VECTOR["cases"] if case["name"] == "dispatch-unit")
NOW = START + 30
SHIFT = NOW - int(datetime.datetime.fromisoformat(FRAME["now"].replace("Z", "+00:00")).timestamp())
TABLE = RESOURCES["table_arn"].rsplit("/", 1)[1]
TENANT_ID = RESOURCES["scope"]["tenant_id"]
RUN_ID = "unit-" + OWNER[:16]
MACHINE = RESOURCES["machine_arn"]


def _shifted(text):
    def move(match):
        moment = datetime.datetime.fromisoformat(match.group(0).replace("Z", "+00:00"))
        return (moment + datetime.timedelta(seconds=SHIFT)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return re.sub(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", move, text)


def _record(**changes):
    value = json.loads(_shifted(FRAME["record"])) | {"machine_arn": MACHINE} | changes
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


CONTROL = _shifted(FRAME["control"])


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _keys():
    return _mb()._product_module("cnes_infra.control_plane.dynamodb_keys")


def _units():
    return [dict(unit, tenant_id=TENANT_ID) for unit in DISPATCH["producao"]["units"]]


def _unit_item(unit):
    pk, sk = _keys().unit_key(TENANT_ID, RUN_ID, unit["unit_id"])
    return {"pk": {"S": pk}, "sk": {"S": sk}, "entity": {"S": "RUNUNIT"}, "payload": {"S": json.dumps(unit)},
            "gsi5pk": {"S": "RUN_ITEMS#x"}, "gsi5sk": {"S": "UNIT#x"}}


def _seed_journal(monkeypatch, units):
    args, _, _ = _case(monkeypatch, "unit-seed")
    session = _mb().assume_mode_session(**args)
    session.client.call = lambda service, name, **parameters: {"ResponseMetadata": _metadata()}
    broker = _mb().ModeBroker(_Evidence(), args["governance"], args["journal"], session, prepared_sha256="3" * 64,
                              credential_limit=args["credential_limit"], clock=args["clock"])
    for unit in units:
        broker.call(role="mode_seed", service="dynamodb", operation="put_item",
                    parameters={"TableName": TABLE, "Item": _unit_item(unit), "ConditionExpression": "attribute_not_exists(pk)"})
    return args["journal"]


class _Dynamo:
    def __init__(self, record, *, statuses=("RUNNING", "SUCCEEDED"), execution=None, after=None):
        frames, keys = _mb().product_frames(), _keys()
        tenant = frames.tenant_partition(TENANT_ID)
        run = keys.run_entity_key(TENANT_ID, RUN_ID)
        self.items = {run: {"pk": {"S": run[0]}, "sk": {"S": run[1]}, "entity": {"S": "RUN"},
                            "payload": {"S": json.dumps({"tenant_id": TENANT_ID, "run_id": RUN_ID, "state": "PROCESSING"})}},
                      (tenant, frames.record_key(OWNER, "unit")): {"payload": {"S": record}},
                      (tenant, frames.control_key(OWNER)): {"payload": {"S": CONTROL}}}
        for unit in _units():
            item = _unit_item(unit)
            self.items[(item["pk"]["S"], item["sk"]["S"])] = item
        for key, item in self.items.items():
            item.update({"pk": {"S": key[0]}, "sk": {"S": key[1]}})
        self.calls, self.statuses, self.execution, self.after = [], list(statuses), execution, after or {}

    def __call__(self, service, name, /, **parameters):
        self.calls.append((name, copy.deepcopy(parameters)))
        if name == "get_item":
            item = self.items.get((parameters["Key"]["pk"]["S"], parameters["Key"]["sk"]["S"]))
            return ({"Item": copy.deepcopy(item)} if item is not None else {}) | {"ResponseMetadata": _metadata()}
        if name == "start_execution":
            arn = self.execution or MACHINE.replace(":stateMachine:", ":execution:") + ":" + parameters["name"]
            return {"executionArn": arn, "startDate": datetime.datetime.fromtimestamp(NOW, datetime.timezone.utc),
                    "ResponseMetadata": _metadata()}
        for action in parameters.get("TransactItems", []):
            if "Put" in action:
                item = action["Put"]["Item"]
                self.items[(item["pk"]["S"], item["sk"]["S"])] = copy.deepcopy(item)
            update = action.get("Update")
            if update is not None and "ADD #token :one" in update["UpdateExpression"]:
                values = update["ExpressionAttributeValues"]
                self.items[("ENV#prod#SEMAPHORE", "UNIT")] = {
                    "pk": {"S": "ENV#prod#SEMAPHORE"}, "sk": {"S": "UNIT"}, "token": {"N": "1"},
                    "holder_tenant_id": values[":tenant"], "holder_run_id": values[":run"],
                    "holder_dispatch_id": values[":dispatch"]}
        hook = self.after.get(len([call for call in self.calls if call[0] == "transact_write_items"]))
        if name == "transact_write_items" and hook is not None:
            hook(self)
        return {"ResponseMetadata": _metadata()}

    def describe(self, service, name, /, **parameters):
        self.calls.append((name, copy.deepcopy(parameters)))
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return {"executionArn": parameters["executionArn"], "stateMachineArn": MACHINE, "name": parameters["executionArn"].rsplit(":", 1)[1],
                "status": status, "startDate": datetime.datetime.fromtimestamp(NOW, datetime.timezone.utc),
                "input": "{}", "ResponseMetadata": _metadata()}


def _world(monkeypatch, *, record=None, clock=None, seeds=1, wait=True, source=None, **dynamo):
    seeded = [_seed_journal(monkeypatch, _units()) for _ in range(seeds)]
    args, _, _ = _case(monkeypatch, "unit-start", source=source)
    raw = record or _record()
    args["journal"], _ = _journal("unit-start", {"record": raw.encode()}, source)
    start, uw = _mb().assume_unit_start_sessions(**args)
    keeper = SimpleNamespace(_contexts=[*seeded, args["journal"]])
    plan = _mb().unit_start_plan(keeper, args["journal"], resources=RESOURCES, now=NOW)
    table = _Dynamo(raw, **dynamo)
    start.client.call, uw.client.call = table, table.describe
    broker = _mb().ModeBroker(_Evidence(), args["governance"], args["journal"], start, prepared_sha256="3" * 64,
                              credential_limit=args["credential_limit"], clock=clock or args["clock"],
                              sleep=lambda seconds: None, wait=uw if wait else None, unit=plan)
    return broker, args["journal"], table, plan


def _binding(raw=None, **changes):
    return {"tenant_id": TENANT_ID, "run_ids": [RUN_ID], "owner_sha256": OWNER,
            "record_sha256": c.sha((raw or _record()).encode()), "phase": "unit", "context_kind": "promotion"} | changes


def _dispatch(broker, **changes):
    return broker.dispatch_unit({"kind": "dispatch-unit", "binding": _binding(**changes)})


def _names(table):
    return [name for name, _ in table.calls]


def test_plano_do_unit_start_vem_das_unidades_do_seed_e_do_record_do_journal(monkeypatch):
    broker, journal, _, plan = _world(monkeypatch)
    assert plan.locator == _mb().UnitLocator(TENANT_ID, (RUN_ID,), OWNER, c.sha(_record().encode()), "unit", "promotion")
    assert plan.start.promotion_id == "promo-1" and plan.start.now == datetime.datetime.fromtimestamp(NOW, datetime.timezone.utc)
    assert list(plan.start.dispatch.unit_ids) == DISPATCH["producao"]["result"]["unit_ids"]
    assert plan.execution == MACHINE.replace(":stateMachine:", ":execution:") + ":" + plan.start.dispatch.dispatch_id
    assert broker.unit is plan


@pytest.mark.parametrize("seeds", [0, 2])
def test_plano_exige_exatamente_um_journal_do_unit_seed(monkeypatch, seeds):
    with pytest.raises(ValueError, match="^mode unit seed journal$"):
        _world(monkeypatch, seeds=seeds)


@pytest.mark.parametrize("changes", [{"machine_arn": MACHINE + "-other"}, {"phase": "recovery", "mode": "recovery"},
                                     {"canary_id": "f" * 32}, {"owner_sha256": "b" * 64}])
def test_plano_recusa_record_fora_do_unit_start(monkeypatch, changes):
    with pytest.raises(ValueError, match="^mode unit plan record$"):
        _world(monkeypatch, record=_record(**changes))


def test_dispatch_unit_faz_a_sequencia_no_ux_e_espera_no_uw(monkeypatch):
    broker, journal, table, plan = _world(monkeypatch)
    reply = _dispatch(broker)
    assert reply["tasks"] == [] and reply["outputs"] == []
    assert reply["execution"] == {"executionArn": plan.execution, "stateMachineArn": MACHINE,
                                  "name": plan.start.dispatch.dispatch_id, "status": "SUCCEEDED",
                                  "startDate": c.utc(NOW)}
    names = _names(table)
    assert names.count("start_execution") == 1 and names.count("describe_execution") == 2
    assert names.index("start_execution") < names.index("describe_execution")
    assert len(journal.call_receipts) == len(table.calls) and broker.uncertainty == []
    assert [timing["kind"] for timing in journal._timings] == ["wait"]


def test_frame_do_dispatch_le_o_dispatch_ativo_record_control_e_ticket_e_grava_a_admissao(monkeypatch):
    broker, _, table, plan = _world(monkeypatch)
    _dispatch(broker)
    frames, keys = _mb().product_frames(), _keys()
    tenant = frames.tenant_partition(TENANT_ID)
    reads = [(call["Key"]["pk"]["S"], call["Key"]["sk"]["S"]) for name, call in table.calls if name == "get_item"]
    after_reserve = reads[4:8]
    assert after_reserve == [keys.dispatch_key(TENANT_ID, RUN_ID), (tenant, frames.record_key(OWNER, "unit")),
                             (tenant, frames.control_key(OWNER)), (tenant, frames.ticket_key(OWNER, plan.effect))]
    admission = [call for name, call in table.calls if name == "transact_write_items"][1]
    puts = [item["Put"]["Item"]["sk"]["S"] for item in admission["TransactItems"]]
    assert puts == [frames.ticket_key(OWNER, plan.effect), frames.control_key(OWNER), "PROD_CANARY#" + plan.start.dispatch.dispatch_id]


def test_acquire_e_claim_usam_o_promotion_id_do_record(monkeypatch):
    broker, _, table, _ = _world(monkeypatch)
    _dispatch(broker)
    acquire, claim = [call for name, call in table.calls if name == "transact_write_items"][2:4]
    assert acquire["TransactItems"][0]["ConditionCheck"]["ExpressionAttributeValues"][":canary"] == {"S": "promo-1"}
    assert claim["TransactItems"][1]["Update"]["ExpressionAttributeValues"][":canary"] == {"S": "promo-1"}


def test_start_execution_e_o_do_construtor_na_maquina_dos_recursos(monkeypatch):
    broker, _, table, plan = _world(monkeypatch)
    _dispatch(broker)
    request = next(call for name, call in table.calls if name == "start_execution")
    assert request == {"stateMachineArn": MACHINE, **_mb().product_dispatch().start_execution(plan.start.dispatch)}


def test_b3_le_record_control_e_ticket_entre_o_claim_e_o_start(monkeypatch):
    broker, _, table, plan = _world(monkeypatch)
    _dispatch(broker)
    frames = _mb().product_frames()
    tenant = frames.tenant_partition(TENANT_ID)
    names = _names(table)
    start = names.index("start_execution")
    claim = [index for index, name in enumerate(names) if name == "transact_write_items"][3]
    window = [(call["Key"]["pk"]["S"], call["Key"]["sk"]["S"]) for _, call in table.calls[claim + 1:start]]
    assert window == [(tenant, frames.record_key(OWNER, "unit")), (tenant, frames.control_key(OWNER)),
                      (tenant, frames.ticket_key(OWNER, plan.effect))]


def _unknown_ticket(table):
    frames = _mb().product_frames()
    tenant = frames.tenant_partition(TENANT_ID)
    for key, item in table.items.items():
        if key[0] == tenant and key[1].startswith("PROD_CANARY_EFFECT#"):
            changed = frames.parse_mapping(item["payload"]["S"], "ticket") | {"state": "UNKNOWN"}
            item["payload"]["S"] = frames.canonical_text(changed)
            assert frames.parse_ticket(item["payload"]["S"]).state == "UNKNOWN"


def test_b3_recusa_ticket_que_nao_esta_pendente_sem_start(monkeypatch):
    broker, _, table, _ = _world(monkeypatch, after={4: _unknown_ticket})
    with pytest.raises(ValueError, match="^mode unit live$"):
        _dispatch(broker)
    assert "start_execution" not in _names(table)


def test_b3_usa_relogio_novo_e_nao_o_do_estagio(monkeypatch):
    times = {"now": NOW}
    record = _record(canary_deadline=c.utc(NOW + 60))

    def late(table):
        times["now"] = NOW + 61
    broker, _, table, _ = _world(monkeypatch, record=record, clock=lambda: times["now"], after={4: late})
    with pytest.raises(ValueError, match="^mode unit live$"):
        _dispatch(broker, record_sha256=c.sha(record.encode()))
    assert "start_execution" not in _names(table)


def test_c1_recusa_pedido_fora_dos_alvos_antes_do_sdk(monkeypatch):
    broker, journal, table, _ = _world(monkeypatch)
    product = _mb().product_dispatch()
    original = product.attempt_request

    def shifted(start):
        request = original(start)
        return request | {"Key": {"pk": request["Key"]["pk"], "sk": {"S": "MONTH#2099-01"}}}
    monkeypatch.setattr(product, "attempt_request", shifted)
    with pytest.raises(ValueError, match="^mode unit dispatch call$"):
        _dispatch(broker)
    assert "update_item" not in _names(table) and "start_execution" not in _names(table)


def test_arn_de_execucao_divergente_recusa_antes_do_bind(monkeypatch):
    broker, _, table, plan = _world(monkeypatch, execution=MACHINE.replace(":stateMachine:", ":execution:") + ":outro")
    with pytest.raises(ValueError, match="^mode unit execution$"):
        _dispatch(broker)
    assert _names(table).count("transact_write_items") == 4 and "describe_execution" not in _names(table)


def test_espera_so_descreve_o_arn_exato_ate_o_terminal(monkeypatch):
    broker, journal, table, plan = _world(monkeypatch, statuses=("RUNNING", "RUNNING", "FAILED"))
    reply = _dispatch(broker)
    described = [call for name, call in table.calls if name == "describe_execution"]
    assert described == [{"executionArn": plan.execution}] * 3 and reply["execution"]["status"] == "FAILED"


def test_dispatch_ativo_de_outro_dispatch_recusa_antes_da_admissao(monkeypatch):
    def other(table):
        key = _keys().dispatch_key(TENANT_ID, RUN_ID)
        item = table.items[key]
        item["payload"]["S"] = json.dumps(json.loads(item["payload"]["S"]) | {"dispatch_id": "f" * 16})
    broker, _, table, _ = _world(monkeypatch, after={1: other})
    with pytest.raises(ValueError, match="^mode unit dispatch mismatch$"):
        _dispatch(broker)
    assert _names(table).count("transact_write_items") == 1


def test_dispatch_unit_uma_vez(monkeypatch):
    broker, _, table, _ = _world(monkeypatch)
    _dispatch(broker)
    count = len(table.calls)
    with pytest.raises(ValueError, match="^mode unit dispatch once$"):
        _dispatch(broker)
    assert len(table.calls) == count


@pytest.mark.parametrize("changes", [{"run_ids": ["unit-" + "b" * 16]}, {"record_sha256": "0" * 64},
                                     {"tenant_id": "prod-canary-" + "f" * 32}, {"phase": "recovery"}])
def test_binding_do_filho_diferente_do_locator_recusa_antes_de_qualquer_chamada(monkeypatch, changes):
    broker, _, table, _ = _world(monkeypatch)
    with pytest.raises(ValueError, match="^mode unit dispatch binding$"):
        _dispatch(broker, **changes)
    assert table.calls == []


def test_dispatch_unit_sem_parte_de_espera_recusa_antes_de_qualquer_chamada(monkeypatch):
    broker, _, table, _ = _world(monkeypatch, wait=False)
    with pytest.raises(ValueError, match="^mode method outside table$"):
        _dispatch(broker)
    assert table.calls == []


@pytest.mark.parametrize("operation, parameters", [
    ("describe_execution", {"executionArn": MACHINE.replace(":stateMachine:", ":execution:") + ":outro"}),
    ("describe_execution", {"executionArn": MACHINE.replace(":stateMachine:", ":execution:") + ":*"}),
    ("start_execution", {"stateMachineArn": MACHINE, "name": "outro", "input": "{}"}),
])
def test_validador_do_dispatch_recusa_execucao_fora_do_arn_exato_e_do_construtor(monkeypatch, operation, parameters):
    broker, _, _, plan = _world(monkeypatch)
    scope = broker._call_scope() | {"unit": broker._unit_scope()}
    native = {"role": "mode_dispatch", "service": "stepfunctions", "operation": operation, "parameters": parameters}
    with pytest.raises(ValueError, match="^mode unit dispatch call$"):
        _mb().validate_mode_dispatch_call("unit-start", native, scope)
    exact = {"executionArn": plan.execution} if operation == "describe_execution" else broker._unit_scope()["start"]
    assert _mb().validate_mode_dispatch_call("unit-start", native | {"parameters": exact}, scope) == exact


@pytest.mark.parametrize("operation", ["recovery-start", "audit-start", "unit-seed"])
def test_validador_do_dispatch_e_so_do_unit_start(monkeypatch, operation):
    broker, _, _, plan = _world(monkeypatch)
    scope = broker._call_scope() | {"unit": broker._unit_scope()}
    native = {"role": "mode_dispatch", "service": "stepfunctions", "operation": "describe_execution",
              "parameters": {"executionArn": plan.execution}}
    with pytest.raises(ValueError, match="^mode unit dispatch call$"):
        _mb().validate_mode_dispatch_call(operation, native, scope)
