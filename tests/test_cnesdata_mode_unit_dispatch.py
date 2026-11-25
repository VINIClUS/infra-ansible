"""P16b Q1b (c-1125-p16b-repin item 2, ruling 7): B1 seed units and the keeper unit-start sequence over the vendored
builders, request for request equal to the product native path of the vector."""
import copy
import datetime
import json
import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
VECTOR = json.loads((FIXTURES / "cnesdata_mode_canary_frames_vector.json").read_text())
CASES = {case["name"]: case for case in VECTOR["dispatch"]["cases"]}
STEPS = ("reserve", "admit", "claim", "bind", "confirm")
FENCE, SEMAPHORE = ("ENV#prod#FENCE", "FENCE"), ("ENV#prod#SEMAPHORE", "UNIT")


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _keys():
    return _mb()._product_module("cnes_infra.control_plane.dynamodb_keys")


def _locator(case, **changes):
    return _mb().UnitLocator(**(case["locator"] | {"run_ids": tuple(case["locator"]["run_ids"])} | changes))


def _seed_item(unit):
    pk, sk = _keys().unit_key(unit["tenant_id"], unit["run_id"], unit["unit_id"])
    return {"pk": {"S": pk}, "sk": {"S": sk}, "entity": {"S": "RUNUNIT"}, "payload": {"S": json.dumps(unit)},
            "gsi5pk": {"S": "RUN_ITEMS#x"}, "gsi5sk": {"S": "UNIT#x"}}


def _put(item, response=None):
    return {"call": {"role": "mode_seed", "service": "dynamodb", "operation": "put_item",
                     "parameters": {"TableName": "cnesdata-prod-control-plane", "Item": item,
                                    "ConditionExpression": "attribute_not_exists(pk)"}},
            "response": {} if response is None else response}


def _seed_calls(case):
    run = {"pk": {"S": "TENANT#x"}, "sk": {"S": "RUN#x"}, "entity": {"S": "RUN"}, "payload": {"S": "{}"}}
    record = {"pk": {"S": "TENANT#x"}, "sk": {"S": "PROD_CANARY#x"}, "entity": {"S": "MODECANARYRECORD"},
              "payload": {"S": "{}"}}
    read = {"call": {"role": "mode_seed", "service": "dynamodb", "operation": "get_item",
                     "parameters": {"TableName": "t", "Key": {"pk": {"S": "a"}, "sk": {"S": "b"}}, "ConsistentRead": True}},
            "response": {"Item": _seed_item(dict(case["units"][0], unit_id="f" * 32))}}
    return [_put(record), _put(run), read, *(_put(_seed_item(unit)) for unit in case["units"])]


@pytest.mark.parametrize("name", sorted(CASES))
def test_unidades_do_b1_sao_os_putitem_runuint_liquidados_do_seed_iguais_ao_vetor(name):
    case = CASES[name]
    assert _mb().unit_seed_units(_seed_calls(case), _locator(case)) == case["units"]


@pytest.mark.parametrize("mutation", ["failed-put", "foreign-run", "foreign-tenant", "key-mismatch", "none"])
def test_b1_recusa_unidade_que_nao_e_um_putitem_liquidado_do_proprio_run(mutation):
    case = CASES["producao"]
    calls = _seed_calls(case)
    unit = calls[-1]["call"]["parameters"]["Item"]
    if mutation == "failed-put":
        calls[-1]["response"] = {"Error": {"Code": "ConditionalCheckFailedException"}}
    if mutation == "foreign-run":
        calls[-1] = _put(_seed_item(dict(case["units"][-1], run_id="unit-" + "b" * 16)))
    if mutation == "foreign-tenant":
        calls[-1] = _put(_seed_item(dict(case["units"][-1], tenant_id="prod-canary-" + "f" * 32)))
    if mutation == "key-mismatch":
        unit["payload"]["S"] = json.dumps(dict(case["units"][-1], unit_id="e" * 32))
    if mutation == "none":
        calls = calls[:3]
    with pytest.raises(ValueError, match="^mode unit seed units$"):
        _mb().unit_seed_units(calls, _locator(case))


class _Table:
    def __init__(self, case, *, fence_version=1, holder=None, active=None):
        self.items, self.events, self.case = {}, [], case
        for item in (case["run_item"], *case["unit_items"]):
            self.items[(item["pk"]["S"], item["sk"]["S"])] = item
        self.items[FENCE] = {"pk": {"S": FENCE[0]}, "sk": {"S": FENCE[1]}, "version": {"N": str(fence_version)},
                             "state": {"S": "OPEN"}}
        if active is not None:
            pk, sk = _keys().dispatch_key(case["locator"]["tenant_id"], case["locator"]["run_ids"][0])
            self.items[(pk, sk)] = {"pk": {"S": pk}, "sk": {"S": sk}, "payload": {"S": json.dumps(active)}}
        self.holder = holder

    def read(self, request):
        self.events.append(["get_item", copy.deepcopy(request)])
        item = self.items.get((request["Key"]["pk"]["S"], request["Key"]["sk"]["S"]))
        return copy.deepcopy(item)

    def write(self, operation, request):
        self.events.append([operation, copy.deepcopy(request)])
        for action in request.get("TransactItems", []):
            if "Put" in action:
                item = action["Put"]["Item"]
                self.items[(item["pk"]["S"], item["sk"]["S"])] = copy.deepcopy(item)
            update = action.get("Update")
            if update is not None and "ADD #token :one" in update["UpdateExpression"]:
                values = update["ExpressionAttributeValues"]
                holder = self.holder or (values[":tenant"]["S"], values[":run"]["S"], values[":dispatch"]["S"])
                self.items[SEMAPHORE] = {"pk": {"S": SEMAPHORE[0]}, "sk": {"S": SEMAPHORE[1]}, "token": {"N": "1"},
                                         "holder_tenant_id": {"S": holder[0]}, "holder_run_id": {"S": holder[1]},
                                         "holder_dispatch_id": {"S": holder[2]}}
        return {}

    def admit(self):
        self.events.append("admit")

    def live(self):
        self.events.append("live")

    def launch(self, request):
        self.events.append(["start_execution", request])
        return self.case["result"]["execution_ref"]


def _start(case):
    now = datetime.datetime.fromisoformat(case["now"])
    return _mb().unit_start_targets(_locator(case), case["units"], table=case["table"], now=now)[0]


def _steps(table, start):
    return _mb().unit_dispatch_steps(start, read=table.read, write=table.write, admit=table.admit, live=table.live,
                                     launch=table.launch)


@pytest.mark.parametrize("name", sorted(CASES))
def test_sequencia_do_keeper_e_a_do_caminho_nativo_do_produto_no_vetor(name):
    case = CASES[name]
    table = _Table(case)
    permit, execution = _steps(table, _start(case))
    expected = [request for step in STEPS for request in case["result"]["requests"][step]]
    assert [event for event in table.events if type(event) is list and event[0] != "start_execution"] == expected
    assert (permit.token, permit.fence_version) == (case["result"]["permit"]["token"], case["result"]["permit"]["fence_version"])
    assert execution == case["result"]["execution_ref"]
    assert ["start_execution", case["result"]["start_execution"]] in table.events


def test_frame_do_dispatch_vem_depois_do_reserve_e_antes_do_acquire_e_o_b3_antes_do_start():
    case = CASES["producao"]
    table = _Table(case)
    _steps(table, _start(case))
    marks = [event if type(event) is str else event[0] for event in table.events]
    reserve = len(case["result"]["requests"]["reserve"])
    assert marks[reserve - 1:reserve + 2] == ["transact_write_items", "admit", "transact_write_items"]
    claim = marks.index("live")
    assert marks[claim - 1:claim + 2] == ["transact_write_items", "live", "start_execution"]


def test_versao_do_fence_do_permit_vem_da_releitura_e_fence_ausente_e_zero():
    case = CASES["producao"]
    table = _Table(case)
    del table.items[FENCE]
    permit, _ = _steps(table, _start(case))
    assert (permit.token, permit.fence_version) == (1, 0)


@pytest.mark.parametrize("mutation, message", [
    ("active", "^mode unit dispatch reserve$"),
    ("foreign-holder", "^mode unit dispatch permit$"),
    ("foreign-tenant-holder", "^mode unit dispatch permit$"),
    ("missing-unit", "^mode unit dispatch reserve$"),
])
def test_sequencia_recusa_antes_da_escrita_seguinte(mutation, message):
    case = CASES["producao"]
    start = _start(case)
    tenant, run = case["locator"]["tenant_id"], case["locator"]["run_ids"][0]
    table = _Table(case, active={"dispatch_id": "f" * 16, "state": "RESERVED"} if mutation == "active" else None,
                   holder={"foreign-holder": (tenant, run, "f" * 16),
                           "foreign-tenant-holder": ("prod-canary-" + "f" * 32, run, start.dispatch.dispatch_id)}.get(mutation))
    if mutation == "missing-unit":
        item = case["unit_items"][-1]
        del table.items[(item["pk"]["S"], item["sk"]["S"])]
    writes = len([event for event in table.events if type(event) is list and event[0] != "get_item"])
    with pytest.raises(ValueError, match=message):
        _steps(table, start)
    done = [event[0] for event in table.events if type(event) is list and event[0] != "get_item"]
    assert "start_execution" not in done and "live" not in table.events
    if mutation in ("active", "missing-unit"):
        assert done == [] and writes == 0
    else:
        assert done == ["transact_write_items", "transact_write_items"]
