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
SECTION = VECTOR["unit_observe"]
CLUSTER = RESOURCES["cluster_arn"]
TASK_PREFIX = CLUSTER.replace(":cluster/", ":task/") + "/"
TASK_IDS = ("ab" * 16, "0f" * 16)
REVISION = RESOURCES["revisions"]["unit"]


def _definition(change=None):
    value = json.loads(SECTION["definition"].replace(json.dumps(SECTION["cluster_arn"]), json.dumps(CLUSTER)))
    parameters = value["States"]["RunUnits"]["ItemProcessor"]["States"]["RunProcessor"]["Parameters"]
    if change is not None:
        change(value, parameters)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _readbacks(definition=None):
    return c.canonical(SECTION["readbacks"] | {"state_machine": {"stateMachineArn": MACHINE,
                                                                 "definition": definition or _definition()}})


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


def _native_task(arn):
    return {"taskArn": arn, "clusterArn": CLUSTER, "lastStatus": "STOPPED", "taskDefinitionArn": REVISION,
            "stopCode": "EssentialContainerExited", "cpu": "256", "attachments": [{"id": "eni"}],
            "containers": [{"name": "processor", "exitCode": 0, "containerArn": arn + "/c", "lastStatus": "STOPPED"}],
            "overrides": {"containerOverrides": [{"name": "processor", "command": ["run"],
                                                  "environment": [{"name": "UNIT_ID", "value": arn[-32:]}]}],
                          "inferenceAcceleratorOverrides": []}}


def _projected(arn):
    return {"taskArn": arn, "clusterArn": CLUSTER, "lastStatus": "STOPPED", "taskDefinitionArn": REVISION,
            "containers": [{"name": "processor", "exitCode": 0}],
            "overrides": {"containerOverrides": [{"name": "processor", "environment": [{"name": "UNIT_ID", "value": arn[-32:]}]}]}}


class _Dynamo:
    def __init__(self, record, *, statuses=("RUNNING", "SUCCEEDED"), execution=None, after=None, output=None,
                 described=None, terminal=None):
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
        self.uw, self.terminal, self.described = [], terminal, described
        tasks = [{"TaskArn": TASK_PREFIX + task_id, "LastStatus": "STOPPED"} for task_id in TASK_IDS]
        self.output_text = json.dumps(tasks if output is None else output)

    def _item(self, parameters):
        item = self.items.get((parameters["Key"]["pk"]["S"], parameters["Key"]["sk"]["S"]))
        return ({"Item": copy.deepcopy(item)} if item is not None else {}) | {"ResponseMetadata": _metadata()}

    def __call__(self, service, name, /, **parameters):
        self.calls.append((name, copy.deepcopy(parameters)))
        if name == "get_item":
            return self._item(parameters)
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

    def _commit(self, dispatch_id):
        for unit in _units():
            key = _keys().unit_key(TENANT_ID, RUN_ID, unit["unit_id"])
            manifest = {"manifest_id": "manifest-" + unit["unit_id"], "manifest_key": f"tmp/{unit['unit_id']}/manifest.json"}
            payload = json.loads(self.items[key]["payload"]["S"]) | {"state": "SUCCEEDED", "attempt": 1,
                                                                      "dispatch_id": dispatch_id, "output_manifests": [manifest]}
            self.items[key]["payload"]["S"] = json.dumps(payload)

    def describe(self, service, name, /, **parameters):
        self.calls.append((name, copy.deepcopy(parameters)))
        self.uw.append(name)
        if name == "get_item":
            return self._item(parameters)
        if name == "describe_tasks":
            response = (self.described(parameters["tasks"]) if self.described is not None
                        else {"tasks": [_native_task(arn) for arn in parameters["tasks"]], "failures": []})
            return response | {"ResponseMetadata": _metadata()}
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        moment = datetime.datetime.fromtimestamp(NOW, datetime.timezone.utc)
        response = {"executionArn": parameters["executionArn"], "stateMachineArn": MACHINE,
                    "name": parameters["executionArn"].rsplit(":", 1)[1], "status": status, "startDate": moment,
                    "input": "{}", "ResponseMetadata": _metadata()}
        if status == "SUCCEEDED":
            self._commit(response["name"])
            response["output"] = self.output_text
        if status != "RUNNING":
            response["stopDate"] = moment
            if self.terminal is not None:
                self.terminal(self)
        return response


def _world(monkeypatch, *, record=None, clock=None, seeds=1, wait=True, source=None, readbacks=None, **dynamo):
    seeded = [_seed_journal(monkeypatch, _units()) for _ in range(seeds)]
    args, _, _ = _case(monkeypatch, "unit-start", source=source)
    raw = record or _record()
    args["journal"], _ = _journal("unit-start", {"record": raw.encode(), "readbacks": readbacks or _readbacks()}, source)
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


def test_plano_leva_o_cluster_unico_da_maquina_do_readback_igual_ao_cluster_dos_recursos(monkeypatch):
    _, _, _, plan = _world(monkeypatch)
    assert plan.cluster == CLUSTER == _mb().product_unit_observe().unit_cluster(_definition())


def _other(value, parameters):
    parameters["Cluster"] = CLUSTER + "-other"


def _missing(value, parameters):
    del parameters["Cluster"]


def _two(value, parameters):
    value["States"]["Extra"] = {"Type": "Task", "End": True, "Parameters": {"Cluster": CLUSTER + "-other"}}


def _service(value, parameters):
    parameters["Cluster"] = CLUSTER.replace(":cluster/", ":service/")


@pytest.mark.parametrize("readbacks", [_readbacks(_definition(_other)), _readbacks(_definition(_missing)),
                                       _readbacks(_definition(_two)), _readbacks(_definition(_service)),
                                       _readbacks("{"), c.canonical({"fixture_only": "readbacks"})],
                         ids=["outro-cluster", "sem-cluster", "dois-clusters", "servico-com-conta", "definicao-invalida",
                              "readback-sem-maquina"])
def test_plano_recusa_cluster_da_maquina_diferente_do_recurso_antes_de_ler_o_seed(monkeypatch, readbacks):
    with pytest.raises(ValueError, match="^mode unit cluster$"):
        _world(monkeypatch, seeds=0, readbacks=readbacks)


def _reads(plan):
    return list(_mb().product_unit_observe().unit_output_reads(TABLE, TENANT_ID, RUN_ID, plan.start.dispatch.unit_ids))


def test_dispatch_unit_faz_a_sequencia_no_ux_e_no_uw_espera_descreve_as_tasks_e_le_os_outputs(monkeypatch):
    broker, journal, table, plan = _world(monkeypatch)
    reply = _dispatch(broker)
    reads, arns = _reads(plan), [TASK_PREFIX + task_id for task_id in sorted(TASK_IDS)]
    assert set(reply) == {"execution", "tasks", "failures", "outputs"}
    assert reply["execution"] == {"executionArn": plan.execution, "stateMachineArn": MACHINE,
                                  "name": plan.start.dispatch.dispatch_id, "status": "SUCCEEDED", "input": "{}",
                                  "output": table.output_text}
    assert reply["tasks"] == [_projected(arn) for arn in arns] and reply["failures"] == []
    items = [table.items[(read["Key"]["pk"]["S"], read["Key"]["sk"]["S"])] for read in reads]
    assert reply["outputs"] == _mb().product_unit_observe().unit_outputs(TENANT_ID, RUN_ID, plan.start.dispatch.unit_ids,
                                                                         items)
    assert [output["state"] for output in reply["outputs"]] == ["SUCCEEDED"] * len(reads) == ["SUCCEEDED"] * 2
    assert table.uw == ["describe_execution", "describe_execution", "describe_tasks", "get_item", "get_item"]
    assert [call for name, call in table.calls if name == "describe_tasks"] == [{"cluster": CLUSTER, "tasks": arns}]
    assert [call for _, call in table.calls[-2:]] == reads
    names = _names(table)
    assert names.count("start_execution") == 1 and names.index("start_execution") < names.index("describe_execution")
    assert len(journal.call_receipts) == len(table.calls) and broker.uncertainty == []
    assert [timing["kind"] for timing in journal._timings] == ["wait"]


def test_slot_do_unit_guarda_a_resposta_e_o_described_fica_so_para_recovery_e_audit(monkeypatch):
    broker, _, _, _ = _world(monkeypatch)
    assert broker.unit_observed is None
    reply = _dispatch(broker)
    assert broker.unit_observed == reply and broker.unit_observed is not reply and broker.described is None


def test_execucao_sem_sucesso_nao_descreve_tasks_e_projeta_a_unidade_pendente_sem_recusar(monkeypatch):
    broker, _, table, plan = _world(monkeypatch, statuses=("RUNNING", "FAILED"))
    reply = _dispatch(broker)
    assert reply["execution"]["status"] == "FAILED" and "output" not in reply["execution"]
    assert (reply["tasks"], reply["failures"]) == ([], []) and "describe_tasks" not in table.uw
    assert [(output["state"], output["attempt"], output["dispatch_id"], output["output_manifests"])
            for output in reply["outputs"]] == [("PENDING", 0, None, [])] * 2
    assert table.uw[-2:] == ["get_item", "get_item"] and [call for _, call in table.calls[-2:]] == _reads(plan)


def test_falhas_do_describe_tasks_seguem_na_resposta(monkeypatch):
    def described(arns):
        return {"tasks": [_native_task(arns[0])], "failures": [{"arn": arns[1], "reason": "MISSING", "detail": "x"}]}
    broker, _, _, _ = _world(monkeypatch, described=described)
    reply = _dispatch(broker)
    arns = [TASK_PREFIX + task_id for task_id in sorted(TASK_IDS)]
    assert reply["tasks"] == [_projected(arns[0])] and reply["failures"] == [{"arn": arns[1], "reason": "MISSING"}]


@pytest.mark.parametrize("name", sorted(case["name"] for case in SECTION["cases"]))
def test_projecoes_do_uw_preservam_as_respostas_sinteticas_do_vetor_e_descartam_as_datas(name):
    """Amendment 3: the synthetic responses check projection completeness only, never as AWS fixtures."""
    case = {item["name"]: item for item in SECTION["cases"]}[name]
    execution = case["execution"]["response"]
    native = execution | {"startDate": "2026-11-26T00:00:00Z", "stopDate": "2026-11-26T00:01:00Z", "ResponseMetadata": {}}
    projected = _mb()._mode_response("stepfunctions", "describe_execution", native, {})
    assert set(projected) == set(execution) == {"executionArn", "stateMachineArn", "name", "status", "input"} | (
        {"output"} if name != "execucao-nao-succeeded" else set())
    assert projected == execution
    if case["describe_tasks"] is not None:
        response = case["describe_tasks"]["response"]
        assert _mb()._mode_response("ecs", "describe_tasks", response, {}, unit=True) == response


def _many(count, item):
    return [copy.deepcopy(item) for _ in range(count)]


@pytest.mark.parametrize("response", [
    {"tasks": _many(101, _projected(TASK_PREFIX + "0" * 32)), "failures": []},
    {"tasks": [], "failures": _many(101, {"arn": "a", "reason": "MISSING"})},
    {"tasks": ["task"], "failures": []},
    {"tasks": [_projected(TASK_PREFIX + "0" * 32) | {"containers": _many(11, {"name": "p", "exitCode": 0})}],
     "failures": []},
    {"tasks": [_projected(TASK_PREFIX + "0" * 32) | {"overrides": {"containerOverrides": [
        {"name": "p", "environment": _many(33, {"name": "N", "value": "v"})}]}}], "failures": []},
    {"tasks": [_projected(TASK_PREFIX + "0" * 32) | {"overrides": ["x"]}], "failures": []},
    {"tasks": [], "failures": [], "nextToken": "x"}],
    ids=["101-tasks", "101-falhas", "task-nao-objeto", "11-containers", "33-variaveis", "overrides-nao-objeto",
         "campo-de-topo"])
def test_projecao_das_tasks_do_uw_recusa_resposta_fora_dos_limites(response):
    with pytest.raises(ValueError, match="^finite native unit ECS response$"):
        _mb()._mode_response("ecs", "describe_tasks", response, {}, unit=True)


def test_projecao_das_tasks_de_recovery_e_audit_continua_a_de_uma_task():
    response = {"tasks": [_native_task(TASK_PREFIX + task_id) for task_id in TASK_IDS], "failures": []}
    assert len(_mb()._mode_response("ecs", "describe_tasks", response, {}, unit=True)["tasks"]) == 2
    with pytest.raises(ValueError, match="^finite native ECS response$"):
        _mb()._mode_response("ecs", "describe_tasks", response, {})


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


def test_c1_recusa_describe_tasks_de_cluster_diferente_do_recurso_antes_do_sdk(monkeypatch):
    """Second of the three cluster checks: C1 compares the DescribeTasks cluster with the resources cluster."""
    other = CLUSTER + "-other"
    broker, journal, table, plan = _world(monkeypatch, output=[{"TaskArn": other.replace(":cluster/", ":task/") + "/" + "0" * 32}])
    broker.unit = plan._replace(cluster=other)
    with pytest.raises(ValueError, match="^mode unit dispatch call$"):
        _dispatch(broker)
    assert "describe_tasks" not in table.uw and "get_item" not in table.uw and broker.unit_observed is None


def _scope(broker, part, **changes):
    return broker._call_scope() | {"unit": broker._unit_scope() | {"part": part} | changes}


def _native(service, operation, parameters):
    return {"role": "mode_dispatch", "service": service, "operation": operation, "parameters": parameters}


def test_c1_do_uw_admite_so_a_proxima_leitura_exata_dos_outputs(monkeypatch):
    broker, _, _, plan = _world(monkeypatch)
    first, second = _reads(plan)
    scope = _scope(broker, "uw")
    assert _mb().validate_mode_dispatch_call("unit-start", _native("dynamodb", "get_item", first), scope) == first
    foreign = first | {"Key": first["Key"] | {"sk": {"S": "UNIT#" + "0" * 64}}}
    for parameters in (second, foreign, first | {"ConsistentRead": False}, first | {"TableName": "outra"}):
        with pytest.raises(ValueError, match="^mode unit dispatch call$"):
            _mb().validate_mode_dispatch_call("unit-start", _native("dynamodb", "get_item", parameters), scope)
    broker._unit_reads = 1
    assert _mb().validate_mode_dispatch_call("unit-start", _native("dynamodb", "get_item", second),
                                             _scope(broker, "uw")) == second
    broker._unit_reads = 2
    with pytest.raises(ValueError, match="^mode unit dispatch call$"):
        _mb().validate_mode_dispatch_call("unit-start", _native("dynamodb", "get_item", second), _scope(broker, "uw"))


def test_c1_do_uw_admite_so_o_describe_tasks_esperado_no_cluster_dos_recursos(monkeypatch):
    broker, _, _, _ = _world(monkeypatch)
    request = {"cluster": CLUSTER, "tasks": [TASK_PREFIX + "0" * 32]}
    assert _mb().validate_mode_dispatch_call("unit-start", _native("ecs", "describe_tasks", request),
                                             _scope(broker, "uw", describe=request)) == request
    other = {"cluster": CLUSTER + "-other", "tasks": [TASK_PREFIX + "0" * 32]}
    for parameters, describe in ((request, None), (request | {"tasks": [TASK_PREFIX + "1" * 32]}, request),
                                 (other, other)):
        with pytest.raises(ValueError, match="^mode unit dispatch call$"):
            _mb().validate_mode_dispatch_call("unit-start", _native("ecs", "describe_tasks", parameters),
                                              _scope(broker, "uw", describe=describe))


def test_c1_separa_a_espera_e_as_leituras_no_uw_do_inicio_no_ux(monkeypatch):
    broker, _, _, plan = _world(monkeypatch)
    request = {"cluster": CLUSTER, "tasks": [TASK_PREFIX + "0" * 32]}
    for native in (_native("stepfunctions", "describe_execution", {"executionArn": plan.execution}),
                   _native("ecs", "describe_tasks", request)):
        with pytest.raises(ValueError, match="^mode unit dispatch call$"):
            _mb().validate_mode_dispatch_call("unit-start", native, _scope(broker, "ux", describe=request))
    start = broker._unit_scope()["start"]
    for native in (_native("stepfunctions", "start_execution", start),
                   _native("dynamodb", "transact_write_items", {"TransactItems": []})):
        with pytest.raises(ValueError, match="^mode unit dispatch call$"):
            _mb().validate_mode_dispatch_call("unit-start", native, _scope(broker, "uw"))


def _drop_unit(table):
    key = _keys().unit_key(TENANT_ID, RUN_ID, _units()[1]["unit_id"])
    del table.items[key]


def _other_entity(table):
    table.items[_keys().unit_key(TENANT_ID, RUN_ID, _units()[1]["unit_id"])]["entity"] = {"S": "RUN"}


def _no_manifests(table):
    item = table.items[_keys().unit_key(TENANT_ID, RUN_ID, _units()[1]["unit_id"])]
    payload = json.loads(item["payload"]["S"])
    del payload["output_manifests"]
    item["payload"]["S"] = json.dumps(payload)


@pytest.mark.parametrize("spoil", [_drop_unit, _other_entity, _no_manifests], ids=["ausente", "entidade", "sem-campo"])
def test_output_recusado_pelo_produto_falha_a_operacao_sem_slot_e_mantem_os_recibos(monkeypatch, spoil):
    broker, journal, table, _ = _world(monkeypatch, terminal=spoil)
    with pytest.raises(ValueError, match="^mode_unit_outputs=refused$"):
        _dispatch(broker)
    assert broker.unit_observed is None and table.uw[-2:] == ["get_item", "get_item"]
    assert len(journal.call_receipts) == len(table.calls) and broker.uncertainty == []


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
    scope = _scope(broker, "uw" if operation == "describe_execution" else "ux")
    native = {"role": "mode_dispatch", "service": "stepfunctions", "operation": operation, "parameters": parameters}
    with pytest.raises(ValueError, match="^mode unit dispatch call$"):
        _mb().validate_mode_dispatch_call("unit-start", native, scope)
    exact = {"executionArn": plan.execution} if operation == "describe_execution" else broker._unit_scope()["start"]
    assert _mb().validate_mode_dispatch_call("unit-start", native | {"parameters": exact}, scope) == exact


@pytest.mark.parametrize("operation", ["recovery-start", "audit-start", "unit-seed"])
def test_validador_do_dispatch_e_so_do_unit_start(monkeypatch, operation):
    broker, _, _, plan = _world(monkeypatch)
    scope = _scope(broker, "uw")
    native = {"role": "mode_dispatch", "service": "stepfunctions", "operation": "describe_execution",
              "parameters": {"executionArn": plan.execution}}
    with pytest.raises(ValueError, match="^mode unit dispatch call$"):
        _mb().validate_mode_dispatch_call(operation, native, scope)


def _product_text(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def test_passo_unit_execution_igual_ao_texto_do_produto_da_execucao_devolvida_e_aceito(monkeypatch):
    broker, journal, _, _ = _world(monkeypatch)
    reply = _dispatch(broker)
    body = _product_text(reply["execution"])
    assert journal.observe("unit-execution", body) == c.sha(body)
    assert journal._observations[-1] == {"kind": "unit-execution", "sha256": c.sha(body), "size": len(body)}


@pytest.mark.parametrize("change", [{"status": "RUNNING"}, {"name": "outro"}, {"extra": 1}],
                         ids=["status", "nome", "campo-extra"])
def test_passo_unit_execution_diferente_da_execucao_devolvida_recusa(monkeypatch, change):
    broker, journal, _, _ = _world(monkeypatch)
    reply = _dispatch(broker)
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe("unit-execution", _product_text(reply["execution"] | change))
    assert journal._observations == []


def test_passo_unit_execution_com_a_resposta_de_um_poll_intermediario_recusa(monkeypatch):
    broker, journal, table, _ = _world(monkeypatch)
    _dispatch(broker)
    index = _names(table).index("describe_execution")
    first = c.loads(journal.call_bytes[journal.call_receipts[index]["response_sha256"]], canonical=True)
    assert first["status"] == "RUNNING"
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe("unit-execution", _product_text(first))


def test_passo_unit_execution_antes_do_dispatch_recusa(monkeypatch):
    broker, journal, _, plan = _world(monkeypatch)
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe("unit-execution", _product_text({"executionArn": plan.execution, "status": "SUCCEEDED"}))


def test_passo_unit_execution_sem_mode_broker_recusa():
    from test_cnesdata_mode_stages import _start_journal
    journal = _start_journal("unit-start")
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe("unit-execution", c.canonical({"step": "unit-execution"}))


def test_passos_unit_task_e_unit_output_sao_os_elementos_do_slot_na_ordem_do_filho(monkeypatch):
    broker, journal, _, _ = _world(monkeypatch)
    reply = _dispatch(broker)
    for kind, items in (("unit-task", reply["tasks"]), ("unit-output", reply["outputs"])):
        for item in items:
            body = _product_text(item)
            assert journal.observe(kind, body) == c.sha(body)
    assert [entry["kind"] for entry in journal._observations] == ["unit-task"] * 2 + ["unit-output"] * 2


@pytest.mark.parametrize("kind, field", [("unit-task", "tasks"), ("unit-output", "outputs")])
def test_passo_fora_da_ordem_ou_alem_do_slot_recusa(monkeypatch, kind, field):
    broker, journal, _, _ = _world(monkeypatch)
    reply = _dispatch(broker)
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe(kind, _product_text(reply[field][1]))
    for item in reply[field]:
        journal.observe(kind, _product_text(item))
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe(kind, _product_text(reply[field][0]))
    assert [entry["kind"] for entry in journal._observations] == [kind] * 2


@pytest.mark.parametrize("kind", ["unit-task", "unit-output"])
def test_passos_do_unit_start_antes_do_dispatch_recusam(monkeypatch, kind):
    broker, journal, _, _ = _world(monkeypatch)
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe(kind, _product_text({"taskArn": TASK_PREFIX + "0" * 32}))
    assert journal._observations == []


def test_passo_unit_task_sem_tasks_no_slot_recusa(monkeypatch):
    broker, journal, _, _ = _world(monkeypatch, statuses=("RUNNING", "FAILED"))
    _dispatch(broker)
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe("unit-task", _product_text(_projected(TASK_PREFIX + "0" * 32)))
