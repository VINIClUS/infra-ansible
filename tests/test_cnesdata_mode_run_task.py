"""P16b design 4.1: run_task equals the product route re-derived from the readbacks; describe_tasks only for the own task."""
import copy
import json

import pytest

from test_cnesdata_mode_readback import RESOURCES, REVISIONS, _responses

PRODUCT_ROUTES = {"recovery": {"locator": "PROD_CANARY_BINDING", "command": ["recover-once"]},
                  "audit": {"locator": "PROD_CANARY_AUDIT_OBSERVE", "command": ["dispatch-outbox-once"]}}
TOKEN = "mc-" + "0123456789abcdef" * 3 + "0123456789ab"
LOCATOR = json.dumps({"owner_sha256": "a" * 64, "phase": "recovery"}, sort_keys=True)
TASK = "arn:aws:ecs:us-east-2:111122223333:task/cnesdata-prod/" + "f" * 32


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _readbacks(mode):
    responses = _responses(mode)
    container = responses[f"task_definitions.{mode}"]["taskDefinition"]["containerDefinitions"][0]
    container["command"] = list(PRODUCT_ROUTES[mode]["command"])
    return json.loads(_mb().mode_readback_bytes(mode, RESOURCES, responses))


def _request(mode, **changes):
    request = {"cluster": RESOURCES["cluster_arn"], "taskDefinition": REVISIONS[mode], "count": 1,
               "enableExecuteCommand": False,
               "networkConfiguration": {"awsvpcConfiguration": {"subnets": ["subnet-b", "subnet-a"],
                                                                "securityGroups": ["sg-1"], "assignPublicIp": "ENABLED"}},
               "overrides": {"containerOverrides": [{"name": f"processor-{mode}", "environment": [
                   {"name": PRODUCT_ROUTES[mode]["locator"], "value": LOCATOR}]}]},
               "clientToken": TOKEN, "launchType": "FARGATE", "platformVersion": "1.4.0"}
    return request | changes


def _validate(mode, request, readbacks=None, record=None, resources=None):
    return _mb().validate_mode_run_task(mode, request, readbacks=readbacks or _readbacks(mode),
                                        record=record or {"revisions": dict(REVISIONS)}, resources=resources or RESOURCES)


def test_rotas_do_run_task_sao_as_constantes_do_produto():
    """Labelled literals of CnesData develop 1d0054c8 scripts/promotion/mode_canary.py (sha256 a73aaadb...): _COMMANDS
    and _LOCATOR_KEYS (:31-32), _TOKEN_LIMIT (:36) and client_token, "mc-" plus 60 hex (:150-154)."""
    assert _mb().MODE_RUN_TASK_ROUTES == PRODUCT_ROUTES


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_run_task_igual_a_rota_do_produto_e_admitido(mode):
    assert _validate(mode, _request(mode)) is None


def test_launch_type_e_platform_version_so_entram_quando_presentes_no_readback():
    readbacks = _readbacks("recovery")
    del readbacks["schedules"]["recovery"]["Target"]["EcsParameters"]["LaunchType"]
    del readbacks["schedules"]["recovery"]["Target"]["EcsParameters"]["PlatformVersion"]
    request = _request("recovery")
    with pytest.raises(ValueError, match="^mode run_task route$"):
        _validate("recovery", request, readbacks)
    del request["launchType"], request["platformVersion"]
    assert _validate("recovery", request, readbacks) is None
    with pytest.raises(ValueError, match="^mode run_task route$"):
        _validate("recovery", _request("recovery", launchType="EC2"))


def _container(**changes):
    return {"containerOverrides": [{"name": "processor-recovery", "environment": [
        {"name": "PROD_CANARY_BINDING", "value": LOCATOR}]} | changes]}


@pytest.mark.parametrize("changes", [
    {"cluster": "arn:aws:ecs:us-east-2:111122223333:cluster/other"},
    {"taskDefinition": REVISIONS["audit"]},
    {"count": 2}, {"count": True}, {"enableExecuteCommand": True}, {"enableExecuteCommand": 0},
    {"networkConfiguration": {"awsvpcConfiguration": {"subnets": ["subnet-a", "subnet-b"], "securityGroups": ["sg-1"],
                                                      "assignPublicIp": "ENABLED"}}},
    {"networkConfiguration": {"awsvpcConfiguration": {"subnets": ["subnet-b", "subnet-a"], "securityGroups": ["sg-1"],
                                                      "assignPublicIp": "DISABLED"}}},
    {"overrides": _container(command=["sh"])}, {"overrides": _container(name="processor-audit")},
    {"overrides": _container(environment=[{"name": "PROD_CANARY_AUDIT_OBSERVE", "value": LOCATOR}])},
    {"overrides": _container(environment=[{"name": "PROD_CANARY_BINDING", "value": LOCATOR},
                                          {"name": "EXTRA", "value": "1"}])},
    {"overrides": _container(environment=[{"name": "PROD_CANARY_BINDING", "value": ""}])},
    {"overrides": _container(environment=[{"name": "PROD_CANARY_BINDING", "value": "x" * 4097}])},
    {"overrides": _container(environment=[{"name": "PROD_CANARY_BINDING", "value": 7}])},
    {"overrides": {"containerOverrides": [_container()["containerOverrides"][0]] * 2}},
    {"overrides": _container() | {"taskRoleArn": "arn:aws:iam::111122223333:role/other"}},
    {"clientToken": TOKEN[:-1]}, {"clientToken": TOKEN + "0"}, {"clientToken": TOKEN.upper()},
    {"clientToken": "xx" + TOKEN[2:]}, {"clientToken": None},
    {"startedBy": "x"}, {"propagateTags": "TASK_DEFINITION"}, {"tags": []}, {"placementConstraints": []}],
    ids=lambda changes: next(iter(changes)))
def test_run_task_fora_da_rota_rederivada_recusa(changes):
    with pytest.raises(ValueError, match="^mode run_task route$"):
        _validate("recovery", _request("recovery", **changes))


def test_run_task_sem_overrides_recusa():
    request = _request("recovery")
    del request["overrides"]
    with pytest.raises(ValueError, match="^mode run_task route$"):
        _validate("recovery", request)


def _drop_command(definition):
    del definition["containerDefinitions"][0]["command"]


def _two_containers(definition):
    definition["containerDefinitions"].append(copy.deepcopy(definition["containerDefinitions"][0]))


@pytest.mark.parametrize("case", ["revisao-do-schedule", "task-count", "retries", "cluster", "comando", "sem-comando",
                                  "dois-containers", "revisao-da-task", "rede-sem-ip-publico", "record-diverge",
                                  "unit", "sem-schedule"])
def test_rota_recusa_readbacks_fora_do_alvo_do_produto(case):
    mode, readbacks, record, resources = "recovery", _readbacks("recovery"), {"revisions": dict(REVISIONS)}, RESOURCES
    target = readbacks["schedules"]["recovery"]["Target"]
    definition = readbacks["task_definitions"]["recovery"]["taskDefinition"]
    if case == "revisao-do-schedule":
        target["EcsParameters"]["TaskDefinitionArn"] = REVISIONS["audit"]
    if case == "task-count":
        target["EcsParameters"]["TaskCount"] = 2
    if case == "retries":
        target["RetryPolicy"]["MaximumRetryAttempts"] = 1
    if case == "cluster":
        target["Arn"] = "arn:aws:ecs:us-east-2:111122223333:cluster/other"
    if case == "comando":
        definition["containerDefinitions"][0]["command"] = ["dispatch-outbox-once"]
    if case == "sem-comando":
        _drop_command(definition)
    if case == "dois-containers":
        _two_containers(definition)
    if case == "revisao-da-task":
        definition["taskDefinitionArn"] = REVISIONS["audit"]
    if case == "rede-sem-ip-publico":
        del target["EcsParameters"]["NetworkConfiguration"]["awsvpcConfiguration"]["AssignPublicIp"]
    if case == "record-diverge":
        record = {"revisions": dict(REVISIONS) | {"recovery": REVISIONS["audit"]}}
    if case == "unit":
        mode = "unit"
    if case == "sem-schedule":
        del readbacks["schedules"]
    with pytest.raises(ValueError, match="^mode run_task readbacks$"):
        _validate(mode, _request("recovery"), readbacks, record, resources)


def test_task_count_ausente_no_readback_vale_um():
    readbacks = _readbacks("audit")
    del readbacks["schedules"]["audit"]["Target"]["EcsParameters"]["TaskCount"]
    assert _validate("audit", _request("audit"), readbacks) is None


def test_describe_tasks_admite_so_a_propria_tarefa_devolvida_pelo_run_task():
    assert _mb().validate_mode_describe_tasks({"cluster": RESOURCES["cluster_arn"], "tasks": [TASK]},
                                              cluster_arn=RESOURCES["cluster_arn"], launched=[TASK]) is None


@pytest.mark.parametrize("parameters, launched", [
    ({"cluster": RESOURCES["cluster_arn"], "tasks": [TASK]}, []),
    ({"cluster": RESOURCES["cluster_arn"], "tasks": [TASK[:-1] + "e"]}, [TASK]),
    ({"cluster": RESOURCES["cluster_arn"], "tasks": [TASK, TASK]}, [TASK]),
    ({"cluster": RESOURCES["cluster_arn"], "tasks": []}, [TASK]),
    ({"cluster": "arn:aws:ecs:us-east-2:111122223333:cluster/other", "tasks": [TASK]}, [TASK]),
    ({"cluster": RESOURCES["cluster_arn"], "tasks": [TASK], "include": ["TAGS"]}, [TASK]),
    ({"tasks": [TASK]}, [TASK]), ([TASK], [TASK])],
    ids=["antes-do-run-task", "outra-tarefa", "duas", "nenhuma", "outro-cluster", "include", "sem-cluster", "lista"])
def test_describe_tasks_fora_da_propria_tarefa_recusa(parameters, launched):
    with pytest.raises(ValueError, match="^mode describe_tasks own task$"):
        _mb().validate_mode_describe_tasks(parameters, cluster_arn=RESOURCES["cluster_arn"], launched=launched)
