"""P16b design 4.4 (ruling 1 item 4): the closed ModeReadback key set, its read calls and its stable projection."""
import copy
import json

import pytest

from tools.cnesdata_delivery import contract as c

ACCOUNT = "111122223333"
REGION = "us-east-2"
REVISIONS = {mode: f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/cnesdata-prod-processor-{mode}:7"
             for mode in ("unit", "recovery", "audit")}
RESOURCES = {
    "machine_arn": f"arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:cnesdata-prod-processing",
    "cluster_arn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/cnesdata-prod",
    "revisions": REVISIONS,
    "schedule_arns": {mode: f"arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule/cnesdata-prod/cnesdata-prod-{mode}"
                      for mode in ("recovery", "audit")},
    "alarm_arns": {name: f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:cnesdata-prod-scheduler-{name.replace('_', '-')}"
                   for name in ("audit_outbox_backlog", "audit_repeated_failure", "recovery_repeated_failure")},
}
KEYS = {"unit": ("state_machine", "task_definitions.unit"),
        "recovery": ("state_machine", "schedules.recovery", "task_definitions.recovery", "alarms.recovery"),
        "audit": ("state_machine", "schedules.audit", "task_definitions.audit", "alarms.audit")}
MODES = tuple(KEYS)


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _machine():
    return {"stateMachineArn": RESOURCES["machine_arn"], "definition": json.dumps({"StartAt": "unit"}),
            "name": "cnesdata-prod-processing", "status": "ACTIVE", "creationDate": "2026-11-01T00:00:00Z",
            "revisionId": "r-1", "roleArn": f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-machine"}


def _schedule(mode, **ecs):
    parameters = {"TaskDefinitionArn": REVISIONS[mode], "TaskCount": 1, "LaunchType": "FARGATE", "PlatformVersion": "1.4.0",
                  "NetworkConfiguration": {"awsvpcConfiguration": {"Subnets": ["subnet-b", "subnet-a"],
                                                                   "SecurityGroups": ["sg-1"], "AssignPublicIp": "ENABLED"}},
                  "EnableExecuteCommand": False, "Tags": []} | ecs
    return {"Arn": RESOURCES["schedule_arns"][mode], "Name": f"cnesdata-prod-{mode}", "GroupName": "cnesdata-prod",
            "State": "ENABLED", "CreationDate": "2026-11-01T00:00:00Z", "LastModificationDate": "2026-11-02T00:00:00Z",
            "Target": {"Arn": RESOURCES["cluster_arn"], "RoleArn": f"arn:aws:iam::{ACCOUNT}:role/scheduler",
                       "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 900},
                       "EcsParameters": parameters, "Input": "{}"}}


def _task_definition(mode, command=True):
    container = {"name": f"processor-{mode}", "image": "registry/processor@sha256:" + "a" * 64, "cpu": 256,
                 "environment": [{"name": "X", "value": "1"}]}
    if command:
        container["command"] = ["python", "-m", f"processor.{mode}"]
    return {"taskDefinition": {"taskDefinitionArn": REVISIONS[mode], "family": f"cnesdata-prod-processor-{mode}",
                               "taskRoleArn": f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-processor-{mode}",
                               "revision": 7, "registeredAt": "2026-11-01T00:00:00Z", "status": "ACTIVE",
                               "containerDefinitions": [container]},
            "tags": [{"key": "k", "value": "v"}]}


def _alarm(mode, **changes):
    name = f"cnesdata-prod-scheduler-{mode}-repeated-failure"
    alarm = {"AlarmName": name, "AlarmArn": RESOURCES["alarm_arns"][f"{mode}_repeated_failure"],
             "Dimensions": [{"Name": "RuleName", "Value": f"cnesdata-prod-scheduler-{mode}-failed"}],
             "EvaluationPeriods": 2, "DatapointsToAlarm": 2, "ActionsEnabled": True,
             "AlarmActions": [f"arn:aws:sns:{REGION}:{ACCOUNT}:cnesdata-prod-alerts"], "StateValue": "OK",
             "StateReason": "fine", "StateUpdatedTimestamp": "2026-11-02T00:00:00Z", "Threshold": 1} | changes
    return {"MetricAlarms": [alarm], "CompositeAlarms": []}


def _responses(mode):
    responses = {"state_machine": _machine(), f"task_definitions.{mode}": _task_definition(mode)}
    if mode != "unit":
        responses |= {f"schedules.{mode}": _schedule(mode), f"alarms.{mode}": _alarm(mode)}
    return responses


def _expected(mode):
    document = {"state_machine": {"stateMachineArn": RESOURCES["machine_arn"], "definition": json.dumps({"StartAt": "unit"})},
                "task_definitions": {mode: {"taskDefinition": {
                    "taskDefinitionArn": REVISIONS[mode],
                    "taskRoleArn": f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-processor-{mode}",
                    "containerDefinitions": [{"name": f"processor-{mode}", "command": ["python", "-m", f"processor.{mode}"]}]}}}}
    if mode != "unit":
        document["schedules"] = {mode: {"Target": {
            "Arn": RESOURCES["cluster_arn"], "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 900},
            "EcsParameters": {"TaskDefinitionArn": REVISIONS[mode], "TaskCount": 1, "LaunchType": "FARGATE",
                              "PlatformVersion": "1.4.0", "NetworkConfiguration": {"awsvpcConfiguration": {
                                  "Subnets": ["subnet-b", "subnet-a"], "SecurityGroups": ["sg-1"], "AssignPublicIp": "ENABLED"}}}}}}
        document["alarms"] = {mode: {
            "AlarmName": f"cnesdata-prod-scheduler-{mode}-repeated-failure",
            "Dimensions": [{"Name": "RuleName", "Value": f"cnesdata-prod-scheduler-{mode}-failed"}],
            "EvaluationPeriods": 2, "DatapointsToAlarm": 2, "ActionsEnabled": True,
            "AlarmActions": [f"arn:aws:sns:{REGION}:{ACCOUNT}:cnesdata-prod-alerts"]}}
    return document


def test_conjunto_de_chaves_por_modo_e_fechado_e_independe_do_historico_do_lease():
    assert _mb().MODE_READBACK_KEYS == KEYS


def test_leituras_do_unit_sao_a_maquina_e_a_revisao_unit_do_mode_input():
    assert _mb().mode_readback_calls("unit", RESOURCES) == [
        {"key": "state_machine", "service": "stepfunctions", "operation": "describe_state_machine",
         "parameters": {"stateMachineArn": RESOURCES["machine_arn"]}},
        {"key": "task_definitions.unit", "service": "ecs", "operation": "describe_task_definition",
         "parameters": {"taskDefinition": REVISIONS["unit"]}}]


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_leituras_agendadas_sao_maquina_schedule_revisao_e_alarme_de_falha_repetida_do_modo(mode):
    assert _mb().mode_readback_calls(mode, RESOURCES) == [
        {"key": "state_machine", "service": "stepfunctions", "operation": "describe_state_machine",
         "parameters": {"stateMachineArn": RESOURCES["machine_arn"]}},
        {"key": f"schedules.{mode}", "service": "scheduler", "operation": "get_schedule",
         "parameters": {"Name": f"cnesdata-prod-{mode}", "GroupName": "cnesdata-prod"}},
        {"key": f"task_definitions.{mode}", "service": "ecs", "operation": "describe_task_definition",
         "parameters": {"taskDefinition": REVISIONS[mode]}},
        {"key": f"alarms.{mode}", "service": "cloudwatch", "operation": "describe_alarms",
         "parameters": {"AlarmNames": [f"cnesdata-prod-scheduler-{mode}-repeated-failure"]}}]


@pytest.mark.parametrize("mode, field, value", [
    ("unit", "machine_arn", "arn:aws:states:us-east-2:111122223333:execution:cnesdata-prod-processing:x"),
    ("recovery", "schedule_arns", {"recovery": "arn:aws:scheduler:us-east-2:111122223333:schedule/only-name",
                                   "audit": RESOURCES["schedule_arns"]["audit"]}),
    ("audit", "alarm_arns", RESOURCES["alarm_arns"] | {
        "audit_repeated_failure": "arn:aws:cloudwatch:us-east-2:111122223333:metric:x"}),
    ("unit", "revisions", REVISIONS | {"unit": "arn:aws:ecs:us-east-2:111122223333:cluster/cnesdata-prod"}),
    ("audit", "revisions", REVISIONS | {"audit": REVISIONS["audit"] + "\n"})])
def test_alvo_fora_da_forma_do_recurso_recusa_antes_de_qualquer_leitura(mode, field, value):
    with pytest.raises(ValueError, match="^mode readback target$"):
        _mb().mode_readback_calls(mode, RESOURCES | {field: value})


@pytest.mark.parametrize("mode", MODES)
def test_projecao_guarda_so_os_campos_que_o_produto_le_em_bytes_canonicos(mode):
    raw = _mb().mode_readback_bytes(mode, RESOURCES, _responses(mode))
    assert raw == (json.dumps(_expected(mode), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    assert c.loads(raw, canonical=True) == _expected(mode)


@pytest.mark.parametrize("mode", MODES)
def test_campos_volateis_nao_mudam_a_projecao_entao_antes_e_depois_coincidem(mode):
    before = _mb().mode_readback_bytes(mode, RESOURCES, _responses(mode))
    changed = copy.deepcopy(_responses(mode))
    changed["state_machine"].update(creationDate="2026-11-20T00:00:00Z", revisionId="r-9", status="UPDATING")
    changed[f"task_definitions.{mode}"]["taskDefinition"].update(registeredAt="2026-11-20T00:00:00Z", revision=8)
    if mode != "unit":
        changed[f"schedules.{mode}"].update(State="DISABLED", LastModificationDate="2026-11-20T00:00:00Z")
        changed[f"alarms.{mode}"]["MetricAlarms"][0].update(StateValue="ALARM", StateUpdatedTimestamp="2026-11-21T00:00:00Z")
    assert _mb().mode_readback_bytes(mode, RESOURCES, changed) == before


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_ausencia_de_task_count_launch_type_platform_version_e_command_e_preservada(mode):
    responses = _responses(mode)
    for key in ("TaskCount", "LaunchType", "PlatformVersion"):
        del responses[f"schedules.{mode}"]["Target"]["EcsParameters"][key]
    responses[f"task_definitions.{mode}"] = _task_definition(mode, command=False)
    document = c.loads(_mb().mode_readback_bytes(mode, RESOURCES, responses), canonical=True)
    assert set(document["schedules"][mode]["Target"]["EcsParameters"]) == {"TaskDefinitionArn", "NetworkConfiguration"}
    assert document["task_definitions"][mode]["taskDefinition"]["containerDefinitions"] == [{"name": f"processor-{mode}"}]


@pytest.mark.parametrize("mode, key, path, value", [
    ("recovery", "alarms.recovery", ("MetricAlarms", 0, "EvaluationPeriods"), 2.0),
    ("audit", "schedules.audit", ("Target", "EcsParameters", "TaskCount"), 1.5),
    ("audit", "schedules.audit", ("Target", "RetryPolicy", "MaximumEventAgeInSeconds"), 900.0)])
def test_numero_nao_inteiro_na_projecao_recusa(mode, key, path, value):
    responses = _responses(mode)
    node = responses[key]
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    with pytest.raises(ValueError, match="^mode readback non-integer$"):
        _mb().mode_readback_bytes(mode, RESOURCES, responses)


def test_numero_nao_inteiro_fora_da_projecao_nao_entra_nem_recusa():
    responses = _responses("recovery")
    responses["alarms.recovery"]["MetricAlarms"][0]["Threshold"] = 1.5
    assert _mb().mode_readback_bytes("recovery", RESOURCES, responses) == _mb().mode_readback_bytes("recovery", RESOURCES, _responses("recovery"))


@pytest.mark.parametrize("mode", MODES)
def test_respostas_fora_do_conjunto_de_chaves_do_modo_recusam(mode):
    responses = _responses(mode)
    for broken in ({key: value for key, value in responses.items() if key != "state_machine"},
                   responses | {"alarms.unit": _alarm("recovery")}):
        with pytest.raises(ValueError, match="^mode readback key set$"):
            _mb().mode_readback_bytes(mode, RESOURCES, broken)


@pytest.mark.parametrize("change", [
    lambda r: r["state_machine"].pop("definition"),
    lambda r: r["state_machine"].update(definition={"StartAt": "unit"}),
    lambda r: r["schedules.recovery"].pop("Target"),
    lambda r: r["schedules.recovery"]["Target"].pop("EcsParameters"),
    lambda r: r["schedules.recovery"]["Target"]["EcsParameters"].pop("TaskDefinitionArn"),
    lambda r: r["task_definitions.recovery"].pop("taskDefinition"),
    lambda r: r["task_definitions.recovery"]["taskDefinition"].update(containerDefinitions={}),
    lambda r: r["alarms.recovery"].update(MetricAlarms=[]),
    lambda r: r["alarms.recovery"].update(MetricAlarms=_alarm("recovery")["MetricAlarms"] * 2),
    lambda r: r["alarms.recovery"].update(MetricAlarms=_alarm("audit")["MetricAlarms"])])
def test_resposta_sem_a_estrutura_que_o_produto_le_recusa(change):
    responses = _responses("recovery")
    change(responses)
    with pytest.raises(ValueError, match="^mode readback shape$"):
        _mb().mode_readback_bytes("recovery", RESOURCES, responses)
