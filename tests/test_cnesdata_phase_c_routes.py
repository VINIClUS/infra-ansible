"""P17 ruling 1g, binding on P16b: Phase C element routes from the C deploy post-apply readback rows (read_routes)."""
import copy
import json

import pytest

from tools.cnesdata_delivery import lifecycle_contract as lc

PREFIX = "arn:aws:ecs:us-east-2:111122223333:task-definition/cnesdata-prod-processor-"
MACHINE = "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod-processing"
REV = {"unit": PREFIX + "unit:9", "recovery": PREFIX + "recovery:9", "audit": PREFIX + "audit:9"}


def _definition(unit=REV["unit"]):
    return json.dumps({"StartAt": "unit", "States": {"unit": {"Type": "Task", "Parameters": {"TaskDefinition": unit}}}})


def _machine(**changes):
    return {"service": "stepfunctions", "operation": "describe_state_machine",
            "observed": {"stateMachineArn": MACHINE, "definition": _definition(), "status": "ACTIVE"} | changes}


def _schedule(mode, revision=None):
    return {"service": "scheduler", "operation": "get_schedule",
            "observed": {"Name": f"cnesdata-prod-{mode}", "Target": {
                "Arn": "arn:aws:ecs:us-east-2:111122223333:cluster/cnesdata-prod",
                "EcsParameters": {"TaskDefinitionArn": revision or REV[mode], "TaskCount": 1}}}}


def _task(mode, environment=None, containers=1):
    environment = environment if environment is not None else [{"name": "AWS_STATE_MACHINE_ARN", "value": MACHINE}]
    container = {"name": f"processor-{mode}", "environment": environment}
    return {"service": "ecs", "operation": "describe_task_definition",
            "observed": {"taskDefinition": {"taskDefinitionArn": REV[mode], "containerDefinitions": [container] * containers}}}


def _after(mode):
    rows = [{"service": "iam", "operation": "get_role", "observed": {"Role": {"RoleName": "x"}}}, _machine(),
            _schedule("recovery"), _task("unit"), _task("recovery")]
    return rows + ([_schedule("audit")] if mode == "audit" else [])


def _routes(mode, after=None, phase_b=None):
    return lc.phase_c_routes(mode, after=_after(mode) if after is None else after,
                             phase_b=[_machine()] if phase_b is None else phase_b)


def test_rotas_do_phase_c_recovery_vem_das_leituras_pos_apply_com_o_audit_ainda_nulo():
    assert _routes("recovery") == {"unit": REV["unit"], "recovery": REV["recovery"], "audit": None}


def test_rotas_do_phase_c_audit_tem_os_tres_modos_lidos():
    assert _routes("audit") == REV


def test_rota_lida_vale_mesmo_quando_difere_da_revisao_ativada():
    """The projection reports what the deploy job read back; routes_match downstream decides, never a rendered target."""
    drifted = PREFIX + "recovery:8"
    after = [row for row in _after("recovery") if row["operation"] != "get_schedule"] + [_schedule("recovery", drifted)]
    after = [row for row in after if row["operation"] != "describe_task_definition"] + [_task("unit")]
    task = _task("recovery")
    task["observed"]["taskDefinition"]["taskDefinitionArn"] = drifted
    assert _routes("recovery", after + [task])["recovery"] == drifted


def test_schedule_ausente_no_readback_nao_entra_nas_rotas():
    after = _after("recovery") + [{"service": "scheduler", "operation": "get_schedule", "observed": {"absent": True}}]
    assert _routes("recovery", after)["audit"] is None


@pytest.mark.parametrize("case", ["definicao", "arn", "sem-linha-b", "duas-linhas", "sem-linha-apos", "dois-alvos-unit"])
def test_unit_so_e_admitido_quando_a_maquina_lida_e_a_da_phase_b(case):
    after, phase_b = _after("recovery"), [_machine()]
    if case == "definicao":
        after[1] = _machine(definition=_definition(PREFIX + "unit:8"))
    if case == "arn":
        after[1] = _machine(stateMachineArn=MACHINE + "-other")
    if case == "sem-linha-b":
        phase_b = []
    if case == "duas-linhas":
        after.append(_machine())
    if case == "sem-linha-apos":
        del after[1]
    if case == "dois-alvos-unit":
        definition = json.loads(_definition())
        definition["States"]["other"] = {"Type": "Task", "Parameters": {"TaskDefinition": PREFIX + "unit:8"}}
        after[1] = _machine(definition=json.dumps(definition))
        phase_b = [copy.deepcopy(after[1])]
    with pytest.raises(ValueError, match="^phase_c=routes field=machine$"):
        _routes("recovery", after, phase_b)


@pytest.mark.parametrize("rows", [[_schedule("recovery")], [_schedule("recovery", PREFIX + "other:1")]],
                         ids=["duplicado", "fora-da-familia"])
def test_cada_modo_tem_no_maximo_uma_linha_de_schedule_da_propria_familia(rows):
    with pytest.raises(ValueError, match="^phase_c=routes field=scheduler_mode$"):
        _routes("recovery", _after("recovery") + rows)


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_modo_aplicado_sem_schedule_lido_recusa(mode):
    after = [row for row in _after(mode) if not (row["operation"] == "get_schedule"
                                                 and mode in row["observed"]["Target"]["EcsParameters"]["TaskDefinitionArn"])]
    with pytest.raises(ValueError, match="^phase_c=routes field=applied$"):
        _routes(mode, after)


@pytest.mark.parametrize("case", ["sem-task-recovery", "sem-task-unit", "arn-diferente", "sem-variavel", "dois-containers",
                                  "task-duplicada"])
def test_ambiente_das_tasks_unit_e_recovery_carrega_a_maquina_exata(case):
    after = [row for row in _after("recovery") if row["operation"] != "describe_task_definition"]
    tasks = {"unit": _task("unit"), "recovery": _task("recovery")}
    if case == "sem-task-recovery":
        del tasks["recovery"]
    if case == "sem-task-unit":
        del tasks["unit"]
    if case == "arn-diferente":
        tasks["recovery"] = _task("recovery", [{"name": "AWS_STATE_MACHINE_ARN", "value": MACHINE + "-other"}])
    if case == "sem-variavel":
        tasks["unit"] = _task("unit", [])
    if case == "dois-containers":
        tasks["unit"] = _task("unit", containers=2)
    rows = list(tasks.values()) + ([_task("recovery")] if case == "task-duplicada" else [])
    with pytest.raises(ValueError, match="^phase_c=routes field=environment$"):
        _routes("recovery", after + rows)


@pytest.mark.parametrize("mode", ["unit", "final", None])
def test_so_os_estagios_c_tem_rotas_do_elemento(mode):
    with pytest.raises(ValueError, match="^phase_c=routes field=mode$"):
        lc.phase_c_routes(mode, after=_after("audit"), phase_b=[_machine()])


def test_linha_de_readback_fora_da_forma_recusa():
    after = _after("recovery")
    after[2] = {"service": "scheduler", "operation": "get_schedule", "observed": {"Target": {}}}
    with pytest.raises(ValueError, match="^phase_c=routes field=readbacks$"):
        _routes("recovery", after)
