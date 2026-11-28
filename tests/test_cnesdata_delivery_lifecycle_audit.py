"""Audit independente do lifecycle: produtor do approval.json e specs de readback sem parametros."""
import copy

import pytest

from fixtures.cnesdata_phase_a_replay import ReplayChain
from test_cnesdata_delivery_lifecycle import ReadbackAWS, ReadbackGuard, change
from tools.cnesdata_delivery import contract as c, drift_catalog, drift_handoff, lifecycle_contract as lc
from tools.cnesdata_delivery import lifecycle_runtime as lr

ROLE = "module.runtime_iam.aws_iam_role.fence[0]"
SCHEDULE = 'module.schedulers.aws_scheduler_schedule.mode["audit"]'
GROUP = 'module.schedulers.aws_scheduler_schedule_group.mode["audit"]'
MACHINE_ARN = "arn:aws:states:sa-east-1:111122223333:stateMachine:cnesdata-prod-processor"
STATE_MACHINE = lc.STATE_MACHINE
SOURCE = "a" * 40
APPROVAL_KEYS = "version owner purpose direction plan_sha256 inputs_sha256 checkpoint_sha256 delta drift_matrix readbacks"
ROLE_ATTRIBUTES = {"name": "cnesdata-prod-fence", "arn": "arn:aws:iam::111122223333:role/cnesdata-prod-fence"}
SCHEDULE_ATTRIBUTES = {"name": "cnesdata-prod-audit", "group_name": "cnesdata-prod-audit"}
OWNER = {"owner_sha256": "b" * 64, "generation": 3, "source_sha": SOURCE}


def spec(address=ROLE, service="iam", operation="get_role", **extra):
    return {"service": service, "operation": operation, "address": address, "absent": False} | extra


def plan_of(*rows):
    return {"resource_changes": list(rows)}


def role_plan():
    return plan_of(change(ROLE, ROLE_ATTRIBUTES, ROLE_ATTRIBUTES, ["update"]))


def schedule_plan():
    return plan_of(change(SCHEDULE, SCHEDULE_ATTRIBUTES, SCHEDULE_ATTRIBUTES, ["update"]))


def group_plan():
    group = {"name": "cnesdata-prod-audit"}
    return plan_of(change(GROUP, group, group, ["no-op"]))


def test_recusa_spec_de_approval_com_parameters():
    with pytest.raises(ValueError, match="closed object fields"):
        lr.readback_calls(role_plan(), [spec(parameters={"RoleName": "cnesdata-prod-fence"})], "before")


def test_deriva_parametros_dos_atributos_de_identidade_sem_parameters_na_spec():
    calls = lr.readback_calls(role_plan(), [spec()], "before")
    assert calls == [spec() | {"parameters": {"RoleName": "cnesdata-prod-fence"}}]


def test_spec_do_approval_exige_absent_booleano():
    for broken in ({"service": "iam", "operation": "get_role", "address": ROLE},
                   spec() | {"absent": "false"}):
        with pytest.raises(ValueError, match="closed object fields|readback spec"):
            lr.readback_calls(role_plan(), [broken], "before")


def test_aceita_spec_agrupada_list_schedules_com_members_sem_parameters():
    grouped = spec(GROUP, "scheduler", "list_schedules", members=["cnesdata-prod-audit"])
    calls = lr.readback_calls(group_plan(), [grouped], "before")
    assert calls == [grouped | {"parameters": {"GroupName": "cnesdata-prod-audit"}}]
    page = {"Schedules": [{"Name": "cnesdata-prod-audit", "GroupName": "cnesdata-prod-audit"}]}
    reports = lr.readbacks(ReadbackAWS([page]), calls, ReadbackGuard())
    assert reports[0]["observed"] == page


def test_recusa_spec_agrupada_sem_members_e_members_fora_do_agrupado():
    with pytest.raises(ValueError, match="closed object fields"):
        lr.readback_calls(schedule_plan(), [spec(SCHEDULE, "scheduler", "list_schedules")], "before")
    with pytest.raises(ValueError, match="closed object fields"):
        lr.readback_calls(role_plan(), [spec(members=["x"])], "before")


def test_recusa_spec_agrupada_com_parameters():
    grouped = spec(SCHEDULE, "scheduler", "list_schedules", members=[], parameters={"GroupName": "g"})
    with pytest.raises(ValueError, match="closed object fields"):
        lr.readback_calls(schedule_plan(), [grouped], "before")


def test_recusa_endereco_fora_do_plano_e_estagio_desconhecido():
    with pytest.raises(ValueError, match="readback address"):
        lr.readback_calls(role_plan(), [spec("module.x.aws_iam_role.other")], "before")
    with pytest.raises(ValueError, match="readback specs"):
        lr.readback_calls(role_plan(), [spec()], "during")


def test_spec_absent_so_vale_para_endereco_deletado_no_estagio_after():
    deleted = plan_of(change(ROLE, ROLE_ATTRIBUTES, None, ["delete"]))
    calls = lr.readback_calls(deleted, [spec(absent=True)], "after")
    assert calls[0]["parameters"] == {"RoleName": "cnesdata-prod-fence"} and calls[0]["absent"] is True
    with pytest.raises(ValueError, match="absent readback"):
        lr.readback_calls(deleted, [spec(absent=True)], "before")
    with pytest.raises(ValueError, match="absence identity"):
        lr.readback_calls(role_plan(), [spec(absent=True)], "after")


def test_resolvedor_unico_deriva_tipo_do_lifecycle_pela_identidade_do_lifecycle():
    machine = {"arn": MACHINE_ARN, "definition": "{}"}
    plan = plan_of(change(STATE_MACHINE, machine, machine | {"definition": '{"a":1}'}, ["update"]))
    machine_spec = spec(STATE_MACHINE, "stepfunctions", "describe_state_machine")
    calls = lr.readback_calls(plan, [machine_spec], "before")
    assert calls[0]["parameters"] == {"stateMachineArn": MACHINE_ARN}


def test_absent_de_tipo_do_lifecycle_segue_a_regra_de_ausencia_do_catalogo():
    plan = plan_of(change(STATE_MACHINE, {"arn": MACHINE_ARN}, None, ["delete"]))
    absent = spec(STATE_MACHINE, "stepfunctions", "describe_state_machine", absent=True)
    [call] = lr.readback_calls(plan, [absent], "after")
    assert call["parameters"] == {"stateMachineArn": MACHINE_ARN}


def test_spec_agrupada_exige_endereco_do_grupo_e_nao_do_schedule():
    grouped = spec(SCHEDULE, "scheduler", "list_schedules", members=["cnesdata-prod-audit"])
    with pytest.raises(ValueError, match="^readback catalog operation$"):
        lr.readback_calls(schedule_plan(), [grouped], "before")


@pytest.mark.parametrize("operation", ["delete_role", "update_role"])
def test_approval_recusa_spec_com_operacao_que_nao_e_leitura(operation):
    with pytest.raises(ValueError, match="^read-only API boundary$"):
        lr.readback_calls(role_plan(), [spec(operation=operation)], "before")


def test_approval_recusa_leitura_que_nao_e_a_operacao_do_catalogo_para_o_tipo_do_endereco():
    machine = {"arn": MACHINE_ARN, "definition": "{}"}
    plan = plan_of(change(STATE_MACHINE, machine, machine | {"definition": '{"a":1}'}, ["update"]))
    with pytest.raises(ValueError, match="^readback catalog operation$"):
        lr.readback_calls(plan, [spec(STATE_MACHINE, "iam", "get_role")], "before")


def machine_plan(arn=True):
    before = {"definition": '{"TaskDefinition":"unit:1"}', "role_arn": "role"} | ({"arn": MACHINE_ARN} if arn else {})
    return plan_of(change(STATE_MACHINE, before, before | {"definition": '{"TaskDefinition":"unit:2"}'}, ["update"]))


def stage_rules():
    return {"before": [], "after": []}, {"matrix_version": 2, "source_sha": SOURCE, "purpose": "phase-b",
                                         "before": [], "after": [], "absent": []}


def sfn_stage(stage, service, operation):
    readbacks, matrix = stage_rules()
    readbacks[stage] = [spec(STATE_MACHINE, service, operation)]
    matrix[stage] = [{"address": STATE_MACHINE, "attribute": "definition", "readback": 0, "path": ["definition"],
                      "encoding": "json"}]
    lr._approval_stage(machine_plan(), readbacks[stage], matrix, stage)


@pytest.mark.parametrize("stage", ["before", "after"])
def test_build_approval_deriva_a_leitura_do_catalogo_da_state_machine(stage):
    approval = lr.build_approval(**b_case())
    assert approval["readbacks"][stage] == [spec(STATE_MACHINE, "stepfunctions", "describe_state_machine")]
    sfn_stage(stage, "stepfunctions", "describe_state_machine")


@pytest.mark.parametrize("stage", ["before", "after"])
def test_approval_recusa_spec_mutante_da_state_machine(stage):
    with pytest.raises(ValueError, match="^read-only API boundary$"):
        sfn_stage(stage, "stepfunctions", "delete_state_machine")


@pytest.mark.parametrize("stage", ["before", "after"])
def test_approval_recusa_leitura_de_outro_tipo_no_endereco_da_state_machine(stage):
    with pytest.raises(ValueError, match="^readback catalog operation$"):
        sfn_stage(stage, "iam", "get_role")


def sfn_state(before):
    return c.canonical({"version": 4, "serial": 1, "resources": [
        {"mode": "managed", "module": "module.processing", "type": "aws_sfn_state_machine", "name": "processor",
         "instances": [{"index_key": 0, "attributes": before}]}]})


def b_case(**override):
    plan = machine_plan()
    before = plan["resource_changes"][0]["change"]["before"]
    payload = {"plan.bin": b"binary-plan", "plan.json": c.canonical(plan), "inputs.json": b'{"x":1}\n',
               "checkpoint.json": b'{"c":1}\n'}
    governance = {"source_sha": SOURCE} | override
    step = {"purpose": "phase-b", "direction": "advance", "mode": "established"}
    return {"governance": governance, "step": step, "owner": OWNER, "payload": payload,
            "before_raw": sfn_state(before)}


def test_audit_produz_approval_com_hashes_exatos_e_delta_do_estado_real():
    case = b_case()
    approval = lr.build_approval(**case)
    payload, plan = case["payload"], c.loads(case["payload"]["plan.json"], state=True)
    c.closed(approval, APPROVAL_KEYS)
    assert approval["version"] == 1 and approval["owner"] == OWNER
    assert (approval["purpose"], approval["direction"]) == ("phase-b", "advance")
    assert approval["plan_sha256"] == c.sha(payload["plan.bin"])
    assert approval["inputs_sha256"] == c.sha(payload["inputs.json"])
    assert approval["checkpoint_sha256"] == c.sha(payload["checkpoint.json"])
    assert approval["delta"]["before"] == lc.state_resources(c.loads(case["before_raw"], state=True))
    assert (approval["delta"]["original"], approval["delta"]["created"]) == ({}, {})
    lc.validate_delta(plan, approval["delta"])
    derived = drift_handoff.lifecycle(plan, c.loads(case["before_raw"], state=True), SOURCE, "phase-b")
    assert (approval["drift_matrix"], approval["readbacks"]) == derived
    assert c.loads(c.canonical(approval), canonical=True) == approval


def test_audit_calcula_expected_changes_com_o_mesmo_filtro_do_validate_delta():
    case = b_case()
    plan = c.loads(case["payload"]["plan.json"], state=True)
    plan["resource_changes"].append(change("module.x.aws_cloudwatch_log_group.noop", {"a": 1}, {"a": 1}, ["no-op"]))
    case["payload"]["plan.json"] = c.canonical(plan)
    delta = lr.build_approval(**case)["delta"]
    managed = [row for row in plan["resource_changes"] if row["change"]["actions"] != ["no-op"]]
    assert delta["expected_changes_sha256"] == c.sha(c.canonical(managed))


def test_audit_recusa_plano_que_o_validate_delta_recusa():
    case = b_case()
    plan = c.loads(case["payload"]["plan.json"], state=True)
    plan["resource_changes"][0]["change"]["after"]["role_arn"] = "other-role"
    case["payload"]["plan.json"] = c.canonical(plan)
    with pytest.raises(ValueError, match="invariant"):
        lr.build_approval(**case)


def test_audit_recusa_estado_real_diferente_do_before_do_plano():
    case = b_case()
    case["before_raw"] = sfn_state({"definition": "other", "role_arn": "role"})
    with pytest.raises(ValueError, match="actual checkpoint resource"):
        lr.build_approval(**case)


def test_audit_recusa_direcao_converge_sem_custodia_de_original_e_created():
    case = b_case()
    case["step"] = case["step"] | {"direction": "converge"}
    with pytest.raises(ValueError, match="audit converge custody unavailable"):
        lr.build_approval(**case)


def derived_with(monkeypatch, mutate):
    derive = drift_handoff.lifecycle

    def mutated(*args):
        matrix, readbacks = derive(*args)
        mutate(matrix)
        return matrix, readbacks
    monkeypatch.setattr(lr.drift_handoff, "lifecycle", mutated)


@pytest.mark.parametrize("field,value", [("source_sha", "c" * 40), ("purpose", "phase-c-audit")])
def test_audit_recusa_matriz_derivada_de_outra_fonte_ou_proposito(monkeypatch, field, value):
    derived_with(monkeypatch, lambda matrix: matrix.update({field: value}))
    with pytest.raises(ValueError, match="governed drift matrix identity"):
        lr.build_approval(**b_case())


def test_audit_recusa_matriz_derivada_sem_envelope_versao_1_ou_sem_lista_absent(monkeypatch):
    derived_with(monkeypatch, lambda matrix: matrix.update({"matrix_version": 1}))
    with pytest.raises(ValueError, match="governed drift matrix identity"):
        lr.build_approval(**b_case())
    derived_with(monkeypatch, lambda matrix: matrix.pop("absent"))
    with pytest.raises(ValueError, match="closed object fields"):
        lr.build_approval(**b_case())


MACHINE_SPEC = spec(STATE_MACHINE, "stepfunctions", "describe_state_machine")


@pytest.mark.parametrize("mutation,message", [
    ("spec-absent-sem-delete", "absence identity"),
    ("linha-absent-sem-delete", "absent drift"),
    ("linha-absent-aberta", "closed object fields")])
def test_audit_liga_absent_da_matriz_v2_aos_deletes_do_plano(mutation, message):
    _, matrix = stage_rules()
    absent = mutation == "spec-absent-sem-delete"
    matrix["after"] = [{"address": STATE_MACHINE, "readback": 0}]
    if not absent:
        matrix["absent"] = [{"address": STATE_MACHINE, "readback": 0}]
    if mutation == "linha-absent-aberta":
        matrix["absent"][0]["path"] = []
    with pytest.raises(ValueError, match=message):
        lr._approval_stage(machine_plan(arn=False), [MACHINE_SPEC | {"absent": absent}], matrix, "after")


def test_audit_aceita_inventario_agrupado_sem_linha_da_matriz():
    plan = machine_plan(arn=False)
    plan["resource_changes"].append(change(GROUP, {"name": "cnesdata-prod-audit"},
                                           {"name": "cnesdata-prod-audit"}, ["no-op"]))
    grouped = spec(GROUP, "scheduler", "list_schedules", members=["cnesdata-prod-audit"])
    lr._approval_stage(plan, [grouped], stage_rules()[1], "before")


def test_audit_recusa_readbacks_com_parameters_no_approval():
    with pytest.raises(ValueError, match="closed object fields"):
        lr._approval_stage(machine_plan(arn=False), [spec(parameters={"RoleName": "x"})], stage_rules()[1], "before")


def test_audit_recusa_linha_da_matriz_que_aponta_para_endereco_alheio():
    _, matrix = stage_rules()
    matrix["after"] = [{"address": "module.x.other", "readback": 0}]
    with pytest.raises(ValueError, match="readback address binding"):
        lr._approval_stage(machine_plan(arn=False), [spec(STATE_MACHINE, "stepfunctions", "describe_state_machine")],
                           matrix, "after")


def test_audit_aceita_c_inicial_que_cria_o_schedule_do_modo():
    address = 'module.schedulers.aws_scheduler_schedule.mode["recovery"]'
    after = {"name": "cnesdata-prod-recovery", "group_name": "cnesdata-prod-recovery"}
    case = b_case()
    plan = plan_of(change(address, None, after, ["create"]))
    case["payload"]["plan.json"] = c.canonical(plan)
    case["step"] = {"purpose": "phase-c-recovery", "direction": "advance", "mode": "initial"}
    case["before_raw"] = c.canonical({"version": 4, "serial": 1, "resources": []})
    approval = lr.build_approval(**case)
    assert approval["delta"]["before"] == {} and approval["purpose"] == "phase-c-recovery"
    lc.validate_delta(plan, approval["delta"])


def test_main_aceita_o_papel_audit_e_recusa_papel_desconhecido(monkeypatch):
    seen = []
    monkeypatch.setattr(lr, "admission", lambda role, **options: seen.append((role, options)))
    lr.main("audit", "preflight")
    assert seen == [("audit", {"resolve_payloads": False})]
    with pytest.raises(ValueError, match="closed lifecycle command"):
        lr.main("approve", "preflight")


def test_replay_p2_deriva_chamadas_iguais_ao_caminho_legado_e_satisfaz_a_ligacao_do_drift(monkeypatch, tmp_path):
    chain = ReplayChain(monkeypatch, tmp_path)
    plan = c.loads(chain.plan_files["plan.json"], state=True)
    state = c.loads(c.canonical(chain.final_state), state=True)
    matrix = chain.gov["drift_matrix"]
    for stage, extra in (("before", {}), ("after", {"state": state})):
        legacy = chain.gov["readbacks"][stage]
        calls = lr.readback_calls(plan, [item | {"absent": False} for item in legacy], stage, **extra)
        required = drift_catalog.PHASE_A_ENVELOPE.required(plan, c.stage_expectation(plan, stage, extra.get("state")))
        assert len(calls) == len({address for address, _ in required}) > 15 and len(matrix[stage]) == len(required) > 50
        assert [{k: v for k, v in call.items() if k != "absent"} for call in calls] == \
            drift_catalog.readback_calls(plan, legacy, stage, extra.get("state"))
        assert all("parameters" not in item for item in legacy)
        reports = [{"service": call["service"], "operation": call["operation"],
                    "observed": copy.deepcopy(chain.responses[stage][call["operation"], __import__("json").dumps(
                        call["parameters"], sort_keys=True)])} for call in calls]
        c.drift_coverage(plan, reports, matrix, matrix["source_sha"], matrix["purpose"], stage, extra.get("state"),
                         specs=calls, envelope=drift_catalog.PHASE_A_ENVELOPE)


STEPS = {"a-plan": {"role": "plan"}, "a-deploy": {"role": "deploy"}, "a-audit": {"role": "audit"}}


@pytest.mark.parametrize("role", ["plan", "audit"])
def test_plan_ou_audit_apos_deploy_nao_e_bloqueado_pelo_approval_republicado(role):
    origins = {"checkpoint.json": "a-deploy", "approval.json": "a-deploy"}
    lr.admit_approval_origin({"lifecycle_steps": STEPS}, role, origins)


@pytest.mark.parametrize("producer", ["a-deploy", "a-plan"])
def test_deploy_recusa_approval_de_produtor_que_nao_e_o_audit(producer):
    with pytest.raises(ValueError, match="approval producer is not the independent audit"):
        lr.admit_approval_origin({"lifecycle_steps": STEPS}, "deploy",
                                 {"plan.bin": "a-plan", "approval.json": producer})


def test_deploy_aceita_approval_do_audit_e_recusa_sem_approval():
    gov = {"lifecycle_steps": STEPS}
    lr.admit_approval_origin(gov, "deploy", {"plan.bin": "a-plan", "approval.json": "a-audit"})
    with pytest.raises(ValueError, match="independent audit approval absent"):
        lr.admit_approval_origin(gov, "deploy", {"plan.bin": "a-plan"})


@pytest.mark.parametrize("address", [SCHEDULE, STATE_MACHINE], ids=["schedule", "state-machine"])
def test_approval_recusa_leitura_agrupada_after_fora_do_grupo_de_schedules(address):
    grouped = spec(address, "scheduler", "list_schedules", members=["cnesdata-prod-audit"])
    with pytest.raises(ValueError, match="^readback catalog operation$"):
        lr._approval_stage(machine_plan(arn=False), [grouped], stage_rules()[1], "after")


def test_approval_aceita_leitura_agrupada_after_no_grupo_de_schedules():
    grouped = spec(GROUP, "scheduler", "list_schedules", members=["cnesdata-prod-audit"])
    lr._approval_stage(machine_plan(arn=False), [grouped], stage_rules()[1], "after")
