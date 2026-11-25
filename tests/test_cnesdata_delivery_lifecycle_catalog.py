"""P12: catalogo e envelope do lifecycle, prova de ausencia (N5) e chamadores com specs."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
INVENTORY = ROOT / "tests/fixtures/cnesdata_drift_inventory.json"
SOURCE = "a" * 40
ACCOUNT = "111122223333"
MACHINE_ARN = f"arn:aws:states:sa-east-1:{ACCOUNT}:stateMachine:synthetic-processor"
LIFECYCLE_TYPES = {
    "aws_iam_role", "aws_iam_role_policy", "aws_sfn_state_machine", "aws_scheduler_schedule",
    "aws_scheduler_schedule_group", "aws_cloudwatch_event_rule", "aws_cloudwatch_metric_alarm",
    "aws_s3_bucket_lifecycle_configuration", "aws_cloudfront_response_headers_policy"}
ABSENT_CASES = {
    "aws_sfn_state_machine": ("stepfunctions", "describe_state_machine", "StateMachineDoesNotExist"),
    "aws_scheduler_schedule": ("scheduler", "get_schedule", "ResourceNotFoundException"),
    "aws_scheduler_schedule_group": ("scheduler", "get_schedule_group", "ResourceNotFoundException"),
    "aws_cloudwatch_event_rule": ("events", "describe_rule", "ResourceNotFoundException"),
}


def catalog():
    from tools.cnesdata_delivery import drift_catalog
    return drift_catalog


def contract():
    from tools.cnesdata_delivery import contract as c
    return c


def runtime():
    from tools.cnesdata_delivery import lifecycle_runtime
    return lifecycle_runtime


def contrato():
    from tools.cnesdata_delivery import lifecycle_contract
    return lifecycle_contract


def envelope():
    return catalog().LIFECYCLE_ENVELOPE


class AwsError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeAWS:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def call(self, service, operation, **parameters):
        self.calls.append((service, operation, parameters))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return dict(response)


class Guard:
    def check(self, operation_seconds=1):
        return None


def spec(service, operation, address, absent=False, **extra):
    return {"service": service, "operation": operation, "address": address, "absent": absent} | extra


def read(operation_spec, response):
    value = runtime().readbacks(FakeAWS([response]), [operation_spec | {"parameters": {"X": "y"}}], Guard())
    return value[0]["observed"]


def change(address, before, after, actions=("update",)):
    return {"address": address, "mode": "managed", "type": address.split(".")[-2].split("[")[0],
            "change": {"actions": list(actions), "before": before, "after": after, "after_unknown": {}}}


def plan(*changes):
    return {"resource_changes": list(changes)}


def deletion_plan():
    lc = contrato()
    addresses = sorted(lc.scheduler_closure("recovery")) + [lc.STATE_MACHINE]
    return plan(*[change(address, identity_of(address), None, ("delete",)) for address in addresses]), addresses


def identity_of(address):
    tipo = catalog().resource_type(address)
    return {
        "aws_sfn_state_machine": {"arn": MACHINE_ARN, "name": "synthetic-processor"},
        "aws_scheduler_schedule": {"name": "synthetic-recovery", "group_name": "synthetic-recovery"},
        "aws_scheduler_schedule_group": {"name": "synthetic-recovery"},
        "aws_cloudwatch_event_rule": {"name": "synthetic-recovery-failed"},
        "aws_cloudwatch_metric_alarm": {"alarm_name": "synthetic-" + address[-12:]},
    }[tipo]


def absent_spec(address):
    tipo = catalog().resource_type(address)
    if tipo == "aws_cloudwatch_metric_alarm":
        return spec("cloudwatch", "describe_alarms", address, True)
    service, operation, _ = ABSENT_CASES[tipo]
    return spec(service, operation, address, True)


def absent_response(address):
    tipo = catalog().resource_type(address)
    if tipo == "aws_cloudwatch_metric_alarm":
        return {"MetricAlarms": [], "CompositeAlarms": []}
    return AwsError(ABSENT_CASES[tipo][2])


def deletion_matrix(addresses):
    rows = [{"address": address, "readback": index} for index, address in enumerate(addresses)]
    return {"matrix_version": 2, "source_sha": SOURCE, "purpose": "phase-c-recovery", "before": [], "after": [],
            "absent": rows}


def after_coverage(plan_, calls, reports, matrix_):
    return contract().drift_coverage(plan_, reports, matrix_, SOURCE, "phase-c-recovery", "after",
                                     {"resources": []}, specs=calls, envelope=envelope())


def test_envelope_do_lifecycle_tem_covered_e_supported_da_spec():
    found = envelope()
    assert found.covered == {"aws_iam_role", "aws_iam_role_policy"}
    assert found.supported == LIFECYCLE_TYPES
    assert catalog().ENVELOPES["lifecycle"] is found


def test_supported_cobre_todo_tipo_que_o_lifecycle_altera():
    lc, mapa = contrato(), catalog()
    changed = {mapa.resource_type(address) for mode in ("recovery", "audit") for address in lc.scheduler_closure(mode)}
    changed |= {mapa.resource_type(lc.STATE_MACHINE), mapa.resource_type(lc.API_POLICY)}
    changed |= {"aws_s3_bucket_lifecycle_configuration", "aws_cloudfront_response_headers_policy"}
    assert changed <= envelope().supported


def test_supported_e_exatamente_o_que_a_allowlist_de_leitura_do_lifecycle_cobre():
    mapa = catalog()
    allowed = {(service, operation) for service, operations in runtime().LIFECYCLE_READ_API.items()
               for operation in operations}
    read_by_types = {mapa._operation(tipo) for tipo in envelope().supported}
    assert read_by_types <= allowed
    assert allowed - read_by_types == {("scheduler", "list_schedules")}


def test_catalogo_do_lifecycle_igual_ao_inventario():
    mapa = catalog()
    found = json.loads(INVENTORY.read_text())["types"]
    for tipo in LIFECYCLE_TYPES:
        classified = set(mapa.CATALOG[tipo]) | set(mapa.NOT_OBSERVABLE[tipo])
        assert classified == set(found[tipo]), (tipo, sorted(classified ^ set(found[tipo])))
        assert not set(mapa.CATALOG[tipo]) & set(mapa.NOT_OBSERVABLE[tipo]), tipo
        service, operation = mapa._operation(tipo)
        assert tipo in mapa.IDENTITY | mapa.LIFECYCLE_IDENTITY
        assert operation in mapa.LIFECYCLE_READ_ONLY.get(service, set()) | mapa.READ_ONLY.get(service, set())


def test_catalogo_do_alarme_liga_o_indice_inteiro_da_lista_de_alarmes():
    path = catalog().CATALOG["aws_cloudwatch_metric_alarm"]["alarm_name"][2]
    assert path == ("MetricAlarms", 0, "AlarmName")


def test_recusa_tipo_alterado_sem_entrada_no_catalogo():
    plan_ = plan(change("module.x.aws_sns_topic.t[0]", {"name": "t"}, {"name": "t", "tags": {}}))
    with pytest.raises(ValueError, match="unsupported changed type"):
        envelope().required(plan_, {"module.x.aws_sns_topic.t[0]": {"name": "t"}})


def test_recusa_atributo_nao_classificado_de_tipo_alterado():
    address = contrato().STATE_MACHINE
    attributes = {"arn": MACHINE_ARN, "atributo_novo_do_provider": "x"}
    plan_ = plan(change(address, attributes, attributes))
    with pytest.raises(ValueError, match="unclassified attribute"):
        envelope().required(plan_, {address: attributes})


def test_recusa_delete_sem_linha_de_ausencia():
    plan_, addresses = deletion_plan()
    calls = catalog().lifecycle_calls(plan_, [absent_spec(address) for address in addresses], "after",
                                      {"resources": []})
    reports = [{"service": s["service"], "operation": s["operation"], "observed": {"absent": True}} for s in calls]
    matrix = deletion_matrix(addresses)
    assert after_coverage(plan_, calls, reports, matrix) is None
    for missing in (addresses[0], contrato().STATE_MACHINE):
        rows = [row for row in matrix["absent"] if row["address"] != missing]
        with pytest.raises(ValueError, match="absent drift coverage"):
            after_coverage(plan_, calls, reports, matrix | {"absent": rows})


def test_delete_do_closure_e_do_state_machine_fecha_com_notfound_derivado_do_plano():
    plan_, addresses = deletion_plan()
    calls = catalog().lifecycle_calls(plan_, [absent_spec(address) for address in addresses], "after",
                                      {"resources": []})
    assert calls[-1]["parameters"] == {"stateMachineArn": MACHINE_ARN}
    reports = runtime().readbacks(FakeAWS([absent_response(address) for address in addresses]), calls, Guard())
    assert all(report["observed"] == {"absent": True} for report in reports)
    assert after_coverage(plan_, calls, reports, deletion_matrix(addresses)) is None


@pytest.mark.parametrize("tipo", sorted(ABSENT_CASES))
def test_notfound_do_servico_prova_ausencia(tipo):
    service, operation, code = ABSENT_CASES[tipo]
    assert read(spec(service, operation, "a", True), AwsError(code)) == {"absent": True}


@pytest.mark.parametrize("tipo,code", [
    ("aws_sfn_state_machine", "ResourceNotFound"), ("aws_sfn_state_machine", "InvalidArn"),
    ("aws_sfn_state_machine", "ResourceNotFoundException"), ("aws_scheduler_schedule", "StateMachineDoesNotExist"),
    ("aws_scheduler_schedule", "ResourceNotFound"), ("aws_scheduler_schedule_group", "AccessDeniedException"),
    ("aws_cloudwatch_event_rule", "ThrottlingException"), ("aws_cloudwatch_event_rule", "NoSuchEntity")])
def test_recusa_codigo_de_erro_desconhecido_como_prova_de_ausencia(tipo, code):
    service, operation, _ = ABSENT_CASES[tipo]
    with pytest.raises(ValueError, match="readback unknown"):
        read(spec(service, operation, "a", True), AwsError(code))


def test_recusa_notfound_quando_a_spec_nao_declara_ausencia():
    service, operation, code = ABSENT_CASES["aws_scheduler_schedule"]
    with pytest.raises(ValueError, match="readback unknown"):
        read(spec(service, operation, "a", False), AwsError(code))


@pytest.mark.parametrize("service,operation,field", [
    ("stepfunctions", "describe_state_machine", "status"), ("scheduler", "get_schedule_group", "State")])
def test_estado_deleting_prova_ausencia_e_projeta_observed(service, operation, field):
    assert read(spec(service, operation, "a", True), {field: "DELETING", "Name": "x"}) == {"absent": True}


@pytest.mark.parametrize("service,operation,field", [
    ("stepfunctions", "describe_state_machine", "status"), ("scheduler", "get_schedule_group", "State")])
@pytest.mark.parametrize("state", ["ACTIVE", "FAILED", None])
def test_recusa_estado_diferente_de_deleting_como_prova_de_ausencia(service, operation, field, state):
    with pytest.raises(ValueError, match="resource still exists"):
        read(spec(service, operation, "a", True), {field: state, "Name": "x"})


def test_recusa_deleting_quando_a_spec_nao_declara_ausencia():
    with pytest.raises(ValueError, match="DELETING"):
        read(spec("scheduler", "get_schedule_group", "a", False), {"State": "DELETING"})


@pytest.mark.parametrize("service,operation", [("scheduler", "get_schedule"), ("events", "describe_rule")])
def test_recusa_ausencia_sem_estado_deleting_para_schedule_e_regra(service, operation):
    with pytest.raises(ValueError, match="resource still exists"):
        read(spec(service, operation, "a", True), {"Name": "x", "State": "DELETING"})


def test_alarme_com_lista_vazia_prova_ausencia_so_quando_a_spec_declara():
    alarm = spec("cloudwatch", "describe_alarms", "a", True)
    assert read(alarm, {"MetricAlarms": [], "CompositeAlarms": []}) == {"absent": True}
    with pytest.raises(ValueError, match="readback absent"):
        read(alarm | {"absent": False}, {"MetricAlarms": [], "CompositeAlarms": []})


def test_recusa_absent_true_com_alarme_existente():
    alarm = spec("cloudwatch", "describe_alarms", "a", True)
    with pytest.raises(ValueError, match="resource still exists"):
        read(alarm, {"MetricAlarms": [{"AlarmName": "x"}], "CompositeAlarms": []})
    with pytest.raises(ValueError, match="resource still exists"):
        read(alarm, {"MetricAlarms": [], "CompositeAlarms": [{"AlarmName": "x"}]})


def test_alarme_presente_exige_exatamente_um_e_nenhum_composto():
    alarm = spec("cloudwatch", "describe_alarms", "a", False)
    one = {"MetricAlarms": [{"AlarmName": "x"}], "CompositeAlarms": []}
    assert read(alarm, one) == one
    for value in ({"MetricAlarms": [{"AlarmName": "x"}, {"AlarmName": "y"}], "CompositeAlarms": []},
                  {"MetricAlarms": [{"AlarmName": "x"}], "CompositeAlarms": [{"AlarmName": "z"}]}):
        with pytest.raises(ValueError, match="readback absent"):
            read(alarm, value)


def test_estado_active_com_spec_de_presenca_continua_passando():
    assert read(spec("scheduler", "get_schedule_group", "a"), {"State": "ACTIVE"}) == {"State": "ACTIVE"}
    assert read(spec("stepfunctions", "describe_state_machine", "a"), {"status": "ACTIVE"}) == {"status": "ACTIVE"}


def test_codigos_de_ausencia_batem_com_os_modelos_do_botocore_instalado():
    session = pytest.importorskip("botocore.session")
    models = session.get_session()
    for (service, operation), codes in catalog().ABSENT_CODES.items():
        name = "".join(part.title() for part in operation.split("_"))
        shapes = models.get_service_model(service).operation_model(name).error_shapes
        found = {shape.metadata.get("error", {}).get("code", shape.name) for shape in shapes
                 if "NotFound" in shape.name or "DoesNotExist" in shape.name}
        assert set(codes) == found, (service, operation)
    assert set(catalog().ABSENT_CODES) == {(s, o) for s, o, _ in ABSENT_CASES.values()}


def test_alarme_presente_liga_linha_ao_indice_zero_da_lista():
    address = "module.schedulers.aws_cloudwatch_metric_alarm.lost_invocation[\"recovery\"]"
    attributes = {"alarm_name": "synthetic-recovery", "comparison_operator": "GreaterThanThreshold"}
    plan_ = plan(change(address, attributes, attributes))
    observed = {"MetricAlarms": [{"AlarmName": "synthetic-recovery", "ComparisonOperator": "GreaterThanThreshold"}],
                "CompositeAlarms": []}
    call = spec("cloudwatch", "describe_alarms", address, parameters={"AlarmNames": ["synthetic-recovery"]})
    rows = [{"address": address, "attribute": name, "readback": 0, "path": ["MetricAlarms", 0, field],
             "encoding": "identity"}
            for name, field in (("alarm_name", "AlarmName"), ("comparison_operator", "ComparisonOperator"))]
    matrix = {"matrix_version": 2, "source_sha": SOURCE, "purpose": "phase-b", "before": rows, "after": [],
              "absent": []}
    report = {"service": "cloudwatch", "operation": "describe_alarms", "observed": observed}
    assert contract().drift_coverage(plan_, [report], matrix, SOURCE, "phase-b", "before", specs=[call],
                                     envelope=envelope()) is None


def test_lifecycle_calls_derivam_parametros_do_atributo_de_identidade():
    address = "module.schedulers.aws_scheduler_schedule.mode[\"recovery\"]"
    attributes = {"name": "synthetic-recovery", "group_name": "synthetic-group"}
    plan_ = plan(change(address, attributes, attributes))
    [call] = catalog().lifecycle_calls(plan_, [spec("scheduler", "get_schedule", address)], "before")
    assert call["parameters"] == {"Name": "synthetic-recovery", "GroupName": "synthetic-group"}


@pytest.mark.parametrize("mutation", ["endereco-ausente", "parametro-divergente", "absent-sem-delete",
                                      "campo-extra", "parametro-igual"])
def test_lifecycle_calls_recusam_spec_fora_da_forma_ou_do_plano(mutation):
    address = "module.schedulers.aws_scheduler_schedule.mode[\"recovery\"]"
    attributes = {"name": "synthetic-recovery", "group_name": "synthetic-group"}
    plan_ = plan(change(address, attributes, attributes))
    call = spec("scheduler", "get_schedule", address)
    if mutation == "endereco-ausente":
        call = spec("scheduler", "get_schedule", "module.schedulers.aws_scheduler_schedule.other[0]")
    if mutation == "parametro-divergente":
        call |= {"parameters": {"Name": "outro", "GroupName": "synthetic-group"}}
    if mutation == "absent-sem-delete":
        call |= {"absent": True}
    if mutation == "campo-extra":
        call |= {"expected_sha256": "0" * 64}
    if mutation == "parametro-igual":
        call |= {"parameters": {"Name": "synthetic-recovery", "GroupName": "synthetic-group"}}
    with pytest.raises(ValueError):
        catalog().lifecycle_calls(plan_, [call], "before")


def test_spec_agrupada_de_membros_nao_e_orfa_nem_liga_linha_de_outro_endereco():
    group = "module.schedulers.aws_scheduler_schedule_group.mode[\"recovery\"]"
    role = "module.iam.aws_iam_role.fence[0]"
    plan_ = plan(change(group, {"name": "synthetic-recovery"}, {"name": "synthetic-recovery"}, ("no-op",)),
                 change(role, {"name": "synthetic-fence", "path": "/"}, {"name": "synthetic-fence", "path": "/"}))
    calls = catalog().lifecycle_calls(plan_, [spec("iam", "get_role", role), spec(
        "scheduler", "list_schedules", group, members=[])], "before")
    assert calls[1]["parameters"] == {"GroupName": "synthetic-recovery"}
    reports = [{"service": "iam", "operation": "get_role", "observed": {"Role": {"RoleName": "synthetic-fence", "Path": "/"}}},
               {"service": "scheduler", "operation": "list_schedules", "observed": {"Schedules": []}}]
    row = {"address": role, "attribute": "name", "readback": 0, "path": ["Role", "RoleName"], "encoding": "identity"}
    other = row | {"attribute": "path", "path": ["Role", "Path"]}
    matrix = {"matrix_version": 2, "source_sha": SOURCE, "purpose": "phase-b", "before": [row], "after": [],
              "absent": []}

    def coverage(rows):
        return contract().drift_coverage(plan_, reports, matrix | {"before": rows}, SOURCE, "phase-b", "before",
                                         specs=calls, envelope=envelope())
    assert coverage([row, other]) is None
    with pytest.raises(ValueError, match="readback address binding"):
        coverage([row, other | {"readback": 1}])


def test_catalog_sha256_continua_computado_do_documento_com_o_envelope_do_lifecycle():
    mapa, c = catalog(), contract()
    assert mapa.CATALOG_SHA256 == c.sha(c.canonical(mapa.catalog_document()))
    assert "lifecycle" in mapa.catalog_document()["envelopes"]


OBSERVED_SCALARS = {
    "aws_cloudwatch_metric_alarm": {
        "threshold": "Threshold", "period": "Period", "metric_name": "MetricName", "namespace": "Namespace",
        "statistic": "Statistic", "treat_missing_data": "TreatMissingData", "comparison_operator": "ComparisonOperator",
        "evaluation_periods": "EvaluationPeriods"},
    "aws_cloudwatch_event_rule": {"description": "Description"},
    "aws_scheduler_schedule": {"description": "Description", "target": "Target"},
}


@pytest.mark.parametrize("tipo,name,field", [(t, n, f) for t, rows in OBSERVED_SCALARS.items()
                                             for n, f in rows.items()])
def test_atributo_que_o_lifecycle_altera_e_observado_e_nao_isento(tipo, name, field):
    mapa = catalog()
    assert name in mapa.CATALOG[tipo] and name not in mapa.NOT_OBSERVABLE[tipo]
    assert mapa.CATALOG[tipo][name][2][-1] == field


def test_isencao_so_guarda_atributo_de_state_ou_bloco_sem_codificacao():
    mapa = catalog()
    scalars = {"threshold", "period", "metric_name", "namespace", "statistic", "treat_missing_data", "description"}
    for tipo in LIFECYCLE_TYPES:
        assert not scalars & set(mapa.NOT_OBSERVABLE[tipo]), tipo


ALARM = "module.schedulers.aws_cloudwatch_metric_alarm.lost_invocation[\"recovery\"]"


def alarm_coverage(threshold_state, threshold_live):
    from decimal import Decimal
    attributes = {"alarm_name": "synthetic-recovery", "threshold": threshold_state}
    plan_ = plan(change(ALARM, attributes, attributes))
    live = runtime()._dates({"MetricAlarms": [{"AlarmName": "synthetic-recovery", "Threshold": threshold_live}],
                             "CompositeAlarms": []})
    call = spec("cloudwatch", "describe_alarms", ALARM, parameters={"AlarmNames": ["synthetic-recovery"]})
    rows = [{"address": ALARM, "attribute": name, "readback": 0, "path": ["MetricAlarms", 0, field],
             "encoding": "identity"} for name, field in (("alarm_name", "AlarmName"), ("threshold", "Threshold"))]
    matrix = {"matrix_version": 2, "source_sha": SOURCE, "purpose": "phase-b", "before": rows, "after": [],
              "absent": []}
    report = {"service": "cloudwatch", "operation": "describe_alarms", "observed": live}
    assert Decimal
    return contract().drift_coverage(plan_, [report], matrix, SOURCE, "phase-b", "before", specs=[call],
                                     envelope=envelope())


def test_limiar_do_alarme_com_float_da_aws_confere_com_o_state():
    from decimal import Decimal
    assert alarm_coverage(Decimal("1"), 1.0) is None
    assert alarm_coverage(Decimal("2.5"), 2.5) is None


def test_recusa_limiar_do_alarme_que_divergiu_ao_vivo():
    from decimal import Decimal
    with pytest.raises(ValueError, match="saved-plan live functional drift"):
        alarm_coverage(Decimal("1"), 5.0)


SCHEDULE = "module.schedulers.aws_scheduler_schedule.mode[\"recovery\"]"


def state_target(task="synthetic-task:1", **extra):
    ecs = {"task_definition_arn": task, "task_count": 1, "launch_type": "FARGATE",
           "network_configuration": [{"assign_public_ip": False, "subnets": ["s-b", "s-a"],
                                      "security_groups": ["sg-1"]}]} | extra
    return [{"arn": "synthetic-cluster", "role_arn": "synthetic-role", "input": "{}",
             "retry_policy": [{"maximum_event_age_in_seconds": 3600, "maximum_retry_attempts": 2}],
             "ecs_parameters": [ecs]}]


def live_target(task="synthetic-task:1"):
    return {"Arn": "synthetic-cluster", "RoleArn": "synthetic-role", "Input": "{}",
            "RetryPolicy": {"MaximumEventAgeInSeconds": 3600, "MaximumRetryAttempts": 2},
            "EcsParameters": {"TaskDefinitionArn": task, "TaskCount": 1, "LaunchType": "FARGATE",
                              "NetworkConfiguration": {"awsvpcConfiguration": {
                                  "AssignPublicIp": "DISABLED", "Subnets": ["s-a", "s-b"],
                                  "SecurityGroups": ["sg-1"]}}}}


def target_coverage(state, live):
    attributes = {"name": "synthetic-recovery", "group_name": "synthetic-recovery", "target": state}
    plan_ = plan(change(SCHEDULE, attributes, attributes))
    call = spec("scheduler", "get_schedule", SCHEDULE,
                parameters={"Name": "synthetic-recovery", "GroupName": "synthetic-recovery"})
    observed = {"Name": "synthetic-recovery", "GroupName": "synthetic-recovery", "Target": live}
    entries = {"name": ["Name"], "group_name": ["GroupName"], "target": ["Target"]}
    rows = [{"address": SCHEDULE, "attribute": name, "readback": 0, "path": path,
             "encoding": "scheduler-target" if name == "target" else "identity"} for name, path in entries.items()]
    matrix = {"matrix_version": 2, "source_sha": SOURCE, "purpose": "phase-c-recovery", "before": rows,
              "after": [], "absent": []}
    report = {"service": "scheduler", "operation": "get_schedule", "observed": observed}
    return contract().drift_coverage(plan_, [report], matrix, SOURCE, "phase-c-recovery", "before",
                                     specs=[call], envelope=envelope())


def test_target_do_schedule_confere_com_projecao_fechada_e_canonica():
    assert target_coverage(state_target(), live_target()) is None


@pytest.mark.parametrize("mutation", ["task", "role", "subnet", "retry", "bloco-desconhecido"])
def test_recusa_target_do_schedule_que_divergiu_ou_tem_bloco_fora_da_projecao(mutation):
    state, live = state_target(), live_target()
    if mutation == "task":
        live = live_target("synthetic-task:2")
    if mutation == "role":
        live["RoleArn"] = "other-role"
    if mutation == "subnet":
        live["EcsParameters"]["NetworkConfiguration"]["awsvpcConfiguration"]["Subnets"] = ["s-a"]
    if mutation == "retry":
        live["RetryPolicy"]["MaximumRetryAttempts"] = 9
    if mutation == "bloco-desconhecido":
        live["SqsParameters"] = {"MessageGroupId": "g"}
    with pytest.raises(ValueError, match="saved-plan live functional drift|drift target projection"):
        target_coverage(state, live)


def test_target_do_state_com_bloco_fora_da_projecao_e_recusado():
    state = state_target()
    state[0]["sqs_parameters"] = [{"message_group_id": "g"}]
    with pytest.raises(ValueError, match="drift target projection"):
        target_coverage(state, live_target())


def test_fase_a_continua_recusando_leitura_de_lifecycle_na_admissao():
    mapa = catalog()
    machine = contrato().STATE_MACHINE
    attributes = {"arn": MACHINE_ARN}
    plan_ = plan(change(machine, attributes, attributes, ("no-op",)))
    read_spec = {"service": "stepfunctions", "operation": "describe_state_machine", "address": machine}
    matrix = {"matrix_version": 2, "source_sha": SOURCE, "purpose": "phase-a", "before": [], "after": [],
              "absent": []}
    with pytest.raises(ValueError, match="read-only API boundary"):
        mapa.admit_stages(plan_, {"before": [read_spec], "after": [read_spec]}, matrix, [])
    assert "stepfunctions" not in mapa.READ_ONLY and "aws_sfn_state_machine" not in mapa.IDENTITY
    with pytest.raises(ValueError, match="read-only API boundary"):
        mapa.require_read_only("cloudwatch", "describe_alarms")


def realistic_state_target():
    ecs = {"capacity_provider_strategy": [], "enable_ecs_managed_tags": False, "enable_execute_command": False,
           "group": "", "launch_type": "FARGATE", "network_configuration": [{
               "assign_public_ip": False, "security_groups": ["sg-1"], "subnets": ["s-a", "s-b"]}],
           "placement_constraints": [], "placement_strategy": [], "platform_version": "", "propagate_tags": "",
           "reference_id": "", "tags": {}, "task_count": 1, "task_definition_arn": "synthetic-task:1"}
    return [{"arn": "synthetic-cluster", "dead_letter_config": [], "ecs_parameters": [ecs],
             "eventbridge_parameters": [], "input": "", "kinesis_parameters": [], "retry_policy": [{
                 "maximum_event_age_in_seconds": 3600, "maximum_retry_attempts": 2}],
             "role_arn": "synthetic-role", "sagemaker_pipeline_parameters": [], "sqs_parameters": []}]


def realistic_live_target():
    return {"Arn": "synthetic-cluster", "RoleArn": "synthetic-role",
            "RetryPolicy": {"MaximumEventAgeInSeconds": 3600, "MaximumRetryAttempts": 2},
            "EcsParameters": {"TaskDefinitionArn": "synthetic-task:1", "TaskCount": 1, "LaunchType": "FARGATE",
                              "EnableECSManagedTags": False, "EnableExecuteCommand": False,
                              "NetworkConfiguration": {"awsvpcConfiguration": {
                                  "AssignPublicIp": "DISABLED", "Subnets": ["s-b", "s-a"],
                                  "SecurityGroups": ["sg-1"]}}}}


def test_target_com_forma_realista_do_state_do_tofu_confere_com_a_leitura_da_aws():
    assert target_coverage(realistic_state_target(), realistic_live_target()) is None


def test_recusa_target_realista_cuja_leitura_ao_vivo_divergiu():
    live = realistic_live_target()
    live["EcsParameters"]["TaskDefinitionArn"] = "synthetic-task:2"
    with pytest.raises(ValueError, match="saved-plan live functional drift"):
        target_coverage(realistic_state_target(), live)


def test_bloco_vazio_com_string_vazia_no_state_nao_conta_como_bloco_desconhecido():
    state = realistic_state_target()
    state[0]["sqs_parameters"] = [{"message_group_id": ""}]
    assert target_coverage(state, realistic_live_target()) is None


def strategy_state(*order):
    state = realistic_state_target()
    state[0]["ecs_parameters"][0]["placement_strategy"] = [{"type": t, "field": f} for t, f in order]
    return state


def strategy_live(*order):
    live = realistic_live_target()
    live["EcsParameters"]["PlacementStrategy"] = [{"type": t, "field": f} for t, f in order]
    return live


def test_placement_strategy_preserva_a_ordem_porque_o_ecs_a_trata_como_ordenada():
    first, second = ("spread", "attribute:ecs.availability-zone"), ("binpack", "memory")
    assert target_coverage(strategy_state(first, second), strategy_live(first, second)) is None
    with pytest.raises(ValueError, match="saved-plan live functional drift"):
        target_coverage(strategy_state(first, second), strategy_live(second, first))


def test_recusa_chave_de_tag_duplicada_na_leitura_do_target():
    state = realistic_state_target()
    state[0]["ecs_parameters"][0]["tags"] = {"a": "1"}
    live = realistic_live_target()
    live["EcsParameters"]["Tags"] = [{"a": "1"}, {"a": "2"}]
    with pytest.raises(ValueError, match="drift target projection"):
        target_coverage(state, live)


def test_tipos_do_envelope_da_fase_a_ficam_dentro_das_tabelas_estritas():
    mapa = catalog()
    for tipo in mapa.PHASE_A_ENVELOPE.supported:
        assert tipo in mapa.IDENTITY, tipo
        service, operation = mapa._operation(tipo)
        assert operation in mapa.READ_ONLY[service], tipo
    assert mapa.PHASE_A_ENVELOPE.identity is mapa.IDENTITY


def tag_case(state_tags, live_tags):
    state = realistic_state_target()
    state[0]["ecs_parameters"][0]["tags"] = state_tags
    live = realistic_live_target()
    if live_tags:
        live["EcsParameters"]["Tags"] = live_tags
    return target_coverage(state, live)


def test_tag_com_valor_vazio_e_tag_real_e_confere_nos_dois_lados():
    assert tag_case({"a": ""}, [{"a": ""}]) is None


@pytest.mark.parametrize("state_tags,live_tags", [({"a": ""}, None), ({}, [{"a": ""}])])
def test_recusa_tag_de_valor_vazio_presente_so_em_um_dos_lados(state_tags, live_tags):
    with pytest.raises(ValueError, match="saved-plan live functional drift"):
        tag_case(state_tags, live_tags)


OMITTED_IDENTITY = {
    "aws_sfn_state_machine": (
        "module.processing.aws_sfn_state_machine.processor[0]", {"arn": MACHINE_ARN}),
    "aws_scheduler_schedule": (
        'module.schedulers.aws_scheduler_schedule.mode["recovery"]',
        {"name": "synthetic-recovery", "group_name": "synthetic-recovery"}),
    "aws_cloudwatch_event_rule": (
        'module.schedulers.aws_cloudwatch_event_rule.task_outcome["recovery_failed"]',
        {"name": "synthetic-recovery-failed"}),
    "aws_cloudwatch_metric_alarm": (
        'module.schedulers.aws_cloudwatch_metric_alarm.lost_invocation["recovery"]',
        {"alarm_name": "synthetic-recovery"}),
    "aws_cloudfront_response_headers_policy": (
        "module.static_web.aws_cloudfront_response_headers_policy.this",
        {"id": "synthetic-policy"}),
}
REAL_EXTRA = {
    "aws_sfn_state_machine": {"status": "ACTIVE", "type": "STANDARD", "roleArn": "synthetic-role",
                              "definition": "{}", "creationDate": "2026-11-21T00:00:00Z"},
    "aws_scheduler_schedule": {"State": "ENABLED", "ScheduleExpression": "rate(1 hour)",
                               "ActionAfterCompletion": "NONE",
                               "ScheduleExpressionTimezone": "UTC"},
    "aws_cloudwatch_event_rule": {"State": "ENABLED", "EventBusName": "default"},
    "aws_cloudwatch_metric_alarm": {"CompositeAlarms": [], "MetricAlarms": [
        {"ComparisonOperator": "GreaterThanThreshold", "EvaluationPeriods": 1,
         "ActionsEnabled": True}]},
    "aws_cloudfront_response_headers_policy": {"ETag": "E1", "ResponseHeadersPolicy": {
        "ResponseHeadersPolicyConfig": {"Name": "synthetic-policy"}}},
}
OPTIONAL_LIFECYCLE = [
    ("aws_sfn_state_machine", "description", ["", None], "texto"),
    ("aws_scheduler_schedule", "description", ["", None], "texto"),
    ("aws_scheduler_schedule", "kms_key_arn", ["", None], "synthetic-key"),
    ("aws_cloudwatch_event_rule", "description", ["", None], "texto"),
    ("aws_cloudwatch_event_rule", "role_arn", ["", None], "synthetic-role"),
    ("aws_cloudwatch_event_rule", "event_pattern", ["", None], '{"source":["x"]}'),
    ("aws_cloudwatch_event_rule", "schedule_expression", ["", None], "rate(1 hour)"),
    ("aws_cloudwatch_metric_alarm", "alarm_description", ["", None], "texto"),
    ("aws_cloudwatch_metric_alarm", "metric_name", ["", None], "ExecutionsFailed"),
    ("aws_cloudwatch_metric_alarm", "namespace", ["", None], "AWS/States"),
    ("aws_cloudwatch_metric_alarm", "statistic", ["", None], "Sum"),
    ("aws_cloudwatch_metric_alarm", "extended_statistic", ["", None], "p99"),
    ("aws_cloudwatch_metric_alarm", "unit", ["", None], "Count"),
    ("aws_cloudwatch_metric_alarm", "threshold_metric_id", ["", None], "m1"),
    ("aws_cloudwatch_metric_alarm", "datapoints_to_alarm", [0, None], 2),
    ("aws_cloudwatch_metric_alarm", "period", [0, None], 300),
    ("aws_cloudwatch_metric_alarm", "threshold", [0, None], 1),
    ("aws_cloudwatch_metric_alarm", "alarm_actions", [[], None], ["synthetic-topic"]),
    ("aws_cloudwatch_metric_alarm", "ok_actions", [[], None], ["synthetic-topic"]),
    ("aws_cloudwatch_metric_alarm", "insufficient_data_actions", [[], None], ["synthetic-topic"]),
    ("aws_cloudfront_response_headers_policy", "comment", ["", None], "texto"),
]


REAL_PATHS = {
    ("aws_sfn_state_machine", "arn"): ("stateMachineArn",),
    ("aws_sfn_state_machine", "description"): ("description",),
    ("aws_sfn_state_machine", "name"): ("name",),
    ("aws_scheduler_schedule", "schedule_expression_timezone"): ("ScheduleExpressionTimezone",),
    ("aws_cloudwatch_metric_alarm", "evaluation_periods"): ("MetricAlarms", 0, "EvaluationPeriods"),
    ("aws_cloudfront_response_headers_policy", "name"): (
        "ResponseHeadersPolicy", "ResponseHeadersPolicyConfig", "Name"),
    ("aws_scheduler_schedule", "name"): ("Name",),
    ("aws_scheduler_schedule", "group_name"): ("GroupName",),
    ("aws_scheduler_schedule", "description"): ("Description",),
    ("aws_scheduler_schedule", "kms_key_arn"): ("KmsKeyArn",),
    ("aws_cloudwatch_event_rule", "name"): ("Name",),
    ("aws_cloudwatch_event_rule", "description"): ("Description",),
    ("aws_cloudwatch_event_rule", "role_arn"): ("RoleArn",),
    ("aws_cloudwatch_event_rule", "event_pattern"): ("EventPattern",),
    ("aws_cloudwatch_event_rule", "schedule_expression"): ("ScheduleExpression",),
    **{("aws_cloudwatch_metric_alarm", attribute): ("MetricAlarms", 0, member) for attribute, member in {
        "alarm_name": "AlarmName", "alarm_description": "AlarmDescription", "metric_name": "MetricName",
        "namespace": "Namespace", "statistic": "Statistic", "extended_statistic": "ExtendedStatistic",
        "unit": "Unit", "threshold_metric_id": "ThresholdMetricId", "datapoints_to_alarm": "DatapointsToAlarm",
        "period": "Period", "threshold": "Threshold", "alarm_actions": "AlarmActions", "ok_actions": "OKActions",
        "insufficient_data_actions": "InsufficientDataActions"}.items()},
    ("aws_cloudfront_response_headers_policy", "id"): ("ResponseHeadersPolicy", "Id"),
    ("aws_cloudfront_response_headers_policy", "comment"): (
        "ResponseHeadersPolicy", "ResponseHeadersPolicyConfig", "Comment"),
}
BOTOCORE_MEMBERS = ROOT / "tests/fixtures/cnesdata_delivery_botocore_members.json"
BOTOCORE_REGENERATE = (
    "PYTHONPATH=$PWD:$PWD/tests uv run --no-project --python 3.12 --with botocore==1.44.5 --with pytest python -c "
    "'import test_cnesdata_delivery_lifecycle_catalog as t; t.write_botocore_members()'")


def _botocore_level(shape, depth, key, levels):
    if shape.type_name == "list":
        _botocore_level(shape.member, depth, key + "[]", levels)
        return
    if shape.type_name != "structure" or depth == 0:
        return
    levels[key] = {name: [member.type_name, name in shape.required_members]
                   for name, member in sorted(shape.members.items())}
    for name, member in shape.members.items():
        _botocore_level(member, depth - 1, f"{key}.{name}" if key else name, levels)


def write_botocore_members():
    """Regenera BOTOCORE_MEMBERS dos shapes do botocore; do CATALOG so sai a profundidade de cada operacao."""
    import botocore
    from botocore.session import get_session
    session, depths, operations = get_session(), {}, {}
    for entries in catalog().CATALOG.values():
        for service, operation, path, _ in entries.values():
            depth = sum(type(part) is str for part in path)
            depths[(service, operation)] = max(depths.get((service, operation), 0), depth)
    for (service, operation), depth in sorted(depths.items()):
        model = session.get_service_model(service)
        names = {botocore.xform_name(name): name for name in model.operation_names}
        levels = {}
        _botocore_level(model.operation_model(names[operation]).output_shape, depth, "", levels)
        operations[f"{service} {operation}"] = levels
    document = {"botocore": botocore.__version__, "regenerate": BOTOCORE_REGENERATE, "operations": operations}
    BOTOCORE_MEMBERS.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")


def botocore_walk(service, operation, path):
    levels = json.loads(BOTOCORE_MEMBERS.read_text())["operations"][f"{service} {operation}"]
    key, kind, required = "", "structure", []
    for part in path:
        if type(part) is int:
            assert kind == "list", (service, operation, path)
            key, kind = key + "[]", "structure"
            continue
        members = levels.get(key, {})
        assert part in members, (service, operation, path, sorted(members))
        kind = members[part][0]
        required.append(members[part][1])
        key = f"{key}.{part}" if key else part
    return required


def put(target, path, value):
    *parents, leaf = path
    for index, component in enumerate(parents):
        child = [{}] if type(path[index + 1]) is int else {}
        target = target.setdefault(component, child) if type(target) is dict else target[component]
    target[leaf] = value


def drop(target, path):
    for component in path[:-1]:
        target = target[component]
    target.pop(path[-1], None)


def optional_case(tipo, attribute, planned, live=None):
    entries = catalog().CATALOG[tipo]
    address, identity = OMITTED_IDENTITY[tipo]
    attributes = identity | {attribute: planned}
    observed = json.loads(json.dumps(REAL_EXTRA[tipo]))
    for name, value in identity.items():
        put(observed, REAL_PATHS[(tipo, name)], value)
    if live is None:
        drop(observed, REAL_PATHS[(tipo, attribute)])
    else:
        put(observed, REAL_PATHS[(tipo, attribute)], live)
    service, operation = entries[attribute][:2]
    rows = [{"address": address, "attribute": name, "readback": 0, "path": list(entries[name][2]),
             "encoding": entries[name][3]} for name in sorted(attributes)]
    matrix = {"matrix_version": 2, "source_sha": SOURCE, "purpose": "phase-b", "before": rows,
              "after": [], "absent": []}
    report = {"service": service, "operation": operation, "observed": observed}
    call = spec(service, operation, address, parameters={"X": "y"})
    plan_ = plan(change(address, attributes, attributes))
    return lambda: contract().drift_coverage(plan_, [report], matrix, SOURCE, "phase-b", "before",
                                             specs=[call], envelope=envelope())


CATALOG_PATHS = sorted((tipo, attribute) for tipo, entries in catalog().CATALOG.items() for attribute in entries)
OMITTED_PATHS = sorted((tipo, attribute) for tipo, entries in catalog().OMITTED.items() for attribute in entries)


def test_membros_congelados_do_botocore_registram_versao_e_comando_de_regeneracao():
    document = json.loads(BOTOCORE_MEMBERS.read_text())
    assert (document["botocore"], document["regenerate"]) == ("1.44.5", BOTOCORE_REGENERATE)
    assert {key for key in document["operations"]} == {
        f"{service} {operation}" for entries in catalog().CATALOG.values() for service, operation, _, _ in entries.values()}


@pytest.mark.parametrize("tipo,attribute", CATALOG_PATHS)
def test_caminho_do_catalogo_existe_nos_membros_de_saida_do_botocore(tipo, attribute):
    service, operation, path, _ = catalog().CATALOG[tipo][attribute]
    botocore_walk(service, operation, path)


LEAF_OMITTED_TYPES = {"aws_ecs_task_definition"}
ECS_OMITTED_PATHS = [path for path in OMITTED_PATHS if path[0] in LEAF_OMITTED_TYPES]


def omitted_member_is_optional(tipo, attribute):
    service, operation, path, _ = catalog().CATALOG[tipo][attribute]
    required = botocore_walk(service, operation, path)
    return not required[-1] if tipo in LEAF_OMITTED_TYPES else not all(required)


@pytest.mark.parametrize("tipo,attribute", OMITTED_PATHS)
def test_omissao_declarada_aponta_para_membro_que_a_aws_pode_omitir(tipo, attribute):
    assert omitted_member_is_optional(tipo, attribute)


@pytest.mark.parametrize("tipo,attribute", ECS_OMITTED_PATHS)
def test_omissao_declarada_com_a_folha_obrigatoria_no_botocore_e_recusada(tipo, attribute, monkeypatch, tmp_path):
    document = json.loads(BOTOCORE_MEMBERS.read_text())
    service, operation, path, _ = catalog().CATALOG[tipo][attribute]
    document["operations"][f"{service} {operation}"][".".join(path[:-1])][path[-1]][1] = True
    mutated = tmp_path / "members.json"
    mutated.write_text(json.dumps(document))
    monkeypatch.setitem(globals(), "BOTOCORE_MEMBERS", mutated)
    assert not omitted_member_is_optional(tipo, attribute)


@pytest.mark.parametrize("tipo,attribute", sorted(REAL_PATHS))
def test_resposta_viva_dos_testes_de_omissao_usa_membros_reais_do_botocore(tipo, attribute):
    service, operation = catalog().CATALOG[tipo][attribute][:2]
    botocore_walk(service, operation, REAL_PATHS[(tipo, attribute)])


@pytest.mark.parametrize("tipo,attribute,empties,filled", OPTIONAL_LIFECYCLE)
def test_leitura_real_sem_campo_opcional_casa_com_o_vazio_declarado(
        tipo, attribute, empties, filled):
    for empty in empties:
        assert optional_case(tipo, attribute, empty)() is None


@pytest.mark.parametrize("tipo,attribute,empties,filled", OPTIONAL_LIFECYCLE)
def test_campo_opcional_presente_e_diferente_continua_recusado(tipo, attribute, empties, filled):
    planned = None if catalog().CATALOG[tipo][attribute][3] == "json" else empties[0]
    with pytest.raises(ValueError, match="saved-plan live functional drift"):
        optional_case(tipo, attribute, planned, filled)()


@pytest.mark.parametrize("tipo,attribute,empties,filled", OPTIONAL_LIFECYCLE)
def test_campo_opcional_omitido_com_valor_planejado_nao_vazio_e_recusado(
        tipo, attribute, empties, filled):
    with pytest.raises(ValueError, match="drift response field"):
        optional_case(tipo, attribute, filled)()


@pytest.mark.parametrize("tipo,attribute", [
    ("aws_sfn_state_machine", "name"), ("aws_scheduler_schedule", "schedule_expression_timezone"),
    ("aws_cloudwatch_metric_alarm", "evaluation_periods"),
    ("aws_cloudfront_response_headers_policy", "name")])
def test_campo_sem_omissao_declarada_ausente_na_leitura_continua_recusado(tipo, attribute):
    with pytest.raises(ValueError, match="drift response field"):
        optional_case(tipo, attribute, "")()


def test_container_de_topo_do_lifecycle_ausente_nao_vale_como_omissao():
    mapa, c = catalog(), contract()
    for tipo, attribute in (("aws_cloudfront_response_headers_policy", "comment"),
                            ("aws_cloudwatch_metric_alarm", "metric_name")):
        _, _, path, encoding = mapa.CATALOG[tipo][attribute]
        row = {"address": "x", "attribute": attribute, "readback": 0, "path": list(path),
               "encoding": encoding}
        with pytest.raises(ValueError, match="drift response field"):
            c._projection(row, {}, "", c.ENCODINGS, mapa.OMITTED[tipo][attribute])
