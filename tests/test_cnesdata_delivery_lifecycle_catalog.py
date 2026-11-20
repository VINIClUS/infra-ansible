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
        assert tipo in mapa.IDENTITY and mapa._operation(tipo)[1] in mapa.READ_ONLY[mapa._operation(tipo)[0]]


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
                                      "campo-extra"])
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
