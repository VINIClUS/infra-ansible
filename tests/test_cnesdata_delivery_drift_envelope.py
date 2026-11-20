"""G5: catalogo, NOT_OBSERVABLE, envelope, completude, ligacao linha-spec e codificacoes (P06)."""
import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
INVENTORY = ROOT / "tests/fixtures/cnesdata_drift_inventory.json"
SOURCE = "a" * 40
ROLE = "module.iam.aws_iam_role.fence[0]"
OTHER = "module.iam.aws_iam_role.outro[0]"
TABLE = "module.processing.aws_dynamodb_table.canary[0]"
BUCKET = "module.processing.aws_s3_bucket.canary[0]"
POLICY_DOC = '{"Statement":[{"Action":"sts:AssumeRole","Effect":"Allow"}],"Version":"2012-10-17"}'


def catalog():
    from tools.cnesdata_delivery import drift_catalog
    return drift_catalog


def contract():
    from tools.cnesdata_delivery import contract as c
    return c


def inventory():
    return json.loads(INVENTORY.read_text())


def role(name="fence", **extra):
    return {"name": name, "path": "/", "max_session_duration": 3600, "assume_role_policy": POLICY_DOC,
            "force_detach_policies": False} | extra


def change(address, before, after, actions=("update",)):
    return {"address": address, "mode": "managed", "type": address.split(".")[-2],
            "change": {"actions": list(actions), "before": before, "after": after, "after_unknown": {}}}


def plan(*changes):
    return {"resource_changes": list(changes)}


def observed_role(name="fence"):
    return {"Role": {"RoleName": name, "Path": "/", "MaxSessionDuration": 3600,
                     "AssumeRolePolicyDocument": json.loads(POLICY_DOC), "RoleId": "AROAEXAMPLE"}}


ROLE_PATHS = {"name": (["Role", "RoleName"], "identity"), "path": (["Role", "Path"], "identity"),
              "max_session_duration": (["Role", "MaxSessionDuration"], "identity"),
              "assume_role_policy": (["Role", "AssumeRolePolicyDocument"], "json")}


def role_rows(address=ROLE, readback=0, names=None):
    names = sorted(ROLE_PATHS) if names is None else names
    return [{"address": address, "attribute": name, "readback": readback, "path": ROLE_PATHS[name][0],
             "encoding": ROLE_PATHS[name][1]} for name in names]


def call(address=ROLE, name="fence", **extra):
    return {"service": "iam", "operation": "get_role", "address": address, "parameters": {"RoleName": name}} | extra


def report(observed):
    return {"service": "iam", "operation": "get_role", "sha256": "0" * 64, "observed": observed}


def matrix(before=(), after=(), absent=None, version=2):
    value = {"matrix_version": version, "source_sha": SOURCE, "purpose": "phase-a",
             "before": list(before), "after": list(after)}
    absent = [] if absent is None and version == 2 else absent
    return value if absent is None else value | {"absent": list(absent)}


def coverage(plan_, reports, matrix_, stage="before", **kwargs):
    return contract().drift_coverage(plan_, reports, matrix_, SOURCE, "phase-a", stage, **kwargs)


def phase_a():
    return catalog().PHASE_A_ENVELOPE


def test_catalogo_igual_ao_inventario():
    mapa, found = catalog(), inventory()["types"]
    assert set(mapa.CATALOG) == set(found) == set(mapa.NOT_OBSERVABLE)
    for tipo, names in found.items():
        classified = set(mapa.CATALOG[tipo]) | set(mapa.NOT_OBSERVABLE[tipo])
        assert set(names) <= classified, (tipo, sorted(set(names) - classified))
        assert classified <= set(names), (tipo, sorted(classified - set(names)))


def test_inventario_vem_do_provider_travado_e_so_tem_nomes():
    found = inventory()
    assert found["provider"] == {"source": "registry.opentofu.org/hashicorp/aws", "version": "6.54.0"}
    for names in found["types"].values():
        assert names == sorted(set(names)) and all(type(name) is str for name in names)


def test_atributo_isento_nao_tem_entrada_no_catalogo():
    mapa = catalog()
    for tipo, exempt in mapa.NOT_OBSERVABLE.items():
        assert not set(exempt) & set(mapa.CATALOG[tipo]), tipo


def test_todo_tipo_do_catalogo_declara_identidade_e_entradas_fechadas():
    mapa = catalog()
    encodings = {"identity", "json", "tags-kv", "json-set", "ecs-container-definitions"}
    for tipo, entries in mapa.CATALOG.items():
        assert tipo in mapa.IDENTITY
        for attribute, (service, operation, path, encoding) in entries.items():
            assert operation in mapa.READ_ONLY[service], (tipo, attribute)
            assert encoding in encodings and type(path) is tuple and path, (tipo, attribute)
        assert len({entry[:2] for entry in entries.values()}) == 1, tipo


def test_envelope_da_phase_a_e_o_minimo_da_spec():
    envelope = phase_a()
    assert envelope.covered == {"aws_iam_role", "aws_iam_role_policy", "aws_ecs_task_definition"}
    assert envelope.supported == envelope.covered | {
        "aws_dynamodb_table", "aws_s3_bucket_policy", "aws_s3_bucket_object_lock_configuration"}
    assert envelope.supported <= set(catalog().CATALOG)


def test_versioning_sem_atributo_observavel_fica_fora_do_supported_e_mudanca_e_recusada():
    versioning = "module.processing.aws_s3_bucket_versioning.canary[0]"
    assert "aws_s3_bucket_versioning" not in catalog().CATALOG
    plan_ = plan(change(ROLE, role(), role()), change(versioning, {"bucket": "b", "versioning_configuration": []},
                                                      {"bucket": "b", "versioning_configuration": [{"status": "x"}]}))
    with pytest.raises(ValueError, match="unsupported changed type"):
        coverage(plan_, [report(observed_role())], matrix(role_rows()), specs=[call()], envelope=phase_a())


def test_catalog_sha256_e_computado_do_catalogo():
    mapa, c = catalog(), contract()
    expected = c.sha(c.canonical(mapa.catalog_document()))
    assert mapa.CATALOG_SHA256 == expected
    document = mapa.catalog_document()
    assert set(document) == {"catalog", "envelopes", "identity", "not_observable", "omitted", "container_defaults"}


def test_envelope_aceita_linhas_ligadas_ao_catalogo():
    plan_ = plan(change(ROLE, role(), role()))
    assert coverage(plan_, [report(observed_role())], matrix(role_rows()), specs=[call()],
                    envelope=phase_a()) is None


def test_recusa_atributo_fora_do_catalogo_e_de_not_observable():
    plan_ = plan(change(ROLE, role(novo_atributo="x"), role(novo_atributo="x")))
    with pytest.raises(ValueError, match="unclassified attribute"):
        coverage(plan_, [report(observed_role())], matrix(role_rows()), specs=[call()], envelope=phase_a())


def test_recusa_linha_para_atributo_so_state():
    plan_ = plan(change(ROLE, role(), role()))
    rows = role_rows() + [{"address": ROLE, "attribute": "force_detach_policies", "readback": 0,
                           "path": ["Role", "Path"], "encoding": "identity"}]
    with pytest.raises(ValueError, match="not observable drift row"):
        coverage(plan_, [report(observed_role())], matrix(rows), specs=[call()], envelope=phase_a())


@pytest.mark.parametrize("field,value", [("path", ["Role", "RoleId"]), ("encoding", "json")])
def test_recusa_linha_que_diverge_do_catalogo(field, value):
    plan_ = plan(change(ROLE, role(), role()))
    rows = role_rows()
    rows[1] = rows[1] | {field: value}
    with pytest.raises(ValueError, match="catalog drift row"):
        coverage(plan_, [report(observed_role())], matrix(rows), specs=[call()], envelope=phase_a())


def test_recusa_linha_cuja_operacao_diverge_do_catalogo():
    plan_ = plan(change(ROLE, role(), role()))
    spec = call() | {"operation": "get_role_policy"}
    with pytest.raises(ValueError, match="catalog drift row"):
        coverage(plan_, [report(observed_role()) | {"operation": "get_role_policy"}], matrix(role_rows()),
                 specs=[spec], envelope=phase_a())


def test_recusa_atributo_coberto_sem_linha():
    plan_ = plan(change(ROLE, role(), role()))
    with pytest.raises(ValueError, match="incomplete governed drift coverage"):
        coverage(plan_, [report(observed_role())], matrix(role_rows(names=["name", "path"])), specs=[call()],
                 envelope=phase_a())


def test_drift_coverage_com_specs_liga_cada_linha_a_sua_spec():
    plan_ = plan(change(ROLE, role(), role()), change(OTHER, role("outro"), role("outro")))
    rows = role_rows() + role_rows(OTHER, 1)
    reports = [report(observed_role()), report(observed_role("outro"))]
    specs = [call(), call(OTHER, "outro")]
    assert coverage(plan_, reports, matrix(rows), specs=specs, envelope=phase_a()) is None
    swapped = [specs[1], specs[0]]
    with pytest.raises(ValueError, match="readback address binding"):
        coverage(plan_, reports, matrix(rows), specs=swapped, envelope=phase_a())


def strict_case():
    plan_ = plan(change(ROLE, {"name": "fence"}, {"name": "fence"}))
    rows = [{"address": ROLE, "attribute": "name", "readback": 0, "path": ["Role", "RoleName"], "encoding": "identity"}]
    return plan_, [report(observed_role())], matrix(rows, version=1)


def test_drift_coverage_sem_envelope_tambem_liga_linha_a_spec_quando_recebe_specs():
    plan_, reports, matrix_ = strict_case()
    assert coverage(plan_, reports, matrix_, specs=[call()]) is None
    with pytest.raises(ValueError, match="readback address binding"):
        coverage(plan_, reports, matrix_, specs=[call(OTHER)])


@pytest.mark.parametrize("mutation,message", [
    ("orfa", "orphan readback"), ("tamanho", "drift readback specs"),
    ("relatorio", "readback report binding"), ("chave-extra", "drift readback spec fields")])
def test_specs_de_drift_coverage_sao_fechadas_e_sem_orfa(mutation, message):
    plan_, reports, matrix_ = strict_case()
    specs = [call()]
    if mutation == "orfa":
        specs.append(call(OTHER))
        reports.append(report(observed_role()))
    if mutation == "tamanho":
        specs.append(call(OTHER))
    if mutation == "relatorio":
        reports[0] = reports[0] | {"operation": "get_role_policy"}
    if mutation == "chave-extra":
        specs[0] = specs[0] | {"expected_sha256": "0" * 64}
    with pytest.raises(ValueError, match=message):
        coverage(plan_, reports, matrix_, specs=specs)


def test_chamada_sem_envelope_continua_estrita():
    plan_, reports, matrix_ = strict_case()
    assert coverage(plan_, reports, matrix_) is None
    with pytest.raises(ValueError, match="closed object fields"):
        coverage(plan_, reports, matrix_ | {"matrix_version": 2, "absent": []})
    loose = plan(change(ROLE, {"name": "fence", "force_detach_policies": False},
                        {"name": "fence", "force_detach_policies": False}))
    with pytest.raises(ValueError, match="incomplete governed drift coverage"):
        coverage(loose, reports, matrix_)


def test_envelope_exige_matrix_version_2_com_absent_e_specs():
    plan_ = plan(change(ROLE, role(), role()))
    with pytest.raises(ValueError, match="closed object fields"):
        coverage(plan_, [report(observed_role())], matrix(role_rows(), version=1), specs=[call()],
                 envelope=phase_a())
    with pytest.raises(ValueError, match="governed drift matrix identity"):
        coverage(plan_, [report(observed_role())], matrix(role_rows(), absent=[], version=1), specs=[call()],
                 envelope=phase_a())
    with pytest.raises(ValueError, match="drift readback specs"):
        coverage(plan_, [report(observed_role())], matrix(role_rows(), absent=[]), envelope=phase_a())


def test_envelope_aceita_matriz_v2_com_absent_vazio():
    plan_ = plan(change(ROLE, role(), role()))
    assert coverage(plan_, [report(observed_role())], matrix(role_rows(), absent=[]), specs=[call()],
                    envelope=phase_a()) is None


def test_recusa_tipo_alterado_fora_do_envelope():
    plan_ = plan(change(ROLE, role(), role()), change("aws_kms_key.k", {"key_id": "k"}, {"key_id": "k", "x": 1}))
    with pytest.raises(ValueError, match="unsupported changed type"):
        coverage(plan_, [report(observed_role())], matrix(role_rows()), specs=[call()], envelope=phase_a())


def test_recusa_mudanca_em_s3_canary_fora_do_supported():
    plan_ = plan(change(ROLE, role(), role()), change(BUCKET, {"bucket": "b"}, {"bucket": "b", "tags": {}}))
    with pytest.raises(ValueError, match="unsupported changed type"):
        coverage(plan_, [report(observed_role())], matrix(role_rows()), specs=[call()], envelope=phase_a())


def test_covered_inclui_instancia_no_op_dos_tipos_cobertos_e_exclui_o_resto():
    plan_ = plan(change(ROLE, role(), role(), ("no-op",)), change(TABLE, {"name": "t"}, {"name": "t"}, ("no-op",)))
    assert coverage(plan_, [report(observed_role())], matrix(role_rows()), specs=[call()],
                    envelope=phase_a()) is None
    with pytest.raises(ValueError, match="incomplete governed drift coverage"):
        coverage(plan_, [report(observed_role())], matrix(role_rows(names=["name"])), specs=[call()],
                 envelope=phase_a())
    extra = role_rows() + [{"address": TABLE, "attribute": "name", "readback": 0, "path": ["Table", "TableName"],
                            "encoding": "identity"}]
    with pytest.raises(ValueError, match="unknown/duplicate drift coverage"):
        coverage(plan_, [report(observed_role())], matrix(extra), specs=[call()], envelope=phase_a())


def test_tipo_supported_alterado_entra_no_covered():
    observed = {"Table": {"TableName": "t", "DeletionProtectionEnabled": True}}
    plan_ = plan(change(TABLE, {"name": "t", "deletion_protection_enabled": False},
                        {"name": "t", "deletion_protection_enabled": True}))
    spec = {"service": "dynamodb", "operation": "describe_table", "address": TABLE, "parameters": {"TableName": "t"}}
    rows = [{"address": TABLE, "attribute": "name", "readback": 0, "path": ["Table", "TableName"],
             "encoding": "identity"}]
    reports = [{"service": "dynamodb", "operation": "describe_table", "sha256": "0" * 64, "observed": observed}]
    with pytest.raises(ValueError, match="incomplete governed drift coverage"):
        coverage(plan_, reports, matrix(rows), specs=[spec], envelope=phase_a())
    rows.append({"address": TABLE, "attribute": "deletion_protection_enabled", "readback": 0,
                 "path": ["Table", "DeletionProtectionEnabled"], "encoding": "identity"})
    with pytest.raises(ValueError, match="saved-plan live functional drift"):
        coverage(plan_, reports, matrix(rows), specs=[spec], envelope=phase_a())


def delete_envelope():
    return catalog().Envelope(covered={"aws_iam_role"}, supported={"aws_iam_role"})


def deletion(name="fence", observed=None):
    plan_ = plan(change(ROLE, role(), None, ("delete",)))
    state = {"resources": []}
    spec = call(name=name, absent=True)
    reports = [report({"absent": True} if observed is None else observed)]
    return plan_, state, spec, reports


def test_delete_exige_linha_de_ausencia_e_aceita_nome_do_before():
    plan_, state, spec, reports = deletion()
    rows = matrix(absent=[{"address": ROLE, "readback": 0}])
    assert coverage(plan_, reports, rows, "after", state=state, specs=[spec], envelope=delete_envelope()) is None
    with pytest.raises(ValueError, match="absent drift coverage"):
        coverage(plan_, [], matrix(absent=[]), "after", state=state, specs=[], envelope=delete_envelope())


def test_ausencia_exige_nome_igual_ao_before():
    plan_, state, spec, reports = deletion(name="outro")
    with pytest.raises(ValueError, match="absence identity"):
        coverage(plan_, reports, matrix(absent=[{"address": ROLE, "readback": 0}]), "after", state=state,
                 specs=[spec], envelope=delete_envelope())


@pytest.mark.parametrize("mutation,message", [
    ("existe", "absent drift proof"), ("spec-sem-absent", "absent drift proof"),
    ("endereco-nao-removido", "absent drift coverage"), ("outro-endereco", "readback address binding"),
    ("chave-extra", "closed object fields")])
def test_linha_de_ausencia_e_fechada_e_provada(mutation, message):
    plan_, state, spec, reports = deletion()
    row = {"address": ROLE, "readback": 0}
    if mutation == "existe":
        reports = [report(observed_role())]
    if mutation == "spec-sem-absent":
        spec = call()
    if mutation == "endereco-nao-removido":
        plan_ = plan(change(ROLE, role(), None, ("delete",)), change(TABLE, {"name": "t"}, {"name": "t"}, ("no-op",)))
        state = {"resources": [{"mode": "managed", "module": "module.processing", "type": "aws_dynamodb_table",
                                "name": "canary", "instances": [{"index_key": 0, "attributes": {"name": "t"}}]}]}
        spec = {"service": "dynamodb", "operation": "describe_table", "address": TABLE, "absent": True,
                "parameters": {"TableName": "t"}}
        row = {"address": TABLE, "readback": 0}
    if mutation == "outro-endereco":
        row = {"address": OTHER, "readback": 0}
    if mutation == "chave-extra":
        row = row | {"attribute": "name"}
    with pytest.raises(ValueError, match=message):
        coverage(plan_, reports, matrix(absent=[row]), "after", state=state, specs=[spec],
                 envelope=delete_envelope())


def test_linha_de_ausencia_so_vale_no_estagio_after():
    plan_ = plan(change(ROLE, role(), None, ("delete",)))
    assert coverage(plan_, [report(observed_role())], matrix(role_rows(), absent=[{"address": ROLE, "readback": 0}]),
                    specs=[call()], envelope=delete_envelope()) is None


def test_envelope_recusa_tipo_supported_sem_catalogo():
    with pytest.raises(ValueError, match="envelope catalog"):
        catalog().Envelope(covered={"aws_iam_role"}, supported={"aws_iam_role", "aws_kms_key"})
    with pytest.raises(ValueError, match="envelope catalog"):
        catalog().Envelope(covered={"aws_iam_role", "aws_kms_key"}, supported={"aws_iam_role"})


def test_runtime_passa_specs_em_toda_chamada_de_drift_coverage():
    source = (ROOT / "tools/cnesdata_delivery/runtime.py").read_text()
    nodes = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)]
    calls = [node for node in nodes if getattr(node.func, "id", None) == "_coverage"]
    assert len(calls) == 5
    assert all(any(keyword.arg == "specs" for keyword in node.keywords) for node in calls)
    direct = [node for node in nodes if getattr(node.func, "attr", None) == "drift_coverage"]
    assert len(direct) == 1 and {keyword.arg for keyword in direct[0].keywords} == {"specs", "envelope"}


TASK = 'module.processing.aws_ecs_task_definition.processor["unit"]'
CONTAINERS = [{"name": "app", "image": "img:1", "essential": True, "mountPoints": [],
               "environment": [{"name": "B", "value": "2"}, {"name": "A", "value": "1"}]},
              {"name": "sidecar", "image": "side:1", "secrets": []}]


def task(containers=None, compatibilities=("FARGATE", "EC2")):
    return {"family": "processor", "requires_compatibilities": list(compatibilities),
            "container_definitions": json.dumps(CONTAINERS if containers is None else containers)}


def task_case(observed_containers, observed_compatibilities=("EC2", "FARGATE")):
    plan_ = plan(change(TASK, task(), task()))
    rows = [{"address": TASK, "attribute": name, "readback": 0, "path": ["taskDefinition", key], "encoding": encoding}
            for name, key, encoding in (("family", "family", "identity"),
                                        ("requires_compatibilities", "requiresCompatibilities", "json-set"),
                                        ("container_definitions", "containerDefinitions", "ecs-container-definitions"))]
    spec = {"service": "ecs", "operation": "describe_task_definition", "address": TASK,
            "parameters": {"taskDefinition": "processor"}}
    observed = {"taskDefinition": {"family": "processor", "requiresCompatibilities": list(observed_compatibilities),
                                   "containerDefinitions": observed_containers}}
    reports = [{"service": "ecs", "operation": "describe_task_definition", "sha256": "0" * 64, "observed": observed}]
    return plan_, reports, matrix(rows), [spec]


def api_containers():
    return [{"name": "sidecar", "image": "side:1", "portMappings": [], "volumesFrom": []},
            {"name": "app", "image": "img:1", "essential": True, "cpu": None, "portMappings": [],
             "environment": [{"name": "A", "value": "1"}, {"name": "B", "value": "2"}]}]


def test_codificacao_ecs_container_definitions_ignora_ordem_e_campos_vazios():
    plan_, reports, matrix_, specs = task_case(api_containers())
    assert coverage(plan_, reports, matrix_, specs=specs, envelope=phase_a()) is None


@pytest.mark.parametrize("mutation", ["imagem", "variavel", "container-a-mais"])
def test_codificacao_ecs_container_definitions_recusa_diferenca_funcional(mutation):
    containers = api_containers()
    if mutation == "imagem":
        containers[1]["image"] = "img:2"
    if mutation == "variavel":
        containers[1]["environment"][0]["value"] = "9"
    if mutation == "container-a-mais":
        containers.append({"name": "outro", "image": "o:1"})
    plan_, reports, matrix_, specs = task_case(containers)
    with pytest.raises(ValueError, match="saved-plan live functional drift"):
        coverage(plan_, reports, matrix_, specs=specs, envelope=phase_a())


def test_codificacao_ecs_container_definitions_recusa_nome_duplicado():
    plan_, reports, matrix_, specs = task_case(api_containers() + [{"name": "app", "image": "img:1"}])
    with pytest.raises(ValueError, match="drift container projection"):
        coverage(plan_, reports, matrix_, specs=specs, envelope=phase_a())


def test_codificacao_json_set_ignora_ordem_e_recusa_elemento_diferente():
    plan_, reports, matrix_, specs = task_case(api_containers(), ("FARGATE",))
    with pytest.raises(ValueError, match="saved-plan live functional drift"):
        coverage(plan_, reports, matrix_, specs=specs, envelope=phase_a())


def tags_case(observed_tags):
    attributes = role(tags_all={"Project": "cnes", "ReleaseId": "r1"})
    plan_ = plan(change(ROLE, attributes, attributes))
    rows = role_rows() + [{"address": ROLE, "attribute": "tags_all", "readback": 0, "path": ["Role", "Tags"],
                           "encoding": "tags-kv"}]
    observed = observed_role()
    observed["Role"]["Tags"] = observed_tags
    return plan_, [report(observed)], matrix(rows), [call()]


def test_codificacao_tags_kv_compara_lista_de_chave_valor_com_mapa():
    tags = [{"Key": "ReleaseId", "Value": "r1"}, {"Key": "Project", "Value": "cnes"}]
    plan_, reports, matrix_, specs = tags_case(tags)
    assert coverage(plan_, reports, matrix_, specs=specs, envelope=phase_a()) is None


@pytest.mark.parametrize("tags,message", [
    ([{"Key": "ReleaseId", "Value": "r2"}, {"Key": "Project", "Value": "cnes"}], "saved-plan live functional drift"),
    ([{"Key": "ReleaseId", "Value": "r1"}], "saved-plan live functional drift"),
    ([{"Key": "ReleaseId", "Value": "r1"}, {"Key": "ReleaseId", "Value": "r1"}, {"Key": "Project", "Value": "cnes"}],
     "drift tags projection"),
    ([{"Key": "ReleaseId", "Value": "r1", "Extra": 1}, {"Key": "Project", "Value": "cnes"}], "drift tags projection"),
    ({"ReleaseId": "r1", "Project": "cnes"}, "drift tags projection")])
def test_codificacao_tags_kv_recusa_valor_diferente_duplicata_e_forma_errada(tags, message):
    plan_, reports, matrix_, specs = tags_case(tags)
    with pytest.raises(ValueError, match=message):
        coverage(plan_, reports, matrix_, specs=specs, envelope=phase_a())


@pytest.mark.parametrize("encoding", ["tags-kv", "json-set", "ecs-container-definitions"])
def test_chamada_sem_envelope_so_aceita_identity_e_json(encoding):
    plan_, reports, matrix_ = strict_case()
    matrix_["before"][0]["encoding"] = encoding
    with pytest.raises(ValueError, match="unknown drift projection encoding"):
        coverage(plan_, reports, matrix_, specs=[call()])


TABLE_NAME = {"name": "t"}


def omitted_case(tipo, attribute, observed, expected, absent_at=None):
    mapa = catalog()
    service, operation, path, encoding = mapa.CATALOG[tipo][attribute]
    address = ROLE if tipo == "aws_iam_role" else TABLE
    identity = {"name": "fence"} if tipo == "aws_iam_role" else TABLE_NAME
    attributes = identity | {attribute: expected}
    plan_ = plan(change(address, attributes, attributes))
    spec = {"service": service, "operation": operation, "address": address,
            "parameters": {"RoleName": "fence"} if tipo == "aws_iam_role" else {"TableName": "t"}}
    names = sorted({"name", attribute})
    rows = [{"address": address, "attribute": name, "readback": 0, "path": list(mapa.CATALOG[tipo][name][2]),
             "encoding": mapa.CATALOG[tipo][name][3]} for name in names]
    reports = [{"service": service, "operation": operation, "sha256": "0" * 64, "observed": observed}]
    return plan_, reports, matrix(rows), spec


ROLE_OBSERVED = {"Role": {"RoleName": "fence"}}
TABLE_OBSERVED = {"Table": {"TableName": "t"}}
OMITTED_CASES = [
    ("aws_iam_role", "description", ROLE_OBSERVED, ["", None], "texto"),
    ("aws_iam_role", "permissions_boundary", ROLE_OBSERVED, ["", None], "arn-x"),
    ("aws_iam_role", "tags_all", ROLE_OBSERVED, [{}, None], {"ReleaseId": "x"}),
    ("aws_dynamodb_table", "billing_mode", TABLE_OBSERVED, ["PROVISIONED"], "PAY_PER_REQUEST"),
    ("aws_dynamodb_table", "table_class", TABLE_OBSERVED, ["STANDARD"], "STANDARD_INFREQUENT_ACCESS"),
    ("aws_dynamodb_table", "stream_enabled", TABLE_OBSERVED, [False, None], True),
    ("aws_dynamodb_table", "stream_view_type", TABLE_OBSERVED, ["", None], "NEW_IMAGE"),
    ("aws_dynamodb_table", "stream_arn", TABLE_OBSERVED, ["", None], "arn-x"),
    ("aws_dynamodb_table", "stream_label", TABLE_OBSERVED, ["", None], "label"),
]


@pytest.mark.parametrize("tipo,attribute,observed,empties,filled", OMITTED_CASES)
def test_campo_omitido_pela_api_casa_so_com_o_vazio_declarado(tipo, attribute, observed, empties, filled):
    for empty in empties:
        plan_, reports, rows, spec = omitted_case(tipo, attribute, observed, empty)
        assert coverage(plan_, reports, rows, specs=[spec], envelope=phase_a()) is None
    plan_, reports, rows, spec = omitted_case(tipo, attribute, observed, filled)
    with pytest.raises(ValueError, match="drift response field"):
        coverage(plan_, reports, rows, specs=[spec], envelope=phase_a())


def test_campo_omitido_vazio_nao_aceita_valor_diferente_do_declarado():
    plan_, reports, rows, spec = omitted_case("aws_dynamodb_table", "billing_mode", TABLE_OBSERVED, "OUTRO")
    with pytest.raises(ValueError, match="drift response field"):
        coverage(plan_, reports, rows, specs=[spec], envelope=phase_a())


def test_campo_omitido_so_vale_em_atributo_declarado():
    plan_, reports, rows, spec = omitted_case("aws_iam_role", "path", ROLE_OBSERVED, "")
    with pytest.raises(ValueError, match="drift response field"):
        coverage(plan_, reports, rows, specs=[spec], envelope=phase_a())


def test_omissao_no_ultimo_componente_do_caminho_tambem_casa_o_vazio():
    observed = {"Role": {"RoleName": "fence", "PermissionsBoundary": {}}}
    plan_, reports, rows, spec = omitted_case("aws_iam_role", "permissions_boundary", observed, "")
    assert coverage(plan_, reports, rows, specs=[spec], envelope=phase_a()) is None


def test_valor_presente_na_api_continua_comparado_ao_state():
    observed = {"Role": {"RoleName": "fence", "Description": "x"}}
    plan_, reports, rows, spec = omitted_case("aws_iam_role", "description", observed, "")
    with pytest.raises(ValueError, match="saved-plan live functional drift"):
        coverage(plan_, reports, rows, specs=[spec], envelope=phase_a())


def test_v1_sem_envelope_continua_estrito_com_campo_omitido():
    plan_, reports, rows, spec = omitted_case("aws_iam_role", "description", ROLE_OBSERVED, "")
    rows = rows | {"matrix_version": 1}
    rows.pop("absent")
    with pytest.raises(ValueError, match="drift response field"):
        coverage(plan_, reports, rows, specs=[spec])


def test_omitidos_declarados_so_apontam_atributos_do_catalogo_e_entram_no_hash():
    mapa, c = catalog(), contract()
    for tipo, entries in mapa.OMITTED.items():
        assert set(entries) <= set(mapa.CATALOG[tipo]), tipo
    assert "omitted" in mapa.catalog_document()
    altered = mapa.catalog_document() | {"omitted": {}}
    assert c.sha(c.canonical(altered)) != mapa.CATALOG_SHA256


def container_case(expected_cpu, observed_cpu):
    expected = {"name": "app", "image": "i"} | ({} if expected_cpu is None else {"cpu": expected_cpu})
    seen = {"name": "app", "image": "i"} | ({} if observed_cpu is None else {"cpu": observed_cpu})
    address = "module.processing.aws_ecs_task_definition.processor[\"unit\"]"
    attributes = {"family": "f", "container_definitions": json.dumps([expected])}
    plan_ = plan(change(address, attributes, attributes))
    mapa = catalog()
    rows = [{"address": address, "attribute": name, "readback": 0, "path": list(mapa.CATALOG["aws_ecs_task_definition"][name][2]),
             "encoding": mapa.CATALOG["aws_ecs_task_definition"][name][3]} for name in ("container_definitions", "family")]
    observed = {"taskDefinition": {"family": "f", "containerDefinitions": [seen]}}
    spec = {"service": "ecs", "operation": "describe_task_definition", "address": address,
            "parameters": {"taskDefinition": "f"}}
    reports = [{"service": "ecs", "operation": "describe_task_definition", "sha256": "0" * 64, "observed": observed}]
    return plan_, reports, matrix(rows), spec


@pytest.mark.parametrize("expected,observed", [(None, 0), (0, None), (0, 0), (None, None), (256, 256)])
def test_cpu_zero_do_container_equivale_a_ausencia_nos_dois_sentidos(expected, observed):
    plan_, reports, rows, spec = container_case(expected, observed)
    assert coverage(plan_, reports, rows, specs=[spec], envelope=phase_a()) is None


@pytest.mark.parametrize("expected,observed", [(256, None), (None, 256), (256, 0), (0, 256)])
def test_cpu_diferente_de_zero_omitido_ou_divergente_e_recusado(expected, observed):
    plan_, reports, rows, spec = container_case(expected, observed)
    with pytest.raises(ValueError, match="saved-plan live functional drift"):
        coverage(plan_, reports, rows, specs=[spec], envelope=phase_a())


def test_id_da_task_definition_no_state_e_a_familia():
    assert catalog().CATALOG["aws_ecs_task_definition"]["id"][2] == ("taskDefinition", "family")
    attributes = {"family": "f", "id": "f"}
    address = 'module.processing.aws_ecs_task_definition.processor["unit"]'
    plan_ = plan(change(address, attributes, attributes))
    rows = [{"address": address, "attribute": name, "readback": 0, "path": list(catalog().CATALOG[
        "aws_ecs_task_definition"][name][2]), "encoding": "identity"} for name in ("family", "id")]
    spec = {"service": "ecs", "operation": "describe_task_definition", "address": address,
            "parameters": {"taskDefinition": "f"}}
    reports = [{"service": "ecs", "operation": "describe_task_definition", "sha256": "0" * 64,
                "observed": {"taskDefinition": {"family": "f"}}}]
    assert coverage(plan_, reports, matrix(rows), specs=[spec], envelope=phase_a()) is None
