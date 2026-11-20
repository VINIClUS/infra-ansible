"""G4: readbacks por estagio com parametros derivados da identidade do plano (P05)."""
import ast
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
GATE = ROOT / "tools/cnesdata_delivery"
WORKFLOWS = ROOT / ".github/workflows"
REUSABLES = ("reusable-cnesdata-infra-plan-gate.yml", "reusable-cnesdata-infra-deploy-gate.yml",
             "reusable-cnesdata-application-gate.yml")


def catalog():
    from tools.cnesdata_delivery import drift_catalog
    return drift_catalog


def change(address, before, after, actions=("update",), unknown=None):
    return {"address": address, "mode": "managed", "type": address.split(".")[-2],
            "change": {"actions": list(actions), "before": before, "after": after,
                       "after_unknown": {} if unknown is None else unknown}}


ROLE = "module.iam.aws_iam_role.fence[0]"
POLICY = "module.iam.aws_iam_role_policy.fence[0]"


def plan(*changes):
    return {"resource_changes": list(changes)}


def role_plan(before=None, after=None, actions=("update",), unknown=None):
    before = {"name": "fence", "tags": {}} if before is None else before
    after = {"name": "fence", "tags": {"ReleaseId": "x"}} if after is None else after
    return plan(change(ROLE, before, after, actions, unknown))


def spec(address=ROLE, operation="get_role", service="iam"):
    return {"service": service, "operation": operation, "address": address}


def test_parametros_da_leitura_vem_do_atributo_de_identidade():
    mapa = catalog()
    assert mapa.parameters("aws_iam_role", {"name": "fence", "tags": {}}) == {"RoleName": "fence"}
    assert mapa.parameters("aws_iam_role_policy", {"role": "r", "name": "p", "policy": "{}"}) == {
        "RoleName": "r", "PolicyName": "p"}
    assert mapa.parameters("aws_ecs_task_definition", {"family": "f", "revision": 4}) == {"taskDefinition": "f"}
    assert mapa.parameters("aws_dynamodb_table", {"name": "t"}) == {"TableName": "t"}
    assert mapa.parameters("aws_s3_bucket_policy", {"bucket": "b"}) == {"Bucket": "b"}
    assert mapa.parameters("aws_ecs_cluster", {"name": "c"}) == {"clusters": ["c"]}


def test_parametros_do_estagio_after_vem_do_state_e_do_before_vem_do_plano():
    mapa = catalog()
    state = {"resources": [{"mode": "managed", "module": "module.iam", "type": "aws_iam_role", "name": "fence",
                            "instances": [{"index_key": 0, "attributes": {"name": "fence", "tags": {"ReleaseId": "x"}}}]}]}
    bound = mapa.readback_calls(role_plan(), [spec()], "after", state)
    assert bound == [{**spec(), "parameters": {"RoleName": "fence"}}]
    assert mapa.readback_calls(role_plan(), [spec()], "before") == bound


@pytest.mark.parametrize("extra", [{"parameters": {"RoleName": "fence"}}, {"expected_sha256": "0" * 64}])
def test_recusa_spec_com_parametros_ou_hash_residuais(extra):
    with pytest.raises(ValueError):
        catalog().readback_calls(role_plan(), [spec() | extra], "before")


def test_recusa_tipo_sem_identidade_e_endereco_fora_do_plano():
    mapa = catalog()
    with pytest.raises(ValueError, match="identity type"):
        mapa.readback_calls(plan(change("aws_kms_key.k", {"name": "k"}, {"name": "k"})),
                            [spec("aws_kms_key.k")], "before")
    with pytest.raises(ValueError, match="readback address"):
        mapa.readback_calls(role_plan(), [spec("module.iam.aws_iam_role.outro[0]")], "before")


def test_recusa_linha_cuja_spec_pertence_a_outro_endereco():
    mapa = catalog()
    calls = [{**spec(ROLE), "parameters": {"RoleName": "fence"}},
             {**spec(POLICY, "get_role_policy"), "parameters": {"RoleName": "r", "PolicyName": "p"}}]
    row = {"address": ROLE, "attribute": "name", "readback": 0, "path": ["Role", "RoleName"], "encoding": "identity"}
    mapa.bind_rows(calls, [row, row | {"address": POLICY, "readback": 1}])
    with pytest.raises(ValueError, match="readback address binding"):
        mapa.bind_rows(calls, [row | {"readback": 1}])


def test_recusa_leitura_orfa_que_nenhuma_linha_referencia():
    mapa = catalog()
    calls = [{**spec(ROLE), "parameters": {"RoleName": "fence"}}]
    with pytest.raises(ValueError, match="orphan readback"):
        mapa.bind_rows(calls, [])


@pytest.mark.parametrize("case", ["desconhecida", "mudou-fora-de-create-delete", "mudou-no-after-do-state"])
def test_recusa_identidade_desconhecida_ou_divergente_entre_before_e_after(case):
    mapa = catalog()
    state = None
    stage = "before"
    if case == "desconhecida":
        bad = role_plan(unknown={"name": True})
    elif case == "mudou-fora-de-create-delete":
        bad = role_plan(after={"name": "outro", "tags": {}})
    else:
        bad = role_plan()
        stage = "after"
        state = {"resources": [{"mode": "managed", "module": "module.iam", "type": "aws_iam_role", "name": "fence",
                                "instances": [{"index_key": 0, "attributes": {"name": "outro", "tags": {}}}]}]}
    with pytest.raises(ValueError):
        mapa.readback_calls(bad, [spec()], stage, state)


def test_identidade_pode_mudar_na_substituicao_mas_nao_pode_faltar():
    mapa = catalog()
    replaced = role_plan(after={"name": "novo", "tags": {}}, actions=("delete", "create"))
    assert mapa.readback_calls(replaced, [spec()], "before")[0]["parameters"] == {"RoleName": "fence"}
    with pytest.raises(ValueError, match="readback identity"):
        mapa.readback_calls(role_plan(actions=("delete", "create"), after={"tags": {}}), [spec()], "before")


def test_criacao_nao_tem_before_e_identidade_vem_do_plano():
    mapa = catalog()
    created = role_plan(before=None, actions=("create",))
    created["resource_changes"][0]["change"]["before"] = None
    with pytest.raises(ValueError, match="readback absent before"):
        mapa.readback_calls(created, [spec()], "before")


def test_ausencia_exige_nome_igual_ao_before():
    mapa = catalog()
    deleted = plan(change(ROLE, {"name": "fence", "tags": {}}, None, ("delete",)))
    assert mapa.absence(deleted, ROLE, {"RoleName": "fence"}) == {"RoleName": "fence"}
    with pytest.raises(ValueError, match="absence identity"):
        mapa.absence(deleted, ROLE, {"RoleName": "outro"})
    with pytest.raises(ValueError, match="absence identity"):
        mapa.absence(role_plan(), "module.iam.aws_iam_role.inexistente[0]", {"RoleName": "fence"})


def reusable_lists():
    found = {}
    for name in REUSABLES:
        raw = (WORKFLOWS / name).read_text()
        found[name] = [ast.literal_eval(value) for value in re.findall(r"files = (\[[\s\S]*?\])", raw)]
    return found


def imported_modules(path):
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module == "tools.cnesdata_delivery":
            names |= {alias.name + ".py" for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("tools.cnesdata_delivery."):
            names.add(node.module.rsplit(".", 1)[1] + ".py")
    return names


def closure(entry):
    pending, seen = [entry], set()
    while pending:
        name = pending.pop()
        if name in seen or not (GATE / name).is_file():
            continue
        seen.add(name)
        pending.extend(imported_modules(GATE / name))
    return seen


def test_listas_dos_reusables_cobrem_os_modulos_do_pyboot():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    pyboot = [name for name in lc.APPLICATION_PYBOOT if name.endswith(".py")]
    entry = {"application": closure("application_gate.py"), "infra": closure("apply_gate.py")}
    assert "drift_catalog.py" in pyboot and "drift_catalog.py" in closure("runtime.py")
    lists = reusable_lists()
    assert [len(lists[name]) for name in REUSABLES] == [2, 2, 1]
    for name, values in lists.items():
        for files in values:
            required = (entry["application"] if "application" in name else entry["infra"]) | set(pyboot)
            assert required <= set(files), (name, sorted(required - set(files)))
            assert len(files) == len(set(files)), name


FENCE_ROLE = "module.runtime_iam.aws_iam_role.promotion_fence_operator[0]"
FENCE_POLICY = "module.runtime_iam.aws_iam_role_policy.promotion_fence_operator[0]"
TRACKED = "module.processing.aws_iam_role_policy.step_functions_ecs[0]"


def admission_case():
    plan_ = plan(change(FENCE_ROLE, {"name": "f"}, {"name": "f"}), change(FENCE_POLICY, {"role": "f", "name": "p"},
                 {"role": "f", "name": "p"}), change(TRACKED, {"role": "r", "name": "t"}, {"role": "r", "name": "t"}),
                 change(ROLE, {"name": "fence"}, {"name": "fence"}),
                 change(FENCE_ROLE.replace("fence_operator", "outro"), {"name": "o"}, {"name": "o"}))
    after = [spec(FENCE_ROLE), spec(FENCE_POLICY, "get_role_policy"), spec(TRACKED, "get_role_policy")]
    rows = [{"address": s["address"], "attribute": "name", "readback": i, "path": ["x"], "encoding": "identity"}
            for i, s in enumerate(after)]
    readbacks = {"before": [], "after": after}
    matrix = {"before": [], "after": rows}
    return plan_, readbacks, matrix, {TRACKED}


def test_admissao_pre_acquire_aceita_after_completo():
    mapa = catalog()
    mapa.admit_stages(*admission_case())


@pytest.mark.parametrize("mutation,message", [
    ("orfa-after", "orphan readback"), ("orfa-before", "orphan readback"),
    ("rastreado-duplicado", "tracked policy readback"), ("rastreado-ausente", "tracked policy readback"),
    ("fence-duplicado", "fence readback"), ("fence-ausente", "fence readback")])
def test_admissao_pre_acquire_recusa_after_mal_formado(mutation, message):
    mapa = catalog()
    plan_, readbacks, matrix, tracked = admission_case()
    after, rows = readbacks["after"], matrix["after"]
    if mutation == "orfa-after":
        after.append(spec(FENCE_ROLE.replace("fence_operator", "outro")))
    if mutation == "orfa-before":
        readbacks["before"].append(spec())
    if mutation in {"rastreado-duplicado", "fence-duplicado"}:
        source = TRACKED if mutation == "rastreado-duplicado" else FENCE_ROLE
        index = next(i for i, s in enumerate(after) if s["address"] == source)
        after.append(dict(after[index]))
        rows.append(rows[index] | {"readback": len(after) - 1})
    if mutation in {"rastreado-ausente", "fence-ausente"}:
        gone = TRACKED if mutation == "rastreado-ausente" else FENCE_POLICY
        index = next(i for i, s in enumerate(after) if s["address"] == gone)
        del after[index]
        rows[:] = [r | {"readback": r["readback"] - (r["readback"] > index)} for r in rows if r["readback"] != index]
    with pytest.raises(ValueError, match=message):
        mapa.admit_stages(plan_, readbacks, matrix, tracked)


def state_of(address_type, name, attributes, module="module.iam"):
    return {"resources": [{"mode": "managed", "module": module, "type": address_type, "name": name,
                           "instances": [{"index_key": 0, "attributes": attributes}]}]}


CREATES = {
    "acm": ("aws_acm_certificate.static_web", "aws_acm_certificate", "static_web",
            {"domain_name": "d.example"}, {"arn": True, "id": True}, {"arn": "arn:x", "domain_name": "d.example", "id": "i"},
            "describe_certificate", "acm", {"CertificateArn": "arn:x"}),
    "politica-de-role-criado": ("module.iam.aws_iam_role_policy.canary[0]", "aws_iam_role_policy", "canary",
                                {"name": "p", "policy": "{}"}, {"role": True, "id": True},
                                {"role": "canary-role", "name": "p", "policy": "{}", "id": "i"},
                                "get_role_policy", "iam", {"RoleName": "canary-role", "PolicyName": "p"}),
    "s3-de-bucket-criado": ("module.processing.aws_s3_bucket_versioning.canary[0]", "aws_s3_bucket_versioning",
                            "canary", {"versioning_configuration": []}, {"bucket": True, "id": True},
                            {"bucket": "canary-bucket", "versioning_configuration": [], "id": "i"},
                            "get_bucket_versioning", "s3", {"Bucket": "canary-bucket"}),
}


def create_case(name):
    address, tipo, local, after, unknown, applied, operation, service, expected = CREATES[name]
    module = address.rsplit(".", 2)[0] if address.startswith("module.") else ""
    plan_ = plan(change(address, None, after, ("create",), unknown))
    state = state_of(tipo, local, applied, module)
    state["resources"][0]["instances"][0]["index_key"] = 0 if address.endswith("[0]") else None
    if not address.endswith("[0]"):
        del state["resources"][0]["instances"][0]["index_key"]
        del state["resources"][0]["module"]
    return plan_, state, spec(address, operation, service), expected


@pytest.mark.parametrize("name", sorted(CREATES))
def test_criacao_com_identidade_desconhecida_no_plano_le_do_state_aplicado(name):
    mapa = catalog()
    plan_, state, one, expected = create_case(name)
    assert mapa.admit_stages(plan_, {"before": [], "after": [one]}, {"before": [], "after": [
        {"address": one["address"], "attribute": "id", "readback": 0, "path": ["x"], "encoding": "identity"}]}, set()) is None
    assert mapa.readback_calls(plan_, [one], "after", state)[0]["parameters"] == expected


@pytest.mark.parametrize("name", sorted(CREATES))
def test_criacao_recusa_identidade_ausente_do_plano_e_valor_vazio_no_state(name):
    mapa = catalog()
    plan_, state, one, _ = create_case(name)
    change_ = plan_["resource_changes"][0]["change"]
    rows = {"before": [], "after": [{"address": one["address"], "attribute": "id", "readback": 0, "path": ["x"],
                                     "encoding": "identity"}]}
    change_["after_unknown"] = {"id": True}
    with pytest.raises(ValueError, match="readback identity"):
        mapa.admit_stages(plan_, {"before": [], "after": [one]}, rows, set())
    change_["after_unknown"] = CREATES[name][4]
    attributes = state["resources"][0]["instances"][0]["attributes"]
    attributes[next(k for k in CREATES[name][4] if k != "id")] = ""
    with pytest.raises(ValueError, match="readback identity value"):
        mapa.readback_calls(plan_, [one], "after", state)


def test_atualizacao_continua_exigindo_identidade_conhecida_no_plano():
    with pytest.raises(ValueError, match="readback identity"):
        catalog().readback_calls(role_plan(unknown={"name": True}), [spec()], "after",
                                 state_of("aws_iam_role", "fence", {"name": "fence", "tags": {"ReleaseId": "x"}}))


def admit_case_mutation(mutation):
    plan_, readbacks, matrix, tracked = admission_case()
    victim = readbacks["after"][2]
    if mutation == "chave-extra":
        victim["parameters"] = {}
    if mutation == "operacao":
        victim["operation"] = "delete_role"
    if mutation == "servico":
        victim["service"] = "kms"
    if mutation == "endereco-fora-do-plano":
        victim["address"] = matrix["after"][2]["address"] = "module.iam.aws_iam_role_policy.fantasma[0]"
    if mutation == "tipo-fora-do-catalogo":
        plan_["resource_changes"].append(change("aws_kms_key.k", {"name": "k"}, {"name": "k"}))
        victim["address"] = matrix["after"][2]["address"] = "aws_kms_key.k"
    return plan_, readbacks, matrix, tracked


@pytest.mark.parametrize("mutation,message", [
    ("chave-extra", "closed object fields"), ("operacao", "read-only API boundary"),
    ("servico", "read-only API boundary"), ("endereco-fora-do-plano", "readback address"),
    ("tipo-fora-do-catalogo", "identity type")])
def test_admissao_pre_acquire_valida_toda_spec_do_after(mutation, message):
    plan_, readbacks, matrix, _ = admit_case_mutation(mutation)
    with pytest.raises(ValueError, match=message):
        catalog().admit_stages(plan_, readbacks, matrix, set())


def test_admissao_recusa_spec_extra_do_fence_com_outra_operacao():
    plan_, readbacks, matrix, tracked = admission_case()
    readbacks["after"].append(spec(FENCE_ROLE, "get_role_policy"))
    matrix["after"].append(matrix["after"][0] | {"readback": 3})
    with pytest.raises(ValueError, match="fence readback"):
        catalog().admit_stages(plan_, readbacks, matrix, tracked)


def admit_one(plan_, one, stage):
    row = [{"address": one["address"], "attribute": "name", "readback": 0, "path": ["x"], "encoding": "identity"}]
    readbacks = {"before": [], "after": []} | {stage: [one]}
    matrix = {"before": [], "after": []} | {stage: row}
    return catalog().admit_stages(plan_, readbacks, matrix, set())


def test_spec_de_after_em_endereco_removido_e_recusada_antes_do_acquire():
    deleted = role_plan(after=None, actions=("delete",))
    deleted["resource_changes"][0]["change"]["after"] = None
    with pytest.raises(ValueError, match="readback absent after"):
        admit_one(deleted, spec(), "after")
    assert admit_one(deleted, spec(), "before") is None


def test_spec_de_before_em_endereco_criado_e_recusada_antes_do_acquire():
    created = role_plan(actions=("create",))
    created["resource_changes"][0]["change"]["before"] = None
    with pytest.raises(ValueError, match="readback absent before"):
        admit_one(created, spec(), "before")
    assert admit_one(created, spec(), "after") is None


@pytest.mark.parametrize("value", ["", 7, None, ["fence"]])
@pytest.mark.parametrize("actions", [("update",), ("create",)])
def test_identidade_conhecida_do_after_tem_de_ser_str_nao_vazia(actions, value):
    bad = role_plan(before={"name": value, "tags": {}}, after={"name": value, "tags": {}}, actions=actions)
    if actions == ("create",):
        bad["resource_changes"][0]["change"]["before"] = None
    with pytest.raises(ValueError, match="readback identity"):
        admit_one(bad, spec(), "after")


@pytest.mark.parametrize("value", ["", 7, None, ["fence"]])
def test_identidade_do_before_tem_de_ser_str_nao_vazia(value):
    with pytest.raises(ValueError, match="readback identity"):
        admit_one(role_plan(before={"name": value, "tags": {}}, after={"name": value, "tags": {}}), spec(), "before")


def test_relaxacao_de_criacao_nao_vale_para_spec_de_before():
    replaced = role_plan(before={"tags": {}}, after={"name": "novo", "tags": {}}, actions=("delete", "create"))
    with pytest.raises(ValueError, match="readback identity"):
        admit_one(replaced, spec(), "before")
    assert admit_one(replaced, spec(), "after") is None
