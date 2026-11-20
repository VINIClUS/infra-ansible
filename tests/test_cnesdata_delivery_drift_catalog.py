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


def test_identidade_pode_mudar_na_substituicao_mas_nao_pode_ser_desconhecida():
    mapa = catalog()
    replaced = role_plan(after={"name": "novo", "tags": {}}, actions=("delete", "create"))
    assert mapa.readback_calls(replaced, [spec()], "before")[0]["parameters"] == {"RoleName": "fence"}
    with pytest.raises(ValueError, match="readback identity"):
        mapa.readback_calls(role_plan(actions=("delete", "create"), unknown={"name": True}), [spec()], "before")


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
