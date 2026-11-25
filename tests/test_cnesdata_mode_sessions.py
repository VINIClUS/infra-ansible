"""P16b ruling 4 item 1: mode session policies, scoped by the vendored vector and strict subsets of the role grants."""
import json
import pathlib

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.iam_boundary import effective_iam

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
ROLES = json.loads((FIXTURES / "cnesdata_mode_roles.json").read_text())
VECTOR = json.loads((FIXTURES / "cnesdata_mode_canary_frames_vector.json").read_text())
RESOURCES = ROLES["fields"]["resources"]
OWNER = "a" * 64
CANARY = "0123456789abcdef0123456789abcdef"
ENABLED = int(c.instant(ROLES["fields"]["enabled_until"]))
DEADLINE = ENABLED - 600
NOW = c.utc(DEADLINE - 300)
TENANT = "TENANT#" + RESOURCES["scope"]["tenant_id"].encode().hex()
OPERATIONS = [name for name, entry in lc.MODE_SESSION_OPERATIONS.items() if entry[2] == "promotion"]
PRODUCT_SEED_RUN_PREFIXES = {"unit": ("unit",), "recovery": ("recovery-a", "recovery-b")}
DYNAMODB = {"get": "dynamodb:GetItem", "put": "dynamodb:PutItem"}
VECTOR_ACTIONS = {"Put": "dynamodb:PutItem", "Update": "dynamodb:UpdateItem", "ConditionCheck": "dynamodb:ConditionCheckItem",
                  "Delete": "dynamodb:DeleteItem"}
CLUSTER = {"ecs:cluster": RESOURCES["cluster_arn"]}
PASSED = {"iam:PassedToService": "ecs-tasks.amazonaws.com"}
TASK = RESOURCES["cluster_arn"].replace(":cluster/", ":task/") + "/" + "f" * 32
EXECUTION = RESOURCES["machine_arn"].replace(":stateMachine:", ":execution:") + ":probe"


def _sp():
    from tools.cnesdata_delivery import session_policy
    return session_policy


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _session(operation, resources=None, owner=OWNER, deadline=DEADLINE):
    return _sp().mode_session_policy(operation, resources=RESOURCES if resources is None else resources,
                                     owner_sha256=owner, deadline=deadline)


def _role(operation):
    return ROLES["roles"][lc.MODE_SESSION_OPERATIONS[operation][1]]["policy"]["PolicyDocument"]


def _allowed(operation, action, resource, context=None, at=NOW):
    return effective_iam(_role(operation), [_session(operation)], action, resource, {"aws:CurrentTime": at} | (context or {}))


def _role_allows(operation, action, resource, context=None, at=NOW):
    role = _role(operation)
    return effective_iam(role, [role], action, resource, {"aws:CurrentTime": at} | (context or {}))


def _phase(operation):
    return lc.MODE_SESSION_OPERATIONS[operation][3]


def _run(name):
    return TENANT + "#RUN#" + name.encode().hex()


def _mode_runs(operation):
    return [run for run in RESOURCES["scope"]["run_ids"]
            if any(run == f"{prefix}-{OWNER[:16]}" for prefix in PRODUCT_SEED_RUN_PREFIXES[_phase(operation)])]


def _dynamodb(policy):
    found = {}
    for statement in policy["Statement"]:
        actions = [statement["Action"]] if type(statement["Action"]) is str else statement["Action"]
        for action in actions:
            if action.startswith("dynamodb:"):
                keys = statement["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"]
                found.setdefault(action, set()).update(keys)
    return found


def _vector_writes(names):
    writes = set()
    for case in VECTOR["cases"]:
        result = case.get("result")
        if case["name"] not in names or not isinstance(result, dict):
            continue
        items = result.get("items") or ([{"Put": result}] if "Item" in result else [])
        for item in items:
            (operation, body), = item.items()
            writes.add((VECTOR_ACTIONS[operation], (body.get("Item") or body["Key"])["pk"]["S"]))
    return writes


def test_produto_semeia_os_runs_com_os_prefixos_do_modo():
    """Labelled literal of CnesData develop 1d0054c8 scripts/promotion/mode_canary_seed.py:39 _RUN_PREFIXES
    (sha256 6fb83a43a783e2532f897e3ae855ab6d156dfc58cc766789c09cd5974ed09c63), split by the seed operation phase."""
    assert _sp().MODE_SEED_RUN_PREFIXES == PRODUCT_SEED_RUN_PREFIXES


def test_papeis_vem_do_construtor_do_produto_sobre_o_mesmo_mode_input():
    """Provenance of the mode-roles fixture: product _documents over these fields, account 111122223333 only."""
    assert ROLES["source"] == {"repository": "CnesData", "commit": "1d0054c87501de3bbc5f55cfa618b4f54124c55f",
                               "path": "scripts/promotion/prepare_mode_canary.py", "builder": "_documents",
                               "sha256": "6bde6b649cc5b369b3d918ba4a3a1fb7d90aa426298df1b3c8fdc14a50fc48a5"}
    assert set(ROLES["roles"]) == set(lc.MODE_ALIASES)
    assert {_run(run) for run in RESOURCES["scope"]["run_ids"]} >= {pk for _, pk in _vector_writes({"dispatch-unit"})} - {TENANT}


def test_sessao_existe_para_as_oito_operacoes_de_promotion_e_nao_para_o_drill():
    assert len(OPERATIONS) == 8
    for operation in OPERATIONS:
        assert _session(operation)["Version"] == "2012-10-17"
    for operation in ("drill-seed", "drill-unit-start", "drill-observe", "unit", None):
        with pytest.raises(ValueError, match="^mode session operation$"):
            _session(operation)


def test_ux_grava_o_frame_dispatch_unit_por_put_e_leva_as_acoes_do_caminho_nativo_do_unit():
    """Q1: the dispatch-unit control CAS is a conditional Put; UpdateItem is the SEMAPHORE/ATTEMPTS native path only."""
    writes = _vector_writes({"dispatch-unit"})
    assert {action for action, _ in writes} == {"dynamodb:PutItem"}
    assert set(_dynamodb(_session("unit-start"))) == {"dynamodb:ConditionCheckItem", "dynamodb:GetItem", "dynamodb:PutItem",
                                                      "dynamodb:UpdateItem"}
    assert _dynamodb(_session("unit-start"))["dynamodb:UpdateItem"] == {"ENV#prod#ATTEMPTS", "ENV#prod#SEMAPHORE"}


@pytest.mark.parametrize("operation, cases", [("recovery-start", {"ledger-admit", "ledger-unknown", "ledger-settle"})])
def test_chaves_de_escrita_da_sessao_sao_as_particoes_dos_itens_do_vetor(operation, cases):
    writes = _vector_writes(cases)
    assert writes and _dynamodb(_session(operation))["dynamodb:PutItem"] == {pk for _, pk in writes}


@pytest.mark.parametrize("operation, cases", [("recovery-start", {"ledger-admit", "ledger-unknown", "ledger-settle"})])
def test_leitura_forte_do_ledger_fica_na_particao_do_tenant(operation, cases):
    assert _dynamodb(_session(operation))["dynamodb:GetItem"] == {TENANT}


@pytest.mark.parametrize("operation", ["unit-seed", "recovery-seed"])
def test_seed_grava_o_record_do_vetor_e_as_particoes_dos_runs_do_proprio_modo(operation):
    record = next(case for case in VECTOR["cases"] if case["name"] == "record-item")["result"]["pk"]["S"]
    keys = _dynamodb(_session(operation))
    assert keys == {"dynamodb:GetItem": {record} | {_run(run) for run in _mode_runs(operation)},
                    "dynamodb:PutItem": {record} | {_run(run) for run in _mode_runs(operation)}}
    assert record == TENANT and len(_mode_runs(operation)) == (1 if _phase(operation) == "unit" else 2)


def _sample_key(family, binding, run):
    owner = binding["owner_sha256"]
    tenant = "TENANT#" + ("prod-canary-" + binding["canary_id"]).encode().hex()
    samples = {"control": (tenant, f"PROD_CANARY_CONTROL#{owner}"), "ticket": (tenant, f"PROD_CANARY_EFFECT#{owner}#" + "b" * 64),
               "seed-run": (tenant, "RUN#" + run.encode().hex()),
               "seed-raw": (tenant, "RAW_MANIFEST#" + ("manifest-" + owner[:16]).encode().hex()),
               "seed-unit": (tenant + "#RUN#" + run.encode().hex(), "UNIT#" + ("c" * 32).encode().hex()),
               "binding": (tenant + "#RUN#" + run.encode().hex(), "PROD_CANARY#" + str(binding["dispatch_id"]))}
    if family.startswith("record-"):
        return tenant, f"PROD_CANARY#{owner}#" + family.removeprefix("record-")
    return samples[family]


@pytest.mark.parametrize("operation", ["unit-seed", "recovery-seed", "unit-start", "recovery-start"])
def test_papel_e_sessao_admitem_cada_chave_que_o_fence_c1_admite_nos_frames_da_operacao(operation):
    """Liveness: an over-narrowed session would surface only as AccessDenied on the first real run."""
    frames = _sp().MODE_SESSION_FRAMES[operation]
    checked = 0
    for frame in frames:
        binding = {"canary_id": CANARY, "owner_sha256": OWNER, "run_ids": _mode_runs(operation),
                   "dispatch_id": "1a2b3c4d5e6f7a8b" if frame == "dispatch-unit" else None}
        for family, action in sorted(_mb().MODE_KEY_FRAMES[frame]):
            for run in binding["run_ids"]:
                key = _sample_key(family, binding, run)
                assert _mb().admit_mode_key(frame, action, key, binding=binding) == family
                assert _allowed(operation, DYNAMODB[action], RESOURCES["table_arn"], {"dynamodb:LeadingKeys": [key[0]]})
                checked += 1
    assert checked > 0 and set(frames) <= set(_mb().MODE_KEY_FRAMES)



BROAD = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def test_sessao_sob_papel_amplo_nega_pedido_dynamodb_sem_leading_keys():
    """NIT 6: under Allow *, every DynamoDB statement of every mode session allows its own leading key and, by its
    own Null guard, denies the same request without dynamodb:LeadingKeys."""
    covered = set()
    for operation in OPERATIONS:
        for statement in _session(operation)["Statement"]:
            if not statement["Action"][0].startswith("dynamodb:"):
                continue
            covered.add(operation)
            key = statement["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"][0]
            for action in statement["Action"]:
                now = {"aws:CurrentTime": NOW}
                assert effective_iam(BROAD, [_session(operation)], action, RESOURCES["table_arn"],
                                     now | {"dynamodb:LeadingKeys": [key]}), (operation, action)
                assert not effective_iam(BROAD, [_session(operation)], action, RESOURCES["table_arn"], now), (
                    operation, action)
    assert {"unit-start", "unit-seed", "recovery-start"} <= covered

def _calls(operation):
    """Labelled literal of CnesData develop 06849119 scripts/promotion/_adapter_abi.py (sha256 1b0fd24e1e777...):
    MODE_EFFECT_CALLS per operation; the unit-start keeper steps unit-execution and unit-task run under the ux wait
    part (ruling 5 item 3 (2))."""
    phase, data = _phase(operation), RESOURCES["data_bucket_arn"]
    if operation.endswith("-seed"):
        return [(action, data + "/" + key, {}) for key in RESOURCES["scope"]["raw_object_keys"]
                for action in ("s3:PutObject", "s3:GetObject")]
    if operation == "unit-start":
        return [("states:StartExecution", RESOURCES["machine_arn"], {})]
    if operation.endswith("-start"):
        return [("ecs:RunTask", RESOURCES["revisions"][phase], CLUSTER), ("ecs:DescribeTasks", TASK, CLUSTER),
                ("iam:PassRole", RESOURCES["task_role_arns"][phase], PASSED), ("iam:PassRole", RESOURCES["execution_role_arn"], PASSED)]
    reads = {"describe_state_machine": ("states:DescribeStateMachine", lambda _: RESOURCES["machine_arn"]),
             "get_schedule": ("scheduler:GetSchedule", lambda mode: RESOURCES["schedule_arns"][mode]),
             "describe_task_definition": ("ecs:DescribeTaskDefinition", lambda mode: RESOURCES["revisions"][mode]),
             "describe_alarms": ("cloudwatch:DescribeAlarms", lambda mode: RESOURCES["alarm_arns"][mode + "_repeated_failure"])}
    calls = [(reads[call["operation"]][0], reads[call["operation"]][1](phase), {})
             for call in _mb().mode_readback_calls(phase, RESOURCES)]
    return calls + ([("s3:GetObject", data + "/" + key, {}) for key in RESOURCES["scope"]["output_object_keys"]]
                    if phase == "unit" else [])


@pytest.mark.parametrize("operation", OPERATIONS)
def test_papel_e_sessao_admitem_cada_chamada_nativa_da_operacao(operation):
    for action, resource, context in _calls(operation):
        assert _allowed(operation, action, resource, context), (action, resource)


def _probes(policy):
    for statement in policy["Statement"]:
        actions = [statement["Action"]] if type(statement["Action"]) is str else statement["Action"]
        resources = [statement["Resource"]] if type(statement["Resource"]) is str else statement["Resource"]
        condition = statement.get("Condition", {})
        context = {}
        context |= CLUSTER if "ArnEquals" in condition else {}
        context |= PASSED if "StringEquals" in condition else {}
        keys = condition.get("ForAllValues:StringEquals", {}).get("dynamodb:LeadingKeys", [None])
        for action in actions:
            for resource in resources:
                concrete = resource.replace(":*", ":probe").replace("/*", "/" + "f" * 32)
                concrete = RESOURCES["revisions"]["unit"] if concrete == "*" else concrete
                for key in keys:
                    yield action, concrete, context | ({"dynamodb:LeadingKeys": [key]} if key else {})


def _wait(deadline=DEADLINE):
    return _sp().mode_unit_wait_policy(resources=RESOURCES, deadline=deadline)


def test_papel_e_espera_do_ux_admitem_as_etapas_unit_execution_e_unit_task():
    for action, resource, context in (("states:DescribeExecution", EXECUTION, {}), ("ecs:DescribeTasks", TASK, CLUSTER)):
        assert effective_iam(_role("unit-start"), [_wait()], action, resource, {"aws:CurrentTime": NOW} | context)


def test_cada_permissao_da_espera_do_ux_esta_na_concessao_do_papel():
    probes = list(_probes(_wait()))
    assert probes
    for action, resource, context in probes:
        assert _role_allows("unit-start", action, resource, context), (action, resource, context)


@pytest.mark.parametrize("change", [{"machine_arn": "arn:aws:states:us-east-1:111122223333:stateMachine:cnesdata-prod-processing"},
                                    {"cluster_arn": "arn:aws:ecs:us-east-2:111122223333:cluster/*"}],
                         ids=["maquina-de-outra-regiao", "cluster-curinga"])
def test_espera_do_ux_recusa_recursos_fora_da_forma(change):
    with pytest.raises(ValueError, match="^mode session resources$"):
        _sp().mode_unit_wait_policy(resources=RESOURCES | change, deadline=DEADLINE)


@pytest.mark.parametrize("operation", OPERATIONS)
def test_cada_permissao_da_sessao_esta_na_concessao_do_papel(operation):
    probes = list(_probes(_session(operation)))
    assert probes
    for action, resource, context in probes:
        assert _role_allows(operation, action, resource, context), (action, resource, context)
        assert _allowed(operation, action, resource, context), (action, resource, context)


@pytest.mark.parametrize("operation, action, resource, context", [
    ("unit-seed", "dynamodb:PutItem", RESOURCES["table_arn"], {"dynamodb:LeadingKeys": [_run("recovery-a-" + OWNER[:16])]}),
    ("recovery-seed", "dynamodb:PutItem", RESOURCES["table_arn"], {"dynamodb:LeadingKeys": [_run("unit-" + OWNER[:16])]}),
    ("unit-start", "dynamodb:UpdateItem", RESOURCES["table_arn"], {"dynamodb:LeadingKeys": [TENANT]}),
    ("unit-start", "dynamodb:Query", RESOURCES["table_arn"], {"dynamodb:LeadingKeys": [_run("unit-" + OWNER[:16])]}),
    ("unit-start", "ecs:RunTask", RESOURCES["revisions"]["recovery"], CLUSTER),
    ("unit-start", "states:StopExecution", EXECUTION, {}),
    ("recovery-start", "states:StartExecution", RESOURCES["machine_arn"], {}),
    ("recovery-start", "dynamodb:PutItem", RESOURCES["table_arn"], {"dynamodb:LeadingKeys": [_run("recovery-a-" + OWNER[:16])]}),
    ("recovery-start", "ecs:StopTask", TASK, CLUSTER),
    ("audit-start", "ecs:RunTask", RESOURCES["revisions"]["audit"], CLUSTER, ),
    ("unit-observe", "scheduler:GetSchedule", RESOURCES["schedule_arns"]["recovery"], {}),
    ("unit-observe", "dynamodb:GetItem", RESOURCES["table_arn"], {"dynamodb:LeadingKeys": [TENANT]}),
    ("recovery-observe", "scheduler:GetSchedule", RESOURCES["schedule_arns"]["audit"], {}),
    ("recovery-observe", "s3:GetObject", RESOURCES["data_bucket_arn"] + "/" + RESOURCES["scope"]["output_object_keys"][0], {}),
    ("audit-observe", "cloudwatch:DescribeAlarms", RESOURCES["alarm_arns"]["recovery_repeated_failure"], {}),
    ("audit-observe", "states:DescribeExecution", EXECUTION, {})],
    ids=["us-run-recovery", "rs-run-unit", "ux-update", "ux-query-run", "ux-run-task", "ux-stop-execution", "rx-start-execution",
         "rx-run-partition", "rx-stop-task", "ax-expirado", "uo-schedule", "uo-dynamodb", "ro-schedule-audit", "ro-output",
         "ao-alarm-recovery", "ao-execution"])
def test_sessao_e_subconjunto_estrito_do_papel(operation, action, resource, context):
    at = c.utc(DEADLINE) if operation == "audit-start" else NOW
    assert _role_allows(operation, action, resource, context, at)
    assert not _allowed(operation, action, resource, context, at)


@pytest.mark.parametrize("operation", OPERATIONS)
def test_toda_sessao_vence_no_prazo_mesmo_com_o_papel_ainda_habilitado(operation):
    action, resource, context = next(_probes(_session(operation)))
    assert _role_allows(operation, action, resource, context, c.utc(DEADLINE))
    assert not _allowed(operation, action, resource, context, c.utc(DEADLINE))
    assert c.canonical(_session(operation)) != c.canonical(_role(operation))


def _change(path, value):
    resources = json.loads(json.dumps(RESOURCES))
    node = resources
    for key in path[:-1]:
        node = node[key]
    if value is None:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return resources


@pytest.mark.parametrize("path, value", [
    (("index_arn",), None), (("extra",), "x"), (("scope", "audit_object_keys"), None), (("revisions", "other"), "x"),
    (("table_arn",), "arn:aws:dynamodb:us-east-2:111122223333:table/other"), (("machine_arn",), "*"),
    (("cluster_arn",), "arn:aws:ecs:us-east-2:111122223333:service/x"), (("data_bucket_arn",), "arn:aws:s3:::other"),
    (("execution_role_arn",), "arn:aws:iam::111122223333:user/x"), (("scope", "tenant_id"), "Prod_Canary"),
    (("scope", "raw_object_keys"), []), (("scope", "raw_object_keys"), ["a", "a"]), (("scope", "output_object_keys"), ["a*"]),
    (("revisions", "recovery"), "arn:aws:ecs:us-east-2:111122223333:task-definition/x"),
    (("task_role_arns", "audit"), 7), (("scope", "audit_object_keys"), ["a*"])],
    ids=["sem-index", "campo-extra", "sem-audit-keys", "modo-extra", "tabela-alheia", "maquina-curinga", "cluster-invalido",
         "bucket-alheio", "role-invalida", "tenant-invalido", "raw-vazio", "raw-duplicado", "output-curinga",
         "revisao-sem-numero", "task-role-nao-texto", "audit-curinga"])
def test_sessao_recusa_recursos_fora_da_forma_do_mode_input(path, value):
    with pytest.raises(ValueError, match="^mode session resources$"):
        _session("unit-start", _change(path, value))


@pytest.mark.parametrize("operation", ["unit-seed", "recovery-seed", "unit-start"])
def test_sessao_recusa_escopo_sem_run_do_proprio_modo_e_owner(operation):
    runs = [run for run in RESOURCES["scope"]["run_ids"] if run not in _mode_runs(operation)]
    with pytest.raises(ValueError, match="^mode session runs$"):
        _session(operation, _change(("scope", "run_ids"), runs))
    with pytest.raises(ValueError, match="^mode session runs$"):
        _session(operation, owner="b" * 64)


@pytest.mark.parametrize("owner, deadline", [("A" * 64, DEADLINE), ("a" * 63, DEADLINE), (None, DEADLINE),
                                             (OWNER, str(DEADLINE)), (OWNER, True), (OWNER, -1)])
def test_sessao_recusa_owner_ou_prazo_fora_da_forma(owner, deadline):
    with pytest.raises(ValueError):
        _session("recovery-start", owner=owner, deadline=deadline)
