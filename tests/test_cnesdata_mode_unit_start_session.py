"""P16b Q1 (c-1125-p16b-repin item 2): the ux keys from the vendored unit-start builders, inside the mode_dispatch grant."""
import datetime
import json
import pathlib

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.iam_boundary import effective_iam

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
ROLES = json.loads((FIXTURES / "cnesdata_mode_roles.json").read_text())
VECTOR = json.loads((FIXTURES / "cnesdata_mode_canary_frames_vector.json").read_text())
DISPATCH = {case["name"]: case for case in VECTOR["dispatch"]["cases"]}
RESOURCES = ROLES["fields"]["resources"]
ROLE = ROLES["roles"]["mode_dispatch"]["policy"]["PolicyDocument"]
OWNER = "a" * 64
UNIT_RUN = "unit-" + OWNER[:16]
TABLE = RESOURCES["table_arn"].rsplit("/", 1)[1]
TENANT = "TENANT#" + RESOURCES["scope"]["tenant_id"].encode().hex()
RUN = TENANT + "#RUN#" + UNIT_RUN.encode().hex()
OTHER_RUN = TENANT + "#RUN#" + ("recovery-a-" + OWNER[:16]).encode().hex()
FOREIGN = "TENANT#" + ("prod-canary-" + "f" * 32).encode().hex()
FENCE, SEMAPHORE, ATTEMPTS = "ENV#prod#FENCE", "ENV#prod#SEMAPHORE", "ENV#prod#ATTEMPTS"
DEADLINE = int(c.instant(ROLES["fields"]["enabled_until"])) - 600
NOW = c.utc(DEADLINE - 300)
DERIVED = {"dynamodb:GetItem": {TENANT, RUN, FENCE, SEMAPHORE}, "dynamodb:PutItem": {TENANT, RUN},
           "dynamodb:ConditionCheckItem": {TENANT, RUN, FENCE}, "dynamodb:UpdateItem": {SEMAPHORE, ATTEMPTS}}
ACTIONS = ("GetItem", "PutItem", "UpdateItem", "ConditionCheckItem", "Query", "DeleteItem", "BatchGetItem", "BatchWriteItem",
           "Scan")
PROBE_KEYS = (TENANT, RUN, OTHER_RUN, FOREIGN, FENCE, SEMAPHORE, ATTEMPTS, "OUTBOX#CURSOR", "ENV#prod#OTHER")
STEPS = ("reserve", "admit", "claim", "bind", "confirm")


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _session():
    from tools.cnesdata_delivery import session_policy
    return session_policy.mode_session_policy("unit-start", resources=RESOURCES, owner_sha256=OWNER, deadline=DEADLINE)


def _effective(policy, action, key, at=NOW):
    return effective_iam(ROLE, [policy], "dynamodb:" + action, RESOURCES["table_arn"],
                         {"aws:CurrentTime": at, "dynamodb:LeadingKeys": [key]})


def _locator(case, **changes):
    value = case["locator"] | changes
    return _mb().UnitLocator(value["tenant_id"], tuple(value["run_ids"]), value["owner_sha256"], value["record_sha256"],
                             value["phase"], value["context_kind"])


def _targets(case, locator=None, units=None, table=None):
    return _mb().unit_start_targets(locator or _locator(case), case["units"] if units is None else units,
                                    table=table or case["table"], now=datetime.datetime.fromisoformat(case["now"]))


def _requests(case):
    return [tuple(request) for step in STEPS for request in case["result"]["requests"][step]]


def _frame_targets(case, table):
    frames = _mb().product_frames()
    locator, result = case["locator"], case["result"]
    owner, tenant = locator["owner_sha256"], frames.tenant_partition(locator["tenant_id"])
    holder = _mb().UnitHolder(result["dispatch_id"], locator["run_ids"][0], locator["tenant_id"])
    effect = frames.effect_id(locator["record_sha256"], "start-execution", frames.start_request(holder, result["unit_ids"]))
    run = tenant + "#RUN#" + locator["run_ids"][0].encode().hex()
    return {("GetItem", table, tenant, frames.record_key(owner, "unit")), ("GetItem", table, tenant, frames.control_key(owner)),
            ("GetItem", table, tenant, frames.ticket_key(owner, effect)), ("PutItem", table, tenant, frames.control_key(owner)),
            ("PutItem", table, tenant, frames.ticket_key(owner, effect)),
            ("PutItem", table, run, "PROD_CANARY#" + result["dispatch_id"])}


def _rekeyed(case, tenant_id, run_id, rename=None):
    rename = rename or {}
    return [unit | {"tenant_id": tenant_id, "run_id": run_id, "unit_id": rename.get(unit["unit_id"], unit["unit_id"]),
                    "depends_on_unit_ids": [rename.get(item, item) for item in unit["depends_on_unit_ids"]]}
            for unit in case["units"]]


@pytest.mark.parametrize("name", sorted(DISPATCH))
def test_alvos_derivados_sao_os_requests_do_vetor_mais_os_frames_e_as_leituras_do_contexto(name):
    case = DISPATCH[name]
    start, effect, targets = _targets(case)
    requests = set(_mb().product_dispatch().request_targets(_requests(case)))
    assert requests | _frame_targets(case, case["table"]) == set(targets) and not requests & _frame_targets(case, case["table"])
    assert start.dispatch.dispatch_id == case["result"]["dispatch_id"] and list(start.dispatch.unit_ids) == case["result"]["unit_ids"]
    assert start.lease_seconds == 3600 and start.promotion_id == case["locator"]["owner_sha256"]


def test_gate_do_vetor_e_a_uniao_dos_alvos_de_requests_derivados_nos_tres_casos():
    found = set()
    for case in DISPATCH.values():
        found |= set(_targets(case)[2]) - _frame_targets(case, case["table"])
    assert found == {tuple(target) for target in VECTOR["dispatch"]["gate"]}


def test_alvos_seguem_o_tenant_o_run_e_as_unidades_do_estagio_e_nao_o_gate_do_vetor():
    case, tenant = DISPATCH["producao"], RESOURCES["scope"]["tenant_id"]
    rename = {unit["unit_id"]: format(index, "032x") for index, unit in enumerate(case["units"], start=7)}
    locator = _locator(case, tenant_id=tenant, run_ids=[UNIT_RUN], owner_sha256=OWNER, record_sha256="5" * 64)
    _, _, targets = _targets(case, locator, _rekeyed(case, tenant, UNIT_RUN, rename), TABLE)
    gate = {tuple(target) for target in VECTOR["dispatch"]["gate"]}
    assert not set(targets) & gate and {pk for _, _, pk, _ in targets} == {TENANT, RUN, FENCE, SEMAPHORE, ATTEMPTS}
    units = {sk for _, _, pk, sk in targets if sk.startswith("UNIT#")}
    assert units == {"UNIT#" + rename[unit_id].encode().hex() for unit_id in case["result"]["unit_ids"]}


@pytest.mark.parametrize("name, month", [("fim-do-mes", "MONTH#2026-12"), ("inicio-do-mes", "MONTH#2027-01"),
                                         ("producao", "MONTH#2026-11")])
def test_mes_do_attempts_e_o_do_relogio_do_estagio_e_nao_o_do_lease(name, month):
    start, _, targets = _targets(DISPATCH[name])
    months = {sk for action, _, pk, sk in targets if pk == ATTEMPTS}
    assert months == {month} and {action for action, _, pk, _ in targets if pk == ATTEMPTS} == {"UpdateItem"}
    lease = start.now + datetime.timedelta(seconds=start.lease_seconds)
    assert (name != "fim-do-mes") or f"MONTH#{lease.year:04d}-{lease.month:02d}" != month


def test_concorrencia_do_start_e_a_constante_vendorizada_de_producao():
    start = _targets(DISPATCH["producao"])[0]
    assert len(start.dispatch.unit_ids) == 2 and start.dispatch.max_concurrency == 1
    assert _mb().product_dispatch().PRODUCTION_MAX_CONCURRENCY == 1


def test_projecao_por_particao_vem_dos_construtores_e_nao_depende_das_unidades():
    case, tenant = DISPATCH["producao"], RESOURCES["scope"]["tenant_id"]
    locator = _locator(case, tenant_id=tenant, run_ids=[UNIT_RUN], owner_sha256=OWNER, record_sha256="5" * 64)
    projected = {}
    for action, _, pk, _ in _targets(case, locator, _rekeyed(case, tenant, UNIT_RUN), TABLE)[2]:
        projected.setdefault("dynamodb:" + action, set()).add(pk)
    grants = _mb().unit_start_grants(RESOURCES, OWNER)
    assert {action: set(keys) for action, keys in grants.items()} == projected == DERIVED


@pytest.mark.parametrize("action", ACTIONS)
def test_dynamodb_do_ux_tem_o_efeito_exato_dos_alvos_derivados_sobre_o_papel(action):
    session = _session()
    for key in PROBE_KEYS:
        assert _effective(session, action, key) is (key in DERIVED.get("dynamodb:" + action, set())), (action, key)
        assert _effective(session, action, key, c.utc(DEADLINE)) is False


def test_cada_alvo_derivado_esta_no_grant_do_mode_dispatch():
    for action, keys in DERIVED.items():
        for key in keys:
            assert effective_iam(ROLE, [ROLE], action, RESOURCES["table_arn"],
                                 {"aws:CurrentTime": NOW, "dynamodb:LeadingKeys": [key]}), (action, key)


def _separate(session):
    statements = [statement for statement in session["Statement"] if not any(
        action.startswith("dynamodb:") for action in statement["Action"])]
    expiry = {"DateLessThan": {"aws:CurrentTime": c.utc(DEADLINE)}}
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": [action], "Resource": RESOURCES["table_arn"],
         "Condition": expiry | {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": sorted(keys)},
                                "Null": {"dynamodb:LeadingKeys": "false"}}} for action, keys in sorted(DERIVED.items())]
        + statements}


def test_fundir_declaracoes_do_ux_nao_muda_a_permissao_efetiva_do_papel():
    """Ruling 5 item 3 (1): effective(role and merged) equals effective(role and one statement per action)."""
    session = _session()
    separate = _separate(session)
    dynamodb = [statement for statement in session["Statement"] if statement["Action"][0].startswith("dynamodb:")]
    assert len(dynamodb) == 2 and dynamodb[1]["Action"] == ["dynamodb:UpdateItem"]
    for at in (NOW, c.utc(DEADLINE)):
        for action in ACTIONS:
            for key in PROBE_KEYS:
                assert _effective(session, action, key, at) is _effective(separate, action, key, at), (action, key, at)


def test_ux_fundido_cabe_no_limite_de_2048_do_sts_e_o_por_acao_nao():
    session = _session()
    assert len(c.canonical(session).decode().strip()) <= 2048 < len(c.canonical(_separate(session)).decode().strip())


@pytest.mark.parametrize("action, key", [("ConditionCheckItem", SEMAPHORE), ("Query", RUN), ("UpdateItem", TENANT),
                                         ("UpdateItem", RUN), ("PutItem", FENCE), ("DeleteItem", RUN),
                                         ("ConditionCheckItem", OTHER_RUN), ("PutItem", FOREIGN)],
                         ids=["cancel-reserved", "query-run", "update-tenant", "update-run", "put-fence", "delete-run",
                              "check-outro-run", "put-tenant-alheio"])
def test_ux_nega_o_que_o_caminho_nativo_do_unit_nao_usa(action, key):
    assert _effective(_session(), action, key) is False


@pytest.mark.parametrize("action, key", [("Query", RUN), ("UpdateItem", TENANT), ("UpdateItem", RUN),
                                         ("ConditionCheckItem", OTHER_RUN), ("PutItem", OTHER_RUN)])
def test_papel_concede_o_que_o_ux_estreita(action, key):
    assert effective_iam(ROLE, [ROLE], "dynamodb:" + action, RESOURCES["table_arn"],
                         {"aws:CurrentTime": NOW, "dynamodb:LeadingKeys": [key]})
