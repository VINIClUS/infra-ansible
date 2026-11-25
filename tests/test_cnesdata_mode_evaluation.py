"""P16b ruling 4 item 2: mode-evaluation.json in the fence-evaluation shape, built at prepare and recomputed at stage."""
import copy
import json
import pathlib

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

ROLES = json.loads((pathlib.Path(__file__).resolve().parent / "fixtures" / "cnesdata_mode_roles.json").read_text())
RESOURCES = ROLES["fields"]["resources"]
OWNER = "a" * 64
DEADLINE = int(c.instant(ROLES["fields"]["enabled_until"])) - 600
OBSERVED = c.utc(DEADLINE - 300)
CODES = {code: (operation, alias) for operation, (code, alias, context, _) in lc.MODE_SESSION_OPERATIONS.items()
         if context == "promotion"}
NAMES = {name.split("-")[1]: name for names in ROLES["fields"]["delegation_sessions"].values() for name in names}
ROLE_ARNS = {alias: ROLES["roles"][alias]["role"]["Role"]["Arn"] for alias in lc.MODE_ALIASES}
PARTS = {"uw": "ux"}
SCOPE = {"resources": RESOURCES, "owner_sha256": OWNER, "role_arns": ROLE_ARNS, "session_names": NAMES, "deadline": DEADLINE}
GOVERNANCE = {"account_id": "111122223333", "state_bucket": "synthetic-state", "evidence_bucket": "synthetic-evidence",
              "evidence_prefix": "cnesdata/prod/evidence/", "evidence_kms_key_arn":
              "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-0000-0000-000000000000",
              "roles": {"application": "arn:aws:iam::111122223333:role/cnesdata-prod-application"},
              "application_delegations": ROLE_ARNS}
SYNTHETIC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                     "Resource": sorted(ROLE_ARNS.values())}]}
PROPOSAL_CASES = (
    [f"assume-{code}" for code in CODES] + [f"assume-{code}-other-session" for code in CODES] + [f"{code}-expired" for code in CODES]
    + [f"{code}-{name}" for code in ("us", "rs") for name in ("put-tenant", "put-own-run", "put-raw", "put-foreign-tenant",
                                                               "put-other-mode-run", "get-fence", "put-output")]
    + ["ux-put-ticket", "ux-put-binding", "ux-start-execution", "ux-update-control", "ux-run-task",
       "ux-stop-execution", "ux-put-recovery-run", "ux-check-fence", "ux-update-semaphore", "ux-consume-attempt",
       "ux-check-unit-run", "ux-check-semaphore", "ux-query-unit-run", "ux-update-unit-run", "ux-describe-own-execution"]
    + ["assume-uw", "assume-uw-other-session", "uw-expired", "uw-describe-own-execution", "uw-describe-own-task",
       "uw-describe-foreign-cluster-task", "uw-start-execution"]
    + ["rx-run-recovery", "rx-pass-recovery-role", "rx-put-ticket", "rx-run-audit-revision", "rx-run-other-cluster",
       "rx-pass-unit-role", "rx-put-run-partition", "rx-start-execution"]
    + ["ax-run-audit", "ax-pass-audit-role", "ax-run-recovery-revision", "ax-pass-other-role", "ax-get-tenant"]
    + [f"{code}-{name}" for code in ("uo", "ro", "ao") for name in ("describe-machine", "describe-task-definition",
                                                                     "get-tenant", "get-audit-object")]
    + ["uo-get-output", "ro-get-own-schedule", "ro-describe-own-alarm", "ro-get-audit-schedule", "ro-get-output",
       "ao-get-own-schedule", "ao-describe-own-alarm", "ao-get-recovery-schedule", "ao-get-output"])


def _ib():
    from tools.cnesdata_delivery import iam_boundary
    return iam_boundary


def _documents(codes=tuple(CODES), deadline=DEADLINE):
    """Application identity and managed policy are synthetic; the role policies come from the mode-roles fixture."""
    from tools.cnesdata_delivery import session_policy
    documents = {"application_identity": SYNTHETIC, "application_managed": SYNTHETIC}
    for code in codes:
        operation, alias = CODES[code]
        request = session_policy.application_request(GOVERNANCE, "b" * 40, 44, 1, operation, application_purpose="promotion",
                                                     delegations=[alias], sessions={alias: NAMES[code]})
        documents["application_session." + code] = json.loads(request["Policy"])
        documents["session." + code] = session_policy.mode_session_policy(operation, resources=RESOURCES, owner_sha256=OWNER,
                                                                          deadline=deadline)
        documents["role." + alias] = ROLES["roles"][alias]["policy"]["PolicyDocument"]
    if "ux" in codes:
        documents["session.uw"] = session_policy.mode_unit_wait_policy(resources=RESOURCES, deadline=deadline)
    return documents


def _prepare(documents=None, scope=None, observed=OBSERVED):
    return _ib().mode_effective_evaluation(_documents() if documents is None else documents, SCOPE if scope is None else scope,
                                           evaluator_source_sha="c" * 40, observed_at=observed)


def test_casos_de_modo_sao_os_da_tabela_aceita_no_ruling_4():
    assert len(PROPOSAL_CASES) == len(set(PROPOSAL_CASES)) == 94
    assert set(lc.MODE_EVALUATION_CASES) == set(PROPOSAL_CASES)
    assert all(lc.MODE_EVALUATION_CASES[case][0] in set(CODES) | set(PARTS) for case in PROPOSAL_CASES)
    assert lc.MODE_SESSION_PARTS == PARTS
    assert all(case.startswith(("assume-" + code, code + "-")) for case, (code, _) in lc.MODE_EVALUATION_CASES.items())


def test_avaliacao_de_modo_tem_a_forma_da_fence_evaluation():
    documents = _documents()
    report = _prepare(documents)
    assert set(report) == {"schema_version", "evaluator_source_sha", "documents", "cases"}
    assert report["schema_version"] == 1 and report["evaluator_source_sha"] == "c" * 40
    assert report["documents"] == {name: c.sha(c.canonical(value)) for name, value in documents.items()}
    assert len(report["documents"]) == 23 and set(report["documents"]) == lc.MODE_EVALUATION_DOCUMENTS
    assert "session.uw" in report["documents"] and "application_session.uw" not in report["documents"]
    assert [case["case_id"] for case in report["cases"]] == list(lc.MODE_EVALUATION_CASES)
    for case in report["cases"]:
        assert set(case) == {"case_id", "action", "resource", "context", "expected", "observed"}
        assert case["action"] == lc.MODE_EVALUATION_CASES[case["case_id"]][1] and case["observed"] is case["expected"]
    assert lc.validate_mode_evaluation(report) is None


def _case(report, case_id):
    return next(case for case in report["cases"] if case["case_id"] == case_id)


def test_casos_permitidos_e_negados_seguem_a_tabela():
    report = _prepare()
    allowed = {case["case_id"] for case in report["cases"] if case["expected"]}
    assert allowed == {f"assume-{code}" for code in [*CODES, *PARTS]} | {
        "us-put-tenant", "us-put-own-run", "us-put-raw", "rs-put-tenant", "rs-put-own-run", "rs-put-raw", "ux-put-ticket",
        "ux-put-binding", "ux-start-execution", "uw-describe-own-execution", "uw-describe-own-task", "ux-check-fence",
        "ux-update-semaphore",
        "ux-consume-attempt", "ux-check-unit-run", "rx-run-recovery", "rx-pass-recovery-role",
        "rx-put-ticket", "ax-run-audit", "ax-pass-audit-role", "uo-describe-machine", "uo-describe-task-definition",
        "uo-get-output", "ro-describe-machine", "ro-describe-task-definition", "ro-get-own-schedule", "ro-describe-own-alarm",
        "ao-describe-machine", "ao-describe-task-definition", "ao-get-own-schedule", "ao-describe-own-alarm"}


def test_caso_expirado_e_o_primeiro_caso_permitido_da_sessao_no_prazo():
    report = _prepare()
    first = {"us": "us-put-tenant", "rs": "rs-put-tenant", "ux": "ux-put-ticket", "rx": "rx-run-recovery",
             "ax": "ax-run-audit", "uo": "uo-describe-machine", "ro": "ro-describe-machine", "ao": "ao-describe-machine",
             "uw": "uw-describe-own-execution"}
    for code, case_id in first.items():
        expired, allowed = _case(report, code + "-expired"), _case(report, case_id)
        assert expired["context"] == allowed["context"] | {"aws:CurrentTime": c.utc(DEADLINE)}
        assert (expired["action"], expired["resource"], expired["expected"]) == (allowed["action"], allowed["resource"], False)
        assert allowed["context"]["aws:CurrentTime"] == OBSERVED


def test_casos_de_assume_usam_o_nome_de_sessao_exato_da_operacao():
    report = _prepare()
    for code, (_, alias) in CODES.items():
        exact, other = _case(report, "assume-" + code), _case(report, f"assume-{code}-other-session")
        assert exact["resource"] == other["resource"] == ROLE_ARNS[alias]
        assert exact["context"]["sts:RoleSessionName"] == NAMES[code]
        assert other["context"]["sts:RoleSessionName"] != NAMES[code]


def test_parte_de_espera_assume_o_mesmo_papel_e_nome_do_ux_sem_documento_de_aplicacao_proprio():
    report = _prepare()
    for suffix in ("", "-other-session"):
        part, session = _case(report, f"assume-uw{suffix}"), _case(report, f"assume-ux{suffix}")
        assert {key: part[key] for key in ("action", "resource", "context", "expected")} == {
            key: session[key] for key in ("action", "resource", "context", "expected")}
    assert "uw" not in SCOPE["session_names"] and lc.MODE_SESSION_OPERATIONS["unit-start"][0] == "ux"


@pytest.mark.parametrize("name, change, case_id", [
    ("role.mode_seed", lambda doc: doc | {"Statement": doc["Statement"][:1]}, "us-put-raw"),
    ("role.mode_dispatch", lambda doc: doc | {"Statement": doc["Statement"] + [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
     None),
    ("application_session.ux", lambda doc: doc | {"Statement": [s for s in doc["Statement"] if "NotResource" not in s
                                                                and "Condition" not in s]}, "assume-ux-other-session")],
    ids=["papel-sem-raw", "papel-amplo-continua-negado-pela-sessao", "sessao-da-aplicacao-sem-nome"])
def test_documento_que_muda_um_caso_recusa_a_preparacao(name, change, case_id):
    documents = _documents()
    documents[name] = change(copy.deepcopy(documents[name]))
    if case_id is None:
        assert _prepare(documents)["documents"][name] == c.sha(c.canonical(documents[name]))
        return
    with pytest.raises(ValueError, match=f"^effective IAM case {case_id}$"):
        _prepare(documents)


def test_sessao_avaliada_e_a_do_construtor_no_prazo_preparado():
    documents = _documents()
    documents["session.ux"] = _documents(("ux",), DEADLINE + 60)["session.ux"]
    with pytest.raises(ValueError, match="^mode evaluation session document$"):
        _prepare(documents)


@pytest.mark.parametrize("change, message", [
    ({"deadline": str(DEADLINE)}, "integer range"), ({"owner_sha256": "b" * 64}, "mode session runs"),
    ({"role_arns": {alias: arn for alias, arn in ROLE_ARNS.items() if alias != "mode_observe"}}, "closed object fields"),
    ({"session_names": NAMES | {"ux": "mc-ux-" + "0" * 39}}, "mode evaluation scope"),
    ({"session_names": NAMES | {"ux": NAMES["rx"]}}, "mode evaluation scope"),
    ({"role_arns": ROLE_ARNS | {"mode_seed": "arn:aws:iam::111122223333:role/cnesdata-prod-mode-*"}}, "mode evaluation scope"),
    ({"role_arns": ROLE_ARNS | {"mode_seed": ROLE_ARNS["mode_dispatch"]}}, "mode evaluation scope"),
    ({"extra": 1}, "closed object fields")],
    ids=["prazo-texto", "outro-owner", "sem-papel", "nome-curto", "nome-de-outra-sessao", "papel-curinga", "papel-trocado",
         "campo-extra"])
def test_escopo_fora_da_forma_recusa_a_preparacao(change, message):
    with pytest.raises(ValueError, match=f"^{message}$"):
        _prepare(scope=SCOPE | change)


@pytest.mark.parametrize("deadline", [DEADLINE - 300, DEADLINE - 301])
def test_preparacao_observa_antes_do_prazo_da_sessao(deadline):
    with pytest.raises(ValueError, match="^mode evaluation before session deadline$"):
        _prepare(_documents(deadline=deadline), SCOPE | {"deadline": deadline})


def test_documentos_fora_do_conjunto_fechado_recusam():
    documents = _documents()
    with pytest.raises(ValueError, match="^mode evaluation documents$"):
        _prepare({name: value for name, value in documents.items() if name != "role.mode_observe"})
    with pytest.raises(ValueError, match="^mode evaluation documents$"):
        _prepare(documents | {"freeze": {}})


def _stage(code, report=None, documents=None, scope=None):
    alias = CODES[PARTS.get(code, code)][1]
    names = {"application_identity", "application_managed", "application_session." + PARTS.get(code, code), "role." + alias,
             "session." + code}
    documents = {name: value for name, value in _documents().items() if name in names} if documents is None else documents
    return _ib().mode_stage_evaluation(_prepare() if report is None else report, documents, SCOPE if scope is None else scope,
                                       code=code)


@pytest.mark.parametrize("code", [*CODES, *PARTS])
def test_estagio_recalcula_os_casos_da_propria_sessao_e_exige_igualdade(code):
    report = _prepare()
    rows = _stage(code, report)
    assert rows == [case for case in report["cases"] if lc.MODE_EVALUATION_CASES[case["case_id"]][0] == code]
    assert {row["case_id"] for row in rows} >= {"assume-" + code, code + "-expired"}


def test_estagio_recusa_documento_diferente_do_preparado():
    report = _prepare()
    documents = {name: value for name, value in _documents().items()
                 if name in {"application_identity", "application_managed", "application_session.ux", "role.mode_dispatch",
                             "session.ux"}}
    changed = documents | {"role.mode_dispatch": ROLES["roles"]["mode_observe"]["policy"]["PolicyDocument"]}
    with pytest.raises(ValueError, match="^mode stage evaluation documents$"):
        _stage("ux", report, changed)
    with pytest.raises(ValueError, match="^mode stage evaluation documents$"):
        _stage("ux", report, documents | {"session.rx": _documents(("rx",))["session.rx"]})
    with pytest.raises(ValueError, match="^mode stage evaluation documents$"):
        _stage("ux", report, documents | {"session.ux": _documents(("ux",), DEADLINE + 60)["session.ux"]})
    wait = {name: value for name, value in documents.items() if name != "session.ux"} | {"session.uw": _documents()["session.uw"]}
    assert _stage("uw", report, wait)
    with pytest.raises(ValueError, match="^mode stage evaluation documents$"):
        _stage("uw", report, wait | {"session.uw": documents["session.ux"]})
    with pytest.raises(ValueError, match="^mode stage evaluation documents$"):
        _stage("uw", report, documents | {"session.uw": wait["session.uw"]})


def test_estagio_recusa_caso_preparado_adulterado():
    report = _prepare()
    tampered = copy.deepcopy(report)
    _case(tampered, "ux-put-binding")["resource"] = RESOURCES["table_arn"] + "-other"
    with pytest.raises(ValueError, match="^mode stage evaluation cases$"):
        _stage("ux", tampered)
    with pytest.raises(ValueError, match="^mode stage evaluation cases$"):
        _stage("ux", report, scope=SCOPE | {"resources": RESOURCES | {"revisions": RESOURCES["revisions"] | {
            "recovery": RESOURCES["revisions"]["recovery"][:-1] + "8"}}})


@pytest.mark.parametrize("code", ["unit", "ds", None])
def test_estagio_so_recalcula_sessoes_de_promotion(code):
    with pytest.raises(ValueError, match="^mode stage evaluation code$"):
        _ib().mode_stage_evaluation(_prepare(), {}, SCOPE, code=code)


def _mutate(path, value):
    report = _prepare()
    node = report
    for key in path[:-1]:
        node = node[key]
    if value is KeyError:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return report


@pytest.mark.parametrize("path, value", [
    (("schema_version",), 2), (("evaluator_source_sha",), "c" * 39), (("documents", "freeze"), "a" * 64),
    (("documents", "session.ux"), KeyError), (("documents", "role.mode_seed"), "x"), (("cases", 0, "observed"), False),
    (("cases", 0, "action"), "sts:TagSession"), (("cases", 0, "context", "aws:SourceIp"), "10.0.0.1"),
    (("cases", 0, "case_id"), "assume-us-copy"), (("cases", 1, "case_id"), "assume-us"), (("cases", 0, "extra"), 1),
    (("cases", 2, "context", "dynamodb:LeadingKeys"), ["a", "b", "c"]), (("cases", 0, "resource"), ""),
    (("cases", 0, "context", "aws:CurrentTime"), KeyError), (("extra",), 1)],
    ids=["schema", "sha-curto", "documento-extra", "documento-ausente", "digest-invalido", "observado-diverge", "acao-diverge",
         "contexto-desconhecido", "caso-desconhecido", "caso-duplicado", "campo-extra-no-caso", "chaves-demais",
         "recurso-vazio", "sem-instante", "campo-extra"])
def test_validador_da_avaliacao_de_modo_recusa_documento_fora_da_forma(path, value):
    with pytest.raises(ValueError, match="^mode evaluation$"):
        lc.validate_mode_evaluation(_mutate(path, value))


def test_validador_recusa_avaliacao_incompleta():
    report = _prepare()
    report["cases"] = report["cases"][:-1]
    with pytest.raises(ValueError, match="^mode evaluation$"):
        lc.validate_mode_evaluation(report)


@pytest.mark.parametrize("case_id, action, key, expected", [
    ("ux-check-fence", "dynamodb:ConditionCheckItem", "ENV#prod#FENCE", True),
    ("ux-update-semaphore", "dynamodb:UpdateItem", "ENV#prod#SEMAPHORE", True),
    ("ux-consume-attempt", "dynamodb:UpdateItem", "ENV#prod#ATTEMPTS", True),
    ("ux-check-unit-run", "dynamodb:ConditionCheckItem", "unit", True),
    ("ux-check-semaphore", "dynamodb:ConditionCheckItem", "ENV#prod#SEMAPHORE", False),
    ("ux-query-unit-run", "dynamodb:Query", "unit", False),
    ("ux-update-unit-run", "dynamodb:UpdateItem", "unit", False)])
def test_casos_do_q1_no_ux_fixam_as_chaves_do_caminho_nativo_do_unit(case_id, action, key, expected):
    report = _prepare()
    run = "TENANT#" + RESOURCES["scope"]["tenant_id"].encode().hex() + "#RUN#" + ("unit-" + OWNER[:16]).encode().hex()
    case = _case(report, case_id)
    assert (case["action"], case["resource"], case["expected"], case["observed"]) == (
        action, RESOURCES["table_arn"], expected, expected)
    assert case["context"]["dynamodb:LeadingKeys"] == [run if key == "unit" else key]


@pytest.mark.parametrize("case_id, action, resource, expected", [
    ("ux-describe-own-execution", "states:DescribeExecution", "execution", False),
    ("uw-describe-own-execution", "states:DescribeExecution", "execution", True),
    ("uw-describe-own-task", "ecs:DescribeTasks", "task", True),
    ("uw-describe-foreign-cluster-task", "ecs:DescribeTasks", "foreign", False),
    ("uw-start-execution", "states:StartExecution", "machine", False)])
def test_casos_da_divisao_do_ux_separam_o_inicio_da_espera(case_id, action, resource, expected):
    report = _prepare()
    tasks = RESOURCES["cluster_arn"].replace(":cluster/", ":task/")
    resources = {"execution": RESOURCES["machine_arn"].replace(":stateMachine:", ":execution:") + ":probe",
                 "task": tasks + "/" + "0" * 32, "foreign": tasks + "-foreign/" + "0" * 32, "machine": RESOURCES["machine_arn"]}
    case = _case(report, case_id)
    assert (case["action"], case["resource"], case["expected"], case["observed"]) == (action, resources[resource], expected,
                                                                                    expected)
