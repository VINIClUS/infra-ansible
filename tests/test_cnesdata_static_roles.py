"""Roles estaticos pelos readbacks pos-apply autenticados no proprio run: role_id, politica e IAM efetivo (#55, P15b)."""
import copy
import itertools

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_runtime as lr

from test_cnesdata_static_stage import ACCOUNT, BUCKET, DISTRIBUTION, EVIDENCE_GOVERNANCE, KEYS, ROLES, _journal

BUCKET_ARN = "arn:aws:s3:::" + BUCKET
ENABLED_UNTIL = "2027-02-12T00:00:00Z"
EXPIRY = {"DateLessThan": {"aws:CurrentTime": ENABLED_UNTIL}}
ROLE_POLICIES = {
    "observer": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListMultipartUploadParts"],
         "Resource": [BUCKET_ARN + "/assets/*", BUCKET_ARN + "/index.html", BUCKET_ARN + "/theme-init.js"]},
        {"Effect": "Allow", "Action": ["s3:ListBucketVersions", "s3:ListBucketMultipartUploads"], "Resource": BUCKET_ARN},
        {"Effect": "Allow", "Action": "cloudfront:GetInvalidation", "Resource": DISTRIBUTION}]},
    "normal": {"Version": "2012-10-17", "Statement": [
        *({"Effect": "Allow", "Action": action, "Resource": [BUCKET_ARN + "/" + key for key in sorted(KEYS)],
           "Condition": EXPIRY} for action in ("s3:PutObject", "s3:GetObject")),
        {"Effect": "Allow", "Action": ["cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"],
         "Resource": DISTRIBUTION, "Condition": EXPIRY}]},
}
ROLE_FACTS = {alias: {"role_arn": ROLES[alias], "role_name": ROLES[alias].rsplit("/", 1)[1],
                      "role_id": "AROA" + alias.upper().ljust(17, "X"), "policy_name": ROLES[alias].rsplit("/", 1)[1] + "-runtime",
                      "policy": ROLE_POLICIES[alias]} for alias in ROLES}
FENCE_NAME = "cnesdata-prod-promotion-fence-operator"


def _rows(name_part, facts):
    role = "module.runtime_iam.aws_iam_role." + name_part + "[0]"
    policy = "module.runtime_iam.aws_iam_role_policy." + name_part + "[0]"
    name = facts["role_name"]
    return [({"service": "iam", "operation": "get_role", "address": role, "absent": False},
             {"service": "iam", "operation": "get_role", "observed": {"Role": {
                 "Arn": facts["role_arn"], "RoleName": name, "RoleId": facts["role_id"], "Path": "/",
                 "MaxSessionDuration": 3600, "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}}}),
            ({"service": "iam", "operation": "get_role_policy", "address": policy, "absent": False},
             {"service": "iam", "operation": "get_role_policy", "observed": {
                 "RoleName": name, "PolicyName": facts["policy_name"], "PolicyDocument": facts["policy"]}})]


def role_readbacks(aliases=("observer", "normal"), *, facts=None, mutate=None):
    """After-apply readback specs and reports of the static roles, with an unrelated fence role pair first."""
    facts = copy.deepcopy(facts or ROLE_FACTS)
    fence = {"role_arn": f"arn:aws:iam::{ACCOUNT}:role/{FENCE_NAME}", "role_name": FENCE_NAME,
             "role_id": "AROAFENCEXXXXXXXXXXXX", "policy_name": "fence", "policy": ROLE_POLICIES["observer"]}
    pairs = _rows("promotion_fence_operator", fence)
    for alias in aliases:
        pairs += _rows("static_" + alias, facts[alias])
    specs, reports = [copy.deepcopy(spec) for spec, _ in pairs], [copy.deepcopy(report) for _, report in pairs]
    if mutate is not None:
        mutate(specs, reports)
    return specs, reports


def role_files(aliases=("observer", "normal"), *, facts=None, mutate=None):
    """Deploy checkpoint and approval whose after readbacks carry the static roles."""
    specs, reports = role_readbacks(aliases, facts=facts, mutate=mutate)
    approval = {"version": 1, "readbacks": {"before": [], "after": specs}}
    checkpoint = {"purpose": "application-prepare", "readbacks": reports}
    return {"checkpoint.json": c.canonical(checkpoint), "approval.json": c.canonical(approval)}


def _index(specs, alias, operation):
    return next(index for index, spec in enumerate(specs)
                if spec["address"].endswith("static_" + alias + "[0]") and spec["operation"] == operation)


def test_politicas_do_fixture_sao_as_static_policies_do_498_para_as_candidate_keys():
    import json
    from test_cnesdata_application_gate import _static_policies
    plan = {"candidate_keys": sorted(KEYS), "enabled_until": ENABLED_UNTIL, "distribution_arn": DISTRIBUTION,
            "retire_versions": []}
    assert {alias: json.loads(text) for alias, text in _static_policies(BUCKET_ARN, plan).items()} == ROLE_POLICIES


def test_fatos_do_role_estatico_vem_do_readback_pos_apply_com_specs_na_forma_governada_do_approval():
    from tools.cnesdata_delivery import static_inputs as si
    specs, _ = role_readbacks()
    assert [lr._spec_fields(spec) for spec in specs] == [False] * 6
    assert all(set(spec) == {"service", "operation", "address", "absent"} for spec in specs)
    files = role_files()
    facts = si.static_role_facts(files["checkpoint.json"], files["approval.json"], governance=EVIDENCE_GOVERNANCE,
                                 aliases=("observer", "normal"))
    assert facts == ROLE_FACTS
    only = si.static_role_facts(files["checkpoint.json"], files["approval.json"], governance=EVIDENCE_GOVERNANCE,
                                aliases=("observer",))
    assert only == {"observer": ROLE_FACTS["observer"]}


def _drop(alias, operation):
    def mutate(specs, reports):
        index = _index(specs, alias, operation)
        del specs[index], reports[index]
    return mutate


def _twice(alias, operation):
    def mutate(specs, reports):
        index = _index(specs, alias, operation)
        specs.append(copy.deepcopy(specs[index]))
        reports.append(copy.deepcopy(reports[index]))
    return mutate


def _report(alias, operation, change):
    def mutate(specs, reports):
        change(reports[_index(specs, alias, operation)])
    return mutate


@pytest.mark.parametrize("mutate, message", [
    (_drop("normal", "get_role"), "static_role=readback_shape alias=normal operation=get_role"),
    (_drop("observer", "get_role_policy"), "static_role=readback_shape alias=observer operation=get_role_policy"),
    (_twice("normal", "get_role"), "static_role=readback_shape alias=normal operation=get_role"),
    (_twice("observer", "get_role_policy"), "static_role=readback_shape alias=observer operation=get_role_policy"),
    (lambda specs, reports: _second_policy(specs, reports),
     "static_role=readback_shape alias=normal operation=get_role_policy"),
    (_report("normal", "get_role_policy", lambda report: report["observed"].update(PolicyName="cnesdata-prod-static-normal")),
     "static_role=readback_shape alias=normal operation=get_role_policy"),
    (lambda specs, reports: reports.pop(), "static_role=readbacks_unaligned"),
    (_report("normal", "get_role", lambda report: report.update(operation="get_role_policy")),
     "static_role=readback_shape alias=normal operation=get_role"),
    (_report("observer", "get_role", lambda report: report["observed"]["Role"].update(
        Arn=f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-static-other")), "static_role=identity alias=observer"),
    (_report("observer", "get_role", lambda report: report["observed"]["Role"].update(RoleId="")),
     "static_role=identity alias=observer"),
    (_report("normal", "get_role_policy", lambda report: report["observed"].update(RoleName="cnesdata-prod-static-observer")),
     "static_role=readback_shape alias=observer operation=get_role_policy"),
    (_report("normal", "get_role_policy", lambda report: report["observed"].update(PolicyDocument="{}")),
     "static_role=policy alias=normal")])
def test_fatos_do_role_estatico_recusam_readback_ausente_duplicado_desalinhado_ou_fora_da_governanca(mutate, message):
    from tools.cnesdata_delivery import static_inputs as si
    files = role_files(mutate=mutate)
    with pytest.raises(ValueError, match=f"^{message}$"):
        si.static_role_facts(files["checkpoint.json"], files["approval.json"], governance=EVIDENCE_GOVERNANCE,
                             aliases=("observer", "normal"))


def _second_policy(specs, reports):
    name = ROLE_FACTS["normal"]["role_name"]
    specs.append({"service": "iam", "operation": "get_role_policy", "absent": False,
                  "address": "module.runtime_iam.aws_iam_role_policy.static_normal_extra[0]"})
    reports.append({"service": "iam", "operation": "get_role_policy",
                    "observed": {"RoleName": name, "PolicyName": name + "-extra", "PolicyDocument": ROLE_POLICIES["observer"]}})


@pytest.mark.parametrize("mutate, expected", [
    (None, ROLE_FACTS), (_second_policy, "static_role=readback_shape alias=normal operation=get_role_policy")])
def test_transposicao_de_relatorios_com_specs_governados_nunca_entrega_fato_trocado(mutate, expected):
    from tools.cnesdata_delivery import static_inputs as si
    specs, reports = role_readbacks(mutate=mutate)
    assert all(lr._spec_fields(spec) is False for spec in specs)
    approval = c.canonical({"version": 1, "readbacks": {"before": [], "after": specs}})
    outcomes = {}
    for first, second in itertools.combinations(range(len(specs)), 2):
        swapped = copy.deepcopy(reports)
        swapped[first], swapped[second] = swapped[second], swapped[first]
        checkpoint = c.canonical({"purpose": "application-prepare", "readbacks": swapped})
        try:
            outcomes[first, second] = si.static_role_facts(checkpoint, approval, governance=EVIDENCE_GOVERNANCE,
                                                           aliases=("observer", "normal"))
        except ValueError as error:
            outcomes[first, second] = str(error)
    assert len(outcomes) == len(specs) * (len(specs) - 1) // 2 in (15, 21)
    assert outcomes == dict.fromkeys(outcomes, expected)


def test_politica_da_sessao_normal_restringe_os_objetos_as_candidate_keys_autenticadas():
    from tools.cnesdata_delivery import session_policy
    keys = ["assets/app.js", "index.html", "theme-init.js"]
    normal = session_policy.static_session_policy("normal", bucket_arn=BUCKET_ARN, distribution_arn=DISTRIBUTION,
                                                  deadline=2000, keys=keys)
    assert normal["Statement"][0]["Resource"] == [BUCKET_ARN + "/" + key for key in keys]
    observer = session_policy.static_session_policy("observer", bucket_arn=BUCKET_ARN, distribution_arn=None, deadline=2000)
    assert observer["Statement"][1]["Resource"] == BUCKET_ARN + "/*"
    for alias, extra in (("normal", {}), ("observer", {"keys": keys}), ("normal", {"keys": ["assets/*"]}),
                         ("normal", {"keys": []})):
        with pytest.raises(ValueError, match="^static session keys$"):
            session_policy.static_session_policy(alias, bucket_arn=BUCKET_ARN, distribution_arn=DISTRIBUTION,
                                                 deadline=2000, **extra)


def test_politica_normal_de_14_chaves_do_build_real_cabe_no_limite_do_sts():
    from tools.cnesdata_delivery import session_policy
    keys = sorted(["index.html", "theme-init.js"]
                  + [f"assets/index-{index:02d}DmPMWKvL.{kind}" for index, kind in enumerate(["js", "css"] * 6)])
    policy = session_policy.static_session_policy("normal", bucket_arn=BUCKET_ARN, distribution_arn=DISTRIBUTION,
                                                  deadline=2000, keys=keys)
    assert len(keys) == 14 and len(c.canonical(policy).decode().strip()) <= 2048


def _sts(monkeypatch, *, roles=ROLE_FACTS, user=None, operation="publish-static"):
    from tools.cnesdata_delivery import application_gate as ag, aws_boundary, lifecycle_contract as lc
    from test_cnesdata_static_inputs import _inventory_journal
    journal = _journal()[0] if operation == "publish-static" else _inventory_journal()[0]
    now, limit = (1505, 1505 + 900) if operation == "publish-static" else (1100, 2000)
    binding = ag._static_binding(EVIDENCE_GOVERNANCE, journal)
    names = lc.static_sessions(binding, operation)
    calls, factory = [], []

    def identity(alias):
        return (user or {}).get(alias, ROLE_FACTS[alias]["role_id"]) + ":" + names[alias]

    def assumed(alias):
        return ROLES[alias].replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + names[alias]

    class Operation:
        def call(self, service, method, **parameters):
            calls.append(parameters)
            alias = next(name for name, arn in ROLES.items() if arn == parameters["RoleArn"])
            from datetime import datetime, timezone
            return {"PackedPolicySize": 10, "AssumedRoleUser": {"Arn": assumed(alias), "AssumedRoleId": identity(alias)},
                    "Credentials": {
                "AccessKeyId": alias, "SecretAccessKey": "synthetic-secret", "SessionToken": "synthetic-token",
                "Expiration": datetime.fromtimestamp(limit, timezone.utc)}}

    class Delegated:
        def __init__(self, governance, *, credentials):
            alias = credentials["AccessKeyId"]
            self.identity = {"Account": ACCOUNT, "Arn": assumed(alias), "UserId": identity(alias)}
    monkeypatch.setattr(aws_boundary, "AWS", Delegated)
    def assume():
        return ag._assume_static_session(governance=EVIDENCE_GOVERNANCE, journal=journal, binding=binding, roles=roles,
                                         credential_limit=limit,
                                         operation_session=lambda *args: factory.append(args) or Operation(),
                                         clock=lambda: now)
    return assume, journal, names, calls, factory


def test_sessao_estatica_fixa_o_user_id_no_role_id_do_readback_e_restringe_o_normal_as_chaves(monkeypatch):
    from tools.cnesdata_delivery import lifecycle_contract as lc, session_policy
    assume, journal, names, calls, factory = _sts(monkeypatch)
    session = assume()
    plan = lc.static_plan(journal._inputs["static-plan"], bucket=BUCKET)
    normal = session_policy.static_session_policy("normal", bucket_arn=BUCKET_ARN, distribution_arn=DISTRIBUTION,
                                                  deadline=journal._request["stage"]["deadline"], keys=plan["candidate_keys"])
    assert calls[1]["Policy"] == c.canonical(normal).decode().strip()
    assert set(session.clients) == {"observer", "normal"} and len(factory) == 1


@pytest.mark.parametrize("alias", ["observer", "normal"])
def test_sessao_estatica_recusa_user_id_de_outro_role_id(monkeypatch, alias):
    assume, journal, names, calls, factory = _sts(monkeypatch, user={alias: "AROA" + "OTHER".ljust(17, "X")})
    with pytest.raises(ValueError, match="^static exact native role ID/session/account$"):
        assume()
    assert len(calls) == (1 if alias == "observer" else 2)


def _without(alias, action):
    roles = copy.deepcopy(ROLE_FACTS)
    for statement in roles[alias]["policy"]["Statement"]:
        actions = [statement["Action"]] if type(statement["Action"]) is str else statement["Action"]
        statement["Action"] = [item for item in actions if item != action] or ["s3:GetBucketTagging"]
    return roles


@pytest.mark.parametrize("roles, message", [
    (_without("normal", "s3:PutObject"), "static_role=effective_iam alias=normal action=s3:PutObject"),
    (_without("normal", "cloudfront:CreateInvalidation"), "static_role=effective_iam alias=normal action=cloudfront:CreateInvalidation"),
    (_without("observer", "s3:GetObjectVersion"), "static_role=effective_iam alias=observer action=s3:GetObjectVersion"),
    (_without("observer", "s3:ListBucketVersions"), "static_role=effective_iam alias=observer action=s3:ListBucketVersions")])
def test_sessao_estatica_confere_iam_efetivo_de_cada_chamada_do_produto_antes_do_sts(monkeypatch, roles, message):
    assume, journal, names, calls, factory = _sts(monkeypatch, roles=roles)
    with pytest.raises(ValueError, match=f"^{message}$"):
        assume()
    assert calls == [] and factory == []


def test_iam_efetivo_do_normal_recusa_role_que_so_alcanca_outra_chave(monkeypatch):
    roles = copy.deepcopy(ROLE_FACTS)
    roles["normal"]["policy"]["Statement"][0]["Resource"] = BUCKET_ARN + "/assets/*"
    assume, journal, names, calls, factory = _sts(monkeypatch, roles=roles)
    with pytest.raises(ValueError, match="^static_role=effective_iam alias=normal action=s3:PutObject$"):
        assume()
    assert calls == [] and factory == []


@pytest.mark.parametrize("roles", [{"observer": ROLE_FACTS["observer"]},
                                   ROLE_FACTS | {"normal": ROLE_FACTS["normal"] | {"role_arn": ROLES["observer"]}}])
def test_sessao_estatica_recusa_fatos_de_role_incompletos_ou_fora_da_governanca(monkeypatch, roles):
    assume, journal, names, calls, factory = _sts(monkeypatch, roles=roles)
    with pytest.raises(ValueError, match="^static exact protected roles$"):
        assume()
    assert calls == [] and factory == []


def test_sessao_do_inventory_usa_so_o_observer_do_readback(monkeypatch):
    assume, journal, names, calls, factory = _sts(monkeypatch, roles={"observer": ROLE_FACTS["observer"]},
                                                  operation="inventory")
    session = assume()
    assert set(session.clients) == {"observer"} and len(calls) == 1


def test_capability_do_publish_static_le_os_roles_do_checkpoint_operacional_e_recusa_antes_do_sts():
    from test_cnesdata_application_gate import _prepare_stage_keeper
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store = _prepare_stage_keeper()
    journal, _, _, _ = _journal()
    minted = []
    with pytest.raises(ValueError, match="^static_role=readback_shape alias=normal operation=get_role$"):
        ag.static_capability(governance=EVIDENCE_GOVERNANCE, journal=journal, keeper=keeper, credential_limit=6000,
                             operation_session=lambda *args: minted.append(args), clock=lambda: 1505,
                             carrier=ag._static_binding(EVIDENCE_GOVERNANCE, journal),
                             prepared=role_files(("observer",)))
    assert minted == [] and journal._failed and store.get()[0]["status"] == "held"


def test_capability_do_inventory_le_o_observer_do_deploy_observer_bootstrap_e_recusa_antes_do_sts():
    from test_cnesdata_application_gate import _prepare_stage_keeper
    from test_cnesdata_static_inputs import _inventory_journal
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store = _prepare_stage_keeper()
    journal = _inventory_journal()[0]
    minted = []
    with pytest.raises(ValueError, match="^static_role=readback_shape alias=observer operation=get_role$"):
        ag.inventory_capability(governance=EVIDENCE_GOVERNANCE, journal=journal, keeper=keeper, credential_limit=2000,
                                operation_session=lambda *args: minted.append(args), clock=lambda: 1100,
                                publication=role_files(()))
    assert minted == [] and journal._failed and store.get()[0]["status"] == "held"


OBSERVER_STEP_NAME = "application-prepare-observer-bootstrap"


def _observer_files(owner, *, checkpoint=None, approval=None):
    files = role_files(("observer",))
    base_checkpoint = c.loads(files["checkpoint.json"], canonical=True) | {"owner": owner, "plan_sha256": "9" * 64}
    base_approval = c.loads(files["approval.json"], canonical=True) | {
        "owner": owner, "purpose": "application-prepare", "direction": "advance", "plan_sha256": "9" * 64,
        "delta": {"purpose": "application-prepare", "direction": "advance", "mode": "observer-bootstrap"}}
    return {"checkpoint.json": c.canonical(base_checkpoint | (checkpoint or {})),
            "approval.json": c.canonical(base_approval | (approval or {})), "plan.json": b'{"plan":1}'}


def _observer_read(files):
    from test_cnesdata_stage_events import GOVERNANCE, IDENTITY, OWNER, RUN, _GitHub, _Guard
    from test_cnesdata_static_inputs import OBSERVER_STEP
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr
    index = {"version": 1, "source_sha": "b" * 40, "run_id": 4242, "run_attempt": 1, "step": OBSERVER_STEP_NAME,
             "owner_sha256": OWNER["owner_sha256"], "generation": OWNER["generation"], **IDENTITY,
             "files": [{"name": name, "size": len(raw), "sha256": c.sha(raw)} for name, raw in sorted(files.items())]}
    governance = GOVERNANCE | {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "evidence",
                               "context_kind": "promotion",
                               "lifecycle_steps": GOVERNANCE["lifecycle_steps"] | {OBSERVER_STEP_NAME: OBSERVER_STEP}}
    request = {"source_sha": "b" * 40, "step": "application", "application_purpose": "promotion",
               "caller_binding_sha256": "c" * 64}
    prefix = lr.namespace(governance, request, RUN, OBSERVER_STEP_NAME)
    reads = []

    class Store:
        def get(self, bucket, key, maximum=None):
            reads.append(key)
            return files[key.removeprefix(prefix)], None
    api = _GitHub(OBSERVER_STEP["job_name"], OBSERVER_STEP_NAME, index=index)
    result = ag._observer_publication(api, Store(), governance, request, dict(RUN), dict(OWNER), _Guard(), 1300)
    return result, reads, prefix


def test_observer_bootstrap_le_so_checkpoint_e_approval_do_proprio_deploy_do_dono():
    from test_cnesdata_stage_events import OWNER
    files = _observer_files(dict(OWNER))
    result, reads, prefix = _observer_read(files)
    assert result == {name: files[name] for name in ("checkpoint.json", "approval.json")}
    assert reads == [prefix + "approval.json", prefix + "checkpoint.json"]


@pytest.mark.parametrize("checkpoint, approval", [
    ({"purpose": "phase-b"}, None), ({"owner": {"owner_sha256": "5" * 64}}, None),
    (None, {"delta": {"purpose": "application-prepare", "direction": "advance", "mode": "operational"}}),
    (None, {"plan_sha256": "8" * 64}), (None, {"direction": "rollback"})])
def test_observer_bootstrap_recusa_checkpoint_ou_approval_de_outro_dono_proposito_ou_modo(checkpoint, approval):
    from test_cnesdata_stage_events import OWNER
    files = _observer_files(dict(OWNER), checkpoint=checkpoint, approval=approval)
    with pytest.raises(ValueError, match="^observer-bootstrap=publication_binding$"):
        _observer_read(files)
