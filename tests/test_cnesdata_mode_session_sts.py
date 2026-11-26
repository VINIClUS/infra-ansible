"""P16b c-1124-p16b-next item 1: the mc-* STS session of one mode effect operation, on injected prepared authority."""
import copy
import json
import pathlib
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

ROLES = json.loads((pathlib.Path(__file__).resolve().parent / "fixtures" / "cnesdata_mode_roles.json").read_text())
RESOURCES = ROLES["fields"]["resources"]
OWNER = "a" * 64
DEADLINE = int(c.instant(ROLES["fields"]["enabled_until"])) - 600
START = DEADLINE - 1500
OBSERVED = c.utc(START - 600)
EFFECTS = ("unit-seed", "recovery-seed", "unit-start", "recovery-start", "audit-start")
CODES = {code: (operation, alias) for operation, (code, alias, context, _) in lc.MODE_SESSION_OPERATIONS.items()
         if context == "promotion"}
NAMES = {name.split("-")[1]: name for names in ROLES["fields"]["delegation_sessions"].values() for name in names}
ROLE_ARNS = {alias: ROLES["roles"][alias]["role"]["Role"]["Arn"] for alias in lc.MODE_ALIASES}
ROLE_IDS = {alias: "AROA" + alias.upper().replace("_", "") for alias in lc.MODE_ALIASES}
IDENTITY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                    "Resource": sorted(ROLE_ARNS.values())}]}


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _governance():
    return {"role": "application", "account_id": "111122223333", "state_bucket": "synthetic-state",
            "evidence_bucket": "synthetic-evidence", "evidence_prefix": "cnesdata/prod/evidence/",
            "evidence_kms_key_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-0000-0000-000000000000",
            "roles": {"application": "arn:aws:iam::111122223333:role/cnesdata-prod-application"},
            "application_delegations": dict(ROLE_ARNS),
            "application_coordination_policy": c.canonical(IDENTITY).decode().strip()}


def _application(pin=None):
    from tools.cnesdata_delivery.session_owner import _terraform_document_digest
    return SimpleNamespace(application_fragment={"policy_sha256": _terraform_document_digest(IDENTITY)},
                           pin={"document": copy.deepcopy(IDENTITY) if pin is None else pin})


def _documents(governance, owner, managed=IDENTITY, resources=RESOURCES, deadline=DEADLINE):
    from tools.cnesdata_delivery import session_policy
    documents = {"application_identity": IDENTITY, "application_managed": managed}
    for code, (operation, alias) in CODES.items():
        request = session_policy.application_request(governance, owner["source_sha"], owner["run_id"], owner["run_attempt"],
                                                     operation, application_purpose="promotion", delegations=[alias],
                                                     sessions={alias: NAMES[code]})
        documents["application_session." + code] = json.loads(request["Policy"])
        documents["session." + code] = session_policy.mode_session_policy(operation, resources=resources, owner_sha256=OWNER,
                                                                          deadline=deadline)
        documents["role." + alias] = ROLES["roles"][alias]["policy"]["PolicyDocument"]
    documents["session.uw"] = session_policy.mode_unit_wait_policy(resources=resources, owner_sha256=OWNER, deadline=deadline)
    return documents


def _authority(governance, owner, managed=IDENTITY, resources=RESOURCES, deadline=DEADLINE):
    from tools.cnesdata_delivery.iam_boundary import mode_effective_evaluation
    roles = copy.deepcopy(ROLES["roles"])
    for alias, entry in roles.items():
        entry["role"]["Role"]["RoleId"] = ROLE_IDS[alias]
    scope = {"resources": resources, "owner_sha256": OWNER, "role_arns": dict(ROLE_ARNS), "session_names": dict(NAMES),
             "deadline": deadline}
    documents = _documents(governance, owner, managed, resources, deadline)
    evaluation = mode_effective_evaluation(documents, scope, evaluator_source_sha="c" * 40, observed_at=OBSERVED)
    return _mb().ModeAuthority(evaluation, documents, scope, roles)


class _Factory:
    def __init__(self, client):
        self.client, self.calls = client, []

    def __call__(self, operation, role, stage):
        self.calls.append((operation, role["role_arn"], role["session_name"], dict(stage)))
        return self.client


def _journal(operation, inputs=None, source=None):
    from test_cnesdata_mode_stages import _mode_case
    request, owner, window, fixture = _mode_case(operation)
    if source is not None:
        owner["source_sha"] = request["source_sha"] = request["owner"]["source_sha"] = source
    inputs = fixture | (inputs or {})
    request["inputs"] = {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in inputs.items()}
    shift = START - window["admitted_at"]
    for key in ("close", "fixed_deadline", "input_deadline", "admitted_at", "deadline", "preparation_deadline"):
        window[key] += shift
    owner["owner_sha256"] = request["owner"]["owner_sha256"] = OWNER
    request["stage"] = {key: value for key, value in window.items() if key not in lc.application_identity(owner)}

    class Guard:
        def check(self, seconds=0):
            return None
    return ag.AdapterJournal(c.canonical(request), operation=operation, owner=owner, window=window, inputs=inputs,
                             activation_sha256=request["activation_sha256"], guard=Guard()), owner


def _case(monkeypatch, operation="recovery-start", mutation=None, source=None):
    journal, owner = _journal(operation, source=source)
    now = journal._request["stage"]["deadline"] - 40 if mutation == "late" else START + 30
    governance, application = _governance(), _application()
    code, alias = lc.MODE_SESSION_OPERATIONS[operation][:2]
    resources = RESOURCES
    if mutation == "policy-limit":
        resources = copy.deepcopy(RESOURCES)
        prefix = resources["scope"]["raw_object_keys"][0].rsplit("/", 1)[0]
        resources["scope"]["raw_object_keys"] = sorted(resources["scope"]["raw_object_keys"]
                                                       + [f"{prefix}/extra-{index}.parquet" for index in range(8)])
    managed = IDENTITY
    if mutation == "managed-expired":
        managed = copy.deepcopy(IDENTITY)
        managed["Statement"].append({"Effect": "Deny", "Action": "*", "Resource": "*",
                                     "Condition": {"DateGreaterThanEquals": {"aws:CurrentTime": c.utc(now)}}})
        application = _application(managed)
    authority = _authority(governance, owner, managed, resources)
    if mutation == "owner":
        authority.scope["owner_sha256"] = "b" * 64
    if mutation == "role-document":
        authority.documents["role." + alias] = {"Version": "2012-10-17", "Statement": []}
    if mutation == "session-name":
        authority.scope["session_names"][code] = "mc-" + code + "-" + "0" * 40
    if mutation == "role-arn":
        authority.roles[alias]["role"]["Role"]["Arn"] += "-other"
    if mutation == "role-id":
        del authority.roles[alias]["role"]["Role"]["RoleId"]
    if mutation == "trust":
        authority.roles[alias]["role"]["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]["StringEquals"][
            "sts:RoleSessionName"] = ["mc-" + code + "-" + "1" * 40]
    if mutation == "delegation":
        governance["application_delegations"][alias] = governance["application_delegations"][alias] + "-other"
    if mutation == "identity":
        application.pin["document"] = {"Version": "2012-10-17", "Statement": []}
    if mutation == "inline":
        governance["evidence_bucket"] = "synthetic-other"
    factory, calls, native = _native(monkeypatch, code, alias, now, mutation)
    credential_limit = now + 899 if mutation == "credential" else now + 3000
    args = dict(governance=governance, application=application, authority=authority, journal=journal,
                credential_limit=credential_limit, operation_session=factory, clock=lambda: now)
    return args, calls, native


def _native(monkeypatch, code, alias, now, mutation=None):
    from tools.cnesdata_delivery import aws_boundary
    calls, native = [], []
    arn, role_id = ROLE_ARNS[alias], ROLE_IDS[alias]
    assumed = arn.replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + NAMES[code]
    identity = {"Account": "111122223333", "Arn": assumed, "UserId": role_id + ":" + NAMES[code]}
    if mutation == "native-arn":
        identity["Arn"] += "-foreign"
    if mutation == "native-id":
        identity["UserId"] = "AROAOTHER:" + NAMES[code]

    class Operation:
        def call(self, service, operation_name, **parameters):
            calls.append((service, operation_name, parameters))
            expiry = now + (901 if mutation == "expiration" else 900)
            return {"PackedPolicySize": 10, "AssumedRoleUser": {"Arn": assumed, "AssumedRoleId": role_id + ":" + NAMES[code]},
                    "Credentials": {"AccessKeyId": "synthetic-key", "SecretAccessKey": "synthetic-secret",
                                    "SessionToken": "synthetic-token", "Expiration": datetime.fromtimestamp(expiry, timezone.utc)}}

    class Delegated:
        def __init__(self, governance, *, credentials):
            self.governance = governance
            self.identity = self.call("sts", "get_caller_identity")

        def call(self, service, operation_name, **parameters):
            native.append((service, operation_name, parameters))
            return dict(identity)
    monkeypatch.setattr(aws_boundary, "AWS", Delegated)
    return _Factory(Operation()), calls, native


@pytest.mark.parametrize("operation", EFFECTS)
def test_sessao_mc_de_cada_efeito_assume_o_papel_do_alias_com_a_politica_do_construtor(monkeypatch, operation):
    from tools.cnesdata_delivery.session_policy import mode_session_policy
    args, calls, native = _case(monkeypatch, operation)
    session = _mb().assume_mode_session(**args)
    code, alias = lc.MODE_SESSION_OPERATIONS[operation][:2]
    stage = args["journal"]._request["stage"]
    minted = min(stage["deadline"], args["credential_limit"], DEADLINE)
    policy = mode_session_policy(operation, resources=RESOURCES, owner_sha256=OWNER, deadline=minted)
    assert calls == [("sts", "assume_role", {"RoleArn": ROLE_ARNS[alias], "RoleSessionName": NAMES[code],
                                             "DurationSeconds": 900, "Policy": c.canonical(policy).decode().strip()})]
    assert native == [("sts", "get_caller_identity", {})]
    assert args["operation_session"].calls == [(operation, ROLE_ARNS[alias], NAMES[code], stage)]
    assert (session.code, session.alias, session.deadline) == (code, alias, minted)
    assert session.evidence is args["operation_session"].client and session.client.governance["roles"] == {alias: ROLE_ARNS[alias]}
    assert session.request_binding == c.sha(c.canonical(args["journal"]._request))
    c.digest(session.commitment)


@pytest.mark.parametrize("operation", ["unit-record", "unit-observe", "recovery-observe", "audit-record"])
def test_sessao_mc_e_so_dos_cinco_efeitos(monkeypatch, operation):
    args, calls, _ = _case(monkeypatch, "recovery-start")
    args["journal"], _ = _journal(operation)
    with pytest.raises(ValueError, match="^mode session original operation$"):
        _mb().assume_mode_session(**args)
    assert calls == [] and args["operation_session"].calls == []


REFUSALS = {
    "late": "^mode session original stage/credential window$",
    "credential": "^mode session original stage/credential window$",
    "owner": "^mode session original owner$",
    "role-document": "^mode stage evaluation documents$",
    "session-name": "^effective IAM case assume-rx$",
    "role-arn": "^mode session role readback$",
    "role-id": "^mode session role readback$",
    "trust": "^mode session role readback$",
    "delegation": "^mode session role readback$",
    "identity": "^mode session application documents$",
    "inline": "^mode session application documents$",
    "managed-expired": "^mode session operation effective IAM$",
    "policy-limit": "^mode STS policy limit$",
}


@pytest.mark.parametrize("mutation", sorted(REFUSALS))
def test_sessao_mc_recusa_antes_do_sts_sem_credencial(monkeypatch, mutation):
    args, calls, native = _case(monkeypatch, "recovery-seed" if mutation == "policy-limit" else "recovery-start", mutation)
    with pytest.raises(ValueError, match=REFUSALS[mutation]):
        _mb().assume_mode_session(**args)
    assert calls == native == [] and args["operation_session"].calls == []


@pytest.mark.parametrize("mutation, message", [("expiration", "^mode STS expiration$"),
                                               ("native-arn", "^mode exact native role ID/session/account$"),
                                               ("native-id", "^mode exact native role ID/session/account$")])
def test_sessao_mc_recusa_resposta_do_sts_fora_do_exato(monkeypatch, mutation, message):
    args, calls, _ = _case(monkeypatch, mutation=mutation)
    with pytest.raises(ValueError, match=message):
        _mb().assume_mode_session(**args)
    assert len(calls) == 1


def test_prazo_da_sessao_e_o_menor_entre_o_estagio_e_o_prazo_avaliado(monkeypatch):
    args, _, _ = _case(monkeypatch)
    stage = args["journal"]._request["stage"]
    session = _mb().assume_mode_session(**args)
    assert session.deadline == stage["deadline"] < DEADLINE
    assert session.scope == args["authority"].scope


def test_prazo_avaliado_anterior_ao_estagio_limita_a_sessao_e_a_politica(monkeypatch):
    from tools.cnesdata_delivery.session_policy import mode_session_policy
    args, calls, _ = _case(monkeypatch)
    stage = args["journal"]._request["stage"]
    earlier = stage["deadline"] - 10
    args["authority"] = _authority(args["governance"], args["journal"]._request["owner"], deadline=earlier)
    session = _mb().assume_mode_session(**args)
    policy = mode_session_policy("recovery-start", resources=RESOURCES, owner_sha256=OWNER, deadline=earlier)
    assert session.deadline == earlier < stage["deadline"]
    assert calls[0][2]["Policy"] == c.canonical(policy).decode().strip()
