"""Plan and audit never delete lifecycle resources: static managed Deny, identity premise, deploy converge unchanged."""
import json

import pytest

from fixtures.cnesdata_iam_evaluation import decision, effective
from test_cnesdata_delivery_observer_roles import AUDIT_NAME, AUDIT_POLICY, audit_values
from test_cnesdata_delivery_oidc import activation_input, native, render, rendered_policies
from tools.cnesdata_delivery import session_policy as sp
from tools.cnesdata_delivery.session_policy import LIFECYCLE_DELETES

assert native
ACCOUNT = "111122223333"
STATE = "arn:aws:s3:::synthetic-state/"
RESOURCES = [
    f"arn:aws:states:us-east-2:{ACCOUNT}:stateMachine:cnesdata-prod-mode",
    f"arn:aws:scheduler:us-east-2:{ACCOUNT}:schedule/cnesdata-prod/cnesdata-prod-audit",
    f"arn:aws:scheduler:us-east-2:{ACCOUNT}:schedule-group/cnesdata-prod",
    f"arn:aws:events:us-east-2:{ACCOUNT}:rule/cnesdata-prod-audit",
    f"arn:aws:cloudwatch:us-east-2:{ACCOUNT}:alarm:cnesdata-prod-audit",
    STATE + "shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json",
    "*",
]
EVERYTHING = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
DELETE_AND_RESOURCES = [(action, resource) for action in LIFECYCLE_DELETES for resource in RESOURCES]


def governance():
    return {"account_id": ACCOUNT, "state_bucket": "synthetic-state", "evidence_bucket": "synthetic-evidence",
            "evidence_prefix": "cnesdata/prod/evidence/",
            "evidence_kms_key_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000002",
            "state_kms_key_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000001",
            "roles": {"plan": f"arn:aws:iam::{ACCOUNT}:role/cnesdata-test-plan",
                      "deploy": f"arn:aws:iam::{ACCOUNT}:role/cnesdata-test-deploy",
                      "audit": f"arn:aws:iam::{ACCOUNT}:role/{AUDIT_NAME}"}}


@pytest.fixture(scope="module")
def world(native):
    resources, _ = render(native, audit_values(), "lifecycle-delete-deny")
    return resources


def managed(world, role):
    return json.loads(world[f'aws_iam_policy.delivery_session["{role}"]']["policy"])


def inline_sessions(role):
    gov = governance()
    historical = {"protocol": "legacy-infra", "source_sha": "e" * 40, "run_id": 41, "run_attempt": 1,
                  "status": "applied", "purpose": "phase-a"}
    sessions = {
        "lifecycle advance": sp.lifecycle_request(gov, "a" * 40, 42, 1, role, "step", direction="advance"),
        "lifecycle converge": sp.lifecycle_request(gov, "a" * 40, 42, 1, role, "step", direction="converge"),
        "build": sp.request(gov, "a" * 40, 42, 1, role, []),
    }
    if role == "plan":
        sessions["historical"] = sp.lifecycle_request(
            gov, "a" * 40, 42, 1, role, "step", direction="advance", predecessor=historical)
    return {name: json.loads(item["Policy"]) for name, item in sessions.items()}


@pytest.mark.parametrize("role", ["plan", "audit"])
def test_sessoes_de_plan_e_audit_negam_os_cinco_deletes_mesmo_com_identidade_permissiva(world, role):
    document = managed(world, role)
    for name, inline in inline_sessions(role).items():
        for action, resource in DELETE_AND_RESOURCES:
            assert not effective(EVERYTHING, document, inline, action, resource), (role, name, action, resource)


@pytest.mark.parametrize("role", ["plan", "audit"])
def test_politica_gerenciada_de_plan_e_audit_carrega_o_deny_estatico_da_mesma_lista(world, role):
    statements = managed(world, role)["Statement"]
    assert {"Effect": "Deny", "Action": LIFECYCLE_DELETES, "Resource": "*"} in statements


def test_politica_gerenciada_do_deploy_nao_carrega_o_deny_estatico(world):
    assert not any(s["Effect"] == "Deny" and s.get("Action") == LIFECYCLE_DELETES
                   for s in managed(world, "deploy")["Statement"])


@pytest.mark.parametrize("role", ["plan", "audit"])
def test_sessao_inline_de_plan_e_audit_nao_repete_o_deny_dos_deletes(role):
    for name, inline in inline_sessions(role).items():
        assert not any(s["Effect"] == "Deny" and s.get("Action") == LIFECYCLE_DELETES
                       for s in inline["Statement"]), (role, name)


def test_identidades_de_plan_e_audit_nao_permitem_nenhum_dos_cinco_deletes(world):
    identities = {"plan": rendered_policies(world, "plan")[0], "audit": json.loads(world[AUDIT_POLICY]["policy"])}
    for role, identity in identities.items():
        for action, resource in DELETE_AND_RESOURCES:
            assert decision(identity, action, resource) != "Allow", (role, action, resource)


def test_sessao_de_ativacao_nega_os_cinco_deletes(native):
    resources, _ = render(native, activation_input(audit_values()), "lifecycle-delete-activation")
    activation = json.loads(resources["aws_iam_policy.plan_activation_session[0]"]["policy"])
    for action, resource in DELETE_AND_RESOURCES:
        assert decision(activation, action, resource) != "Allow", (action, resource)
