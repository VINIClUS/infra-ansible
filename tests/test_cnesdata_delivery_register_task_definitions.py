"""Deploy-only task-definition registration grant that holds whichever resource IAM evaluates."""
import json

import pytest
from test_cnesdata_delivery_oidc import native, render, variables  # noqa: F401

REGISTER = {"Effect": "Allow", "Action": ["ecs:RegisterTaskDefinition"], "Resource": "*"}
TAG = {"Effect": "Allow", "Action": ["ecs:TagResource"], "Resource": "*",
       "Condition": {"StringEquals": {"ecs:CreateAction": "RegisterTaskDefinition"}}}
ACTIONS = {"ecs:RegisterTaskDefinition", "ecs:TagResource"}
REVISION = "arn:aws:ecs:us-east-2:111122223333:task-definition/cnesdata-prod-processor:4"


def flagged(enabled=True):
    values = variables()
    values["audit"] = {"role_name": "cnesdata-test-audit", "workflow_sha": "e" * 40}
    if enabled is not None:
        values["delivery_register_task_definitions"] = enabled
    return values


def registration(policy):
    return [statement for statement in policy["Statement"]
            if ACTIONS & set([statement.get("Action")] if isinstance(statement.get("Action"), str) else statement.get("Action", []))]


def policies(resources):
    return {address: json.loads(value["policy"]) for address, value in resources.items()
            if address.startswith(("aws_iam_role_policy.", "aws_iam_policy."))}


def test_com_a_flag_o_deploy_registra_task_definition_em_qualquer_recurso_e_marca_so_na_criacao(native):
    resources, _ = render(native, flagged(), "register-task-definitions-on")
    documents = policies(resources)
    assert registration(documents['aws_iam_role_policy.delivery["deploy"]']) == [REGISTER, TAG]
    others = {address: registration(policy) for address, policy in documents.items()
              if address != 'aws_iam_role_policy.delivery["deploy"]'}
    assert 'aws_iam_role_policy.delivery["plan"]' in others and "aws_iam_role_policy.delivery_audit[0]" in others
    assert {address: found for address, found in others.items() if found} == {}


@pytest.mark.parametrize("enabled", [None, False])
def test_sem_a_flag_nenhuma_politica_ganha_registro_de_task_definition(native, enabled):
    resources, _ = render(native, flagged(enabled), f"register-task-definitions-{enabled}")
    assert {address: found for address, found in policies(resources).items() if registration(found)} == {}


def test_com_a_flag_a_sessao_do_deploy_registra_em_qualquer_recurso_e_marca_so_na_criacao(native):
    from fixtures.cnesdata_iam_evaluation import effective
    from tools.cnesdata_delivery.session_policy import lifecycle_request
    resources, _ = render(native, flagged(), "register-task-definitions-session")
    identity = json.loads(resources['aws_iam_role_policy.delivery["deploy"]']["policy"])
    managed = json.loads(resources['aws_iam_policy.delivery_session["deploy"]']["policy"])
    governance = {"account_id": "111122223333", "state_bucket": "synthetic-state", "evidence_bucket": "synthetic-evidence",
                  "evidence_prefix": "cnesdata/prod/evidence/",
                  "evidence_kms_key_arn": variables()["github_delivery"]["evidence_kms_arn"],
                  "roles": {"deploy": "arn:aws:iam::111122223333:role/cnesdata-test-deploy"}}
    inline = json.loads(lifecycle_request(governance, "a" * 40, 123, 1, "deploy", "phase-a-deploy",
                                          direction="advance")["Policy"])
    creation = {"ecs:CreateAction": "RegisterTaskDefinition"}
    for resource in ("*", REVISION):
        assert effective(identity, managed, inline, "ecs:RegisterTaskDefinition", resource)
        assert effective(identity, managed, inline, "ecs:TagResource", resource, creation)
        assert not effective(identity, managed, inline, "ecs:TagResource", resource)


@pytest.mark.parametrize("resource", ["*", "arn:aws:ecs:us-east-2:111122223333:task-definition/cnesdata-prod-processor:*"])
def test_product_permissions_com_recurso_curinga_continua_recusado_com_a_flag(native, resource):
    values = flagged()
    values["github_delivery"]["product_permissions"] = [{"actions": ["ecs:RegisterTaskDefinition"], "resources": [resource]}]
    code, _, diagnostics = native.plan(values, "register-task-definitions-wildcard-product")
    assert code != 0 and diagnostics
