"""Actual ToFu-rendered D1/D3 matrix; no local execution is claimed by the S3 proposal."""

import json

import pytest

from test_cnesdata_delivery_oidc import render, variables
from fixtures.cnesdata_delivery_oidc_native import Native
from fixtures.cnesdata_iam_evaluation import allowed
from fixtures.cnesdata_session_cases import assert_matrix, inline


@pytest.fixture(scope="module")
def native():
    instance = Native()
    yield instance
    instance.temp.cleanup()


@pytest.mark.parametrize(
    "same_bucket,same_key", [(False, False), (False, True), (True, False), (True, True)]
)
def test_documentos_nativos_preservam_intersecao_com_uniao_e_deny_global(
    native, same_bucket, same_key
):
    values = variables()
    settings = values["github_delivery"]
    settings["evidence_bucket_arn"] = "arn:aws:s3:::cnesdata-evid-4f6e21"
    settings["state_bucket_arn"] = (
        settings["evidence_bucket_arn"]
        if same_bucket
        else "arn:aws:s3:::cnesdata-state-4f6e21"
    )
    if same_key:
        settings["state_kms_arn"] = settings["evidence_kms_arn"]
    product = "arn:aws:s3:::cnesdata-product-aaaaaa"
    settings["read_resource_arns"] = [product]
    settings["product_permissions"] = [
        {"actions": ["s3:PutBucketObjectLockConfiguration"], "resources": [product]}
    ]
    resources, outputs = render(
        native, values, f"session-sharing-{same_bucket}-{same_key}"
    )
    governance = {
        "account_id": values["account_id"],
        "evidence_prefix": settings["evidence_prefix"],
        "evidence_bucket": settings["evidence_bucket_arn"].split(":::")[1],
        "state_bucket": settings["state_bucket_arn"].split(":::")[1],
        "evidence_kms_key_arn": settings["evidence_kms_arn"],
        "state_kms_key_arn": settings["state_kms_arn"],
        "roles": {
            role: f"arn:aws:iam::{values['account_id']}:role/{settings[role + '_role_name']}"
            for role in ("plan", "deploy")
        },
    }
    assert set(outputs["github"]["value"]) == {
        "infrastructure_plan_role_arn",
        "infrastructure_deploy_role_arn",
    }
    assert not any(
        "attachment" in address or "permissions_boundary" in address
        for address in resources
    )
    for role in ("plan", "deploy"):
        identity = json.loads(
            resources[f'aws_iam_role_policy.delivery["{role}"]']["policy"]
        )
        managed = json.loads(
            resources[f'aws_iam_policy.delivery_session["{role}"]']["policy"]
        )
        session = inline(governance, role)
        assert_matrix(
            identity, managed, json.loads(session["Policy"]), governance, role
        )


def test_colisao_de_listing_produto_e_evidence_sem_prefixos_governados_fecha(native):
    values = variables()
    values["github_delivery"]["read_resource_arns"] = [
        values["github_delivery"]["evidence_bucket_arn"]
    ]
    code, _, diagnostics = native.plan(values, "session-product-evidence-collision")
    assert code != 0 and diagnostics


@pytest.mark.parametrize("product_count,pass_count", [(0, 0), (0, 1), (1, 0), (1, 1), (2, 2)])
def test_permissoes_deploy_heterogeneas_preservam_escopo_e_condicoes(
    native, product_count, pass_count
):
    values = variables()
    settings = values["github_delivery"]
    products = [f"arn:aws:s3:::cnesdata-product-{i}" for i in range(2)]
    roles = [f"arn:aws:iam::111122223333:role/cnesdata-task-{i}" for i in range(2)]
    settings["product_permissions"] = [
        {"actions": ["s3:PutBucketObjectLockConfiguration"], "resources": [product]}
        for product in products[:product_count]
    ]
    settings["pass_roles"] = [
        {"arn": role, "service": "ecs-tasks.amazonaws.com"}
        for role in roles[:pass_count]
    ]
    resources, _ = render(native, values, f"session-deploy-{product_count}-{pass_count}")
    for role in ("plan", "deploy"):
        identity = json.loads(resources[f'aws_iam_role_policy.delivery["{role}"]']["policy"])
        assert allowed(
            identity, "s3:PutObject", settings["state_bucket_arn"] + "/cnesdata/prod/opentofu.tfstate"
        ) is (role == "deploy")
        for index, product in enumerate(products):
            assert allowed(identity, "s3:PutBucketObjectLockConfiguration", product) is (
                role == "deploy" and index < product_count
            )
        for index, passed_role in enumerate(roles):
            assert allowed(
                identity, "iam:PassRole", passed_role,
                {"iam:PassedToService": "ecs-tasks.amazonaws.com"},
            ) is (role == "deploy" and index < pass_count)
            assert not allowed(identity, "iam:PassRole", passed_role)
            assert not allowed(
                identity, "iam:PassRole", passed_role,
                {"iam:PassedToService": "lambda.amazonaws.com"},
            )
