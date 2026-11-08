"""Rendered native role/trust/effective policy checks, not Terraform text assertions."""
import json
from pathlib import Path

import pytest

from test_cnesdata_delivery_roles_anywhere import inputs

FIXTURE = Path(__file__).parent / "fixtures/cnesdata_delivery_roles_anywhere"


@pytest.fixture(scope="module")
def native():
    from fixtures.cnesdata_delivery_oidc_native import Native
    instance = Native()
    yield instance
    instance.temp.cleanup()


def variables():
    return {"account_id": "111122223333", "region": "us-east-2", "ca_certificate_pem": (FIXTURE / "ca.crt").read_text(),
            "identity": {"trust_anchor_name": "synthetic-anchor", "role_name": "synthetic-cnesdata-api", "profile_name": "synthetic-profile",
                         "common_name": "synthetic-cnesdata-api", "san_uri": "spiffe://synthetic.invalid/cnesdata/api", "duration_seconds": 900},
            "github_delivery": {"provider_arn": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
                "provider_client_ids": ["sts.amazonaws.com"], "provider_thumbprints": ["0" * 40], "read_resource_arns": [],
                "plan_role_name": "cnesdata-test-plan", "deploy_role_name": "cnesdata-test-deploy", "plan_workflow_sha": "a" * 40,
                "deploy_workflow_sha": "b" * 40, "enabled_until": "2030-01-01T00:00:00Z", "state_bucket_arn": "arn:aws:s3:::synthetic-state",
                "state_kms_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000001",
                "evidence_bucket_arn": "arn:aws:s3:::synthetic-evidence",
                "evidence_kms_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000002",
                "evidence_prefix": "cnesdata/prod/evidence/", "product_permissions": [], "pass_roles": []}}


def render(native, values, name):
    code, plans, errors = native.plan(values, name)
    assert code == 0, json.dumps(errors, indent=2)
    values = plans[0]["planned_values"]
    return {r["address"]: r["values"] for r in values["root_module"]["resources"] if r["mode"] == "managed"}, values["outputs"]


def test_rendered_oidc_roles_are_separate_and_exact(native):
    resources, outputs = render(native, variables(), "oidc")
    for role, char in (("plan", "a"), ("deploy", "b")):
        rendered = resources[f'aws_iam_role.delivery["{role}"]']
        trust = json.loads(rendered["assume_role_policy"])
        assert len(trust["Statement"]) == 1
        statement = trust["Statement"][0]
        assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
        assert statement["Principal"] == {"Federated": variables()["github_delivery"]["provider_arn"]}
        exact = statement["Condition"]["StringEquals"]
        assert exact == {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub":
            f"repo:VINIClUS/CnesData:environment:production:job_workflow_ref:VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-{role}-gate.yml@{char * 40}"}
        assert statement["Condition"]["DateLessThan"] == {"aws:CurrentTime": "2030-01-01T00:00:00Z"}
        policy = json.loads(resources[f'aws_iam_role_policy.delivery["{role}"]']["policy"])
        assert any(s["Effect"] == "Deny" and "sts:AssumeRole" in s["Action"] for s in policy["Statement"])
        state = "arn:aws:s3:::synthetic-state/cnesdata/prod/opentofu.tfstate"
        writers = [s for s in policy["Statement"] if s["Effect"] == "Allow" and s["Resource"] == state and "s3:PutObject" in s["Action"]]
        assert bool(writers) is (role == "deploy")
        assert not any(s["Effect"] == "Allow" and any(a.endswith(":*") for a in s["Action"]) for s in policy["Statement"])
    assert set(outputs["github"]["value"]) == {"infrastructure_plan_role_arn", "infrastructure_deploy_role_arn"}
    assert not any(key.startswith("aws_iam_openid_connect_provider.") for key in resources)


@pytest.mark.parametrize("field,value", [("plan_workflow_sha", "main"), ("provider_arn", "arn:aws:iam::999988887777:oidc-provider/token.actions.githubusercontent.com")])
def test_native_rejects_unreviewed_provider_or_mutable_trust(native, field, value):
    data = variables()
    data["github_delivery"][field] = value
    code, _, diagnostics = native.plan(data, "invalid-" + field)
    assert code != 0 and diagnostics
