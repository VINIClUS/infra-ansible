"""B1a: documentos completos e bindings nativos sem executar AWS."""

import copy

import pytest
from fixtures.cnesdata_aws_bootstrap_mutations import CONTROLS, MUTATIONS
from fixtures.cnesdata_aws_bootstrap_native import (
    FOUNDATION,
    assert_policy,
    observation,
)
from fixtures.cnesdata_aws_bootstrap_native import (
    native as native_fixture,
)
from test_cnesdata_aws_bootstrap_backend import assert_backend, require_reference

native = native_fixture


def _permission_targets(case):
    buckets, logs, objects, locks = [], [], [], []
    for root in ("foundation", "budget-backend"):
        declared = case["roots"][root]
        bucket = "arn:aws:s3:::" + declared["backend"]["bucket"]
        obj = bucket + "/" + declared["backend"]["key"]
        buckets.append(bucket)
        logs.append("arn:aws:s3:::" + declared["logging"]["bucket"])
        objects.append(obj)
        locks.append(obj + ".tflock")
    return buckets, logs, objects, locks


def _executor_permissions(buckets, objects, locks, key):
    return [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"],
         "Resource": objects + locks},
        {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": locks},
        {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
         "Resource": buckets},
        {"Effect": "Allow", "Action": ["kms:Encrypt", "kms:Decrypt",
         "kms:GenerateDataKey", "kms:DescribeKey"], "Resource": key},
    ]


def _readback_permissions(targets, object_sets, key):
    buckets, logs = targets
    objects, locks = object_sets
    return [
        {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:GetBucketVersioning",
         "s3:GetBucketLogging", "s3:GetEncryptionConfiguration", "s3:GetBucketPolicy",
         "s3:GetBucketOwnershipControls", "s3:GetBucketPublicAccessBlock",
         "s3:GetBucketTagging"], "Resource": buckets + logs},
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": buckets},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
         "Resource": objects + locks},
        {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key},
        {"Effect": "Allow", "Action": ["kms:DescribeKey", "kms:GetKeyPolicy",
         "kms:GetKeyRotationStatus", "kms:ListResourceTags"], "Resource": key},
    ]


def expected_permissions(case):
    buckets, logs, objects, locks = _permission_targets(case)
    key = case["expected"]["cmk"]
    return _executor_permissions(buckets, objects, locks, key), _readback_permissions(
        (buckets, logs), (objects, locks), key)

def assert_cmk(plan, case):
    key = observation(plan, "aws_kms_key.foundation")
    required = {
        "key_usage": "ENCRYPT_DECRYPT",
        "customer_master_key_spec": "SYMMETRIC_DEFAULT",
        "multi_region": False,
        "is_enabled": True,
        "enable_key_rotation": True,
        "deletion_window_in_days": 30,
        "bypass_policy_lockout_safety_check": False,
    }
    for field, value in required.items():
        assert key[field] == value, f"cmk_property: {field}"
    assert key["arn"] == case["expected"]["cmk"], "cmk_arn_binding"
    assert key["tags"] == case["tags"] | {"Owner": case["roots"]["foundation"]["owner"]}
    assert_policy(
        key["policy"],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::" + case["account_id"] + ":root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        },
        "cmk_account_delegation",
    )
    config = next(
        r
        for r in plan["configuration"]["root_module"]["resources"]
        if r["address"] == "aws_kms_key.foundation"
    )
    refs = config["expressions"]["policy"].get("references", []) + config.get("depends_on", [])
    assert not any(x.startswith(("aws_iam_role.", "aws_iam_policy.")) for x in refs), (
        "cmk_role_cycle"
    )


def _identity_resources(plan, case):
    addresses = [("operator", "aws_iam_user.bootstrap_operator"),
                 ("readback", "aws_iam_role.bootstrap_readback"),
                 ("executor", "aws_iam_role.bootstrap_executor"),
                 ("boundary", "aws_iam_policy.executor_boundary")]
    for label, address in addresses:
        observed = observation(plan, address)
        assert observed["name"] == case["identities"][label]["name"], (
            f"identity_name_binding: {label}"
        )
        assert observed["path"] == case["identities"][label]["path"], (
            f"identity_path_binding: {label}"
        )
        assert observed["arn"] == case["expected"][label], f"identity_arn_binding: {label}"
        assert observed["tags"] == case["tags"] | {"Owner": case["roots"]["foundation"]["owner"]}


def _operator_policies(plan, case, user):
    attachment = observation(plan, "aws_iam_user_policy_attachment.local_login")
    assert attachment["policy_arn"] == "arn:aws:iam::aws:policy/SignInLocalDevelopmentAccess"
    assert attachment["user"] == user["name"], "login_user_binding"
    require_reference(plan, "aws_iam_user_policy_attachment.local_login", "user",
                      "aws_iam_user.bootstrap_operator")
    assume = observation(plan, "aws_iam_user_policy.local_assume")
    assert assume["user"] == user["name"], "assume_user_binding"
    require_reference(plan, "aws_iam_user_policy.local_assume", "user",
                      "aws_iam_user.bootstrap_operator")
    assert_policy(assume["policy"], {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole",
        "Resource": [case["expected"]["readback"], case["expected"]["executor"]],
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}, "local_assume")


def _role_policies(plan, user):
    for label in ("readback", "executor"):
        address = "aws_iam_role.bootstrap_" + label
        require_reference(plan, "aws_iam_user_policy.local_assume", "policy", address)
        role = observation(plan, address)
        assert role["max_session_duration"] == 3600
        assert_policy(role["assume_role_policy"], {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole",
            "Principal": {"AWS": user["arn"]},
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}, "trust_" + label)
        require_reference(plan, address, "assume_role_policy", "aws_iam_user.bootstrap_operator")
        inline = "aws_iam_role_policy.bootstrap_" + label
        assert observation(plan, inline)["role"] == role["name"], (
            f"inline_role_binding: {label}"
        )
        require_reference(plan, inline, "role", address)


def assert_identities(plan, case):
    _identity_resources(plan, case)
    user = observation(plan, "aws_iam_user.bootstrap_operator")
    assert user["force_destroy"] is False
    _operator_policies(plan, case, user)
    _role_policies(plan, user)
    executor = observation(plan, "aws_iam_role.bootstrap_executor")
    assert executor["permissions_boundary"] == case["expected"]["boundary"], (
        "executor_boundary_binding"
    )
    require_reference(plan, "aws_iam_role.bootstrap_executor", "permissions_boundary",
                      "aws_iam_policy.executor_boundary")

def assert_foundation(plan, case):
    managed = [r for r in plan.get("resource_changes", []) if r.get("mode") == "managed"]
    assert {r["address"] for r in managed} == set(FOUNDATION), (
        "mandatory_foundation_22_absent_or_extra"
    )
    assert len(managed) == 22 and all(r["change"]["actions"] == ["create"] for r in managed)
    assert_cmk(plan, case)
    assert_identities(plan, case)
    executor, readback = expected_permissions(case)
    for address, statements in (
        ("aws_iam_policy.executor_boundary", executor),
        ("aws_iam_role_policy.bootstrap_executor", executor),
        ("aws_iam_role_policy.bootstrap_readback", readback),
    ):
        assert_policy(
            observation(plan, address)["policy"],
            {"Version": "2012-10-17", "Statement": statements},
            address,
        )
        require_reference(plan, address, "policy", "aws_kms_key.foundation")
    assert_backend(plan, case, "foundation")
    output = plan["configuration"]["root_module"]["outputs"]["bootstrap_foundation"]
    refs = output["expression"].get("references", [])
    assert any(x.startswith("aws_kms_key.foundation.") for x in refs), "cmk_output_native_reference"
    fragment = plan["planned_values"]["outputs"]["bootstrap_foundation"]["value"]
    product_keys = {
        "schema_version",
        "account_id",
        "kms_key_arn",
        "roles_anywhere",
        "github",
        "budget_freeze",
        "storage",
        "account_baseline",
    }
    assert not (product_keys <= fragment.keys() and fragment["schema_version"] == 2), (
        "product_contract_premature"
    )


@pytest.mark.parametrize("case_id", ["a", "b"])
def test_foundation_atual_exige_22_recursos_policies_relacoes_e_output(native, case_id):
    result = native.plan(case_id, "foundation", "target")
    assert_foundation(result["plan"], result["case"])


@pytest.mark.parametrize("case_id", ["a", "b"])
def test_witness_foundation_nativo_satisfaz_contrato_com_nomes_distintos(native, case_id):
    result = native.plan(case_id, "foundation", "witness")
    assert_foundation(result["plan"], result["case"])


@pytest.mark.parametrize(
    "address",
    ["aws_kms_key.foundation", "aws_s3_bucket.state", "aws_s3_bucket.logging"],
)
def test_witness_foundation_prova_prevent_destroy_nativo(native, address):
    result = native.plan("a", "foundation", "witness")
    assert_foundation(result["plan"], result["case"])
    native.prove_prevent_destroy(result, address)


REJECTIONS = {
    "executor_boundary_deny_all": "policy_document_mismatch: aws_iam_policy.executor_boundary",
    "executor_policy_deny_all": "policy_document_mismatch: aws_iam_role_policy.bootstrap_executor",
    "readback_policy_deny_all": "policy_document_mismatch: aws_iam_role_policy.bootstrap_readback",
    "executor_conditions_wrong_account": (
        "policy_document_mismatch: aws_iam_policy.executor_boundary"
    ),
    "readback_action_resource_crosswired": (
        "policy_document_mismatch: aws_iam_role_policy.bootstrap_readback"
    ),
    "kms_condition_prevents_recovery": "policy_document_mismatch: cmk_account_delegation",
    "state_bucket_policy_deny_all": "policy_document_mismatch: state_bucket",
    "logging_deny_delivery": "policy_document_mismatch: logging_bucket",
    "executor_boundary_points_elsewhere": "executor_boundary_binding",
    "executor_inline_policy_attached_to_readback": "inline_role_binding: executor",
    "assume_policy_attached_to_other_user": "assume_user_binding",
    "bucket_controls_attach_to_foreign_bucket": "bucket_binding:",
    "state_bucket_policy_allows_delete_state": "policy_document_mismatch: state_bucket",
    "readback_role_name_does_not_match_mock_arn": "identity_name_binding: readback",
    "logging_lifecycle_expires_state": "lifecycle_bucket_binding",
    "logging_lifecycle_wrong_prefix_and_glacier": "lifecycle_prefix",
    "logging_owner_foreign_and_object_lock": "bucket_object_lock: logging",
    "control_trust_missing_mfa": "policy_document_mismatch: trust_readback",
    "control_kms_rotation_disabled": "cmk_property: enable_key_rotation",
    "control_executor_deletes_state": (
        "policy_document_mismatch: aws_iam_role_policy.bootstrap_executor"
    ),
    "control_logging_sourceaccount_absent": "policy_document_mismatch: logging_bucket",
}


@pytest.mark.parametrize("mutation", MUTATIONS + CONTROLS)
def test_oraculo_rejeita_sobreviventes_e_preserva_controles_nativos(native, mutation):
    baseline = native.plan("a", "foundation", "witness")
    assert_foundation(baseline["plan"], baseline["case"])
    altered = native.mutated_witness_plan(mutation, root="foundation")
    with pytest.raises(AssertionError, match=REJECTIONS[mutation]):
        assert_foundation(altered["plan"], altered["case"])


EXTRA_REJECTIONS = {
    "logging_glacier_only": "lifecycle_forbidden: transition",
    "logging_owner_only": "bucket_owner_tags: logging",
    "logging_object_lock_only": "bucket_object_lock: logging",
    "logging_sourcearn_absent": "policy_document_mismatch: logging_bucket",
    "logging_wildcard_resource": "policy_document_mismatch: logging_bucket",
    "logging_sse_kms": "encryption_algorithm: logging",
    "logging_cycle_to_source": "logging_target_binding",
    "logging_wrong_source": "logging_source_binding",
    "logging_removed": "mandatory_foundation_22_absent_or_extra",
    "logging_expiration_31": "lifecycle_expiration",
    "logging_prefix_only": "logging_prefix",
    "login_attached_other_user": "login_user_binding",
}


@pytest.mark.parametrize("mutation", EXTRA_REJECTIONS)
def test_oraculo_rejeita_defeitos_independentes_nativos(native, mutation):
    baseline = native.plan("a", "foundation", "witness")
    assert_foundation(baseline["plan"], baseline["case"])
    altered = native.mutated_witness_plan(mutation, root="foundation")
    with pytest.raises(AssertionError, match=EXTRA_REJECTIONS[mutation]):
        assert_foundation(altered["plan"], altered["case"])


@pytest.mark.parametrize(
    "address,statement_index",
    [("aws_iam_policy.executor_boundary", i) for i in range(4)]
    + [("aws_iam_role_policy.bootstrap_executor", i) for i in range(4)]
    + [("aws_iam_role_policy.bootstrap_readback", i) for i in range(5)],
)
def test_documento_json_rejeita_remocao_de_cada_permissao_necessaria(
    native, address, statement_index
):
    import json

    baseline = native.plan("a", "foundation", "witness")
    assert_foundation(baseline["plan"], baseline["case"])
    original = json.loads(observation(baseline["plan"], address)["policy"])
    actions = original["Statement"][statement_index]["Action"]
    actions = actions if isinstance(actions, list) else [actions]
    for action in actions:
        altered = copy.deepcopy(baseline["plan"])
        attributes = observation(altered, address)
        document = copy.deepcopy(original)
        statement = document["Statement"][statement_index]
        remaining = [x for x in actions if x != action]
        if remaining:
            statement["Action"] = remaining
        else:
            document["Statement"].pop(statement_index)
        attributes["policy"] = json.dumps(document)
        with pytest.raises(AssertionError, match="policy_document_mismatch: " + address):
            assert_foundation(altered, baseline["case"])


@pytest.mark.parametrize(
    "address",
    ["aws_kms_key.foundation", "aws_s3_bucket.state", "aws_s3_bucket.logging"],
)
def test_foundation_atual_exige_prevent_destroy_nativo(native, address):
    result = native.plan("a", "foundation", "target")
    assert_foundation(result["plan"], result["case"])
    native.prove_prevent_destroy(result, address)
