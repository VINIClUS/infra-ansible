"""B1a: relações de origem/sink, policies completas e outputs do backend Budget."""

import pytest
from fixtures.cnesdata_aws_bootstrap_native import (
    BUDGET,
    assert_policy,
    observation,
)
from fixtures.cnesdata_aws_bootstrap_native import (
    native as native_fixture,
)

native = native_fixture

def configured(plan, address):
    return next(r["expressions"] for r in plan["configuration"]["root_module"]["resources"]
                if r["address"] == address)


def require_reference(plan, address, field, target):
    configs = plan["configuration"]["root_module"].get("resources", [])
    config = next((r for r in configs if r["address"] == address), None)
    assert config is not None, f"native_config_absent: {address}"
    refs = config.get("expressions", {}).get(field, {}).get("references", [])
    assert any(ref == target or ref.startswith(target + ".") for ref in refs), (
        f"native_binding_reference: {address}.{field} -> {target}"
    )


def assert_backend(plan, case, root):
    """Oráculo semântico fechado; não chama/builda o witness."""
    providers = plan["configuration"]["provider_config"]
    assert set(providers) == {"aws"}, "provider_owner_scope"
    provider = providers["aws"]["expressions"]
    assert "var.region" in provider["region"].get("references", []), "provider_region_binding"
    assert "var.account_id" in provider["allowed_account_ids"].get("references", []), "provider_account_binding"
    assert plan["variables"]["region"]["value"] == case["region"]
    assert plan["variables"]["account_id"]["value"] == case["account_id"]
    assert all(r["provider_config_key"] == "aws" for r in plan["configuration"]["root_module"]["resources"]), "resource_provider_binding"
    declared = case["roots"][root]
    bucket, sink = declared["backend"]["bucket"], declared["logging"]["bucket"]
    prefix = f"access/{bucket}/"
    state_arn, sink_arn = f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{sink}"
    key = case["expected"]["cmk"]
    assert bucket != sink and declared["logging"]["prefix"] == prefix
    assert case["roots"]["foundation"]["backend"]["bucket"] != case["roots"]["budget-backend"]["backend"]["bucket"]
    for label, expected_bucket in (("state", bucket), ("logging", sink)):
        obj = observation(plan, f"aws_s3_bucket.{label}")
        assert obj["bucket"] == expected_bucket, f"bucket_name_binding: {label}"
        assert obj["arn"] == f"arn:aws:s3:::{expected_bucket}", f"bucket_arn_binding: {label}"
        assert obj["force_destroy"] is False, f"bucket_force_destroy: {label}"
        assert obj.get("object_lock_enabled") is False, f"bucket_object_lock: {label}"
        assert obj["tags"] == case["tags"] | {"Owner": declared["owner"]}, f"bucket_owner_tags: {label}"
        for kind in ("aws_s3_bucket_public_access_block", "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_policy"):
            control = observation(plan, f"{kind}.{label}")
            assert control["bucket"] == expected_bucket, f"bucket_binding: {kind}.{label}"
            require_reference(plan, f"{kind}.{label}", "bucket", f"aws_s3_bucket.{label}")
        public = observation(plan, f"aws_s3_bucket_public_access_block.{label}")
        assert all(public[k] is True for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")), f"public_access_block: {label}"
        if root == "foundation" or label == "logging":
            ownership = observation(plan, f"aws_s3_bucket_ownership_controls.{label}")
            assert ownership["bucket"] == expected_bucket, f"ownership_bucket_binding: {label}"
            assert ownership["rule"][0]["object_ownership"] == "BucketOwnerEnforced", f"ownership_mode: {label}"
            require_reference(plan, f"aws_s3_bucket_ownership_controls.{label}", "bucket", f"aws_s3_bucket.{label}")
    versioning = observation(plan, "aws_s3_bucket_versioning.state")
    assert versioning["bucket"] == bucket, "versioning_bucket_binding"
    assert len(versioning["versioning_configuration"]) == 1
    assert versioning["versioning_configuration"][0]["status"] == "Enabled", "state_versioning"
    require_reference(plan, "aws_s3_bucket_versioning.state", "bucket", "aws_s3_bucket.state")
    for label, algorithm, expected_key in (("state", "aws:kms", key), ("logging", "AES256", None)):
        rules = observation(plan, f"aws_s3_bucket_server_side_encryption_configuration.{label}")["rule"]
        assert len(rules) == 1
        encryption = rules[0]["apply_server_side_encryption_by_default"]
        assert len(encryption) == 1
        assert encryption[0]["sse_algorithm"] == algorithm, f"encryption_algorithm: {label}"
        if expected_key:
            assert encryption[0]["kms_master_key_id"] == expected_key, f"encryption_key_binding: {label}"
        if label == "logging":
            configured_rule = configured(plan, "aws_s3_bucket_server_side_encryption_configuration.logging")["rule"][0]
            assert "kms_master_key_id" not in configured_rule["apply_server_side_encryption_by_default"][0], "logging_configured_kms_key"
        if label == "state":
            assert rules[0]["bucket_key_enabled"] is True, "state_bucket_key"
    tls = lambda arn: {"Effect": "Deny", "Action": "s3:*", "Principal": "*",
                       "Resource": [arn, arn + "/*"],
                       "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
    assert_policy(observation(plan, "aws_s3_bucket_policy.state")["policy"], {
        "Version": "2012-10-17", "Statement": [tls(state_arn)]}, "state_bucket")
    assert_policy(observation(plan, "aws_s3_bucket_policy.logging")["policy"], {
        "Version": "2012-10-17", "Statement": [tls(sink_arn), {
            "Effect": "Allow", "Principal": {"Service": "logging.s3.amazonaws.com"},
            "Action": "s3:PutObject", "Resource": sink_arn + "/" + prefix + "*",
            "Condition": {"StringEquals": {"aws:SourceAccount": case["account_id"]},
                          "ArnLike": {"aws:SourceArn": state_arn}}}]}, "logging_bucket")
    logging = observation(plan, "aws_s3_bucket_logging.state")
    assert logging["bucket"] == bucket, "logging_source_binding"
    assert logging["target_bucket"] == sink, "logging_target_binding"
    assert logging["target_prefix"] == prefix, "logging_prefix"
    require_reference(plan, "aws_s3_bucket_logging.state", "bucket", "aws_s3_bucket.state")
    require_reference(plan, "aws_s3_bucket_logging.state", "target_bucket", "aws_s3_bucket.logging")
    lifecycle = observation(plan, "aws_s3_bucket_lifecycle_configuration.logging")
    assert lifecycle["bucket"] == sink, "lifecycle_bucket_binding"
    require_reference(plan, "aws_s3_bucket_lifecycle_configuration.logging", "bucket", "aws_s3_bucket.logging")
    assert len(lifecycle["rule"]) == 1, "lifecycle_rule_count"
    rule = lifecycle["rule"][0]
    assert rule["status"] == "Enabled", "lifecycle_enabled"
    assert len(rule["filter"]) == 1 and rule["filter"][0]["prefix"] == prefix, "lifecycle_prefix"
    assert len(rule["expiration"]) == 1 and rule["expiration"][0]["days"] == 30, "lifecycle_expiration"
    assert not rule["expiration"][0].get("expired_object_delete_marker")
    assert not rule["expiration"][0].get("date")
    # Optional+computed fields receive random mock values; inspect native configuration.
    configured_rule = configured(plan, "aws_s3_bucket_lifecycle_configuration.logging")["rule"][0]
    assert "prefix" not in configured_rule, "lifecycle_legacy_prefix"
    for forbidden in ("transition", "noncurrent_version_transition", "noncurrent_version_expiration"):
        assert not rule.get(forbidden), f"lifecycle_forbidden: {forbidden}"
    assert not rule["filter"][0].get("and") and not rule["filter"][0].get("tag"), "lifecycle_unreviewed_filter"
    # A allowlist completa também exclui Requester Pays, sink versioning,
    # ObjectLock/default retention e lifecycle adicional que poderia purgar state.
    managed = {r["address"] for r in plan.get("resource_changes", []) if r.get("mode") == "managed"}
    assert not any(a.startswith(("aws_s3_bucket_request_payment_configuration.", "aws_s3_bucket_object_lock_configuration.")) for a in managed)
    output_name = "bootstrap_foundation" if root == "foundation" else "bootstrap_backend"
    outputs = plan.get("planned_values", {}).get("outputs", {})
    assert output_name in outputs, f"backend_output_absent: {output_name}"
    fragment = outputs[output_name]["value"]
    assert fragment["contract_version"] == 1
    assert fragment["account_id"] == case["account_id"] and fragment["region"] == case["region"]
    assert fragment["kms_key_arn"] == key
    assert fragment["ready_for_product"] is False and fragment["ready_for_budget_sns"] is False
    assert fragment.get("schema_version") != 2 and not ({"roles_anywhere", "github", "budget_freeze"} & fragment.keys())
    assert set(fragment["backends"]) == {root}, "output_owner_scope"
    assert fragment["backends"][root] == {"bucket": bucket, "key": declared["backend"]["key"],
        "region": case["region"], "use_lockfile": True, "encrypt": True,
        "kms_key_id": key, "owner": declared["owner"]}, "backend_output_binding"
    refs = plan["configuration"]["root_module"]["outputs"][output_name]["expression"].get("references", [])
    assert any(x.startswith("aws_s3_bucket.state") for x in refs), "backend_output_native_reference"


def assert_budget(plan, case):
    managed = [r for r in plan.get("resource_changes", []) if r.get("mode") == "managed"]
    assert {r["address"] for r in managed} == set(BUDGET), "mandatory_budget_backend_12_absent_or_extra"
    assert len(managed) == 12 and all(r["change"]["actions"] == ["create"] for r in managed)
    assert_backend(plan, case, "budget-backend")


@pytest.mark.parametrize("case_id", ["a", "b"])
def test_backend_budget_atual_exige_12_recursos_relacoes_e_output(native, case_id):
    result = native.plan(case_id, "budget-backend", "target")
    assert_budget(result["plan"], result["case"])


@pytest.mark.parametrize("case_id", ["a", "b"])
def test_witness_budget_nativo_satisfaz_contrato_com_nomes_distintos(native, case_id):
    result = native.plan(case_id, "budget-backend", "witness")
    assert_budget(result["plan"], result["case"])


@pytest.mark.parametrize("address", ["aws_s3_bucket.state", "aws_s3_bucket.logging"])
def test_witness_budget_prova_prevent_destroy_nativo(native, address):
    result = native.plan("a", "budget-backend", "witness")
    assert_budget(result["plan"], result["case"])
    native.prove_prevent_destroy(result, address)


@pytest.mark.parametrize("address", ["aws_s3_bucket.state", "aws_s3_bucket.logging"])
def test_backend_budget_atual_exige_prevent_destroy_nativo(native, address):
    result = native.plan("a", "budget-backend", "target")
    assert_budget(result["plan"], result["case"])
    native.prove_prevent_destroy(result, address)


@pytest.mark.parametrize("mutation,rejection", [
    ("state_bucket_policy_deny_all", "policy_document_mismatch: state_bucket"),
    ("logging_deny_delivery", "policy_document_mismatch: logging_bucket"),
    ("bucket_controls_attach_to_foreign_bucket", "bucket_binding:"),
    ("logging_lifecycle_expires_state", "lifecycle_bucket_binding"),
    ("logging_glacier_only", "lifecycle_forbidden: transition"),
    ("logging_sourcearn_absent", "policy_document_mismatch: logging_bucket"),
    ("logging_object_lock_only", "bucket_object_lock: logging"),
    ("logging_cycle_to_source", "logging_target_binding"),
])
def test_backend_budget_rejeita_mutantes_nativos(native, mutation, rejection):
    baseline = native.plan("a", "budget-backend", "witness")
    assert_budget(baseline["plan"], baseline["case"])
    altered = native.plan("a", "budget-backend", "witness", mutation)
    with pytest.raises(AssertionError, match=rejection):
        assert_budget(altered["plan"], altered["case"])


def test_backend_budget_rejeita_conta_estrangeira_sem_alterar_validacao(native):
    with pytest.raises(AssertionError, match="target_input_contract_incompatible") as error:
        native.plan("foreign", "budget-backend", "target")
    assert "account_id deve ser 836651842853" in str(error.value)
