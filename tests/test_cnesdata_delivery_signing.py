"""EXT2 offline signing behavior. Synthetic adapters never stand in for production authority."""

import base64
import copy
from datetime import datetime, timezone
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import shutil
import os
import sys
import subprocess
import io
import zipfile
from types import SimpleNamespace

import pytest

from fixtures.cnesdata_delivery_ext2 import (
    ACCOUNT,
    KEY,
    KEYS,
    PIN,
    REPOSITORY,
    SIGNING_KEY,
    SOURCE,
    S3,
    canonical,
    sha,
    transport_case,
)


@pytest.fixture(scope="module")
def ext2_native():
    from fixtures.cnesdata_delivery_ext2.inventory import Ext2Native

    harness = Ext2Native()
    yield harness
    harness.temp.cleanup()


def test_disabled_ext2_has_no_resources_or_usable_output(ext2_native):
    from fixtures.cnesdata_delivery_ext2.inventory import FOUR, variables, values

    v = variables(False)
    v.pop("ext2_enabled")  # The actual default must close it.
    code, plans, errors = ext2_native.plan(v, "ext2-disabled")
    assert code == 0, errors
    assert not set(values(plans[0])) & FOUR
    assert plans[0]["planned_values"]["outputs"]["ext2"]["value"] is None


def test_ext2_native_creates_exactly_four_with_independent_full_policy_oracles(
    ext2_native,
):
    from fixtures.cnesdata_delivery_ext2.inventory import (
        ALIAS,
        FOUR,
        ROLE,
        key_policy,
        policy,
        trust,
        variables,
        values,
    )

    v = variables()
    code, plans, errors = ext2_native.plan(v, "ext2-four")
    assert code == 0, errors
    resources = values(plans[0])
    assert set(resources) & FOUR == FOUR
    assert len(resources) == 13  # 9 pre-existing delivery/RA resources, 4 EXT2.
    role = resources["aws_iam_role.ext2_gate[0]"]
    assert role["name"] == ROLE.rsplit("/", 1)[1]
    assert json.loads(role["assume_role_policy"]) == trust(v)
    inline = resources["aws_iam_role_policy.ext2_gate[0]"]
    assert inline["role"] == role["name"]
    assert json.loads(inline["policy"]) == policy(v)
    key = resources["aws_kms_key.ext2_signing[0]"]
    assert (
        key["key_usage"] == "SIGN_VERIFY"
        and key["customer_master_key_spec"] == "ECC_NIST_P256"
    )
    assert key["is_enabled"] is True and key["multi_region"] is False
    assert json.loads(key["policy"]) == key_policy(v)
    alias = resources["aws_kms_alias.ext2_signing[0]"]
    assert (
        alias["name"] == ALIAS
        and alias["target_key_id"] == SIGNING_KEY.rsplit("/", 1)[1]
    )


# Operations an administrator needs to create, refresh and manage the key and its alias.
# AWS requires kms:CreateAlias/UpdateAlias/DeleteAlias in the TARGET key's policy (alias-access.html)
# and the CreateKey lockout check requires the caller to keep kms:PutKeyPolicy.
EXT2_ADMIN_REQUIRED = {
    "kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:GetPublicKey",
    "kms:ListResourceTags", "kms:GetKeyRotationStatus",
    "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias",
}
EXT2_SIGNING_ONLY = {"kms:Sign", "kms:Verify", "kms:*"}


def ext2_key_grants(document):
    """Independent oracle: principal -> unconditional Allow actions in a rendered key policy."""
    grants = {}
    for statement in document["Statement"]:
        assert statement["Effect"] == "Allow" and statement["Resource"] == "*"
        principals = statement["Principal"]["AWS"]
        actions = statement["Action"]
        for principal in [principals] if isinstance(principals, str) else principals:
            entry = grants.setdefault(principal, set())
            entry.update([actions] if isinstance(actions, str) else actions)
    return grants


def ext2_key_policy_admin_violations(document, admins, gate):
    grants = ext2_key_grants(document)
    problems = []
    for admin in admins:
        missing = EXT2_ADMIN_REQUIRED - grants.get(admin, set())
        if missing:
            problems.append(("missing", admin, sorted(missing)))
        if grants.get(admin, set()) & EXT2_SIGNING_ONLY:
            problems.append(("signing", admin))
    if not any("kms:CreateAlias" in actions for actions in grants.values()):
        problems.append(("alias-unreachable",))
    if set(grants) - set(admins) - {gate}:
        problems.append(("extra-principal", sorted(set(grants) - set(admins) - {gate})))
    return problems


def test_ext2_key_policy_oracle_detects_admin_mutations():
    from fixtures.cnesdata_delivery_ext2.inventory import ROLE

    admin = f"arn:aws:iam::{ACCOUNT}:role/synthetic-delivery-operator"
    good = {"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": [admin]}, "Action": sorted(EXT2_ADMIN_REQUIRED), "Resource": "*"},
        {"Effect": "Allow", "Principal": {"AWS": ROLE}, "Action": "kms:Sign", "Resource": "*"},
    ]}
    assert ext2_key_policy_admin_violations(good, [admin], ROLE) == []
    signing = copy.deepcopy(good)
    signing["Statement"][0]["Action"].append("kms:Sign")
    assert ("signing", admin) in ext2_key_policy_admin_violations(signing, [admin], ROLE)
    no_alias = copy.deepcopy(good)
    no_alias["Statement"][0]["Action"].remove("kms:CreateAlias")
    problems = ext2_key_policy_admin_violations(no_alias, [admin], ROLE)
    assert ("alias-unreachable",) in problems and problems[0][0] == "missing"
    extra = copy.deepcopy(good)
    extra["Statement"][1]["Principal"]["AWS"] = [ROLE, f"arn:aws:iam::{ACCOUNT}:root"]
    assert ext2_key_policy_admin_violations(extra, [admin], ROLE)[0][0] == "extra-principal"


@pytest.mark.parametrize("admins", [
    [f"arn:aws:iam::{ACCOUNT}:role/synthetic-delivery-operator"],
    [f"arn:aws:iam::{ACCOUNT}:root"],
    [f"arn:aws:iam::{ACCOUNT}:root", f"arn:aws:iam::{ACCOUNT}:role/synthetic-delivery-operator"],
])
def test_ext2_key_policy_lets_administrators_create_refresh_and_alias_without_signing(ext2_native, admins):
    from fixtures.cnesdata_delivery_ext2.inventory import ROLE, variables, values

    v = variables()
    v["ext2"]["admin_arns"] = admins
    code, plans, errors = ext2_native.plan(v, "ext2-admins-" + str(len(admins)))
    assert code == 0, errors
    document = json.loads(values(plans[0])["aws_kms_key.ext2_signing[0]"]["policy"])
    assert ext2_key_policy_admin_violations(document, admins, ROLE) == []


@pytest.mark.parametrize("admin", [
    "arn:aws:iam::444455556666:root",
    f"arn:aws:iam::{ACCOUNT}:root/extra",
    f"arn:aws:iam::{ACCOUNT}:user/synthetic-user",
    f"arn:aws:iam::{ACCOUNT}:role/cnesdata-delivery-ext2-gate",
])
def test_ext2_admin_rejects_foreign_root_users_and_the_gate(ext2_native, admin):
    from fixtures.cnesdata_delivery_ext2.inventory import variables

    v = variables()
    v["ext2"]["admin_arns"] = [admin]
    code, _, errors = ext2_native.plan(v, "ext2-admin-refused")
    assert code != 0
    assert any("EXT2 requires" in d.get("detail", "") or d["summary"] == "Invalid value for variable"
               for d in errors), errors


def test_ext2_inventory_snapshot_keeps_current_native_source_and_plan_isolated(
    ext2_native,
):
    from fixtures.cnesdata_delivery_ext2.inventory import (
        INVENTORY_BASE,
        INVENTORY_SOURCE,
        ROOT,
        inventory_case,
        snapshot_sources,
        variables,
    )

    inputs = variables(False)
    code, current_plans, errors = ext2_native.plan(inputs, "current-source-isolation")
    assert code == 0, errors
    current_prepared = ext2_native.prepared
    case = inventory_case(ext2_native, enabled=False)
    assert ext2_native.prepared == current_prepared
    assert INVENTORY_BASE == "99fc0e4805b96fbca7df06440d5ea3ad42e53369"
    assert INVENTORY_SOURCE == "d6c2fe101f5a5c2287aabc83ed73dd9f9b95f41f"
    assert case["source_blobs"] == {
        "base": snapshot_sources(INVENTORY_BASE),
        "head": snapshot_sources(INVENTORY_SOURCE),
    }
    for path, raw in case["source_blobs"]["head"].items():
        assert (ext2_native.inventory_prepared / Path(path).name).read_bytes() == raw
    for path in (ROOT / "opentofu/cnesdata-delivery").glob("*.tf"):
        assert (current_prepared / path.name).read_bytes() == path.read_bytes()
    configured = lambda plan: {
        r["address"] for r in plan["configuration"]["root_module"]["resources"]
    }
    assert "aws_iam_role.host_gate" in configured(current_plans[0])
    assert "aws_iam_role.host_gate" not in configured(case["saved_plan"]["json"])
    assert "opentofu/cnesdata-delivery/host-gate.tf" not in case["source_blobs"]["head"]
    # The original current-root cached plan is not replaced by the historical plan.
    assert ext2_native.plan(inputs, "current-source-isolation")[1] == current_plans


def test_ext2_inventory_boundary_exists():
    from tools.cnesdata_delivery.ext2_inventory import verify_ext2_inventory

    with pytest.raises(ValueError):
        verify_ext2_inventory(
            source_blobs={},
            saved_plan={},
            generated_inputs={},
            state_before={},
            state_after={},
            observations={},
            governance={},
        )


@pytest.mark.parametrize("form", ["dict", "json", "rfc3986", "rfc3986-literal-plus"])
def test_iam_policy_normalization_preserves_literal_percent_plus_and_unicode(form):
    from urllib.parse import quote
    from tools.cnesdata_delivery.ext2_inventory import document

    expected = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "synthetic:Get",
                "Resource": "arn:synthetic:literal+100%2F%ZZ café",
            }
        ]
    }
    raw = json.dumps(expected, ensure_ascii=False)
    value = (
        expected
        if form == "dict"
        else raw
        if form == "json"
        else quote(raw, safe="+" if form.endswith("literal-plus") else "")
    )
    assert document(value) == expected
    assert document(document(value)) == expected


@pytest.mark.parametrize(
    "value",
    [
        "%7B%22Statement%22%3A%5B%5D%7G",
        "%257B%2522Statement%2522%253A%255B%255D%257D",
        "%7B%22Statement%22%3A%22%FF%22%7D",
        '{"Statement":[],"Statement":[1]}',
        "%7B%22Statement%22%3A%5B%5D%2C%22Statement%22%3A%5B1%5D%7D",
        '{"Statement":[{"Effect":"Allow","Effect":"Deny"}]}',
        "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Effect%22%3A%22Deny%22%7D%5D%7D",
    ],
)
def test_iam_policy_normalization_rejects_invalid_double_encoding_and_duplicates(value):
    from tools.cnesdata_delivery.ext2_inventory import document

    with pytest.raises(ValueError):
        document(value)


@pytest.mark.parametrize("form", ["dict", "json", "rfc3986"])
def test_iam_policy_normalization_keeps_size_bounds_for_every_form(form):
    from urllib.parse import quote
    from tools.cnesdata_delivery.ext2_inventory import document

    value = {"Statement": ["x" * 100]}
    if form != "dict":
        value = json.dumps(value)
        if form == "rfc3986":
            value = quote(value, safe="")
    with pytest.raises(ValueError):
        document(value, maximum=32)


def test_ext2_plan_binary_is_decoded_by_pinned_offline_tool(tmp_path, monkeypatch):
    from tools.cnesdata_delivery import ext2_inventory as inventory

    calls = []
    tofu = Path(shutil.which("tofu"))

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        assert argv[-3:-1] == ["show", "-json"]
        binary = Path(argv[-1]).read_bytes()
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"binary_sha256": sha(binary)}).encode(),
            stderr=b"",
        )

    monkeypatch.setattr(inventory.subprocess, "run", run)
    result = inventory.read_saved_plan(
        b"synthetic-plan",
        directory=tmp_path,
        tofu=tofu,
        tofu_sha256=sha(tofu.read_bytes()),
    )
    assert result["json"]["binary_sha256"] == sha(b"synthetic-plan")
    assert result["binary"] == b"synthetic-plan"
    assert calls[0][0][:4] == [
        shutil.which("rtk"),
        "proxy",
        shutil.which("unshare"),
        "--user",
    ]
    env = calls[0][1]["env"]
    assert not any(
        "SECRET" in name or name in {"AWS_PROFILE", "AWS_ACCESS_KEY_ID"} for name in env
    )
    with pytest.raises(ValueError):
        inventory.read_saved_plan(
            b"synthetic-plan", directory=tmp_path, tofu=tofu, tofu_sha256="f" * 64
        )


def test_ext2_real_offline_plan_decoder(tmp_path):
    from tools.cnesdata_delivery import ext2_inventory as inventory

    (tmp_path / "main.tf").write_text(
        'terraform { required_version = "= 1.13.2" }\nresource "terraform_data" "synthetic_decoder_only" { input = "offline" }\n'
    )
    env = {
        "PATH": os.defpath,
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "CHECKPOINT_DISABLE": "1",
    }
    tofu = Path(shutil.which("tofu"))
    for args in [
        ["init", "-backend=false", "-input=false"],
        ["plan", "-input=false", "-out=offline.tfplan"],
    ]:
        result = subprocess.run(
            [
                shutil.which("rtk"),
                "proxy",
                shutil.which("unshare"),
                "--user",
                "--map-root-user",
                "--net",
                str(tofu),
                *args,
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr
    binary = (tmp_path / "offline.tfplan").read_bytes()
    decoded = inventory.read_saved_plan(
        binary, directory=tmp_path, tofu=tofu, tofu_sha256=sha(tofu.read_bytes())
    )
    assert (
        decoded["json"]["resource_changes"][0]["address"]
        == "terraform_data.synthetic_decoder_only"
    )
    assert decoded["binary"] == binary
    with pytest.raises(ValueError, match="plan_decode"):
        inventory.read_saved_plan(
            b"invalid saved plan",
            directory=tmp_path,
            tofu=tofu,
            tofu_sha256=sha(tofu.read_bytes()),
        )


@pytest.mark.parametrize("purpose,count", [("bootstrap", 9), ("phase-a", 7)])
def test_product_bootstrap_inventory_remains_closed(purpose, count):
    from fixtures.cnesdata_iam_inventory import inventory
    from fixtures.cnesdata_iam_sources import ACCOUNT as PRODUCT_ACCOUNT, REGION
    from tools.cnesdata_delivery.iam_source import SourceResolver

    plan, sources, inputs, _, policies = inventory(purpose)
    resolver = SourceResolver(
        plan,
        sources,
        {
            "generated_inputs": inputs,
            "account_id": PRODUCT_ACCOUNT,
            "region": REGION,
            "purpose": purpose,
        },
    )
    assert len(policies) == count
    for address in policies:
        resolver.precheck(address)
    with pytest.raises(ValueError, match="iam=policy_scope"):
        resolver.precheck("aws_iam_role_policy.ext2_gate[0]")


@pytest.mark.parametrize("historical", [False, True])
def test_ext2_effective_grants_are_finite_and_every_explicit_deny_wins(
    ext2_native, gate, crypto, historical
):
    from fixtures.cnesdata_delivery_ext2.inventory import (
        decision,
        policy,
        key_policy,
        variables,
        ROLE,
    )

    v = variables()
    code, plans, errors = ext2_native.plan(v, "ext2-four")
    assert code == 0, errors
    from fixtures.cnesdata_delivery_ext2.inventory import values

    rendered = values(plans[0])
    identity = json.loads(rendered["aws_iam_role_policy.ext2_gate[0]"]["policy"])
    assert identity == policy(v)
    key = json.loads(rendered["aws_kms_key.ext2_signing[0]"]["policy"])
    assert key == key_policy(v)
    gov = signing_case(crypto)[0]
    session = json.loads(gate.session_policy(gov, historical=historical))
    current = v["ext2"]["current_object_arns"][0]
    context = {
        "aws:CurrentTime": "2027-01-01T00:00:00Z",
        "s3:object-lock-mode": "COMPLIANCE",
        "s3:object-lock-retain-until-date": v["ext2"]["retain_until"],
        "s3:x-amz-server-side-encryption": "aws:kms",
        "s3:x-amz-server-side-encryption-aws-kms-key-id": KEY,
        "kms:MessageType": "DIGEST",
        "kms:SigningAlgorithm": "ECDSA_SHA_256",
        "kms:ViaService": "s3.us-east-2.amazonaws.com",
        "kms:EncryptionContext:aws:s3:arn": current,
    }

    def effective(action, resource, ctx, layers=()):
        documents = [identity, session, *layers]
        if resource == SIGNING_KEY:
            documents.append(key)
        return all(
            decision(p, action, resource, ctx, ROLE) == "allow" for p in documents
        )

    for action, resource in [
        ("s3:GetObjectVersion", current),
        ("s3:GetObjectRetention", current),
        ("kms:Decrypt", KEY),
        ("kms:GetPublicKey", SIGNING_KEY),
    ]:
        assert effective(action, resource, context)
        # Model all mandatory policy layers as exact allows, then one explicit Deny.
        for layer in ["bucket", "key", "boundary", "SCP", "freeze"]:
            allow = {
                "Statement": [
                    {
                        "Sid": layer,
                        "Effect": "Allow",
                        "Action": action,
                        "Resource": resource,
                    }
                ]
            }
            assert effective(action, resource, context, [allow])
            allow["Statement"].append(
                {"Effect": "Deny", "Action": action, "Resource": resource}
            )
            assert not effective(action, resource, context, [allow])
    for action, resource in [
        ("s3:PutObject", current),
        ("s3:PutObjectRetention", current),
        ("kms:Sign", SIGNING_KEY),
        ("kms:GenerateDataKey", KEY),
    ]:
        assert effective(action, resource, context) is (not historical)
        assert not effective(
            action, resource, context | {"aws:CurrentTime": v["ext2"]["enabled_until"]}
        )
    foreign = [
        current.replace("cnesdata", "other-app"),
        current.replace("/123/", "/999/"),
        current.replace("synthetic-ext2-evidence", "other-bucket"),
        "arn:aws:s3:::synthetic-state/cnesdata/prod/opentofu.tfstate",
        "arn:aws:s3:::synthetic-state/cnesdata/prod/opentofu.tfstate.tflock",
        "arn:aws:s3:::synthetic-state/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json",
    ]
    for resource in foreign:
        for action in ["s3:GetObjectVersion", "s3:PutObject", "s3:PutObjectRetention"]:
            assert not effective(action, resource, context)
    for action in [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:BypassGovernanceRetention",
        "s3:PutObjectLegalHold",
        "s3:PutObjectAcl",
        "s3:PutObjectTagging",
        "s3:ListBucketVersions",
    ]:
        assert not effective(action, current, context)
    for arn in [
        KEY,
        SIGNING_KEY.replace(ACCOUNT, "999988887777"),
        SIGNING_KEY.replace("us-east-2", "us-west-2"),
    ]:
        assert not effective("kms:Sign", arn, context)
    for key_name, value in [
        ("kms:MessageType", "RAW"),
        ("kms:SigningAlgorithm", "ECDSA_SHA_384"),
    ]:
        assert not effective("kms:Sign", SIGNING_KEY, context | {key_name: value})
    for key_name, value in [
        ("kms:ViaService", "s3.us-west-2.amazonaws.com"),
        ("kms:EncryptionContext:aws:s3:arn", foreign[0]),
    ]:
        assert not effective("kms:Decrypt", KEY, context | {key_name: value})
    for action in ["s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]:
        assert decision(identity, action, current, context) == "deny"
    assert (
        decision(
            identity, "s3:ListBucketMultipartUploads", v["ext2"]["bucket_arn"], context
        )
        == "deny"
    )
    for arn in v["ext2"]["history_object_arns"]:
        assert decision(identity, "s3:GetObjectVersion", arn, context) == "allow"
        assert decision(identity, "s3:PutObject", arn, context) == "implicit"
        assert decision(identity, "s3:PutObjectRetention", arn, context) == "implicit"


@pytest.mark.parametrize("mode", ["disabled", "noop"])
def test_ext2_inventory_all_existing_resources_remain_observed(ext2_native, mode):
    from fixtures.cnesdata_delivery_ext2.inventory import (
        inventory_case,
        InventoryAPI,
        rebind,
    )
    from tools.cnesdata_delivery import ext2_inventory as inventory

    case = inventory_case(ext2_native, enabled=mode != "disabled")
    if mode == "noop":
        case["state_before"] = copy.deepcopy(case["state_after"])
        for row in case["saved_plan"]["json"]["resource_changes"]:
            if row["mode"] == "managed":
                row["change"]["actions"] = ["no-op"]
                row["change"]["before"] = copy.deepcopy(row["change"]["after"])
        rebind(case)
    api = InventoryAPI(case)
    result = inventory.verify_ext2_inventory(
        **case,
        observations=inventory.observe_inventory(
            state=case["state_after"], iam=api, kms=api, rolesanywhere=api
        ),
    )
    assert result.ext2_count == (0 if mode == "disabled" else 4)
    assert result.prior_count == 9
    assert len(api.covered) == (9 if mode == "disabled" else 13)


@pytest.mark.parametrize("enabled", [False, True])
def test_ext2_inventory_output_is_source_derived(ext2_native, enabled):
    from fixtures.cnesdata_delivery_ext2.inventory import (
        inventory_case,
        InventoryAPI,
        rebind,
    )
    from tools.cnesdata_delivery import ext2_inventory as inventory

    case = inventory_case(ext2_native, enabled)
    plan = case["saved_plan"]["json"]
    plan["planned_values"]["outputs"]["ext2"]["value"] = {"role_arn": "foreign"}
    plan["output_changes"]["ext2"]["after"] = {"role_arn": "foreign"}
    case["state_after"]["outputs"]["ext2"] = {
        "value": {"role_arn": "foreign"},
        "sensitive": True,
    }
    rebind(case)
    api = InventoryAPI(case)
    observed = inventory.observe_inventory(
        state=case["state_after"], iam=api, kms=api, rolesanywhere=api
    )
    with pytest.raises(ValueError):
        inventory.verify_ext2_inventory(**case, observations=observed)


@pytest.mark.parametrize(
    "mutation",
    ["provider", "plan-field", "failed-check", "data-action", "unsealed-plan"],
)
def test_ext2_inventory_rejects_unreviewed_plan_configuration(ext2_native, mutation):
    from fixtures.cnesdata_delivery_ext2.inventory import (
        inventory_case,
        InventoryAPI,
        rebind,
    )
    from tools.cnesdata_delivery import ext2_inventory as inventory

    case = inventory_case(ext2_native)
    plan = case["saved_plan"]["json"]
    if mutation == "provider":
        plan["configuration"]["provider_config"]["evil"] = copy.deepcopy(
            plan["configuration"]["provider_config"]["aws"]
        )
    elif mutation == "plan-field":
        plan["target"] = ["aws_kms_key.ext2_signing[0]"]
    elif mutation == "failed-check":
        plan["checks"][0]["status"] = "fail"
    elif mutation == "data-action":
        plan["resource_changes"].append(
            {
                "mode": "data",
                "address": "data.aws_iam_role.foreign",
                "change": {"actions": ["read"]},
            }
        )
    rebind(case)
    if mutation == "unsealed-plan":
        case["saved_plan"] = dict(case["saved_plan"])
    api = InventoryAPI(case)
    observed = inventory.observe_inventory(
        state=case["state_after"], iam=api, kms=api, rolesanywhere=api
    )
    with pytest.raises(ValueError):
        inventory.verify_ext2_inventory(**case, observations=observed)


def test_ext2_inventory_resolves_only_source_defined_new_producer_unknowns(ext2_native):
    from fixtures.cnesdata_delivery_ext2.inventory import (
        inventory_case,
        InventoryAPI,
        rebind,
    )
    from tools.cnesdata_delivery import ext2_inventory as inventory

    case = inventory_case(ext2_native)
    fields = {
        "aws_iam_role.ext2_gate[0]": ["arn", "id"],
        "aws_iam_role_policy.ext2_gate[0]": ["role", "policy"],
        "aws_kms_key.ext2_signing[0]": ["arn", "id", "key_id", "policy"],
        "aws_kms_alias.ext2_signing[0]": ["target_key_id", "target_key_arn"],
    }
    for row in case["saved_plan"]["json"]["resource_changes"]:
        for field in fields.get(row["address"], []):
            row["change"]["after"].pop(field)
            row["change"]["after_unknown"][field] = True
    output = case["saved_plan"]["json"]["output_changes"]["ext2"]
    output["after_unknown"] = {"role_arn": True, "signing_key_arn": True}
    for field in output["after_unknown"]:
        output["after"].pop(field)
    case["saved_plan"]["json"]["planned_values"]["outputs"]["ext2"].pop("value")
    rebind(case)
    api = InventoryAPI(case)
    result = inventory.verify_ext2_inventory(
        **case,
        observations=inventory.observe_inventory(
            state=case["state_after"], iam=api, kms=api, rolesanywhere=api
        ),
    )
    assert result.ext2_count == 4


@pytest.mark.parametrize("policy_format", ["dict", "json", "rfc3986"])
def test_ext2_inventory_derives_full_trust_grants_key_alias_from_source(
    ext2_native, policy_format
):
    from fixtures.cnesdata_delivery_ext2.inventory import inventory_case, InventoryAPI
    from tools.cnesdata_delivery import ext2_inventory as inventory

    case = inventory_case(ext2_native)
    api = InventoryAPI(case, policy_format=policy_format)
    observed = inventory.observe_inventory(
        state=case["state_after"], iam=api, kms=api, rolesanywhere=api
    )
    result = inventory.verify_ext2_inventory(**case, observations=observed)
    assert result.ext2_count == 4 and result.prior_count == 9
    assert api.covered == set(inventory.state_resources(case["state_after"]))
    assert not any(
        name.startswith(("put", "create", "update", "delete", "sign", "import"))
        for name, _ in api.calls
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "extra",
        "missing",
        "import",
        "delete",
        "replace",
        "prior-update",
        "prior-missing",
        "prior-readback",
        "extra-inline",
        "extra-attached",
        "trust",
        "policy",
        "key-policy",
        "alias",
        "unknown-policy",
        "source-policy",
        "source-resource",
        "config-expression",
        "lineage",
        "serial",
        "unsealed-observation",
        "omitted-observation",
        "spki",
        "key-state",
    ],
)
def test_ext2_inventory_rejects_adoption_drift_and_correlated_state_api_mutation(
    ext2_native, mutation
):
    from fixtures.cnesdata_delivery_ext2.inventory import (
        inventory_case,
        InventoryAPI,
        rebind,
    )
    from tools.cnesdata_delivery import ext2_inventory as inventory

    case = inventory_case(ext2_native)
    plan = case["saved_plan"]["json"]
    changes = {r["address"]: r for r in plan["resource_changes"]}
    rows = case["state_after"]["resources"]
    by_name = {
        r["type"] + "." + r["name"]: r["instances"][0]["attributes"] for r in rows
    }
    if mutation == "extra":
        rows.append(
            copy.deepcopy(rows[0]) | {"type": "aws_s3_bucket", "name": "external"}
        )
    elif mutation == "missing":
        case["state_after"]["resources"] = [
            r for r in rows if r["type"] != "aws_kms_alias"
        ]
    elif mutation == "import":
        changes["aws_kms_key.ext2_signing[0]"]["change"]["importing"] = {"id": "adopt"}
    elif mutation in {"delete", "replace", "prior-update"}:
        a = (
            "aws_iam_role.api"
            if mutation == "prior-update"
            else "aws_kms_key.ext2_signing[0]"
        )
        changes[a]["change"]["actions"] = {
            "delete": ["delete"],
            "replace": ["delete", "create"],
            "prior-update": ["update"],
        }[mutation]
    elif mutation == "prior-missing":
        case["state_before"]["resources"].pop()
    elif mutation in {"trust", "policy", "key-policy"}:
        kind, field = {
            "trust": ("aws_iam_role.ext2_gate", "assume_role_policy"),
            "policy": ("aws_iam_role_policy.ext2_gate", "policy"),
            "key-policy": ("aws_kms_key.ext2_signing", "policy"),
        }[mutation]
        body = json.loads(by_name[kind][field])
        body["Statement"].append({"Effect": "Allow", "Action": "*", "Resource": "*"})
        by_name[kind][field] = json.dumps(body)
        changes[kind + "[0]"]["change"]["after"][field] = by_name[kind][field]
    elif mutation == "alias":
        by_name["aws_kms_alias.ext2_signing"]["target_key_id"] = (
            "00000000-0000-4000-8000-000000000099"
        )
        changes["aws_kms_alias.ext2_signing[0]"]["change"]["after"]["target_key_id"] = (
            by_name["aws_kms_alias.ext2_signing"]["target_key_id"]
        )
    elif mutation == "unknown-policy":
        changes["aws_iam_role_policy.ext2_gate[0]"]["change"]["after_unknown"] = {
            "policy": True,
            "role": True,
        }
    elif mutation.startswith("source-"):
        path = "opentofu/cnesdata-delivery/evidence.tf"
        raw = case["source_blobs"]["head"][path]
        raw = (
            raw.replace(b'"kms:Sign"', b'"kms:*"')
            if mutation == "source-policy"
            else raw + b'\nresource "aws_s3_bucket" "external" { bucket = "adopt" }\n'
        )
        case["source_blobs"]["head"][path] = raw
        case["governance"]["sources"][path] = sha(raw)
    elif mutation == "config-expression":
        row = next(
            r
            for r in plan["configuration"]["root_module"]["resources"]
            if r["address"] == "aws_iam_role_policy.ext2_gate"
        )
        row["expressions"]["role"] = {"constant_value": "cnesdata-delivery-ext2-gate"}
    elif mutation == "lineage":
        case["state_after"]["lineage"] = "foreign"
    elif mutation == "serial":
        case["state_after"]["serial"] = 1
    rebind(case)
    api = InventoryAPI(case)
    api.mutation = mutation
    with pytest.raises(ValueError):
        observed = inventory.observe_inventory(
            state=case["state_after"], iam=api, kms=api, rolesanywhere=api
        )
        if mutation == "unsealed-observation":
            observed = dict(observed.values)
        elif mutation == "omitted-observation":
            observed.values.pop("aws_iam_role.api")
        inventory.verify_ext2_inventory(**case, observations=observed)


@pytest.fixture(scope="module")
def crypto(tmp_path_factory):
    directory = tmp_path_factory.mktemp("ext2-synthetic-ephemeral-key")
    executable = shutil.which("openssl")
    assert executable, "OpenSSL required, no skip/fallback"
    key = directory / "synthetic-private.pem"
    subprocess.run(
        [
            executable,
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            str(key),
        ],
        check=True,
        capture_output=True,
    )
    key.chmod(0o600)
    public = subprocess.run(
        [executable, "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    return {
        "path": executable,
        "sha256": sha(Path(executable).read_bytes()),
        "private": key,
        "public": public,
        "directory": directory,
    }


class KMS:
    def __init__(self, crypto):
        self.crypto = crypto
        self.calls = []
        self.error = None
        self.double_hash = False
        self.policy = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "synthetic-offline"}],
        }
        self.metadata = {
            "Arn": SIGNING_KEY,
            "KeyId": SIGNING_KEY.rsplit("/", 1)[1],
            "Enabled": True,
            "KeyState": "Enabled",
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "ECC_NIST_P256",
            "Origin": "AWS_KMS",
            "MultiRegion": False,
        }
        self.meta = SimpleNamespace(
            config=SimpleNamespace(retries={"total_max_attempts": 1})
        )

    def describe_key(self, **kwargs):
        self.calls.append(("describe", kwargs))
        return {"KeyMetadata": self.metadata.copy()}

    def get_public_key(self, **kwargs):
        self.calls.append(("public", kwargs))
        return {
            "KeyId": SIGNING_KEY,
            "PublicKey": self.crypto["public"],
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "ECC_NIST_P256",
            "SigningAlgorithms": ["ECDSA_SHA_256"],
        }

    def get_key_policy(self, **kwargs):
        self.calls.append(("policy", kwargs))
        return {"Policy": json.dumps(self.policy)}

    def sign(self, **kwargs):
        self.calls.append(("sign", kwargs))
        if self.error:
            raise self.error
        digest = kwargs["Message"]
        if self.double_hash:
            digest = hashlib.sha256(digest).digest()
        path = self.crypto["directory"] / "digest.bin"
        path.write_bytes(digest)
        signature = subprocess.run(
            [
                self.crypto["path"],
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.crypto["private"]),
                "-pkeyopt",
                "digest:sha256",
                "-in",
                str(path),
            ],
            check=True,
            capture_output=True,
        ).stdout
        return {
            "KeyId": SIGNING_KEY,
            "Signature": signature,
            "SigningAlgorithm": "ECDSA_SHA_256",
        }


class FixtureConsumer:
    """Synthetic future #470 schema and admission fixture, not installed by runtime."""

    def __init__(self, candidate, phase_a, fields):
        self.candidate, self.phase_a, self.fields = candidate, phase_a, fields
        self.calls = []

    def admit(self, payload, *, github, governance, now, historical=False):
        self.calls.append(historical)
        assert github is not None
        if payload != canonical(self.fields):
            raise ValueError("fixture schema/binding mismatch")
        if self.phase_a is None:
            raise ValueError("fixture missing Phase A")
        return {
            "candidate_bytes": self.candidate,
            "phase_a_bytes": self.phase_a,
            "activation_fields": self.fields.copy(),
        }


def signing_case(crypto):
    gov, _, api, _ = transport_case()
    candidate = canonical(
        {
            "repository": REPOSITORY,
            "release_id": "synthetic-release",
            "source_sha": SOURCE,
            "fixture_only": True,
        }
    )
    binding_input = {
        "repository": REPOSITORY,
        "release_id": "synthetic-release",
        "source_sha": SOURCE,
        "candidate_sha256": sha(candidate),
    }
    binding = sha(b"cnesdata:prod:canary:v1\0" + canonical(binding_input).rstrip(b"\n"))
    revisions = {
        mode: f"arn:aws:ecs:us-east-2:{ACCOUNT}:task-definition/synthetic-{mode}:3"
        for mode in ("unit", "recovery", "audit")
    }
    phase_a = canonical(
        {
            "fixture_only": True,
            "source_sha": SOURCE,
            "binding_sha256": binding,
            "revisions": revisions,
            "proof_kind": "iam-readback-and-evaluation",
        }
    )
    fields = {
        "project": "cnesdata",
        "environment": "prod",
        "schema_version": 1,
        **binding_input,
        "binding_sha256": binding,
        "canary_id": binding[:32],
        "derivation": "cnesdata:prod:canary:v1",
        "revisions": revisions,
        "ecr_uri": f"{ACCOUNT}.dkr.ecr.us-east-2.amazonaws.com/cnesdata@sha256:"
        + "d" * 64,
        "phase_a_evidence_digest": sha(phase_a),
    }
    adapter = FixtureConsumer(candidate, phase_a, fields)
    kms = KMS(crypto)
    gov.update(
        {
            "activation_enabled": True,
            "invocation": {"run_id": "123", "run_attempt": "1", "source_sha": SOURCE},
            "authorization": {
                "run_id": "123",
                "run_attempt": "1",
                "source_sha": SOURCE,
                "release_id": fields["release_id"],
                "candidate_sha256": sha(candidate),
                "expires_at": "2029-01-01T00:00:00Z",
                "frozen": False,
            },
            "signing": {
                "key_arn": SIGNING_KEY,
                "spki_sha256": sha(crypto["public"]),
                "spki_der_b64": base64.b64encode(crypto["public"]).decode(),
                "key_policy_sha256": sha(canonical(kms.policy)),
            },
            "crypto": {
                "openssl_path": crypto["path"],
                "openssl_sha256": crypto["sha256"],
            },
            "principal_sha256": "f" * 64,
        }
    )
    return gov, api, kms, S3(), adapter, canonical(fields)


@pytest.fixture
def gate():
    from tools.cnesdata_delivery import signing_gate

    return signing_gate


def sign(gate, case):
    gov, api, kms, s3, adapter, payload = case
    return gate.sign_activation(
        payload,
        phase_a=adapter,
        github=api,
        kms=kms,
        s3=s3,
        governance=gov,
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )


def test_phase_a_precedes_the_only_sign(gate, crypto):
    case = signing_case(crypto)
    result = sign(gate, case)
    gov, _, kms, s3, adapter, payload = case
    calls = [args for op, args in kms.calls if op == "sign"]
    assert calls == [
        {
            "KeyId": SIGNING_KEY,
            "Message": hashlib.sha256(payload).digest(),
            "MessageType": "DIGEST",
            "SigningAlgorithm": "ECDSA_SHA_256",
        }
    ]
    assert adapter.calls == [False]
    assert result.payload.body == payload
    assert result.receipt.version_id == "3"
    assert json.loads(result.receipt.body)["activation"][
        "phase_a_evidence_digest"
    ] == sha(adapter.phase_a)
    assert [args["Key"] for op, args in s3.calls if op == "put"] == KEYS
    assert result.member_bytes == canonical(
        {
            "receipt_version_id": "3",
            "receipt_sha256": sha(result.receipt.body),
            "receipt_size": len(result.receipt.body),
        }
    )
    assert b"bucket" not in result.member_bytes and b"arn:" not in result.member_bytes
    assert result.signature.body not in result.member_bytes
    assert "GenerateDataKey" not in gate.session_policy(gov, historical=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_sha", "e" * 40),
        ("candidate_sha256", "e" * 64),
        ("phase_a_evidence_digest", "e" * 64),
        ("binding_sha256", "e" * 64),
        ("canary_id", "e" * 32),
        ("environment", "dev"),
        ("project", "other"),
        ("release_id", "other"),
        ("revisions", {"unit": "mutable:latest"}),
        ("ecr_uri", "other@sha256:" + "d" * 64),
    ],
)
def test_mixed_binding_cannot_reach_sign(gate, crypto, field, value):
    case = signing_case(crypto)
    case[4].fields[field] = value
    altered = case[:-1] + (canonical(case[4].fields),)
    with pytest.raises(ValueError):
        sign(gate, altered)
    assert not any(op == "sign" for op, _ in case[2].calls)


def test_missing_phase_a_or_unintegrated_consumer_cannot_sign(gate, crypto):
    case = signing_case(crypto)
    case[4].phase_a = None
    with pytest.raises(ValueError):
        sign(gate, case)
    no_adapter = case[:4] + (None,) + case[5:]
    with pytest.raises(ValueError):
        sign(gate, no_adapter)
    assert not any(op == "sign" for op, _ in case[2].calls)


@pytest.mark.parametrize(
    "mutation",
    [
        "disabled",
        "frozen",
        "expired",
        "past-retention",
        "another-attempt",
        "noncanonical",
        "automatic-retry",
    ],
)
def test_no_resign_after_ambiguous_sign_or_age(gate, crypto, mutation):
    case = signing_case(crypto)
    if mutation == "disabled":
        case[0]["activation_enabled"] = False
    if mutation == "frozen":
        case[0]["authorization"]["frozen"] = True
    if mutation == "expired":
        case[0]["authorization"]["expires_at"] = "2026-01-01T00:00:00Z"
    if mutation == "past-retention":
        case[0]["storage"]["retain_until"] = "2026-01-01T00:00:00Z"
    if mutation == "another-attempt":
        case[0]["authorization"]["run_attempt"] = "2"
    if mutation == "noncanonical":
        case = case[:-1] + (case[-1].rstrip(b"\n"),)
    if mutation == "automatic-retry":
        case[2].meta.config.retries = {"total_max_attempts": 3}
    with pytest.raises(ValueError):
        sign(gate, case)
    assert not any(op == "sign" for op, _ in case[2].calls)


def test_ambiguous_sign_does_not_retry_or_write(gate, crypto):
    case = signing_case(crypto)
    case[2].error = RuntimeError("accepted but timed out; private token detail")
    with pytest.raises(ValueError, match="recovery_required") as error:
        sign(gate, case)
    assert "token" not in str(error.value)
    assert len([x for x in case[2].calls if x[0] == "sign"]) == 1
    assert not case[3].calls


def test_independent_prehash_verifier_rejects_double_hash(gate, crypto):
    case = signing_case(crypto)
    case[2].double_hash = True
    with pytest.raises(ValueError):
        sign(gate, case)
    assert len([x for x in case[2].calls if x[0] == "sign"]) == 1
    assert not case[3].calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("Enabled", False),
        ("KeyUsage", "ENCRYPT_DECRYPT"),
        ("KeySpec", "RSA_2048"),
        ("Arn", KEY),
        ("MultiRegion", True),
    ],
)
def test_signing_key_identity_and_capabilities_are_read_back(
    gate, crypto, field, value
):
    case = signing_case(crypto)
    case[2].metadata[field] = value
    with pytest.raises(ValueError):
        sign(gate, case)
    assert not any(op == "sign" for op, _ in case[2].calls)


def test_publish_reference_only_after_all_readbacks(gate, crypto):
    case = signing_case(crypto)
    case[3].head_mutation["BucketKeyEnabled"] = True
    with pytest.raises(ValueError):
        sign(gate, case)
    assert not any(args["Key"] == KEYS[2] for op, args in case[3].calls if op == "put")


def test_repeated_in_process_authorization_cannot_sign_twice(gate, crypto):
    case = signing_case(crypto)
    sign(gate, case)
    with pytest.raises(ValueError, match="recovery_required"):
        sign(gate, case)
    assert len([x for x in case[2].calls if x[0] == "sign"]) == 1


def published_case(gate, crypto):
    case = signing_case(crypto)
    produced = sign(gate, case)
    gov, api, kms, s3, adapter, payload = case
    _, ref, _, _ = transport_case()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("receipt-ref.json", produced.member_bytes)
    archive = buffer.getvalue()
    ref["artifact_digest"] = "sha256:" + sha(archive)
    path = f"repos/{REPOSITORY}/actions/artifacts/456"
    api.responses[path]["digest"] = ref["artifact_digest"]
    api.responses[path]["size_in_bytes"] = len(archive)
    api.responses[path + "/zip"] = archive
    api.responses[f"repos/{REPOSITORY}/actions/jobs/789/steps/2/logs"] = (
        b"EXT2_ARTIFACT_COMMIT_V1 "
        + canonical(
            {
                "artifact_id": "456",
                "artifact_digest": ref["artifact_digest"],
                "receipt_ref_sha256": sha(produced.member_bytes),
            }
        )
    )
    api.responses[f"repos/{REPOSITORY}/actions/runs/123/attempts/1"].update(
        status="completed", conclusion="success"
    )
    gov["provenance"]["accepted_history"] = [ref.copy()]
    from fixtures.cnesdata_delivery_ext2 import install_historical_consumer

    install_historical_consumer(
        gov, api, adapter.candidate, adapter.phase_a, adapter.fields
    )
    gov["signing"]["spki_der_b64"] = base64.b64encode(crypto["public"]).decode()
    for name in list(gov):
        if name.startswith("_") or name == "principal_sha256":
            del gov[name]
    gov["authorization"]["frozen"] = True
    kms.calls.clear()
    s3.calls.clear()
    return case, ref, produced


def test_retained_activation_reads_original_versions_without_resign_or_refresh(
    gate, crypto, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    case, reference, produced = published_case(gate, crypto)
    gov, api, kms, s3, adapter, payload = case
    result = gate.read_retained_activation(
        reference,
        github=api,
        s3=s3,
        governance=gov,
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    assert (
        result.payload_bytes == payload
        and result.signature_der == produced.signature.body
    )
    assert result.receipt_bytes == produced.receipt.body
    assert result.signing_spki_der == crypto["public"]
    assert result.authenticated_reference == reference
    assert adapter.calls == [False]
    assert not kms.calls and not any(op == "put" for op, _ in s3.calls)
    assert {args["VersionId"] for op, args in s3.calls if op == "head"} == {
        "1",
        "2",
        "3",
    }


def test_historical_explicit_spki_handoff_needs_no_prior_cli_key_insertion(
    gate, crypto, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    case, reference, produced = published_case(gate, crypto)
    gov, api, kms, s3, _, payload = case
    gov = json.loads(
        json.dumps(gov)
    )  # A fresh handoff contains no object/callable state.
    assert not any(name.startswith("_") for name in gov)
    result = gate.read_retained_activation(
        reference,
        github=api,
        s3=s3,
        governance=gov,
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    assert (
        result.payload_bytes == payload
        and result.signature_der == produced.signature.body
    )
    assert result.signing_spki_der == crypto["public"]
    assert not kms.calls and not any(op == "put" for op, _ in s3.calls)


def test_publisher_matches_explicit_spki_handoff_to_actual_public_key(gate, crypto):
    case = signing_case(crypto)
    case[0]["signing"]["spki_der_b64"] = base64.b64encode(crypto["public"]).decode()
    result = sign(gate, case)
    assert result.signing_spki_der == crypto["public"]
    assert len([op for op, _ in case[2].calls if op == "sign"]) == 1


@pytest.mark.parametrize("historical", [False, True])
@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "invalid-base64",
        "padding-bits",
        "oversize",
        "wrong-pin",
        "correlated-key",
    ],
)
def test_spki_handoff_is_required_canonical_and_bound_to_original_key(
    gate, crypto, historical, mutation, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    if historical:
        case, reference, _ = published_case(gate, crypto)
    else:
        case = signing_case(crypto)
    gov, api, kms, s3, _, _ = case
    encoded = base64.b64encode(crypto["public"]).decode()
    gov["signing"]["spki_der_b64"] = encoded
    if mutation == "missing":
        del gov["signing"]["spki_der_b64"]
        monkeypatch.setenv(
            "SPKI_DER_B64", encoded
        )  # Env/caller material is not the governed handoff.
    elif mutation == "invalid-base64":
        gov["signing"]["spki_der_b64"] = encoded + "\n"
    elif mutation == "padding-bits":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        gov["signing"]["spki_der_b64"] = (
            encoded[:-3] + alphabet[alphabet.index(encoded[-3]) + 1] + "=="
        )
    elif mutation == "oversize":
        gov["signing"]["spki_der_b64"] = "A" * 1048576
    elif mutation == "wrong-pin":
        gov["signing"]["spki_sha256"] = "f" * 64
    else:
        # A distinct valid P-256 public key, not a malformed-DER stand-in.
        key = tmp_path / "other-ephemeral.pem"
        subprocess.run(
            [
                crypto["path"],
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                str(key),
            ],
            check=True,
            capture_output=True,
        )
        public = subprocess.run(
            [crypto["path"], "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        gov["signing"]["spki_der_b64"] = base64.b64encode(public).decode()
        gov["signing"]["spki_sha256"] = sha(public)
    with pytest.raises(ValueError):
        if historical:
            gate.read_retained_activation(
                reference,
                github=api,
                s3=s3,
                governance=gov,
                now=datetime(2027, 1, 1, tzinfo=timezone.utc),
            )
        else:
            sign(gate, case)
    assert not any(op == "sign" for op, _ in kms.calls)
    assert not any(op == "put" for op, _ in s3.calls)
    if historical:
        assert not kms.calls


@pytest.mark.parametrize("mutation", ["missing", "source", "bytes"])
def test_fresh_historical_consumer_source_authority_cannot_be_replaced(
    gate, crypto, mutation, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    case, reference, _ = published_case(gate, crypto)
    gov, api, kms, s3, _, _ = case
    if mutation == "missing":
        del gov["consumer"]
    elif mutation == "source":
        gov["consumer"]["source_sha"] = "f" * 40
    else:
        path = f"repos/{REPOSITORY}/contents/release/verify_activation.py?ref={SOURCE}"
        raw = b"def admit_ext2(*a, **kw): return {}\n"
        api.responses[path].update(
            content=base64.b64encode(raw).decode(),
            size=len(raw),
            sha=hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw
            ).hexdigest(),
        )
    with pytest.raises(ValueError):
        gate.read_retained_activation(
            reference,
            github=api,
            s3=s3,
            governance=gov,
            now=datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
    assert not kms.calls and not any(op == "put" for op, _ in s3.calls)


def test_historical_cli_verification_never_requests_kms_key_metadata(
    gate, crypto, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    case, reference, _ = published_case(gate, crypto)
    gov, api, kms, s3, _, _ = case
    request = {
        "request_version": 1,
        "mode": "historical",
        "source_sha": SOURCE,
        "inputs": None,
        "ext2_post_upload_receipt_v1": reference,
    }
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("historical KMS metadata is forbidden")

    monkeypatch.setattr(gate, "_configuration", lambda: (gov, request, api))
    monkeypatch.setattr(gate, "_selection", lambda current, request: current)
    monkeypatch.setattr(
        gate, "_clients", lambda current, historical: {"kms": kms, "s3": s3}
    )
    monkeypatch.setattr(gate, "read_signing_key", forbidden)
    monkeypatch.setattr(gate, "_utc", lambda: datetime(2027, 1, 1, tzinfo=timezone.utc))
    monkeypatch.setattr(sys, "argv", ["signing_gate", "verify"])
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "github-output"))
    assert gate.main() == 0
    assert not calls and not kms.calls and not any(op == "put" for op, _ in s3.calls)


@pytest.mark.parametrize(
    "mutation",
    [
        "receipt",
        "payload",
        "signature",
        "spki",
        "issuer",
        "expired-admission",
        "missing-api",
    ],
)
def test_retained_evidence_or_current_authorization_cannot_be_replaced(
    gate, crypto, mutation, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    case, reference, _ = published_case(gate, crypto)
    gov, api, kms, s3, _, _ = case
    if mutation in {"receipt", "payload", "signature"}:
        index = {"payload": 0, "signature": 1, "receipt": 2}[mutation]
        s3.objects[(KEYS[index], str(index + 1))] += b"altered"
    if mutation == "spki":
        gov["signing"]["spki_der_b64"] = base64.b64encode(b"wrong").decode()
    if mutation == "issuer":
        gov["provenance"]["workflow_sha"] = "f" * 40
    if mutation == "expired-admission":
        gov["authorization"]["expires_at"] = "2026-01-01T00:00:00Z"
    if mutation == "missing-api":
        api.responses[f"repos/{REPOSITORY}/actions/jobs/789/steps/2/logs"] = (
            RuntimeError("404")
        )
    with pytest.raises(ValueError):
        gate.read_retained_activation(
            reference,
            github=api,
            s3=s3,
            governance=gov,
            now=datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
    assert not kms.calls and not any(op == "put" for op, _ in s3.calls)


def test_current_and_historical_session_permissions_fit_without_widening(gate, crypto):
    gov = signing_case(crypto)[0]
    current = json.loads(gate.session_policy(gov, historical=False))
    historical = json.loads(gate.session_policy(gov, historical=True))
    current_actions = {a for s in current["Statement"] for a in s["Action"]}
    history_actions = {a for s in historical["Statement"] for a in s["Action"]}
    assert "kms:Sign" in current_actions and "kms:GenerateDataKey" in current_actions
    assert (
        not {"kms:Sign", "s3:PutObject", "s3:PutObjectRetention", "kms:GenerateDataKey"}
        & history_actions
    )
    for document in (current, historical):
        for statement in document["Statement"]:
            resources = (
                statement["Resource"]
                if isinstance(statement["Resource"], list)
                else [statement["Resource"]]
            )
            assert all("*" not in r and "opentofu.tfstate" not in r for r in resources)
    huge = copy.deepcopy(gov)
    huge["storage"]["current_keys"] = [
        k.replace("ext2/current", "x" * 700 + "/current") for k in KEYS
    ]
    huge["storage"]["current_prefix"] = huge["storage"]["current_keys"][0].split(
        SOURCE
    )[0]
    with pytest.raises(ValueError, match="capacity"):
        gate.session_policy(huge, historical=False)


class STS:
    def __init__(self, now):
        self.now = now
        self.calls = []
        self.error = None

    def assume_role_with_web_identity(self, **parameters):
        self.calls.append(parameters)
        if self.error:
            raise self.error
        return {
            "PackedPolicySize": 43,
            "AssumedRoleUser": {
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/cnesdata-delivery-ext2-gate/"
                + parameters["RoleSessionName"]
            },
            "Credentials": {
                "AccessKeyId": "synthetic-id",
                "SecretAccessKey": "synthetic-secret",
                "SessionToken": "synthetic-session",
                "Expiration": self.now + timedelta(seconds=900),
            },
        }


@pytest.mark.parametrize("historical", [False, True])
def test_single_owned_role_uses_exact_inline_session_and_temporary_credentials(
    gate, crypto, historical
):
    gov = signing_case(crypto)[0]
    gov["session_duration_seconds"] = 900
    now = datetime(2027, 1, 1, tzinfo=timezone.utc)
    sts = STS(now)
    result = gate.authorize_session(
        governance=gov, sts=sts, token="synthetic-oidc", historical=historical, now=now
    )
    assert len(sts.calls) == 1
    parameters = sts.calls[0]
    assert (
        parameters["RoleArn"]
        == f"arn:aws:iam::{ACCOUNT}:role/cnesdata-delivery-ext2-gate"
    )
    assert (
        parameters["DurationSeconds"] == 900
        and parameters["WebIdentityToken"] == "synthetic-oidc"
    )
    assert "PolicyArns" not in parameters
    assert json.loads(parameters["Policy"]) == json.loads(
        gate.session_policy(gov, historical=historical)
    )
    if historical:
        assert (
            "GenerateDataKey" not in parameters["Policy"]
            and "kms:Sign" not in parameters["Policy"]
        )
    assert result["AccessKeyId"] == "synthetic-id"


def test_sts_capacity_failure_cannot_export_or_fall_back(gate, crypto, capsys):
    gov = signing_case(crypto)[0]
    gov["session_duration_seconds"] = 900
    now = datetime(2027, 1, 1, tzinfo=timezone.utc)
    sts = STS(now)
    sts.error = RuntimeError("PackedPolicyTooLarge private credentials")
    with pytest.raises(ValueError):
        gate.authorize_session(
            governance=gov, sts=sts, token="private-token", historical=False, now=now
        )
    assert len(sts.calls) == 1 and capsys.readouterr().out == ""


def test_publisher_record_uses_real_uploader_outputs_and_api_job_identity(gate):
    gov, ref, api, member = transport_case()
    gov["invocation"] = {"run_id": "123", "run_attempt": "1", "source_sha": SOURCE}
    reference, record = gate.publisher_reference(
        member,
        artifact_id="456",
        artifact_digest=ref["artifact_digest"],
        github=api,
        governance=gov,
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    assert reference == ref
    assert (
        record
        == "EXT2_ARTIFACT_COMMIT_V1 "
        + canonical(
            {
                "artifact_id": "456",
                "artifact_digest": ref["artifact_digest"],
                "receipt_ref_sha256": sha(member),
            }
        )
        .decode()
        .strip()
    )
    assert "arn:" not in record and "synthetic-ext2-evidence" not in record


def test_workflow_pins_custom_sub_and_publisher_closure():
    import yaml

    path = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/reusable-cnesdata-signing-gate.yml"
    )
    assert path.is_file(), "ratified reusable is not implemented"
    workflow = yaml.safe_load(path.read_text())
    assert set(workflow["on"]) == {"workflow_call"} and workflow["permissions"] == {}
    jobs = workflow["jobs"]
    assert set(jobs) == {"validate-no-creds", "sign-store-publish", "verify-handoff"}
    assert "id-token" not in jobs["validate-no-creds"]["permissions"]
    assert jobs["sign-store-publish"]["permissions"]["id-token"] == "write"
    assert jobs["verify-handoff"]["permissions"]["id-token"] == "write"
    assert jobs["verify-handoff"]["needs"] == [
        "validate-no-creds",
        "sign-store-publish",
    ]
    steps = jobs["sign-store-publish"]["steps"]
    upload = [
        step
        for step in steps
        if step.get("uses", "").startswith("actions/upload-artifact@")
    ]
    assert len(upload) == 1 and upload[0]["uses"].endswith(
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    )
    assert upload[0]["with"]["overwrite"] is False
    assert upload[0]["with"]["path"] == ".ext2-public/receipt-ref.json"
    publisher = [
        step for step in steps if step.get("name") == "Commit EXT2 artifact reference"
    ]
    assert len(publisher) == 1 and "publish-commit" in publisher[0]["run"]
    assert steps.index(upload[0]) < steps.index(publisher[0])
    for job in jobs.values():
        assert job["runs-on"] == "ubuntu-latest" and job["environment"] == "production"
        assert any("PYBOOT" in step.get("run", "") for step in job["steps"])
    assert set(workflow["on"]["workflow_call"]["outputs"]) == {
        "ext2_post_upload_receipt_v1"
    }


@pytest.mark.parametrize("mode", ["approved", "tampered", "stale_bytecode"])
def test_consumer_loader_executes_only_verified_source_bytes(
    gate, tmp_path, monkeypatch, mode
):
    import py_compile

    gov, _, api, _ = transport_case()
    sources = {
        "release/activation.schema.json": b'{"type":"object"}',
        "release/verify_activation.py": b"def admit_ext2(*a, **kw): return {}\n",
        "release/build_activation.py": (
            b"def prepare_ext2(*a, **kw): return b'GOOD'\n"
            b"def render_ext2(*a, **kw): return {}\n"
        ),
    }
    gov["consumer"] = {
        "repository": REPOSITORY,
        "source_sha": SOURCE,
        "files": [{"path": p, "sha256": sha(raw)} for p, raw in sources.items()],
    }
    for path, raw in sources.items():
        api.responses[f"repos/{REPOSITORY}/contents/{path}?ref={SOURCE}"] = {
            "type": "file",
            "path": path,
            "encoding": "base64",
            "size": len(raw),
            "content": base64.b64encode(raw).decode(),
            "sha": hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw
            ).hexdigest(),
        }
    monkeypatch.chdir(tmp_path)
    if mode == "tampered":
        gov["consumer"]["files"][1]["sha256"] = "f" * 64
        with pytest.raises(ValueError, match="consumer_bytes"):
            gate._load_consumer(gov, {}, api)
        return
    if mode == "stale_bytecode":
        target = tmp_path / ".ext2-private/consumer/release/build_activation.py"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            sources["release/build_activation.py"].replace(b"GOOD", b"EVIL")
        )
        stamp = 1700000000
        os.utime(target, (stamp, stamp))
        py_compile.compile(str(target), doraise=True)
        write = Path.write_bytes

        def preserve_mtime(path, raw):
            result = write(path, raw)
            if path == target:
                os.utime(path, (stamp, stamp))
            return result

        monkeypatch.setattr(Path, "write_bytes", preserve_mtime)
    consumer = gate._load_consumer(gov, {}, api)
    assert (
        consumer.prepare(api, gov, datetime(2027, 1, 1, tzinfo=timezone.utc)) == b"GOOD"
    )


def test_current_authorization_is_checked_again_after_slow_readbacks(gate, crypto):
    case = signing_case(crypto)
    observations = iter(
        [
            datetime(2027, 1, 1, tzinfo=timezone.utc),
            datetime(2030, 1, 1, tzinfo=timezone.utc),
        ]
    )
    case[0]["_clock"] = lambda: next(observations)
    with pytest.raises(ValueError):
        sign(gate, case)
    assert not any(op == "sign" for op, _ in case[2].calls)


def test_private_request_is_data_only_and_hash_source_mode_bound(gate):
    _, ref, _, _ = transport_case()
    request = {
        "request_version": 1,
        "mode": "historical",
        "source_sha": SOURCE,
        "inputs": None,
        "ext2_post_upload_receipt_v1": ref,
    }
    raw = canonical(request)
    assert (
        gate.decode_request(raw, digest=sha(raw), source_sha=SOURCE, mode="historical")
        == request
    )
    for changed in [
        request | {"script": "caller.py"},
        request | {"source_sha": "f" * 40},
        request | {"mode": "activation"},
    ]:
        body = canonical(changed)
        with pytest.raises(ValueError):
            gate.decode_request(
                body, digest=sha(body), source_sha=SOURCE, mode="historical"
            )
    with pytest.raises(ValueError):
        gate.decode_request(raw, digest="f" * 64, source_sha=SOURCE, mode="historical")


def test_cli_without_authentic_protected_governance_fails_before_sdk(gate, tmp_path):
    env = {
        "PATH": os.defpath,
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "CNESDATA_DELIVERY_GOVERNANCE": "private-invalid-owner-fact",
    }
    result = subprocess.run(
        [sys.executable, "-m", "tools.cnesdata_delivery.signing_gate", "preflight"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0 and result.stdout == ""
    assert "Traceback" not in result.stderr and "private-invalid" not in result.stderr


@pytest.mark.parametrize("tampered", [False, True])
def test_actual_workflow_bootstrap_fetches_only_api_pinned_helper_bytes(
    tmp_path, monkeypatch, tampered
):
    import urllib.request
    import urllib.parse
    import yaml

    path = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/reusable-cnesdata-signing-gate.yml"
    )
    assert path.is_file(), "bootstrap workflow is not implemented"
    workflow = yaml.safe_load(path.read_text())
    steps = workflow["jobs"]["validate-no-creds"]["steps"]
    script = next(step["run"] for step in steps if "PYBOOT" in step.get("run", ""))
    source = script.split("<<'PYBOOT'\n", 1)[1].rsplit("\nPYBOOT", 1)[0]
    gov, _, api, _ = transport_case()
    gov["activation_enabled"] = True
    env = {
        "CNESDATA_DELIVERY_GOVERNANCE": canonical({"ext2": gov}).decode(),
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/develop",
        "GITHUB_SHA": SOURCE,
        "EXPECTED_SOURCE_SHA": SOURCE,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_TOKEN": "fixture-token",
    }
    if tampered:
        p = f"repos/VINIClUS/infra-ansible/contents/tools/cnesdata_delivery/evidence.py?ref={PIN}"
        api.responses[p]["content"] = base64.b64encode(b"unapproved source").decode()
    calls = []

    def urlopen(request, timeout):
        calls.append(request.full_url)
        parsed = urllib.parse.urlsplit(request.full_url)
        assert (
            parsed.scheme == "https"
            and parsed.netloc == "api.github.com"
            and timeout == 20
        )
        key = parsed.path.lstrip("/") + ("?" + parsed.query if parsed.query else "")
        return io.BytesIO(json.dumps(api.responses[key]).encode())

    opened = []

    def build_opener(*handlers):
        assert len(handlers) == 1
        assert (
            handlers[0].redirect_request(
                None, None, 302, "redirect", {}, "https://evil.invalid"
            )
            is None
        )
        opened.append(True)
        return SimpleNamespace(open=urlopen)

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.chdir(tmp_path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    if tampered:
        with pytest.raises((ValueError, AssertionError)):
            exec(compile(source, "ratified-workflow-bootstrap", "exec"), {})
        assert not (tmp_path / "tools/cnesdata_delivery/evidence.py").exists()
    else:
        exec(compile(source, "ratified-workflow-bootstrap", "exec"), {})
        assert (tmp_path / "tools/cnesdata_delivery/evidence.py").is_file()
        assert len(list(tmp_path.glob("tools/cnesdata_delivery/*"))) == 5
    assert opened, (
        "source bootstrap must refuse metadata redirects before code is trusted"
    )
    assert all("@main" not in url and "private-token" not in url for url in calls)
