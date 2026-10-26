"""Witness sintético para os contratos nativos do bootstrap."""

import copy
import json
import re


def observation(plan, address):
    matches = [
        r
        for r in plan.get("resource_changes", [])
        if r.get("mode") == "managed" and r["address"] == address
    ]
    assert len(matches) == 1, f"mandatory_resource_absent_or_duplicate: {address}"
    assert matches[0]["change"]["actions"] == ["create"], f"native_create_required: {address}"
    return matches[0]["change"]["after"]


def _expr(value):
    return "${" + value + "}"

def _document(statements):
    return json.dumps({"Version": "2012-10-17", "Statement": statements})

def _add(resources, kind, label, **values):
    resources.setdefault(kind, {})[label] = values

def _bucket_resources(resources, core, selected, key):
    state_bucket = _expr(selected + ".backend.bucket")
    logging_bucket = _expr(selected + ".logging.bucket")
    state_arn = "arn:aws:s3:::" + state_bucket
    logging_arn = "arn:aws:s3:::" + logging_bucket
    tags = _expr("merge(var.tags, { Owner = " + selected + ".owner })")
    for name, bucket in (("state", state_bucket), ("logging", logging_bucket)):
        _add(
            resources,
            "aws_s3_bucket",
            name,
            bucket=bucket,
            force_destroy=False,
            object_lock_enabled=False,
            tags=tags,
            lifecycle={"prevent_destroy": True},
        )
        _add_public_access(resources, name)
        if core or name == "logging":
            _add_ownership(resources, name)
        _add_encryption(resources, name, key)
        _add_bucket_policy(resources, name, (state_arn, logging_arn), selected)
    _add_state_logging(resources, selected)

def _add_public_access(resources, name):
    _add(
        resources,
        "aws_s3_bucket_public_access_block",
        name,
        bucket=_expr(f"aws_s3_bucket.{name}.id"),
        block_public_acls=True,
        block_public_policy=True,
        ignore_public_acls=True,
        restrict_public_buckets=True,
    )

def _add_ownership(resources, name):
    _add(
        resources,
        "aws_s3_bucket_ownership_controls",
        name,
        bucket=_expr(f"aws_s3_bucket.{name}.id"),
        rule=[{"object_ownership": "BucketOwnerEnforced"}],
    )

def _add_encryption(resources, name, key):
    default = {"sse_algorithm": "aws:kms", "kms_master_key_id": key}
    if name == "logging":
        default = {"sse_algorithm": "AES256"}
    rule = {"apply_server_side_encryption_by_default": [default]}
    if name == "state":
        rule["bucket_key_enabled"] = True
    _add(
        resources,
        "aws_s3_bucket_server_side_encryption_configuration",
        name,
        bucket=_expr(f"aws_s3_bucket.{name}.id"),
        rule=[rule],
    )

def _add_bucket_policy(resources, name, arns, selected):
    state_arn, logging_arn = arns
    arn = state_arn if name == "state" else logging_arn
    statements = [
        {
            "Effect": "Deny",
            "Action": "s3:*",
            "Principal": "*",
            "Resource": [arn, arn + "/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
    ]
    if name == "logging":
        statements.append(
            {
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Principal": {"Service": "logging.s3.amazonaws.com"},
                "Resource": logging_arn + "/" + _expr(selected + ".logging.prefix") + "*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": _expr("var.account_id")},
                    "ArnLike": {"aws:SourceArn": state_arn},
                },
            }
        )
    _add(
        resources,
        "aws_s3_bucket_policy",
        name,
        bucket=_expr(f"aws_s3_bucket.{name}.id"),
        policy=_document(statements),
    )

def _add_state_logging(resources, selected):
    prefix = _expr(selected + ".logging.prefix")
    _add(
        resources,
        "aws_s3_bucket_versioning",
        "state",
        bucket=_expr("aws_s3_bucket.state.id"),
        versioning_configuration=[{"status": "Enabled"}],
    )
    _add(
        resources,
        "aws_s3_bucket_logging",
        "state",
        bucket=_expr("aws_s3_bucket.state.id"),
        target_bucket=_expr("aws_s3_bucket.logging.id"),
        target_prefix=prefix,
    )
    _add(
        resources,
        "aws_s3_bucket_lifecycle_configuration",
        "logging",
        bucket=_expr("aws_s3_bucket.logging.id"),
        rule=[
            {
                "id": "retain-30-days",
                "status": "Enabled",
                "filter": [{"prefix": prefix}],
                "expiration": [{"days": 30}],
            }
        ],
    )

def _identity_context(key):
    reader = _expr("aws_iam_role.bootstrap_readback.arn")
    writer = _expr("aws_iam_role.bootstrap_executor.arn")
    roots, logs, objects, locks = [], [], [], []
    for root in ("foundation", "budget-backend"):
        base = "var.roots." + root
        bucket = "arn:aws:s3:::${" + base + ".backend.bucket}"
        obj = bucket + "/${" + base + ".backend.key}"
        roots.append(bucket)
        logs.append("arn:aws:s3:::${" + base + ".logging.bucket}")
        objects.append(obj)
        locks.append(obj + ".tflock")
    return reader, writer, _permissions(roots, objects, locks, key), _readback_permissions(
        (roots, logs), (objects, locks), key)


def _identity_bindings(resources, executor, readback):
    owner = "merge(var.tags, { Owner = var.roots.foundation.owner })"
    tags = _expr(owner)
    _add(resources, "aws_iam_user", "bootstrap_operator",
         name=_expr("var.identities.operator.name"), path=_expr("var.identities.operator.path"),
         force_destroy=False, tags=tags)
    _add(resources, "aws_iam_policy", "executor_boundary",
         name=_expr("var.identities.boundary.name"), path=_expr("var.identities.boundary.path"),
         policy=_document(executor), tags=tags)
    _roles(resources, (executor, readback))


def _foundation_identity_resources(resources, key):
    reader, writer, executor, readback = _identity_context(key)
    _identity_bindings(resources, executor, readback)
    _add(resources, "aws_iam_user_policy_attachment", "local_login",
         user=_expr("aws_iam_user.bootstrap_operator.name"),
         policy_arn="arn:aws:iam::aws:policy/SignInLocalDevelopmentAccess")
    _add(resources, "aws_iam_user_policy", "local_assume",
         name="synthetic-local-assume", user=_expr("aws_iam_user.bootstrap_operator.name"),
         policy=_document([{"Effect": "Allow", "Action": "sts:AssumeRole",
                            "Resource": [reader, writer],
                            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]))

def _permissions(roots, objects, locks, key):
    return [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"],
            "Resource": objects + locks,
        },
        {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": locks},
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
            "Resource": roots,
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:DescribeKey",
            ],
            "Resource": key,
        },
    ]

def _readback_permissions(targets, object_sets, key):
    roots, logs = targets
    objects, locks = object_sets
    return [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketLocation",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketPolicy",
                "s3:GetBucketOwnershipControls",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketTagging",
            ],
            "Resource": roots + logs,
        },
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": roots},
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:GetObjectVersion"],
            "Resource": objects + locks,
        },
        {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key},
        {
            "Effect": "Allow",
            "Action": [
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
                "kms:GetKeyRotationStatus",
                "kms:ListResourceTags",
            ],
            "Resource": key,
        },
    ]

def _roles(resources, policies):
    executor, readback = policies
    for short in ("readback", "executor"):
        trust = _document(
            [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": _expr("aws_iam_user.bootstrap_operator.arn")},
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                }
            ]
        )
        attrs = {
            "name": _expr(f"var.identities.{short}.name"),
            "path": _expr(f"var.identities.{short}.path"),
            "max_session_duration": 3600,
            "assume_role_policy": trust,
            "tags": _expr("merge(var.tags, { Owner = var.roots.foundation.owner })"),
        }
        if short == "executor":
            attrs["permissions_boundary"] = _expr("aws_iam_policy.executor_boundary.arn")
        _add(resources, "aws_iam_role", "bootstrap_" + short, **attrs)
        policy = executor if short == "executor" else readback
        _add(
            resources,
            "aws_iam_role_policy",
            "bootstrap_" + short,
            name="synthetic-" + short,
            role=_expr("aws_iam_role.bootstrap_" + short + ".name"),
            policy=_document(policy),
        )

def _variables(exact=False):
    names = ["account_id", "region", "roots", "identities", "tags"]
    if not exact:
        names.extend(("backend", "kms_key_arn"))
    return {name: {"type": "any"} for name in names}


def _declared_addresses(work):
    declared = set()
    for path in work.glob("*.tf*"):
        if path.suffix == ".json":
            data = json.loads(path.read_text()).get("resource", {})
            declared.update(f"{kind}.{label}" for kind, items in data.items() for label in items)
        elif path.suffix == ".tf":
            declared.update(
                f"{kind}.{label}"
                for kind, label in re.findall(r'resource\s+"([^"]+)"\s+"([^"]+)"', path.read_text())
            )
    return declared

def _mock_blocks(case, root, declared, source):
    blocks = []
    if source == "witness" or declared:
        for name in ("state", "logging"):
            address = f"aws_s3_bucket.{name}"
            if address not in declared:
                continue
            section = "backend" if name == "state" else "logging"
            bucket = case["roots"][root][section]["bucket"]
            blocks.append(
                f"override_resource {{\n target = {address}\n"
                f' values = {{ id = "{bucket}", arn = "arn:aws:s3:::{bucket}" }}\n}}'
            )
    if "aws_kms_key.foundation" in declared:
        blocks.extend(_identity_overrides(case, declared))
    blocks.append(
        'mock_data "aws_caller_identity" { defaults = { account_id = '
        + json.dumps(case["account_id"])
        + " } }"
    )
    return blocks

def _identity_overrides(case, declared):
    blocks = []
    for address, name in (
        ("aws_iam_user.bootstrap_operator", "operator"),
        ("aws_iam_role.bootstrap_readback", "readback"),
        ("aws_iam_role.bootstrap_executor", "executor"),
        ("aws_iam_policy.executor_boundary", "boundary"),
    ):
        if address in declared:
            blocks.append(
                f"override_resource {{\n target = {address}\n"
                f' values = {{ arn = "{case["expected"][name]}" }}\n}}'
            )
    cmk = case["expected"]["cmk"]
    blocks.append(
        'mock_resource "aws_kms_key" { defaults = { arn = '
        + json.dumps(cmk)
        + ", key_id = "
        + json.dumps(cmk.split("/")[-1])
        + " } }"
    )
    return blocks

def _write_mock_file(work, case, root, source):
    blocks = _mock_blocks(case, root, _declared_addresses(work), source)
    content = (
        'mock_provider "aws" {\n'
        + "\n".join(blocks)
        + '\n}\nrun "contract" {\n command = plan\n providers = { aws = aws }\n}\n'
    )
    (work / "contract.tftest.hcl").write_text(content)

def _lifecycle_state(harness, native, address):
    attributes = copy.deepcopy(observation(native["plan"], address))
    kind, name = address.split(".")
    schema = harness.run(native["work"], ["providers", "schema", "-json"])
    assert schema.returncode == 0, schema.stderr
    version = json.loads(schema.stdout)["provider_schemas"]["registry.opentofu.org/hashicorp/aws"][
        "resource_schemas"
    ][kind]["version"]
    attributes["id"] = (
        native["case"]["expected"]["cmk"].split("/")[-1]
        if kind == "aws_kms_key"
        else attributes["bucket"]
    )
    return {
        "version": 4,
        "terraform_version": "1.13.2",
        "serial": 1,
        "lineage": "synthetic-lifecycle-proof",
        "outputs": {},
        "resources": [
            {
                "mode": "managed",
                "type": kind,
                "name": name,
                "provider": 'provider["registry.opentofu.org/hashicorp/aws"]',
                "instances": [
                    {
                        "schema_version": version,
                        "attributes": attributes,
                        "sensitive_attributes": [],
                    }
                ],
            }
        ],
    }

def _safety_override(work):
    return work / "safety_override.tf.json"

def _destroy_plan(harness, native, address):
    kind, name = address.split(".")
    work = native["work"]
    state_path = work / f"synthetic-{kind}-{name}.tfstate"
    state_path.write_text(json.dumps(_lifecycle_state(harness, native, address)))
    override = _safety_override(work)
    override.write_text(
        json.dumps(
            {
                "provider": {
                    "aws": {
                        "region": "us-east-2",
                        "access_key": "synthetic",
                        "secret_key": "synthetic",
                        "skip_credentials_validation": True,
                        "skip_requesting_account_id": True,
                        "skip_metadata_api_check": True,
                        "allowed_account_ids": [],
                    }
                }
            }
        )
    )
    try:
        args = [
            "plan",
            "-destroy",
            "-refresh=false",
            "-input=false",
            "-no-color",
            f"-state={state_path.name}",
            "-var-file=inputs.tfvars.json",
        ]
        result = harness.run(work, args)
        report = {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        (work / f"destroy-{kind}-{name}.json").write_text(json.dumps(report, indent=2))
        return result
    finally:
        override.unlink()
