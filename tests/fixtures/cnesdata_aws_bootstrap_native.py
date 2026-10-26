"""B1a: parâmetros literais, OpenTofu offline e witness exclusivamente sintético.

Não importa planner, checkpoint, executor ou inventário. O witness valida o
harness; não é configuração de produção nem prova de apply/ordenação AWS.
"""

import copy
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FOUNDATION = (
    "aws_iam_user.bootstrap_operator", "aws_iam_user_policy_attachment.local_login",
    "aws_iam_user_policy.local_assume", "aws_iam_policy.executor_boundary",
    "aws_iam_role.bootstrap_readback", "aws_iam_role.bootstrap_executor",
    "aws_iam_role_policy.bootstrap_readback", "aws_iam_role_policy.bootstrap_executor",
    "aws_kms_key.foundation", "aws_s3_bucket.state", "aws_s3_bucket_versioning.state",
    "aws_s3_bucket_public_access_block.state",
    "aws_s3_bucket_server_side_encryption_configuration.state",
    "aws_s3_bucket_ownership_controls.state", "aws_s3_bucket_policy.state",
    "aws_s3_bucket.logging", "aws_s3_bucket_ownership_controls.logging",
    "aws_s3_bucket_public_access_block.logging",
    "aws_s3_bucket_server_side_encryption_configuration.logging",
    "aws_s3_bucket_policy.logging", "aws_s3_bucket_lifecycle_configuration.logging",
    "aws_s3_bucket_logging.state",
)
BUDGET = tuple(a for a in FOUNDATION if not a.startswith(("aws_iam_", "aws_kms_"))
               and a != "aws_s3_bucket_ownership_controls.state")
assert len(FOUNDATION) == 22 and len(BUDGET) == 12

# ARNs são literais independentes da construção HCL do witness. Names/path são
# inputs nativos. O oráculo ainda deve conferir os nomes reais antes dos mocks.
CASES = {
    "a": {
        "account_id": "836651842853", "region": "us-east-2",
        "roots": {
            "foundation": {"owner": "infra-ansible:cnesdata", "backend": {
                "bucket": "example-a-foundation-state", "key": "bootstrap/foundation.tfstate"},
                "logging": {"bucket": "example-a-foundation-logs",
                            "prefix": "access/example-a-foundation-state/"}},
            "budget-backend": {"owner": "personal-infra-live:cnesdata", "backend": {
                "bucket": "example-a-budget-state", "key": "bootstrap/backend.tfstate"},
                "logging": {"bucket": "example-a-budget-logs",
                            "prefix": "access/example-a-budget-state/"}},
        },
        "identities": {
            "operator": {"name": "example-a-operator", "path": "/a/"},
            "readback": {"name": "example-a-readback", "path": "/a/"},
            "executor": {"name": "example-a-executor", "path": "/a/"},
            "boundary": {"name": "example-a-boundary", "path": "/a/"},
        },
        "tags": {"Project": "CnesData", "Fixture": "a"},
        "expected": {
            "operator": "arn:aws:iam::836651842853:user/a/example-a-operator",
            "readback": "arn:aws:iam::836651842853:role/a/example-a-readback",
            "executor": "arn:aws:iam::836651842853:role/a/example-a-executor",
            "boundary": "arn:aws:iam::836651842853:policy/a/example-a-boundary",
            "cmk": "arn:aws:kms:us-east-2:836651842853:key/00000000-0000-4000-8000-000000000001",
        },
    },
    "b": {
        "account_id": "836651842853", "region": "us-east-2",
        "roots": {
            "foundation": {"owner": "infra-ansible:cnesdata", "backend": {
                "bucket": "example-b-state-local-bootstrap", "key": "bootstrap/foundation-b.tfstate"},
                "logging": {"bucket": "example-b-local-access-logs",
                            "prefix": "access/example-b-state-local-bootstrap/"}},
            "budget-backend": {"owner": "personal-infra-live:cnesdata", "backend": {
                "bucket": "example-b-state-budget-only", "key": "bootstrap/backend-b.tfstate"},
                "logging": {"bucket": "example-b-budget-access-logs",
                            "prefix": "access/example-b-state-budget-only/"}},
        },
        "identities": {
            "operator": {"name": "second-console-operator", "path": "/different/"},
            "readback": {"name": "second-local-reader", "path": "/different/"},
            "executor": {"name": "second-local-state-writer", "path": "/different/"},
            "boundary": {"name": "second-state-boundary", "path": "/different/"},
        },
        "tags": {"Project": "CnesData", "Fixture": "b"},
        "expected": {
            "operator": "arn:aws:iam::836651842853:user/different/second-console-operator",
            "readback": "arn:aws:iam::836651842853:role/different/second-local-reader",
            "executor": "arn:aws:iam::836651842853:role/different/second-local-state-writer",
            "boundary": "arn:aws:iam::836651842853:policy/different/second-state-boundary",
            "cmk": "arn:aws:kms:us-east-2:836651842853:key/00000000-0000-4000-8000-000000000002",
        },
    },
}


def observation(plan, address):
    matches = [r for r in plan.get("resource_changes", [])
               if r.get("mode") == "managed" and r["address"] == address]
    assert len(matches) == 1, f"mandatory_resource_absent_or_duplicate: {address}"
    assert matches[0]["change"]["actions"] == ["create"], f"native_create_required: {address}"
    return matches[0]["change"]["after"]


def assert_policy(actual, expected, label):
    """Normalização sintática fechada, não avaliação de permissões IAM."""
    def document(value):
        value = json.loads(value) if isinstance(value, str) else copy.deepcopy(value)
        assert set(value) == {"Version", "Statement"}, f"policy_envelope: {label}"
        assert value["Version"] == "2012-10-17"
        assert isinstance(value["Statement"], list) and value["Statement"]

        def sequence(value):
            seq = value if isinstance(value, list) else [value]
            assert all(isinstance(x, str) for x in seq), f"policy_scalar_type: {label}"
            assert len(seq) == len(set(seq)), f"policy_duplicate_value: {label}"
            return sorted(seq)

        statements = []
        for statement in value["Statement"]:
            assert set(statement) <= {"Sid", "Effect", "Action", "Resource", "Principal", "Condition"}, label
            statement.pop("Sid", None)
            assert statement["Effect"] in {"Allow", "Deny"}
            statement["Action"] = sequence(statement["Action"])
            if "Resource" in statement:
                statement["Resource"] = sequence(statement["Resource"])
            if "Principal" in statement:
                principal = statement["Principal"]
                if isinstance(principal, dict):
                    principal = {k: sequence(v) for k, v in principal.items()}
                    if principal == {"AWS": ["*"]}:
                        principal = "*"
                else:
                    assert principal == "*", f"policy_principal_type: {label}"
                statement["Principal"] = principal
            conditions = statement.get("Condition")
            if conditions is not None:
                normalized = {}
                for operator, pairs in conditions.items():
                    assert isinstance(pairs, dict) and pairs
                    values = {}
                    for key, val in pairs.items():
                        if operator == "Bool":
                            vals = val if isinstance(val, list) else [val]
                            assert all(v in (True, False, "true", "false") for v in vals)
                            val = [str(v).lower() for v in vals]
                        values[key] = sequence(val)
                    if operator == "ArnLike" and all(not any(c in v for c in "*?")
                                                    for vals in values.values() for v in vals):
                        operator = "ArnEquals"
                    assert operator not in normalized, f"policy_duplicate_operator: {label}"
                    normalized[operator] = values
                statement["Condition"] = normalized
            statements.append(json.dumps(statement, sort_keys=True, separators=(",", ":")))
        assert len(statements) == len(set(statements)), f"policy_duplicate_statement: {label}"
        return sorted(statements)

    assert document(actual) == document(expected), f"policy_document_mismatch: {label}"


class NativeHarness:
    def __init__(self, base, provider_dir):
        self.base = base
        self.cache = {}
        self.failures = {}
        self.commands = []
        self.provider_dir = provider_dir
        mirror = base / "mirror/registry.opentofu.org/hashicorp/aws/6.54.0"
        mirror.mkdir(parents=True)
        (mirror / "linux_amd64").symlink_to(provider_dir)
        self.cli_config = base / "tofu.rc"
        self.cli_config.write_text('provider_installation {\n filesystem_mirror {\n path = '
                                   + json.dumps(str(base / "mirror"))
                                   + '\n include = ["registry.opentofu.org/hashicorp/aws"]\n }\n}\n')
        self.home = base / "home"
        self.home.mkdir(mode=0o700)
        self.env = {"PATH": os.defpath, "HOME": str(self.home), "TMPDIR": str(base), "LANG": "C.UTF-8",
                    "AWS_EC2_METADATA_DISABLED": "true", "AWS_CONFIG_FILE": "/dev/null",
                    "AWS_SHARED_CREDENTIALS_FILE": "/dev/null", "TF_IN_AUTOMATION": "1",
                    "CHECKPOINT_DISABLE": "1", "TF_CLI_CONFIG_FILE": str(self.cli_config)}
        version = self.run(base, ["version", "-json"])
        assert version.returncode == 0, f"offline_harness_version: {version.stderr}"
        assert json.loads(version.stdout)["terraform_version"] == "1.13.2"
        self.prepared = base / "prepared"
        self.prepared.mkdir()
        (self.prepared / "versions.tf.json").write_text(json.dumps({"terraform": {
            "required_providers": {"aws": {"source": "hashicorp/aws", "version": "=6.54.0"}}}}))
        lock = next((p / ".terraform.lock.hcl" for p in provider_dir.parents
                     if (p / ".terraform.lock.hcl").is_file()), None)
        assert lock, "offline_harness_absent: cached checksum lock"
        shutil.copy2(lock, self.prepared / ".terraform.lock.hcl")
        init = self.run(self.prepared, ["init", "-backend=false", "-input=false", "-lockfile=readonly"])
        assert init.returncode == 0, f"offline_harness_init: {init.stdout}\n{init.stderr}"

    def run(self, folder, args):
        assert args[0] in {"version", "init", "test", "providers", "plan"}
        assert not any(x in {"apply", "import", "-force-copy", "-reconfigure"} for x in args)
        self.commands.append({"cwd": str(folder), "args": args})
        result = subprocess.run([shutil.which("rtk"), "proxy", shutil.which("unshare"),
                               "--user", "--map-root-user", "--net", shutil.which("tofu"), *args],
                              cwd=folder, env=self.env, text=True, capture_output=True, timeout=180, check=False)
        (self.base / "commands.json").write_text(json.dumps({"commands": self.commands, "environment": self.env}, indent=2))
        (folder / (args[0] + "-stderr.txt")).write_text(result.stderr)
        (folder / (args[0] + "-stdout.txt")).write_text(result.stdout)
        return result

    def plan(self, case_id="a", root="foundation", source="target", mutation=None):
        key = (case_id, root, source, mutation)
        if key in self.failures:
            raise AssertionError(self.failures[key])
        if key in self.cache:
            return self.cache[key]
        case = copy.deepcopy(CASES["a" if case_id == "foreign" else case_id])
        if case_id == "foreign":
            case["account_id"] = "111111111111"
            case["expected"]["cmk"] = "arn:aws:kms:us-east-2:111111111111:key/00000000-0000-4000-8000-000000000001"
        work = self.base / ("-".join(x or "none" for x in key))
        work.mkdir()
        inputs = {k: case[k] for k in ("account_id", "region", "roots", "identities", "tags")}
        inputs.update(backend=case["roots"][root], kms_key_arn=case["expected"]["cmk"])
        if source == "witness":
            config = witness_config(root)
            if mutation:
                mutate(config, mutation)
            (work / "synthetic.tf.json").write_text(json.dumps(config, indent=2))
        else:
            origin = (REPO / "opentofu/cnesdata-bootstrap/foundation" if root == "foundation"
                      else Path("/home/vinicius/code/personal-infra-live/bootstrap"))
            files = [*origin.glob("*.tf"), *origin.glob("*.tf.json")]
            for file in files:
                assert not file.is_symlink(), "native_source_symlink"
                shutil.copy2(file, work / file.name)
            if not files:
                (work / "empty.tf.json").write_text(json.dumps({"terraform": {
                    "required_providers": {"aws": {"source": "hashicorp/aws", "version": "=6.54.0"}}},
                    "variable": {k: {"type": "any"} for k in inputs}}))
        shutil.copytree(self.prepared / ".terraform", work / ".terraform", symlinks=True)
        shutil.copy2(self.prepared / ".terraform.lock.hcl", work / ".terraform.lock.hcl")
        (work / "inputs.tfvars.json").write_text(json.dumps(inputs))
        self.mock_file(work, case, root, source)
        result = self.run(work, ["test", "-json", "-verbose", "-var-file=inputs.tfvars.json"])
        events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        (work / "native-events.jsonl").write_text(result.stdout)
        errors = [x.get("diagnostic", {}) for x in events if x.get("diagnostic", {}).get("severity") == "error"]
        if source == "target" and errors and all(x["summary"] == "Invalid value for variable" for x in errors):
            self.failures[key] = "target_input_contract_incompatible: " + "; ".join(x["detail"] for x in errors)
            raise AssertionError(self.failures[key])
        assert result.returncode == 0, f"native_plan_error: {[(x['summary'], x['detail']) for x in errors]}\n{result.stderr}"
        plans = [x["test_plan"] for x in events if "test_plan" in x]
        assert len(plans) == 1, "native_plan_missing"
        (work / "native-plan.json").write_text(json.dumps(plans[0], indent=2, sort_keys=True))
        result = {"plan": plans[0], "case": case, "root": root, "work": work, "source": source}
        self.cache[key] = result
        return result

    def mock_file(self, work, case, root, source):
        blocks = []
        declared = set()
        for path in work.glob("*.tf*"):
            if path.suffix == ".json":
                data = json.loads(path.read_text()).get("resource", {})
                declared.update(f"{kind}.{label}" for kind, items in data.items() for label in items)
            elif path.suffix == ".tf":
                declared.update(f"{kind}.{label}" for kind, label in re.findall(r'resource\s+"([^"]+)"\s+"([^"]+)"', path.read_text()))
        if source == "witness" or declared:
            for name in ("state", "logging"):
                if f"aws_s3_bucket.{name}" not in declared:
                    continue
                bucket = case["roots"][root]["backend" if name == "state" else "logging"]["bucket"]
                blocks.append(f'override_resource {{\n target = aws_s3_bucket.{name}\n'
                              f' values = {{ id = "{bucket}", arn = "arn:aws:s3:::{bucket}" }}\n}}')
        if "aws_kms_key.foundation" in declared:
            for address, name in (("aws_iam_user.bootstrap_operator", "operator"),
                                  ("aws_iam_role.bootstrap_readback", "readback"),
                                  ("aws_iam_role.bootstrap_executor", "executor"),
                                  ("aws_iam_policy.executor_boundary", "boundary")):
                if address not in declared:
                    continue
                blocks.append(f'override_resource {{\n target = {address}\n'
                              f' values = {{ arn = "{case["expected"][name]}" }}\n}}')
            blocks.append('mock_resource "aws_kms_key" { defaults = { arn = '
                          + json.dumps(case["expected"]["cmk"]) + ', key_id = '
                          + json.dumps(case["expected"]["cmk"].split("/")[-1]) + ' } }')
        blocks.append('mock_data "aws_caller_identity" { defaults = { account_id = '
                      + json.dumps(case["account_id"]) + ' } }')
        (work / "contract.tftest.hcl").write_text('mock_provider "aws" {\n' + '\n'.join(blocks)
            + '\n}\nrun "contract" {\n command = plan\n providers = { aws = aws }\n}\n')

    def prove_prevent_destroy(self, native, address):
        attributes = copy.deepcopy(observation(native["plan"], address))
        kind, name = address.split(".")
        schema = self.run(native["work"], ["providers", "schema", "-json"])
        assert schema.returncode == 0, schema.stderr
        version = json.loads(schema.stdout)["provider_schemas"]["registry.opentofu.org/hashicorp/aws"]["resource_schemas"][kind]["version"]
        attributes["id"] = (native["case"]["expected"]["cmk"].split("/")[-1]
                            if kind == "aws_kms_key" else attributes["bucket"])
        state = {"version": 4, "terraform_version": "1.13.2", "serial": 1,
                 "lineage": "synthetic-lifecycle-proof", "outputs": {}, "resources": [{
                     "mode": "managed", "type": kind, "name": name,
                     "provider": 'provider["registry.opentofu.org/hashicorp/aws"]',
                     "instances": [{"schema_version": version, "attributes": attributes,
                                    "sensitive_attributes": []}]}]}
        work = native["work"]
        state_path = work / f"synthetic-{kind}-{name}.tfstate"
        state_path.write_text(json.dumps(state))
        override = work / "safety_override.tf.json"
        override.write_text(json.dumps({"provider": {"aws": {"region": "us-east-2",
            "access_key": "synthetic", "secret_key": "synthetic", "skip_credentials_validation": True,
            "skip_requesting_account_id": True, "skip_metadata_api_check": True, "allowed_account_ids": []}}}))
        try:
            result = self.run(work, ["plan", "-destroy", "-refresh=false", "-input=false", "-no-color",
                                     f"-state={state_path.name}", "-var-file=inputs.tfvars.json"])
            (work / f"destroy-{kind}-{name}.json").write_text(json.dumps({"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}, indent=2))
            assert result.returncode != 0, f"prevent_destroy_absent: {address}"
            assert "instance cannot be destroyed" in result.stderr.lower(), f"lifecycle_not_proved: {result.stderr}"
            assert "prevent_destroy" in result.stderr
        finally:
            override.unlink()


@pytest.fixture(scope="module")
def native(tmp_path_factory):
    assert shutil.which("unshare") and shutil.which("tofu") and shutil.which("rtk"), "offline_binaries_absent"
    candidates = sorted(Path("/tmp").glob("budget-inspect-*/.terraform/providers/registry.opentofu.org/hashicorp/aws/6.54.0/linux_amd64"))
    configured = os.environ.get("CNESDATA_TEST_AWS_PROVIDER_DIR")
    provider = Path(configured) if configured else (candidates[0] if candidates else None)
    assert provider and (provider / "terraform-provider-aws").is_file(), "cached_provider_absent"
    return NativeHarness(tmp_path_factory.mktemp("cnesdata-b1a"), provider.resolve())


def witness_config(root):
    """Condição sintética independente dos expected docs; DAG KMS ruling B1a."""
    core = root == "foundation"
    selected = "var.roots.foundation" if core else "var.backend"
    expr = lambda value: "${" + value + "}"
    doc = lambda statements: json.dumps({"Version": "2012-10-17", "Statement": statements})
    key = expr("aws_kms_key.foundation.arn") if core else expr("var.kms_key_arn")
    state_bucket = expr(selected + ".backend.bucket")
    log_bucket = expr(selected + ".logging.bucket")
    prefix = expr(selected + ".logging.prefix")
    state_arn = f"arn:aws:s3:::{state_bucket}"
    sink_arn = f"arn:aws:s3:::{log_bucket}"
    tags = expr("merge(var.tags, { Owner = " + selected + ".owner })")
    res = {}

    def add(kind, label, **values):
        res.setdefault(kind, {})[label] = values

    for name, bucket in (("state", state_bucket), ("logging", log_bucket)):
        add("aws_s3_bucket", name, bucket=bucket, force_destroy=False, object_lock_enabled=False,
            tags=tags, lifecycle={"prevent_destroy": True})
        add("aws_s3_bucket_public_access_block", name, bucket=expr(f"aws_s3_bucket.{name}.id"),
            block_public_acls=True, block_public_policy=True, ignore_public_acls=True, restrict_public_buckets=True)
        if core or name == "logging":
            add("aws_s3_bucket_ownership_controls", name, bucket=expr(f"aws_s3_bucket.{name}.id"),
                rule=[{"object_ownership": "BucketOwnerEnforced"}])
        encryption = {"sse_algorithm": "aws:kms", "kms_master_key_id": key} if name == "state" else {"sse_algorithm": "AES256"}
        rule = {"apply_server_side_encryption_by_default": [encryption]}
        if name == "state":
            rule["bucket_key_enabled"] = True
        add("aws_s3_bucket_server_side_encryption_configuration", name,
            bucket=expr(f"aws_s3_bucket.{name}.id"), rule=[rule])
        tls = {"Effect": "Deny", "Action": "s3:*", "Principal": "*",
               "Resource": [state_arn, state_arn + "/*"] if name == "state" else [sink_arn, sink_arn + "/*"],
               "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
        statements = [tls]
        if name == "logging":
            statements.append({"Effect": "Allow", "Action": "s3:PutObject",
                "Principal": {"Service": "logging.s3.amazonaws.com"}, "Resource": sink_arn + "/" + prefix + "*",
                "Condition": {"StringEquals": {"aws:SourceAccount": expr("var.account_id")},
                              "ArnLike": {"aws:SourceArn": state_arn}}})
        add("aws_s3_bucket_policy", name, bucket=expr(f"aws_s3_bucket.{name}.id"), policy=doc(statements))
    add("aws_s3_bucket_versioning", "state", bucket=expr("aws_s3_bucket.state.id"),
        versioning_configuration=[{"status": "Enabled"}])
    add("aws_s3_bucket_logging", "state", bucket=expr("aws_s3_bucket.state.id"),
        target_bucket=expr("aws_s3_bucket.logging.id"), target_prefix=prefix)
    add("aws_s3_bucket_lifecycle_configuration", "logging", bucket=expr("aws_s3_bucket.logging.id"),
        rule=[{"id": "retain-30-days", "status": "Enabled", "filter": [{"prefix": prefix}],
               "expiration": [{"days": 30}]}])
    if core:
        reader = expr("aws_iam_role.bootstrap_readback.arn")
        writer = expr("aws_iam_role.bootstrap_executor.arn")
        key_policy = [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::${var.account_id}:root"}, "Action": "kms:*", "Resource": "*"},
        ]
        add("aws_kms_key", "foundation", description="synthetic B1a witness only", key_usage="ENCRYPT_DECRYPT",
            customer_master_key_spec="SYMMETRIC_DEFAULT", is_enabled=True, enable_key_rotation=True,
            multi_region=False, deletion_window_in_days=30, bypass_policy_lockout_safety_check=False,
            tags=tags, policy=doc(key_policy), lifecycle={"prevent_destroy": True})
        buckets, logs, objects, locks = [], [], [], []
        for root_name in ("foundation", "budget-backend"):
            base = f"var.roots.{root_name}"
            bucket = f"arn:aws:s3:::${{{base}.backend.bucket}}"
            obj = bucket + f"/${{{base}.backend.key}}"
            buckets.append(bucket)
            logs.append(f"arn:aws:s3:::${{{base}.logging.bucket}}")
            objects.append(obj)
            locks.append(obj + ".tflock")
        executor = [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"], "Resource": objects + locks},
            {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": locks},
            {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": buckets},
            {"Effect": "Allow", "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"], "Resource": key},
        ]
        readback = [
            {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetBucketLogging", "s3:GetEncryptionConfiguration", "s3:GetBucketPolicy", "s3:GetBucketOwnershipControls", "s3:GetBucketPublicAccessBlock", "s3:GetBucketTagging"], "Resource": buckets + logs},
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": buckets},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"], "Resource": objects + locks},
            {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key},
            {"Effect": "Allow", "Action": ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListResourceTags"], "Resource": key},
        ]
        add("aws_iam_user", "bootstrap_operator", name=expr("var.identities.operator.name"),
            path=expr("var.identities.operator.path"), force_destroy=False, tags=tags)
        add("aws_iam_policy", "executor_boundary", name=expr("var.identities.boundary.name"),
            path=expr("var.identities.boundary.path"), policy=doc(executor), tags=tags)
        for short in ("readback", "executor"):
            trust = doc([{"Effect": "Allow", "Action": "sts:AssumeRole",
                          "Principal": {"AWS": expr("aws_iam_user.bootstrap_operator.arn")},
                          "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}])
            attrs = {"name": expr(f"var.identities.{short}.name"), "path": expr(f"var.identities.{short}.path"),
                     "max_session_duration": 3600, "assume_role_policy": trust, "tags": tags}
            if short == "executor":
                attrs["permissions_boundary"] = expr("aws_iam_policy.executor_boundary.arn")
            add("aws_iam_role", f"bootstrap_{short}", **attrs)
            add("aws_iam_role_policy", f"bootstrap_{short}", name=f"synthetic-{short}",
                role=expr(f"aws_iam_role.bootstrap_{short}.name"), policy=doc(executor if short == "executor" else readback))
        add("aws_iam_user_policy_attachment", "local_login", user=expr("aws_iam_user.bootstrap_operator.name"),
            policy_arn="arn:aws:iam::aws:policy/SignInLocalDevelopmentAccess")
        add("aws_iam_user_policy", "local_assume", name="synthetic-local-assume", user=expr("aws_iam_user.bootstrap_operator.name"),
            policy=doc([{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": [reader, writer],
                         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]))
    output = {"contract_version": 1, "account_id": expr("var.account_id"), "region": expr("var.region"),
              "kms_key_arn": key, "ready_for_product": False, "ready_for_budget_sns": False,
              "backends": {root: {"bucket": expr("aws_s3_bucket.state.bucket"),
                  "key": expr(selected + ".backend.key"), "region": expr("var.region"),
                  "use_lockfile": True, "encrypt": True, "kms_key_id": key,
                  "owner": expr(selected + ".owner")}}}
    return {"terraform": {"required_version": "=1.13.2", "required_providers": {
                "aws": {"source": "hashicorp/aws", "version": "=6.54.0"}}},
            "provider": {"aws": {"region": expr("var.region"), "allowed_account_ids": [expr("var.account_id")]}},
            "variable": {k: {"type": "any"} for k in ("account_id", "region", "roots", "identities", "tags", "backend", "kms_key_arn")},
            "resource": res, "output": {"bootstrap_foundation" if core else "bootstrap_backend": {"value": output}}}


MUTATIONS = (
    "executor_boundary_deny_all", "executor_policy_deny_all", "readback_policy_deny_all",
    "executor_conditions_wrong_account", "readback_action_resource_crosswired",
    "kms_condition_prevents_recovery", "state_bucket_policy_deny_all", "logging_deny_delivery",
    "executor_boundary_points_elsewhere", "executor_inline_policy_attached_to_readback",
    "assume_policy_attached_to_other_user", "bucket_controls_attach_to_foreign_bucket",
    "state_bucket_policy_allows_delete_state", "readback_role_name_does_not_match_mock_arn",
    "logging_lifecycle_expires_state", "logging_lifecycle_wrong_prefix_and_glacier",
    "logging_owner_foreign_and_object_lock",
)
CONTROLS = ("control_trust_missing_mfa", "control_kms_rotation_disabled",
            "control_executor_deletes_state", "control_logging_sourceaccount_absent")


def mutate(config, name):
    r = config["resource"]
    def policy(kind, label, change):
        doc = json.loads(r[kind][label]["policy"])
        change(doc["Statement"])
        r[kind][label]["policy"] = json.dumps(doc)
    deny = {"Effect": "Deny", "Action": "*", "Resource": "*"}
    if name in {"executor_boundary_deny_all", "executor_policy_deny_all", "readback_policy_deny_all"}:
        kind, label = {"executor_boundary_deny_all": ("aws_iam_policy", "executor_boundary"),
                       "executor_policy_deny_all": ("aws_iam_role_policy", "bootstrap_executor"),
                       "readback_policy_deny_all": ("aws_iam_role_policy", "bootstrap_readback")}[name]
        policy(kind, label, lambda s: s.append(copy.deepcopy(deny)))
    elif name == "executor_conditions_wrong_account":
        for kind, label in (("aws_iam_policy", "executor_boundary"), ("aws_iam_role_policy", "bootstrap_executor")):
            policy(kind, label, lambda s: [x.update(Condition={"StringEquals": {"aws:PrincipalAccount": "999999999999"}}) for x in s])
    elif name == "readback_action_resource_crosswired":
        policy("aws_iam_role_policy", "bootstrap_readback", lambda s: s[0].update(Resource="${aws_kms_key.foundation.arn}"))
    elif name == "kms_condition_prevents_recovery":
        policy("aws_kms_key", "foundation", lambda s: [x.update(Condition={"StringEquals": {"aws:PrincipalAccount": "999999999999"}}) for x in s])
    elif name in {"state_bucket_policy_deny_all", "logging_deny_delivery"}:
        label = "state" if name.startswith("state") else "logging"
        policy("aws_s3_bucket_policy", label, lambda s: s.append(copy.deepcopy(deny) | {"Principal": "*"}))
    elif name == "executor_boundary_points_elsewhere":
        r["aws_iam_role"]["bootstrap_executor"]["permissions_boundary"] = "arn:aws:iam::${var.account_id}:policy/unreviewed"
    elif name == "executor_inline_policy_attached_to_readback":
        r["aws_iam_role_policy"]["bootstrap_executor"]["role"] = "${aws_iam_role.bootstrap_readback.name}"
    elif name == "assume_policy_attached_to_other_user":
        r["aws_iam_user_policy"]["local_assume"]["user"] = "foreign-user"
    elif name == "bucket_controls_attach_to_foreign_bucket":
        for kind, values in r.items():
            if kind.startswith("aws_s3_bucket_"):
                for attrs in values.values():
                    attrs["bucket"] = "example-foreign-bucket"
    elif name == "state_bucket_policy_allows_delete_state":
        policy("aws_s3_bucket_policy", "state", lambda s: s.append({"Effect": "Allow",
            "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::${var.roots.foundation.backend.bucket}/*",
            "Principal": {"AWS": "arn:aws:iam::${var.account_id}:role${var.identities.executor.path}${var.identities.executor.name}"}}))
    elif name == "readback_role_name_does_not_match_mock_arn":
        r["aws_iam_role"]["bootstrap_readback"]["name"] = "foreign-reader-name"
    elif name == "logging_lifecycle_expires_state":
        r["aws_s3_bucket_lifecycle_configuration"]["logging"]["bucket"] = "${aws_s3_bucket.state.id}"
    elif name == "logging_lifecycle_wrong_prefix_and_glacier":
        rule = r["aws_s3_bucket_lifecycle_configuration"]["logging"]["rule"][0]
        rule["filter"] = [{"prefix": "foreign/"}]
        rule["transition"] = [{"days": 1, "storage_class": "GLACIER"}]
    elif name == "logging_owner_foreign_and_object_lock":
        r["aws_s3_bucket"]["logging"].update(tags={"Owner": "foreign-owner"}, object_lock_enabled=True)
    elif name == "control_trust_missing_mfa":
        for attrs in r["aws_iam_role"].values():
            trust = json.loads(attrs["assume_role_policy"])
            trust["Statement"][0].pop("Condition")
            attrs["assume_role_policy"] = json.dumps(trust)
    elif name == "control_kms_rotation_disabled":
        r["aws_kms_key"]["foundation"]["enable_key_rotation"] = False
    elif name == "control_executor_deletes_state":
        policy("aws_iam_role_policy", "bootstrap_executor", lambda s: s[1].update(Resource=s[0]["Resource"]))
    elif name == "control_logging_sourceaccount_absent":
        policy("aws_s3_bucket_policy", "logging", lambda s: s[1]["Condition"].pop("StringEquals"))
    elif name == "logging_glacier_only":
        r["aws_s3_bucket_lifecycle_configuration"]["logging"]["rule"][0]["transition"] = [{"days": 1, "storage_class": "GLACIER"}]
    elif name == "logging_owner_only":
        r["aws_s3_bucket"]["logging"]["tags"] = {"Owner": "foreign-owner"}
    elif name == "logging_object_lock_only":
        r["aws_s3_bucket"]["logging"]["object_lock_enabled"] = True
    elif name == "logging_sourcearn_absent":
        policy("aws_s3_bucket_policy", "logging", lambda s: s[1]["Condition"].pop("ArnLike"))
    elif name == "logging_wildcard_resource":
        policy("aws_s3_bucket_policy", "logging", lambda s: s[1].update(Resource="*"))
    elif name == "logging_sse_kms":
        r["aws_s3_bucket_server_side_encryption_configuration"]["logging"]["rule"][0]["apply_server_side_encryption_by_default"][0]["sse_algorithm"] = "aws:kms"
    elif name == "logging_cycle_to_source":
        r["aws_s3_bucket_logging"]["state"]["target_bucket"] = "${aws_s3_bucket.state.id}"
    elif name == "logging_wrong_source":
        r["aws_s3_bucket_logging"]["state"]["bucket"] = "${aws_s3_bucket.logging.id}"
    elif name == "logging_removed":
        r.pop("aws_s3_bucket_logging")
    elif name == "logging_expiration_31":
        r["aws_s3_bucket_lifecycle_configuration"]["logging"]["rule"][0]["expiration"] = [{"days": 31}]
    elif name == "logging_prefix_only":
        r["aws_s3_bucket_logging"]["state"]["target_prefix"] = "foreign/"
    elif name == "login_attached_other_user":
        r["aws_iam_user_policy_attachment"]["local_login"]["user"] = "foreign-user"
    else:
        raise AssertionError(f"unknown mutation: {name}")
