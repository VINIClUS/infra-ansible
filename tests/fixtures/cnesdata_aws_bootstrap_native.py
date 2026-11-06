"""B1a: parâmetros literais, OpenTofu offline e witness exclusivamente sintético.
Não importa planner, checkpoint, executor ou inventário. O witness valida o
harness; não é configuração de produção nem prova de apply/ordenação AWS.
"""

import copy
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import cast
import pytest
from fixtures.cnesdata_aws_bootstrap_mutations import mutate
from fixtures.cnesdata_aws_bootstrap_witness import (
    _add,
    _bucket_resources,
    _destroy_plan,
    _document,
    _expr,
    _foundation_identity_resources,
    _variables,
    _write_mock_file,
    observation,
)

__all__ = ["observation"]
REPO = Path(__file__).resolve().parents[2]
FOUNDATION = (
    "aws_iam_user.bootstrap_operator",
    "aws_iam_user_policy_attachment.local_login",
    "aws_iam_user_policy.local_assume",
    "aws_iam_policy.executor_boundary",
    "aws_iam_role.bootstrap_readback",
    "aws_iam_role.bootstrap_executor",
    "aws_iam_role_policy.bootstrap_readback",
    "aws_iam_role_policy.bootstrap_executor",
    "aws_kms_key.foundation",
    "aws_s3_bucket.state",
    "aws_s3_bucket_versioning.state",
    "aws_s3_bucket_public_access_block.state",
    "aws_s3_bucket_server_side_encryption_configuration.state",
    "aws_s3_bucket_ownership_controls.state",
    "aws_s3_bucket_policy.state",
    "aws_s3_bucket.logging",
    "aws_s3_bucket_ownership_controls.logging",
    "aws_s3_bucket_public_access_block.logging",
    "aws_s3_bucket_server_side_encryption_configuration.logging",
    "aws_s3_bucket_policy.logging",
    "aws_s3_bucket_lifecycle_configuration.logging",
    "aws_s3_bucket_logging.state",
)
BUDGET = tuple(
    a
    for a in FOUNDATION
    if not a.startswith(("aws_iam_", "aws_kms_")) and a != "aws_s3_bucket_ownership_controls.state"
)
assert len(FOUNDATION) == 22 and len(BUDGET) == 12

# ARNs são literais independentes da construção HCL do witness. Names/path são
# inputs nativos. O oráculo ainda deve conferir os nomes reais antes dos mocks.
CASES = {
    "a": {
        "account_id": "836651842853",
        "region": "us-east-2",
        "roots": {
            "foundation": {
                "owner": "infra-ansible:cnesdata",
                "backend": {
                    "bucket": "example-a-foundation-state",
                    "key": "bootstrap/foundation.tfstate",
                },
                "logging": {
                    "bucket": "example-a-foundation-logs",
                    "prefix": "access/example-a-foundation-state/",
                },
            },
            "budget-backend": {
                "owner": "personal-infra-live:cnesdata",
                "backend": {
                    "bucket": "example-a-budget-state",
                    "key": "bootstrap/backend.tfstate",
                },
                "logging": {
                    "bucket": "example-a-budget-logs",
                    "prefix": "access/example-a-budget-state/",
                },
            },
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
        "account_id": "836651842853",
        "region": "us-east-2",
        "roots": {
            "foundation": {
                "owner": "infra-ansible:cnesdata",
                "backend": {
                    "bucket": "example-b-state-local-bootstrap",
                    "key": "bootstrap/foundation-b.tfstate",
                },
                "logging": {
                    "bucket": "example-b-local-access-logs",
                    "prefix": "access/example-b-state-local-bootstrap/",
                },
            },
            "budget-backend": {
                "owner": "personal-infra-live:cnesdata",
                "backend": {
                    "bucket": "example-b-state-budget-only",
                    "key": "bootstrap/backend-b.tfstate",
                },
                "logging": {
                    "bucket": "example-b-budget-access-logs",
                    "prefix": "access/example-b-state-budget-only/",
                },
            },
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

def _case_for(case_id):
    mutations = {
        "foundation-source-sink": "foundation",
        "foundation-foreign-prefix": "foundation",
        "budget-source-sink": "budget-backend",
        "budget-foreign-prefix": "budget-backend",
    }
    base_id = "a" if case_id == "foreign" or case_id in mutations else case_id
    case = copy.deepcopy(CASES[base_id])
    if case_id == "foreign":
        case["account_id"] = "111111111111"
        case["expected"]["cmk"] = (
            "arn:aws:kms:us-east-2:111111111111:key/00000000-0000-4000-8000-000000000001"
        )
    if case_id in mutations:
        root = mutations[case_id]
        if case_id.endswith("source-sink"):
            case["roots"][root]["logging"]["bucket"] = case["roots"][root]["backend"]["bucket"]
        else:
            case["roots"][root]["logging"]["prefix"] = "access/foreign-source/"
    return case
def _root_mode(root):
    exact = root.endswith("-inputs-only")
    return root.removesuffix("-inputs-only"), exact
def _input_values(case, root, exact):
    names = ("account_id", "region", "roots", "identities", "tags")
    values = {name: case[name] for name in names}
    if not exact:
        values.update(backend=case["roots"][root], kms_key_arn=case["expected"]["cmk"])
    return values
def _input_diagnostics(errors):
    summaries = {item.get("summary") for item in errors}
    return summaries <= {"Invalid value for variable", "Missing required argument",
                          "No value for required variable"}
def _policy_values(value, label):
    values = value if isinstance(value, list) else [value]
    assert all(isinstance(item, str) for item in values), f"policy_scalar_type: {label}"
    assert len(values) == len(set(values)), f"policy_duplicate_value: {label}"
    return sorted(values)
def _condition_value(operator, value):
    if operator != "Bool":
        return value
    values = value if isinstance(value, list) else [value]
    assert all(item in (True, False, "true", "false") for item in values)
    return [str(item).lower() for item in values]
def _condition_operator(operator, values):
    if operator == "ArnLike" and all(
        not any(char in value for char in "*?")
        for values_list in values.values()
        for value in values_list
    ):
        return "ArnEquals"
    return operator
def _policy_condition(conditions, label):
    normalized = {}
    for operator, pairs in conditions.items():
        assert isinstance(pairs, dict) and pairs
        values = {key: _policy_values(_condition_value(operator, value), label)
                  for key, value in pairs.items()}
        operator = _condition_operator(operator, values)
        assert operator not in normalized, f"policy_duplicate_operator: {label}"
        normalized[operator] = values
    return normalized
def _policy_principal(principal, label):
    if isinstance(principal, dict):
        principal = {key: _policy_values(value, label) for key, value in principal.items()}
        return "*" if principal == {"AWS": ["*"]} else principal
    assert principal == "*", f"policy_principal_type: {label}"
    return principal
def _policy_statement(statement, label):
    assert set(statement) <= {
        "Sid",
        "Effect",
        "Action",
        "Resource",
        "Principal",
        "Condition",
    }, label
    statement = copy.deepcopy(statement)
    statement.pop("Sid", None)
    assert statement["Effect"] in {"Allow", "Deny"}
    statement["Action"] = _policy_values(statement["Action"], label)
    for field in ("Resource", "Principal"):
        if field in statement:
            statement[field] = (
                _policy_principal(statement[field], label)
                if field == "Principal"
                else _policy_values(statement[field], label)
            )
    if "Condition" in statement:
        statement["Condition"] = _policy_condition(statement["Condition"], label)
    return json.dumps(statement, sort_keys=True, separators=(",", ":"))
def _normalized_policy(value, label):
    value = json.loads(value) if isinstance(value, str) else copy.deepcopy(value)
    assert set(value) == {"Version", "Statement"}, f"policy_envelope: {label}"
    assert value["Version"] == "2012-10-17"
    assert isinstance(value["Statement"], list) and value["Statement"]
    statements = [_policy_statement(statement, label) for statement in value["Statement"]]
    assert len(statements) == len(set(statements)), f"policy_duplicate_statement: {label}"
    return sorted(statements)
def assert_policy(actual, expected, label):
    """Normalização sintática fechada, não avaliação de permissões IAM."""
    assert _normalized_policy(actual, label) == _normalized_policy(expected, label), (
        f"policy_document_mismatch: {label}"
    )
def _foundation_witness(resources, key):
    _add(
        resources,
        "aws_kms_key",
        "foundation",
        description="synthetic B1a witness only",
        key_usage="ENCRYPT_DECRYPT",
        customer_master_key_spec="SYMMETRIC_DEFAULT",
        is_enabled=True,
        enable_key_rotation=True,
        multi_region=False,
        deletion_window_in_days=30,
        bypass_policy_lockout_safety_check=False,
        tags=_expr("merge(var.tags, { Owner = var.roots.foundation.owner })"),
        policy=_document(
            [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::${var.account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        ),
        lifecycle={"prevent_destroy": True},
    )
    _foundation_identity_resources(resources, key)
def _witness_document(root, selected, key, resources):
    output_root = "bootstrap_foundation" if root == "foundation" else "bootstrap_backend"
    output = {
        "contract_version": 1,
        "account_id": _expr("var.account_id"),
        "region": _expr("var.region"),
        "kms_key_arn": key,
        "ready_for_product": False,
        "ready_for_budget_sns": False,
        "backends": {
            root: {
                "bucket": _expr("aws_s3_bucket.state.bucket"),
                "key": _expr(selected + ".backend.key"),
                "region": _expr("var.region"),
                "use_lockfile": True,
                "encrypt": True,
                "kms_key_id": key,
                "owner": _expr(selected + ".owner"),
            }
        },
    }
    return {
        "terraform": {
            "required_version": "=1.13.2",
            "required_providers": {"aws": {"source": "hashicorp/aws", "version": "=6.54.0"}},
        },
        "provider": {
            "aws": {
                "region": _expr("var.region"),
                "allowed_account_ids": [_expr("var.account_id")],
            }
        },
        "variable": _variables(),
        "resource": resources,
        "output": {output_root: {"value": output}},
    }
def witness_config(root, exact=False):
    """Monta um plano sintético independente do HCL de produção."""
    core = root == "foundation"
    selected = "var.roots.foundation" if core else "var.backend"
    key = _expr("aws_kms_key.foundation.arn") if core else _expr("var.kms_key_arn")
    resources = {}
    _bucket_resources(resources, core, selected, key)
    if core:
        _foundation_witness(resources, key)
    document = _witness_document(root, selected, key, resources)
    document["variable"] = _variables(exact)
    return document
class NativeHarness:
    def __init__(self, base, provider_dir):
        self.base = base
        self.cache = {}
        self.failures = {}
        self.commands = []
        mirror = base / "mirror/registry.opentofu.org/hashicorp/aws/6.54.0"
        mirror.mkdir(parents=True)
        (mirror / "linux_amd64").symlink_to(provider_dir)
        self.cli_config = base / "tofu.rc"
        provider_block = ('provider_installation {\n filesystem_mirror {\n path = '
                          + json.dumps(str(base / "mirror"))
                          + '\n include = ["registry.opentofu.org/hashicorp/aws"]\n }\n}\n')
        self.cli_config.write_text(provider_block)
        self.home = base / "home"
        self.home.mkdir(mode=0o700)
        self.env = {
            "PATH": os.defpath,
            "HOME": str(self.home),
            "TMPDIR": str(base),
            "LANG": "C.UTF-8",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_CONFIG_FILE": "/dev/null",
            "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
            "TF_IN_AUTOMATION": "1",
            "CHECKPOINT_DISABLE": "1",
            "TF_CLI_CONFIG_FILE": str(self.cli_config),
        }
        version = self.run(base, ["version", "-json"])
        assert version.returncode == 0, f"offline_harness_version: {version.stderr}"
        assert json.loads(version.stdout)["terraform_version"] == "1.13.2"
        self.prepared = base / "prepared"
        self.prepared.mkdir()
        required = {"terraform": {"required_providers": {
            "aws": {"source": "hashicorp/aws", "version": "=6.54.0"}}}}
        (self.prepared / "versions.tf.json").write_text(json.dumps(required))
        lock = next((p / ".terraform.lock.hcl" for p in provider_dir.parents
                     if (p / ".terraform.lock.hcl").is_file()), None)
        assert lock, "offline_harness_absent: cached checksum lock"
        shutil.copy2(lock, self.prepared / ".terraform.lock.hcl")
        init = self.run(self.prepared, ["init", "-backend=false", "-input=false",
                                        "-lockfile=readonly"])
        assert init.returncode == 0, f"offline_harness_init: {init.stdout}\n{init.stderr}"
    def run(self, folder, args):
        assert args[0] in {"version", "init", "test", "providers", "plan"}
        assert not any(x in {"apply", "import", "-force-copy", "-reconfigure"} for x in args)
        self.commands.append({"cwd": str(folder), "args": args})
        result = subprocess.run(
            [
                cast(str, shutil.which("rtk")),
                "proxy",
                cast(str, shutil.which("unshare")),
                "--user",
                "--map-root-user",
                "--net",
                cast(str, shutil.which("tofu")),
                *args,
            ],
            cwd=folder,
            env=self.env,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        (self.base / "commands.json").write_text(
            json.dumps({"commands": self.commands, "environment": self.env}, indent=2)
        )
        (folder / (args[0] + "-stderr.txt")).write_text(result.stderr)
        (folder / (args[0] + "-stdout.txt")).write_text(result.stdout)
        return result
    def plan(self, case_id="a", root="foundation", source="target"):
        return self._plan((case_id, root, source, None))
    def mutated_witness_plan(self, mutation, root="foundation", case_id="a"):
        return self._plan((case_id, root, "witness", mutation))
    def _plan(self, key):
        case_id, requested_root, source, mutation = key
        root, exact = _root_mode(requested_root)
        if key in self.failures:
            raise AssertionError(self.failures[key])
        if key in self.cache:
            return self.cache[key]
        case = _case_for(case_id)
        work = self.base / ("-".join(x or "none" for x in key))
        work.mkdir()
        inputs = _input_values(case, root, exact)
        if source == "witness":
            config = witness_config(root, exact)
            if mutation:
                mutate(config, mutation)
            (work / "synthetic.tf.json").write_text(json.dumps(config, indent=2))
        else:
            self._copy_source(work, root, inputs)
        self._copy_provider(work)
        (work / "inputs.tfvars.json").write_text(json.dumps(inputs))
        context = (case, root, source)
        _write_mock_file(work, case, root, source)
        result = self._read_plan(work, context, key)
        result["inputs"] = inputs
        self.cache[key] = result
        return result
    def _copy_source(self, work, root, inputs):
        origin = (
            REPO / "opentofu/cnesdata-bootstrap/foundation"
            if root == "foundation"
            else Path("/home/vinicius/code/personal-infra-live/bootstrap")
        )
        files = [*origin.glob("*.tf"), *origin.glob("*.tf.json")]
        for file in files:
            assert not file.is_symlink(), "native_source_symlink"
            shutil.copy2(file, work / file.name)
        if not files:
            config = {
                "terraform": {
                    "required_providers": {"aws": {"source": "hashicorp/aws", "version": "=6.54.0"}}
                },
                "variable": {key: {"type": "any"} for key in inputs},
            }
            (work / "empty.tf.json").write_text(json.dumps(config))
    def _copy_provider(self, work):
        shutil.copytree(self.prepared / ".terraform", work / ".terraform", symlinks=True)
        shutil.copy2(self.prepared / ".terraform.lock.hcl", work / ".terraform.lock.hcl")
    def _read_plan(self, work, context, key):
        case, root, source = context
        result = self.run(work, ["test", "-json", "-verbose", "-var-file=inputs.tfvars.json"])
        events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        (work / "native-events.jsonl").write_text(result.stdout)
        errors = [
            event.get("diagnostic", {})
            for event in events
            if event.get("diagnostic", {}).get("severity") == "error"
        ]
        if source == "target" and errors and _input_diagnostics(errors):
            message = "; ".join(item.get("detail", "") for item in errors)
            self.failures[key] = "target_input_contract_incompatible: " + message
            raise AssertionError(self.failures[key])
        assert result.returncode == 0, (
            f"native_plan_error: {[(x['summary'], x['detail']) for x in errors]}\n{result.stderr}"
        )
        plans = [event["test_plan"] for event in events if "test_plan" in event]
        assert len(plans) == 1, "native_plan_missing"
        (work / "native-plan.json").write_text(json.dumps(plans[0], indent=2, sort_keys=True))
        return {
            "plan": plans[0],
            "case": case,
            "root": root,
            "work": work,
            "source": source,
        }
    def prove_prevent_destroy(self, native, address):
        result = _destroy_plan(self, native, address)
        assert result.returncode != 0, f"prevent_destroy_absent: {address}"
        assert "instance cannot be destroyed" in result.stderr.lower(), (
            f"lifecycle_not_proved: {result.stderr}"
        )
        assert "prevent_destroy" in result.stderr
@pytest.fixture(scope="module")
def native(tmp_path_factory):
    assert shutil.which("unshare") and shutil.which("tofu") and shutil.which("rtk"), (
        "offline_binaries_absent"
    )
    candidates = sorted(
        Path("/tmp").glob(
            "budget-inspect-*/.terraform/providers/registry.opentofu.org/hashicorp/aws/"
            "6.54.0/linux_amd64"
        )
    )
    configured = os.environ.get("CNESDATA_TEST_AWS_PROVIDER_DIR")
    provider = Path(configured) if configured else (candidates[0] if candidates else None)
    assert provider and (provider / "terraform-provider-aws").is_file(), "cached_provider_absent"
    return NativeHarness(tmp_path_factory.mktemp("cnesdata-b1a"), provider.resolve())
