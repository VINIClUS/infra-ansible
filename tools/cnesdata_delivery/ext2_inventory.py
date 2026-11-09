"""Read-only delivery-root inventory. No product policy resolver, apply or credentials.

Governance is an operator-authenticated checkpoint, never caller JSON. Source hashes
authenticate bytes; HCL evaluation independently derives the complete EXT2 documents.
Observations must come from this process's SDK observer, including every prior resource.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, cast

from tools.cnesdata_delivery import evidence as e
from tools.cnesdata_delivery import ext2_transport as t
from tools.cnesdata_delivery.iam_expression import (
    Budget,
    Evaluator,
    attributes,
    parse,
    reference_sets,
    source_blocks,
)

ROOT = "opentofu/cnesdata-delivery"
STATE = "shared/cnesdata-delivery/prod/opentofu.tfstate"
BASE = "99fc0e4805b96fbca7df06440d5ea3ad42e53369"
FOUR = {
    "aws_iam_role.ext2_gate[0]": "signing.tf",
    "aws_iam_role_policy.ext2_gate[0]": "evidence.tf",
    "aws_kms_key.ext2_signing[0]": "signing.tf",
    "aws_kms_alias.ext2_signing[0]": "signing.tf",
}
FILES = {
    "roles-anywhere.tf",
    "oidc.tf",
    "session-policies.tf",
    "variables.tf",
    "outputs.tf",
    "providers.tf",
    "versions.tf",
    "backend.tf",
    ".terraform.lock.hcl",
}
PRIOR = {
    "aws_iam_role.api",
    "aws_rolesanywhere_trust_anchor.ca",
    "aws_rolesanywhere_profile.api",
}
ROLE = "cnesdata-delivery-ext2-gate"
_SEAL = object()


class _SavedPlan(dict[str, Any]):
    def __init__(self, binary: bytes, decoded: dict[str, Any], tofu_sha256: str):
        super().__init__(binary=binary, json=decoded)
        self.seal, self.tofu_sha256 = _SEAL, tofu_sha256
        self.binary_sha256, self.json_sha256 = (
            e.sha(binary),
            e.sha(t.canonical(decoded)),
        )


def read_saved_plan(
    binary: bytes, *, directory: Path, tofu: Path, tofu_sha256: str
) -> _SavedPlan:
    """Decode the exact saved binary using a pinned tool in a network namespace.

    `directory` is the operator's already initialized offline source closure. This
    function never initializes a backend, installs a provider, plans, or applies.
    """
    check(type(binary) is bytes and 0 < len(binary) <= 32 * 1024**2, "plan_binary")
    check(
        tofu.is_file() and e.sha(tofu.read_bytes()) == t.hex_digest(tofu_sha256),
        "tofu_pin",
    )
    rtk, unshare = shutil.which("rtk"), shutil.which("unshare")
    if rtk is None or unshare is None:
        raise ValueError("ext2=inventory_decoder_tools")
    check(directory.is_dir(), "decoder_directory")
    with tempfile.TemporaryDirectory(prefix="ext2-show-") as scratch:
        path = Path(scratch) / "reviewed.tfplan"
        path.write_bytes(binary)
        path.chmod(0o600)
        env = {
            "PATH": os.defpath,
            "HOME": scratch,
            "LANG": "C.UTF-8",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_CONFIG_FILE": "/dev/null",
            "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
            "CHECKPOINT_DISABLE": "1",
        }
        result = subprocess.run(
            [
                rtk,
                "proxy",
                unshare,
                "--user",
                "--map-root-user",
                "--net",
                str(tofu),
                "show",
                "-json",
                str(path),
            ],
            cwd=directory,
            env=env,
            capture_output=True,
            timeout=60,
            check=False,
        )
        check(
            result.returncode == 0 and len(result.stdout) <= 32 * 1024**2, "plan_decode"
        )
        decoded = document(result.stdout.decode("utf-8"), maximum=32 * 1024**2)
    check(type(decoded) is dict, "plan_json")
    return _SavedPlan(binary, decoded, tofu_sha256)


def check(condition: Any, code: str) -> None:
    e.require(condition, "inventory_" + code)


def document(value: Any, *, maximum: int = 32768) -> Any:
    if type(value) is str:
        check(0 < len(value.encode()) <= maximum, "document_size")

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result = {}
            for key, item in items:
                check(key not in result, "document_duplicate")
                result[key] = item
            return result

        return t.loads(
            t.canonical(json.loads(value, object_pairs_hook=pairs)), maximum=maximum
        )
    check(type(value) is dict, "document")
    return value


def closed(value: Any, required: set[str], optional: set[str]) -> dict[str, Any]:
    check(
        type(value) is dict and required <= set(value) <= required | optional, "fields"
    )
    return cast(dict[str, Any], value)


def state_resources(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    closed(
        state,
        {"version", "terraform_version", "serial", "lineage", "outputs", "resources"},
        {"check_results"},
    )
    check(
        state["version"] == 4 and state["terraform_version"] == "1.13.2", "state_format"
    )
    check(type(state["serial"]) is int and state["serial"] >= 0, "state_serial")
    check(
        type(state["resources"]) is list and len(state["resources"]) <= 32, "state_size"
    )
    result = {}
    for raw in state["resources"]:
        row = closed(raw, {"mode", "type", "name", "provider", "instances"}, {"module"})
        check(
            not row.get("module") and row["mode"] in {"managed", "data"}, "state_root"
        )
        check(
            row["provider"] == 'provider["registry.opentofu.org/hashicorp/aws"]',
            "state_provider",
        )
        if row["mode"] == "data":
            check(
                row["type"] + "." + row["name"]
                in {
                    "aws_caller_identity.current",
                    "aws_iam_openid_connect_provider.github",
                },
                "state_data",
            )
            continue
        check(
            type(row["instances"]) is list and 0 < len(row["instances"]) <= 2,
            "state_instances",
        )
        for raw_instance in row["instances"]:
            instance = closed(
                raw_instance,
                {"schema_version", "attributes"},
                {
                    "index_key",
                    "sensitive_attributes",
                    "private",
                    "dependencies",
                    "create_before_destroy",
                },
            )
            address = row["type"] + "." + row["name"]
            if "index_key" in instance:
                index = instance["index_key"]
                check(
                    index in (0, "plan", "deploy") and type(index) is not bool,
                    "state_index",
                )
                address += "[" + json.dumps(index) + "]"
            check(
                address not in result and type(instance["attributes"]) is dict,
                "state_duplicate",
            )
            result[address] = instance["attributes"]
    return result


def projection(address: str, r: dict[str, Any]) -> dict[str, Any]:
    kind = address.split(".", 1)[0]
    if kind == "aws_iam_role":
        check(
            not r.get("inline_policy") and not r.get("managed_policy_arns"),
            "embedded_policy",
        )
        return {
            "name": r["name"],
            "arn": r["arn"],
            "trust": document(r["assume_role_policy"]),
            "path": r.get("path") or "/",
            "duration": r["max_session_duration"],
            "boundary": r.get("permissions_boundary"),
        }
    if kind == "aws_iam_role_policy":
        return {"name": r["name"], "role": r["role"], "policy": document(r["policy"])}
    if kind == "aws_iam_policy":
        return {
            "name": r["name"],
            "arn": r["arn"],
            "policy": document(r["policy"]),
            "attachments": 0,
            "boundaries": 0,
        }
    if kind == "aws_rolesanywhere_trust_anchor":
        check(
            len(r["source"]) == 1 and len(r["source"][0]["source_data"]) == 1,
            "anchor_source",
        )
        return {
            "name": r["name"],
            "id": r["id"],
            "arn": r["arn"],
            "enabled": r["enabled"],
            "source": r["source"][0]["source_type"],
            "certificate": r["source"][0]["source_data"][0]["x509_certificate_data"],
        }
    if kind == "aws_rolesanywhere_profile":
        return {
            "name": r["name"],
            "id": r["id"],
            "arn": r["arn"],
            "enabled": r["enabled"],
            "duration": r["duration_seconds"],
            "roles": r["role_arns"],
            "accept_name": r["accept_role_session_name"],
            "managed": r.get("managed_policy_arns") or [],
            "session": r.get("session_policy"),
            "instances": bool(r.get("require_instance_properties")),
        }
    if kind == "aws_kms_key":
        return {
            "id": r["key_id"],
            "arn": r["arn"],
            "policy": document(r["policy"]),
            "usage": r["key_usage"],
            "spec": r["customer_master_key_spec"],
            "enabled": r["is_enabled"],
            "multi": r["multi_region"],
            "origin": "AWS_KMS",
            "state": "Enabled",
        }
    if kind == "aws_kms_alias":
        return {
            "name": r["name"],
            "target": r["target_key_id"],
            "arn": r["target_key_arn"],
        }
    raise ValueError("ext2=inventory_resource_type")


@dataclass(frozen=True)
class _Observations:
    values: dict[str, dict[str, Any]]
    seal: object


def observe_inventory(
    *, state: dict[str, Any], iam: Any, kms: Any, rolesanywhere: Any
) -> _Observations:
    """Perform only GET/List APIs through the governed operator's read-only SDK clients.

    List responses must be complete. No pagination fallback can omit an extra policy.
    SDK failures propagate closed; none is interpreted as resource absence.
    """
    resources = state_resources(state)
    result = {}
    for address, r in resources.items():
        kind = address.split(".", 1)[0]
        if kind == "aws_iam_role":
            role = iam.get_role(RoleName=r["name"])["Role"]
            inline = iam.list_role_policies(RoleName=r["name"], MaxItems=1000)
            attached = iam.list_attached_role_policies(
                RoleName=r["name"], MaxItems=1000
            )
            names = [
                v["name"]
                for a, v in resources.items()
                if a.startswith("aws_iam_role_policy.") and v["role"] == r["name"]
            ]
            check(
                inline.get("IsTruncated") is False
                and attached.get("IsTruncated") is False
                and sorted(inline["PolicyNames"]) == sorted(names)
                and not attached["AttachedPolicies"],
                "role_policy_set",
            )
            result[address] = {
                "name": role["RoleName"],
                "arn": role["Arn"],
                "trust": document(role["AssumeRolePolicyDocument"]),
                "path": role["Path"],
                "duration": role["MaxSessionDuration"],
                "boundary": role.get("PermissionsBoundary", {}).get(
                    "PermissionsBoundaryArn"
                ),
            }
        elif kind == "aws_iam_role_policy":
            value = iam.get_role_policy(RoleName=r["role"], PolicyName=r["name"])
            result[address] = {
                "name": value["PolicyName"],
                "role": value["RoleName"],
                "policy": document(value["PolicyDocument"]),
            }
        elif kind == "aws_iam_policy":
            value = iam.get_policy(PolicyArn=r["arn"])["Policy"]
            version = iam.get_policy_version(
                PolicyArn=r["arn"], VersionId=value["DefaultVersionId"]
            )["PolicyVersion"]
            check(
                version["IsDefaultVersion"] is True
                and version["VersionId"] == value["DefaultVersionId"],
                "policy_version",
            )
            result[address] = {
                "name": value["PolicyName"],
                "arn": value["Arn"],
                "policy": document(version["Document"]),
                "attachments": value["AttachmentCount"],
                "boundaries": value["PermissionsBoundaryUsageCount"],
            }
        elif kind == "aws_rolesanywhere_trust_anchor":
            value = rolesanywhere.get_trust_anchor(trustAnchorId=r["id"])["trustAnchor"]
            result[address] = {
                "name": value["name"],
                "id": value["trustAnchorId"],
                "arn": value["trustAnchorArn"],
                "enabled": value["enabled"],
                "source": value["source"]["sourceType"],
                "certificate": value["source"]["sourceData"]["x509CertificateData"],
            }
        elif kind == "aws_rolesanywhere_profile":
            value = rolesanywhere.get_profile(profileId=r["id"])["profile"]
            result[address] = {
                "name": value["name"],
                "id": value["profileId"],
                "arn": value["profileArn"],
                "enabled": value["enabled"],
                "duration": value["durationSeconds"],
                "roles": value["roleArns"],
                "accept_name": value["acceptRoleSessionName"],
                "managed": value.get("managedPolicyArns", []),
                "session": value.get("sessionPolicy"),
                "instances": value.get("requireInstanceProperties", False),
            }
        elif kind == "aws_kms_key":
            key = kms.describe_key(KeyId=r["arn"])["KeyMetadata"]
            policy = kms.get_key_policy(KeyId=r["arn"], PolicyName="default")["Policy"]
            public = kms.get_public_key(KeyId=r["arn"])
            check(
                key["AWSAccountId"] == r["arn"].split(":")[4]
                and public["KeyId"] == key["Arn"]
                and public["KeyUsage"] == key["KeyUsage"]
                and public["KeySpec"] == key["KeySpec"]
                and public["SigningAlgorithms"]
                == key["SigningAlgorithms"]
                == ["ECDSA_SHA_256"],
                "key_public_identity",
            )
            check(
                type(public["PublicKey"]) is bytes
                and 0 < len(public["PublicKey"]) <= 4096,
                "key_spki",
            )
            result[address] = {
                "id": key["KeyId"],
                "arn": key["Arn"],
                "policy": document(policy),
                "usage": key["KeyUsage"],
                "spec": key["KeySpec"],
                "enabled": key["Enabled"],
                "multi": key["MultiRegion"],
                "origin": key["Origin"],
                "state": key["KeyState"],
                "spki_sha256": e.sha(public["PublicKey"]),
            }
        elif kind == "aws_kms_alias":
            key = kms.describe_key(KeyId=r["name"])["KeyMetadata"]
            result[address] = {
                "name": r["name"],
                "target": key["KeyId"],
                "arn": key["Arn"],
            }
        else:
            raise ValueError("ext2=inventory_observer_type")
    return _Observations(result, _SEAL)


def _source_closure(blobs: Any, gov: dict[str, Any]) -> dict[str, bytes]:
    t.closed(blobs, {"base", "head"})
    for name, manifest, files in (
        ("base", "base_sources", FILES),
        ("head", "sources", FILES | {"signing.tf", "evidence.tf"}),
    ):
        sources = blobs[name]
        check(
            type(sources) is dict and set(sources) == {ROOT + "/" + f for f in files},
            "source_set",
        )
        check(set(gov[manifest]) == set(sources), "source_manifest")
        for path, raw in sources.items():
            check(
                type(raw) is bytes
                and 0 < len(raw) <= 262144
                and e.sha(raw) == t.hex_digest(gov[manifest][path]),
                "source_bytes",
            )
    for path, raw in blobs["base"].items():
        head = blobs["head"][path]
        check(
            head.startswith(raw)
            if path.endswith(("variables.tf", "outputs.tf"))
            else head == raw,
            "base_preserved",
        )

    def declarations(name: str) -> set[tuple[str, str]]:
        return {
            (kind, label)
            for path, raw in blobs[name].items()
            if path.endswith(".tf")
            for kind, label, _ in source_blocks(raw)
            if kind != "locals"
        }

    check(
        declarations("head") - declarations("base")
        == {
            ("variable", "ext2"),
            ("variable", "ext2_enabled"),
            ("output", "ext2"),
            *(("resource", address[:-3]) for address in FOUR),
        },
        "nominal_declarations",
    )
    return blobs["head"]


def _resolve_sources(
    sources: dict[str, bytes],
    inputs: dict[str, Any],
    state: dict[str, dict[str, Any]],
    plan: dict[str, Any],
) -> Any:
    blocks = {}
    for path, raw in sources.items():
        if path.endswith(".tf"):
            for kind, name, body in source_blocks(raw):
                if kind == "locals":
                    continue  # Existing locals are authenticated unchanged; EXT2 uses none.
                check((kind, name) not in blocks, "source_duplicate")
                blocks[kind, name] = (path, attributes(body))
    configured = plan["configuration"]["root_module"]
    check(not configured.get("module_calls"), "module")
    config = {
        r["address"]: r for r in configured["resources"] if r["mode"] == "managed"
    }
    source_resources = {name for kind, name in blocks if kind == "resource"}
    check(
        set(config) == source_resources
        and len(config) == sum(r["mode"] == "managed" for r in configured["resources"]),
        "configuration_set",
    )
    for name, value in plan["variables"].items():
        check(("variable", name) in blocks, "input_unknown")
        if name in inputs:
            check(
                t.canonical(value["value"]) == t.canonical(inputs[name]), "input_value"
            )
        else:
            attrs = blocks["variable", name][1]
            check("default" in attrs, "input_missing")
            default = Evaluator(lambda *_: None, Budget()).value(
                parse(attrs["default"], Budget())
            )
            check(t.canonical(value["value"]) == t.canonical(default), "input_default")
    check(set(inputs) <= set(plan["variables"]), "input_set")
    resolved_inputs = {k: v["value"] for k, v in plan["variables"].items()}

    def lookup(path: tuple[Any, ...], scope: dict[str, Any]) -> Any:
        if path[0] == "var":
            value = resolved_inputs[path[1]]
            tail = path[2:]
        else:
            check(
                len(path) == 4
                and path[2] == 0
                and path[0] + "." + path[1] + "[0]" in FOUR,
                "reference",
            )
            check(
                (path[0], path[3])
                in {
                    ("aws_iam_role", "id"),
                    ("aws_iam_role", "arn"),
                    ("aws_kms_key", "arn"),
                    ("aws_kms_key", "key_id"),
                    ("aws_kms_alias", "name"),
                },
                "producer",
            )
            value = state[path[0] + "." + path[1] + "[0]"][path[3]]
            tail = ()
        for field in tail:
            value = value[field]
        return value

    for address, file in FOUR.items():
        base = address[:-3]
        path, attrs = blocks["resource", base]
        check(
            path == ROOT + "/" + file and "count" in attrs and "for_each" not in attrs,
            "resource_source",
        )
        expressions = config[base]["expressions"]
        check(set(expressions) == set(attrs) - {"count"}, "expression_fields")
        for field, raw in attrs.items():
            node = parse(raw, Budget())
            required, allowed = reference_sets(node)
            expression = (
                config[base]["count_expression"]
                if field == "count"
                else expressions[field]
            )
            check(
                set(expression) <= {"references", "constant_value"}, "expression_shape"
            )
            refs = set(expression.get("references", []))
            check(required <= refs <= allowed, "expression_binding")
            if not required:
                check(
                    expression.get("constant_value")
                    == Evaluator(lookup, Budget()).value(node),
                    "constant_binding",
                )
            if field != "count" and address not in state:
                continue
            expected = Evaluator(lookup, Budget()).value(node)
            if field == "count":
                check(
                    expected == (1 if inputs.get("ext2_enabled", False) else 0), "count"
                )
            elif address in state:
                actual = state[address][field]
                if field in {"policy", "assume_role_policy"}:
                    actual, expected = document(actual), document(expected)
                check(t.canonical(actual) == t.canonical(expected), "source_" + field)
    output = blocks["output", "ext2"][1]
    check(
        set(output) == {"description", "sensitive", "value"}
        and Evaluator(lookup, Budget()).value(parse(output["sensitive"], Budget()))
        is True,
        "output_source",
    )
    node = parse(output["value"], Budget())
    required, allowed = reference_sets(node)
    expression = configured["outputs"]["ext2"]["expression"]
    refs = set(expression.get("references", []))
    check(required <= refs <= allowed, "output_expression")
    expected_output = Evaluator(lookup, Budget()).value(node)
    change = plan["output_changes"]["ext2"]
    check(
        change["after_sensitive"] is True
        and plan["planned_values"]["outputs"]["ext2"]["sensitive"] is True,
        "output_sensitive",
    )
    _known_plan(
        change["after"], change.get("after_unknown", {}), expected_output, "output.ext2"
    )
    planned = plan["planned_values"]["outputs"]["ext2"]
    if "value" in planned:
        _known_plan(
            planned["value"],
            change.get("after_unknown", {}),
            expected_output,
            "output.ext2",
        )
    else:
        check(bool(change.get("after_unknown")), "output_unknown")
    return expected_output


def _known_plan(
    after: Any, unknown: Any, actual: Any, address: str, path: tuple[Any, ...] = ()
) -> None:
    if unknown is False:
        unknown = {}
    if unknown is True:
        # Unknowns may arise only from these four producers. Documents themselves
        # still resolve completely from HCL and the exact observed post-state IDs.
        permitted = {
            "output.ext2": {"role_arn", "signing_key_arn"},
            "aws_iam_role.ext2_gate[0]": {
                "id",
                "arn",
                "create_date",
                "unique_id",
                "name_prefix",
            },
            "aws_iam_role_policy.ext2_gate[0]": {"id", "name_prefix", "policy", "role"},
            "aws_kms_key.ext2_signing[0]": {"id", "key_id", "arn", "policy", "region"},
            "aws_kms_alias.ext2_signing[0]": {
                "id",
                "arn",
                "target_key_arn",
                "region",
                "name_prefix",
                "target_key_id",
            },
        }
        check(
            after is None
            and len(path) == 1
            and path[0] in permitted.get(address, set()),
            "unknown",
        )
        return
    if type(after) is dict:
        check(
            type(actual) is dict
            and type(unknown) is dict
            and set(unknown) <= set(actual),
            "plan_object",
        )
        check(set(actual) == set(after) | set(unknown), "plan_fields")
        for key in actual:
            _known_plan(
                after.get(key),
                unknown.get(key, {}),
                actual[key],
                address,
                path + (key,),
            )
    elif type(after) is list:
        check(type(actual) is list and len(after) == len(actual), "plan_list")
        check(
            type(unknown) in {dict, list}
            and (not unknown or len(unknown) == len(after)),
            "unknown_list",
        )
        for i, value in enumerate(after):
            _known_plan(
                value, unknown[i] if unknown else {}, actual[i], address, path + (i,)
            )
    else:
        check(not unknown and t.canonical(after) == t.canonical(actual), "plan_value")


@dataclass(frozen=True)
class VerifiedInventory:
    ext2_count: int
    prior_count: int
    source_sha: str
    plan_sha256: str
    state_after_sha256: str


def verify_ext2_inventory(
    *,
    source_blobs: Any,
    saved_plan: dict[str, Any],
    generated_inputs: dict[str, Any],
    state_before: dict[str, Any],
    state_after: dict[str, Any],
    observations: Any,
    governance: dict[str, Any],
) -> VerifiedInventory:
    """Verify a frozen operator plan/state checkpoint; never authorizes or applies it."""
    g = t.closed(
        governance,
        {
            "root",
            "state_key",
            "base_sha",
            "source_sha",
            "base_sources",
            "sources",
            "plan_sha256",
            "plan_json_sha256",
            "inputs_sha256",
            "before_sha256",
            "after_sha256",
            "spki_sha256",
            "tofu_sha256",
        },
    )
    check(
        g["root"] == ROOT and g["state_key"] == STATE and g["base_sha"] == BASE, "root"
    )
    t.hex_digest(g["source_sha"], 40)
    check(
        isinstance(saved_plan, _SavedPlan)
        and saved_plan.seal is _SEAL
        and set(saved_plan) == {"binary", "json"}
        and saved_plan.tofu_sha256 == t.hex_digest(g["tofu_sha256"])
        and saved_plan.binary_sha256 == e.sha(saved_plan["binary"])
        and saved_plan.json_sha256 == e.sha(t.canonical(saved_plan["json"])),
        "decoded_plan",
    )
    check(
        type(saved_plan["binary"]) is bytes
        and 0 < len(saved_plan["binary"]) <= 32 * 1024**2,
        "plan_binary",
    )
    plan = saved_plan["json"]
    closed(
        plan,
        {
            "format_version",
            "terraform_version",
            "variables",
            "planned_values",
            "resource_changes",
            "output_changes",
            "configuration",
            "timestamp",
            "errored",
        },
        {"checks", "relevant_attributes", "prior_state"},
    )
    check(plan["format_version"] == "1.2", "plan_version")
    check(
        plan["configuration"]["provider_config"]
        == {
            "aws": {
                "name": "aws",
                "full_name": "registry.opentofu.org/hashicorp/aws",
                "version_constraint": "6.54.0",
                "expressions": {
                    "allowed_account_ids": {"references": ["var.account_id"]},
                    "region": {"references": ["var.region"]},
                },
            }
        },
        "provider_configuration",
    )
    check(
        all(
            row["status"] == "pass"
            and all(i["status"] == "pass" for i in row.get("instances", []))
            for row in plan.get("checks", [])
        ),
        "plan_checks",
    )
    allowed_data = {
        "data.aws_caller_identity.current",
        "data.aws_iam_openid_connect_provider.github[0]",
    }
    for row in plan["resource_changes"]:
        check(row["mode"] in {"managed", "data"}, "plan_mode")
        if row["mode"] == "data":
            check(
                row["address"] in allowed_data
                and row["change"]["actions"] in (["read"], ["no-op"]),
                "plan_data",
            )
    for raw, digest in (
        (saved_plan["binary"], "plan_sha256"),
        (t.canonical(plan), "plan_json_sha256"),
        (t.canonical(generated_inputs), "inputs_sha256"),
        (t.canonical(state_before), "before_sha256"),
        (t.canonical(state_after), "after_sha256"),
    ):
        check(e.sha(raw) == t.hex_digest(g[digest]), "checkpoint_" + digest)
    sources = _source_closure(source_blobs, g)
    before, after = state_resources(state_before), state_resources(state_after)
    check(
        state_before["lineage"] == state_after["lineage"]
        and re.fullmatch(r"[0-9a-f-]{36}", state_before["lineage"]),
        "lineage",
    )
    enabled = generated_inputs.get("ext2_enabled", False)
    check(
        type(enabled) is bool
        and plan["terraform_version"] == "1.13.2"
        and plan.get("errored") is False,
        "plan_format",
    )
    expected_prior = set(PRIOR)
    if generated_inputs.get("github_delivery") is not None:
        expected_prior |= {
            kind + '["' + role + '"]'
            for kind in (
                "aws_iam_role.delivery",
                "aws_iam_role_policy.delivery",
                "aws_iam_policy.delivery_session",
            )
            for role in ("plan", "deploy")
        }
    check(set(before) - set(FOUR) == expected_prior, "prior_complete")
    existing = set(before) & set(FOUR)
    check(not existing or existing == set(FOUR), "partial_adoption")
    check(enabled or not existing, "disabled_adoption")
    new = set(FOUR) if enabled else set()
    check(set(after) == expected_prior | new, "after_complete")
    check(
        state_after["serial"]
        == state_before["serial"] + (1 if new and not existing else 0),
        "serial",
    )
    changes = [r for r in plan["resource_changes"] if r["mode"] == "managed"]
    check(
        len(changes) == len(after) and {r["address"] for r in changes} == set(after),
        "plan_complete",
    )
    for row in changes:
        address, change = row["address"], row["change"]
        check(
            row.get("provider_name") == "registry.opentofu.org/hashicorp/aws"
            and not row.get("previous_address")
            and not change.get("importing")
            and not row.get("generated_config"),
            "adoption",
        )
        create = address in new and address not in existing
        check(change["actions"] == (["create"] if create else ["no-op"]), "actions")
        check(
            change["before"] is None
            if create
            else change["before"] == before[address] == after[address],
            "prior_unchanged",
        )
        _known_plan(
            change["after"], change.get("after_unknown", {}), after[address], address
        )
    expected_output = _resolve_sources(sources, generated_inputs, after, plan)
    state_output = state_after["outputs"].get("ext2")
    if expected_output is None:
        check(
            state_output is None or state_output.get("value") is None, "disabled_output"
        )
    else:
        check(
            type(state_output) is dict
            and state_output.get("sensitive") is True
            and t.canonical(state_output.get("value")) == t.canonical(expected_output),
            "state_output",
        )
    check(
        isinstance(observations, _Observations)
        and observations.seal is _SEAL
        and set(observations.values) == set(after),
        "observations",
    )
    for address, resource in after.items():
        actual = dict(observations.values[address])
        if address == "aws_kms_key.ext2_signing[0]":
            check(actual.pop("spki_sha256", None) == g["spki_sha256"], "spki_pin")
        check(
            t.canonical(actual) == t.canonical(projection(address, resource)),
            "api_" + address,
        )
    if enabled:
        role, key = (
            after["aws_iam_role.ext2_gate[0]"],
            after["aws_kms_key.ext2_signing[0]"],
        )
        account = generated_inputs["account_id"]
        check(
            role["name"] == role["id"] == ROLE
            and role["arn"] == f"arn:aws:iam::{account}:role/{ROLE}"
            and not role.get("permissions_boundary"),
            "role_identity",
        )
        check(
            re.fullmatch(
                r"arn:aws:kms:us-east-2:" + account + r":key/[0-9a-f-]{36}", key["arn"]
            )
            and key["id"] == key["key_id"] == key["arn"].rsplit("/", 1)[1]
            and key["key_usage"] == "SIGN_VERIFY"
            and key["customer_master_key_spec"] == "ECC_NIST_P256"
            and key["is_enabled"] is True
            and key["multi_region"] is False
            and not key.get("custom_key_store_id")
            and not key.get("xks_key_id")
            and not key.get("bypass_policy_lockout_safety_check"),
            "key_identity",
        )
        for field in ("policy",):
            policy = document(after["aws_iam_role_policy.ext2_gate[0]"][field])
            allowed = {
                "s3:AbortMultipartUpload",
                "s3:ListMultipartUploadParts",
                "s3:ListBucketMultipartUploads",
                "s3:GetObjectVersion",
                "s3:GetObjectRetention",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketVersioning",
                "s3:GetBucketObjectLockConfiguration",
                "s3:PutObject",
                "s3:PutObjectRetention",
                "kms:DescribeKey",
                "kms:GetPublicKey",
                "kms:GetKeyPolicy",
                "kms:Sign",
                "kms:Decrypt",
                "kms:GenerateDataKey",
            }
            for statement in policy["Statement"]:
                actions = statement["Action"]
                check(
                    set([actions] if type(actions) is str else actions) <= allowed,
                    "grant_actions",
                )
    return VerifiedInventory(
        len(new),
        len(expected_prior),
        g["source_sha"],
        g["plan_sha256"],
        g["after_sha256"],
    )
