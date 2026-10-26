"""Catálogo finito e bindings declarados dos quatro roots do bootstrap."""

from collections.abc import Mapping
import re
from typing import Any


STORAGE = frozenset((
    "aws_s3_bucket.state", "aws_s3_bucket_versioning.state",
    "aws_s3_bucket_public_access_block.state",
    "aws_s3_bucket_server_side_encryption_configuration.state", "aws_s3_bucket_policy.state",
    "aws_s3_bucket.logging", "aws_s3_bucket_ownership_controls.logging",
    "aws_s3_bucket_public_access_block.logging",
    "aws_s3_bucket_server_side_encryption_configuration.logging", "aws_s3_bucket_policy.logging",
    "aws_s3_bucket_lifecycle_configuration.logging", "aws_s3_bucket_logging.state",
))
FOUNDATION = STORAGE | frozenset((
    "aws_s3_bucket_ownership_controls.state", "aws_kms_key.foundation",
    "aws_iam_user.bootstrap_operator", "aws_iam_user_policy_attachment.local_login",
    "aws_iam_user_policy.local_assume", "aws_iam_policy.executor_boundary",
    "aws_iam_role.bootstrap_readback", "aws_iam_role.bootstrap_executor",
    "aws_iam_role_policy.bootstrap_readback", "aws_iam_role_policy.bootstrap_executor",
))
SUCCESSORS = (
    "budget_operator", "shared_identity_manager", "github_infrastructure_plan",
    "github_infrastructure_deploy", "github_host_deploy", "roles_anywhere_api",
)
HANDOFF = frozenset(
    address for name in SUCCESSORS for address in (
        "aws_iam_role." + name, "aws_iam_policy." + name + "_boundary",
        "aws_iam_role_policy." + name)) | {"aws_iam_user_policy.successor_assume"}
CATALOG = {
    "foundation": FOUNDATION, "budget-backend": STORAGE, "identity-handoff": HANDOFF,
    "budget-identities": frozenset((
        "aws_iam_policy.freeze", "aws_iam_role.budget_action", "aws_iam_role_policy.budget_action",
    )),
}
ROOT_LAYOUT = {
    "foundation": ("opentofu/cnesdata-bootstrap/foundation", "infra-ansible:cnesdata",
                   "bootstrap/foundation.tfstate", "foundation"),
    "identity-handoff": ("opentofu/cnesdata-bootstrap/identity-handoff", "infra-ansible:cnesdata",
                         "bootstrap/identity-handoff.tfstate", "foundation"),
    "budget-backend": ("personal-infra-live/bootstrap", "personal-infra-live:cnesdata",
                       "bootstrap/backend.tfstate", "budget-backend"),
    "budget-identities": (
        "personal-infra-live/bootstrap-identities", "personal-infra-live:cnesdata",
        "bootstrap/budget-identities.tfstate", "budget-backend"),
}
PROVIDER_ASSIGNED = {"aws_kms_key.foundation", "aws_iam_user_policy_attachment.local_login"}


def _policies(addresses: frozenset[str]) -> set[str]:
    return {address for address in addresses if address.startswith((
        "aws_iam_", "aws_kms_key.", "aws_s3_bucket_policy."))
        and not address.startswith("aws_iam_user.")}


def _resource_names(root: Mapping[str, Any]) -> bool:
    for address, resource in root["resources"].items():
        kind, label = address.split(".")
        expected_kind = "provider_assigned" if address in PROVIDER_ASSIGNED else "configured"
        if resource["identity_kind"] != expected_kind:
            return False
        name = resource["configured_name"]
        if kind == "aws_s3_bucket":
            slot = "backend" if label == "state" else "logging"
            if name != root[slot]["bucket"]:
                return False
            continue
        if kind.startswith("aws_iam_") and address not in PROVIDER_ASSIGNED:
            if not name:
                return False
            continue
        if name is not None:
            return False
    return True


def _root_layout(roots: Mapping[str, Any], root_id: str) -> bool:
    root = roots[root_id]
    path, owner, key, storage_id = ROOT_LAYOUT[root_id]
    storage = roots[storage_id]
    return all((
        root["root_path"] == path, root["owner"] == owner, root["backend"]["key"] == key,
        root["backend"]["bucket"] == storage["backend"]["bucket"],
        root["logging"]["bucket"] == storage["logging"]["bucket"],
        root["logging"]["prefix"] == "access/" + root["backend"]["bucket"] + "/",
        root["source_sha"] == storage["source_sha"],
        set(root["resources"]) == CATALOG[root_id], _resource_names(root),
    ))


def _identities(run: Mapping[str, Any]) -> bool:
    resources = run["roots"]["foundation"]["resources"]
    addresses = {
        "operator": "aws_iam_user.bootstrap_operator",
        "readback": "aws_iam_role.bootstrap_readback",
        "executor": "aws_iam_role.bootstrap_executor",
        "boundary": "aws_iam_policy.executor_boundary",
    }
    return all(
        identity["name"] == resources[addresses[name]]["configured_name"]
        and re.fullmatch(r"/(?:[A-Za-z0-9_+=,.@-]+/)*", identity["path"]) is not None
        and all(part not in (".", "..") for part in identity["path"].split("/"))
        for name, identity in run["identities"].items())


def valid_scope(run: Mapping[str, Any], initial: Mapping[str, Any]) -> bool:
    """Returns: se catálogo, destinos, owners e bindings pertencem ao escopo fechado."""
    roots = run["roots"]
    maps = (roots, run["policy_template_digests"], initial["allowed_resource_actions"],
            initial["allowed_state_actions"])
    if not all(set(value) == set(CATALOG) for value in maps):
        return False
    if not all(_root_layout(roots, root_id) for root_id in CATALOG):
        return False
    buckets = [roots[root_id][slot]["bucket"] for root_id in ("foundation", "budget-backend")
               for slot in ("backend", "logging")]
    if len(set(buckets)) != 4 or not all(buckets):
        return False
    if not _identities(run):
        return False
    return all(
        set(run["policy_template_digests"][root_id]) == _policies(addresses)
        and set(initial["allowed_resource_actions"][root_id]) == addresses
        for root_id, addresses in CATALOG.items())
