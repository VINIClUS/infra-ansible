"""Gramática estática completa do BootstrapSpec v2, sem validação semântica."""

from collections.abc import Mapping
from typing import Any

from tools.aws_bootstrap.catalog import CATALOG, SUCCESSORS
from tools.aws_bootstrap.template_validation import (
    CONFIGURED_PATHS,
    DIGEST,
    DOCUMENT,
    POLICY_DIGESTS,
    SOURCE,
    Validator,
    arn_term,
    configured,
    enum,
    mapping,
    nullable,
    ordered_sequence,
    policy_templates,
    record,
    sequence,
    text,
)

PROFILE_IDS = ("bootstrap_readback", "bootstrap_executor", *SUCCESSORS, "budget_action")
PROFILE_ID = enum(*PROFILE_IDS)
CONTEXT_ENTRY = record(
    {
        "key": text,
        "type": enum("string", "boolean", "numeric", "date", "arn"),
        "values": sequence(text),
    }
)


def context(value: Any) -> bool:
    return sequence(CONTEXT_ENTRY)(value) and len({item["key"] for item in value}) == len(value)


SOURCE_REF = record(
    {
        "origin": enum("repository", "synthetic"),
        "repository": text,
        "source_sha": SOURCE,
        "path": text,
        "content_sha256": DIGEST,
        "input_schema_sha256": nullable(DIGEST),
        "parent_source_ids": sequence(text),
        "content_utf8": text,
    }
)
EXTERNAL_BINDING = record(
    {
        "exact_arn": text,
        "owner": text,
        "source_id": text,
        "observation_sha256": DIGEST,
    }
)
CAPABILITY = record(
    {
        "action": text,
        "resources": sequence(arn_term),
        "context": context,
        "exception_source_id": nullable(text),
    }
)
PROBE = record(
    {
        "probe_id": text,
        "subject_id": PROFILE_ID,
        "kind": enum("read", "simulation"),
        "action": text,
        "resource": arn_term,
        "context": context,
        "expected": enum("match", "allowed", "implicitDeny", "explicitDeny"),
        "expected_snapshot_sha256": nullable(DIGEST),
    }
)


def probe(value: Any) -> bool:
    if not PROBE(value):
        return False
    if value["kind"] == "read":
        return value["expected"] == "match" and value["expected_snapshot_sha256"] is not None
    return value["expected"] != "match" and value["expected_snapshot_sha256"] is None


REQUIREMENT = record(
    {
        "principal_profile": PROFILE_ID,
        "capability_id": text,
        "action": text,
        "resource": arn_term,
        "context": context,
        "dependency_requirement_ids": sequence(text),
    }
)
NEXT_PLAN = record(
    {
        "owner": text,
        "source_ids": sequence(text),
        "plan_sha256": DIGEST,
        "requirements": mapping(text, REQUIREMENT),
    }
)


def role_ref(profile_id: str) -> Validator:
    root = "identity-handoff"
    if profile_id.startswith("bootstrap_"):
        root = "foundation"
    if profile_id == "budget_action":
        root = "budget-identities"
    return lambda value: (
        configured(value)
        and value["root_id"] == root
        and (value["address"] == "aws_iam_role." + profile_id)
    )


def null(value: Any) -> bool:
    return value is None


def profile(profile_id: str) -> Validator:
    boundary = profile_id not in ("bootstrap_readback", "budget_action")
    session = profile_id != "budget_action"
    return record(
        {
            "role_ref": role_ref(profile_id),
            "source_ids": sequence(text),
            "trust_template_sha256": DIGEST,
            "policy_template_sha256": DIGEST,
            "boundary_template_sha256": DIGEST if boundary else null,
            "session_template_sha256": DIGEST if session else null,
            "template_documents_sha256": ordered_sequence(DIGEST),
            "capabilities": mapping(text, CAPABILITY),
            "probes": mapping(text, probe),
            "documents": record(
                {
                    "trust": DOCUMENT,
                    "inline": DOCUMENT,
                    "boundary": DOCUMENT if boundary else null,
                    "session": DOCUMENT if session else null,
                }
            ),
        }
    )


CAPABILITY_CATALOG = record(
    {
        "sources": mapping(text, SOURCE_REF),
        "profiles": record({name: profile(name) for name in PROFILE_IDS}),
        "external_bindings": mapping(text, EXTERNAL_BINDING),
        "next_plans": mapping(text, NEXT_PLAN),
        "configured_iam_paths": CONFIGURED_PATHS,
        "policy_templates": policy_templates,
    }
)


def exact_roots(validator: Validator) -> Validator:
    return lambda value: (
        validator(value)
        and set(value) == set(CATALOG)
        and all(set(value[root]["resources"]) == addresses for root, addresses in CATALOG.items())
    )


def bootstrap_spec_v2(
    run_fields: Mapping[str, Validator],
    step_fields: Mapping[str, Validator],
) -> Validator:
    return record(
        {
            "contract_version": lambda value: type(value) is int and value == 2,
            "run": record(
                {
                    **run_fields,
                    "roots": exact_roots(run_fields["roots"]),
                    "policy_template_digests": POLICY_DIGESTS,
                    "capability_catalog": CAPABILITY_CATALOG,
                }
            ),
            "step": record(
                {
                    **step_fields,
                    "stage": lambda value: (
                        step_fields["stage"](value)
                        or enum(
                            "budget_identities",
                            "migrate_budget_identities",
                            "identity_handoff",
                            "migrate_identity_handoff",
                        )(value)
                    ),
                }
            ),
        }
    )
