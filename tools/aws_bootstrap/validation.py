"""Schemas fechados dos records foundation/genesis do kernel puro."""

from collections.abc import Callable, Mapping
from datetime import datetime
from math import isfinite
import re
from typing import Any


Validator = Callable[[Any], bool]
ROOT_IDS = ("foundation", "budget-backend", "identity-handoff", "budget-identities")
FINANCIAL_LINES = (
    "cmk", "kms_requests", "backends", "logging_sinks", "iam", "restore_egress",
    "independent_recovery_media",
)


def _text(value: Any) -> bool:
    return isinstance(value, str)


def _number(value: Any) -> bool:
    return type(value) is int or type(value) is float and isfinite(value)


def _boolean(value: Any) -> bool:
    return type(value) is bool


def _integer(value: Any) -> bool:
    return type(value) is int


def _nonempty(value: Any) -> bool:
    return _text(value) and bool(value)


def _natural(value: Any) -> bool:
    return _integer(value) and value >= 0


def _union(*validators: Validator) -> Validator:
    return lambda value: any(validator(value) for validator in validators)


def instant(value: str) -> datetime:
    """Raises: ValueError com código fixo para timestamp inválido."""
    if not value.endswith("Z"):
        raise ValueError("invalid_timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("invalid_timestamp") from None


def valid_expiry(value: str) -> str | None:
    """Returns: timestamp recebido quando válido, ou null."""
    try:
        instant(value)
    except (ValueError, TypeError, AttributeError):
        return None
    return value


def configured_identifier(run: Mapping[str, Any], root: str, address: str) -> str:
    """Returns: ID configurado pelo catálogo, sem antecipar IDs de provider."""
    name = run["roots"][root]["resources"][address]["configured_name"]
    kind, label = address.split(".")
    if kind.startswith("aws_s3_"):
        slot = "backend" if label == "state" else "logging"
        return run["roots"][root][slot]["bucket"]
    if kind == "aws_iam_policy":
        path = run["identities"]["boundary"]["path"]
        return "arn:aws:iam::" + run["account_id"] + ":policy" + path + name
    if kind == "aws_iam_user_policy":
        return run["identities"]["operator"]["name"] + ":" + name
    if kind == "aws_iam_role_policy":
        role = run["roots"][root]["resources"]["aws_iam_role." + label]["configured_name"]
        return role + ":" + name
    return name


def _null(value: Any) -> bool:
    return value is None



def _pattern(expression: str) -> Validator:
    return lambda value: _text(value) and re.fullmatch(expression, value) is not None


def _enum(*values: str) -> Validator:
    return lambda value: _text(value) and value in values


def _nullable(validator: Validator) -> Validator:
    return lambda value: value is None or validator(value)


def _sequence(validator: Validator) -> Validator:
    return lambda value: isinstance(value, (list, tuple)) and all(map(validator, value))


def _mapping(key: Validator, child: Validator) -> Validator:
    return lambda value: isinstance(value, Mapping) and all(
        key(name) and child(item) for name, item in value.items())


def _record(fields: Mapping[str, Validator]) -> Validator:
    return lambda value: isinstance(value, Mapping) and set(value) == set(fields) and all(
        validator(value[name]) for name, validator in fields.items())


def _json(value: Any) -> bool:
    if value is None or type(value) is bool or _text(value) or _number(value):
        return True
    if isinstance(value, Mapping):
        return all(_text(key) and _json(child) for key, child in value.items())
    return isinstance(value, (list, tuple)) and all(_json(child) for child in value)


DIGEST = _pattern(r"[0-9a-f]{64}")
SOURCE = _pattern(r"[0-9a-f]{40}")
ACCOUNT = _pattern(r"[0-9]{12}")
ADDRESS = _pattern(r"aws_[a-z0-9_]+\.[a-zA-Z0-9_]+")
LABEL = _pattern(r"[A-Za-z0-9_.:/+=@ -]+")
ROOT = _enum(*ROOT_IDS)
TAGS = _mapping(LABEL, _text)
JSON_OBJECT = _mapping(_text, _json)
IDENTITY_KIND = _enum("configured", "provider_assigned")
OBSERVATION_STATUS = _enum("absent", "present", "inconclusive")
RESOURCE = _record({"configured_name": _nullable(_text), "identity_kind": IDENTITY_KIND})
ROOT_RECORD = _record({
    "root_path": _text, "source_sha": SOURCE, "owner": _text,
    "backend": _record({"bucket": _text, "key": _text}),
    "logging": _record({"bucket": _text, "prefix": _text}),
    "resources": _mapping(ADDRESS, RESOURCE),
})
ROOTS = _mapping(ROOT, ROOT_RECORD)
RESOURCE_ACTIONS = _mapping(
    ROOT, _mapping(ADDRESS, _sequence(_enum("create", "configure", "noop"))))
STATE_ACTIONS = _mapping(ROOT, _sequence(_enum("migrate")))
WINDOW = {"not_before": _text, "expires_at": _text}
STAGES = _enum(
    "foundation", "migrate_bootstrap", "budget_backend", "migrate_budget", "mark_backends_ready",
    "verify_restricted_identity", "complete_initial", "review_adoption", "review_restore",
)
STEP = _record({
    "step_id": _text, "stage": STAGES, "root_id": _nullable(ROOT),
    "execution_mode": _enum("initial_local", "subsequent"),
    "execution_surface": _enum("local", "ci"), "enabled": _boolean,
    "expected_principal_arn": _text, **WINDOW, "input_bindings": _sequence(_record({
        "input": _enum("kms_key_arn"), "value": _nonempty, "origin_receipt_sha256": DIGEST})),
    "binary_plan_sha256": _nullable(DIGEST), "migration_config_sha256": _nullable(DIGEST),
})
RUN = _record({
    "initial_run_id": _text, "account_id": ACCOUNT, "region": _text,
    "source_sha": SOURCE, "inventory_sha": DIGEST, "roots": ROOTS,
    "identities": _record({name: _record({"name": _text, "path": _text})
                           for name in ("operator", "readback", "executor", "boundary")}),
    "tags": TAGS, "policy_template_digests": _mapping(ROOT, _mapping(ADDRESS, DIGEST)),
    "backend_template_sha256": DIGEST, "cost_manifest_sha256": DIGEST,
})
INITIAL = _record({
    "authorization_id": _text, "initial_run_id": _text, "run_sha256": DIGEST,
    "account_id": ACCOUNT, "region": _text, "roots": ROOTS,
    "allowed_resource_actions": RESOURCE_ACTIONS, "allowed_state_actions": STATE_ACTIONS, **WINDOW,
})
STAGE = _record({
    "authorization_id": _text, "authority_sha256": DIGEST, "run_sha256": DIGEST,
    "step_sha256": DIGEST, "parent_checkpoint_sha256": _nullable(DIGEST),
    "binary_plan_sha256": _nullable(DIGEST), "migration_config_sha256": _nullable(DIGEST),
    "before_manifest_sha256": _nullable(DIGEST), "after_manifest_sha256": _nullable(DIGEST),
    **WINDOW,
})
SNAPSHOT_FIELDS = {
    "exact_id": _nullable(_text), "owner": _nullable(_text), "tags": TAGS,
    "attributes": JSON_OBJECT, "policy_documents": _sequence(JSON_OBJECT),
}
OBSERVATION = _record({
    **SNAPSHOT_FIELDS, "observed_at": _text, "observation_status": OBSERVATION_STATUS,
    "source_evidence_sha256": DIGEST,
})
EVIDENCE = _record({
    "kind": _enum("resource_observation"), "run_sha256": DIGEST, "root_id": ROOT,
    "address": ADDRESS, "observed_at": _text,
    "observation": _record({**SNAPSHOT_FIELDS, "status": OBSERVATION_STATUS}),
})
COST_FIELDS = {
    "currency": _text, "basis": _text, "project_forecast_gross": _number,
    "aggregate_forecast_gross": _number, "project_limit": _number, "aggregate_limit": _number,
    "rotation_max": _number,
}
FINANCIAL = _record({
    **COST_FIELDS, "observed_at": _text, "net_actual": _number, "net_forecast": _number,
    "lines": _mapping(_enum(*FINANCIAL_LINES), _record({
        name: _number for name in ("quantity", "min", "base", "max")})),
})
HEAD = _record({
    "generation": _integer, "checkpoint_sha256": DIGEST, "receipt_sha256": _sequence(DIGEST),
})
ACTIVATION = _record({
    "login_active": _boolean, "mfa_device_active": _boolean,
    "credential_source_verified": _boolean, "trust_sha256": _nullable(DIGEST),
    "policy_sha256": _nullable(DIGEST), "session_policy_sha256": _nullable(DIGEST),
})
LOCAL = _record({"kind": _enum("local"), "machine_id": _nonempty, "path": _nonempty})
REMOTE = _record({name: _nonempty for name in ("account", "region", "bucket", "key", "owner")})
ROOT_STATE = _record({
    "owner": _nonempty, "backend_location": _union(LOCAL, REMOTE), "lineage": _nonempty,
    "serial": _natural, "state_sha256": DIGEST, "resource_ids": _mapping(ADDRESS, _nonempty),
    "version_id": _nullable(_nonempty),
})
ROOT_STATES = _mapping(ROOT, ROOT_STATE)
TARGET = _record({
    "configured_name": _nullable(_text), "identity_kind": IDENTITY_KIND,
    "exact_id": _nullable(_text),
})
STATE_TARGET_FIELDS = {
    "kind": _enum("root_state"), "action": _enum("migrate"), "source": ROOT_STATE,
    "destination": REMOTE,
}
RESOURCE_RECEIPT_TARGET = _record({
    "kind": _enum("resource"), "address": ADDRESS, "action": _enum("create", "configure", "noop"),
    "configured_name": _nullable(_nonempty), "identity_kind": IDENTITY_KIND,
})
RECEIPT = _record({
    "run_sha256": DIGEST, "origin_step_id": _nonempty, "origin_spec_sha256": DIGEST,
    "origin_authorization_sha256": DIGEST, "intent_sha256": DIGEST, "root_id": ROOT,
    "target": _union(RESOURCE_RECEIPT_TARGET, _record(STATE_TARGET_FIELDS)),
    "exact_id": _nullable(_nonempty), "observed_after_sha256": DIGEST, "state_sha256": DIGEST,
    "lineage": _nonempty, "serial": _natural, "checkpoint_generation": _natural,
    "observed_at": _text,
})
RECORD = _record({
    "step": STEP, "spec_sha256": DIGEST, "authority": INITIAL, "authority_sha256": DIGEST,
    "stage_authorization": STAGE, "receipt_sha256": _sequence(DIGEST),
    "parent_checkpoint_sha256": _nullable(DIGEST),
})
INTENT = _record({
    "run_sha256": DIGEST, "step_id": _nonempty, "spec_sha256": DIGEST, "root_id": ROOT,
    "target": _union(_record(STATE_TARGET_FIELDS), _record({
        "kind": _enum("resource_set"), "resources": _mapping(ADDRESS, _record({
            "action": _enum("create", "configure", "noop"), "target": TARGET}))})),
    "authorization_sha256": DIGEST, "binary_plan_sha256": _nullable(DIGEST),
    "migration_config_sha256": _nullable(DIGEST), "before_manifest_sha256": DIGEST,
    "after_manifest_sha256": DIGEST, "parent_checkpoint_sha256": _nullable(DIGEST),
    **WINDOW, "principal_arn": _nonempty,
})
RESOURCE_MANIFEST = _record({
    "run_sha256": DIGEST, "root_id": ROOT, "observed_at": _text,
    "resources": _mapping(ADDRESS, OBSERVATION),
})
MIGRATION_FIELDS = {
    "root_id": ROOT, "source": ROOT_STATE, "destination": REMOTE,
    "destination_empty": _boolean, "destination_state": _nullable(ROOT_STATE),
}
STATE_BEFORE = _record({
    "run_sha256": DIGEST, "observed_at": _text, **MIGRATION_FIELDS,
})
OBSERVED_STATE = _record({
    "run_sha256": DIGEST, "root_id": ROOT, "observed_at": _text, "state": ROOT_STATE,
})
MIGRATION = _record({**MIGRATION_FIELDS, "evidence_sha256": _sequence(DIGEST)})
RESULT_FIELDS = {"run_sha256": DIGEST, "step_sha256": DIGEST}
MIGRATION_RESULTS = {
    "freeze": {"checkpoint_sha256": DIGEST, "executor_principal_arn": _nonempty,
               "held_intent_sha256": _nullable(DIGEST), "freeze_id": _nonempty},
    "independent_backup": {"media_id": _nonempty, "copy_id": _nonempty,
                           "ciphertext_sha256": DIGEST, "plaintext_state_sha256": DIGEST},
    "remote_lock": {"checkpoint_sha256": DIGEST, "holder_principal_arn": _nonempty,
                    "lock_location": REMOTE, "lock_id": _nonempty, "lock_version_id": _nonempty},
    "quarantine_restore": {"backup_evidence_sha256": DIGEST, "restored_state": ROOT_STATE},
}
MIGRATION_EVIDENCE = _union(*(_record({
    "kind": _enum(kind), "root_id": ROOT, "source": ROOT_STATE, "destination": REMOTE,
    "observed_at": _text, "result": _record({**RESULT_FIELDS, **fields}),
}) for kind, fields in MIGRATION_RESULTS.items()))
CMK = _record({
    **{name: _nonempty for name in ("arn", "account_id", "region", "key_manager", "key_state",
                                   "key_spec", "key_usage", "owner")},
    "rotation_enabled": _boolean, "tags": TAGS, "policy_document": JSON_OBJECT,
})
ORPHAN = _record({
    "intent_sha256": DIGEST, "initial_run_id": _nonempty, "root_id": ROOT, "address": ADDRESS,
    "observation": OBSERVATION,
})
HISTORICAL = _union(RESOURCE_MANIFEST, STATE_BEFORE, OBSERVED_STATE, EVIDENCE,
                    MIGRATION_EVIDENCE)
FRAME_FIELDS = {
    "contract_version": _integer, "initial_run_id": _nonempty, "run_sha256": DIGEST,
    "generation": _natural, "previous_sha256": _nullable(DIGEST), "current_step_id": _nonempty,
    "initial_complete": _boolean, "handoff_status": _nonempty,
    "stage": _enum("foundation_pending", "foundation_partial", "foundation_verified",
                   "migration_pending", "bootstrap_state_migrated", "budget_backend_pending",
                   "budget_backend_partial", "budget_backend_verified", "budget_state_migrated",
                   "backends_ready_initial_open"),
    "status": _enum("pending", "partial", "complete"), "stage_records": _sequence(RECORD),
    "root_states": ROOT_STATES, "receipts": _sequence(RECEIPT), "intent": _nullable(INTENT),
    "updated_at": _text,
}
CHECKPOINT = _record({
    **FRAME_FIELDS, "history": _sequence(_record({
        "snapshot": _record(FRAME_FIELDS), "evidence": _mapping(DIGEST, HISTORICAL)})),
})

READBACK = _record({
    "evaluated_at": _text, "observed_at": _text, "caller_account": ACCOUNT, "caller_arn": _text,
    "session_kind": _enum("root", "user", "assumed_role"), "session_expiration": _text,
    "mfa_verified": _boolean,
    "authorizations": _record({
        "initial": _nullable(INITIAL), "stage": _nullable(STAGE), "subsequent": _null}),
    "verified_authorization_sha256": _sequence(DIGEST),
    "resources": _mapping(ROOT, _mapping(ADDRESS, OBSERVATION)),
    "root_states": ROOT_STATES, "known_checkpoint_head": _nullable(HEAD), "cmk": _nullable(CMK),
    "financial": FINANCIAL, "migration": _nullable(MIGRATION),
    "orphan_candidates": _sequence(ORPHAN),
    "identity_activation": ACTIVATION, "evidence": _mapping(
        DIGEST, _union(EVIDENCE, MIGRATION_EVIDENCE)),
})
RESOURCE_OPERATION = _record({
    "kind": _enum("resource"), "root_id": ROOT, "address": ADDRESS,
    "action": _enum("create", "configure", "noop"), "target": TARGET,
    "before_manifest_sha256": DIGEST, "after_manifest_sha256": DIGEST,
})
OPERATION = _union(RESOURCE_OPERATION, _record({
    **STATE_TARGET_FIELDS, "root_id": ROOT, "before_manifest_sha256": DIGEST,
    "after_manifest_sha256": DIGEST,
}))
PROPOSAL_FIELDS = {"root_id": ROOT, "evidence_sha256": _sequence(DIGEST),
                   "required_evidence": _sequence(_nonempty)}
PROPOSAL = _union(_record({
    **PROPOSAL_FIELDS, "kind": _enum("adoption_review"), "target": _record({
        "address": ADDRESS, "configured_name": _nullable(_nonempty),
        "identity_kind": IDENTITY_KIND, "exact_id": _nonempty, "intent_sha256": DIGEST}),
}), _record({
    **PROPOSAL_FIELDS, "kind": _enum("restore_quarantine"), "source": ROOT_STATE,
    "destination": REMOTE,
}))
PLAN = _record({
    "contract_version": _integer, "run_sha256": DIGEST, "step_sha256": DIGEST,
    "spec_sha256": DIGEST, "readback_sha256": DIGEST, "checkpoint_sha256": _nullable(DIGEST),
    "authorization_sha256": DIGEST, "stage": STAGES, "expires_at": _nullable(_text),
    "status": _enum("ready", "blocked", "review_required"), "operations": _sequence(OPERATION),
    "proposals": _sequence(PROPOSAL), "blocked_reasons": _sequence(_text),
    "required_evidence": _sequence(_text), "estimated_cost": _record(COST_FIELDS),
})
SCHEMAS = {
    "BootstrapSpec": _record({"contract_version": _integer, "run": RUN, "step": STEP}),
    "Readback": READBACK, "BootstrapPlan": PLAN, "Checkpoint": CHECKPOINT,
}


def validate_record(name: str, value: Any) -> None:
    """Raises: ValueError com código fixo quando a estrutura recebida é inválida."""
    if not SCHEMAS[name](value):
        raise ValueError("invalid_bootstrap_input")
