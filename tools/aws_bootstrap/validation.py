"""Schemas fechados dos records foundation/genesis do kernel puro."""

from collections.abc import Callable, Mapping
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


def _null(value: Any) -> bool:
    return value is None


def _empty(value: Any) -> bool:
    return isinstance(value, (list, tuple)) and not value


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
    "expected_principal_arn": _text, **WINDOW, "input_bindings": _empty,
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
READBACK = _record({
    "evaluated_at": _text, "observed_at": _text, "caller_account": ACCOUNT, "caller_arn": _text,
    "session_kind": _enum("root", "user", "assumed_role"), "session_expiration": _text,
    "mfa_verified": _boolean,
    "authorizations": _record({
        "initial": _nullable(INITIAL), "stage": _nullable(STAGE), "subsequent": _null}),
    "verified_authorization_sha256": _sequence(DIGEST),
    "resources": _mapping(ROOT, _mapping(ADDRESS, OBSERVATION)),
    "root_states": _record({}), "known_checkpoint_head": _nullable(HEAD), "cmk": _null,
    "financial": FINANCIAL, "migration": _null, "orphan_candidates": _empty,
    "identity_activation": ACTIVATION, "evidence": _mapping(DIGEST, EVIDENCE),
})
TARGET = _record({
    "configured_name": _nullable(_text), "identity_kind": IDENTITY_KIND,
    "exact_id": _nullable(_text),
})
OPERATION = _record({
    "kind": _enum("resource"), "root_id": ROOT, "address": ADDRESS,
    "action": _enum("create", "configure", "noop"), "target": TARGET,
    "before_manifest_sha256": DIGEST, "after_manifest_sha256": DIGEST,
})
PLAN = _record({
    "contract_version": _integer, "run_sha256": DIGEST, "step_sha256": DIGEST,
    "spec_sha256": DIGEST, "readback_sha256": DIGEST, "checkpoint_sha256": _nullable(DIGEST),
    "authorization_sha256": DIGEST, "stage": STAGES, "expires_at": _nullable(_text),
    "status": _enum("ready", "blocked", "review_required"), "operations": _sequence(OPERATION),
    "proposals": _empty, "blocked_reasons": _sequence(_text),
    "required_evidence": _sequence(_text), "estimated_cost": _record(COST_FIELDS),
})
SCHEMAS = {
    "BootstrapSpec": _record({"contract_version": _integer, "run": RUN, "step": STEP}),
    "Readback": READBACK, "BootstrapPlan": PLAN,
}


def validate_record(name: str, value: Any) -> None:
    """Raises: ValueError com código fixo quando a estrutura recebida é inválida."""
    if not SCHEMAS[name](value):
        raise ValueError("invalid_bootstrap_input")
