"""Planejamento puro do primeiro passo foundation, sem qualquer execução."""

from collections.abc import Mapping
from fractions import Fraction
from typing import Any

from tools.aws_bootstrap.catalog import FOUNDATION, valid_scope
from tools.aws_bootstrap.contract import BootstrapPlan, BootstrapSpec, Checkpoint, Readback, digest
from tools.aws_bootstrap.lifecycle import C2Evaluation, evaluate_c2
from tools.aws_bootstrap.validation import (
    FINANCIAL_LINES, instant as _instant, valid_expiry as _valid_expiry,
)


REQUIRED_EVIDENCE = (
    "adapter_authorization_provenance", "native_binary_and_after_review", "private_runtime_lock",
    "fresh_readback_before_effect", "scanner_gate_b2", "operational_financial_readback",
)
COST_FIELDS = (
    "currency", "basis", "project_forecast_gross", "aggregate_forecast_gross",
    "project_limit", "aggregate_limit", "rotation_max",
)
SNAPSHOT_FIELDS = ("exact_id", "owner", "tags", "attributes", "policy_documents")


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _genesis(spec: BootstrapSpec, facts: Readback, checkpoint: Any) -> None:
    step = spec.step
    checks = (
        (spec.contract_version == 1, "unsupported_contract_version"),
        (step["stage"] == step["root_id"] == "foundation", "unsupported_bootstrap_surface"),
        (step["execution_mode"] == "initial_local", "unsupported_bootstrap_surface"),
        (step["execution_surface"] == "local", "unsupported_bootstrap_surface"),
        (checkpoint is None and facts.known_checkpoint_head is None, "unsupported_checkpoint"),
        (not facts.root_states and not facts.orphan_candidates, "genesis_not_empty"),
        (not step["input_bindings"], "unsupported_input_bindings"),
        (facts.authorizations["subsequent"] is None, "unsupported_authorization"),
        (facts.cmk is None and facts.migration is None, "genesis_not_empty"),
        (step["migration_config_sha256"] is None, "unexpected_migration_config"),
    )
    for condition, reason in checks:
        _require(condition, reason)


def _window(grant: Mapping[str, Any], facts: Readback) -> None:
    observed = _instant(facts.observed_at)
    evaluated = _instant(facts.evaluated_at)
    _require(_instant(grant["not_before"]) <= observed <= evaluated
             < _instant(grant["expires_at"]), "authorization_window_invalid")


def _authorizations(spec: BootstrapSpec, facts: Readback) -> None:
    run, step = spec.run, spec.step
    initial, stage = facts.authorizations["initial"], facts.authorizations["stage"]
    checks = (
        (initial["roots"] == run["roots"], "authorization_scope_mismatch"),
        (initial["run_sha256"] == stage["run_sha256"] == digest(run), "authorization_run_mismatch"),
        (stage["authority_sha256"] == digest(initial), "authorization_authority_mismatch"),
        (stage["step_sha256"] == digest(step), "authorization_step_mismatch"),
        ({digest(initial), digest(stage)} <= set(facts.verified_authorization_sha256),
         "authorization_not_verified"),
        (stage["parent_checkpoint_sha256"] is None, "unsupported_checkpoint"),
        (stage["binary_plan_sha256"] == step["binary_plan_sha256"], "binary_plan_mismatch"),
        (stage["migration_config_sha256"] is None, "unexpected_migration_config"),
        (initial["account_id"] == run["account_id"] == facts.caller_account, "account_mismatch"),
        (initial["region"] == run["region"], "region_mismatch"),
        (initial["initial_run_id"] == run["initial_run_id"], "initial_run_mismatch"),
    )
    for condition, reason in checks:
        _require(condition, reason)
    for grant in (initial, stage, step):
        _window(grant, facts)
    _require(_instant(initial["not_before"]) <= _instant(stage["not_before"])
             < _instant(stage["expires_at"]) <= _instant(initial["expires_at"]),
             "authorization_window_invalid")
    _require(stage["not_before"] == step["not_before"]
             and stage["expires_at"] == step["expires_at"], "stage_window_mismatch")


def _caller(spec: BootstrapSpec, facts: Readback) -> None:
    root_arn = "arn:aws:iam::" + spec.run["account_id"] + ":root"
    _require(facts.caller_arn == spec.step["expected_principal_arn"] == root_arn,
             "caller_mismatch")
    _require(facts.session_kind == "root" and facts.mfa_verified is True, "caller_unverified")
    _require(_instant(facts.evaluated_at) < _instant(facts.session_expiration), "session_expired")


def _catalog(spec: BootstrapSpec, facts: Readback) -> None:
    _require(valid_scope(spec.run, facts.authorizations["initial"]), "run_scope_invalid")
    resources = spec.run["roots"]["foundation"]["resources"]
    _require(set(resources) == FOUNDATION, "foundation_catalog_mismatch")
    _require(set(facts.resources) == {"foundation"}, "observation_root_mismatch")
    _require(set(facts.resources["foundation"]) == FOUNDATION, "observation_catalog_mismatch")
    actions = facts.authorizations["initial"]["allowed_resource_actions"]["foundation"]
    _require(all("create" in actions[address] for address in FOUNDATION), "create_not_authorized")


def _observation(spec: BootstrapSpec, facts: Readback, address: str) -> None:
    value = facts.resources["foundation"][address]
    source_hash = value["source_evidence_sha256"]
    source = facts.evidence[source_hash]
    snapshot = {name: value[name] for name in SNAPSHOT_FIELDS}
    snapshot["status"] = value["observation_status"]
    checks = (
        (digest(source) == source_hash, "resource_evidence_digest_mismatch"),
        (source["kind"] == "resource_observation", "resource_evidence_kind_mismatch"),
        (source["run_sha256"] == digest(spec.run), "resource_evidence_run_mismatch"),
        (source["root_id"] == "foundation" and source["address"] == address,
         "resource_evidence_target_mismatch"),
        (source["observed_at"] == value["observed_at"] == facts.observed_at,
         "resource_evidence_time_mismatch"),
        (source["observation"] == snapshot, "resource_evidence_snapshot_mismatch"),
    )
    for condition, reason in checks:
        _require(condition, reason)
    _require(snapshot["status"] != "inconclusive",
             "resource_observation_inconclusive:foundation:" + address)
    _require(snapshot["status"] == "absent",
             "resource_observation_not_absent:foundation:" + address)
    _require(value["exact_id"] is None and value["owner"] is None,
             "resource_absence_contradictory:foundation:" + address)
    _require(not value["tags"] and not value["attributes"] and not value["policy_documents"],
             "resource_absence_contradictory:foundation:" + address)


def _manifests(spec: BootstrapSpec, facts: Readback) -> None:
    before = {"run_sha256": digest(spec.run), "root_id": "foundation",
              "observed_at": facts.observed_at, "resources": facts.resources["foundation"]}
    stage = facts.authorizations["stage"]
    _require(stage["before_manifest_sha256"] == digest(before), "before_manifest_mismatch")
    after_hash = stage["after_manifest_sha256"]
    _require(isinstance(after_hash, str) and len(after_hash) == 64, "after_manifest_required")


def _financial(spec: BootstrapSpec, facts: Readback) -> None:
    value = facts.financial
    _require(digest(value) == spec.run["cost_manifest_sha256"], "cost_manifest_mismatch")
    _require(0 <= value["project_forecast_gross"] <= value["project_limit"] <= 8,
             "project_cost_limit_exceeded")
    _require(0 <= value["aggregate_forecast_gross"] <= value["aggregate_limit"] <= 15,
             "aggregate_cost_limit_exceeded")
    _require(_valid_ledger(value), "financial_manifest_invalid")


def _valid_ledger(value: Mapping[str, Any]) -> bool:
    lines = value["lines"]
    if value["currency"] != "USD" or set(lines) != set(FINANCIAL_LINES):
        return False
    if not all(line["quantity"] >= 0 and 0 <= line["min"] <= line["base"] <= line["max"]
               for line in lines.values()):
        return False
    if any(lines[name]["quantity"] != quantity for name, quantity in (
            ("cmk", 1), ("backends", 2), ("logging_sinks", 2))):
        return False
    if lines["independent_recovery_media"]["quantity"] < 1:
        return False
    reserve = sum(Fraction(str(line["quantity"])) * Fraction(str(line["max"]))
                  for line in lines.values())
    reserve += 2 * Fraction(str(lines["cmk"]["quantity"])) * Fraction(str(lines["cmk"]["max"]))
    return reserve <= Fraction(str(value["rotation_max"])) <= min(
        Fraction(str(value["project_forecast_gross"])),
        Fraction(str(value["aggregate_forecast_gross"])))


def _configured_id(run: Mapping[str, Any], address: str) -> str:
    root = run["roots"]["foundation"]
    name = root["resources"][address]["configured_name"]
    kind, label = address.split(".")
    if kind.startswith("aws_s3_"):
        bucket = "backend" if label == "state" else "logging"
        return root[bucket]["bucket"]
    if kind == "aws_iam_policy":
        path = run["identities"]["boundary"]["path"]
        return "arn:aws:iam::" + run["account_id"] + ":policy" + path + name
    if kind == "aws_iam_user_policy":
        return run["identities"]["operator"]["name"] + ":" + name
    if kind == "aws_iam_role_policy":
        role = root["resources"]["aws_iam_role." + label]["configured_name"]
        return role + ":" + name
    return name


def _target(run: Mapping[str, Any], address: str) -> dict[str, Any]:
    configured = run["roots"]["foundation"]["resources"][address]
    name = configured["configured_name"]
    exact_id = None if configured["identity_kind"] == "provider_assigned" else (
        _configured_id(run, address)
    )
    return {"configured_name": name, "identity_kind": configured["identity_kind"],
            "exact_id": exact_id}


def _operation(spec: BootstrapSpec, facts: Readback, address: str) -> dict[str, Any]:
    stage = facts.authorizations["stage"]
    return {"kind": "resource", "root_id": "foundation", "address": address, "action": "create",
            "target": _target(spec.run, address),
            "before_manifest_sha256": stage["before_manifest_sha256"],
            "after_manifest_sha256": stage["after_manifest_sha256"]}


def _reason(spec: BootstrapSpec, facts: Readback, checkpoint: Any) -> str | None:
    if not spec.step["enabled"]:
        return "step_disabled"
    try:
        _genesis(spec, facts, checkpoint)
        _authorizations(spec, facts)
        _caller(spec, facts)
        _catalog(spec, facts)
        _financial(spec, facts)
        if spec.step["binary_plan_sha256"] is None:
            return "binary_plan_required_for_resource_apply"
        _manifests(spec, facts)
        for address in sorted(FOUNDATION):
            _observation(spec, facts, address)
    except ValueError as error:
        return str(error)
    except (KeyError, TypeError, AttributeError):
        return "invalid_bootstrap_input"
    return None


def _checkpoint_digest(checkpoint: Any) -> str | None:
    try:
        return None if checkpoint is None else digest(checkpoint)
    except (ValueError, TypeError, RecursionError, OverflowError):
        return None


def _evaluate(spec: BootstrapSpec, facts: Readback, checkpoint: Any) -> C2Evaluation:
    if checkpoint is None:
        reason = _reason(spec, facts, checkpoint)
        operations = () if reason else tuple(_operation(spec, facts, address)
                                             for address in sorted(FOUNDATION))
        return C2Evaluation(reason, operations)
    if not spec.step["enabled"]:
        return C2Evaluation("step_disabled")
    try:
        value = (checkpoint if isinstance(checkpoint, Checkpoint)
                 else Checkpoint.from_mapping(checkpoint))
        _require(valid_scope(spec.run, facts.authorizations["initial"]), "run_scope_invalid")
        _financial(spec, facts)
    except ValueError as error:
        return C2Evaluation(str(error))
    except (KeyError, TypeError, AttributeError):
        return C2Evaluation("invalid_bootstrap_input")
    return evaluate_c2(spec, facts, value.as_mapping())


def plan_bootstrap(spec: BootstrapSpec, facts: Readback, checkpoint: Any) -> BootstrapPlan:
    """Retorna operações/propostas inertes ou bloqueio com código fixo."""
    evaluation = _evaluate(spec, facts, checkpoint)
    reason, proposals = evaluation.blocked_reason, evaluation.proposals
    required = REQUIRED_EVIDENCE + tuple(item for proposal in proposals
                                         for item in proposal["required_evidence"])
    return BootstrapPlan.from_mapping({
        "contract_version": 1, "run_sha256": digest(spec.run), "step_sha256": digest(spec.step),
        "spec_sha256": digest(spec), "readback_sha256": digest(facts),
        "checkpoint_sha256": _checkpoint_digest(checkpoint),
        "authorization_sha256": digest(facts.authorizations["stage"]),
        "stage": spec.step["stage"], "expires_at": _valid_expiry(spec.step["expires_at"]),
        "status": "blocked" if reason else ("review_required" if proposals else "ready"),
        "operations": evaluation.operations, "proposals": proposals,
        "blocked_reasons": () if reason is None else (reason,),
        "required_evidence": required,
        "estimated_cost": {name: facts.financial[name] for name in COST_FIELDS},
    })
