"""Avaliação C2 pura, com operações inertes e propostas restritas."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tools.aws_bootstrap.catalog import CATALOG
from tools.aws_bootstrap.checkpoint import (
    migration_evidence, observation_matches, quarantine_location, remote_location,
    resource_target, state_identity, validate_checkpoint,
)
from tools.aws_bootstrap.contract import BootstrapSpec, Readback, digest, freeze
from tools.aws_bootstrap.validation import instant


CMK_ADDRESS = "aws_kms_key.foundation"
ADOPTION_EVIDENCE = ("independent_orphan_observation", "materialized_policy_review",
                     "adoption_stage_authorization")
RESTORE_EVIDENCE = ("bounded_quarantine_credential", "quarantine_stage_authorization",
                    "independent_restore_verification")


@dataclass(frozen=True)
class C2Evaluation:
    blocked_reason: str | None
    operations: tuple[dict[str, Any], ...] = ()
    proposals: tuple[dict[str, Any], ...] = ()


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _head(facts: Readback, cp: Mapping) -> None:
    head = facts.known_checkpoint_head
    _require(head is not None and head["generation"] == cp["generation"]
             and head["checkpoint_sha256"] == digest(cp)
             and head["receipt_sha256"] == tuple(digest(r) for r in cp["receipts"]),
             "checkpoint_head_mismatch")


def _window(grant: Mapping, facts: Readback) -> None:
    _require(instant(grant["not_before"]) <= instant(facts.observed_at)
             <= instant(facts.evaluated_at) < instant(grant["expires_at"]),
             "authorization_window_invalid")


def _current(spec: BootstrapSpec, facts: Readback, cp: Mapping) -> None:
    run, step = spec.run, spec.step
    initial, stage = facts.authorizations["initial"], facts.authorizations["stage"]
    checks = (
        (initial == cp["stage_records"][0]["authority"], "authorization_authority_mismatch"),
        (initial["roots"] == run["roots"], "authorization_scope_mismatch"),
        (initial["run_sha256"] == stage["run_sha256"] == digest(run), "authorization_run_mismatch"),
        (stage["authority_sha256"] == digest(initial), "authorization_authority_mismatch"),
        (stage["step_sha256"] == digest(step), "authorization_step_mismatch"),
        (stage["parent_checkpoint_sha256"] == digest(cp), "checkpoint_history_invalid"),
        (initial["account_id"] == run["account_id"] == facts.caller_account, "account_mismatch"),
        (initial["region"] == run["region"], "region_mismatch"),
        (initial["initial_run_id"] == run["initial_run_id"], "initial_run_mismatch"),
        (stage["binary_plan_sha256"] == step["binary_plan_sha256"], "binary_plan_mismatch"),
        (stage["migration_config_sha256"] == step["migration_config_sha256"],
         "migration_evidence_invalid"),
    )
    for condition, reason in checks:
        _require(condition, reason)
    required = {digest(initial), digest(stage)} | {
        digest(record["stage_authorization"]) for record in cp["stage_records"]}
    _require(required <= set(facts.verified_authorization_sha256), "authorization_not_verified")
    for grant in (initial, stage, step):
        _window(grant, facts)
    _require(instant(initial["not_before"]) <= instant(stage["not_before"])
             < instant(stage["expires_at"]) <= instant(initial["expires_at"]),
             "authorization_window_invalid")
    _require(all(stage[key] == step[key] for key in ("not_before", "expires_at")),
             "stage_window_mismatch")
    root_arn = "arn:aws:iam::" + run["account_id"] + ":root"
    _require(facts.caller_arn == step["expected_principal_arn"] == root_arn, "caller_mismatch")
    _require(facts.session_kind == "root" and facts.mfa_verified is True, "caller_unverified")
    _require(instant(facts.evaluated_at) < instant(facts.session_expiration), "session_expired")
    _require(step["step_id"] not in {r["step"]["step_id"] for r in cp["stage_records"]},
             "authorization_step_mismatch")
    previous = cp["stage_records"][-1]["step"]
    if step["stage"] == previous["stage"] and step["binary_plan_sha256"] is not None:
        _require(step["binary_plan_sha256"] != previous["binary_plan_sha256"],
                 "binary_plan_mismatch")


def _surface(spec: BootstrapSpec, cp: Mapping) -> None:
    step = spec.step
    _require(spec.contract_version == 1, "unsupported_contract_version")
    _require(step["execution_mode"] == "initial_local" and step["execution_surface"] == "local",
             "unsupported_bootstrap_surface")
    stages = {
        "foundation": ({"foundation_pending", "foundation_partial"}, "foundation"),
        "migrate_bootstrap": ({"foundation_verified"}, "foundation"),
        "budget_backend": ({"bootstrap_state_migrated", "budget_backend_pending",
                            "budget_backend_partial"}, "budget-backend"),
        "migrate_budget": ({"budget_backend_verified"}, "budget-backend"),
        "mark_backends_ready": ({"budget_state_migrated"}, None),
        "review_adoption": ({"foundation_pending", "foundation_partial"}, "foundation"),
        "review_restore": ({cp["stage"]}, step["root_id"]),
    }
    _require(step["stage"] in stages, "unsupported_bootstrap_surface")
    allowed, root = stages[step["stage"]]
    _require(cp["stage"] in allowed and step["root_id"] == root,
             "checkpoint_history_invalid")


def _cmk(spec: BootstrapSpec, facts: Readback, observation: Mapping) -> None:
    run, value = spec.run, facts.cmk
    _require(value is not None, "cmk_binding_invalid")
    owner = run["roots"]["foundation"]["owner"]
    tags = {**run["tags"], "Owner": owner, "InitialRunId": run["initial_run_id"],
            "RunSpecSha256": digest(run)}
    policy = {"Version": "2012-10-17", "Statement": [{
        "Sid": "EnableIAMUserPermissions", "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::" + run["account_id"] + ":root"},
        "Action": "kms:*", "Resource": "*"}]}
    expected = {"account_id": run["account_id"], "region": run["region"],
                "key_manager": "CUSTOMER", "key_state": "Enabled", "key_spec": "SYMMETRIC_DEFAULT",
                "key_usage": "ENCRYPT_DECRYPT", "rotation_enabled": True, "owner": owner,
                "tags": tags, "policy_document": policy}
    _require(all(value[key] == freeze(item) for key, item in expected.items()),
             "cmk_binding_invalid")
    prefix = "arn:aws:kms:" + run["region"] + ":" + run["account_id"] + ":key/"
    _require(value["arn"].startswith(prefix) and len(value["arn"]) > len(prefix),
             "cmk_binding_invalid")
    attrs = {key: item for key, item in value.items()
             if key not in ("owner", "tags", "policy_document")}
    _require(observation["observation_status"] == "present"
             and observation["exact_id"] == value["arn"]
             and observation["owner"] == owner and observation["tags"] == tags
             and observation["attributes"] == attrs
             and observation["policy_documents"] == (value["policy_document"],),
             "cmk_binding_invalid")


def _cmk_receipt(spec: BootstrapSpec, facts: Readback, cp: Mapping) -> None:
    observation = facts.resources["foundation"][CMK_ADDRESS]
    _cmk(spec, facts, observation)
    _require(observation_matches(spec.run, "foundation", {"address": CMK_ADDRESS,
             "observation": observation, "evidence": facts.evidence}), "cmk_binding_invalid")
    receipts = [r for r in cp["receipts"] if r["root_id"] == "foundation"
                and r["target"].get("address") == CMK_ADDRESS and r["target"]["action"] == "create"]
    _require(len(receipts) == 1, "cmk_binding_invalid")
    receipt = receipts[0]
    _require(receipt["exact_id"] == facts.cmk["arn"]
             == facts.root_states["foundation"]["resource_ids"][CMK_ADDRESS], "cmk_binding_invalid")
    if spec.step["stage"] == "budget_backend":
        binding = {"input": "kms_key_arn", "value": facts.cmk["arn"],
                   "origin_receipt_sha256": digest(receipt)}
        _require(spec.step["input_bindings"] == (binding,), "cmk_binding_invalid")
    else:
        _require(not spec.step["input_bindings"], "unsupported_input_bindings")


def _live_states(facts: Readback, cp: Mapping) -> None:
    _require(facts.root_states == cp["root_states"], "checkpoint_history_invalid")


def _observation(spec: BootstrapSpec, facts: Readback, context: Mapping) -> None:
    root, address = context["root"], context["address"]
    value = facts.resources[root][address]
    _require(observation_matches(spec.run, root, {"address": address, "observation": value,
                                                 "evidence": facts.evidence}),
             "resource_evidence_snapshot_mismatch")
    _require(value["observed_at"] == facts.observed_at, "resource_evidence_time_mismatch")
    _require(value["observation_status"] != "inconclusive",
             "resource_observation_inconclusive:" + root + ":" + address)
    if value["observation_status"] == "absent":
        ids = context["checkpoint"]["root_states"].get(root, {}).get("resource_ids", {})
        _require(address not in ids, "checkpoint_history_invalid")
        _require(value["exact_id"] is None and value["owner"] is None and not value["tags"]
                 and not value["attributes"] and not value["policy_documents"],
                 "resource_absence_contradictory:" + root + ":" + address)
        return
    receipts = [r for r in context["checkpoint"]["receipts"] if r["root_id"] == root
                and r["target"].get("address") == address]
    _require(bool(receipts), "orphan_candidates_ambiguous")
    _require(value["exact_id"] == receipts[-1]["exact_id"]
             == facts.root_states[root]["resource_ids"][address], "checkpoint_history_invalid")
    historical = _payload(context["checkpoint"], receipts[-1]["observed_after_sha256"])
    old = historical["resources"][address]
    _require(all(value[key] == old[key] for key in
                 ("exact_id", "owner", "tags", "attributes", "policy_documents")),
             "resource_evidence_snapshot_mismatch")


def _converged_roots(spec: BootstrapSpec, facts: Readback, cp: Mapping) -> None:
    for root, state in cp["root_states"].items():
        _require(set(facts.resources[root]) == CATALOG[root], "observation_catalog_mismatch")
        for address in state["resource_ids"]:
            _observation(spec, facts, {"root": root, "address": address, "checkpoint": cp})


def _proposal_surface(spec: BootstrapSpec, facts: Readback) -> None:
    _require(not spec.step["input_bindings"] and spec.step["binary_plan_sha256"] is None
             and spec.step["migration_config_sha256"] is None, "unsupported_bootstrap_surface")
    _require(all(facts.authorizations["stage"][k] is None for k in
                 ("before_manifest_sha256", "after_manifest_sha256")),
             "unsupported_bootstrap_surface")


def _payload(cp: Mapping, key: str) -> Any:
    return next(entry["evidence"][key] for entry in cp["history"] if key in entry["evidence"])


def _resources(spec: BootstrapSpec, facts: Readback, cp: Mapping) -> tuple[dict, ...]:
    root = spec.step["root_id"]
    _require(spec.step["binary_plan_sha256"] is not None, "binary_plan_required_for_resource_apply")
    _require(spec.step["migration_config_sha256"] is None, "unexpected_migration_config")
    _require(set(facts.resources[root]) == CATALOG[root], "observation_catalog_mismatch")
    stage = facts.authorizations["stage"]
    before = {"run_sha256": digest(spec.run), "root_id": root,
              "observed_at": facts.observed_at, "resources": facts.resources[root]}
    _require(stage["before_manifest_sha256"] == digest(before), "before_manifest_mismatch")
    _require(stage["after_manifest_sha256"] is not None, "after_manifest_required")
    operations = []
    for address in sorted(CATALOG[root]):
        _observation(spec, facts, {"root": root, "address": address, "checkpoint": cp})
        value = facts.resources[root][address]
        present = value["observation_status"] == "present"
        action = "noop" if present else "create"
        allowed = facts.authorizations["initial"]["allowed_resource_actions"][root][address]
        reason = "authorization_scope_mismatch" if present else "create_not_authorized"
        _require(action in allowed, reason)
        target = resource_target(spec.run, root, address)
        if present:
            target["exact_id"] = value["exact_id"]
        operations.append({"kind": "resource", "root_id": root, "address": address,
                           "action": action, "target": target,
                           "before_manifest_sha256": stage["before_manifest_sha256"],
                           "after_manifest_sha256": stage["after_manifest_sha256"]})
    return tuple(operations)


def _migration(spec: BootstrapSpec, facts: Readback, cp: Mapping) -> tuple[dict, ...]:
    invalid = False
    try:
        value, step = facts.migration, spec.step
        root = step["root_id"]
        _require(value["root_id"] == root, "migration_evidence_invalid")
        _require(value["source"] == cp["root_states"][root], "migration_evidence_invalid")
        _require(value["source"]["backend_location"].get("kind") == "local",
                 "migration_evidence_invalid")
        _require(value["destination"] == remote_location(spec.run, root),
                 "migration_evidence_invalid")
        destination = value["destination_state"]
        _require(value["destination_empty"] == (destination is None), "migration_evidence_invalid")
        if destination is not None:
            _require(state_identity(value["source"], destination), "migration_evidence_invalid")
            _require(destination["backend_location"] == value["destination"]
                     and destination["version_id"] is not None, "migration_evidence_invalid")
        _require(step["binary_plan_sha256"] is None and step["migration_config_sha256"] is not None,
                 "migration_evidence_invalid")
        _require("migrate" in facts.authorizations["initial"]["allowed_state_actions"][root],
                 "migration_evidence_invalid")
        before = {key: item for key, item in value.items() if key != "evidence_sha256"}
        before.update(run_sha256=digest(spec.run), observed_at=facts.observed_at)
        grant = facts.authorizations["stage"]
        _require(grant["before_manifest_sha256"] == digest(before)
                 and grant["after_manifest_sha256"] is not None, "migration_evidence_invalid")
        evidence = {key: facts.evidence[key] for key in value["evidence_sha256"]}
        _require(len(evidence) == len(value["evidence_sha256"]), "migration_evidence_invalid")
        context = {**before, "checkpoint": cp, "principal": facts.caller_arn}
        migration_evidence(spec.run, step, context, evidence)
    except (ValueError, KeyError, TypeError, AttributeError):
        invalid = True
    if invalid:
        raise ValueError("migration_evidence_invalid")
    return ({"kind": "root_state", "root_id": root, "action": "migrate", "source": value["source"],
             "destination": value["destination"],
             "before_manifest_sha256": grant["before_manifest_sha256"],
             "after_manifest_sha256": grant["after_manifest_sha256"]},)


def _adoption(spec: BootstrapSpec, facts: Readback, cp: Mapping) -> dict:
    _require(bool(facts.orphan_candidates), "orphan_observation_required")
    invalid = False
    try:
        _require(len(facts.orphan_candidates) == 1, "orphan_candidates_ambiguous")
        value = facts.orphan_candidates[0]
        _require(value["root_id"] == spec.step["root_id"] == "foundation"
                 and value["address"] == CMK_ADDRESS, "orphan_candidates_ambiguous")
        _require(value["initial_run_id"] == spec.run["initial_run_id"],
                 "orphan_candidates_ambiguous")
        intents = [e["snapshot"]["intent"] for e in cp["history"]
                   if e["snapshot"]["intent"] is not None]
        intent = next(i for i in intents if digest(i) == value["intent_sha256"])
        _require(intent["root_id"] == value["root_id"]
                 and CMK_ADDRESS in intent["target"]["resources"],
                 "orphan_candidates_ambiguous")
        _require(not any(r["target"].get("address") == CMK_ADDRESS for r in cp["receipts"]),
                 "orphan_candidates_ambiguous")
        observation = value["observation"]
        _require(observation_matches(spec.run, value["root_id"], {"address": CMK_ADDRESS,
                 "observation": observation, "evidence": facts.evidence}),
                 "orphan_candidates_ambiguous")
        _require(observation["observed_at"] == facts.observed_at, "orphan_candidates_ambiguous")
        _cmk(spec, facts, observation)
    except (ValueError, KeyError, TypeError, StopIteration):
        invalid = True
    if invalid:
        raise ValueError("orphan_candidates_ambiguous")
    configured = spec.run["roots"]["foundation"]["resources"][CMK_ADDRESS]
    return {"kind": "adoption_review", "root_id": "foundation", "target": {
        "address": CMK_ADDRESS, **configured, "exact_id": observation["exact_id"],
        "intent_sha256": value["intent_sha256"]},
        "evidence_sha256": [observation["source_evidence_sha256"]],
        "required_evidence": ADOPTION_EVIDENCE}


def _restore(spec: BootstrapSpec, facts: Readback, cp: Mapping) -> dict:
    invalid = False
    try:
        root = spec.step["root_id"]
        evidence = {key: value for key, value in facts.evidence.items() if "result" in value
                    and value["result"]["step_sha256"] == digest(spec.step)
                    and value["kind"] in ("freeze", "independent_backup")}
        kinds = {v["kind"]: (k, v) for k, v in evidence.items()}
        _require(len(evidence) == 2 and set(kinds) == {"freeze", "independent_backup"},
                 "restore_proposal_invalid")
        freeze, backup = kinds["freeze"][1], kinds["independent_backup"][1]
        source, destination = freeze["source"], freeze["destination"]
        _require(any(e["snapshot"]["root_states"].get(root) == source for e in cp["history"]),
                 "restore_proposal_invalid")
        _require(destination == quarantine_location(spec.run, root, source),
                 "restore_proposal_invalid")
        for key, value in evidence.items():
            _require(digest(value) == key and value["root_id"] == root
                     and value["source"] == source and value["destination"] == destination,
                     "restore_proposal_invalid")
            _require(value["result"]["run_sha256"] == digest(spec.run)
                     and value["observed_at"] == facts.observed_at, "restore_proposal_invalid")
            _window({**spec.step, "not_before": value["observed_at"]}, facts)
        result = freeze["result"]
        held_intent = None if cp["intent"] is None else digest(cp["intent"])
        _require(result["checkpoint_sha256"] == digest(cp)
                 and result["executor_principal_arn"] == facts.caller_arn
                 and result["held_intent_sha256"] == held_intent,
                 "restore_proposal_invalid")
        _require(backup["result"]["plaintext_state_sha256"] == source["state_sha256"],
                 "restore_proposal_invalid")
    except (ValueError, KeyError, TypeError, AttributeError):
        invalid = True
    if invalid:
        raise ValueError("restore_proposal_invalid")
    return {"kind": "restore_quarantine", "root_id": root, "source": source,
            "destination": destination,
            "evidence_sha256": [kinds[k][0] for k in ("freeze", "independent_backup")],
            "required_evidence": RESTORE_EVIDENCE}


def evaluate_c2(
    spec: BootstrapSpec, facts: Readback, checkpoint: Mapping[str, Any],
) -> C2Evaluation:
    """Returns: avaliação inerte; erros expõem somente códigos fixos."""
    try:
        validate_checkpoint(checkpoint, spec)
        _head(facts, checkpoint)
        _current(spec, facts, checkpoint)
        _surface(spec, checkpoint)
        stage = spec.step["stage"]
        if stage in ("review_adoption", "review_restore", "mark_backends_ready"):
            _proposal_surface(spec, facts)
        if stage == "review_adoption":
            return C2Evaluation(None, proposals=(_adoption(spec, facts, checkpoint),))
        _live_states(facts, checkpoint)
        if stage == "review_restore":
            return C2Evaluation(None, proposals=(_restore(spec, facts, checkpoint),))
        if CMK_ADDRESS in checkpoint["root_states"].get("foundation", {}).get("resource_ids", {}):
            _cmk_receipt(spec, facts, checkpoint)
        _converged_roots(spec, facts, checkpoint)
        if stage in ("foundation", "budget_backend"):
            return C2Evaluation(None, _resources(spec, facts, checkpoint))
        if stage in ("migrate_bootstrap", "migrate_budget"):
            return C2Evaluation(None, _migration(spec, facts, checkpoint))
        _require(stage == "mark_backends_ready", "unsupported_bootstrap_surface")
        return C2Evaluation(None)
    except ValueError as error:
        return C2Evaluation(str(error))
    except (KeyError, TypeError, AttributeError, StopIteration):
        return C2Evaluation("invalid_bootstrap_input")
