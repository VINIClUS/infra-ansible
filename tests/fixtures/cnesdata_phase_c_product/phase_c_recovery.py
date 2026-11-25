"""Phase C de recovery: oráculo por modo, apply revisado exato e aceite do canary de recovery."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, Final, cast

from scripts.promotion._phase_c_core import (
    MODES,
    PhaseBContext,
    PhaseCContext,
    PhaseCWatchdog,
    _canonical,
    _require_utc,
    accept_mode_canary,
    accept_recovery_canary,
    assert_fence,
    mode_result,
    object_hash,
    verify_mode_route,
)
from scripts.promotion.accept_routing import observe_gate, read_routes
from scripts.promotion.phase_b import _assert_task_revisions_unchanged, _context_from_admitted

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from scripts.promotion.verify_routes import NativePhaseB

Node = dict[str, Any]
APPLY_SECONDS: Final = 300
SCHEDULE: Final = 'module.schedulers.aws_scheduler_schedule.mode["{}"]'
RUN_POLICY: Final = 'module.schedulers.aws_iam_role_policy.run["{}"]'
VARIABLES: Final = {
    "unit": "processor_active_unit_task_definition_arn",
    "recovery": "scheduler_recovery_task_definition_arn",
    "audit": "scheduler_audit_task_definition_arn",
}
_SCHEDULERS: Final = "module.schedulers."
_EVENTS: Final = {"recovery": ("recovery_failed",), "audit": ("audit_failed", "audit_succeeded")}
INITIAL: Final = {
    mode: (
        f'{_SCHEDULERS}aws_scheduler_schedule_group.mode["{mode}"]',
        SCHEDULE.format(mode),
        *(f'{_SCHEDULERS}aws_cloudwatch_event_rule.task_outcome["{e}"]' for e in events),
        f'{_SCHEDULERS}aws_cloudwatch_metric_alarm.repeated_failure["{mode}"]',
        f'{_SCHEDULERS}aws_cloudwatch_metric_alarm.lost_invocation["{mode}"]',
        *((f"{_SCHEDULERS}aws_cloudwatch_metric_alarm.outbox_backlog[0]",) * (mode == "audit")),
    )
    for mode, events in _EVENTS.items()
}
_EMPTY_TARGET: Final = ("input", "dead_letter_config", "eventbridge_parameters",
                        "kinesis_parameters", "sagemaker_pipeline_parameters", "sqs_parameters")
_EMPTY_ECS: Final = ("capacity_provider_strategy", "placement_constraints", "placement_strategy",
                     "propagate_tags", "reference_id", "group", "tags")


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def phase_c_context(phase_b: PhaseBContext, evidence: Mapping[str, Any],
                    close: Mapping[str, Any]) -> PhaseCContext:
    """Raises: ValueError: Handoff alterado, outra activation ou close-drain de outra Phase B."""
    _require(phase_b.activation is not None, "phase_c=original_activation_required")
    _require(phase_b == _context_from_admitted(phase_b.canary, phase_b.activation),
             "phase_c=retained_handoff_changed")
    routes = evidence.get("routes") or {}
    _require(evidence.get("kind") == "phase-b", "phase_c=phase_b_kind")
    activation = hashlib.sha256(phase_b.activation or b"").hexdigest()
    _require(evidence.get("common", {}).get("activation_sha256") == activation,
             "phase_c=activation_binding")
    _require(object_hash(close) == evidence.get("close_drain_sha256")
             and close.get("common") == evidence.get("common"), "phase_c=close_binding")
    mode = "initial" if phase_b.phase_a["active_before"] is None else "established"
    _require(routes.get("mode") == mode, "phase_c=phase_b_mode")
    _require(routes.get("unit_revision") == phase_b.canary["revisions"]["unit"],
             "phase_c=phase_b_unit")
    PhaseCWatchdog.from_close(close)
    return PhaseCContext(phase_b, deepcopy(dict(evidence)), deepcopy(dict(close)))


def _changes(plan: Mapping[str, Any]) -> dict[str, Node]:
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise ValueError("plan=resource_changes")
    managed = [item for item in changes if item.get("mode") == "managed"]
    addresses = [item["address"] for item in managed]
    _require(len(addresses) == len(set(addresses)), "plan=duplicate_address")
    return {
        item["address"]: item["change"]
        for item in managed
        if item["change"].get("actions") != ["no-op"]
    }


def _variables(plan: Mapping[str, Any], mode: str, context: PhaseCContext) -> None:
    values = plan.get("variables") or {}
    for name, expected in context.routes_for(mode).items():
        _require((values.get(VARIABLES[name]) or {}).get("value") == expected,
                 f"variables={name}")


def _target(value: Mapping[str, Any]) -> Node:
    return value["target"][0]["ecs_parameters"][0]


def _subset(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def _empty(actual: Mapping[str, Any], keys: tuple[str, ...]) -> bool:
    return all(actual.get(key) in (None, [], {}, "") for key in keys)


def _schedule_after(change: Node, mode: str, context: PhaseCContext) -> None:
    after = change.get("after") or {}
    canary = context.phase_b.canary
    network = canary["network"]
    target = {
        "arn": canary["cluster"],
        "role_arn": f"arn:aws:iam::{canary['account_id']}:role/cnesdata-prod-scheduler-{mode}",
        "retry_policy": [{"maximum_retry_attempts": 0, "maximum_event_age_in_seconds": 900}],
    }
    ecs = {
        "task_definition_arn": context.revisions[mode], "launch_type": "FARGATE",
        "task_count": 1, "enable_execute_command": False,
        "network_configuration": [{
            "assign_public_ip": network["public_ip"] == "ENABLED",
            "security_groups": [network["security_group"]],
            "subnets": sorted(network["subnets"]),
        }],
    }
    names = {"name": f"cnesdata-prod-{mode}", "group_name": f"cnesdata-prod-{mode}",
             "state": "ENABLED", "schedule_expression": "rate(30 minutes)"}
    _require(
        _subset(after, names)
        and after["flexible_time_window"][0].get("mode") == "OFF"
        and _subset(after["target"][0], target) and _empty(after["target"][0], _EMPTY_TARGET)
        and _subset(_target(after), ecs) and _empty(_target(after), _EMPTY_ECS)
        and not (change.get("after_unknown") or {}).get("target"),
        f"schedule={mode}_target",
    )


def _schedule_contract(change: Node, mode: str, context: PhaseCContext) -> None:
    _schedule_after(change, mode, context)
    prior = context.prior[mode]
    if prior is None:
        return
    before, after = deepcopy(change["before"]), deepcopy(change["after"])
    _require(_target(before).get("task_definition_arn") == prior, f"schedule={mode}_prior")
    _target(before)["task_definition_arn"] = context.revisions[mode]
    _require(before == after, f"schedule={mode}_non_route_change")


def _statements(value: Mapping[str, Any] | None) -> list[Node]:
    policy = (value or {}).get("policy") or "{}"
    document = json.loads(policy) if isinstance(policy, str) else policy
    return list(document.get("Statement", []))


def _run_task(revision: str | None, cluster: str) -> list[Node]:
    if revision is None:
        return []
    return [{"Effect": "Allow", "Action": "ecs:RunTask", "Resource": revision,
             "Condition": {"ArnEquals": {"ecs:cluster": cluster}}}]


def _run_policy_contract(change: Node, mode: str, context: PhaseCContext) -> None:
    cluster = context.phase_b.canary["cluster"]
    before, after = _statements(change.get("before")), _statements(change.get("after"))
    old, new = _run_task(context.prior[mode], cluster), _run_task(context.revisions[mode], cluster)
    _require([s for s in before if s.get("Action") == "ecs:RunTask"] == old,
             f"run_policy={mode}_prior_grant")
    _require([s for s in after if s.get("Action") == "ecs:RunTask"] == new,
             f"run_policy={mode}_grant")
    _require([s for s in before if s not in old] == [s for s in after if s not in new],
             f"run_policy={mode}_other_grants")


def review_scheduler_plan(plan: Mapping[str, Any], mode: str, context: PhaseCContext) -> str:
    """Returns: initial/established. Raises: ValueError: Delta fora do Scheduler do modo."""
    _require(mode == context.next_mode, "phase_c=order")
    _require(len(context.canaries) == len(context.accepted), "phase_c=prior_canary")
    _variables(plan, mode, context)
    _assert_task_revisions_unchanged(plan)
    changes = _changes(plan)
    initial = context.prior[mode] is None
    expected = {
        **dict.fromkeys(INITIAL[mode] if initial else (SCHEDULE.format(mode),),
                        ["create"] if initial else ["update"]),
        RUN_POLICY.format(mode): ["update"],
    }
    _require(set(changes) == set(expected), f"delta=unexpected resources={sorted(changes)!r}")
    _require(all(changes[a].get("actions") == expected[a] for a in expected), "delta=action")
    _schedule_contract(changes[SCHEDULE.format(mode)], mode, context)
    _run_policy_contract(changes[RUN_POLICY.format(mode)], mode, context)
    return "initial" if initial else "established"


def review_recovery_plan(plan: Mapping[str, Any], context: PhaseCContext) -> str:
    """Returns: initial/established. Raises: ValueError: Plan muda unit, audit ou fora de ordem."""
    return review_scheduler_plan(plan, "recovery", context)


def _audited(approval: Mapping[str, Any], mode: str, context: PhaseCContext,
             before: Node) -> tuple[bytes, bytes]:
    raw = Path(approval["plan_path"]).read_bytes()
    audit = Path(approval["audit_path"]).read_bytes()
    _require(hashlib.sha256(audit).hexdigest() == approval["audit_sha256"],
             "phase_c=original_audit_hash")
    report = json.loads(audit)
    _require(
        report.get("decision") == "ACCEPT"
        and report.get("phase") == f"phase-c-{mode}"
        and report.get("plan_sha256") == hashlib.sha256(raw).hexdigest()
        and report.get("checkpoint") == before
        and report.get("source_sha") == context.close["common"]["source_sha"],
        "phase_c=exact_independent_audit_required",
    )
    return raw, audit


def _apply_reviewed(native: NativePhaseB, raw: bytes, review: Callable[[Node], None],
                    before: Node) -> bytes:
    with TemporaryDirectory(prefix="reviewed-phase-c-") as directory:
        reviewed = Path(directory) / "reviewed.tfplan"
        reviewed.write_bytes(raw)
        reviewed.chmod(0o400)
        review(native.show(reviewed))
        _require(native.checkpoint()[0] == before and reviewed.read_bytes() == raw,
                 "phase_c=checkpoint_or_binary_changed")
        applied = native.apply(reviewed)
        _require(reviewed.read_bytes() == raw, "phase_c=applied_binary_changed")
    return applied


def _advanced(before: Node, after: Node) -> None:
    _require(after["lineage"] == before["lineage"] and after["serial"] > before["serial"],
             "phase_c=checkpoint_not_advanced")


@dataclass(frozen=True, slots=True)
class PhaseCEvidence:
    """Insumos do elemento phase-c: o deploy C do keeper fornece todos menos a forma."""

    mode: str
    close: Mapping[str, Any]
    before: Node
    after: Node
    plan_sha256: str
    audit_sha256: str
    apply_output: bytes
    routes: Any
    observed_at: datetime


def _projected(mode: str, routes: Any) -> bool:
    if mode not in MODES or type(routes) is not dict:
        return False
    values = cast("Node", routes)
    applied = ("unit", *MODES[: MODES.index(mode) + 1])
    return (set(values) == {"unit", *MODES}
            and all(value is None or type(value) is str for value in values.values())
            and all(type(values[name]) is str and values[name] for name in applied))


def phase_c_evidence(evidence: PhaseCEvidence) -> bytes:
    """Returns: Bytes canônicos do elemento `phase-c-<mode>` com apply_sha256 da saída do apply.

    Raises: ValueError: phase_c=checkpoint_not_advanced, phase_c=routes ou relógio não UTC.
    """
    _advanced(evidence.before, evidence.after)
    _require(_projected(evidence.mode, evidence.routes), "phase_c=routes")
    close = evidence.close
    return _canonical({
        "version": 1, "kind": f"phase-c-{evidence.mode}", "common": dict(close["common"]),
        "close_drain_sha256": object_hash(close), "before": evidence.before,
        "after": evidence.after, "plan_sha256": evidence.plan_sha256,
        "audit_sha256": evidence.audit_sha256,
        "apply_sha256": hashlib.sha256(evidence.apply_output).hexdigest(),
        "routes": evidence.routes, "observed_at": _require_utc(evidence.observed_at),
    })


def execute_reviewed_phase_c(context: PhaseCContext, native: NativePhaseB,
                             approval: Mapping[str, Any]) -> Node:
    """Aplica só o binário auditado do próximo modo sobre o checkpoint real, antes do corte."""
    mode, close = context.next_mode, context.close
    _require(mode is not None, "phase_c=complete")
    before, _ = native.checkpoint()
    _require(before == context.checkpoint, "phase_c=checkpoint_chain")
    raw, audit = _audited(approval, str(mode), context, before)

    def review(plan: Node) -> None:
        review_scheduler_plan(plan, str(mode), context)
        assert_fence(observe_gate(native)[1], close)
        context.watchdog.admit(f"phase-c-{mode}", datetime.now(UTC), APPLY_SECONDS)

    applied = _apply_reviewed(native, raw, review, before)
    native.assert_clean()
    after, state = native.checkpoint()
    _advanced(before, after)
    routes = read_routes(native, context, state)
    _require(routes == context.routes_for(str(mode)), "phase_c=routes")
    assert_fence(observe_gate(native)[1], close)
    return json.loads(phase_c_evidence(PhaseCEvidence(
        str(mode), close, before, after, hashlib.sha256(raw).hexdigest(),
        hashlib.sha256(audit).hexdigest(), applied, routes, datetime.now(UTC))))


__all__ = [
    "APPLY_SECONDS",
    "INITIAL",
    "RUN_POLICY",
    "SCHEDULE",
    "VARIABLES",
    "PhaseCContext",
    "PhaseCEvidence",
    "accept_mode_canary",
    "accept_recovery_canary",
    "execute_reviewed_phase_c",
    "mode_result",
    "phase_c_context",
    "phase_c_evidence",
    "review_recovery_plan",
    "review_scheduler_plan",
    "verify_mode_route",
]
