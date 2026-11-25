"""Aceite puro da Phase C: janela, fence, mode-result e rota, sem pydantic no import."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

from cnes_infra.aws.mode_canary import canonical_text
from scripts.promotion._stage_windows import close_windows
from scripts.promotion.mode_canary import RESULT_FIELDS, RESULT_SCHEMA
from scripts.promotion.rollback_api_static import CONVERGENCE_SECONDS, RECOVERY_SECONDS

if TYPE_CHECKING:
    from collections.abc import Mapping

Node = dict[str, Any]
MODES: Final = ("recovery", "audit")
_RESULT_COMMON: Final = ("canary_id", "candidate_sha256", "release_id", "source_sha")


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def object_hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _require_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("reason=datetime_not_utc")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class PhaseBContext:
    """Referências originais autenticadas; não reconstruídas de um JSON do caller."""

    canary: Node
    phase_a: Node
    machine: Node
    activation: bytes | None = None

    @property
    def oracle(self) -> Node:
        return {
            "active_before": self.phase_a["active_before"],
            "unit_revision": self.canary["revisions"]["unit"],
            "state_machine_arn": self.machine["arn"],
            "machine_after": self.machine,
        }


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


class WindowCutoff(ValueError):
    """Passo recusado pelo watchdog; carrega a decisão de convergência com o fence fechado."""

    def __init__(self, decision: Node) -> None:
        super().__init__(f"window=cutoff step={decision['step']}")
        self.decision = decision


@dataclass(frozen=True)
class PhaseCWatchdog:
    """Prazo F original do close-drain; nenhum passo novo depois de F menos a reserva."""

    closed_at: datetime
    fixed_deadline: datetime

    @classmethod
    def from_close(cls, close: Mapping[str, Any]) -> PhaseCWatchdog:
        """Raises: ValueError: F original além do prazo fixo governado desde o fechamento."""
        seconds = close_windows(close, "window")["fixed_deadline_seconds"]
        closed, fixed = _instant(close["close_confirmed_at"]), _instant(close["fixed_deadline"])
        _require(closed < fixed <= closed + timedelta(seconds=seconds), "window=fixed")
        return cls(closed, fixed)

    @property
    def cutoff(self) -> datetime:
        return self.fixed_deadline - timedelta(seconds=RECOVERY_SECONDS)

    def admit(self, step: str, now: datetime, seconds: int) -> None:
        """Raises: WindowCutoff: Passo que terminaria depois do corte da reserva de recovery."""
        if now + timedelta(seconds=seconds) > self.cutoff:
            raise WindowCutoff(self.converge(step, now))

    def converge(self, step: str, now: datetime) -> Node:
        """Returns: Decisão de convergência às rotas anteriores, fence fechado, sem reset de F."""
        deadline = min(self.fixed_deadline, now + timedelta(seconds=RECOVERY_SECONDS))
        return {
            "version": 1,
            "action": "converge-prior-routes",
            "step": step,
            "fence": "CLOSED",
            "reopen": False,
            "choice_at": _require_utc(now),
            "fixed_deadline": _require_utc(self.fixed_deadline),
            "recovery_deadline": _require_utc(deadline),
            "convergence_budget_seconds": CONVERGENCE_SECONDS,
        }


@dataclass(frozen=True)
class CanaryAcceptance:
    """Aceite de um mode-result, emitido só pelos aceites de recovery e audit."""

    mode: str
    common: Node
    phase_c_sha256: str
    result_sha256: str
    routing_sha256: str
    task_receipts: int
    observed_at: str
    freeze_proof_sha256: str | None
    deadline_drill_sha256: str | None
    operational_requirements: tuple[str, ...]


def assert_fence(state: Any, close: Mapping[str, Any]) -> None:
    """Raises: ValueError: Fence diferente do fechado no close-drain ou permit em voo."""
    fence, expected = state.fence, close["fence"]
    _require(fence.state.value == "CLOSED" and fence.promotion_id == expected["promotion_id"]
             and fence.version == expected["version"], "fence=closed_readback")
    _require(state.permit is None, "fence=permit_in_flight")


def _second(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(microsecond=0)


@dataclass(frozen=True)
class PhaseCContext:
    """Phase B autenticada, close-drain original, fases C e canaries aceitos, em ordem."""

    phase_b: PhaseBContext
    phase_b_evidence: Node
    close: Node
    accepted: tuple[Node, ...] = ()
    canaries: tuple[CanaryAcceptance, ...] = ()

    @property
    def activation_sha256(self) -> str:
        return hashlib.sha256(self.phase_b.activation or b"").hexdigest()

    @property
    def revisions(self) -> Node:
        return dict(self.phase_b.canary["revisions"])

    @property
    def initial(self) -> bool:
        return self.phase_b_evidence["routes"]["mode"] == "initial"

    @property
    def prior(self) -> dict[str, str | None]:
        routes = self.phase_b_evidence["routes"]
        return {mode: None if self.initial else routes[f"{mode}_revision"] for mode in MODES}

    @property
    def next_mode(self) -> str | None:
        return MODES[len(self.accepted)] if len(self.accepted) < len(MODES) else None

    @property
    def checkpoint(self) -> Node:
        return (self.accepted[-1] if self.accepted else self.phase_b_evidence)["after"]

    @property
    def watchdog(self) -> PhaseCWatchdog:
        return PhaseCWatchdog.from_close(self.close)

    def routes_for(self, mode: str) -> dict[str, str | None]:
        """Returns: Rotas esperadas depois do apply do modo; o outro modo fica onde estava."""
        applied = MODES[: MODES.index(mode) + 1]
        return {
            "unit": self.revisions["unit"],
            **{m: self.revisions[m] if m in applied else self.prior[m] for m in MODES},
        }

    def accept(self, evidence: Mapping[str, Any]) -> PhaseCContext:
        """Raises: ValueError: Evidência fora da ordem, da cadeia de checkpoint ou das rotas."""
        mode = self.next_mode
        _require(
            mode is not None
            and evidence.get("kind") == f"phase-c-{mode}"
            and evidence.get("common") == self.phase_b_evidence["common"]
            and evidence.get("close_drain_sha256") == self.phase_b_evidence["close_drain_sha256"]
            and evidence.get("before") == self.checkpoint
            and evidence.get("routes") == self.routes_for(str(mode))
            and len(self.canaries) == len(self.accepted),
            "phase_c=evidence",
        )
        return replace(self, accepted=(*self.accepted, deepcopy(dict(evidence))))


def _bound(result: Node, mode: str, context: PhaseCContext) -> None:
    applied = [e for e in context.accepted if e["kind"] == f"phase-c-{mode}"]
    _require(len(applied) == 1, "canary=route_not_accepted")
    _require(len(context.canaries) == MODES.index(mode), "canary=order")
    canary, common = context.phase_b.canary, context.close["common"]
    _require(
        all(result["common"][key] == canary[key] for key in _RESULT_COMMON)
        and result["common"]["activation_sha256"] == context.activation_sha256
        and result["common"]["promotion_generation"] == common["promotion_generation"],
        "canary=common",
    )
    observed = _second(result["observed_at"])
    _require(_second(result["fixed_deadline"]) == _second(context.close["fixed_deadline"])
             and observed >= _second(applied[0]["observed_at"]), "canary=window")
    context.watchdog.admit(f"canary-{mode}", observed, 0)


def mode_result(raw: bytes, mode: str, context: PhaseCContext, readbacks: Node) -> Node:
    """Returns: mode-result aceito. Raises: ValueError: Result de outra janela ou incompleto."""
    result = json.loads(raw)
    _require(canonical_text(result).encode() == raw and set(result) == set(RESULT_FIELDS)
             and result["schema"] == RESULT_SCHEMA and result["mode"] == mode, "canary=schema")
    _bound(result, mode, context)
    _require(not result["pending"] and not result["unknown"], "canary=pending")
    routing = hashlib.sha256(canonical_text(readbacks).encode()).hexdigest()
    _require(result["routing_before_sha256"] == routing == result["routing_after_sha256"],
             "canary=routing")
    _require(len(result["task_receipts"]) == 1, "canary=single_task")
    return result


def _route_role_deadline(readbacks: Node, mode: str, context: PhaseCContext) -> None:
    canary, revision = context.phase_b.canary, context.revisions[mode]
    target = readbacks["schedules"][mode]["Target"]
    definition = readbacks["task_definitions"][mode]["taskDefinition"]
    _require(target["EcsParameters"]["TaskDefinitionArn"] == revision
             and definition.get("taskDefinitionArn") == revision, "route=revision")
    role = f"arn:aws:iam::{canary['account_id']}:role/cnesdata-prod-processor-{mode}"
    _require(definition.get("taskRoleArn") == role, "route=role")
    _require(target["RetryPolicy"] == {"MaximumRetryAttempts": 0,
                                       "MaximumEventAgeInSeconds": 900}, "route=deadline")
    network = canary["network"]
    vpc = target["EcsParameters"]["NetworkConfiguration"]["awsvpcConfiguration"]
    _require(vpc == {"Subnets": sorted(network["subnets"]),
                     "SecurityGroups": [network["security_group"]],
                     "AssignPublicIp": network["public_ip"]}, "route=network")


def verify_mode_route(readbacks: Node, mode: str, context: PhaseCContext) -> None:
    """Raises: ValueError: Revisão, rede, role, prazo ou alarme de falha fora do alvo do modo."""
    _route_role_deadline(readbacks, mode, context)
    alarm = readbacks["alarms"][mode]
    _require(
        alarm.get("AlarmName") == f"cnesdata-prod-scheduler-{mode}-repeated-failure"
        and alarm.get("Dimensions")
        == [{"Name": "RuleName", "Value": f"cnesdata-prod-scheduler-{mode}-failed"}]
        and (alarm.get("EvaluationPeriods"), alarm.get("DatapointsToAlarm")) == (2, 2)
        and alarm.get("ActionsEnabled") is True
        and bool(alarm.get("AlarmActions")),
        "route=alarm",
    )


def accept_mode_canary(raw: bytes, mode: str, context: PhaseCContext,
                       evidence: Mapping[str, Any]) -> PhaseCContext:
    """Returns: Contexto com o aceite do canary. Raises: ValueError: Rota, janela ou fence."""
    verify_mode_route(evidence["readbacks"], mode, context)
    result = mode_result(raw, mode, context, evidence["readbacks"])
    assert_fence(evidence["gate"], context.close)
    accepted = CanaryAcceptance(
        mode=mode, common=dict(result["common"]),
        phase_c_sha256=object_hash(context.accepted[MODES.index(mode)]),
        result_sha256=hashlib.sha256(raw).hexdigest(),
        routing_sha256=result["routing_before_sha256"],
        task_receipts=len(result["task_receipts"]), observed_at=result["observed_at"],
        freeze_proof_sha256=result["freeze_proof_sha256"],
        deadline_drill_sha256=result["deadline_drill_sha256"],
        operational_requirements=tuple(result["operational_requirements"]),
    )
    return replace(context, canaries=(*context.canaries, accepted))


def accept_recovery_canary(raw: bytes, context: PhaseCContext, readbacks: Node,
                           gate_state: Any) -> PhaseCContext:
    """Returns: Contexto com o canary de recovery aceito. Raises: ValueError: Permit em voo."""
    return accept_mode_canary(raw, "recovery", context,
                              {"readbacks": readbacks, "gate": gate_state})


def accept_audit_canary(raw: bytes, context: PhaseCContext, readbacks: Node,
                        gate_state: Any) -> PhaseCContext:
    """Returns: Contexto com o audit aceito. Raises: ValueError: Sem prova do freeze simulado."""
    accepted = accept_mode_canary(raw, "audit", context,
                                  {"readbacks": readbacks, "gate": gate_state})
    if accepted.canaries[-1].freeze_proof_sha256 is None:
        raise ValueError("canary=freeze_proof")
    return accepted


__all__ = [
    "MODES",
    "CanaryAcceptance",
    "PhaseBContext",
    "PhaseCContext",
    "PhaseCWatchdog",
    "WindowCutoff",
    "accept_audit_canary",
    "accept_mode_canary",
    "accept_recovery_canary",
    "assert_fence",
    "mode_result",
    "object_hash",
    "verify_mode_route",
]
