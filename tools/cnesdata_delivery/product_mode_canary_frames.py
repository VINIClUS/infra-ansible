"""Formatos fechados do ledger de modo: record, control, ticket, binding e transições."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Final, cast

from cnes_domain.orchestration.mode_canary import (
    ModeCanaryBinding,
    ModeCanaryControl,
    ModeCanaryRecord,
    SyntheticContextRequired,
    SyntheticEffectTicket,
)
from cnes_infra.control_plane.dynamodb_keys import run_partition, tenant_partition

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from cnes_domain.control_plane.environment_gate import PermitHolder
    from cnes_domain.ports.processing import StartRunExecution

TENANT_PREFIX: Final = "prod-canary-"
GENESIS_LEDGER_SHA256: Final = sha256(b"[]\n").hexdigest()
CEILINGS: Final = {
    "promotion": {"unit_tasks": 8, "recovery_resumes": 8, "recovery_hangs": 1},
    "readiness": {"unit_tasks": 8, "recovery_resumes": 8, "recovery_hangs": 2},
}
COUNTERS: Final = {
    "start-execution": "unit_tasks", "run-recovery": "recovery_resumes",
    "run-hang": "recovery_hangs",
}
EFFECT_KINDS: Final = frozenset({*COUNTERS, "native-mutation", "settle-permit"})
RECORD_ENTITY: Final = "MODECANARYRECORD"
CONTROL_ENTITY: Final = "MODECANARYCONTROL"
EFFECT_ENTITY: Final = "MODECANARYEFFECT"
BINDING_ENTITY: Final = "MODECANARYBINDING"
INSERT_ONLY: Final = "attribute_not_exists(pk)"
SWAP: Final = "payload = :old"


def canonical_text(mapping: dict[str, Any]) -> str:
    """Returns: JSON ordenado e compacto em UTF-8 com LF terminal único."""
    return json.dumps(mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def digest(text: str) -> str:
    """Returns: sha256 hex do texto em UTF-8."""
    return sha256(text.encode()).hexdigest()


def refuse(reason: str) -> SyntheticContextRequired:
    """Returns: Recusa do contexto sintético `reason=<x> field=tenant_id`."""
    return SyntheticContextRequired(f"reason={reason} field=tenant_id")


def stamp(moment: datetime) -> str:
    """Returns: Instante UTC em segundos. Raises: SyntheticContextRequired: clock_not_utc."""
    if moment.utcoffset() != timedelta(0):
        raise refuse("clock_not_utc")
    return moment.isoformat(timespec="seconds")


def start_request(holder: PermitHolder | StartRunExecution, unit_ids: Sequence[str]) -> str:
    """Returns: request_sha256 do start nativo do dispatch."""
    return digest(canonical_text({
        "dispatch_id": holder.dispatch_id, "run_id": holder.run_id,
        "tenant_id": holder.tenant_id, "unit_ids": list(unit_ids),
    }))


def effect_id(record_sha256: str, kind: str, request_sha256: str) -> str:
    """Returns: effect_id do ticket ligado ao record da fase, ao tipo e ao request."""
    return digest(canonical_text({
        "effect_kind": kind, "phase_record_sha256": record_sha256,
        "request_sha256": request_sha256,
    }))


def record_key(owner_sha256: str, phase: str) -> str:
    """Returns: Sort key do record da fase do owner."""
    return f"PROD_CANARY#{owner_sha256}#{phase}"


def control_key(owner_sha256: str) -> str:
    """Returns: Sort key do control único do owner."""
    return f"PROD_CANARY_CONTROL#{owner_sha256}"


def ticket_key(owner_sha256: str, identifier: str) -> str:
    """Returns: Sort key do ticket do efeito."""
    return f"PROD_CANARY_EFFECT#{owner_sha256}#{identifier}"


def put(table: str, item: dict[str, str], condition: str,
        values: dict[str, Any] | None) -> dict[str, Any]:
    """Returns: Elemento `Put` de TransactWriteItems com atributos string e condição."""
    request: dict[str, Any] = {
        "TableName": table, "Item": {name: {"S": value} for name, value in item.items()},
        "ConditionExpression": condition,
    }
    if values:
        request["ExpressionAttributeValues"] = values
    return {"Put": request}


def _item(pk: str, sort_key: str, entity: str, text: str) -> dict[str, str]:
    return {"pk": pk, "sk": sort_key, "entity": entity, "payload": text}


def parse_mapping(text: str, kind: str) -> dict[str, Any]:
    """Returns: Objeto JSON canônico. Raises: SyntheticContextRequired: invalid/not_canonical."""
    try:
        mapping = json.loads(text)
    except json.JSONDecodeError as error:
        raise refuse(f"{kind}_invalid") from error
    if type(mapping) is not dict:
        raise refuse(f"{kind}_invalid")
    if canonical_text(cast("dict[str, Any]", mapping)) != text:
        raise refuse(f"{kind}_not_canonical")
    return cast("dict[str, Any]", mapping)


def parse_control(text: str) -> ModeCanaryControl:
    """Returns: Control fechado. Raises: SyntheticContextRequired: control_invalid."""
    mapping = parse_mapping(text, "control")
    try:
        return ModeCanaryControl.from_mapping(mapping)
    except ValueError as error:
        raise refuse("control_invalid") from error


def parse_ticket(text: str) -> SyntheticEffectTicket:
    """Returns: Ticket fechado. Raises: SyntheticContextRequired: ticket_invalid."""
    mapping = parse_mapping(text, "ticket")
    try:
        return SyntheticEffectTicket.from_mapping(mapping)
    except ValueError as error:
        raise refuse("ticket_invalid") from error


def require_control(text: str | None, record: ModeCanaryRecord) -> ModeCanaryControl:
    """Returns: Control ACTIVE do contexto do record.

    Raises: SyntheticContextRequired: control_missing, control_mismatch ou control_sealed.
    """
    if text is None:
        raise refuse("control_missing")
    control = parse_control(text)
    generation = record.promotion_generation
    if (
        control.owner_sha256 != record.owner_sha256
        or control.context_kind != record.context_kind
        or control.context_manifest_sha256 != record.context_manifest_sha256
        or (generation is not None and control.generation != generation)
    ):
        raise refuse("control_mismatch")
    if control.admission_state != "ACTIVE":
        raise refuse("control_sealed")
    return control


def record_item(record: ModeCanaryRecord, text: str) -> dict[str, Any]:
    """Returns: Item insert-only do record com os bytes exatos do texto.

    Raises: SyntheticContextRequired: Texto não canônico, inválido ou de outro record.
    """
    mapping = parse_mapping(text, "record")
    try:
        parsed = ModeCanaryRecord.from_mapping(mapping)
    except ValueError as error:
        raise refuse("record_invalid") from error
    if parsed != record:
        raise refuse("record_mismatch")
    pk = tenant_partition(f"{TENANT_PREFIX}{record.canary_id}")
    item = _item(pk, record_key(record.owner_sha256, record.phase), RECORD_ENTITY, text)
    return {name: {"S": value} for name, value in item.items()}


def initial_control(record: ModeCanaryRecord, admitted_at: datetime) -> dict[str, Any]:
    """Returns: Control ACTIVE inicial do owner, com prazo no fixed_deadline da promoção.

    Raises: SyntheticContextRequired: Record sem fixed_deadline/geração ou relógio não UTC.
    """
    if record.fixed_deadline is None or record.promotion_generation is None:
        raise refuse("control_invalid")
    return {
        "schema": "cnesdata.mode-canary-control/v1", "owner_sha256": record.owner_sha256,
        "generation": record.promotion_generation, "context_kind": record.context_kind,
        "context_manifest_sha256": record.context_manifest_sha256,
        "admission_state": "ACTIVE", "admitted_at": stamp(admitted_at),
        "deadline": stamp(record.fixed_deadline), "sealed_at": None,
        "ledger_sha256": GENESIS_LEDGER_SHA256,
        "admitted_counts": dict.fromkeys(COUNTERS.values(), 0),
    }


@dataclass(frozen=True, slots=True)
class Effect:
    """Efeito a admitir: tipo, request, alvo, quantidade e binding do dispatch."""

    kind: str
    request_sha256: str
    target_sha256: str
    amount: int
    binding_item: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class LedgerState:
    """Leitura forte do contexto: binding, record, control e ticket do effect_id."""

    binding: ModeCanaryBinding
    record: ModeCanaryRecord
    control_text: str | None
    ticket_text: str | None


@dataclass(frozen=True, slots=True)
class Admission:
    """effect_id do ticket e TransactItems a executar; None quando já admitido."""

    effect_id: str
    items: list[dict[str, Any]] | None


def require_bound(binding: ModeCanaryBinding, record: ModeCanaryRecord,
                  holder: PermitHolder) -> None:
    """Raises: SyntheticContextRequired: run_not_bound fora do binding ou do record."""
    if not binding.permits(holder.tenant_id, holder.run_id) or holder.run_id not in record.run_ids:
        raise refuse("run_not_bound")


def dispatch_effect(binding: ModeCanaryBinding, record: ModeCanaryRecord, holder: PermitHolder,
                    unit_ids: Sequence[str]) -> Effect:
    """Returns: start-execution do dispatch com o item de binding do holder.

    Raises: SyntheticContextRequired: run_not_bound.
    """
    require_bound(binding, record, holder)
    document = {
        "schema": "cnesdata.mode-canary-binding/v1", "tenant_id": holder.tenant_id,
        "run_id": holder.run_id, "dispatch_id": holder.dispatch_id,
        "owner_sha256": binding.owner_sha256, "record_sha256": binding.record_sha256,
        "phase": binding.phase, "context_kind": binding.context_kind,
    }
    return Effect("start-execution", start_request(holder, unit_ids), digest(record.machine_arn),
                  len(unit_ids), document)


def ledger_effect(kind: str, request_sha256: str, target_sha256: str) -> Effect:
    """Returns: Efeito unitário do ledger. Raises: SyntheticContextRequired: effect_kind_invalid."""
    if kind not in EFFECT_KINDS:
        raise refuse("effect_kind_invalid")
    return Effect(kind, request_sha256, target_sha256, 1, None)


def _new_ticket(effect: Effect, control: ModeCanaryControl, record_sha256: str,
                window: tuple[datetime, datetime]) -> str:
    return canonical_text({
        "schema": "cnesdata.mode-canary-effect/v1",
        "effect_id": effect_id(record_sha256, effect.kind, effect.request_sha256),
        "owner_sha256": control.owner_sha256, "generation": control.generation,
        "context_manifest_sha256": control.context_manifest_sha256,
        "phase_record_sha256": record_sha256, "effect_kind": effect.kind,
        "request_sha256": effect.request_sha256, "target_sha256": effect.target_sha256,
        "admitted_at": stamp(window[0]), "deadline": stamp(window[1]),
        "state": "PENDING", "receipt_sha256": None,
    })


def _next_control(control_text: str, effect: Effect, ticket: str) -> str:
    control = parse_mapping(control_text, "control")
    counter = COUNTERS.get(effect.kind)
    if counter is not None:
        total = control["admitted_counts"][counter] + effect.amount
        if total > CEILINGS[control["context_kind"]][counter]:
            raise refuse("budget_exhausted")
        control["admitted_counts"] = control["admitted_counts"] | {counter: total}
    control["ledger_sha256"] = digest(canonical_text({
        "previous_ledger_sha256": control["ledger_sha256"], "ticket_sha256": digest(ticket),
    }))
    return canonical_text(control)


def _transaction(table: str, state: LedgerState, effect: Effect,
                 ticket: tuple[str, str]) -> list[dict[str, Any]]:
    identifier, text = ticket
    control_text = cast("str", state.control_text)
    owner = state.binding.owner_sha256
    pk = tenant_partition(state.binding.tenant_id)
    items = [
        put(table, _item(pk, ticket_key(owner, identifier), EFFECT_ENTITY, text),
            INSERT_ONLY, None),
        put(table, _item(pk, control_key(owner), CONTROL_ENTITY,
                         _next_control(control_text, effect, text)),
            SWAP, {":old": {"S": control_text}}),
    ]
    binding = effect.binding_item
    if binding is not None:
        sort_key = f"PROD_CANARY#{binding['dispatch_id']}"
        pk = run_partition(binding["tenant_id"], binding["run_id"])
        items.append(put(table, _item(pk, sort_key, BINDING_ENTITY, canonical_text(binding)),
                         INSERT_ONLY, None))
    return items


def admission(table: str, state: LedgerState, effect: Effect, now: datetime) -> Admission:
    """Returns: effect_id e a transação ticket+control(+binding); items None na reentrada.

    Raises: SyntheticContextRequired: Control ausente/divergente/selado, contexto vencido,
        ticket_conflict, budget_exhausted ou relógio não UTC.
    """
    record_sha256 = state.binding.record_sha256
    identifier = effect_id(record_sha256, effect.kind, effect.request_sha256)
    control = require_control(state.control_text, state.record)
    deadline = min(state.record.expires_at, state.record.canary_deadline, control.deadline)
    if now >= deadline:
        raise refuse("context_expired")
    if state.ticket_text is not None:
        existing = parse_ticket(state.ticket_text)
        if (existing.effect_kind, existing.request_sha256) != (effect.kind,
                                                               effect.request_sha256):
            raise refuse("ticket_conflict")
        return Admission(identifier, None)
    ticket = _new_ticket(effect, control, record_sha256, (now, deadline))
    return Admission(identifier, _transaction(table, state, effect, (identifier, ticket)))


def transition(table: str, binding: ModeCanaryBinding, ticket_text: str | None,
               change: tuple[str, str | None]) -> dict[str, Any] | None:
    """Returns: PutItem CAS do ticket para UNKNOWN/SETTLED; None quando já aplicado.

    Raises: SyntheticContextRequired: ticket_missing, ticket_settled ou ticket inválido.
    """
    if ticket_text is None:
        raise refuse("ticket_missing")
    ticket = parse_ticket(ticket_text)
    state, receipt = change
    if ticket.state == state and ticket.receipt_sha256 == receipt:
        return None
    if ticket.state == "SETTLED":
        raise refuse("ticket_settled")
    changed = parse_mapping(ticket_text, "ticket") | {"state": state, "receipt_sha256": receipt}
    item = _item(tenant_partition(binding.tenant_id),
                 ticket_key(binding.owner_sha256, ticket.effect_id), EFFECT_ENTITY,
                 canonical_text(changed))
    return cast("dict[str, Any]", put(table, item, SWAP, {":old": {"S": ticket_text}})["Put"])


__all__ = [
    "BINDING_ENTITY",
    "CEILINGS",
    "CONTROL_ENTITY",
    "COUNTERS",
    "EFFECT_ENTITY",
    "EFFECT_KINDS",
    "GENESIS_LEDGER_SHA256",
    "INSERT_ONLY",
    "RECORD_ENTITY",
    "SWAP",
    "TENANT_PREFIX",
    "Admission",
    "Effect",
    "LedgerState",
    "admission",
    "canonical_text",
    "control_key",
    "digest",
    "dispatch_effect",
    "effect_id",
    "initial_control",
    "ledger_effect",
    "parse_control",
    "parse_mapping",
    "parse_ticket",
    "put",
    "record_item",
    "record_key",
    "refuse",
    "require_bound",
    "require_control",
    "stamp",
    "start_request",
    "ticket_key",
    "transition",
]
