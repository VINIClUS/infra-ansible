"""Construtores puros do start nativo do unit: dispatch, item RUNDISPATCH e requests DynamoDB."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Final

from cnes_infra.aws.mode_canary_frames import refuse
from cnes_infra.control_plane.dynamodb_keys import (
    dispatch_key,
    item_key,
    key_component,
    run_entity_key,
    timestamp,
    unit_key,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from cnes_domain.orchestration.mode_canary import ModeCanaryBinding

DISPATCH_ENTITY: Final = "RUNDISPATCH"
FIRST_GENERATION: Final = 1
# Why: production pins processor_max_concurrency (the deployment limit) to 1, so the StartExecution
# input and its request_sha256 carry min(len(unit_ids), 1). Equal to processor_settings by test.
PRODUCTION_MAX_CONCURRENCY: Final = 1
# Why: copies of the product's gate and quota literals, never imported, so a moved key or field in
# the product breaks the recorder parity instead of moving the keeper with it.
FENCE_KEY: Final = ("ENV#prod#FENCE", "FENCE")
SEMAPHORE_KEY: Final = ("ENV#prod#SEMAPHORE", "UNIT")
ATTEMPTS_PARTITION: Final = "ENV#prod#ATTEMPTS"
ATTEMPT_LIMIT: Final = 200
_ATTEMPT_RETENTION: Final = timedelta(days=400)
_CANDIDATES: Final = frozenset({"PENDING", "FAILED_RETRYABLE", "LEASED"})
_SATISFIED: Final = frozenset({"SUCCEEDED", "SUCCEEDED_DEGRADED"})
_SHAPES: Final = {"RESERVED": (False, False), "STARTING": (True, False), "STARTED": (True, True)}
_SEPARATOR: Final = "\x1f"
_GATE_NAMES: Final = {
    "#entity": "entity", "#token": "token", "#updated": "updated_at",
    "#holder_tenant": "holder_tenant_id", "#holder_run": "holder_run_id",
    "#holder_dispatch": "holder_dispatch_id", "#acquired": "acquired_at", "#lease": "lease_until",
    "#execution_ref": "execution_ref", "#canary": "canary_promotion_id", "#state": "state",
    "#promotion": "promotion_id", "#generation": "generation", "#request": "request_sha256",
    "#start": "start_state",
}
_HELD: Final = "#token = :token AND attribute_exists(#holder_dispatch)"
_ACQUIRE_SET: Final = (
    "SET #entity = :entity, #holder_tenant = :tenant, #holder_run = :run, "
    "#holder_dispatch = :dispatch, #acquired = :now, #lease = :lease, #updated = :now, "
    "#canary = :canary, #generation = :generation, #request = :request, #start = :reserved "
    "ADD #token :one"
)
_CLAIM_NAMES: Final = {
    "#token": "token", "#tenant": "holder_tenant_id", "#run": "holder_run_id",
    "#dispatch": "holder_dispatch_id", "#generation": "generation", "#request": "request_sha256",
    "#fence": "fence_version", "#start": "start_state", "#initial": "initial_state",
    "#updated": "updated_at", "#canary": "canary_promotion_id", "#lease": "lease_until",
}
_CLAIM_SET: Final = (
    "SET #generation = :generation, #request = :request, #fence = :fence, "
    "#start = :starting, #initial = :reserved, #updated = :updated"
)
_CLAIM_CONDITION: Final = (
    "#token = :token AND #tenant = :tenant AND #run = :run "
    "AND #dispatch = :dispatch AND #lease > :updated AND "
    "(attribute_not_exists(#start) OR #start = :reserved) AND "
    "(attribute_not_exists(#generation) OR #generation = :generation) AND "
    "(attribute_not_exists(#request) OR #request = :request) AND "
    "(attribute_not_exists(#canary) OR #canary = :canary)"
)
_FENCE_CLAIM: Final = (
    "(attribute_not_exists(pk) AND :version = :zero) OR "
    "(#version = :version AND (#state = :open OR "
    "(#state = :closed AND #promotion = :promotion)))"
)
_ATTEMPT_CONDITION: Final = (
    "(attribute_not_exists(#count) OR #count < :limit) "
    "AND (attribute_not_exists(#ids) OR NOT contains(#ids, :id))"
)
_OPERATIONS: Final = {"get_item": "GetItem", "update_item": "UpdateItem"}
_TRANSACT: Final = {
    "ConditionCheck": "ConditionCheckItem", "Update": "UpdateItem", "Put": "PutItem",
}


@dataclass(frozen=True, slots=True)
class UnitDispatch:
    """Dispatch da primeira geração do run do unit, como a reserva nativa o grava."""

    tenant_id: str
    run_id: str
    wave_id: str
    dispatch_id: str
    unit_ids: tuple[str, ...]
    max_concurrency: int


@dataclass(frozen=True, slots=True)
class DispatchStep:
    """Estado do item RUNDISPATCH: RESERVED, STARTING com claim ou STARTED com execution_ref."""

    state: str
    lease_until: datetime
    start_claim: Mapping[str, Any] | None = None
    execution_ref: str | None = None


@dataclass(frozen=True, slots=True)
class UnitStart:
    """Start do dispatch: tabela, relógio único do estágio, lease e promoção do canário.

    Raises: SyntheticContextRequired: clock_not_utc, dispatch_lease ou dispatch_promotion.
    """

    dispatch: UnitDispatch
    table: str
    now: datetime
    lease_seconds: int
    promotion_id: str

    def __post_init__(self) -> None:
        _utc(self.now)
        if type(self.lease_seconds) is not int or self.lease_seconds < 1:
            raise refuse("dispatch_lease")
        if type(self.promotion_id) is not str or not self.promotion_id:
            raise refuse("dispatch_promotion")


@dataclass(frozen=True, slots=True)
class StartPermit:
    """Token do semáforo adquirido e versão do fence lidos depois do acquire.

    Raises: SyntheticContextRequired: dispatch_permit.
    """

    token: int
    fence_version: int

    def __post_init__(self) -> None:
        if not (type(self.token) is int and self.token >= 1
                and type(self.fence_version) is int and self.fence_version >= 0):
            raise refuse("dispatch_permit")


def unit_dispatch(locator: ModeCanaryBinding, units: Sequence[Mapping[str, Any]],
                  now: datetime) -> UnitDispatch:
    """Returns: Dispatch das unidades prontas do run do unit, com wave e dispatch_id da reserva.

    Raises: SyntheticContextRequired: dispatch_locator, dispatch_units ou clock_not_utc.
    """
    if locator.phase != "unit" or len(locator.run_ids) != 1:
        raise refuse("dispatch_locator")
    tenant, run = locator.tenant_id, locator.run_ids[0]
    if any((unit["tenant_id"], unit["run_id"]) != (tenant, run) for unit in units):
        raise refuse("dispatch_units")
    unit_ids = _ready(units, _utc(now))
    if not unit_ids:
        raise refuse("dispatch_units")
    wave = sha256(_SEPARATOR.join(unit_ids).encode()).hexdigest()[:16]
    raw = _SEPARATOR.join((tenant, run, wave, str(FIRST_GENERATION)))
    return UnitDispatch(tenant, run, wave, sha256(raw.encode()).hexdigest()[:16], unit_ids,
                        min(len(unit_ids), PRODUCTION_MAX_CONCURRENCY))


def start_execution(dispatch: UnitDispatch) -> dict[str, str]:
    """Returns: name e input do StartExecution do executor nativo para o dispatch."""
    return {"name": dispatch.dispatch_id, "input": _request_json(dispatch)}


def start_request_sha256(dispatch: UnitDispatch) -> str:
    """Returns: request_sha256 do StartRunExecution ligado ao claim do start."""
    return sha256(_request_json(dispatch).encode()).hexdigest()


def start_claim(dispatch: UnitDispatch, permit_token: int, fence_version: int,
                promotion_id: str | None) -> dict[str, Any]:
    """Returns: DispatchStartClaim do dispatch na ordem dos campos do modelo."""
    return {"dispatch_id": dispatch.dispatch_id, "generation": FIRST_GENERATION,
            "permit_token": permit_token, "fence_version": fence_version,
            "request_sha256": start_request_sha256(dispatch), "promotion_id": promotion_id}


def run_dispatch_item(dispatch: UnitDispatch, step: DispatchStep) -> dict[str, Any]:
    """Returns: Item RUNDISPATCH do adapter no estado do passo.

    Raises: SyntheticContextRequired: dispatch_state ou clock_not_utc.
    """
    shape = (step.start_claim is not None, step.execution_ref is not None)
    if _SHAPES.get(step.state) != shape:
        raise refuse("dispatch_state")
    lease = _utc(step.lease_until).isoformat().replace("+00:00", "Z")
    payload = {
        "tenant_id": dispatch.tenant_id, "run_id": dispatch.run_id,
        "wave_id": dispatch.wave_id, "dispatch_id": dispatch.dispatch_id,
        "generation": FIRST_GENERATION, "unit_ids": list(dispatch.unit_ids),
        "state": step.state, "lease_until": lease, "execution_ref": step.execution_ref,
        "terminal_outcome": None,
        "start_claim": None if step.start_claim is None else dict(step.start_claim),
        "canceled_before_send": False,
    }
    pk, sk = dispatch_key(dispatch.tenant_id, dispatch.run_id)
    index = f"RUN_ITEMS#{key_component(dispatch.tenant_id)}#{key_component(dispatch.run_id)}"
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return {"pk": {"S": pk}, "sk": {"S": sk}, "entity": {"S": DISPATCH_ENTITY},
            "payload": {"S": text}, "gsi5pk": {"S": index}, "gsi5sk": {"S": "DISPATCH#ACTIVE"}}


def step_reads(start: UnitStart, step: str) -> tuple[dict[str, Any], ...]:
    """Returns: GetItem fortes do produto no passo reserve, gate, claim ou bind, em ordem.

    Raises: SyntheticContextRequired: dispatch_step.
    """
    dispatch = start.dispatch
    tenant, run = dispatch.tenant_id, dispatch.run_id
    active, entity = dispatch_key(tenant, run), run_entity_key(tenant, run)
    units = tuple(unit_key(tenant, run, unit_id) for unit_id in dispatch.unit_ids)
    keys = {"reserve": (entity, active, *units), "gate": (FENCE_KEY, SEMAPHORE_KEY),
            "claim": (active, SEMAPHORE_KEY), "bind": (entity, active)}.get(step)
    if keys is None:
        raise refuse("dispatch_step")
    return tuple({"TableName": start.table, "Key": item_key(*key), "ConsistentRead": True}
                 for key in keys)


def reserve_request(start: UnitStart, run_item: Mapping[str, Any],
                    unit_items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Returns: TransactWriteItems da reserva: checks do RUN e dos UNIT e o Put RESERVED.

    Raises: SyntheticContextRequired: dispatch_run ou dispatch_units.
    """
    dispatch = start.dispatch
    if json.loads(_run_item(start, run_item)["payload"]["S"])["state"] != "PROCESSING":
        raise refuse("dispatch_run")
    keys = [unit_key(dispatch.tenant_id, dispatch.run_id, unit_id) for unit_id in dispatch.unit_ids]
    if len(unit_items) != len(keys) or not all(
            _keyed(item, key) for item, key in zip(unit_items, keys, strict=True)):
        raise refuse("dispatch_units")
    checks = [_check(start.table, item) for item in (run_item, *unit_items)]
    reserved = run_dispatch_item(dispatch, DispatchStep("RESERVED", _lease(start)))
    return {"TransactItems": [*checks, _put(start.table, reserved, None)]}


def acquire_request(start: UnitStart) -> dict[str, Any]:
    """Returns: TransactWriteItems do acquire: check do FENCE e update do SEMAPHORE."""
    dispatch = start.dispatch
    fence = "attribute_not_exists(pk) OR #state = :open OR #promotion = :canary"
    check = {"TableName": start.table, "Key": item_key(*FENCE_KEY), "ConditionExpression": fence,
             "ExpressionAttributeNames": _names(fence), "ExpressionAttributeValues": {
                 ":open": _text("OPEN"), ":canary": _text(start.promotion_id)}}
    values = {
        ":entity": _text("UNITSEMAPHORE"), ":tenant": _text(dispatch.tenant_id),
        ":run": _text(dispatch.run_id), ":dispatch": _text(dispatch.dispatch_id),
        ":now": _text(timestamp(start.now)), ":lease": _text(timestamp(_lease(start))),
        ":one": _number(1), ":canary": _text(start.promotion_id),
        ":generation": _number(FIRST_GENERATION),
        ":request": _text(start_request_sha256(dispatch)), ":reserved": _text("RESERVED"),
    }
    update = _gate_update(_ACQUIRE_SET, "attribute_not_exists(#holder_dispatch)", values)
    return {"TransactItems": [
        {"ConditionCheck": check},
        {"Update": {"TableName": start.table, "Key": item_key(*SEMAPHORE_KEY), **update}},
    ]}


def attempt_request(start: UnitStart) -> dict[str, Any]:
    """Returns: UpdateItem do ADD condicional da tentativa no mês UTC do relógio do estágio."""
    now, dispatch_id = start.now, start.dispatch.dispatch_id
    month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return {
        "TableName": start.table,
        "Key": item_key(ATTEMPTS_PARTITION, f"MONTH#{now.year:04d}-{now.month:02d}"),
        "UpdateExpression": "SET #entity = :entity, #expires = :expires ADD #count :one, "
                            "#ids :idset",
        "ConditionExpression": _ATTEMPT_CONDITION,
        "ExpressionAttributeNames": {"#entity": "entity", "#expires": "expires_at",
                                     "#count": "attempts", "#ids": "dispatch_ids"},
        "ExpressionAttributeValues": {
            ":entity": _text("EXECUTIONATTEMPTS"),
            ":expires": _number(int((month + _ATTEMPT_RETENTION).timestamp())),
            ":one": _number(1), ":idset": {"SS": [dispatch_id]}, ":id": _text(dispatch_id),
            ":limit": _number(ATTEMPT_LIMIT)},
        "ReturnValues": "ALL_OLD",
        "ReturnValuesOnConditionCheckFailure": "ALL_OLD",
    }


def claim_request(start: UnitStart, permit: StartPermit) -> dict[str, Any]:
    """Returns: TransactWriteItems do claim: check do FENCE, update do SEMAPHORE e Put STARTING."""
    dispatch = start.dispatch
    claim = start_claim(dispatch, permit.token, permit.fence_version, start.promotion_id)
    fence = {"TableName": start.table, "Key": item_key(*FENCE_KEY),
             "ConditionExpression": _FENCE_CLAIM, "ExpressionAttributeNames": {
                 "#state": "state", "#promotion": "promotion_id", "#version": "version"},
             "ExpressionAttributeValues": {
                 ":version": _number(permit.fence_version), ":zero": _number(0),
                 ":open": _text("OPEN"), ":closed": _text("CLOSED"),
                 ":promotion": _text(start.promotion_id)}}
    values = {
        ":token": _number(permit.token), ":tenant": _text(dispatch.tenant_id),
        ":run": _text(dispatch.run_id), ":dispatch": _text(dispatch.dispatch_id),
        ":generation": _number(FIRST_GENERATION), ":request": _text(claim["request_sha256"]),
        ":fence": _number(permit.fence_version), ":starting": _text("STARTING"),
        ":reserved": _text("RESERVED"), ":updated": _text(start.now.isoformat()),
        ":canary": _text(start.promotion_id),
    }
    semaphore = {"TableName": start.table, "Key": item_key(*SEMAPHORE_KEY),
                 "UpdateExpression": _CLAIM_SET, "ConditionExpression": _CLAIM_CONDITION,
                 "ExpressionAttributeNames": _CLAIM_NAMES, "ExpressionAttributeValues": values}
    reserved = run_dispatch_item(dispatch, DispatchStep("RESERVED", _lease(start)))
    starting = run_dispatch_item(dispatch, DispatchStep("STARTING", _lease(start), claim))
    return {"TransactItems": [{"ConditionCheck": fence}, {"Update": semaphore},
                              _put(start.table, starting, reserved["payload"]["S"])]}


def bind_request(start: UnitStart, permit: StartPermit, execution_ref: str,
                 run_item: Mapping[str, Any]) -> dict[str, Any]:
    """Returns: TransactWriteItems do bind: check do RUN e Put STARTED sobre o STARTING.

    Raises: SyntheticContextRequired: dispatch_run.
    """
    dispatch = start.dispatch
    claim = start_claim(dispatch, permit.token, permit.fence_version, start.promotion_id)
    starting = run_dispatch_item(dispatch, DispatchStep("STARTING", _lease(start), claim))
    started = run_dispatch_item(
        dispatch, DispatchStep("STARTED", _lease(start), claim, execution_ref))
    return {"TransactItems": [_check(start.table, _run_item(start, run_item)),
                              _put(start.table, started, starting["payload"]["S"])]}


def confirm_requests(start: UnitStart, permit: StartPermit,
                     execution_ref: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns: UpdateItem de bind_unit_permit e de renew_unit_permit do confirm, em ordem."""
    bound = "(attribute_not_exists(#execution_ref) OR #execution_ref = :ref)"
    now, token = _text(timestamp(start.now)), _number(permit.token)
    bind = _gate_update(
        "SET #execution_ref = :ref, #updated = :now, #start = :started", f"{_HELD} AND {bound}",
        {":token": token, ":ref": _text(execution_ref), ":started": _text("STARTED"),
         ":now": now})
    renew = _gate_update("SET #lease = :lease, #updated = :now", _HELD, {
        ":token": token, ":lease": _text(timestamp(_lease(start))), ":now": now})
    key = {"TableName": start.table, "Key": item_key(*SEMAPHORE_KEY)}
    return key | bind, key | renew


def request_targets(
    requests: Iterable[Sequence[Any]],
) -> tuple[tuple[str, str, str, str], ...]:
    """Returns: (ação IAM, tabela, pk, sk) ordenados e únicos dos requests (operação, kwargs).

    Raises: SyntheticContextRequired: dispatch_request.
    """
    targets: set[tuple[str, str, str, str]] = set()
    for operation, request in requests:
        if operation == "transact_write_items":
            targets.update(_target(_TRANSACT.get(kind), body)
                           for action in request["TransactItems"] for kind, body in action.items())
        else:
            targets.add(_target(_OPERATIONS.get(operation), request))
    return tuple(sorted(targets))


def _target(action: str | None, request: Mapping[str, Any]) -> tuple[str, str, str, str]:
    if action is None:
        raise refuse("dispatch_request")
    key = request["Key"] if "Key" in request else request["Item"]
    return action, request["TableName"], key["pk"]["S"], key["sk"]["S"]


def _utc(moment: datetime) -> datetime:
    if moment.utcoffset() != timedelta(0):
        raise refuse("clock_not_utc")
    return moment


def _lease(start: UnitStart) -> datetime:
    return start.now + timedelta(seconds=start.lease_seconds)


def _text(value: str) -> dict[str, str]:
    return {"S": value}


def _number(value: int) -> dict[str, str]:
    return {"N": str(value)}


def _names(*expressions: str) -> dict[str, str]:
    used = " ".join(expressions)
    return {placeholder: name for placeholder, name in _GATE_NAMES.items() if placeholder in used}


def _gate_update(expression: str, condition: str,
                 values: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {"UpdateExpression": expression, "ConditionExpression": condition,
            "ExpressionAttributeNames": _names(expression, condition),
            "ExpressionAttributeValues": values}


def _keyed(item: Mapping[str, Any], key: tuple[str, str]) -> bool:
    return item.get("pk") == _text(key[0]) and item.get("sk") == _text(key[1])


def _run_item(start: UnitStart, item: Mapping[str, Any]) -> Mapping[str, Any]:
    if not _keyed(item, run_entity_key(start.dispatch.tenant_id, start.dispatch.run_id)):
        raise refuse("dispatch_run")
    return item


def _check(table: str, item: Mapping[str, Any]) -> dict[str, Any]:
    return {"ConditionCheck": {
        "TableName": table, "Key": {"pk": item["pk"], "sk": item["sk"]},
        "ConditionExpression": "payload = :expected",
        "ExpressionAttributeValues": {":expected": item["payload"]}}}


def _put(table: str, item: dict[str, Any], expected: str | None) -> dict[str, Any]:
    if expected is None:
        return {"Put": {"TableName": table, "Item": item,
                        "ConditionExpression": "attribute_not_exists(pk)"}}
    return {"Put": {"TableName": table, "Item": item, "ConditionExpression": "payload = :expected",
                    "ExpressionAttributeValues": {":expected": _text(expected)}}}


def _live(unit: Mapping[str, Any], now: datetime) -> bool:
    lease = unit["lease_until"]
    return unit["state"] == "LEASED" and lease is not None and datetime.fromisoformat(lease) > now


def _dependency_state(states: Mapping[str, str], dependency: str) -> str:
    # Why: the planner indexes by_id[dependency] and raises KeyError, so a ghost fails closed.
    if dependency not in states:
        raise refuse("dispatch_units")
    return states[dependency]


def _ready(units: Sequence[Mapping[str, Any]], now: datetime) -> tuple[str, ...]:
    if any(_live(unit, now) for unit in units):
        return ()
    states = {unit["unit_id"]: unit["state"] for unit in units}
    return tuple(sorted(
        unit["unit_id"] for unit in units if unit["state"] in _CANDIDATES
        and all(_dependency_state(states, dependency) in _SATISFIED
                for dependency in unit["depends_on_unit_ids"])
    ))


def _request_json(dispatch: UnitDispatch) -> str:
    return json.dumps({
        "tenant_id": dispatch.tenant_id, "run_id": dispatch.run_id, "wave_id": dispatch.wave_id,
        "dispatch_id": dispatch.dispatch_id, "unit_ids": list(dispatch.unit_ids),
        "max_concurrency": dispatch.max_concurrency,
    }, separators=(",", ":"), sort_keys=True)


__all__ = [
    "ATTEMPTS_PARTITION",
    "ATTEMPT_LIMIT",
    "DISPATCH_ENTITY",
    "FENCE_KEY",
    "FIRST_GENERATION",
    "PRODUCTION_MAX_CONCURRENCY",
    "SEMAPHORE_KEY",
    "DispatchStep",
    "StartPermit",
    "UnitDispatch",
    "UnitStart",
    "acquire_request",
    "attempt_request",
    "bind_request",
    "claim_request",
    "confirm_requests",
    "request_targets",
    "reserve_request",
    "run_dispatch_item",
    "start_claim",
    "start_execution",
    "start_request_sha256",
    "step_reads",
    "unit_dispatch",
]
