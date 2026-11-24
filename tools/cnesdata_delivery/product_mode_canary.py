"""Namespace reservado e binding imutável do canary de modo."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Final, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from cnes_domain.control_plane.environment_gate import PermitHolder

TENANT_PREFIX: Final = "prod-canary-"
MAX_SELECTED_RUNS: Final = 2
PHASES: Final = frozenset({"unit", "recovery", "audit", "readiness"})
CONTEXT_KINDS: Final = frozenset({"promotion", "readiness"})
_CANONICAL_TENANT: Final = re.compile(r"prod-canary-[0-9a-f]{32}")
_SHA256: Final = re.compile(r"[0-9a-f]{64}")


class SyntheticContextRequired(ValueError):
    """Tenant do namespace sintético sem contexto autorizado instalado."""


@dataclass(frozen=True, slots=True)
class ModeCanaryGrant:
    """Autorização de admissão de um holder sintético; promotion_id é None fora de promoção."""

    promotion_id: str | None


class ModeCanaryAdmissionProvider(Protocol):
    """Provider fechado do contexto; recusa o holder fora dele com SyntheticContextRequired."""

    def binding_for(self, holder: PermitHolder, now: datetime) -> ModeCanaryGrant:
        raise NotImplementedError


def is_mode_canary_namespace(tenant_id: str) -> bool:
    """Returns: True se o tenant usa o prefixo reservado, em qualquer caixa ou sufixo."""
    return tenant_id.lower().startswith(TENANT_PREFIX)


def is_canonical_mode_canary_tenant(tenant_id: str) -> bool:
    """Returns: True somente para a forma `prod-canary-<32 hex minúsculos>`."""
    return _CANONICAL_TENANT.fullmatch(tenant_id) is not None


def require_normal_tenant(tenant_id: str) -> None:
    """Raises: SyntheticContextRequired: Tenant do namespace reservado, `field=tenant_id`."""
    if is_mode_canary_namespace(tenant_id):
        raise SyntheticContextRequired("reason=synthetic_context_required field=tenant_id")


def require_context(binding: ModeCanaryBinding | None, tenant_id: str, run_id: str) -> None:
    """Raises: SyntheticContextRequired: Namespace reservado fora do binding instalado."""
    if not is_mode_canary_namespace(tenant_id):
        return
    if binding is None or not binding.permits(tenant_id, run_id):
        raise SyntheticContextRequired("reason=synthetic_context_required field=tenant_id")


def _reject(field: str) -> ValueError:
    return ValueError(f"reason=invalid field={field}")


type _Check = Callable[[Any], Any]


def _invalid() -> ValueError:
    return ValueError("reason=invalid")


def _hex(length: int) -> _Check:
    pattern = re.compile(f"[0-9a-f]{{{length}}}")

    def check(value: Any) -> str:
        if type(value) is not str or pattern.fullmatch(value) is None:
            raise _invalid()
        return value

    return check


def _text(value: Any) -> str:
    if type(value) is not str or not value:
        raise _invalid()
    return value


def _const(expected: str) -> _Check:
    def check(value: Any) -> str:
        if value != expected:
            raise _invalid()
        return expected

    return check


def _enum(options: frozenset[str]) -> _Check:
    def check(value: Any) -> str:
        if type(value) is not str or value not in options:
            raise _invalid()
        return value

    return check


def _int(minimum: int) -> _Check:
    def check(value: Any) -> int:
        if type(value) is not int or value < minimum:
            raise _invalid()
        return value

    return check


def _utc(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise _invalid() from error
    if parsed.utcoffset() != timedelta(0):
        raise _invalid()
    return parsed


def _nullable(check: _Check) -> _Check:
    def nullable(value: Any) -> Any:
        return None if value is None else check(value)

    return nullable


def _as_dict(value: Any) -> dict[str, Any] | None:
    return cast("dict[str, Any]", value) if type(value) is dict else None


def _as_list(value: Any) -> list[Any] | None:
    return cast("list[Any]", value) if type(value) in (list, tuple) else None


def _unique_texts(minimum: int, maximum: int) -> _Check:
    def check(value: Any) -> tuple[str, ...]:
        sequence = _as_list(value)
        if sequence is None or not minimum <= len(sequence) <= maximum:
            raise _invalid()
        items = tuple(_text(item) for item in sequence)
        if len(set(items)) != len(items):
            raise _invalid()
        return items

    return check


def _exact_map(names: tuple[str, ...], check: _Check) -> _Check:
    def exact(value: Any) -> dict[str, Any]:
        mapping = _as_dict(value)
        if mapping is None or set(mapping) != set(names):
            raise _invalid()
        return {name: check(mapping[name]) for name in names}

    return exact


def _closed(mapping: Any, spec: Mapping[str, _Check], kind: str) -> dict[str, Any]:
    source = _as_dict(mapping)
    if source is None or set(source) != set(spec):
        raise ValueError(f"reason=fields_mismatch kind={kind}")
    checked: dict[str, Any] = {}
    for name, check in spec.items():
        try:
            checked[name] = check(source[name])
        except ValueError as error:
            raise _reject(name) from error
    return checked


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("reason=duplicate_key")
        result[key] = value
    return result


def _load_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text, object_pairs_hook=_unique_pairs)
    except json.JSONDecodeError as error:
        raise ValueError("reason=invalid_json") from error
    result = _as_dict(value)
    if result is None:
        raise ValueError("reason=invalid_json")
    return result


def _expect(condition: bool, field: str) -> None:
    if not condition:
        raise _reject(field)


_SHA64: Final = _hex(64)
_LOCATOR_FIELDS: Final[dict[str, _Check]] = {
    "tenant_id": _text, "run_ids": _unique_texts(1, MAX_SELECTED_RUNS),
    "owner_sha256": _SHA64, "record_sha256": _SHA64, "phase": _text, "context_kind": _text,
}


@dataclass(frozen=True, slots=True)
class ModeCanaryBinding:
    """Locator validado do contexto sintético; não autoriza efeitos sozinho."""

    tenant_id: str
    run_ids: tuple[str, ...]
    owner_sha256: str
    record_sha256: str
    phase: str
    context_kind: str

    def __post_init__(self) -> None:
        """Raises: ValueError: Campo fora do formato fechado, `field=<nome>`."""
        if not is_canonical_mode_canary_tenant(self.tenant_id):
            raise _reject("tenant_id")
        if not self._valid_run_ids():
            raise _reject("run_ids")
        for field in ("owner_sha256", "record_sha256"):
            if _SHA256.fullmatch(getattr(self, field)) is None:
                raise _reject(field)
        if self.phase not in PHASES:
            raise _reject("phase")
        if self.context_kind not in CONTEXT_KINDS:
            raise _reject("context_kind")

    def _valid_run_ids(self) -> bool:
        ids = self.run_ids
        return (
            type(ids) is tuple
            and 1 <= len(ids) <= MAX_SELECTED_RUNS
            and len(set(ids)) == len(ids)
            and all(type(run_id) is str and run_id for run_id in ids)
        )

    @classmethod
    def from_locator(cls, text: str) -> ModeCanaryBinding:
        """Raises: ValueError: JSON inválido, duplicado, com campos fora do fechado ou inválidos."""
        fields = _closed(_load_object(text), _LOCATOR_FIELDS, "locator")
        return cls(
            tenant_id=fields["tenant_id"], run_ids=fields["run_ids"],
            owner_sha256=fields["owner_sha256"], record_sha256=fields["record_sha256"],
            phase=fields["phase"], context_kind=fields["context_kind"],
        )

    def permits(self, tenant_id: str, run_id: str) -> bool:
        """Returns: True se o par tenant/run consta do binding."""
        return tenant_id == self.tenant_id and run_id in self.run_ids


_MODES: Final = frozenset({"unit", "recovery", "audit"})
_PROMOTION_PHASES: Final = _MODES
_SCENARIO_FAULTS: Final = {
    "unit_wave": ("none",),
    "recovery_resume": ("none",),
    "recovery_overlap_a": ("none",),
    "recovery_overlap_b": ("none",),
    "recovery_failure": ("synthetic_read_failure",),
    "recovery_deadline": ("hang_no_dispatch",),
    "audit_delivery": ("none",),
    "readiness_pipeline": ("none",),
    "readiness_hang_first": ("hang_no_dispatch",),
    "readiness_hang_second": ("hang_no_dispatch",),
    "readiness_periodic_audit": ("none",),
}
_REVISIONS: Final = ("unit", "recovery", "audit")
_COUNTERS: Final = ("unit_tasks", "recovery_resumes", "recovery_hangs")
_RECORD_FIELDS: Final[dict[str, _Check]] = {
    "schema": _const("cnesdata.mode-canary/v2"),
    "activation_sha256": _SHA64, "candidate_sha256": _SHA64, "source_sha": _hex(40),
    "release_id": _text, "canary_id": _hex(32), "owner_sha256": _SHA64,
    "promotion_id": _nullable(_text), "promotion_generation": _nullable(_int(1)),
    "phase_receipt_sha256": _SHA64, "machine_arn": _text,
    "revisions": _exact_map(_REVISIONS, _text),
    "run_ids": _unique_texts(1, MAX_SELECTED_RUNS),
    "fixture_manifest_sha256": _SHA64, "seed_manifest_sha256": _SHA64,
    "fixed_deadline": _nullable(_utc), "stage_deadline": _utc, "canary_deadline": _utc,
    "phase": _enum(PHASES), "freeze_policy_sha256": _SHA64, "expires_at": _utc,
    "context_kind": _enum(CONTEXT_KINDS), "context_manifest_sha256": _SHA64,
    "scenario": _enum(frozenset(_SCENARIO_FAULTS)),
    "fault": _enum(frozenset({"none", "synthetic_read_failure", "hang_no_dispatch"})),
    "mode": _enum(_MODES),
}
_CONTROL_FIELDS: Final[dict[str, _Check]] = {
    "schema": _const("cnesdata.mode-canary-control/v1"), "owner_sha256": _SHA64,
    "generation": _int(1), "context_kind": _enum(CONTEXT_KINDS),
    "context_manifest_sha256": _SHA64, "admission_state": _enum(frozenset({"ACTIVE", "SEALED"})),
    "admitted_at": _utc, "deadline": _utc, "sealed_at": _nullable(_utc), "ledger_sha256": _SHA64,
    "admitted_counts": _exact_map(_COUNTERS, _int(0)),
}
_TICKET_FIELDS: Final[dict[str, _Check]] = {
    "schema": _const("cnesdata.mode-canary-effect/v1"), "effect_id": _SHA64,
    "owner_sha256": _SHA64, "generation": _int(1), "context_manifest_sha256": _SHA64,
    "phase_record_sha256": _SHA64,
    "effect_kind": _enum(frozenset({
        "native-mutation", "start-execution", "run-recovery", "run-hang", "settle-permit",
    })),
    "request_sha256": _SHA64, "target_sha256": _SHA64, "admitted_at": _utc, "deadline": _utc,
    "state": _enum(frozenset({"PENDING", "UNKNOWN", "SETTLED"})),
    "receipt_sha256": _nullable(_SHA64),
}


def _check_record_context(record: dict[str, Any]) -> None:
    promotion = record["context_kind"] == "promotion"
    scenario = record["scenario"]
    _expect(scenario.startswith("readiness_") is not promotion, "scenario")
    _expect(record["fault"] in _SCENARIO_FAULTS[scenario], "fault")
    if promotion:
        _expect(record["phase"] in _PROMOTION_PHASES, "phase")
        _expect(record["mode"] == record["phase"], "mode")
        _expect(record["fixed_deadline"] is not None, "fixed_deadline")
        _expect(record["promotion_id"] is not None, "promotion_id")
        _expect(record["promotion_generation"] is not None, "promotion_generation")
        ceiling = min(record["fixed_deadline"], record["stage_deadline"])
        _expect(record["canary_deadline"] <= ceiling, "canary_deadline")
        return
    _expect(record["phase"] == "readiness", "phase")
    _expect(record["fixed_deadline"] is None, "fixed_deadline")
    _expect(record["promotion_id"] is None, "promotion_id")
    _expect(record["promotion_generation"] is None, "promotion_generation")
    _expect(record["canary_deadline"] == record["stage_deadline"], "canary_deadline")


@dataclass(frozen=True, slots=True)
class ModeCanaryRecord:
    """Registro imutável da fase; só vale com o control item ativo do mesmo contexto."""

    schema: str
    activation_sha256: str
    candidate_sha256: str
    source_sha: str
    release_id: str
    canary_id: str
    owner_sha256: str
    promotion_id: str | None
    promotion_generation: int | None
    phase_receipt_sha256: str
    machine_arn: str
    revisions: dict[str, str]
    run_ids: tuple[str, ...]
    fixture_manifest_sha256: str
    seed_manifest_sha256: str
    fixed_deadline: datetime | None
    stage_deadline: datetime
    canary_deadline: datetime
    phase: str
    freeze_policy_sha256: str
    expires_at: datetime
    context_kind: str
    context_manifest_sha256: str
    scenario: str
    fault: str
    mode: str

    @classmethod
    def from_mapping(cls, mapping: Any) -> ModeCanaryRecord:
        """Raises: ValueError: Campos fora dos 26 fechados, valor inválido ou união violada."""
        checked = _closed(mapping, _RECORD_FIELDS, "record")
        _check_record_context(checked)
        return cls(**checked)


@dataclass(frozen=True, slots=True)
class ModeCanaryControl:
    """Item de controle do contexto; ACTIVE admite efeitos, SEALED só quiescência."""

    schema: str
    owner_sha256: str
    generation: int
    context_kind: str
    context_manifest_sha256: str
    admission_state: str
    admitted_at: datetime
    deadline: datetime
    sealed_at: datetime | None
    ledger_sha256: str
    admitted_counts: dict[str, int]

    @classmethod
    def from_mapping(cls, mapping: Any) -> ModeCanaryControl:
        """Raises: ValueError: Campos fora do fechado, estado e sealed_at incoerentes."""
        checked = _closed(mapping, _CONTROL_FIELDS, "control")
        _expect((checked["admission_state"] == "SEALED") is (checked["sealed_at"] is not None),
                "sealed_at")
        _expect(checked["deadline"] > checked["admitted_at"], "deadline")
        return cls(**checked)


@dataclass(frozen=True, slots=True)
class SyntheticEffectTicket:
    """Ticket admitido antes de qualquer efeito sintético; reentrada o reutiliza."""

    schema: str
    effect_id: str
    owner_sha256: str
    generation: int
    context_manifest_sha256: str
    phase_record_sha256: str
    effect_kind: str
    request_sha256: str
    target_sha256: str
    admitted_at: datetime
    deadline: datetime
    state: str
    receipt_sha256: str | None

    @classmethod
    def from_mapping(cls, mapping: Any) -> SyntheticEffectTicket:
        """Raises: ValueError: Campos fora do fechado ou ticket liquidado sem recibo."""
        checked = _closed(mapping, _TICKET_FIELDS, "ticket")
        _expect(checked["state"] != "SETTLED" or checked["receipt_sha256"] is not None,
                "receipt_sha256")
        _expect(checked["deadline"] > checked["admitted_at"], "deadline")
        return cls(**checked)


@dataclass(frozen=True, slots=True)
class AuditObserveLocator:
    """Override observacional da task audit; não habilita trabalho nem altera cursor."""

    event_ids: tuple[str, ...]
    owner_sha256: str
    record_sha256: str

    @classmethod
    def from_json(cls, text: str) -> AuditObserveLocator:
        """Raises: ValueError: JSON inválido, campos fora do fechado ou ids repetidos."""
        fields = _closed(_load_object(text), _AUDIT_LOCATOR_FIELDS, "audit_locator")
        return cls(**fields)


_AUDIT_LOCATOR_FIELDS: Final[dict[str, _Check]] = {
    "event_ids": _unique_texts(1, 100), "owner_sha256": _SHA64, "record_sha256": _SHA64,
}


__all__ = [
    "CONTEXT_KINDS",
    "MAX_SELECTED_RUNS",
    "PHASES",
    "TENANT_PREFIX",
    "AuditObserveLocator",
    "ModeCanaryAdmissionProvider",
    "ModeCanaryBinding",
    "ModeCanaryControl",
    "ModeCanaryGrant",
    "ModeCanaryRecord",
    "SyntheticContextRequired",
    "SyntheticEffectTicket",
    "is_canonical_mode_canary_tenant",
    "is_mode_canary_namespace",
    "require_context",
    "require_normal_tenant",
]
