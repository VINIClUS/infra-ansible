"""Valores imutáveis e serialização canônica do kernel puro de bootstrap."""

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Any, Self

from tools.aws_bootstrap.validation import validate_record


def freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(child) for child in value)
    return value


def plain(value: Any) -> Any:
    if isinstance(value, _FrozenRecord):
        return plain(value.as_mapping())
    if isinstance(value, Mapping):
        return {key: plain(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(child) for child in value]
    return value


def canonical(value: Any) -> bytes:
    """Retorna bytes JSON UTF-8 canônicos, recusando números não finitos."""
    return json.dumps(plain(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    """Retorna SHA256 dos bytes canônicos do valor recebido."""
    return sha256(canonical(value)).hexdigest()


@dataclass(frozen=True)
class _FrozenRecord:
    _values: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Self:
        """Retorna uma cópia imutável do mapping recebido."""
        invalid = False
        try:
            validate_record(cls.__name__, value)
            canonical(value)
        except (ValueError, TypeError, RecursionError, OverflowError):
            invalid = True
        if invalid:
            raise ValueError("invalid_bootstrap_input")
        return cls(freeze(value))

    def as_mapping(self) -> Mapping[str, Any]:
        """Retorna o conteúdo imutável completo do record."""
        return self._values

    def __getattr__(self, name: str) -> Any:
        try:
            return self._values[name]
        except KeyError as error:
            raise AttributeError(name) from error


@dataclass(frozen=True)
class BootstrapSpec(_FrozenRecord):
    """Preserva o spec completo e isolado do mapping do chamador."""


@dataclass(frozen=True)
class Readback(_FrozenRecord):
    """Transporta os fatos completos sem autenticar sua origem."""


@dataclass(frozen=True)
class BootstrapPlan(_FrozenRecord):
    """Preserva o resultado inerte profundamente imutável do planejamento."""


@dataclass(frozen=True)
class Checkpoint(_FrozenRecord):
    """Preserva estrutura e história recebidas sem validar sua semântica."""
