"""Transporte local dos quatro pares literais foundation, sem decisões do planner."""

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from hashlib import sha256
import json
from pathlib import Path


DATA = Path(__file__).with_name("cnesdata_bootstrap_foundation_plan")


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def digest(value):
    return sha256(canonical(value)).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key=" + key)
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("nonfinite=" + value)


def _expand(value, seen):
    if isinstance(value, dict):
        if "$include" in value:
            if set(value) != {"$include"}:
                raise ValueError("mixed_include_directive")
            return _load(value["$include"], seen)
        return {key: _expand(child, seen) for key, child in value.items()}
    if isinstance(value, list):
        return [_expand(child, seen) for child in value]
    return value


def _bundle_path(relative):
    path = (DATA / relative).resolve()
    if Path(relative).is_absolute() or not path.is_relative_to(DATA.resolve()):
        raise ValueError("outside_bundle=" + relative)
    return path


def _load(relative, seen=()):
    path = _bundle_path(relative)
    if relative in seen:
        raise ValueError("invalid_include=" + relative)
    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object,
        parse_constant=_invalid_constant,
    )
    return _expand(value, seen + (relative,))


def _ensure_materialized(value):
    if isinstance(value, dict):
        if "$include" in value:
            raise ValueError("unexpanded_include")
        for child in value.values():
            _ensure_materialized(child)
    if isinstance(value, list):
        for child in value:
            _ensure_materialized(child)


def load_case(name):
    """Retorna o input e os companions expandidos, preservando o oráculo literal."""
    descriptor = _load("bundle.json")["cases"][name]
    case = {key: _load(descriptor[key]) for key in (
        "input", "expected", "before_manifest", "after_manifest",
    )}
    _ensure_materialized(case)
    binary = descriptor["binary_artifact"]
    case["binary_bytes"] = None if binary is None else _bundle_path(binary).read_bytes()
    return case


def plain(value):
    if isinstance(value, Mapping):
        return {key: plain(child) for key, child in value.items()}
    if is_dataclass(value):
        return {item.name: plain(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, (tuple, list)):
        return [plain(child) for child in value]
    return value


def field(value, name):
    return value[name] if isinstance(value, Mapping) else getattr(value, name)


@dataclass(frozen=True)
class LoadedCase:
    name: str
    payload: dict

    @property
    def input(self):
        return self.payload["input"]

    @property
    def expected(self):
        return self.payload["expected"]
