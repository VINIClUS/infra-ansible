"""Reusable workflows must declare every secret they read."""

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
SECRET_READ = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")
GOVERNED = (
    "reusable-cnesdata-application-gate.yml",
    "reusable-cnesdata-infra-plan-gate.yml",
    "reusable-cnesdata-infra-deploy-gate.yml",
    "reusable-cnesdata-signing-gate.yml",
)


def _declared(path: Path) -> dict:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    triggers = document.get("on", document.get(True))
    return (triggers["workflow_call"] or {}).get("secrets") or {}


def _reusables() -> list[Path]:
    return sorted(
        path
        for path in WORKFLOWS.glob("reusable-*.yml")
        if "workflow_call" in (yaml.safe_load(path.read_text("utf-8")).get("on")
                               or yaml.safe_load(path.read_text("utf-8")).get(True))
    )


def test_ha_reusables_cnesdata_para_cobrir() -> None:
    names = {path.name for path in _reusables()}
    assert set(GOVERNED) <= names
    assert "reusable-cnesdata-host-deploy-gate.yml" in names


@pytest.mark.parametrize("path", _reusables(), ids=lambda path: path.name)
def test_reusable_declara_todo_secret_que_le(path: Path) -> None:
    read = set(SECRET_READ.findall(path.read_text(encoding="utf-8")))
    assert read <= set(_declared(path)), sorted(read - set(_declared(path)))


@pytest.mark.parametrize("name", GOVERNED)
def test_secret_de_governanca_e_obrigatorio(name: str) -> None:
    declared = _declared(WORKFLOWS / name)
    assert declared["CNESDATA_DELIVERY_GOVERNANCE"]["required"] is True
