"""Caracterização pública de ausência coerente e permissão create em foundation."""

from copy import deepcopy
from typing import Any

import pytest

from fixtures.cnesdata_bootstrap_foundation_case import digest, field, load_case, plain
from test_cnesdata_bootstrap_validation_privacy import _executar_duas_vezes
from tools.aws_bootstrap.contract import BootstrapPlan


ADDRESS = "aws_kms_key.foundation"
SNAPSHOT_FIELDS = ("exact_id", "owner", "tags", "attributes", "policy_documents")
CONTRADICTIONS = (
    ("exact_id", "synthetic-key-id"),
    ("owner", "synthetic-owner"),
    ("tags", {"Synthetic": "present"}),
    ("attributes", {"synthetic": True}),
    ("policy_documents", [{"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
        "Action": "kms:DescribeKey", "Resource": "*",
    }]}]),
)


def _entrada_enabled() -> dict[str, Any]:
    entrada = load_case("enabled")["input"]
    assert isinstance(entrada, dict)
    return entrada


def _snapshot(observation: dict[str, Any]) -> dict[str, Any]:
    return {"status": observation["observation_status"],
            **{name: observation[name] for name in SNAPSHOT_FIELDS}}


def _reatar_stage(entrada: dict[str, Any]) -> None:
    spec, facts = entrada["spec"], entrada["facts"]
    initial, stage = facts["authorizations"]["initial"], facts["authorizations"]["stage"]
    stage["authority_sha256"] = digest(initial)
    stage["step_sha256"] = digest(spec["step"])
    stage["before_manifest_sha256"] = digest({
        "run_sha256": digest(spec["run"]), "root_id": "foundation",
        "observed_at": facts["observed_at"], "resources": facts["resources"]["foundation"],
    })
    facts["verified_authorization_sha256"] = [digest(initial), digest(stage)]


def _alterar_ausencia(entrada: dict[str, Any], campo: str, valor: Any) -> None:
    facts = entrada["facts"]
    observation = facts["resources"]["foundation"][ADDRESS]
    source = facts["evidence"].pop(observation["source_evidence_sha256"])
    observation[campo] = deepcopy(valor)
    source["observation"] = _snapshot(observation)
    source_hash = digest(source)
    observation["source_evidence_sha256"] = source_hash
    facts["evidence"][source_hash] = source
    _reatar_stage(entrada)


def _conferir_integridade(entrada: dict[str, Any]) -> None:
    spec, facts = entrada["spec"], entrada["facts"]
    initial, stage = facts["authorizations"]["initial"], facts["authorizations"]["stage"]
    assert initial["roots"] == spec["run"]["roots"]
    assert initial["run_sha256"] == stage["run_sha256"] == digest(spec["run"])
    assert stage["authority_sha256"] == digest(initial)
    assert stage["step_sha256"] == digest(spec["step"])
    assert stage["binary_plan_sha256"] == spec["step"]["binary_plan_sha256"] is not None
    assert set(facts["verified_authorization_sha256"]) == {digest(initial), digest(stage)}
    assert stage["not_before"] == spec["step"]["not_before"]
    assert stage["expires_at"] == spec["step"]["expires_at"]
    assert set(facts["resources"]) == {"foundation"}
    resources = facts["resources"]["foundation"]
    assert len(resources) == 22
    assert set(resources) == set(spec["run"]["roots"]["foundation"]["resources"])
    assert set(initial["allowed_resource_actions"]["foundation"]) == set(resources)
    assert set(facts["evidence"]) == {item["source_evidence_sha256"] for item in resources.values()}
    before = {"run_sha256": digest(spec["run"]), "root_id": "foundation",
              "observed_at": facts["observed_at"], "resources": resources}
    assert stage["before_manifest_sha256"] == digest(before)
    for address, observation in resources.items():
        source_hash = observation["source_evidence_sha256"]
        source = facts["evidence"][source_hash]
        assert digest(source) == source_hash
        assert source["kind"] == "resource_observation"
        assert source["run_sha256"] == digest(spec["run"])
        assert source["root_id"] == "foundation" and source["address"] == address
        assert source["observed_at"] == observation["observed_at"] == facts["observed_at"]
        assert source["observation"] == _snapshot(observation)


def _exigir_bloqueio(plano: BootstrapPlan, motivo: str) -> None:
    assert field(plano, "status") == "blocked"
    assert plain(field(plano, "operations")) == []
    assert plain(field(plano, "blocked_reasons")) == [motivo]


@pytest.mark.parametrize("campo,valor", CONTRADICTIONS, ids=SNAPSHOT_FIELDS)
def test_ausencia_contraditoria_bloqueia_mesmo_com_evidencia_e_grants_coerentes(
    campo: str, valor: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = _entrada_enabled()
    anterior = deepcopy(entrada)
    _alterar_ausencia(entrada, campo, valor)
    observation = entrada["facts"]["resources"]["foundation"][ADDRESS]
    original = anterior["facts"]["resources"]["foundation"][ADDRESS]
    assert observation["observation_status"] == "absent"
    assert [name for name in SNAPSHOT_FIELDS if observation[name] != original[name]] == [campo]
    assert entrada["spec"] == anterior["spec"]
    assert entrada["facts"]["authorizations"]["initial"] == (
        anterior["facts"]["authorizations"]["initial"]
    )
    _conferir_integridade(entrada)
    plano = _executar_duas_vezes(entrada, monkeypatch)
    _exigir_bloqueio(plano, "resource_absence_contradictory:foundation:aws_kms_key.foundation")


def test_retirar_create_de_um_endereco_bloqueia_todas_as_operacoes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = _entrada_enabled()
    anterior = deepcopy(entrada)
    permissoes = entrada["facts"]["authorizations"]["initial"]["allowed_resource_actions"]
    assert permissoes["foundation"][ADDRESS] == ["create"]
    permissoes["foundation"][ADDRESS].remove("create")
    _reatar_stage(entrada)
    initial = deepcopy(entrada["facts"]["authorizations"]["initial"])
    assert initial["allowed_resource_actions"]["foundation"][ADDRESS] == []
    initial["allowed_resource_actions"]["foundation"][ADDRESS] = ["create"]
    assert initial == anterior["facts"]["authorizations"]["initial"]
    assert entrada["spec"] == anterior["spec"]
    assert entrada["facts"]["resources"] == anterior["facts"]["resources"]
    assert entrada["facts"]["evidence"] == anterior["facts"]["evidence"]
    _conferir_integridade(entrada)
    plano = _executar_duas_vezes(entrada, monkeypatch)
    _exigir_bloqueio(plano, "create_not_authorized")


def test_enabled_intacto_preserva_vinte_e_duas_operacoes_e_targets_literais(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caso = load_case("enabled")
    entrada, esperado = caso["input"], caso["expected"]
    assert isinstance(entrada, dict) and isinstance(esperado, dict)
    _conferir_integridade(entrada)
    plano = _executar_duas_vezes(entrada, monkeypatch)
    assert field(plano, "status") == "ready"
    assert plain(field(plano, "blocked_reasons")) == []
    operacoes = plain(field(plano, "operations"))
    assert isinstance(operacoes, list)
    assert len(operacoes) == 22
    assert len({item["address"] for item in operacoes}) == 22
    assert {item["address"]: item for item in operacoes} == {
        item["address"]: item for item in esperado["operations"]
    }
