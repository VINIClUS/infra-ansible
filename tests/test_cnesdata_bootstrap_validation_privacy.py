"""Regressão pública de privacidade nas falhas de parsing de timestamps."""

from copy import deepcopy
from typing import Any

import pytest

from fixtures.cnesdata_bootstrap_foundation_case import canonical, digest, field, load_case, plain
from test_cnesdata_bootstrap_foundation_plan import _bloquear_fronteiras, _projecao_dtos
from tools.aws_bootstrap.contract import BootstrapPlan, BootstrapSpec, Readback
from tools.aws_bootstrap.planner import plan_bootstrap


CANARY = "timestamp_privado_sinteticoZ"
TIMESTAMPS = (
    ("facts", "observed_at"), ("facts", "evaluated_at"),
    ("facts", "authorizations", "initial", "not_before"),
    ("facts", "authorizations", "initial", "expires_at"),
    ("facts", "authorizations", "stage", "not_before"),
    ("facts", "authorizations", "stage", "expires_at"),
)


def _atualizar_observacoes(entrada: dict[str, Any]) -> None:
    facts = entrada["facts"]
    evidence: dict[str, Any] = {}
    for observation in facts["resources"]["foundation"].values():
        source = facts["evidence"][observation["source_evidence_sha256"]]
        observation["observed_at"] = facts["observed_at"]
        source["observed_at"] = facts["observed_at"]
        observation["source_evidence_sha256"] = digest(source)
        evidence[digest(source)] = source
    facts["evidence"] = evidence


def _reatar_integridade(entrada: dict[str, Any]) -> None:
    spec, facts = entrada["spec"], entrada["facts"]
    initial, stage = facts["authorizations"]["initial"], facts["authorizations"]["stage"]
    stage["authority_sha256"] = digest(initial)
    stage["step_sha256"] = digest(spec["step"])
    stage["before_manifest_sha256"] = digest({
        "run_sha256": digest(spec["run"]), "root_id": "foundation",
        "observed_at": facts["observed_at"], "resources": facts["resources"]["foundation"],
    })
    facts["verified_authorization_sha256"] = [digest(initial), digest(stage)]


def _conferir_integridade(entrada: dict[str, Any]) -> None:
    spec, facts = entrada["spec"], entrada["facts"]
    initial, stage = facts["authorizations"]["initial"], facts["authorizations"]["stage"]
    assert initial["run_sha256"] == stage["run_sha256"] == digest(spec["run"])
    assert stage["authority_sha256"] == digest(initial)
    assert stage["step_sha256"] == digest(spec["step"])
    assert set(facts["verified_authorization_sha256"]) == {digest(initial), digest(stage)}
    assert stage["not_before"] == spec["step"]["not_before"]
    assert stage["expires_at"] == spec["step"]["expires_at"]
    before = {"run_sha256": digest(spec["run"]), "root_id": "foundation",
              "observed_at": facts["observed_at"], "resources": facts["resources"]["foundation"]}
    assert stage["before_manifest_sha256"] == digest(before)
    for observation in facts["resources"]["foundation"].values():
        source_hash = observation["source_evidence_sha256"]
        source = facts["evidence"][source_hash]
        assert digest(source) == source_hash
        assert source["observed_at"] == observation["observed_at"] == facts["observed_at"]


def _entrada_enabled() -> dict[str, Any]:
    entrada = load_case("enabled")["input"]
    assert isinstance(entrada, dict)
    return entrada


def _preparar_entrada(path: tuple[str, ...]) -> dict[str, Any]:
    entrada = _entrada_enabled()
    target = entrada
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = CANARY
    if path[1] == "observed_at":
        _atualizar_observacoes(entrada)
    if len(path) == 4 and path[2] == "stage":
        entrada["spec"]["step"][path[-1]] = CANARY
    _reatar_integridade(entrada)
    _conferir_integridade(entrada)
    return entrada


@pytest.fixture(params=TIMESTAMPS, ids=lambda path: ".".join(path[1:]))
def entrada_invalida(request: pytest.FixtureRequest) -> dict[str, Any]:
    return _preparar_entrada(request.param)


def _publico(plano: BootstrapPlan) -> dict[str, Any]:
    value = plain(plano.as_mapping())
    assert isinstance(value, dict)
    return value


def _executar_duas_vezes(
    entrada: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> BootstrapPlan:
    anterior = deepcopy(entrada)
    eventos = []
    planos: list[BootstrapPlan] = []
    with monkeypatch.context() as patch:
        _bloquear_fronteiras(patch, eventos)
        spec = BootstrapSpec.from_mapping(entrada["spec"])
        facts = Readback.from_mapping(entrada["facts"])
        for _ in range(2):
            if _projecao_dtos(spec, facts, anterior) != canonical(anterior):
                raise AssertionError("public_dto_input_mismatch")
            planos.append(plan_bootstrap(spec, facts, entrada["checkpoint"]))
            if _projecao_dtos(spec, facts, anterior) != canonical(anterior):
                raise AssertionError("public_dto_mutated")
            if entrada != anterior:
                raise AssertionError("planner_input_mutated")
    assert eventos == []
    assert entrada == anterior
    assert _publico(planos[0]) == _publico(planos[1])
    return planos[0]


def _exigir_bloqueio_timestamp(plano: BootstrapPlan) -> None:
    assert field(plano, "status") == "blocked"
    assert plain(field(plano, "operations")) == []
    assert plain(field(plano, "blocked_reasons")) == ["invalid_timestamp"]


def _exigir_privacidade(plano: BootstrapPlan) -> None:
    serializado = canonical(_publico(plano)).decode("utf-8")
    assert CANARY not in serializado
    assert CANARY.replace("Z", "+00:00") not in serializado
    assert CANARY.removesuffix("Z") not in serializado
    assert "Invalid isoformat string" not in serializado


def _exigir_foundation_pronta(plano: BootstrapPlan) -> None:
    assert field(plano, "status") == "ready"
    assert len(field(plano, "operations")) == 22
    assert plain(field(plano, "blocked_reasons")) == []


def test_timestamp_invalido_bloqueia_com_codigo_fixo(
    entrada_invalida: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    plano = _executar_duas_vezes(entrada_invalida, monkeypatch)
    _exigir_bloqueio_timestamp(plano)


def test_timestamp_invalido_nao_vaza_valor_ou_mensagem_do_parser(
    entrada_invalida: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    plano = _executar_duas_vezes(entrada_invalida, monkeypatch)
    _exigir_privacidade(plano)


def test_timestamp_valido_preserva_foundation_pronta_com_vinte_e_duas_criacoes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = _entrada_enabled()
    plano = _executar_duas_vezes(entrada, monkeypatch)
    _exigir_foundation_pronta(plano)
