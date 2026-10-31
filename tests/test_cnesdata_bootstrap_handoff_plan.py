"""Readback v2 sintético: transporte local, sem autoridade ou execução comprovada."""

from copy import deepcopy
from typing import Any, cast

import pytest

from fixtures.cnesdata_bootstrap_foundation_case import canonical, digest, load_case, plain
from test_cnesdata_bootstrap_foundation_plan import _bloquear_fronteiras, _provar_imutabilidade
from tools.aws_bootstrap.contract import Readback
from tools.aws_bootstrap.contract import canonical as canonical_publico
from tools.aws_bootstrap.contract import digest as digest_publico


NEGATIVOS = (
    ("N01-version-bool", "v2", ("contract_version",), "set", True),
    ("N02-version-one", "v2", ("contract_version",), "set", 1),
    ("N03-version-unknown", "v2", ("contract_version",), "set", 3),
    ("N04-marker-missing", "v2", ("contract_version",), "delete", None),
    ("N05-coverage-missing", "v2", ("successor_coverage",), "delete", None),
    ("N06-coverage-nonnull", "v2", ("successor_coverage",), "set", {}),
    ("N07-verification-missing", "v2", ("authorizations", "verification"), "delete", None),
    ("N08-verification-nonnull", "v2", ("authorizations", "verification"), "set", {}),
    ("N09-subsequent-nonnull", "v2", ("authorizations", "subsequent"), "set", {}),
    ("N10-roles-missing", "v2", ("identity_activation", "role_proofs"), "delete", None),
    ("N11-roles-nonempty", "v2", ("identity_activation", "role_proofs"), "set",
     {"bootstrap_readback": {}}),
    ("N12-service-missing", "v2", ("identity_activation", "budget_service_proof"), "delete",
     None),
    ("N13-service-nonnull", "v2", ("identity_activation", "budget_service_proof"), "set", {}),
    ("N14-unknown-field", "v2", ("identity_activation", "future_proof"), "set", True),
    ("N15-marked-legacy", "v1", ("contract_version",), "set", 2),
    ("N16-version-float-equal", "v2", ("contract_version",), "set", 2.0),
    ("N17-version-string-two", "v2", ("contract_version",), "set", "2"),
)
POSITIVOS = (("P01-readback-v2", "v2"), ("L01-readback-v1", "v1"))


def _carregar() -> tuple[dict[str, Any], dict[str, Any]]:
    caso = cast(dict[str, Any], load_case("c3a-readback-transport"))
    legado = cast(dict[str, Any], load_case("enabled"))
    entradas = {"v2": caso["input"], "v1": legado["input"]["facts"]}
    esperado = caso["expected"]
    assert caso["before_manifest"] is None and caso["after_manifest"] is None
    assert caso["binary_bytes"] is None
    assert esperado["case_ids"] == [v[0] for v in (*POSITIVOS, *NEGATIVOS)]
    assert esperado["synthetic"] is True
    assert esperado["operational_gate"] == "GATE_NOT_RELEASED"
    assert esperado["raw_scanner_status"] == "FAIL" and esperado["semantics"] == "UNREACHED"
    for versao, entrada in entradas.items():
        assert digest(entrada) == esperado[versao + "_sha256"]
        _conferir_campos(entrada, esperado, versao)
    _conferir_grant(entradas["v2"], esperado)
    return entradas, esperado


def _conferir_campos(entrada: dict, esperado: dict, versao: str) -> None:
    assert sorted(entrada) == esperado[versao + "_fields"]
    assert sorted(entrada["authorizations"]) == esperado[versao + "_authorizations_fields"]
    assert sorted(entrada["identity_activation"]) == esperado[versao + "_activation_fields"]
    if versao == "v1":
        assert "contract_version" not in entrada and "successor_coverage" not in entrada
        assert "verification" not in entrada["authorizations"]
        assert "role_proofs" not in entrada["identity_activation"]
        assert "budget_service_proof" not in entrada["identity_activation"]
        return
    assert type(entrada["contract_version"]) is int and entrada["contract_version"] == 2
    assert entrada["successor_coverage"] is None
    assert entrada["authorizations"]["verification"] is None
    assert entrada["authorizations"]["subsequent"] is None
    assert entrada["identity_activation"]["role_proofs"] == {}
    assert entrada["identity_activation"]["budget_service_proof"] is None


def _conferir_grant(entrada: dict, esperado: dict) -> None:
    initial = entrada["authorizations"]["initial"]
    stage = entrada["authorizations"]["stage"]
    pares = {tuple(par) for par in esperado["grant_pairs"]}
    assert len(pares) == len(esperado["grant_pairs"]) == 56
    assert set(initial["roots"]) == set(esperado["roots"])
    assert {(r, a) for r, v in initial["roots"].items() for a in v["resources"]} == pares
    actions = initial["allowed_resource_actions"]
    assert {(r, a) for r, v in actions.items() for a in v} == pares
    assert initial["allowed_state_actions"] == {r: ["migrate"] for r in esperado["roots"]}
    assert stage["authority_sha256"] == digest(initial)
    assert stage["run_sha256"] == initial["run_sha256"]
    assert entrada["verified_authorization_sha256"] == [digest(initial), digest(stage)]


def _aceitar(entrada: dict, esperado: dict, versao: str) -> None:
    anterior = deepcopy(entrada)
    copia = deepcopy(entrada)
    primeiro = Readback.from_mapping(copia)
    segundo = Readback.from_mapping(copia)
    assert copia == anterior
    for valor in (primeiro, segundo):
        assert type(valor) is Readback
        assert plain(valor.as_mapping()) == anterior
        assert canonical_publico(valor) == canonical(anterior)
        assert digest_publico(valor) == esperado[versao + "_sha256"]
        _provar_imutabilidade(valor)
        _provar_imutabilidade(valor.as_mapping())
    copia["resources"]["foundation"]["mutation_probe"] = True
    copia["verified_authorization_sha256"].append("alterado")
    for valor in (primeiro, segundo):
        assert plain(valor.as_mapping()) == anterior
        assert canonical_publico(valor) == canonical(anterior)
    assert entrada == anterior


def _mutar(entrada: dict, caso: tuple) -> dict:
    alterada = deepcopy(entrada)
    _, _, caminho, operacao, valor = caso
    destino = alterada
    for chave in caminho[:-1]:
        destino = destino[chave]
    if operacao == "delete":
        del destino[caminho[-1]]
    else:
        destino[caminho[-1]] = deepcopy(valor)
    return alterada


def _rejeitar(invalida: dict) -> None:
    for _ in range(2):
        with pytest.raises(ValueError) as erro:
            Readback.from_mapping(invalida)
        assert str(erro.value) == "invalid_bootstrap_input"
        assert erro.value.__cause__ is None and erro.value.__context__ is None


@pytest.mark.parametrize("versao", [v[1] for v in POSITIVOS], ids=[v[0] for v in POSITIVOS])
def test_readback_preserva_forma_bytes_hash_e_imutabilidade(
    versao: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entradas, esperado = _carregar()
    anterior = deepcopy(entradas)
    eventos: list[str] = []
    try:
        with monkeypatch.context() as patch:
            _bloquear_fronteiras(patch, eventos)
            _aceitar(entradas[versao], esperado, versao)
    finally:
        assert entradas == anterior
        assert eventos == []


@pytest.mark.parametrize("caso", NEGATIVOS, ids=[v[0] for v in NEGATIVOS])
def test_readback_rejeita_defeito_literal_apos_aceitar_controle(
    caso: tuple, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entradas, esperado = _carregar()
    versao = caso[1]
    invalida = _mutar(entradas[versao], caso)
    anterior = deepcopy((entradas, invalida))
    eventos: list[str] = []
    try:
        with monkeypatch.context() as patch:
            _bloquear_fronteiras(patch, eventos)
            _aceitar(entradas[versao], esperado, versao)
            _rejeitar(invalida)
    finally:
        assert (entradas, invalida) == anterior
        assert eventos == []
