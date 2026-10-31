"""BootstrapSpec v2 sintético: transporte fechado e imutável, sem execução operacional."""

from copy import deepcopy
from hashlib import sha256
from typing import Any, cast

import pytest

from fixtures.cnesdata_bootstrap_foundation_case import DATA, canonical, load_case, plain
from test_cnesdata_bootstrap_foundation_plan import _bloquear_fronteiras, _provar_imutabilidade
from tools.aws_bootstrap.contract import BootstrapSpec
from tools.aws_bootstrap.contract import canonical as canonical_publico
from tools.aws_bootstrap.contract import digest as digest_publico


CATALOGO = ("run", "capability_catalog")
PERFIL = (*CATALOGO, "profiles", "bootstrap_readback")
STATEMENT = (
    *CATALOGO,
    "policy_templates",
    "foundation",
    "aws_iam_role_policy.bootstrap_readback",
    0,
    "Statement",
    0,
)
SLOT = {
    "kind": "provider_slot",
    "root_id": "foundation",
    "address": "aws_kms_key.foundation",
    "attribute": "arn",
}
OBSERVADO = {
    "kind": "observed",
    "root_id": "foundation",
    "address": "aws_kms_key.foundation",
    "attribute": "arn",
    "origin_receipt_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
}
POSITIVOS = (("P01-spec-template-v2", "v2"), ("L01-spec-v1", "v1"))
NEGATIVOS = (
    ("N01-version-missing", "v2", (("delete", ("contract_version",), None),)),
    ("N02-version-bool", "v2", (("set", ("contract_version",), True),)),
    ("N03-version-float", "v2", (("set", ("contract_version",), 2.0),)),
    ("N04-version-string", "v2", (("set", ("contract_version",), "2"),)),
    ("N05-version-one-with-v2", "v2", (("set", ("contract_version",), 1),)),
    ("N06-version-unknown", "v2", (("set", ("contract_version",), 3),)),
    ("N07-catalog-missing", "v2", (("delete", CATALOGO, None),)),
    ("N08-catalog-unknown-field", "v2", (("set", (*CATALOGO, "unknown"), True),)),
    ("N09-session-missing", "v2", (("delete", (*PERFIL, "documents", "session"), None),)),
    ("N10-not-resource", "v2", (("set", (*STATEMENT, "NotResource"), "*"),)),
    (
        "N11-slot-attribute-missing",
        "v2",
        (("delete", (*STATEMENT, "Resource", "attribute"), None),),
    ),
    (
        "N12-slot-receipt",
        "v2",
        (
            (
                "set",
                (*STATEMENT, "Resource", "origin_receipt_sha256"),
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            ),
        ),
    ),
    ("N13-observed-in-template", "v2", (("set", (*STATEMENT, "Resource"), OBSERVADO),)),
    (
        "N14-slot-outside-domain",
        "v2",
        (
            (
                "set",
                (*STATEMENT, "Resource", "address"),
                "aws_iam_user_policy_attachment.local_login",
            ),
        ),
    ),
    ("N15-slot-in-action", "v2", (("set", (*STATEMENT, "Action"), SLOT),)),
    (
        "N16-old-rendered-digests",
        "v2",
        (
            (
                "copy",
                (*PERFIL, "rendered_documents_sha256"),
                (*PERFIL, "template_documents_sha256"),
            ),
            ("delete", (*PERFIL, "template_documents_sha256"), None),
        ),
    ),
    (
        "N17-configured-root-missing",
        "v2",
        (("delete", (*CATALOGO, "configured_iam_paths", "budget-backend"), None),),
    ),
    ("N18-v1-marked-v2", "v1", (("set", ("contract_version",), 2),)),
    ("N19-version-unknown-with-v1", "v1", (("set", ("contract_version",), 3),)),
)


def _carregar() -> tuple[dict[str, Any], dict[str, Any]]:
    caso = cast(dict[str, Any], load_case("c3a-spec-template-transport"))
    legado = cast(dict[str, Any], load_case("enabled"))
    entradas = {"v2": caso["input"], "v1": legado["input"]["spec"]}
    esperado = caso["expected"]
    assert caso["before_manifest"] is None and caso["after_manifest"] is None
    assert caso["binary_bytes"] is None
    assert esperado["case_ids"] == [item[0] for item in (*POSITIVOS, *NEGATIVOS)]
    assert esperado["synthetic"] is True
    assert esperado["operational_gate"] == "GATE_NOT_RELEASED"
    assert esperado["raw_scanner_status"] == "FAIL"
    assert set(esperado["downstream_boundaries"].values()) == {"UNREACHED"}
    assert canonical({"á": "café\n"}) == b'{"\xc3\xa1":"caf\xc3\xa9\\n"}'
    for caminho, selo in esperado["fixture_sha256"].items():
        assert sha256((DATA / caminho).read_bytes()).hexdigest() == selo, caminho
    for versao, entrada in entradas.items():
        referencia = canonical(deepcopy(entrada))
        assert sha256(referencia).hexdigest() == esperado[versao + "_sha256"]
        assert len(referencia) == esperado[versao + "_canonical_utf8_bytes"]
    _conferir_literal(entradas["v2"], esperado)
    return entradas, esperado


def _conferir_literal(entrada: dict, esperado: dict) -> None:
    run = entrada["run"]
    inventory_sha = run["inventory_sha"]
    assert type(inventory_sha) is str and len(inventory_sha) == 64
    assert set(inventory_sha) <= set("0123456789abcdef")
    catalogo = run["capability_catalog"]
    assert type(entrada["contract_version"]) is int and entrada["contract_version"] == 2
    assert entrada["step"]["input_bindings"] == []
    assert {root: len(value["resources"]) for root, value in run["roots"].items()} == (
        esperado["root_sizes"]
    )
    assert sum(esperado["root_sizes"].values()) == 56
    assert set(catalogo["profiles"]) == set(esperado["profiles"])
    assert set(catalogo["policy_templates"]) == set(esperado["root_sizes"])
    assert set(catalogo["configured_iam_paths"]) == set(esperado["root_sizes"])
    for root, documentos in catalogo["policy_templates"].items():
        assert set(documentos) == set(run["policy_template_digests"][root])
        for endereco, documentos_recurso in documentos.items():
            assert (
                sha256(canonical(documentos_recurso)).hexdigest()
                == (run["policy_template_digests"][root][endereco])
            )
    for fonte in catalogo["sources"].values():
        assert fonte["origin"] == "synthetic"
        assert sha256(fonte["content_utf8"].encode("utf-8")).hexdigest() == fonte["content_sha256"]


def _aceitar(entrada: dict, esperado: dict, versao: str) -> None:
    referencia = deepcopy(entrada)
    bytes_referencia = canonical(referencia)
    copia = deepcopy(entrada)
    primeiro = BootstrapSpec.from_mapping(copia)
    segundo = BootstrapSpec.from_mapping(copia)
    assert copia == referencia
    for valor in (primeiro, segundo):
        assert type(valor) is BootstrapSpec
        assert plain(valor.as_mapping()) == referencia
        assert canonical_publico(valor) == bytes_referencia
        assert digest_publico(valor) == esperado[versao + "_sha256"]
        _provar_imutabilidade(valor)
        _provar_imutabilidade(valor.as_mapping())
    _alterar_copia(copia, versao)
    for valor in (primeiro, segundo):
        assert plain(valor.as_mapping()) == referencia
        assert canonical_publico(valor) == bytes_referencia
        assert digest_publico(valor) == esperado[versao + "_sha256"]
    assert entrada == referencia


def _alterar_copia(copia: dict, versao: str) -> None:
    copia["run"]["roots"]["foundation"]["resources"]["aws_kms_key.foundation"].clear()
    copia["run"]["tags"]["Project"] = "alterado"
    if versao == "v2":
        catalogo = copia["run"]["capability_catalog"]
        catalogo["sources"]["catalog"]["parent_source_ids"].append("alterado")
        catalogo["sources"]["catalog"]["content_utf8"] = "alterado"
        perfil = catalogo["profiles"]["bootstrap_readback"]
        perfil["source_ids"].append("alterado")
        perfil["documents"]["inline"]["Statement"][0]["Resource"].clear()


def _obter(entrada: Any, caminho: tuple) -> Any:
    valor = entrada
    for chave in caminho:
        valor = valor[chave]
    return valor


def _mutar(entrada: dict, operacoes: tuple) -> dict:
    alterada = deepcopy(entrada)
    for operacao, caminho, valor in operacoes:
        destino = _obter(alterada, caminho[:-1])
        if operacao == "delete":
            del destino[caminho[-1]]
        else:
            novo = _obter(alterada, valor) if operacao == "copy" else valor
            destino[caminho[-1]] = deepcopy(novo)
    return alterada


def _rejeitar(entrada: dict) -> None:
    anterior = deepcopy(entrada)
    for _ in range(2):
        with pytest.raises(ValueError, match="^invalid_bootstrap_input$") as erro:
            BootstrapSpec.from_mapping(entrada)
        assert type(erro.value) is ValueError
        assert str(erro.value) == "invalid_bootstrap_input"
        assert erro.value.__cause__ is None and erro.value.__context__ is None
        assert entrada == anterior


@pytest.mark.parametrize("caso", POSITIVOS, ids=[item[0] for item in POSITIVOS])
def test_spec_preserva_mapping_bytes_hash_e_imutabilidade(caso, monkeypatch) -> None:
    entradas, esperado = _carregar()
    anterior = deepcopy(entradas)
    eventos = []
    try:
        with monkeypatch.context() as patch:
            _bloquear_fronteiras(patch, eventos)
            _aceitar(entradas[caso[1]], esperado, caso[1])
    finally:
        assert eventos == []
        assert entradas == anterior


@pytest.mark.parametrize("caso", NEGATIVOS, ids=[item[0] for item in NEGATIVOS])
def test_spec_rejeita_defeito_apos_aceitar_controle(caso, monkeypatch) -> None:
    entradas, esperado = _carregar()
    anterior = deepcopy(entradas)
    _, versao, operacoes = caso
    alterada = None
    anterior_alterada = None
    eventos = []
    try:
        with monkeypatch.context() as patch:
            _bloquear_fronteiras(patch, eventos)
            _aceitar(entradas[versao], esperado, versao)
            alterada = _mutar(entradas[versao], operacoes)
            anterior_alterada = deepcopy(alterada)
            _rejeitar(alterada)
    finally:
        assert eventos == []
        assert entradas == anterior
        assert alterada == anterior_alterada
