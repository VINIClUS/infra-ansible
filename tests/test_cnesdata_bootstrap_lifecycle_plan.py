"""História C2, migrações e propostas no seam puro com oráculos literais."""

from copy import deepcopy
from typing import Any, cast

import pytest

from fixtures.cnesdata_bootstrap_foundation_case import canonical, digest, field, load_case, plain
from test_cnesdata_bootstrap_contract_validation import (
    CANARY, _canais_sem_canario as _canais_sem_canario,
)
from test_cnesdata_bootstrap_foundation_plan import _bloquear_fronteiras, _provar_imutabilidade
from test_cnesdata_bootstrap_validation_privacy import _executar_duas_vezes
from tools.aws_bootstrap.contract import BootstrapPlan, BootstrapSpec, Readback, freeze
from tools.aws_bootstrap.planner import plan_bootstrap


INDEX = cast(dict[str, Any], load_case("c2-index")["expected"])
CASES = [*INDEX["positive"], *INDEX["negative"]]


def _comparar(plano: BootstrapPlan, esperado: dict[str, Any]) -> None:
    atual = cast(dict[str, Any], plain(plano.as_mapping()))
    for campo, valor in esperado.items():
        if campo == "operations":
            assert sorted(atual[campo], key=canonical) == sorted(valor, key=canonical)
        else:
            assert atual[campo] == valor
    assert CANARY not in canonical(atual).decode()
    _provar_imutabilidade(plano)


@pytest.mark.parametrize("nome", CASES)
def test_lifecycle_preserva_oraculo_literal_origens_e_fronteiras(
    nome: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    caso = cast(dict[str, Any], load_case(nome))
    entrada, esperado = caso["input"], caso["expected"]
    anterior = deepcopy(entrada)
    checkpoint = freeze(entrada["checkpoint"])
    eventos: list[str] = []
    planos: list[BootstrapPlan] = []
    try:
        with monkeypatch.context() as patch:
            _bloquear_fronteiras(patch, eventos)
            spec = BootstrapSpec.from_mapping(entrada["spec"])
            facts = Readback.from_mapping(entrada["facts"])
            for _ in range(2):
                planos.append(plan_bootstrap(spec, facts, checkpoint))
                assert plain(spec.as_mapping()) == anterior["spec"]
                assert plain(facts.as_mapping()) == anterior["facts"]
            _provar_imutabilidade(spec)
            _provar_imutabilidade(facts)
    finally:
        assert entrada == anterior
        assert plain(checkpoint) == anterior["checkpoint"]
        assert eventos == []
    assert plain(planos[0].as_mapping()) == plain(planos[1].as_mapping())
    _comparar(planos[0], esperado)


def test_controle_genesis_null_mantem_seam_existente_e_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caso = cast(dict[str, Any], load_case("enabled"))
    anterior = deepcopy(caso["input"])
    plano = _executar_duas_vezes(caso["input"], monkeypatch)
    assert caso["input"] == anterior
    _comparar(plano, caso["expected"])


def _valor(documento: Any, path: tuple[Any, ...]) -> Any:
    for key in path:
        documento = documento[key]
    return documento


NOVOS_RECORDS = (
    ("c2-partial", ("facts", "root_states", "foundation"), "owner"),
    ("c2-partial", ("facts", "root_states", "foundation", "backend_location"), "machine_id"),
    ("c2-budget", ("facts", "root_states", "foundation", "backend_location"), "account"),
    ("c2-budget", ("facts", "cmk"), "key_usage"),
    ("c2-budget", ("spec", "step", "input_bindings", 0), "origin_receipt_sha256"),
    ("c2-migrate-foundation", ("facts", "migration"), "destination_state"),
    ("c2-migrate-foundation", ("facts", "migration", "source"), "resource_ids"),
    ("c2-migrate-foundation", ("facts", "migration", "destination"), "key"),
    ("c2-adopt", ("facts", "orphan_candidates", 0), "intent_sha256"),
)


@pytest.mark.parametrize("nome,record", [(n, (p, c)) for n, p, c in NOVOS_RECORDS],
                         ids=["/".join(map(str, p)) for _, p, _ in NOVOS_RECORDS])
@pytest.mark.parametrize("modo", ("unknown", "missing"))
def test_novos_records_rejeitam_extensao_ou_campo_ausente_sem_vazar_input(
    nome: str, record: tuple[tuple[Any, ...], str], modo: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case(nome)["input"])
    path, campo = record
    classe = BootstrapSpec if path[0] == "spec" else Readback
    valido = deepcopy(entrada[path[0]])
    documento = _valor(entrada, path)
    if modo == "unknown":
        documento[CANARY] = True
    else:
        del documento[campo]
    anterior = deepcopy(entrada)
    eventos: list[str] = []
    try:
        with monkeypatch.context() as patch:
            _bloquear_fronteiras(patch, eventos)
            classe.from_mapping(valido)
            with pytest.raises(ValueError) as erro:
                classe.from_mapping(entrada[path[0]])
            assert str(erro.value) == "invalid_bootstrap_input"
            assert erro.value.__cause__ is None and erro.value.__context__ is None
    finally:
        assert entrada == anterior
        assert eventos == []


@pytest.mark.parametrize("kind,campo", (
    ("freeze", "held_intent_sha256"), ("independent_backup", "ciphertext_sha256"),
    ("remote_lock", "lock_id"), ("quarantine_restore", "restored_state"),
))
@pytest.mark.parametrize("modo", ("unknown", "missing"))
def test_resultados_de_migracao_sao_records_fechados(
    kind: str, campo: str, modo: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case("c2-migrate-foundation")["input"])
    valido = deepcopy(entrada["facts"])
    result = next(v["result"] for v in entrada["facts"]["evidence"].values() if v["kind"] == kind)
    if modo == "unknown":
        result[CANARY] = True
    else:
        del result[campo]
    anterior = deepcopy(entrada)
    eventos: list[str] = []
    try:
        with monkeypatch.context() as patch:
            _bloquear_fronteiras(patch, eventos)
            Readback.from_mapping(valido)
            with pytest.raises(ValueError) as erro:
                Readback.from_mapping(entrada["facts"])
            assert str(erro.value) == "invalid_bootstrap_input"
    finally:
        assert entrada == anterior
        assert eventos == []


@pytest.mark.parametrize("nome,path,valor", (
    ("c2-partial", ("root_states", "foundation", "serial"), True),
    ("c2-partial", ("root_states", "foundation", "backend_location", "path"), 123),
    ("c2-budget", ("cmk", "rotation_enabled"), "true"),
    ("c2-migrate-foundation", ("migration", "destination_empty"), 1),
))
def test_tipos_dos_fatos_novos_nao_mascaram_bool_ou_string(
    nome: str, path: tuple[Any, ...], valor: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    caso = cast(dict[str, Any], load_case(nome))
    facts = cast(dict[str, Any], caso["input"]["facts"])
    valido = deepcopy(facts)
    _valor(facts, path[:-1])[path[-1]] = valor
    anterior = deepcopy(facts)
    eventos: list[str] = []
    try:
        with monkeypatch.context() as patch:
            _bloquear_fronteiras(patch, eventos)
            Readback.from_mapping(valido)
            with pytest.raises(ValueError) as erro:
                Readback.from_mapping(facts)
            assert str(erro.value) == "invalid_bootstrap_input"
    finally:
        assert facts == anterior
        assert eventos == []


@pytest.mark.parametrize("nome", ("c2-migrate-foundation", "c2-adopt", "c2-restore"))
def test_novas_variantes_do_plano_validam_operacao_ou_proposta(
    nome: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    esperado = cast(dict[str, Any], load_case(nome)["expected"])
    invalido = deepcopy(esperado)
    item = (invalido["operations"] or invalido["proposals"])[0]
    item[CANARY] = True
    anterior = deepcopy(invalido)
    eventos: list[str] = []
    try:
        with monkeypatch.context() as patch:
            _bloquear_fronteiras(patch, eventos)
            BootstrapPlan.from_mapping(esperado)
            with pytest.raises(ValueError) as erro:
                BootstrapPlan.from_mapping(invalido)
            assert str(erro.value) == "invalid_bootstrap_input"
    finally:
        assert invalido == anterior
        assert eventos == []


@pytest.mark.parametrize("checkpoint,sha_esperado", (
    ({"history": CANARY}, "canonical"), ({"contract_version": True}, "canonical"),
    ({"history": [float("nan")]}, None),
))
def test_checkpoint_mapping_invalido_nao_quebra_envelope_bloqueado(
    checkpoint: dict[str, Any], sha_esperado: str | None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case("enabled")["input"])
    entrada["checkpoint"] = checkpoint
    anterior = deepcopy(entrada)
    cp = freeze(checkpoint)
    eventos: list[str] = []
    try:
        with monkeypatch.context() as patch:
            _bloquear_fronteiras(patch, eventos)
            spec = BootstrapSpec.from_mapping(entrada["spec"])
            facts = Readback.from_mapping(entrada["facts"])
            plano = plan_bootstrap(spec, facts, cp)
    finally:
        assert entrada == anterior
        assert plain(cp) == anterior["checkpoint"]
        assert eventos == []
    _comparar(plano, {"status": "blocked", "operations": [], "proposals": [],
                      "blocked_reasons": ["invalid_bootstrap_input"]})
    assert field(plano, "checkpoint_sha256") == (
        digest(checkpoint) if sha_esperado == "canonical" else None)
