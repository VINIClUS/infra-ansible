"""Primeiro tracer B1b: quatro pares literais no seam puro de foundation."""

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import fields, is_dataclass
from functools import partial
import builtins
import datetime
import io
import os
import socket
import subprocess
import sys
import time
from types import MappingProxyType
from typing import Any, ClassVar, cast

import pytest

import fixtures.cnesdata_bootstrap_foundation_case as transporte_fixture
from fixtures.cnesdata_bootstrap_foundation_case import (
    LoadedCase, canonical, field, load_case, plain,
)
from tools.aws_bootstrap.contract import BootstrapSpec, Readback
from tools.aws_bootstrap.planner import plan_bootstrap


@pytest.fixture(params=("enabled", "disabled", "no-binary", "inconclusive"))
def caso(request):
    return LoadedCase(request.param, load_case(request.param))


def _negar_efeito(eventos, nome, *args, **kwargs):
    eventos.append(nome)
    raise AssertionError("external_effect=" + nome)


class _AmbienteBloqueado(Mapping):
    def __init__(self, eventos):
        self.eventos = eventos

    def __getitem__(self, key):
        return _negar_efeito(self.eventos, "environment")

    def __iter__(self):
        return _negar_efeito(self.eventos, "environment")

    def __len__(self):
        return _negar_efeito(self.eventos, "environment")


def _bloquear_fronteiras(patch, eventos):
    alvos = (
        (builtins, ("open",)), (io, ("open",)),
        (os, ("open", "read", "write", "stat", "lstat", "scandir", "listdir", "mkdir",
              "unlink", "remove", "rename", "replace", "chmod", "getenv", "system",
              "popen", "fork", "posix_spawn", "execve", "urandom")),
        (socket, ("socket", "create_connection", "getaddrinfo")),
        (subprocess, ("Popen", "run", "call", "check_call", "check_output")),
        (time, ("time", "time_ns", "monotonic", "monotonic_ns", "perf_counter", "sleep")),
    )
    for modulo, nomes in alvos:
        for nome in nomes:
            patch.setattr(modulo, nome, partial(_negar_efeito, eventos, nome))
    patch.setattr(os, "environ", _AmbienteBloqueado(eventos))
    patch.setattr(_RelogioBloqueado, "eventos", eventos, raising=False)
    patch.setattr(datetime, "datetime", _RelogioBloqueado)


class _RelogioBloqueado(datetime.datetime):
    eventos: ClassVar[list[str]]

    @classmethod
    def now(cls, tz=None):
        return _negar_efeito(cls.eventos, "datetime.now")

    @classmethod
    def utcnow(cls):
        return _negar_efeito(cls.eventos, "datetime.utcnow")


def _planejar(caso, monkeypatch):
    eventos = []
    entrada = deepcopy(caso.input)
    with monkeypatch.context() as patch:
        _bloquear_fronteiras(patch, eventos)
        spec = BootstrapSpec.from_mapping(caso.input["spec"])
        facts = Readback.from_mapping(caso.input["facts"])
        _exigir_igual(caso.input, entrada, "from_mapping_input_mutated")
        plano = _chamar_preservando(spec, facts, caso.input)
    assert eventos == [], "public_boundary_effects=" + repr(eventos)
    return spec, facts, plano


def _projecao_dtos(spec, facts, entrada):
    return canonical({
        "spec": {nome: plain(field(spec, nome)) for nome in entrada["spec"]},
        "facts": {nome: plain(field(facts, nome)) for nome in entrada["facts"]},
        "checkpoint": entrada["checkpoint"],
    })


def _exigir_igual(atual, esperado, motivo):
    if atual != esperado:
        raise AssertionError(motivo)


def _chamar_preservando(spec, facts, entrada):
    anterior = deepcopy(entrada)
    dto_antes = _projecao_dtos(spec, facts, anterior)
    _exigir_igual(dto_antes, canonical(anterior), "public_dto_input_mismatch")
    plano = plan_bootstrap(spec, facts, entrada["checkpoint"])
    _exigir_igual(_projecao_dtos(spec, facts, anterior), dto_antes, "public_dto_mutated")
    _exigir_igual(entrada, anterior, "planner_input_mutated")
    return plano


def _operacoes(plano):
    operacoes = plain(field(plano, "operations"))
    enderecos = [field(operacao, "address") for operacao in operacoes]
    assert len(enderecos) == len(set(enderecos)), "duplicate_resource_address"
    return {field(operacao, "address"): operacao for operacao in operacoes}


def _provar_imutabilidade(value):
    if isinstance(value, Mapping):
        with pytest.raises((TypeError, AttributeError)):
            cast(dict[str, Any], value)["mutation_probe"] = "alterado"
        for child in value.values():
            _provar_imutabilidade(child)
        return
    if isinstance(value, (tuple, list)):
        with pytest.raises((TypeError, AttributeError)):
            cast(list[Any], value).append("alterado")
        for child in value:
            _provar_imutabilidade(child)
        return
    if is_dataclass(value):
        for item in fields(value):
            _provar_imutabilidade(getattr(value, item.name))
            with pytest.raises((TypeError, AttributeError)):
                setattr(value, item.name, "alterado")


def test_quatro_casos_exigem_status_quantidade_e_motivo_exatos(caso, monkeypatch):
    esperado = {
        "enabled": ("ready", 22, []),
        "disabled": ("blocked", 0, ["step_disabled"]),
        "no-binary": ("blocked", 0, ["binary_plan_required_for_resource_apply"]),
        "inconclusive": (
            "blocked", 0,
            ["resource_observation_inconclusive:foundation:aws_kms_key.foundation"],
        ),
    }
    _, _, plano = _planejar(caso, monkeypatch)
    atual = (
        field(plano, "status"), len(field(plano, "operations")),
        plain(field(plano, "blocked_reasons")),
    )
    assert atual == esperado[caso.name]


def test_operacoes_unicas_preservam_targets_acoes_e_manifestos_literais(caso, monkeypatch):
    _, _, plano = _planejar(caso, monkeypatch)
    esperadas = {operacao["address"]: operacao for operacao in caso.expected["operations"]}
    assert _operacoes(plano) == esperadas


def test_metadados_digests_requisitos_custos_e_propostas_sao_literais(caso, monkeypatch):
    _, _, plano = _planejar(caso, monkeypatch)
    nomes = set(caso.expected) - {"status", "operations", "blocked_reasons"}
    atual = {nome: plain(field(plano, nome)) for nome in nomes}
    assert atual == {nome: caso.expected[nome] for nome in nomes}


def test_planejamento_e_deterministico_e_preserva_inputs(caso, monkeypatch):
    anterior = deepcopy(caso.input)
    spec, facts, primeiro = _planejar(caso, monkeypatch)
    eventos = []
    with monkeypatch.context() as patch:
        _bloquear_fronteiras(patch, eventos)
        segundo = _chamar_preservando(spec, facts, caso.input)
    assert eventos == []
    nomes = tuple(caso.expected)
    assert {nome: plain(field(primeiro, nome)) for nome in nomes} == {
        nome: plain(field(segundo, nome)) for nome in nomes
    }
    assert caso.input == anterior


def test_valores_publicos_rejeitam_mutacao_nested(caso, monkeypatch):
    spec, facts, plano = _planejar(caso, monkeypatch)
    for valor, nomes in ((spec, caso.input["spec"]), (facts, caso.input["facts"]),
                         (plano, caso.expected)):
        for nome in nomes:
            _provar_imutabilidade(field(valor, nome))
        with pytest.raises((AttributeError, TypeError)):
            setattr(valor, next(iter(nomes)), "alterado")


def test_desserializacao_isola_inputs_mutaveis(caso, monkeypatch):
    spec, facts, _ = _planejar(caso, monkeypatch)
    antes_spec = plain(field(spec, "run"))
    antes_facts = plain(field(facts, "resources"))
    caso.input["spec"]["run"]["tags"]["mutation_probe"] = "alterado"
    caso.input["facts"]["resources"]["foundation"]["aws_kms_key.foundation"]["tags"][
        "mutation_probe"
    ] = "alterado"
    assert plain(field(spec, "run")) == antes_spec
    assert plain(field(facts, "resources")) == antes_facts


def test_guarda_rejeita_mutacao_dto_na_primeira_chamada(caso, monkeypatch):
    chamadas = []
    original = plan_bootstrap

    def mutar_primeira(spec, facts, checkpoint):
        chamadas.append(1)
        if len(chamadas) == 1:
            alterado = dict(field(spec, "run"))
            alterado["initial_run_id"] = "mutacao-primeira-chamada"
            object.__setattr__(spec, "run", MappingProxyType(alterado))
        return original(spec, facts, checkpoint)

    monkeypatch.setattr(sys.modules[__name__], "plan_bootstrap", mutar_primeira)
    with pytest.raises(AssertionError, match="public_dto_mutated"):
        test_planejamento_e_deterministico_e_preserva_inputs(caso, monkeypatch)
    assert len(chamadas) == 1


@pytest.fixture
def transporte(tmp_path, monkeypatch):
    data = tmp_path / "bundle"
    data.mkdir()
    descriptor = {
        "input": "input.json", "expected": "expected.json", "before_manifest": "before.json",
        "after_manifest": "after.json", "binary_artifact": "inside.bin",
    }
    documents = {
        "bundle.json": {"cases": {"controle": descriptor}},
        "input.json": {"spec": {}, "facts": {}, "checkpoint": None},
        "expected.json": {}, "before.json": {}, "after.json": {},
        "payload.json": {"literal": "incluido"},
    }
    for name, value in documents.items():
        (data / name).write_bytes(canonical(value))
    (data / "inside.bin").write_bytes(b"inside-synthetic")
    (tmp_path / "outside.bin").write_bytes(b"outside-synthetic")
    monkeypatch.setattr(transporte_fixture, "DATA", data)
    return data, documents


@pytest.mark.parametrize("escape", ("parent", "absolute", "symlink"))
def test_transporte_rejeita_binario_fora_do_bundle(transporte, escape):
    data, documents = transporte
    outside = data.parent / "outside.bin"
    paths = {"parent": "../outside.bin", "absolute": str(outside), "symlink": "link.bin"}
    if escape == "symlink":
        (data / "link.bin").symlink_to(outside)
    documents["bundle.json"]["cases"]["controle"]["binary_artifact"] = paths[escape]
    (data / "bundle.json").write_bytes(canonical(documents["bundle.json"]))
    with pytest.raises(ValueError, match="outside_bundle="):
        load_case("controle")


def test_transporte_rejeita_include_com_campos_extras(transporte):
    data, _ = transporte
    value = {"nested": [{"$include": "payload.json", "extra": True}]}
    (data / "input.json").write_bytes(canonical(value))
    with pytest.raises(ValueError, match="mixed_include_directive"):
        load_case("controle")


def test_transporte_materializa_include_e_binario_validos(transporte):
    data, _ = transporte
    (data / "input.json").write_bytes(canonical({"nested": [{"$include": "payload.json"}]}))
    loaded = load_case("controle")
    assert loaded["input"] == {"nested": [{"literal": "incluido"}]}
    assert loaded["binary_bytes"] == b"inside-synthetic"


def _sem_diretivas(value):
    if isinstance(value, Mapping):
        assert "$include" not in value
        for child in value.values():
            _sem_diretivas(child)
    if isinstance(value, (tuple, list)):
        for child in value:
            _sem_diretivas(child)


def test_casos_materializados_nao_conservam_diretivas(caso):
    _sem_diretivas(caso.payload)
