"""P35 fix round 2: the wait step hydrates the governed catalog and takes the producers of the request payloads from it."""
import os

import pytest

from test_cnesdata_preflight_names_only import _case
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import stage_wait


def _inputs(monkeypatch, tmp_path, **request_changes):
    monkeypatch.chdir(tmp_path)
    lr, _, _ = _case(monkeypatch, "in_progress")
    request = c.loads(os.environ["REQUEST_DESCRIPTOR"].encode(), canonical=True) | request_changes
    governance = c.loads(os.environ["CNESDATA_DELIVERY_GOVERNANCE"].encode(), canonical=True, limit=262144)
    return lr.GitHub(), governance, request


def test_produtores_vem_do_passo_governado_e_dos_nomes_do_pedido(monkeypatch, tmp_path):
    api, governance, request = _inputs(monkeypatch, tmp_path)
    assert stage_wait._producers(api, {}, governance, request) == [{"name": "producer-plan / execute", "step": "producer"}]


def test_passo_fora_do_catalogo_governado_e_recusado(monkeypatch, tmp_path):
    api, governance, request = _inputs(monkeypatch, tmp_path, step="ungoverned")
    with pytest.raises(ValueError, match="governed step"):
        stage_wait._producers(api, {}, governance, request)


@pytest.mark.parametrize("payloads", [{"plan": {"step": "other"}}, {}, {"other": {"step": "producer"}}])
def test_nomes_do_pedido_fora_das_entradas_do_passo_sao_recusados(monkeypatch, tmp_path, payloads):
    api, governance, request = _inputs(monkeypatch, tmp_path, payloads=payloads)
    with pytest.raises(ValueError):
        stage_wait._producers(api, {}, governance, request)


def test_passo_sem_entradas_nao_tem_produtores_para_esperar(monkeypatch, tmp_path):
    api, governance, request = _inputs(monkeypatch, tmp_path, step="producer", payloads={})
    assert stage_wait._producers(api, {}, governance, request) == []
