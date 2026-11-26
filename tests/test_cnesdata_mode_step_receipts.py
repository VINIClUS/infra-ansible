"""P16b c-1124-p16b-next item 3 (design 4.3): the recovery-task and audit-task steps bind the final DescribeTasks reply."""
import json

import pytest

from test_cnesdata_mode_effect_ecs import _describe, _ecs_broker, _run
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc


def _product_text(task):
    return (json.dumps(task, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_passo_igual_ao_texto_do_produto_da_tarefa_final_e_aceito(monkeypatch, mode):
    broker, journal, native, _ = _ecs_broker(monkeypatch, mode, statuses=("RUNNING", "STOPPED"))
    _run(journal, mode)
    reply, _ = _describe(journal, mode)
    body = _product_text(reply["value"]["tasks"][0])
    assert reply["value"]["tasks"][0]["lastStatus"] == "STOPPED"
    assert journal.observe(f"{mode}-task", body) == c.sha(body)
    assert journal._observations[-1] == {"kind": f"{mode}-task", "sha256": c.sha(body), "size": len(body)}


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_passo_com_a_tarefa_de_um_poll_intermediario_recusa(monkeypatch, mode):
    broker, journal, native, _ = _ecs_broker(monkeypatch, mode, statuses=("RUNNING", "STOPPED"))
    _run(journal, mode)
    _describe(journal, mode)
    first = c.loads(journal.call_bytes[journal.call_receipts[1]["response_sha256"]], canonical=True)
    assert first["tasks"][0]["lastStatus"] == "RUNNING" and len(journal.call_receipts) == 3
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe(f"{mode}-task", c.canonical(first["tasks"][0]))
    assert journal._observations == []


def test_passo_antes_de_qualquer_describe_recusa(monkeypatch):
    broker, journal, native, _ = _ecs_broker(monkeypatch)
    reply, _ = _run(journal)
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe("recovery-task", c.canonical(reply["value"]["tasks"][0]))


@pytest.mark.parametrize("change", [{"lastStatus": "RUNNING"}, {"stopCode": "TaskFailedToStart"}, {"extra": 1},
                                    {"containers": [{"name": "processor-recovery", "exitCode": False,
                                                     "lastStatus": "STOPPED"}]}],
                         ids=["status", "stop-code", "campo-extra", "exit-code-booleano"])
def test_passo_com_a_tarefa_alterada_recusa(monkeypatch, change):
    broker, journal, native, _ = _ecs_broker(monkeypatch)
    _run(journal)
    reply, _ = _describe(journal)
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe("recovery-task", c.canonical(reply["value"]["tasks"][0] | change))


def test_passo_de_tarefa_sem_mode_broker_recusa():
    from test_cnesdata_mode_stages import _lease_journal
    journal = _lease_journal("recovery-start")
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe("recovery-task", c.canonical({"lastStatus": "STOPPED"}))


def test_passo_de_tarefa_de_outra_operacao_continua_recusado_pela_tabela(monkeypatch):
    broker, journal, native, _ = _ecs_broker(monkeypatch)
    _run(journal)
    reply, _ = _describe(journal)
    with pytest.raises(ValueError, match="^adapter operation observation$"):
        journal.observe("audit-task", _product_text(reply["value"]["tasks"][0]))


def test_resultado_final_continua_aceito_sem_passo(monkeypatch):
    broker, journal, native, _ = _ecs_broker(monkeypatch)
    _run(journal)
    _describe(journal)
    assert journal.observe(lc.ADAPTER_OBSERVATIONS["recovery-start"], c.canonical({"fixture": "result"}))


def test_passo_liga_a_ultima_resposta_quando_o_filho_descreve_de_novo(monkeypatch):
    broker, journal, native, _ = _ecs_broker(monkeypatch)
    _run(journal)
    first, _ = _describe(journal)
    inner = broker.session.client.call

    def call(service, name, **parameters):
        response = inner(service, name, **parameters)
        response["tasks"][0]["containers"][0]["exitCode"] = 1
        return response
    broker.session.client.call = call
    second, _ = _describe(journal)
    assert first["value"]["tasks"][0] != second["value"]["tasks"][0]
    with pytest.raises(ValueError, match="^mode step receipt$"):
        journal.observe("recovery-task", c.canonical(first["value"]["tasks"][0]))
    body = c.canonical(second["value"]["tasks"][0])
    assert journal.observe("recovery-task", body) == c.sha(body)
