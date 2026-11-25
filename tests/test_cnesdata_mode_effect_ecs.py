"""P16b c-1124-p16b-next item 1: ModeBroker run_task by the product route and the bounded native DescribeTasks wait."""
from datetime import datetime, timezone

import pytest

from test_cnesdata_mode_effect_broker import _Evidence, _frame, _metadata, _mb
from test_cnesdata_mode_run_task import REVISIONS, TASK, _readbacks, _request
from test_cnesdata_mode_session_sts import _case, _journal
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c

ALIASES = {"recovery": "mode_dispatch", "audit": "mode_audit_launch"}
OTHER_TASK = TASK[:-1] + "e"


class _Clock:
    def __init__(self, value):
        self.value, self.sleeps = value, []

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


def _task(mode, status, **extra):
    return {"taskArn": TASK, "taskDefinitionArn": REVISIONS[mode], "lastStatus": status, "desiredStatus": "STOPPED",
            "group": "family:x", "createdAt": datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc),
            "containers": [{"name": f"processor-{mode}", "exitCode": 0, "lastStatus": status, "image": "registry/x",
                            "networkInterfaces": [{"privateIpv4Address": "10.0.0.1"}]}]} | extra


def _ecs_broker(monkeypatch, mode="recovery", statuses=("STOPPED",), fail_at=None):
    operation = mode + "-start"
    args, _, _ = _case(monkeypatch, operation)
    args["journal"], _ = _journal(operation, {"readbacks": c.canonical(_readbacks(mode)),
                                              "record": c.canonical({"revisions": dict(REVISIONS)})})
    args["journal"]._timings = []
    clock = _Clock(args["clock"]())
    args["clock"] = clock
    session = _mb().assume_mode_session(**args)
    native, pending = [], list(statuses)

    def sdk(service, name, **parameters):
        native.append((service, name, parameters))
        if fail_at is not None and len(native) == fail_at:
            raise RuntimeError("timeout")
        if name == "run_task":
            return {"tasks": [_task(mode, "PROVISIONING")], "failures": [], "ResponseMetadata": _metadata()}
        status = pending.pop(0) if len(pending) > 1 else pending[0]
        return {"tasks": [_task(mode, status, stopCode="EssentialContainerExited")], "failures": [],
                "ResponseMetadata": _metadata()}
    session.client.call = sdk
    broker = _mb().ModeBroker(_Evidence(), args["governance"], args["journal"], session, prepared_sha256="3" * 64,
                              credential_limit=args["credential_limit"], clock=clock, sleep=clock.sleep)
    return broker, args["journal"], native, clock


def _run(journal, mode="recovery", role=None, **changes):
    return ag._adapter_message(_frame("ecs", "run_task", _request(mode, **changes), role or ALIASES[mode]), journal)


def _describe(journal, mode="recovery", task=TASK):
    cluster = _request(mode)["cluster"]
    return ag._adapter_message(_frame("ecs", "describe_tasks", {"cluster": cluster, "tasks": [task]}, ALIASES[mode]), journal)


def _projected(mode, status):
    return {"taskArn": TASK, "taskDefinitionArn": REVISIONS[mode], "lastStatus": status,
            "stopCode": "EssentialContainerExited",
            "containers": [{"name": f"processor-{mode}", "exitCode": 0, "lastStatus": status}]}


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_run_task_igual_a_rota_do_produto_vai_ao_ecs_e_devolve_a_tarefa_projetada(monkeypatch, mode):
    broker, journal, native, _ = _ecs_broker(monkeypatch, mode)
    reply, _ = _run(journal, mode)
    assert reply == {"kind": "sdk-result", "value": {"tasks": [
        {"taskArn": TASK, "taskDefinitionArn": REVISIONS[mode], "lastStatus": "PROVISIONING",
         "containers": [{"name": f"processor-{mode}", "exitCode": 0, "lastStatus": "PROVISIONING"}]}], "failures": []}}
    assert native == [("ecs", "run_task", _request(mode))] and len(journal.call_receipts) == 1
    assert broker.uncertainty == []


@pytest.mark.parametrize("case, message", [("rota", "^mode run_task route$"), ("alias", "^mode call alias$"),
                                           ("segundo", "^mode run_task once$")])
def test_run_task_fora_da_rota_alias_errado_ou_repetido_recusa_antes_do_io(monkeypatch, case, message):
    broker, journal, native, _ = _ecs_broker(monkeypatch)
    if case == "segundo":
        _run(journal)
    with pytest.raises(ValueError, match=message):
        _run(journal, role="mode_audit_launch" if case == "alias" else None, **({"count": 2} if case == "rota" else {}))
    assert len(native) == (1 if case == "segundo" else 0) and broker.uncertainty == []


def test_describe_tasks_espera_ate_parar_e_devolve_so_a_ultima_resposta(monkeypatch):
    broker, journal, native, clock = _ecs_broker(monkeypatch, statuses=("RUNNING", "RUNNING", "STOPPED"))
    _run(journal)
    started = clock.value
    reply, _ = _describe(journal)
    assert reply == {"kind": "sdk-result", "value": {"tasks": [_projected("recovery", "STOPPED")], "failures": []}}
    assert [call[1] for call in native] == ["run_task"] + ["describe_tasks"] * 3 and len(journal.call_receipts) == 4
    assert clock.sleeps == [5, 5] and broker.uncertainty == []
    stage = journal._request["stage"]
    end = min(stage["deadline"] - 38, broker.credential_limit - 121, broker.session.deadline) - 30
    assert journal._timings == [{"kind": "wait", "started_at": started, "ended_at": started + 10, "wait_end": end,
                                 "polls": 3, "terminal": True}]


def test_describe_tasks_termina_no_fim_da_espera_com_a_tarefa_rodando_sem_incerteza(monkeypatch):
    broker, journal, native, clock = _ecs_broker(monkeypatch, statuses=("RUNNING",))
    _run(journal)
    stage = journal._request["stage"]
    end = min(stage["deadline"] - 38, broker.credential_limit - 121, broker.session.deadline) - 30
    clock.value = end - 12
    reply, _ = _describe(journal)
    assert reply["value"]["tasks"] == [_projected("recovery", "RUNNING")]
    assert journal._timings[-1] == {"kind": "wait", "started_at": end - 12, "ended_at": end - 2, "wait_end": end, "polls": 3,
                                    "terminal": False}
    assert end + 30 < stage["deadline"] and broker.uncertainty == [] and not journal._failed


def test_describe_tasks_depois_do_fim_da_espera_recusa_antes_do_io(monkeypatch):
    broker, journal, native, clock = _ecs_broker(monkeypatch)
    _run(journal)
    stage = journal._request["stage"]
    clock.value = min(stage["deadline"] - 38, broker.credential_limit - 121, broker.session.deadline) - 30
    with pytest.raises(ValueError, match="^mode wait elapsed$"):
        _describe(journal)
    assert len(native) == 1


@pytest.mark.parametrize("case", ["antes-do-run-task", "outra-tarefa"])
def test_describe_tasks_so_da_tarefa_que_o_run_task_lancou(monkeypatch, case):
    broker, journal, native, _ = _ecs_broker(monkeypatch)
    if case == "outra-tarefa":
        _run(journal)
    with pytest.raises(ValueError, match="^mode describe_tasks own task$"):
        _describe(journal, task=OTHER_TASK if case == "outra-tarefa" else TASK)
    assert len(native) == (1 if case == "outra-tarefa" else 0)


@pytest.mark.parametrize("fail_at", [1, 3], ids=["run-task", "segunda-espera"])
def test_resultado_desconhecido_no_run_task_ou_na_espera_envenena_sem_retry(monkeypatch, fail_at):
    broker, journal, native, _ = _ecs_broker(monkeypatch, statuses=("RUNNING", "STOPPED"), fail_at=fail_at)
    with pytest.raises(ValueError, match="^mode native SDK outcome unknown$"):
        _run(journal)
        _describe(journal)
    assert len(native) == fail_at and broker.uncertainty and journal._failed and journal.unknown


def test_resposta_do_ecs_com_campo_fora_de_tasks_e_failures_envenena(monkeypatch):
    broker, journal, native, _ = _ecs_broker(monkeypatch)

    def sdk(service, name, **parameters):
        native.append((service, name, parameters))
        return {"tasks": [], "failures": [], "nextToken": "x", "ResponseMetadata": _metadata()}
    broker.session.client.call = sdk
    with pytest.raises(ValueError, match="^finite native ECS response$"):
        _run(journal)
    assert broker.uncertainty and journal._failed


def test_falha_do_run_task_volta_ao_filho_como_resposta_definitiva(monkeypatch):
    broker, journal, native, _ = _ecs_broker(monkeypatch)

    def sdk(service, name, **parameters):
        native.append((service, name, parameters))
        return {"tasks": [], "failures": [{"arn": "arn:x", "reason": "RESOURCE:MEMORY", "detail": "d"}],
                "ResponseMetadata": _metadata()}
    broker.session.client.call = sdk
    reply, _ = _run(journal)
    assert reply == {"kind": "sdk-result", "value": {"tasks": [], "failures": [
        {"arn": "arn:x", "reason": "RESOURCE:MEMORY", "detail": "d"}]}}
    with pytest.raises(ValueError, match="^mode run_task once$"):
        _run(journal)
