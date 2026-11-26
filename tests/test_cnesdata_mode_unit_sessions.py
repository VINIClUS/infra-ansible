"""P16b ruling 7 item 1: unit-start mints ux and its wait part uw on the same role and session name, both before any
dispatch write."""
import pytest

from test_cnesdata_mode_effect_broker import _Evidence
from test_cnesdata_mode_session_sts import DEADLINE, NAMES, OWNER, RESOURCES, ROLE_ARNS, _case
from tools.cnesdata_delivery import contract as c


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _policies(args):
    from tools.cnesdata_delivery.session_policy import mode_session_policy, mode_unit_wait_policy
    minted = min(args["journal"]._request["stage"]["deadline"], args["credential_limit"], DEADLINE)
    start = mode_session_policy("unit-start", resources=RESOURCES, owner_sha256=OWNER, deadline=minted)
    wait = mode_unit_wait_policy(resources=RESOURCES, owner_sha256=OWNER, deadline=minted)
    return [c.canonical(policy).decode().strip() for policy in (start, wait)]


def test_unit_start_cunha_ux_e_uw_no_mesmo_papel_e_nome_de_sessao(monkeypatch):
    args, calls, native = _case(monkeypatch, "unit-start")
    start, wait = _mb().assume_unit_start_sessions(**args)
    assert calls == [("sts", "assume_role", {"RoleArn": ROLE_ARNS["mode_dispatch"], "RoleSessionName": NAMES["ux"],
                                             "DurationSeconds": 900, "Policy": policy}) for policy in _policies(args)]
    assert native == [("sts", "get_caller_identity", {})] * 2
    stage = args["journal"]._request["stage"]
    assert args["operation_session"].calls == [("unit-start", ROLE_ARNS["mode_dispatch"], NAMES["ux"], stage)] * 2
    assert (start.code, start.alias, wait.code, wait.alias) == ("ux", "mode_dispatch", "uw", "mode_dispatch")
    assert start.request_binding == wait.request_binding == c.sha(c.canonical(args["journal"]._request))
    assert start.deadline == wait.deadline and start.scope == wait.scope
    assert start.commitment != wait.commitment


@pytest.mark.parametrize("operation", ["unit-seed", "recovery-start", "audit-start"])
def test_cunhagem_do_unit_start_e_so_do_unit_start(monkeypatch, operation):
    args, calls, _ = _case(monkeypatch, operation)
    with pytest.raises(ValueError, match="^mode unit sessions original operation$"):
        _mb().assume_unit_start_sessions(**args)
    assert calls == [] and args["operation_session"].calls == []


@pytest.mark.parametrize("name, message", [("session.uw", "^mode stage evaluation documents$"),
                                           ("session.ux", "^mode stage evaluation documents$")])
def test_documento_de_qualquer_parte_divergente_recusa_antes_de_qualquer_sts(monkeypatch, name, message):
    args, calls, native = _case(monkeypatch, "unit-start")
    args["authority"].documents[name] = {"Version": "2012-10-17", "Statement": []}
    with pytest.raises(ValueError, match=message):
        _mb().assume_unit_start_sessions(**args)
    assert calls == native == [] and args["operation_session"].calls == []


def test_sessao_de_efeito_isolada_nao_cunha_a_parte_uw(monkeypatch):
    args, calls, _ = _case(monkeypatch, "unit-start")
    session = _mb().assume_mode_session(**args)
    assert session.code == "ux" and len(calls) == 1


def _broker(monkeypatch, operation="unit-start", wait=None):
    args, _, _ = _case(monkeypatch, operation)
    if operation == "unit-start":
        start, sessions = _mb().assume_unit_start_sessions(**args)
        wait = sessions if wait is None else wait(start, sessions)
    else:
        start = _mb().assume_mode_session(**args)
    return _mb().ModeBroker(_Evidence(), args["governance"], args["journal"], start, prepared_sha256="3" * 64,
                            credential_limit=args["credential_limit"], clock=args["clock"], wait=wait)


def test_broker_do_unit_start_guarda_a_parte_de_espera(monkeypatch):
    broker = _broker(monkeypatch)
    assert broker.wait.code == "uw" and broker.wait.request_binding == broker.session.request_binding


@pytest.mark.parametrize("mutation", ["start-as-wait", "other-binding", "foreign"])
def test_broker_recusa_espera_que_nao_e_a_parte_uw_da_mesma_requisicao(monkeypatch, mutation):
    def wait(start, sessions):
        if mutation == "start-as-wait":
            return start
        if mutation == "other-binding":
            sessions.request_binding = "0" * 64
            return sessions
        return object()
    with pytest.raises(ValueError, match="^mode wait original context$"):
        _broker(monkeypatch, wait=wait)


def test_broker_fora_do_unit_start_recusa_parte_de_espera(monkeypatch):
    args, _, _ = _case(monkeypatch, "unit-start")
    _, wait = _mb().assume_unit_start_sessions(**args)
    with pytest.raises(ValueError, match="^mode wait original context$"):
        _broker(monkeypatch, "recovery-start", wait=lambda *_: wait)
