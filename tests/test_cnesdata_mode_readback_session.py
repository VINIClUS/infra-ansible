"""P16b c-1124-p16b-next item 2 (ruling 5): the mode_observe session of a ModeReadback, bound to its <mode>-readbacks request."""
import copy
import json

import pytest

from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401

import test_cnesdata_mode_session_sts as sts
from test_cnesdata_mode_readback import _responses
from test_cnesdata_mode_readback_context import GOVERNANCE, _Client, _Store, _world
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.session_policy import mode_session_policy

STAGES = {"unit": "unit", "recovery": "phase-c-recovery", "audit": "phase-c-audit"}


def _staged(monkeypatch, world, mode, purpose=None):
    real = world.keeper.lease.check

    def check():
        record = copy.deepcopy(real())
        window = record["lifecycle"]
        seconds = lc.governed_windows(window["windows"])["stages"][STAGES[mode]]
        window.update(stage=STAGES[mode], deadline=min(window["fixed_deadline"], window["admitted_at"] + seconds))
        if purpose is not None:
            record |= {"application_purpose": purpose, "context_kind": lc.APPLICATION_CONTEXTS[purpose]}
        return record
    if mode != "unit" or purpose is not None:
        monkeypatch.setattr(world.keeper.lease, "check", check)


def _resources(monkeypatch, owner):
    short = owner["owner_sha256"][:16]
    roles = json.loads(json.dumps(sts.ROLES).replace("a" * 16, short).replace("61" * 16, short.encode().hex()))
    monkeypatch.setattr(sts, "ROLES", roles)
    return roles["fields"]["resources"]


def _case(monkeypatch, mode="unit", mutation=None, purpose=None):
    world, _, _ = _world(monkeypatch)
    _staged(monkeypatch, world, mode, purpose)
    record = world.keeper.lease.check()
    owner, window = lc.owner_binding(record), record["lifecycle"]
    monkeypatch.setattr(sts, "OWNER", owner["owner_sha256"])
    governance, application = sts._governance(), sts._application()
    code, alias = lc.MODE_SESSION_OPERATIONS[mode + "-observe"][:2]
    resources = _resources(monkeypatch, owner)
    authority = sts._authority(governance, owner, resources=resources)
    if mutation == "owner":
        authority.scope["owner_sha256"] = "b" * 64
    if mutation == "role-arn":
        authority.roles[alias]["role"]["Role"]["Arn"] += "-other"
    if mutation == "session-name":
        authority.scope["session_names"][code] = "mc-" + code + "-" + "0" * 40
    if mutation == "identity":
        application.ops_pin["document"] = {"Version": "2012-10-17", "Statement": []}
    if mutation == "late":
        world.clock.value = window["deadline"] - 40
    now = world.clock.value
    factory, calls, native = sts._native(monkeypatch, code, alias, now, mutation)
    args = dict(governance=governance, application=application, authority=authority, guard=ag.KeeperGuard(world.keeper),
                mode=mode, credential_limit=now + (899 if mutation == "credential" else 3000), operation_session=factory,
                clock=lambda: world.clock.value)
    return args, world, (owner, window), calls, native


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


@pytest.mark.parametrize("mode", ["unit", "recovery", "audit"])
def test_sessao_de_leitura_assume_o_mode_observe_com_a_politica_de_observe_e_o_pedido_de_readbacks(monkeypatch, mode):
    args, _, (owner, window), calls, native = _case(monkeypatch, mode)
    session = _mb().assume_readback_session(**args)
    code = lc.MODE_SESSION_OPERATIONS[mode + "-observe"][0]
    request = _mb().mode_readback_request(owner, window, mode)
    minted = min(window["deadline"], args["credential_limit"], sts.DEADLINE)
    policy = mode_session_policy(mode + "-observe", resources=args["authority"].scope["resources"], owner_sha256=owner["owner_sha256"],
                                 deadline=minted)
    assert calls == [("sts", "assume_role", {"RoleArn": sts.ROLE_ARNS["mode_observe"], "RoleSessionName": sts.NAMES[code],
                                             "DurationSeconds": 900, "Policy": c.canonical(policy).decode().strip()})]
    assert native == [("sts", "get_caller_identity", {})]
    assert args["operation_session"].calls == [(mode + "-observe", sts.ROLE_ARNS["mode_observe"], sts.NAMES[code],
                                                request["stage"])]
    assert (session.code, session.alias, session.deadline) == (code, "mode_observe", minted)
    assert session.request_binding == c.sha(c.canonical(request)) and session.scope == args["authority"].scope
    assert session.client.governance["roles"] == {"mode_observe": sts.ROLE_ARNS["mode_observe"]}
    c.digest(session.commitment)


def test_sessao_de_leitura_alimenta_o_mode_readback_do_mesmo_lease(monkeypatch):
    args, world, _, _, _ = _case(monkeypatch)
    session = _mb().assume_readback_session(**args)
    session.client = _Client("unit")
    readback = _mb().ModeReadback(_Store(), GOVERNANCE, session, guard=args["guard"], mode="unit",
                                  clock=lambda: world.clock.value)
    assert readback.read() == _mb().mode_readback_bytes("unit", session.scope["resources"], _responses("unit"))


REFUSALS = {
    "late": "^mode session original stage/credential window$",
    "credential": "^mode session original stage/credential window$",
    "owner": "^mode session original owner$",
    "role-arn": "^mode session role readback$",
    "session-name": "^effective IAM case assume-uo$",
    "identity": "^mode session application documents$",
}


@pytest.mark.parametrize("mutation", sorted(REFUSALS))
def test_sessao_de_leitura_recusa_antes_do_sts(monkeypatch, mutation):
    args, _, _, calls, native = _case(monkeypatch, mutation=mutation)
    with pytest.raises(ValueError, match=REFUSALS[mutation]):
        _mb().assume_readback_session(**args)
    assert calls == native == [] and args["operation_session"].calls == []


@pytest.mark.parametrize("mutation, message", [("expiration", "^mode STS expiration$"),
                                               ("native-arn", "^mode exact native role ID/session/account$"),
                                               ("native-id", "^mode exact native role ID/session/account$")])
def test_sessao_de_leitura_recusa_resposta_do_sts_fora_do_exato(monkeypatch, mutation, message):
    args, _, _, calls, _ = _case(monkeypatch, mutation=mutation)
    with pytest.raises(ValueError, match=message):
        _mb().assume_readback_session(**args)
    assert len(calls) == 1


@pytest.mark.parametrize("change", ["modo", "guarda", "autoridade", "proposito"])
def test_sessao_de_leitura_fora_do_contexto_original_recusa_antes_do_sts(monkeypatch, change):
    args, world, _, calls, native = _case(monkeypatch, purpose="mode-readiness-drill" if change == "proposito" else None)
    if change == "modo":
        args["mode"] = "drill"
    if change == "guarda":
        args["guard"] = type("Guard", (), {"keeper": world.keeper, "check": lambda self, seconds=0: None})()
    if change == "autoridade":
        args["authority"] = tuple(args["authority"])
    with pytest.raises(ValueError, match="^mode readback original context$"):
        _mb().assume_readback_session(**args)
    assert calls == native == [] and args["operation_session"].calls == []


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_sessao_de_leitura_de_outro_modo_na_janela_unit_recusa(monkeypatch, mode):
    args, _, _, calls, _ = _case(monkeypatch)
    args["mode"] = mode
    with pytest.raises(ValueError, match="^mode session original stage/credential window$"):
        _mb().assume_readback_session(**args)
    assert calls == [] and args["operation_session"].calls == []


def test_sessao_de_leitura_com_lease_perdido_nao_chega_ao_sts(monkeypatch):
    args, world, _, calls, _ = _case(monkeypatch)
    real = world.keeper.lease.check
    seen = []

    def check():
        seen.append(1)
        if len(seen) > 1:
            raise ValueError("keeper lease lost")
        return real()
    monkeypatch.setattr(world.keeper.lease, "check", check)
    with pytest.raises(ValueError, match="^keeper lease lost$"):
        _mb().assume_readback_session(**args)
    assert calls == [] and args["operation_session"].calls == []
