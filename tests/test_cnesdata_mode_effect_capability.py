"""P16b fix round 1 item 2, ruling 8 amendment 1: the seed and start capability on the stage ModeAuthority (us, rs, rx,
ax; ux and uw behind the unit-start gate), the readback session of the mode as reads, and both unit-start gate layers."""
import ast
import inspect
from types import SimpleNamespace

import pytest

import test_cnesdata_mode_session_sts as sts
from test_cnesdata_mode_readback_context import _Store
from test_cnesdata_mode_readback_session import _case as _read_case
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery import lifecycle_runtime as lr
from tools.cnesdata_delivery import mode_broker as mb

CAPABILITY, SOURCE = ag.mode_capability, ag.mode_input_source
EFFECTS = ("unit-seed", "recovery-seed", "unit-start", "recovery-start", "audit-start")
INPUTS = {operation: {name: c.canonical({"fixture_input": name}) for name in lc.ADAPTER_INPUTS[operation].split()}
          for operation in EFFECTS}
PREPARED = c.canonical({"fixture_prepared": "fence"})
SESSIONS = ("mode_prepared_authority", "assume_readback_session", "assume_mode_session", "assume_unit_start_sessions",
            "unit_start_plan", "_mode_sts")


class _Stop(Exception):
    pass


def test_portao_do_unit_start_entregue_e_o_literal_fechado_sem_outra_atribuicao():
    tree = ast.parse(inspect.getsource(mb))
    assigned = [node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
                and any(isinstance(target, ast.Name) and target.id == "MODE_UNIT_START_OPEN"
                        for target in (node.targets if isinstance(node, ast.Assign) else [node.target]))]
    assert mb.MODE_UNIT_START_OPEN is False and len(assigned) == 1
    assert isinstance(assigned[0].value, ast.Constant) and assigned[0].value.value is False
    assert not any(isinstance(node, ast.Global) and "MODE_UNIT_START_OPEN" in node.names for node in ast.walk(tree))


def _touch(monkeypatch):
    touched = []
    for name in SESSIONS:
        def refuse(*args, _name=name, **kwargs):
            touched.append(_name)
            raise AssertionError(_name)
        monkeypatch.setattr(mb, name, refuse)
    return touched


def test_capability_do_unit_start_recusa_antes_de_qualquer_sts_e_le_o_portao_a_cada_chamada(monkeypatch):
    touched = _touch(monkeypatch)
    journal = SimpleNamespace(_failed=False, _request={"operation": "unit-start"})
    with pytest.raises(ValueError, match="^mode_unit_start=p16d_pending$"):
        CAPABILITY(journal=journal, keeper=None, guard=None, context=None)
    assert journal._failed is True and touched == []
    monkeypatch.setattr(mb, "MODE_UNIT_START_OPEN", True)
    journal = SimpleNamespace(_failed=False, _request={"operation": "unit-start"})
    with pytest.raises(ValueError, match="^mode effect original context$"):
        CAPABILITY(journal=journal, keeper=None, guard=None, context=None)
    assert journal._failed is True and touched == []


def test_estagio_de_producao_recusa_o_unit_start_antes_de_qualquer_capability_ou_sts(monkeypatch):
    from test_cnesdata_mode_stages import _enter_unit, _known, _mode_world
    world = _mode_world(monkeypatch)
    _enter_unit(world)
    fake_source, fake_capability = ag.mode_input_source, ag.mode_capability
    touched = _touch(monkeypatch)
    context = ag.ModeContext(governance="g", authority="a", prepared="p", credential_limit=6000, operation_session="o",
                             clock=world.clock, aws="evidence", activation_sha256=c.sha(world.activation), product="product")
    capabilities = []

    def source(**kwargs):
        return (SOURCE if kwargs["operation"] == "unit-start" else fake_source)(**kwargs)

    def capability(*, journal, keeper, guard):
        capabilities.append(journal._request["operation"])
        real = CAPABILITY if journal._request["operation"] == "unit-start" else fake_capability
        return real(journal=journal, keeper=keeper, guard=guard, context=context)

    def invoke(*, journal, timeout):
        return ag.invoke_adapter(journal=journal, timeout=timeout)
    monkeypatch.setattr(ag, "mode_input_source", source)
    with pytest.raises(ValueError, match="^mode_unit_start=p16d_pending$"):
        ag.mode_stage(world.keeper, "unit", known=_known(world), invoke=invoke, capability=capability,
                      credential_limit=6000, clock=world.clock, context=context)
    assert touched == [] and capabilities == ["unit-record", "unit-seed"]
    assert [call[0] for call in world.mode.calls] == ["unit-record", "unit-seed"]
    assert not any(type(item) is mb.ModeReadback for item in world.keeper._contexts)
    assert all(item._request["operation"] != "unit-start" for item in world.keeper._contexts
               if type(item) is ag.AdapterJournal)


@pytest.mark.parametrize("operation", ["unit-seed", "recovery-seed", "recovery-start", "audit-start"])
def test_nenhum_seed_ou_start_recusa_mais_com_mode_broker_unconnected(monkeypatch, operation):
    touched = _touch(monkeypatch)
    journal = SimpleNamespace(_failed=False, _request={"operation": operation})
    with pytest.raises(ValueError, match="^mode effect original context$"):
        CAPABILITY(journal=journal, keeper=None, guard=None, context=None)
    assert journal._failed is True and touched == []
    assert "mode_broker=unconnected" not in inspect.getsource(ag)


def _effect(monkeypatch, operation, *, read=True, activation=None):
    mode = operation.partition("-")[0]
    args, world, (owner, window), _, _ = _read_case(monkeypatch, mode)
    readback = None
    if read:
        reads = mb.assume_readback_session(**args)
        readback = mb.ModeReadback(_Store(), args["governance"], reads, guard=args["guard"], mode=mode, clock=args["clock"])
    code, alias = lc.MODE_SESSION_OPERATIONS[operation][:2]
    factory, calls, _ = sts._native(monkeypatch, code, alias, world.clock.value)
    authorities = []
    monkeypatch.setattr(mb, "mode_prepared_authority",
                        lambda prepared, **kwargs: authorities.append((prepared, kwargs)) or args["authority"])
    context = ag.ModeContext(governance=args["governance"], authority=args["application"],
                             prepared=lr.PreparedFence({"fence-prepared.json": PREPARED}),
                             credential_limit=args["credential_limit"], operation_session=factory, clock=args["clock"],
                             aws=_Store(), activation_sha256=activation or c.sha(world.activation), product="product")
    return SimpleNamespace(world=world, args=args, readback=readback, context=context, calls=calls,
                           authorities=authorities, owner=owner, window=window)


def _run(effect, operation):
    admitted = []

    def capability(*, journal, keeper, guard):
        broker = CAPABILITY(journal=journal, keeper=keeper, guard=guard, context=effect.context)
        admitted.append(broker)
        return broker

    def invoke(*, journal, timeout):
        broker = journal._broker
        admitted.append((broker.aws, broker.session.client, getattr(broker.reads, "client", None),
                         getattr(broker.wait, "client", None)))
        raise _Stop()
    with pytest.raises(_Stop):
        ag.run_mode_operation(effect.world.keeper, operation, inputs=dict(INPUTS[operation]),
                              activation=effect.world.activation, invoke=invoke, capability=capability,
                              credential_limit=effect.args["credential_limit"], clock=effect.args["clock"])
    return admitted


@pytest.mark.parametrize("operation", ["unit-seed", "recovery-seed", "recovery-start", "audit-start"])
def test_capability_de_seed_e_start_cunha_a_sessao_mc_e_admite_o_mode_broker_com_a_leitura_do_readback(monkeypatch,
                                                                                                    operation):
    start = operation.endswith("-start")
    effect = _effect(monkeypatch, operation, read=start)
    broker, (aws, client, reads, wait) = _run(effect, operation)
    code, alias = lc.MODE_SESSION_OPERATIONS[operation][:2]
    assert type(broker) is mb.ModeBroker and broker.journal._broker is broker and broker in effect.world.keeper._contexts
    assert (broker.session.code, broker.session.alias) == (code, alias)
    assert broker.session.request_binding == c.sha(c.canonical(broker.journal._request))
    assert broker.reads is (effect.readback.session if start else None) and broker.wait is None and broker.unit is None
    assert broker.prepared_sha256 == c.sha(PREPARED) and broker.credential_limit == effect.args["credential_limit"]
    assert aws is effect.context.aws and client is not None and (reads is not None) is start and wait is None
    assert [call[:2] for call in effect.calls] == [("sts", "assume_role")]
    (prepared, kwargs), = effect.authorities
    assert prepared is effect.context.prepared and kwargs == {
        "governance": effect.args["governance"], "application": effect.args["application"], "owner": effect.owner,
        "activation_sha256": c.sha(effect.world.activation), "window": effect.window}
    assert broker.aws is None and broker.session.client is None and (not start or broker.reads.client is None)


@pytest.mark.parametrize("mutation, message", [("no-readback", "^mode readback original context$"),
                                               ("authority", "^mode prepared authority binding$"),
                                               ("activation", "^mode effect original context$")])
def test_capability_de_start_recusa_antes_do_sts_e_envenena_o_journal(monkeypatch, mutation, message):
    effect = _effect(monkeypatch, "recovery-start", read=mutation != "no-readback",
                     activation="9" * 64 if mutation == "activation" else None)
    if mutation == "authority":
        def binding(prepared, **kwargs):
            raise ValueError("mode prepared authority binding")
        monkeypatch.setattr(mb, "mode_prepared_authority", binding)
    with pytest.raises(ValueError, match=message):
        _run(effect, "recovery-start")
    (journal,) = [item for item in effect.world.keeper._contexts
                  if type(item) is ag.AdapterJournal and item._request["operation"] == "recovery-start"]
    assert effect.calls == [] and journal._failed is True and getattr(journal, "_broker", None) is None
    assert not any(type(item) is mb.ModeBroker for item in effect.world.keeper._contexts)


def _plan(effect, order):
    def plan(keeper, journal, *, resources, now):
        order.append(("plan", len(effect.calls), keeper is effect.world.keeper, journal._request["operation"],
                      resources == effect.args["authority"].scope["resources"], now == effect.args["clock"]()))
        return mb.UnitPlan(mb.UnitLocator("prod-canary-fixture", ("run",), effect.owner["owner_sha256"], "0" * 64, "unit",
                                          "promotion"), None, None, None, (), "execution")
    return plan


def test_unit_start_aberto_por_fixture_planeja_antes_de_cunhar_ux_e_uw_e_entrega_o_plano_ao_broker(monkeypatch):
    monkeypatch.setattr(mb, "MODE_UNIT_START_OPEN", True)
    effect, order = _effect(monkeypatch, "unit-start"), []
    monkeypatch.setattr(mb, "unit_start_plan", _plan(effect, order))
    broker, (_, client, reads, wait) = _run(effect, "unit-start")
    assert order == [("plan", 0, True, "unit-start", True, True)]
    assert (broker.session.code, broker.wait.code) == ("ux", "uw") and broker.wait.alias == broker.session.alias
    assert broker.unit.locator.owner_sha256 == effect.owner["owner_sha256"] and broker.reads is effect.readback.session
    assert [call[:2] for call in effect.calls] == [("sts", "assume_role")] * 2
    assert client is not None and reads is not None and wait is not None
    assert broker.session.client is None and broker.reads.client is None and broker.wait.client is None


def test_unit_start_aberto_por_fixture_recusa_no_plano_sem_cunhar_credencial(monkeypatch):
    monkeypatch.setattr(mb, "MODE_UNIT_START_OPEN", True)
    effect = _effect(monkeypatch, "unit-start")

    def plan(keeper, journal, *, resources, now):
        raise ValueError("mode unit plan record")
    monkeypatch.setattr(mb, "unit_start_plan", plan)
    with pytest.raises(ValueError, match="^mode unit plan record$"):
        _run(effect, "unit-start")
    assert effect.calls == []
