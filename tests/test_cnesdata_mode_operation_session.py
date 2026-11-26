"""P16f: execute()'s operation session serves the mode operations with the delegation their broker evaluates."""

from types import SimpleNamespace

import pytest
from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

PROMOTION_MODE_OPERATIONS = [operation for operation, (_, _, context, _) in lc.MODE_SESSION_OPERATIONS.items()
                             if context == lc.APPLICATION_CONTEXTS["promotion"]]


def _world(monkeypatch):
    from test_cnesdata_application_gate import _policy_world
    return _policy_world(monkeypatch)


def _mode_role(world, operation):
    code, alias = lc.MODE_SESSION_OPERATIONS[operation][:2]
    return code, {"role_arn": world.governance["application_delegations"][alias], "role_id": "AROAMODEFIXTURE",
                  "session_name": f"mc-{code}-" + "a" * 40}


def _fence_request(world, operation, role):
    from tools.cnesdata_delivery import session_policy
    owner = world.owner
    return session_policy.application_request(world.governance, owner["source_sha"], owner["run_id"], owner["run_attempt"],
        operation, application_purpose="promotion", delegations=("fence_operator",),
        sessions={"fence_operator": role["session_name"]})


def test_cobre_todas_as_operacoes_de_modo_de_promocao():
    assert sorted(PROMOTION_MODE_OPERATIONS) == sorted(("unit-seed", "unit-start", "unit-observe", "recovery-seed",
                                                         "recovery-start", "recovery-observe", "audit-start", "audit-observe"))


@pytest.mark.parametrize("operation", PROMOTION_MODE_OPERATIONS)
def test_sessao_de_operacao_de_modo_e_a_restricao_que_o_broker_avalia(monkeypatch, operation):
    from tools.cnesdata_delivery import mode_broker, session_owner
    world = _world(monkeypatch)
    code, role = _mode_role(world, operation)
    world.args["operation_session"](operation, role, {"deadline": 1900})
    (restriction,) = world.minted.values()
    application = world.args["authority"]
    documents = {"application_identity": session_owner.application_identity_document(world.governance,
                                                                                    application.application_fragment),
                 "application_managed": session_owner.operation_authority(application).pin["document"],
                 "application_session." + code: c.loads(restriction["Policy"].encode())}
    target = SimpleNamespace(owner=world.owner, operation=operation)
    mode_broker._mode_application(world.governance, application, documents, target, role, lambda: 1300)


@pytest.mark.parametrize("operation", lc.MODE_OBSERVES)
def test_observe_de_modo_pelo_caminho_fence_usa_o_fence_operator(monkeypatch, operation):
    world = _world(monkeypatch)
    role = c.loads(world.args["prepared"]["fence-role.json"], canonical=True)
    world.args["operation_session"](operation, role, {"deadline": 1900})
    (restriction,) = world.minted.values()
    assert restriction == _fence_request(world, operation, role)


@pytest.mark.parametrize("operation, use_fence_role, message", [
    ("recovery-start", True, "operation session delegation"), ("unit-seed", True, "operation session delegation"),
    ("drill-seed", False, "operation session operation"), ("drill-observe", False, "operation session operation")])
def test_sessao_de_operacao_recusa_efeito_de_modo_fora_da_sua_delegacao(monkeypatch, operation, use_fence_role, message):
    world = _world(monkeypatch)
    role = (c.loads(world.args["prepared"]["fence-role.json"], canonical=True) if use_fence_role
            else _mode_role(world, operation)[1])
    with pytest.raises(ValueError, match=f"^{message}$"):
        world.args["operation_session"](operation, role, {"deadline": 1900})
    assert world.minted == {}
