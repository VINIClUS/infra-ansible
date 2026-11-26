"""Lease do legado escrevivel nas sessoes build/request; lifecycle read-only; identidade le o ops e a ativacao."""
import json

import pytest

from fixtures.cnesdata_iam_evaluation import effective
from test_cnesdata_delivery_oidc import activation_input, application_values, native, render, rendered_policies
from test_cnesdata_session_lifecycle_delete_deny import governance
from tools.cnesdata_delivery import session_policy as sp
from tools.cnesdata_delivery.coordination_lease import KEY

assert native
LEASE = "arn:aws:s3:::synthetic-state/" + KEY


@pytest.fixture(scope="module")
def world(native):
    resources, _ = render(native, application_values(), "lease-ops-read")
    return resources


@pytest.mark.parametrize("role", ["plan", "deploy"])
def test_sessao_legada_build_request_escreve_o_lease(world, role):
    identity, managed = rendered_policies(world, role)
    inline = json.loads(sp.request(governance(), "a" * 40, 42, 1, role, [])["Policy"])
    assert effective(identity, managed, inline, "s3:PutObject", LEASE)
    assert effective(identity, managed, inline, "s3:GetObject", LEASE)
    assert not effective(identity, managed, inline, "s3:DeleteObject", LEASE)


@pytest.mark.parametrize("role", ["plan", "deploy"])
def test_sessao_de_ciclo_de_vida_continua_sem_escrita_no_lease(world, role):
    identity, managed = rendered_policies(world, role)
    for direction in ("advance",):
        inline = json.loads(sp.lifecycle_request(
            governance(), "a" * 40, 42, 1, role, "step", direction=direction)["Policy"])
        assert effective(identity, managed, inline, "s3:GetObject", LEASE)
        assert not effective(identity, managed, inline, "s3:PutObject", LEASE)


def test_identidade_da_application_le_a_politica_ops_e_a_de_sessao(world):
    identity = json.loads(world["aws_iam_role_policy.application[0]"]["policy"])
    arn = "arn:aws:iam::111122223333:policy/cnesdata-prod-application-{}"
    from fixtures.cnesdata_iam_evaluation import decision
    for name in ("session", "ops-session"):
        for action in ("iam:GetPolicy", "iam:GetPolicyVersion"):
            assert decision(identity, action, arn.format(name)) == "Allow", (name, action)


def test_identidade_do_plan_le_a_politica_de_ativacao(native):
    resources, _ = render(native, activation_input(application_values()), "lease-ops-activation")
    identity, _ = rendered_policies(resources, "plan")
    from fixtures.cnesdata_iam_evaluation import decision
    arn = "arn:aws:iam::111122223333:policy/cnesdata-test-plan-activation-session"
    for action in ("iam:GetPolicy", "iam:GetPolicyVersion"):
        assert decision(identity, action, arn) == "Allow"
