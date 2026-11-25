"""Write-side exclusivity of the keeper plan inputs: exact keys, reserved prefix, step name bound."""
import json

import pytest

SOURCE, RUN, ATTEMPT = "b" * 40, 44, 2
PLANS = ("observer-bootstrap-plan", "application-prepare-operational-plan", "phase-b-plan",
         "phase-c-recovery-plan", "phase-c-audit-plan")
RUN_ARN = "arn:aws:s3:::synthetic-evidence/cnesdata/prod/evidence/lifecycle/" + SOURCE + f"/{RUN}/{ATTEMPT}/"


def _governance(extra=None):
    steps = {name: {"role": "plan", "job_name": name} for name in PLANS}
    steps |= {"observer-bootstrap-audit": {"role": "audit", "job_name": "a"}, "observer-bootstrap-deploy": {"role": "deploy", "job_name": "d"}}
    return {"account_id": "111122223333", "state_bucket": "synthetic-state", "evidence_bucket": "synthetic-evidence",
            "evidence_prefix": "cnesdata/prod/evidence/", "application_delegations": {},
            "evidence_kms_key_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000002",
            "roles": {"application": "arn:aws:iam::111122223333:role/cnesdata-prod-application"}, "lifecycle_steps": steps} | (extra or {})


def _puts(request):
    for statement in json.loads(request["Policy"])["Statement"]:
        if statement["Action"] == "s3:PutObject" and statement["Effect"] == "Allow":
            return statement["Resource"]


WILDCARD = RUN_ARN + "plan-inputs-*/inputs.json"


def test_keeper_escreve_apenas_keeper_terminal_e_um_recurso_limitado_de_plan_inputs():
    from tools.cnesdata_delivery.session_policy import application_request
    request = application_request(_governance(), SOURCE, RUN, ATTEMPT, "keeper", application_purpose="promotion")
    assert _puts(request) == [RUN_ARN + "keeper/*", RUN_ARN + "terminal/*", WILDCARD]


def test_recurso_de_plan_inputs_nao_e_alargado_nem_perde_o_membro():
    from tools.cnesdata_delivery.session_policy import application_request
    resources = _puts(application_request(_governance(), SOURCE, RUN, ATTEMPT, "keeper", application_purpose="promotion"))
    assert RUN_ARN + "*" not in resources and not any(r.endswith("plan-inputs-*") or r.endswith("plan-inputs-*/*") for r in resources)
    assert [r for r in resources if "plan-inputs-" in r] == [WILDCARD]


def test_chaves_do_keeper_ficam_presas_a_execucao_e_tentativa_pedidas():
    from tools.cnesdata_delivery.session_policy import application_request
    other = application_request(_governance(), SOURCE, RUN + 1, ATTEMPT + 1, "keeper", application_purpose="promotion")
    assert all(f"/{RUN + 1}/{ATTEMPT + 1}/" in resource for resource in _puts(other))
    assert not any(f"/{RUN}/{ATTEMPT}/" in resource for resource in _puts(other))


@pytest.mark.parametrize("step, delegations, sessions", [
    ("publish-static", ["normal", "observer"], {"normal": "sp-publish-" + "a" * 40, "observer": "sp-i-" + "a" * 40}),
    ("unit-start", ["mode_dispatch"], {"mode_dispatch": "mc-ux-" + "a" * 40}),
    ("closed-ready", [], None),
], ids=["publish-static", "sessao-de-modo", "closed-ready"])
def test_sessao_de_aplicacao_que_nao_e_keeper_nunca_escreve_em_plan_inputs(step, delegations, sessions):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.session_policy import application_request
    governance = _governance() | {"application_delegations": {name: f"arn:aws:iam::111122223333:role/cnesdata-prod-{suffix}"
                                                              for name, suffix in lc.APPLICATION_DELEGATIONS.items()}}
    request = application_request(governance, SOURCE, RUN, ATTEMPT, step, application_purpose="promotion",
                                  delegations=delegations, sessions=sessions)
    resources = _puts(request)
    assert resources == [RUN_ARN + step + "/*"] and "plan-inputs-" not in request["Policy"]


@pytest.mark.parametrize("role", ["plan", "audit", "deploy"])
def test_sessoes_de_gate_nao_escrevem_no_prefixo_reservado(role):
    from tools.cnesdata_delivery.session_policy import lifecycle_request
    with pytest.raises(ValueError, match="reserved plan-inputs step"):
        lifecycle_request(_governance(), SOURCE, RUN, ATTEMPT, role, "plan-inputs-phase-b-plan", direction="advance")


def test_sessao_de_operacao_da_aplicacao_nao_escreve_no_prefixo_reservado():
    from tools.cnesdata_delivery.session_policy import application_request
    with pytest.raises(ValueError, match="reserved plan-inputs step"):
        application_request(_governance(), SOURCE, RUN, ATTEMPT, "plan-inputs-phase-b-plan", application_purpose="promotion")


def test_catalogo_recusa_passo_com_o_prefixo_reservado():
    from tools.cnesdata_delivery import plan_inputs
    with pytest.raises(ValueError, match="reserved plan-inputs step"):
        plan_inputs.plan_steps(_governance()["lifecycle_steps"] | {"plan-inputs-x": {"role": "deploy"}})


def test_catalogo_recusa_nome_de_plano_acima_de_52_caracteres():
    from tools.cnesdata_delivery import plan_inputs
    steps = _governance()["lifecycle_steps"]
    assert plan_inputs.plan_steps(steps | {"p" * 52: {"role": "plan"}})
    with pytest.raises(ValueError, match="plan step name length"):
        plan_inputs.plan_steps(steps | {"p" * 53: {"role": "plan"}})
