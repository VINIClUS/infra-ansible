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


def test_keeper_escreve_apenas_as_chaves_exatas_dos_passos_de_plano():
    from tools.cnesdata_delivery.session_policy import application_request
    request = application_request(_governance(), SOURCE, RUN, ATTEMPT, "keeper", application_purpose="promotion")
    assert _puts(request) == [RUN_ARN + "keeper/*", RUN_ARN + "terminal/*",
                              *[RUN_ARN + "plan-inputs-" + name + "/inputs.json" for name in sorted(PLANS)]]
    assert not any(resource.endswith("plan-inputs-*") or resource.endswith("plan-inputs-*/*") for resource in _puts(request))


def test_chaves_do_keeper_ficam_presas_a_execucao_e_tentativa_pedidas():
    from tools.cnesdata_delivery.session_policy import application_request
    other = application_request(_governance(), SOURCE, RUN + 1, ATTEMPT + 1, "keeper", application_purpose="promotion")
    assert all(f"/{RUN + 1}/{ATTEMPT + 1}/" in resource for resource in _puts(other))
    assert not any(f"/{RUN}/{ATTEMPT}/" in resource for resource in _puts(other))


def test_keeper_sem_catalogo_de_passos_nao_ganha_chave_de_plan_inputs():
    from tools.cnesdata_delivery.session_policy import application_request
    governance = _governance()
    del governance["lifecycle_steps"]
    request = application_request(governance, SOURCE, RUN, ATTEMPT, "keeper", application_purpose="promotion")
    assert _puts(request) == [RUN_ARN + "keeper/*", RUN_ARN + "terminal/*"]


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
