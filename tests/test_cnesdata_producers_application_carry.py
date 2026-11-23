"""P19 audit carries: catalog mirrors the consumer's static step rules, lease keys, assembly keys."""
import copy
import re

import pytest

from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.producers import application, governance_assembly

ARN = "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod-lifecycle"
SELECTION = {"selection_version": 1, "ext2_post_upload_receipt_v1": {"fixture": "isolated"}}


def infra(role, purpose, job_name, **extra):
    fields = {"job_name": job_name, "producer_job": "execute", "admission_steps": ["Repeat source gate"],
              "mode": extra.pop("mode", "initial"), "direction": extra.pop("direction", "advance")}
    return application.step(role, purpose, **fields, **extra)


def base_catalog():
    fence = lc.FENCE_PREPARE_PRODUCER
    return {
        "operational-plan": infra("plan", "application-prepare", "operational-plan / execute", mode="operational",
                                  activation_selection=copy.deepcopy(SELECTION)),
        "operational-audit": infra("audit", "application-prepare", "operational-audit / audit", mode="operational"),
        fence["step"]: infra("deploy", "application-prepare", fence["job_name"], mode="operational",
                             historical_entry=True),
        "phase-b-deploy": infra("deploy", "phase-b", "phase-b / execute", mode="phase-b"),
        "recovery-deploy": infra("deploy", "phase-c-recovery", "recovery / execute", mode="recovery",
                                 direction="converge", delete_resources=[ARN]),
    }


def mutated(change):
    steps = base_catalog()
    change(steps)
    return steps


def test_catalogo_de_referencia_e_aceito():
    application.catalog(base_catalog())


FENCE = lc.FENCE_PREPARE_PRODUCER["step"]


@pytest.mark.parametrize("change", [
    lambda s: s["operational-audit"].update(historical_entry=True),
    lambda s: s["phase-b-deploy"].update(historical_entry=True),
    lambda s: s[FENCE].update(historical_entry=False),
    lambda s: s["recovery-deploy"].update(historical_entry=True),
], ids=["audit", "outro-purpose", "valor-falso", "converge"])
def test_catalogo_recusa_historical_entry_fora_de_plan_deploy_prepare_advance(change):
    with pytest.raises(ValueError, match="step historical entry"):
        application.catalog(mutated(change))


@pytest.mark.parametrize("change", [
    lambda s: s["operational-plan"].pop("activation_selection"),
    lambda s: s["operational-plan"].update(activation_selection="isolated"),
    lambda s: s["operational-plan"].update(activation_selection={"selection_version": 1}),
    lambda s: s["operational-plan"]["activation_selection"].update(selection_version=2),
    lambda s: s["operational-plan"]["activation_selection"].update(selection_version=True),
    lambda s: s["operational-plan"]["activation_selection"].update(extra=1),
    lambda s: s["operational-plan"]["activation_selection"].update(ext2_post_upload_receipt_v1="ref"),
], ids=["ausente", "nao-dict", "sem-referencia", "versao-2", "versao-bool", "chave-extra", "referencia-nao-dict"])
def test_catalogo_recusa_plano_operacional_sem_selecao_de_ativacao_fechada(change):
    with pytest.raises(ValueError, match="step activation selection"):
        application.catalog(mutated(change))


@pytest.mark.parametrize("change", [
    lambda s: s["operational-plan"].update(delete_resources=[ARN]),
    lambda s: s["phase-b-deploy"].update(delete_resources=[ARN]),
], ids=["plan", "deploy-advance"])
def test_catalogo_recusa_delete_resources_em_plan_e_deploy_advance(change):
    with pytest.raises(ValueError, match="step delete resources"):
        application.catalog(mutated(change))


@pytest.mark.parametrize("value", [
    True, None, [], [ARN] * 2, [ARN.replace("states", "iam")], [ARN.replace("cnesdata-prod", "other")],
    [ARN.replace("111122223333", "12345")], [ARN + str(index) for index in range(9)], "arn", [1],
], ids=["true", "nulo", "vazio", "repetido", "servico", "outro-produto", "conta", "nove", "string", "nao-string"])
def test_catalogo_recusa_converge_deploy_com_inventario_de_delete_invalido(value):
    with pytest.raises(ValueError, match="step delete resources"):
        application.catalog(mutated(lambda s: s["recovery-deploy"].update(delete_resources=value)))


def test_catalogo_recusa_converge_deploy_sem_inventario_de_delete():
    with pytest.raises(ValueError, match="step delete resources"):
        application.catalog(mutated(lambda s: s["recovery-deploy"].pop("delete_resources")))


def test_catalogo_aceita_ate_oito_arns_unicos():
    arns = [ARN + str(index) for index in range(8)]
    application.catalog(mutated(lambda s: s["recovery-deploy"].update(delete_resources=arns)))


@pytest.mark.parametrize("field", ["purpose", "direction", "mode"])
def test_catalogo_recusa_fence_cujo_delta_difere_do_produtor_fixo(field):
    fence = lc.FENCE_PREPARE_PRODUCER
    steps = base_catalog()
    steps[FENCE].update({field: "converge" if field == "direction" else "other"})
    if field == "direction":
        steps[FENCE]["delete_resources"] = [ARN]
    with pytest.raises(ValueError, match="catalog fence prepare producer|step"):
        application.catalog(steps)
    assert fence[field] != steps[FENCE][field]


def test_catalogo_recusa_fence_com_direction_converge_com_razao_propria():
    steps = base_catalog()
    steps[FENCE].update(direction="converge", delete_resources=[ARN])
    steps[FENCE].pop("historical_entry")
    with pytest.raises(ValueError, match="catalog fence prepare delta"):
        application.catalog(steps)


def lease(**changes):
    return {"status": "released", "repository": "VINIClUS/CnesData", "run_id": 7, "run_attempt": 1,
            "checkpoint_sha256": "a" * 64} | changes


@pytest.mark.parametrize("changes, reason", [
    ({"status": "held"}, "predecessor lease status=held"),
    ({"repository": "VINIClUS/other"}, "predecessor lease repository=VINIClUS/other"),
    ({"run_id": 8}, "predecessor lease run=8/1"),
    ({"run_attempt": 2}, "predecessor lease run=7/2"),
    ({"checkpoint_sha256": "b" * 64}, "predecessor lease checkpoint"),
], ids=["status", "repositorio", "run", "attempt", "checkpoint"])
def test_lease_do_predecessor_recusa_cada_condicao_com_chave_propria(changes, reason):
    selector = {"run_id": 7, "run_attempt": 1}
    with pytest.raises(ValueError, match=re.escape(reason)):
        application._lease(lease(**changes), selector, "a" * 64)


def test_lease_do_predecessor_liberado_e_aceito():
    application._lease(lease(), {"run_id": 7, "run_attempt": 1}, "a" * 64)


def test_assembly_nao_aceita_o_manifesto_inline_como_chave_de_governanca():
    assert "application_product_source_manifest" not in governance_assembly.GOVERNANCE_KEYS


def test_crosscheck_recusa_o_manifesto_inline():
    with pytest.raises(ValueError, match="governance key=application_product_source_manifest"):
        governance_assembly.crosscheck({"application_product_source_manifest": {}}, {})
