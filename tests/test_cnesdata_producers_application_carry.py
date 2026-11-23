"""P19 audit carries: catalog mirrors the consumer's static step rules, lease keys, assembly keys."""
import copy
import re

import pytest

from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.producers import application, governance_assembly

MARKER = {"selection_version": 1, "ext2_post_upload_receipt_v1": {}}
SELECTION = MARKER
ACCOUNT = "111122223333"


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
        "phase-b-deploy": infra("deploy", "phase-b", "phase-b / execute", mode="initial"),
        "recovery-deploy": infra("deploy", "phase-c-recovery", "recovery / execute", mode="initial"),
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
    lambda s: s["operational-plan"]["activation_selection"].update(ext2_post_upload_receipt_v1={"run_id": "1"}),
    lambda s: s["operational-plan"]["activation_selection"].update(ext2_post_upload_receipt_v1=None),
], ids=["ausente", "nao-dict", "sem-referencia", "versao-2", "versao-bool", "chave-extra", "referencia-nao-dict",
        "recibo-no-catalogo", "recibo-nulo"])
def test_catalogo_recusa_plano_operacional_sem_selecao_de_ativacao_fechada(change):
    with pytest.raises(ValueError, match="step activation selection"):
        application.catalog(mutated(change))


@pytest.mark.parametrize("field", ["purpose", "direction", "mode"])
def test_catalogo_recusa_fence_cujo_delta_difere_do_produtor_fixo(field):
    fence = lc.FENCE_PREPARE_PRODUCER
    steps = base_catalog()
    steps[FENCE].update({field: "converge" if field == "direction" else "other"})
    with pytest.raises(ValueError, match="catalog fence prepare producer|step|prepare mode|converge custody"):
        application.catalog(steps)
    assert fence[field] != steps[FENCE][field]


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


@pytest.mark.parametrize("change", [
    lambda s: s["operational-plan"].update(job_name=f"plan {ACCOUNT} / execute"),
    lambda s: (s["operational-plan"].update(job_name=f"job {ACCOUNT}"),
               s["phase-b-deploy"]["input_jobs"].update(x={"name": f"job {ACCOUNT}", "step": "operational-plan"})),
    lambda s: s["phase-b-deploy"]["admission_steps"].append(f"step={ACCOUNT}"),
], ids=["job-name", "input-job", "admissao"])
def test_catalogo_recusa_numero_de_conta_em_qualquer_lugar(change):
    with pytest.raises(ValueError, match="catalog account number"):
        application.catalog(mutated(change))


def test_catalogo_aceita_doze_digitos_dentro_de_um_digest_hexadecimal():
    run = "a" + "9" * 12 + "b"
    steps = base_catalog()
    steps["operational-plan"]["job_name"] = f"plan sha256:{run} / execute"
    steps["operational-audit"]["admission_steps"] = [f"digest {run}"]
    application.catalog(steps)


@pytest.mark.parametrize("role", ["plan", "audit", "deploy"])
def test_catalogo_recusa_converge_para_todo_papel(role):
    steps = base_catalog()
    steps["recovery-step"] = infra(role, "phase-c-recovery", f"recovery-{role} / execute", mode="initial",
                                   direction="converge")
    with pytest.raises(ValueError, match="lifecycle converge custody unavailable"):
        application.catalog(steps)


def test_catalogo_recusa_converge_antes_de_qualquer_leitura_de_rede(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("network"))
    steps = base_catalog()
    steps["phase-b-deploy"].update(direction="converge")
    with pytest.raises(ValueError, match="lifecycle converge custody unavailable"):
        application.catalog(steps)


def test_catalogo_recusa_a_chave_delete_resources_como_chave_desconhecida():
    steps = base_catalog()
    steps["phase-b-deploy"]["delete_resources"] = ["states:stateMachine:cnesdata-prod"]
    with pytest.raises(ValueError) as refused:
        application.catalog(steps)
    assert "step delete resources" not in str(refused.value)
