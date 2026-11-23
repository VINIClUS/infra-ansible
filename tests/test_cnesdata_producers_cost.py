"""Derivador do manifesto de custo do gate e cost_context por proposito (P18, N4)."""
import copy
import json
from decimal import Decimal
from pathlib import Path

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.producers import cost_context, cost_ledger

SOURCE = (Path(__file__).parent / "fixtures/cnesdata_cost_source_manifest.json").read_bytes()
NOW = 1794053700
SHA = "a" * 40
CATEGORIES = {"kms-encryption", "kms-signing", "s3-requests-versions-logs", "cloudfront-waf"}


def encoded(document):
    return json.dumps(document, indent=1).encode()


def derive(raw=SOURCE, **kwargs):
    return cost_ledger.derive(raw, source_sha=SHA, calculated_at=c.utc(NOW - 60),
                              expires_at=kwargs.get("expires_at", c.utc(NOW + 3600)))


def document(mutate=None):
    value = json.loads(SOURCE)
    if mutate:
        mutate(value)
    return encoded(value)


def context(**changes):
    return {"source_sha": SHA, "checkpoint_sha256": c.sha(SOURCE), "target_sha256": "e" * 64} | changes


def owner_block(**changes):
    return {"plan": "FREE", "status": "ACTIVE", "subscription_sha256": "1" * 64,
            "distribution_sha256": "2" * 64, "waf_binding_sha256": "3" * 64,
            "observed_at": c.utc(NOW - 30), "expires_at": c.utc(NOW + 7200)} | changes


def active_stage(**changes):
    return cost_context.stage("phase-a", SHA, context(),
                              owner_block(**changes))


def line(identifier, price, maximum, scope="product", allowance=0):
    return {"id": identifier, "scope": scope, "unit_price_usd": price,
            "quantity": {"min": 0, "base": 0, "max": maximum}, "free_allowance": {"min": 0, "base": 0, "max": allowance},
            "status": "verified", "max_basis": "cap", "source": {"url": "https://example.invalid/p", "term": "t"}}


def test_manifesto_derivado_passa_validate_cost():
    derived = derive()
    stage = active_stage()
    cost, evidence = cost_context.cost_objects(derived, stage)
    c.validate_cost(cost, purpose="phase-a", stage=stage, evidence=evidence, manifest=derived["manifest"],
                    now=NOW, source_manifest_sha256=derived["source_manifest_sha256"])
    assert evidence["measurement"]["excluded"] == derived["excluded"]


def test_totais_arredondam_cada_componente_para_cima():
    derived = derive()
    manifest = derived["manifest"]
    assert manifest["gross"] is True and manifest["credits_usd"] == "0.00"
    product = sum(Decimal(item["monthly_usd"]) for item in manifest["components"] if item["scope"] == "product")
    total = sum(Decimal(item["monthly_usd"]) for item in manifest["components"])
    assert (derived["product_monthly_usd"], derived["aggregate_monthly_usd"]) == (f"{product:.2f}", f"{total:.2f}")
    assert product <= 8 and total < 15


def test_cada_linha_com_preco_vira_um_componente_e_a_categoria_exigida_existe():
    derived = derive()
    priced = [x for x in json.loads(SOURCE)["lines"] if x["unit_price_usd"] is not None]
    assert len(derived["manifest"]["components"]) == len(priced)
    assert CATEGORIES <= {item["category"] for item in derived["manifest"]["components"]}


def test_scope_shared_vira_aggregate_only_e_nenhum_componente_fica_unbound():
    components = derive()["manifest"]["components"]
    assert {item["scope"] for item in components} == {"product", "aggregate-only"}
    assert all(item["unbound"] is False for item in components)


def test_linha_de_franquia_nao_verificada_e_excluida_com_motivo():
    derived = derive()
    assert derived["excluded"] == [{"id": "cognito_allowance", "reason": "credit not applied"}]


def credit_variants():
    null = line("cognito_allowance", None, 5)
    null["status"] = "unverified"
    return [null, line("credit_line", -3, 10), line("cognito_allowance", None, 0)]


def without_allowance(value):
    value["lines"] = [item for item in value["lines"] if item["id"] != "cognito_allowance"]


@pytest.mark.parametrize("credit", credit_variants(), ids=["nulo", "preco-negativo", "nulo-sem-quantidade"])
def test_excluir_a_linha_de_credito_nunca_reduz_max(credit):
    plain = derive(document(without_allowance))
    with_credit = derive(document(lambda value: (without_allowance(value), value["lines"].append(credit))))
    assert Decimal(with_credit["aggregate_monthly_usd"]) >= Decimal(plain["aggregate_monthly_usd"])
    assert with_credit["aggregate_monthly_usd"] == plain["aggregate_monthly_usd"]
    assert with_credit["product_monthly_usd"] == plain["product_monthly_usd"]
    assert {"id": credit["id"], "reason": "credit not applied"} in with_credit["excluded"]


def test_franquia_da_propria_linha_abate_so_aquela_linha():
    def allowance(value):
        next(x for x in value["lines"] if x["id"] == "cloudwatch_alarm_metrics")["free_allowance"]["max"] = 25

    lowered = derive(document(allowance))
    delta = Decimal(derive()["aggregate_monthly_usd"]) - Decimal(lowered["aggregate_monthly_usd"])
    assert delta == Decimal("2.50")


def test_other_projects_spend_vem_do_manifesto_e_nao_do_codigo():
    def change(value):
        spend = next(item for item in value["lines"] if item["id"] == "other_projects_spend")
        spend["quantity"] = {"min": 1.17, "base": 1.17, "max": 1.17}
        spend["measurement"]["total_usd"] = 1.17

    base, moved = derive(), derive(document(change))
    delta = Decimal(moved["aggregate_monthly_usd"]) - Decimal(base["aggregate_monthly_usd"])
    assert delta == Decimal("0.65")
    source = Path(cost_ledger.__file__).read_text()
    assert "0.52" not in source and "other_projects_spend" in source


def test_other_projects_spend_sem_medicao_datada_e_recusado():
    def strip(value):
        next(item for item in value["lines"] if item["id"] == "other_projects_spend").pop("measurement")

    with pytest.raises(ValueError, match="measurement"):
        derive(document(strip))


def test_linha_sem_categoria_e_recusada():
    with pytest.raises(ValueError, match="category"):
        derive(document(lambda value: value["lines"].append(line("brand_new_line", 1, 1))))


def test_cada_linha_registra_url_da_fonte_e_data_de_recuperacao():
    sources = derive()["sources"]
    assert len(sources) == len(json.loads(SOURCE)["lines"])
    assert all({"id", "url", "retrieved_on"} == set(item) and item["retrieved_on"] == "2026-11-01" for item in sources)


def test_manifesto_de_fonte_recusa_regiao_e_moeda_diferentes():
    for key, value in (("region", "us-east-1"), ("currency", "BRL")):
        with pytest.raises(ValueError, match="source manifest"):
            derive(document(lambda doc, key=key, value=value: doc.__setitem__(key, value)))


def test_source_manifest_sha256_e_o_sha_dos_bytes_verbatim():
    assert derive()["source_manifest_sha256"] == c.sha(SOURCE)


def test_estouro_do_teto_do_produto_e_recusado_antes_de_emitir():
    def inflate(value):
        next(x for x in value["lines"] if x["id"] == "fargate_vcpu_hours")["quantity"]["max"] = 1000

    with pytest.raises(ValueError, match="budget"):
        derive(document(inflate))


def test_validade_do_manifesto_acompanha_as_datas_do_ciclo():
    derived = derive(expires_at=c.utc(NOW + 1800))
    assert derived["manifest"]["calculated_at"] == c.utc(NOW - 60)
    assert derived["manifest"]["expires_at"] == c.utc(NOW + 1800) and derived["manifest"]["source_sha"] == SHA


@pytest.mark.parametrize("purpose", ["acm-certificate", "bootstrap"])
def test_cost_context_pre_ativacao_nao_leva_o_bloco_do_cloudfront(purpose):
    stage = cost_context.stage(purpose, SHA, context(), None)
    assert stage == {"stage": "pre-activation", "source_sha": SHA, "checkpoint_sha256": c.sha(SOURCE),
                     "target_sha256": "e" * 64, "cloudfront": None, "unbound_required": True}


def test_cost_context_pre_ativacao_recusa_bloco_do_cloudfront():
    with pytest.raises(ValueError, match="cloudfront"):
        cost_context.stage("bootstrap", SHA, context(), owner_block())


def test_cost_context_active_leva_o_bloco_do_dono_sem_alteracao():
    stage = active_stage()
    assert stage["stage"] == "active" and stage["unbound_required"] is False and stage["cloudfront"] == owner_block()


@pytest.mark.parametrize("missing", ["subscription_sha256", "distribution_sha256", "waf_binding_sha256"])
def test_active_sem_digest_do_dono_e_recusado(missing):
    block = owner_block()
    block.pop(missing)
    with pytest.raises(ValueError):
        cost_context.stage("phase-a", SHA, context(), block)
    with pytest.raises(ValueError):
        cost_context.stage("phase-a", SHA, context(), None)


@pytest.mark.parametrize("changes", [{"plan": "PRO"}, {"status": "PENDING"}, {"subscription_sha256": "xyz"}])
def test_active_recusa_bloco_que_o_gate_recusaria(changes):
    with pytest.raises(ValueError):
        active_stage(**changes)


def test_cost_context_recusa_digest_de_checkpoint_ausente_ou_malformado():
    for bad in ({}, {"checkpoint_sha256": "d" * 64}, {"checkpoint_sha256": "q", "target_sha256": "e" * 64}):
        with pytest.raises(ValueError):
            cost_context.stage("phase-a", SHA, bad, owner_block())


def test_cost_objects_exige_cloudfront_valido_ate_o_fim_do_custo():
    derived = derive(expires_at=c.utc(NOW + 9000))
    with pytest.raises(ValueError, match="cloudfront"):
        cost_context.cost_objects(derived, active_stage())


def test_cost_objects_e_deterministico_e_nao_muta_a_entrada():
    derived = derive()
    snapshot = copy.deepcopy(derived)
    first = cost_context.cost_objects(derived, active_stage())
    assert first == cost_context.cost_objects(derived, active_stage()) and derived == snapshot


def test_stage_recusa_contexto_cujo_source_sha_difere_do_source():
    for bad in (context(source_sha="0" * 40), {k: v for k, v in context().items() if k != "source_sha"}):
        with pytest.raises(ValueError, match="cost context source_sha"):
            cost_context.stage("phase-a", SHA, bad, owner_block())


def test_cost_objects_recusa_checkpoint_diferente_do_sha_do_manifesto_fonte():
    derived = derive()
    stage = cost_context.stage("phase-a", SHA, context(checkpoint_sha256="0" * 64), owner_block())
    with pytest.raises(ValueError, match="cost context checkpoint"):
        cost_context.cost_objects(derived, stage)


def test_derivacao_pre_ativacao_e_recusada_com_razao_chave_valor():
    derived = derive()
    stage = cost_context.stage("bootstrap", SHA, context(), None)
    with pytest.raises(ValueError, match="stage=pre-activation"):
        cost_context.cost_objects(derived, stage)


def spend_line(value):
    return next(item for item in value["lines"] if item["id"] == "other_projects_spend")


def unpriced_spend(value):
    spend_line(value)["unit_price_usd"] = None
    spend_line(value).pop("measurement")


def absent_spend(value):
    value["lines"] = [item for item in value["lines"] if item["id"] != "other_projects_spend"]


@pytest.mark.parametrize("mutate, reason", [
    (unpriced_spend, "other projects spend price id=other_projects_spend"),
    (absent_spend, "other projects spend count=0"),
    (lambda value: value["lines"].append(copy.deepcopy(spend_line(value))), "other projects spend count=2"),
    (lambda value: spend_line(value).__setitem__("unit_price_usd", -1), "other projects spend price id=other_projects_spend"),
], ids=["sem-preco-e-sem-medicao", "ausente", "duplicada", "preco-negativo"])
def test_other_projects_spend_fora_de_uma_linha_precificada_e_recusado(mutate, reason):
    with pytest.raises(ValueError, match=reason):
        derive(document(mutate))


@pytest.mark.parametrize("field, value", [
    ("measured_on", None), ("measured_on", "ontem"), ("measured_on", "2026-11-23"), ("measured_on", 20261123),
    ("month", None), ("month", "novembro"), ("month", "2026-13"), ("month", "2026-11-01"), ("month", 202611),
], ids=lambda item: str(item))
def test_other_projects_spend_com_medicao_de_valor_invalido_e_recusada(field, value):
    with pytest.raises(ValueError, match="other projects spend measurement"):
        derive(document(lambda document_: spend_line(document_)["measurement"].__setitem__(field, value)))


@pytest.mark.parametrize("identifier", ["brand_new_line", "kms_signing", "fargate_vcpu_hours"])
def test_linha_sem_preco_fora_da_allowlist_e_recusada(identifier):
    def unpriced(value):
        found = [item for item in value["lines"] if item["id"] == identifier]
        if not found:
            value["lines"].append(line(identifier, None, 1))
        for item in found:
            item["unit_price_usd"] = None

    with pytest.raises(ValueError, match=f"unpriced line id={identifier}"):
        derive(document(unpriced))


def test_so_a_allowlist_sem_preco_e_o_credito_negativo_sao_excluidos():
    derived = derive(document(lambda value: value["lines"].append(line("credit_line", -3, 10))))
    assert derived["excluded"] == [{"id": "cognito_allowance", "reason": "credit not applied"},
                                   {"id": "credit_line", "reason": "credit not applied"}]
