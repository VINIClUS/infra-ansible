"""Produtores externos EXT-1/EXT-2: provider OIDC e bucket de evidencia, planos nativos."""
import json
from pathlib import Path
import sys

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests/fixtures"))
from cnesdata_delivery_prerequisites_native import ROOT, Native  # noqa: E402

BUCKET = "cnesdata-prod-evidence-111122223333"
BASE = {"account_id": "111122223333", "region": "us-east-2"}
OIDC = {"github_oidc_enabled": True}
EVIDENCE = {"evidence_enabled": True, "evidence_bucket_name": BUCKET}
EVIDENCE_TYPES = {
    "aws_kms_key", "aws_kms_alias", "aws_s3_bucket", "aws_s3_bucket_versioning",
    "aws_s3_bucket_public_access_block", "aws_s3_bucket_ownership_controls",
    "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_policy",
    "aws_s3_bucket_lifecycle_configuration",
}


@pytest.fixture(scope="module")
def native():
    helper = Native()
    yield helper
    helper.temp.cleanup()


def planned(native, values, name):
    code, plans, errors = native.plan({**BASE, **values}, name)
    assert code == 0, errors
    assert len(plans) == 1
    return plans[0]["planned_values"]


def resources(values):
    return {r["address"]: r for r in values["root_module"].get("resources", [])}


def by_type(values, kind):
    found = [r for r in resources(values).values() if r["type"] == kind]
    assert len(found) == 1, kind
    return found[0]["values"]


def test_padrao_desligado_nao_planeja_nenhum_recurso(native):
    values = planned(native, {}, "disabled")
    assert resources(values) == {}
    assert values["outputs"] == {"github_oidc_provider": None, "evidence_storage": None}


def test_provider_oidc_unico_com_audience_sts(native):
    values = planned(native, OIDC, "oidc")
    assert set(resources(values)) == {"aws_iam_openid_connect_provider.github[0]"}
    provider = by_type(values, "aws_iam_openid_connect_provider")
    assert provider["url"] == "https://token.actions.githubusercontent.com"
    assert provider["client_id_list"] == ["sts.amazonaws.com"]
    assert values["outputs"]["evidence_storage"] is None


def test_evidencia_cria_somente_bucket_cmk_e_configuracoes(native):
    values = planned(native, EVIDENCE, "evidence")
    assert {r["type"] for r in resources(values).values()} == EVIDENCE_TYPES
    assert values["outputs"]["github_oidc_provider"] is None


def test_bucket_tem_object_lock_versionamento_e_nome_exato(native):
    values = planned(native, EVIDENCE, "evidence")
    bucket = by_type(values, "aws_s3_bucket")
    assert bucket["bucket"] == BUCKET
    assert bucket["object_lock_enabled"] is True
    assert bucket["force_destroy"] is False
    assert by_type(values, "aws_s3_bucket_versioning")["versioning_configuration"][0]["status"] == "Enabled"


def test_sem_retencao_padrao_porque_retain_until_vem_por_objeto(native):
    values = planned(native, EVIDENCE, "evidence")
    assert not any("object_lock" in r["type"] for r in resources(values).values())
    assert "aws_s3_bucket_object_lock_configuration" not in (ROOT / "evidence.tf").read_text()


def test_bucket_bloqueia_acesso_publico_e_forca_dono(native):
    values = planned(native, EVIDENCE, "evidence")
    block = by_type(values, "aws_s3_bucket_public_access_block")
    assert all(block[k] is True for k in (
        "block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"))
    rule = by_type(values, "aws_s3_bucket_ownership_controls")["rule"][0]
    assert rule["object_ownership"] == "BucketOwnerEnforced"


def test_sse_kms_sem_bucket_key_com_cmk_dedicada(native):
    values = planned(native, EVIDENCE, "evidence")
    rules = by_type(values, "aws_s3_bucket_server_side_encryption_configuration")["rule"]
    assert len(rules) == 1 and rules[0]["bucket_key_enabled"] is False
    assert rules[0]["apply_server_side_encryption_by_default"][0]["sse_algorithm"] == "aws:kms"
    text = (ROOT / "evidence.tf").read_text()
    assert "kms_master_key_id = aws_kms_key.evidence[0].arn" in text
    key = by_type(values, "aws_kms_key")
    assert key["enable_key_rotation"] is True and key["key_usage"] == "ENCRYPT_DECRYPT"
    assert key["customer_master_key_spec"] == "SYMMETRIC_DEFAULT"
    assert key["multi_region"] is False


def test_policy_nega_transporte_sem_tls_no_bucket_e_objetos(native):
    values = planned(native, EVIDENCE, "evidence")
    policy = json.loads(by_type(values, "aws_s3_bucket_policy")["policy"])
    deny = [s for s in policy["Statement"] if s["Effect"] == "Deny"]
    assert len(deny) == 1 and deny[0]["Principal"] == "*" and deny[0]["Action"] == "s3:*"
    assert deny[0]["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    assert set(deny[0]["Resource"]) == {f"arn:aws:s3:::{BUCKET}", f"arn:aws:s3:::{BUCKET}/*"}


def test_lifecycle_so_aborta_multipart_e_nunca_expira_versoes(native):
    values = planned(native, EVIDENCE, "evidence")
    rules = by_type(values, "aws_s3_bucket_lifecycle_configuration")["rule"]
    assert len(rules) == 1 and rules[0]["status"] == "Enabled"
    assert rules[0]["abort_incomplete_multipart_upload"][0]["days_after_initiation"] == 7
    for forbidden in ("expiration", "noncurrent_version_expiration", "transition"):
        assert not rules[0].get(forbidden)


def test_outputs_entregam_fragmentos_consumidos_por_ext1_e_ext2(native):
    values = planned(native, {**OIDC, **EVIDENCE}, "both")
    assert len(resources(values)) == 1 + len(EVIDENCE_TYPES)
    storage = values["outputs"]["evidence_storage"]
    assert storage["evidence_bucket_name"] == BUCKET
    assert storage["evidence_bucket_arn"] == f"arn:aws:s3:::{BUCKET}"
    text = (ROOT / "outputs.tf").read_text()
    for name in ("thumbprint_list", "client_id_list", "kms_key_arn", "arn"):
        assert name in text


@pytest.mark.parametrize("values", [
    {"evidence_enabled": True},
    {"evidence_enabled": True, "evidence_bucket_name": "Bad_Name"},
    {"evidence_enabled": True, "evidence_bucket_name": "a..b"},
])
def test_evidencia_ligada_exige_nome_de_bucket_valido(native, values):
    code, _, errors = native.plan({**BASE, **values}, "bad-" + str(abs(hash(json.dumps(values)))))
    assert code != 0 and errors


def test_conta_e_regiao_fixas(native):
    code, _, errors = native.plan({"account_id": "123", "region": "us-east-2"}, "bad-account")
    assert code != 0 and errors
    code, _, errors = native.plan({"account_id": "111122223333", "region": "us-west-2"}, "bad-region")
    assert code != 0 and errors


def test_raiz_nao_cria_iam_role_nem_segundo_provider_e_tem_chave_propria():
    text = "\n".join(p.read_text() for p in ROOT.glob("*.tf"))
    assert text.count('resource "aws_iam_openid_connect_provider"') == 1
    assert 'resource "aws_iam_role' not in text and 'resource "aws_iam_policy' not in text
    backend = (ROOT / "backend.tf").read_text()
    assert 'key          = "shared/cnesdata-delivery-prerequisites/prod/opentofu.tfstate"' in backend
    delivery = (REPO / "opentofu/cnesdata-delivery/backend.tf").read_text()
    assert "cnesdata-delivery-prerequisites" not in delivery


def test_raiz_delivery_continua_consumindo_provider_e_bucket_como_externos():
    oidc = (REPO / "opentofu/cnesdata-delivery/oidc.tf").read_text()
    assert 'data "aws_iam_openid_connect_provider" "github"' in oidc
    assert 'resource "aws_s3_bucket"' not in "\n".join(
        p.read_text() for p in (REPO / "opentofu/cnesdata-delivery").glob("*.tf"))


def test_lock_do_provider_identico_ao_do_foundation():
    lock = ROOT / ".terraform.lock.hcl"
    foundation = REPO / "opentofu/cnesdata-bootstrap/foundation/.terraform.lock.hcl"
    assert lock.read_bytes() == foundation.read_bytes()
