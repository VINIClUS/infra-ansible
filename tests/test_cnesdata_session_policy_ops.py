"""Operation sessions use the ops managed policy; the keeper keeps the application one; pairing is preserved."""
import json
import pathlib
import re

import pytest

SOURCE, RUN, ATTEMPT = "b" * 40, 44, 1
ACCOUNT = "111122223333"
BUCKET, STATE = "evidence-bucket", "state-bucket"
PREFIX = "cnesdata/prod/evidence/"
RUN_ARN = f"arn:aws:s3:::{BUCKET}/{PREFIX}lifecycle/{SOURCE}/{RUN}/{ATTEMPT}/"
LEASE = f"arn:aws:s3:::{STATE}/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"
HISTORY = [f"arn:aws:s3:::{BUCKET}/{PREFIX}old/{name}" for name in ("terminal.json", "lease.json", "checkpoint.json")]
STATE_KMS = f"arn:aws:kms:us-east-2:{ACCOUNT}:key/00000000-0000-4000-8000-000000000001"
TF = pathlib.Path(__file__).resolve().parents[1] / "opentofu" / "cnesdata-delivery" / "session-policies.tf"
ROLE = lambda suffix: f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-{suffix}"
NAME_N, NAME_O = "sp-publish-" + "a" * 40, "sp-i-" + "a" * 40
NOW = {"aws:CurrentTime": "2026-11-26T00:00:00Z"}


def governance():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    return {"account_id": ACCOUNT, "state_bucket": STATE, "evidence_bucket": BUCKET, "evidence_prefix": PREFIX,
            "evidence_kms_key_arn": f"arn:aws:kms:us-east-2:{ACCOUNT}:key/00000000-0000-4000-8000-000000000002",
            "roles": {name: ROLE(name) for name in ("plan", "audit", "deploy", "application")},
            "application_delegations": {alias: ROLE(suffix) for alias, suffix in lc.APPLICATION_DELEGATIONS.items()}}


IAM_READS = ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:GetPolicy",
             "iam:GetPolicyVersion"]
KMS_STATE = {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], "Resource": STATE_KMS,
             "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-2.amazonaws.com",
                                            "kms:EncryptionContext:aws:s3:arn": [f"arn:aws:s3:::{STATE}", LEASE]}}}
OPS_MANAGED = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": IAM_READS, "Resource": "*"},
    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": LEASE}, KMS_STATE]}
KEEPER_MANAGED = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": [*IAM_READS, "sts:AssumeRole"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": LEASE}, KMS_STATE,
    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": HISTORY}]}
IDENTITY = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], "Resource": [LEASE, *HISTORY, RUN_ARN + "*"]},
    {"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": "*"}]}
LIFECYCLE_MANAGED = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": LEASE}]}


def allowed(request_or_policy, managed, action, resource, context=None):
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    policy = json.loads(request_or_policy["Policy"])
    return effective_iam(IDENTITY, [managed, policy], action, resource, NOW | (context or {}))


def operation(aliases=("normal",), names=None):
    from tools.cnesdata_delivery.session_policy import application_request
    names = names or {"normal": NAME_N, "observer": NAME_O}
    return application_request(governance(), SOURCE, RUN, ATTEMPT, "publish-static", application_purpose="promotion",
                               delegations=list(aliases), sessions={alias: names[alias] for alias in aliases})


def keeper():
    from tools.cnesdata_delivery.session_policy import application_request
    return application_request(governance(), SOURCE, RUN, ATTEMPT, "keeper", application_purpose="promotion")


def test_sessao_de_operacao_usa_o_arn_ops_e_o_keeper_o_arn_application():
    from tools.cnesdata_delivery.session_policy import managed_arn
    gov = governance()
    assert managed_arn(gov, "application_ops") == f"arn:aws:iam::{ACCOUNT}:policy/cnesdata-prod-application-ops-session"
    assert [item["arn"] for item in operation()["PolicyArns"]] == [managed_arn(gov, "application_ops")]
    assert [item["arn"] for item in keeper()["PolicyArns"]] == [managed_arn(gov, "application")]
    assert managed_arn(gov, "application") == f"arn:aws:iam::{ACCOUNT}:policy/cnesdata-prod-application-session"


def test_arn_ops_so_existe_para_o_role_da_application():
    from tools.cnesdata_delivery.session_policy import managed_arn
    with pytest.raises(ValueError):
        managed_arn(governance(), "application_other")


@pytest.mark.parametrize("action,resource", [
    ("s3:PutObject", LEASE), ("s3:DeleteObject", LEASE), ("s3:GetObject", HISTORY[0]), ("s3:GetObject", HISTORY[2]),
    ("s3:GetObject", f"arn:aws:s3:::{BUCKET}/{PREFIX}other/x"), ("s3:PutObject", RUN_ARN + "other-step/x.json"),
    ("s3:PutObject", HISTORY[0]), ("s3:DeleteObject", RUN_ARN + "publish-static/x.json")])
def test_sessao_de_operacao_e_negada_no_lease_no_historico_e_fora_do_proprio_passo(action, resource):
    assert allowed(operation(), OPS_MANAGED, action, resource) is False


@pytest.mark.parametrize("action,resource", [
    ("s3:GetObject", LEASE), ("s3:GetObject", RUN_ARN + "any/x.json"), ("s3:PutObject", RUN_ARN + "publish-static/x.json")])
def test_sessao_de_operacao_le_o_lease_le_o_run_e_grava_o_proprio_passo(action, resource):
    assert allowed(operation(), OPS_MANAGED, action, resource) is True


@pytest.mark.parametrize("aliases", [(), ("normal",), ("normal", "observer")])
def test_sessao_de_operacao_nao_recebe_lease_put_nem_historico_do_documento_application(aliases):
    request = operation(aliases) if aliases else None
    from tools.cnesdata_delivery.session_policy import application_request
    request = request or application_request(governance(), SOURCE, RUN, ATTEMPT, "closed-ready", application_purpose="promotion")
    assert allowed(request, OPS_MANAGED, "s3:PutObject", LEASE) is False
    assert allowed(request, OPS_MANAGED, "s3:GetObject", HISTORY[1]) is False


def test_keeper_continua_gravando_o_lease_e_lendo_o_historico():
    request = keeper()
    assert allowed(request, KEEPER_MANAGED, "s3:PutObject", LEASE) is True
    assert allowed(request, KEEPER_MANAGED, "s3:GetObject", HISTORY[0]) is True
    assert allowed(request, KEEPER_MANAGED, "s3:PutObject", RUN_ARN + "keeper/x.json") is True
    assert allowed(request, KEEPER_MANAGED, "s3:PutObject", RUN_ARN + "publish-static/x.json") is False


def test_keeper_e_negado_em_assume_role():
    assert allowed(keeper(), KEEPER_MANAGED, "sts:AssumeRole", ROLE("static-normal")) is False
    assert allowed(keeper(), OPS_MANAGED, "sts:AssumeRole", ROLE("static-normal")) is False


@pytest.mark.parametrize("role", ["plan", "audit", "deploy"])
def test_sessao_de_lifecycle_e_negada_em_lease_put_sem_negacao_inline(role):
    from tools.cnesdata_delivery.session_policy import lifecycle_request
    request = lifecycle_request(governance(), SOURCE, RUN, ATTEMPT, role, "step", direction="advance")
    assert allowed(request, LIFECYCLE_MANAGED, "s3:PutObject", LEASE) is False
    assert LEASE not in json.loads(request["Policy"])["Statement"].__repr__()
    assert allowed(request, LIFECYCLE_MANAGED, "s3:GetObject", LEASE) is True


def test_delegacao_pareia_cada_role_com_o_proprio_nome_de_sessao():
    pair = operation(("normal", "observer"))
    normal, observer = ROLE("static-normal"), ROLE("static-observer")
    assert allowed(pair, OPS_MANAGED, "sts:AssumeRole", normal, {"sts:RoleSessionName": NAME_N}) is True
    assert allowed(pair, OPS_MANAGED, "sts:AssumeRole", observer, {"sts:RoleSessionName": NAME_O}) is True
    assert allowed(pair, OPS_MANAGED, "sts:AssumeRole", normal, {"sts:RoleSessionName": NAME_O}) is False
    assert allowed(pair, OPS_MANAGED, "sts:AssumeRole", observer, {"sts:RoleSessionName": NAME_N}) is False
    assert allowed(pair, OPS_MANAGED, "sts:AssumeRole", normal, {"sts:RoleSessionName": NAME_N + "-x"}) is False
    assert allowed(pair, OPS_MANAGED, "sts:AssumeRole", ROLE("static-recovery"), {"sts:RoleSessionName": NAME_N}) is False
    assert allowed(pair, OPS_MANAGED, "sts:AssumeRole", normal) is False


def test_sessao_sem_delegacao_nao_assume_nenhum_role():
    from tools.cnesdata_delivery.session_policy import application_request
    request = application_request(governance(), SOURCE, RUN, ATTEMPT, "closed-ready", application_purpose="promotion")
    assert allowed(request, OPS_MANAGED, "sts:AssumeRole", ROLE("static-normal"), {"sts:RoleSessionName": NAME_N}) is False


def test_nenhuma_sessao_de_operacao_carrega_negacao_de_lease_nem_de_leitura_fora_do_run():
    statements = json.loads(operation(("normal", "observer"))["Policy"])["Statement"]
    assert [s for s in statements if s["Effect"] == "Deny"] == []


def _block(name):
    text = TF.read_text()
    start = text.index(f'resource "aws_iam_policy" "{name}"')
    return text[start:text.index("\n}\n", start)]


def test_tf_ops_nao_tem_lease_put_historico_nem_assume_role():
    block = _block("application_ops_session")
    assert "PutObject" not in block and "application_history" not in block and "sts:AssumeRole" not in block
    assert '"${var.application_promotion.role_name}-ops-session"' in block
    assert "count       = var.application_promotion == null ? 0 : 1" in block
    assert "iam:GetPolicyVersion" in block and "kms:Decrypt" in block and "s3:GetObject" in block


def test_tf_application_mantem_lease_put_historico_e_assume_role_para_o_keeper():
    block = _block("application_session")
    assert '"s3:GetObject", "s3:PutObject"' in block and "application_history" in block and "sts:AssumeRole" in block


def test_tf_delivery_session_so_le_o_lease():
    block = _block("delivery_session")
    lease = [line for line in block.splitlines() if "coordination/cnesdata-prod.lease.json" in line and "kms" not in line]
    assert len(lease) == 1 and "s3:PutObject" not in lease[0] and "s3:GetObject" in lease[0]
    assert re.search(r'tflock" }', block) and "tfstate\" }" in block


MAIN_SESSION_DIGESTS = {
    "session.ao": "0b0e73169475af824133260c97f32495419e50391cec244c98002666fe3173fc",
    "session.ax": "90c7d2616bd08144f81e4804a52c200c4c97210dd7dd2fd55ec5cd27fcc0d607",
    "session.ro": "501f91be42ed9e847d8de0c0a52aa03c0cc252751f3150925c40092f3e7071f3",
    "session.rs": "cbbc3cb4d17286d6f76f10b48abc933cd58885f8eb7b2fa667e13b14a3e4efa5",
    "session.rx": "22bfdd6d78b9323cdeb190dc05ec9627faf24cfdc560dad868a4788ba81e8c58",
    "session.uo": "fc6b975f77b08d12c5ea97dd0b71543749ca26d489853ad460e237d9ffcb6e35",
    "session.us": "18ff53943fb8e9b0294145106e056fa9a2d31ff4cfc76d21b4083890f47bfcc6",
    "session.uw": "8b5d510e6b2eba6bd23abe192f7865ee8e70e6a4811c6892d6d36caaea90ef2b",
    "session.ux": "d34d00a8b3edb259fde43b2bc74d7a4e2c08ac8ea5042af93a05a91178026998"}


def test_os_nove_documentos_session_de_modo_ficam_identicos_aos_bytes_do_main():
    from test_cnesdata_mode_evaluation import _documents
    from tools.cnesdata_delivery import contract as c
    found = {name: c.sha(c.canonical(value)) for name, value in _documents().items() if name.startswith("session.")}
    assert found == MAIN_SESSION_DIGESTS
