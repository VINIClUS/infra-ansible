"""Lado da ferramenta do role de audit: sessao gerenciada, pin do owner e gate_shas.audit."""
import json
import sys
from types import SimpleNamespace

import pytest

from fixtures.cnesdata_iam_evaluation import effective
from test_cnesdata_application_gate import _application_caller_fixture
from test_cnesdata_delivery_observer_roles import (
    ACCOUNT, AUDIT_NAME, AUDIT_POLICY, AUDIT_SESSION, CONFIG, EVIDENCE_KMS, LEASE_KEY, STATE_KMS, VIA_S3,
    audit_values, lifecycle_keys, native, render,
)
from tools.cnesdata_delivery import contract as c, lifecycle_runtime, provenance, session_owner
from tools.cnesdata_delivery.session_policy import LIFECYCLE_DELETES, lifecycle_request, managed_arn

assert native
AUDIT_ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/{AUDIT_NAME}"
AUDIT_SESSION_ARN = f"arn:aws:iam::{ACCOUNT}:policy/{AUDIT_NAME}-session"
AUDIT_REUSABLE = ".github/workflows/reusable-cnesdata-infra-audit-gate.yml"
STATE = "arn:aws:s3:::synthetic-state/cnesdata/prod/opentofu.tfstate"
LEASE = "arn:aws:s3:::synthetic-state/" + LEASE_KEY
TFLOCK = STATE + ".tflock"
SENTINEL = "0" * 40


def audit_governance():
    return {"account_id": ACCOUNT, "roles": {"audit": AUDIT_ROLE_ARN}, "state_bucket": "synthetic-state",
            "evidence_bucket": "synthetic-evidence", "evidence_prefix": CONFIG["evidence_prefix"],
            "evidence_kms_key_arn": EVIDENCE_KMS, "state_kms_key_arn": STATE_KMS}


def audit_request(governance=None, direction="advance", delete_resources=()):
    return lifecycle_request(governance or audit_governance(), "a" * 40, 42, 1, "audit", "observer-bootstrap-audit",
                             direction=direction, delete_resources=delete_resources)


def test_managed_arn_do_audit_deriva_a_sessao_do_nome_do_role():
    assert managed_arn(audit_governance(), "audit") == AUDIT_SESSION_ARN


@pytest.mark.parametrize("name", ["cnesdata-test-plan", "limnopulse-audit", "cnesdata-audit"])
def test_managed_arn_do_audit_recusa_role_fora_do_padrao_do_audit(name):
    governance = audit_governance()
    governance["roles"]["audit"] = f"arn:aws:iam::{ACCOUNT}:role/{name}"
    with pytest.raises(ValueError, match="deterministic governed session role"):
        managed_arn(governance, "audit")


def test_lifecycle_request_do_audit_usa_a_sessao_do_audit_e_nega_deletes():
    request = audit_request()
    policy = json.loads(request["Policy"])
    assert request["PolicyArns"] == [{"arn": AUDIT_SESSION_ARN}]
    assert {"Effect": "Deny", "Action": LIFECYCLE_DELETES, "Resource": "*"} in policy["Statement"]


def test_lifecycle_request_do_audit_converge_continua_sessao_de_leitura():
    policy = json.loads(audit_request(direction="converge")["Policy"])
    assert {"Effect": "Deny", "Action": LIFECYCLE_DELETES, "Resource": "*"} in policy["Statement"]
    arn = f"arn:aws:states:us-east-2:{ACCOUNT}:stateMachine:cnesdata-prod-mode"
    with pytest.raises(ValueError, match="advance/read session cannot delete"):
        audit_request(direction="converge", delete_resources=[arn])


def test_sessao_efetiva_do_audit_libera_so_o_caminho_do_codigo(native):
    resources, _ = render(native, audit_values(), "audit-effective-session")
    identity = json.loads(resources[AUDIT_POLICY]["policy"])
    managed = json.loads(resources[AUDIT_SESSION]["policy"])
    assert resources[AUDIT_SESSION]["name"] == AUDIT_SESSION_ARN.rsplit("/", 1)[1]
    request = audit_request()
    assert request["PolicyArns"] == [{"arn": AUDIT_SESSION_ARN}]
    inline = json.loads(request["Policy"])
    keys = lifecycle_keys()
    context = lambda arn: VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": arn}
    allowed = [
        ("iam:GetPolicy", AUDIT_SESSION_ARN, None), ("iam:GetPolicyVersion", AUDIT_SESSION_ARN, None),
        ("s3:GetObject", STATE, None), ("s3:GetObject", LEASE, None),
        ("kms:Decrypt", STATE_KMS, context(STATE)), ("kms:Decrypt", STATE_KMS, context(LEASE)),
        ("s3:ListBucket", "arn:aws:s3:::synthetic-state", {"s3:prefix": LEASE_KEY}),
        ("s3:GetObject", keys["keeper"], None), ("s3:GetObject", keys["payload"], None),
        ("s3:PutObject", keys["own"], {"s3:if-none-match": "*"}),
        ("kms:GenerateDataKey", EVIDENCE_KMS, context(keys["own"])),
        ("kms:Decrypt", EVIDENCE_KMS, context(keys["payload"])),
    ]
    refused = [
        ("s3:PutObject", STATE, {"s3:if-none-match": "*"}), ("s3:PutObject", LEASE, {"s3:if-none-match": "*"}),
        ("s3:PutObject", TFLOCK, None), ("s3:DeleteObject", TFLOCK, None), ("s3:PutObject", keys["own"], None),
        ("s3:PutObject", keys["payload"], {"s3:if-none-match": "*"}),
        ("kms:Encrypt", EVIDENCE_KMS, context(keys["own"])),
        ("sts:AssumeRole", f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-api", None),
    ]
    assert [item for item in allowed if not effective(identity, managed, inline, *item)] == []
    assert [item for item in refused if effective(identity, managed, inline, *item)] == []


def owner_governance(workflow_path=".github/workflows/owner-root-proof.yml"):
    governance = audit_governance()
    owner = {"repository": "VINIClUS/infra-ansible", "workflow_path": workflow_path, "workflow_sha": "e" * 40}
    document = {"Version": "2012-10-17", "Statement": []}
    pin = {"account_id": ACCOUNT, "role_arn": AUDIT_ROLE_ARN, "policy_arn": AUDIT_SESSION_ARN,
           "root_source_sha": "d" * 40, "default_version_id": "v3", "document": document,
           "document_sha256": c.sha(c.canonical(document)), "observed_at": c.utc(1999999990),
           "expires_at": c.utc(2000007200), "frozen_until": c.utc(2000007200), "owner_producer": owner}
    governance.update(session_policy_pins={"audit": pin}, proof_producers=[owner])
    return governance


def test_pin_do_owner_aceita_a_sessao_gerenciada_do_audit():
    governance = owner_governance()
    assert session_owner._pin(governance, "audit") == governance["session_policy_pins"]["audit"]


def test_pin_do_owner_recusa_sessao_do_audit_com_outro_nome():
    governance = owner_governance()
    governance["session_policy_pins"]["audit"]["policy_arn"] = f"arn:aws:iam::{ACCOUNT}:policy/{AUDIT_NAME}"
    with pytest.raises(ValueError, match="own deterministic session policy"):
        session_owner._pin(governance, "audit")


def test_pin_do_owner_recusa_o_reusable_do_audit_como_produtor_do_proprio_pin():
    with pytest.raises(ValueError, match="consumer self-measurement forbidden"):
        session_owner._pin(owner_governance(AUDIT_REUSABLE), "audit")


def swap_gate_sha(governance, api, run, role, sha):
    old = governance["gate_shas"][role]
    api.raw = api.raw.replace(b"@" + old.encode(), b"@" + sha.encode())
    manifest = governance["application_product_source_manifest"]
    manifest["files"][run["path"]] = c.sha(api.raw)
    governance["application_product_source_closure_sha256"] = c.sha(c.canonical(manifest))
    reference = run["referenced_workflows"][0]
    reference.update(path=reference["path"].replace("@" + old, "@" + sha), sha=sha)
    governance["gate_shas"][role] = sha


def admit(governance, api, role, step):
    observed = lifecycle_runtime.source_admission(governance, api, role, "b" * 40, 44, 2)
    return provenance.application_caller(api, governance, observed, role, step)


def test_admissao_do_audit_autentica_o_reusable_do_audit_no_proprio_gate_sha(monkeypatch):
    governance, api, run, step, _, _ = _application_caller_fixture(monkeypatch, "promotion", "audit")
    assert run["referenced_workflows"][0]["path"].endswith(AUDIT_REUSABLE + "@" + governance["gate_shas"]["audit"])
    assert admit(governance, api, "audit", step)["run_attempt"] == 2


def test_admissao_do_audit_exige_gate_sha_do_audit_na_governanca(monkeypatch):
    governance, api, _, step, _, _ = _application_caller_fixture(monkeypatch, "promotion", "audit")
    governance["gate_shas"].pop("audit")
    with pytest.raises(ValueError, match="gate_shas role absent role=audit"):
        admit(governance, api, "audit", step)


@pytest.mark.parametrize("role", ["audit", "plan", "deploy", "application"])
def test_admissao_recusa_gate_sha_sentinela_de_quarenta_zeros(monkeypatch, role):
    governance, api, run, step, _, _ = _application_caller_fixture(monkeypatch, "promotion", role)
    swap_gate_sha(governance, api, run, role, SENTINEL)
    with pytest.raises(ValueError, match=f"gate_shas sentinel role={role}"):
        admit(governance, api, role, step)


ROLES_QUE_ADMITEM = ["plan", "deploy", "audit", "application"]
CASOS_INVALIDOS = ["absent", "sentinel", "malformed"]


def break_gate_sha(governance, api, run, role, case):
    if case == "absent":
        governance["gate_shas"].pop(role)
        return f"gate_shas role absent role={role}"
    swap_gate_sha(governance, api, run, role, SENTINEL if case == "sentinel" else governance["gate_shas"][role].upper())
    return f"gate_shas {case} role={role}"


@pytest.mark.parametrize("role", ROLES_QUE_ADMITEM)
@pytest.mark.parametrize("case", CASOS_INVALIDOS)
def test_admissao_recusa_gate_sha_invalido_do_proprio_papel(monkeypatch, role, case):
    governance, api, run, _, _, _ = _application_caller_fixture(monkeypatch, "promotion", role)
    message = break_gate_sha(governance, api, run, role, case)
    with pytest.raises(ValueError, match=message):
        lifecycle_runtime.source_admission(governance, api, role, "b" * 40, 44, 2)


@pytest.mark.parametrize("role", ROLES_QUE_ADMITEM)
@pytest.mark.parametrize("case", CASOS_INVALIDOS)
def test_conversao_do_caller_recusa_gate_sha_invalido_apos_admissao_valida(monkeypatch, role, case):
    governance, api, run, step, _, _ = _application_caller_fixture(monkeypatch, "promotion", role)
    observed = lifecycle_runtime.source_admission(governance, api, role, "b" * 40, 44, 2)
    message = break_gate_sha(governance, api, run, role, case)
    with pytest.raises(ValueError, match=message):
        provenance.application_caller(api, governance, observed, role, step)


@pytest.mark.parametrize("role", ROLES_QUE_ADMITEM)
@pytest.mark.parametrize("case", CASOS_INVALIDOS)
def test_credencial_oidc_le_so_o_proprio_gate_sha_valido_de_cada_papel(monkeypatch, role, case):
    calls = []
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda *a, **k: calls.append(a)))
    monkeypatch.setitem(sys.modules, "botocore", SimpleNamespace(UNSIGNED="synthetic"))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kwargs: kwargs))
    gate_shas = {name: "e" * 40 for name in ROLES_QUE_ADMITEM if name != role}
    if case != "absent":
        gate_shas[role] = SENTINEL if case == "sentinel" else "E" * 40
    message = f"gate_shas role absent role={role}" if case == "absent" else f"gate_shas {case} role={role}"
    with pytest.raises(ValueError, match=message):
        lifecycle_runtime.oidc_credentials({"gate_shas": gate_shas}, role, {}, {"id": 44, "run_attempt": 2})
    assert calls == []


@pytest.mark.parametrize("value", ["E" * 40, "e" * 39, "e" * 41, None, 7, "g" * 40])
def test_gate_sha_malformado_recusa_com_chave_e_papel(value):
    with pytest.raises(ValueError, match="^gate_shas malformed role=deploy$"):
        c.gate_sha({"gate_shas": {"deploy": value}}, "deploy")




class CountingAPI:
    def __init__(self, inner):
        self.inner, self.reads = inner, []

    def read(self, path, **kwargs):
        self.reads.append(path)
        return self.inner.read(path, **kwargs)


def all_gate_shas(governance, role):
    shas = {"application": "a" * 40, "plan": "1" * 40, "deploy": "2" * 40, "audit": "3" * 40}
    shas[role] = governance["gate_shas"][role]
    governance["gate_shas"] = shas


@pytest.mark.parametrize("role", ROLES_QUE_ADMITEM)
def test_governanca_com_os_quatro_gate_shas_validos_admite_cada_papel(monkeypatch, role):
    governance, api, _, step, _, _ = _application_caller_fixture(monkeypatch, "promotion", role)
    all_gate_shas(governance, role)
    assert admit(governance, api, role, step)["run_attempt"] == 2


@pytest.mark.parametrize("role", ROLES_QUE_ADMITEM)
@pytest.mark.parametrize("audit,message", [(None, "gate_shas role absent role=audit"),
                                           (SENTINEL, "gate_shas sentinel role=audit")])
def test_governanca_com_plan_e_deploy_sem_audit_valido_para_na_primeira_admissao(monkeypatch, role, audit, message):
    governance, api, _, _, _, _ = _application_caller_fixture(monkeypatch, "promotion", role)
    all_gate_shas(governance, role)
    if audit is None:
        governance["gate_shas"].pop("audit")
    else:
        governance["gate_shas"]["audit"] = audit
    counting = CountingAPI(api)
    with pytest.raises(ValueError, match=message):
        lifecycle_runtime.source_admission(governance, counting, role, "b" * 40, 44, 2)
    assert counting.reads == []


@pytest.mark.parametrize("pinned", [{"plan": "1" * 40}, {"deploy": "2" * 40}])
def test_regra_do_contrato_exige_audit_quando_a_governanca_tem_plan_ou_deploy(pinned):
    with pytest.raises(ValueError, match="gate_shas role absent role=audit"):
        c.require_audit_gate({"gate_shas": pinned})
    c.require_audit_gate({"gate_shas": pinned | {"audit": "3" * 40}})
    c.require_audit_gate({"gate_shas": {"application": "a" * 40}})
