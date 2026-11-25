"""Roles do observador (X_R) e do escritor de phase-inputs da raiz de entrega, renderizados nativamente."""
import copy
import json
import re

import pytest

from fixtures.cnesdata_iam_evaluation import allowed, decision
from test_cnesdata_delivery_oidc import application_values, native, render, variables
from tools.cnesdata_delivery.contract import REPOSITORY as CNESDATA
from tools.cnesdata_delivery.coordination_lease import KEY as LEASE_KEY
from tools.cnesdata_delivery.lifecycle_runtime import namespace
from tools.cnesdata_delivery.producers import observer as producer, phase_inputs
from tools.cnesdata_delivery.producers.pins import REPOSITORY as INFRA
from tools.cnesdata_delivery.producers.release_guard import OBSERVER as OBSERVER_REUSABLE


ACCOUNT = "111122223333"
OIDC = "token.actions.githubusercontent.com"
X = "e" * 40
DEADLINE = "2030-01-01T00:00:00Z"
OBSERVER_ROLE, OBSERVER_POLICY = "aws_iam_role.observer[0]", "aws_iam_role_policy.observer[0]"
WRITER_ROLE, WRITER_POLICY = "aws_iam_role.phase_inputs_writer[0]", "aws_iam_role_policy.phase_inputs_writer[0]"
WRITER_NAME = "cnesdata-prod-phase-inputs-writer"
AUDIT_NAME = "cnesdata-test-audit"
AUDIT_ROLE, AUDIT_POLICY = 'aws_iam_role.delivery["audit"]', "aws_iam_role_policy.delivery_audit[0]"
AUDIT_SESSION = 'aws_iam_policy.delivery_session["audit"]'
AUDIT_REUSABLE = f"{INFRA}/.github/workflows/reusable-cnesdata-infra-audit-gate.yml"
AUDIT_ACTIONS = {"iam:GetPolicy", "iam:GetPolicyVersion", "s3:GetObject", "s3:ListBucket", "s3:PutObject",
                 "kms:Decrypt", "kms:GenerateDataKey"}
OBSERVER_SUB = f"repo:{INFRA}:environment:cnesdata-observer"
WRITER_SUB = f"repo:{CNESDATA}:environment:production"
WRITER_REF = f"{CNESDATA}/.github/workflows/phase-a-prepare.yml@refs/heads/main"
CLUSTER = f"arn:aws:ecs:us-east-2:{ACCOUNT}:cluster/cnesdata-prod"
ECR = f"arn:aws:ecr:us-east-2:{ACCOUNT}:repository/cnesdata-prod-api"
TABLES = [f"arn:aws:dynamodb:us-east-2:{ACCOUNT}:table/cnesdata-prod-jobs",
          f"arn:aws:dynamodb:us-east-2:{ACCOUNT}:table/cnesdata-prod-leases"]
BUCKETS = ["arn:aws:s3:::cnesdata-prod-static-web", "arn:aws:s3:::cnesdata-prod-artifacts"]
STATE_BUCKET, EVIDENCE_BUCKET = "arn:aws:s3:::synthetic-state", "arn:aws:s3:::synthetic-evidence"
CONFIG = {"evidence_prefix": "cnesdata/prod/evidence/"}
STATE_KMS = variables()["github_delivery"]["state_kms_arn"]
EVIDENCE_KMS = variables()["github_delivery"]["evidence_kms_arn"]
OTHER_ACCOUNT = ACCOUNT.replace("1", "9")
VIA_S3 = {"kms:ViaService": "s3.us-east-2.amazonaws.com"}
N11 = {"dynamodb:DescribeTable", "s3:GetBucketPolicy", "s3:GetBucketVersioning",
       "s3:GetBucketObjectLockConfiguration"}
REPEATED = {"iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRole", "iam:GetRolePolicy",
            "ecs:DescribeTaskDefinition", "ecs:DescribeClusters", "ecr:DescribeRepositories",
            "ecr:DescribeImages", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"}
READS = REPEATED | N11 | {"s3:GetObject", "s3:ListBucket", "kms:Decrypt"}
STS_DENIES = ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"]
PRODUCER_ACTIONS = {
    ("iam", "get_role"): "iam:GetRole", ("iam", "get_role_policy"): "iam:GetRolePolicy",
    ("iam", "get_policy"): "iam:GetPolicy", ("iam", "get_policy_version"): "iam:GetPolicyVersion",
    ("ecs", "describe_task_definition"): "ecs:DescribeTaskDefinition",
    ("ecs", "describe_clusters"): "ecs:DescribeClusters",
    ("ecr", "describe_repositories"): "ecr:DescribeRepositories", ("ecr", "describe_images"): "ecr:DescribeImages",
    ("ecr", "batch_get_image"): "ecr:BatchGetImage",
    ("ecr", "get_download_url_for_layer"): "ecr:GetDownloadUrlForLayer",
    ("s3", "get_object"): "s3:GetObject", ("s3", "list_objects_v2"): "s3:ListBucket",
    ("s3", "get_bucket_policy"): "s3:GetBucketPolicy", ("s3", "get_bucket_versioning"): "s3:GetBucketVersioning",
    ("s3", "get_object_lock_configuration"): "s3:GetBucketObjectLockConfiguration",
    ("dynamodb", "describe_table"): "dynamodb:DescribeTable"}
FORA_DO_O1 = {("scheduler", "get_schedule"), ("acm", "describe_certificate")}
SSE_KMS_IMPLICITO = {"kms:Decrypt"}


def observer_values(sha=X):
    values = variables()
    values["observer"] = {"workflow_sha": sha, "cluster_arn": CLUSTER, "repository_arn": ECR,
                          "table_arns": TABLES, "bucket_arns": BUCKETS}
    return values


def writer_values():
    values = variables()
    values["phase_inputs_writer_enabled"] = True
    return values


def audit_values(sha=X):
    values = variables()
    values["audit"] = {"role_name": AUDIT_NAME, "workflow_sha": sha}
    return values


def host_gate(sha):
    return {"workflow_sha": sha,
            "objects": [{"arn": "arn:aws:s3:::synthetic-evidence/cnesdata/platform.json", "version": "exact-version"}],
            "ssm_parameter_arns": [f"arn:aws:ssm:us-east-2:{ACCOUNT}:parameter/cnesdata/deploy/" + name
                                   for name in ("ssh-key", "cloudflare-client-id", "cloudflare-client-secret")],
            "ssm_key_arn": EVIDENCE_KMS[:-1] + "3",
            "decrypt_keys": [{"arn": EVIDENCE_KMS,
                              "object_arns": ["arn:aws:s3:::synthetic-evidence/cnesdata/platform.json"]}]}


def every_trust(shas):
    from fixtures.cnesdata_delivery_ext2.inventory import variables as ext2_variables
    values = application_values()
    values["github_delivery"]["plan_workflow_sha"] = shas["plan"]
    values["github_delivery"]["deploy_workflow_sha"] = shas["deploy"]
    values["application_promotion"]["workflow_sha"] = shas["application"]
    values["host_gate"] = host_gate(shas["host"])
    values["ext2_enabled"] = True
    values["ext2"] = copy.deepcopy(ext2_variables(True)["ext2"]) | {"workflow_sha": shas["ext2"]}
    values["observer"] = observer_values(shas["observer"])["observer"]
    values["phase_inputs_writer_enabled"] = True
    values["audit"] = audit_values(shas["audit"])["audit"]
    return values


TRUST_ROLES = {"plan": 'aws_iam_role.delivery["plan"]', "deploy": 'aws_iam_role.delivery["deploy"]',
               "application": "aws_iam_role.application[0]", "host": "aws_iam_role.host_gate[0]",
               "ext2": "aws_iam_role.ext2_gate[0]", "observer": OBSERVER_ROLE, "audit": AUDIT_ROLE}


def statement_of(resources, address):
    trust = json.loads(resources[address]["assume_role_policy"])
    assert len(trust["Statement"]) == 1
    return trust, trust["Statement"][0]


def condition_values(statement):
    for block in statement["Condition"].values():
        for value in block.values():
            yield from [value] if isinstance(value, str) else value


def oidc_context(sub, ref, now="2029-12-31T23:59:59Z"):
    return {f"{OIDC}:aud": "sts.amazonaws.com", f"{OIDC}:sub": sub, f"{OIDC}:job_workflow_ref": ref,
            "aws:CurrentTime": now}


def evidence(key):
    return EVIDENCE_BUCKET + "/" + key


def test_observador_e_escritor_ficam_ausentes_por_padrao(native):
    resources, outputs = render(native, variables(), "observer-writer-closed")
    assert not any(address.startswith(("aws_iam_role.observer", "aws_iam_role_policy.observer",
                                       "aws_iam_role.phase_inputs_writer",
                                       "aws_iam_role_policy.phase_inputs_writer")) for address in resources)
    assert set(outputs["github"]["value"]) == {"infrastructure_plan_role_arn", "infrastructure_deploy_role_arn"}


def test_trust_do_observador_fixa_sub_aud_x_r_e_prazo_sem_curinga(native):
    resources, _ = render(native, observer_values(), "observer-trust")
    role = resources[OBSERVER_ROLE]
    trust, statement = statement_of(resources, OBSERVER_ROLE)
    assert role["name"] == "cnesdata-delivery-observer" and role["max_session_duration"] == 3600
    assert statement["Effect"] == "Allow" and statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert statement["Principal"] == {"Federated": variables()["github_delivery"]["provider_arn"]}
    assert statement["Condition"] == {
        "StringEquals": {f"{OIDC}:aud": "sts.amazonaws.com", f"{OIDC}:sub": OBSERVER_SUB,
                         f"{OIDC}:job_workflow_ref": f"{OBSERVER_REUSABLE}@{X}"},
        "DateLessThan": {"aws:CurrentTime": DEADLINE}}
    assert not any(char in value for value in condition_values(statement) for char in "*?")
    good = oidc_context(OBSERVER_SUB, f"{OBSERVER_REUSABLE}@{X}")
    assert allowed(trust, "sts:AssumeRoleWithWebIdentity", "*", good)
    for change in ({f"{OIDC}:job_workflow_ref": f"{OBSERVER_REUSABLE}@{'f' * 40}"},
                   {f"{OIDC}:job_workflow_ref": f"{OBSERVER_REUSABLE}@refs/heads/main"},
                   {f"{OIDC}:sub": f"repo:{INFRA}:ref:refs/heads/main"},
                   {f"{OIDC}:sub": f"repo:{CNESDATA}:environment:cnesdata-observer"},
                   {f"{OIDC}:aud": "https://github.com/VINIClUS"},
                   {"aws:CurrentTime": DEADLINE}):
        assert not allowed(trust, "sts:AssumeRoleWithWebIdentity", "*", good | change), change


def test_politica_do_observador_tem_so_as_leituras_e_nega_assume_e_escrita(native):
    resources, _ = render(native, observer_values(), "observer-policy")
    policy = json.loads(resources[OBSERVER_POLICY]["policy"])
    allows = [s for s in policy["Statement"] if s["Effect"] == "Allow"]
    denies = [s for s in policy["Statement"] if s["Effect"] == "Deny"]
    assert {action for s in allows for action in s["Action"]} == READS
    assert not any("*" in action for s in allows for action in s["Action"])
    assert {"Effect": "Deny", "Action": STS_DENIES, "Resource": "*"} in denies
    assert [s for s in denies if "NotAction" in s] == [
        {"Effect": "Deny", "NotAction": sorted(READS), "Resource": "*"}]
    phase_inputs_key = evidence(phase_inputs._namespace_prefix(CONFIG, ASKED_RUN) + "promotion.json")
    for action, resource in (("s3:PutObject", phase_inputs_key), ("s3:DeleteObject", phase_inputs_key),
                             ("s3:PutObject", STATE_BUCKET + "/" + producer.STATE_KEY),
                             ("s3:PutBucketPolicy", BUCKETS[0]), ("dynamodb:UpdateTable", TABLES[0]),
                             ("ecr:PutImage", ECR), ("ecs:RegisterTaskDefinition", "*"),
                             ("iam:PutRolePolicy", f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-api"),
                             ("kms:Encrypt", EVIDENCE_KMS), ("kms:GenerateDataKey", EVIDENCE_KMS),
                             ("sts:AssumeRole", "*"), ("sts:AssumeRoleWithWebIdentity", "*"), ("sts:AssumeRoot", "*")):
        assert decision(policy, action, resource) == "Deny", (action, resource)


ASKED_RUN = {"source_sha": "a" * 40, "payload_reference": {"run_id": 42, "run_attempt": 1}}


def test_observador_decifra_o_estado_com_bucket_key_pelo_contexto_do_arn_do_bucket(native):
    resources, _ = render(native, observer_values(), "observer-policy")
    policy = json.loads(resources[OBSERVER_POLICY]["policy"])
    context = VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": STATE_BUCKET}
    assert allowed(policy, "kms:Decrypt", STATE_KMS, context)
    assert not allowed(policy, "kms:Decrypt", EVIDENCE_KMS, context)
    assert not allowed(policy, "kms:Decrypt", STATE_KMS, context | {"kms:ViaService": "ec2.us-east-2.amazonaws.com"})
    assert not allowed(policy, "kms:Decrypt", STATE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": EVIDENCE_BUCKET})
    for action in ("kms:Encrypt", "kms:GenerateDataKey", "kms:ReEncryptFrom", "kms:ReEncryptTo"):
        assert not allowed(policy, action, STATE_KMS, context), action
    assert not allowed(policy, "s3:ListBucket", STATE_BUCKET)
    assert not allowed(policy, "s3:GetObject", STATE_BUCKET + "/" + producer.STATE_KEY + ".tflock")


def test_observador_le_o_que_o_produtor_le_e_nada_fora_dos_recursos_nomeados(native):
    resources, _ = render(native, observer_values(), "observer-policy")
    policy = json.loads(resources[OBSERVER_POLICY]["policy"])
    state = STATE_BUCKET + "/" + producer.STATE_KEY
    asked = {"source_sha": "a" * 40, "payload_reference": {"run_id": 42, "run_attempt": 1}}
    base = phase_inputs._namespace_prefix(CONFIG, asked)
    assert allowed(policy, "s3:GetObject", state)
    assert allowed(policy, "kms:Decrypt", STATE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": state})
    for obj in [evidence(base + name) for name in phase_inputs.NAMES]:
        assert allowed(policy, "s3:GetObject", obj)
        assert allowed(policy, "kms:Decrypt", EVIDENCE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": obj})
        assert not allowed(policy, "kms:Decrypt", EVIDENCE_KMS,
                           {"kms:ViaService": "ec2.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": obj})
    assert allowed(policy, "s3:ListBucket", EVIDENCE_BUCKET, {"s3:prefix": base})
    lifecycle = evidence(CONFIG["evidence_prefix"] + "lifecycle/" + "a" * 40 + "/42/1/terminal/terminal.json")
    planned = evidence(CONFIG["evidence_prefix"] + "a" * 40 + "/42/1/planned/envelope.json")
    for obj in (state + ".tflock", STATE_BUCKET + "/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json",
                lifecycle, planned):
        assert not allowed(policy, "s3:GetObject", obj), obj
        for key in (STATE_KMS, EVIDENCE_KMS):
            assert not allowed(policy, "kms:Decrypt", key, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": obj})
    for prefix in (CONFIG["evidence_prefix"], CONFIG["evidence_prefix"] + "lifecycle/"):
        assert not allowed(policy, "s3:ListBucket", EVIDENCE_BUCKET, {"s3:prefix": prefix})
    assert not allowed(policy, "s3:ListBucket", STATE_BUCKET, {"s3:prefix": base})
    for role in ("plan", "deploy"):
        assert allowed(policy, "iam:GetPolicyVersion", f"arn:aws:iam::{ACCOUNT}:policy/cnesdata-test-{role}-session")
    assert not allowed(policy, "iam:GetPolicy", f"arn:aws:iam::{ACCOUNT}:policy/cnesdata-prod-application-session")
    assert not allowed(policy, "iam:GetPolicy", f"arn:aws:iam::{ACCOUNT}:policy/limnopulse-session")
    assert allowed(policy, "iam:GetRolePolicy", f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-static-observer")
    for role in ("cnesdata-test-plan", "cnesdata-delivery-observer", "limnopulse-observer"):
        assert not allowed(policy, "iam:GetRole", f"arn:aws:iam::{ACCOUNT}:role/{role}"), role
    assert allowed(policy, "ecs:DescribeTaskDefinition", "*")
    assert allowed(policy, "ecs:DescribeClusters", CLUSTER)
    assert not allowed(policy, "ecs:DescribeClusters", CLUSTER + "-other")
    for action in ("ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"):
        assert allowed(policy, action, ECR) and not allowed(policy, action, ECR + "-other")
    for table in TABLES:
        assert allowed(policy, "dynamodb:DescribeTable", table)
    assert not allowed(policy, "dynamodb:DescribeTable", TABLES[0] + "-other")
    for action in N11 - {"dynamodb:DescribeTable"}:
        for bucket in BUCKETS:
            assert allowed(policy, action, bucket)
        for bucket in (STATE_BUCKET, EVIDENCE_BUCKET, BUCKETS[0] + "-other"):
            assert not allowed(policy, action, bucket), (action, bucket)


def test_observador_le_a_politica_de_sessao_do_application_quando_existe(native):
    values = observer_values()
    values["application_promotion"] = application_values()["application_promotion"]
    resources, _ = render(native, values, "observer-application")
    policy = json.loads(resources[OBSERVER_POLICY]["policy"])
    for name in ("cnesdata-test-plan", "cnesdata-test-deploy", "cnesdata-prod-application"):
        assert allowed(policy, "iam:GetPolicy", f"arn:aws:iam::{ACCOUNT}:policy/{name}-session"), name


def test_leituras_do_observador_repetem_as_ja_aprovadas_para_os_gates(native):
    values = observer_values()
    values["github_delivery"]["read_resource_arns"] = [CLUSTER]
    resources, _ = render(native, values, "observer-subset")
    observer = json.loads(resources[OBSERVER_POLICY]["policy"])
    plan = json.loads(resources['aws_iam_role_policy.delivery["plan"]']["policy"])
    approved = {a for s in plan["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
    observed = {a for s in observer["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
    assert REPEATED | N11 <= approved
    assert observed <= approved


def test_toda_leitura_do_produtor_no_o1_tem_acao_permitida_ao_observador(native):
    from tools.cnesdata_delivery.producers.aws_reader import READS as PRODUCER_READS
    issued = {(service, operation) for service, operations in PRODUCER_READS.items() for operation in operations}
    assert issued == set(PRODUCER_ACTIONS) | FORA_DO_O1
    resources, _ = render(native, observer_values(), "observer-policy")
    policy = json.loads(resources[OBSERVER_POLICY]["policy"])
    granted = {a for s in policy["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
    assert set(PRODUCER_ACTIONS.values()) | SSE_KMS_IMPLICITO == granted
    for service, operation in FORA_DO_O1:
        assert not any(action.startswith(service + ":") for action in granted)


def test_trust_do_escritor_fixa_production_e_phase_a_prepare_no_main(native):
    resources, _ = render(native, writer_values(), "writer-trust")
    role = resources[WRITER_ROLE]
    trust, statement = statement_of(resources, WRITER_ROLE)
    assert role["name"] == WRITER_NAME and role["max_session_duration"] == 3600
    assert statement["Effect"] == "Allow" and statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert statement["Principal"] == {"Federated": variables()["github_delivery"]["provider_arn"]}
    assert statement["Condition"] == {"StringEquals": {
        f"{OIDC}:aud": "sts.amazonaws.com", f"{OIDC}:sub": WRITER_SUB, f"{OIDC}:job_workflow_ref": WRITER_REF}}
    assert not any(char in value for value in condition_values(statement) for char in "*?")
    good = oidc_context(WRITER_SUB, WRITER_REF)
    assert allowed(trust, "sts:AssumeRoleWithWebIdentity", "*", good)
    for change in ({f"{OIDC}:sub": f"repo:{CNESDATA}:ref:refs/heads/main"},
                   {f"{OIDC}:job_workflow_ref": WRITER_REF.replace("refs/heads/main", "refs/heads/develop")},
                   {f"{OIDC}:job_workflow_ref": WRITER_REF.replace("phase-a-prepare", "promote-production")},
                   {f"{OIDC}:sub": OBSERVER_SUB}):
        assert not allowed(trust, "sts:AssumeRoleWithWebIdentity", "*", good | change), change


def test_escritor_so_cria_em_phase_inputs_com_if_none_match_e_contexto_kms(native):
    resources, _ = render(native, writer_values(), "writer-policy")
    policy = json.loads(resources[WRITER_POLICY]["policy"])
    scope = evidence(CONFIG["evidence_prefix"] + "phase-inputs/*")
    assert policy["Statement"] == [
        {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": scope,
         "Condition": {"Null": {"s3:if-none-match": "false"}}},
        {"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Encrypt"], "Resource": EVIDENCE_KMS,
         "Condition": {"StringEquals": VIA_S3, "StringLike": {"kms:EncryptionContext:aws:s3:arn": scope}}}]
    asked = {"source_sha": "a" * 40, "payload_reference": {"run_id": 42, "run_attempt": 1}}
    base = phase_inputs._namespace_prefix(CONFIG, asked)
    created = [evidence(base + name) for name in phase_inputs.NAMES]
    for obj in created:
        assert allowed(policy, "s3:PutObject", obj, {"s3:if-none-match": "*"})
        assert not allowed(policy, "s3:PutObject", obj)
        for action in ("kms:GenerateDataKey", "kms:Encrypt"):
            assert allowed(policy, action, EVIDENCE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": obj})
        for action in ("s3:GetObject", "s3:DeleteObject", "s3:PutObjectAcl", "s3:GetObjectVersion"):
            assert not allowed(policy, action, obj, {"s3:if-none-match": "*"})
        assert not allowed(policy, "kms:Decrypt", EVIDENCE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": obj})
    for obj in (evidence(CONFIG["evidence_prefix"] + "lifecycle/x.json"), evidence(CONFIG["evidence_prefix"] + "x.json"),
                STATE_BUCKET + "/" + CONFIG["evidence_prefix"] + "phase-inputs/x.json"):
        assert not allowed(policy, "s3:PutObject", obj, {"s3:if-none-match": "*"}), obj
        assert not allowed(policy, "kms:GenerateDataKey", EVIDENCE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": obj})
    assert not allowed(policy, "kms:GenerateDataKey", EVIDENCE_KMS,
                       {"kms:ViaService": "ec2.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": created[0]})
    assert not allowed(policy, "s3:ListBucket", EVIDENCE_BUCKET, {"s3:prefix": base})
    assert not allowed(policy, "sts:AssumeRole", "*")


def test_trusts_sao_entradas_separadas_que_o_apply_pode_igualar_a_x(native):
    same = every_trust({role: X for role in TRUST_ROLES})
    resources, _ = render(native, same, "trusts-equal-x")
    for role, address in TRUST_ROLES.items():
        _, statement = statement_of(resources, address)
        assert statement["Condition"]["StringEquals"][f"{OIDC}:job_workflow_ref"].endswith("@" + X), role
    _, writer = statement_of(resources, WRITER_ROLE)
    assert writer["Condition"]["StringEquals"][f"{OIDC}:job_workflow_ref"] == WRITER_REF
    distinct = dict(zip(TRUST_ROLES, ("a" * 40, "b" * 40, "c" * 40, "d" * 40, "f" * 40, "1" * 40, "2" * 40)))
    resources, _ = render(native, every_trust(distinct), "trusts-distinct")
    for role, address in TRUST_ROLES.items():
        _, statement = statement_of(resources, address)
        assert statement["Condition"]["StringEquals"][f"{OIDC}:job_workflow_ref"].endswith("@" + distinct[role]), role


SHA_FIELDS = {"plan": ("github_delivery", "plan_workflow_sha"), "deploy": ("github_delivery", "deploy_workflow_sha"),
              "application": ("application_promotion", "workflow_sha"), "host": ("host_gate", "workflow_sha"),
              "ext2": ("ext2", "workflow_sha"), "observer": ("observer", "workflow_sha"),
              "audit": ("audit", "workflow_sha")}


@pytest.mark.parametrize("role", sorted(SHA_FIELDS))
def test_variavel_de_trust_recusa_a_sentinela_de_quarenta_zeros(native, role):
    values = every_trust({name: X for name in TRUST_ROLES})
    group, field = SHA_FIELDS[role]
    values[group][field] = "0" * 40
    code, _, errors = native.plan(values, "sentinel-" + role)
    assert code != 0 and any("40-zero" in json.dumps(item) for item in errors), errors


@pytest.mark.parametrize("index,sha", list(enumerate(["main", "refs/heads/main", "E" * 40, "e" * 39, "e" * 41, "*"])))
def test_x_r_recusa_valor_que_nao_e_sha_de_quarenta_hex(native, index, sha):
    code, _, errors = native.plan(observer_values(sha), f"observer-sha-{index}")
    assert code != 0 and any(item["severity"] == "error" for item in errors), errors


@pytest.mark.parametrize("index,change", list(enumerate([
    {"cluster_arn": "arn:aws:ecs:us-east-2:111122223333:cluster/*"},
    {"cluster_arn": CLUSTER.replace(ACCOUNT, OTHER_ACCOUNT)},
    {"repository_arn": "arn:aws:ecr:us-east-2:111122223333:repository/*"},
    {"table_arns": ["arn:aws:dynamodb:us-east-2:111122223333:table/*"]},
    {"table_arns": []},
    {"bucket_arns": ["arn:aws:s3:::cnesdata-*"]},
    {"bucket_arns": ["arn:aws:s3:::limnopulse-prod"]},
    {"bucket_arns": []},
])))
def test_observador_recusa_recurso_com_curinga_de_outra_conta_ou_vazio(native, index, change):
    values = observer_values()
    values["observer"] |= change
    code, _, errors = native.plan(values, f"observer-resource-{index}")
    assert code != 0 and any(item["severity"] == "error" for item in errors), errors


@pytest.mark.parametrize("name", ["observer", "writer"])
def test_observador_e_escritor_exigem_o_provider_compartilhado(native, name):
    values = observer_values() if name == "observer" else writer_values()
    values["github_delivery"] = None
    code, _, errors = native.plan(values, "no-provider-" + name)
    assert code != 0 and any(item["severity"] == "error" for item in errors), errors


@pytest.mark.parametrize("target", ["product", "pass"])
@pytest.mark.parametrize("role", [WRITER_NAME, "cnesdata-delivery-observer", AUDIT_NAME])
def test_permissoes_de_produto_nunca_alcancam_observador_escritor_nem_audit(native, target, role):
    values = writer_values()
    values["audit"] = audit_values()["audit"]
    arn = f"arn:aws:iam::{ACCOUNT}:role/{role}"
    if target == "product":
        values["github_delivery"]["product_permissions"] = [{"actions": ["iam:PutRolePolicy"], "resources": [arn]}]
    else:
        values["github_delivery"]["pass_roles"] = [{"arn": arn, "service": "ecs-tasks.amazonaws.com"}]
    code, _, errors = native.plan(values, f"reach-{target}-{role}")
    assert code != 0 and any(item["severity"] == "error" for item in errors), errors


@pytest.mark.parametrize("target", ["product", "pass"])
def test_permissoes_de_produto_seguem_aceitas_para_role_do_produto(native, target):
    values = writer_values()
    values["audit"] = audit_values()["audit"]
    arn = f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-api"
    if target == "product":
        values["github_delivery"]["product_permissions"] = [{"actions": ["iam:PutRolePolicy"], "resources": [arn]}]
    else:
        values["github_delivery"]["pass_roles"] = [{"arn": arn, "service": "ecs-tasks.amazonaws.com"}]
    resources, _ = render(native, values, "reach-control-" + target)
    assert WRITER_ROLE in resources and AUDIT_ROLE in resources


def lifecycle_keys():
    governance = {"evidence_prefix": CONFIG["evidence_prefix"]}
    request = {"source_sha": "a" * 40, "step": "observer-bootstrap-audit"}
    run = {"id": 42, "run_attempt": 1}
    return {"keeper": evidence(namespace(governance, {"source_sha": "a" * 40, "step": "keeper"}, run) + "checkpoint.json"),
            "payload": evidence(namespace(governance, request, run, "observer-bootstrap-plan") + "plan.bin"),
            "own": evidence(namespace(governance, request, run) + "approval.json")}


def test_audit_fica_ausente_por_padrao(native):
    resources, _ = render(native, variables(), "observer-writer-closed")
    assert not any("audit" in address for address in resources)
    assert {a for a in resources if a.startswith("aws_iam_role_policy.delivery")} == {
        'aws_iam_role_policy.delivery["plan"]', 'aws_iam_role_policy.delivery["deploy"]'}


def test_trust_do_audit_espelha_plan_deploy_com_sha_proprio_e_prazo(native):
    resources, _ = render(native, audit_values(), "audit-trust")
    role = resources[AUDIT_ROLE]
    trust, statement = statement_of(resources, AUDIT_ROLE)
    assert role["name"] == AUDIT_NAME and role["max_session_duration"] == 3600
    assert statement["Effect"] == "Allow" and statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert statement["Principal"] == {"Federated": variables()["github_delivery"]["provider_arn"]}
    assert statement["Condition"] == {
        "StringEquals": {f"{OIDC}:aud": "sts.amazonaws.com", f"{OIDC}:sub": WRITER_SUB,
                         f"{OIDC}:job_workflow_ref": f"{AUDIT_REUSABLE}@{X}"},
        "DateLessThan": {"aws:CurrentTime": DEADLINE}}
    assert not any(char in value for value in condition_values(statement) for char in "*?")
    _, plan = statement_of(resources, TRUST_ROLES["plan"])
    assert set(plan["Condition"]) == set(statement["Condition"])
    assert plan["Condition"]["StringEquals"][f"{OIDC}:sub"] == statement["Condition"]["StringEquals"][f"{OIDC}:sub"]
    good = oidc_context(WRITER_SUB, f"{AUDIT_REUSABLE}@{X}")
    assert allowed(trust, "sts:AssumeRoleWithWebIdentity", "*", good)
    for change in ({f"{OIDC}:job_workflow_ref": AUDIT_REUSABLE.replace("-audit-", "-plan-") + "@" + X},
                   {f"{OIDC}:job_workflow_ref": f"{AUDIT_REUSABLE}@{'a' * 40}"},
                   {f"{OIDC}:job_workflow_ref": f"{AUDIT_REUSABLE}@refs/heads/main"},
                   {f"{OIDC}:sub": f"repo:{CNESDATA}:ref:refs/heads/main"},
                   {"aws:CurrentTime": DEADLINE}):
        assert not allowed(trust, "sts:AssumeRoleWithWebIdentity", "*", good | change), change


def test_audit_tem_politica_de_sessao_gerenciada_no_nome_que_o_runtime_deriva(native):
    resources, _ = render(native, audit_values(), "audit-trust")
    assert re.fullmatch(rf"arn:aws:iam::{ACCOUNT}:role/cnesdata-[a-z0-9-]+-audit",
                        f"arn:aws:iam::{ACCOUNT}:role/{resources[AUDIT_ROLE]['name']}")
    assert resources[AUDIT_SESSION]["name"] == AUDIT_NAME + "-session"


def test_politica_do_audit_le_estado_lease_e_lifecycle_e_so_publica_no_proprio_lifecycle(native):
    resources, _ = render(native, audit_values(), "audit-trust")
    policy = json.loads(resources[AUDIT_POLICY]["policy"])
    allows = [s for s in policy["Statement"] if s["Effect"] == "Allow"]
    denies = [s for s in policy["Statement"] if s["Effect"] == "Deny"]
    assert {action for s in allows for action in s["Action"]} == AUDIT_ACTIONS
    assert {"Effect": "Deny", "Action": STS_DENIES, "Resource": "*"} in denies
    assert {"Effect": "Deny", "NotAction": sorted(AUDIT_ACTIONS), "Resource": "*"} in denies
    lifecycle = evidence(CONFIG["evidence_prefix"] + "lifecycle/*")
    assert {"Effect": "Deny", "Action": ["s3:PutObject"], "NotResource": lifecycle} in denies
    keys = lifecycle_keys()
    state, lease = STATE_BUCKET + "/" + producer.STATE_KEY, STATE_BUCKET + "/" + LEASE_KEY
    tflock = state + ".tflock"
    for obj in (state, lease):
        assert allowed(policy, "s3:GetObject", obj)
        assert allowed(policy, "kms:Decrypt", STATE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": obj})
    for obj in keys.values():
        assert allowed(policy, "s3:GetObject", obj)
        assert allowed(policy, "kms:Decrypt", EVIDENCE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": obj})
    assert allowed(policy, "s3:PutObject", keys["own"], {"s3:if-none-match": "*"})
    assert not allowed(policy, "s3:PutObject", keys["own"])
    assert allowed(policy, "kms:GenerateDataKey", EVIDENCE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": keys["own"]})
    assert allowed(policy, "s3:ListBucket", STATE_BUCKET, {"s3:prefix": producer.STATE_KEY})
    assert allowed(policy, "iam:GetPolicyVersion", f"arn:aws:iam::{ACCOUNT}:policy/{AUDIT_NAME}-session")
    assert not allowed(policy, "iam:GetPolicy", f"arn:aws:iam::{ACCOUNT}:policy/cnesdata-test-plan-session")
    phase_inputs_key = evidence(phase_inputs._namespace_prefix(CONFIG, ASKED_RUN) + "promotion.json")
    other = evidence(CONFIG["evidence_prefix"] + "a" * 40 + "/42/1/planned/envelope.json")
    for obj in (tflock, phase_inputs_key, other):
        assert not allowed(policy, "s3:GetObject", obj), obj
    assert not allowed(policy, "kms:Decrypt", STATE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": tflock})
    assert not allowed(policy, "kms:Decrypt", EVIDENCE_KMS,
                       {"kms:ViaService": "ec2.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": keys["own"]})
    assert not allowed(policy, "kms:GenerateDataKey", STATE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": lease})
    assert not allowed(policy, "s3:ListBucket", EVIDENCE_BUCKET, {"s3:prefix": CONFIG["evidence_prefix"]})
    for action, resource, context in (
            ("s3:PutObject", state, {"s3:if-none-match": "*"}), ("s3:PutObject", lease, {"s3:if-none-match": "*"}),
            ("s3:PutObject", tflock, {"s3:if-none-match": "*"}), ("s3:PutObject", phase_inputs_key, {"s3:if-none-match": "*"}),
            ("s3:DeleteObject", keys["own"], {}), ("s3:DeleteObject", tflock, {}), ("kms:Encrypt", EVIDENCE_KMS, {}),
            ("iam:PutRolePolicy", f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-api", {}),
            ("states:StartExecution", "*", {}), ("sts:AssumeRole", "*", {}), ("sts:AssumeRoleWithWebIdentity", "*", {})):
        assert decision(policy, action, resource, context) == "Deny", (action, resource)


def test_plan_e_deploy_ficam_identicos_com_o_audit(native):
    closed, _ = render(native, variables(), "observer-writer-closed")
    opened, _ = render(native, audit_values(), "audit-trust")
    for role in ("plan", "deploy"):
        for address in (f'aws_iam_role.delivery["{role}"]', f'aws_iam_role_policy.delivery["{role}"]',
                        f'aws_iam_policy.delivery_session["{role}"]'):
            assert opened[address] == closed[address], address
    assert {a for a in opened if a.startswith("aws_iam_role_policy.delivery[")} == {
        'aws_iam_role_policy.delivery["plan"]', 'aws_iam_role_policy.delivery["deploy"]'}


def test_observador_le_a_politica_de_sessao_do_audit_quando_existe(native):
    values = observer_values()
    values["audit"] = audit_values()["audit"]
    resources, _ = render(native, values, "observer-audit")
    policy = json.loads(resources[OBSERVER_POLICY]["policy"])
    assert allowed(policy, "iam:GetPolicy", f"arn:aws:iam::{ACCOUNT}:policy/{AUDIT_NAME}-session")


@pytest.mark.parametrize("index,change", list(enumerate([
    {"role_name": "cnesdata-test-plan"}, {"role_name": "limnopulse-audit"}, {"role_name": "cnesdata-*-audit"},
    {"role_name": "audit"}, {"workflow_sha": "main"}, {"workflow_sha": "E" * 40}, {"workflow_sha": "e" * 39},
    {"workflow_sha": "refs/heads/main"},
])))
def test_audit_recusa_nome_fora_do_padrao_ou_sha_que_nao_e_quarenta_hex(native, index, change):
    values = audit_values()
    values["audit"] |= change
    code, _, errors = native.plan(values, f"audit-invalid-{index}")
    assert code != 0 and any(item["severity"] == "error" for item in errors), errors


def test_audit_exige_o_provider_compartilhado(native):
    values = audit_values()
    values["github_delivery"] = None
    code, _, errors = native.plan(values, "no-provider-audit")
    assert code != 0 and any(item["severity"] == "error" for item in errors), errors
