"""Contexto KMS do bucket de state, que usa S3 Bucket Key, em todos os roles que o decifram."""
import json

import pytest

from fixtures.cnesdata_iam_evaluation import allowed
from test_cnesdata_delivery_observer_roles import STATE_BUCKET, STATE_KMS, EVIDENCE_BUCKET, VIA_S3, audit_values, native, render
from test_cnesdata_delivery_oidc import application_values, variables

assert native
OTHER_BUCKET = "arn:aws:s3:::synthetic-other"
CASES = [("plano-e-deploy", variables), ("audit", audit_values), ("application", application_values)]


def state_statements(resources):
    for address, values in resources.items():
        if "policy" not in values or not isinstance(values["policy"], str):
            continue
        document = json.loads(values["policy"])
        statements = document["Statement"]
        for statement in statements:
            actions = statement.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            if statement.get("Effect") == "Allow" and statement.get("Resource") == STATE_KMS and actions:
                yield address, document, actions


@pytest.mark.parametrize("name, factory", CASES)
def test_roles_decifram_o_estado_com_bucket_key_pelo_contexto_do_arn_do_bucket(native, name, factory):
    resources, _ = render(native, factory(), "bucket-key-" + name)
    found = list(state_statements(resources))
    assert found
    context = VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": STATE_BUCKET}
    for address, document, actions in found:
        for action in actions:
            assert allowed(document, action, STATE_KMS, context), (address, action)
            assert not allowed(document, action, STATE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": OTHER_BUCKET}), (address, action)
            assert not allowed(document, action, STATE_KMS, VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": EVIDENCE_BUCKET}), (address, action)
            assert not allowed(document, action, STATE_KMS, {"kms:ViaService": "ec2.us-east-2.amazonaws.com",
                                                             "kms:EncryptionContext:aws:s3:arn": STATE_BUCKET}), (address, action)


@pytest.mark.parametrize("name, factory", CASES)
def test_roles_nao_ganham_o_contexto_do_bucket_na_chave_de_evidencia_sem_bucket_key(native, name, factory):
    resources, _ = render(native, factory(), "evidence-no-bucket-key-" + name)
    evidence_kms = variables()["github_delivery"]["evidence_kms_arn"]
    context = VIA_S3 | {"kms:EncryptionContext:aws:s3:arn": EVIDENCE_BUCKET}
    for address, values in resources.items():
        if isinstance(values.get("policy"), str) and values["policy"].startswith("{"):
            document = json.loads(values["policy"])
            for action in ("kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"):
                assert not allowed(document, action, evidence_kms, context), (address, action)
