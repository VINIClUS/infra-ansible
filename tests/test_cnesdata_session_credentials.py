"""Actual credentials/admission path; only original HTTP/SDK/process boundaries are faked."""

import urllib.request

import pytest

from fixtures.cnesdata_delivery_chain import Chain
from tools.cnesdata_delivery import runtime
from test_cnesdata_session_owner import original_owner


@pytest.mark.parametrize("self_asserted", [False, True])
def test_handoff_ausente_ou_autodeclarado_por_consumidor_bloqueia_antes_do_oidc(
    monkeypatch, tmp_path, self_asserted
):
    chain = Chain(monkeypatch, tmp_path)
    if self_asserted:
        gov = original_owner()[0]
        consumer = {
            "repository": "VINIClUS/infra-ansible",
            "workflow_path": ".github/workflows/reusable-cnesdata-infra-plan-gate.yml",
            "workflow_sha": "b" * 40,
        }
        chain.gov["roles"] = gov["roles"]
        chain.gov["session_policy_pins"] = gov["session_policy_pins"]
        chain.gov["session_policy_pins"]["plan"]["owner_producer"] = consumer
        chain.gov["proof_producers"] = [consumer]
        chain.run(
            consumer["repository"],
            100,
            consumer["workflow_path"],
            source=consumer["workflow_sha"],
        )
        chain.configure("plan", 1)
    requests = []

    def oidc(*args, **kwargs):
        requests.append(args)
        return chain.oidc(*args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", oidc)
    with pytest.raises(ValueError, match="original owner|independent original owner"):
        runtime.credentials("plan")
    assert not requests and not hasattr(chain, "sts_request")
    assert not (tmp_path / "credentials.env").exists()


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"PackedPolicySize": True},
        {"PackedPolicySize": 101},
        {"PackedPolicySize": -1},
        {"PackedPolicySize": 1, "SessionTokenUtilization": 101},
    ],
)
def test_utilizacao_packed_invalida_nao_e_aceita_como_prova(response):
    from tools.cnesdata_delivery.session_policy import validate_response

    with pytest.raises(ValueError):
        validate_response(response)


def test_sessao_sts_tem_arn_proprio_e_tres_readbacks_antes_do_export(
    monkeypatch, tmp_path
):
    from fixtures.cnesdata_session_chain import OwnerChain
    from tools.cnesdata_delivery.session_policy import managed_arn

    chain = OwnerChain(monkeypatch, tmp_path)
    import boto3

    sessions = []
    factory = boto3.Session

    def session(**arguments):
        sessions.append(arguments)
        assert not (tmp_path / "credentials.env").exists()
        return factory(**arguments)

    monkeypatch.setattr(boto3, "Session", session)
    runtime.credentials("plan")
    assert chain.sts_request["PolicyArns"] == [{"arn": managed_arn(chain.gov, "plan")}]
    assert (
        len(chain.sts_request["Policy"])
        + len(chain.sts_request["PolicyArns"][0]["arn"])
        <= 2048
    )
    assert chain.owner_calls == ["get_policy", "get_policy_version", "get_policy"]
    assert sessions[0]["aws_access_key_id"] == "offline-access"
    assert sessions[0]["aws_session_token"] == "offline-session"
    assert (tmp_path / "credentials.env").is_file()


@pytest.mark.parametrize(
    "failure",
    [
        "packed-error",
        "packed-size",
        "attached",
        "default-second",
        "document",
        "denied",
        "wrong-principal",
    ],
)
def test_sts_ou_readback_rejeitado_nunca_exporta_credenciais(
    monkeypatch, tmp_path, failure
):
    from fixtures.cnesdata_session_chain import OwnerChain

    chain = OwnerChain(
        monkeypatch, tmp_path, None if failure.startswith("packed") else failure
    )
    if failure == "packed-error":
        chain.sts_failure = ValueError("PackedPolicyTooLarge")
    if failure == "packed-size":
        chain.packed_size = 101
    with pytest.raises(ValueError):
        runtime.credentials("plan")
    assert hasattr(chain, "sts_request")
    if failure.startswith("packed") or failure == "wrong-principal":
        assert not chain.owner_calls
    else:
        assert chain.owner_calls and chain.owner_calls[0] == "get_policy"
    assert not (tmp_path / "credentials.env").exists()


def test_put_object_do_sdk_mantem_contexto_de_objeto_sem_bucket_key(
    monkeypatch, tmp_path
):
    from fixtures.cnesdata_session_chain import OwnerChain
    from tools.cnesdata_delivery.aws_boundary import AWS

    chain = OwnerChain(monkeypatch, tmp_path)
    operations = []
    sdk = chain.sdk

    def request(service, operation, arguments):
        operations.append((service, operation, arguments))
        return sdk(service, operation, arguments)

    monkeypatch.setattr(chain, "sdk", request)
    AWS(runtime.configuration("plan")).put(
        chain.gov["evidence_bucket"], "synthetic-sdk-request", b"bounded bytes"
    )
    parameters = next(
        arguments
        for service, operation, arguments in operations
        if operation == "put_object"
    )
    assert parameters["BucketKeyEnabled"] is False
    assert parameters["ServerSideEncryption"] == "aws:kms"
