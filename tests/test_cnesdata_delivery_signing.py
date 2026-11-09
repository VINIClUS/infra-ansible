"""EXT2 offline signing behavior. Synthetic adapters never stand in for production authority."""

import base64
import copy
from datetime import datetime, timezone
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import shutil
import os
import sys
import subprocess
import io
import zipfile
from types import SimpleNamespace

import pytest

from fixtures.cnesdata_delivery_ext2 import (
    ACCOUNT,
    KEY,
    KEYS,
    PIN,
    REPOSITORY,
    SIGNING_KEY,
    SOURCE,
    S3,
    canonical,
    sha,
    transport_case,
)


@pytest.fixture(scope="module")
def crypto(tmp_path_factory):
    directory = tmp_path_factory.mktemp("ext2-synthetic-ephemeral-key")
    executable = shutil.which("openssl")
    assert executable, "OpenSSL required, no skip/fallback"
    key = directory / "synthetic-private.pem"
    subprocess.run(
        [
            executable,
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            str(key),
        ],
        check=True,
        capture_output=True,
    )
    key.chmod(0o600)
    public = subprocess.run(
        [executable, "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    return {
        "path": executable,
        "sha256": sha(Path(executable).read_bytes()),
        "private": key,
        "public": public,
        "directory": directory,
    }


class KMS:
    def __init__(self, crypto):
        self.crypto = crypto
        self.calls = []
        self.error = None
        self.double_hash = False
        self.policy = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "synthetic-offline"}],
        }
        self.metadata = {
            "Arn": SIGNING_KEY,
            "KeyId": SIGNING_KEY.rsplit("/", 1)[1],
            "Enabled": True,
            "KeyState": "Enabled",
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "ECC_NIST_P256",
            "Origin": "AWS_KMS",
            "MultiRegion": False,
        }
        self.meta = SimpleNamespace(
            config=SimpleNamespace(retries={"total_max_attempts": 1})
        )

    def describe_key(self, **kwargs):
        self.calls.append(("describe", kwargs))
        return {"KeyMetadata": self.metadata.copy()}

    def get_public_key(self, **kwargs):
        self.calls.append(("public", kwargs))
        return {
            "KeyId": SIGNING_KEY,
            "PublicKey": self.crypto["public"],
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "ECC_NIST_P256",
            "SigningAlgorithms": ["ECDSA_SHA_256"],
        }

    def get_key_policy(self, **kwargs):
        self.calls.append(("policy", kwargs))
        return {"Policy": json.dumps(self.policy)}

    def sign(self, **kwargs):
        self.calls.append(("sign", kwargs))
        if self.error:
            raise self.error
        digest = kwargs["Message"]
        if self.double_hash:
            digest = hashlib.sha256(digest).digest()
        path = self.crypto["directory"] / "digest.bin"
        path.write_bytes(digest)
        signature = subprocess.run(
            [
                self.crypto["path"],
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.crypto["private"]),
                "-pkeyopt",
                "digest:sha256",
                "-in",
                str(path),
            ],
            check=True,
            capture_output=True,
        ).stdout
        return {
            "KeyId": SIGNING_KEY,
            "Signature": signature,
            "SigningAlgorithm": "ECDSA_SHA_256",
        }


class FixtureConsumer:
    """Synthetic future #470 schema and admission fixture, not installed by runtime."""

    def __init__(self, candidate, phase_a, fields):
        self.candidate, self.phase_a, self.fields = candidate, phase_a, fields
        self.calls = []

    def admit(self, payload, *, github, governance, now, historical=False):
        self.calls.append(historical)
        assert github is not None
        if payload != canonical(self.fields):
            raise ValueError("fixture schema/binding mismatch")
        if self.phase_a is None:
            raise ValueError("fixture missing Phase A")
        return {
            "candidate_bytes": self.candidate,
            "phase_a_bytes": self.phase_a,
            "activation_fields": self.fields.copy(),
        }


def signing_case(crypto):
    gov, _, api, _ = transport_case()
    candidate = canonical(
        {
            "repository": REPOSITORY,
            "release_id": "synthetic-release",
            "source_sha": SOURCE,
            "fixture_only": True,
        }
    )
    binding_input = {
        "repository": REPOSITORY,
        "release_id": "synthetic-release",
        "source_sha": SOURCE,
        "candidate_sha256": sha(candidate),
    }
    binding = sha(b"cnesdata:prod:canary:v1\0" + canonical(binding_input).rstrip(b"\n"))
    revisions = {
        mode: f"arn:aws:ecs:us-east-2:{ACCOUNT}:task-definition/synthetic-{mode}:3"
        for mode in ("unit", "recovery", "audit")
    }
    phase_a = canonical(
        {
            "fixture_only": True,
            "source_sha": SOURCE,
            "binding_sha256": binding,
            "revisions": revisions,
            "proof_kind": "iam-readback-and-evaluation",
        }
    )
    fields = {
        "project": "cnesdata",
        "environment": "prod",
        "schema_version": 1,
        **binding_input,
        "binding_sha256": binding,
        "canary_id": binding[:32],
        "derivation": "cnesdata:prod:canary:v1",
        "revisions": revisions,
        "ecr_uri": f"{ACCOUNT}.dkr.ecr.us-east-2.amazonaws.com/cnesdata@sha256:"
        + "d" * 64,
        "phase_a_evidence_digest": sha(phase_a),
    }
    adapter = FixtureConsumer(candidate, phase_a, fields)
    kms = KMS(crypto)
    gov.update(
        {
            "activation_enabled": True,
            "invocation": {"run_id": "123", "run_attempt": "1", "source_sha": SOURCE},
            "authorization": {
                "run_id": "123",
                "run_attempt": "1",
                "source_sha": SOURCE,
                "release_id": fields["release_id"],
                "candidate_sha256": sha(candidate),
                "expires_at": "2029-01-01T00:00:00Z",
                "frozen": False,
            },
            "signing": {
                "key_arn": SIGNING_KEY,
                "spki_sha256": sha(crypto["public"]),
                "key_policy_sha256": sha(canonical(kms.policy)),
            },
            "crypto": {
                "openssl_path": crypto["path"],
                "openssl_sha256": crypto["sha256"],
            },
            "principal_sha256": "f" * 64,
        }
    )
    return gov, api, kms, S3(), adapter, canonical(fields)


@pytest.fixture
def gate():
    from tools.cnesdata_delivery import signing_gate

    return signing_gate


def sign(gate, case):
    gov, api, kms, s3, adapter, payload = case
    return gate.sign_activation(
        payload,
        phase_a=adapter,
        github=api,
        kms=kms,
        s3=s3,
        governance=gov,
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )


def test_phase_a_precedes_the_only_sign(gate, crypto):
    case = signing_case(crypto)
    result = sign(gate, case)
    gov, _, kms, s3, adapter, payload = case
    calls = [args for op, args in kms.calls if op == "sign"]
    assert calls == [
        {
            "KeyId": SIGNING_KEY,
            "Message": hashlib.sha256(payload).digest(),
            "MessageType": "DIGEST",
            "SigningAlgorithm": "ECDSA_SHA_256",
        }
    ]
    assert adapter.calls == [False]
    assert result.payload.body == payload
    assert result.receipt.version_id == "3"
    assert json.loads(result.receipt.body)["activation"][
        "phase_a_evidence_digest"
    ] == sha(adapter.phase_a)
    assert [args["Key"] for op, args in s3.calls if op == "put"] == KEYS
    assert result.member_bytes == canonical(
        {
            "receipt_version_id": "3",
            "receipt_sha256": sha(result.receipt.body),
            "receipt_size": len(result.receipt.body),
        }
    )
    assert b"bucket" not in result.member_bytes and b"arn:" not in result.member_bytes
    assert result.signature.body not in result.member_bytes
    assert "GenerateDataKey" not in gate.session_policy(gov, historical=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_sha", "e" * 40),
        ("candidate_sha256", "e" * 64),
        ("phase_a_evidence_digest", "e" * 64),
        ("binding_sha256", "e" * 64),
        ("canary_id", "e" * 32),
        ("environment", "dev"),
        ("project", "other"),
        ("release_id", "other"),
        ("revisions", {"unit": "mutable:latest"}),
        ("ecr_uri", "other@sha256:" + "d" * 64),
    ],
)
def test_mixed_binding_cannot_reach_sign(gate, crypto, field, value):
    case = signing_case(crypto)
    case[4].fields[field] = value
    altered = case[:-1] + (canonical(case[4].fields),)
    with pytest.raises(ValueError):
        sign(gate, altered)
    assert not any(op == "sign" for op, _ in case[2].calls)


def test_missing_phase_a_or_unintegrated_consumer_cannot_sign(gate, crypto):
    case = signing_case(crypto)
    case[4].phase_a = None
    with pytest.raises(ValueError):
        sign(gate, case)
    no_adapter = case[:4] + (None,) + case[5:]
    with pytest.raises(ValueError):
        sign(gate, no_adapter)
    assert not any(op == "sign" for op, _ in case[2].calls)


@pytest.mark.parametrize(
    "mutation",
    [
        "disabled",
        "frozen",
        "expired",
        "past-retention",
        "another-attempt",
        "noncanonical",
        "automatic-retry",
    ],
)
def test_no_resign_after_ambiguous_sign_or_age(gate, crypto, mutation):
    case = signing_case(crypto)
    if mutation == "disabled":
        case[0]["activation_enabled"] = False
    if mutation == "frozen":
        case[0]["authorization"]["frozen"] = True
    if mutation == "expired":
        case[0]["authorization"]["expires_at"] = "2026-01-01T00:00:00Z"
    if mutation == "past-retention":
        case[0]["storage"]["retain_until"] = "2026-01-01T00:00:00Z"
    if mutation == "another-attempt":
        case[0]["authorization"]["run_attempt"] = "2"
    if mutation == "noncanonical":
        case = case[:-1] + (case[-1].rstrip(b"\n"),)
    if mutation == "automatic-retry":
        case[2].meta.config.retries = {"total_max_attempts": 3}
    with pytest.raises(ValueError):
        sign(gate, case)
    assert not any(op == "sign" for op, _ in case[2].calls)


def test_ambiguous_sign_does_not_retry_or_write(gate, crypto):
    case = signing_case(crypto)
    case[2].error = RuntimeError("accepted but timed out; private token detail")
    with pytest.raises(ValueError, match="recovery_required") as error:
        sign(gate, case)
    assert "token" not in str(error.value)
    assert len([x for x in case[2].calls if x[0] == "sign"]) == 1
    assert not case[3].calls


def test_independent_prehash_verifier_rejects_double_hash(gate, crypto):
    case = signing_case(crypto)
    case[2].double_hash = True
    with pytest.raises(ValueError):
        sign(gate, case)
    assert len([x for x in case[2].calls if x[0] == "sign"]) == 1
    assert not case[3].calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("Enabled", False),
        ("KeyUsage", "ENCRYPT_DECRYPT"),
        ("KeySpec", "RSA_2048"),
        ("Arn", KEY),
        ("MultiRegion", True),
    ],
)
def test_signing_key_identity_and_capabilities_are_read_back(
    gate, crypto, field, value
):
    case = signing_case(crypto)
    case[2].metadata[field] = value
    with pytest.raises(ValueError):
        sign(gate, case)
    assert not any(op == "sign" for op, _ in case[2].calls)


def test_publish_reference_only_after_all_readbacks(gate, crypto):
    case = signing_case(crypto)
    case[3].head_mutation["BucketKeyEnabled"] = True
    with pytest.raises(ValueError):
        sign(gate, case)
    assert not any(args["Key"] == KEYS[2] for op, args in case[3].calls if op == "put")


def test_repeated_in_process_authorization_cannot_sign_twice(gate, crypto):
    case = signing_case(crypto)
    sign(gate, case)
    with pytest.raises(ValueError, match="recovery_required"):
        sign(gate, case)
    assert len([x for x in case[2].calls if x[0] == "sign"]) == 1


def published_case(gate, crypto):
    case = signing_case(crypto)
    produced = sign(gate, case)
    gov, api, kms, s3, adapter, payload = case
    _, ref, _, _ = transport_case()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("receipt-ref.json", produced.member_bytes)
    archive = buffer.getvalue()
    ref["artifact_digest"] = "sha256:" + sha(archive)
    path = f"repos/{REPOSITORY}/actions/artifacts/456"
    api.responses[path]["digest"] = ref["artifact_digest"]
    api.responses[path]["size_in_bytes"] = len(archive)
    api.responses[path + "/zip"] = archive
    api.responses[f"repos/{REPOSITORY}/actions/jobs/789/steps/2/logs"] = (
        b"EXT2_ARTIFACT_COMMIT_V1 "
        + canonical(
            {
                "artifact_id": "456",
                "artifact_digest": ref["artifact_digest"],
                "receipt_ref_sha256": sha(produced.member_bytes),
            }
        )
    )
    api.responses[f"repos/{REPOSITORY}/actions/runs/123/attempts/1"].update(
        status="completed", conclusion="success"
    )
    gov["provenance"]["accepted_history"] = [ref.copy()]
    gov["_consumer_adapter"] = adapter
    gov["_signing_spki_der"] = crypto["public"]
    gov["authorization"]["frozen"] = True
    kms.calls.clear()
    s3.calls.clear()
    return case, ref, produced


def test_retained_activation_reads_original_versions_without_resign_or_refresh(
    gate, crypto
):
    case, reference, produced = published_case(gate, crypto)
    gov, api, kms, s3, adapter, payload = case
    result = gate.read_retained_activation(
        reference,
        github=api,
        s3=s3,
        governance=gov,
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    assert (
        result.payload_bytes == payload
        and result.signature_der == produced.signature.body
    )
    assert result.receipt_bytes == produced.receipt.body
    assert result.signing_spki_der == crypto["public"]
    assert result.authenticated_reference == reference
    assert adapter.calls == [False, True]
    assert not kms.calls and not any(op == "put" for op, _ in s3.calls)
    assert {args["VersionId"] for op, args in s3.calls if op == "head"} == {
        "1",
        "2",
        "3",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "receipt",
        "payload",
        "signature",
        "spki",
        "issuer",
        "expired-admission",
        "missing-api",
    ],
)
def test_retained_evidence_or_current_authorization_cannot_be_replaced(
    gate, crypto, mutation
):
    case, reference, _ = published_case(gate, crypto)
    gov, api, kms, s3, _, _ = case
    if mutation in {"receipt", "payload", "signature"}:
        index = {"payload": 0, "signature": 1, "receipt": 2}[mutation]
        s3.objects[(KEYS[index], str(index + 1))] += b"altered"
    if mutation == "spki":
        gov["_signing_spki_der"] = b"wrong"
    if mutation == "issuer":
        gov["provenance"]["workflow_sha"] = "f" * 40
    if mutation == "expired-admission":
        gov["authorization"]["expires_at"] = "2026-01-01T00:00:00Z"
    if mutation == "missing-api":
        api.responses[f"repos/{REPOSITORY}/actions/jobs/789/steps/2/logs"] = (
            RuntimeError("404")
        )
    with pytest.raises(ValueError):
        gate.read_retained_activation(
            reference,
            github=api,
            s3=s3,
            governance=gov,
            now=datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
    assert not kms.calls and not any(op == "put" for op, _ in s3.calls)


def test_current_and_historical_session_permissions_fit_without_widening(gate, crypto):
    gov = signing_case(crypto)[0]
    current = json.loads(gate.session_policy(gov, historical=False))
    historical = json.loads(gate.session_policy(gov, historical=True))
    current_actions = {a for s in current["Statement"] for a in s["Action"]}
    history_actions = {a for s in historical["Statement"] for a in s["Action"]}
    assert "kms:Sign" in current_actions and "kms:GenerateDataKey" in current_actions
    assert (
        not {"kms:Sign", "s3:PutObject", "s3:PutObjectRetention", "kms:GenerateDataKey"}
        & history_actions
    )
    for document in (current, historical):
        for statement in document["Statement"]:
            resources = (
                statement["Resource"]
                if isinstance(statement["Resource"], list)
                else [statement["Resource"]]
            )
            assert all("*" not in r and "opentofu.tfstate" not in r for r in resources)
    huge = copy.deepcopy(gov)
    huge["storage"]["current_keys"] = [
        k.replace("ext2/current", "x" * 700 + "/current") for k in KEYS
    ]
    huge["storage"]["current_prefix"] = huge["storage"]["current_keys"][0].split(
        SOURCE
    )[0]
    with pytest.raises(ValueError, match="capacity"):
        gate.session_policy(huge, historical=False)


class STS:
    def __init__(self, now):
        self.now = now
        self.calls = []
        self.error = None

    def assume_role_with_web_identity(self, **parameters):
        self.calls.append(parameters)
        if self.error:
            raise self.error
        return {
            "PackedPolicySize": 43,
            "AssumedRoleUser": {
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/cnesdata-delivery-ext2-gate/"
                + parameters["RoleSessionName"]
            },
            "Credentials": {
                "AccessKeyId": "synthetic-id",
                "SecretAccessKey": "synthetic-secret",
                "SessionToken": "synthetic-session",
                "Expiration": self.now + timedelta(seconds=900),
            },
        }


@pytest.mark.parametrize("historical", [False, True])
def test_single_owned_role_uses_exact_inline_session_and_temporary_credentials(
    gate, crypto, historical
):
    gov = signing_case(crypto)[0]
    gov["session_duration_seconds"] = 900
    now = datetime(2027, 1, 1, tzinfo=timezone.utc)
    sts = STS(now)
    result = gate.authorize_session(
        governance=gov, sts=sts, token="synthetic-oidc", historical=historical, now=now
    )
    assert len(sts.calls) == 1
    parameters = sts.calls[0]
    assert (
        parameters["RoleArn"]
        == f"arn:aws:iam::{ACCOUNT}:role/cnesdata-delivery-ext2-gate"
    )
    assert (
        parameters["DurationSeconds"] == 900
        and parameters["WebIdentityToken"] == "synthetic-oidc"
    )
    assert "PolicyArns" not in parameters
    assert json.loads(parameters["Policy"]) == json.loads(
        gate.session_policy(gov, historical=historical)
    )
    if historical:
        assert (
            "GenerateDataKey" not in parameters["Policy"]
            and "kms:Sign" not in parameters["Policy"]
        )
    assert result["AccessKeyId"] == "synthetic-id"


def test_sts_capacity_failure_cannot_export_or_fall_back(gate, crypto, capsys):
    gov = signing_case(crypto)[0]
    gov["session_duration_seconds"] = 900
    now = datetime(2027, 1, 1, tzinfo=timezone.utc)
    sts = STS(now)
    sts.error = RuntimeError("PackedPolicyTooLarge private credentials")
    with pytest.raises(ValueError):
        gate.authorize_session(
            governance=gov, sts=sts, token="private-token", historical=False, now=now
        )
    assert len(sts.calls) == 1 and capsys.readouterr().out == ""


def test_publisher_record_uses_real_uploader_outputs_and_api_job_identity(gate):
    gov, ref, api, member = transport_case()
    gov["invocation"] = {"run_id": "123", "run_attempt": "1", "source_sha": SOURCE}
    reference, record = gate.publisher_reference(
        member,
        artifact_id="456",
        artifact_digest=ref["artifact_digest"],
        github=api,
        governance=gov,
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    assert reference == ref
    assert (
        record
        == "EXT2_ARTIFACT_COMMIT_V1 "
        + canonical(
            {
                "artifact_id": "456",
                "artifact_digest": ref["artifact_digest"],
                "receipt_ref_sha256": sha(member),
            }
        )
        .decode()
        .strip()
    )
    assert "arn:" not in record and "synthetic-ext2-evidence" not in record


def test_workflow_pins_custom_sub_and_publisher_closure():
    import yaml

    path = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/reusable-cnesdata-signing-gate.yml"
    )
    assert path.is_file(), "ratified reusable is not implemented"
    workflow = yaml.safe_load(path.read_text())
    assert set(workflow["on"]) == {"workflow_call"} and workflow["permissions"] == {}
    jobs = workflow["jobs"]
    assert set(jobs) == {"validate-no-creds", "sign-store-publish", "verify-handoff"}
    assert "id-token" not in jobs["validate-no-creds"]["permissions"]
    assert jobs["sign-store-publish"]["permissions"]["id-token"] == "write"
    assert jobs["verify-handoff"]["permissions"]["id-token"] == "write"
    assert jobs["verify-handoff"]["needs"] == [
        "validate-no-creds",
        "sign-store-publish",
    ]
    steps = jobs["sign-store-publish"]["steps"]
    upload = [
        step
        for step in steps
        if step.get("uses", "").startswith("actions/upload-artifact@")
    ]
    assert len(upload) == 1 and upload[0]["uses"].endswith(
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    )
    assert upload[0]["with"]["overwrite"] is False
    assert upload[0]["with"]["path"] == ".ext2-public/receipt-ref.json"
    publisher = [
        step for step in steps if step.get("name") == "Commit EXT2 artifact reference"
    ]
    assert len(publisher) == 1 and "publish-commit" in publisher[0]["run"]
    assert steps.index(upload[0]) < steps.index(publisher[0])
    for job in jobs.values():
        assert job["runs-on"] == "ubuntu-latest" and job["environment"] == "production"
        assert any("PYBOOT" in step.get("run", "") for step in job["steps"])
    assert set(workflow["on"]["workflow_call"]["outputs"]) == {
        "ext2_post_upload_receipt_v1"
    }


@pytest.mark.parametrize("mode", ["approved", "tampered", "stale_bytecode"])
def test_consumer_loader_executes_only_verified_source_bytes(
    gate, tmp_path, monkeypatch, mode
):
    import py_compile

    gov, _, api, _ = transport_case()
    sources = {
        "release/activation.schema.json": b'{"type":"object"}',
        "release/verify_activation.py": b"def admit_ext2(*a, **kw): return {}\n",
        "release/build_activation.py": (
            b"def prepare_ext2(*a, **kw): return b'GOOD'\n"
            b"def render_ext2(*a, **kw): return {}\n"
        ),
    }
    gov["consumer"] = {
        "repository": REPOSITORY,
        "source_sha": SOURCE,
        "files": [{"path": p, "sha256": sha(raw)} for p, raw in sources.items()],
    }
    for path, raw in sources.items():
        api.responses[f"repos/{REPOSITORY}/contents/{path}?ref={SOURCE}"] = {
            "type": "file",
            "path": path,
            "encoding": "base64",
            "size": len(raw),
            "content": base64.b64encode(raw).decode(),
            "sha": hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw
            ).hexdigest(),
        }
    monkeypatch.chdir(tmp_path)
    if mode == "tampered":
        gov["consumer"]["files"][1]["sha256"] = "f" * 64
        with pytest.raises(ValueError, match="consumer_bytes"):
            gate._load_consumer(gov, {}, api)
        return
    if mode == "stale_bytecode":
        target = tmp_path / ".ext2-private/consumer/release/build_activation.py"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            sources["release/build_activation.py"].replace(b"GOOD", b"EVIL")
        )
        stamp = 1700000000
        os.utime(target, (stamp, stamp))
        py_compile.compile(str(target), doraise=True)
        write = Path.write_bytes

        def preserve_mtime(path, raw):
            result = write(path, raw)
            if path == target:
                os.utime(path, (stamp, stamp))
            return result

        monkeypatch.setattr(Path, "write_bytes", preserve_mtime)
    consumer = gate._load_consumer(gov, {}, api)
    assert (
        consumer.prepare(api, gov, datetime(2027, 1, 1, tzinfo=timezone.utc)) == b"GOOD"
    )


def test_current_authorization_is_checked_again_after_slow_readbacks(gate, crypto):
    case = signing_case(crypto)
    observations = iter(
        [
            datetime(2027, 1, 1, tzinfo=timezone.utc),
            datetime(2030, 1, 1, tzinfo=timezone.utc),
        ]
    )
    case[0]["_clock"] = lambda: next(observations)
    with pytest.raises(ValueError):
        sign(gate, case)
    assert not any(op == "sign" for op, _ in case[2].calls)


def test_private_request_is_data_only_and_hash_source_mode_bound(gate):
    _, ref, _, _ = transport_case()
    request = {
        "request_version": 1,
        "mode": "historical",
        "source_sha": SOURCE,
        "inputs": None,
        "ext2_post_upload_receipt_v1": ref,
    }
    raw = canonical(request)
    assert (
        gate.decode_request(raw, digest=sha(raw), source_sha=SOURCE, mode="historical")
        == request
    )
    for changed in [
        request | {"script": "caller.py"},
        request | {"source_sha": "f" * 40},
        request | {"mode": "activation"},
    ]:
        body = canonical(changed)
        with pytest.raises(ValueError):
            gate.decode_request(
                body, digest=sha(body), source_sha=SOURCE, mode="historical"
            )
    with pytest.raises(ValueError):
        gate.decode_request(raw, digest="f" * 64, source_sha=SOURCE, mode="historical")


def test_cli_without_authentic_protected_governance_fails_before_sdk(gate, tmp_path):
    env = {
        "PATH": os.defpath,
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "CNESDATA_DELIVERY_GOVERNANCE": "private-invalid-owner-fact",
    }
    result = subprocess.run(
        [sys.executable, "-m", "tools.cnesdata_delivery.signing_gate", "preflight"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0 and result.stdout == ""
    assert "Traceback" not in result.stderr and "private-invalid" not in result.stderr


@pytest.mark.parametrize("tampered", [False, True])
def test_actual_workflow_bootstrap_fetches_only_api_pinned_helper_bytes(
    tmp_path, monkeypatch, tampered
):
    import urllib.request
    import urllib.parse
    import yaml

    path = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/reusable-cnesdata-signing-gate.yml"
    )
    assert path.is_file(), "bootstrap workflow is not implemented"
    workflow = yaml.safe_load(path.read_text())
    steps = workflow["jobs"]["validate-no-creds"]["steps"]
    script = next(step["run"] for step in steps if "PYBOOT" in step.get("run", ""))
    source = script.split("<<'PYBOOT'\n", 1)[1].rsplit("\nPYBOOT", 1)[0]
    gov, _, api, _ = transport_case()
    gov["activation_enabled"] = True
    env = {
        "CNESDATA_DELIVERY_GOVERNANCE": canonical({"ext2": gov}).decode(),
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/develop",
        "GITHUB_SHA": SOURCE,
        "EXPECTED_SOURCE_SHA": SOURCE,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_TOKEN": "fixture-token",
    }
    if tampered:
        p = f"repos/VINIClUS/infra-ansible/contents/tools/cnesdata_delivery/evidence.py?ref={PIN}"
        api.responses[p]["content"] = base64.b64encode(b"unapproved source").decode()
    calls = []

    def urlopen(request, timeout):
        calls.append(request.full_url)
        parsed = urllib.parse.urlsplit(request.full_url)
        assert (
            parsed.scheme == "https"
            and parsed.netloc == "api.github.com"
            and timeout == 20
        )
        key = parsed.path.lstrip("/") + ("?" + parsed.query if parsed.query else "")
        return io.BytesIO(json.dumps(api.responses[key]).encode())

    opened = []

    def build_opener(*handlers):
        assert len(handlers) == 1
        assert (
            handlers[0].redirect_request(
                None, None, 302, "redirect", {}, "https://evil.invalid"
            )
            is None
        )
        opened.append(True)
        return SimpleNamespace(open=urlopen)

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.chdir(tmp_path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    if tampered:
        with pytest.raises((ValueError, AssertionError)):
            exec(compile(source, "ratified-workflow-bootstrap", "exec"), {})
        assert not (tmp_path / "tools/cnesdata_delivery/evidence.py").exists()
    else:
        exec(compile(source, "ratified-workflow-bootstrap", "exec"), {})
        assert (tmp_path / "tools/cnesdata_delivery/evidence.py").is_file()
        assert len(list(tmp_path.glob("tools/cnesdata_delivery/*"))) == 5
    assert opened, (
        "source bootstrap must refuse metadata redirects before code is trusted"
    )
    assert all("@main" not in url and "private-token" not in url for url in calls)
