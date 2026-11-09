"""EXT2 one-signature boundary. Consumer schema remains owned by CnesData#470."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import hashlib
import base64
import copy
import importlib
import importlib.util
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import sys
from typing import Any, cast

from tools.cnesdata_delivery import evidence as e
from tools.cnesdata_delivery import ext2_transport as t

FIELDS = frozenset(
    "project environment schema_version repository release_id source_sha candidate_sha256 "
    "binding_sha256 canary_id derivation revisions ecr_uri phase_a_evidence_digest".split()
)


def _authorization(
    governance: dict[str, Any],
    fields: dict[str, Any],
    now: datetime,
    *,
    historical: bool = False,
) -> None:
    if "_clock" in governance:
        e.require(callable(governance["_clock"]), "runtime_clock")
        now = governance["_clock"]()
    e.require(governance.get("activation_enabled") is True, "gate_disabled")
    auth = t.closed(
        governance["authorization"],
        {
            "run_id",
            "run_attempt",
            "source_sha",
            "release_id",
            "candidate_sha256",
            "expires_at",
            "frozen",
        },
    )
    invocation = governance["invocation"]
    e.require(
        all(auth[k] == invocation[k] for k in ("run_id", "run_attempt", "source_sha")),
        "authorization_invocation",
    )
    e.require(
        auth["release_id"] == fields["release_id"]
        and auth["candidate_sha256"] == fields["candidate_sha256"]
        and e.date(auth["expires_at"]) > e.date(now),
        "authorization_binding_expiry",
    )
    e.require(
        e.date(governance["storage"]["retain_until"]) > e.date(now), "retention_horizon"
    )
    e.require(
        type(auth["frozen"]) is bool and (historical or auth["frozen"] is False),
        "frozen",
    )


def _admission(
    payload: bytes,
    consumer: Any,
    github: Any,
    governance: dict[str, Any],
    now: datetime,
    *,
    historical: bool = False,
) -> dict[str, Any]:
    # Only runtime's API-pinned consumer module can supply this adapter. No JSON
    # flag, caller path or hash-only receipt can construct production admission.
    t.loads(payload, 262144)
    e.require(
        consumer is not None and callable(getattr(consumer, "admit", None)),
        "consumer_not_integrated",
    )
    try:
        admission = cast(Any, consumer).admit(
            payload,
            github=github,
            governance=governance,
            now=now,
            historical=historical,
        )
    except Exception:
        raise ValueError("ext2=consumer_admission_failed") from None
    t.closed(admission, {"candidate_bytes", "phase_a_bytes", "activation_fields"})
    candidate_bytes, phase_a_bytes = (
        admission["candidate_bytes"],
        admission["phase_a_bytes"],
    )
    candidate_raw = t.loads(candidate_bytes, 262144)
    e.require(type(candidate_raw) is dict, "candidate_shape")
    candidate = cast(dict[str, Any], candidate_raw)
    t.loads(phase_a_bytes, 262144)
    fields = t.closed(admission["activation_fields"], FIELDS)
    e.require(
        fields["project"] == "cnesdata"
        and fields["environment"] == "prod"
        and type(fields["schema_version"]) is int
        and fields["schema_version"] == 1
        and fields["repository"] == t.REPOSITORY
        and fields["derivation"] == "cnesdata:prod:canary:v1",
        "activation_context",
    )
    e.require(
        candidate.get("repository") == t.REPOSITORY
        and candidate.get("source_sha") == governance["provenance"]["source_sha"]
        and type(candidate.get("release_id")) is str
        and 0 < len(candidate["release_id"]) <= 512,
        "candidate_identity",
    )
    binding_input = {
        k: candidate[k] for k in ("repository", "release_id", "source_sha")
    }
    binding_input["candidate_sha256"] = e.sha(candidate_bytes)
    binding = e.sha(b"cnesdata:prod:canary:v1\0" + t.canonical(binding_input)[:-1])
    e.require(
        all(fields[k] == value for k, value in binding_input.items())
        and fields["binding_sha256"] == binding
        and fields["canary_id"] == binding[:32]
        and fields["phase_a_evidence_digest"] == e.sha(phase_a_bytes),
        "activation_binding",
    )
    revisions = t.closed(fields["revisions"], {"unit", "recovery", "audit"})
    account = e.storage_config(governance)["account_id"]
    arn = (
        r"arn:aws:ecs:us-east-2:"
        + account
        + r":task-definition/[A-Za-z0-9_-]{1,255}:[1-9][0-9]{0,9}"
    )
    e.require(
        all(
            type(v) is str and re.fullmatch(arn, v) is not None
            for v in revisions.values()
        )
        and len(set(revisions.values())) == 3,
        "exact_revisions",
    )
    e.require(
        type(fields["ecr_uri"]) is str
        and re.fullmatch(
            account
            + r"\.dkr\.ecr\.us-east-2\.amazonaws\.com/[a-z0-9_./-]+@sha256:[0-9a-f]{64}",
            fields["ecr_uri"],
        )
        is not None,
        "ecr_identity",
    )
    return fields


def _governed_signing_spki(governance: dict[str, Any]) -> bytes:
    config = t.closed(
        governance.get("signing"),
        {"key_arn", "spki_sha256", "key_policy_sha256", "spki_der_b64"},
    )
    account = e.storage_config(governance)["account_id"]
    e.require(
        re.fullmatch(
            r"arn:aws:kms:us-east-2:" + account + r":key/[0-9a-f-]{36}",
            config["key_arn"],
        )
        is not None
        and config["key_arn"] != governance["storage"]["cipher_kms_key_arn"],
        "signing_key_scope",
    )
    encoded = config["spki_der_b64"]
    e.require(type(encoded) is str and len(encoded) == 124, "signing_spki_encoding")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception:
        raise ValueError("ext2=signing_spki_encoding") from None
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    e.require(
        base64.b64encode(raw).decode("ascii") == encoded
        and len(raw) == 91
        and raw.startswith(prefix)
        and e.sha(raw) == t.hex_digest(config["spki_sha256"]),
        "signing_spki_pin",
    )
    t.hex_digest(config["key_policy_sha256"])
    return raw


def read_signing_key(kms: Any, governance: dict[str, Any]) -> bytes:
    governed_spki = _governed_signing_spki(governance)
    config = governance["signing"]
    try:
        metadata = kms.describe_key(KeyId=config["key_arn"])["KeyMetadata"]
        public = kms.get_public_key(KeyId=config["key_arn"])
        policy = kms.get_key_policy(KeyId=config["key_arn"], PolicyName="default")[
            "Policy"
        ]
        import json

        policy_bytes = t.canonical(json.loads(policy))
    except Exception:
        raise ValueError("ext2=key_readback_failed") from None
    expected = {
        "Arn": config["key_arn"],
        "KeyId": config["key_arn"].rsplit("/", 1)[1],
        "Enabled": True,
        "KeyState": "Enabled",
        "KeyUsage": "SIGN_VERIFY",
        "KeySpec": "ECC_NIST_P256",
        "Origin": "AWS_KMS",
        "MultiRegion": False,
    }
    e.require(
        all(
            type(metadata.get(k)) is type(v) and metadata[k] == v
            for k, v in expected.items()
        ),
        "signing_key_metadata",
    )
    e.require(
        public.get("KeyId") == config["key_arn"]
        and public.get("KeyUsage") == "SIGN_VERIFY"
        and public.get("KeySpec") == "ECC_NIST_P256"
        and public.get("SigningAlgorithms") == ["ECDSA_SHA_256"],
        "signing_public_metadata",
    )
    spki = public.get("PublicKey")
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    e.require(
        type(spki) is bytes
        and len(spki) == 91
        and spki.startswith(prefix)
        and spki == governed_spki
        and e.sha(spki) == t.hex_digest(config["spki_sha256"])
        and e.sha(policy_bytes) == t.hex_digest(config["key_policy_sha256"]),
        "signing_key_pins",
    )
    return spki


def verify_signature(
    payload: bytes, signature: bytes, spki: bytes, *, governance: dict[str, Any]
) -> None:
    crypto = t.closed(governance["crypto"], {"openssl_path", "openssl_sha256"})
    executable = Path(crypto["openssl_path"])
    e.require(
        executable.is_absolute()
        and executable.is_file()
        and not executable.is_symlink()
        and os.access(executable, os.X_OK)
        and e.sha(executable.read_bytes()) == t.hex_digest(crypto["openssl_sha256"]),
        "openssl_pin",
    )
    e.require(
        type(signature) is bytes
        and 8 <= len(signature) <= 72
        and signature[0] == 0x30
        and signature[1] == len(signature) - 2,
        "signature_der",
    )
    with tempfile.TemporaryDirectory(prefix="ext2-verify-") as temp:
        root = Path(temp)
        for name, raw in (
            ("spki.der", spki),
            ("signature.der", signature),
            ("digest.bin", hashlib.sha256(payload).digest()),
        ):
            (root / name).write_bytes(raw)
        try:
            result = subprocess.run(
                [
                    str(executable),
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    str(root / "spki.der"),
                    "-sigfile",
                    str(root / "signature.der"),
                    "-pkeyopt",
                    "digest:sha256",
                    "-in",
                    str(root / "digest.bin"),
                ],
                capture_output=True,
                timeout=20,
                check=False,
                env={
                    "PATH": os.defpath,
                    "LANG": "C.UTF-8",
                    "OPENSSL_CONF": "/dev/null",
                },
            )
        except Exception:
            raise ValueError("ext2=signature_verifier_unavailable") from None
    e.require(result.returncode == 0, "signature_invalid")


@dataclass(frozen=True)
class SignedEvidence:
    payload: e.VerifiedObject
    signature: e.VerifiedObject
    receipt: e.VerifiedObject
    signing_spki_der: bytes
    member_bytes: bytes


def session_policy(governance: dict[str, Any], *, historical: bool) -> str:
    storage = e.storage_config(governance)
    objects = [storage["bucket_arn"] + "/" + key for key in storage["current_keys"]]
    objects += [
        value["bucket_arn"] + "/" + value["key"] for value in storage["history_objects"]
    ]
    objects = sorted(set(objects))
    sign_key = governance["signing"]["key_arn"]
    current = [storage["bucket_arn"] + "/" + key for key in storage["current_keys"]]
    object_actions = ["s3:GetObjectVersion", "s3:GetObjectRetention"]
    if not historical:
        object_actions += ["s3:PutObject", "s3:PutObjectRetention"]
    statements: list[dict[str, Any]] = [
        {
            "Effect": "Allow",
            "Action": object_actions,
            "Resource": objects if historical else current,
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketVersioning",
                "s3:GetBucketObjectLockConfiguration",
            ],
            "Resource": storage["bucket_arn"],
        },
        {
            "Effect": "Allow",
            "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:GetKeyPolicy"],
            "Resource": sign_key,
        },
        {
            "Effect": "Allow",
            "Action": ["kms:Decrypt"]
            if historical
            else ["kms:Decrypt", "kms:GenerateDataKey"],
            "Resource": storage["cipher_kms_key_arn"],
            "Condition": {
                "StringEquals": {"kms:ViaService": "s3.us-east-2.amazonaws.com"},
                "StringLike": {"kms:EncryptionContext:aws:s3:arn": objects},
            },
        },
    ]
    if not historical:
        history_only = sorted(set(objects) - set(current))
        if history_only:
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObjectVersion", "s3:GetObjectRetention"],
                    "Resource": history_only,
                }
            )
        statements += [
            {
                "Effect": "Allow",
                "Action": ["kms:Sign"],
                "Resource": sign_key,
                "Condition": {
                    "StringEquals": {
                        "kms:SigningAlgorithm": "ECDSA_SHA_256",
                        "kms:MessageType": "DIGEST",
                    }
                },
            }
        ]
    policy = (
        t.canonical({"Version": "2012-10-17", "Statement": statements})
        .decode()
        .rstrip("\n")
    )
    e.require(len(policy) <= 2048, "session_policy_capacity")
    return policy


def sign_activation(
    payload: bytes,
    *,
    phase_a: Any,
    github: Any,
    kms: Any,
    s3: Any,
    governance: dict[str, Any],
    now: datetime,
) -> SignedEvidence:
    e.require(not governance.get("_mutation_started", False), "recovery_required")
    fields = _admission(payload, phase_a, github, governance, now)
    _authorization(governance, fields, now)
    t.authenticate_invocation(
        github=github,
        governance=governance,
        invocation=governance["invocation"],
        now=now,
    )
    e.require(
        kms.meta.config.retries.get("total_max_attempts") == 1, "sdk_mutating_retries"
    )
    spki = read_signing_key(kms, governance)
    _authorization(governance, fields, now)
    # This process must never repeat an ambiguous mutation. The protected owner
    # authorization fixes one exact run/attempt; rerun requires reviewed recovery.
    governance["_mutation_started"] = True
    try:
        signed = kms.sign(
            KeyId=governance["signing"]["key_arn"],
            Message=hashlib.sha256(payload).digest(),
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
    except Exception:
        raise ValueError("ext2=recovery_required") from None
    e.require(
        signed.get("KeyId") == governance["signing"]["key_arn"]
        and signed.get("SigningAlgorithm") == "ECDSA_SHA_256",
        "signature_response",
    )
    signature = signed.get("Signature")
    verify_signature(payload, signature, spki, governance=governance)
    config = e.storage_config(governance)
    verified: list[e.VerifiedObject] = []
    for raw, key in zip((payload, signature), config["current_keys"][:2]):
        _authorization(governance, fields, now)
        verified.append(e.store_and_verify(raw, key=key, s3=s3, governance=governance))
    invocation, profile = governance["invocation"], governance["provenance"]
    receipt = {
        "receipt_version": 1,
        "kind": "ext2-post-upload-readback",
        "channel": "ext2-gate-private-output-v1",
        "issuer": {
            "repository": t.PRODUCER,
            "workflow_path": t.WORKFLOW,
            "workflow_sha": profile["workflow_sha"],
            "run_id": invocation["run_id"],
            "run_attempt": invocation["run_attempt"],
            "role_session_sha256": t.hex_digest(governance["principal_sha256"]),
        },
        "execution": {
            "repository": t.REPOSITORY,
            "repository_id": profile["repository_id"],
            "owner_id": profile["owner_id"],
            "caller_workflow_path": profile["caller_workflow_path"],
            "caller_source_sha": profile["source_sha"],
        },
        "activation": {
            "payload_sha256": e.sha(payload),
            "signature_der_sha256": e.sha(signature),
            "signing_spki_sha256": e.sha(spki),
            "phase_a_evidence_digest": fields["phase_a_evidence_digest"],
        },
        "object": verified[0].reference(),
        "signature_object": verified[1].reference(),
        "retention": {
            "mode": "COMPLIANCE",
            "retain_until": config["retain_until"],
            "retention_policy_id": config["retention_policy_id"],
        },
        "observed_at": e.date(now).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "result": "success",
    }
    raw_receipt = t.canonical(receipt)
    e.require(len(raw_receipt) <= 65536, "receipt_size")
    _authorization(governance, fields, now)
    result = e.store_and_verify(
        raw_receipt, key=config["current_keys"][2], s3=s3, governance=governance
    )
    member = t.canonical(
        {
            "receipt_version_id": result.version_id,
            "receipt_sha256": result.content_sha256,
            "receipt_size": len(result.body),
        }
    )
    t.decode_member(member)
    return SignedEvidence(verified[0], verified[1], result, spki, member)


@dataclass(frozen=True)
class VerifiedActivation:
    payload_bytes: bytes
    signature_der: bytes
    signing_spki_der: bytes
    receipt_bytes: bytes
    payload_object: e.VerifiedObject
    signature_object: e.VerifiedObject
    receipt_object: e.VerifiedObject
    authenticated_reference: dict[str, Any]


def verify_ext2_reference(
    reference: dict[str, Any],
    *,
    github: Any,
    s3: Any,
    governance: dict[str, Any],
    now: datetime,
    historical: bool,
) -> VerifiedActivation:
    spki = _governed_signing_spki(governance)
    authenticated = t.authenticate_reference(
        reference,
        github=github,
        governance=governance,
        current_invocation=None if historical else governance["invocation"],
        now=now,
    )
    storage, member = e.storage_config(governance), authenticated.receipt_reference
    receipt_ref = {
        "bucket_arn": storage["bucket_arn"],
        "key": storage["current_keys"][2],
        "version_id": member["receipt_version_id"],
        "content_sha256": member["receipt_sha256"],
        "content_length": member["receipt_size"],
        "server_side_encryption": "aws:kms",
        "cipher_kms_key_arn": storage["cipher_kms_key_arn"],
        "bucket_key_enabled": False,
    }
    receipt_object = e.read_version(receipt_ref, s3=s3, governance=governance)
    receipt = t.closed(
        t.loads(receipt_object.body, 65536),
        {
            "receipt_version",
            "kind",
            "channel",
            "issuer",
            "execution",
            "activation",
            "object",
            "signature_object",
            "retention",
            "observed_at",
            "result",
        },
    )
    e.require(
        type(receipt["receipt_version"]) is int
        and receipt["receipt_version"] == 1
        and receipt["kind"] == "ext2-post-upload-readback"
        and receipt["channel"] == "ext2-gate-private-output-v1"
        and receipt["result"] == "success",
        "receipt_context",
    )
    issuer = t.closed(
        receipt["issuer"],
        {
            "repository",
            "workflow_path",
            "workflow_sha",
            "run_id",
            "run_attempt",
            "role_session_sha256",
        },
    )
    expected_issuer = {
        "repository": t.PRODUCER,
        "workflow_path": t.WORKFLOW,
        "workflow_sha": reference["reusable_workflow_sha"],
        "run_id": reference["run_id"],
        "run_attempt": reference["run_attempt"],
    }
    e.require(all(issuer[k] == v for k, v in expected_issuer.items()), "receipt_issuer")
    t.hex_digest(issuer["role_session_sha256"])  # diagnostic only; never authority
    profile = governance["provenance"]
    e.require(
        receipt["execution"]
        == {
            "repository": t.REPOSITORY,
            "repository_id": profile["repository_id"],
            "owner_id": profile["owner_id"],
            "caller_workflow_path": reference["caller_workflow_path"],
            "caller_source_sha": reference["source_sha"],
        },
        "receipt_execution",
    )
    e.require(
        receipt["retention"]
        == {
            "mode": "COMPLIANCE",
            "retain_until": storage["retain_until"],
            "retention_policy_id": storage["retention_policy_id"],
        },
        "receipt_retention",
    )
    e.require(e.date(receipt["observed_at"]) <= e.date(now), "receipt_observation")
    payload = e.read_version(receipt["object"], s3=s3, governance=governance)
    signature = e.read_version(
        receipt["signature_object"], s3=s3, governance=governance
    )
    e.require(
        payload.key == storage["current_keys"][0]
        and signature.key == storage["current_keys"][1],
        "receipt_object_slots",
    )
    if historical:
        # Reconstruct data from authenticated contracted inputs. No prior CLI or
        # Python adapter object is required; the existing consumer closure is
        # fetched and authenticated by exactly the same source loader as the CLI.
        request = {
            "request_version": 1,
            "mode": "historical",
            "inputs": None,
            "source_sha": t.hex_digest(governance["invocation"]["source_sha"], 40),
            "ext2_post_upload_receipt_v1": dict(reference),
        }
        consumer = _load_consumer(governance, request, github)
    else:
        consumer = governance.get("_consumer_adapter")
    fields = _admission(
        payload.body,
        consumer,
        github,
        governance,
        now,
        historical=historical,
    )
    _authorization(governance, fields, now, historical=historical)
    e.require(
        receipt["activation"]
        == {
            "payload_sha256": payload.content_sha256,
            "signature_der_sha256": signature.content_sha256,
            "signing_spki_sha256": e.sha(spki),
            "phase_a_evidence_digest": fields["phase_a_evidence_digest"],
        },
        "receipt_activation_binding",
    )
    verify_signature(payload.body, signature.body, spki, governance=governance)
    return VerifiedActivation(
        payload.body,
        signature.body,
        spki,
        receipt_object.body,
        payload,
        signature,
        receipt_object,
        dict(reference),
    )


def read_retained_activation(
    reference: dict[str, Any],
    *,
    github: Any,
    s3: Any,
    governance: dict[str, Any],
    now: datetime,
) -> VerifiedActivation:
    return verify_ext2_reference(
        reference, github=github, s3=s3, governance=governance, now=now, historical=True
    )


def authorize_session(
    *, governance: dict[str, Any], sts: Any, token: str, historical: bool, now: datetime
) -> dict[str, Any]:
    e.require(governance.get("activation_enabled") is True, "gate_disabled")
    duration = governance.get("session_duration_seconds")
    e.require(type(duration) is int and 900 <= duration <= 3600, "session_duration")
    e.require(type(token) is str and 0 < len(token) <= 16384, "oidc_absent")
    inv = governance["invocation"]
    t.closed(inv, {"run_id", "run_attempt", "source_sha"})
    _authorization(governance, governance["authorization"], now, historical=historical)
    role = (
        "arn:aws:iam::"
        + governance["storage"]["account_id"]
        + ":role/cnesdata-delivery-ext2-gate"
    )
    name = (
        "ext2-"
        + t.positive_id(inv["run_id"])
        + "-"
        + t.positive_id(inv["run_attempt"])
        + "-"
        + t.hex_digest(inv["source_sha"], 40)[:16]
    )
    e.require(len(name) <= 64, "session_name")
    policy = session_policy(governance, historical=historical)
    try:
        response = sts.assume_role_with_web_identity(
            RoleArn=role,
            RoleSessionName=name,
            WebIdentityToken=token,
            DurationSeconds=duration,
            Policy=policy,
        )
        packed = response["PackedPolicySize"]
        credentials = response["Credentials"]
        e.require(type(packed) is int and 0 <= packed <= 100, "session_capacity")
        e.require(
            response["AssumedRoleUser"]["Arn"]
            == "arn:aws:sts::"
            + governance["storage"]["account_id"]
            + ":assumed-role/cnesdata-delivery-ext2-gate/"
            + name,
            "session_principal",
        )
        e.require(
            all(
                type(credentials.get(k)) is str and bool(credentials[k])
                for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")
            )
            and e.date(now)
            < e.date(credentials["Expiration"])
            <= e.date(now) + timedelta(seconds=cast(int, duration)),
            "temporary_credentials",
        )
    except Exception:
        raise ValueError("ext2=session_rejected") from None
    return credentials


def publisher_reference(
    member: bytes,
    *,
    artifact_id: str,
    artifact_digest: str,
    github: Any,
    governance: dict[str, Any],
    now: datetime,
) -> tuple[dict[str, Any], str]:
    t.decode_member(member)
    t.positive_id(artifact_id)
    e.require(artifact_digest.startswith("sha256:"), "publisher_digest")
    t.hex_digest(artifact_digest[7:])
    inv, profile = governance["invocation"], governance["provenance"]
    t.authenticate_invocation(
        github=github, governance=governance, invocation=inv, now=now
    )
    path = f"repos/{t.REPOSITORY}/actions/runs/{inv['run_id']}/attempts/{inv['run_attempt']}"
    jobs: list[dict[str, Any]] = []
    total = None
    for page in range(1, 5):
        response = t._read(github, path + f"/jobs?per_page=100&page={page}")
        count = response.get("total_count")
        e.require(
            type(count) is int
            and 0 < count <= 256
            and (total is None or count == total),
            "publisher_jobs",
        )
        total = count
        rows = response.get("jobs")
        e.require(type(rows) is list and 0 < len(rows) <= 100, "publisher_jobs_page")
        jobs.extend(rows)
        e.require(
            len(jobs) <= count and len({row["id"] for row in jobs}) == len(jobs),
            "publisher_jobs_inventory",
        )
        if len(jobs) == count:
            break
    e.require(len(jobs) == total, "publisher_jobs_incomplete")
    selected = [row for row in jobs if row.get("name") == profile["publisher_job_name"]]
    e.require(len(selected) == 1, "publisher_job_ambiguous")
    job = selected[0]
    e.require(
        job.get("run_id") == int(inv["run_id"])
        and job.get("head_sha") == inv["source_sha"]
        and job.get("status") in {"in_progress", "completed"}
        and job.get("conclusion") in {None, "success"},
        "publisher_job_identity",
    )
    steps = [step for step in job.get("steps", []) if step.get("name") == t.COMMIT_STEP]
    e.require(
        len(steps) == 1 and type(steps[0].get("number")) is int,
        "publisher_step_identity",
    )
    ref = {
        "repository": t.REPOSITORY,
        "run_id": inv["run_id"],
        "run_attempt": inv["run_attempt"],
        "artifact_id": artifact_id,
        "artifact_digest": artifact_digest,
        "publisher_job_id": str(job["id"]),
        "publisher_step_number": steps[0]["number"],
        "source_sha": inv["source_sha"],
        "caller_workflow_path": profile["caller_workflow_path"],
        "reusable_workflow_sha": profile["workflow_sha"],
    }
    t.validate_reference(ref)
    metadata_path = f"repos/{t.REPOSITORY}/actions/artifacts/{artifact_id}"
    metadata = t._read(github, metadata_path)
    origin = metadata.get("workflow_run", {})
    e.require(
        metadata.get("id") == int(artifact_id)
        and metadata.get("expired") is False
        and metadata.get("digest") == artifact_digest
        and e.date(metadata.get("expires_at")) > e.date(now)
        and origin.get("id") == int(inv["run_id"])
        and origin.get("head_sha") == inv["source_sha"]
        and origin.get("repository_id") == profile["repository_id"]
        and origin.get("head_repository_id") == profile["repository_id"],
        "publisher_artifact",
    )
    archive = t._read(github, metadata_path + "/zip", raw=True, maximum=1024**2)
    e.require(
        e.sha(archive) == artifact_digest[7:]
        and metadata.get("size_in_bytes") == len(archive)
        and t.unpack_member(archive) == member,
        "publisher_uploaded_bytes",
    )
    record = t.MARKER + t.canonical(
        {
            "artifact_id": artifact_id,
            "artifact_digest": artifact_digest,
            "receipt_ref_sha256": e.sha(member),
        }
    ).decode().rstrip("\n")
    return ref, record


def decode_request(
    raw: bytes, *, digest: str, source_sha: str, mode: str
) -> dict[str, Any]:
    e.require(e.sha(raw) == t.hex_digest(digest), "request_digest")
    request = t.closed(
        t.loads(raw, 65536),
        {
            "request_version",
            "mode",
            "source_sha",
            "inputs",
            "ext2_post_upload_receipt_v1",
        },
    )
    e.require(
        type(request["request_version"]) is int
        and request["request_version"] == 1
        and mode in {"activation", "historical"}
        and request["mode"] == mode
        and request["source_sha"] == t.hex_digest(source_sha, 40),
        "request_context",
    )
    if mode == "historical":
        e.require(request["inputs"] is None, "historical_request_inputs")
        t.validate_reference(request["ext2_post_upload_receipt_v1"])
    else:
        e.require(
            request["ext2_post_upload_receipt_v1"] is None,
            "activation_request_reference",
        )
        inputs = t.closed(
            request["inputs"],
            {
                "candidate_reference",
                "phase_a_reference",
                "retained_unit_task_definition_arns",
            },
        )
        for ref in (inputs["candidate_reference"], inputs["phase_a_reference"]):
            t.closed(
                ref,
                {
                    "repository",
                    "run_id",
                    "run_attempt",
                    "artifact_id",
                    "artifact_digest",
                    "workflow_path",
                    "workflow_sha",
                    "source_sha",
                },
            )
            e.require(
                ref["repository"] == t.REPOSITORY and ref["source_sha"] == source_sha,
                "input_source",
            )
            for name in ("run_id", "run_attempt", "artifact_id"):
                t.positive_id(ref[name])
            t.hex_digest(ref["workflow_sha"], 40)
            e.require(
                type(ref["artifact_digest"]) is str
                and ref["artifact_digest"].startswith("sha256:"),
                "input_artifact_digest",
            )
            t.hex_digest(ref["artifact_digest"][7:])
            e.require(
                re.fullmatch(
                    r"\.github/workflows/[A-Za-z0-9_-]+\.yml", ref["workflow_path"]
                )
                is not None,
                "input_workflow",
            )
        retained = inputs["retained_unit_task_definition_arns"]
        e.require(
            type(retained) is list
            and len(retained) <= 128
            and all(type(x) is str for x in retained)
            and retained == sorted(set(retained)),
            "retained_inputs",
        )
    return request


def _utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _configuration() -> tuple[dict[str, Any], dict[str, Any], t.GitHubClient]:
    # Reuse the existing protected environment variable. No new secret, public
    # caller-selected role, SDK endpoint, script, backend or session policy input.
    root = t.loads(os.environ.get("CNESDATA_DELIVERY_GOVERNANCE", "").encode(), 65536)
    e.require(
        type(root) is dict and type(root.get("ext2")) is dict,
        "protected_governance_absent",
    )
    gov = cast(dict[str, Any], copy.deepcopy(cast(dict[str, Any], root)["ext2"]))
    allowed = {
        "authority",
        "activation_enabled",
        "storage",
        "provenance",
        "authorization",
        "signing",
        "crypto",
        "consumer",
        "session_duration_seconds",
        "history",
    }
    e.require(
        set(gov) == allowed
        and gov["authority"] == "infra-ansible#29/6727502727"
        and gov["activation_enabled"] is True,
        "protected_governance_contract",
    )
    e.require(
        os.environ.get("GITHUB_REPOSITORY") == t.REPOSITORY
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REF") == "refs/heads/develop",
        "runtime_context",
    )
    source = os.environ.get("EXPECTED_SOURCE_SHA", "")
    e.require(source == os.environ.get("GITHUB_SHA"), "runtime_source")
    invocation = {
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "source_sha": source,
    }
    gov["invocation"] = invocation
    gov["_clock"] = _utc
    request = decode_request(
        os.environ.get("REQUEST_DESCRIPTOR", "").encode(),
        digest=os.environ.get("REQUEST_DESCRIPTOR_SHA256", ""),
        source_sha=source,
        mode=os.environ.get("EXT2_MODE", ""),
    )
    github = t.GitHubClient(os.environ.get("GITHUB_TOKEN", ""))
    t.authenticate_invocation(
        github=github, governance=gov, invocation=invocation, now=_utc()
    )
    e.storage_config(gov)
    _authorization(
        gov, gov["authorization"], _utc(), historical=request["mode"] == "historical"
    )
    _governed_signing_spki(gov)
    return gov, request, github


def _selection(gov: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    if request["mode"] == "activation":
        return gov
    history = gov["history"]
    e.require(type(history) is list and len(history) <= 128, "history_profiles")
    history = cast(list[dict[str, Any]], history)
    selected = [
        row
        for row in history
        if row.get("reference") == request["ext2_post_upload_receipt_v1"]
    ]
    e.require(len(selected) == 1, "history_profile_absent")
    entry = t.closed(
        selected[0],
        {"reference", "storage", "provenance", "signing", "crypto", "consumer"},
    )
    result = copy.deepcopy(gov)
    for key in ("storage", "provenance", "signing", "crypto", "consumer"):
        result[key] = copy.deepcopy(entry[key])
    e.require(
        result["storage"]["account_id"] == gov["storage"]["account_id"]
        and result["storage"]["region"] == gov["storage"]["region"]
        and result["storage"]["bucket_arn"] == gov["storage"]["bucket_arn"],
        "historical_owner_scope",
    )
    e.storage_config(result)
    return result


class _Consumer:
    def __init__(self, verifier: Any, builder: Any, request: dict[str, Any]):
        self.verifier, self.builder, self.request = verifier, builder, request

    def admit(
        self,
        payload: bytes,
        *,
        github: Any,
        governance: dict[str, Any],
        now: datetime,
        historical: bool = False,
    ) -> dict[str, Any]:
        return self.verifier.admit_ext2(
            payload,
            request=self.request,
            github=github,
            governance=governance,
            now=now,
            historical=historical,
        )

    def prepare(self, github: Any, governance: dict[str, Any], now: datetime) -> bytes:
        value = self.builder.prepare_ext2(
            self.request, github=github, governance=governance, now=now
        )
        e.require(type(value) is bytes, "consumer_payload_bytes")
        return value

    def render(
        self, verified: VerifiedActivation, governance: dict[str, Any]
    ) -> dict[str, Any]:
        value = self.builder.render_ext2(
            verified, request=self.request, governance=governance
        )
        t.closed(
            value,
            {
                "processor_active_unit_task_definition_arn",
                "processor_retained_unit_task_definition_arns",
                "scheduler_recovery_task_definition_arn",
                "scheduler_audit_task_definition_arn",
            },
        )
        return value


def _private_root() -> Path:
    path = Path.cwd() / ".ext2-private"
    e.require(not path.is_symlink(), "private_path")
    path.mkdir(mode=0o700, exist_ok=True)
    path.chmod(0o700)
    return path


def _load_consumer(
    gov: dict[str, Any], request: dict[str, Any], github: Any
) -> _Consumer:
    config = t.closed(gov.get("consumer"), {"repository", "source_sha", "files"})
    e.require(
        config["repository"] == t.REPOSITORY
        and config["source_sha"] == gov["provenance"]["source_sha"],
        "consumer_source",
    )
    names = {
        "release/verify_activation.py",
        "release/build_activation.py",
        "release/activation.schema.json",
    }
    raw_entries = config["files"]
    e.require(
        type(raw_entries) is list and len(raw_entries) == 3, "consumer_closure_count"
    )
    entries = cast(list[dict[str, Any]], raw_entries)
    e.require(
        {entry["path"] for entry in entries} == names,
        "consumer_closure",
    )
    root = _private_root() / "consumer"
    e.require(not root.is_symlink(), "consumer_path")
    root.mkdir(mode=0o700, exist_ok=True)
    modules = {}
    for entry in entries:
        t.closed(entry, {"path", "sha256"})
        path = entry["path"]
        item = t._read(
            github,
            f"repos/{t.REPOSITORY}/contents/{path}?ref={config['source_sha']}",
            maximum=2 * 1024**2,
        )
        e.require(
            item.get("type") == "file"
            and item.get("path") == path
            and item.get("encoding") == "base64",
            "consumer_file",
        )
        try:
            raw = base64.b64decode(item["content"].replace("\n", ""), validate=True)
        except Exception:
            raise ValueError("ext2=consumer_encoding") from None
        e.require(
            0 < len(raw) <= 262144
            and len(raw) == item.get("size")
            and e.sha(raw) == t.hex_digest(entry["sha256"])
            and hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw
            ).hexdigest()
            == item.get("sha"),
            "consumer_bytes",
        )
        target = root / path
        target.parent.mkdir(mode=0o700, exist_ok=True)
        e.require(
            not target.parent.is_symlink() and not target.is_symlink(), "consumer_path"
        )
        target.write_bytes(raw)
        target.chmod(0o600)
        if path.endswith(".json"):
            # Consumer-owned schema; no parallel EXT2 activation schema.
            json.loads(raw)
            continue
        name = "ext2_consumer_" + target.stem
        spec = importlib.util.spec_from_file_location(name, target)
        if spec is None or spec.loader is None:
            raise ValueError("ext2=consumer_module")
        module = importlib.util.module_from_spec(spec)
        # Execute the bytes authenticated above, never a timestamp/size-matched pyc.
        exec(compile(raw, str(target), "exec"), module.__dict__)
        modules[target.stem] = module
    verifier, builder = modules["verify_activation"], modules["build_activation"]
    e.require(
        callable(getattr(verifier, "admit_ext2", None))
        and callable(getattr(builder, "prepare_ext2", None))
        and callable(getattr(builder, "render_ext2", None)),
        "consumer_not_integrated",
    )
    return _Consumer(verifier, builder, request)


def _oidc_token() -> str:
    from urllib.parse import urlsplit
    from urllib.request import Request, build_opener

    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    parsed = urlsplit(url)
    e.require(
        parsed.scheme == "https"
        and parsed.username is None
        and parsed.password is None
        and (parsed.hostname or "").endswith(".actions.githubusercontent.com")
        and parsed.port in {None, 443},
        "oidc_endpoint",
    )
    url += ("&" if parsed.query else "?") + "audience=sts.amazonaws.com"
    request = Request(
        url,
        headers={
            "Authorization": "Bearer "
            + os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
        },
    )
    # Unlike the artifact download, OIDC never follows a redirect with credentials.
    with build_opener(t._NoRedirect()).open(request, timeout=20) as response:
        raw = response.read(65537)
    e.require(len(raw) <= 65536, "oidc_response_size")
    value = json.loads(raw)["value"]
    e.require(type(value) is str and bool(value), "oidc_response")
    return value


def _sdk_clients(credentials: dict[str, Any] | None = None) -> dict[str, Any]:
    # Runtime-only checksum-locked dependencies; public unit tests use explicit
    # SDK boundary doubles and never fall back to ambient credentials.
    for package in ("boto3", "botocore"):
        e.require(importlib.metadata.version(package) == "1.40.71", "sdk_version")
    boto3 = importlib.import_module("boto3")
    botocore = importlib.import_module("botocore")
    config_type = importlib.import_module("botocore.config").Config
    kwargs = (
        {}
        if credentials is None
        else {
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretAccessKey"],
            "aws_session_token": credentials["SessionToken"],
        }
    )
    session = boto3.session.Session(region_name="us-east-2", **kwargs)
    result = {}
    for name in ("sts",) if credentials is None else ("s3", "kms", "sts"):
        options = {
            "retries": {"total_max_attempts": 1, "mode": "standard"},
            "connect_timeout": 20,
            "read_timeout": 20,
        }
        if credentials is None:
            options["signature_version"] = botocore.UNSIGNED
        result[name] = session.client(
            name,
            region_name="us-east-2",
            endpoint_url=f"https://{name}.us-east-2.amazonaws.com",
            verify=True,
            config=config_type(**options),
        )
    return result


def _clients(gov: dict[str, Any], historical: bool) -> dict[str, Any]:
    anonymous = _sdk_clients()
    credentials = authorize_session(
        governance=gov,
        sts=anonymous["sts"],
        token=_oidc_token(),
        historical=historical,
        now=_utc(),
    )
    clients = _sdk_clients(credentials)
    identity = clients["sts"].get_caller_identity()
    expected = (
        "arn:aws:sts::"
        + gov["storage"]["account_id"]
        + ":assumed-role/cnesdata-delivery-ext2-gate/"
    )
    e.require(
        identity.get("Account") == gov["storage"]["account_id"]
        and identity.get("Arn", "").startswith(expected),
        "actual_principal",
    )
    gov["principal_sha256"] = e.sha(
        t.canonical({"Account": identity["Account"], "Arn": identity["Arn"]})
    )
    gov["_s3"] = clients["s3"]
    return clients


def _output(reference: dict[str, Any]) -> None:
    raw = t.canonical(t.validate_reference(reference))
    e.require(len(raw) <= 4096, "output_size")
    name = os.environ.get("GITHUB_OUTPUT", "")
    e.require(bool(name), "github_output_absent")
    with Path(name).open("a") as out:
        out.write("ext2_post_upload_receipt_v1=" + raw.decode().rstrip("\n") + "\n")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Protected EXT2 signing and versioned readback"
    )
    parser.add_argument(
        "stage", choices=("preflight", "sign", "publish-commit", "verify")
    )
    args = parser.parse_args()
    try:
        current, request, github = _configuration()
        gov = _selection(current, request)
        if args.stage == "publish-commit":
            e.require(request["mode"] == "activation", "publisher_mode")
            _authorization(gov, gov["authorization"], _utc())
            member = (Path.cwd() / ".ext2-public/receipt-ref.json").read_bytes()
            digest = os.environ.get("EXT2_ARTIFACT_SHA256", "")
            if not digest.startswith("sha256:"):
                digest = "sha256:" + digest
            reference, record = publisher_reference(
                member,
                artifact_id=os.environ.get("EXT2_ARTIFACT_ID", ""),
                artifact_digest=digest,
                github=github,
                governance=gov,
                now=_utc(),
            )
            _output(reference)
            print(record)
            return 0
        consumer = _load_consumer(gov, request, github)
        if request["mode"] == "activation":
            gov["_consumer_adapter"] = consumer
        if args.stage == "preflight":
            return 0
        historical = request["mode"] == "historical"
        e.require(args.stage != "sign" or not historical, "sign_mode")
        clients = _clients(gov, historical=historical or args.stage == "verify")
        if args.stage == "sign":
            payload = consumer.prepare(github, gov, _utc())
            result = sign_activation(
                payload,
                phase_a=consumer,
                github=github,
                kms=clients["kms"],
                s3=clients["s3"],
                governance=gov,
                now=_utc(),
            )
            directory = Path.cwd() / ".ext2-public"
            e.require(not directory.is_symlink(), "member_path")
            directory.mkdir(exist_ok=True)
            destination = directory / "receipt-ref.json"
            e.require(not destination.is_symlink(), "member_path")
            destination.write_bytes(result.member_bytes)
        else:
            reference = (
                request["ext2_post_upload_receipt_v1"]
                if historical
                else t.loads(
                    os.environ.get("EXT2_POST_UPLOAD_RECEIPT", "").encode(), 4096
                )
            )
            if not historical:
                read_signing_key(clients["kms"], gov)
            verified = verify_ext2_reference(
                reference,
                github=github,
                s3=clients["s3"],
                governance=gov,
                now=_utc(),
                historical=historical,
            )
            rendered = consumer.render(verified, gov)
            root = _private_root()
            destination = root / "rendered-inputs.json"
            e.require(not destination.is_symlink(), "renderer_path")
            destination.write_bytes(t.canonical(rendered))
            destination.chmod(0o600)
            _output(reference)
        return 0
    except Exception:
        # SDK errors, tokens, payloads, private paths and URL redirects must not
        # escape via a traceback or a command's stderr into public workflow logs.
        print(
            "EXT2 gate rejected; reviewed recovery or missing governed facts required.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
