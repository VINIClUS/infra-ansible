"""Owned EXT2 S3 boundary. No bucket adoption, latest reads or mutating retries."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, TypeGuard, cast

MAX_OBJECT = 262144
REFERENCE_FIELDS = frozenset(
    "bucket_arn key version_id content_sha256 content_length "
    "server_side_encryption cipher_kms_key_arn bucket_key_enabled".split()
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError("ext2=" + message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def checksum(raw: bytes) -> str:
    return base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")


def date(value: Any) -> datetime:
    if isinstance(value, datetime):
        require(
            value.tzinfo is not None and value.microsecond == 0, "retention_timestamp"
        )
        return value.astimezone(timezone.utc)
    require(
        type(value) is str
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value) is not None,
        "retention_timestamp",
    )
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise ValueError("ext2=retention_timestamp") from None


def key_valid(key: Any) -> TypeGuard[str]:
    return (
        type(key) is str
        and 0 < len(key) <= 1024
        and key.startswith("cnesdata/prod/")
        and re.fullmatch(r"[A-Za-z0-9_./-]+", key) is not None
        and not any(part in {"", ".", ".."} for part in key.split("/"))
    )


def storage_config(governance: dict[str, Any]) -> dict[str, Any]:
    raw = governance.get("storage")
    fields = {
        "account_id",
        "region",
        "bucket_name",
        "bucket_arn",
        "cipher_kms_key_arn",
        "current_prefix",
        "history_prefix",
        "current_keys",
        "history_objects",
        "retain_until",
        "retention_policy_id",
    }
    require(type(raw) is dict and set(raw) == fields, "storage_contract")
    value = cast(dict[str, Any], raw)
    require(
        re.fullmatch(r"[0-9]{12}", value["account_id"]) is not None
        and value["region"] == "us-east-2",
        "storage_identity",
    )
    require(
        re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", value["bucket_name"])
        is not None
        and value["bucket_arn"] == "arn:aws:s3:::" + value["bucket_name"],
        "storage_bucket",
    )
    require(
        re.fullmatch(
            r"arn:aws:kms:us-east-2:" + value["account_id"] + r":key/[0-9a-f-]{36}",
            value["cipher_kms_key_arn"],
        )
        is not None,
        "cipher_identity",
    )
    prefixes = [value["current_prefix"], value["history_prefix"]]
    require(
        all(type(p) is str and p.endswith("/") and key_valid(p[:-1]) for p in prefixes)
        and not any(a.startswith(b) for a, b in (prefixes, prefixes[::-1])),
        "storage_prefixes",
    )
    keys = value["current_keys"]
    require(
        type(keys) is list
        and len(keys) == 3
        and len(set(keys)) == 3
        and all(key_valid(k) and k.startswith(prefixes[0]) for k in keys),
        "current_keys",
    )
    require(
        type(value["history_objects"]) is list and len(value["history_objects"]) <= 128,
        "history_catalog",
    )
    require(
        type(value["retention_policy_id"]) is str
        and 0 < len(value["retention_policy_id"]) <= 128,
        "retention_policy",
    )
    date(value["retain_until"])
    return value


def _call(s3: Any, operation: str, **parameters: Any) -> dict[str, Any]:
    try:
        result = getattr(s3, operation)(**parameters)
    except Exception:
        raise ValueError("ext2=readback_unavailable") from None
    require(type(result) is dict, "readback_shape")
    return result


def bucket_readback(s3: Any, config: dict[str, Any]) -> None:
    parameters = {
        "Bucket": config["bucket_name"],
        "ExpectedBucketOwner": config["account_id"],
    }
    require(
        _call(s3, "get_bucket_versioning", **parameters).get("Status") == "Enabled",
        "versioning",
    )
    lock = _call(s3, "get_object_lock_configuration", **parameters).get(
        "ObjectLockConfiguration", {}
    )
    require(lock.get("ObjectLockEnabled") == "Enabled", "object_lock")
    encryption = _call(s3, "get_bucket_encryption", **parameters).get(
        "ServerSideEncryptionConfiguration", {}
    )
    rules = encryption.get("Rules")
    require(
        type(rules) is list and len(rules) == 1 and type(rules[0]) is dict,
        "bucket_encryption",
    )
    rule = cast(dict[str, Any], rules[0])
    require(rule.get("BucketKeyEnabled") is False, "bucket_key_default")
    require(
        rule.get("ApplyServerSideEncryptionByDefault")
        == {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": config["cipher_kms_key_arn"]},
        "bucket_cipher",
    )


def _version(value: Any) -> str:
    require(
        type(value) is str
        and 0 < len(value) <= 1024
        and value != "null"
        and not any(ord(c) < 32 for c in value),
        "version_id",
    )
    return value


@dataclass(frozen=True)
class VerifiedObject:
    body: bytes
    bucket_arn: str
    key: str
    version_id: str
    content_sha256: str
    cipher_kms_key_arn: str
    retain_until: str

    def reference(self) -> dict[str, Any]:
        return {
            "bucket_arn": self.bucket_arn,
            "key": self.key,
            "version_id": self.version_id,
            "content_sha256": self.content_sha256,
            "content_length": len(self.body),
            "server_side_encryption": "aws:kms",
            "cipher_kms_key_arn": self.cipher_kms_key_arn,
            "bucket_key_enabled": False,
        }


def _reference(reference: Any, config: dict[str, Any]) -> dict[str, Any]:
    require(
        type(reference) is dict and set(reference) == REFERENCE_FIELDS,
        "object_reference",
    )
    ref = cast(dict[str, Any], reference)
    require(
        ref["bucket_arn"] == config["bucket_arn"] and key_valid(ref["key"]),
        "object_scope",
    )
    require(
        ref["key"] in config["current_keys"]
        or (
            ref["key"].startswith(config["history_prefix"])
            and ref in config["history_objects"]
        ),
        "object_catalog",
    )
    require(
        ref["server_side_encryption"] == "aws:kms"
        and ref["cipher_kms_key_arn"] == config["cipher_kms_key_arn"]
        and ref["bucket_key_enabled"] is False,
        "object_cipher",
    )
    require(
        type(ref["content_length"]) is int
        and 0 < ref["content_length"] <= MAX_OBJECT
        and type(ref["content_sha256"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", ref["content_sha256"]) is not None,
        "object_digest",
    )
    _version(ref["version_id"])
    return ref


def read_version(
    reference: dict[str, Any], *, s3: Any, governance: dict[str, Any]
) -> VerifiedObject:
    config = storage_config(governance)
    ref = _reference(reference, config)
    bucket_readback(s3, config)
    return _read_verified(ref, s3, config)


def _read_verified(
    ref: dict[str, Any], s3: Any, config: dict[str, Any]
) -> VerifiedObject:
    parameters = {
        "Bucket": config["bucket_name"],
        "Key": ref["key"],
        "VersionId": ref["version_id"],
        "ExpectedBucketOwner": config["account_id"],
    }
    head = _call(s3, "head_object", **parameters, ChecksumMode="ENABLED")
    require(
        head.get("VersionId") == ref["version_id"]
        and head.get("DeleteMarker", False) is False,
        "head_version",
    )
    require(
        type(head.get("ContentLength")) is int
        and head["ContentLength"] == ref["content_length"],
        "head_length",
    )
    require(head.get("BucketKeyEnabled") is False, "object_bucket_key")
    require(
        head.get("ServerSideEncryption") == "aws:kms"
        and head.get("SSEKMSKeyId") == config["cipher_kms_key_arn"],
        "head_cipher",
    )
    result = _call(s3, "get_object", **parameters, ChecksumMode="ENABLED")
    require(
        result.get("VersionId") == ref["version_id"]
        and result.get("DeleteMarker", False) is False,
        "get_version",
    )
    require(
        type(result.get("ContentLength")) is int
        and result["ContentLength"] == ref["content_length"],
        "get_length",
    )
    for field, expected in (
        ("BucketKeyEnabled", False),
        ("ServerSideEncryption", "aws:kms"),
        ("SSEKMSKeyId", config["cipher_kms_key_arn"]),
    ):
        if field in result:
            require(
                type(result[field]) is type(expected) and result[field] == expected,
                "get_cipher",
            )
    stream = cast(Any, result.get("Body"))
    try:
        raw = stream.read(ref["content_length"] + 1)
    except Exception:
        raise ValueError("ext2=body_unavailable") from None
    finally:
        if hasattr(stream, "close"):
            stream.close()
    require(
        type(raw) is bytes
        and len(raw) == ref["content_length"]
        and sha(raw) == ref["content_sha256"],
        "body_digest",
    )
    require(head.get("ChecksumSHA256") == checksum(raw), "head_checksum")
    require(
        "ChecksumSHA256" not in result or result["ChecksumSHA256"] == checksum(raw),
        "get_checksum",
    )
    retention = _call(s3, "get_object_retention", **parameters).get("Retention", {})
    require(
        retention.get("Mode") == "COMPLIANCE"
        and date(retention.get("RetainUntilDate")) == date(config["retain_until"]),
        "object_retention",
    )
    bucket_readback(s3, config)
    return VerifiedObject(
        raw,
        config["bucket_arn"],
        ref["key"],
        ref["version_id"],
        sha(raw),
        config["cipher_kms_key_arn"],
        config["retain_until"],
    )


def store_and_verify(
    body: bytes, *, key: str, s3: Any, governance: dict[str, Any]
) -> VerifiedObject:
    config = storage_config(governance)
    require(type(body) is bytes and 0 < len(body) <= MAX_OBJECT, "object_size")
    require(key in config["current_keys"], "write_scope")
    require(
        s3.meta.config.retries.get("total_max_attempts") == 1, "sdk_mutating_retries"
    )
    bucket_readback(s3, config)
    try:
        result = s3.put_object(
            Bucket=config["bucket_name"],
            Key=key,
            Body=body,
            ExpectedBucketOwner=config["account_id"],
            IfNoneMatch="*",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=config["cipher_kms_key_arn"],
            BucketKeyEnabled=False,
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=date(config["retain_until"]),
            ChecksumAlgorithm="SHA256",
            ChecksumSHA256=checksum(body),
        )
    except Exception:
        raise ValueError("ext2=recovery_required") from None
    require(type(result) is dict, "recovery_required")
    version = _version(result.get("VersionId"))
    require(
        "ChecksumSHA256" not in result or result["ChecksumSHA256"] == checksum(body),
        "put_checksum",
    )
    reference = VerifiedObject(
        body,
        config["bucket_arn"],
        key,
        version,
        sha(body),
        config["cipher_kms_key_arn"],
        config["retain_until"],
    ).reference()
    return _read_verified(_reference(reference, config), s3, config)
