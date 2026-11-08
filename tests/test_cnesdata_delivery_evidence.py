"""Behavioral, offline S3/provenance/inventory contracts for the owned EXT2 boundary."""

import io

import pytest

from fixtures.cnesdata_delivery_ext2 import BUCKET, KEY, KEYS, UNTIL, S3, checksum, governance, sha


@pytest.fixture
def evidence():
    from tools.cnesdata_delivery import evidence
    return evidence


def test_put_explicit_false_and_versioned_readback(evidence):
    s3 = S3()
    raw = b'{"fixture_only":true}\n'
    result = evidence.store_and_verify(raw, key=KEYS[0], s3=s3, governance=governance())
    assert result.body == raw
    assert result.version_id == "1" and result.content_sha256 == sha(raw)
    put = next(args for op, args in s3.calls if op == "put")
    assert put == {"Bucket": BUCKET, "Key": KEYS[0], "Body": raw,
                   "ExpectedBucketOwner": "111122223333", "IfNoneMatch": "*",
                   "ServerSideEncryption": "aws:kms", "SSEKMSKeyId": KEY,
                   "BucketKeyEnabled": False, "ObjectLockMode": "COMPLIANCE",
                   "ObjectLockRetainUntilDate": evidence.date(UNTIL),
                   "ChecksumAlgorithm": "SHA256", "ChecksumSHA256": checksum(raw)}
    for op in ("head", "get", "retention"):
        args = next(args for name, args in s3.calls if name == op)
        assert args["VersionId"] == "1"
        assert args["ExpectedBucketOwner"] == "111122223333"
        assert "ServerSideEncryption" not in args and "Range" not in args
    assert [name for name, _ in s3.calls].count("encryption") == 2


@pytest.mark.parametrize("value", [None, True, "false", 0, "missing"])
@pytest.mark.parametrize("level", ["bucket", "head"])
def test_bucket_key_readback_fails_closed(evidence, value, level, monkeypatch):
    s3 = S3()
    if level == "bucket":
        s3.bucket_key = value
    elif value == "missing":
        original = s3.head_object
        def missing(**kwargs):
            result = original(**kwargs)
            del result["BucketKeyEnabled"]
            return result
        monkeypatch.setattr(s3, "head_object", missing)
    else:
        s3.head_mutation["BucketKeyEnabled"] = value
    with pytest.raises(ValueError):
        evidence.store_and_verify(b"original", key=KEYS[0], s3=s3, governance=governance())
    if level == "bucket":
        assert not any(name == "put" for name, _ in s3.calls)


@pytest.mark.parametrize("field,value", [
    ("VersionId", "another-version"), ("VersionId", "null"), ("ContentLength", 0),
    ("ContentLength", True), ("SSEKMSKeyId", KEY[:-1] + "9"),
    ("ServerSideEncryption", "AES256"), ("ChecksumSHA256", checksum(b"other")),
    ("DeleteMarker", True),
])
def test_head_metadata_must_match_returned_version_and_original_bytes(evidence, field, value):
    s3 = S3()
    s3.head_mutation[field] = value
    with pytest.raises(ValueError):
        evidence.store_and_verify(b"original", key=KEYS[0], s3=s3, governance=governance())


@pytest.mark.parametrize("mutation", ["truncated", "version", "checksum", "bucket-key", "cipher", "mode", "date"])
def test_receipt_own_version_is_verified_before_publication(evidence, mutation):
    s3 = S3()
    if mutation == "truncated":
        s3.get_mutation["Body"] = io.BytesIO(b"short")
    if mutation == "version":
        s3.get_mutation["VersionId"] = "other"
    if mutation == "checksum":
        s3.get_mutation["ChecksumSHA256"] = checksum(b"other")
    if mutation == "bucket-key":
        s3.get_mutation["BucketKeyEnabled"] = True
    if mutation == "cipher":
        s3.get_mutation["SSEKMSKeyId"] = KEY[:-1] + "9"
    if mutation == "mode":
        s3.retention_mutation["Mode"] = "GOVERNANCE"
    if mutation == "date":
        s3.retention_mutation["RetainUntilDate"] = "2031-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        evidence.store_and_verify(b"receipt original", key=KEYS[2], s3=s3, governance=governance())


@pytest.mark.parametrize("message", ["timeout after acceptance", "409", "412"])
def test_ambiguous_put_requires_recovery(evidence, message):
    s3 = S3()
    s3.put_error = RuntimeError(message + " confidential SDK detail")
    with pytest.raises(ValueError, match="recovery_required") as error:
        evidence.store_and_verify(b"original", key=KEYS[0], s3=s3, governance=governance())
    assert "confidential" not in str(error.value)
    assert len([x for x in s3.calls if x[0] == "put"]) == 1


def test_verified_retry_only_reads_authenticated_reference(evidence):
    s3 = S3()
    config = governance()
    original = evidence.store_and_verify(b"original", key=KEYS[0], s3=s3, governance=config)
    s3.calls.clear()
    restored = evidence.read_version(original.reference(), s3=s3, governance=config)
    assert restored.body == b"original" and not any(name == "put" for name, _ in s3.calls)
    bad = original.reference() | {"content_sha256": sha(b"different")}
    with pytest.raises(ValueError):
        evidence.read_version(bad, s3=s3, governance=config)


@pytest.mark.parametrize("key", ["cnesdata/prod/opentofu.tfstate", KEYS[0] + ".tflock",
    KEYS[0].replace("ext2", "other-app"), KEYS[0].replace("/123/", "/999/"),
    "shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"])
def test_other_keys_fail_before_sdk_mutation(evidence, key):
    s3 = S3()
    with pytest.raises(ValueError):
        evidence.store_and_verify(b"original", key=key, s3=s3, governance=governance())
    assert s3.calls == []


def test_sdk_automatic_mutating_retries_are_rejected(evidence):
    s3 = S3()
    s3.meta.config.retries = {"total_max_attempts": 3}
    with pytest.raises(ValueError):
        evidence.store_and_verify(b"original", key=KEYS[0], s3=s3, governance=governance())
    assert s3.calls == []


def test_bucket_configuration_change_after_put_fails(evidence, monkeypatch):
    s3 = S3()
    original = s3.get_object_retention
    def changed(**kwargs):
        s3.bucket_key = True
        return original(**kwargs)
    monkeypatch.setattr(s3, "get_object_retention", changed)
    with pytest.raises(ValueError):
        evidence.store_and_verify(b"original", key=KEYS[0], s3=s3, governance=governance())
