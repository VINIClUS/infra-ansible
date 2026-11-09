"""Behavioral, offline S3/provenance/inventory contracts for the owned EXT2 boundary."""

import io
from datetime import datetime, timezone
import json
import stat
import zipfile
from urllib.error import HTTPError

import pytest

from fixtures.cnesdata_delivery_ext2 import (
    BUCKET,
    KEY,
    KEYS,
    UNTIL,
    S3,
    checksum,
    governance,
    sha,
)
from fixtures.cnesdata_delivery_ext2 import (
    PIN,
    REPOSITORY,
    SOURCE,
    canonical,
    transport_case,
)


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
    assert put == {
        "Bucket": BUCKET,
        "Key": KEYS[0],
        "Body": raw,
        "ExpectedBucketOwner": "111122223333",
        "IfNoneMatch": "*",
        "ServerSideEncryption": "aws:kms",
        "SSEKMSKeyId": KEY,
        "BucketKeyEnabled": False,
        "ObjectLockMode": "COMPLIANCE",
        "ObjectLockRetainUntilDate": evidence.date(UNTIL),
        "ChecksumAlgorithm": "SHA256",
        "ChecksumSHA256": checksum(raw),
    }
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
        evidence.store_and_verify(
            b"original", key=KEYS[0], s3=s3, governance=governance()
        )
    if level == "bucket":
        assert not any(name == "put" for name, _ in s3.calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("VersionId", "another-version"),
        ("VersionId", "null"),
        ("ContentLength", 0),
        ("ContentLength", True),
        ("SSEKMSKeyId", KEY[:-1] + "9"),
        ("ServerSideEncryption", "AES256"),
        ("ChecksumSHA256", checksum(b"other")),
        ("DeleteMarker", True),
    ],
)
def test_head_metadata_must_match_returned_version_and_original_bytes(
    evidence, field, value
):
    s3 = S3()
    s3.head_mutation[field] = value
    with pytest.raises(ValueError):
        evidence.store_and_verify(
            b"original", key=KEYS[0], s3=s3, governance=governance()
        )


@pytest.mark.parametrize(
    "mutation",
    ["truncated", "version", "checksum", "bucket-key", "cipher", "mode", "date"],
)
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
        evidence.store_and_verify(
            b"receipt original", key=KEYS[2], s3=s3, governance=governance()
        )


@pytest.mark.parametrize("message", ["timeout after acceptance", "409", "412"])
def test_ambiguous_put_requires_recovery(evidence, message):
    s3 = S3()
    s3.put_error = RuntimeError(message + " confidential SDK detail")
    with pytest.raises(ValueError, match="recovery_required") as error:
        evidence.store_and_verify(
            b"original", key=KEYS[0], s3=s3, governance=governance()
        )
    assert "confidential" not in str(error.value)
    assert len([x for x in s3.calls if x[0] == "put"]) == 1


def test_verified_retry_only_reads_authenticated_reference(evidence):
    s3 = S3()
    config = governance()
    original = evidence.store_and_verify(
        b"original", key=KEYS[0], s3=s3, governance=config
    )
    s3.calls.clear()
    restored = evidence.read_version(original.reference(), s3=s3, governance=config)
    assert restored.body == b"original" and not any(
        name == "put" for name, _ in s3.calls
    )
    bad = original.reference() | {"content_sha256": sha(b"different")}
    with pytest.raises(ValueError):
        evidence.read_version(bad, s3=s3, governance=config)


@pytest.mark.parametrize(
    "key",
    [
        "cnesdata/prod/opentofu.tfstate",
        KEYS[0] + ".tflock",
        KEYS[0].replace("ext2", "other-app"),
        KEYS[0].replace("/123/", "/999/"),
        "shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json",
    ],
)
def test_other_keys_fail_before_sdk_mutation(evidence, key):
    s3 = S3()
    with pytest.raises(ValueError):
        evidence.store_and_verify(b"original", key=key, s3=s3, governance=governance())
    assert s3.calls == []


def test_sdk_automatic_mutating_retries_are_rejected(evidence):
    s3 = S3()
    s3.meta.config.retries = {"total_max_attempts": 3}
    with pytest.raises(ValueError):
        evidence.store_and_verify(
            b"original", key=KEYS[0], s3=s3, governance=governance()
        )
    assert s3.calls == []


def test_bucket_configuration_change_after_put_fails(evidence, monkeypatch):
    s3 = S3()
    original = s3.get_object_retention

    def changed(**kwargs):
        s3.bucket_key = True
        return original(**kwargs)

    monkeypatch.setattr(s3, "get_object_retention", changed)
    with pytest.raises(ValueError):
        evidence.store_and_verify(
            b"original", key=KEYS[0], s3=s3, governance=governance()
        )


@pytest.fixture
def transport():
    from tools.cnesdata_delivery import ext2_transport

    return ext2_transport


def authenticate(transport, gov, ref, api, *, historical=False):
    return transport.authenticate_reference(
        ref,
        github=api,
        governance=gov,
        current_invocation=None
        if historical
        else {"run_id": "123", "run_attempt": "1", "source_sha": SOURCE},
        now=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )


def test_artifact_attempt_is_bound_by_publisher_step_api(transport):
    gov, ref, api, member = transport_case()
    metadata = api.responses[f"repos/{REPOSITORY}/actions/artifacts/456"]
    assert "run_attempt" not in metadata["workflow_run"]
    verified = authenticate(transport, gov, ref, api)
    assert verified.receipt_reference == json.loads(member)
    assert verified.reference == ref
    assert f"repos/{REPOSITORY}/actions/jobs/789/steps/2/logs" in api.calls


@pytest.mark.parametrize(
    "mutation",
    ["attempt", "job", "step", "source", "fork", "pin", "ambiguous-pin", "event"],
)
def test_artifact_attempt_cannot_be_supplied_by_labels_or_receipt(transport, mutation):
    gov, ref, api, _ = transport_case()
    run = api.responses[f"repos/{REPOSITORY}/actions/runs/123/attempts/1"]
    if mutation == "attempt":
        run["run_attempt"] = 2
    if mutation == "job":
        ref["publisher_job_id"] = "999"
    if mutation == "step":
        ref["publisher_step_number"] = 1
    if mutation == "source":
        run["head_sha"] = "f" * 40
    if mutation == "fork":
        run["head_repository"] = {"id": 999, "full_name": "fork/CnesData"}
    if mutation == "pin":
        run["referenced_workflows"][0]["path"] = "VINIClUS/infra-ansible/branch@main"
    if mutation == "ambiguous-pin":
        run["referenced_workflows"] *= 2
    if mutation == "event":
        run["event"] = "pull_request_target"
    # An invented field in the artifact must never supply authoritative attempt.
    api.responses[f"repos/{REPOSITORY}/actions/artifacts/456"]["workflow_run"][
        "run_attempt"
    ] = 1
    with pytest.raises(ValueError):
        authenticate(transport, gov, ref, api)


def test_current_run_does_not_wait_for_its_own_completion(transport):
    gov, ref, api, _ = transport_case()
    authenticate(transport, gov, ref, api)
    with pytest.raises(ValueError):
        authenticate(transport, gov, ref, api, historical=True)
    api.responses[f"repos/{REPOSITORY}/actions/runs/123/attempts/1"].update(
        status="completed", conclusion="success"
    )
    authenticate(transport, gov, ref, api, historical=True)
    gov["provenance"]["accepted_history"] = []
    with pytest.raises(ValueError):
        authenticate(transport, gov, ref, api, historical=True)


@pytest.mark.parametrize(
    "mutation",
    [
        "publisher-incomplete",
        "publisher-duplicate",
        "closure",
        "helper-missing",
        "record-duplicate",
        "wrong-record",
    ],
)
def test_source_closure_not_labels_authenticates_publisher(transport, mutation):
    gov, ref, api, _ = transport_case()
    run = f"repos/{REPOSITORY}/actions/runs/123/attempts/1"
    log = f"repos/{REPOSITORY}/actions/jobs/789/steps/2/logs"
    if mutation == "publisher-incomplete":
        api.responses[run + "/jobs?per_page=100&page=1"]["jobs"][0]["status"] = (
            "in_progress"
        )
    if mutation == "publisher-duplicate":
        page = api.responses[run + "/jobs?per_page=100&page=1"]
        page["jobs"].append(page["jobs"][0] | {"id": 999})
        page["total_count"] = 2
    if mutation == "closure":
        p = f"repos/VINIClUS/infra-ansible/contents/tools/cnesdata_delivery/evidence.py?ref={PIN}"
        api.responses[p]["content"] = "c3Bvb2ZlZCBjYWxsZXIgc2NyaXB0"
    if mutation == "helper-missing":
        gov["provenance"]["closure"].pop()
    if mutation == "record-duplicate":
        api.responses[log] *= 2
    if mutation == "wrong-record":
        api.responses[log] = api.responses[log].replace(b'"456"', b'"999"')
    with pytest.raises(ValueError):
        authenticate(transport, gov, ref, api)


@pytest.mark.parametrize(
    "mutation", ["archive", "member", "size", "digest", "receipt-extra"]
)
def test_distinct_archive_member_receipt_digests(transport, mutation):
    gov, ref, api, member = transport_case()
    artifact = f"repos/{REPOSITORY}/actions/artifacts/456"
    if mutation == "archive":
        api.responses[artifact + "/zip"] += b"repacked"
    if mutation == "member":
        log = f"repos/{REPOSITORY}/actions/jobs/789/steps/2/logs"
        api.responses[log] = api.responses[log].replace(sha(member).encode(), b"f" * 64)
    if mutation == "size":
        api.responses[artifact]["size_in_bytes"] += 1
    if mutation == "digest":
        api.responses[artifact]["digest"] = "sha256:" + "f" * 64
    if mutation == "receipt-extra":
        body = json.loads(member) | {"self_hash": "d" * 64}
        with pytest.raises(ValueError):
            transport.decode_member(canonical(body))
        return
    with pytest.raises(ValueError):
        authenticate(transport, gov, ref, api)


@pytest.mark.parametrize(
    "mutation",
    ["expired", "missing-log", "incomplete-pages", "too-many-jobs", "oversized-log"],
)
def test_expired_or_deleted_provenance_has_no_local_fallback(transport, mutation):
    gov, ref, api, _ = transport_case()
    if mutation == "expired":
        api.responses[f"repos/{REPOSITORY}/actions/artifacts/456"]["expired"] = True
    if mutation == "missing-log":
        api.responses[f"repos/{REPOSITORY}/actions/jobs/789/steps/2/logs"] = (
            RuntimeError("410 token secret")
        )
    if mutation in {"incomplete-pages", "too-many-jobs"}:
        jobs = api.responses[
            f"repos/{REPOSITORY}/actions/runs/123/attempts/1/jobs?per_page=100&page=1"
        ]
        jobs["total_count"] = 2 if mutation == "incomplete-pages" else 257
    if mutation == "oversized-log":
        api.responses[f"repos/{REPOSITORY}/actions/jobs/789/steps/2/logs"] = (
            b"x" * 65537
        )
    with pytest.raises(ValueError):
        authenticate(transport, gov, ref, api)


@pytest.mark.parametrize(
    "name,mode",
    [
        ("../receipt-ref.json", 0),
        ("extra.json", 0),
        ("receipt-ref.json", stat.S_IFLNK | 0o777),
    ],
)
def test_transport_bounds_and_safe_extraction(transport, name, mode):
    _, _, _, member = transport_case()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as bundle:
        entry = zipfile.ZipInfo(name)
        entry.external_attr = mode << 16
        bundle.writestr(entry, member)
    with pytest.raises(ValueError):
        transport.unpack_member(buf.getvalue())


def test_duplicate_member_json_and_noncanonical_bytes_fail(transport):
    for raw in [
        b'{"receipt_size":1,"receipt_size":2}\n',
        b"{}",
        b"\xef\xbb\xbf{}\n",
        b'{"v":NaN}\n',
    ]:
        with pytest.raises(ValueError):
            transport.decode_member(raw)


@pytest.mark.parametrize(
    "destination",
    [
        "https://evil.invalid/receipt",
        "http://results.actions.githubusercontent.com/x",
        "https://user:secret@results.actions.githubusercontent.com/x",
        "https://fake.blob.core.windows.net/x",
    ],
)
def test_download_redirect_hosts_are_restricted_without_credential_forwarding(
    transport, destination
):
    calls = []

    def opener(request, timeout):
        calls.append(request)
        assert timeout == 20
        raise HTTPError(
            request.full_url, 302, "redirect", {"Location": destination}, None
        )

    client = transport.GitHubClient("synthetic-token-never-print", opener=opener)
    with pytest.raises(ValueError) as error:
        client.read(f"repos/{REPOSITORY}/actions/artifacts/456/zip", raw=True)
    assert len(calls) == 1 and "secret" not in str(error.value)


def test_download_token_stays_on_api_and_no_second_redirect(transport):
    calls = []

    class Response(io.BytesIO):
        def __init__(self):
            super().__init__(b"downloaded")
            self.headers = {}

    def opener(request, timeout):
        calls.append(request)
        if len(calls) == 1:
            raise HTTPError(
                request.full_url,
                302,
                "redirect",
                {
                    "Location": "https://productionresultssa1.blob.core.windows.net/controlled?signature=private"
                },
                None,
            )
        return Response()

    client = transport.GitHubClient("synthetic-token-never-print", opener=opener)
    assert (
        client.read(f"repos/{REPOSITORY}/actions/artifacts/456/zip", raw=True)
        == b"downloaded"
    )
    assert calls[0].get_header("Authorization") == "Bearer synthetic-token-never-print"
    assert calls[1].get_header("Authorization") is None
    calls.clear()

    def twice(request, timeout):
        calls.append(request)
        raise HTTPError(
            request.full_url,
            302,
            "redirect",
            {"Location": "https://results.actions.githubusercontent.com/private"},
            None,
        )

    with pytest.raises(ValueError):
        transport.GitHubClient("synthetic-token", opener=twice).read(
            f"repos/{REPOSITORY}/actions/artifacts/456/zip", raw=True
        )
    assert len(calls) == 2
