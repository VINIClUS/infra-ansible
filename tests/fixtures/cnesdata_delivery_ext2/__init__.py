"""Synthetic offline EXT2 contracts. Never an owner handoff or production receipt."""

import base64
import copy
import hashlib
import io
import json
import zipfile
from types import SimpleNamespace


ACCOUNT = "111122223333"
SOURCE = "a" * 40
PIN = "b" * 40
BUCKET = "synthetic-ext2-evidence"
KEY = f"arn:aws:kms:us-east-2:{ACCOUNT}:key/00000000-0000-4000-8000-000000000001"
SIGNING_KEY = KEY[:-1] + "2"
UNTIL = "2030-01-01T00:00:00Z"
PREFIX = "cnesdata/prod/ext2/current/"
HISTORY = "cnesdata/prod/ext2/history/"
KEYS = [
    f"{PREFIX}{SOURCE}/123/1/{name}"
    for name in ("activation.json", "activation.sig.der", "post-upload-receipt.json")
]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checksum(raw):
    return base64.b64encode(hashlib.sha256(raw).digest()).decode()


def canonical(value):
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode()


WORKFLOW = ".github/workflows/reusable-cnesdata-signing-gate.yml"
CALLER = ".github/workflows/synthetic-offline-ext2.yml"
REPOSITORY = "VINIClUS/CnesData"
OWNED = [
    "tools/cnesdata_delivery/" + name
    for name in (
        "evidence.py",
        "ext2_transport.py",
        "signing_gate.py",
        "ext2_inventory.py",
        "runtime-requirements.txt",
    )
]


class GitHub:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def read(self, path, *, raw=False, maximum=8 * 1024**2):
        self.calls.append(path)
        value = self.responses[path]
        if isinstance(value, Exception):
            raise value
        if raw:
            assert type(value) is bytes
            if len(value) > maximum:
                raise ValueError("fixture response exceeds boundary")
            return value
        return copy.deepcopy(value)


def transport_case():
    """A fake future caller is data only: no workflow/capability is created."""
    member = canonical(
        {
            "receipt_version_id": "receipt-version",
            "receipt_sha256": "c" * 64,
            "receipt_size": 1200,
        }
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("receipt-ref.json", member)
    archive = buffer.getvalue()
    reference = {
        "repository": REPOSITORY,
        "run_id": "123",
        "run_attempt": "1",
        "artifact_id": "456",
        "artifact_digest": "sha256:" + sha(archive),
        "publisher_job_id": "789",
        "publisher_step_number": 2,
        "source_sha": SOURCE,
        "caller_workflow_path": CALLER,
        "reusable_workflow_sha": PIN,
    }
    run_path = f"repos/{REPOSITORY}/actions/runs/123/attempts/1"
    artifact_path = f"repos/{REPOSITORY}/actions/artifacts/456"
    sources = [(REPOSITORY, SOURCE, CALLER), ("VINIClUS/infra-ansible", PIN, WORKFLOW)]
    sources += [("VINIClUS/infra-ansible", PIN, name) for name in OWNED]
    closure, responses = [], {}
    for repo, revision, path in sources:
        content = ("offline contract fixture: " + path + "\n").encode()
        closure.append(
            {
                "repository": repo,
                "revision": revision,
                "path": path,
                "sha256": sha(content),
            }
        )
        responses[f"repos/{repo}/contents/{path}?ref={revision}"] = {
            "type": "file",
            "encoding": "base64",
            "size": len(content),
            "path": path,
            "content": base64.b64encode(content).decode(),
            "sha": hashlib.sha1(
                b"blob " + str(len(content)).encode() + b"\0" + content
            ).hexdigest(),
        }
    profile = {
        "repository_id": 1177879951,
        "owner_id": 124298687,
        "source_sha": SOURCE,
        "caller_workflow_path": CALLER,
        "workflow_sha": PIN,
        "closure": closure,
        "publisher_job_name": "synthetic / sign-store-publish",
        "publisher_steps": [
            "Set up job",
            "Commit EXT2 artifact reference",
            "Complete job",
        ],
        "required_checks": ["synthetic-required"],
        "accepted_history": [reference.copy()],
    }
    gov = governance() | {"provenance": profile}
    repo = {"id": 1177879951, "full_name": REPOSITORY, "owner": {"id": 124298687}}
    responses.update(
        {
            run_path: {
                "id": 123,
                "run_attempt": 1,
                "repository": repo,
                "head_repository": repo,
                "head_sha": SOURCE,
                "head_branch": "develop",
                "event": "workflow_dispatch",
                "path": CALLER,
                "status": "in_progress",
                "conclusion": None,
                "referenced_workflows": [
                    {
                        "path": "VINIClUS/infra-ansible/" + WORKFLOW + "@" + PIN,
                        "sha": PIN,
                    }
                ],
            },
            run_path + "/jobs?per_page=100&page=1": {
                "total_count": 1,
                "jobs": [
                    {
                        "id": 789,
                        "run_id": 123,
                        "head_sha": SOURCE,
                        "name": profile["publisher_job_name"],
                        "status": "completed",
                        "conclusion": "success",
                        "steps": [
                            {
                                "number": number,
                                "name": name,
                                "status": "completed",
                                "conclusion": "success",
                            }
                            for number, name in enumerate(profile["publisher_steps"], 1)
                        ],
                    }
                ],
            },
            f"repos/{REPOSITORY}/actions/jobs/789/steps/2/logs": b"2026-11-08T00:00:00.000Z EXT2_ARTIFACT_COMMIT_V1 "
            + canonical(
                {
                    "artifact_id": "456",
                    "artifact_digest": reference["artifact_digest"],
                    "receipt_ref_sha256": sha(member),
                }
            ),
            artifact_path: {
                "id": 456,
                "expired": False,
                "expires_at": "2030-01-01T00:00:00Z",
                "size_in_bytes": len(archive),
                "digest": reference["artifact_digest"],
                "workflow_run": {
                    "id": 123,
                    "repository_id": 1177879951,
                    "head_repository_id": 1177879951,
                    "head_sha": SOURCE,
                },
            },
            artifact_path + "/zip": archive,
            f"repos/{REPOSITORY}/compare/{SOURCE}...develop": {"status": "identical"},
            f"repos/{REPOSITORY}/commits/{SOURCE}/check-runs?per_page=100": {
                "total_count": 1,
                "check_runs": [
                    {
                        "name": "synthetic-required",
                        "head_sha": SOURCE,
                        "conclusion": "success",
                        "status": "completed",
                    }
                ],
            },
        }
    )
    return gov, reference, GitHub(responses), member


def governance():
    return {
        "storage": {
            "account_id": ACCOUNT,
            "region": "us-east-2",
            "bucket_name": BUCKET,
            "bucket_arn": "arn:aws:s3:::" + BUCKET,
            "cipher_kms_key_arn": KEY,
            "current_prefix": PREFIX,
            "history_prefix": HISTORY,
            "current_keys": KEYS.copy(),
            "history_objects": [],
            "retain_until": UNTIL,
            "retention_policy_id": "synthetic-owner-policy",
        }
    }


class S3:
    """Records the actual SDK boundary; deliberately no transfer/multipart API."""

    def __init__(self):
        self.calls = []
        self.objects = {}
        self.bucket_key = False
        self.head_mutation = {}
        self.get_mutation = {}
        self.retention_mutation = {}
        self.put_error = None
        self.meta = SimpleNamespace(
            config=SimpleNamespace(retries={"total_max_attempts": 1})
        )

    def get_bucket_encryption(self, **kwargs):
        self.calls.append(("encryption", kwargs))
        rule = {
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": KEY,
            }
        }
        if self.bucket_key != "missing":
            rule["BucketKeyEnabled"] = self.bucket_key
        return {"ServerSideEncryptionConfiguration": {"Rules": [rule]}}

    def get_bucket_versioning(self, **kwargs):
        self.calls.append(("versioning", kwargs))
        return {"Status": "Enabled"}

    def get_object_lock_configuration(self, **kwargs):
        self.calls.append(("lock", kwargs))
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    def put_object(self, **kwargs):
        self.calls.append(("put", kwargs))
        if self.put_error:
            raise self.put_error
        version = str(len(self.objects) + 1)
        self.objects[(kwargs["Key"], version)] = kwargs["Body"]
        return {"VersionId": version, "ChecksumSHA256": checksum(kwargs["Body"])}

    def head_object(self, **kwargs):
        self.calls.append(("head", kwargs))
        body = self.objects[(kwargs["Key"], kwargs["VersionId"])]
        result = {
            "VersionId": kwargs["VersionId"],
            "ContentLength": len(body),
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KEY,
            "BucketKeyEnabled": False,
            "ChecksumSHA256": checksum(body),
        }
        result.update(copy.deepcopy(self.head_mutation))
        return result

    def get_object(self, **kwargs):
        self.calls.append(("get", kwargs))
        body = self.objects[(kwargs["Key"], kwargs["VersionId"])]
        return {
            "VersionId": kwargs["VersionId"],
            "ContentLength": len(body),
            "Body": io.BytesIO(body),
            "ChecksumSHA256": checksum(body),
            **self.get_mutation,
        }

    def get_object_retention(self, **kwargs):
        self.calls.append(("retention", kwargs))
        return {
            "Retention": {
                "Mode": "COMPLIANCE",
                "RetainUntilDate": UNTIL,
                **self.retention_mutation,
            }
        }
