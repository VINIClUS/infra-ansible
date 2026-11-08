"""Synthetic offline EXT2 contracts. Never an owner handoff or production receipt."""

import base64
import copy
import hashlib
import io
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
KEYS = [f"{PREFIX}{SOURCE}/123/1/{name}" for name in
        ("activation.json", "activation.sig.der", "post-upload-receipt.json")]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checksum(raw):
    return base64.b64encode(hashlib.sha256(raw).digest()).decode()


def governance():
    return {"storage": {"account_id": ACCOUNT, "region": "us-east-2", "bucket_name": BUCKET,
            "bucket_arn": "arn:aws:s3:::" + BUCKET, "cipher_kms_key_arn": KEY,
            "current_prefix": PREFIX, "history_prefix": HISTORY, "current_keys": KEYS.copy(),
            "history_objects": [], "retain_until": UNTIL, "retention_policy_id": "synthetic-owner-policy"}}


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
        self.meta = SimpleNamespace(config=SimpleNamespace(retries={"total_max_attempts": 1}))

    def get_bucket_encryption(self, **kwargs):
        self.calls.append(("encryption", kwargs))
        rule = {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": KEY}}
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
        result = {"VersionId": kwargs["VersionId"], "ContentLength": len(body),
                  "ServerSideEncryption": "aws:kms", "SSEKMSKeyId": KEY,
                  "BucketKeyEnabled": False, "ChecksumSHA256": checksum(body)}
        result.update(copy.deepcopy(self.head_mutation))
        return result

    def get_object(self, **kwargs):
        self.calls.append(("get", kwargs))
        body = self.objects[(kwargs["Key"], kwargs["VersionId"])]
        return {"VersionId": kwargs["VersionId"], "ContentLength": len(body),
                "Body": io.BytesIO(body), "ChecksumSHA256": checksum(body), **self.get_mutation}

    def get_object_retention(self, **kwargs):
        self.calls.append(("retention", kwargs))
        return {"Retention": {"Mode": "COMPLIANCE", "RetainUntilDate": UNTIL,
                              **self.retention_mutation}}
