"""Read-only AWS boundary of the observer: an allowlist of operations, no write path."""
import hashlib
import json
import os
import urllib.request
from datetime import datetime
from urllib.parse import urlparse

from tools.cnesdata_delivery import contract as c, drift_catalog

READS = {service: set(operations) for service, operations in drift_catalog.READ_ONLY.items()} | {
    "ecr": {"describe_repositories", "describe_images", "batch_get_image", "get_download_url_for_layer"},
    "s3": drift_catalog.READ_ONLY["s3"] | {"get_object", "list_objects_v2"}}
REGION = "us-east-2"
AUDIENCE = "sts.amazonaws.com"


def require_read(service, operation):
    c.require(operation in READS.get(service, set()), f"read-only API boundary service={service} operation={operation}")


def _dates(value):
    if type(value) is datetime:
        return c.utc(value.timestamp())
    if type(value) is dict:
        return {key: _dates(child) for key, child in value.items()}
    if type(value) is list:
        return [_dates(child) for child in value]
    return value


class Reader:
    def __init__(self, session, account=None):
        self.session, self.account, self.clients = session, account, {}

    def _client(self, service):
        if service not in self.clients:
            self.clients[service] = self.session.client(service, region_name=REGION)
        return self.clients[service]

    def call(self, service, operation, **parameters):
        require_read(service, operation)
        response = getattr(self._client(service), operation)(**parameters)
        response.pop("ResponseMetadata", None)
        return _dates(response)

    def read(self, bucket, key, maximum=128 * 1024**2):
        require_read("s3", "get_object")
        extra = {"ExpectedBucketOwner": self.account} if self.account else {}
        try:
            response = self._client("s3").get_object(Bucket=bucket, Key=key, **extra)
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
                raise KeyError(key) from None
            raise
        c.require(response.get("ContentLength", maximum + 1) <= maximum, "private object size")
        with response["Body"] as stream:
            data = stream.read(maximum + 1)
        c.require(len(data) <= maximum, "private body limit")
        return data

    def list(self, bucket, prefix):
        require_read("s3", "list_objects_v2")
        keys, token = [], None
        while True:
            extra = {"ContinuationToken": token} if token else {}
            page = self._client("s3").list_objects_v2(Bucket=bucket, Prefix=prefix, **extra)
            keys += [item["Key"] for item in page.get("Contents", [])]
            token = page.get("NextContinuationToken")
            if not token:
                return sorted(keys)

    def blob(self, repository, digest, keep):
        url = self.call("ecr", "get_download_url_for_layer", registryId=self.account, repositoryName=repository,
                        layerDigest=digest)["downloadUrl"]
        parsed = urlparse(url)
        c.require(parsed.scheme == "https" and (parsed.hostname or "").endswith(".amazonaws.com"), "ECR blob host")
        hasher, size, body = hashlib.sha256(), 0, bytearray()
        with urllib.request.urlopen(url, timeout=20) as response:
            while chunk := response.read(1024**2):
                size += len(chunk)
                hasher.update(chunk)
                if keep:
                    c.require(size <= 4 * 1024**2, "OCI config capacity")
                    body.extend(chunk)
        return {"sha256": hasher.hexdigest(), "size": size, "body": bytes(body) if keep else None}


def web_identity_session(role_arn, environment=None):
    """Args: role ARN, environment. Returns: a boto3 session from the GitHub OIDC token. Raises: ValueError."""
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    environment = os.environ if environment is None else environment
    url = environment["ACTIONS_ID_TOKEN_REQUEST_URL"]
    parsed = urlparse(url)
    c.require(parsed.scheme == "https" and (parsed.hostname or "").endswith(".actions.githubusercontent.com"),
              "OIDC request host")
    request = urllib.request.Request(f"{url}&audience={AUDIENCE}",
                                     headers={"Authorization": "Bearer " + environment["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with urllib.request.urlopen(request, timeout=20) as response:
        token = json.loads(response.read(65536))["value"]
    sts = boto3.Session(region_name=REGION).client("sts", config=Config(signature_version=UNSIGNED))
    issued = sts.assume_role_with_web_identity(RoleArn=role_arn, RoleSessionName="cnesdata-observer",
                                               WebIdentityToken=token, DurationSeconds=900)["Credentials"]
    return boto3.Session(aws_access_key_id=issued["AccessKeyId"], aws_secret_access_key=issued["SecretAccessKey"],
                         aws_session_token=issued["SessionToken"], region_name=REGION)
