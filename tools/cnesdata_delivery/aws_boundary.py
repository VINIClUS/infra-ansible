"""Live SDK boundaries; no AWS import or credential access during preflight/tests."""
import base64
import time
from email.utils import parsedate_to_datetime

from tools.cnesdata_delivery.contract import canonical, digest, loads, require, sha
from tools.cnesdata_delivery.coordination_lease import KEY


def bounded(function, timeout=20):
    """A socket/DNS stall cannot block the supervising thread past the budget.

    A late request is ambiguous: caller fails closed and retains coordination. Never
    retry or reuse a failed client/lease to start another product mutation.
    """
    import threading
    done = threading.Event()
    result = []
    def work():
        try:
            result.append((True, function()))
        except BaseException as error:
            result.append((False, error))
        finally:
            done.set()
    threading.Thread(target=work, daemon=True).start()
    require(done.wait(timeout), "hard SDK/DNS deadline; recovery_required")
    if not result[0][0]:
        raise result[0][1]
    return result[0][1]


class AWS:
    def __init__(self, governance, *, credentials=None):
        import os
        import boto3
        from botocore.config import Config
        credentials = {
            "AccessKeyId": os.environ.get("AWS_ACCESS_KEY_ID"),
            "SecretAccessKey": os.environ.get("AWS_SECRET_ACCESS_KEY"),
            "SessionToken": os.environ.get("AWS_SESSION_TOKEN"),
        } if credentials is None else credentials
        require(all(type(credentials.get(field)) is str and credentials[field]
                    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken")),
                "explicit temporary credentials required")
        self.governance = governance
        self.clients = {}
        require(not any(name in os.environ for name in ("AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_S3",
                    "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_DATA_PATH", "AWS_CA_BUNDLE")), "unreviewed AWS override")
        self.config = Config(region_name="us-east-2", connect_timeout=5, read_timeout=10,
                             retries={"total_max_attempts": 1}, ignore_configured_endpoint_urls=True)
        self.session = boto3.Session(aws_access_key_id=credentials["AccessKeyId"],
                                     aws_secret_access_key=credentials["SecretAccessKey"],
                                     aws_session_token=credentials["SessionToken"], region_name="us-east-2")
        self.last_sample = None
        self.request_id = None
        identity = self.call("sts", "get_caller_identity")
        role = governance["roles"][governance["role"]]
        prefix = role.replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/"
        require(identity["Account"] == governance["account_id"] and identity["Arn"].startswith(prefix), "principal role/account")
        self.identity = identity

    def call(self, service, operation, *, region="us-east-2", **kwargs):
        require(region == "us-east-2" or (region == "us-east-1" and service in {"acm", "wafv2", "cloudfront"}), "governed regional API")
        key = service, region
        if key not in self.clients:
            self.clients[key] = self.session.client(service, region_name=region, config=self.config)
        started = time.monotonic()
        response = bounded(lambda: getattr(self.clients[key], operation)(**kwargs))
        ended = time.monotonic()
        metadata = response["ResponseMetadata"]
        headers = metadata["HTTPHeaders"]
        require("date" in headers, "AWS authenticated server Date")
        server = parsedate_to_datetime(headers["date"]).timestamp()
        require(ended - started <= 20 and abs(time.time() - server) <= 30, "AWS clock/latency uncertainty")
        if self.last_sample is not None:
            _, previous_end, previous_date = self.last_sample
            require(abs((server - previous_date) - (ended - previous_end)) <= 31, "AWS/monotonic clock discontinuity")
        self.last_sample = started, ended, server
        self.request_id = metadata["RequestId"]
        return response

    def get(self, bucket, key, maximum=128 * 1024**2, *, absent=False):
        return bounded(lambda: self._get(bucket, key, maximum, absent=absent))

    def get_state(self, *, absent=False):
        """One exact product-state GetObject; retain its actual version privately."""
        return bounded(lambda: self._get(self.governance["state_bucket"],
                       "cnesdata/prod/opentofu.tfstate", 128 * 1024**2,
                       absent=absent, state=True))

    def _get(self, bucket, key, maximum, *, absent, state=False):
        try:
            response = self.call("s3", "get_object", Bucket=bucket, Key=key,
                                 ExpectedBucketOwner=self.governance["account_id"])
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code")
            if absent and code in {"NoSuchKey", "404"}:
                return (None, {"status": "absent", "version_id": None, "etag_sha256": None}) if state else (None, None)
            raise
        require(response.get("ContentLength", maximum + 1) <= maximum, "private object size")
        with response["Body"] as stream:
            data = stream.read(maximum + 1)
        require(len(data) <= maximum, "private body limit")
        if state:
            version, etag = response.get("VersionId"), response.get("ETag")
            require(type(version) is str and bool(version.strip()) and version != "null", "state version unavailable")
            require(type(etag) is str and bool(etag), "state ETag unavailable")
            return data, {"status": "present", "version_id": version, "etag_sha256": sha(etag.encode())}
        return data, response["ETag"]

    def put(self, bucket, key, data, *, etag=None, key_arn=None):
        require(type(data) is bytes, "S3 content bytes")
        conditions = {"IfMatch": etag} if etag is not None else {"IfNoneMatch": "*"}
        response = self.call("s3", "put_object", Bucket=bucket, Key=key, Body=data,
                             ExpectedBucketOwner=self.governance["account_id"],
            ServerSideEncryption="aws:kms", SSEKMSKeyId=key_arn or self.governance["evidence_kms_key_arn"], BucketKeyEnabled=False,
                             ChecksumSHA256=base64.b64encode(bytes.fromhex(sha(data))).decode(), **conditions)
        return response["ETag"]

    def verify_ecr(self, expected, guard=lambda: None):
        """Re-read original OCI bytes, every descriptor/blob and destination immutability."""
        repository = self.governance["ecr_repository"]
        account = self.governance["account_id"]
        guard()
        observed = self.call("ecr", "describe_repositories", registryId=account,
                             repositoryNames=[repository])["repositories"]
        require(len(observed) == 1, "ECR repository singleton")
        repo = observed[0]
        require(repo["registryId"] == account and repo["repositoryName"] == repository
                and repo["repositoryArn"] == f"arn:aws:ecr:us-east-2:{account}:repository/{repository}"
                and repo["imageTagMutability"] == "IMMUTABLE" and not repo.get("imageTagMutabilityExclusionFilters"), "ECR governed immutable repository")
        image = expected["image_digest"]
        require(image == "sha256:" + digest(image.removeprefix("sha256:")), "image digest")
        metadata = self.call("ecr", "describe_images", registryId=account, repositoryName=repository,
                             imageIds=[{"imageDigest": image}])["imageDetails"]
        require(len(metadata) == 1 and metadata[0]["imageDigest"] == image, "ECR describe digest")
        response = self.call("ecr", "batch_get_image", registryId=account, repositoryName=repository,
                             imageIds=[{"imageDigest": image}], acceptedMediaTypes=[
                                 "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])
        require(not response.get("failures") and len(response["images"]) == 1, "ECR image readback")
        raw = response["images"][0]["imageManifest"].encode()
        require("sha256:" + sha(raw) == image and sha(raw) == expected["manifest_sha256"], "ECR original manifest bytes")
        manifest = loads(raw)
        media = {"application/vnd.oci.image.manifest.v1+json": ("application/vnd.oci.image.config.v1+json", "application/vnd.oci.image.layer.v1.tar+gzip"),
                 "application/vnd.docker.distribution.manifest.v2+json": ("application/vnd.docker.container.image.v1+json", "application/vnd.docker.image.rootfs.diff.tar.gzip")}
        require(manifest.get("schemaVersion") == 2 and manifest.get("mediaType") in media, "OCI manifest media")
        require(manifest["config"]["digest"] == expected["config_digest"] and 0 < len(manifest["layers"]) <= 128, "OCI config/layers")
        descriptors = [manifest["config"], *manifest["layers"]]
        require([x["digest"] for x in descriptors] == expected["blob_digests"], "OCI promotion blob binding")
        from urllib.request import urlopen
        from urllib.parse import urlparse
        for index, item in enumerate(descriptors):
            guard()
            require(item["mediaType"] == media[manifest["mediaType"]][0 if index == 0 else 1], "OCI descriptor media")
            result = self.call("ecr", "get_download_url_for_layer", registryId=account,
                               repositoryName=repository, layerDigest=item["digest"])
            url = result["downloadUrl"]
            parsed = urlparse(url)
            require(parsed.scheme == "https" and parsed.hostname.endswith(".amazonaws.com"), "ECR blob signed host")
            import hashlib
            def download():
                h = hashlib.sha256()
                size = 0
                config = bytearray()
                with urlopen(url, timeout=20) as response:
                    while chunk := response.read(1024**2):
                        guard()
                        size += len(chunk)
                        require(size <= item["size"], "OCI blob size")
                        h.update(chunk)
                        if index == 0:
                            require(size <= 4 * 1024**2, "OCI config capacity")
                            config.extend(chunk)
                return h, size, config
            h, size, config = bounded(download)
            require(size == item["size"] and "sha256:" + h.hexdigest() == item["digest"], "OCI blob exact bytes")
            if index == 0:
                platform = loads(bytes(config))
                require(platform.get("os") == "linux" and platform.get("architecture") == "amd64", "OCI platform")
        return {"repository_sha256": sha(canonical({k: repo[k] for k in ("registryId", "repositoryName", "repositoryArn", "repositoryUri", "imageTagMutability")})), "image_digest": image,
                "config_digest": expected["config_digest"], "manifest_sha256": sha(raw),
                "blob_digests": [x["digest"] for x in descriptors]}


class S3LeaseStore:
    def __init__(self, aws):
        self.aws = aws

    @property
    def request_id(self):
        return self._request_id

    def deadline(self, expires):
        from tools.cnesdata_delivery.coordination_lease import mapped_deadline
        return mapped_deadline(expires, *self.aws.last_sample, time.time())

    def get(self):
        data, etag = self.aws.get(self.aws.governance["state_bucket"], KEY, maximum=65536, absent=True)
        return (loads(data, canonical=True), etag) if data is not None else (None, None)

    def put(self, value, etag):
        from tools.cnesdata_delivery.contract import utc
        self.cas_requested_at = utc(time.time())
        result = self.aws.put(self.aws.governance["state_bucket"], KEY, canonical(value), etag=etag,
                             key_arn=self.aws.governance["state_kms_key_arn"])
        self.cas_responded_at = utc(time.time())
        self._request_id = self.aws.request_id
        return result
