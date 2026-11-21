"""Measurements over the private phase-inputs namespace: object set, R2 binding and OCI byte integrity."""
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.session_policy import _prefix

NAMES = ("candidate.json", "phase-inputs.json", "promotion.json")
PLATFORM = {"os": "linux", "architecture": "amd64"}
MANIFEST_MEDIA = {"application/vnd.oci.image.manifest.v1+json": ("application/vnd.oci.image.config.v1+json",
                                                                   "application/vnd.oci.image.layer.v1.tar+gzip"),
                  "application/vnd.docker.distribution.manifest.v2+json": (
                      "application/vnd.docker.container.image.v1+json", "application/vnd.docker.image.rootfs.diff.tar.gzip")}


def prefix(config):
    return _prefix(config)


def _namespace_prefix(config, asked):
    reference = asked["payload_reference"]
    return prefix(config) + "phase-inputs/{}/{}/{}/".format(
        c.digest(asked["source_sha"], 40), c.integer(reference["run_id"]), c.integer(reference["run_attempt"]))


def _objects(reader, config, asked):
    base = _namespace_prefix(config, asked)
    keys = reader.list(config["evidence_bucket"], base)
    c.require(keys == [base + name for name in NAMES], "phase input namespace objects")
    objects = {name: reader.read(config["evidence_bucket"], base + name) for name in NAMES}
    public = {item["name"]: item for item in asked["public_objects"]}
    c.require(set(public) == set(NAMES) and all(
        public[name]["sha256"] == c.sha(raw) and public[name]["size"] == len(raw) for name, raw in objects.items()),
        "phase input namespace hash")
    namespace = {"purpose": "phase-inputs", "dedicated": True,
                 "payload_reference_sha256": c.sha(c.canonical(asked["payload_reference"])),
                 "prefix_sha256": c.sha(base.encode())}
    return objects, namespace


def _binding(raw, asked):
    candidate = c.r2_candidate(raw)
    binding = c.canary_binding(candidate, c.sha(raw))
    return {"candidate_sha256": c.sha(raw), "release_id": candidate["release_id"], "canary_id": binding["canary_id"],
            "binding_sha256": binding["binding_sha256"], "creator_workflow_sha": c.digest(asked["creator_workflow_sha"], 40)}


def _repository(reader, config, image):
    account, name = config["account_id"], config["ecr_repository"]
    found = reader.call("ecr", "describe_repositories", registryId=account, repositoryNames=[name])["repositories"]
    c.require(len(found) == 1, "ECR repository singleton")
    repo = found[0]
    c.require(repo["registryId"] == account and repo["repositoryName"] == name
              and repo["repositoryArn"] == f"arn:aws:ecr:us-east-2:{account}:repository/{name}"
              and repo["imageTagMutability"] == "IMMUTABLE", "OCI governed immutable repository")
    ids = [{"imageDigest": image}]
    details = reader.call("ecr", "describe_images", registryId=account, repositoryName=name, imageIds=ids)["imageDetails"]
    c.require(len(details) == 1 and details[0]["imageDigest"] == image, "OCI describe digest")
    return repo, ids


def _manifest(reader, config, promotion):
    image = promotion["image_digest"]
    repo, ids = _repository(reader, config, image)
    response = reader.call("ecr", "batch_get_image", registryId=config["account_id"],
                           repositoryName=config["ecr_repository"], imageIds=ids,
                           acceptedMediaTypes=list(MANIFEST_MEDIA))
    c.require(not response.get("failures") and len(response["images"]) == 1, "OCI image readback")
    raw = response["images"][0]["imageManifest"].encode()
    c.require("sha256:" + c.sha(raw) == image and c.sha(raw) == promotion["manifest_sha256"], "OCI original manifest bytes")
    return repo, raw


def _blobs(reader, config, manifest, promotion):
    media = MANIFEST_MEDIA[manifest["mediaType"]]
    descriptors = [manifest["config"], *manifest["layers"]]
    c.require(manifest.get("schemaVersion") == 2 and 0 < len(manifest["layers"]) <= 128
              and manifest["config"]["digest"] == promotion["config_digest"]
              and [item["digest"] for item in descriptors] == promotion["blob_digests"], "OCI promotion blob binding")
    for index, item in enumerate(descriptors):
        c.require(item["mediaType"] == media[0 if index == 0 else 1], "OCI descriptor media")
        facts = reader.blob(config["ecr_repository"], item["digest"], index == 0)
        c.require("sha256:" + facts["sha256"] == item["digest"] and facts["size"] == item["size"], "OCI blob exact bytes")
        if index == 0:
            platform = c.loads(facts["body"])
            c.require(platform.get("os") == PLATFORM["os"] and platform.get("architecture") == PLATFORM["architecture"],
                      "OCI platform")


def _oci(reader, config, raw, key):
    promotion = c.loads(raw, canonical=True)
    repo, manifest_raw = _manifest(reader, config, promotion)
    _blobs(reader, config, c.loads(manifest_raw), promotion)
    facts = {name: repo[name] for name in ("registryId", "repositoryName", "repositoryArn", "repositoryUri",
                                           "imageTagMutability")}
    return {"repository_hmac": c.report_hmac(key, "repository", c.canonical(facts)),
            "image_digest": promotion["image_digest"], "config_digest": promotion["config_digest"],
            "manifest_sha256": promotion["manifest_sha256"],
            "blob_digests_sha256": c.sha(c.canonical(promotion["blob_digests"])), "platform": "linux/amd64"}


def measure(reader, config, asked, key):
    """Args: reader, config, request, key bytes. Returns: namespace, R2 and OCI observations. Raises: ValueError."""
    objects, namespace = _objects(reader, config, asked)
    return {"phase_input_namespace": namespace, "r2-candidate-a2-binding": _binding(objects["candidate.json"], asked),
            "oci-promotion-byte-integrity": _oci(reader, config, objects["promotion.json"], key)}
