"""Fake AWS read boundary for the producers; every value is synthetic."""
import copy
import json

from fixtures.cnesdata_phase_a_replay import ACCOUNT, KEY
from tools.cnesdata_delivery import contract as c

SOURCE = "a" * 40
RUN, ATTEMPT = 7001, 1
OBSERVED = "2026-11-20T12:00:00Z"
KEY_HEX = "5a" * 32
EVIDENCE = "cnesdata/prod/evidence/"
OWNER = {"repository": "VINIClUS/infra-ansible", "workflow_path": ".github/workflows/cnesdata-producers.yml",
         "workflow_sha": "9" * 40}
PAYLOAD_REFERENCE = {"repository": c.REPOSITORY, "run_id": RUN, "run_attempt": ATTEMPT, "artifact_id": 4242,
                     "artifact_digest": "sha256:" + "4" * 64, "workflow_path": ".github/workflows/phase-a-prepare.yml",
                     "workflow_sha": "8" * 40, "source_sha": SOURCE}


def config():
    account = ACCOUNT
    roles = {role: f"arn:aws:iam::{account}:role/cnesdata-infra-{role}" for role in ("plan", "deploy")}
    return {"account_id": account, "roles": roles, "state_bucket": "cnesdata-state-4f6e21",
            "evidence_bucket": "cnesdata-evid-4f6e21", "evidence_prefix": EVIDENCE, "ecr_repository": "cnesdata-ecr-9b2d71"}


class FakeReader:
    def __init__(self, objects, responses, blobs=None):
        self.objects, self.responses, self.blobs = objects, responses, blobs or {}
        self.calls, self.reads = [], []

    def call(self, service, operation, **parameters):
        self.calls.append((service, operation))
        found = self.responses[operation, json.dumps(parameters, sort_keys=True)]
        return copy.deepcopy(found)

    def read(self, bucket, key, maximum=128 * 1024**2):
        self.reads.append((bucket, key))
        if (bucket, key) not in self.objects:
            raise KeyError("absent")
        return self.objects[bucket, key]

    def list(self, bucket, prefix):
        return sorted(key for name, key in self.objects if name == bucket and key.startswith(prefix))

    def blob(self, repository, digest, keep):
        data = self.blobs[digest]
        return {"sha256": c.sha(data), "size": len(data), "body": data if keep else None}


def promotion(chain):
    manifest = c.loads(chain.manifest)
    value = {"image_digest": chain.gov["release"]["image_digest"], "manifest_sha256": c.sha(chain.manifest),
             "config_digest": manifest["config"]["digest"],
             "blob_digests": [manifest["config"]["digest"]] + [item["digest"] for item in manifest["layers"]]}
    assert c.sha(c.canonical(value)) == chain.gov["promotion_sha256"]
    return value


def ecr_responses(chain, settings):
    account, name = settings["account_id"], settings["ecr_repository"]
    digest = chain.gov["release"]["image_digest"]
    ids = [{"imageDigest": digest}]
    accepted = ["application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"]

    def key(operation, **parameters):
        return operation, json.dumps(parameters, sort_keys=True)

    repository = {"registryId": account, "repositoryName": name,
                  "repositoryArn": f"arn:aws:ecr:us-east-2:{account}:repository/{name}",
                  "repositoryUri": f"{account}.dkr.ecr.us-east-2.amazonaws.com/{name}",
                  "imageTagMutability": "IMMUTABLE"}
    return {key("describe_repositories", registryId=account, repositoryNames=[name]): {"repositories": [repository]},
            key("describe_images", registryId=account, repositoryName=name, imageIds=ids):
                {"imageDetails": [{"imageDigest": digest}]},
            key("batch_get_image", registryId=account, repositoryName=name, imageIds=ids, acceptedMediaTypes=accepted):
                {"images": [{"imageManifest": chain.manifest.decode()}], "failures": []}}


def namespace_prefix(settings):
    return settings["evidence_prefix"] + f"phase-inputs/{SOURCE}/{RUN}/{ATTEMPT}/"


def request(**changes):
    value = {"purpose": "phase-a", "role": "plan", "source_sha": SOURCE, "observed_at": OBSERVED,
             "payload_reference": PAYLOAD_REFERENCE, "root_source_sha": "d" * 40, "owner_producer": OWNER,
             "creator_workflow_sha": "7" * 40, "public_objects": []}
    return value | changes


def policy_responses(settings, role, document):
    arn = f"arn:aws:iam::{settings['account_id']}:policy/cnesdata-infra-{role}-session"
    return {("get_policy", json.dumps({"PolicyArn": arn}, sort_keys=True)): {"Policy": {
                "Arn": arn, "PolicyName": arn.rsplit("/", 1)[1], "DefaultVersionId": "v3", "AttachmentCount": 0,
                "PermissionsBoundaryUsageCount": 0}},
            ("get_policy_version", json.dumps({"PolicyArn": arn, "VersionId": "v3"}, sort_keys=True)): {
                "PolicyVersion": {"VersionId": "v3", "IsDefaultVersion": True, "Document": document}}}


def world(chain, settings=None, *, phase_inputs=True):
    settings = settings or config()
    objects = {(settings["state_bucket"], KEY): c.canonical(chain.prior),
               (settings["evidence_bucket"], settings["evidence_prefix"] + "phase-inputs/rehearsal/plan.json"):
                   c.canonical(chain.replay.plan)}
    names = {"phase-inputs.json": c.canonical(chain.gov["phase_a_inputs"]),
             "candidate.json": c.canonical({"repository": c.REPOSITORY, "source_sha": SOURCE, "release_id": "fixture"})}
    names["promotion.json"] = c.canonical(promotion(chain))
    prefix = namespace_prefix(settings)
    if phase_inputs:
        for name, raw in names.items():
            objects[settings["evidence_bucket"], prefix + name] = raw
    responses = dict(chain.responses["before"] and {
        (op, params): doc for (op, params), doc in chain.responses["before"].items()})
    document = {"Version": "2012-10-17", "Statement": []}
    for role in ("plan", "deploy"):
        responses |= policy_responses(settings, role, document)
    responses |= ecr_responses(chain, settings)
    return FakeReader(objects, responses, chain.blobs), names, document


def public_objects(names):
    return [{"name": name, "sha256": c.sha(raw), "size": len(raw)} for name, raw in sorted(names.items())]
