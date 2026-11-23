"""Authenticated inputs of the keeper inventory and publish-static operations (#55, P15b)."""
import io
import tarfile

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.provenance import unzip

INVENTORY_SCHEMA = "cnesdata.static-inventory/v1"
INVENTORY_FIELDS = ("schema candidate_sha256 dashboard_sha256 baseline outcome upload_order already_published retire "
                    "retire_latest rollback_versions multipart_keys projected_bytes")
BASELINE_SCHEMA = "cnesdata.static-baseline/v1"
DASHBOARD_ARTIFACT = "production-dashboard"
DASHBOARD_PIN_FIELDS = "id sha256 expires_at source_sha run_id run_attempt"
MANIFEST_MEMBER = "release-manifest.json"
JSON_LIMIT = 1024**2


def authenticated_candidate(raw, governance):
    """R2 candidate whose bytes are the governance release candidate_sha256.

    Returns: the decoded candidate. Raises: ValueError static_inputs=candidate_digest.
    """
    c.require(type(raw) is bytes and c.sha(raw) == governance["release"]["candidate_sha256"],
              "static_inputs=candidate_digest")
    value = c.r2_candidate(raw)
    c.require(type(value) is dict, "static_inputs=candidate_digest")
    return value


def _dashboard_pin(candidate):
    artifacts = candidate.get("artifacts")
    pin = artifacts.get(DASHBOARD_ARTIFACT) if type(artifacts) is dict else None
    c.require(type(pin) is dict and set(pin) == set(DASHBOARD_PIN_FIELDS.split()) and type(pin["id"]) is int
              and type(pin["run_id"]) is int and type(pin["sha256"]) is str and pin["source_sha"] == candidate.get("source_sha"),
              "static_inputs=dashboard_artifact")
    return pin


def dashboard_artifact(api, candidate, *, guard, now):
    """dist.tar of the production-dashboard artifact the candidate pins: id, run, digest, expiry and dist digest.

    Returns: the dist.tar bytes. Raises: ValueError static_inputs=dashboard_artifact or static_inputs=dashboard_sha256.
    """
    pin = _dashboard_pin(candidate)
    path = f"repos/{c.REPOSITORY}/actions/artifacts/{pin['id']}"
    guard.check(20)
    metadata = api.read(path)
    guard.check()
    run = metadata.get("workflow_run") if type(metadata) is dict else None
    c.require(type(run) is dict and metadata.get("id") == pin["id"] and metadata.get("name") == DASHBOARD_ARTIFACT
              and metadata.get("digest") == "sha256:" + pin["sha256"] and metadata.get("expired") is False
              and run.get("id") == pin["run_id"] and run.get("head_sha") == pin["source_sha"]
              and c.instant(metadata["expires_at"]) > now, "static_inputs=dashboard_artifact")
    guard.check(20)
    raw = api.read(path + "/zip", raw=True)
    guard.check()
    c.require(type(raw) is bytes and c.sha(raw) == pin["sha256"], "static_inputs=dashboard_artifact")
    dist = unzip(raw).get("dist.tar")
    c.require(type(dist) is bytes and c.sha(dist) == candidate.get("dashboard_sha256"), "static_inputs=dashboard_sha256")
    return dist


def _manifest(raw):
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        found = [member for member in archive.getmembers() if member.name.removeprefix("./") == MANIFEST_MEMBER]
        c.require(len(found) == 1 and found[0].isfile() and found[0].size <= JSON_LIMIT, "static_inputs=archive_binding")
        handle = archive.extractfile(found[0])
        c.require(handle is not None, "static_inputs=archive_binding")
        return c.loads(handle.read(), limit=JSON_LIMIT)


def archive_bytes(raw, candidate):
    """Product archive whose release-manifest.json names the candidate source_sha and release_id.

    Returns: the archive bytes. Raises: ValueError static_inputs=archive_binding.
    """
    try:
        manifest = _manifest(raw) if type(raw) is bytes else None
    except (OSError, EOFError, ValueError, tarfile.TarError) as error:
        raise ValueError("static_inputs=archive_binding") from error
    c.require(type(manifest) is dict and manifest.get("source_sha") == candidate.get("source_sha")
              and manifest.get("static_release") == candidate.get("release_id"), "static_inputs=archive_binding")
    return raw


def baseline_bytes(raw):
    """Canonical cnesdata.static-baseline/v1 object with the closed current/prior fields.

    Returns: the baseline bytes. Raises: ValueError static_inputs=baseline.
    """
    try:
        value = c.loads(raw, canonical=True, limit=JSON_LIMIT)
    except ValueError as error:
        raise ValueError("static_inputs=baseline") from error
    c.require(type(value) is dict and set(value) == {"schema", "current", "prior"} and value["schema"] == BASELINE_SCHEMA,
              "static_inputs=baseline")
    return raw


def static_plan_bytes(raw, *, binding, inventory):
    """Static plan whose digest is the carrier binding and whose inventory digest is the keeper inventory.

    Returns: the plan bytes. Raises: ValueError static_inputs=static_plan_binding or static_plan_inventory.
    """
    c.require(type(raw) is bytes and c.sha(raw) == binding["static_plan_sha256"], "static_inputs=static_plan_binding")
    plan = lc.static_plan(raw, bucket=lc.STATIC_BUCKET)
    c.require(type(inventory) is bytes and plan["inventory_sha256"] == c.sha(inventory), "static_inputs=static_plan_inventory")
    return raw


def carrier_binding(terraform):
    """static_promotion.binding of the authenticated operational inputs (canonical tfvars JSON).

    Returns: the closed #498 binding. Raises: ValueError static_binding=carrier_absent.
    """
    try:
        value = c.loads(terraform, canonical=True, limit=JSON_LIMIT)
    except ValueError as error:
        raise ValueError("static_binding=carrier_absent") from error
    promotion = value.get("static_promotion") if type(value) is dict else None
    binding = promotion.get("binding") if type(promotion) is dict else None
    c.require(type(binding) is dict and set(binding) == set(lc.STATIC_BINDING_FIELDS.split()), "static_binding=carrier_absent")
    return binding


def compare_binding(binding, carrier):
    """Field-by-field equality of the recomputed binding and the carrier, in the #498 field order.

    Raises: ValueError static_binding=carrier_mismatch field=<name>.
    """
    for field in lc.STATIC_BINDING_FIELDS.split():
        c.require(binding[field] == carrier[field], f"static_binding=carrier_mismatch field={field}")


def tar_member(tar_raw, reference):
    """Bytes of the dist.tar member that the PutObject reference names, checked against its size and sha256.

    Returns: the member bytes. Raises: ValueError static_body=member_absent or static_body=member_digest.
    """
    key = reference["member"]
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode="r:") as archive:
        found = [member for member in archive.getmembers() if member.isfile() and member.name.removeprefix("./") == key]
        c.require(len(found) == 1, f"static_body=member_absent key={key}")
        c.require(found[0].size == reference["size"], f"static_body=member_digest key={key}")
        handle = archive.extractfile(found[0])
        raw = handle.read() if handle is not None else None
    c.require(type(raw) is bytes and len(raw) == reference["size"] and c.sha(raw) == reference["sha256"],
              f"static_body=member_digest key={key}")
    return raw


def inventory_observation(raw, inputs):
    """The single inventory observation, canonical, bound to the candidate, dist.tar and baseline it read.

    Returns: the observation bytes. Raises: ValueError static_inputs=inventory_observation.
    """
    try:
        value = c.loads(raw, canonical=True, limit=JSON_LIMIT)
        baseline = c.loads(inputs["static-baseline"], canonical=True, limit=JSON_LIMIT)
    except ValueError as error:
        raise ValueError("static_inputs=inventory_observation") from error
    c.require(type(value) is dict and set(value) == set(INVENTORY_FIELDS.split()) and value["schema"] == INVENTORY_SCHEMA
              and value["candidate_sha256"] == c.sha(inputs["candidate"])
              and value["dashboard_sha256"] == c.sha(inputs["dashboard-artifact"])
              and c.canonical(value["baseline"]) == c.canonical(baseline), "static_inputs=inventory_observation")
    return raw
