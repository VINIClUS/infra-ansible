"""Application governance producers, each checked by the gate's own consumer before it is emitted."""
import copy
import re

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery import provenance
from tools.cnesdata_delivery import session_policy
from tools.cnesdata_delivery.producers import governance_assembly

STEP_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")
SAME_PRODUCT_ARN = re.compile(r"arn:aws:(?:states|scheduler|events|cloudwatch):us-east-2:\d{12}:[A-Za-z0-9_./:-]+")
ACTIVATION_REFERENCE = "ext2_post_upload_receipt_v1"
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
COMMON = "role purpose job_name producer_job admission_steps input_jobs"
INFRA = COMMON + " mode direction"
OPTIONAL = ("historical_entry", "activation_selection", "delete_resources")
ROLES = ("plan", "deploy", "audit", "application")
PIECES = frozenset("""
    lifecycle_steps_sha256 source_closure_sha256 lifecycle_predecessor predecessor_read application_configuration
    application_fragment application_delegations application_coordination_policy release
""".split())


def _objects(governance, selector, objects):
    names = [key.rsplit("/", 1)[1] for key in session_policy.predecessor_keys(governance, selector)]
    c.require(type(objects) is dict and set(objects) == set(names), f"predecessor objects count={len(objects)}")
    return [{"name": name, "sha256": c.sha(objects[name]), "size": len(objects[name])} for name in names]


def _publication(api, governance, selector, publication):
    from tools.cnesdata_delivery import runtime
    legacy = selector["protocol"] == "legacy-infra"
    c.require(legacy == (publication is None), f"predecessor publication protocol={selector['protocol']}")
    if not legacy:
        return c.closed(copy.deepcopy(publication), "artifact_id artifact_digest")
    _, _, receipt, _ = runtime._published_receipt(api, governance, selector["run_id"], selector["run_attempt"])
    return {"artifact_id": receipt["index_artifact_id"], "artifact_digest": receipt["index_artifact_digest"]}


def _lease(lease, selector, checkpoint):
    c.require(lease["status"] == "released", f"predecessor lease status={lease['status']}")
    c.require(lease["repository"] == c.REPOSITORY, f"predecessor lease repository={lease['repository']}")
    run = (lease["run_id"], lease["run_attempt"])
    c.require(run == (selector["run_id"], selector["run_attempt"]), f"predecessor lease run={run[0]}/{run[1]}")
    c.require(lease["checkpoint_sha256"] == checkpoint, "predecessor lease checkpoint")


def predecessor(api, governance, selector, *, lease, job, objects, publication=None):
    """Args: GitHub API, governance, selector, keyword lease, job {id, name}, private objects, lifecycle publication.

    Returns: predecessor_read and lifecycle_predecessor. Raises: ValueError when authenticate_predecessor refuses.
    """
    from tools.cnesdata_delivery import lifecycle_runtime
    entries = _objects(governance, selector, objects)
    checkpoint = c.sha(objects["checkpoint.json"])
    _lease(lease, selector, checkpoint)
    found = _publication(api, governance, selector, publication)
    reference = {"predecessor_version": 1, "protocol": selector["protocol"], "repository": c.REPOSITORY,
                 "source_sha": selector["source_sha"], "run_id": selector["run_id"],
                 "run_attempt": selector["run_attempt"], "owner_sha256": c.sha(lease["owner"].encode()),
                 "generation": lease.get("generation"), "session_sha256": lease["session_sha256"],
                 "checkpoint_sha256": checkpoint, "artifact_id": found["artifact_id"],
                 "artifact_digest": found["artifact_digest"], "producer_job_id": job["id"],
                 "producer_name": job["name"], "objects": entries}
    value = {"predecessor_read": copy.deepcopy(selector), "lifecycle_predecessor": reference}
    lifecycle_runtime.authenticate_predecessor(api, governance | value)
    return value


def application_section(governance, *, configuration, fragment, coordination_policy, now):
    """Args: governance, keyword tofu input configuration, tofu outputs fragment and coordination policy, now.

    Returns: the four application_* governance keys. Raises: ValueError when the session consumers refuse.
    """
    from tools.cnesdata_delivery import session_owner
    section = {"application_configuration": session_owner.application_configuration(configuration,
                                                                                    governance["account_id"]),
               "application_fragment": c.loads(c.canonical(fragment, limit=65536), canonical=True, limit=65536),
               "application_delegations": copy.deepcopy(fragment["delegations"]),
               "application_coordination_policy": coordination_policy}
    merged = governance | section
    accepted = session_owner.application_fragment(merged, now)
    session_owner.application_identity_document(merged, accepted)
    return section


def release(candidate_raw, image_digest):
    """Args: R2 candidate bytes, image digest. Returns: the closed six-field release. Raises: ValueError."""
    candidate = c.r2_candidate(candidate_raw)
    c.require(candidate.get("repository") == c.REPOSITORY, "release candidate repository")
    c.require(type(image_digest) is str and IMAGE_DIGEST.fullmatch(image_digest) is not None, "release image digest")
    binding = c.canary_binding(candidate, c.sha(candidate_raw))
    return {"release_id": binding["release_id"], "source_sha": c.digest(binding["source_sha"], 40),
            "candidate_sha256": binding["candidate_sha256"], "canary_id": binding["canary_id"],
            "binding_sha256": binding["binding_sha256"], "image_digest": image_digest}


def application_release(value, envelope_raw):
    """Args: release, original Phase A envelope bytes. Returns: the release. Raises: ValueError on any difference."""
    envelope = c.loads(envelope_raw, canonical=True, limit=131072)
    c.require(c.canonical(envelope["plan"]["release"]) == c.canonical(value), "release differs phase a plan release")
    return copy.deepcopy(value)


def caller_binding(governance, run):
    """Args: governance, run {head_sha, id, run_attempt}. Returns: binding and its sha256. Raises: ValueError."""
    purpose = governance["application_purpose"]
    c.require(purpose in lc.APPLICATION_CONTEXTS, f"application purpose={purpose}")
    producer = {"workflow_sha": governance["gate_shas"]["application"],
                "source_closure_sha256": governance["application_source_closure_sha256"]}
    binding = lc.application_caller_binding({
        "application_purpose": purpose, "context_kind": lc.APPLICATION_CONTEXTS[purpose],
        **lc.APPLICATION_CALLERS[purpose], "source_sha": run["head_sha"], "run_id": run["id"],
        "run_attempt": run["run_attempt"], "producer_workflow_sha": producer["workflow_sha"],
        "producer_source_closure_sha256": producer["source_closure_sha256"], "event": "workflow_dispatch",
        "fragment_version": 4}, producer)
    return binding, c.sha(c.canonical(binding))


def _payload(reference):
    c.closed(reference, "artifact_id artifact_digest job_id")
    c.integer(reference["artifact_id"])
    c.integer(reference["job_id"])
    digest = reference["artifact_digest"]
    c.require(type(digest) is str and digest == "sha256:" + c.digest(digest.removeprefix("sha256:")),
              "payload artifact digest")


def descriptor(binding_sha256, *, source_sha, step, payloads, purpose):
    """Args: caller binding sha256, keyword source_sha, step, payloads, purpose. Returns: bytes and sha256."""
    c.require(type(step) is str and STEP_NAME.fullmatch(step) is not None, "descriptor step")
    c.require(purpose in lc.APPLICATION_CONTEXTS and type(payloads) is dict, "descriptor purpose/payloads")
    for name, reference in payloads.items():
        c.require(type(name) is str and STEP_NAME.fullmatch(name) is not None, "descriptor payload name")
        _payload(reference)
    raw = c.canonical({"schema_version": 1, "repository": c.REPOSITORY, "source_sha": c.digest(source_sha, 40),
                       "step": step, "payloads": payloads, "application_purpose": purpose,
                       "caller_binding_sha256": c.digest(binding_sha256)}, limit=65536)
    return raw, c.sha(raw)


def _admission_steps(names):
    c.require(type(names) is list and 1 <= len(names) <= 4 and len(set(names)) == len(names)
              and all(type(name) is str and 1 <= len(name) <= 128 for name in names), "step admission steps")


def _input_jobs(value):
    c.require(type(value) is dict and len(value) <= 8, "step input jobs")
    for name, producer in value.items():
        c.closed(producer, "name step")
        c.require(STEP_NAME.fullmatch(name) is not None and STEP_NAME.fullmatch(producer["step"]) is not None
                  and type(producer["name"]) is str and 1 <= len(producer["name"]) <= 256, "step input job")


def _historical_entry(value):
    if "historical_entry" in value:
        c.require(value["historical_entry"] is True and value["role"] in {"plan", "deploy"}
                  and value["purpose"] == "application-prepare" and value["direction"] == "advance",
                  "step historical entry")


def _activation_selection(value):
    operational = (value["role"], value["mode"]) == ("plan", "operational")
    c.require(not operational or "activation_selection" in value, "step activation selection")
    if "activation_selection" in value:
        selection = value["activation_selection"]
        c.require(type(selection) is dict and set(selection) == {"selection_version", ACTIVATION_REFERENCE}
                  and type(selection["selection_version"]) is int and selection["selection_version"] == 1
                  and type(selection[ACTIVATION_REFERENCE]) is dict, "step activation selection")


def _delete_resources(value):
    inventory = value.get("delete_resources")
    if value["direction"] == "advance" or value["role"] == "plan":
        c.require(inventory is None and "delete_resources" not in value, "step delete resources")
        return
    c.require(type(inventory) is list and 1 <= len(inventory) <= 8 and len(set(inventory)) == len(inventory)
              and all(type(arn) is str and SAME_PRODUCT_ARN.fullmatch(arn) and "cnesdata-prod" in arn
                      for arn in inventory), "step delete resources")


def _infra(value):
    c.require(type(value["mode"]) is str and STEP_NAME.fullmatch(value["mode"]) is not None
              and value["direction"] in {"advance", "converge"}, "step mode/direction")
    _historical_entry(value)
    _activation_selection(value)
    _delete_resources(value)


def step(role, purpose, *, job_name, producer_job, admission_steps, input_jobs=None, **infra):
    """Args: role, purpose, keyword job fields, input jobs, infra mode/direction/options. Returns: one step."""
    c.require(role in ROLES and (purpose in lc.PURPOSES or (role, purpose) == ("application", "application-prepare")),
              f"step role={role} purpose={purpose}")
    value = {"role": role, "purpose": purpose, "job_name": job_name, "producer_job": producer_job,
             "admission_steps": copy.deepcopy(admission_steps), "input_jobs": copy.deepcopy(input_jobs or {})}
    return value | copy.deepcopy(infra)


def _validate_step(value):
    infra = value.get("role") != "application"
    c.closed(value, (INFRA if infra else COMMON) + "".join(" " + key for key in OPTIONAL if infra and key in value))
    c.require(value["role"] in ROLES and (value["purpose"] in lc.PURPOSES or not infra), "step role/purpose")
    c.require(value["purpose"] == "application-prepare" or infra, "application step purpose")
    c.require(type(value["job_name"]) is str and 1 <= len(value["job_name"]) <= 256
              and STEP_NAME.fullmatch(value["producer_job"]) is not None, "step job")
    _admission_steps(value["admission_steps"])
    _input_jobs(value["input_jobs"])
    if infra:
        _infra(value)


def _cross(steps):
    names = [item["job_name"] for item in steps.values()]
    c.require(len(set(names)) == len(names), "catalog job names unique")
    for item in steps.values():
        for producer in item["input_jobs"].values():
            c.require(producer["step"] in steps and steps[producer["step"]]["job_name"] == producer["name"],
                      f"catalog input step={producer['step']}")
    phase_b = [name for name, item in steps.items()
               if (item["role"], item["purpose"], item.get("direction")) == ("deploy", "phase-b", "advance")]
    c.require(len(phase_b) == 1, f"catalog phase-b advance count={len(phase_b)}")
    fence = lc.FENCE_PREPARE_PRODUCER
    shape = ("deploy", fence["purpose"], fence["mode"])
    prepared = [name for name, item in steps.items() if (item["role"], item["purpose"], item.get("mode")) == shape]
    named = all(steps[name]["job_name"] == fence["job_name"] for name in prepared)
    c.require(prepared in ([], [fence["step"]]) and named, "catalog fence prepare producer")
    if fence["step"] in steps:
        c.require(prepared == [fence["step"]], "catalog fence prepare producer")
        c.require(steps[fence["step"]]["direction"] == fence["direction"], "catalog fence prepare delta")


def catalog(steps):
    """Args: {step name: step}. Returns: the lifecycle_steps catalog. Raises: ValueError on any refused step."""
    c.require(type(steps) is dict and 1 <= len(steps) <= 256, "finite lifecycle catalog")
    for name, value in steps.items():
        c.require(type(name) is str and STEP_NAME.fullmatch(name) is not None, "catalog step name")
        _validate_step(value)
    _cross(steps)
    return c.loads(c.canonical(steps), canonical=True)


def catalog_member(steps):
    """Args: {step name: step}. Returns: canonical catalog member bytes and its governance reference."""
    raw = c.canonical(catalog(steps), limit=provenance.LIFECYCLE_STEPS_LIMIT)
    return raw, {"lifecycle_steps_sha256": c.sha(raw)}


def source_closure_reference(manifest):
    """Args: product source manifest. Returns: the source_closure_sha256 reference the gate recomputes."""
    return {"source_closure_sha256": c.sha(c.canonical(provenance.source_closure(manifest)))}


def document(base, pieces, catalog_raw):
    """Args: base governance, application pieces, catalog member bytes. Returns: the document. Raises: ValueError.

    New governed keys enter through governance_assembly.GOVERNANCE_KEYS, never through this function.
    """
    from tools.cnesdata_delivery import application_gate, lifecycle_runtime
    c.require(PIECES <= set(pieces), f"application pieces missing count={len(PIECES - set(pieces))}")
    merged = copy.deepcopy(base) | copy.deepcopy(pieces)
    for key in merged:
        c.require(key in governance_assembly.GOVERNANCE_KEYS, f"governance key={key}")
    c.require("application_product_source_manifest" not in merged, "inline product source manifest")
    purpose = merged["application_purpose"]
    c.require(purpose in lc.APPLICATION_CONTEXTS and merged["context_kind"] == lc.APPLICATION_CONTEXTS[purpose],
              f"application purpose={purpose} context={merged['context_kind']}")
    application_gate.application_release_sha256(merged)
    lifecycle_runtime.validate_predecessor_reference(merged)
    governance_assembly.references(merged)
    c.require(type(catalog_raw) is bytes and c.sha(catalog_raw) == merged["lifecycle_steps_sha256"],
              "lifecycle steps member")
    catalog_member(c.loads(catalog_raw, canonical=True, limit=provenance.LIFECYCLE_STEPS_LIMIT))
    return merged
