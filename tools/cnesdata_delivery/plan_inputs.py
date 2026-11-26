"""Keeper-published plan inputs for the plan gate and the application gate."""
import re

from tools.cnesdata_delivery import contract as c, lifecycle_contract as lc
from tools.cnesdata_delivery.session_policy import PLAN_INPUTS_MEMBER as MEMBER, PLAN_INPUTS_PREFIX as PREFIX, plan_step_names as plan_steps

LIMIT = 131072


def step_name(plan_step):
    """Args: plan step name. Returns: the keeper producer step of its inputs."""
    return PREFIX + plan_step


def artifact_name(plan_step, run_id, attempt):
    return f"cnesdata-plan-inputs-{plan_step}-{run_id}-{attempt}"


def index_bytes(owner, *, step, files, source_sha, run, attempt):
    """Args: lease owner binding, plan step, private files, source, run, attempt. Returns: the closed public index bytes."""
    entries = [{"name": name, "size": len(raw), "sha256": c.sha(raw)} for name, raw in sorted(files.items())]
    return c.canonical({"version": 1, "source_sha": source_sha, "run_id": run, "run_attempt": attempt, "step": step_name(step),
                        "owner_sha256": owner["owner_sha256"], "generation": owner["generation"], "files": entries,
                        **lc.application_identity(owner)})


def _consumer_started(api, run, step, guard):
    from tools.cnesdata_delivery.application_gate import _same_run_job
    job = _same_run_job(api, run, kind="plan-inputs-consumer", job_name=step["job_name"], guard=guard)
    c.require(job is not None and job["status"] == "in_progress", "plan_inputs=consumer_not_in_progress")
    return c.instant(job["started_at"])


def _publication(api, run, plan_step, started, now):
    listing = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run['id']}/artifacts?per_page=100&page=1")
    c.require(listing["total_count"] == len(listing["artifacts"]) <= 100, "plan_inputs=publication_inventory")
    name = artifact_name(plan_step, run["id"], run["run_attempt"])
    found = [item for item in listing["artifacts"] if item["name"] == name]
    c.require(len(found) == 1, "plan_inputs=publication_unique")
    c.require(started < c.instant(found[0]["created_at"]) <= now, "plan_inputs=publication_interval")
    return found[0], name


def _public_index(api, run, item, name, now):
    from tools.cnesdata_delivery.provenance import unzip
    path = f"repos/{c.REPOSITORY}/actions/artifacts/{item['id']}"
    metadata = api.read(path)
    c.require(metadata["id"] == item["id"] and metadata["name"] == name and metadata["digest"] == item["digest"]
              and metadata["workflow_run"]["id"] == run["id"] and metadata.get("expired") is False
              and c.instant(metadata["expires_at"]) > now, "plan_inputs=publication_metadata")
    raw = api.read(path + "/zip", raw=True)
    c.require("sha256:" + c.sha(raw) == item["digest"], "plan_inputs=publication_digest")
    return unzip(raw)


def read_plan_inputs(*, api, aws, governance, request, run, step, owner, guard, now):
    """DD-2 consumer rule: the unique keeper artifact of this plan step, created while this plan job runs.

    Args: GitHub reader, private store, governance, request, run, plan step, lease owner, guard, now.
    Returns: the inputs.json bytes. Raises: ValueError plan_inputs=<reason>.
    """
    from tools.cnesdata_delivery.lifecycle_runtime import private_payload
    started = _consumer_started(api, run, step, guard)
    item, name = _publication(api, run, request["step"], started, now)
    public = _public_index(api, run, item, name, now)
    index, files = private_payload(aws, governance, request | {"step": step_name(request["step"])}, run, public, guard=guard)
    c.require(index["step"] == step_name(request["step"]) and index["owner_sha256"] == owner["owner_sha256"]
              and index["generation"] == owner["generation"], "plan_inputs=owner")
    c.require(set(files) == {MEMBER} and 0 < len(files[MEMBER]) <= LIMIT, "plan_inputs=files")
    return files[MEMBER]


def attach(role, payload, origins, **context):
    """Plan gate only: add the keeper inputs.json to the private payload, refusing any other source of that name."""
    if role != "plan":
        return
    c.require(MEMBER not in payload, "ambiguous private payload")
    payload[MEMBER] = read_plan_inputs(**context)
    origins[MEMBER] = step_name(context["request"]["step"])


RESERVED = ("static_promotion", "mode_canary")
BINDING_FIELDS = ("release_id", "run_id", "run_attempt", "generation", "product_source_sha", "shared_source_sha")
PLAN_FIELDS = ("candidate_keys", "rollback_versions", "retire_versions", "multipart_keys")


def _static_request(binding, application_promotion, enabled_until):
    c.require(set(binding) == set(BINDING_FIELDS) and type(application_promotion) is dict
              and type(enabled_until) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", enabled_until),
              "plan_inputs=static_request")
    c.require(type(binding["release_id"]) is str and re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?", binding["release_id"]),
              "plan_inputs=static_release_id")
    for key in ("run_id", "run_attempt", "generation"):
        c.require(type(binding[key]) is int and 1 <= binding[key] <= 2**53 - 1, "plan_inputs=static_binding")
    for key in ("product_source_sha", "shared_source_sha"):
        c.require(type(binding[key]) is str and re.fullmatch(r"[0-9a-f]{40}", binding[key]), "plan_inputs=static_binding")


def static_promotion_input(*, binding, application_promotion, enabled_until, plan, inventory):
    """Parity port of CnesData static_promotion_input (mode operational), pinned by the product-generated vector.

    Returns: the nine-field static_promotion. Raises: ValueError on any binding, window or plan mismatch.
    """
    _static_request(binding, application_promotion, enabled_until)
    record = lc.static_plan(plan, bucket=lc.STATIC_BUCKET)
    c.require(record["inventory_sha256"] == c.sha(inventory), "plan_inputs=static_plan_inventory")
    return {"mode": "operational", "application_promotion": application_promotion,
            "binding": dict(binding) | {"static_plan_sha256": c.sha(plan)}, "inventory_sha256": record["inventory_sha256"],
            "enabled_until": enabled_until, **{name: record[name] for name in PLAN_FIELDS}}


def static_bootstrap_input(*, binding, application_promotion, enabled_until):
    """Parity port of CnesData static_bootstrap_input (mode observer-bootstrap): no plan, no inventory, empty lists."""
    _static_request(binding, application_promotion, enabled_until)
    return {"mode": "observer-bootstrap", "application_promotion": application_promotion,
            "binding": dict(binding) | {"static_plan_sha256": None}, "inventory_sha256": None,
            "enabled_until": enabled_until, **{name: [] for name in PLAN_FIELDS}}


def inputs_bytes(base, static_promotion, mode_canary):
    """Parity port of CnesData 86ce51e8 inputs_bytes: the var-file bytes with both reserved keys explicit."""
    c.require(not any(name in base for name in RESERVED), "inputs=reserved_key")
    raw = c.canonical(base | {"static_promotion": static_promotion, "mode_canary": mode_canary}, 4 * LIMIT)
    c.require(len(raw) <= LIMIT, "inputs=size")
    return raw


BOOTSTRAP_PLAN = "observer-bootstrap-plan"
OPERATIONAL_PLAN = "application-prepare-operational-plan"


def compose(plan_step, base, static_args, extras):
    """The per-plan inputs.json: bootstrap and operational carry a static_promotion, the other plans only the base.

    Args: plan step, base inputs, static_promotion arguments (binding, application_promotion, enabled_until) or None,
    extras (plan, inventory and mode_canary, operational only). Returns: the canonical bytes. Raises: ValueError plan_inputs=compose.
    """
    if plan_step == BOOTSTRAP_PLAN:
        c.require(set(extras) == set() and static_args is not None, "plan_inputs=compose")
        return inputs_bytes(base, static_bootstrap_input(**static_args), None)
    if plan_step == OPERATIONAL_PLAN:
        c.require(set(extras) == {"plan", "inventory", "mode_canary"} and static_args is not None
                  and type(extras["mode_canary"]) is dict, "plan_inputs=compose")
        return inputs_bytes(base, static_promotion_input(**static_args, plan=extras["plan"], inventory=extras["inventory"]),
                            extras["mode_canary"])
    c.require(not extras, "plan_inputs=compose")
    return inputs_bytes(base, None, None)


def require_custody(raw, phase_a_inputs):
    """Every one of the six original Phase A inputs is present in the tfvars and equals the custody value."""
    value = c.loads(raw, canonical=True, limit=LIMIT)
    c.require(type(value) is dict and all(key in value and c.canonical(value[key]) == c.canonical(phase_a_inputs[key])
                                          for key in PHASE_A_KEYS), "plan_inputs=custody")


def publish_plan_inputs(*, keeper, api, run, owner, plan_step, step, raw, phase_a_inputs, credential_limit, clock=None):
    """DD-2 publisher: private inputs.json plus the public index artifact, while the plan job is in progress.

    Args: original keeper, GitHub reader, run, lease owner, plan step, its catalog step, the inputs bytes, Phase A custody inputs, credential limit.
    Returns: the verified upload receipt. Raises: ValueError plan_inputs=<reason> before any write.
    """
    import time
    from tools.cnesdata_delivery import application_gate as gate
    from tools.cnesdata_delivery.lifecycle_runtime import namespace
    c.require(type(raw) is bytes and 0 < len(raw) <= LIMIT, "plan_inputs=files")
    require_custody(raw, phase_a_inputs)
    guard = gate.KeeperGuard(keeper)
    _consumer_started(api, run, step, guard)
    prefix = namespace(keeper.governance, {"source_sha": owner["source_sha"], "step": step_name(plan_step)}, run)
    bucket = keeper.governance["evidence_bucket"]
    guard.check(20)
    keeper.evidence_aws.put(bucket, prefix + MEMBER, raw)
    guard.check(20)
    observed, _ = keeper.evidence_aws.get(bucket, prefix + MEMBER)
    c.require(observed == raw, "plan_inputs=readback")
    index = index_bytes(owner, step=plan_step, files={MEMBER: raw}, source_sha=owner["source_sha"], run=run["id"], attempt=run["run_attempt"])
    return gate._upload_keeper_artifact(keeper, api, run, name=artifact_name(plan_step, run["id"], run["run_attempt"]),
                                        files={"index.json": index}, guard=guard, credential_limit=credential_limit,
                                        clock=clock or time.time)


PHASE_A_KEYS = ("image_digest", "processor_active_unit_task_definition_arn", "processor_retained_unit_task_definition_arns",
                "canary_storage_enabled", "canary_release_id", "canary_trusted_principal_arn")
MODE_CANARY_MEMBER = "mode-canary.json"


def base_inputs(governance, historical):
    """Args: governance, the keeper's Phase A originals. Returns: product_inputs plus the six original Phase A inputs."""
    phase = historical["envelope"]["plan"]["phase_a_inputs"]
    product = governance["product_inputs"]
    c.require(set(phase) == set(PHASE_A_KEYS) and not set(product) & (set(phase) | set(RESERVED)), "plan_inputs=base_collision")
    return product | phase


def mode_canary_source(*, api, run, owner, guard, now):
    """The product-built mode_canary object, from the unique same-run artifact of the static-inventory job (P28*)."""
    from tools.cnesdata_delivery import application_gate as gate
    files = gate._caller_artifact(api, run, owner, job_name=gate.INVENTORY_PROBE, members={MODE_CANARY_MEMBER}, guard=guard, now=now,
                                  name=f"cnesdata-lifecycle-inputs-{owner['run_id']}-{owner['run_attempt']}")
    try:
        value = c.loads(files[MODE_CANARY_MEMBER], canonical=True, limit=LIMIT)
    except ValueError as error:
        raise ValueError("plan_inputs=mode_canary") from error
    c.require(type(value) is dict, "plan_inputs=mode_canary")
    return value
