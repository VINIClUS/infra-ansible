"""Closed lifecycle oracles; authority is authenticated by lifecycle_runtime.

The legacy plan/apply envelopes and 1980-second initial admission remain separate.
No credentials, network, caller commands or lifecycle side effects in this module.
"""
import base64
import hashlib
import time
import re

from tools.cnesdata_delivery import contract as c

APPLICATION_CONTEXTS = {"promotion": "promotion", "mode-readiness-drill": "readiness"}
APPLICATION_CALLERS = {
    purpose: {"repository": c.REPOSITORY, "workflow_path": ".github/workflows/" + workflow,
              "ref": "refs/heads/main", "environment": "production"}
    for purpose, workflow in (("promotion", "promote-production.yml"),
                              ("mode-readiness-drill", "readiness-production.yml"))
}
APPLICATION_DELEGATIONS = {
    "observer": "static-observer", "normal": "static-normal", "recovery": "static-recovery",
    "seeder": "canary-seeder", "verifier": "canary-verifier", "fence_operator": "promotion-fence-operator",
    "mode_seed": "mode-seed", "mode_dispatch": "mode-dispatch",
    "mode_audit_launch": "mode-audit-launch", "mode_observe": "mode-observe",
}


def phase_a_originals(carrier):
    """Decode private historical bytes; current provenance/custody is separate.

    Historical timestamps remain original evidence. They are never compared to
    a new wall clock or reissued as a current credential/freeze observation.
    """
    import base64
    from tools.cnesdata_delivery.runtime import verify_drift_evidence
    c.closed(carrier, "carrier_version origin files")
    c.require(type(carrier["carrier_version"]) is int and carrier["carrier_version"] == 1,
              "Phase A carrier version")
    c.canonical(carrier, limit=196608)
    origin = carrier["origin"]
    c.closed(origin, "predecessor_version protocol repository source_sha run_id run_attempt owner_sha256 generation "
             "session_sha256 checkpoint_sha256 artifact_id artifact_digest producer_job_id producer_name objects")
    c.require(type(origin["predecessor_version"]) is int and origin["predecessor_version"] == 1
              and origin["protocol"] == "legacy-infra" and origin["repository"] == c.REPOSITORY,
              "Phase A original legacy custody")
    c.digest(origin["source_sha"], 40)
    for key in ("run_id", "run_attempt", "artifact_id", "producer_job_id"):
        c.integer(origin[key])
    if origin["generation"] is not None:
        c.integer(origin["generation"])
    for key in ("owner_sha256", "session_sha256", "checkpoint_sha256"):
        c.digest(origin[key])
    c.require(origin["artifact_digest"] == "sha256:" + c.digest(origin["artifact_digest"].removeprefix("sha256:"))
              and type(origin["producer_name"]) is str and 1 <= len(origin["producer_name"]) <= 256,
              "Phase A original artifact/job")
    objects = origin["objects"]
    names = {"envelope.json", "checkpoint.json", "drift.json", "lease.json", "ecr-before.json"}
    c.require(type(objects) is list and len(objects) == len(names)
              and {item["name"] for item in objects} == names, "Phase A full original H4 inventory")
    indexed = {}
    for item in objects:
        c.closed(item, "name sha256 size")
        c.digest(item["sha256"])
        c.integer(item["size"], 1, 262144)
        indexed[item["name"]] = item
    entries = carrier["files"]
    c.require(type(entries) is list and [item["name"] for item in entries] ==
              ["checkpoint.json", "drift.json", "envelope.json"], "Phase A exact sorted raw inventory")
    raw, total = {}, 0
    for entry in entries:
        c.closed(entry, "name sha256 size bytes_base64")
        c.integer(entry["size"], 1, 131072)
        c.require(type(entry["bytes_base64"]) is str, "Phase A base64 string")
        body = base64.b64decode(entry["bytes_base64"], validate=True)
        total += len(body)
        c.require(total <= 131072 and len(body) == entry["size"] and c.sha(body) == c.digest(entry["sha256"])
                  and {key: entry[key] for key in ("name", "sha256", "size")} == indexed[entry["name"]]
                  and base64.b64encode(body).decode() == entry["bytes_base64"], "Phase A exact original raw bytes")
        raw[entry["name"]] = body
    envelope, checkpoint, drift = (c.loads(raw[name], canonical=True, limit=131072)
                                  for name in ("envelope.json", "checkpoint.json", "drift.json"))
    def private(value):
        if type(value) is dict:
            for key, item in value.items():
                c.require(key.lower().replace("_", "").replace("-", "") not in {
                    "credentials", "accesskeyid", "secretaccesskey", "sessiontoken", "accesstoken", "password",
                    "privatekey", "authorization", "statejson", "terraformstate"}, "Phase A secret/raw state")
                private(item)
        elif type(value) is list:
            for item in value:
                private(item)
        elif type(value) is str:
            c.require(not re.search(r"BEGIN (?:RSA |EC )?PRIVATE KEY|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", value),
                      "Phase A secret value")
    for value in (envelope, checkpoint, drift):
        c._secrets(value)
        private(value)
    c.closed(envelope, "schema_version status plan apply plan_binding_sha256")
    c.require(type(envelope["schema_version"]) is int and envelope["schema_version"] == 1
              and envelope["status"] == "applied", "Phase A original applied envelope")
    plan = c.closed(envelope["plan"], "repository source_sha producer package purpose created_at expires_at binary_sha256 json_sha256 "
        "inputs_sha256 dependencies toolchain backend state_before policy cost drift release phase_a_inputs")
    applied = c.closed(envelope["apply"], "producer consumed_plan_artifact plan_binding_sha256 started_at completed_at result lease principal state_after drift outputs")
    c.require(plan["repository"] == origin["repository"] and plan["source_sha"] == origin["source_sha"]
              and plan["purpose"] == "phase-a" and applied["result"] == "success"
              and applied["plan_binding_sha256"] == envelope["plan_binding_sha256"] == c.sha(c.canonical(plan)),
              "Phase A original source/plan/apply")
    for producer, workflow in ((plan["producer"], ".github/workflows/infra-plan.yml"),
                               (applied["producer"], ".github/workflows/infra-apply.yml")):
        c.closed(producer, "workflow_path workflow_sha run_id run_attempt")
        c.require(producer["workflow_path"] == workflow, "Phase A original producer workflow")
        c.digest(producer["workflow_sha"], 40)
        c.integer(producer["run_id"])
        c.integer(producer["run_attempt"])
    c.require(all(applied["producer"][key] == origin[key] for key in ("run_id", "run_attempt")), "Phase A original apply execution")
    release = c.closed(plan["release"], "release_id source_sha candidate_sha256 canary_id binding_sha256 image_digest")
    phase = c.closed(plan["phase_a_inputs"], "image_digest processor_active_unit_task_definition_arn processor_retained_unit_task_definition_arns "
                     "canary_storage_enabled canary_release_id canary_trusted_principal_arn")
    c.require(release["source_sha"] == origin["source_sha"] and phase["canary_storage_enabled"] is True
              and phase["canary_release_id"] == release["canary_id"] and phase["image_digest"] == release["image_digest"]
              and re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", phase["canary_trusted_principal_arn"]),
              "Phase A original release/principal")
    for key in ("candidate_sha256", "binding_sha256"):
        c.digest(release[key])
    c.closed(checkpoint, "state_after state_object outputs readbacks drift_sha256 operation_completed_at")
    _fence_state(checkpoint["state_after"])
    _fence_state({key: value for key, value in c.closed(applied["state_after"], "lineage serial state_sha256 outputs_sha256").items()
                  if key != "outputs_sha256"})
    state_object = c.closed(checkpoint["state_object"], "status version_id etag_sha256")
    c.require(state_object["status"] == "present" and type(state_object["version_id"]) is str
              and state_object["version_id"] not in {"", "null"}, "Phase A original versioned state identity")
    c.digest(state_object["etag_sha256"])
    outputs = c.closed(checkpoint["outputs"], "processor_task_definition_arns image_digest active_before retained_before retained_after canary_id "
                       "binding_sha256 resource_fingerprints grant_fingerprints route_fingerprints")
    c.require(c.canonical(outputs) == c.canonical(applied["outputs"])
              and c.sha(c.canonical(outputs)) == applied["state_after"]["outputs_sha256"]
              and outputs["canary_id"] == release["canary_id"] and outputs["binding_sha256"] == release["binding_sha256"]
              and outputs["image_digest"] == release["image_digest"]
              and checkpoint["state_after"] == {key: applied["state_after"][key] for key in checkpoint["state_after"]},
              "Phase A original outputs/state")
    lease = applied["lease"]
    c.closed(lease, "protocol owner_sha256 repository run_id run_attempt session_sha256 acquired_at released_at ttl_seconds "
             "renew_interval_seconds safety_margin_seconds acquire_etag_sha256 release_etag_sha256 renewal_count checkpoint_sha256 evidence_sha256 terminal_status")
    c.require(lease["protocol"] == "s3-cas-v1" and lease["terminal_status"] == "released"
              and all(c.canonical(lease[key]) == c.canonical(origin[key]) for key in
                      ("repository", "run_id", "run_attempt", "owner_sha256", "session_sha256", "checkpoint_sha256"))
              and origin["checkpoint_sha256"] == indexed["checkpoint.json"]["sha256"]
              and lease["evidence_sha256"] == indexed["lease.json"]["sha256"], "Phase A original lease/checkpoint")
    ecr_raw = c.canonical(drift["ecr_before"])
    c.require(len(ecr_raw) == indexed["ecr-before.json"]["size"] and c.sha(ecr_raw) == indexed["ecr-before.json"]["sha256"],
              "Phase A retained ECR original commitment")
    verify_drift_evidence(envelope, raw["drift.json"], ecr_raw)
    c.require(checkpoint["drift_sha256"] == c.sha(raw["drift.json"])
              and c.canonical(checkpoint["readbacks"]) == c.canonical(drift["post_readbacks"]), "Phase A original readbacks")
    c.require(c.instant(plan["created_at"]) <= c.instant(applied["started_at"])
              <= c.instant(checkpoint["operation_completed_at"]) <= c.instant(applied["completed_at"])
              < c.instant(plan["expires_at"]), "Phase A original temporal order")
    return {"envelope": envelope, "checkpoint": checkpoint, "drift": drift,
            "predecessor_reference": origin, "raw": raw}


def phase_a_carrier(origin, files):
    import base64
    c.require(type(files) is dict and set(files) == {"checkpoint.json", "drift.json", "envelope.json"},
              "Phase A three original raw files")
    carrier = {"carrier_version": 1, "origin": origin, "files": [
        {"name": name, "sha256": c.sha(raw), "size": len(raw), "bytes_base64": base64.b64encode(raw).decode()}
        for name, raw in sorted(files.items())]}
    phase_a_originals(carrier)
    return carrier


MODE_ALIASES = ("mode_seed", "mode_dispatch", "mode_audit_launch", "mode_observe")
MODE_ADDRESSES = frozenset(f"module.runtime_iam.{kind}.{alias}[0]" for alias in MODE_ALIASES
                           for kind in ("aws_iam_role", "aws_iam_role_policy"))
MODE_INPUT_FIELDS = ("schema_version context_kind application_principal_arn owner context_manifest delegation_sessions "
                     "resources enabled_until")
MODE_GATE_ORIGINALS = ("product_source_closure_sha256 shared_source_sha shared_source_closure_sha256 release_id "
                       "fixture_manifest_sha256")
MODE_PRODUCT_COMMITTED = "scenario_plan_sha256 predecessor_terminal_sha256 admitted_at deadline"
MODE_FIXTURE_MANIFEST = "tests/production/fixtures/mode_canary/fixture-manifest.json"
MODE_CLOSED_POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
MODE_SESSION_OPERATIONS = {
    "unit-seed": ("us", "mode_seed", "promotion", "unit"),
    "unit-start": ("ux", "mode_dispatch", "promotion", "unit"),
    "unit-observe": ("uo", "mode_observe", "promotion", "unit"),
    "recovery-seed": ("rs", "mode_seed", "promotion", "recovery"),
    "recovery-start": ("rx", "mode_dispatch", "promotion", "recovery"),
    "recovery-observe": ("ro", "mode_observe", "promotion", "recovery"),
    "audit-start": ("ax", "mode_audit_launch", "promotion", "audit"),
    "audit-observe": ("ao", "mode_observe", "promotion", "audit"),
    "drill-seed": ("ds", "mode_seed", "readiness", "readiness"),
    "drill-unit-start": ("dx", "mode_dispatch", "readiness", "readiness"),
    "drill-recovery-start": ("dr", "mode_dispatch", "readiness", "readiness"),
    "drill-hang-first": ("h1", "mode_dispatch", "readiness", "readiness"),
    "drill-hang-second": ("h2", "mode_dispatch", "readiness", "readiness"),
    "drill-observe": ("do", "mode_observe", "readiness", "readiness"),
}
CALLER_BINDING_FIELDS = ("application_purpose context_kind repository workflow_path ref environment source_sha "
                         "run_id run_attempt producer_workflow_sha producer_source_closure_sha256")
ADAPTER_INPUTS = {
    "inventory": "candidate dashboard-artifact archive static-baseline",
    "close-drain": "activation expirations",
    "closed-ready": "activation close-drain phase-b membership",
    "publish-static": "candidate dashboard-artifact static-plan inventory host-receipt",
    "rollback-api-static": "static-plan inventory publication host-recovery-receipt recovery-decision",
    "reopen": "activation routing canaries membership",
    "terminal-readback": "routing membership host-receipt static-receipt decision",
    "retire-static": "static-plan inventory publication routing",
    "unit-seed": "record mode-start fixture-manifest fixture-cnes-local fixture-cnes-nacional",
    "recovery-seed": "record mode-start fixture-manifest fixture-cnes-local fixture-cnes-nacional",
    "unit-start": "record readbacks previous mode-seed mode-start",
    "recovery-start": "record readbacks previous mode-seed mode-start",
    "audit-start": "record readbacks previous mode-seed mode-start audit-event-ids",
    "unit-observe": "activation close-drain record mode-result readbacks observed",
    "recovery-observe": "activation network close-drain phase-b phase-c mode-result readbacks",
    "audit-observe": "activation network close-drain phase-b phase-c mode-result readbacks recovery-result recovery-readbacks",
}
# Amendment 6886977054 decision 5 put retire-static in final; 6963763481 decision 1 (R16) admits it in no
# stage in this slice, because the final budget does not fit it. The remedy belongs to the post-API amendment.
ADAPTER_STAGES = {
    "inventory": {"application-prepare"}, "close-drain": {"application-prepare"}, "closed-ready": {"api"},
    "publish-static": {"static"}, "rollback-api-static": {"recovery"}, "reopen": {"final", "recovery"},
    "terminal-readback": {"application-prepare", "final", "recovery"}, "retire-static": set(),
    **{name: {"unit"} for name in ("unit-seed", "unit-start", "unit-observe")},
    **{name: {"phase-c-recovery"} for name in ("recovery-seed", "recovery-start", "recovery-observe")},
    **{name: {"phase-c-audit"} for name in ("audit-start", "audit-observe")},
}
ADAPTER_OBSERVATIONS = {
    "inventory": "inventory", "close-drain": "close-drain", "closed-ready": "closed-ready",
    "publish-static": "publication", "rollback-api-static": "rollback", "reopen": "routing", "terminal-readback": "terminal",
    "retire-static": "retirement",
    **{name: "mode-seed" for name in ("unit-seed", "recovery-seed")},
    **{name: "mode-result" for name in ("unit-start", "recovery-start", "audit-start")},
    **{name: "mode" for name in ("unit-observe", "recovery-observe", "audit-observe")},
}
STATIC_BINDING_FIELDS = "release_id run_id run_attempt generation product_source_sha shared_source_sha static_plan_sha256"
# #498 static-promotion.tf locals.static_operations by ABI operation. Queue item 3e admits the observer
# (inventory session) in the static stage; decision 5 gives retire-static its own normal session.
STATIC_SESSION_OPERATIONS = {
    "inventory": {"observer": "inventory"},
    "publish-static": {"normal": "publish", "observer": "inventory"},
    "retire-static": {"normal": "retire"},
}


def static_session(binding, operation):
    """#498 locals.static_sessions: sp-<op>-sha256(jsonencode(binding + operation) + LF)[:40].

    The inventory name commits to no plan (static_plan_sha256 null), so it exists before the plan.
    c.canonical equals jsonencode on this closed ASCII binding. A name is not an STS admission.
    """
    c.closed(binding, STATIC_BINDING_FIELDS)
    c.require(operation in {"inventory", "publish", "retire"}, "closed static session operation")
    c.require(type(binding["release_id"]) is str and re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?", binding["release_id"]),
              "static session release id")
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(binding[key])
    for key in ("product_source_sha", "shared_source_sha"):
        c.digest(binding[key], 40)
    if operation != "inventory" or binding["static_plan_sha256"] is not None:
        c.digest(binding["static_plan_sha256"])
    value = binding | {"operation": operation} | ({"static_plan_sha256": None} if operation == "inventory" else {})
    return "sp-" + ("i" if operation == "inventory" else operation) + "-" + c.sha(c.canonical(value))[:40]


def static_sessions(binding, operation):
    """Exact delegation -> session names for one static ABI operation; the caller authenticates the binding."""
    c.require(operation in STATIC_SESSION_OPERATIONS, "closed static session operation")
    return {alias: static_session(binding, name) for alias, name in STATIC_SESSION_OPERATIONS[operation].items()}


STATIC_MEMBER_LIMIT = 1024**2
STATIC_UPLOAD_FLOOR = 512 * 1024
STATIC_ROOT_BLOCK_SECONDS = 5 * 20


def s3_put_body(parameters):
    """PutObject Body as the dist.tar member reference {member, size, sha256}; member is the Key (P15b).

    ChecksumSHA256 is base64 of that sha256, as the product sends it; the broker reads and checks the bytes.
    """
    c.require(type(parameters) is dict and type(parameters.get("ChecksumSHA256")) is str, "S3 Body PutObject parameters")
    body = c.closed(parameters.get("Body"), "member size sha256")
    c.require(body["member"] == parameters.get("Key"), "S3 Body member")
    c.integer(body["size"], 0, STATIC_MEMBER_LIMIT)
    c.digest(body["sha256"])
    c.require(parameters["ChecksumSHA256"] == base64.b64encode(bytes.fromhex(body["sha256"])).decode("ascii"),
              "S3 Body ChecksumSHA256")
    return dict(body)


def s3_body_value(stream, *, maximum):
    """GetObject Body -> {"sha256", "size"}; reads at most maximum + 1 bytes and refuses past maximum."""
    c.integer(maximum, 0)
    digest, size = hashlib.sha256(), 0
    while size <= maximum:
        chunk = stream.read(maximum + 1 - size)
        c.require(type(chunk) is bytes, "S3 Body stream bytes")
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    c.require(size <= maximum, "S3 Body bound")
    return {"sha256": digest.hexdigest(), "size": size}


STATIC_BUCKET = "cnesdata-prod-static-web"
STATIC_PLAN_SCHEMA = "cnesdata.static-plan/v1"
STATIC_PLAN_FIELDS = "schema bucket distribution_arn inventory_sha256 candidate_keys rollback_versions retire_versions multipart_keys"
STATIC_ENTRYPOINTS = ("index.html", "theme-init.js")
STATIC_INVALIDATION_PATHS = {"Quantity": 2, "Items": ["/index.html", "/theme-init.js"]}
# R17 (6963763481 decision 2): CnesData 9cdd452f wire names and the only boto3 methods they dispatch to.
STATIC_SDK_METHODS = {
    ("s3", "ListObjectVersions"): "list_object_versions", ("s3", "HeadObject"): "head_object",
    ("s3", "ListMultipartUploads"): "list_multipart_uploads", ("s3", "ListParts"): "list_parts",
    ("s3", "PutObject"): "put_object", ("s3", "GetObject"): "get_object",
    ("cloudfront", "CreateInvalidation"): "create_invalidation", ("s3", "DeleteObject"): "delete_object",
}
_STATIC_OBSERVER_CALLS = frozenset(("observer", "s3", name) for name in
                                   ("ListObjectVersions", "HeadObject", "ListMultipartUploads", "ListParts"))
STATIC_SDK_OPERATIONS = {
    "inventory": _STATIC_OBSERVER_CALLS,
    "publish-static": _STATIC_OBSERVER_CALLS | {("normal", "s3", "PutObject"), ("normal", "s3", "GetObject"),
                                                ("normal", "cloudfront", "CreateInvalidation")},
    "retire-static": frozenset({("normal", "s3", "DeleteObject")}),
}


def _static_key(key):
    c.require(type(key) is str and len(key) <= 1024
              and re.fullmatch(r"assets/[A-Za-z0-9._/-]+|index\.html|theme-init\.js", key) is not None
              and all(part not in {"", ".", ".."} for part in key.split("/")), "static key")
    return key


def _static_version(version):
    c.require(type(version) is str and len(version) <= 1024 and version != "null"
              and re.fullmatch(r"[A-Za-z0-9._~+/=-]+", version) is not None, "static version id")
    return version


def _static_keys(keys, minimum):
    c.require(type(keys) is list and len(keys) >= minimum and all(_static_key(key) for key in keys)
              and keys == sorted(set(keys)), "static keys sorted distinct")
    return keys


def _static_refs(refs):
    c.require(type(refs) is list, "static version refs")
    for ref in refs:
        c.closed(ref, "key version_id")
        _static_key(ref["key"])
        _static_version(ref["version_id"])
    c.require(len({(ref["key"], ref["version_id"]) for ref in refs}) == len(refs), "static version refs distinct")
    return {(ref["key"], ref["version_id"]) for ref in refs}


def static_plan(raw, *, bucket):
    """CnesData 9cdd452f cnesdata.static-plan/v1 under the #498 static_promotion rules; bucket is authenticated."""
    plan = c.loads(raw, canonical=True, limit=1024**2)
    c.closed(plan, STATIC_PLAN_FIELDS)
    c.require(plan["schema"] == STATIC_PLAN_SCHEMA and type(bucket) is str and plan["bucket"] == bucket, "static plan bucket")
    c.require(type(plan["distribution_arn"]) is str
              and re.fullmatch(r"arn:aws:cloudfront::[0-9]{12}:distribution/[A-Z0-9]+", plan["distribution_arn"]) is not None,
              "static plan distribution")
    c.digest(plan["inventory_sha256"])
    _static_keys(plan["candidate_keys"], 1)
    _static_keys(plan["multipart_keys"], 0)
    rollback, retire = _static_refs(plan["rollback_versions"]), _static_refs(plan["retire_versions"])
    c.require([ref["key"] for ref in plan["rollback_versions"]] in ([], list(STATIC_ENTRYPOINTS)), "static plan rollback pair")
    c.require(not rollback & retire, "static plan retire/rollback overlap")
    return plan


def _static_text(value):
    return type(value) is str and 1 <= len(value) <= 1024


def _static_list_versions(parameters, bucket, plan):
    markers = set(parameters) - {"Bucket"}
    c.require(parameters.get("Bucket") == bucket and markers in (set(), {"KeyMarker", "VersionIdMarker"})
              and all(_static_text(parameters[name]) for name in markers), "static call parameters")


def _static_head(parameters, bucket, plan):
    c.closed(parameters, "Bucket Key VersionId ChecksumMode")
    c.require(parameters["Bucket"] == bucket and parameters["ChecksumMode"] == "ENABLED", "static call parameters")
    _static_key(parameters["Key"])
    _static_version(parameters["VersionId"])


def _static_uploads(parameters, bucket, plan):
    c.require(parameters == {"Bucket": bucket}, "static call parameters")


def _static_parts(parameters, bucket, plan):
    c.closed(parameters, "Bucket Key UploadId")
    c.require(parameters["Bucket"] == bucket and _static_text(parameters["UploadId"]), "static call parameters")
    _static_key(parameters["Key"])


def _static_put(parameters, bucket, plan):
    asset = parameters.get("Key") not in STATIC_ENTRYPOINTS
    c.closed(parameters, "Bucket Key Body ContentType CacheControl ChecksumSHA256" + (" IfNoneMatch" if asset else ""))
    c.require(parameters["Bucket"] == bucket and parameters["Key"] in plan["candidate_keys"]
              and (not asset or parameters["IfNoneMatch"] == "*")
              and all(type(parameters[name]) is str and 1 <= len(parameters[name]) <= 256
                      for name in ("ContentType", "CacheControl")), "static call parameters")
    s3_put_body(parameters)


def _static_get(parameters, bucket, plan):
    c.closed(parameters, "Bucket Key")
    c.require(parameters["Bucket"] == bucket and parameters["Key"] in plan["candidate_keys"], "static call parameters")


def _static_invalidation(parameters, bucket, plan):
    c.closed(parameters, "DistributionId InvalidationBatch")
    batch = c.closed(parameters["InvalidationBatch"], "Paths CallerReference")
    c.require(parameters["DistributionId"] == plan["distribution_arn"].rsplit("/", 1)[1]
              and c.canonical(batch["Paths"]) == c.canonical(STATIC_INVALIDATION_PATHS)
              and type(batch["CallerReference"]) is str and re.fullmatch(r"[0-9a-f]{32}", batch["CallerReference"]) is not None,
              "static call parameters")


def _static_delete(parameters, bucket, plan):
    c.closed(parameters, "Bucket Key VersionId")
    c.require(parameters["Bucket"] == bucket
              and {"key": parameters["Key"], "version_id": parameters["VersionId"]} in plan["retire_versions"],
              "static call parameters")


_STATIC_CALLS = {
    "ListObjectVersions": _static_list_versions, "HeadObject": _static_head, "ListMultipartUploads": _static_uploads,
    "ListParts": _static_parts, "PutObject": _static_put, "GetObject": _static_get,
    "CreateInvalidation": _static_invalidation, "DeleteObject": _static_delete,
}


def validate_static_call(*, request, role, service, operation, parameters, bucket, plan):
    """R17 closed catalogue: one product wire call -> its boto3 method, every value bound to bucket and plan.

    Scope, not domain acceptance. inventory has no plan; retire-static's DeleteObject shape is SYNTHETIC (R3).
    """
    kind = request.get("operation") if type(request) is dict else None
    c.require(all(type(name) is str for name in (role, service, operation)) and kind in STATIC_SDK_OPERATIONS
              and (role, service, operation) in STATIC_SDK_OPERATIONS[kind] and type(parameters) is dict,
              "closed static SDK operation")
    if kind == "inventory":
        c.require(plan is None and type(bucket) is str and bucket != "", "static inventory call scope")
    else:
        c.require(type(plan) is dict and static_plan(c.canonical(plan), bucket=bucket) == plan, "static call plan")
    _STATIC_CALLS[operation](parameters, bucket, plan)
    return STATIC_SDK_METHODS[service, operation]


ADAPTER_ABI_VERSION = 3
ADAPTER_STAGE_FIELDS = ("close fixed_deadline input_deadline stage admitted_at deadline decision preparation_deadline sequence "
                        "checkpoint_sha256 windows")
FENCE_PREPARE_PRODUCER = {
    "workflow_path": ".github/workflows/reusable-cnesdata-infra-deploy-gate.yml", "job": "execute", "step_id": "gate",
    "step_name": "Execute under CAS watchdog and verify final publication", "step": "application-prepare-operational",
    "job_name": "application-prepare-operational / execute", "purpose": "application-prepare", "mode": "operational", "direction": "advance",
}
# Amendment 2026-11-13 item 5: one tuple for producer (eight completed + gate running) and consumer (nine completed).
FENCE_PREPARE_STEPS = (
    "Load actual immutable producer from authenticated run", "Verify complete public source and admission proof",
    "Check out authenticated exact product source", "Check out pinned artifact SDK bundle",
    "Set pinned Node runtime for the artifact SDK", "Install checksum-locked protected runtime",
    "Bridge masked artifact runtime from Node action handler", "Repeat source gate then request exact OIDC role",
    FENCE_PREPARE_PRODUCER["step_name"],
)
FENCE_PREPARE_FILES = frozenset({"checkpoint.json", "approval.json", "fence-prepared.json", "fence-role.json",
                               "fence-readbacks.json", "fence-origins.json", "fence-chain.json", "fence-evaluation.json"})
FENCE_ORIGIN_FIELDS = "repository source_sha run_id run_attempt job_id artifact_id artifact_digest producer_name step name sha256 size"
FENCE_PHASE_A_FILES = frozenset({"envelope.json", "checkpoint.json", "drift.json"})
FENCE_HISTORY_GAPS = frozenset({"plan.json", "inputs.tfvars.json"})
FENCE_EVALUATION_CASES = {
    "assume-exact": "sts:AssumeRole", "assume-other-session": "sts:AssumeRole", "app-direct-get": "dynamodb:GetItem",
    "get-fence": "dynamodb:GetItem", "get-tenant": "dynamodb:GetItem", "update-fence": "dynamodb:UpdateItem",
    "probe-own": "states:DescribeExecution", "probe-foreign": "states:DescribeExecution", "write-own-evidence": "s3:PutObject",
    "put-lease": "s3:PutObject", "freeze-expired": "dynamodb:GetItem",
}
FENCE_SCHEMAS = {
    "fence-prepared.json": "schema_version proof_kind operation application_purpose context_kind owner caller_binding_sha256 activation_sha256 application_fragment_sha256 producer preparation files outcome",
    "fence-role.json": "schema_version role_arn role_name role_id policy_name release_id session_name trust policy max_session_duration tags original_projection_sha256 current_projection_sha256",
    "fence-origins.json": "schema_version phase_a current_source_sha current_source_closure_sha256 current_plan projection_source_files",
    "fence-chain.json": "schema_version owner_sha256 generation anchor_sha256 head_sha256 entries",
    "fence-evaluation.json": "schema_version evaluator_source_sha documents cases",
    "fence-readbacks.json": "proof_kind readbacks",
}


def _fence_origin(value):
    c.closed(value, FENCE_ORIGIN_FIELDS)
    c.require(value["repository"] == c.REPOSITORY, "fence original repository")
    for key in ("run_id", "run_attempt", "job_id", "artifact_id"):
        c.integer(value[key])
    c.integer(value["size"], 1, 128 * 1024**2)
    c.digest(value["source_sha"], 40)
    c.digest(value["sha256"])
    c.require(value["artifact_digest"] == "sha256:" + c.digest(value["artifact_digest"].removeprefix("sha256:")), "fence artifact digest")
    c.require(type(value["producer_name"]) is str and 1 <= len(value["producer_name"]) <= 128
              and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value["step"])
              and re.fullmatch(r"[a-z][a-z0-9.-]{0,63}\.(?:json|bin)", value["name"]), "fence original finite file/producer")


def _fence_state(value):
    c.closed(value, "lineage serial state_sha256")
    c.require(type(value["lineage"]) is str and 1 <= len(value["lineage"]) <= 128, "fence state lineage")
    c.integer(value["serial"], 0)
    c.digest(value["state_sha256"])


def _fence_readback_document(value, role, preparation):
    from email.utils import parsedate_to_datetime
    c.require(value["proof_kind"] == "iam-readback-and-evaluation" and type(value["readbacks"]) is list
              and len(value["readbacks"]) == 2, "fence two original readbacks")
    operations = ("get_role", "list_role_policies", "list_attached_role_policies", "get_role_policy")
    previous, bodies, request_ids = None, None, set()
    for row in value["readbacks"]:
        c.closed(row, "observed_at observations")
        c.integer(row["observed_at"])
        c.require(preparation["admitted_at"] <= row["observed_at"] < preparation["deadline"]
                  and (previous is None or row["observed_at"] >= previous + 10), "fence original spaced observation")
        c.require(type(row["observations"]) is list and len(row["observations"]) == 4, "fence eight exact IAM reads")
        current = []
        for operation, report in zip(operations, row["observations"]):
            c.closed(report, "service operation parameters response")
            parameters = {"RoleName": role["role_name"]}
            if operation.startswith("list_"):
                parameters["MaxItems"] = 100
            if operation == "get_role_policy":
                parameters["PolicyName"] = role["policy_name"]
            c.require(report["service"] == "iam" and report["operation"] == operation
                      and report["parameters"] == parameters, "fence exact readback request")
            response = report["response"]
            c.require(type(response) is dict and "ResponseMetadata" in response, "fence native response")
            metadata = response["ResponseMetadata"]
            c.closed(metadata, "RequestId HTTPStatusCode HTTPHeaders" + (" RetryAttempts" if "RetryAttempts" in metadata else ""))
            c.require(type(metadata["RequestId"]) is str and 1 <= len(metadata["RequestId"]) <= 256
                      and metadata["RequestId"] not in request_ids and type(metadata["HTTPStatusCode"]) is int
                      and metadata["HTTPStatusCode"] == 200 and type(metadata["HTTPHeaders"]) is dict, "fence original request metadata")
            request_ids.add(metadata["RequestId"])
            c.require(all(type(k) is str and type(v) is str and len(k) <= 128 and len(v) <= 4096 for k, v in metadata["HTTPHeaders"].items()), "fence bounded SDK headers")
            date = parsedate_to_datetime(metadata["HTTPHeaders"]["date"])
            c.require(date.tzinfo is not None and abs(date.timestamp() - row["observed_at"]) <= 30, "fence original SDK clock")
            body = {key: item for key, item in response.items() if key != "ResponseMetadata"}
            if operation == "get_role":
                c.closed(body, "Role")
                item = body["Role"]
                expected = {"RoleName": role["role_name"], "Arn": role["role_arn"], "RoleId": role["role_id"], "MaxSessionDuration": 3600,
                            "AssumeRolePolicyDocument": role["trust"], "Tags": [{"Key": "ReleaseId", "Value": role["release_id"]}]}
                c.require(set(expected) <= set(item) <= set(expected) | {"Path", "CreateDate", "Description", "RoleLastUsed"}
                          and all(c.canonical(item[key]) == c.canonical(expected[key]) for key in expected), "fence original role projection")
            elif operation == "get_role_policy":
                c.require(body == {"RoleName": role["role_name"], "PolicyName": role["policy_name"], "PolicyDocument": role["policy"]}, "fence original policy readback")
            else:
                expected = {"PolicyNames": [role["policy_name"]], "IsTruncated": False} if operation == "list_role_policies" else {"AttachedPolicies": [], "IsTruncated": False}
                c.require(c.canonical(body) == c.canonical(expected), "fence exact inline/attached inventory")
            current.append(body)
        c.require(bodies is None or c.canonical(bodies) == c.canonical(current), "fence identity/documents changed between reads")
        previous, bodies = row["observed_at"], current
    c.require(previous == preparation["observed_at"], "fence original completed observation")


def _fence_producer(producer, owner):
    c.closed(producer, "repository source_sha workflow_sha run_id run_attempt job_id " + " ".join(FENCE_PREPARE_PRODUCER))
    c.require(all(producer[key] == value for key, value in FENCE_PREPARE_PRODUCER.items())
              and all(c.canonical(producer[key]) == c.canonical(owner[key])
                      for key in ("repository", "source_sha", "run_id", "run_attempt")), "fence protected deploy producer")
    c.digest(producer["workflow_sha"], 40)
    for key in ("run_id", "run_attempt", "job_id"):
        c.integer(producer[key])


def fence_current_origin(producer, checkpoint_raw):
    """A current producer has no enclosing artifact digest before publication."""
    return {key: producer[key] for key in ("repository", "source_sha", "run_id", "run_attempt", "job_id")} | {
        "producer_name": producer["job_name"], "step": producer["step"], "name": "checkpoint.json",
        "sha256": c.sha(checkpoint_raw), "size": len(checkpoint_raw)}


def fence_predecessor_baseline(raw, reference, carrier):
    """Validate the external predecessor baseline, without relabelling it as an entry."""
    history = phase_a_originals(carrier)
    c.closed(reference, "predecessor_version protocol repository source_sha run_id run_attempt owner_sha256 generation "
             "session_sha256 checkpoint_sha256 artifact_id artifact_digest producer_job_id producer_name objects")
    c.require(type(reference["predecessor_version"]) is int and reference["predecessor_version"] == 1
              and reference["repository"] == c.REPOSITORY and reference["protocol"] in {"legacy-infra", "lifecycle"}
              and c.sha(raw) == c.digest(reference["checkpoint_sha256"]), "fence original predecessor raw commitment")
    prior = c.loads(raw, canonical=True, limit=262144)
    if reference["protocol"] == "legacy-infra":
        c.require(c.canonical(reference) == c.canonical(history["predecessor_reference"])
                  and raw == history["raw"]["checkpoint.json"], "fence initial original Phase A checkpoint")
        state = prior["state_after"]
    else:
        c.closed(prior, "version owner state state_object previous_checkpoint_sha256 assessment_sha256 inputs window phase_a_originals")
        c.require(type(prior["version"]) is int and prior["version"] == 2
                  and c.canonical(prior["phase_a_originals"]) == c.canonical(carrier), "fence terminal v2 original Phase A custody")
        for key in ("run_id", "run_attempt", "generation", "artifact_id", "producer_job_id"):
            c.integer(reference[key])
        c.require(all(c.canonical(prior["owner"][key]) == c.canonical(reference[key]) for key in
                      ("repository", "source_sha", "run_id", "run_attempt", "owner_sha256", "generation", "session_sha256")),
                  "fence predecessor original terminal owner")
        state = prior["state"]
    _fence_state(state)
    original = history["checkpoint"]["state_after"]
    c.require(state["lineage"] == original["lineage"] and state["serial"] >= original["serial"], "fence predecessor Phase A lineage/progression")
    state_object = c.closed(prior["state_object"], "status version_id etag_sha256")
    c.require(state_object["status"] == "present" and type(state_object["version_id"]) is str
              and state_object["version_id"] not in {"", "null"}, "fence predecessor original state object")
    c.digest(state_object["etag_sha256"])
    return state, state_object


APPLICATION_GATE_REPOSITORY = "VINIClUS/infra-ansible"
APPLICATION_GATE_WORKFLOW = ".github/workflows/reusable-cnesdata-application-gate.yml"
APPLICATION_PYBOOT = ("contract.py", "provenance.py", "coordination_lease.py", "drift_catalog.py", "drift_handoff.py", "aws_boundary.py",
                      "runtime.py",
                      "lifecycle_contract.py", "lifecycle_runtime.py", "application_gate.py", "outputs.py",
                      "session_policy.py", "evidence.py", "ext2_transport.py", "iam_expression.py", "iam_source.py",
                      "iam_boundary.py", "session_owner.py", "session_grouping.py", "signing_gate.py",
                      "static_inputs.py", "terminal_gate.py", "runtime-requirements.txt")
APPLICATION_CLOSURE_PATHS = tuple(sorted(["tools/cnesdata_delivery/" + name for name in APPLICATION_PYBOOT]
                                         + [APPLICATION_GATE_WORKFLOW]))


def application_source_closure(read):
    """Producer closure (#55 2nd slice, decision 1): PYBOOT files plus the reusable.

    read(path) returns the exact bytes at governance gate_shas.application.
    """
    files = {}
    for path in APPLICATION_CLOSURE_PATHS:
        raw = read(path)
        c.require(type(raw) is bytes and len(raw) <= 256 * 1024, "application closure file")
        files[path] = c.sha(raw)
    return c.sha(c.canonical({"files": files}))


def fence_source_closure(projection_source_files):
    """Amendment 2026-11-13 item 4: commitment of the traversed projection source files."""
    return c.sha(c.canonical(projection_source_files))


def validate_fence_checkpoint_chain(chain, checkpoint_raw, owner, *, predecessor_raw, predecessor_reference, producer):
    """Validate a chain whose original bytes/producer are independently protected."""
    c.closed(chain, FENCE_SCHEMAS["fence-chain.json"])
    c.require(type(chain["schema_version"]) is int and chain["schema_version"] == 3, "fence chain schema")
    _fence_producer(producer, owner)
    c.require(chain["owner_sha256"] == owner["owner_sha256"] and type(chain["generation"]) is int and chain["generation"] == owner["generation"]
              and type(chain["entries"]) is list and 1 <= len(chain["entries"]) <= 256, "fence current keeper ancestry")
    checkpoint = c.loads(checkpoint_raw, canonical=True)
    c.closed(checkpoint, "state state_object owner purpose plan_sha256 readbacks phase_a_originals")
    original_state, _ = fence_predecessor_baseline(predecessor_raw, predecessor_reference, checkpoint["phase_a_originals"])
    previous, serial = c.digest(chain["anchor_sha256"]), original_state["serial"]
    c.require(previous == c.sha(predecessor_raw) == predecessor_reference["checkpoint_sha256"], "fence original selected predecessor anchor")
    seen = {previous}
    for sequence, entry in enumerate(chain["entries"]):
        c.closed(entry, "sequence checkpoint_sha256 previous_checkpoint_sha256 state state_object origin")
        c.require(type(entry["sequence"]) is int and entry["sequence"] == sequence and entry["previous_checkpoint_sha256"] == previous, "fence ordered checkpoint ancestry")
        _fence_state(entry["state"])
        c.closed(entry["state_object"], "status version_id etag_sha256")
        c.require(entry["state_object"]["status"] == "present" and type(entry["state_object"]["version_id"]) is str
                  and bool(entry["state_object"]["version_id"]) and entry["state_object"]["version_id"] != "null", "fence current state object")
        c.digest(entry["state_object"]["etag_sha256"])
        if sequence == len(chain["entries"]) - 1:
            expected = fence_current_origin(producer, checkpoint_raw)
            c.closed(entry["origin"], " ".join(expected))
            c.require(c.canonical(entry["origin"]) == c.canonical(expected), "fence current original producer/checkpoint")
        else:
            _fence_origin(entry["origin"])
        c.require(entry["state"]["lineage"] == original_state["lineage"] and entry["state"]["serial"] >= serial
                  and all(entry["origin"][key] == owner[key] for key in ("source_sha", "run_id", "run_attempt"))
                  and entry["origin"]["sha256"] == entry["checkpoint_sha256"], "fence current lineage/original checkpoint")
        previous, serial = c.digest(entry["checkpoint_sha256"]), entry["state"]["serial"]
        c.require(previous not in seen, "fence checkpoint cycle")
        seen.add(previous)
    _fence_state(checkpoint["state"])
    c.require(chain["head_sha256"] == previous == c.sha(checkpoint_raw)
              and c.canonical(checkpoint["owner"]) == c.canonical(owner)
              and c.canonical(checkpoint["state"]) == c.canonical(chain["entries"][-1]["state"])
              and c.canonical(checkpoint["state_object"]) == c.canonical(chain["entries"][-1]["state_object"]), "fence original current checkpoint")
    return checkpoint


def validate_fence_prepared_package(files, *, owner, fragment, activation_sha256, producer, preparation, originals,
                                   predecessor_raw, predecessor_reference):
    """Closed codec against protected originals; never a provenance/capability API.

    The protected producer must authenticate the arguments and derive original
    role/source/evaluation/chain documents before calling. The current transport
    cannot yet supply all historical Phase A inputs; privileged wiring is closed.
    """
    c.require(type(files) is dict and set(files) == FENCE_PREPARE_FILES, "fence exact private inventory")
    c.require(type(originals) is dict and set(originals) == FENCE_PREPARE_FILES - {"fence-prepared.json"}, "fence complete protected original documents")
    c.closed(fragment, "fragment_version account_id region application_role_arn application_role_name producer caller_by_purpose provider_arn lease evidence delegations trust_sha256 policy_sha256 enabled_until"
             + (" predecessor_reads" if "predecessor_reads" in fragment else ""))
    c.require(type(fragment.get("fragment_version")) is int and fragment["fragment_version"] == 4
              and fragment["caller_by_purpose"] == APPLICATION_CALLERS, "fence current schema4 authority")
    c.require(application_identity(owner, required=True)["application_purpose"] == "promotion", "fence only current promotion owner")
    c.closed(owner, " ".join(OWNER_FIELDS + ["owner_sha256", *APPLICATION_OWNER_FIELDS]))
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(owner[key])
    c.require(owner["repository"] == c.REPOSITORY, "fence current owner repository")
    c.digest(owner["source_sha"], 40)
    for key in ("owner_sha256", "release_sha256", "session_sha256"):
        c.digest(owner[key])
    c.require(fragment["delegations"] == {alias: "arn:aws:iam::" + fragment["account_id"] + ":role/cnesdata-prod-" + suffix
                                         for alias, suffix in APPLICATION_DELEGATIONS.items()}, "fence current ten aliases")
    values = {}
    for name, raw in files.items():
        c.require(type(raw) is bytes and 0 < len(raw) <= 1024**2, "fence private file bound")
        values[name] = c.loads(raw, canonical=True, limit=1024**2)
        if name in FENCE_SCHEMAS:
            c.closed(values[name], FENCE_SCHEMAS[name])
        if name != "fence-prepared.json":
            c.require(raw == originals[name], "fence original producer bytes")
        if "schema_version" in values[name]:
            version = 3 if name == "fence-chain.json" else 1
            c.require(type(values[name]["schema_version"]) is int and values[name]["schema_version"] == version, "fence document schema")
    manifest = values["fence-prepared.json"]
    c.require(manifest["proof_kind"] == "iam-readback-and-evaluation" and manifest["operation"] == "closed-ready"
              and manifest["application_purpose"] == manifest["context_kind"] == "promotion"
              and manifest["outcome"] == "observed", "fence observation only, not adapter acceptance")
    c.require(c.canonical(manifest["owner"]) == c.canonical(owner)
              and manifest["caller_binding_sha256"] == owner["caller_binding_sha256"]
              and manifest["activation_sha256"] == c.digest(activation_sha256)
              and manifest["application_fragment_sha256"] == c.sha(c.canonical(fragment)), "fence original current binding")
    c.closed(manifest["producer"], "repository source_sha workflow_sha run_id run_attempt job_id " + " ".join(FENCE_PREPARE_PRODUCER))
    c.require(c.canonical(manifest["producer"]) == c.canonical(producer), "fence protected deploy producer")
    _fence_producer(producer, owner)
    c.closed(manifest["preparation"], "admitted_at deadline observed_at")
    c.require(c.canonical(manifest["preparation"]) == c.canonical(preparation), "fence original preparation window")
    for value in preparation.values():
        c.integer(value)
    c.require(preparation["admitted_at"] <= preparation["observed_at"] < preparation["deadline"] <= preparation["admitted_at"] + 900,
              "fence preparation is not future F")
    expected = [{"name": name, "sha256": c.sha(files[name]), "size": len(files[name])} for name in sorted(FENCE_PREPARE_FILES - {"fence-prepared.json"})]
    c.require(c.canonical(manifest["files"]) == c.canonical(expected), "fence complete private commitments without self hash")
    origins, role, chain = (values[name] for name in ("fence-origins.json", "fence-role.json", "fence-chain.json"))
    old = origins["phase_a"]
    c.closed(old, "source_sha source_closure_sha256 release_id canary_id candidate_sha256 plan_binary_sha256 plan_json_sha256 inputs_sha256 plan_receipt state files")
    c.require(origins["current_source_sha"] == owner["source_sha"], "fence current and historical sources distinguished")
    c.digest(origins["current_source_closure_sha256"])
    current_plan = origins["current_plan"]
    c.closed(current_plan, "source_sha run_id run_attempt step index_sha256 plan_binary_sha256 plan_json_sha256 inputs_sha256")
    c.require(all(c.canonical(current_plan[key]) == c.canonical(owner[key]) for key in ("source_sha", "run_id", "run_attempt"))
              and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", current_plan["step"]), "fence distinct original current plan")
    for key in ("index_sha256", "plan_binary_sha256", "plan_json_sha256", "inputs_sha256"):
        c.digest(current_plan[key])
    source_files = origins["projection_source_files"]
    c.require(type(source_files) is list and 1 <= len(source_files) <= 64, "fence finite projection closure")
    paths = []
    for item in source_files:
        c.closed(item, "path sha256")
        c.require(re.fullmatch(r"infra/opentofu/(?:env/prod|modules/[a-z0-9-]+)/[a-z0-9_.-]+\.tf", item["path"]), "fence original source path")
        c.digest(item["sha256"])
        paths.append(item["path"])
    c.require(paths == sorted(set(paths)), "fence exact projection source inventory")
    c.require(old["source_closure_sha256"] == fence_source_closure(source_files), "fence historical projection source closure")
    c.digest(old["source_sha"], 40)
    for key in ("source_closure_sha256", "candidate_sha256", "plan_binary_sha256", "plan_json_sha256", "inputs_sha256"):
        c.digest(old[key])
    for key in ("release_id", "canary_id"):
        c.require(type(old[key]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", old[key]), "fence original release identity")
    c.require(type(old["files"]) is dict and set(old["files"]) == FENCE_PHASE_A_FILES, "fence Phase A original inventory")
    for name, reference in old["files"].items():
        _fence_origin(reference)
        c.require(reference["name"] == name and reference["source_sha"] == old["source_sha"], "fence original Phase A source/file")
    c.closed(old["plan_receipt"], "plan_binding_sha256 consumed_plan_artifact")
    c.digest(old["plan_receipt"]["plan_binding_sha256"])
    consumed = old["plan_receipt"]["consumed_plan_artifact"]
    c.closed(consumed, "artifact_id artifact_sha256 run_id run_attempt")
    for key in ("artifact_id", "run_id", "run_attempt"):
        c.integer(consumed[key])
    c.digest(consumed["artifact_sha256"])
    # These commitments come from the authenticated applied envelope. Requiring
    # raw binary/candidate bytes would add no input to the finite role resolver.
    _fence_state(old["state"])
    c.require(role["role_name"] == "cnesdata-prod-promotion-fence-operator"
              and role["role_arn"] == fragment["delegations"]["fence_operator"]
              and role["policy_name"] == role["role_name"] + "-gate"
              and role["release_id"] == old["canary_id"] and role["session_name"] == "promotion-fence-" + old["canary_id"], "fence original release/session")
    c.require(type(role["role_id"]) is str and bool(role["role_id"]) and type(role["max_session_duration"]) is int
              and role["max_session_duration"] == 3600 and role["tags"] == {"ReleaseId": old["canary_id"]}, "fence original role identity/tags")
    expected_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": fragment["application_role_arn"]},
        "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:RoleSessionName": role["session_name"]}}}]}
    c.require(role["trust"] == expected_trust, "fence original trust compatible with current schema4 principal")
    projection = {key: role[key] for key in ("role_arn", "role_name", "role_id", "policy_name", "trust", "policy", "max_session_duration", "tags")}
    c.require(role["original_projection_sha256"] == role["current_projection_sha256"] == c.sha(c.canonical(projection)), "fence role projection, not entire historical state")
    checkpoint = validate_fence_checkpoint_chain(chain, files["checkpoint.json"], owner,
        predecessor_raw=predecessor_raw, predecessor_reference=predecessor_reference, producer=producer)
    original = phase_a_originals(checkpoint["phase_a_originals"])
    original_plan, original_apply = original["envelope"]["plan"], original["envelope"]["apply"]
    reference = original["predecessor_reference"]
    expected_history = {"source_sha": original_plan["source_sha"], "release_id": original_plan["release"]["release_id"],
        "canary_id": original_plan["release"]["canary_id"], "candidate_sha256": original_plan["release"]["candidate_sha256"],
        "plan_binary_sha256": original_plan["binary_sha256"], "plan_json_sha256": original_plan["json_sha256"], "inputs_sha256": original_plan["inputs_sha256"],
        "plan_receipt": {"plan_binding_sha256": original_apply["plan_binding_sha256"], "consumed_plan_artifact": original_apply["consumed_plan_artifact"]},
        "state": original["checkpoint"]["state_after"]}
    c.require(all(c.canonical(old[key]) == c.canonical(value) for key, value in expected_history.items()),
              "fence Phase A metadata matches original carrier bytes")
    indexed = {entry["name"]: entry for entry in reference["objects"]}
    for name in FENCE_PHASE_A_FILES:
        expected_origin = {key: reference[key] for key in ("repository", "source_sha", "run_id", "run_attempt", "artifact_id", "artifact_digest")}
        expected_origin |= {"job_id": reference["producer_job_id"], "producer_name": reference["producer_name"], "step": "applied", **indexed[name]}
        c.require(c.canonical(old["files"][name]) == c.canonical(expected_origin), "fence Phase A original public/private origin")
    observed = {}
    for report in original["checkpoint"]["readbacks"]:
        if report["service"] == "iam" and report["operation"] in {"get_role", "get_role_policy"}:
            body = report["observed"]
            name = body.get("Role", {}).get("RoleName") if report["operation"] == "get_role" else body.get("RoleName")
            if name == role["role_name"]:
                c.require(report["operation"] not in observed, "fence unique original role readback")
                observed[report["operation"]] = body
    c.require(set(observed) == {"get_role", "get_role_policy"}, "fence complete original role readbacks")
    native_role, native_policy = observed["get_role"]["Role"], observed["get_role_policy"]
    c.require(native_role["Arn"] == role["role_arn"] and native_role["RoleId"] == role["role_id"]
              and native_role["MaxSessionDuration"] == role["max_session_duration"] and not native_role.get("PermissionsBoundary")
              and native_role["Tags"] == [{"Key": "ReleaseId", "Value": old["canary_id"]}]
              and c.canonical(native_role["AssumeRolePolicyDocument"]) == c.canonical(role["trust"])
              and native_policy["PolicyName"] == role["policy_name"]
              and c.canonical(native_policy["PolicyDocument"]) == c.canonical(role["policy"])
              and original_plan["phase_a_inputs"]["canary_trusted_principal_arn"] == fragment["application_role_arn"],
              "fence role projection matches original carried IAM bytes")
    c.require(current_plan["plan_binary_sha256"] == checkpoint["plan_sha256"], "fence current applied saved plan")
    approval = values["approval.json"]
    c.require(current_plan["inputs_sha256"] == approval["inputs_sha256"], "fence current original inputs")
    c.closed(approval, "version owner purpose direction plan_sha256 inputs_sha256 checkpoint_sha256 delta drift_matrix readbacks")
    c.closed(approval["delta"], "purpose direction mode before original created expected_changes_sha256")
    c.require(type(approval["version"]) is int and approval["version"] == 1 and c.canonical(approval["owner"]) == c.canonical(owner)
              and approval["purpose"] == checkpoint["purpose"] == "application-prepare" and approval["direction"] == "advance"
              and approval["plan_sha256"] == checkpoint["plan_sha256"]
              and approval["checkpoint_sha256"] == chain["entries"][-1]["previous_checkpoint_sha256"]
              and all(approval["delta"][key] == FENCE_PREPARE_PRODUCER[key] for key in ("purpose", "direction", "mode")), "fence original applied deploy branch")
    _fence_readback_document(values["fence-readbacks.json"], role, preparation)
    evaluation = values["fence-evaluation.json"]
    c.require(evaluation["evaluator_source_sha"] == producer["workflow_sha"], "fence original evaluator source")
    c.closed(evaluation["documents"], "application_identity application_managed application_session fence_identity fence_session freeze")
    for digest in evaluation["documents"].values():
        c.digest(digest)
    c.require(type(evaluation["cases"]) is list and len(evaluation["cases"]) == len(FENCE_EVALUATION_CASES), "fence complete effective IAM cases")
    seen = set()
    for case in evaluation["cases"]:
        c.closed(case, "case_id action resource context expected observed")
        c.require(case["case_id"] in FENCE_EVALUATION_CASES and case["case_id"] not in seen
                  and case["action"] == FENCE_EVALUATION_CASES[case["case_id"]]
                  and type(case["resource"]) is str and 1 <= len(case["resource"]) <= 2048 and type(case["context"]) is dict
                  and type(case["expected"]) is bool and type(case["observed"]) is bool and case["expected"] == case["observed"], "fence original IAM evaluation result")
        c.require(set(case["context"]) <= {"sts:RoleSessionName", "dynamodb:LeadingKeys", "aws:CurrentTime"}, "fence finite IAM context keys")
        for key, value in case["context"].items():
            if key == "dynamodb:LeadingKeys":
                c.require(type(value) is list and len(value) <= 2 and all(type(x) is str and len(x) <= 128 for x in value), "fence finite IAM leading keys")
            else:
                c.require(type(value) is str and 1 <= len(value) <= 128, "fence finite IAM context value")
        seen.add(case["case_id"])
    return manifest


def validate_adapter_request(raw, *, operation, owner, window, inputs, activation_sha256):
    """ABI3 byte binding only; provenance and domain validators remain mandatory.

    The old generic canary adapter route is deliberately unavailable: #499 uses
    different identities and producers that must be integrated before dispatch.
    """
    request = c.loads(raw, canonical=True, limit=128 * 1024)
    c.closed(request, "abi_version operation repository source_sha owner checkpoint_sha256 activation_sha256 stage inputs")
    c.require(type(request["abi_version"]) is int and request["abi_version"] == ADAPTER_ABI_VERSION
              and operation in ADAPTER_INPUTS and request["operation"] == operation, "closed adapter ABI/operation")
    identity = application_identity(owner, required=True)
    c.require(identity["application_purpose"] == "promotion" and application_identity(window, required=True) == identity,
              "original adapter purpose/caller")
    c.require(request["repository"] == owner["repository"] == c.REPOSITORY
              and request["source_sha"] == c.digest(owner["source_sha"], 40), "adapter original source")
    c.closed(request["owner"], " ".join(OWNER_FIELDS) + " owner_sha256")
    c.require(request["owner"] == {key: owner[key] for key in [*OWNER_FIELDS, "owner_sha256"]}, "adapter original owner")
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(request["owner"][key])
    for key in ("release_sha256", "session_sha256", "owner_sha256"):
        c.digest(request["owner"][key])
    c.closed(request["stage"], ADAPTER_STAGE_FIELDS)
    c.require(request["stage"] == {key: window[key] for key in ADAPTER_STAGE_FIELDS.split()}
              and window["stage"] in ADAPTER_STAGES[operation], "adapter original stage")
    c.require(request["checkpoint_sha256"] == c.digest(window["checkpoint_sha256"])
              and request["activation_sha256"] == c.digest(activation_sha256), "adapter original checkpoint/activation")
    c.closed(request["inputs"], ADAPTER_INPUTS[operation])
    c.require(type(inputs) is dict and set(inputs) == set(request["inputs"]), "adapter complete original input inventory")
    for name, reference in request["inputs"].items():
        c.closed(reference, "sha256 size")
        c.integer(reference["size"], 1, 128 * 1024**2)
        c.require(type(inputs[name]) is bytes and len(inputs[name]) == reference["size"]
                  and c.sha(inputs[name]) == c.digest(reference["sha256"]), "adapter original input bytes")
    return request


def validate_adapter_result(raw, *, request, observations, call_receipts, pending, unknown):
    """Compare with the shared broker journal, never an adapter success flag."""
    result = c.loads(raw, canonical=True, limit=128 * 1024)
    c.closed(result, "abi_version operation owner_sha256 generation checkpoint_sha256 observations call_receipts_sha256 pending unknown")
    c.integer(result["generation"])
    c.require(type(result["abi_version"]) is int and result["abi_version"] == ADAPTER_ABI_VERSION
              and result["operation"] == request["operation"] in ADAPTER_INPUTS
              and result["owner_sha256"] == request["owner"]["owner_sha256"]
              and result["generation"] == request["owner"]["generation"]
              and result["checkpoint_sha256"] == request["checkpoint_sha256"], "adapter result original binding")
    c.require(type(result["observations"]) is list and result["observations"] == observations, "adapter registered observations")
    for item in result["observations"]:
        c.closed(item, "kind sha256 size")
        c.require(item["kind"] == ADAPTER_OBSERVATIONS[result["operation"]], "adapter operation observation")
        c.digest(item["sha256"])
        c.integer(item["size"], 1, 1024**2)
    c.require(type(call_receipts) is list and result["call_receipts_sha256"] == c.sha(c.canonical(call_receipts)),
              "adapter original call receipts")
    for key, original in (("pending", pending), ("unknown", unknown)):
        c.require(type(result[key]) is list and result[key] == original, "adapter uncertainty must be preserved")
        for item in result[key]:
            c.closed(item, "kind reference_sha256")
            c.require(type(item["kind"]) is str and 1 <= len(item["kind"]) <= 64, "adapter uncertainty kind")
            c.digest(item["reference_sha256"])
    return result


def _product_context_bytes(value):
    """Product A3 UTF-8 codec; deliberately distinct from ASCII session names."""
    import json
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    c.require(len(raw) <= 131072, "mode context full request bound")
    return raw


def _mode_instant(value, label):
    try:
        moment = int(c.instant(value))
    except ValueError:
        moment = None
    c.require(moment is not None and c.utc(moment) == value, f"mode {label} instant")
    return moment


def decode_mode_context(inputs_raw):
    """Decode the adopted wrapper inside the entire bounded generated request.

    This codec accepts no alternate representation or silent normalization. Its
    return is not admission: all fifteen manifest fields require semantic and
    original-evidence validation separately.
    """
    inputs = c.loads(inputs_raw, limit=131072)
    c.require(_product_context_bytes(inputs) == inputs_raw and type(inputs) is dict
              and type(inputs.get("mode_canary")) is dict, "mode context original request bytes")
    wrapper = inputs["mode_canary"].get("context_manifest")
    c.closed(wrapper, "canonical_utf8 sha256")
    c.require(type(wrapper["canonical_utf8"]) is str, "mode context UTF-8 text")
    raw = wrapper["canonical_utf8"].encode("utf-8")
    c.require(c.sha(raw) == c.digest(wrapper["sha256"]), "mode context inner bytes digest")
    manifest = c.loads(raw, limit=131072)
    c.require(type(manifest) is dict and _product_context_bytes(manifest) == raw, "mode context canonical inner bytes")
    return manifest, raw


def validate_mode_context(inputs_raw, *, owner, application_purpose, originals):
    """Bind the adopted manifest to protected originals and derive finite sessions.

    The caller must authenticate owner and every original producer before using
    this pure check. This neither admits STS nor proves the mode policy oracle.
    """
    manifest, raw = decode_mode_context(inputs_raw)
    original_fields = ("product_source_sha product_source_closure_sha256 shared_source_sha shared_source_closure_sha256 "
                       "release_id activation_sha256 resources_sha256 fixture_manifest_sha256 scenario_plan_sha256 "
                       "predecessor_terminal_sha256 admitted_at deadline")
    owner_fields = "repository run_id run_attempt generation owner_sha256"
    c.closed(manifest, "schema_version context_kind owner " + original_fields)
    c.closed(originals, original_fields)
    c.closed(manifest["owner"], owner_fields)
    identity = application_identity(owner, required=True)
    c.require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 2
              and application_purpose == identity["application_purpose"]
              and manifest["context_kind"] == identity["context_kind"], "mode context original purpose/schema")
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(manifest["owner"][key])
        c.integer(owner[key])
    c.require(manifest["owner"]["repository"] == c.REPOSITORY
              and manifest["owner"] == {key: owner[key] for key in owner_fields.split()}, "mode context original owner")
    c.digest(manifest["owner"]["owner_sha256"])
    c.require(c.canonical({key: manifest[key] for key in original_fields.split()}) == c.canonical(originals),
              "mode context original producer commitments")
    for key in ("product_source_sha", "shared_source_sha"):
        c.digest(manifest[key], 40)
    c.require(manifest["product_source_sha"] == c.digest(owner["source_sha"], 40), "mode context current source")
    for key in ("product_source_closure_sha256", "shared_source_closure_sha256", "activation_sha256", "resources_sha256",
                "fixture_manifest_sha256", "scenario_plan_sha256"):
        c.digest(manifest[key])
    c.require(type(manifest["release_id"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", manifest["release_id"]),
              "mode context release id")
    predecessor = manifest["predecessor_terminal_sha256"]
    if predecessor is not None:
        c.digest(predecessor)
    c.require(manifest["context_kind"] != "readiness" or predecessor is not None, "readiness original predecessor")
    admitted, deadline = (_mode_instant(manifest[key], "context " + key) for key in ("admitted_at", "deadline"))
    maximum = PROMOTION_CONTEXT_SECONDS if manifest["context_kind"] == "promotion" else 14400
    c.require(0 < deadline - admitted <= maximum, "mode context original bounded deadline")
    digest = c.sha(raw)
    sessions = {alias: [] for alias in MODE_ALIASES}
    for operation, (_, alias, context, phase) in MODE_SESSION_OPERATIONS.items():
        if context != manifest["context_kind"]:
            continue
        binding = {key: manifest[key] for key in ("schema_version", "context_kind", "product_source_sha", "product_source_closure_sha256",
                   "shared_source_sha", "shared_source_closure_sha256", "release_id", "activation_sha256")}
        binding.update(manifest["owner"], operation=operation, phase=phase, context_manifest_sha256=digest)
        sessions[alias].append(mode_session(binding, application_purpose)["session_name"])
    return {"manifest": manifest, "context_manifest_sha256": digest,
            "delegation_sessions": {alias: sorted(set(names)) for alias, names in sessions.items()}}


def validate_closed_ready_call(*, request, role, service, operation, parameters, account, control_table_arn, machine_arn, members):
    """F2 request scope from protected resources and original frozen membership.

    This does not authenticate artifacts or replace the domain producer. The
    broker must validate those originals before providing these arguments.
    """
    c.require(request["operation"] == "closed-ready" and request["stage"]["stage"] == "api"
              and role == "fence_operator" and (service, operation) in {("dynamodb", "get_item"), ("stepfunctions", "describe_execution")},
              "closed-ready finite SDK operation")
    c.require(type(account) is str and re.fullmatch(r"[0-9]{12}", account), "closed-ready account")
    table = re.fullmatch(r"arn:aws:dynamodb:us-east-2:" + account + r":table/(cnesdata-prod-[A-Za-z0-9_.-]+)", control_table_arn)
    c.require(table and re.fullmatch(r"arn:aws:states:us-east-2:" + account + r":stateMachine:cnesdata-prod", machine_arn),
              "closed-ready protected resource scope")
    if service == "dynamodb":
        c.closed(parameters, "TableName Key ConsistentRead")
        allowed = [{"TableName": table[1], "Key": {"pk": {"S": pk}, "sk": {"S": sk}}, "ConsistentRead": True}
                   for pk, sk in (("ENV#prod#FENCE", "FENCE"), ("ENV#prod#SEMAPHORE", "UNIT"))]
        c.require(any(c.canonical(parameters) == c.canonical(value) for value in allowed), "closed-ready strong original gate read")
        return parameters
    c.require(type(members) is list and len(members) <= 4096, "closed-ready frozen membership bound")
    executions, dispatches = set(), set()
    for member in members:
        c.closed(member, "dispatch_id request_sha256 generation initial_state execution_ref resolution proof_sha256 observed_at send_disabled_at")
        dispatch = c.digest(member["dispatch_id"], 16)
        c.require(dispatch not in dispatches, "closed-ready duplicate member")
        dispatches.add(dispatch)
        c.integer(member["generation"], 0)
        c.digest(member["request_sha256"])
        c.digest(member["proof_sha256"])
        execution = machine_arn.replace(":stateMachine:", ":execution:") + ":" + dispatch
        c.require((member["resolution"] == "TERMINAL" and member["execution_ref"] == execution)
                  or (member["resolution"] == "CANCEL_BEFORE_SEND" and member["execution_ref"] is None),
                  "closed-ready original member execution")
        executions.add(execution)
    c.closed(parameters, "executionArn includedData")
    c.require(parameters["executionArn"] in executions and parameters["includedData"] == "METADATA_ONLY",
              "closed-ready exact fresh metadata probe")
    return parameters


def closed_ready_probe_response(response, *, execution_arn, machine_arn):
    """Discard execution payloads before any receipt, artifact or adapter IPC."""
    c.require(type(response) is dict and response.get("input") in (None, "") and response.get("output") in (None, ""),
              "unexpected private execution payload")
    c.require(response.get("executionArn") == execution_arn and response.get("stateMachineArn") == machine_arn
              and response.get("name") == execution_arn.rsplit(":", 1)[1]
              and response.get("status") in {"RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"}
              and "startDate" in response, "closed-ready original execution response")
    return {key: response[key] for key in ("executionArn", "stateMachineArn", "name", "status", "startDate", "stopDate") if key in response}


FENCE_SDK_OPERATIONS = {
    "closed-ready": frozenset({("dynamodb", "get_item"), ("stepfunctions", "describe_execution")}),
    "close-drain": frozenset({("dynamodb", "get_item"), ("dynamodb", "update_item"), ("dynamodb", "transact_write_items"),
                              ("stepfunctions", "describe_execution")}),
}
# Correction 6906038586 item 3: sha256 of each canonical template of the product call vector
# (CnesData 2c66f62c tests/production/delivery/close_drain_call_vector.json, sha256 44d0cf91...).
CLOSE_DRAIN_TEMPLATES = {
    "describe_execution": frozenset({"73abbbba755b953e02c6f9438ad7970e1700692cb4e01d4f8c811139a59b1ac8"}),
    "get_item": frozenset({"d61d73ab325a8325b9f6116c7e587d18d6a8ff343c49237632a35b17928a8ac3",
                           "6a14005ede4a28abbae4e8d0d38e6b8a4270d6570e263b59b6ef212162e5aacf"}),
    "transact_write_items": frozenset({"488182a89ce72bff7532ce45a759f334518b81702afddc421b9fb64251673d43"}),
    "update_item": frozenset({"20178d9ee8df5eb38a3b210d97631fd81384ebed7ffd4cd66e4dc953a201b42f"}),
    "close_transaction.update": frozenset({"e571c06ad956c46aed25786e104768ea1bfc10a12e1c967d1ccea63ee70b2ab8",
                                           "2e7ecb7704b6e3f94c01ede6c3ef22816d7383511b545c13fddc41882fda730e"}),
    "close_transaction.condition_check": frozenset({"6df09e291a7b1db922f9428fb32b3291ba85ceff4fd1683e37ffc0adfb91a1f5",
                                                    "ab59c7ddffe33fdf00a4e0cf8a73494c955e5ca5ef7dc7d08b57aa3ceb74880a"}),
}
CLOSE_DRAIN_PLACEHOLDERS = {
    "execution": "<state-machine-execution>:<dispatch_id>",
    "semaphore": "<AND over sorted semaphore attributes: #vN = :vN | attribute_not_exists(#vN)>",
    "transact": ["<close_transaction.update>", "<close_transaction.condition_check>"],
}
_DYNAMODB_TYPES = frozenset({"S", "N", "B", "SS", "NS", "BS", "M", "L", "NULL", "BOOL"})


def _pinned(kind, template):
    c.require(c.sha(c.canonical(template, limit=128 * 1024)) in CLOSE_DRAIN_TEMPLATES[kind], "close-drain pinned " + kind + " template")


def _semaphore_check(check, item):
    if item is None:
        return check
    c.closed(check, "TableName Key ConditionExpression ExpressionAttributeNames ExpressionAttributeValues")
    names, values = check["ExpressionAttributeNames"], check["ExpressionAttributeValues"]
    c.require(type(names) is dict and 1 <= len(names) <= 64 and set(names) == {f"#v{index}" for index in range(len(names))},
              "close-drain semaphore attribute names")
    attributes = [names[f"#v{index}"] for index in range(len(names))]
    c.require(all(type(name) is str for name in attributes) and attributes == sorted(set(attributes))
              and not {"pk", "sk"} & set(attributes) and set(item) - {"pk", "sk"} <= set(attributes),
              "close-drain semaphore sorted attributes")
    conditions, expected = [], {}
    for index, name in enumerate(attributes):
        if name in item:
            conditions.append(f"#v{index} = :v{index}")
            expected[f":v{index}"] = item[name]
        else:
            conditions.append(f"attribute_not_exists(#v{index})")
    c.require(check["ConditionExpression"] == " AND ".join(conditions)
              and c.canonical(values) == c.canonical(expected), "close-drain semaphore CAS equals the strong read")
    return {key: check[key] for key in ("TableName", "Key")} | {
        key: CLOSE_DRAIN_PLACEHOLDERS["semaphore"] for key in ("ConditionExpression", "ExpressionAttributeNames", "ExpressionAttributeValues")}


def _close_history(history):
    c.require(type(history) in (list, tuple) and len(history) <= 8192, "close-drain journal history")
    semaphore, writes = (), []
    for entry in history:
        c.closed(entry, "call response")
        call = entry["call"]
        if call["operation"] == "get_item" and call["parameters"]["Key"]["pk"]["S"] == "ENV#prod#SEMAPHORE":
            semaphore = (entry["response"].get("Item"),)
        if call["operation"] in {"update_item", "transact_write_items"}:
            writes.append(call)
    return semaphore, writes


def _typed_values(values):
    c.require(type(values) is dict and 1 <= len(values) <= 64
              and all(type(item) is dict and len(item) == 1 and set(item) <= _DYNAMODB_TYPES for item in values.values()),
              "close-drain typed expression values")
    return sorted(values)


def _close_transaction(parameters, item, owner_sha256, call, table):
    c.closed(parameters, "TransactItems")
    items = parameters["TransactItems"]
    c.require(type(items) is list and len(items) == 2 and type(items[0]) is dict and list(items[0]) == ["Update"]
              and type(items[1]) is dict and list(items[1]) == ["ConditionCheck"]
              and type(items[0]["Update"]) is dict and type(items[1]["ConditionCheck"]) is dict, "close transaction shape")
    _pinned("transact_write_items", call | {"parameters": {"TransactItems": CLOSE_DRAIN_PLACEHOLDERS["transact"]}})
    update, check = items[0]["Update"], items[1]["ConditionCheck"]
    values = update.get("ExpressionAttributeValues")
    _pinned("close_transaction.update", {"Update": update | {"ExpressionAttributeValues": _typed_values(values)}})
    c.require(update["TableName"] == check.get("TableName") == table and values[":state"] == {"S": "CLOSED"}
              and values[":entity"] == {"S": "PROMOTIONFENCE"} and values[":promotion"] == {"S": owner_sha256}
              and values.get(":open", {"S": "OPEN"}) == {"S": "OPEN"}
              and re.fullmatch(r"[1-9][0-9]{0,17}", values[":version"].get("N", "")), "close transaction original owner values")
    _pinned("close_transaction.condition_check", {"ConditionCheck": _semaphore_check(check, item)})


def _close_confirm(parameters, transact, call, table):
    c.closed(parameters, "TableName Key UpdateExpression ConditionExpression ExpressionAttributeNames ExpressionAttributeValues")
    values = parameters["ExpressionAttributeValues"]
    _pinned("update_item", call | {"parameters": parameters | {"ExpressionAttributeValues": _typed_values(values)}})
    version = transact["parameters"]["TransactItems"][0]["Update"]["ExpressionAttributeValues"][":version"]
    c.require(parameters["TableName"] == table and values[":closed"] == {"S": "CLOSED"} and values[":version"] == version
              and list(values[":confirmed"]) == ["S"], "close confirm of the transaction version")


def validate_close_drain_call(*, request, role, service, operation, parameters, account, control_table_arn, machine_arn, history=()):
    """Decision 4 and correction 6906038586: finite close-drain scope pinned to the product vector.

    Writes stay inside the close: one transaction after a strong SEMAPHORE read, then one
    confirm of that version, then none. This is not artifact or domain authentication.
    """
    stage = request["stage"]
    c.require(request["operation"] == "close-drain" and stage["stage"] == "application-prepare" and stage["close"] is None
              and stage["decision"] is None and role == "fence_operator"
              and (service, operation) in FENCE_SDK_OPERATIONS["close-drain"], "close-drain finite SDK operation")
    c.require(type(account) is str and re.fullmatch(r"[0-9]{12}", account) and type(control_table_arn) is str
              and type(machine_arn) is str and type(parameters) is dict, "close-drain account/scope")
    table = re.fullmatch(r"arn:aws:dynamodb:us-east-2:" + account + r":table/(cnesdata-prod-[A-Za-z0-9_.-]+)", control_table_arn)
    c.require(table and machine_arn == "arn:aws:states:us-east-2:" + account + ":stateMachine:cnesdata-prod",
              "close-drain protected resource scope")
    call = {"role": role, "service": service, "operation": operation}
    if operation == "describe_execution":
        c.closed(parameters, "executionArn includedData")
        prefix, arn = machine_arn.replace(":stateMachine:", ":execution:") + ":", parameters["executionArn"]
        c.require(type(arn) is str and arn.startswith(prefix) and re.fullmatch(r"[0-9a-f]{16}", arn[len(prefix):]),
                  "close-drain exact execution probe")
        _pinned("describe_execution", call | {"parameters": parameters | {"executionArn": CLOSE_DRAIN_PLACEHOLDERS["execution"]}})
        return parameters
    if operation == "get_item":
        c.require(parameters.get("TableName") == table[1], "close-drain protected table")
        _pinned("get_item", call | {"parameters": parameters})
        return parameters
    semaphore, writes = _close_history(history)
    if operation == "transact_write_items":
        c.require(not writes and semaphore != (), "close transaction once, after a strong SEMAPHORE read")
        _close_transaction(parameters, semaphore[0], request["owner"]["owner_sha256"], call, table[1])
    else:
        c.require([write["operation"] for write in writes] == ["transact_write_items"], "close confirm once, after the transaction")
        _close_confirm(parameters, writes[0], call, table[1])
    return parameters


def validate_fence_call(*, request, history=(), **arguments):
    """Per-operation fence SDK scope; closed-ready keeps its frozen-member validator."""
    if request["operation"] == "close-drain":
        return validate_close_drain_call(request=request, history=history, **arguments)
    return validate_closed_ready_call(request=request, **arguments)


def application_caller_binding(evidence, producer):
    """Exact codec for separately authenticated source/run/claim observations."""
    c.closed(evidence, CALLER_BINDING_FIELDS + " event fragment_version")
    purpose = evidence["application_purpose"]
    c.require(purpose in APPLICATION_CONTEXTS and evidence["context_kind"] == APPLICATION_CONTEXTS[purpose],
              "application purpose/context")
    c.require(type(evidence["fragment_version"]) is int and evidence["fragment_version"] == 4
              and evidence["event"] == "workflow_dispatch", "application original manual schema4 caller")
    c.require(all(evidence[k] == value for k, value in APPLICATION_CALLERS[purpose].items()), "application exact purpose caller")
    c.require(evidence["producer_workflow_sha"] == c.digest(producer["workflow_sha"], 40)
              and evidence["producer_source_closure_sha256"] == c.digest(producer["source_closure_sha256"]),
              "application original producer closure")
    c.digest(evidence["source_sha"], 40)
    for name in ("run_id", "run_attempt"):
        c.integer(evidence[name])
    return {key: evidence[key] for key in CALLER_BINDING_FIELDS.split()}


def mode_session(binding, application_purpose):
    """Fourteen nominal algorithms only; a codec is not a preparation receipt."""
    c.closed(binding, "schema_version context_kind operation phase repository product_source_sha product_source_closure_sha256 "
             "shared_source_sha shared_source_closure_sha256 release_id activation_sha256 run_id run_attempt generation owner_sha256 context_manifest_sha256")
    c.require(type(binding["schema_version"]) is int and binding["schema_version"] == 2
              and binding["repository"] == c.REPOSITORY and binding["operation"] in MODE_SESSION_OPERATIONS,
              "mode session nominal operation")
    code, alias, context, phase = MODE_SESSION_OPERATIONS[binding["operation"]]
    c.require(application_purpose in APPLICATION_CONTEXTS and APPLICATION_CONTEXTS[application_purpose] == context
              and binding["context_kind"] == context and binding["phase"] == phase, "mode session original purpose/phase")
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(binding[key])
    for key, value in binding.items():
        if key not in {"schema_version", "run_id", "run_attempt", "generation"}:
            c.require(type(value) is str and value.isascii(), "mode session ASCII strings")
    for key in ("product_source_sha", "shared_source_sha"):
        c.digest(binding[key], 40)
    for key in ("product_source_closure_sha256", "shared_source_closure_sha256", "activation_sha256", "owner_sha256", "context_manifest_sha256"):
        c.digest(binding[key])
    c.require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", binding["release_id"]), "mode session release id")
    digest = c.sha(c.canonical(binding))
    return {"alias": alias, "session_name": "mc-" + code + "-" + digest[:40], "binding_sha256": digest}


PURPOSES = frozenset({"application-prepare", "phase-b", "phase-c-recovery", "phase-c-audit", "static-maintenance"})
STAGES = {"phase-b": (360, 720), "api": (180, 360), "static": (180, 360), "unit": (120, 360),
          "phase-c-recovery": (240, 660), "phase-c-audit": (240, 660), "final": (60, 180)}
FINAL_RESERVE = 420
STAGE_SUM_CEILING = 1830
PROMOTION_CONTEXT_SECONDS = 1200
# Amendment 6886977054 decision 3: only the ratified transitions. close -> B has no external
# event (the close CAS enters phase-b); every transition after the API needs its own amendment.
# P02 DD-3 rows: static -> unit is internal (the settled publish-static); unit is internal (the unit
# acceptance); the two C rows are external (the C deploy job) plus the acceptance of their mode.
STAGE_TRIGGERS = {"application-prepare": ("prepared", "phase-b"), "phase-b": ("phase-b", "api"), "api": ("host", "static"),
                  "static": ("publish-static", "unit"),
                  "unit": ("unit", "phase-c-recovery"),
                  "phase-c-recovery": ("phase-c-recovery", "phase-c-audit"),
                  "phase-c-audit": ("phase-c-audit", "final")}
OPERATION_TRIGGERS = {"inventory": ("application-prepare", "observer-bootstrap"),
                      "rollback-api-static": ("recovery", "host-recovery")}
MODE_STAGE_PREVIOUS = {"phase-c-recovery": "unit", "phase-c-audit": "phase-c-recovery", "final": "phase-c-audit"}
CLOSE_DRAIN_FIELDS = ("version kind common fence close_confirmed_at drain_observed_at frozen_membership_sha256 members proofs "
                      "permit input_expirations fixed_deadline decision windows")
CLOSE_EXPIRATION_KINDS = frozenset({"envelope", "artifact", "platform", "cost", "credential", "activation", "plan"})
OWNER_FIELDS = "repository source_sha run_id run_attempt release_sha256 generation session_sha256".split()
STATE_MACHINE = "module.processing.aws_sfn_state_machine.processor[0]"
API_POLICY = "module.runtime_iam.aws_iam_role_policy.api[0]"

# Pinned AWS6.54.0 native schema: computed=true, optional/required absent.
# Proof sha256 9a477dedf8b09ed69f33033917c72b7187bc1b415f90b1daaba972411255c123.
COMPUTED_OUTPUTS = {
    "aws_sfn_state_machine": {"arn", "creation_date", "description", "revision_id", "state_machine_version_arn", "status", "version_description"},
    "aws_scheduler_schedule": {"arn"},
    "aws_scheduler_schedule_group": {"arn", "creation_date", "last_modification_date", "state"},
    "aws_iam_role": {"arn", "create_date", "unique_id"},
    "aws_iam_role_policy": set(),
    "aws_cloudwatch_event_rule": {"arn"},
    "aws_cloudwatch_metric_alarm": {"arn"},
}


def scheduler_closure(mode):
    c.require(mode in {"recovery", "audit"}, "scheduler mode")
    fields = [f'aws_scheduler_schedule.mode["{mode}"]', f'aws_scheduler_schedule_group.mode["{mode}"]',
              f'aws_cloudwatch_event_rule.task_outcome["{mode}_failed"]',
              f'aws_cloudwatch_metric_alarm.repeated_failure["{mode}"]',
              f'aws_cloudwatch_metric_alarm.lost_invocation["{mode}"]']
    if mode == "audit":
        fields += ['aws_cloudwatch_event_rule.task_outcome["audit_succeeded"]',
                   'aws_cloudwatch_metric_alarm.outbox_backlog[0]']
    return {"module.schedulers." + name for name in fields}


def state_resources(state):
    """Actual raw state address map; reject deposed/multiple identities."""
    result = {}
    for row in state.get("resources", []):
        if row.get("mode") != "managed":
            continue
        prefix = (row.get("module", "") + ".").lstrip(".") + row["type"] + "." + row["name"]
        for instance in row.get("instances", []):
            c.require(not instance.get("deposed"), "deposed state is uncertain")
            suffix = "[" + c.canonical(instance["index_key"]).decode().strip() + "]" if "index_key" in instance else ""
            address = prefix + suffix
            c.require(address not in result, "duplicate state identity")
            result[address] = instance["attributes"]
    return result



def has_unknown(value):
    """Terraform masks are recursive booleans; an empty/false block is known."""
    if type(value) is bool:
        return value
    c.require(type(value) in {dict, list}, "malformed unknown mask")
    values = value.values() if type(value) is dict else value
    return any([has_unknown(item) for item in values])

def mode_fixture_manifest_sha256(manifest):
    """Args: authenticated product source manifest. Returns: fixture-manifest.json digest. Raises: ValueError."""
    files = manifest["files"]
    c.require(type(files) is dict and MODE_FIXTURE_MANIFEST in files and type(files[MODE_FIXTURE_MANIFEST]) is str
              and re.fullmatch(r"[0-9a-f]{64}", files[MODE_FIXTURE_MANIFEST]) is not None, "mode fixture manifest original")
    return files[MODE_FIXTURE_MANIFEST]


def mode_canary_stage(before):
    """Args: audited full-state resources. Returns: initial or established. Raises: ValueError if partial."""
    c.require(type(before) is dict, "mode prepare baseline")
    present = MODE_ADDRESSES & set(before)
    c.require(present in (set(), MODE_ADDRESSES), "mode partial baseline")
    return "established" if present else "initial"


def _mode_inventory(plan):
    rows = {row["address"]: row for row in plan["resource_changes"]}
    c.require(len(rows) == len(plan["resource_changes"]) and MODE_ADDRESSES <= set(rows), "mode exact eight-address inventory")
    return rows


def _mode_row(row, before, stage):
    change = row["change"]
    c.require(not row.get("importing") and not change.get("importing"), "mode no import")
    c.require(row["mode"] == "managed", "mode managed inventory")
    c.require(change["before"] == before.get(row["address"]), "mode actual baseline")
    kind = "aws_iam_role" if ".aws_iam_role." in row["address"] else "aws_iam_role_policy"
    c.require(row["type"] == kind, "mode exact resource kind")
    if change["actions"] == ["no-op"]:
        c.require(type(change["after"]) is dict and change["before"] == change["after"]
                  and not has_unknown(change.get("after_unknown", {})), "mode all other resources noop")
        return
    if stage == "initial":
        c.require(change["actions"] == ["create"] and change["before"] is None, "mode initial create only")
    else:
        c.require(change["actions"] == ["update"] and type(change["before"]) is dict, "mode established update only")
    c.require(type(change["after"]) is dict, "mode exact resource kind")
    computed = COMPUTED_OUTPUTS[kind] | {"id"}
    c.require(not has_unknown({key: value for key, value in change.get("after_unknown", {}).items()
                               if key not in computed}), "mode unknown authority")


def validate_mode_canary_delta(plan, before, *, stage):
    """Structural gate only; source/input/trust/output audit is also mandatory.

    Stage comes from the authenticated baseline, never a new caller wire field.
    This does not admit a prepare or replace the complete independent oracle.
    """
    c.require(stage in {"initial", "established"} and type(before) is dict, "mode prepare baseline")
    c._secrets(plan)
    rows = _mode_inventory(plan)
    c.require(set(before) <= set(rows), "mode exact eight-address inventory")
    for address, row in rows.items():
        if address in MODE_ADDRESSES:
            _mode_row(row, before, stage)
            continue
        change = row["change"]
        c.require(not row.get("importing") and not change.get("importing"), "mode no import")
        if row["mode"] != "managed":
            c.require(row["mode"] == "data" and change["actions"] in (["read"], ["no-op"]), "mode data read only")
            continue
        c.require(change["before"] == before.get(address), "mode actual baseline")
        c.require(change["actions"] == ["no-op"] and change["before"] == change["after"]
                  and not has_unknown(change.get("after_unknown", {})), "mode all other resources noop")
    return set(MODE_ADDRESSES)


def validate_mode_canary_input(inputs_raw, *, owner, application_purpose, principal_arn, originals, activation_sha256):
    """Bind the generated mode_canary input to the gate originals and to its own manifest.

    Args: request bytes, owner, purpose, principal, MODE_GATE_ORIGINALS, activation (promotion only).
    Returns: validate_mode_context result plus enabled_until and principal. Raises: ValueError.
    """
    manifest, _ = decode_mode_context(inputs_raw)
    mode = c.loads(inputs_raw, limit=131072)["mode_canary"]
    c.closed(mode, MODE_INPUT_FIELDS)
    c.closed(originals, MODE_GATE_ORIGINALS)
    c.require(type(mode["schema_version"]) is int and mode["schema_version"] == 2, "mode input schema")
    c.require(type(manifest) is dict and mode["context_kind"] == manifest.get("context_kind"), "mode input context")
    c.require(mode["owner"] == manifest.get("owner"), "mode input owner")
    c.require(mode["application_principal_arn"] == principal_arn, "mode application principal")
    promotion = manifest["context_kind"] == "promotion"
    if promotion:
        c.require(activation_sha256 is not None, "mode promotion activation original")
        bound = {"activation_sha256": c.digest(activation_sha256)}
    else:
        c.require(activation_sha256 is None, "mode readiness activation original")
        bound = {"activation_sha256": manifest.get("activation_sha256")}
    committed = {key: manifest.get(key) for key in MODE_PRODUCT_COMMITTED.split()}
    resources = {"resources_sha256": c.sha(c.canonical(mode["resources"])), "product_source_sha": owner["source_sha"]}
    context = validate_mode_context(inputs_raw, owner=owner, application_purpose=application_purpose,
                                    originals=originals | bound | committed | resources)
    c.require(mode["delegation_sessions"] == context["delegation_sessions"], "mode delegation sessions")
    admitted = _mode_instant(manifest["admitted_at"], "context admitted_at")
    enabled = _mode_instant(mode["enabled_until"], "enabled_until")
    c.require(admitted < enabled, "mode enabled_until after admission")
    c.require(promotion or enabled <= _mode_instant(manifest["deadline"], "context deadline"),
              "mode readiness enabled_until deadline")
    return context | {"enabled_until": mode["enabled_until"], "application_principal_arn": principal_arn}


def _mode_trust(admitted, alias, closed):
    statement = {"Effect": "Deny" if closed else "Allow", "Principal": {"AWS": admitted["application_principal_arn"]},
                 "Action": "sts:AssumeRole"}
    if not closed:
        statement["Condition"] = {"DateLessThan": {"aws:CurrentTime": admitted["enabled_until"]},
                                  "StringEquals": {"sts:RoleSessionName": admitted["delegation_sessions"][alias]}}
    return {"Version": "2012-10-17", "Statement": [statement]}


def _mode_document(after, field):
    c.require(type(after) is dict and type(after.get(field)) is str, "mode trust document")
    return c.loads(after[field].encode("utf-8"), limit=65536)


def validate_mode_canary_trust(plan, admitted):
    """Args: plan, validate_mode_canary_input result. Returns: role addresses. Raises: ValueError."""
    rows = _mode_inventory(plan)
    readiness = admitted["manifest"]["context_kind"] == "readiness"
    roles = []
    for alias in MODE_ALIASES:
        closed = readiness and alias == "mode_audit_launch"
        address = f"module.runtime_iam.aws_iam_role.{alias}[0]"
        c.require(_mode_document(rows[address]["change"]["after"], "assume_role_policy") == _mode_trust(admitted, alias, closed),
                  "mode trust document")
        if closed:
            policy = rows[f"module.runtime_iam.aws_iam_role_policy.{alias}[0]"]["change"]["after"]
            c.require(_mode_document(policy, "policy") == MODE_CLOSED_POLICY, "mode closed policy")
        roles.append(address)
    return sorted(roles)


def mode_readback_expected(resources, account):
    """Args: applied state resources, account. Returns: alias -> expected IAM readback. Raises: ValueError."""
    c.require(type(resources) is dict and MODE_ADDRESSES <= set(resources), "mode output applied inventory")
    expected = {}
    for alias in MODE_ALIASES:
        role = resources[f"module.runtime_iam.aws_iam_role.{alias}[0]"]
        policy = resources[f"module.runtime_iam.aws_iam_role_policy.{alias}[0]"]
        c.require(role["arn"] == f"arn:aws:iam::{account}:role/{role['name']}" and policy["role"] == role["name"],
                  "mode output applied inventory")
        expected[alias] = {
            "role": {"Role": {"RoleName": role["name"], "Arn": role["arn"],
                              "AssumeRolePolicyDocument": _mode_document(role, "assume_role_policy"),
                              "MaxSessionDuration": role["max_session_duration"]}},
            "policy": {"RoleName": policy["role"], "PolicyName": policy["name"],
                       "PolicyDocument": _mode_document(policy, "policy")}}
    return expected


def mode_observed_role(observed, role, attributes):
    """Args: observed get_role, state-derived Role fields, applied role attributes. Returns: observed. Raises: ValueError."""
    c.require(type(observed) is dict and set(observed) == {"Role"} and type(observed["Role"]) is dict
              and all(observed["Role"].get(key) == value for key, value in role.items())
              and observed["Role"].get("RoleId") == attributes.get("unique_id")
              and observed["Role"].get("Path") == attributes.get("path"), "mode output role identity")
    return observed


def admitted_delta(purpose, direction, mode):
    """Args: purpose, direction, mode. Raises: ValueError when the lifecycle delta rule refuses the combination."""
    if purpose == "application-prepare":
        c.require(direction == "advance" and mode in {"observer-bootstrap", "operational", "mode-canary"}, "prepare mode")
    elif purpose == "phase-b":
        c.require(mode in {"initial", "established"}, "B checkpoint mode")
    elif purpose.startswith("phase-c-"):
        c.require(mode in {"initial", "established"}, "C checkpoint mode")
    else:
        c.require(direction == "advance" and mode == "post-open", "maintenance after OPEN")


def validate_delta(plan, approval):
    """Source-bound independent audit plus closed structural phase oracle.

    approval is authenticated evidence, not workflow input. Its complete change
    digest includes exact values/unknown masks/output-relevant references; runtime
    additionally verifies actual checkpoint, source closure and binary digest.
    """
    c.closed(approval, "purpose direction mode before original created expected_changes_sha256")
    purpose, direction, mode = (approval[k] for k in ("purpose", "direction", "mode"))
    c.require(purpose in PURPOSES and direction in {"advance", "converge"}, "lifecycle purpose/direction")
    c._secrets(plan)
    changes = [r for r in plan.get("resource_changes", []) if r.get("mode") == "managed"
               and r["change"]["actions"] not in (["no-op"], ["read"])]
    c.require(c.sha(c.canonical(changes)) == c.digest(approval["expected_changes_sha256"]), "independent exact delta audit")
    c.require(len(changes) == len({r["address"] for r in changes}), "duplicate change")
    creates, updates = set(), {}
    oracle = frozenset()
    admitted_delta(purpose, direction, mode)
    if purpose == "application-prepare":
        if mode == "mode-canary":
            validate_mode_canary_delta(plan, approval["before"], stage=mode_canary_stage(approval["before"]))
            return changes
        if mode == "operational":
            oracle, rows, stage = MODE_ADDRESSES, _mode_inventory(plan), mode_canary_stage(approval["before"])
            for address in sorted(MODE_ADDRESSES):
                _mode_row(rows[address], approval["before"], stage)
        roles = ("observer",) if mode == "observer-bootstrap" else ("normal", "recovery")
        for name in roles:
            for kind in ("aws_iam_role", "aws_iam_role_policy"):
                address = f"module.runtime_iam.{kind}.static_{name}[0]"
                creates.add(address)
                updates[address] = {"assume_role_policy"} if kind == "aws_iam_role" else {"policy"}
    elif purpose == "phase-b":
        updates[STATE_MACHINE] = {"definition"}
        if mode == "initial":
            creates.add(STATE_MACHINE)
            updates[API_POLICY] = {"policy"}
    elif purpose.startswith("phase-c-"):
        target = purpose.removeprefix("phase-c-")
        creates = scheduler_closure(target) if mode == "initial" else set()
        updates[f'module.schedulers.aws_scheduler_schedule.mode["{target}"]'] = {"target"}
        updates[f'module.schedulers.aws_iam_role_policy.run["{target}"]'] = {"policy"}
    else:
        updates = {"module.static_web.aws_s3_bucket_lifecycle_configuration.this": {"rule"},
                   "module.static_web.aws_cloudfront_response_headers_policy.this": {"security_headers_config", "custom_headers_config"}}
    for row in changes:
        address, change = row["address"], row["change"]
        if address in oracle:
            continue
        before, after, actions = change["before"], change["after"], change["actions"]
        computed = COMPUTED_OUTPUTS.get(row["type"], set())
        c.require(address in creates | set(updates), "unapproved phase resource")
        c.require(before == approval["before"].get(address), "actual checkpoint resource")
        c.require(not row.get("importing") and actions in (["create"], ["update"], ["delete"]), "no imports/replacement")
        if actions == ["delete"]:
            c.require(direction == "converge" and address in creates and purpose != "application-prepare"
                      and address not in approval["original"] and approval["created"].get(address) == before,
                      "delete requires original absence and own exact create")
            c.require(after is None, "inverse delete after")
        elif actions == ["create"]:
            c.require(direction == "advance" and address in creates and before is None, "closed initial create")
        else:
            c.require(address in updates and type(before) is dict and type(after) is dict, "closed phase update")
            mutable = updates[address]
            if direction == "converge":
                original = approval["original"].get(address)
                c.require(type(original) is dict
                          and {key: after.get(key) for key in mutable} == {key: original.get(key) for key in mutable},
                          "original resource restoration required")
            c.require({k: v for k, v in before.items() if k not in mutable | computed}
                      == {k: v for k, v in after.items() if k not in mutable | computed}, "phase update invariant")
            if "aws_scheduler_schedule.mode" in address:
                def without_revision(value):
                    import copy
                    item = copy.deepcopy(value)
                    for target in item.get("target", []):
                        for ecs in target.get("ecs_parameters", []):
                            ecs.pop("task_definition_arn", None)
                    return item
                c.require(without_revision({k: v for k, v in before.items() if k not in computed})
                          == without_revision({k: v for k, v in after.items() if k not in computed}), "scheduler target invariant")
        unknown = change.get("after_unknown", {})
        if actions == ["update"]:
            c.require(not has_unknown({k: v for k, v in unknown.items() if k not in computed}), "updated authority cannot be unknown")
        elif actions == ["create"]:
            c.require(set(k for k, v in unknown.items() if has_unknown(v)) <= computed | {"id", "tags_all"},
                      "unknown initial authority")
    return changes


APPLICATION_OWNER_FIELDS = ("application_purpose", "context_kind", "caller_binding_sha256")


def application_identity(value, *, required=False):
    """Atomic current caller fields; historical records keep their original form."""
    present = set(value) & set(APPLICATION_OWNER_FIELDS)
    if not present and not required:
        return {}
    c.require(present == set(APPLICATION_OWNER_FIELDS), "complete current application identity")
    purpose = value["application_purpose"]
    c.require(purpose in APPLICATION_CONTEXTS and value["context_kind"] == APPLICATION_CONTEXTS[purpose], "original application purpose/context")
    c.digest(value["caller_binding_sha256"])
    return {key: value[key] for key in APPLICATION_OWNER_FIELDS}


def owner_binding(record):
    c.require(record.get("lifecycle_version") == 1, "lifecycle owner protocol")
    c.require(record["repository"] == c.REPOSITORY, "owner repository")
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(record[key])
    c.digest(record["source_sha"], 40)
    for key in ("release_sha256", "session_sha256"):
        c.digest(record[key])
    return {key: record[key] for key in OWNER_FIELDS} | {"owner_sha256": c.sha(record["owner"].encode())} | application_identity(record)


class DelegatedLeaseView:
    """Read-only capability; renewal ETags may change, original owner may not."""
    def __init__(self, store, binding, *, clock=time.time, monotonic=None):
        c.closed(binding, " ".join(OWNER_FIELDS) + " owner_sha256 " + " ".join(application_identity(binding)))
        self.store, self.binding = store, dict(binding)
        self.clock, self.monotonic = clock, monotonic or clock
        self.failed = False

    def check(self):
        try:
            c.require(not self.failed, "delegated owner previously uncertain")
            value, etag = self.store.get()
            c.require(value is not None and etag is not None and value.get("status") == "held"
                      and owner_binding(value) == self.binding, "delegated owner changed/released")
            c.require(type(value.get("expires_at")) is int and value["expires_at"] > self.clock() + 157,
                      "delegated owner expiry")
            self.acquired_at = value["acquired_at"]
            if hasattr(self.store, "deadline"):
                c.require(self.monotonic() + 157 < self.store.deadline(value["expires_at"]),
                          "delegated owner clock uncertainty")
            return value
        except Exception:
            self.failed = True
            raise


def _window_keys(value):
    return ",".join(map(str, value)) if type(value) is dict else type(value).__name__


def _window_changes(before, after):
    def fields(value):
        value = value if type(value) is dict else {}
        stages = value.get("stages") if type(value.get("stages")) is dict else {}
        return {**{name: stages.get(name) for name in STAGES}, "fixed_deadline_seconds": value.get("fixed_deadline_seconds")}
    old, new = fields(before), fields(after)
    return ",".join(name for name in new if old[name] != new[name]) or "other"


def governed_windows(value):
    """Args: windows vector. Returns: the same vector. Raises: ValueError outside the code bounds."""
    c.closed(value, "stages fixed_deadline_seconds")
    stages, fixed = value["stages"], value["fixed_deadline_seconds"]
    c.require(type(stages) is dict and set(stages) == set(STAGES), "stage_windows keys=" + _window_keys(stages))
    for name, (low, high) in STAGES.items():
        seconds = stages[name]
        c.require(type(seconds) is int and low <= seconds <= high,
                  f"stage window stage={name} value={seconds} min={low} max={high}")
    total = sum(stages.values())
    c.require(total <= STAGE_SUM_CEILING, f"stage windows sum={total} ceiling={STAGE_SUM_CEILING}")
    post_static = later_seconds(value, "static")
    c.require(post_static <= PROMOTION_CONTEXT_SECONDS,
              f"stage_windows post_static={post_static} context={PROMOTION_CONTEXT_SECONDS}")
    c.require(type(fixed) is int and fixed == total + FINAL_RESERVE,
              f"fixed_deadline_seconds value={fixed} expected={total + FINAL_RESERVE}")
    return value


def stage_windows(governance):
    """Args: application governance. Returns: windows vector in stage order. Raises: ValueError; never a default."""
    for key in ("stage_windows", "fixed_deadline_seconds"):
        c.require(key in governance, f"governance key={key} absent")
    stages = governance["stage_windows"]
    c.require(type(stages) is dict and set(stages) == set(STAGES), "stage_windows keys=" + _window_keys(stages))
    return governed_windows({"stages": {name: stages[name] for name in STAGES},
                             "fixed_deadline_seconds": governance["fixed_deadline_seconds"]})


def later_seconds(windows, stage):
    order = list(STAGES)
    return sum(windows["stages"][name] for name in order[order.index(stage) + 1:])


def fixed_deadline(close, input_deadline, windows):
    return min(close + windows["fixed_deadline_seconds"], input_deadline)


def checkpoint_transition(previous, current):
    c.closed(current, "sequence preparation_deadline close fixed_deadline input_deadline stage admitted_at deadline decision checkpoint_sha256"
             + " windows" + (" predecessor_sha256" if "predecessor_sha256" in current else "")
             + " " + " ".join(application_identity(current)))
    if "predecessor_sha256" in current:
        c.digest(current["predecessor_sha256"])
    c.integer(current["sequence"], 0)
    c.digest(current["checkpoint_sha256"])
    c.require(current["preparation_deadline"] > 0, "preparation deadline")
    governed_windows(current["windows"])
    if previous is None:
        c.require(current["sequence"] == 0 and current["close"] is None
                  and current["fixed_deadline"] is None and current["decision"] is None,
                  "initial lifecycle is before fence")
    else:
        c.require(application_identity(current) == application_identity(previous), "original current caller cannot change")
        c.require(current.get("predecessor_sha256") == previous.get("predecessor_sha256"), "original historical reference cannot change")
        c.require(current["sequence"] == previous["sequence"] + 1
                  and current["preparation_deadline"] == previous["preparation_deadline"],
                  "checkpoint sequence/preparation rearm")
        c.require(current["windows"] == previous["windows"],
                  "original stage windows cannot change changed=" + _window_changes(previous["windows"], current["windows"]))
        if previous["close"] is not None:
            c.require(all(current[k] == previous[k] for k in ("close", "fixed_deadline", "input_deadline")),
                      "original fence cannot rearm")
        if previous["decision"] is not None:
            c.require(current["decision"] == previous["decision"], "original recovery cannot rearm")
        if current["stage"] == previous["stage"]:
            c.require(current["admitted_at"] == previous["admitted_at"] and current["deadline"] == previous["deadline"],
                      "same stage cannot rearm")
        elif current["decision"] is None:
            stages = ["application-prepare", *STAGES]
            c.require(previous["stage"] in stages and current["stage"] in stages
                      and stages.index(current["stage"]) == stages.index(previous["stage"]) + 1,
                      "normal phases cannot skip or retreat")
            c.require(current["admitted_at"] >= previous["admitted_at"], "stage admission precedes predecessor")
        else:
            c.require(current["stage"] == "recovery" and previous["stage"] != "recovery",
                      "recovery stage cannot restart")
    if current["close"] is not None:
        c.require(current["fixed_deadline"] == fixed_deadline(current["close"], current["input_deadline"], current["windows"]),
                  "original fixed deadline")


def close_window(previous, raw, *, checkpoint_sha256, infra_bound, now):
    """Decision 2: F from the keeper journal close-drain observation, never caller JSON.

    input_deadline is the earliest original expiration and F must equal the host's
    close.fixed_deadline. An earlier infra-known expiration refuses; it is never adopted.
    """
    value = c.closed(c.loads(raw, canonical=True, limit=1024**2), CLOSE_DRAIN_FIELDS)
    c.require(type(value["version"]) is int and value["version"] == 2 and value["kind"] == "close-drain",
              "close-drain observation version/kind")
    c.require(value["windows"] == governed_windows(previous["windows"]),
              "close-drain windows differ from keeper windows changed=" + _window_changes(previous["windows"], value["windows"]))
    c.require(value["permit"] is None and value["decision"] is None, "original idle permit/decision")
    expirations = value["input_expirations"]
    c.require(type(expirations) is list and expirations, "original input expirations")
    keys = []
    for expiry in expirations:
        c.closed(expiry, "kind object_sha256 expires_at")
        c.require(expiry["kind"] in CLOSE_EXPIRATION_KINDS, "original input expiration kind")
        keys.append((expiry["kind"], c.digest(expiry["object_sha256"])))
    c.require(keys == sorted(set(keys)), "unique original input expirations")
    close = int(c.instant(value["close_confirmed_at"]))
    input_deadline = int(min(c.instant(expiry["expires_at"]) for expiry in expirations))
    fixed = fixed_deadline(close, input_deadline, previous["windows"])
    c.require(c.instant(value["fixed_deadline"]) == fixed, "original fixed deadline")
    c.require(type(infra_bound) is int and input_deadline <= infra_bound,
              "infra-known authenticated expiration precedes input deadline")
    c.require(previous["stage"] == "application-prepare" and previous["close"] is None and previous["decision"] is None
              and previous["admitted_at"] <= close <= now and close < previous["preparation_deadline"],
              "close inside the preparation stage")
    return previous | {"sequence": previous["sequence"] + 1, "close": close, "fixed_deadline": fixed,
                       "input_deadline": input_deadline, "stage": "phase-b", "admitted_at": close,
                       "deadline": min(fixed, close + previous["windows"]["stages"]["phase-b"]),
                       "checkpoint_sha256": c.digest(checkpoint_sha256)}


def api_window(previous, *, checkpoint_sha256, now):
    """Decision 3, B -> API: admitted when the keeper observes the completed B publication, never at close."""
    admitted = int(now)
    c.require(previous["stage"] == "phase-b" and previous["close"] is not None and previous["decision"] is None
              and previous["admitted_at"] <= admitted, "API follows the closed phase-b stage")
    return previous | {"sequence": previous["sequence"] + 1, "stage": "api", "admitted_at": admitted,
                       "deadline": min(previous["fixed_deadline"], admitted + previous["windows"]["stages"]["api"]),
                       "checkpoint_sha256": c.digest(checkpoint_sha256)}


def static_window(previous, *, now):
    """DD-3, API -> static: admitted on the accepted host handoff; the host changes no state checkpoint."""
    admitted = int(now)
    c.require(previous["stage"] == "api" and previous["close"] is not None and previous["decision"] is None
              and previous["admitted_at"] <= admitted, "static follows the closed API stage")
    return previous | {"sequence": previous["sequence"] + 1, "stage": "static", "admitted_at": admitted,
                       "deadline": min(previous["fixed_deadline"], admitted + previous["windows"]["stages"]["static"])}


def unit_window(previous, *, now):
    """DD-3, static -> unit: admitted on the settled publish-static observation; publication changes no state checkpoint."""
    admitted = int(now)
    c.require(previous["stage"] == "static" and previous["close"] is not None and previous["decision"] is None
              and previous["admitted_at"] <= admitted, "unit follows the closed static stage")
    return previous | {"sequence": previous["sequence"] + 1, "stage": "unit", "admitted_at": admitted,
                       "deadline": min(previous["fixed_deadline"], admitted + previous["windows"]["stages"]["unit"])}


def mode_stage_window(previous, stage, *, now, checkpoint_sha256=None):
    """DD-3 after unit: unit -> phase-c-recovery keeps the checkpoint (the unit changes no state); the C
    transitions take the checkpoint of the C deploy that ran in the stage being left."""
    admitted = int(now)
    c.require(stage in MODE_STAGE_PREVIOUS, f"mode stage window stage={stage}")
    c.require(previous["stage"] == MODE_STAGE_PREVIOUS[stage] and previous["close"] is not None
              and previous["decision"] is None and previous["admitted_at"] <= admitted,
              f"{stage} follows the closed {MODE_STAGE_PREVIOUS[stage]} stage")
    c.require((checkpoint_sha256 is None) == (stage == "phase-c-recovery"), f"{stage} checkpoint")
    window = previous | {"sequence": previous["sequence"] + 1, "stage": stage, "admitted_at": admitted,
                         "deadline": min(previous["fixed_deadline"], admitted + previous["windows"]["stages"][stage])}
    return window if checkpoint_sha256 is None else window | {"checkpoint_sha256": c.digest(checkpoint_sha256)}


def phase_capacity(window, *, now, credential_deadline, operation_seconds):
    """Wall-clock samples are conservative; each admission spends existing time."""
    c.require(type(operation_seconds) in (int, float) and 0 < operation_seconds <= 1800,
              "bounded operation")
    c.require(now + operation_seconds + 120 < credential_deadline, "credential finalization margin")
    close, fixed = window["close"], window["fixed_deadline"]
    if close is None:
        c.require(fixed is None and window["stage"] == "application-prepare" and window["decision"] is None
                  and now + operation_seconds + 157 < window["preparation_deadline"], "pre-fence prepare deadline")
        return
    windows = governed_windows(window["windows"])
    c.require(fixed == fixed_deadline(close, window["input_deadline"], windows) and close <= window["admitted_at"] <= now,
              "original F deadline")
    decision = window["decision"]
    if decision is not None:
        c.closed(decision, "choice_at deadline checkpoint_sha256")
        c.digest(decision["checkpoint_sha256"])
        c.require(close <= decision["choice_at"] <= now and decision["deadline"] == min(fixed, decision["choice_at"] + 420),
                  "original recovery deadline")
        c.require(window["stage"] == "recovery" and window["deadline"] <= min(decision["deadline"], decision["choice_at"] + 300)
                  and now + operation_seconds + 37 < window["deadline"]
                  and window["deadline"] + 120 <= decision["deadline"], "recovery convergence/finalization")
    else:
        c.require(window["stage"] in STAGES, "closed phase")
        duration, later = windows["stages"][window["stage"]], later_seconds(windows, window["stage"])
        deadline = window["deadline"]
        c.require(deadline <= min(fixed, window["admitted_at"] + duration)
                  and now + operation_seconds + 37 < deadline
                  and fixed - now >= max(0, deadline - now) + later + FINAL_RESERVE, "phase remaining capacity")


def adapter_seconds(window, *, now, credential_deadline, operation):
    """Args: lifecycle window, sampled now, credential deadline, operation. Returns: largest admitted timeout."""
    margin = 158 if window["close"] is None else 38
    seconds = int(min(window["deadline"] - now - margin, credential_deadline - now - 121))
    c.require(seconds >= 1, f"{operation} capacity seconds={seconds}")
    phase_capacity(window, now=now, credential_deadline=credential_deadline, operation_seconds=seconds)
    return seconds


def terminal_deadline(window):
    if window["close"] is None:
        return window["preparation_deadline"]
    if window["decision"] is not None:
        decision = window["decision"]
        c.require(decision["deadline"] == min(window["fixed_deadline"], decision["choice_at"] + 420),
                  "original terminal recovery deadline")
        return decision["deadline"]
    return min(window["fixed_deadline"], window["deadline"])

def terminal_result(value, *, now, deadline):
    common = "kind fence accepted_modes routes_match state_clean quiescent pending unknown observed_at"
    failure = value.get("kind") in {"failed-closed-quiescent", "failed-prepare-quiescent"}
    c.closed(value, common + (" restoration" if failure else ""))
    prepare = value["kind"] == "failed-prepare-quiescent"
    routes = (value["fence"], value["routes_match"]) == (None, None) if prepare else value["routes_match"] is True
    c.require(value["state_clean"] is True and value["quiescent"] is True
              and value["pending"] == [] and value["unknown"] == []
              and routes and value["observed_at"] <= now < deadline
              and now - value["observed_at"] <= 30, "terminal uncertainty/drift/expiry")
    if value["kind"] == "accepted-open":
        c.require(value["fence"] == "OPEN" and set(value["accepted_modes"]) == {"unit", "recovery", "audit"}
                  and len(value["accepted_modes"]) == 3, "all routes accepted and OPEN required")
        return "accepted"
    c.require(failure and value["accepted_modes"] == [], "closed terminal kind")
    restored = value["restoration"]
    c.closed(restored, "unit recovery audit api static first_static_absent")
    c.require(all(restored[k] is True for k in ("unit", "recovery", "audit", "api"))
              and (restored["static"] is True or restored["first_static_absent"] is True), "original recovery incomplete")
    c.require(value["fence"] == "CLOSED" or prepare, "failed promotion must remain CLOSED")
    return "failed"


ENVELOPE_LIMIT = 786432
ENVELOPE_BLOBS = {"payload": (1, 262144), "signature": (8, 72), "receipt": (1, 65536), "signing_spki": (91, 91)}
RENDERED_TARGETS = ("processor_active_unit_task_definition_arn processor_retained_unit_task_definition_arns "
                    "scheduler_recovery_task_definition_arn scheduler_audit_task_definition_arn")


def _blob(value, low, high):
    c.closed(value, "sha256 size bytes_base64")
    c.integer(value["size"], low, high)
    c.digest(value["sha256"])
    encoded = value["bytes_base64"]
    c.require(type(encoded) is str and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", encoded) is not None, "envelope base64 alphabet")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ValueError("envelope base64 round trip") from error
    c.require(base64.b64encode(raw).decode() == encoded and len(raw) == value["size"] and c.sha(raw) == value["sha256"],
              "envelope raw bytes commitment")
    return raw


def _envelope_objects(objects, raws):
    from tools.cnesdata_delivery.evidence import REFERENCE_FIELDS, key_valid
    c.require(type(objects) is dict and set(objects) == {"payload", "signature", "receipt"}, "envelope exact object slots")
    shared = {(row["bucket_arn"], row["cipher_kms_key_arn"]) for row in objects.values()}
    c.require(len(shared) == 1 and len({row["key"] for row in objects.values()}) == 3, "envelope one bucket/cipher, distinct keys")
    for name, row in objects.items():
        c.closed(row, " ".join(sorted(REFERENCE_FIELDS)))
        c.require(key_valid(row["key"]) and row["server_side_encryption"] == "aws:kms" and row["bucket_key_enabled"] is False
                  and type(row["version_id"]) is str and 0 < len(row["version_id"]) <= 1024 and row["version_id"] != "null"
                  and not any(ord(ch) < 32 for ch in row["version_id"])
                  and type(row["bucket_arn"]) is str and type(row["cipher_kms_key_arn"]) is str
                  and row["content_length"] is not True and row["content_length"] == len(raws[name])
                  and row["content_sha256"] == c.sha(raws[name]), "envelope original object reference " + name)


def inputs_envelope(raw, *, owner, window):
    """Decode the closed version2 inputs.json carrier of the operational preparation plan.

    Args: canonical bytes, original owner, original keeper preparation window.
    Returns: Terraform bytes, raw activation members, sha256 of the raw payload, carrier hash, rendered targets.
    Raises: ValueError on any deviation; no legacy fallback exists.
    """
    from tools.cnesdata_delivery.ext2_transport import validate_reference
    value = c.loads(raw, canonical=True, limit=ENVELOPE_LIMIT)
    c._secrets(value)
    c.closed(value, "lifecycle_inputs_version owner preparation terraform activation")
    c.require(type(value["lifecycle_inputs_version"]) is int and value["lifecycle_inputs_version"] == 2, "envelope version")
    c.require(c.canonical(value["owner"]) == c.canonical(owner), "envelope original owner")
    prepared = c.closed(value["preparation"], "admitted_at deadline observed_at")
    for key in prepared:
        c.integer(prepared[key])
    c.require(prepared["admitted_at"] == window["admitted_at"] and prepared["deadline"] == window["deadline"]
              and prepared["admitted_at"] <= prepared["observed_at"] < prepared["deadline"] <= prepared["admitted_at"] + 900,
              "envelope original preparation window")
    terraform = _blob(value["terraform"], 1, 131072)
    activation = c.closed(value["activation"], "carrier_version ext2_reference ext2_governance_sha256 payload signature receipt "
                          "signing_spki objects rendered_targets")
    c.require(type(activation["carrier_version"]) is int and activation["carrier_version"] == 1, "envelope carrier version")
    validate_reference(activation["ext2_reference"])
    c.digest(activation["ext2_governance_sha256"])
    raws = {name: _blob(activation[name], *bounds) for name, bounds in ENVELOPE_BLOBS.items()}
    _envelope_objects(activation["objects"], raws)
    targets = c.closed(activation["rendered_targets"], RENDERED_TARGETS)
    retained = targets["processor_retained_unit_task_definition_arns"]
    singles = [targets[key] for key in targets if key != "processor_retained_unit_task_definition_arns"]
    c.require(type(retained) is list and 1 <= len(retained) <= 128 and targets["processor_active_unit_task_definition_arn"] in retained
              and all(type(item) is str and 0 < len(item) <= 2048 for item in singles + retained), "envelope rendered targets")
    return {"terraform": terraform, "activation": raws, "objects": activation["objects"],
            "activation_sha256": c.sha(raws["payload"]),
            "activation_carrier_sha256": c.sha(c.canonical(activation)), "rendered_targets": dict(targets)}
