"""Protected manual execution, live SDK/readback and exact private bytes.

Governance comes from the protected environment's reviewed secret, never workflow
inputs. Absence of an authentic producer handoff fails before AWS credential issuance.
"""
import argparse
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.aws_boundary import AWS, S3LeaseStore
from tools.cnesdata_delivery.coordination_lease import Lease, Watchdog, mapped_deadline
from tools.cnesdata_delivery.provenance import GitHub, historical_plan_governance, preflight, validate_proof

UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


def configuration(role):
    data = os.environ.get("CNESDATA_DELIVERY_GOVERNANCE", "").encode()
    c.require(bool(data), "reviewed protected governance absent; Production closed")
    value = c.loads(data, canonical=True, limit=65536)
    c.require(value.get("authority") == "infra-ansible#28/6715994616+6716076093+6716241666+6716490764+6716699477+6718141241+6718506538" and
              value.get("activation_enabled") is True, "governance authority/activation")
    c.require(value.get("region") == "us-east-2" and set(value["roles"]) == {"plan", "deploy"}
              and value["roles"]["plan"] != value["roles"]["deploy"], "governed distinct roles")
    backend = value["baseline"]["backend"]["configuration"]
    c.require(backend["bucket"] == value["state_bucket"] and backend["kms_key_id"] == value["state_kms_key_arn"]
              and backend["key"] == "cnesdata/prod/opentofu.tfstate" and backend["workspace"] == "default",
              "one exact governed product backend, not delivery state")
    value["role"] = role
    matrix = value.get("drift_matrix")
    c.require(type(matrix) is dict, "concrete governed drift matrix absent; Production blocked")
    c.closed(matrix, "matrix_version source_sha purpose before after")
    c.require(matrix["source_sha"] == os.environ["EXPECTED_SOURCE_SHA"] and matrix["purpose"] == os.environ["PURPOSE"],
              "source/purpose-specific drift matrix required")
    return value


def admission(role):
    governance = configuration(role)
    raw = os.environ["REQUEST_DESCRIPTOR"].encode()
    c.require(c.sha(raw) == c.digest(os.environ["REQUEST_DESCRIPTOR_SHA256"]), "descriptor bytes")
    descriptor = c.loads(raw, canonical=True, limit=65536)
    c.require(os.environ["CONTRACT_REPOSITORY"] == c.REPOSITORY and os.environ["CONTRACT_SOURCE_SHA"] == c.CONTRACT_SHA
              and os.environ["CONTRACT_PATH"] == c.CONTRACT_PATH, "immutable documentary authority")
    api = GitHub()
    external = api.read(f"repos/{c.REPOSITORY}/contents/{c.CONTRACT_PATH}?ref={c.CONTRACT_SHA}")
    import base64
    authority = base64.b64decode(external["content"], validate=False)
    c.require(c.sha(authority) == c.digest(os.environ["CONTRACT_SHA256"]) == governance["contract_sha256"], "authority bytes")
    c.require(descriptor["source_sha"] == os.environ["EXPECTED_SOURCE_SHA"] and os.environ["PURPOSE"] in c.PURPOSES, "source/purpose")
    current = preflight(descriptor, governance, api, role, time.time())
    payload = descriptor["payload_artifact"]
    if role == "plan" and os.environ["PURPOSE"] != "phase-a":
        c.require(payload is None, "initial plan has no future payload")
    else:
        payload_purpose = "phase-inputs" if role == "plan" else "planned"
        c.require(payload is not None and payload_purpose in governance["artifact_purposes"]
                  and payload == governance["artifact_references"][payload_purpose], "independent payload artifact")
    reference = governance["admission_reference"]
    c.require(descriptor["baseline_artifacts"] == governance["baseline_artifacts"], "independent baseline allowlist")
    files = api.artifact(reference, time.time())
    c.require("proof.json" in files, "complete sanitized proof missing")
    proof = validate_proof(c.loads(files["proof.json"], canonical=True), files, governance,
                           api, time.time(), descriptor["source_sha"], os.environ["PURPOSE"], role)
    baseline = governance["baseline"]
    cost_report = next(item for item in proof["reports"] if item["check_id"] == "cost-ledger-purpose-scope")
    c.require(c.loads(files[cost_report["name"]], canonical=True) == baseline["cost_evidence"], "authenticated measured cost report")
    c.validate_cost(governance["cost"], purpose=os.environ["PURPOSE"], stage=baseline["cost_context"],
                    evidence=baseline["cost_evidence"], manifest=baseline["cost_manifest"], now=time.time())
    # Source metadata is live; baseline bodies are authenticated content, not assertions.
    for baseline in descriptor["baseline_artifacts"]:
        api.artifact(baseline["reference"], time.time())
    if role == "deploy":
        payload = descriptor["payload_artifact"]
        c.require(payload is not None and payload["source_sha"] == descriptor["source_sha"], "planned payload source")
        transport = api.artifact(payload, time.time())
        index = c.loads(transport["index.json"], canonical=True, limit=32768)
        c.closed(index, "index_version kind status repository source_sha producer purpose created_at expires_at plan_binding_sha256 envelope_sha256 package_aggregate_sha256 private_locator policy cost drift admission_proof")
        c.require(index["status"] == "planned" and index["source_sha"] == descriptor["source_sha"]
                  and index["purpose"] == os.environ["PURPOSE"] and c.instant(index["expires_at"]) - time.time() >= 1980,
                  "planned admission/expiry")
        c.require(type(index["index_version"]) is int and index["index_version"] == 1
                  and index["kind"] == "cnesdata-private-plan-transport" and index["repository"] == c.REPOSITORY,
                  "transport version/kind/repository")
        c.closed(index["private_locator"], "scope source_sha run_id run_attempt status")
        c.require(index["private_locator"] == {"scope": "cnesdata-prod", "source_sha": descriptor["source_sha"],
                    "run_id": payload["run_id"], "run_attempt": payload["run_attempt"], "status": "planned"}
                  and index["producer"] == {"workflow_path": payload["workflow_path"], "workflow_sha": payload["workflow_sha"],
                    "run_id": payload["run_id"], "run_attempt": payload["run_attempt"]}, "transport exact producing run/attempt")
        for field in ("plan_binding_sha256", "envelope_sha256", "package_aggregate_sha256"):
            c.digest(index[field])
        c.public_safe(index)
        c.require(index["cost"] == governance["cost"], "complete index/A3 cost projection")
        historical = validate_proof(index["admission_proof"], transport,
                                    historical_plan_governance(governance, os.environ["PURPOSE"]),
                                    api, time.time(), descriptor["source_sha"], os.environ["PURPOSE"], "plan")
        c.require(historical["plan_binding_sha256"] is None
                  and proof["plan_binding_sha256"] == index["plan_binding_sha256"],
                  "historical/current proof binding without self-reference")
        c.require(c.instant(historical["observed_at"]) <= c.instant(index["created_at"])
                  and c.instant(index["expires_at"]) <= c.instant(historical["expires_at"]),
                  "historical plan proof temporal binding")
        for field in ("candidate_sha256", "promotion_evidence_sha256"):
            c.require(historical[field] == proof[field], "historical/current release evidence")
            if os.environ["PURPOSE"] == "phase-a":
                c.digest(historical[field])
            else:
                c.require(historical[field] is None, "initial plan has no release proof")
    else:
        index = None
    return governance, descriptor, api, current, proof, files, index


def _prefix(governance, source, run, attempt, status):
    c.digest(source, 40)
    c.integer(int(run))
    c.integer(int(attempt))
    prefix = governance["evidence_prefix"]
    c.require(type(prefix) is str and prefix.startswith("cnesdata/prod/") and ".." not in prefix, "governed evidence namespace")
    return f"{prefix.rstrip('/')}/{source}/{run}/{attempt}/{status}/"


def _environment():
    result = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"], "LANG": "C.UTF-8",
              "TF_IN_AUTOMATION": "1", "CHECKPOINT_DISABLE": "1", "AWS_EC2_METADATA_DISABLED": "true",
              "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
              "AWS_REGION": "us-east-2", "AWS_DEFAULT_REGION": "us-east-2", "TF_WORKSPACE": "default"}
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        c.require(bool(os.environ.get(key)), "temporary credential epoch missing")
        result[key] = os.environ[key]
    if os.environ.get("RUNNER_TRACKING_ID"):
        result["RUNNER_TRACKING_ID"] = os.environ["RUNNER_TRACKING_ID"]
    return result


def _readbacks(aws, governance, watchdog, raw_state=None, resolver=None):
    resources = None
    resolved_policies = set()
    if raw_state is not None:
        from tools.cnesdata_delivery.iam_boundary import bind_state
        resources = bind_state(resolver, c.loads(raw_state, state=True))
    allowed = {"iam": {"get_role", "get_role_policy", "get_policy", "get_policy_version"},
               "ecs": {"describe_task_definition", "describe_clusters"}, "scheduler": {"get_schedule"},
               "s3": {"get_bucket_policy", "get_bucket_versioning", "get_object_lock_configuration"},
               "dynamodb": {"describe_table"}, "acm": {"describe_certificate"}}
    reports = []
    c.require(bool(governance["readbacks"]), "live readback specification missing")
    for spec in governance["readbacks"]:
        watchdog.check()
        c.closed(spec, "service operation parameters expected_sha256")
        c.require(spec["operation"] in allowed.get(spec["service"], set()), "read-only API boundary")
        value = aws.call(spec["service"], spec["operation"], **spec["parameters"])
        value.pop("ResponseMetadata", None)
        # SDK dates are normalized explicitly; no stringify of arbitrary objects.
        def dates(item):
            from datetime import datetime
            if type(item) is datetime:
                return c.utc(item.timestamp())
            if type(item) is dict:
                return {k: dates(v) for k, v in item.items()}
            if type(item) is list:
                return [dates(v) for v in item]
            return item
        encoded = c.canonical(dates(value))
        if raw_state is not None and spec["service"] == "iam" and spec["operation"] == "get_role_policy":
            from tools.cnesdata_delivery.iam_boundary import verify_api
            address = verify_api(resolver, resources, spec["parameters"], value)
            if address is None:
                c.require(c.sha(encoded) == spec["expected_sha256"], "live drift/readback mismatch")
            else:
                c.require(address not in resolved_policies, "iam=duplicate_policy_api")
                resolved_policies.add(address)
        else:
            c.require(c.sha(encoded) == spec["expected_sha256"], "live drift/readback mismatch")
        reports.append({"service": spec["service"], "operation": spec["operation"], "sha256": c.sha(encoded), "observed": dates(value)})
    if resolver is not None and raw_state is not None:
        c.require(resolved_policies == set(resolver.traces), "iam=complete_policy_api_inventory")
    return reports


def _publisher_ready():
    for name in ("ACTIONS_RUNTIME_URL", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL"):
        c.require(bool(os.environ.get(name)), "artifact Node action runtime bridge missing")
    bundle = Path.cwd() / ".delivery-uploader/dist/upload/index.js"
    c.require(bundle.is_file(), "pinned artifact action checkout missing")
    # The checkout SHA is a literal pin in the reusable; never an input or tag.
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=bundle.parents[2],
                              capture_output=True, text=True, check=True, timeout=5).stdout.strip()
    c.require(revision == UPLOAD_SHA, "artifact uploader immutable pin")
    version = subprocess.run(["node", "--version"], capture_output=True, text=True, check=True, timeout=5).stdout.strip()
    c.require(version == "v24.11.1", "artifact SDK Node runtime pin")
    return bundle


def _upload(directory, name, watchdog, temp):
    bundle = _publisher_ready()
    output = temp / (name + ".outputs")
    output.touch(mode=0o600, exist_ok=False)
    allowed = {"PATH", "HOME", "LANG", "RUNNER_TEMP", "RUNNER_TOOL_CACHE", "RUNNER_TRACKING_ID",
               "RUNNER_OS", "RUNNER_ARCH", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
               "GITHUB_JOB", "GITHUB_WORKSPACE", "GITHUB_SERVER_URL", "GITHUB_API_URL", "GITHUB_ACTIONS",
               "ACTIONS_RUNTIME_URL", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL"}
    env = {k: v for k, v in os.environ.items() if k in allowed}
    for command_file in ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_STEP_SUMMARY"):
        private_file = temp / (name + "." + command_file.lower())
        private_file.touch(mode=0o600, exist_ok=False)
        env[command_file] = str(private_file)
    env.update({"INPUT_NAME": name, "INPUT_PATH": str(directory), "INPUT_IF-NO-FILES-FOUND": "error",
                "INPUT_RETENTION-DAYS": "1", "INPUT_COMPRESSION-LEVEL": "0", "INPUT_OVERWRITE": "false",
                "INPUT_INCLUDE-HIDDEN-FILES": "false", "INPUT_ARCHIVE": "true", "GITHUB_OUTPUT": str(output)})
    watchdog.run(["node", str(bundle)], cwd=Path.cwd(), env=env, output=temp / (name + ".log"),
                 timeout=max(1, min(20, int(watchdog.finalization_deadline - time.monotonic()))) if watchdog.finalizing else 20,
                 mutating=False)
    text = output.read_text()
    c.require(len(text) <= 8192, "artifact outputs size")
    lines = iter(text.splitlines())
    values = {}
    for line in lines:
        if not line:
            continue
        if "<<" in line:
            key, delimiter = line.split("<<", 1)
            c.require(bool(delimiter), "artifact output delimiter")
            parts = []
            for part in lines:
                if part == delimiter:
                    break
                parts.append(part)
            else:
                raise ValueError("artifact output unterminated")
            value = "\n".join(parts)
        else:
            c.require("=" in line, "artifact output syntax")
            key, value = line.split("=", 1)
        c.require(key in {"artifact-id", "artifact-digest", "artifact-url"} and key not in values, "artifact output key/duplicate")
        values[key] = value
    c.integer(int(values["artifact-id"]))
    c.digest(values["artifact-digest"].removeprefix("sha256:"))
    return {"id": int(values["artifact-id"]), "digest": "sha256:" + values["artifact-digest"].removeprefix("sha256:")}


def _verify_current_artifact(api, identity, expected_files, run_id):
    from tools.cnesdata_delivery.provenance import unzip
    prefix = f"repos/{c.REPOSITORY}/actions/artifacts/{identity['id']}"
    metadata = api.read(prefix)
    c.require(metadata["digest"] == identity["digest"] and metadata["workflow_run"]["id"] == run_id
              and not metadata["expired"], "current artifact metadata")
    raw = api.read(prefix + "/zip", raw=True)
    c.require("sha256:" + c.sha(raw) == identity["digest"] and unzip(raw) == expected_files, "published artifact exact bytes")


def verify_drift_evidence(envelope, raw, ecr_raw=None, promotion=None):
    """Bind this apply's retained observation and readbacks without changing plan."""
    plan, applied = envelope["plan"], envelope["apply"]
    c.require(c.sha(raw) == applied["drift"]["evidence_sha256"] == applied["drift"]["readback_sha256"],
              "applied private drift report bytes")
    report = c.loads(raw, canonical=True, limit=262144)
    c.closed(report, "drift_report_version repository source_sha purpose run_id run_attempt ecr_before post_readbacks")
    c.require(type(report["drift_report_version"]) is int and report["drift_report_version"] == 1
              and report["repository"] == plan["repository"] == c.REPOSITORY
              and all(report[field] == plan[field] for field in ("source_sha", "purpose"))
              and all(report[field] == applied["producer"][field] for field in ("run_id", "run_attempt")),
              "applied drift report execution identity")
    c.integer(report["run_id"])
    c.integer(report["run_attempt"])
    c.require(type(report["post_readbacks"]) is list and bool(report["post_readbacks"]), "post-apply readbacks absent")
    for readback in report["post_readbacks"]:
        c.closed(readback, "service operation sha256 observed")
        c.require(c.sha(c.canonical(readback["observed"])) == c.digest(readback["sha256"]), "post readback measured bytes")
    if plan["purpose"] != "phase-a":
        c.require(report["ecr_before"] is None and ecr_raw is None, "unexpected ECR observation")
        return report
    observed = report["ecr_before"]
    c.require(type(observed) is dict and ecr_raw is not None and c.canonical(observed) == ecr_raw,
              "retained ECR observation missing/changed")
    c.closed(observed, "observation_version repository source_sha purpose run_id run_attempt observed_at report")
    c.require(type(observed["observation_version"]) is int and observed["observation_version"] == 1
              and all(observed[field] == report[field] for field in ("repository", "source_sha", "purpose", "run_id", "run_attempt"))
              and c.instant(plan["created_at"]) <= c.instant(observed["observed_at"]) <= c.instant(applied["started_at"]),
              "fresh ECR observation before this mutation")
    value = c.closed(observed["report"], "repository_sha256 image_digest config_digest manifest_sha256 blob_digests")
    c.digest(value["repository_sha256"])
    c.require(value["image_digest"] == "sha256:" + c.digest(value["image_digest"].removeprefix("sha256:"))
              and value["image_digest"] == plan["release"]["image_digest"]
              and value["manifest_sha256"] == c.digest(value["image_digest"].removeprefix("sha256:")),
              "fresh ECR image/release binding")
    c.require(value["config_digest"] == "sha256:" + c.digest(value["config_digest"].removeprefix("sha256:"))
              and type(value["blob_digests"]) is list and 2 <= len(value["blob_digests"]) <= 129
              and value["blob_digests"][0] == value["config_digest"], "fresh ECR config/blob binding")
    for digest in value["blob_digests"]:
        c.require(digest == "sha256:" + c.digest(digest.removeprefix("sha256:")), "fresh ECR blob digest")
    if promotion is not None:
        c.require(all(value[field] == promotion[field] for field in ("image_digest", "manifest_sha256", "config_digest", "blob_digests")),
                  "fresh ECR original promotion bytes")
    return report


def _published_receipt(api, governance, run_id, attempt):
    """Public identity needed before minting historically scoped credentials."""
    c.integer(run_id)
    c.integer(attempt)
    run = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}")
    c.require(run["status"] == "completed" and run["conclusion"] == "success" and run["run_attempt"] == attempt
              and run["repository"]["full_name"] == c.REPOSITORY and run["event"] == "workflow_dispatch"
              and run["head_branch"] == "develop", "previous run not terminal success")
    path = run["path"].split("@")[0]
    c.require(path in {".github/workflows/infra-plan.yml", ".github/workflows/infra-apply.yml"}, "previous caller")
    role = "plan" if path.endswith("infra-plan.yml") else "deploy"
    from tools.cnesdata_delivery.provenance import producer_sha
    c.require(producer_sha(run, role) == governance["gate_shas"][role], "previous approved reusable")
    status = "planned" if role == "plan" else "applied"
    artifacts = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100")
    c.require(artifacts["total_count"] <= 100, "bounded history; reviewed recovery required")
    name = f"cnesdata-{status}-receipt-{run_id}-{attempt}"
    matches = [item for item in artifacts["artifacts"] if item["name"] == name]
    c.require(len(matches) == 1, "previous receipt missing/ambiguous")
    reference = {"repository": c.REPOSITORY, "run_id": run_id, "run_attempt": attempt,
                 "artifact_id": matches[0]["id"], "artifact_digest": matches[0]["digest"],
                 "workflow_path": path, "workflow_sha": run["head_sha"], "source_sha": run["head_sha"]}
    content = api.artifact(reference, time.time())
    c.require(set(content) == {"receipt.json"}, "external receipt package")
    receipt = c.loads(content["receipt.json"], canonical=True)
    c.closed(receipt, "receipt_version repository run_id run_attempt envelope_sha256 index_artifact_id index_artifact_digest lease_evidence_sha256 checkpoint_sha256 verified_at result")
    c.require(receipt["result"] == "success" and receipt["receipt_version"] == 1 and receipt["repository"] == c.REPOSITORY
              and receipt["run_id"] == run_id and receipt["run_attempt"] == attempt, "previous receipt binding")
    index_files = api.artifact(reference | {"artifact_id": receipt["index_artifact_id"],
                                           "artifact_digest": receipt["index_artifact_digest"]}, time.time())
    index = c.loads(index_files["index.json"], canonical=True)
    c.closed(index, "index_version kind status repository source_sha producer purpose created_at expires_at plan_binding_sha256 envelope_sha256 package_aggregate_sha256 private_locator policy cost drift admission_proof")
    c.require(index["index_version"] == 1 and index["kind"] == "cnesdata-private-plan-transport"
              and index["repository"] == c.REPOSITORY and index["source_sha"] == run["head_sha"]
              and index["status"] == status and index["purpose"] in c.PURPOSES
              and index["envelope_sha256"] == receipt["envelope_sha256"]
              and index["producer"] == {"workflow_path": path, "workflow_sha": run["head_sha"], "run_id": run_id, "run_attempt": attempt}
              and index["private_locator"] == {"scope": "cnesdata-prod", "source_sha": run["head_sha"],
                                              "run_id": run_id, "run_attempt": attempt, "status": status},
              "previous index identity and locator")
    c.require(c.instant(receipt["verified_at"]) < c.instant(index["expires_at"]) - 120, "previous R1 publication validity")
    c.public_safe(index)
    return run, status, receipt, index


def _session_reads(governance, descriptor, api, index, role, purpose, authority=None):
    """Only governed object keys and API-authenticated complete historical runs."""
    scopes = []
    if role == "deploy":
        locator = index["private_locator"]
        scopes.append(_prefix(governance, locator["source_sha"], locator["run_id"], locator["run_attempt"], "planned") + "*")
    elif purpose == "phase-a":
        c.require(set(governance["phase_input_objects"]) == {"phase-inputs.json", "candidate.json", "promotion.json"}, "exact private Phase A inputs")
        for spec in governance["phase_input_objects"].values():
            c.digest(spec["sha256"])
        from tools.cnesdata_delivery.session_grouping import phase_input_reads
        scopes += phase_input_reads(governance, descriptor, authority)
    candidates = []
    for caller in ("infra-plan.yml", "infra-apply.yml"):
        response = api.read(f"repos/{c.REPOSITORY}/actions/workflows/{caller}/runs?branch=develop&event=workflow_dispatch&status=success&per_page=1")
        c.require(type(response["workflow_runs"]) is list and len(response["workflow_runs"]) <= 1, "bounded previous receipt lookup")
        for run in response["workflow_runs"]:
            c.integer(run["id"])
            c.integer(run["run_attempt"])
            c.instant(run["created_at"])
            candidates.append(run)
    if candidates:
        latest = max(candidates, key=lambda run: (c.instant(run["created_at"]), run["id"], run["run_attempt"]))
        run, status, _, _ = _published_receipt(api, governance, latest["id"], latest["run_attempt"])
        scopes.append(_prefix(governance, run["head_sha"], run["id"], run["run_attempt"], status) + "*")
    return sorted(set(scopes))


def previous_success(aws, api, governance, previous, *, details=False):
    """Released is not sufficient: authenticate the prior successful publication."""
    try:
        c.require(previous["status"] == "released" and previous["repository"] == c.REPOSITORY, "terminal lease")
        if previous.get("lifecycle_version") == 1:
            from tools.cnesdata_delivery.application_gate import previous_terminal
            result = previous_terminal(aws, api, governance, previous)
            return result if details else True
        run_id, attempt = previous["run_id"], previous["run_attempt"]
        run, status, receipt, index = _published_receipt(api, governance, run_id, attempt)
        c.require(receipt["checkpoint_sha256"] == previous["checkpoint_sha256"], "previous coordinator receipt binding")
        prefix = _prefix(governance, run["head_sha"], run_id, attempt, status)
        raw, _ = aws.get(governance["evidence_bucket"], prefix + "envelope.json", maximum=262144)
        c.require(c.sha(raw) == receipt["envelope_sha256"], "previous private envelope")
        envelope = c.loads(raw, canonical=True)
        c.require(envelope["status"] == status and envelope["plan"]["source_sha"] == run["head_sha"]
                  and envelope["plan"]["purpose"] == index["purpose"]
                  and envelope["plan"]["backend"] == governance["baseline"]["backend"]
                  and c.instant(receipt["verified_at"]) < c.instant(envelope["plan"]["expires_at"]) - 120,
                  "previous R1 validity/backend/workspace/purpose")
        evidence_raw, _ = aws.get(governance["evidence_bucket"], prefix + "lease.json", maximum=262144)
        c.require(c.sha(evidence_raw) == receipt["lease_evidence_sha256"], "previous lease CAS evidence bytes")
        evidence = c.loads(evidence_raw, canonical=True)
        c.require(evidence["owner_sha256"] == c.sha(previous["owner"].encode()) and evidence["run_id"] == run_id
                  and evidence["run_attempt"] == attempt and evidence["session_sha256"] == previous["session_sha256"]
                  and evidence["checkpoint_sha256"] == receipt["checkpoint_sha256"], "previous owner/run/session CAS")
        checkpoint_raw, _ = aws.get(governance["evidence_bucket"], prefix + "checkpoint.json", maximum=262144)
        c.require(c.sha(checkpoint_raw) == receipt["checkpoint_sha256"], "previous checkpoint bytes")
        checkpoint = c.loads(checkpoint_raw, canonical=True)
        if status == "applied":
            drift_raw, _ = aws.get(governance["evidence_bucket"], prefix + "drift.json", maximum=262144)
            ecr_raw, _ = aws.get(governance["evidence_bucket"], prefix + "ecr-before.json", maximum=65536) if envelope["plan"]["purpose"] == "phase-a" else (None, None)
            verify_drift_evidence(envelope, drift_raw, ecr_raw)
        return {"envelope": envelope, "receipt": receipt, "index": index, "checkpoint": checkpoint,
                "artifact_id": receipt["index_artifact_id"], "artifact_digest": receipt["index_artifact_digest"]} if details else True
    except Exception:
        return False  # retain coordinator and demand reviewed recovery, never TTL takeover


def _reuse_completed(aws, api, governance, lease, plan_envelope, files, baseline, source, purpose):
    """Return an authenticated original receipt; never mint a retry receipt."""
    previous, etag = lease.store.get()
    if previous is None or previous.get("status") != "released":
        return False
    if previous.get("lifecycle_version") == 1:
        # A terminal is not a saved legacy plan. Normal acquisition still
        # authenticates its original publication before any new owner CAS.
        return False
    result = previous_success(aws, api, governance, previous, details=True)
    if not result or result["envelope"]["status"] != "applied":
        return False
    envelope = result["envelope"]
    if envelope["plan_binding_sha256"] != plan_envelope["plan_binding_sha256"]:
        return False
    c.require(envelope["plan"] == plan_envelope["plan"], "retry original plan identity")
    c.validate_envelope(envelope, files, baseline | {"deploy_role_arn": governance["roles"]["deploy"]},
                        time.time(), source, status="applied")
    def guard():
        value, current_etag = lease.store.get()
        c.require(value == previous and current_etag == etag, "retry coordination changed; recovery_required")
    class ReadOnly:
        check = staticmethod(guard)
    guard()
    state_raw, state_object = aws.get_state()
    c.require(state_object == result["checkpoint"]["state_object"], "retry state version/checkpoint changed; recovery_required")
    identity = c.state_identity(state_raw)
    c.require(identity == result["checkpoint"]["state_after"], "retry checkpoint state changed; recovery_required")
    c.require(identity == {k: envelope["apply"]["state_after"][k] for k in identity}, "retry applied state changed; recovery_required")
    state = c.loads(state_raw, state=True)
    saved = c.loads(files["plan.json"], state=True)
    c.applied_state(saved, state)
    reports = _readbacks(aws, governance, ReadOnly(), state_raw if baseline.get("iam_resolver") is not None else None, baseline.get("iam_resolver"))
    c.drift_coverage(saved, reports, governance["drift_matrix"], source, purpose, "after", state)
    if purpose == "phase-a":
        aws.verify_ecr(c.loads(files["promotion.json"], canonical=True), guard=guard)
        observed = _outputs(state_raw, envelope["plan"], f"{governance['account_id']}.dkr.ecr.us-east-2.amazonaws.com/{governance['ecr_repository']}")
    else:
        from tools.cnesdata_delivery import outputs
        observed = outputs.acm(state, aws, governance["account_id"]) if purpose == "acm-certificate" else outputs.bootstrap(state, aws, governance["account_id"])
    c.require(observed == envelope["apply"]["outputs"], "retry applied outputs changed")
    guard()
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"evidence_run_id={envelope['apply']['producer']['run_id']}\n"
                     f"evidence_artifact_id={result['artifact_id']}\n"
                     f"evidence_artifact_digest={result['artifact_digest']}\nevidence_status=applied\n")
    return True


def _planned_checkpoint(aws, api, governance, index, reference, envelope):
    """Authenticate the original planned receipt before permitting a new apply."""
    run, status, receipt, published = _published_receipt(api, governance, reference["run_id"], reference["run_attempt"])
    c.require(status == "planned" and published == index
              and receipt["index_artifact_id"] == reference["artifact_id"]
              and receipt["index_artifact_digest"] == reference["artifact_digest"]
              and receipt["envelope_sha256"] == c.sha(c.canonical(envelope)),
              "original planned receipt/index binding")
    prefix = _prefix(governance, run["head_sha"], run["id"], run["run_attempt"], "planned")
    raw, _ = aws.get(governance["evidence_bucket"], prefix + "checkpoint.json", maximum=262144)
    c.require(c.sha(raw) == receipt["checkpoint_sha256"], "original planned checkpoint bytes")
    checkpoint = c.loads(raw, canonical=True)
    raw, _ = aws.get(governance["evidence_bucket"], prefix + "lease.json", maximum=262144)
    c.require(c.sha(raw) == receipt["lease_evidence_sha256"], "original planned lease bytes")
    evidence = c.loads(raw, canonical=True)
    c.require(evidence["checkpoint_sha256"] == receipt["checkpoint_sha256"]
              and evidence["run_id"] == run["id"] and evidence["run_attempt"] == run["run_attempt"]
              and checkpoint["state_after"] == envelope["plan"]["state_before"],
              "original planned checkpoint/lease/state binding")
    return checkpoint


def execute(role):
    governance, descriptor, api, current, proof, proof_files, index = admission(role)
    _publisher_ready()
    from tools.cnesdata_delivery import session_owner
    session_authority = session_owner.authenticate(governance, descriptor, proof, proof_files, api,
                                                    time.time(), role, os.environ["PURPOSE"],
                                                    plan_binding_sha256=index["plan_binding_sha256"] if role == "deploy" else None)
    aws = AWS(governance)  # only after live public admission has independently passed
    session_expires = c.instant(os.environ["AWS_CREDENTIAL_EXPIRATION"])
    session_owner.verify_managed(aws, session_authority, session_expires)
    source = descriptor["source_sha"]
    run_id, attempt = current["id"], current["run_attempt"]
    session = c.sha(c.canonical({"principal": aws.identity["Arn"], "run_id": run_id, "run_attempt": attempt, "gate": role}))
    # This callback authenticates successful publication; no automatic recovery of held/ambiguous owners.
    lease = Lease(S3LeaseStore(aws), {"repository": c.REPOSITORY, "run_id": run_id,
                  "run_attempt": attempt, "session_sha256": session}, monotonic=time.monotonic,
                  previous_success=lambda previous: previous_success(aws, api, governance, previous))
    bucket = governance["evidence_bucket"]
    purpose = os.environ["PURPOSE"]
    product = Path.cwd() / "product"
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=product, text=True,
                              capture_output=True, check=True, timeout=5).stdout.strip()
    c.require(revision == source, "actual immutable product checkout")
    root = product / "infra/opentofu/env/prod"
    toolchain = governance["baseline"]["toolchain"]
    tofu = shutil.which("tofu")
    c.require(tofu and c.sha(Path(tofu).read_bytes()) == toolchain["opentofu"]["binary_sha256"]
              and c.sha((root / ".terraform.lock.hcl").read_bytes()) == toolchain["lock_sha256"], "actual toolchain bytes")
    baseline = governance["baseline"]
    iam_resolver = None
    def prepare_iam(files):
        from tools.cnesdata_delivery.iam_boundary import authenticate_sources, prepare
        saved = c.loads(files["plan.json"], state=True)
        changed = any(item["type"] == "aws_iam_role_policy" and item["change"]["actions"] != ["no-op"] for item in saved["resource_changes"])
        sources = authenticate_sources(product, source) if changed else {}
        return prepare(saved, c.loads(files["inputs.tfvars.json"]), governance["account_id"], purpose, sources)
    with tempfile.TemporaryDirectory(prefix="cnesdata-private-") as folder:
        temp = Path(folder)
        temp.chmod(0o700)
        if purpose == "phase-a":
            actual = {}
            for entry in baseline["phase_a_graph"]["source_files"]:
                path = (product / entry["path"]).resolve()
                c.require(product.resolve() in path.parents and entry["path"].startswith("infra/opentofu/"), "approved source path")
                actual[entry["path"]] = path.read_bytes()
            baseline = baseline | {"actual_source_files": actual}
        if role == "deploy":
            locator = index["private_locator"]
            prefix = _prefix(governance, source, locator["run_id"], locator["run_attempt"], "planned")
            raw, _ = aws.get(bucket, prefix + "envelope.json", maximum=262144)
            c.require(c.sha(raw) == index["envelope_sha256"], "private envelope commitment")
            envelope = c.loads(raw, canonical=True, limit=262144)
            files = {}
            for entry in envelope["plan"]["package"]["files"]:
                data, _ = aws.get(bucket, prefix + entry["name"], maximum=entry["size"])
                files[entry["name"]] = data
                (temp / entry["name"]).write_bytes(data)
            iam_resolver = prepare_iam(files)
            baseline = baseline | {"iam_resolver": iam_resolver}
            plan = c.validate_envelope(envelope, files, baseline, time.time(), source)
            c.require(index["policy"] == {k: plan["policy"][k] for k in ("verdict", "evidence_sha256")}
                      and index["cost"] == plan["cost"] and index["drift"] == {k: plan["drift"][k] for k in ("verdict", "evidence_sha256")}
                      and index["package_aggregate_sha256"] == plan["package"]["aggregate_sha256"]
                      and index["created_at"] == plan["created_at"] and index["expires_at"] == plan["expires_at"], "full private/public projection")
            c.require(envelope["plan_binding_sha256"] == index["plan_binding_sha256"] and
                      plan["producer"]["run_id"] == descriptor["payload_artifact"]["run_id"] and
                      plan["producer"]["run_attempt"] == descriptor["payload_artifact"]["run_attempt"], "consumed plan run binding")
            expiry = c.instant(plan["expires_at"])
        else:
            bounds = [time.time() + 3600, c.instant(proof["expires_at"]), c.instant(governance["cost"]["expires_at"]), *api.expiries.values()]
            if governance["cost"]["scope"] == "active":
                bounds.append(c.instant(governance["cost"]["cloudfront"]["expires_at"]))
            expiry = min(bounds)
            inputs = governance["product_inputs"]
            files = {}
            if purpose == "phase-a":
                reference = descriptor["payload_artifact"]
                c.require(reference is not None and reference["source_sha"] == source, "Phase A authenticated input source")
                api.artifact(reference, time.time())
                for name in ("phase-inputs.json", "candidate.json", "promotion.json"):
                    spec = governance["phase_input_objects"][name]
                    c.require(spec["key"].startswith(governance["evidence_prefix"]) and ".." not in spec["key"], "private phase input scope")
                    data, _ = aws.get(bucket, spec["key"], maximum=262144)
                    c.require(c.sha(data) == spec["sha256"], "Phase A private input content commitment")
                    files[name] = data
                phase = c.loads(files["phase-inputs.json"], canonical=True)
                c.require(phase == governance["phase_a_inputs"], "Phase A exact transported input")
                inputs = inputs | phase
            if purpose != "phase-a":
                c.require(inputs.get("image_digest") is None and inputs.get("processor_active_unit_task_definition_arn") is None
                          and not inputs.get("processor_retained_unit_task_definition_arns"), "closed bootstrap inputs")
            (temp / "inputs.tfvars.json").write_bytes(c.canonical(inputs))
        if role == "deploy" and _reuse_completed(aws, api, governance, lease, envelope, files, baseline, source, purpose):
            return
        session_owner.verify_managed(aws, session_authority, session_expires)
        lease.acquire()
        expiry = min(expiry, c.instant(proof["expires_at"]), *api.expiries.values())
        sent, received, server = aws.last_sample
        credential_expiry = c.instant(os.environ["AWS_CREDENTIAL_EXPIRATION"])
        watchdog = Watchdog(lease, fixed_deadline=mapped_deadline(expiry, sent, received, server, time.time()),
                            credential_deadline=mapped_deadline(credential_expiry, sent, received, server, time.time()))
        watchdog.admit()
        original_checkpoint = _planned_checkpoint(aws, api, governance, index, descriptor["payload_artifact"], envelope) if role == "deploy" else None
        state_bytes, state_object_before = aws.get_state(absent=True)
        before = c.state_identity(state_bytes)
        if purpose == "bootstrap":
            from tools.cnesdata_delivery.outputs import initial_stage
            initial_stage(state_bytes, governance["bootstrap_checkpoint"], source, aws, governance["account_id"], time.time())
        if role == "deploy":
            c.require(before == plan["state_before"], "state lineage/serial/hash changed")
            c.require(state_object_before == original_checkpoint["state_object"], "state version differs from original planned checkpoint")
            c.scheduler_preflight(c.loads(files["plan.json"], state=True), c.loads(state_bytes, state=True) if state_bytes is not None else None)
            if purpose == "bootstrap":
                from tools.cnesdata_delivery.outputs import initial_admission
                initial_admission(c.loads(files["plan.json"], state=True), c.loads(files["inputs.tfvars.json"]), state_bytes,
                                  governance["bootstrap_checkpoint"], source, aws, governance["account_id"], time.time())
        before_reports = _readbacks(aws, governance, watchdog)
        if role == "deploy":
            c.drift_coverage(c.loads(files["plan.json"], state=True), before_reports, governance["drift_matrix"],
                             source, purpose, "before")
        if purpose == "phase-a":
            promotion = c.loads(files["promotion.json"], canonical=True)
            candidate_raw = files["candidate.json"]
            candidate = c.r2_candidate(candidate_raw)
            release = plan["release"] if role == "deploy" else governance["release"]
            binding = c.canary_binding(candidate, c.sha(candidate_raw))
            c.require(c.sha(candidate_raw) == release["candidate_sha256"] and candidate["source_sha"] == source
                      and all(binding[k] == release[k] for k in ("release_id", "canary_id", "binding_sha256", "source_sha"))
                      and promotion["image_digest"] == release["image_digest"], "real candidate/promotion binding")
            ecr_report = aws.verify_ecr(promotion, guard=watchdog.check)
            ecr_before = {"observation_version": 1, "repository": c.REPOSITORY, "source_sha": source, "purpose": purpose,
                          "run_id": run_id, "run_attempt": attempt, "observed_at": c.utc(time.time()),
                          "report": ecr_report}
            ecr_key = _prefix(governance, source, run_id, attempt, "planned" if role == "plan" else "applied") + "ecr-before.json"
            ecr_raw = c.canonical(ecr_before)
            aws.put(bucket, ecr_key, ecr_raw)
            retained, _ = aws.get(bucket, ecr_key, maximum=65536)
            c.require(retained == ecr_raw, "durable ECR observation before product mutation")
        else:
            ecr_before = None
        backend = dict(baseline["backend"]["configuration"])
        c.require(backend.pop("workspace") == "default", "workspace")
        backend.pop("type")
        backend_file = temp / "backend.json"
        backend_file.write_bytes(c.canonical(backend))
        env = _environment()
        cli_config = temp / "tofu.rc"
        providers = [item["source"] for item in toolchain["providers"]]
        import json
        cli_config.write_text("provider_installation { direct { include = " + json.dumps(providers) + " } }\n")
        env["TF_CLI_CONFIG_FILE"] = str(cli_config)
        watchdog.run([tofu, "init", "-input=false", "-lockfile=readonly", "-backend-config=" + str(backend_file)],
                     cwd=root, env=env, output=temp / "init.log", timeout=45, mutating=False)
        watchdog.run([tofu, "workspace", "show"], cwd=root, env=env, output=temp / "workspace.log", timeout=10, mutating=False)
        c.require((temp / "workspace.log").read_text().strip() == "default", "effective workspace readback")
        metadata = root / ".terraform/terraform.tfstate"
        c.require(metadata.is_file(), "missing effective S3 backend; local init is not authorization")
        c.effective_backend(c.loads(metadata.read_bytes(), state=True), "default", baseline["backend"]["configuration"])
        command = [tofu, "plan", "-input=false", "-lock-timeout=20s", "-var-file=" + str(temp / "inputs.tfvars.json"), "-out=" + str(temp / "plan.bin")]
        if purpose == "acm-certificate":
            command.append("-target=aws_acm_certificate.static_web")
        started = c.utc(time.time())
        if role == "deploy":
            command = [tofu, "apply", "-input=false", "-lock-timeout=20s", str(temp / "plan.bin")]
        attempt_prefix = _prefix(governance, source, run_id, attempt, "planned" if role == "plan" else "applied")
        prepared = {"diagnostic_version": 1, "status": "prepared", "repository": c.REPOSITORY,
                    "source_sha": source, "run_id": run_id, "run_attempt": attempt, "purpose": purpose,
                    "payload_artifact": descriptor["payload_artifact"],
                    "plan_binding_sha256": envelope["plan_binding_sha256"] if role == "deploy" else None,
                    "state_before": before, "state_object_before": state_object_before, "backend_identity_sha256": baseline["backend"]["identity_sha256"],
                    "owner_sha256": c.sha(lease.token.encode()), "session_sha256": session, "prepared_at": started}
        prepared_raw = c.canonical(prepared)
        aws.put(bucket, attempt_prefix + "attempt.json", prepared_raw)
        prepared_readback, _ = aws.get(bucket, attempt_prefix + "attempt.json", maximum=262144)
        c.require(prepared_readback == prepared_raw, "durable recovery checkpoint before product mutation")
        session_owner.verify_managed(aws, session_authority, session_expires)
        if role == "deploy":
            current_state, current_object = aws.get_state(absent=True)
            c.require(current_object == state_object_before and c.state_identity(current_state) == before,
                      "state version/checkpoint changed before apply; recovery_required")
        child = watchdog.run(command, cwd=root, env=env, output=temp / "operation.log")
        if role == "plan":
            watchdog.run([tofu, "show", "-json", str(temp / "plan.bin")], cwd=root, env=env,
                         output=temp / "plan.json", timeout=20, mutating=False)
            files |= {name: (temp / name).read_bytes() for name in ("plan.bin", "plan.json", "inputs.tfvars.json")}
            files["redacted-plan.json"] = c.redacted_plan(files["plan.json"], source, purpose)
            c.validate_delta(c.loads(files["plan.json"], state=True), purpose)
            c.drift_coverage(c.loads(files["plan.json"], state=True), before_reports, governance["drift_matrix"],
                             source, purpose, "before")
            if purpose == "bootstrap":
                from tools.cnesdata_delivery.outputs import initial_admission
                initial_admission(c.loads(files["plan.json"], state=True), c.loads(files["inputs.tfvars.json"]), state_bytes,
                                  governance["bootstrap_checkpoint"], source, aws, governance["account_id"], time.time())
            entries = [{"name": name, "size": len(data), "sha256": c.sha(data)} for name, data in sorted(files.items())]
            # Baseline evaluations must be bound to the newly generated JSON, not reused.
            policy_file = product / "policies/cnesdata.rego"
            evaluator = shutil.which("conftest")
            c.require(evaluator and c.sha(Path(evaluator).read_bytes()) == governance["policy_evaluator_sha256"]
                      and c.sha(policy_file.read_bytes()) == governance["policy_sha256"], "pinned policy/evaluator bytes")
            watchdog.run([evaluator, "test", str(temp / "plan.json"), "--policy", str(policy_file), "--output", "json"],
                         cwd=product, env=env, output=temp / "policy.json", timeout=20, mutating=False)
            files["policy-evaluation.json"] = (temp / "policy.json").read_bytes()
            iam_resolver = prepare_iam(files)
            baseline = baseline | {"iam_resolver": iam_resolver}
            graph = c.validate_graph(c.loads(files["plan.json"], state=True), baseline["phase_a_graph"], baseline["actual_source_files"], iam_resolver) if purpose == "phase-a" else None
            files["policy-proof.json"] = c.canonical({"evaluation_sha256": c.sha(files["policy-evaluation.json"]), "graph_proof": graph})
            files["cost-report.json"] = c.canonical(baseline["cost_evidence"])
            files["cost-manifest.json"] = c.canonical(baseline["cost_manifest"])
            files["drift-before.json"] = c.canonical({"state_before": before, "readbacks": before_reports,
                                                      "ecr_before": ecr_before, "observed_at": started})
            entries = [{"name": name, "size": len(data), "sha256": c.sha(data)} for name, data in sorted(files.items())]
            policy = {"verdict": "pass", "evidence_sha256": c.sha(files["policy-proof.json"]),
                      "policy_sha256": governance["policy_sha256"], "evaluator_sha256": governance["policy_evaluator_sha256"],
                      "plan_json_sha256": c.sha(files["plan.json"])}
            plan = {"repository": c.REPOSITORY, "source_sha": source,
                    "producer": {"workflow_path": ".github/workflows/infra-plan.yml", "workflow_sha": current["head_sha"], "run_id": run_id, "run_attempt": attempt},
                    "package": {"files": entries, "aggregate_sha256": c.sha(c.canonical(entries))}, "purpose": purpose,
                    "created_at": started, "expires_at": c.utc(expiry), "binary_sha256": c.sha(files["plan.bin"]),
                    "json_sha256": c.sha(files["plan.json"]), "inputs_sha256": c.sha(files["inputs.tfvars.json"]),
                    **{k: baseline[k] for k in ("dependencies", "toolchain", "backend")}, "state_before": before,
                    "policy": policy, "cost": governance["cost"],
                    "drift": {"verdict": "pass", "evidence_sha256": c.sha(files["drift-before.json"]), "state_sha256": before["state_sha256"],
                              "observed_at": started, "expires_at": c.utc(expiry)},
                    "release": governance.get("release"), "phase_a_inputs": governance.get("phase_a_inputs")}
            envelope = {"schema_version": 1, "status": "planned", "plan": plan, "apply": None,
                        "plan_binding_sha256": c.sha(c.canonical(plan))}
            c.validate_envelope(envelope, files, baseline, time.time(), source)
        watchdog.finalization_deadline = min(time.monotonic() + 45, watchdog.fixed_deadline - 120, watchdog.credential_deadline - 120)
        after_bytes, state_object_after = aws.get_state(absent=True)
        after = c.state_identity(after_bytes)
        if role == "plan":
            c.require(after == before and state_object_after == state_object_before, "state version changed during plan")
        if role == "deploy":
            c.require(after_bytes is not None, "applied state absent; recovery_required")
            c.applied_state(c.loads(files["plan.json"], state=True), c.loads(after_bytes, state=True))
        reports = _readbacks(aws, governance, watchdog, after_bytes if role == "deploy" and iam_resolver is not None else None, iam_resolver)
        c.drift_coverage(c.loads(files["plan.json"], state=True), reports, governance["drift_matrix"],
                         source, purpose, "after" if role == "deploy" else "before",
                         c.loads(after_bytes, state=True) if role == "deploy" else None)
        applied_outputs = None
        drift_raw = None
        if role == "deploy":
            if purpose == "phase-a":
                applied_outputs = _outputs(after_bytes, plan, f"{governance['account_id']}.dkr.ecr.us-east-2.amazonaws.com/{governance['ecr_repository']}")
            else:
                from tools.cnesdata_delivery import outputs
                state = c.loads(after_bytes, state=True)
                watchdog.check()
                applied_outputs = outputs.acm(state, aws, governance["account_id"]) if purpose == "acm-certificate" else outputs.bootstrap(state, aws, governance["account_id"])
                watchdog.check()
            readbacks_completed_at = c.utc(time.time())
            drift_raw = c.canonical({"drift_report_version": 1, "repository": c.REPOSITORY, "source_sha": source,
                "purpose": purpose, "run_id": run_id, "run_attempt": attempt,
                "ecr_before": ecr_before, "post_readbacks": reports})
            aws.put(bucket, attempt_prefix + "drift.json", drift_raw)
        checkpoint = {"state_after": after, "state_object": state_object_after, "outputs": applied_outputs, "readbacks": reports,
                      "drift_sha256": c.sha(drift_raw) if drift_raw is not None else None,
                      "operation_completed_at": c.utc(time.time())}
        checkpoint_hash = c.sha(c.canonical(checkpoint))
        prefix = _prefix(governance, source, run_id, attempt, "planned" if role == "plan" else "applied")
        aws.put(bucket, prefix + "checkpoint.json", c.canonical(checkpoint))
        aws.put(bucket, prefix + "readback.json", c.canonical(reports))
        aws.put(bucket, prefix + "principal.json", c.canonical(aws.identity))
        lease.release(checkpoint_hash)
        lease_evidence = lease.evidence(checkpoint_hash, child)
        evidence_hash = c.sha(c.canonical(lease_evidence))
        aws.put(bucket, prefix + "lease.json", c.canonical(lease_evidence))
        watchdog.finalizing = True
        if role == "deploy":
            envelope = envelope | {"status": "applied", "apply": {
                "producer": {"workflow_path": ".github/workflows/infra-apply.yml", "workflow_sha": current["head_sha"], "run_id": run_id, "run_attempt": attempt},
                "consumed_plan_artifact": {"artifact_id": descriptor["payload_artifact"]["artifact_id"], "artifact_sha256": descriptor["payload_artifact"]["artifact_digest"].removeprefix("sha256:"),
                                           "run_id": descriptor["payload_artifact"]["run_id"], "run_attempt": descriptor["payload_artifact"]["run_attempt"]},
                "plan_binding_sha256": envelope["plan_binding_sha256"], "started_at": started, "completed_at": checkpoint["operation_completed_at"], "result": "success",
                "lease": {"protocol": "s3-cas-v1", "owner_sha256": c.sha(lease.token.encode()), "repository": c.REPOSITORY,
                          "run_id": run_id, "run_attempt": attempt, "session_sha256": session, "acquired_at": lease.acquired_at, "released_at": lease.release_event["responded_at"],
                          "ttl_seconds": 300, "renew_interval_seconds": 60, "safety_margin_seconds": 120,
                          "acquire_etag_sha256": lease.acquire_event["etag_sha256"], "release_etag_sha256": lease.release_event["etag_sha256"],
                          "renewal_count": len(lease.renewals), "checkpoint_sha256": checkpoint_hash, "evidence_sha256": evidence_hash, "terminal_status": "released"},
                "principal": {"kind": "assumed-role", "account_id": governance["account_id"], "region": "us-east-2", "gate": "deploy", "role_arn": governance["roles"]["deploy"],
                              "session_sha256": session, "credential_expires_at": os.environ["AWS_CREDENTIAL_EXPIRATION"], "evidence_sha256": c.sha(c.canonical(aws.identity))},
                "state_after": after | {"outputs_sha256": c.sha(c.canonical(applied_outputs))},
                "drift": {"verdict": "clean", "evidence_sha256": c.sha(drift_raw), "readback_sha256": c.sha(drift_raw), "observed_at": readbacks_completed_at},
                "outputs": applied_outputs}}
        status = envelope["status"]
        raw = c.canonical(envelope)
        c.require(len(raw) <= 262144, "envelope size")
        if role == "deploy":
            c.validate_envelope(envelope, files, baseline | {"deploy_role_arn": governance["roles"]["deploy"]},
                                time.time(), source, status="applied")
            observed_drift, _ = aws.get(bucket, prefix + "drift.json", maximum=262144)
            retained_ecr, _ = aws.get(bucket, prefix + "ecr-before.json", maximum=65536) if purpose == "phase-a" else (None, None)
            verify_drift_evidence(envelope, observed_drift, retained_ecr, promotion if purpose == "phase-a" else None)
        aws.put(bucket, prefix + "envelope.json", raw)
        for name, data in files.items():
            if role == "plan":
                aws.put(bucket, prefix + name, data)
        observed, _ = aws.get(bucket, prefix + "envelope.json", maximum=262144)
        c.require(observed == raw, "private final publication readback")
        producer = plan["producer"] if role == "plan" else envelope["apply"]["producer"]
        index = {"index_version": 1, "kind": "cnesdata-private-plan-transport", "status": status, "repository": c.REPOSITORY,
                 "source_sha": source, "producer": producer, "purpose": purpose, "created_at": plan["created_at"], "expires_at": plan["expires_at"],
                 "plan_binding_sha256": envelope["plan_binding_sha256"], "envelope_sha256": c.sha(raw), "package_aggregate_sha256": plan["package"]["aggregate_sha256"],
                 "private_locator": {"scope": "cnesdata-prod", "source_sha": source, "run_id": run_id, "run_attempt": attempt, "status": status},
                 "policy": {k: plan["policy"][k] for k in ("verdict", "evidence_sha256")},
                 "cost": plan["cost"],
                 "drift": {"verdict": "pass" if role == "plan" else "clean", "evidence_sha256": plan["drift"]["evidence_sha256"] if role == "plan" else envelope["apply"]["drift"]["evidence_sha256"]},
                 "admission_proof": proof}
        public = temp / "public"
        public.mkdir()
        public_files = {"index.json": c.canonical(index), "redacted-plan.json": files["redacted-plan.json"],
                        **{r["name"]: proof_files[r["name"]] for r in proof["reports"]}}
        c.public_safe(index)
        for name, data in public_files.items():
            (public / name).write_bytes(data)
        artifact = _upload(public, f"cnesdata-{status}-{run_id}-{attempt}", watchdog, temp)
        _verify_current_artifact(api, artifact, public_files, run_id)
        receipt = {"receipt_version": 1, "repository": c.REPOSITORY, "run_id": run_id, "run_attempt": attempt,
                   "envelope_sha256": c.sha(raw), "index_artifact_id": artifact["id"], "index_artifact_digest": artifact["digest"],
                   "lease_evidence_sha256": evidence_hash, "checkpoint_sha256": checkpoint_hash,
                   "verified_at": c.utc(time.time()), "result": "success"}
        receipt_dir = temp / "receipt"
        receipt_dir.mkdir()
        receipt_bytes = c.canonical(receipt)
        (receipt_dir / "receipt.json").write_bytes(receipt_bytes)
        final = _upload(receipt_dir, f"cnesdata-{status}-receipt-{run_id}-{attempt}", watchdog, temp)
        _verify_current_artifact(api, final, {"receipt.json": receipt_bytes}, run_id)
        watchdog.check()
        c.require(time.monotonic() < watchdog.finalization_deadline, "R1 publication deadline; recovery_required")
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"evidence_run_id={run_id}\nevidence_artifact_id={artifact['id']}\nevidence_artifact_digest={artifact['digest']}\nevidence_status={status}\n")


def _outputs(raw_state, plan, repository_uri):
    state = c.loads(raw_state, state=True)
    root = {name: item["value"] for name, item in state["outputs"].items()}
    if plan["purpose"] == "acm-certificate":
        return {"acm_dns_validation_records": root["acm_dns_validation_records"]}
    if plan["purpose"] == "bootstrap":
        return {}
    phase, release = plan["phase_a_inputs"], plan["release"]
    revisions = root["processor_task_definition_arns"]
    c.closed(revisions, "unit recovery audit")
    checked_modes = set()
    groups = {"resource_fingerprints": [], "grant_fingerprints": [], "route_fingerprints": []}
    for resource in state.get("resources", []):
        if resource.get("mode") != "managed":
            continue
        prefix = (resource.get("module", "") + ".").lstrip(".") + resource["type"] + "." + resource["name"]
        for instance in resource["instances"]:
            address = prefix
            if "index_key" in instance:
                import json
                key = instance["index_key"]
                from decimal import Decimal
                address += "[" + json.dumps(int(key) if type(key) is Decimal else key, ensure_ascii=False) + "]"
            observed = {"address": address, "observed": instance["attributes"]}
            if prefix == "module.processing.aws_ecs_task_definition.processor":
                mode = instance["index_key"]
                containers = c.loads(instance["attributes"]["container_definitions"].encode(), state=True)
                selected = [item for item in containers if item["name"] == root["processor_container_name"]]
                c.require(len(selected) == 1 and selected[0]["image"] == repository_uri + "@" + release["image_digest"]
                          and instance["attributes"]["arn"] == revisions[mode], "real applied ECS image/revision")
                checked_modes.add(mode)
            item = {"address": address, "fingerprint_sha256": c.sha(c.canonical(observed))}
            if address.startswith(("module.processing.", "module.runtime_iam.aws_iam_role.canary_", "module.runtime_iam.aws_iam_role_policy.canary_")):
                groups["resource_fingerprints"].append(item)
            if resource["type"] in {"aws_iam_role_policy", "aws_iam_role"}:
                groups["grant_fingerprints"].append(item)
            if resource["type"] in {"aws_scheduler_schedule", "aws_sfn_state_machine", "aws_route", "aws_route_table"}:
                groups["route_fingerprints"].append(item)
    for key, items in groups.items():
        c.require(len(items) <= 64, "fingerprint capacity")
        groups[key] = sorted(items, key=lambda item: item["address"])
    c.require(checked_modes == {"unit", "recovery", "audit"}, "all applied processor modes observed")
    return {"processor_task_definition_arns": revisions, "image_digest": release["image_digest"],
            "active_before": phase["processor_active_unit_task_definition_arn"],
            "retained_before": phase["processor_retained_unit_task_definition_arns"],
            "retained_after": sorted(set(phase["processor_retained_unit_task_definition_arns"] + [revisions["unit"]])),
            "canary_id": release["canary_id"], "binding_sha256": release["binding_sha256"], **groups}


def main(role):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preflight", "credentials", "execute"))
    args = parser.parse_args()
    try:
        from tools.cnesdata_delivery.lifecycle_contract import PURPOSES
        if os.environ.get("PURPOSE") in PURPOSES:
            from tools.cnesdata_delivery.lifecycle_runtime import main as lifecycle_main
            return lifecycle_main(role, args.operation)
        if args.operation == "preflight":
            admission(role)
        elif args.operation == "credentials":
            credentials(role)
        else:
            execute(role)
    except Exception as error:
        # SDK diagnostics / Terraform values / URLs are private; log only a safe type.
        raise SystemExit("delivery gate closed: " + type(error).__name__ + "; recovery_required after any ambiguous operation") from None


def credentials(role):
    """Mint OIDC only after independently repeating the complete public gate."""
    governance, descriptor, api, current, proof, proof_files, index = admission(role)
    _publisher_ready()
    from tools.cnesdata_delivery import session_owner, session_policy
    authority = session_owner.authenticate(governance, descriptor, proof, proof_files, api,
                                           time.time(), role, os.environ["PURPOSE"],
                                           plan_binding_sha256=index["plan_binding_sha256"] if role == "deploy" else None)
    session_request = session_policy.request(governance, descriptor["source_sha"], current["id"], current["run_attempt"], role,
                   _session_reads(governance, descriptor, api, index, role, os.environ["PURPOSE"], authority))
    import base64
    import urllib.request
    from urllib.parse import urlparse
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    parsed = urlparse(url)
    c.require(parsed.scheme == "https" and parsed.hostname and
              parsed.hostname.endswith(".actions.githubusercontent.com"), "OIDC request host")
    url += "&audience=sts.amazonaws.com"
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with urllib.request.urlopen(request, timeout=20) as response:
        token = c.loads(response.read(65536))["value"]
    parts = token.split(".")
    c.require(len(parts) == 3, "OIDC token shape")
    claims = c.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    workflow = f"VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-{role}-gate.yml@{governance['gate_shas'][role]}"
    c.require(claims["iss"] == "https://token.actions.githubusercontent.com" and claims["aud"] == "sts.amazonaws.com"
              and claims["sub"] == f"repo:{c.REPOSITORY}:environment:production:job_workflow_ref:{workflow}"
              and claims["job_workflow_ref"] == workflow and claims["repository"] == c.REPOSITORY
              and claims["ref"] == "refs/heads/develop", "OIDC governed claims")
    client = boto3.client("sts", region_name="us-east-2", config=Config(signature_version=UNSIGNED,
                          connect_timeout=5, read_timeout=10, retries={"total_max_attempts": 1}, ignore_configured_endpoint_urls=True))
    from tools.cnesdata_delivery.aws_boundary import bounded
    response = bounded(lambda: client.assume_role_with_web_identity(RoleArn=governance["roles"][role],
        RoleSessionName=f"cnesdata-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}",
        WebIdentityToken=token, DurationSeconds=3600, **session_request))
    value = session_policy.validate_response(response)
    session_owner.verify_managed(AWS(governance, credentials=value), authority, value["Expiration"].timestamp())
    # Runner workflow-command control channel, not an ordinary log line. Register
    # before GITHUB_ENV, whose next-step environment block would otherwise expose it.
    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
        secret = value[field]
        c.require(type(secret) is str and secret and "\n" not in secret and "\r" not in secret, "credential transport string")
        print("::add-mask::" + secret.replace("%", "%25"), flush=True)
    with open(os.environ["GITHUB_ENV"], "a") as output:
        for name, field in (("AWS_ACCESS_KEY_ID", "AccessKeyId"), ("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"),
                            ("AWS_SESSION_TOKEN", "SessionToken")):
            output.write(name + "=" + value[field] + "\n")
        output.write("AWS_CREDENTIAL_EXPIRATION=" + c.utc(value["Expiration"].timestamp()) + "\n")
