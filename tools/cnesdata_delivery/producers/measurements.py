"""Measurement builders per check_id; each returns the public, closed measurement of §5.2."""
import copy
import re

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.producers.pins import REPOSITORY

DRIFT = ("handoff_sha256 rehearsal_plan_sha256 catalog_sha256 matrix_version source_sha purpose state_identity "
         "rows_before rows_after absent_rows readbacks_before readbacks_after")
BACKEND = "identity_sha256 key workspace region encrypt use_lockfile bucket_hmac kms_key_id_sha256"
PLAN_INDEX = "plan_binding_sha256 envelope_sha256 package_aggregate_sha256"
TRANSPORT_INDEX = ("index_version kind status repository source_sha producer purpose created_at expires_at "
                   + PLAN_INDEX + " private_locator policy cost drift admission_proof")
PRODUCER = "repository workflow_path workflow_sha run_id run_attempt"


def drift_baseline(observation):
    value = observation.get("rehearsal_plan_sha256")
    c.require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "rehearsal plan sha256")
    c.closed(observation, DRIFT)
    return copy.deepcopy(observation)


def dependency_pins(pins, closure, x_star):
    c.require(all(pin["source_sha"] == c.digest(x_star, 40) and pin["repository"] == REPOSITORY for pin in pins),
              "dependency pin source or repository")
    c.require(all(pin["content_sha256"] == c.digest(closure) for pin in pins), "recomputed closure differs from pins")
    return {"pins": copy.deepcopy(pins), "closure_recomputed_sha256": closure}


def toolchain(value, lock_providers):
    c.require(value["providers"] == lock_providers, "lock providers differ from measurement")
    return copy.deepcopy(value) | {"lock_providers_equal": True}


def backend(value):
    c.closed(value, BACKEND)
    c.require(value["workspace"] == "default", "backend workspace")
    for field in ("identity_sha256", "bucket_hmac", "kms_key_id_sha256"):
        c.digest(value[field])
    return copy.deepcopy(value)


def policy_evaluation(facts, namespace, hashes):
    value = {"managed_session_policy": facts, "policy_sha256": c.digest(hashes["policy_sha256"]),
             "conftest_sha256": c.digest(hashes["conftest_sha256"])}
    return value | ({} if namespace is None else {"phase_input_namespace": namespace})


def cost_ledger(evidence):
    c.require(evidence["check_id"] == "cost-ledger-purpose-scope", "cost evidence check")
    return evidence["measurement"]


def source_checks(api, source, names):
    base = f"repos/{c.REPOSITORY}"
    status = api.read(f"{base}/compare/{source}...main")["status"]
    c.require(status in {"ahead", "identical"}, "source not contained in main")
    runs = api.read(f"{base}/commits/{source}/check-runs?per_page=100")["check_runs"]
    required = []
    for name in sorted(set(names)):
        c.require(any(run["name"] == name and run["conclusion"] == "success" and run["head_sha"] == source
                      for run in runs), "required source check")
        required.append({"name": name, "conclusion": "success", "head_sha": source})
    return {"branch": "main", "compare_status": status, "required": required}


def artifact_origin(api, entries):
    found = []
    for entry in sorted(entries, key=lambda item: item["purpose"]):
        ref = entry["reference"]
        run = api.read(f"repos/{ref['repository']}/actions/runs/{ref['run_id']}/attempts/{ref['run_attempt']}")
        meta = api.read(f"repos/{ref['repository']}/actions/artifacts/{ref['artifact_id']}")
        interior = c.instant(run["run_started_at"]) < c.instant(meta["created_at"]) < c.instant(run["updated_at"])
        c.require(interior, "artifact creation not interior to the run attempt")
        found.append({"purpose": entry["purpose"], "reference_sha256": c.sha(c.canonical(ref)),
                      "artifact_digest": ref["artifact_digest"], "run_id": ref["run_id"],
                      "run_attempt": ref["run_attempt"], "run_started_at": run["run_started_at"],
                      "created_at": meta["created_at"], "updated_at": run["updated_at"],
                      "expires_at": meta["expires_at"], "interior": True})
    return found


def promotion_origin(promotion_sha256, producer, artifact_digest):
    c.closed(producer, PRODUCER)
    return {"promotion_sha256": c.digest(promotion_sha256), "producer": copy.deepcopy(producer),
            "artifact_digest": artifact_digest}


def exact_plan_package(index, artifact_digest):
    c.closed(index, TRANSPORT_INDEX)
    return {key: c.digest(index[key]) for key in PLAN_INDEX.split()} | {"index_artifact_digest": artifact_digest}


def planned_binding(source, purpose, references, candidate_sha256):
    return {"source_sha": c.digest(source, 40), "purpose": purpose,
            "phase_inputs_reference_sha256": c.digest(references["phase_inputs"]),
            "planned_reference_sha256": c.digest(references["planned"]),
            "release_candidate_sha256": c.digest(candidate_sha256)}
