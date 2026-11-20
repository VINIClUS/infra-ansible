"""Assembler inputs from authenticated baseline artifacts, the observations and the public request."""
import os
import re
import time

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.producers import chain, cost_context, cost_ledger, measurements, pins
from tools.cnesdata_delivery.producers.assembler import cost_baseline

BASELINES = ("backend", "cost", "policy", "shared-outputs", "toolchain")
SOURCE_MANIFEST = "cost-manifest-source.json"
COST_CONTEXT = "cost-context.json"


def _member(files, name):
    c.require(name in files, f"baseline member absent name={name}")
    return files[name]


def producer(environment=None):
    """Returns: the caller identity the proof is produced under, from the GitHub run environment."""
    env = os.environ if environment is None else environment
    match = re.fullmatch(r"([^/]+/[^/]+)/(\.github/workflows/[^@]+)@.+", env["GITHUB_WORKFLOW_REF"])
    c.require(match is not None, "caller workflow ref")
    return {"repository": match.group(1), "workflow_path": match.group(2), "workflow_sha": env["GITHUB_SHA"],
            "run_id": int(env["GITHUB_RUN_ID"]), "run_attempt": int(env["GITHUB_RUN_ATTEMPT"])}


def _cost(request, members, observed_at):
    source = request["source_sha"]
    context = c.loads(_member(members["cost"], COST_CONTEXT))
    derived = cost_ledger.derive(_member(members["cost"], SOURCE_MANIFEST), source_sha=source,
                                 calculated_at=observed_at, expires_at=request["cost_expires_at"])
    stage = cost_context.stage(request["purpose"], source, context, request.get("cloudfront"))
    return cost_baseline(request["purpose"], derived, stage), derived


def _phase_a(request, observations):
    promotion = {item["name"]: item for item in request["public_objects"]}["promotion.json"]
    return {"promotion469-origin": measurements.promotion_origin(
                promotion["sha256"], request["promotion_producer"], request["payload_reference"]["artifact_digest"]),
            "r2-candidate-a2-binding": observations["r2-candidate-a2-binding"],
            "oci-promotion-byte-integrity": observations["oci-promotion-byte-integrity"]}


def _measured(api, request, observations, bundle):
    members, baseline = bundle
    role, source = request["role"], request["source_sha"]
    hashes = c.loads(_member(members["policy"], "policy.json"))
    toolchain = c.loads(_member(members["toolchain"], "toolchain.json"))
    closure = pins.producer_pins(pins.api_reader(api), request["x_star"])[0]["content_sha256"]
    namespace = observations.get("phase_input_namespace")
    value = {
        "source-develop-checks": measurements.source_checks(api, source, request["required_checks"]),
        "artifact-origin-attempt-expiry": measurements.artifact_origin(api, [
            {"purpose": name, "reference": reference} for name, reference in request["references"].items()]),
        "dependency-pins": measurements.dependency_pins(request["dependencies"], closure),
        "toolchain-lock-selections": measurements.toolchain(toolchain, toolchain["providers"]),
        "backend-identity-workspace": measurements.backend(c.loads(_member(members["backend"], "backend.json"))),
        "policy-evaluation": measurements.policy_evaluation(observations["session_facts"][role], namespace, hashes),
        "cost-ledger-purpose-scope": measurements.cost_ledger(baseline["cost_evidence"]),
        "drift-baseline": measurements.drift_baseline(observations["drift-baseline"])}
    return value | (_phase_a(request, observations) if request["purpose"] == "phase-a" else {})


def _limits(request, baseline, times):
    return {"proof": times["proof_expires_at"], "cost": baseline["cost"]["expires_at"],
            "cloudfront": baseline["cost_context"]["cloudfront"]["expires_at"], "pin": times["pin_expires_at"],
            "frozen": times["frozen_until"], "artifacts": [request["artifact_expires_at"]],
            "plan": request["plan_expires_at"]}


def build(api, request, observed):
    """Args: GitHub API, merged request, observer files. Returns: (assembler inputs, extra public members)."""
    observations = c.loads(observed["observations.json"], canonical=True)
    members = {name: api.artifact(reference, request["now"]) for name, reference in request["references"].items()
               if name != "drift"}
    c.require(set(BASELINES) <= set(members), "baseline references")
    members["drift"] = {"drift-handoff.json": observed["drift-handoff.json"]}
    baseline, derived = _cost(request, members, observations["observed_at"])
    times = chain.expiry_chain(observations["observed_at"])
    chain.validate_chain(times, _limits(request, baseline, times))
    entries = [{"purpose": name, "reference": request["references"][name], "members": members[name],
                "expires_at": request["artifact_expires_at"]} for name in sorted(members)]
    values = {"purpose": request["purpose"], "role": request["role"], "source_sha": request["source_sha"],
              "observed_at": observations["observed_at"], "producer": request["producer"],
              "measurements": _measured(api, request, observations, (members, baseline)), "artifacts": entries,
              "candidate_sha256": request.get("candidate_sha256"),
              "promotion_evidence_sha256": request.get("promotion_evidence_sha256"),
              "plan_binding_sha256": request.get("plan_binding_sha256")}
    return values, {"cost-baseline.json": c.canonical(baseline), "cost-sources.json": c.canonical(derived["sources"])}


def request_from(environment):
    """Args: GitHub run environment. Returns: the merged public request, drift reference included."""
    value = c.loads(environment["REQUEST"].encode())
    caller = producer(environment)
    drift = {"repository": caller["repository"], "run_id": caller["run_id"], "run_attempt": caller["run_attempt"],
             "artifact_id": int(environment["DRIFT_ARTIFACT_ID"]), "artifact_digest": environment["DRIFT_ARTIFACT_DIGEST"],
             "workflow_path": caller["workflow_path"], "workflow_sha": caller["workflow_sha"],
             "source_sha": caller["workflow_sha"]}
    return value | {"purpose": environment["PURPOSE"], "role": environment["ROLE"],
                    "source_sha": environment["SOURCE_SHA"], "x_star": environment["X_STAR"], "producer": caller,
                    "references": value["references"] | {"drift": drift}, "now": time.time()}
