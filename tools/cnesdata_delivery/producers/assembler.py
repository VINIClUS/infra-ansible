"""Job assemble: proof.json and reports from measurements, without AWS, credentials or report keys."""
import argparse
import os
import sys
from collections import namedtuple
from pathlib import Path

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.producers import cost_context, measurements
from tools.cnesdata_delivery.producers.chain import expiry_chain, validate_chain
from tools.cnesdata_delivery.provenance import BASE_CHECKS

PHASE_A_CHECKS = {"promotion469-origin", "r2-candidate-a2-binding", "oci-promotion-byte-integrity"}
DEPLOY_CHECKS = {"exact-saved-plan-package", "planned-source-input-binding"}
PRODUCER = "repository workflow_path workflow_sha run_id run_attempt"
REPORT_LIMIT = 262144
Assembled = namedtuple("Assembled", "files proof")
__all__ = ["Assembled", "artifact_names", "assemble", "cost_baseline", "expiry_chain", "required_checks",
           "validate_chain"]


def required_checks(purpose, role):
    return sorted(BASE_CHECKS | (PHASE_A_CHECKS if purpose == "phase-a" else set())
                  | (DEPLOY_CHECKS if role == "deploy" else set()))


def artifact_names(source, role, run, attempt):
    return {"drift": f"delivery-drift-{source[:8]}-{run}-{attempt}",
            "admission": f"delivery-admission-{role}-{run}-{attempt}"}


def cost_baseline(purpose, derived, checkpoint):
    """Args: purpose, derived ledger, cost stage. Returns: the governance baseline cost fields and cost."""
    c.require(checkpoint["stage"] == cost_context.stage_name(purpose), "cost stage differs from purpose")
    c.require(checkpoint["stage"] == "active", "pre-activation cost not derived")
    cost, evidence = cost_context.cost_objects(derived, checkpoint)
    return {"cost_context": checkpoint, "cost_evidence": evidence, "cost_manifest": derived["manifest"],
            "source_manifest_sha256": derived["source_manifest_sha256"], "cost": cost}


def _reports(inputs, chain):
    source, files, checks, reports = inputs["source_sha"], {}, [], []
    subject = c.sha(c.canonical({"purpose": inputs["purpose"], "role": inputs["role"], "source_sha": source}))
    for check_id in required_checks(inputs["purpose"], inputs["role"]):
        measured = inputs["measurements"][check_id]
        c.public_safe(measured)
        raw = c.canonical({"check_id": check_id, "source_sha": source, "measurement": measured}, limit=REPORT_LIMIT)
        digest = c.sha(c.canonical(measured))
        checks.append({"check_id": check_id, "subject_sha256": subject, "expected_sha256": digest,
                       "observed_sha256": digest, "result": "pass", "observed_at": chain["observed_at"],
                       "expires_at": chain["check_expires_at"]})
        reports.append({"check_id": check_id, "name": check_id + ".json", "size": len(raw), "sha256": c.sha(raw)})
        files[check_id + ".json"] = raw
    return files, checks, reports


def _artifacts(entries, chain):
    proof = c.instant(chain["proof_expires_at"])
    result = []
    for entry in sorted(entries, key=lambda item: item["purpose"]):
        c.require(c.instant(entry["expires_at"]) >= proof, "artifact expiry below proof expiry")
        inventory = [{"name": name, "size": len(raw), "sha256": c.sha(raw)} for name, raw in sorted(entry["members"].items())]
        result.append({"purpose": entry["purpose"], "reference": entry["reference"],
                       "content_sha256": c.sha(c.canonical(inventory)), "expires_at": entry["expires_at"]})
    return result


def _binding(inputs):
    value = inputs["plan_binding_sha256"]
    if inputs["role"] == "deploy":
        c.digest(value)
    else:
        c.require(value is None, "plan admission has no saved-plan binding")
    return value


def assemble(inputs):
    """Args: purpose, role, source_sha, observed_at, producer, measurements, artifacts, release fields.

    Returns: Assembled(files, proof). Raises: ValueError before any file is produced.
    """
    if inputs["purpose"] == "phase-a":
        measurements.drift_baseline(inputs["measurements"]["drift-baseline"])
    c.require(sorted(inputs["measurements"]) == required_checks(inputs["purpose"], inputs["role"]), "complete checks")
    c.closed(inputs["producer"], PRODUCER)
    chain = expiry_chain(inputs["observed_at"])
    files, checks, reports = _reports(inputs, chain)
    proof = {"proof_version": 1, "source": {"repository": c.REPOSITORY, "ref": "refs/heads/main",
                                            "source_sha": inputs["source_sha"]},
             "producer": inputs["producer"], "artifacts": _artifacts(inputs["artifacts"], chain), "reports": reports,
             "checks": checks, "candidate_sha256": inputs["candidate_sha256"],
             "promotion_evidence_sha256": inputs["promotion_evidence_sha256"],
             "plan_binding_sha256": _binding(inputs), "observed_at": chain["observed_at"],
             "expires_at": chain["proof_expires_at"]}
    return Assembled(files | {"proof.json": c.canonical(proof)}, proof)


def main(argv=None):
    from tools.cnesdata_delivery.producers import inputs
    from tools.cnesdata_delivery.provenance import GitHub
    parser = argparse.ArgumentParser(description="CnesData delivery assembler")
    parser.add_argument("--observed", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    observed = {path.name: path.read_bytes() for path in Path(args.observed).iterdir()}
    values, extra = inputs.build(GitHub(), inputs.request_from(os.environ), observed)
    built = assemble(values)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, raw in (built.files | extra).items():
        (out / name).write_bytes(raw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
