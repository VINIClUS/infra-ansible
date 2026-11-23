"""Owner CLI: governance documents under the write ceilings, cross-checks and the release guard."""
import argparse
import sys
from pathlib import Path

from tools.cnesdata_delivery import contract as c, drift_handoff
from tools.cnesdata_delivery.producers import baseline_commitments, hmac_key, release_guard
from tools.cnesdata_delivery.producers.chain import expiry_chain

CLI_CEILING = 40960
SECRET_CEILING = 47952
SESSION_ROLES = ("plan", "deploy", "application")
GOVERNANCE_KEYS = frozenset("""
    account_id activation_enabled activation_read admission_reference application_configuration
    application_coordination_policy application_delegations application_fragment
    application_product_source_closure_sha256
    application_product_source_manifest_artifact application_purpose application_source_closure_sha256
    artifact_purposes artifact_references authenticated_application_caller authority authorization baseline
    baseline_artifacts bootstrap_checkpoint caller_allowlist consumer contract_sha256 cost cost_handoff
    context_kind credentials crypto dependencies drift_handoff drift_matrix ecr_repository evidence_bucket
    evidence_kms_key_arn evidence_prefix ext2 gate_shas history host images lifecycle_authority
    lifecycle_contract lifecycle_enabled lifecycle_predecessor lifecycle_steps_sha256 lifecycle_terminal_job
    phase_a_inputs phase_input_objects plan_run_id policy_evaluator_sha256 policy_sha256 predecessor_read
    principal_sha256 product_inputs promotion_sha256 proof_producers provenance readbacks region release
    report_hmac_key required_checks role roles runner runtime_contract_sha256 runtime_probes runtime_sha256
    session_duration_seconds session_owner_references session_policy_pins signing signing_spki_pem_sha256
    source_closure_sha256 source_files source_sha state_bucket state_kms_key_arn storage workflows
""".split())
HYDRATED_KEYS = frozenset(("lifecycle_steps", "source_closure"))
REFERENCES = ("lifecycle_steps_sha256", "source_closure_sha256")


def render(document, ceiling=CLI_CEILING):
    """Args: governance document, ceiling in bytes. Returns: canonical bytes. Raises: ValueError over the ceiling."""
    c.require(ceiling <= SECRET_CEILING, f"write ceiling above the secret ceiling ceiling={ceiling}")
    raw = c.canonical(document)
    c.require(len(raw) <= ceiling, f"governance above the write ceiling size={len(raw)} ceiling={ceiling}")
    return raw


def _cost_stage(document):
    cost, baseline = document.get("cost"), document.get("baseline", {})
    if cost is not None and "cost_context" in baseline:
        c.require(cost["scope"] == baseline["cost_context"]["stage"], "cost scope differs from cost context stage")


def _closed_keys(document):
    for key in document:
        c.require(key in GOVERNANCE_KEYS, f"governance key={key}")


def _pin_chain(role, pin, start):
    chain = expiry_chain(start)
    ok = (pin["observed_at"] == start and c.instant(pin["expires_at"]) >= c.instant(chain["proof_expires_at"])
          and c.instant(pin["frozen_until"]) >= c.instant(chain["frozen_until"]))
    c.require(ok, f"expiry chain violated element=pin role={role}")


def _expiry_chain(document):
    pins = document.get("session_policy_pins") or {}
    c.require(type(pins) is dict, "session pins shape")
    for role, pin in pins.items():
        c.require(role in SESSION_ROLES, f"session pin role={role}")
        c.require(type(pin) is dict and {"observed_at", "expires_at", "frozen_until"} <= set(pin),
                  f"session pin fields role={role}")
    for role, pin in pins.items():
        start = pins["plan"]["observed_at"] if role == "deploy" and "plan" in pins else pin["observed_at"]
        _pin_chain(role, pin, start)
    cost = document.get("cost")
    if cost and cost.get("cloudfront"):
        ok = c.instant(cost["cloudfront"]["expires_at"]) >= c.instant(cost["expires_at"])
        c.require(ok, "expiry chain violated element=cloudfront")


def references(document):
    """Args: governance document. Raises: ValueError on an inline hydrated object or a malformed reference."""
    for key in HYDRATED_KEYS:
        c.require(key not in document, f"governance key={key}")
    for key in REFERENCES:
        if key in document:
            c.digest(document[key])


def crosscheck(document, commitments):
    """Args: governance document, public commitments. Raises: ValueError on any hash or format mismatch."""
    _closed_keys(document)
    _expiry_chain(document)
    c.report_key(document)
    value = document["product_inputs"]["shared_outputs"]
    c.require(c.sha(c.canonical(value)) == c.digest(commitments["shared_outputs_sha256"]), "shared outputs hash")
    for pin in document.get("dependencies", []):
        c.digest(pin["content_sha256"])
        c.digest(pin["source_sha"], 40)
    if "drift_handoff" in document:
        drift_handoff.pin(document)
    references(document)
    _cost_stage(document)


def _release_check(args):
    release_guard.check(Path(args.repo), args.x_star, args.k)


def _render(args):
    document = c.loads(Path(args.document).read_bytes())
    commitments = c.loads(Path(args.commitments).read_bytes())
    crosscheck(document, commitments)
    sys.stdout.buffer.write(render(document))


def _lifecycle_objects(args):
    from tools.cnesdata_delivery.producers import application
    output = Path(args.output)
    c.require(output.name == "lifecycle-steps.json" and not output.exists(), f"catalog member output={output.name}")
    raw, reference = application.catalog_member(c.loads(Path(args.steps).read_bytes()))
    manifest = c.loads(Path(args.manifest).read_bytes(), canonical=True, limit=4 * 1024**2)
    pinned = reference | application.source_closure_reference(manifest)
    output.write_bytes(raw)
    sys.stdout.buffer.write(c.canonical(pinned))


def _baseline_inputs(args):
    private = c.loads(Path(args.private).read_bytes())
    key = hmac_key.Custody().lookup()
    c.require(key is not None, "report hmac key absent from custody")
    sys.stdout.buffer.write(c.canonical(baseline_commitments.dispatch_inputs(private, key)))


def _key(args):
    custody = hmac_key.Custody()
    key = hmac_key.rotate(custody, custody.lookup()) if args.action == "rotate" else hmac_key.new_key()
    if args.action == "generate":
        custody.store(key)
    custody.deliver(key, args.repo, args.environment)


def parser():
    root = argparse.ArgumentParser(description="CnesData delivery owner CLI")
    commands = root.add_subparsers(dest="command", required=True)
    check = commands.add_parser("release-check")
    for name in ("--repo", "--x-star", "--k"):
        check.add_argument(name, required=True)
    check.set_defaults(run=_release_check)
    document = commands.add_parser("render")
    for name in ("--document", "--commitments"):
        document.add_argument(name, required=True)
    document.set_defaults(run=_render)
    objects = commands.add_parser("lifecycle-objects")
    for name in ("--steps", "--manifest", "--output"):
        objects.add_argument(name, required=True)
    objects.set_defaults(run=_lifecycle_objects)
    inputs = commands.add_parser("baseline-inputs")
    inputs.add_argument("--private", required=True)
    inputs.set_defaults(run=_baseline_inputs)
    key = commands.add_parser("key")
    key.add_argument("action", choices=("generate", "rotate"))
    key.add_argument("--repo", required=True)
    key.add_argument("--environment", required=True)
    key.set_defaults(run=_key)
    return root


def _refuse(reason):
    sys.stderr.write(f"refused reason={reason}\n")
    return 1


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        args.run(args)
    except ValueError as error:
        return _refuse(error)
    except KeyError as error:
        return _refuse(f"missing key={error.args[0]}")
    except (AttributeError, TypeError) as error:
        return _refuse(f"malformed type={type(error).__name__}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
