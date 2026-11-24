"""Job observe: read-only measurements and the sanitized handoff; one code path for CI and local mode."""
import argparse
import os
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import unquote

from tools.cnesdata_delivery import contract as c, drift_catalog, session_owner
from tools.cnesdata_delivery.producers import aws_reader, chain, drift_handoff, phase_inputs, rehearsal_plan
from tools.cnesdata_delivery.session_policy import managed_arn

STATE_KEY = rehearsal_plan.STATE_KEY
ROLES = ("plan", "deploy", "audit")
CONFIG_KEYS = "account_id roles state_bucket evidence_bucket evidence_prefix ecr_repository shared_outputs"
Observed = namedtuple("Observed", "files pins")


def _reports(reader, calls):
    reports = []
    for call in calls:
        drift_catalog.require_read_only(call["service"], call["operation"])
        value = reader.call(call["service"], call["operation"], **call["parameters"])
        reports.append({"service": call["service"], "operation": call["operation"],
                        "sha256": c.sha(c.canonical(value)), "observed": value})
    return reports


def _live_before(reader, plan, document):
    calls = drift_catalog.readback_calls(plan, document["readbacks"]["before"], "before")
    reports = _reports(reader, calls)
    envelope = drift_catalog.ENVELOPES[document["purpose"]]
    c.drift_coverage(plan, reports, document["matrix"], document["source_sha"], document["purpose"], "before",
                     specs=calls, envelope=envelope)


def _drift_baseline(document, raw, rehearsal_sha, state_raw):
    matrix, readbacks = document["matrix"], document["readbacks"]
    return {"handoff_sha256": c.sha(raw), "rehearsal_plan_sha256": rehearsal_sha,
            "catalog_sha256": document["catalog_sha256"], "matrix_version": matrix["matrix_version"],
            "source_sha": document["source_sha"], "purpose": document["purpose"],
            "state_identity": c.state_identity(state_raw), "rows_before": len(matrix["before"]),
            "rows_after": len(matrix["after"]), "absent_rows": len(matrix["absent"]),
            "readbacks_before": len(readbacks["before"]), "readbacks_after": len(readbacks["after"])}


def _document(version):
    return c.loads(unquote(version).encode()) if type(version) is str else version


def _pin(reader, config, role, asked):
    arn = managed_arn(config, role)
    policy = reader.call("iam", "get_policy", PolicyArn=arn)["Policy"]
    default = policy["DefaultVersionId"]
    version = reader.call("iam", "get_policy_version", PolicyArn=arn, VersionId=default)["PolicyVersion"]
    c.require(version["VersionId"] == default and version["IsDefaultVersion"] is True, "default version readback")
    document = _document(version["Document"])
    times = chain.expiry_chain(asked["observed_at"])
    pin = {"account_id": config["account_id"], "role_arn": config["roles"][role], "policy_arn": arn,
           "root_source_sha": asked["root_source_sha"], "default_version_id": default, "document": document,
           "document_sha256": c.sha(c.canonical(document, limit=65536)), "observed_at": times["pin_observed_at"],
           "expires_at": times["pin_expires_at"], "frozen_until": times["frozen_until"],
           "owner_producer": asked["owner_producer"]}
    session_owner._metadata(policy, pin)
    return pin


def _strings(value):
    if type(value) is str:
        return [value]
    children = value.values() if type(value) is dict else value if type(value) is list else []
    return [text for child in children for text in _strings(child)]


def _private_values(config):
    values = [config[name] for name in CONFIG_KEYS.split() if type(config[name]) is str]
    values += [text for text in _strings(config["shared_outputs"]) if len(text) >= 12]
    return [value for value in values + list(config["roles"].values()) if value]


def _sanitize(files, config, key_hex, pins):
    governance = config | {"report_hmac_key": key_hex, "session_policy_pins": pins}
    private = _private_values(config)
    for raw in files.values():
        c.public_safe(c.loads(raw, canonical=True), config)
        c.refuse_account_derived(raw, governance)
        text = raw.decode()
        c.require(not any(value in text for value in private), "configuration value in a public file")


def observe(reader, config, asked, key_hex):
    """Args: read-only reader, private config, public request, report key (hex).

    Returns: Observed(files, pins); pins only in local mode. Raises: ValueError, never partial files.
    """
    c.require(asked["purpose"] in drift_catalog.ENVELOPES, "purpose without envelope")
    key = c.report_key({"report_hmac_key": key_hex})
    plan_raw = rehearsal_plan.plan(config, phase_inputs.release_inputs(reader, config, asked), reader.session)
    plan, rehearsal_sha = c.loads(plan_raw, state=True), c.sha(plan_raw)
    state_raw = reader.read(config["state_bucket"], STATE_KEY)
    document = drift_handoff.generate(plan, c.loads(state_raw, state=True), asked["source_sha"], asked["purpose"])
    raw = drift_handoff.serialize(document)
    _live_before(reader, plan, document)
    pins = {role: _pin(reader, config, role, asked) for role in ROLES}
    observations = {"observed_at": asked["observed_at"], "drift-baseline": _drift_baseline(document, raw, rehearsal_sha, state_raw),
                    "session_facts": {role: session_owner._facts(pin, key) for role, pin in pins.items()}}
    observations |= phase_inputs.measure(reader, config, asked, key)
    files = {"drift-handoff.json": raw, "observations.json": c.canonical(observations)}
    _sanitize(files, config, key_hex, pins)
    return Observed(files, pins if asked.get("mode") == "local" else None)


def _session(asked):
    if asked.get("mode") == "local":
        import boto3
        return boto3.Session(region_name=aws_reader.REGION)
    return aws_reader.web_identity_session(os.environ["OBSERVER_ROLE_ARN"])


def _config():
    config = c.loads(os.environ["OBSERVER_CONFIG"].encode())
    c.closed(config, CONFIG_KEYS)
    c.closed(config["roles"], " ".join(ROLES))
    c.require(type(config["shared_outputs"]) is dict and bool(config["shared_outputs"]), "observer shared_outputs")
    return config


def _run(args):
    config = _config()
    asked = c.loads(Path(args.request).read_bytes())
    session = _session(asked)
    result = observe(aws_reader.Reader(session, config["account_id"]), config, asked, os.environ["REPORT_HMAC_KEY"])
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, raw in result.files.items():
        (out / name).write_bytes(raw)
    if result.pins is not None and args.private_out:
        private = Path(args.private_out)
        private.write_bytes(c.canonical(result.pins))
        private.chmod(0o600)


def main(argv=None):
    parser = argparse.ArgumentParser(description="CnesData delivery observer")
    parser.add_argument("--request", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--private-out")
    args = parser.parse_args(argv)
    try:
        _run(args)
    except Exception as error:
        sys.stderr.write(f"refused reason={type(error).__name__}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
