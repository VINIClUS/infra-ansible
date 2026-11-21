"""Protected application admission, own-role bootstrap, keeper and finite IPC.

Operational execution composes the original keeper and stops at the static stage
with the lease held (R18); finish and the terminal publication are not connected.
Defaults grant no access.
"""
import re
import time

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.coordination_lease import Lease, Watchdog


def authenticate_adapter_closure(product, source, manifest, manifest_sha256):
    """Authenticate before loading the fixed adapter; never import at preflight.

    The protected manifest covers the entire tracked product tree, so an omitted
    transitive helper/configuration cannot silently become an import dependency.
    Ignored and untracked files are rejected too: they may shadow source imports.
    This is source authentication, not a domain-operation success receipt.
    """
    import re
    import subprocess
    from pathlib import Path
    product = Path(product)
    c.digest(source, 40)
    c.closed(manifest, "version source_sha files")
    c.require(manifest["version"] == 1 and manifest["source_sha"] == source
              and c.sha(c.canonical(manifest, limit=4 * 1024**2)) == c.digest(manifest_sha256), "original adapter source manifest")
    expected = manifest["files"]
    c.require(type(expected) is dict and 1 <= len(expected) <= 16384
              and "scripts/promotion/promote_api.py" in expected, "fixed adapter closure inventory")
    c.require(product.is_dir() and not product.is_symlink(), "adapter real checkout")
    def git(*args):
        return subprocess.run(["git", *args], cwd=product, capture_output=True, check=True, timeout=10).stdout
    c.require(git("rev-parse", "HEAD").decode().strip() == source, "adapter immutable checkout")
    c.require(not git("status", "--porcelain", "--ignored", "--untracked-files=all"), "dirty or shadowed adapter closure")
    tree = git("ls-tree", "-r", "-z", source)
    c.require(tree.endswith(b"\0") and len(tree) <= 4 * 1024**2, "bounded adapter tree")
    result, aggregate = {}, 0
    for entry in tree[:-1].split(b"\0"):
        metadata, encoded_name = entry.split(b"\t", 1)
        mode, kind, _ = metadata.split(b" ")
        name = encoded_name.decode("utf-8")
        c.require(mode in {b"100644", b"100755"} and kind == b"blob"
                  and re.fullmatch(r"[A-Za-z0-9_.@/-]+", name) and ".." not in name.split("/")
                  and name in expected, "adapter source mode/path/inventory")
        path = product / name
        c.require(path.is_file() and not path.is_symlink() and product.resolve() in path.resolve().parents
                  and path.stat().st_size <= 8 * 1024**2, "adapter real bounded source file")
        raw = path.read_bytes()
        aggregate += len(raw)
        c.require(aggregate <= 128 * 1024**2 and raw == git("show", source + ":" + name)
                  and c.sha(raw) == c.digest(expected[name]), "adapter original source blob")
        result[name] = raw
    c.require(set(result) == set(expected), "complete adapter source closure")
    return result


# Amendment 2026-11-13 item 8: the closed registry of terminal validator types. The
# accepted-open eight are the amendment list; decision/restoration are the failure
# proofs already required by the closed _terminal_inputs branches.
TERMINAL_VALIDATOR_FACTS = {
    "unit": "accepted", "recovery": "accepted", "audit": "accepted", "host": "accepted", "static": "accepted",
    "routing": "fence routes_match", "membership": "resolved",
    "quiescence": "quiescent state_clean pending unknown observed_at",
    "decision": "", "restoration": "unit recovery audit api static first_static_absent",
}


def _terminal_inputs(assessment, window, inputs):
    c.require(type(inputs) is dict, "original terminal inputs")
    for digest in inputs.values():
        c.digest(digest)
    c.require(set(inputs) == _terminal_required(assessment["kind"], window), "complete original terminal proofs")


def _terminal_required(kind, window):
    if kind == "accepted-open":
        c.require(window["stage"] == "final" and window["decision"] is None, "accepted terminal phase")
        required = {"unit", "recovery", "audit", "host", "static", "routing", "membership", "quiescence"}
    elif kind == "failed-closed-quiescent":
        c.require(window["stage"] == "recovery" and window["decision"] is not None, "original recovery terminal decision")
        required = {"decision", "restoration", "routing", "membership", "quiescence"}
    else:
        c.require(kind == "failed-prepare-quiescent" and window["close"] is None
                  and window["stage"] == "application-prepare" and window["decision"] is None,
                  "closed terminal kind/phase")
        required = {"restoration", "routing", "quiescence"}
    return required


# Amendment 6886977054 decision 6: pure in-process terminal validators over keeper journal
# observations or bytes a caller authenticated, never caller JSON. `source` is a closed role ->
# sha256 map; a journal role selects observation bytes of its own kind, an artifact role only the
# factory's authenticated bytes, and the result commits to the map. TERMINAL_VALIDATORS registers them.
TERMINAL_SOURCE_ROLES = {"routing": "routing", "static": "publication closed-ready", "membership": "close-drain terminal",
                         "quiescence": "terminal", "host": "host-handoff closed-ready", "decision": "recovery-decision"}
TERMINAL_ARTIFACT_ROLES = frozenset({"host-handoff", "recovery-decision"})
# SYNTHETIC shapes: the product has no reopen/terminal-readback handler yet (R3).
ROUTING_FIELDS = "version kind fence routes_match"
TERMINAL_READBACK_FIELDS = "version kind members quiescent state_clean pending unknown observed_at"
# host_gate.validate_closed_ready: member identity (exact types of _closed_members), frozen member
# shape, resolved set, closed-ready.
MEMBER_IDENTITY_TYPES = {"dispatch_id": (str,), "request_sha256": (str,), "generation": (int,), "initial_state": (str,),
                         "execution_ref": (str, type(None)), "resolution": (str,)}
MEMBER_IDENTITY = " ".join(MEMBER_IDENTITY_TYPES)
FROZEN_MEMBER_FIELDS = MEMBER_IDENTITY + " proof_sha256 observed_at send_disabled_at"
MEMBER_RESOLVED = frozenset({"TERMINAL", "ABSENT_PROVEN", "CANCEL_BEFORE_SEND"})
CLOSED_READY_FIELDS = ("version kind common close_drain_sha256 phase_b_sha256 fence permit members proofs observed_at "
                       "exclusion stage decision")
# CnesData 9cdd452f scripts/promotion/_api_static_records.py PUBLICATION_SCHEMA/PUBLICATION_FIELDS;
# field types of publish_dashboard.PublicationReceipt.
PUBLICATION_SCHEMA = "cnesdata.static-publication/v1"
PUBLICATION_FIELDS = "schema plan_sha256 closed_ready_sha256 uploaded already_published invalidation_id"
# host_gate.py public handoff (version 1) and validate_recovery_decision.
HOST_HANDOFF_FIELDS = ("version kind caller producer_sha closed_ready_sha256 original_request_sha256 status response_sha256 "
                       "proof_sha256 receipt_sha256 witness_sha256 operation_id binding_sha256 generation recovery_decision "
                       "recovery_proof_sha256")
HOST_HANDOFF_STATUS = frozenset({"accepted", "rolled_back", "recovery_required"})
CLOSED_READY_COMMON = ("repository release_id source_sha candidate_sha256 canary_id activation_sha256 promotion_id "
                       "promotion_generation caller")
RECOVERY_DECISION_FIELDS = ("version operation_id binding_sha256 generation choice_at choice_monotonic_ms clock_boot_id "
                            "fixed_deadline recovery_deadline allocated_seconds convergence_budget_seconds "
                            "finalization_budget_seconds uncertainty_budget_seconds checkpoint_sha256")


def _terminal_sources(kind, source, observations, authenticated=None):
    c.closed(source, TERMINAL_SOURCE_ROLES[kind])
    c.require(type(observations) is dict, "terminal journal observations")
    found = {}
    for role in TERMINAL_SOURCE_ROLES[kind].split():
        digest = c.digest(source[role])
        raw = (authenticated or {}).get(role) if role in TERMINAL_ARTIFACT_ROLES else observations.get(digest)
        c.require(type(raw) is bytes and c.sha(raw) == digest, f"terminal source role={role}")
        found[role] = c.loads(raw, canonical=True, limit=1024**2)
    return found


def _versioned(value, kind, fields):
    c.closed(value, fields)
    c.require(type(value["version"]) is int and value["version"] == 1 and value["kind"] == kind,
              f"terminal source kind={kind}")
    return value


def _member(member, fields):
    c.closed(member, fields)
    c.require(all(type(member[key]) in kinds for key, kinds in MEMBER_IDENTITY_TYPES.items()), "terminal member identity types")


def routing_terminal_validator(source, *, owner, window, observations):
    """Routing facts from the `routing` journal observation (reopen)."""
    value = _versioned(_terminal_sources("routing", source, observations)["routing"], "routing", ROUTING_FIELDS)
    c.require(value["fence"] in {"OPEN", "CLOSED"} and type(value["routes_match"]) is bool, "terminal routing facts")
    return {"sha256": c.sha(c.canonical(source)), "facts": {"fence": value["fence"], "routes_match": value["routes_match"]}}


def static_terminal_validator(source, *, owner, window, observations):
    """Static acceptance: the `publication` observation bound to the closed-ready observation digest."""
    found = _terminal_sources("static", source, observations)
    publication = c.closed(found["publication"], PUBLICATION_FIELDS)
    _versioned(found["closed-ready"], "closed-ready", CLOSED_READY_FIELDS)
    c.digest(publication["plan_sha256"])
    uploaded, already = publication["uploaded"], publication["already_published"]
    c.require(type(uploaded) is list and all(type(item) is list and len(item) == 2
                                             and all(type(part) is str for part in item) for item in uploaded)
              and type(already) is list and all(type(key) is str for key in already)
              and type(publication["invalidation_id"]) in (str, type(None)), "terminal static publication types")
    c.require(publication["schema"] == PUBLICATION_SCHEMA and publication["closed_ready_sha256"] == source["closed-ready"],
              "terminal static publication binding")
    return {"sha256": c.sha(c.canonical(source)), "facts": {"accepted": True}}


def membership_terminal_validator(source, *, owner, window, observations):
    """Membership resolution: frozen close-drain members against the terminal-readback members."""
    found = _terminal_sources("membership", source, observations)
    close = _versioned(found["close-drain"], "close-drain", lc.CLOSE_DRAIN_FIELDS)
    readback = _versioned(found["terminal"], "terminal", TERMINAL_READBACK_FIELDS)
    frozen, final = close["members"], readback["members"]
    c.require(type(frozen) is list and type(final) is list
              and close["frozen_membership_sha256"] == c.sha(c.canonical(frozen)), "terminal frozen membership")
    for member in frozen:
        _member(member, FROZEN_MEMBER_FIELDS)
    for member in final:
        _member(member, MEMBER_IDENTITY)

    def identity(member):
        return [member[key] for key in MEMBER_IDENTITY.split()]
    resolved = ([identity(member) for member in frozen] == [identity(member) for member in final]
                and all(member["resolution"] in MEMBER_RESOLVED for member in final))
    return {"sha256": c.sha(c.canonical(source)), "facts": {"resolved": resolved}}


def quiescence_terminal_validator(uncertainty):
    """Factory over the keeper's uncertainty(); held SDK uncertainty is reported as unknown, never dropped."""
    c.require(callable(uncertainty), "keeper uncertainty source")

    def validator(source, *, owner, window, observations):
        found = _terminal_sources("quiescence", source, observations)
        value = _versioned(found["terminal"], "terminal", TERMINAL_READBACK_FIELDS)
        c.require(type(value["quiescent"]) is bool and type(value["state_clean"]) is bool
                  and type(value["pending"]) is list and type(value["unknown"]) is list, "terminal quiescence facts")
        held = uncertainty()
        c.require(type(held) is list, "keeper uncertainty")
        return {"sha256": c.sha(c.canonical(source)), "facts": {
            "quiescent": value["quiescent"], "state_clean": value["state_clean"], "pending": value["pending"],
            "unknown": value["unknown"] + held, "observed_at": int(c.instant(value["observed_at"]))}}
    return validator


def host_terminal_validator(handoff_raw):
    """Factory over host-handoff bytes a caller authenticated (artifact cnesdata-host-handoff-<run>-<attempt>)."""
    c.require(type(handoff_raw) is bytes, "authenticated host handoff bytes")

    def validator(source, *, owner, window, observations):
        found = _terminal_sources("host", source, observations, {"host-handoff": handoff_raw})
        handoff = _versioned(found["host-handoff"], "host-handoff", HOST_HANDOFF_FIELDS)
        ready = _versioned(found["closed-ready"], "closed-ready", CLOSED_READY_FIELDS)
        common = c.closed(ready["common"], CLOSED_READY_COMMON)
        c.require(handoff["status"] in HOST_HANDOFF_STATUS and handoff["closed_ready_sha256"] == source["closed-ready"]
                  and handoff["caller"] == common["caller"], "terminal host handoff binding")
        return {"sha256": c.sha(c.canonical(source)), "facts": {"accepted": handoff["status"] == "accepted"}}
    return validator


def decision_terminal_validator(decision_raw):
    """Factory over the authenticated recovery-decision input; it binds the lease decision and adds no fact."""
    c.require(type(decision_raw) is bytes, "authenticated recovery decision bytes")

    def validator(source, *, owner, window, observations):
        found = _terminal_sources("decision", source, observations, {"recovery-decision": decision_raw})
        value = c.closed(found["recovery-decision"], RECOVERY_DECISION_FIELDS)
        decision = window["decision"]
        c.require(type(value["version"]) is int and value["version"] == 1 and decision is not None
                  and decision["choice_at"] == int(c.instant(value["choice_at"]))
                  and decision["deadline"] == int(c.instant(value["recovery_deadline"]))
                  and window["fixed_deadline"] == int(c.instant(value["fixed_deadline"])), "terminal recovery decision binding")
        return {"sha256": c.sha(c.canonical(source)), "facts": {}}
    return validator


def _verify_cas_chain(evidence, released):
    """Order by ETags, not timestamps: several writes may share one UTC second."""
    checkpoints, renewals = evidence["checkpoints"], evidence["renewals"]
    c.require(type(checkpoints) is list and 1 <= len(checkpoints) <= 256
              and type(renewals) is list and len(renewals) <= 256, "bounded original CAS journal")
    sequence = released["lifecycle"]["sequence"]
    c.integer(sequence, 0, 255)
    c.require([x["sequence"] for x in checkpoints] == list(range(sequence + 1)), "complete checkpoint sequence")
    c.require(checkpoints[-1]["lifecycle_sha256"] == c.sha(c.canonical(released["lifecycle"])), "final CAS lifecycle binding")
    events = [evidence["acquire"], *checkpoints, *renewals, evidence["release"]]
    by_previous, etags = {}, set()
    for event in events:
        extra = " sequence lifecycle_sha256" if "sequence" in event else ""
        c.closed(event, "requested_at responded_at previous_etag_sha256 etag_sha256 expires_at request_id_sha256" + extra)
        for field in ("etag_sha256", "request_id_sha256"):
            c.digest(event[field])
        c.digest(event["previous_etag_sha256"])  # Lifecycle always follows a released owner.
        if extra:
            c.digest(event["lifecycle_sha256"])
        sent, received, expires = (c.instant(event[x]) for x in ("requested_at", "responded_at", "expires_at"))
        c.require(sent <= received <= sent + 20 and received < expires, "CAS original IO interval")
        c.require(event["previous_etag_sha256"] not in by_previous and event["etag_sha256"] not in etags,
                  "CAS journal fork/duplicate")
        by_previous[event["previous_etag_sha256"]] = event
        etags.add(event["etag_sha256"])
    current, previous_response, ordered_checkpoints = evidence["acquire"], 0, []
    for position in range(len(events)):
        c.require(current is not None and c.instant(current["requested_at"]) >= previous_response,
                  "CAS journal gap/time reversal")
        if "sequence" in current:
            ordered_checkpoints.append(current["sequence"])
        previous_response = c.instant(current["responded_at"])
        if position == len(events) - 1:
            c.require(current == evidence["release"], "CAS release must be last")
        else:
            c.require(current != evidence["release"], "CAS writes after release")
        current = by_previous.pop(current["etag_sha256"], None)
    c.require(ordered_checkpoints == list(range(sequence + 1)), "CAS checkpoint order")
    c.require(len(by_previous) == 1 and current is None
              and c.instant(evidence["release"]["expires_at"]) == released["expires_at"], "CAS released record expiry")
    c.require(evidence["acquire"]["requested_at"] >= released["acquired_at"], "CAS original acquisition")


def verify_terminal_bundle(files, released):
    """Validate private originals; publication/run provenance is checked separately."""
    c.require(set(files) == {"terminal.json", "checkpoint.json", "lease.json"}, "exact terminal package")
    c.require(released["status"] == "released", "terminal released coordinator")
    terminal, checkpoint, evidence = (c.loads(files[name], canonical=True, limit=262144)
                                      for name in ("terminal.json", "checkpoint.json", "lease.json"))
    c.closed(terminal, "version owner checkpoint_sha256 promotion_status coordination_status assessment completed_at deadline")
    c.closed(checkpoint, "version owner state state_object previous_checkpoint_sha256 assessment_sha256 inputs window phase_a_originals")
    c.closed(evidence, "protocol owner_sha256 " + " ".join(lc.OWNER_FIELDS)
             + " lifecycle_version acquire renewals release watchdog_until_release checkpoint_sha256 checkpoints "
             + " ".join(lc.application_identity(evidence)))
    owner = lc.owner_binding(released)
    c.require(type(checkpoint["version"]) is int and checkpoint["version"] == 2
              and terminal["version"] == evidence["lifecycle_version"] == 1
              and terminal["owner"] == checkpoint["owner"] == owner
              and {key: evidence[key] for key in owner} == owner, "terminal original owner/generation")
    lc.phase_a_originals(checkpoint["phase_a_originals"])
    digest = c.sha(files["checkpoint.json"])
    c.require(terminal["checkpoint_sha256"] == evidence["checkpoint_sha256"] == released["checkpoint_sha256"] == digest,
              "terminal original checkpoint bytes")
    window = checkpoint["window"]
    final_window = window | {"sequence": window["sequence"] + 1, "checkpoint_sha256": digest}
    lc.checkpoint_transition(window, final_window)
    c.require(released["lifecycle"] == final_window and checkpoint["previous_checkpoint_sha256"] == window["checkpoint_sha256"],
              "terminal original window")
    c.require(checkpoint["assessment_sha256"] == c.sha(c.canonical(terminal["assessment"])), "terminal original assessment")
    _terminal_inputs(terminal["assessment"], window, checkpoint["inputs"])
    deadline = lc.terminal_deadline(window)
    c.require(terminal["deadline"] == deadline, "terminal original deadline")
    status = lc.terminal_result(terminal["assessment"], now=terminal["completed_at"], deadline=deadline)
    c.require(terminal["promotion_status"] == status and terminal["coordination_status"] == "quiescent-released"
              and evidence["protocol"] == "s3-cas-v1"
              and evidence["watchdog_until_release"] == {"quiescence_sha256": checkpoint["inputs"]["quiescence"]},
              "terminal original result/quiescence")
    _verify_cas_chain(evidence, released)
    c.require(c.instant(evidence["release"]["responded_at"]) <= terminal["completed_at"], "terminal completion precedes release")
    return {"terminal": terminal, "checkpoint": checkpoint, "evidence": evidence}


class ReleasedPublicationGuard(Watchdog):
    """Bounded publication after release, with no renewal or product mutation."""
    def __init__(self, lease, record, etag, *, deadline, credential_deadline,
                 clock=time.time, monotonic=time.monotonic):
        super().__init__(lease, fixed_deadline=monotonic() + deadline - clock(),
                         credential_deadline=monotonic() + credential_deadline - clock(), monotonic=monotonic)
        c.require(record["status"] == "released" and etag == lease.etag, "original released publisher")
        self.record, self.etag, self.clock = record, etag, clock
        self.limit, self.credential_limit = deadline, credential_deadline
        self.finalizing = True
        self.finalization_deadline = self.fixed_deadline

    def check(self, operation_seconds=0):
        c.require(not self.cancelled and self.clock() + 20 + operation_seconds + 17 < self.limit
                  and self.clock() + 20 + operation_seconds + 120 < self.credential_limit,
                  "released publication IO capacity")
        record, etag = self.lease.store.get()
        c.require(record == self.record and etag == self.etag, "released publication ownership changed")
        c.require(self.clock() + operation_seconds + 17 < self.limit, "released publication deadline")

    def run(self, command, *, cwd, env, output, timeout=20, mutating=False):
        c.require(not mutating, "released publisher cannot mutate product")
        self.check(timeout)
        return super().run(command, cwd=cwd, env=env, output=output, timeout=timeout, mutating=False)


def publish_terminal(aws, api, governance, files, guard, temp):
    """Publish only original keeper bytes; an incomplete upload is no receipt."""
    from tools.cnesdata_delivery import lifecycle_runtime, runtime
    result = verify_terminal_bundle(files, guard.record)
    owner = result["terminal"]["owner"]
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"]}
    request = {"source_sha": owner["source_sha"], "step": "terminal"}
    prefix = lifecycle_runtime.namespace(governance, request, run)
    entries = []
    for name, raw in sorted(files.items()):
        guard.check(20)
        aws.put(governance["evidence_bucket"], prefix + name, raw)
        guard.check(20)
        observed, _ = aws.get(governance["evidence_bucket"], prefix + name, maximum=len(raw))
        c.require(observed == raw, "terminal private publication readback")
        entries.append({"name": name, "sha256": c.sha(raw), "size": len(raw)})
    index = {"version": 1, "source_sha": owner["source_sha"], "run_id": owner["run_id"],
             "run_attempt": owner["run_attempt"], "step": "terminal", "owner_sha256": owner["owner_sha256"],
             "generation": owner["generation"], "files": entries, **lc.application_identity(owner)}
    raw_index = c.canonical(index)
    c.public_safe(index, governance)
    directory = temp / "terminal-public"
    directory.mkdir()
    (directory / "index.json").write_bytes(raw_index)
    receipt = runtime._upload(directory, "lifecycle-terminal", guard, temp)
    guard.check(20)
    runtime._verify_current_artifact(api, receipt, {"index.json": raw_index}, run["id"])
    guard.check()
    return receipt


def published_terminal(api, governance, previous):
    """Public original identity, authenticated before historical S3 credentials."""
    from tools.cnesdata_delivery.provenance import lifecycle_artifact
    owner = lc.owner_binding(previous)
    run_id, attempt = owner["run_id"], owner["run_attempt"]
    prefix = f"repos/{c.REPOSITORY}"
    run = api.read(f"{prefix}/actions/runs/{run_id}/attempts/{attempt}")
    c.require(run["status"] == "completed" and run["conclusion"] == "success"
              and run["head_branch"] == "main", "previous lifecycle run not terminal success; reviewed recovery required")
    pin = c.digest(governance["gate_shas"]["application"], 40)
    reusable = "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-application-gate.yml@"
    refs = [x for x in run.get("referenced_workflows", []) if x["path"].startswith(reusable)]
    c.require(len(refs) == 1 and refs[0]["path"] == reusable + pin and refs[0]["sha"] == pin, "previous application reusable")
    artifacts = api.read(f"{prefix}/actions/runs/{run_id}/artifacts?per_page=100")
    c.require(artifacts["total_count"] <= 100, "bounded lifecycle history")
    matches = [x for x in artifacts["artifacts"] if x["name"] == "lifecycle-terminal"]
    c.require(len(matches) == 1, "previous terminal missing/ambiguous")
    jobs = api.read(f"{prefix}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    c.require(jobs["total_count"] <= 100, "bounded lifecycle producer jobs")
    producers = [x for x in jobs["jobs"] if x["name"] == governance["lifecycle_terminal_job"]]
    c.require(len(producers) == 1, "previous terminal producer missing/ambiguous")
    reference = {"artifact_id": matches[0]["id"], "artifact_digest": matches[0]["digest"], "job_id": producers[0]["id"]}
    public = lifecycle_artifact(api, reference, time.time(), source=owner["source_sha"], run_id=run_id,
                                attempt=attempt, producer_name=governance["lifecycle_terminal_job"], artifact_name="lifecycle-terminal")
    c.require(set(public) == {"index.json"}, "terminal public receipt package")
    index = c.loads(public["index.json"], canonical=True)
    c.closed(index, "version source_sha run_id run_attempt step owner_sha256 generation files " + " ".join(lc.application_identity(index)))
    c.require(lc.application_identity(index) == lc.application_identity(owner)
              and index["version"] == 1 and index["step"] == "terminal"
              and all(index[k] == owner[k] for k in ("source_sha", "run_id", "run_attempt", "owner_sha256", "generation")),
              "terminal public original owner")
    c.require(type(index["files"]) is list and len(index["files"]) == 3
              and {x["name"] for x in index["files"]} == {"terminal.json", "checkpoint.json", "lease.json"},
              "terminal exact original file inventory")
    for entry in index["files"]:
        c.closed(entry, "name sha256 size")
        c.digest(entry["sha256"])
        c.integer(entry["size"], 1, 262144)
    c.public_safe(index, governance)
    return run, reference, public


def previous_terminal(aws, api, governance, previous):
    from tools.cnesdata_delivery import lifecycle_runtime
    run, reference, public = published_terminal(api, governance, previous)
    index, files = lifecycle_runtime.private_payload(aws, governance, {"source_sha": previous["source_sha"]}, run, public)
    result = verify_terminal_bundle(files, previous)
    c.require(result["terminal"]["promotion_status"] == "accepted", "failed terminal requires exact reviewed recovery acceptance")
    return result | {"index": index, "artifact_id": reference["artifact_id"], "artifact_digest": reference["artifact_digest"]}


def authenticated_previous(aws, api, governance, previous):
    """Keeper's protected historical validator; never reads product state."""
    from tools.cnesdata_delivery import lifecycle_runtime, runtime, session_policy
    reference = lifecycle_runtime.authenticate_predecessor(api, governance)
    c.require(previous["status"] == "released" and previous["repository"] == c.REPOSITORY
              and all(previous[k] == reference[k] for k in ("run_id", "run_attempt", "session_sha256", "checkpoint_sha256"))
              and c.sha(previous["owner"].encode()) == reference["owner_sha256"]
              and previous.get("generation") == reference["generation"], "original released predecessor selection")
    result = runtime.previous_success(aws, api, governance, previous, details=True)
    c.require(type(result) is dict and result["artifact_id"] == reference["artifact_id"]
              and result["artifact_digest"] == reference["artifact_digest"], "original predecessor publication")
    original_source = (result["terminal"]["owner"]["source_sha"] if reference["protocol"] == "lifecycle"
                       else result["envelope"]["plan"]["source_sha"])
    c.require(original_source == reference["source_sha"], "original predecessor source")
    entries = {x["name"]: x for x in reference["objects"]}
    originals = {}
    for key in session_policy.predecessor_keys(governance, governance["predecessor_read"]):
        entry = entries[key.rsplit("/", 1)[1]]
        raw, _ = aws.get(governance["evidence_bucket"], key, maximum=entry["size"])
        c.require(len(raw) == entry["size"] and c.sha(raw) == entry["sha256"], "original selected historical bytes")
        originals[entry["name"]] = raw
    if reference["protocol"] == "legacy-infra":
        carrier = lc.phase_a_carrier(reference, {name: originals[name] for name in ("envelope.json", "checkpoint.json", "drift.json")})
    else:
        carrier = result["checkpoint"]["phase_a_originals"]
        lc.phase_a_originals(carrier)
    return result | {"predecessor_reference": reference, "phase_a_originals": carrier,
                     "checkpoint_raw": originals["checkpoint.json"]}


class _TerminalStore:
    """Deadline guard around the same original store, never another writer."""
    def __init__(self, original, clock, deadline):
        self.original, self.clock, self.limit = original, clock, deadline

    def __getattr__(self, name):
        return getattr(self.original, name)

    def _before(self):
        c.require(self.clock() + 37 < self.limit, "terminal CAS IO deadline")

    def get(self):
        self._before()
        result = self.original.get()
        c.require(self.clock() < self.limit, "terminal read deadline")
        return result

    def put(self, value, etag):
        self._before()
        result = self.original.put(value, etag)
        c.require(self.clock() < self.limit, "terminal CAS response unknown after deadline")
        return result


_ADAPTER_CHILD = r'''
import base64, importlib.machinery, importlib.util, os, sys
sys.path.insert(0, sys.argv[2])
from tools.cnesdata_delivery import contract as c
product = sys.argv[1]
sys.path.insert(0, product)
class AuthorizedPackages:
    # Queue item 3c: closed roots by authorized path; parents are stubs, leaves load by file, nothing falls back.
    ROOTS = {"cnes_domain": "packages/cnes_domain/src/cnes_domain", "cnes_infra": "packages/cnes_infra/src/cnes_infra"}
    def find_spec(self, name, path=None, target=None):
        parts = name.split(".")
        if parts[0] not in self.ROOTS:
            return None
        base = os.path.join(product, self.ROOTS[parts[0]], *parts[1:])
        if os.path.isdir(base):
            spec = importlib.machinery.ModuleSpec(name, None, is_package=True)
            spec.submodule_search_locations = [base]
            return spec
        if os.path.isfile(base + ".py"):
            return importlib.util.spec_from_file_location(name, base + ".py")
        raise ModuleNotFoundError("adapter authorized path " + name, name=name)
sys.meta_path.insert(0, AuthorizedPackages())
def receive():
    raw = sys.stdin.buffer.readline(192 * 1024**2 + 1)
    return c.loads(raw, canonical=True, limit=192 * 1024**2)
def send(value):
    sys.stdout.buffer.write(c.canonical(value, limit=2 * 1024**2))
    sys.stdout.buffer.flush()
class Context:
    def exchange(self, value):
        send(value)
        return receive()
    def read(self, name):
        return base64.b64decode(self.exchange({"kind": "read", "name": name})["bytes"], validate=True)
    def guard(self):
        c.require(self.exchange({"kind": "guard"}) == {"guarded": True}, "original guard response")
    def evidence_snapshot(self):
        return self.exchange({"kind": "evidence-snapshot"})
    def observe(self, kind, raw):
        c.require(type(raw) is bytes, "original observation bytes")
        return self.exchange({"kind": "observe", "observation_kind": kind, "bytes": base64.b64encode(raw).decode()})["sha256"]
    def call(self, role, service, operation, parameters):
        reply = self.exchange({"kind": "call", "role": role, "service": service, "operation": operation, "parameters": parameters})
        if reply.get("kind") == "sdk-error":
            c.closed(reply, "kind code")
            c.require(reply["code"] == "ExecutionDoesNotExist", "closed shared SDK error")
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": reply["code"]}}, "DescribeExecution")
        c.closed(reply, "kind value")
        c.require(reply["kind"] == "sdk-result", "original shared SDK result")
        return reply["value"]
start = receive()
c.closed(start, "kind request")
c.require(start["kind"] == "start", "fixed adapter start")
request = start["request"]
spec = importlib.util.spec_from_file_location("scripts.promotion.promote_api", product + "/scripts/promotion/promote_api.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = module.execute_shared_operation(request["operation"], request, Context())
raw = result if type(result) is bytes else c.canonical(result, limit=128 * 1024)
send({"kind": "result", "bytes": base64.b64encode(raw).decode()})
'''


def _adapter_message(frame, journal):
    import base64
    value = c.loads(frame, canonical=True, limit=2 * 1024**2)
    kind = value.get("kind")
    if kind == "read":
        c.closed(value, "kind name")
        return {"bytes": base64.b64encode(journal.read(value["name"])).decode()}, None
    if kind == "guard":
        c.closed(value, "kind")
        journal.guard()
        return {"guarded": True}, None
    if kind == "evidence-snapshot":
        c.closed(value, "kind")
        return journal.evidence_snapshot(), None
    if kind == "call":
        c.closed(value, "kind role service operation parameters")
        c.require(type(getattr(journal, "_broker", None)) is ClosedReadyBroker, "adapter protected SDK admission absent")
        return journal._broker.call(**{key: value[key] for key in ("role", "service", "operation", "parameters")}), None
    if kind in {"observe", "result"}:
        c.closed(value, "kind bytes" + (" observation_kind" if kind == "observe" else ""))
        raw = base64.b64decode(value["bytes"], validate=True)
        if kind == "result":
            c.require(len(raw) <= 128 * 1024, "adapter result bound")
            return None, raw
        return {"sha256": journal.observe(value["observation_kind"], raw)}, None
    # No product call reaches STS/SDK until the concrete protected broker and
    # parameter validators are installed. A missing implementation never grants.
    raise ValueError("adapter SDK broker unavailable or unknown frame")


def invoke_adapter(*, product, source, manifest, manifest_sha256, journal, timeout):
    """Fixed authenticated child with bounded IPC and no inherited credentials.

    This isolates credentials and transport; it is not an OS sandbox or a
    domain acceptance. SDK operations remain closed until broker integration.
    """
    import os
    import signal
    import subprocess
    import sys
    import tempfile
    from pathlib import Path
    c.integer(timeout, 1, 900)
    c.require(journal._request["source_sha"] == source, "adapter original source request")
    authenticate_adapter_closure(product, source, manifest, manifest_sha256)
    journal._guard.check(timeout + 7)
    journal.guard()
    with tempfile.TemporaryDirectory(prefix="cnesdata-adapter-") as home:
        env = {"PATH": os.defpath, "HOME": home, "LANG": "C.UTF-8", "AWS_CONFIG_FILE": "/dev/null",
               "AWS_SHARED_CREDENTIALS_FILE": "/dev/null", "AWS_EC2_METADATA_DISABLED": "true"}
        child = subprocess.Popen([sys.executable, "-I", "-B", "-c", _ADAPTER_CHILD, str(Path(product).resolve()),
                                  str(Path(__file__).resolve().parents[2])], cwd=product, env=env,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            result = _adapter_exchange(child, journal, timeout)
            c.require(child.wait(timeout=2) == 0, "adapter child failed")
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise ValueError("adapter child group still active")
            authenticate_adapter_closure(product, source, manifest, manifest_sha256)
            return journal.validate_result(result)
        except BaseException:
            journal._failed = True
            raise
        finally:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if child.poll() is None:
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()


def _adapter_exchange(child, journal, timeout):
    import os
    import selectors
    outgoing = memoryview(c.canonical({"kind": "start", "request": journal._request}))
    incoming, result = b"", None
    deadline, next_guard = time.monotonic() + timeout, time.monotonic() + 5
    os.set_blocking(child.stdin.fileno(), False)
    os.set_blocking(child.stdout.fileno(), False)
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        selector.register(child.stdin, selectors.EVENT_WRITE)
        while True:
            now = time.monotonic()
            c.require(now < deadline, "adapter original process deadline")
            if now >= next_guard:
                journal.guard()
                next_guard = time.monotonic() + 5
            for key, event in selector.select(min(0.25, deadline - now)):
                if event & selectors.EVENT_WRITE:
                    written = os.write(key.fd, outgoing[:65536])
                    outgoing = outgoing[written:]
                    if not outgoing:
                        selector.unregister(child.stdin)
                else:
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(child.stdout)
                        continue
                    incoming += chunk
                    c.require(len(incoming) <= 2 * 1024**2, "adapter frame bound")
                    while b"\n" in incoming:
                        frame, incoming = incoming.split(b"\n", 1)
                        c.require(result is None and not outgoing, "adapter sequential original frames")
                        reply, completed = _adapter_message(frame + b"\n", journal)
                        if completed is not None:
                            result = completed
                        else:
                            outgoing = memoryview(c.canonical(reply, limit=192 * 1024**2))
                            selector.register(child.stdin, selectors.EVENT_WRITE)
            if child.poll() is not None and child.stdout not in [key.fileobj for key in selector.get_map().values()]:
                c.require(not incoming and not outgoing and result is not None, "adapter complete result frame")
                return result


def _sdk_private_fields(value):
    """Reject credential keys before private journal retention or child IPC."""
    if type(value) is dict:
        for key, item in value.items():
            normalized = key.lower().replace("_", "").replace("-", "")
            c.require(normalized not in {"credentials", "accesskeyid", "secretaccesskey", "sessiontoken", "accesstoken",
                                         "authorization", "password", "privatekey"}, "SDK credential/private field")
            _sdk_private_fields(item)
    elif type(value) is list:
        for item in value:
            _sdk_private_fields(item)


class _FenceSession:
    """Shared-only result of the finite STS boundary; never exposed over IPC.

    evidence is the operation client that assumed the fence role; it is the client of the SDK evidence.
    """
    def __init__(self, client, commitment, scope, deadline, request_binding, evidence):
        self.client, self.commitment = client, c.digest(commitment)
        self.scope = c.loads(c.canonical(scope), canonical=True)
        self.deadline, self.request_binding, self.evidence = deadline, request_binding, evidence


def _assume_fence_session(*, governance, role, scope, journal, prepared_sha256, credential_limit, operation_session, clock=time.time):
    """Exact native delegation after the caller authenticates prepared authority.

    This internal boundary is not package admission. The shared dispatcher must
    supply the original protected role/scope, never adapter frame parameters.
    """
    from tools.cnesdata_delivery.aws_boundary import AWS
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    from tools.cnesdata_delivery.session_policy import validate_response
    c.require(type(journal) is AdapterJournal and journal._request["operation"] in {"closed-ready", "close-drain"}
              and journal._identity["application_purpose"] == "promotion", "fence original promotion journal")
    request, stage = journal._request, journal._request["stage"]
    close = request["operation"] == "close-drain"
    if close:
        deadline = stage["preparation_deadline"]
        c.require(stage["stage"] == "application-prepare" and stage["close"] is None and stage["decision"] is None
                  and stage["deadline"] == deadline and stage["admitted_at"] <= clock() and clock() + 40 < deadline
                  and clock() + 900 <= credential_limit, "fence original preparation/credential window")
    else:
        deadline = stage["deadline"]
        c.require(stage["stage"] == "api" and stage["deadline"] == min(stage["fixed_deadline"], stage["admitted_at"] + 180)
                  and stage["fixed_deadline"] - stage["admitted_at"] >= 1440
                  and stage["admitted_at"] <= clock() and clock() + 40 < stage["deadline"]
                  and clock() + 900 <= credential_limit, "fence original API/credential window")
    c.closed(scope, "account control_table_arn machine_arn" + ("" if close else " members"))
    c.require(scope["account"] == governance["account_id"] and governance["role"] == "application"
              and role["role_arn"] == governance["application_delegations"]["fence_operator"]
              and role["role_name"] == "cnesdata-prod-promotion-fence-operator"
              and role["role_arn"] == "arn:aws:iam::" + scope["account"] + ":role/" + role["role_name"]
              and role["session_name"] == "promotion-fence-" + role["release_id"]
              and type(role["role_id"]) is str and bool(role["role_id"]), "fence exact protected role/session")
    probe_prefix = scope["machine_arn"].replace(":stateMachine:", ":execution:") + ":"
    validate = lc.validate_close_drain_call if close else lc.validate_closed_ready_call
    for pk, sk in (("ENV#prod#FENCE", "FENCE"), ("ENV#prod#SEMAPHORE", "UNIT")):
        validate(request=request, role="fence_operator", service="dynamodb", operation="get_item",
            parameters={"TableName": scope["control_table_arn"].rsplit("/", 1)[1], "Key": {"pk": {"S": pk}, "sk": {"S": sk}},
                        "ConsistentRead": True}, **scope)
    for member in [] if close else scope["members"]:
        lc.validate_closed_ready_call(request=request, role="fence_operator", service="stepfunctions", operation="describe_execution",
            parameters={"executionArn": probe_prefix + member["dispatch_id"], "includedData": "METADATA_ONLY"}, **scope)
    from tools.cnesdata_delivery.session_policy import fence_close_session_policy, fence_session_policy
    build = fence_close_session_policy if close else fence_session_policy
    policy = build(control_table_arn=scope["control_table_arn"], execution_prefix=probe_prefix, deadline=deadline)
    encoded = c.canonical(policy).decode().strip()
    c.require(len(encoded) <= 2048, "fence STS policy limit")
    context = {"aws:CurrentTime": c.utc(clock())}
    for key in ("ENV#prod#FENCE", "ENV#prod#SEMAPHORE"):
        c.require(effective_iam(role["policy"], [policy], "dynamodb:GetItem", scope["control_table_arn"],
                                context | {"dynamodb:LeadingKeys": [key]}), "fence original effective strong-read grant")
    for action, key in (("dynamodb:UpdateItem", "ENV#prod#FENCE"), ("dynamodb:ConditionCheckItem", "ENV#prod#SEMAPHORE")) if close else ():
        c.require(effective_iam(role["policy"], [policy], action, scope["control_table_arn"],
                                context | {"dynamodb:LeadingKeys": [key]}), "fence original effective close-write grant")
    c.require(effective_iam(role["policy"], [policy], "states:DescribeExecution", probe_prefix + "0" * 16, context),
              "fence original effective metadata-probe grant")
    journal._guard.check(40)
    journal.guard()
    operation = operation_session(request["operation"], role, stage)
    c.require(clock() + 40 < deadline and clock() + 900 <= credential_limit, "fence original window after operation session")
    response = operation.call("sts", "assume_role", RoleArn=role["role_arn"], RoleSessionName=role["session_name"],
                              DurationSeconds=900, Policy=encoded)
    credentials = validate_response(response)
    expiry = credentials["Expiration"]
    c.require(getattr(expiry, "tzinfo", None) is not None and clock() + 140 < expiry.timestamp()
              <= min(credential_limit, clock() + 900), "fence original STS expiration")
    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
        c.require(type(credentials[field]) is str and credentials[field] and "\n" not in credentials[field]
                  and "\r" not in credentials[field], "fence temporary credential shape")
    journal.guard()
    client = AWS(governance | {"role": "fence_operator", "roles": {"fence_operator": role["role_arn"]}}, credentials=credentials)
    expected_arn = role["role_arn"].replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + role["session_name"]
    expected_id = role["role_id"] + ":" + role["session_name"]
    c.require(client.identity["Account"] == scope["account"] and client.identity["Arn"] == expected_arn
              and client.identity["UserId"] == expected_id
              and response["AssumedRoleUser"] == {"Arn": expected_arn, "AssumedRoleId": expected_id},
              "fence exact native role ID/session/account")
    journal.guard()
    c.require(clock() + 20 < deadline, "fence STS completed in original API window")
    binding = c.sha(c.canonical(request))
    commitment = c.sha(c.canonical({"prepared_sha256": c.digest(prepared_sha256), "request_sha256": binding,
        "role_arn": role["role_arn"], "role_id": role["role_id"], "session_name": role["session_name"],
        "policy_sha256": c.sha(c.canonical(policy)), "expires_at": c.utc(expiry.timestamp()),
        "account": scope["account"], "arn": expected_arn, "user_id": expected_id}))
    return _FenceSession(client, commitment, scope, deadline, binding, operation)


class AdapterJournal:
    """Shared-side originals, never a product SDK client or domain acceptance.

    The isolated proxy exposes read/guard/observe and read-only ABI metadata.
    Call receipts and uncertainty belong to the shared broker, not the product.
    """
    def __init__(self, raw, *, operation, owner, window, inputs, activation_sha256, guard):
        self._request = lc.validate_adapter_request(raw, operation=operation, owner=owner, window=window,
            inputs=inputs, activation_sha256=activation_sha256)
        c.require(callable(getattr(guard, "check", None)), "adapter original guard required")
        self._guard, self._failed, self._inputs = guard, False, dict(inputs)
        self._identity = lc.application_identity(owner, required=True)
        self._observations, self._call_receipts, self._pending, self._unknown = [], [], [], []
        self._observation_bytes, self._observation_links = {}, []
        self._call_bytes, self._inflight = {}, None
        self._durable_count, self._durable_last, self._durable_active = 0, None, None

    def evidence_snapshot(self):
        """Read-only copy of existing ABI2 metadata; never refresh authority."""
        return {"call_receipts_sha256": c.sha(c.canonical(self._call_receipts)),
                "pending": self.pending, "unknown": self.unknown}

    def _next_durable(self):
        c.require(not self._failed and self._inflight is None and self._durable_active is None,
                  "original durable call must settle before another intent")
        c.integer(self._durable_count, 0, 8191)
        c.require(self._durable_count == len(self._call_receipts), "in-memory receipt cannot advance durable ordinal")
        c.require((self._durable_count == 0) == (self._durable_last is None), "original durable receipt ancestry")
        if self._durable_last is not None:
            c.digest(self._durable_last)
        return self._durable_count, self._durable_last

    @property
    def call_receipts(self):
        return c.loads(c.canonical(self._call_receipts), canonical=True)

    @property
    def call_bytes(self):
        return dict(self._call_bytes)

    @property
    def pending(self):
        return c.loads(c.canonical(self._pending), canonical=True)

    @property
    def unknown(self):
        return c.loads(c.canonical(self._unknown), canonical=True)

    def begin_sdk_call(self, raw, *, role_session_sha256):
        """Shared-only intent journal, not SDK admission or a prepared-role proof.

        No IPC frame exposes these methods. A concrete broker must authenticate
        the role and validate parameters before recording an intent or doing IO.
        """
        request = c.loads(raw, canonical=True, limit=128 * 1024)
        c.closed(request, "role service operation parameters")
        c.require(request["role"] == "fence_operator"
                  and (request["service"], request["operation"]) in lc.FENCE_SDK_OPERATIONS.get(self._request["operation"], ()),
                  "closed SDK journal operation")
        c.require(type(request["parameters"]) is dict and self._inflight is None, "single original SDK request")
        if self._durable_active is not None:
            active = self._durable_active
            c.require(active._reserved and active._state == "created" and active._sequence == len(self._call_receipts)
                      and active._native_sha256 == c.sha(raw) and active._session_sha256 == role_session_sha256,
                      "original reserved durable SDK call")
        c._secrets(request)
        _sdk_private_fields(request)
        c.digest(role_session_sha256)
        self.guard()
        binding = c.sha(c.canonical({key: self._request[key] for key in ("owner", "checkpoint_sha256", "activation_sha256", "stage")}))
        intent = {"sequence": len(self._call_receipts), "request_sha256": c.sha(raw), "role_session_sha256": role_session_sha256,
                  "guard_before_sha256": binding, "started_monotonic_ns": time.monotonic_ns()}
        ticket = c.sha(c.canonical(intent))
        self._call_bytes[c.sha(raw)] = raw
        self._call_bytes[ticket] = c.canonical(intent)
        self._inflight = (ticket, intent)
        self._pending.append({"kind": "sdk-call", "reference_sha256": ticket})
        return ticket

    def complete_sdk_call(self, ticket, raw, *, request_id, server_date):
        """Preserve a sanitized native response only after the original guard."""
        from email.utils import parsedate_to_datetime
        c.require(self._inflight is not None and ticket == self._inflight[0], "original SDK call ticket")
        try:
            c.require(not self._failed, "adapter context failed; late response remains unknown")
            ended = time.monotonic_ns()
            intent = self._inflight[1]
            response = c.loads(raw, canonical=True, limit=1024**2)
            c.require(type(response) is dict and type(request_id) is str and 1 <= len(request_id) <= 256
                      and type(server_date) is str, "original SDK response metadata")
            c._secrets(response)
            _sdk_private_fields(response)
            request = c.loads(self._call_bytes[intent["request_sha256"]], canonical=True)
            allowed = ({"Item"} if request["operation"] == "get_item" else set() if request["service"] == "dynamodb" else
                       {"executionArn", "stateMachineArn", "name", "status", "startDate", "stopDate"})
            absence = request["service"] == "stepfunctions" and response == {"Error": {"Code": "ExecutionDoesNotExist"}}
            c.require(absence or set(response) <= allowed, "SDK response already sanitized before journal")
            server = parsedate_to_datetime(server_date)
            c.require(server.tzinfo is not None and 0 <= ended - intent["started_monotonic_ns"] <= 20 * 10**9
                      and abs(time.time() - server.timestamp()) <= 30, "SDK clock/latency uncertainty")
            self.guard()
            receipt = intent | {"response_sha256": c.sha(raw), "request_id": request_id, "server_date": server_date,
                                "ended_monotonic_ns": ended, "guard_after_sha256": intent["guard_before_sha256"]}
            self._call_bytes[c.sha(raw)] = raw
            self._call_receipts.append(receipt)
            self._pending.remove({"kind": "sdk-call", "reference_sha256": ticket})
            self._inflight = None
            return c.loads(c.canonical(receipt), canonical=True)
        except BaseException:
            self.fail_sdk_call(ticket)
            raise

    def _settled_calls(self):
        """This journal's own guarded receipts as call/response pairs; the close-drain write history."""
        return [{"call": c.loads(self._call_bytes[receipt["request_sha256"]], canonical=True),
                 "response": c.loads(self._call_bytes[receipt["response_sha256"]], canonical=True)}
                for receipt in self._call_receipts]

    def fail_sdk_call(self, ticket):
        """Unresolved IO poisons this context; no exception/credential is stored."""
        c.require(self._inflight is not None and ticket == self._inflight[0], "original SDK call ticket")
        reference = {"kind": "sdk-call", "reference_sha256": ticket}
        if reference not in self._unknown:
            self._unknown.append(reference)
        self._failed = True

    @property
    def observations(self):
        return c.loads(c.canonical(self._observations), canonical=True)

    @property
    def observation_bytes(self):
        return dict(self._observation_bytes)

    @property
    def observation_links(self):
        return c.loads(c.canonical(self._observation_links), canonical=True)

    def guard(self):
        c.require(not self._failed, "adapter context failed; original recovery required")
        try:
            self._guard.check()
        except BaseException:
            self._failed = True
            raise

    def read(self, name):
        c.require(type(name) is str and name in self._inputs, "adapter named original input")
        self.guard()
        raw = self._inputs[name]
        self.guard()
        return raw

    def observe(self, kind, raw):
        c.require(self._durable_active is None, "durable SDK receipt unresolved")
        if getattr(self, "_broker", None) is not None:
            c.require(self._durable_count == len(self._call_receipts), "all observations require durable SDK receipts")
        c.require(kind == lc.ADAPTER_OBSERVATIONS[self._request["operation"]], "adapter operation observation")
        value = c.loads(raw, canonical=True, limit=1024**2)
        c.require(type(value) is dict and value, "adapter observation requires original domain object")
        c._secrets(value)
        self.guard()
        digest = c.sha(raw)
        self.guard()
        self._observation_bytes[digest] = raw
        self._observations.append({"kind": kind, "sha256": digest, "size": len(raw)})
        self._observation_links.append({"observation_sha256": digest, "call_receipts_sha256": c.sha(c.canonical(self._call_receipts))})
        return digest

    def validate_result(self, raw):
        c.require(self._durable_active is None, "durable SDK receipt unresolved")
        if getattr(self, "_broker", None) is not None:
            c.require(self._durable_count == len(self._call_receipts), "all results require durable SDK receipts")
        if self._inflight is not None:
            self.fail_sdk_call(self._inflight[0])
            raise ValueError("native SDK call unresolved; no adapter completion")
        self.guard()
        lc.validate_adapter_result(raw, request=self._request, observations=self._observations,
            call_receipts=self._call_receipts, pending=self._pending, unknown=self._unknown)
        self.guard()
        return raw  # Preserve adapter bytes; a domain validator must still accept them.


class ClosedReadyEvidence:
    """Immutable own-step evidence, not a role capability or SDK dispatcher.

    A stable key fences retries across processes. Existing intent without a
    complete receipt is unknown, including a crash before the native read.
    Settled data are historical evidence, never a fresh probe or replay permit.
    Only the original broker can turn a newly created reservation into native IO.
    """
    SUFFIXES = ("intent", "response", "receipt")

    def __init__(self, aws, governance, journal, native_raw, *, prepared_sha256, role_session_sha256, scope):
        from tools.cnesdata_delivery.lifecycle_runtime import closed_ready_evidence_keys
        c.require(type(journal) is AdapterJournal and governance["role"] == "application", "shared closed-ready journal")
        operation = journal._request["operation"]
        c.closed(scope, "account control_table_arn machine_arn" + (" members" if operation == "closed-ready" else ""))
        c.require(scope["account"] == governance["account_id"], "original journal account")
        native = c.loads(native_raw, canonical=True, limit=128 * 1024)
        c.closed(native, "role service operation parameters")
        lc.validate_fence_call(request=journal._request, history=journal._settled_calls(), **native, **scope)
        _sdk_private_fields(native)
        request = journal._request
        sequence, previous = journal._next_durable()
        intent = {"schema_version": 2, "operation": operation, "owner": request["owner"],
                  "sequence": sequence, "previous_receipt_sha256": previous,
                  "caller": journal._identity, "adapter_request_sha256": c.sha(c.canonical(request)),
                  "checkpoint_sha256": request["checkpoint_sha256"], "activation_sha256": request["activation_sha256"],
                  "prepared_sha256": c.digest(prepared_sha256), "role_session_sha256": c.digest(role_session_sha256),
                  "call": native}
        self._intent_raw = c.canonical(intent, limit=128 * 1024)
        self.intent_sha256 = c.sha(self._intent_raw)
        # Proof/session/activation changes collide at the same operation locus;
        # they cannot mint another ticket after an unresolved native call.
        self._sequence, self._previous = sequence, previous
        c.require(request["source_sha"] == request["owner"]["source_sha"], "closed-ready evidence source")
        self._keys = closed_ready_evidence_keys(governance, owner=request["owner"], caller=journal._identity,
                                                checkpoint_sha256=request["checkpoint_sha256"], sequence=sequence,
                                                operation=operation)
        self._aws, self._bucket, self._journal = aws, governance["evidence_bucket"], journal
        self._native_sha256, self._session_sha256 = c.sha(native_raw), role_session_sha256
        self._binding = c.sha(c.canonical({key: request[key] for key in ("owner", "checkpoint_sha256", "activation_sha256", "stage")}))
        self._state, self._reserved, self._response, self._receipt = "unexamined", False, None, None

    @property
    def uncertainty(self):
        return [{"kind": "sdk-call", "reference_sha256": self.intent_sha256}] if self._state == "unknown" else []

    @property
    def original_response(self):
        return self._response

    @property
    def original_receipt(self):
        return c.loads(c.canonical(self._receipt), canonical=True) if self._receipt is not None else None

    def _read(self, name):
        self._journal._guard.check(20)
        self._journal.guard()
        raw, _ = self._aws.get(self._bucket, self._keys[name], maximum=1024**2, absent=True)
        self._journal.guard()
        c.require(raw is None or type(raw) is bytes and len(raw) <= 1024**2, "bounded original evidence bytes")
        return raw

    def _write(self, name, raw):
        self._journal._guard.check(20)
        self._journal.guard()
        try:
            # AWS.put creates with IfNoneMatch="*" and the existing KMS context.
            self._aws.put(self._bucket, self._keys[name], raw)
        except Exception as error:
            c.require(getattr(error, "response", {}).get("Error", {}).get("Code") == "PreconditionFailed",
                      "evidence creation result unknown")
            created = False
        else:
            created = True
        self._journal.guard()
        c.require(self._read(name) == raw, "immutable evidence collision/readback")
        return created

    def _validate_receipt(self, raw, response):
        value = c.loads(raw, canonical=True, limit=128 * 1024)
        c.closed(value, "schema_version intent_sha256 response_sha256 call_receipt")
        c.require(type(value["schema_version"]) is int and value["schema_version"] == 2
                  and value["intent_sha256"] == self.intent_sha256 and value["response_sha256"] == c.sha(response),
                  "original durable receipt binding")
        receipt = value["call_receipt"]
        c.closed(receipt, "sequence request_sha256 role_session_sha256 guard_before_sha256 started_monotonic_ns "
                 "response_sha256 request_id server_date ended_monotonic_ns guard_after_sha256")
        c.integer(receipt["sequence"], 0, 8191)
        c.require(receipt["sequence"] == self._sequence, "original durable ordinal receipt")
        for key in ("started_monotonic_ns", "ended_monotonic_ns"):
            c.integer(receipt[key], 0)
        c.require(receipt["request_sha256"] == self._native_sha256 and receipt["role_session_sha256"] == self._session_sha256
                  and receipt["guard_before_sha256"] == receipt["guard_after_sha256"] == self._binding
                  and receipt["response_sha256"] == c.sha(response)
                  and 0 <= receipt["ended_monotonic_ns"] - receipt["started_monotonic_ns"] <= 20 * 10**9,
                  "original durable SDK receipt")
        c.require(type(receipt["request_id"]) is str and 1 <= len(receipt["request_id"]) <= 256
                  and type(receipt["server_date"]) is str, "original SDK metadata")
        from email.utils import parsedate_to_datetime
        c.require(parsedate_to_datetime(receipt["server_date"]).tzinfo is not None, "original SDK Date timezone")
        _sdk_private_fields(c.loads(response, canonical=True, limit=1024**2))
        return receipt

    def reserve(self):
        c.require(self._state == "unexamined", "no automatic replay after evidence attempt")
        c.require(self._journal._next_durable() == (self._sequence, self._previous), "original durable ordinal unchanged")
        self._journal._durable_active = self
        try:
            original = self._read("intent")
            if original is None:
                c.require(self._read("response") is None and self._read("receipt") is None, "orphan durable evidence")
                if self._write("intent", self._intent_raw):
                    self._reserved, self._state = True, "created"
                    return self._state
                original = self._read("intent")
            c.require(original == self._intent_raw, "immutable original intent collision")
            response, receipt = self._read("response"), self._read("receipt")
            if response is None or receipt is None:
                self._state = "unknown"
                return self._state
            self._receipt = self._validate_receipt(receipt, response)
            self._response, self._state = response, "settled"
            return self._state
        except BaseException:
            self.fail()
            raise

    def complete(self, response, receipt):
        c.require(self._reserved and self._state == "created", "only original admitted evidence attempt may complete")
        try:
            c.require(receipt in self._journal.call_receipts
                      and self._journal.call_bytes.get(c.sha(response)) == response, "original guarded in-memory receipt required")
            c.require(self._journal._durable_active is self and self._journal._durable_count == self._sequence
                      and self._journal._durable_last == self._previous, "original active durable receipt ancestry")
            raw = c.canonical({"schema_version": 2, "intent_sha256": self.intent_sha256,
                               "response_sha256": c.sha(response), "call_receipt": receipt}, limit=128 * 1024)
            self._validate_receipt(raw, response)
            self._write("response", response)
            self._write("receipt", raw)
            self._response, self._receipt, self._state, self._reserved = response, receipt, "settled", False
            self._journal._durable_count += 1
            self._journal._durable_last = c.sha(raw)
            self._journal._durable_active = None
        except BaseException:
            self.fail()
            raise

    def fail(self):
        """The original durable intent remains the uncertainty witness."""
        self._state, self._reserved = "unknown", False
        self._journal._failed = True
        for item in self.uncertainty:
            if item not in self._journal._unknown:
                self._journal._unknown.append(item)


class ClosedReadyBroker:
    """Finite private SDK dispatcher with a durable reservation before native IO.

    The SDK set is per operation (closed-ready reads; close-drain adds the pinned close writes).
    Any native error but a validated ExecutionDoesNotExist is unknown (R12): poison, never retry.
    """
    def __init__(self, aws, governance, journal, session, *, prepared_sha256, clock=None):
        c.require(type(journal) is AdapterJournal and type(session) is _FenceSession
                  and session.request_binding == c.sha(c.canonical(journal._request))
                  and getattr(journal, "_broker", None) is None, "one original admitted closed-ready broker")
        self.aws, self.governance, self.journal, self.session = aws, governance, journal, session
        self.prepared_sha256, self.clock = c.digest(prepared_sha256), clock or time.time
        self.evidence = []
        journal._broker = self

    @property
    def uncertainty(self):
        return [item for ledger in self.evidence for item in ledger.uncertainty]

    def call(self, *, role, service, operation, parameters):
        journal, session = self.journal, self.session
        journal.guard()
        c.require(session.request_binding == c.sha(c.canonical(journal._request))
                  and self.clock() + 20 < session.deadline, "original finite SDK request/window")
        lc.validate_fence_call(request=journal._request, history=journal._settled_calls(), role=role, service=service,
                               operation=operation, parameters=parameters, **session.scope)
        native = {"role": role, "service": service, "operation": operation, "parameters": parameters}
        raw = c.canonical(native, limit=128 * 1024)
        ledger = ClosedReadyEvidence(self.aws, self.governance, journal, raw, prepared_sha256=self.prepared_sha256,
                                     role_session_sha256=session.commitment, scope=session.scope)
        self.evidence.append(ledger)
        ticket, created = None, False
        try:
            state = ledger.reserve()
            c.require(state == "created", "existing durable call is historical/unknown; no fresh SDK replay")
            created = True
            ticket = journal.begin_sdk_call(raw, role_session_sha256=session.commitment)
            c.require(self.clock() + 20 < session.deadline, "SDK reservation consumed original budget")
            journal._guard.check(20)
            absent = False
            try:
                response = session.client.call(service, operation, **parameters)
            except Exception as error:
                response = getattr(error, "response", {})
                c.require(service == "stepfunctions" and operation == "describe_execution"
                          and response.get("Error", {}).get("Code") == "ExecutionDoesNotExist"
                          and (journal._request["operation"] == "close-drain" or any(member["resolution"] == "CANCEL_BEFORE_SEND" and member["execution_ref"] is None
                                  and parameters["executionArn"] == session.scope["machine_arn"].replace(":stateMachine:", ":execution:") + ":" + member["dispatch_id"]
                                  for member in session.scope["members"])), "native SDK outcome unknown")
                absent = True
            metadata = response.get("ResponseMetadata", {})
            c.require(type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == (400 if absent else 200),
                      "native SDK authenticated status")
            if absent:
                value = {"Error": {"Code": "ExecutionDoesNotExist"}}
            elif service == "dynamodb":
                fields = ("Item",) if operation == "get_item" else ()
                c.require(set(response) <= {*fields, "ResponseMetadata"}, "finite native DynamoDB response")
                value = {key: response[key] for key in fields if key in response}
            else:
                value = lc.closed_ready_probe_response(response, execution_arn=parameters["executionArn"], machine_arn=session.scope["machine_arn"])
            from tools.cnesdata_delivery.lifecycle_runtime import _exact_sdk_dates
            response_raw = c.canonical(_exact_sdk_dates(value), limit=1024**2)
            c.require(self.clock() < session.deadline, "native response exceeded original API window")
            receipt = journal.complete_sdk_call(ticket, response_raw, request_id=metadata["RequestId"], server_date=metadata["HTTPHeaders"]["date"])
            ledger.complete(response_raw, receipt)
            journal.guard()
            c.require(self.clock() < session.deadline, "durable receipt exceeded original API window")
            return {"kind": "sdk-error", "code": "ExecutionDoesNotExist"} if absent else {"kind": "sdk-result", "value": c.loads(response_raw, canonical=True)}
        except BaseException:
            if created or ledger.uncertainty:
                ledger.fail()
                if ticket is not None and journal._inflight is not None:
                    journal.fail_sdk_call(ticket)
                for item in ledger.uncertainty:
                    if item not in journal._unknown:
                        journal._unknown.append(item)
            journal._failed = True
            raise


def _phase_b_step(governance):
    steps = [(name, step) for name, step in governance["lifecycle_steps"].items()
             if step["role"] == "deploy" and step["purpose"] == "phase-b" and step["direction"] == "advance"]
    c.require(len(steps) == 1, "unique protected phase-b advance step")
    return steps[0]


def _same_run_job(api, run, *, kind, job_name, guard):
    """The unique same-run job with the catalogue name; None while it does not exist."""
    guard.check(20)
    jobs = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100&page=1")
    guard.check()
    c.require(jobs["total_count"] == len(jobs["jobs"]) <= 100, f"complete {kind} publication inventory")
    found = [job for job in jobs["jobs"] if job["name"] == job_name]
    c.require(len(found) <= 1, f"unique {kind} producer job")
    return found[0] if found else None


def _same_run_publication(api, run, owner, job, *, kind, step, guard, now):
    """Decision 3: unique lifecycle-<step> artifact inside the completed-success job interval, original owner."""
    from tools.cnesdata_delivery.provenance import lifecycle_artifact
    c.require(job is not None and job["status"] == "completed" and job["conclusion"] == "success", f"completed {kind} producer")
    guard.check(20)
    artifacts = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run['id']}/artifacts?per_page=100&page=1")
    guard.check()
    c.require(artifacts["total_count"] == len(artifacts["artifacts"]) <= 100, f"complete {kind} publication inventory")
    candidates = [item for item in artifacts["artifacts"] if item["name"] == "lifecycle-" + step
                  and c.instant(job["started_at"]) < c.instant(item["created_at"]) < c.instant(job["completed_at"])]
    c.require(len(candidates) == 1, f"unique {kind} publication in job interval")
    reference = {"job_id": job["id"], "artifact_id": candidates[0]["id"], "artifact_digest": candidates[0]["digest"]}
    public = lifecycle_artifact(api, reference, now, source=owner["source_sha"], run_id=owner["run_id"],
                                attempt=owner["run_attempt"], producer_name=job["name"], artifact_name="lifecycle-" + step)
    index = c.loads(public["index.json"], canonical=True) if set(public) == {"index.json"} else None
    c.require(type(index) is dict and index.get("step") == step and index.get("owner_sha256") == owner["owner_sha256"]
              and type(index.get("generation")) is int and index.get("generation") == owner["generation"],
              f"{kind} original owner")
    return reference, public, candidates[0]


def _phase_b_publication(api, aws, governance, request, run, owner, guard, now):
    """Completed same-run phase-b advance deploy publication (checkpoint + approval) and its authenticated moments."""
    from tools.cnesdata_delivery.lifecycle_runtime import private_payload
    name, step = _phase_b_step(governance)
    job = _same_run_job(api, run, kind="phase-b", job_name=step["job_name"], guard=guard)
    _, public, artifact = _same_run_publication(api, run, owner, job, kind="phase-b", step=name, guard=guard, now=now)
    files = private_payload(aws, governance, request, run, public, guard=guard, names={"checkpoint.json", "approval.json"})[1]
    return files, {"artifact_created_at": artifact["created_at"], "job_completed_at": job["completed_at"]}


def _trigger_producer(governance, kind):
    if kind == "prepared":
        return lc.FENCE_PREPARE_PRODUCER["job_name"], lc.FENCE_PREPARE_PRODUCER["step"]
    if kind == "host":
        return HOST_JOB, None
    name, step = _phase_b_step(governance)
    return step["job_name"], name


def stage_event_source(*, api, governance, run, owner, guard, clock=time.time):
    """Decision 3 event producer over the closed STAGE_TRIGGERS; no dispatch, no reusable output.

    A producer not yet completed-success is no event (the keeper keeps ticking, bounded
    by the stage deadline); a publication that can never be the trigger refuses. The host
    event carries only the job: its handler authenticates the public host handoff (DD-3).
    """
    def next_event(window):
        stage = window["stage"]
        c.require(window["decision"] is None and stage in lc.STAGE_TRIGGERS, f"stage trigger not connected stage={stage}")
        c.require((window["close"] is None) == (stage == "application-prepare"), "stage/close consistency")
        now = clock()
        c.require(now < lc.terminal_deadline(window), f"stage deadline elapsed stage={stage}")
        kind = lc.STAGE_TRIGGERS[stage][0]
        job_name, step = _trigger_producer(governance, kind)
        job = _same_run_job(api, run, kind=kind, job_name=job_name, guard=guard)
        if job is None or job["status"] != "completed" or job["conclusion"] != "success":
            return None
        if kind == "host":
            return {"kind": kind, "reference": {"job_id": job["id"]}}
        reference, _, _ = _same_run_publication(api, run, owner, job, kind=kind, step=step, guard=guard, now=now)
        return {"kind": kind, "reference": reference}
    return next_event


def infra_expiration_bound(authority, api):
    """Errata 6887682424 of decision 2: the closed set of authenticated expirations this gate knows.

    Owner proof expires_at, api.expiries, fragment enabled_until and pin frozen_until
    are all mandatory; a missing one refuses. The guard compares, it never adopts.
    api.expiries is read at call time: the minimum covers what the process authenticated so far.
    """
    from tools.cnesdata_delivery.session_owner import Authority
    c.require(type(authority) is Authority and type(authority.pin) is dict and type(authority.application_fragment) is dict
              and "frozen_until" in authority.pin and "enabled_until" in authority.application_fragment
              and type(api.expiries) is dict and len(api.expiries) > 0, "application authenticated expirations")
    return int(min([authority.expires_at, *api.expiries.values(), c.instant(authority.application_fragment["enabled_until"]),
                    c.instant(authority.pin["frozen_until"])]))



def close_expirations(authority, api):
    """Correction 6906038586 item 1: the close-drain `expirations` input from authenticated originals.

    credential = owner proof bytes, artifact = each authenticated download, platform =
    fragment enabled_until and pin frozen_until. Unbound or duplicate (kind, object) refuses.
    """
    infra_expiration_bound(authority, api)
    c.require(type(authority.proof_sha256) is str and type(getattr(api, "digests", None)) is dict
              and set(api.digests) == set(api.expiries), "close expirations authenticated objects")
    fragment, pin = authority.application_fragment, authority.pin
    entries = sorted([("credential", c.digest(authority.proof_sha256), authority.expires_at),
                      ("platform", c.sha(c.canonical(fragment)), c.instant(fragment["enabled_until"])),
                      ("platform", c.sha(c.canonical(pin)), c.instant(pin["frozen_until"])),
                      *[("artifact", c.digest(api.digests[key]), api.expiries[key]) for key in api.expiries]])
    keys = [entry[:2] for entry in entries]
    c.require(len(set(keys)) == len(keys), "close expirations unique originals")
    return c.canonical([{"kind": kind, "object_sha256": digest, "expires_at": c.utc(int(expiry))}
                        for kind, digest, expiry in entries])


RELEASE_FIELDS = "release_id source_sha candidate_sha256 canary_id binding_sha256 image_digest"


def application_release_sha256(governance):
    """Owner release_sha256 of 6974253889 section 1: the opaque hash of the closed governance release."""
    release = governance.get("release")
    c.require(type(release) is dict and set(release) == set(RELEASE_FIELDS.split()), "application governance release")
    return c.sha(c.canonical(release))


def closed_ready_capability(*, aws, api, governance, request, run, journal, keeper, prepared, credential_limit,
                            guard, operation_session, revisions, clock=time.time):
    """The only connected capability factory (amendment 2026-11-13 item 7).

    Composes the authenticated PreparedFence, fence role, effective scope (item 2),
    membership, the finite STS boundary and ClosedReadyBroker, attached to the
    keeper. Every check precedes STS; any failure poisons the journal, keeps the
    lease held and mints no credential. Other operations/modes stay rejected.
    revisions are the route revisions of the authenticated plan carrier.
    """
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    c.require(type(journal) is AdapterJournal and type(keeper) is Keeper and type(prepared) is lr.PreparedFence,
              "closed-ready original journal/keeper/prepared authority")
    c.require(journal._request["operation"] == "closed-ready" and getattr(journal, "_broker", None) is None,
              "closed-ready only; every other operation remains rejected")
    try:
        stage = journal._request["stage"]
        keeper.lease.check()  # The original keeper still holds the lease; nothing here can renew or release it.
        owner = journal._request["owner"] | journal._identity
        manifest = c.loads(prepared["fence-prepared.json"], canonical=True)
        role = c.loads(prepared["fence-role.json"], canonical=True)
        evaluation = c.loads(prepared["fence-evaluation.json"], canonical=True)
        activation = journal._inputs["activation"]
        c.require(manifest["activation_sha256"] == journal._request["activation_sha256"] == c.sha(activation),
                  "prepared/request/input activation_sha256")
        c.require(manifest["preparation"]["deadline"] == stage["preparation_deadline"]
                  and manifest["preparation"]["admitted_at"] < stage["admitted_at"], "original preparation before API stage")
        c.require(role["role_arn"] == governance["application_delegations"]["fence_operator"], "fence_operator delegation")
        c.require(c.canonical(manifest["owner"]) == c.canonical(owner), "prepared current owner")
        files, moments = _phase_b_publication(api, aws, governance, request, run, owner, guard, clock())
        b_checkpoint = c.loads(files["checkpoint.json"], canonical=True)
        b_approval = c.loads(files["approval.json"], canonical=True)
        c.require(b_approval["checkpoint_sha256"] == c.sha(prepared["checkpoint.json"])
                  and b_approval["plan_sha256"] == b_checkpoint["plan_sha256"] and b_checkpoint["purpose"] == "phase-b"
                  and c.canonical(b_checkpoint["owner"]) == c.canonical(owner)
                  and c.sha(files["checkpoint.json"]) == stage["checkpoint_sha256"] == journal._request["checkpoint_sha256"],
                  "preparation -> B -> API checkpoint ancestry")
        journals = [item.journal if type(item) is ClosedReadyBroker else item for item in keeper._contexts]
        drained = [found._observation_bytes.get(entry["sha256"]) for found in {id(item): item for item in journals}.values()
                   for entry in found._observations if entry["kind"] == "close-drain"]
        c.require(drained == [journal._inputs["close-drain"]], "closed-ready close-drain is the keeper observation")
        c.require(journal._inputs["phase-b"] == api_phase_b_evidence(close_raw=drained[0], prepared=prepared, published=files,
                                                                     moments=moments, admitted_at=stage["admitted_at"],
                                                                     revisions=revisions), "API phase-b evidence")
        cases = {case["case_id"]: case for case in evaluation["cases"]}
        derived = lr.fence_policy_scope(governance, role["policy"])  # The same symbol the prepared evaluation used.
        table, prefix, machine = derived["control_table_arn"], derived["execution_prefix"], derived["machine_arn"]
        c.require(cases["get-fence"]["resource"] == table and cases["probe-own"]["resource"] == prefix + "0" * 16,
                  "capability scope recomputed from prepared policy")
        # Item 3: the evaluated fence_session is the shared constructor at the preparation deadline
        # min(observed_at + 180, frozen_until); _assume_fence_session builds the API session with the same
        # constructor and scope, so the two differ only in DateLessThan and its effective_iam checks stay live.
        from tools.cnesdata_delivery.session_policy import fence_session_policy
        frozen = c.instant(cases["freeze-expired"]["context"]["aws:CurrentTime"])
        prepared_session = fence_session_policy(control_table_arn=table, execution_prefix=prefix,
                                                deadline=int(min(manifest["preparation"]["observed_at"] + 180, frozen)))
        c.require(evaluation["documents"]["fence_session"] == c.sha(c.canonical(prepared_session)),
                  "prepared fence session equals API session except DateLessThan")
        described = [row["observed"] for row in b_checkpoint["readbacks"]
                     if row["service"] == "stepfunctions" and row["operation"] == "describe_state_machine"]
        c.require(len(described) == 1 and described[0].get("stateMachineArn") == machine, "B DescribeStateMachine readback")
        membership = c.loads(journal._inputs["membership"], canonical=True)
        c.closed(membership, "frozen_membership_sha256 members")
        c.require(type(membership["members"]) is list and membership["frozen_membership_sha256"] == c.sha(c.canonical(membership["members"])),
                  "frozen membership commitment")
        c.require(journal._inputs["membership"] == _frozen_membership(drained[0]), "closed-ready membership is the close-drain frozen set")
        scope = {"account": governance["account_id"], "control_table_arn": table, "machine_arn": machine, "members": membership["members"]}
        for member in scope["members"]:
            lc.validate_closed_ready_call(request=journal._request, role="fence_operator", service="stepfunctions",
                operation="describe_execution", parameters={"executionArn": prefix + member["dispatch_id"],
                "includedData": "METADATA_ONLY"}, **scope)
        prepared_sha256 = c.sha(prepared["fence-prepared.json"])
        session = _assume_fence_session(governance=governance, role=role, scope=scope, journal=journal,
                                        prepared_sha256=prepared_sha256, credential_limit=credential_limit,
                                        operation_session=operation_session, clock=clock)
        broker = ClosedReadyBroker(session.evidence, governance, journal, session, prepared_sha256=prepared_sha256, clock=clock)
        keeper.attach(broker)
        return broker
    except BaseException:
        journal._failed = True
        keeper.attach(journal)
        raise


def close_drain_capability(*, aws, api, governance, authority, journal, keeper, prepared, credential_limit,
                           operation_session, clock=time.time):
    """Close-drain capability factory, sibling of closed_ready_capability (decision 4, queue item 3a).

    Composes the authenticated PreparedFence, fence role, recomputed scope and expirations, the local
    operation-session effective_iam and the finite close session. The freeze reread is the last AWS call
    before the operation exchange and the fence STS; any failure poisons the journal, keeps the lease
    held and mints no fence credential. The prepared handler of stage_handlers is the production caller.
    """
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    from tools.cnesdata_delivery.session_owner import application_unfrozen
    c.require(type(journal) is AdapterJournal and type(keeper) is Keeper and type(prepared) is lr.PreparedFence,
              "close-drain original journal/keeper/prepared authority")
    c.require(journal._request["operation"] == "close-drain" and getattr(journal, "_broker", None) is None,
              "close-drain only; every other operation remains rejected")
    try:
        stage = journal._request["stage"]
        keeper.lease.check()  # The original keeper still holds the lease; nothing here can renew or release it.
        owner = journal._request["owner"] | journal._identity
        manifest = c.loads(prepared["fence-prepared.json"], canonical=True)
        role = c.loads(prepared["fence-role.json"], canonical=True)
        evaluation = c.loads(prepared["fence-evaluation.json"], canonical=True)
        c.require(manifest["activation_sha256"] == journal._request["activation_sha256"] == c.sha(journal._inputs["activation"]),
                  "prepared/request/input activation_sha256")
        c.require(manifest["preparation"]["deadline"] == stage["preparation_deadline"]
                  and manifest["preparation"]["admitted_at"] == stage["admitted_at"], "original preparation is the close stage")
        c.require(role["role_arn"] == governance["application_delegations"]["fence_operator"], "fence_operator delegation")
        c.require(c.canonical(manifest["owner"]) == c.canonical(owner), "prepared current owner")
        c.require(journal._inputs["expirations"] == close_expirations(authority, api), "close-drain authenticated expirations")
        cases = {case["case_id"]: case for case in evaluation["cases"]}
        derived = lr.fence_policy_scope(governance, role["policy"])
        table, prefix, machine = derived["control_table_arn"], derived["execution_prefix"], derived["machine_arn"]
        c.require(cases["get-fence"]["resource"] == table and cases["probe-own"]["resource"] == prefix + "0" * 16,
                  "capability scope recomputed from prepared policy")
        scope = {"account": governance["account_id"], "control_table_arn": table, "machine_arn": machine}
        # Change 4: the package evaluation only attests the closed-ready session, so this effective_iam is local, over
        # documents recomputed here: the application identity, the pinned managed policy and the inline the factory sends.
        from tools.cnesdata_delivery import session_owner, session_policy
        from tools.cnesdata_delivery.coordination_lease import KEY
        from tools.cnesdata_delivery.iam_boundary import effective_iam
        inline = c.loads(session_policy.application_request(governance, owner["source_sha"], owner["run_id"], owner["run_attempt"],
            "close-drain", application_purpose="promotion", delegations=("fence_operator",),
            sessions={"fence_operator": role["session_name"]})["Policy"].encode())
        evidence = "arn:aws:s3:::" + governance["evidence_bucket"] + "/" + lr.closed_ready_evidence_keys(governance,
            owner=journal._request["owner"], caller=journal._identity, checkpoint_sha256=journal._request["checkpoint_sha256"],
            sequence=0, operation="close-drain")["intent"]
        named = {"sts:RoleSessionName": role["session_name"]}
        decisions = ((role["role_arn"], "sts:AssumeRole", named, True),
                     (role["role_arn"], "sts:AssumeRole", {"sts:RoleSessionName": role["session_name"] + "-foreign"}, False),
                     (governance["application_delegations"]["normal"], "sts:AssumeRole", named, False),
                     ("arn:aws:s3:::" + governance["state_bucket"] + "/" + KEY, "s3:PutObject", {}, False),
                     (evidence.replace("/close-drain/", "/keeper/"), "s3:PutObject", {}, False), (evidence, "s3:PutObject", {}, True))
        identity = session_owner.application_identity_document(governance, authority.application_fragment)
        c.require(all(effective_iam(identity, [authority.pin["document"], inline], action, resource,
                                    {"aws:CurrentTime": c.utc(clock())} | context) is expected
                      for resource, action, context, expected in decisions), "close-drain operation session effective IAM")
        journal.guard()
        attached = aws.call("iam", "list_attached_role_policies", RoleName=authority.application_fragment["application_role_name"],
                            MaxItems=100)
        application_unfrozen(attached, governance["account_id"])
        prepared_sha256 = c.sha(prepared["fence-prepared.json"])
        session = _assume_fence_session(governance=governance, role=role, scope=scope, journal=journal,
                                        prepared_sha256=prepared_sha256, credential_limit=credential_limit,
                                        operation_session=operation_session, clock=clock)
        broker = ClosedReadyBroker(session.evidence, governance, journal, session, prepared_sha256=prepared_sha256, clock=clock)
        keeper.attach(broker)
        return broker
    except BaseException:
        journal._failed = True
        keeper.attach(journal)
        raise


class Keeper:
    """One process alone owns CAS; delegates consume read-only lease views.

    authenticate_previous is the original successful-publication validator,
    returning its authenticated private checkpoint and protected full reference.
    Admission independently authenticates the reference before any lease write.
    """
    def __init__(self, store, binding, authenticate_previous, *, api, governance, evidence_aws=None, clock=time.time, monotonic=time.monotonic):
        c.require(binding.get("lifecycle_version") == 1, "lifecycle keeper binding")
        self.store, self.clock, self.monotonic = store, clock, monotonic
        self.authenticate_previous = authenticate_previous
        self.api, self.governance = api, governance
        self.predecessor_reference = None
        self._terminal_validators = {}  # Closed registry, empty by default: finish() refuses.
        self.predecessor = None
        self.evidence_aws = evidence_aws if evidence_aws is not None else getattr(store, "aws", None)
        self.phase_a_originals = None
        self.transport_raw = None
        self.lease = Lease(store, binding, clock=clock, monotonic=monotonic, previous_success=self._previous)
        self.last_renewed = None
        self._contexts = []

    def attach(self, context):
        """Register an original journal/broker; its uncertainty keeps the lease held."""
        c.require(type(context) in (AdapterJournal, ClosedReadyBroker), "original adapter context")
        if not any(item is context for item in self._contexts):
            self._contexts.append(context)

    def uncertainty(self):
        """Pending, unknown, in-flight or failed SDK state across every attached context."""
        journals = [item.journal if type(item) is ClosedReadyBroker else item for item in self._contexts]
        found = [{"kind": "context-failed"} for journal in journals if journal._failed]
        found += [{"kind": "sdk-inflight"} for journal in journals if journal._inflight is not None]
        found += [entry for journal in journals for entry in journal.pending + journal.unknown]
        found += [entry for item in self._contexts if type(item) is ClosedReadyBroker for entry in item.uncertainty]
        return found

    def _previous(self, previous):
        details = self.authenticate_previous(previous)
        c.require(type(details) is dict and type(details.get("checkpoint")) is dict,
                  "original predecessor checkpoint authentication")
        reference = details.get("predecessor_reference")
        c.require(type(reference) is dict and self.predecessor_reference is not None
                  and c.canonical(reference) == c.canonical(self.predecessor_reference),
                  "original protected predecessor reference")
        c.require(previous["status"] == "released" and previous["repository"] == c.REPOSITORY
                  and all(previous[k] == reference[k] for k in ("run_id", "run_attempt", "session_sha256", "checkpoint_sha256"))
                  and c.sha(previous["owner"].encode()) == reference["owner_sha256"]
                  and previous.get("generation") == reference["generation"], "original released predecessor selection")
        carrier = details["phase_a_originals"]
        lc.phase_a_originals(carrier)
        if reference["protocol"] == "lifecycle":
            c.require(c.canonical(details["checkpoint"]["phase_a_originals"]) == c.canonical(carrier),
                      "predecessor terminal Phase A custody")
        raw = details["checkpoint_raw"]
        c.require(c.loads(raw, canonical=True) == details["checkpoint"], "original raw predecessor checkpoint")
        c.require(c.sha(raw) == previous["checkpoint_sha256"], "original predecessor bytes")
        self.predecessor = {"lease": dict(previous), "checkpoint": details["checkpoint"], "raw": raw,
                            "reference": c.loads(c.canonical(reference), canonical=True)}
        self.phase_a_originals = c.loads(c.canonical(carrier), canonical=True)
        return True

    def acquire(self, *, preparation_deadline):
        # Lifecycle follows a completed initial delivery; no invented empty state.
        caller = self.governance["authenticated_application_caller"]
        c.closed(caller, lc.CALLER_BINDING_FIELDS)
        lc.application_caller_binding(caller | {"event": "workflow_dispatch", "fragment_version": 4},
            {"workflow_sha": self.governance["gate_shas"]["application"],
             "source_closure_sha256": self.governance["application_source_closure_sha256"]})
        identity = lc.application_identity(self.lease.binding, required=True)
        c.require(identity == {"application_purpose": caller["application_purpose"], "context_kind": caller["context_kind"],
                               "caller_binding_sha256": c.sha(c.canonical(caller))}
                  and all(self.lease.binding[k] == caller[k] for k in ("repository", "source_sha", "run_id", "run_attempt"))
                  and caller["application_purpose"] == self.governance["application_purpose"]
                  and caller["context_kind"] == self.governance["context_kind"], "original current caller before acquire")
        previous, _ = self.store.get()
        c.require(previous is not None and previous.get("status") == "released", "original completed delivery required")
        c.integer(preparation_deadline)
        c.require(self.clock() + 158 < preparation_deadline, "preparation capacity")
        from tools.cnesdata_delivery.lifecycle_runtime import authenticate_predecessor
        reference = authenticate_predecessor(self.api, self.governance)
        c.require((reference["run_id"], reference["run_attempt"]) != (caller["run_id"], caller["run_attempt"]), "distinct original predecessor execution")
        if caller["application_purpose"] == "mode-readiness-drill":
            c.require(reference["protocol"] == "lifecycle", "readiness requires original lifecycle predecessor")
        self.predecessor_reference = c.loads(c.canonical(reference), canonical=True)
        self._previous(previous)  # Complete protected binding before Lease.acquire/CAS.
        original_release = lc.phase_a_originals(self.phase_a_originals)["envelope"]["plan"]["release"]
        c.require(c.sha(c.canonical(original_release)) == c.digest(self.lease.binding["release_sha256"]),
                  "application release binds the original Phase A plan release")
        self.lease.acquire()  # Revalidates the record read by the original CAS owner.
        c.require(self.predecessor is not None, "original predecessor missing")
        now = int(self.clock())
        initial = {"sequence": 0, "preparation_deadline": preparation_deadline,
            "close": None, "fixed_deadline": None, "input_deadline": None,
            "stage": "application-prepare", "admitted_at": now, "deadline": preparation_deadline,
            "decision": None, "checkpoint_sha256": c.sha(self.predecessor["raw"]),
            "predecessor_sha256": c.sha(c.canonical(self.predecessor["reference"])), **identity}
        self.lease.checkpoint(initial)
        self.last_renewed = self.monotonic()
        owner = lc.owner_binding(self.lease.check())
        try:
            c.require(self.evidence_aws is not None, "keeper private transport unavailable")
            from tools.cnesdata_delivery.lifecycle_runtime import namespace, keeper_transport
            prefix = namespace(self.governance, {"source_sha": owner["source_sha"], "step": "keeper"},
                               {"id": owner["run_id"], "run_attempt": owner["run_attempt"]})
            raw = c.canonical({"version": 2, "owner": owner, "predecessor_sha256": initial["predecessor_sha256"],
                               "phase_a_originals": self.phase_a_originals}, limit=262144)
            self.lease.check()
            self.evidence_aws.put(self.governance["evidence_bucket"], prefix + "checkpoint.json", raw)
            class Guard:
                def check(inner, seconds=0):
                    self.lease.check()
            observed = keeper_transport(aws=self.evidence_aws, governance=self.governance, owner=owner,
                                       predecessor=reference, guard=Guard())
            c.require(c.canonical(observed) == raw, "keeper conditional publication readback")
            self.transport_raw = raw
        except BaseException:
            self.lease.failed = True
            raise
        return owner

    def register_terminal_validator(self, kind, validator, *, label):
        """Register one validator per closed type; it reads journal observations or authenticated artifacts."""
        c.require(kind in TERMINAL_VALIDATOR_FACTS and kind not in self._terminal_validators and callable(validator)
                  and type(label) is str and 0 < len(label) <= 128, "closed terminal validator registry")
        self._terminal_validators[kind] = (label, validator)

    def _latest_observation_bytes(self):
        """Disposition 3d of 6963008338: bytes only of the latest registered observation of each kind.

        Journals follow attach order, a broker counts once through its journal, and the
        entries of one journal follow its own `_observations` order.
        """
        journals = []
        for context in self._contexts:
            found = context.journal if type(context) is ClosedReadyBroker else context
            journals += [] if any(known is found for known in journals) else [found]
        latest = {}
        for journal in journals:
            for entry in journal._observations:
                latest[entry["kind"]] = (journal, entry["sha256"])
        return {digest: journal._observation_bytes[digest] for journal, digest in latest.values()
                if digest in journal._observation_bytes}

    def _terminal_proof(self, reference, owner, window):
        """Assemble the assessment from registered validator results, never from caller JSON."""
        c.closed(reference, "kind checkpoint_raw sources")
        c.require(type(reference["checkpoint_raw"]) is bytes and type(reference["sources"]) is dict, "terminal reference shape")
        required = _terminal_required(reference["kind"], window)
        c.require(set(reference["sources"]) == required and required <= set(self._terminal_validators),
                  "terminal validator unavailable; lifecycle disabled")
        observations = self._latest_observation_bytes()
        inputs, facts = {}, {}
        for kind in sorted(required):
            label, validator = self._terminal_validators[kind]
            result = validator(reference["sources"][kind], owner=dict(owner), window=dict(window), observations=dict(observations))
            c.closed(result, "sha256 facts")
            c.closed(result["facts"], TERMINAL_VALIDATOR_FACTS[kind])
            inputs[kind], facts[kind] = c.digest(result["sha256"]), result["facts"]
        quiet, routing = facts["quiescence"], facts["routing"]
        assessment = {"kind": reference["kind"], "fence": routing["fence"], "routes_match": routing["routes_match"],
                      "state_clean": quiet["state_clean"], "quiescent": quiet["quiescent"], "pending": quiet["pending"],
                      "unknown": quiet["unknown"], "observed_at": quiet["observed_at"]}
        if reference["kind"] == "accepted-open":
            c.require(all(facts[kind]["accepted"] is True for kind in ("host", "static"))
                      and facts["membership"]["resolved"] is True, "terminal host/static/membership acceptance")
            assessment["accepted_modes"] = [mode for mode in ("unit", "recovery", "audit") if facts[mode]["accepted"] is True]
        else:
            if "membership" in facts:
                c.require(facts["membership"]["resolved"] is True, "terminal membership resolution")
            assessment |= {"accepted_modes": [], "restoration": facts["restoration"]}
        return {"assessment": assessment, "checkpoint": c.loads(reference["checkpoint_raw"], canonical=True), "inputs": inputs}

    def tick(self):
        """Called by the keeper polling loop; never by delegated jobs."""
        c.require(self.last_renewed is not None, "keeper not acquired")
        if self.monotonic() - self.last_renewed >= 30:
            self.lease.renew()
            self.last_renewed = self.monotonic()
        else:
            self.lease.check()


    def finish(self, reference):
        """Release only after the protected terminal producer validates originals.

        No finally-release. Publication happens after this method and cannot
        retroactively turn promotion failure into accepted promotion.
        """
        c.require(bool(self._terminal_validators), "terminal validator unavailable; lifecycle disabled")
        c.require(not self.uncertainty(), "unresolved SDK uncertainty; lease remains held")
        record = self.lease.check()
        owner, window = lc.owner_binding(record), record["lifecycle"]
        proof = self._terminal_proof(reference, owner, window)
        c.closed(proof, "assessment checkpoint inputs")
        c.require(type(proof["inputs"]) is dict and 1 <= len(proof["inputs"]) <= 32, "original terminal inputs")
        for digest in proof["inputs"].values():
            c.digest(digest)
        checkpoint = proof["checkpoint"]
        assessment = proof["assessment"]
        c.require(c.sha(c.canonical(checkpoint)) == window["checkpoint_sha256"], "original terminal checkpoint bytes")
        if window["sequence"] == 0 and assessment["kind"] == "failed-prepare-quiescent":
            c.require(self.predecessor is not None and checkpoint == self.predecessor["checkpoint"],
                      "original preparation predecessor")
            state = checkpoint["state"] if "state" in checkpoint else checkpoint["state_after"]
        else:
            c.require(checkpoint["owner"] == owner, "original terminal state owner")
            c.require(c.canonical(checkpoint["phase_a_originals"]) == c.canonical(self.phase_a_originals),
                      "current checkpoint preserves admitted Phase A originals")
            state = checkpoint["state"]
        from tools.cnesdata_delivery.lifecycle_runtime import keeper_transport
        class Guard:
            def check(inner, seconds=0):
                self.lease.check()
        transport = keeper_transport(aws=self.evidence_aws, governance=self.governance, owner=owner,
                                     predecessor=self.predecessor_reference, guard=Guard())
        c.require(c.canonical(transport) == self.transport_raw
                  and c.canonical(transport["phase_a_originals"]) == c.canonical(self.phase_a_originals),
                  "terminal original keeper transport custody")
        _terminal_inputs(assessment, window, proof["inputs"])
        now = int(self.clock())
        deadline = lc.terminal_deadline(window)
        c.require(now - 30 <= assessment["observed_at"] <= now, "fresh terminal assessment")
        status = lc.terminal_result(assessment, now=now, deadline=deadline)
        c.require(self.lease.check()["lifecycle"] == window, "terminal phase changed during authentication")
        final_checkpoint = {"version": 2, "owner": owner, "state": state,
            "state_object": checkpoint["state_object"], "previous_checkpoint_sha256": window["checkpoint_sha256"],
                            "assessment_sha256": c.sha(c.canonical(assessment)), "inputs": proof["inputs"], "window": window,
                            "phase_a_originals": self.phase_a_originals}
        lc.phase_a_originals(self.phase_a_originals)
        final_raw = c.canonical(final_checkpoint, limit=262144)
        digest = c.sha(final_raw)
        original_store = self.lease.store
        self.lease.store = _TerminalStore(original_store, self.clock, deadline)
        try:
            self.lease.checkpoint(window | {"sequence": window["sequence"] + 1, "checkpoint_sha256": digest})
            self.lease.release(digest)
        except Exception:
            self.lease.failed = True
            raise
        finally:
            self.lease.store = original_store
        completed = int(self.clock())
        c.require(completed < deadline and completed - assessment["observed_at"] <= 30, "terminal publication observation deadline")
        terminal = {"version": 1, "owner": owner, "checkpoint_sha256": digest,
                    "promotion_status": status, "coordination_status": "quiescent-released",
                    "assessment": assessment, "completed_at": completed, "deadline": deadline}
        evidence = self.lease.evidence(digest, {"quiescence_sha256": proof["inputs"]["quiescence"]})
        return {"checkpoint.json": final_raw, "terminal.json": c.canonical(terminal), "lease.json": c.canonical(evidence)}


def publish_static_closed_ready(journal, keeper):
    """Queue item 6: the publish-static host-receipt binds the single closed-ready observation of the keeper.

    CnesData 9cdd452f checks only the digest shape; any failure poisons the journal and keeps the lease held.
    """
    c.require(type(journal) is AdapterJournal and type(keeper) is Keeper
              and journal._request["operation"] == "publish-static", "publish-static original journal/keeper")
    try:
        c.require(not keeper.uncertainty(), "publish-static keeper uncertainty")
        receipt = _versioned(c.loads(journal._inputs["host-receipt"], canonical=True, limit=1024**2), "host-handoff",
                             HOST_HANDOFF_FIELDS)
        journals = []
        for item in keeper._contexts:
            found = item.journal if type(item) is ClosedReadyBroker else item
            journals += [] if any(known is found for known in journals) else [found]
        ready = [entry["sha256"] for found in journals for entry in found._observations if entry["kind"] == "closed-ready"]
        c.require(len(ready) == 1 and receipt["closed_ready_sha256"] == ready[0],
                  "publish-static host-receipt closed-ready binding")
        return ready[0]
    except BaseException:
        journal._failed = True
        keeper.attach(journal)
        raise


# CnesData 9cdd452f scripts/promotion/_api_static_handoff.py as labelled literals: the keeper-side caller of the
# public host-handoff artifact. Unlike the product, producer_sha is the run's own reusable pin, never a literal.
HOST_JOB = "host-gate / execute"
HOST_JOB_STEPS = ("Repeat source gate before OIDC and exchange exactly three SSH frames",
                  "Publish only the closed public handoff projection",
                  "Fail only after the original recovery handoff is available")
HOST_REUSABLE = "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-host-deploy-gate.yml@"
HOST_MEMBER, HOST_MEMBER_LIMIT, HOST_ZIP_LIMIT = "host-handoff.json", 32768, 65536


def _host_job(api, owner, guard):
    run_id, attempt = owner["run_id"], owner["run_attempt"]
    guard.check(20)
    listing = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page=1")
    guard.check()
    found = [job for job in listing["jobs"] if job["name"] == HOST_JOB]
    c.require(listing["total_count"] == len(listing["jobs"]) <= 100 and len(found) == 1, "host handoff job inventory")
    job = found[0]
    c.require((job["run_id"], job["run_attempt"], job["head_sha"]) == (run_id, attempt, owner["source_sha"])
              and job["status"] == "completed" and job["conclusion"] in {"success", "failure"}, "host handoff job identity")
    steps = {step["name"]: step for step in job["steps"]}
    c.require(all(name in steps for name in HOST_JOB_STEPS), "host handoff job steps")
    gate, handoff, final = (steps[name] for name in HOST_JOB_STEPS)
    c.require(gate["number"] < handoff["number"] < final["number"]
              and (gate["conclusion"], handoff["conclusion"]) == ("success", "success")
              and final["conclusion"] == ("failure" if job["conclusion"] == "failure" else "skipped"), "host handoff job steps")
    return job


def _host_handoff_archive(api, owner, job, guard):
    run_id = owner["run_id"]
    guard.check(20)
    listing = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100&page=1")
    guard.check()
    c.require(listing["total_count"] == len(listing["artifacts"]) <= 100, "host handoff artifact inventory")
    found = [item for item in listing["artifacts"] if item["name"] == f"cnesdata-host-handoff-{run_id}-{owner['run_attempt']}"]
    c.require(len(found) == 1, "host handoff artifact unique")
    meta = found[0]
    c.require(meta["expired"] is False and meta["workflow_run"]["id"] == run_id
              and meta["workflow_run"]["head_sha"] == owner["source_sha"]
              and c.instant(job["started_at"]) < c.instant(meta["created_at"]) <= c.instant(job["completed_at"]),
              "host handoff artifact identity")
    guard.check(20)
    archive = api.read(f"repos/{c.REPOSITORY}/actions/artifacts/{meta['id']}/zip", raw=True, maximum=HOST_ZIP_LIMIT)
    guard.check()
    c.require(type(archive) is bytes and len(archive) <= HOST_ZIP_LIMIT and meta["digest"] == "sha256:" + c.sha(archive),
              "host handoff digest")
    return archive


def _host_handoff_member(archive):
    import io
    import stat
    import zipfile
    try:
        packed = zipfile.ZipFile(io.BytesIO(archive))
    except zipfile.BadZipFile as error:
        raise ValueError("host handoff member") from error
    with packed:
        members = packed.infolist()
        c.require(len(members) == 1 and members[0].filename == HOST_MEMBER and not members[0].is_dir()
                  and stat.S_IFMT(members[0].external_attr >> 16) in {0, stat.S_IFREG} and not members[0].flag_bits & 1,
                  "host handoff member")
        with packed.open(members[0]) as stream:
            raw = stream.read(HOST_MEMBER_LIMIT + 1)
    c.require(0 < len(raw) <= HOST_MEMBER_LIMIT, "host handoff member size")
    return raw


def authenticate_host_handoff(api, owner, *, guard):
    """Authenticated host-handoff bytes of the owner run: job and steps, artifact, digest, member, canonical JSON.

    Args: api GitHub reader, owner binding, keeper guard. Returns: the exact artifact member bytes.
    Raises: ValueError on any missing or divergent proof.
    """
    run_id, attempt = owner["run_id"], owner["run_attempt"]
    guard.check(20)
    run = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}")
    guard.check()
    c.require((run["id"], run["run_attempt"], run["head_sha"]) == (run_id, attempt, owner["source_sha"]), "host handoff run")
    refs = [item for item in run.get("referenced_workflows", []) if item["path"].startswith(HOST_REUSABLE)]
    c.require(len(refs) == 1 and refs[0]["path"] == HOST_REUSABLE + c.digest(refs[0]["sha"], 40), "host handoff reusable")
    job = _host_job(api, owner, guard)
    raw = _host_handoff_member(_host_handoff_archive(api, owner, job, guard))
    value = c.loads(raw, canonical=True, limit=HOST_MEMBER_LIMIT)
    caller = value.get("caller") if type(value) is dict else None
    c.require(type(caller) is dict and value.get("producer_sha") == refs[0]["sha"]
              and (caller.get("repository"), caller.get("source_sha"), caller.get("run_id"), caller.get("run_attempt"))
              == (c.REPOSITORY, owner["source_sha"], run_id, attempt), "host handoff producer/caller")
    return raw


def _journal_validator(validator):
    return lambda keeper: validator


def _quiescence_validator(keeper):
    return quiescence_terminal_validator(keeper.uncertainty)


def _handoff_validator(role):
    """Lazy artifact validator: the handoff is authenticated when the keeper invokes it, before the factory is built."""
    def provider(keeper):
        def validator(source, *, owner, window, observations):
            raw = authenticate_host_handoff(keeper.api, owner, guard=KeeperGuard(keeper))
            if role == "host-handoff":
                return host_terminal_validator(raw)(source, owner=owner, window=window, observations=observations)
            decision = c.loads(raw, canonical=True, limit=HOST_MEMBER_LIMIT)["recovery_decision"]
            c.require(decision is not None, "host handoff recovery decision")
            return decision_terminal_validator(c.canonical(decision))(source, owner=owner, window=window,
                                                                      observations=observations)
        return validator
    return provider


# Closed production registries. They are code constants, never read from governance, environment or
# request. Each kind maps to a SYNTHETIC label (R3: the product has no routing or terminal-readback
# handler) and a provider that builds the validator for one keeper. Only six kinds exist; unit,
# recovery, audit and restoration stay without a validator, so finish() refuses their terminals.
TERMINAL_VALIDATORS = {
    "routing": ("synthetic-routing", _journal_validator(routing_terminal_validator)),
    "static": ("synthetic-static", _journal_validator(static_terminal_validator)),
    "membership": ("synthetic-membership", _journal_validator(membership_terminal_validator)),
    "quiescence": ("synthetic-quiescence", _quiescence_validator),
    "host": ("synthetic-host", _handoff_validator("host-handoff")),
    "decision": ("synthetic-decision", _handoff_validator("recovery-decision")),
}
KEEPER_EVENT_SOURCE = stage_event_source


def register_terminal_validators(keeper, registry):
    c.require(type(keeper) is Keeper and type(registry) is dict and set(registry) <= set(TERMINAL_VALIDATOR_FACTS),
              "terminal validator registry")
    for kind, (label, provider) in sorted(registry.items()):
        keeper.register_terminal_validator(kind, provider(keeper), label=label)


class KeeperGuard:
    """Guard handed to journals/brokers: every check is a keeper tick.

    `_adapter_exchange` calls journal.guard() every five seconds even while a
    child is quiet, so a long adapter run renews the lease (TTL 300s) instead of
    letting it lapse. It never acquires, releases or rearms a window.
    """
    def __init__(self, keeper):
        c.require(type(keeper) is Keeper, "original keeper guard")
        self.keeper = keeper

    def check(self, seconds=0):
        c.require(type(seconds) in (int, float) and 0 <= seconds <= 907, "bounded guard reservation")
        self.keeper.tick()
        self.keeper.lease.check()


def run_closed_ready(*, keeper, request_raw, owner, window, inputs, activation_sha256, capability, product, source,
                     manifest, manifest_sha256, seconds):
    """Closed-ready dispatch: journal under the keeper guard, capability before any child, then the fixed adapter.

    seconds() samples the child timeout after the capability, right before the child starts.
    """
    guard = KeeperGuard(keeper)
    journal = AdapterJournal(request_raw, operation="closed-ready", owner=owner, window=window, inputs=inputs,
                             activation_sha256=activation_sha256, guard=guard)
    keeper.attach(journal)
    capability(journal=journal, keeper=keeper, guard=guard)  # Poisons the journal and holds the lease on failure.
    c.require(type(getattr(journal, "_broker", None)) is ClosedReadyBroker, "closed-ready broker admitted before adapter")
    timeout = seconds()
    return invoke_adapter(product=product, source=source, manifest=manifest, manifest_sha256=manifest_sha256,
                          journal=journal, timeout=timeout)


class _ArtifactTap:
    """Keeps the artifact metadata that lifecycle_artifact already authenticated; every other read is delegated."""
    def __init__(self, inner):
        self._inner, self.metadata = inner, {}

    def read(self, path, **kwargs):
        value = self._inner.read(path, **kwargs)
        head = f"repos/{c.REPOSITORY}/actions/artifacts/"
        if path.startswith(head) and not path.endswith("/zip"):
            self.metadata[int(path.removeprefix(head))] = value
        return value


def _operation_request(operation, *, owner, window, inputs):
    """The ABI2 request of one keeper operation, bound to the keeper window exactly as it is when the operation starts."""
    return c.canonical({"abi_version": 2, "operation": operation, "repository": c.REPOSITORY, "source_sha": owner["source_sha"],
                        "owner": {key: owner[key] for key in [*lc.OWNER_FIELDS, "owner_sha256"]},
                        "checkpoint_sha256": window["checkpoint_sha256"], "activation_sha256": c.sha(inputs["activation"]),
                        "stage": {key: window[key] for key in lc.ADAPTER_STAGE_FIELDS.split()},
                        "inputs": {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in inputs.items()}})


def _close_drain_journal(*, guard, owner, window, activation, expirations):
    """The close-drain ABI2 request, bound to the keeper window exactly as it is at the prepared event."""
    inputs = {"activation": activation, "expirations": expirations}
    return AdapterJournal(_operation_request("close-drain", owner=owner, window=window, inputs=inputs), operation="close-drain",
                          owner=owner, window=window, inputs=inputs, activation_sha256=c.sha(activation), guard=guard)


def _plan_activation(*, aws, api, governance, request, run, prepared, owner, window, guard, now):
    """Ratification 6974253889 section 3: the activation bytes and rendered targets of the authenticated plan carrier.

    The plan download joins api.expiries/api.digests, so close_expirations binds it as one more artifact.
    """
    from tools.cnesdata_delivery.lifecycle_runtime import private_payload
    current = c.loads(prepared["fence-origins.json"], canonical=True)["current_plan"]
    name = current["step"]
    step = governance["lifecycle_steps"].get(name)
    c.require(type(step) is dict and step.get("role") == "plan" and step.get("purpose") == "application-prepare"
              and step.get("mode") == "operational" and type(step.get("job_name")) is str, "activation plan step")
    tap = _ArtifactTap(api)
    job = _same_run_job(tap, run, kind="plan", job_name=step["job_name"], guard=guard)
    reference, public, _ = _same_run_publication(tap, run, owner, job, kind="plan", step=name, guard=guard, now=now)
    key = (c.REPOSITORY, reference["artifact_id"])
    api.expiries[key] = c.instant(tap.metadata[reference["artifact_id"]]["expires_at"])
    api.digests[key] = c.digest(reference["artifact_digest"].removeprefix("sha256:"))
    c.require(c.sha(public["index.json"]) == current["index_sha256"], "activation plan index")
    inputs = private_payload(aws, governance, request, run, public, guard=guard, names={"inputs.json"})[1]["inputs.json"]
    c.require(c.sha(inputs) == c.loads(prepared["approval.json"], canonical=True)["inputs_sha256"], "activation plan inputs")
    decoded = lc.inputs_envelope(inputs, owner=owner, window=window)
    c.require(decoded["activation_sha256"] == c.loads(prepared["fence-prepared.json"], canonical=True)["activation_sha256"],
              "activation bytes")
    return decoded["activation"]["payload"], decoded["rendered_targets"]


def _close_drain_seconds(window, credential_limit, now):
    """Largest whole-second timeout that phase_capacity still admits; sampled right before the child starts."""
    seconds = int(min(window["deadline"] - now - 158, credential_limit - now - 121))
    c.require(seconds >= 1, "close-drain capacity")
    lc.phase_capacity(window, now=now, credential_deadline=credential_limit, operation_seconds=seconds)
    return seconds


CLOSED_READY_PUBLICATION_SECONDS = 20


def _closed_ready_seconds(window, credential_limit, now):
    """Largest API-stage child timeout that still leaves the DD-2 publication slot admitted by phase_capacity."""
    seconds = int(min(window["deadline"] - now - 38, credential_limit - now - 121)) - CLOSED_READY_PUBLICATION_SECONDS
    c.require(seconds >= 1, "closed-ready capacity")
    lc.phase_capacity(window, now=now, credential_deadline=credential_limit, operation_seconds=seconds)
    lc.phase_capacity(window, now=now + seconds, credential_deadline=credential_limit,
                      operation_seconds=CLOSED_READY_PUBLICATION_SECONDS)
    return seconds


ROUTE_REVISIONS = ("unit", "recovery", "audit")
TASK_REVISION = re.compile(r"arn:aws:ecs:us-east-2:\d{12}:task-definition/[A-Za-z0-9_-]{1,255}:[1-9][0-9]{0,9}")


def _state_point(checkpoint):
    return dict(c.closed(dict(checkpoint["state"]), "lineage serial state_sha256"),
                object_version=checkpoint["state_object"]["version_id"])


STATE_MACHINE_REVISION = re.compile(r"arn:aws:states:[a-z0-9-]+:\d{12}:stateMachine:[A-Za-z0-9_-]+")
B_MOMENTS = ("artifact_created_at", "job_completed_at")


def _phase_b_approval(published):
    approval = c.loads(published["approval.json"], canonical=True)
    delta = approval.get("delta") if type(approval) is dict else None
    mode = delta.get("mode") if type(delta) is dict else None
    c.require(mode != "established", "phase_b=established_mode_unsupported")
    c.require(mode == "initial", "phase_b=mode")
    return approval


def _phase_b_observed_at(close, moments, admitted_at):
    """The latest authenticated B publication moment inside drain <= observed_at <= API admission."""
    drain = c.instant(close["drain_observed_at"])
    c.closed(moments, " ".join(B_MOMENTS))
    inside = [moment for moment in (c.instant(moments[name]) for name in B_MOMENTS) if drain <= moment <= admitted_at]
    c.require(bool(inside), "phase_b=observed_at_bounds")
    return c.utc(max(inside))


def api_phase_b_evidence(*, close_raw, prepared, published, moments, admitted_at, revisions):
    """The product Phase B evidence that closed-ready and the host gate read, checked against B and the close-drain.

    Args: close-drain observation bytes, prepared fence package, authenticated B publication and its job/artifact
    moments, API admission, plan-carrier revisions. Returns: canonical phase-b bytes.
    Raises: ValueError phase_b=<reason>; established mode refuses before anything is built.
    """
    approval = _phase_b_approval(published)
    close = c.closed(c.loads(close_raw, canonical=True, limit=1024**2), lc.CLOSE_DRAIN_FIELDS)
    before = c.loads(prepared["checkpoint.json"], canonical=True)
    after = c.loads(published["checkpoint.json"], canonical=True)
    c.require(approval["checkpoint_sha256"] == c.sha(prepared["checkpoint.json"]) and approval["plan_sha256"] == after["plan_sha256"]
              and after["purpose"] == "phase-b", "phase_b=ancestry")
    first, last = _state_point(before), _state_point(after)
    c.require(first["lineage"] == last["lineage"] and first["serial"] < last["serial"]
              and first["object_version"] != last["object_version"], "phase_b=checkpoint_not_advanced")
    machines = [row["observed"].get("stateMachineArn") for row in after["readbacks"]
                if row["service"] == "stepfunctions" and row["operation"] == "describe_state_machine"]
    c.require(len(machines) == 1 and type(machines[0]) is str and STATE_MACHINE_REVISION.fullmatch(machines[0]) is not None,
              "phase_b=state_machine_readback")
    c.require(set(revisions) == set(ROUTE_REVISIONS)
              and all(type(value) is str and TASK_REVISION.fullmatch(value) for value in revisions.values()), "phase_b=revisions")
    routes = {"mode": "initial", "state_machine_arn": machines[0], "unit_environment_state_machine_arn": machines[0],
              "recovery_environment_state_machine_arn": machines[0]} | {mode + "_revision": revisions[mode] for mode in ROUTE_REVISIONS}
    return c.canonical({"version": 1, "kind": "phase-b", "common": close["common"], "close_drain_sha256": c.sha(close_raw),
                        "before": first, "after": last, "plan_sha256": after["plan_sha256"],
                        "audit_sha256": c.sha(published["approval.json"]), "apply_sha256": c.sha(published["checkpoint.json"]),
                        "routes": routes, "observed_at": _phase_b_observed_at(close, moments, admitted_at)})


def _drop_operation_clients(broker):
    """The keeper retains the broker: drop the operation and fence clients, ledgers included, and keep the journal."""
    if broker is None:
        return
    for ledger in broker.evidence:
        ledger._aws = None
    broker.aws = broker.session.evidence = broker.session.client = None


def _frozen_membership(close_raw):
    """The closed-ready membership input: the frozen members and commitment of the keeper close-drain observation."""
    close = c.closed(c.loads(close_raw, canonical=True, limit=1024**2), lc.CLOSE_DRAIN_FIELDS)
    return c.canonical({"frozen_membership_sha256": close["frozen_membership_sha256"], "members": close["members"]})


def _closed_ready_observation(keeper, journal, inputs):
    """The single closed-ready journal observation, bound to the close-drain and phase-b inputs, with no uncertainty."""
    observed = [entry for entry in journal._observations if entry["kind"] == "closed-ready"]
    raw = journal._observation_bytes.get(observed[0]["sha256"]) if len(observed) == len(journal._observations) == 1 else None
    value = c.loads(raw, canonical=True, limit=1024**2) if type(raw) is bytes else None
    c.require(type(value) is dict and set(value) == set(CLOSED_READY_FIELDS.split()) and type(value["version"]) is int
              and value["version"] == 1 and value["kind"] == "closed-ready"
              and value["close_drain_sha256"] == c.sha(inputs["close-drain"]) and value["phase_b_sha256"] == c.sha(inputs["phase-b"])
              and not keeper.uncertainty(), "closed-ready single observation bound to its inputs without uncertainty")
    return raw


CLOSED_READY_PROBE = "closed-ready"
CLOSED_READY_MEMBERS = frozenset({"close-drain.json", "phase-b.json", "closed-ready.json"})


def publish_closed_ready(*, keeper, api, run, owner, files, credential_limit, clock=time.time):
    """DD-2 (2b): upload cnesdata-closed-ready-<run>-<attempt> from the keeper job while the caller probe job runs.

    The host gate binds the artifact to the probe job only by name and interval (HG validate_closed_ready).
    Args: original keeper, GitHub reader, run, owner binding, the three member bytes, credential limit.
    Returns: the verified upload receipt. Raises: ValueError before upload without a running probe.
    """
    import tempfile
    from pathlib import Path
    from tools.cnesdata_delivery import lifecycle_runtime as lr, runtime
    c.require(set(files) == CLOSED_READY_MEMBERS and all(type(raw) is bytes and raw for raw in files.values())
              and sum(len(raw) for raw in files.values()) <= 1024**2, "closed-ready artifact members")
    guard = KeeperGuard(keeper)
    probe = _same_run_job(api, run, kind="closed-ready", job_name=CLOSED_READY_PROBE, guard=guard)
    c.require(probe is not None and probe["status"] == "in_progress", "closed-ready probe in progress before publication")
    window = keeper.lease.check()["lifecycle"]
    watchdog = lr.LifecycleWatchdog(keeper.lease, window, credential_limit, clock=clock, monotonic=keeper.monotonic)
    with tempfile.TemporaryDirectory(prefix="cnesdata-closed-ready-") as directory:
        temp = Path(directory)
        temp.chmod(0o700)
        public = temp / "public"
        public.mkdir()
        for name, raw in sorted(files.items()):
            (public / name).write_bytes(raw)
        receipt = runtime._upload(public, f"cnesdata-closed-ready-{owner['run_id']}-{owner['run_attempt']}", watchdog, temp)
    guard.check(20)
    runtime._verify_current_artifact(api, receipt, dict(files), run["id"])
    guard.check()
    return receipt


def stage_handlers(*, keeper, aws, api, governance, request, run, authority, product, credential_limit, operation_session,
                   clock=time.time):
    """Handlers of the three ratified stage triggers (amendment 6886977054 decision 3, ratification 6974253889, P02 DD-3).

    prepared: authenticated fence package, activation from the plan carrier, close-drain, close window.
    phase-b: B checkpoint ancestry from the prepared checkpoint, API window, then the API operation: closed-ready
    and its DD-2 publication. host: the accepted host handoff of that closed-ready, static window. The static
    stage ends this slice.
    """
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    state = {}

    def prepared(current, reference):
        guard = KeeperGuard(current)
        record = current.lease.check()
        window, owner = record["lifecycle"], lc.owner_binding(record)
        files = lr.fence_prepared_payload(api, aws, governance, request, run, reference, owner=owner, now=clock(),
            predecessor_raw=current.predecessor["raw"], predecessor_reference=current.predecessor_reference, guard=guard)
        activation, targets = _plan_activation(aws=aws, api=api, governance=governance, request=request, run=run,
                                               prepared=files, owner=owner, window=window, guard=guard, now=clock())
        journal = _close_drain_journal(guard=guard, owner=owner, window=window, activation=activation,
                                       expirations=close_expirations(authority, api))
        current.attach(journal)
        broker = close_drain_capability(aws=aws, api=api, governance=governance, authority=authority, journal=journal,
            keeper=current, prepared=files, credential_limit=credential_limit, operation_session=operation_session, clock=clock)
        try:
            seconds = _close_drain_seconds(window, credential_limit, clock())
            invoke_adapter(product=product, source=owner["source_sha"], manifest=governance["application_product_source_manifest"],
                           manifest_sha256=governance["application_product_source_closure_sha256"], journal=journal, timeout=seconds)
        finally:
            _drop_operation_clients(broker)
        observed = [entry for entry in journal._observations if entry["kind"] == "close-drain"]
        c.require(len(journal._observations) == len(observed) == 1 and not current.uncertainty(),
                  "close-drain single observation without uncertainty")
        closed = lc.close_window(current.lease.check()["lifecycle"], journal._observation_bytes[observed[0]["sha256"]],
                                 checkpoint_sha256=c.sha(files["checkpoint.json"]),
                                 infra_bound=infra_expiration_bound(authority, api), now=int(clock()))
        current.lease.checkpoint(closed)
        state.update({"prepared": files, "activation": activation, "close-drain": journal._observation_bytes[observed[0]["sha256"]],
                      "revisions": {"unit": targets["processor_active_unit_task_definition_arn"],
                                    "recovery": targets["scheduler_recovery_task_definition_arn"],
                                    "audit": targets["scheduler_audit_task_definition_arn"]}})

    def phase_b(current, reference):
        files = state.get("prepared")
        c.require(files is not None, "phase-b follows the prepared stage handled by this keeper")
        owner = lc.owner_binding(current.lease.check())
        published, moments = _phase_b_publication(api, aws, governance, request, run, owner, KeeperGuard(current), clock())
        b_checkpoint = c.loads(published["checkpoint.json"], canonical=True)
        b_approval = c.loads(published["approval.json"], canonical=True)
        c.require(b_approval["checkpoint_sha256"] == c.sha(files["checkpoint.json"])
                  and b_approval["plan_sha256"] == b_checkpoint["plan_sha256"] and b_checkpoint["purpose"] == "phase-b"
                  and c.canonical(b_checkpoint["owner"]) == c.canonical(owner), "preparation -> B checkpoint ancestry")
        admitted = clock()
        window = current.lease.check()["lifecycle"]
        c.require(admitted < lc.terminal_deadline(window), "phase-b stage deadline elapsed")
        current.lease.checkpoint(lc.api_window(window, checkpoint_sha256=c.sha(published["checkpoint.json"]),
                                               now=admitted))
        closed_ready(current, published, moments)

    def closed_ready(current, published, moments):
        files, close = state["prepared"], state["close-drain"]
        record = current.lease.check()
        window, owner = record["lifecycle"], lc.owner_binding(record)
        phase = api_phase_b_evidence(close_raw=close, prepared=files, published=published, moments=moments,
                                     admitted_at=window["admitted_at"], revisions=state["revisions"])
        inputs = {"activation": state["activation"], "close-drain": close, "membership": _frozen_membership(close), "phase-b": phase}

        def capability(*, journal, keeper, guard):
            return closed_ready_capability(aws=aws, api=api, governance=governance, request=request, run=run, journal=journal,
                                           keeper=keeper, prepared=files, credential_limit=credential_limit, guard=guard,
                                           operation_session=operation_session, revisions=state["revisions"], clock=clock)
        try:
            run_closed_ready(keeper=current, request_raw=_operation_request("closed-ready", owner=owner, window=window, inputs=inputs),
                             owner=owner, window=window, inputs=inputs, activation_sha256=c.sha(inputs["activation"]),
                             capability=capability, product=product, source=owner["source_sha"],
                             manifest=governance["application_product_source_manifest"],
                             manifest_sha256=governance["application_product_source_closure_sha256"],
                             seconds=lambda: _closed_ready_seconds(window, credential_limit, clock()))
        finally:
            for item in current._contexts:
                if type(item) is AdapterJournal and item._request["operation"] == "closed-ready":
                    _drop_operation_clients(getattr(item, "_broker", None))
        (journal,) = [item for item in current._contexts
                      if type(item) is AdapterJournal and item._request["operation"] == "closed-ready"]
        raw = _closed_ready_observation(current, journal, inputs)
        publish_closed_ready(keeper=current, api=api, run=run, owner=owner, credential_limit=credential_limit, clock=clock,
                             files={"close-drain.json": close, "phase-b.json": inputs["phase-b"], "closed-ready.json": raw})
        state["closed-ready"] = c.sha(raw)

    def host(current, reference):
        c.closed(reference, "job_id")
        ready = state.get("closed-ready")
        c.require(ready is not None, "host follows the closed-ready run of this keeper")
        owner = lc.owner_binding(current.lease.check())
        raw = authenticate_host_handoff(api, owner, guard=KeeperGuard(current))
        handoff = _versioned(c.loads(raw, canonical=True, limit=HOST_MEMBER_LIMIT), "host-handoff", HOST_HANDOFF_FIELDS)
        c.require(handoff["status"] == "accepted" and handoff["closed_ready_sha256"] == ready,
                  "host handoff accepted for the keeper closed-ready")
        c.require(not current.uncertainty(), "host handoff with unresolved keeper uncertainty")
        admitted = clock()
        window = current.lease.check()["lifecycle"]
        c.require(admitted < lc.terminal_deadline(window), "api stage deadline elapsed")
        current.lease.checkpoint(lc.static_window(window, now=admitted))

    return {"prepared": prepared, "phase-b": phase_b, "host": host}


KEEPER_EVENTS = ("prepared", "phase-b", "host")


def keeper_loop(keeper, *, next_event, handlers, poll=5, sleep=time.sleep):
    """The single keeper polling loop over the three ratified stage triggers; it never returns.

    next_event is the authenticated event producer and handlers holds exactly the three stage
    handlers. After the static stage the producer refuses and the lease stays held (R18): there
    is no finish, terminal publication or dispatch here. Any exception leaves the lease held.
    """
    c.require(type(handlers) is dict and set(handlers) == set(KEEPER_EVENTS), "closed keeper handlers")
    c.integer(poll, 1, 25)
    while True:
        keeper.tick()
        event = next_event(keeper.lease.check()["lifecycle"])
        if event is None:
            sleep(poll)
            continue
        c.closed(event, "kind reference")
        c.require(event["kind"] in KEEPER_EVENTS, "closed keeper event")
        handlers[event["kind"]](keeper, event["reference"])


def _verify_session(client, governance, authority, run, expires):
    """Exact own-role session readback shared by credentials and execute; returns the expiry/freeze guard."""
    from tools.cnesdata_delivery import session_owner
    class Guard:
        def check(self, seconds=0):
            c.require(time.time() + seconds < expires <= min(authority.expires_at,
                      c.instant(authority.application_fragment["enabled_until"])), "original bootstrap credential/freeze window")
    report = session_owner.verify_application(client, authority, expires, Guard(), clock=time.time, include_documents=True)
    name = f"cnesdata-{run['id']}-{run['run_attempt']}"
    expected = authority.application_fragment["application_role_arn"].replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + name
    c.require(all(client.identity.get(key) == expected_value for key, expected_value in
                     {"Account": governance["account_id"], "Arn": expected, "UserId": report["role_id"] + ":" + name}.items()),
              "original bootstrap GetCallerIdentity")
    return Guard()


def execute(admitted, *, validators=None, event_source=None, product=None):
    """Operational keeper entry: compose the original keeper and run the stage loop to the static stage.

    The order is the contract: release, adapter closure, owner authority, credential window, AWS and
    session readback, lease binding, keeper, validators, acquire, event source, handlers, loop.
    """
    import os
    from pathlib import Path
    from tools.cnesdata_delivery import lifecycle_runtime as lr, session_owner, session_policy
    validators = TERMINAL_VALIDATORS if validators is None else validators
    event_source = KEEPER_EVENT_SOURCE if event_source is None else event_source
    c.require(type(validators) is dict and {"quiescence", "routing"} <= set(validators) <= set(TERMINAL_VALIDATOR_FACTS),
              "terminal validator unavailable; lifecycle disabled")
    c.require(callable(event_source), "keeper event producer not connected; lifecycle disabled")
    governance, request, step, api, run, _ = admitted
    release_sha256 = application_release_sha256(governance)
    product = Path.cwd() / "product" if product is None else product
    authenticate_adapter_closure(product, request["source_sha"], governance["application_product_source_manifest"],
                                 governance["application_product_source_closure_sha256"])
    authority = session_owner.authenticate_lifecycle(governance, api, request["source_sha"],
                                                     "application", "application-prepare", time.time())
    c.require(type(os.environ.get("AWS_CREDENTIAL_EXPIRATION")) is str, "application credential expiration")
    expires = c.instant(os.environ["AWS_CREDENTIAL_EXPIRATION"])
    c.require(time.time() < expires, "application credential expiration")
    credential_limit = min(expires, authority.expires_at, c.instant(authority.application_fragment["enabled_until"]))
    aws = lr.AWS(governance)
    _verify_session(aws, governance, authority, run, expires)
    caller = governance["authenticated_application_caller"]
    session = c.sha(c.canonical({"principal": aws.identity["Arn"], "run_id": run["id"], "run_attempt": run["run_attempt"],
                                 "gate": "application"}))
    binding = {"repository": c.REPOSITORY, "source_sha": request["source_sha"], "run_id": run["id"],
               "run_attempt": run["run_attempt"], "session_sha256": session, "release_sha256": release_sha256,
               "lifecycle_version": 1, "application_purpose": caller["application_purpose"],
               "context_kind": caller["context_kind"], "caller_binding_sha256": c.sha(c.canonical(caller))}
    keeper = Keeper(lr.S3LeaseStore(aws), binding, lambda previous: authenticated_previous(aws, api, governance, previous),
                    api=api, governance=governance, evidence_aws=aws)
    register_terminal_validators(keeper, validators)
    owner = keeper.acquire(preparation_deadline=int(keeper.clock()) + 900)
    next_event = event_source(api=api, governance=governance, run=run, owner=owner, guard=KeeperGuard(keeper), clock=keeper.clock)
    def operation_session(operation, role, stage):
        c.require(operation in ("close-drain", "closed-ready"), "operation session operation")
        restriction = session_policy.application_request(governance, request["source_sha"], run["id"], run["run_attempt"], operation,
            application_purpose="promotion", delegations=("fence_operator",), sessions={"fence_operator": role["session_name"]})
        value = lr.oidc_credentials(governance, "application", restriction, run, duration=900)
        client = lr.AWS(governance, credentials=value)
        c.require(all(client.identity[key] == aws.identity[key] for key in ("Account", "Arn", "UserId")), "operation session identity")
        c.require(value["Expiration"].timestamp() >= stage["deadline"], "operation session expiration")
        return client

    handlers = stage_handlers(keeper=keeper, aws=aws, api=api, governance=governance, request=request, run=run,
                              authority=authority, product=product, credential_limit=credential_limit,
                              operation_session=operation_session, clock=keeper.clock)
    keeper_loop(keeper, next_event=next_event, handlers=handlers)


def credentials(admitted, *, product=None):
    """Bootstrap own-role credentials with no product delegation authority.

    Operation credentials must be separately admitted after private originals;
    this session cannot AssumeRole even if the own managed policy allows it.
    """
    from pathlib import Path
    from tools.cnesdata_delivery import lifecycle_runtime as lr, session_owner, session_policy
    governance, request, step, api, run, _ = admitted
    product = Path.cwd() / "product" if product is None else product
    manifest = governance["application_product_source_manifest"]
    closure = governance["application_product_source_closure_sha256"]
    authenticate_adapter_closure(product, request["source_sha"], manifest, closure)
    authority = session_owner.authenticate_lifecycle(governance, api, request["source_sha"],
                                                     "application", "application-prepare", time.time())
    restriction = session_policy.application_request(governance, request["source_sha"], run["id"], run["run_attempt"],
        request["step"], application_purpose=request["application_purpose"])
    value = lr.oidc_credentials(governance, "application", restriction, run)
    expires = value["Expiration"].timestamp()
    client = lr.AWS(governance, credentials=value)
    guard = _verify_session(client, governance, authority, run, expires)
    authenticate_adapter_closure(product, request["source_sha"], manifest, closure)
    guard.check()
    lr.export_credentials(value)


def verify_source_closure(governance, api, *, root=None):
    """Recompute the producer closure right after admission (#55 2nd slice, decision 1).

    Python files are the executing tree; the reusable is read at the gate pin,
    never at workflow_sha, which inside a reusable can be the caller's SHA.
    """
    import base64
    import hashlib
    from pathlib import Path
    pin = c.digest(governance["gate_shas"]["application"], 40)
    root = Path(__file__).resolve().parents[2] if root is None else root

    def read(path):
        if path != lc.APPLICATION_GATE_WORKFLOW:
            return (root / path).read_bytes()
        item = api.read(f"repos/{lc.APPLICATION_GATE_REPOSITORY}/contents/{path}?ref={pin}")
        c.require(item["type"] == "file" and item["path"] == path and item["encoding"] == "base64"
                  and type(item["size"]) is int and 0 <= item["size"] <= 256 * 1024, "application gate workflow contents")
        raw = base64.b64decode(item["content"], validate=False)
        blob = hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()
        c.require(len(raw) == item["size"] and blob == item["sha"], "application gate workflow blob")
        return raw

    closure = lc.application_source_closure(read)
    c.require(closure == c.digest(governance["application_source_closure_sha256"]), "application producer closure")
    return closure


def closure(pin):
    """Print the producer closure of this checkout at pin, read by git cat-file, never the working tree."""
    import subprocess
    import sys
    c.digest(pin, 40)

    def read(path):
        return subprocess.run(["git", "cat-file", "blob", f"{pin}:{path}"], check=True, capture_output=True).stdout

    sys.stdout.write(lc.application_source_closure(read) + "\n")


def main(argv=None):
    """Public admission and own-role bootstrap; effects require private capability."""
    import argparse
    from tools.cnesdata_delivery import lifecycle_runtime, session_owner
    parser = argparse.ArgumentParser(description="Protected CnesData application gate")
    parser.add_argument("operation", choices=("preflight", "credentials", "execute", "closure"))
    parser.add_argument("--pin")
    args = parser.parse_args(argv)
    if args.operation == "closure":
        return closure(args.pin)
    c.require(args.pin is None, "pin is closure-only")
    admitted = lifecycle_runtime.admission("application")
    verify_source_closure(admitted[0], admitted[3])
    session_owner.application_fragment(admitted[0], time.time())
    if args.operation == "credentials":
        return credentials(admitted)
    if args.operation == "execute":
        return execute(admitted)
    return admitted


if __name__ == "__main__":
    main()
