"""Protected application admission, own-role bootstrap, keeper and finite IPC.

Operational execution remains disabled until complete capability admission and
the protected producer/keeper dispatch are connected. Defaults grant no access.
"""
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


def _terminal_inputs(assessment, window, inputs):
    c.require(type(inputs) is dict, "original terminal inputs")
    for digest in inputs.values():
        c.digest(digest)
    if assessment["kind"] == "accepted-open":
        c.require(window["stage"] == "final" and window["decision"] is None, "accepted terminal phase")
        required = {"unit", "recovery", "audit", "host", "static", "routing", "membership", "quiescence"}
    elif assessment["kind"] == "failed-closed-quiescent":
        c.require(window["stage"] == "recovery" and window["decision"] is not None, "original recovery terminal decision")
        required = {"decision", "restoration", "routing", "membership", "quiescence"}
    else:
        c.require(assessment["kind"] == "failed-prepare-quiescent" and window["close"] is None
                  and window["stage"] == "application-prepare" and window["decision"] is None,
                  "closed terminal kind/phase")
        required = {"restoration", "routing", "quiescence"}
    c.require(set(inputs) == required, "complete original terminal proofs")


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
    c.public_safe(index)
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
              and run["head_branch"] == "develop", "previous lifecycle run not terminal success; reviewed recovery required")
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
    c.public_safe(index)
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
import base64, importlib.util, sys
sys.path.insert(0, sys.argv[2])
from tools.cnesdata_delivery import contract as c
product = sys.argv[1]
sys.path.insert(0, product)
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
    """Shared-only result of the finite STS boundary; never exposed over IPC."""
    def __init__(self, client, commitment, scope, deadline, request_binding):
        self.client, self.commitment = client, c.digest(commitment)
        self.scope = c.loads(c.canonical(scope), canonical=True)
        self.deadline, self.request_binding = deadline, request_binding


def _assume_fence_session(*, aws, governance, role, scope, journal, prepared_sha256, credential_limit, clock=time.time):
    """Exact native delegation after the caller authenticates prepared authority.

    This internal boundary is not package admission. The shared dispatcher must
    supply the original protected role/scope, never adapter frame parameters.
    """
    from tools.cnesdata_delivery.aws_boundary import AWS
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    from tools.cnesdata_delivery.session_policy import validate_response
    c.require(type(journal) is AdapterJournal and journal._request["operation"] == "closed-ready"
              and journal._identity["application_purpose"] == "promotion", "fence original promotion journal")
    request, stage = journal._request, journal._request["stage"]
    c.require(stage["stage"] == "api" and stage["deadline"] == min(stage["fixed_deadline"], stage["admitted_at"] + 180)
              and stage["fixed_deadline"] - stage["admitted_at"] >= 1440
              and stage["admitted_at"] <= clock() and clock() + 40 < stage["deadline"]
              and clock() + 900 <= credential_limit, "fence original API/credential window")
    c.closed(scope, "account control_table_arn machine_arn members")
    c.require(scope["account"] == governance["account_id"] and governance["role"] == "application"
              and role["role_arn"] == governance["application_delegations"]["fence_operator"]
              and role["role_name"] == "cnesdata-prod-promotion-fence-operator"
              and role["role_arn"] == "arn:aws:iam::" + scope["account"] + ":role/" + role["role_name"]
              and role["session_name"] == "promotion-fence-" + role["release_id"]
              and type(role["role_id"]) is str and bool(role["role_id"]), "fence exact protected role/session")
    probe_prefix = scope["machine_arn"].replace(":stateMachine:", ":execution:") + ":"
    for pk, sk in (("ENV#prod#FENCE", "FENCE"), ("ENV#prod#SEMAPHORE", "UNIT")):
        lc.validate_closed_ready_call(request=request, role="fence_operator", service="dynamodb", operation="get_item",
            parameters={"TableName": scope["control_table_arn"].rsplit("/", 1)[1], "Key": {"pk": {"S": pk}, "sk": {"S": sk}},
                        "ConsistentRead": True}, **scope)
    for member in scope["members"]:
        lc.validate_closed_ready_call(request=request, role="fence_operator", service="stepfunctions", operation="describe_execution",
            parameters={"executionArn": probe_prefix + member["dispatch_id"], "includedData": "METADATA_ONLY"}, **scope)
    from tools.cnesdata_delivery.session_policy import fence_session_policy
    policy = fence_session_policy(control_table_arn=scope["control_table_arn"], execution_prefix=probe_prefix,
                                  deadline=stage["deadline"])
    encoded = c.canonical(policy).decode().strip()
    c.require(len(encoded) <= 2048, "fence STS policy limit")
    context = {"aws:CurrentTime": c.utc(clock())}
    for key in ("ENV#prod#FENCE", "ENV#prod#SEMAPHORE"):
        c.require(effective_iam(role["policy"], [policy], "dynamodb:GetItem", scope["control_table_arn"],
                                context | {"dynamodb:LeadingKeys": [key]}), "fence original effective strong-read grant")
    c.require(effective_iam(role["policy"], [policy], "states:DescribeExecution", probe_prefix + "0" * 16, context),
              "fence original effective metadata-probe grant")
    journal._guard.check(40)
    journal.guard()
    response = aws.call("sts", "assume_role", RoleArn=role["role_arn"], RoleSessionName=role["session_name"],
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
    c.require(clock() + 20 < stage["deadline"], "fence STS completed in original API window")
    binding = c.sha(c.canonical(request))
    commitment = c.sha(c.canonical({"prepared_sha256": c.digest(prepared_sha256), "request_sha256": binding,
        "role_arn": role["role_arn"], "role_id": role["role_id"], "session_name": role["session_name"],
        "policy_sha256": c.sha(c.canonical(policy)), "expires_at": c.utc(expiry.timestamp()),
        "account": scope["account"], "arn": expected_arn, "user_id": expected_id}))
    return _FenceSession(client, commitment, scope, stage["deadline"], binding)


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
        c.require(self._request["operation"] == "closed-ready" and request["role"] == "fence_operator"
                  and (request["service"], request["operation"]) in {("dynamodb", "get_item"), ("stepfunctions", "describe_execution")},
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
            allowed = ({"Item"} if request["service"] == "dynamodb" else
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
        from tools.cnesdata_delivery.lifecycle_runtime import namespace
        c.require(type(journal) is AdapterJournal and governance["role"] == "application", "shared closed-ready journal")
        c.closed(scope, "account control_table_arn machine_arn members")
        c.require(scope["account"] == governance["account_id"], "original journal account")
        native = c.loads(native_raw, canonical=True, limit=128 * 1024)
        c.closed(native, "role service operation parameters")
        lc.validate_closed_ready_call(request=journal._request, **native, **scope)
        _sdk_private_fields(native)
        request = journal._request
        sequence, previous = journal._next_durable()
        intent = {"schema_version": 2, "operation": "closed-ready", "owner": request["owner"],
                  "sequence": sequence, "previous_receipt_sha256": previous,
                  "caller": journal._identity, "adapter_request_sha256": c.sha(c.canonical(request)),
                  "checkpoint_sha256": request["checkpoint_sha256"], "activation_sha256": request["activation_sha256"],
                  "prepared_sha256": c.digest(prepared_sha256), "role_session_sha256": c.digest(role_session_sha256),
                  "call": native}
        self._intent_raw = c.canonical(intent, limit=128 * 1024)
        self.intent_sha256 = c.sha(self._intent_raw)
        # Proof/session/activation changes collide at the same operation locus;
        # they cannot mint another ticket after an unresolved native call.
        operation_sha256 = c.sha(c.canonical({key: intent[key] for key in ("schema_version", "operation", "owner", "caller", "checkpoint_sha256", "sequence")}))
        self._sequence, self._previous = sequence, previous
        owner = request["owner"]
        prefix = namespace(governance, {"source_sha": request["source_sha"], "step": "closed-ready"},
                           {"id": owner["run_id"], "run_attempt": owner["run_attempt"]})
        self._keys = {name: prefix + "sdk-" + operation_sha256[:40] + "-" + name + ".json" for name in self.SUFFIXES}
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
    """Finite private SDK dispatcher with a durable reservation before native IO."""
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
        lc.validate_closed_ready_call(request=journal._request, role=role, service=service, operation=operation,
                                      parameters=parameters, **session.scope)
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
                          and any(member["resolution"] == "CANCEL_BEFORE_SEND" and member["execution_ref"] is None
                                  and parameters["executionArn"] == session.scope["machine_arn"].replace(":stateMachine:", ":execution:") + ":" + member["dispatch_id"]
                                  for member in session.scope["members"]), "native SDK outcome unknown")
                absent = True
            metadata = response.get("ResponseMetadata", {})
            c.require(type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == (400 if absent else 200),
                      "native SDK authenticated status")
            if absent:
                value = {"Error": {"Code": "ExecutionDoesNotExist"}}
            elif service == "dynamodb":
                c.require(set(response) <= {"Item", "ResponseMetadata"}, "finite native DynamoDB response")
                value = {key: response[key] for key in ("Item",) if key in response}
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


class Keeper:
    """One process alone owns CAS; delegates consume read-only lease views.

    authenticate_previous is the original successful-publication validator,
    returning its authenticated private checkpoint and protected full reference.
    Admission independently authenticates the reference before any lease write.
    """
    def __init__(self, store, binding, authenticate_previous, *, api, governance, authenticate_terminal=None, evidence_aws=None, clock=time.time, monotonic=time.monotonic):
        c.require(binding.get("lifecycle_version") == 1, "lifecycle keeper binding")
        self.store, self.clock, self.monotonic = store, clock, monotonic
        self.authenticate_previous = authenticate_previous
        self.api, self.governance = api, governance
        self.predecessor_reference = None
        self.authenticate_terminal = authenticate_terminal
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
        c.require(callable(self.authenticate_terminal), "terminal validator unavailable; lifecycle disabled")
        c.require(not self.uncertainty(), "unresolved SDK uncertainty; lease remains held")
        record = self.lease.check()
        owner, window = lc.owner_binding(record), record["lifecycle"]
        proof = self.authenticate_terminal(reference, owner, dict(window))
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
    class Guard:
        def check(self, seconds=0):
            c.require(time.time() + seconds < expires <= min(authority.expires_at,
                      c.instant(authority.application_fragment["enabled_until"])), "original bootstrap credential/freeze window")
    client = lr.AWS(governance, credentials=value)
    report = session_owner.verify_application(client, authority, expires, Guard(), clock=time.time, include_documents=True)
    name = f"cnesdata-{run['id']}-{run['run_attempt']}"
    expected = authority.application_fragment["application_role_arn"].replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + name
    c.require(all(client.identity.get(key) == expected_value for key, expected_value in
                     {"Account": governance["account_id"], "Arn": expected, "UserId": report["role_id"] + ":" + name}.items()),
              "original bootstrap GetCallerIdentity")
    authenticate_adapter_closure(product, request["source_sha"], manifest, closure)
    Guard().check()
    lr.export_credentials(value)


def main(argv=None):
    """Public admission and own-role bootstrap; effects require private capability."""
    import argparse
    from tools.cnesdata_delivery import lifecycle_runtime, session_owner
    parser = argparse.ArgumentParser(description="Protected CnesData application gate")
    parser.add_argument("operation", choices=("preflight", "credentials", "execute"))
    args = parser.parse_args(argv)
    admitted = lifecycle_runtime.admission("application")
    session_owner.application_fragment(admitted[0], time.time())
    if args.operation == "credentials":
        return credentials(admitted)
    c.require(args.operation == "preflight", "application effect boundary not connected; execution disabled")
    return admitted


if __name__ == "__main__":
    main()
