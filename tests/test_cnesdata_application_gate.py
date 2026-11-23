"""Offline legacy original checkpoint -> continuous lifecycle owner entry."""
import copy
import json
import os
import time
import types

import pytest

from tools.cnesdata_delivery import contract as c, runtime
from tools.cnesdata_delivery.application_gate import Keeper
from tools.cnesdata_delivery.lifecycle_runtime import first_checkpoint
from tools.cnesdata_delivery.aws_boundary import S3LeaseStore
from tools.cnesdata_delivery.provenance import GitHub


@pytest.mark.parametrize("mutation", [None, "omitted-helper", "manifest-digest", "edited-helper", "untracked-shadow", "ignored-shadow", "symlink"])
def test_adapter_preflight_authenticates_complete_original_tree_without_import(tmp_path, mutation):
    import subprocess
    from tools.cnesdata_delivery.application_gate import authenticate_adapter_closure
    def git(*args):
        return subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True).stdout.decode().strip()
    git("init", "-q")
    originals = {"scripts/promotion/promote_api.py": b'raise AssertionError("preflight must not import adapter")\n',
                 "scripts/promotion/helper.py": b"VALUE = 1\n", "assets/routes.json": b'{"version":1}\n',
                 ".gitignore": b"*.pyc\n"}
    for name, raw in originals.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "original adapter source")
    source = git("rev-parse", "HEAD")
    manifest = {"version": 1, "source_sha": source, "files": {name: c.sha(raw) for name, raw in originals.items()}}
    if mutation == "omitted-helper": manifest["files"].pop("scripts/promotion/helper.py")
    digest = c.sha(c.canonical(manifest))
    if mutation == "manifest-digest": digest = "0" * 64
    if mutation == "edited-helper": (tmp_path / "scripts/promotion/helper.py").write_bytes(b"VALUE = 2\n")
    if mutation == "untracked-shadow": (tmp_path / "helper.py").write_bytes(b"VALUE = 3\n")
    if mutation == "ignored-shadow": (tmp_path / "helper.pyc").write_bytes(b"shadow compiled module")
    if mutation == "symlink":
        helper = tmp_path / "scripts/promotion/helper.py"
        helper.unlink()
        helper.symlink_to("promote_api.py")
    if mutation is None:
        assert authenticate_adapter_closure(tmp_path, source, manifest, digest) == originals
    else:
        with pytest.raises(ValueError): authenticate_adapter_closure(tmp_path, source, manifest, digest)


def _current_caller(governance, binding, purpose="promotion"):
    """Protected-current-caller fixture; public provenance is exercised separately."""
    from tools.cnesdata_delivery import lifecycle_contract as lc
    governance.setdefault("gate_shas", {}).setdefault("application", "a" * 40)
    governance.setdefault("application_source_closure_sha256", "d" * 64)
    producer = {"workflow_sha": governance["gate_shas"]["application"],
                "source_closure_sha256": governance["application_source_closure_sha256"]}
    caller = lc.application_caller_binding({"application_purpose": purpose, "context_kind": lc.APPLICATION_CONTEXTS[purpose],
        **lc.APPLICATION_CALLERS[purpose], "source_sha": binding["source_sha"], "run_id": binding["run_id"],
        "run_attempt": binding["run_attempt"], "producer_workflow_sha": producer["workflow_sha"],
        "producer_source_closure_sha256": producer["source_closure_sha256"], "event": "workflow_dispatch", "fragment_version": 4}, producer)
    governance.update(authenticated_application_caller=caller, application_purpose=purpose, context_kind=lc.APPLICATION_CONTEXTS[purpose])
    return {"application_purpose": purpose, "context_kind": lc.APPLICATION_CONTEXTS[purpose],
            "caller_binding_sha256": c.sha(c.canonical(caller))}


def _phase_a_release_sha256():
    """sha256 of the original Phase A plan release in the SYNTHETIC `_phase_a_carrier_case`."""
    envelope = c.loads(_phase_a_carrier_case()[1]["envelope.json"], canonical=True)
    return c.sha(c.canonical(envelope["plan"]["release"]))


def test_original_legacy_checkpoint_enters_new_keeper_without_relabeling(monkeypatch, tmp_path):
    from tools.cnesdata_delivery.application_gate import authenticated_previous
    chain, aws, api, store, previous, reference = _legacy_history_fixture(monkeypatch, tmp_path)
    original = copy.deepcopy(previous)
    reads = []
    def authenticate(value):
        reads.append(copy.deepcopy(value))
        return authenticated_previous(aws, api, chain.gov, value)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": _phase_a_release_sha256(), "session_sha256": "d" * 64, "lifecycle_version": 1}
    binding |= _current_caller(chain.gov, binding)
    keeper = Keeper(store, binding, authenticate, api=api, governance=chain.gov)
    state_reader = aws.get_state
    def forbidden_state_read(*args, **kwargs):
        raise AssertionError("application keeper cannot read state")
    monkeypatch.setattr(aws, "get_state", forbidden_state_read)
    history = {key: value for key, value in chain.objects.items() if "/2/1/applied/" in key[1]}
    owner = keeper.acquire(preparation_deadline=int(time.time()) + 900)
    assert {key: value for key, value in chain.objects.items() if "/2/1/applied/" in key[1]} == history
    monkeypatch.setattr(aws, "get_state", state_reader)
    current, _ = store.get()
    assert reads == [original, original]
    assert owner["generation"] == 1 and owner["run_id"] == 44
    assert keeper.predecessor["lease"]["run_id"] == 2
    assert keeper.predecessor["lease"] == original
    assert current["lifecycle"]["checkpoint_sha256"] == original["checkpoint_sha256"]
    assert current["lifecycle"]["predecessor_sha256"] == c.sha(c.canonical(reference))
    assert owner["application_purpose"] == current["lifecycle"]["application_purpose"] == "promotion"
    assert owner["context_kind"] == current["lifecycle"]["context_kind"] == "promotion"
    assert owner["caller_binding_sha256"] == current["lifecycle"]["caller_binding_sha256"] == binding["caller_binding_sha256"]
    state, state_object = aws.get_state(absent=True)  # plan capability, never application IAM
    historical = first_checkpoint(keeper.predecessor, current, owner, state, state_object)
    assert historical == keeper.predecessor["checkpoint"]
    with pytest.raises(ValueError, match="historical actual state drift"):
        first_checkpoint(keeper.predecessor, current, owner, state, {"foreign": "state-version"})
    changed = copy.deepcopy(current)
    changed["lifecycle"]["sequence"] = 1
    with pytest.raises(ValueError, match="historical checkpoint only"):
        first_checkpoint(keeper.predecessor, changed, owner, state, state_object)
    assert keeper.predecessor["lease"] == original


@pytest.mark.parametrize("purpose", ["promotion", "mode-readiness-drill"])
@pytest.mark.parametrize("mutation", [None, "name", "attempt", "source", "created", "bytes", "status", "caller"])
def test_lifecycle_input_authenticates_original_completed_job_and_archive(purpose, mutation):
    import io
    import zipfile
    from tools.cnesdata_delivery.provenance import lifecycle_artifact
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("index.json", c.canonical({"version": 1}))
    raw = output.getvalue()
    run = {"id": 44, "run_attempt": 2, "head_sha": "b" * 40, "event": "workflow_dispatch",
           "repository": {"full_name": c.REPOSITORY}, "path": ".github/workflows/promote-production.yml"}
    if purpose == "mode-readiness-drill": run["path"] = ".github/workflows/readiness-production.yml"
    if mutation == "caller": run["path"] = ".github/workflows/foreign-production.yml"
    job = {"run_id": 44, "run_attempt": 2, "head_sha": "b" * 40, "name": "phase-b / apply",
           "status": "completed", "conclusion": "success", "started_at": c.utc(1000), "completed_at": c.utc(1100)}
    metadata = {"id": 4, "name": "lifecycle-phase-b-apply", "digest": "sha256:" + c.sha(raw),
                "workflow_run": {"id": 44, "head_sha": "b" * 40}, "expired": False,
                "expires_at": c.utc(2000), "created_at": c.utc(1050)}
    if mutation == "name": metadata["name"] = "lifecycle-other-job"
    if mutation == "attempt": job["run_attempt"] = 1
    if mutation == "source": job["head_sha"] = "a" * 40
    if mutation == "created": metadata["created_at"] = c.utc(1000)
    if mutation == "bytes": raw += b"changed"
    if mutation == "status": job["status"] = "in_progress"
    class API:
        def read(self, path, **kwargs):
            if path.endswith("/zip"): return raw
            if "/artifacts/" in path: return metadata
            if "/jobs/" in path: return job
            return run
    def read():
        return lifecycle_artifact(API(), {"artifact_id": 4, "artifact_digest": metadata["digest"], "job_id": 9},
            1200, source="b" * 40, run_id=44, attempt=2, producer_name="phase-b / apply",
            artifact_name="lifecycle-phase-b-apply", application_purpose=purpose)
    if mutation is None:
        assert read() == {"index.json": c.canonical({"version": 1})}
    else:
        with pytest.raises(ValueError):
            read()


@pytest.mark.parametrize("mutation", ["failed-run", "checkpoint-bytes"])
def test_released_predecessor_without_original_success_cannot_acquire(monkeypatch, tmp_path, mutation):
    from tools.cnesdata_delivery.application_gate import authenticated_previous
    chain, aws, api, store, _, _ = _legacy_history_fixture(monkeypatch, tmp_path)
    original, etag = store.get()
    if mutation == "failed-run":
        chain.runs[c.REPOSITORY, 2]["conclusion"] = "failure"
    else:
        key = next(key for key in chain.objects if "/2/1/applied/" in key[1] and key[1].endswith("checkpoint.json"))
        raw, version = chain.objects[key]
        chain.objects[key] = (raw + b"changed", version)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    binding |= _current_caller(chain.gov, binding)
    keeper = Keeper(store, binding, lambda previous: authenticated_previous(aws, api, chain.gov, previous), api=api, governance=chain.gov)
    with pytest.raises(ValueError):
        keeper.acquire(preparation_deadline=int(time.time()) + 900)
    assert store.get() == (original, etag)


def _admitted_terminal_keeper(store, binding, historical, proof, *, carrier=None):
    """Terminal unit setup only; real historical admission is tested separately."""
    from tools.cnesdata_delivery import lifecycle_contract as lc
    keeper = Keeper(store, binding, lambda previous: pytest.fail("terminal fixture must not enter history"),
                    api=None, governance=None, clock=lambda: 1000, monotonic=lambda: 1000)
    _register_synthetic_terminal_validators(keeper, proof)
    previous = store.get()[0]
    keeper.predecessor = {"lease": previous, "checkpoint": historical, "raw": c.canonical(historical)}
    keeper.lease.previous_success = lambda previous: True  # Test-only already-admitted lease setup.
    keeper.lease.acquire()
    keeper.lease.checkpoint({"sequence": 0, "preparation_deadline": 1900, "close": None,
        "fixed_deadline": None, "input_deadline": None, "stage": "application-prepare", "admitted_at": 1000,
        "deadline": 1900, "decision": None, "checkpoint_sha256": c.sha(c.canonical(historical)),
        "predecessor_sha256": "a" * 64, "windows": MINIMUM_WINDOWS, **lc.application_identity(binding)})
    keeper.last_renewed = 1000
    owner = lc.owner_binding(keeper.lease.check())
    keeper.phase_a_originals = _phase_a_carrier_case()[0] if carrier is None else copy.deepcopy(carrier)
    keeper.predecessor_reference = keeper.phase_a_originals["origin"]
    keeper.governance = {"evidence_bucket": "synthetic-evidence", "evidence_prefix": "cnesdata/prod/evidence/"}
    keeper.transport_raw = c.canonical({"version": 2, "owner": owner,
        "predecessor_sha256": c.sha(c.canonical(keeper.predecessor_reference)), "phase_a_originals": keeper.phase_a_originals})
    class Evidence:
        def get(self, bucket, key, *, maximum):
            assert key.endswith("/keeper/checkpoint.json")
            return keeper.transport_raw, "original-keeper-etag"
    keeper.evidence_aws = Evidence()
    return keeper, owner


def _register_synthetic_terminal_validators(keeper, proof):
    """SYNTHETIC labelled validators (item 8): the product adapter belongs to CnesData #473/#474."""
    def facts(kind, assessment):
        if kind in {"unit", "recovery", "audit"}: return {"accepted": kind in assessment["accepted_modes"]}
        if kind in {"host", "static"}: return {"accepted": True}
        if kind == "routing": return {key: assessment[key] for key in ("fence", "routes_match")}
        if kind == "membership": return {"resolved": True}
        if kind == "quiescence": return {key: assessment[key] for key in ("quiescent", "state_clean", "pending", "unknown", "observed_at")}
        if kind == "restoration": return dict(assessment["restoration"])
        return {}
    for kind in ("unit", "recovery", "audit", "host", "static", "routing", "membership", "quiescence", "decision", "restoration"):
        def validator(source, *, owner, window, observations, kind=kind):
            assert source == "synthetic-" + kind
            return {"sha256": proof["inputs"][kind], "facts": facts(kind, proof["assessment"])}
        keeper.register_terminal_validator(kind, validator, label="synthetic-test-" + kind)
    keeper._synthetic_terminal_proof = proof


def _terminal_reference(keeper):
    proof = keeper._synthetic_terminal_proof
    return {"kind": proof["assessment"]["kind"], "checkpoint_raw": c.canonical(proof["checkpoint"]),
            "sources": {name: "synthetic-" + name for name in proof["inputs"]}}


def _journal_with(*, pending=(), unknown=(), inflight=None, failed=False, observations=()):
    from tools.cnesdata_delivery.application_gate import AdapterJournal
    journal = AdapterJournal.__new__(AdapterJournal)
    journal._pending, journal._unknown, journal._inflight, journal._failed = list(pending), list(unknown), inflight, failed
    journal._observations = [{"kind": kind, "sha256": c.sha(raw), "size": len(raw)} for kind, raw in observations]
    journal._observation_bytes = {c.sha(raw): raw for _, raw in observations}
    return journal


def _accepted_terminal_case():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    class Store:
        def __init__(self):
            self.value, self.etag, self.writes = None, None, 0
        def get(self):
            return copy.deepcopy(self.value), self.etag
        def put(self, value, etag):
            assert etag == self.etag
            self.writes += 1
            self.value, self.etag = copy.deepcopy(value), str(self.writes)
            return self.etag
    historical = {"state_after": {"lineage": "original-lineage", "serial": 1, "state_sha256": "a" * 64}, "state_object": {"VersionId": "prior"}}
    store = Store()
    store.put({"status": "released", "checkpoint_sha256": c.sha(c.canonical(historical)), "run_id": 1}, None)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    proof = {}
    keeper, owner = _admitted_terminal_keeper(store, binding, historical, proof)
    checkpoint = {"owner": owner, "state": historical["state_after"], "state_object": historical["state_object"],
                  "phase_a_originals": keeper.phase_a_originals}
    window = store.get()[0]["lifecycle"]
    for stage, duration in MINIMUM_WINDOWS["stages"].items():
        window = window | {"sequence": window["sequence"] + 1, "close": 1000, "fixed_deadline": 2800,
                           "input_deadline": 3000, "stage": stage, "admitted_at": 1000, "deadline": 1000 + duration,
                           "checkpoint_sha256": c.sha(c.canonical(checkpoint))}
        keeper.lease.checkpoint(window)
    proof.update(assessment={"kind": "accepted-open", "fence": "OPEN", "accepted_modes": ["unit", "recovery", "audit"],
                             "routes_match": True, "state_clean": True, "quiescent": True, "pending": [], "unknown": [], "observed_at": 1000},
                 checkpoint=checkpoint,
                 inputs={name: "e" * 64 for name in ("unit", "recovery", "audit", "host", "static", "routing", "membership", "quiescence")})
    return keeper, store


class _MemoryStore:
    def __init__(self):
        self.value, self.etag, self.writes = None, None, 0

    def get(self):
        return copy.deepcopy(self.value), self.etag

    def put(self, value, etag):
        assert etag == self.etag
        self.writes += 1
        self.value, self.etag = copy.deepcopy(value), str(self.writes)
        return self.etag


def _prepare_stage_keeper(run_id=4242):
    """Real Keeper/Lease at the original application-prepare window (sequence 0); every later write is a real CAS."""
    historical = {"state_after": {"lineage": "original-lineage", "serial": 1, "state_sha256": "a" * 64}, "state_object": {"VersionId": "prior"}}
    store = _MemoryStore()
    store.put({"status": "released", "checkpoint_sha256": c.sha(c.canonical(historical)), "run_id": 1}, None)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": run_id, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    binding |= _current_caller({}, binding)
    keeper, _ = _admitted_terminal_keeper(store, binding, historical, {})
    return keeper, store


@pytest.mark.parametrize("context", ["pending", "unknown", "inflight", "failed", "foreign", "again"])
def test_keeper_retem_o_lease_enquanto_um_contexto_sdk_for_incerto(context):
    keeper, store = _accepted_terminal_case()
    reference = {"kind": "sdk-call", "reference_sha256": "f" * 64}
    if context == "foreign":
        with pytest.raises(ValueError, match="original adapter context"):
            keeper.attach(object())
        return
    settled = _journal_with()
    keeper.attach(settled)
    uncertain = {"pending": _journal_with(pending=[reference]), "unknown": _journal_with(unknown=[reference]),
                 "inflight": _journal_with(inflight=("t" * 64, {})), "failed": _journal_with(failed=True),
                 "again": settled}.get(context)
    keeper.attach(uncertain)
    before = store.get()
    if context == "again":
        files = keeper.finish(_terminal_reference(keeper))
        assert c.loads(files["terminal.json"], canonical=True)["coordination_status"] == "quiescent-released"
        return
    assert keeper.uncertainty()
    with pytest.raises(ValueError, match="unresolved SDK uncertainty"):
        keeper.finish(_terminal_reference(keeper))
    assert store.get() == before and store.get()[0]["status"] != "released"
    keeper.tick()
    assert store.get()[0]["status"] != "released"


@pytest.mark.parametrize("case", ["accepted", "unknown", "unit-closed", "failed-without-decision"])
def test_keeper_terminal_release_requires_full_original_decision(case):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    class Store:
        def __init__(self):
            self.value, self.etag, self.writes = None, None, 0
        def get(self):
            return copy.deepcopy(self.value), self.etag
        def put(self, value, etag):
            assert etag == self.etag
            self.writes += 1
            self.value, self.etag = copy.deepcopy(value), str(self.writes)
            return self.etag
    historical = {"state_after": {"lineage": "original-lineage", "serial": 1, "state_sha256": "a" * 64}, "state_object": {"VersionId": "prior"}}
    store = Store()
    store.put({"status": "released", "checkpoint_sha256": c.sha(c.canonical(historical)), "run_id": 1}, None)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    proof = {}
    keeper, owner = _admitted_terminal_keeper(store, binding, historical, proof)
    checkpoint = {"owner": owner, "state": historical["state_after"], "state_object": historical["state_object"],
                  "phase_a_originals": keeper.phase_a_originals}
    window = store.get()[0]["lifecycle"]
    for stage, duration in MINIMUM_WINDOWS["stages"].items():
        window = window | {"sequence": window["sequence"] + 1, "close": 1000, "fixed_deadline": 2800,
                           "input_deadline": 3000, "stage": stage, "admitted_at": 1000, "deadline": 1000 + duration,
                           "checkpoint_sha256": c.sha(c.canonical(checkpoint))}
        keeper.lease.checkpoint(window)
    assessment = {"kind": "accepted-open", "fence": "OPEN", "accepted_modes": ["unit", "recovery", "audit"],
                  "routes_match": True, "state_clean": True, "quiescent": True, "pending": [], "unknown": [], "observed_at": 1000}
    if case == "unknown": assessment["unknown"] = ["late-effect"]
    if case == "unit-closed": assessment.update(fence="CLOSED", accepted_modes=["unit"])
    if case == "failed-without-decision": assessment["kind"] = "failed-closed-quiescent"
    proof.update(assessment=assessment, checkpoint=checkpoint,
                 inputs={name: "e" * 64 for name in ("unit", "recovery", "audit", "host", "static", "routing", "membership", "quiescence")})
    before = store.get()
    if case != "accepted":
        with pytest.raises(ValueError): keeper.finish(_terminal_reference(keeper))

        assert store.get() == before
    else:
        files = keeper.finish(_terminal_reference(keeper))
        terminal = c.loads(files["terminal.json"], canonical=True)
        assert terminal["promotion_status"] == "accepted"
        assert terminal["coordination_status"] == "quiescent-released"
        assert store.get()[0]["status"] == "released"
        assert store.get()[0]["checkpoint_sha256"] == c.sha(files["checkpoint.json"])
        assert c.loads(files["lease.json"], canonical=True)["generation"] == 1
        with pytest.raises(ValueError): keeper.finish(_terminal_reference(keeper))


def _terminal_fixture(*, failed=False, prepare_failure=False, current_caller=False, carrier=None):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    class Store:
        def __init__(self):
            self.value, self.etag, self.writes = None, None, 0
        def get(self):
            return copy.deepcopy(self.value), self.etag
        def put(self, value, etag):
            assert etag == self.etag
            self.writes += 1
            self.value, self.etag = copy.deepcopy(value), str(self.writes)
            return self.etag
    historical = {"state_after": {"lineage": "original-lineage", "serial": 1, "state_sha256": "a" * 64},
                  "state_object": {"status": "present", "version_id": "prior", "etag_sha256": "f" * 64}}
    store = Store()
    store.put({"status": "released", "checkpoint_sha256": c.sha(c.canonical(historical)), "run_id": 1}, None)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    if current_caller:
        binding |= _current_caller({}, binding)
    proof = {}
    keeper, owner = _admitted_terminal_keeper(store, binding, historical, proof, carrier=carrier)
    checkpoint = {"owner": owner, "state": historical["state_after"], "state_object": historical["state_object"],
                  "phase_a_originals": keeper.phase_a_originals}
    window = store.get()[0]["lifecycle"]
    for stage, duration in ([] if prepare_failure else MINIMUM_WINDOWS["stages"].items()):
        window = window | {"sequence": window["sequence"] + 1, "close": 1000, "fixed_deadline": 2800,
                           "input_deadline": 3000, "stage": stage, "admitted_at": 1000, "deadline": 1000 + duration,
                           "checkpoint_sha256": c.sha(c.canonical(checkpoint))}
        keeper.lease.checkpoint(window)
        keeper.lease.renew()  # Equal timestamps cannot define CAS order.
    assessment = {"kind": "accepted-open", "fence": "OPEN", "accepted_modes": ["unit", "recovery", "audit"],
                  "routes_match": True, "state_clean": True, "quiescent": True, "pending": [], "unknown": [], "observed_at": 1000}
    names = ("unit", "recovery", "audit", "host", "static", "routing", "membership", "quiescence")
    if failed:
        window = window | {"sequence": window["sequence"] + 1, "stage": "recovery", "deadline": 1300,
                           "decision": {"choice_at": 1000, "deadline": 1420, "checkpoint_sha256": window["checkpoint_sha256"]}}
        keeper.lease.checkpoint(window)
        assessment.update(kind="failed-closed-quiescent", fence="CLOSED", accepted_modes=[],
                          restoration={k: True for k in ("unit", "recovery", "audit", "api", "static", "first_static_absent")})
        names = ("decision", "restoration", "routing", "membership", "quiescence")
    if prepare_failure:
        assessment.update(kind="failed-prepare-quiescent", fence="OPEN", accepted_modes=[],
                          restoration={k: True for k in ("unit", "recovery", "audit", "api", "static", "first_static_absent")})
        checkpoint = historical
        names = ("restoration", "routing", "quiescence")
    proof.update(assessment=assessment, checkpoint=checkpoint, inputs={name: "e" * 64 for name in names})
    files = keeper.finish(_terminal_reference(keeper))
    return store, files


def test_prepare_failure_before_first_apply_preserves_historical_state_and_failure():
    from tools.cnesdata_delivery.application_gate import verify_terminal_bundle
    store, files = _terminal_fixture(prepare_failure=True)
    result = verify_terminal_bundle(files, store.get()[0])
    assert result["terminal"]["promotion_status"] == "failed"
    assert result["checkpoint"]["state_object"]["version_id"] == "prior"
    assert result["checkpoint"]["window"]["sequence"] == 0


@pytest.mark.parametrize("failed", [False, True])
def test_terminal_bundle_validates_actual_keeper_chain_and_preserves_failure(failed):
    from tools.cnesdata_delivery.application_gate import verify_terminal_bundle
    store, files = _terminal_fixture(failed=failed)
    result = verify_terminal_bundle(files, store.get()[0])
    assert result["terminal"]["promotion_status"] == ("failed" if failed else "accepted")
    assert result["checkpoint"]["owner"]["generation"] == 1


@pytest.mark.parametrize("mutation", ["missing-renewal", "fork", "reordered-checkpoint", "release-before-acquire",
                                    "owner", "checkpoint", "window", "deadline", "false-accepted"])
def test_terminal_bundle_rejects_broken_cas_and_original_bindings(mutation):
    from tools.cnesdata_delivery.application_gate import verify_terminal_bundle
    store, files = _terminal_fixture(failed=mutation == "false-accepted")
    record = store.get()[0]
    terminal, evidence = (c.loads(files[name], canonical=True) for name in ("terminal.json", "lease.json"))
    if mutation == "missing-renewal": evidence["renewals"].pop()
    if mutation == "fork": evidence["renewals"].append(copy.deepcopy(evidence["renewals"][0]))
    if mutation == "reordered-checkpoint": evidence["checkpoints"][1]["sequence"] = 9
    if mutation == "release-before-acquire": evidence["release"]["requested_at"] = c.utc(999)
    if mutation == "owner": terminal["owner"]["generation"] += 1
    if mutation == "checkpoint": files["checkpoint.json"] += b" "
    if mutation == "window": record["lifecycle"]["admitted_at"] += 1
    if mutation == "deadline": terminal["deadline"] += 1
    if mutation == "false-accepted": terminal["promotion_status"] = "accepted"
    files["terminal.json"], files["lease.json"] = c.canonical(terminal), c.canonical(evidence)
    with pytest.raises(ValueError): verify_terminal_bundle(files, record)


def _publish_terminal_fixture(monkeypatch, tmp_path, *, failed=False, current_caller=False):
    import io
    import zipfile
    from types import SimpleNamespace
    from tools.cnesdata_delivery.application_gate import ReleasedPublicationGuard, publish_terminal
    store, files = _terminal_fixture(failed=failed, current_caller=current_caller)
    record, etag = store.get()
    governance = {"stage_windows": WINDOWS["stages"], "fixed_deadline_seconds": WINDOWS["fixed_deadline_seconds"],
                  "evidence_prefix": "cnesdata/prod/evidence/", "state_bucket": "synthetic-state", "evidence_bucket": "evidence",
                  "gate_shas": {"application": "a" * 40}, "lifecycle_terminal_job": "promotion / keeper"}
    run = {"id": 44, "run_attempt": 1, "head_sha": "b" * 40, "event": "workflow_dispatch",
           "repository": {"full_name": c.REPOSITORY}, "path": ".github/workflows/promote-production.yml",
           "status": "in_progress", "conclusion": None, "head_branch": "main",
           "referenced_workflows": [{"path": "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-application-gate.yml@" + "a" * 40,
                                     "sha": "a" * 40, "ref": "refs/heads/main"}]}
    job = {"id": 9, "run_id": 44, "run_attempt": 1, "head_sha": "b" * 40, "name": "promotion / keeper",
           "status": "completed", "conclusion": "success", "started_at": c.utc(900), "completed_at": c.utc(1050)}
    class API:
        def read(self, path, **kwargs):
            if path.endswith("/zip"): return self.archive
            if "/artifacts/" in path: return self.metadata
            if "artifacts?" in path: return {"total_count": 1, "artifacts": [self.metadata]}
            if "jobs?" in path: return {"total_count": 1, "jobs": [job]}
            if "/jobs/" in path: return job
            return run
    api = API()
    objects = {}
    class AWS:
        def put(self, bucket, key, raw):
            assert bucket == "evidence" and (key.startswith("cnesdata/prod/evidence/lifecycle/" + "b" * 40 + "/44/1/terminal/")
                or key == "cnesdata/prod/evidence/lifecycle/" + "c" * 40 + "/45/1/keeper/checkpoint.json")
            assert key not in objects
            objects[key] = raw
        def get(self, bucket, key, **kwargs):
            assert bucket == "evidence"
            return objects[key], "etag"
    def upload(directory, name, guard, temp):
        assert name == "lifecycle-terminal"
        guard.check(20)
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as archive:
            archive.writestr("index.json", (directory / "index.json").read_bytes())
        api.archive = out.getvalue()
        api.metadata = {"id": 4, "name": name, "digest": "sha256:" + c.sha(api.archive),
                        "workflow_run": {"id": 44, "head_sha": "b" * 40}, "expired": False,
                        "expires_at": c.utc(time.time() + 86400), "created_at": c.utc(1001)}
        return {"id": 4, "digest": api.metadata["digest"]}
    monkeypatch.setattr(runtime, "_upload", upload)
    lease = SimpleNamespace(store=store, etag=etag, acquired_at=record["acquired_at"])
    guard = ReleasedPublicationGuard(lease, record, etag, deadline=1060 if not failed else 1420,
                                    credential_deadline=2000, clock=lambda: 1000, monotonic=lambda: 1000)
    aws = AWS()
    receipt = publish_terminal(aws, api, governance, files, guard, tmp_path)
    assert store.get() == (record, etag)
    assert len(objects) == 3
    run.update(status="completed", conclusion="success")
    return aws, api, governance, store, run, job, objects, receipt


@pytest.mark.parametrize("branch", ["main", "develop"])
def test_published_terminal_admits_only_a_predecessor_run_on_main(monkeypatch, tmp_path, branch):
    """Amendment infra-ansible#55/6993274712. `authenticate_predecessor` refuses a develop run first; this guard is the second."""
    from tools.cnesdata_delivery.application_gate import published_terminal
    aws, api, governance, store, run, job, objects, receipt = _publish_terminal_fixture(monkeypatch, tmp_path)
    previous = store.get()[0]
    run["head_branch"] = branch
    if branch == "main":
        assert published_terminal(api, governance, previous)[0]["head_branch"] == "main"
    else:
        with pytest.raises(ValueError, match="previous lifecycle run not terminal success"):
            published_terminal(api, governance, previous)


@pytest.mark.parametrize("application_purpose", ["promotion", "mode-readiness-drill"])
@pytest.mark.parametrize("mutation", [None, "missing", "incomplete", "tampered", "release", "branch"])
def test_published_original_lifecycle_terminal_allows_successor_without_state_access(monkeypatch, tmp_path, mutation, application_purpose):
    aws, api, governance, store, run, job, objects, receipt = _publish_terminal_fixture(monkeypatch, tmp_path)
    previous = store.get()[0]
    result = runtime.previous_success(aws, api, governance, previous, details=True)
    assert result["artifact_id"] == receipt["id"]
    assert result["terminal"]["promotion_status"] == "accepted"
    original_bytes = copy.deepcopy(objects)
    from tools.cnesdata_delivery.application_gate import authenticated_previous
    reference = {"predecessor_version": 1, "protocol": "lifecycle", "repository": c.REPOSITORY,
                 "source_sha": previous["source_sha"], "run_id": 44, "run_attempt": 1,
                 "owner_sha256": c.sha(previous["owner"].encode()), "generation": previous["generation"],
                 "session_sha256": previous["session_sha256"], "checkpoint_sha256": previous["checkpoint_sha256"],
                 "artifact_id": receipt["id"], "artifact_digest": receipt["digest"],
                 "producer_job_id": job["id"], "producer_name": job["name"],
                 "objects": [{"name": key.rsplit("/", 1)[1], "sha256": c.sha(raw), "size": len(raw)}
                             for key, raw in objects.items()]}
    governance.update(lifecycle_predecessor=reference, predecessor_read={"protocol": "lifecycle",
        "source_sha": previous["source_sha"], "run_id": 44, "run_attempt": 1, "status": "terminal", "purpose": "application"})
    binding = {"repository": c.REPOSITORY, "source_sha": "c" * 40, "run_id": 45, "run_attempt": 1,
               "release_sha256": "c" * 64 if mutation == "release" else _phase_a_release_sha256(),
               "session_sha256": "f" * 64, "lifecycle_version": 1}
    binding |= _current_caller(governance, binding, application_purpose)
    keeper = Keeper(store, binding,
                    lambda value: authenticated_previous(aws, api, governance, value),
                    api=api, governance=governance, evidence_aws=aws, clock=lambda: 1100, monotonic=lambda: 1100)
    if mutation is not None:
        if mutation == "missing": governance.pop("lifecycle_predecessor")
        if mutation == "incomplete": reference.pop("objects")
        if mutation == "tampered": reference["objects"][0]["sha256"] = "0" * 64
        if mutation == "branch": run["head_branch"] = "develop"  # the trail moved to main (amendment 6993274712)
        before = store.get()
        writes = store.writes
        monkeypatch.setattr(keeper.lease, "acquire", lambda: pytest.fail("invalid history reached Lease.acquire"))
        with pytest.raises((ValueError, KeyError), match="application release" if mutation == "release" else None):
            keeper.acquire(preparation_deadline=2000)
        assert store.writes == writes and store.get() == before
        assert objects == original_bytes
        return
    from tools.cnesdata_delivery import lifecycle_runtime
    assert callable(getattr(lifecycle_runtime, "authenticate_application_predecessor", None)), "public history required before STS"
    assert lifecycle_runtime.authenticate_application_predecessor(api, governance, {"id": 45, "run_attempt": 1}) == reference
    owner = keeper.acquire(preparation_deadline=2000)
    assert owner["generation"] == 2 and owner["run_id"] == 45
    assert store.get()[0]["lifecycle"]["predecessor_sha256"] == c.sha(c.canonical(reference))
    assert keeper.predecessor["checkpoint"]["owner"]["run_id"] == 44
    assert {key: c.sha(objects[key]) for key in original_bytes} == {key: c.sha(raw) for key, raw in original_bytes.items()}
    own_key = "cnesdata/prod/evidence/lifecycle/" + "c" * 40 + "/45/1/keeper/checkpoint.json"
    assert set(objects) - set(original_bytes) == {own_key}
    assert c.loads(objects[own_key], canonical=True)["phase_a_originals"] == keeper.predecessor["checkpoint"]["phase_a_originals"]


@pytest.mark.parametrize("mutation", ["failed-run", "cancelled-run", "live-run", "failed-job", "wrong-job", "attempt",
                                    "reusable", "checkpoint-bytes", "released-failure"])
def test_terminal_reacquisition_rejects_missing_original_acceptance(monkeypatch, tmp_path, mutation):
    aws, api, governance, store, run, job, objects, _ = _publish_terminal_fixture(monkeypatch, tmp_path, failed=mutation == "released-failure")
    if mutation == "failed-run": run["conclusion"] = "failure"
    if mutation == "cancelled-run": run["conclusion"] = "cancelled"
    if mutation == "live-run": run["status"] = "in_progress"
    if mutation == "failed-job": job["conclusion"] = "failure"
    if mutation == "wrong-job": job["name"] = "other / keeper"
    if mutation == "attempt": job["run_attempt"] = 2
    if mutation == "reusable": run["referenced_workflows"][0]["sha"] = "f" * 40
    if mutation == "checkpoint-bytes":
        key = next(k for k in objects if k.endswith("checkpoint.json"))
        objects[key] += b"changed"
    original = store.get()
    assert runtime.previous_success(aws, api, governance, original[0], details=True) is False
    assert store.get() == original


def test_released_publication_cannot_renew_or_survive_changed_owner():
    from types import SimpleNamespace
    from tools.cnesdata_delivery.application_gate import ReleasedPublicationGuard
    store, _ = _terminal_fixture()
    record, etag = store.get()
    lease = SimpleNamespace(store=store, etag=etag)
    guard = ReleasedPublicationGuard(lease, record, etag, deadline=1060, credential_deadline=2000,
                                    clock=lambda: 1000, monotonic=lambda: 1000)
    guard.check(20)
    store.put(record | {"owner": "another-owner"}, etag)
    with pytest.raises(ValueError, match="ownership changed"): guard.check(20)


def test_first_plan_history_session_reads_only_original_checkpoint():
    from tools.cnesdata_delivery.session_policy import lifecycle_request, predecessor_keys
    from fixtures.cnesdata_iam_evaluation import allowed
    governance = {"account_id": "111122223333", "evidence_prefix": "cnesdata/prod/evidence/",
                  "evidence_bucket": "synthetic-evidence", "state_bucket": "synthetic-state",
                  "evidence_kms_key_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000002",
                  "roles": {"plan": "arn:aws:iam::111122223333:role/cnesdata-test-plan", "deploy": "arn:aws:iam::111122223333:role/cnesdata-test-deploy"}}
    selector = {"protocol": "legacy-infra", "source_sha": "a" * 40, "run_id": 42, "run_attempt": 2,
                "status": "applied", "purpose": "phase-a"}
    policy = lifecycle_request(governance, "b" * 40, 44, 1, "plan", "prepare-plan", direction="advance", predecessor=selector)
    assert len(policy["Policy"]) + len(policy["PolicyArns"][0]["arn"]) <= 2048
    document = c.loads(policy["Policy"].encode())
    for key in predecessor_keys(governance, selector):
        arn = "arn:aws:s3:::synthetic-evidence/" + key
        context = {"kms:ViaService": "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": arn}
        expected = key.endswith("/checkpoint.json")
        assert allowed(document, "s3:GetObject", arn) is expected
        assert allowed(document, "kms:Decrypt", governance["evidence_kms_key_arn"], context) is expected
        assert not allowed(document, "s3:PutObject", arn)
        assert not allowed(document, "kms:Encrypt", governance["evidence_kms_key_arn"], context)
        assert not allowed(document, "kms:GenerateDataKey", governance["evidence_kms_key_arn"], context)
    for field, value in (("status", "latest"), ("source_sha", "*"), ("run_id", 0), ("purpose", "phase-b")):
        with pytest.raises(ValueError): predecessor_keys(governance, selector | {field: value})
    with pytest.raises(ValueError):
        lifecycle_request(governance, "b" * 40, 44, 1, "deploy", "prepare-apply", direction="advance", predecessor=selector)


def _legacy_history_fixture(monkeypatch, tmp_path, *, job_failed=False):
    """Original Phase A custody through real CAS, API/ZIP and private validators."""
    from fixtures.cnesdata_session_chain import OwnerChain
    from fixtures.cnesdata_delivery_lifecycle import fence_projection_case
    from tools.cnesdata_delivery.coordination_lease import Lease, KEY
    from tools.cnesdata_delivery.session_policy import predecessor_keys
    chain = OwnerChain(monkeypatch, tmp_path)
    chain.gov["evidence_prefix"] = chain.gov["evidence_prefix"].rstrip("/") + "/"
    chain.configure("deploy", 2)
    chain.run(c.REPOSITORY, 2, ".github/workflows/infra-apply.yml", source="9" * 40, role="deploy")
    aws, original_api = runtime.AWS(chain.gov | {"role": "deploy"}), GitHub()
    store = S3LeaseStore(aws)
    carrier, raw = _phase_a_carrier_case()
    envelope, checkpoint, drift = (c.loads(raw[name], canonical=True) for name in ("envelope.json", "checkpoint.json", "drift.json"))
    state = fence_projection_case()[2]
    state["serial"] = 1
    state_raw = c.canonical(state)
    chain.objects[chain.gov["state_bucket"], "cnesdata/prod/opentofu.tfstate"] = state_raw, "phase-a-state-etag"
    _, state_object = aws.get_state()
    checkpoint.update(state_after=c.state_identity(state_raw), state_object=state_object)
    raw["checkpoint.json"] = c.canonical(checkpoint)
    binding = {"repository": c.REPOSITORY, "run_id": 2, "run_attempt": 1, "session_sha256": "9" * 64}
    lease = Lease(store, binding, monotonic=time.monotonic)
    lease.acquire()
    lease.release(c.sha(raw["checkpoint.json"]))
    evidence = lease.evidence(c.sha(raw["checkpoint.json"]), {"pid": 314, "returncode": 0})
    evidence_raw = c.canonical(evidence)
    applied = envelope["apply"]
    applied["state_after"] = checkpoint["state_after"] | {"outputs_sha256": c.sha(c.canonical(checkpoint["outputs"]))}
    applied["lease"].update(owner_sha256=c.sha(lease.token.encode()), checkpoint_sha256=c.sha(raw["checkpoint.json"]),
        evidence_sha256=c.sha(evidence_raw), acquired_at=lease.acquired_at, released_at=lease.release_event["responded_at"],
        acquire_etag_sha256=lease.acquire_event["etag_sha256"], release_etag_sha256=lease.release_event["etag_sha256"],
        ttl_seconds=300, renew_interval_seconds=60, safety_margin_seconds=120)
    raw["envelope.json"] = c.canonical(envelope)
    originals = raw | {"lease.json": evidence_raw, "ecr-before.json": c.canonical(drift["ecr_before"])}
    prefix = runtime._prefix(chain.gov, envelope["plan"]["source_sha"], 2, 1, "applied")
    for name, body in originals.items():
        aws.put(chain.gov["evidence_bucket"], prefix + name, body)
    plan = envelope["plan"]
    index = {"index_version": 1, "kind": "cnesdata-private-plan-transport", "status": "applied", "repository": c.REPOSITORY,
        "source_sha": plan["source_sha"], "producer": applied["producer"], "purpose": "phase-a", "created_at": plan["created_at"],
        "expires_at": plan["expires_at"], "plan_binding_sha256": envelope["plan_binding_sha256"], "envelope_sha256": c.sha(raw["envelope.json"]),
        "package_aggregate_sha256": plan["package"]["aggregate_sha256"], "private_locator": {"scope": "cnesdata-prod",
        "source_sha": plan["source_sha"], "run_id": 2, "run_attempt": 1, "status": "applied"},
        "policy": {key: plan["policy"][key] for key in ("verdict", "evidence_sha256")}, "cost": plan["cost"],
        "drift": {key: plan["drift"][key] for key in ("verdict", "evidence_sha256")}, "admission_proof": "d" * 64}
    publication = chain.add_artifact(2, {"index.json": c.canonical(index)}, ".github/workflows/infra-apply.yml", source=plan["source_sha"], name="cnesdata-applied-2-1")
    receipt = {"receipt_version": 1, "repository": c.REPOSITORY, "run_id": 2, "run_attempt": 1,
        "envelope_sha256": c.sha(raw["envelope.json"]), "index_artifact_id": publication["artifact_id"],
        "index_artifact_digest": publication["artifact_digest"], "lease_evidence_sha256": c.sha(evidence_raw),
        "checkpoint_sha256": c.sha(raw["checkpoint.json"]), "verified_at": applied["completed_at"], "result": "success"}
    chain.add_artifact(2, {"receipt.json": c.canonical(receipt)}, ".github/workflows/infra-apply.yml", source=plan["source_sha"], name="cnesdata-applied-receipt-2-1")
    previous, _ = store.get()
    selector = {"protocol": "legacy-infra", "source_sha": plan["source_sha"], "run_id": 2, "run_attempt": 1,
        "status": "applied", "purpose": "phase-a"}
    reference = {"predecessor_version": 1, "protocol": "legacy-infra", "repository": c.REPOSITORY,
        "source_sha": plan["source_sha"], "run_id": 2, "run_attempt": 1, "owner_sha256": c.sha(previous["owner"].encode()),
        "generation": previous.get("generation"), "session_sha256": previous["session_sha256"], "checkpoint_sha256": previous["checkpoint_sha256"],
        "artifact_id": publication["artifact_id"], "artifact_digest": publication["artifact_digest"], "producer_job_id": 91,
        "producer_name": "apply / execute", "objects": []}
    for key in predecessor_keys(chain.gov, selector):
        body, _ = aws.get(chain.gov["evidence_bucket"], key)
        reference["objects"].append({"name": key.rsplit("/", 1)[1], "sha256": c.sha(body), "size": len(body)})
    chain.gov.update(predecessor_read=selector, lifecycle_predecessor=reference)
    class API:
        def read(self, path, **kwargs):
            if path.endswith("/jobs/91"):
                return {"run_id": 2, "run_attempt": 1, "head_sha": plan["source_sha"], "name": "apply / execute",
                    "status": "completed", "conclusion": "failure" if job_failed else "success",
                    "started_at": c.utc(chain.now - 5), "completed_at": c.utc(chain.now + 5)}
            return original_api.read(path, **kwargs)
        def artifact(self, *args, **kwargs):
            return original_api.artifact(*args, **kwargs)
    api = API()
    assert runtime.previous_success(aws, api, chain.gov, previous, details=True)
    return chain, aws, api, store, previous, reference


@pytest.mark.parametrize("mutation", [None, "generation", "job", "checkpoint-bytes", "release", "current-run", "entry-replay"])
def test_original_receipt_governs_keeper_and_exact_first_plan_checkpoint(monkeypatch, tmp_path, mutation):
    from tools.cnesdata_delivery.application_gate import authenticated_previous
    from tools.cnesdata_delivery.lifecycle_runtime import authenticate_predecessor, historical_checkpoint
    chain, aws, api, store, previous, reference = _legacy_history_fixture(monkeypatch, tmp_path, job_failed=mutation == "job")
    if mutation == "generation": reference["generation"] = 5
    if mutation == "checkpoint-bytes":
        key = next(k for k in chain.objects if "/2/1/applied/" in k[1] and k[1].endswith("checkpoint.json"))
        raw, version = chain.objects[key]
        chain.objects[key] = (raw + b"changed", version)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64 if mutation == "release" else _phase_a_release_sha256(),
               "session_sha256": "d" * 64, "lifecycle_version": 1}
    binding |= _current_caller(chain.gov, binding)
    keeper = Keeper(store, binding, lambda value: authenticated_previous(aws, api, chain.gov, value), api=api, governance=chain.gov)
    before = store.get()
    if mutation in {"generation", "job", "checkpoint-bytes", "release"}:
        monkeypatch.setattr(keeper.lease, "acquire", lambda: pytest.fail("release mismatch reached Lease.acquire"))
        with pytest.raises(ValueError, match="application release" if mutation == "release" else None):
            keeper.acquire(preparation_deadline=int(time.time()) + 900)
        assert store.get() == before
        return
    original_state_reader = aws.get_state
    monkeypatch.setattr(aws, "get_state", lambda **kwargs: pytest.fail("keeper cannot read state"))
    owner = keeper.acquire(preparation_deadline=int(time.time()) + 900)
    record = store.get()[0]
    assert record["lifecycle"]["predecessor_sha256"] == c.sha(c.canonical(reference))
    assert authenticate_predecessor(api, chain.gov) == reference
    if mutation == "current-run": record.update(run_id=2, run_attempt=1)
    if mutation == "entry-replay": record["lifecycle"]["sequence"] = 1
    if mutation:
        with pytest.raises(ValueError): historical_checkpoint(aws, chain.gov, reference, record)
        return
    raw = historical_checkpoint(aws, chain.gov, reference, record)
    state, state_object = original_state_reader(absent=True)
    checkpoint = first_checkpoint(keeper.predecessor, record, owner, state, state_object)
    assert raw == c.canonical(checkpoint)
    # Deploy consumes the original historical bytes carried by the saved plan,
    # without gaining a historical read capability of its own.
    class NoHistory:
        def get(self, *args, **kwargs): pytest.fail("deploy cannot fetch history")
    assert historical_checkpoint(NoHistory(), chain.gov, reference, record, raw=raw) == raw
    assert keeper.predecessor["lease"] == previous


@pytest.mark.parametrize("mutation", ["callback-missing", "callback-incomplete", "callback-tampered",
    "protected-missing", "protected-incomplete", "protected-tampered", "protected-object",
    "lease-owner", "lease-session", "lease-attempt", "lease-generation"])
def test_keeper_requires_protected_reference_before_any_lease_acquire_or_cas(monkeypatch, tmp_path, mutation):
    chain, aws, api, store, previous, reference = _legacy_history_fixture(monkeypatch, tmp_path)
    details = runtime.previous_success(aws, api, chain.gov, previous, details=True)
    details["predecessor_reference"] = copy.deepcopy(reference)
    if mutation == "callback-missing": details.pop("predecessor_reference")
    if mutation == "callback-incomplete": details["predecessor_reference"].pop("objects")
    if mutation == "callback-tampered": details["predecessor_reference"]["producer_job_id"] += 1
    if mutation == "protected-missing": chain.gov.pop("lifecycle_predecessor")
    if mutation == "protected-incomplete": reference.pop("objects")
    if mutation == "protected-tampered": reference["artifact_digest"] = "sha256:" + "0" * 64
    if mutation == "protected-object": reference["objects"].pop()
    if mutation.startswith("lease-"):
        field = {"lease-owner": "owner_sha256", "lease-session": "session_sha256",
                 "lease-attempt": "run_attempt", "lease-generation": "generation"}[mutation]
        reference[field] = 2 if field in {"run_attempt", "generation"} else "0" * 64
        details["predecessor_reference"] = copy.deepcopy(reference)
    writes = []
    def forbidden_write(*args, **kwargs):
        writes.append(args)
        pytest.fail("invalid history must perform ZERO CAS writes")
    monkeypatch.setattr(store, "put", forbidden_write)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    binding |= _current_caller(chain.gov, binding)
    keeper = Keeper(store, binding, lambda value: details, api=api, governance=chain.gov)
    acquire_calls = []
    acquire = keeper.lease.acquire
    def tracked_acquire():
        acquire_calls.append(True)
        return acquire()
    monkeypatch.setattr(keeper.lease, "acquire", tracked_acquire)
    before = store.get()
    with pytest.raises((ValueError, KeyError)):
        keeper.acquire(preparation_deadline=int(time.time()) + 900)
    assert acquire_calls == [] and writes == []
    assert store.get() == before


from fixtures.cnesdata_delivery_lifecycle import MODE_SESSION_VECTORS, CALLER_VECTORS


@pytest.mark.parametrize("vector", MODE_SESSION_VECTORS, ids=lambda x: x["operation"])
def test_mode_session_codec_matches_all_fourteen_ratified_vectors(vector):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert callable(getattr(lc, "mode_session", None)), "nominal session codec required"
    binding = vector["binding"]
    purpose = "promotion" if binding["context_kind"] == "promotion" else "mode-readiness-drill"
    result = lc.mode_session(binding, purpose)
    assert c.canonical(binding).decode() == vector["canonical_utf8"]
    assert result == {"alias": vector["alias"], "session_name": vector["session_name"], "binding_sha256": vector["sha256"]}


@pytest.mark.parametrize("mutation", ["purpose", "phase", "extra", "float", "bool", "unicode", "operation", "owner", "schema"])
def test_mode_session_rejects_mixed_context_or_uncommitted_fields(mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    binding = copy.deepcopy(MODE_SESSION_VECTORS[0]["binding"])
    purpose = "promotion"
    if mutation == "purpose": purpose = "mode-readiness-drill"
    if mutation == "phase": binding["phase"] = "audit"
    if mutation == "extra": binding["session_name"] = "caller-controlled"
    if mutation == "float": binding["generation"] = 7.0
    if mutation == "bool": binding["run_attempt"] = True
    if mutation == "unicode": binding["release_id"] = "reléase"
    if mutation == "operation": binding["operation"] = "static-publish"
    if mutation == "owner": binding["owner_sha256"] = "not-a-digest"
    if mutation == "schema": binding["schema_version"] = 1
    assert callable(getattr(lc, "mode_session", None)), "nominal session codec required"
    with pytest.raises(ValueError): lc.mode_session(binding, purpose)


@pytest.mark.parametrize("vector", CALLER_VECTORS, ids=lambda x: x["name"])
def test_caller_binding_matches_exact_ratified_purpose_map_and_vectors(vector):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert callable(getattr(lc, "application_caller_binding", None)), "exact caller codec required"
    producer = {"workflow_sha": "2e51aaa560372679a54002788d80d46ad4fee5b3", "source_closure_sha256": "6" * 64}
    if vector["valid_pair"]:
        result = lc.application_caller_binding(vector["input"], producer)
        assert c.canonical(result).decode() == vector["caller_binding_canonical_utf8"]
        assert c.sha(c.canonical(result)) == vector["caller_binding_sha256"]
    else:
        with pytest.raises(ValueError): lc.application_caller_binding(vector["input"], producer)



def _application_caller_fixture(monkeypatch, purpose="promotion", role="application"):
    import base64
    from tools.cnesdata_delivery import lifecycle_contract as lc
    caller = lc.APPLICATION_CALLERS[purpose]
    path = (".github/workflows/reusable-cnesdata-application-gate.yml" if role == "application"
            else f".github/workflows/reusable-cnesdata-infra-{role}-gate.yml")
    role_pin = ("a" if role == "application" else "e") * 40
    shared = "VINIClUS/infra-ansible/" + path + "@" + role_pin
    raw = ("on:\n  workflow_dispatch:\njobs:\n  promote:\n    uses: " + shared + "\n").encode()
    manifest = {"version": 1, "source_sha": "b" * 40,
                "files": {caller["workflow_path"]: c.sha(raw), "scripts/promotion/promote_api.py": "c" * 64}}
    gov = {"source_sha": "b" * 40, "application_purpose": purpose, "context_kind": lc.APPLICATION_CONTEXTS[purpose],
           "gate_shas": {"application": "a" * 40, role: role_pin}, "required_checks": ["CI"],
           "application_source_closure_sha256": "d" * 64, "application_product_source_manifest": manifest,
           "application_product_source_closure_sha256": c.sha(c.canonical(manifest))}
    run = {"id": 44, "run_attempt": 2, "head_sha": "b" * 40, "head_branch": "main",
           "repository": {"full_name": c.REPOSITORY}, "event": "workflow_dispatch", "path": caller["workflow_path"],
           "status": "in_progress", "referenced_workflows": [{"path": shared, "sha": role_pin}]}
    step = {"caller_job": "promote", "producer_job": "keeper", "job_name": "promote / keeper",
            "admission_steps": ["Authenticate original caller", "Issue credentials"]}
    job = {"id": 9, "run_id": 44, "run_attempt": 2, "head_sha": "b" * 40, "name": "promote / keeper",
           "status": "in_progress", "conclusion": None,
           "steps": [{"name": "Authenticate original caller", "status": "in_progress"}]}
    claims = {"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com",
              "sub": f"repo:{c.REPOSITORY}:environment:production",
              "repository": c.REPOSITORY, "ref": "refs/heads/main", "environment": "production",
              "job_workflow_ref": shared, "workflow_ref": c.REPOSITORY + "/" + caller["workflow_path"] + "@refs/heads/main",
              "workflow_sha": "b" * 40, "sha": "b" * 40, "event_name": "workflow_dispatch", "run_id": "44", "run_attempt": "2"}
    class API:
        def read(self, path, **kwargs):
            if "/contents/" in path: return {"encoding": "base64", "content": base64.b64encode(self.raw).decode()}
            if "/compare/" in path:
                assert path == f"repos/{c.REPOSITORY}/compare/{'b' * 40}...main", path  # containment is in main (amendment 6993274712)
                return {"status": "identical"}
            if "/check-runs" in path: return {"check_runs": [{"name": "CI", "head_sha": "b" * 40, "conclusion": "success"}]}
            if "/jobs?" in path: return {"total_count": 1, "jobs": [job]}
            return run
    api = API(); api.raw = raw
    for key, value in {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                       "GITHUB_REPOSITORY": c.REPOSITORY, "GITHUB_JOB": "keeper",
                       "GITHUB_WORKFLOW_REF": claims["workflow_ref"], "GITHUB_WORKFLOW_SHA": "b" * 40}.items():
        monkeypatch.setenv(key, value)
    return gov, api, run, step, job, claims


@pytest.mark.parametrize("role", ["application", "plan", "deploy"])
@pytest.mark.parametrize("purpose", ["promotion", "mode-readiness-drill"])
@pytest.mark.parametrize("mutation", [None, "crossed-workflow", "source-bytes", "wrong-uses", "job-attempt", "job-step", "job-name", "job-step-config", "context", "manifest", "env-workflow", "ref-develop", "branch-develop"])
def test_application_caller_authenticates_original_source_job_and_purpose(monkeypatch, purpose, mutation, role):
    from tools.cnesdata_delivery import lifecycle_runtime, provenance
    gov, api, run, step, job, _ = _application_caller_fixture(monkeypatch, purpose, role)
    if mutation == "crossed-workflow": run["path"] = ".github/workflows/other.yml"
    if mutation == "source-bytes": api.raw += b"# changed\n"
    if mutation == "wrong-uses":
        api.raw = api.raw.replace(b"@" + gov["gate_shas"][role].encode(), b"@" + b"c" * 40)
        gov["application_product_source_manifest"]["files"][run["path"]] = c.sha(api.raw)
        gov["application_product_source_closure_sha256"] = c.sha(c.canonical(gov["application_product_source_manifest"]))
        run["referenced_workflows"][0]["path"] = run["referenced_workflows"][0]["path"].replace("@" + gov["gate_shas"][role], "@" + "c" * 40)
        run["referenced_workflows"][0]["sha"] = "c" * 40
    if mutation == "job-attempt": job["run_attempt"] = 1
    if mutation == "job-step": job["steps"][0]["name"] = "Execute arbitrary product code"
    if mutation == "job-name": job["name"] = "other / keeper"
    if mutation == "job-step-config": step["admission_steps"] = "Authenticate original caller"
    if mutation == "context": gov["context_kind"] = "readiness" if purpose == "promotion" else "promotion"
    if mutation == "manifest": gov["application_product_source_closure_sha256"] = "0" * 64
    if mutation == "env-workflow": monkeypatch.setenv("GITHUB_WORKFLOW_REF", "other")
    if mutation == "ref-develop": monkeypatch.setenv("GITHUB_REF", "refs/heads/develop")
    if mutation == "branch-develop": run["head_branch"] = "develop"
    assert callable(getattr(provenance, "application_caller", None)), "source/run caller authenticator required"
    def authenticate():
        observed = lifecycle_runtime.source_admission(gov, api, role, "b" * 40, 44, 2)
        return provenance.application_caller(api, gov, observed, role, step)
    if mutation is None:
        binding = authenticate()
        assert binding["application_purpose"] == purpose and binding["run_attempt"] == 2
        assert binding["producer_workflow_sha"] == gov["gate_shas"]["application"]
        assert binding["workflow_path"] == run["path"] and binding["source_sha"] == "b" * 40
    else:
        with pytest.raises(ValueError): authenticate()


@pytest.mark.parametrize("mutation", [None, "workflow", "sha", "event", "environment", "attempt", "caller-missing",
                                      "sub-staging", "sub-branch", "sub-customized", "reusable-pin", "reusable-path", "ref"])
def test_oidc_application_claim_mismatch_is_rejected_before_sts(monkeypatch, mutation):
    import base64
    import io
    import sys
    from types import SimpleNamespace
    import urllib.request
    from tools.cnesdata_delivery import lifecycle_runtime, lifecycle_contract as lc
    gov, api, run, step, job, claims = _application_caller_fixture(monkeypatch)
    evidence = {"application_purpose": "promotion", "context_kind": "promotion", **lc.APPLICATION_CALLERS["promotion"],
        "source_sha": "b" * 40, "run_id": 44, "run_attempt": 2, "producer_workflow_sha": "a" * 40,
        "producer_source_closure_sha256": "d" * 64, "event": "workflow_dispatch", "fragment_version": 4}
    gov["authenticated_application_caller"] = lc.application_caller_binding(evidence, {"workflow_sha": "a" * 40, "source_closure_sha256": "d" * 64})
    gov["roles"] = {"application": "arn:aws:iam::111122223333:role/cnesdata-prod-application"}
    if mutation == "workflow": claims["workflow_ref"] = c.REPOSITORY + "/.github/workflows/other.yml@refs/heads/main"
    if mutation == "sha": claims["sha"] = "c" * 40
    if mutation == "event": claims["event_name"] = "push"
    if mutation == "environment": claims["environment"] = "staging"
    if mutation == "attempt": claims["run_attempt"] = "1"
    if mutation == "caller-missing": gov.pop("authenticated_application_caller")
    # Amendment infra-ansible#55/6993274712: the default `sub` of a job with an environment, and the reusable pinned by the
    # separate `job_workflow_ref` claim. The customized template (`...:job_workflow_ref:<ref>` inside `sub`) is never issued.
    shared = claims["job_workflow_ref"]
    if mutation == "sub-staging": claims["sub"] = f"repo:{c.REPOSITORY}:environment:staging"
    if mutation == "sub-branch": claims["sub"] = f"repo:{c.REPOSITORY}:ref:refs/heads/main"
    if mutation == "sub-customized": claims["sub"] = f"repo:{c.REPOSITORY}:environment:production:job_workflow_ref:{shared}"
    if mutation == "reusable-pin": claims["job_workflow_ref"] = shared.split("@")[0] + "@" + "f" * 40
    if mutation == "reusable-path": claims["job_workflow_ref"] = shared.replace("application-gate", "infra-plan-gate")
    if mutation == "ref": claims["ref"] = "refs/heads/develop"
    token = "header." + base64.urlsafe_b64encode(c.canonical(claims)).decode().rstrip("=") + ".signature"
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.actions.githubusercontent.com/id?request=1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "synthetic")
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: io.BytesIO(c.canonical({"value": token})))
    calls = []
    class STS:
        def assume_role_with_web_identity(self, **kwargs):
            calls.append(kwargs)
            return {"PackedPolicySize": 1, "Credentials": {"fixture": "no-real-credentials"}}
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda *a, **k: STS()))
    monkeypatch.setitem(sys.modules, "botocore", SimpleNamespace(UNSIGNED="synthetic"))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kwargs: kwargs))
    if mutation is None:
        assert lifecycle_runtime.oidc_credentials(gov, "application", {}, run) == {"fixture": "no-real-credentials"}
        assert len(calls) == 1
    else:
        with pytest.raises((ValueError, KeyError)): lifecycle_runtime.oidc_credentials(gov, "application", {}, run)
        assert calls == []


def _oidc_exchange_case(monkeypatch):
    """The original-run OIDC boundary: only the token endpoint and the STS client are fakes."""
    import base64
    import io
    import sys
    from types import SimpleNamespace
    import urllib.request
    from tools.cnesdata_delivery import lifecycle_contract as lc
    gov, api, run, step, job, claims = _application_caller_fixture(monkeypatch)
    evidence = {"application_purpose": "promotion", "context_kind": "promotion", **lc.APPLICATION_CALLERS["promotion"],
        "source_sha": "b" * 40, "run_id": 44, "run_attempt": 2, "producer_workflow_sha": "a" * 40,
        "producer_source_closure_sha256": "d" * 64, "event": "workflow_dispatch", "fragment_version": 4}
    gov["authenticated_application_caller"] = lc.application_caller_binding(evidence, {"workflow_sha": "a" * 40, "source_closure_sha256": "d" * 64})
    gov["roles"] = {"application": "arn:aws:iam::111122223333:role/cnesdata-prod-application"}
    token = "header." + base64.urlsafe_b64encode(c.canonical(claims)).decode().rstrip("=") + ".signature"
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.actions.githubusercontent.com/id?request=1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "synthetic")
    tokens, calls = [], []
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: tokens.append(a) or io.BytesIO(c.canonical({"value": token})))
    class STS:
        def assume_role_with_web_identity(self, **kwargs):
            calls.append(kwargs)
            return {"PackedPolicySize": 1, "Credentials": {"fixture": "no-real-credentials"}}
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda *a, **k: STS()))
    monkeypatch.setitem(sys.modules, "botocore", SimpleNamespace(UNSIGNED="synthetic"))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kwargs: kwargs))
    return gov, run, tokens, calls


@pytest.mark.parametrize("duration, expected", [("default", 3600), (3600, 3600), (900, 900)])
def test_oidc_credentials_asks_the_ratified_session_duration(monkeypatch, duration, expected):
    """R20 option C: the operation session is the 900 second exchange; keeper, plan and deploy keep 3600."""
    from tools.cnesdata_delivery import lifecycle_runtime
    gov, run, tokens, calls = _oidc_exchange_case(monkeypatch)
    extra = {} if duration == "default" else {"duration": duration}
    assert lifecycle_runtime.oidc_credentials(gov, "application", {}, run, **extra) == {"fixture": "no-real-credentials"}
    assert len(tokens) == 1 and len(calls) == 1 and calls[0]["DurationSeconds"] == expected


@pytest.mark.parametrize("duration", [0, 899, 901, 1800, 3601, 7200, -900, True, 900.0, "900", None])
def test_oidc_credentials_refuses_every_duration_but_the_two_ratified_ones(monkeypatch, duration):
    from tools.cnesdata_delivery import lifecycle_runtime
    gov, run, tokens, calls = _oidc_exchange_case(monkeypatch)
    with pytest.raises(ValueError, match="^OIDC session duration$"):
        lifecycle_runtime.oidc_credentials(gov, "application", {}, run, duration=duration)
    assert tokens == [] and calls == []



@pytest.mark.parametrize("mutation", ["caller-missing", "caller-hash", "purpose", "run", "readiness-legacy"])
def test_keeper_rejects_current_caller_mismatch_before_any_cas(monkeypatch, tmp_path, mutation):
    from tools.cnesdata_delivery.application_gate import authenticated_previous
    chain, aws, api, store, previous, reference = _legacy_history_fixture(monkeypatch, tmp_path)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    binding |= _current_caller(chain.gov, binding, "mode-readiness-drill" if mutation == "readiness-legacy" else "promotion")
    if mutation == "caller-missing": chain.gov.pop("authenticated_application_caller")
    if mutation == "caller-hash": binding["caller_binding_sha256"] = "0" * 64
    if mutation == "purpose": binding["application_purpose"] = "mode-readiness-drill"
    if mutation == "run": binding["run_id"] += 1
    before = store.get()
    writes = []
    def forbidden_write(*args, **kwargs):
        writes.append(args)
        pytest.fail("caller mismatch must reject before CAS")
    monkeypatch.setattr(store, "put", forbidden_write)
    keeper = Keeper(store, binding, lambda value: authenticated_previous(aws, api, chain.gov, value), api=api, governance=chain.gov)
    with pytest.raises((ValueError, KeyError)):
        keeper.acquire(preparation_deadline=int(time.time()) + 900)
    assert writes == [] and store.get() == before


def test_checkpoint_preserves_current_caller_alongside_original_history():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    initial = {"sequence": 0, "preparation_deadline": 1900, "close": None, "fixed_deadline": None,
               "input_deadline": None, "stage": "application-prepare", "admitted_at": 1000, "deadline": 1900,
               "decision": None, "checkpoint_sha256": "a" * 64, "predecessor_sha256": "b" * 64,
               "application_purpose": "promotion", "context_kind": "promotion", "caller_binding_sha256": "c" * 64,
               "windows": MINIMUM_WINDOWS}
    lc.checkpoint_transition(None, initial)
    following = initial | {"sequence": 1, "checkpoint_sha256": "d" * 64}
    lc.checkpoint_transition(initial, following)
    for key, value in (("application_purpose", "mode-readiness-drill"), ("context_kind", "readiness"),
                       ("caller_binding_sha256", "e" * 64), ("predecessor_sha256", "f" * 64)):
        with pytest.raises(ValueError): lc.checkpoint_transition(initial, following | {key: value})
    missing = dict(following)
    for key in ("application_purpose", "context_kind", "caller_binding_sha256"):
        missing.pop(key)
    with pytest.raises(ValueError): lc.checkpoint_transition(initial, missing)



def test_current_application_terminal_transports_caller_without_rewriting_historical_schema(monkeypatch, tmp_path):
    import io
    import zipfile
    aws, api, gov, store, run, job, objects, receipt = _publish_terminal_fixture(monkeypatch, tmp_path, current_caller=True)
    with zipfile.ZipFile(io.BytesIO(api.archive)) as archive:
        index = c.loads(archive.read("index.json"), canonical=True)
    record = store.get()[0]
    assert index["application_purpose"] == record["application_purpose"] == "promotion"
    assert index["caller_binding_sha256"] == record["caller_binding_sha256"]
    result = runtime.previous_success(aws, api, gov, record, details=True)
    assert result["terminal"]["owner"]["caller_binding_sha256"] == index["caller_binding_sha256"]
    assert result["checkpoint"]["window"]["caller_binding_sha256"] == index["caller_binding_sha256"]
    previous_objects = dict(objects)
    assert runtime.previous_success(aws, api, gov, record, details=True) == result
    assert objects == previous_objects


@pytest.mark.parametrize("mutation", [None, "missing", "hash", "purpose"])
def test_current_private_payload_requires_caller_binding_before_private_read(mutation):
    from tools.cnesdata_delivery.lifecycle_runtime import private_payload
    raw = c.canonical({"checkpoint": "fixture"})
    gov = {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "evidence", "context_kind": "promotion"}
    request = {"source_sha": "b" * 40, "step": "prepare-plan", "application_purpose": "promotion", "caller_binding_sha256": "c" * 64}
    run = {"id": 44, "run_attempt": 2}
    index = {"version": 1, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 2, "step": "prepare-plan",
             "owner_sha256": "d" * 64, "generation": 1, "application_purpose": "promotion", "context_kind": "promotion",
             "caller_binding_sha256": "c" * 64, "files": [{"name": "checkpoint.json", "sha256": c.sha(raw), "size": len(raw)}]}
    if mutation == "missing":
        for key in ("application_purpose", "context_kind", "caller_binding_sha256"): index.pop(key)
    if mutation == "hash": index["caller_binding_sha256"] = "e" * 64
    if mutation == "purpose": index.update(application_purpose="mode-readiness-drill", context_kind="readiness")
    reads = []
    class AWS:
        def get(self, *args, **kwargs):
            reads.append(args)
            return raw, "etag"
    if mutation is None:
        assert private_payload(AWS(), gov, request, run, {"index.json": c.canonical(index)})[1] == {"checkpoint.json": raw}
        assert len(reads) == 1
    else:
        with pytest.raises(ValueError): private_payload(AWS(), gov, request, run, {"index.json": c.canonical(index)})
        assert reads == []



@pytest.mark.parametrize("mutation", [None, "missing-reference", "missing-selector", "null-selector", "same-run", "readiness-legacy"])
def test_application_history_public_preflight_preserves_original_protocol_before_sts(monkeypatch, tmp_path, mutation):
    from tools.cnesdata_delivery import lifecycle_runtime
    chain, aws, api, store, previous, reference = _legacy_history_fixture(monkeypatch, tmp_path)
    chain.gov.update(application_purpose="mode-readiness-drill" if mutation == "readiness-legacy" else "promotion")
    current = {"id": 44, "run_attempt": 1}
    if mutation == "missing-reference": chain.gov.pop("lifecycle_predecessor")
    if mutation == "missing-selector": chain.gov.pop("predecessor_read")
    if mutation == "null-selector": chain.gov["predecessor_read"] = None
    if mutation == "same-run": current["id"] = 2
    assert callable(getattr(lifecycle_runtime, "authenticate_application_predecessor", None)), "public history required before STS"
    before = store.get()
    if mutation is None:
        assert lifecycle_runtime.authenticate_application_predecessor(api, chain.gov, current) == reference
        assert reference["protocol"] == "legacy-infra" and chain.gov["predecessor_read"]["purpose"] == "phase-a"
    else:
        with pytest.raises(ValueError): lifecycle_runtime.authenticate_application_predecessor(api, chain.gov, current)
    assert store.get() == before



def test_application_caller_preflight_uses_only_pinned_runtime_dependencies(monkeypatch):
    import sys
    from tools.cnesdata_delivery import lifecycle_runtime, provenance
    gov, api, run, step, job, _ = _application_caller_fixture(monkeypatch)
    monkeypatch.setitem(sys.modules, "yaml", None)
    observed = lifecycle_runtime.source_admission(gov, api, "application", "b" * 40, 44, 2)
    assert provenance.application_caller(api, gov, observed, "application", step)["workflow_path"] == run["path"]



def test_legacy_retry_does_not_treat_original_lifecycle_terminal_as_saved_plan(monkeypatch, tmp_path):
    from types import SimpleNamespace
    aws, api, governance, store, *_ = _publish_terminal_fixture(monkeypatch, tmp_path)
    original = store.get()
    authenticated = runtime.previous_success(aws, api, governance, original[0], details=True)
    assert authenticated["terminal"]["promotion_status"] == "accepted" and "envelope" not in authenticated
    output = tmp_path / "retry-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert runtime._reuse_completed(aws, api, governance, SimpleNamespace(store=store), {}, {}, {}, "b" * 40, "bootstrap") is False
    assert store.get() == original and not output.exists()



WINDOWS = {"stages": {"phase-b": 360, "api": 180, "static": 180, "unit": 180, "phase-c-recovery": 330,
                      "phase-c-audit": 330, "final": 90}, "fixed_deadline_seconds": 2070}
MINIMUM_WINDOWS = {"stages": {"phase-b": 360, "api": 180, "static": 180, "unit": 120, "phase-c-recovery": 240,
                              "phase-c-audit": 240, "final": 60}, "fixed_deadline_seconds": 1800}


def _adapter_case(operation="inventory"):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    owner = {"repository": c.REPOSITORY, "source_sha": "a" * 40, "run_id": 41, "run_attempt": 1,
             "release_sha256": "b" * 64, "generation": 2, "session_sha256": "c" * 64, "owner_sha256": "d" * 64,
             "application_purpose": "promotion", "context_kind": "promotion", "caller_binding_sha256": "e" * 64}
    window = {"close": None, "fixed_deadline": None, "input_deadline": None, "stage": "application-prepare",
              "admitted_at": 1000, "deadline": 1900, "decision": None, "preparation_deadline": 1900,
              "sequence": 1, "checkpoint_sha256": "f" * 64, "windows": WINDOWS, **lc.application_identity(owner)}
    names = {"inventory": ("candidate", "dashboard-artifact", "archive", "static-baseline"),
             "close-drain": ("activation", "expirations"),
             "closed-ready": ("activation", "close-drain", "phase-b", "membership"),
             "publish-static": ("candidate", "dashboard-artifact", "static-plan", "inventory", "host-receipt"),
             "retire-static": ("static-plan", "inventory", "publication", "routing")}[operation]
    if operation == "closed-ready":
        window.update(close=1000, fixed_deadline=3070, input_deadline=4000, stage="api", admitted_at=1300, deadline=1480)
    if operation == "publish-static":
        window.update(close=1000, fixed_deadline=3070, input_deadline=4000, stage="static", admitted_at=1500, deadline=1680)
    if operation == "retire-static":
        window.update(close=1000, fixed_deadline=3070, input_deadline=4000, stage="final", admitted_at=2100, deadline=2160)
    inputs = {name: c.canonical({"fixture_only": name}) for name in names}
    request = {"abi_version": 3, "operation": operation, "repository": c.REPOSITORY, "source_sha": owner["source_sha"],
               "owner": {key: owner[key] for key in [*lc.OWNER_FIELDS, "owner_sha256"]},
               "checkpoint_sha256": window["checkpoint_sha256"], "activation_sha256": "1" * 64,
               "stage": {key: value for key, value in window.items() if key not in lc.application_identity(owner)},
               "inputs": {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in inputs.items()}}
    return request, owner, window, inputs


@pytest.mark.parametrize("operation", ["inventory", "close-drain", "closed-ready", "publish-static"])
@pytest.mark.parametrize("mutation", [None, "extra", "owner", "checkpoint", "stage-time", "bytes", "missing", "extra-input", "readiness", "noncanonical", "source", "canary-old", "activation"])
def test_adapter_request_binds_original_bytes_owner_phase_and_closed_inputs(operation, mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    request, owner, window, inputs = _adapter_case(operation)
    activation = request["activation_sha256"]
    if mutation == "extra":
        request["RoleArn"] = "caller-role"
    if mutation == "owner":
        request["owner"]["generation"] += 1
    if mutation == "checkpoint":
        request["checkpoint_sha256"] = "2" * 64
    if mutation == "stage-time":
        request["stage"]["admitted_at"] += 1
    if mutation == "bytes":
        inputs[next(iter(inputs))] += b" "
    if mutation == "missing":
        inputs.pop(next(iter(inputs)))
    if mutation == "extra-input":
        inputs["caller-path"] = b"other"
    if mutation == "readiness":
        owner.update(application_purpose="mode-readiness-drill", context_kind="readiness")
        window.update(lc.application_identity(owner))
    if mutation == "source":
        request["source_sha"] = "2" * 40
    if mutation == "canary-old":
        operation = request["operation"] = "unit-canary"
    if mutation == "activation":
        request["activation_sha256"] = "2" * 64
    raw = c.canonical(request) + (b" " if mutation == "noncanonical" else b"")
    args = {"operation": operation, "owner": owner, "window": window, "inputs": inputs, "activation_sha256": activation}
    if mutation:
        with pytest.raises(ValueError):
            lc.validate_adapter_request(raw, **args)
    else:
        assert lc.validate_adapter_request(raw, **args) == request


@pytest.mark.parametrize("mutation", [None, "drop-unknown", "drop-pending", "invent-observation", "receipts", "owner", "success"])
def test_adapter_result_cannot_erase_uncertainty_or_invent_observations(mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    request, _, _, _ = _adapter_case()
    observation = c.canonical({"fixture_only": "inventory"})
    observations = [{"kind": "inventory", "sha256": c.sha(observation), "size": len(observation)}]
    receipts = [{"fixture_only": "original shared SDK receipt"}]
    pending, unknown = [{"kind": "call", "reference_sha256": "3" * 64}], [{"kind": "call", "reference_sha256": "4" * 64}]
    result = {"abi_version": 3, "operation": "inventory", "owner_sha256": request["owner"]["owner_sha256"],
              "generation": request["owner"]["generation"], "checkpoint_sha256": request["checkpoint_sha256"],
              "observations": copy.deepcopy(observations), "call_receipts_sha256": c.sha(c.canonical(receipts)),
              "pending": copy.deepcopy(pending), "unknown": copy.deepcopy(unknown)}
    if mutation == "drop-unknown":
        result["unknown"] = []
    if mutation == "drop-pending":
        result["pending"] = []
    if mutation == "invent-observation":
        result["observations"][0]["sha256"] = "9" * 64
    if mutation == "receipts":
        result["call_receipts_sha256"] = "9" * 64
    if mutation == "owner":
        result["generation"] += 1
    if mutation == "success":
        result["success"] = True
    args = {"request": request, "observations": observations, "call_receipts": receipts, "pending": pending, "unknown": unknown}
    if mutation:
        with pytest.raises(ValueError):
            lc.validate_adapter_result(c.canonical(result), **args)
    else:
        assert lc.validate_adapter_result(c.canonical(result), **args) == result



@pytest.mark.parametrize("mutation", [None, "input-swap", "unknown-read", "observation-kind", "noncanonical", "guard", "invent-result"])
def test_adapter_journal_freezes_inputs_and_only_returns_registered_originals(mutation):
    from tools.cnesdata_delivery.application_gate import AdapterJournal
    request, owner, window, inputs = _adapter_case()
    checks = []
    class Guard:
        def check(self, seconds=1):
            checks.append(seconds)
            if mutation == "guard":
                raise ValueError("original owner changed")
    journal = AdapterJournal(c.canonical(request), operation="inventory", owner=owner, window=window, inputs=inputs,
                             activation_sha256=request["activation_sha256"], guard=Guard())
    original = inputs["candidate"]
    if mutation == "input-swap":
        inputs["candidate"] = b"replacement"
        assert journal.read("candidate") == original
        return
    if mutation in {"unknown-read", "guard"}:
        with pytest.raises(ValueError):
            journal.read("not-an-input" if mutation == "unknown-read" else "candidate")
        return
    assert journal.read("candidate") == original
    observed = c.canonical({"fixture_only": "observed-original", "original_input_sha256": c.sha(original)})
    if mutation in {"observation-kind", "noncanonical"}:
        with pytest.raises(ValueError):
            journal.observe("terminal" if mutation == "observation-kind" else "inventory", observed + (b" " if mutation == "noncanonical" else b""))
        assert journal.observations == []
        return
    digest = journal.observe("inventory", observed)
    assert journal.observation_bytes[digest] == observed
    result = {"abi_version": 3, "operation": "inventory", "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
              "checkpoint_sha256": window["checkpoint_sha256"], "observations": journal.observations,
              "call_receipts_sha256": c.sha(c.canonical([])), "pending": [], "unknown": []}
    if mutation == "invent-result":
        result["observations"] = [{"kind": "inventory", "sha256": "0" * 64, "size": len(observed)}]
        with pytest.raises(ValueError):
            journal.validate_result(c.canonical(result))
    else:
        raw = c.canonical(result)
        assert journal.validate_result(raw) == raw
        assert len(checks) >= 6
        assert journal.observation_links == [{"observation_sha256": digest, "call_receipts_sha256": c.sha(c.canonical([]))}]


def test_shared_sdk_journal_preserves_original_read_and_links_observation(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag
    request, owner, window, inputs = _adapter_case("closed-ready")
    checks, ticks = [], iter([1000000000, 1100000000])
    class Guard:
        def check(self, seconds=1):
            checks.append(seconds)
    monkeypatch.setattr(ag.time, "monotonic_ns", lambda: next(ticks))
    monkeypatch.setattr(ag.time, "time", lambda: 1760000000)
    journal = ag.AdapterJournal(c.canonical(request), operation="closed-ready", owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    parameters = {"TableName": "cnesdata-prod-control", "Key": {"pk": {"S": "ENV#prod#FENCE"}, "sk": {"S": "FENCE"}},
                  "ConsistentRead": True}
    native_request = {"role": "fence_operator", "service": "dynamodb", "operation": "get_item", "parameters": parameters}
    ticket = journal.begin_sdk_call(c.canonical(native_request), role_session_sha256="2" * 64)
    assert journal.pending == [{"kind": "sdk-call", "reference_sha256": ticket}]
    assert c.sha(journal.call_bytes[ticket]) == ticket
    response = b'{"Item":{"state":{"S":"CLOSED"}}}\n'
    receipt = journal.complete_sdk_call(ticket, response, request_id="aws-request-1", server_date="Thu, 09 Oct 2025 08:53:20 GMT")
    assert journal.pending == journal.unknown == []
    assert journal.call_bytes[receipt["request_sha256"]] == c.canonical(native_request)
    assert journal.call_bytes[receipt["response_sha256"]] == response
    assert receipt["request_id"] == "aws-request-1" and receipt["server_date"] == "Thu, 09 Oct 2025 08:53:20 GMT"
    assert receipt["started_monotonic_ns"] == 1000000000 and receipt["ended_monotonic_ns"] == 1100000000
    assert receipt["role_session_sha256"] == "2" * 64
    assert len(checks) >= 2
    digest = journal.observe("closed-ready", b'{"fixture_only":"original-domain-receipt"}\n')
    assert journal.observation_links == [{"observation_sha256": digest, "call_receipts_sha256": c.sha(c.canonical(journal.call_receipts))}]
    exposed = journal.call_receipts
    exposed.clear()
    assert len(journal.call_receipts) == 1


@pytest.mark.parametrize("failure", ["lost-response", "late-response", "post-guard", "noncanonical", "clock", "naive-date"])
def test_shared_sdk_journal_retains_unknown_and_never_accepts_late_success(monkeypatch, failure):
    from datetime import datetime
    from tools.cnesdata_delivery import application_gate as ag
    request, owner, window, inputs = _adapter_case("closed-ready")
    ticks = iter([1000000000, 22000000000 if failure == "late-response" else 1100000000, 1200000000])
    class Guard:
        failed = False
        def check(self, seconds=1):
            if self.failed:
                raise ValueError("original owner lost")
    guard = Guard()
    monkeypatch.setattr(ag.time, "monotonic_ns", lambda: next(ticks))
    clock_value = datetime(2025, 10, 9, 8, 53, 20).timestamp() if failure == "naive-date" else 1760000000
    monkeypatch.setattr(ag.time, "time", lambda: clock_value)
    journal = ag.AdapterJournal(c.canonical(request), operation="closed-ready", owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=guard)
    raw = c.canonical({"role": "fence_operator", "service": "dynamodb", "operation": "get_item", "parameters": {}})
    ticket = journal.begin_sdk_call(raw, role_session_sha256="2" * 64)
    if failure == "lost-response":
        journal.fail_sdk_call(ticket)
    else:
        guard.failed = failure == "post-guard"
        server_date = ("Thu, 09 Oct 2025 08:52:20 GMT" if failure == "clock" else
                       "Thu, 09 Oct 2025 08:53:20" if failure == "naive-date" else "Thu, 09 Oct 2025 08:53:20 GMT")
        with pytest.raises(ValueError):
            journal.complete_sdk_call(ticket, b'{}\n' + (b' ' if failure == "noncanonical" else b''), request_id="aws-id",
                server_date=server_date)
    assert journal.pending == journal.unknown == [{"kind": "sdk-call", "reference_sha256": ticket}]
    assert journal.call_receipts == [] and set(journal.call_bytes) == {c.sha(raw), ticket}
    assert journal.call_bytes[c.sha(raw)] == raw and c.sha(journal.call_bytes[ticket]) == ticket
    guard.failed = False
    with pytest.raises(ValueError):
        journal.complete_sdk_call(ticket, b'{}\n', request_id="late-id", server_date="Thu, 09 Oct 2025 08:53:20 GMT")
    with pytest.raises(ValueError):
        journal.begin_sdk_call(raw, role_session_sha256="2" * 64)
    with pytest.raises(ValueError):
        journal.observe("closed-ready", b'{"fixture":"no-success-after-unknown"}\n')
    assert journal.call_receipts == [] and journal.unknown == [{"kind": "sdk-call", "reference_sha256": ticket}]


@pytest.mark.parametrize("response", [
    {"Credentials": {"AccessKeyId": "must-not-escape"}},
    {"Item": {"nested": {"M": {"SessionToken": {"S": "must-not-escape"}}}}},
    {"input": "must-not-escape"}, {"output": "must-not-escape"},
])
def test_shared_sdk_journal_rejects_sensitive_response_before_retention(monkeypatch, response):
    from tools.cnesdata_delivery import application_gate as ag
    request, owner, window, inputs = _adapter_case("closed-ready")
    class Guard:
        def check(self, seconds=1):
            pass
    monkeypatch.setattr(ag.time, "time", lambda: 1760000000)
    journal = ag.AdapterJournal(c.canonical(request), operation="closed-ready", owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    raw = c.canonical({"role": "fence_operator", "service": "dynamodb", "operation": "get_item", "parameters": {}})
    ticket = journal.begin_sdk_call(raw, role_session_sha256="2" * 64)
    with pytest.raises(ValueError):
        journal.complete_sdk_call(ticket, c.canonical(response), request_id="aws-id", server_date="Thu, 09 Oct 2025 08:53:20 GMT")
    assert journal.unknown == [{"kind": "sdk-call", "reference_sha256": ticket}]
    assert all(b"must-not-escape" not in value for value in journal.call_bytes.values())


def test_shared_sdk_journal_cannot_accept_result_while_native_call_is_unresolved():
    from tools.cnesdata_delivery import application_gate as ag
    request, owner, window, inputs = _adapter_case("closed-ready")
    class Guard:
        def check(self, seconds=1):
            pass
    journal = ag.AdapterJournal(c.canonical(request), operation="closed-ready", owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    raw = c.canonical({"role": "fence_operator", "service": "dynamodb", "operation": "get_item", "parameters": {}})
    ticket = journal.begin_sdk_call(raw, role_session_sha256="2" * 64)
    result = {"abi_version": 3, "operation": "closed-ready", "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
              "checkpoint_sha256": window["checkpoint_sha256"], "observations": [], "call_receipts_sha256": c.sha(c.canonical([])),
              "pending": journal.pending, "unknown": []}
    with pytest.raises(ValueError):
        journal.validate_result(c.canonical(result))
    assert journal.unknown == [{"kind": "sdk-call", "reference_sha256": ticket}]


@pytest.mark.parametrize("field,value", [("role", "normal"), ("service", "sts"), ("operation", "update_item"),
                                         ("parameters", {"Credentials": {"AccessKeyId": "must-not-escape"}})])
def test_shared_sdk_journal_rejects_other_operations_before_any_record(field, value):
    from tools.cnesdata_delivery import application_gate as ag
    request, owner, window, inputs = _adapter_case("closed-ready")
    class Guard:
        def check(self, seconds=1):
            raise AssertionError("invalid intent must be rejected first")
    journal = ag.AdapterJournal(c.canonical(request), operation="closed-ready", owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    original = {"role": "fence_operator", "service": "dynamodb", "operation": "get_item", "parameters": {}}
    with pytest.raises(ValueError):
        journal.begin_sdk_call(c.canonical(original | {field: value}), role_session_sha256="2" * 64)
    assert journal.call_bytes == {} and journal.pending == journal.unknown == journal.call_receipts == []


def _durable_closed_ready_case(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag
    request, owner, window, inputs = _adapter_case("closed-ready")
    class Guard:
        def check(self, seconds=1):
            pass
    class Store:
        def __init__(self):
            self.objects, self.writes = {}, []
        def get(self, bucket, key, *, maximum, absent=False):
            assert absent is True
            return self.objects.get(key), None
        def put(self, bucket, key, raw):
            assert key not in self.objects, "existing objects must not be overwritten"
            self.writes.append(key)
            self.objects[key] = raw
    native = {"role": "fence_operator", "service": "dynamodb", "operation": "get_item", "parameters": {
        "TableName": "cnesdata-prod-control", "Key": {"pk": {"S": "ENV#prod#FENCE"}, "sk": {"S": "FENCE"}}, "ConsistentRead": True}}
    scope = {"account": "111122223333", "control_table_arn": "arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control",
             "machine_arn": "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod", "members": []}
    governance = {"role": "application", "account_id": "111122223333", "evidence_bucket": "synthetic-evidence", "evidence_prefix": "cnesdata/prod/evidence/"}
    store = Store()
    monkeypatch.setattr(ag.time, "time", lambda: 1760000000)
    def create(**overrides):
        journal = ag.AdapterJournal(c.canonical(request), operation="closed-ready", owner=owner, window=window, inputs=inputs,
            activation_sha256=request["activation_sha256"], guard=Guard())
        ledger = ag.ClosedReadyEvidence(store, governance, journal, c.canonical(native),
            **({"prepared_sha256": "3" * 64, "role_session_sha256": "2" * 64, "scope": scope} | overrides))
        return ledger, journal
    return create, store, native


def test_durable_closed_ready_preserves_original_receipt_without_replaying_sdk(monkeypatch):
    create, store, native = _durable_closed_ready_case(monkeypatch)
    ledger, journal = create()
    assert ledger.reserve() == "created"
    original_id = ledger.intent_sha256
    ticket = journal.begin_sdk_call(c.canonical(native), role_session_sha256="2" * 64)
    response = b'{"Item":{"state":{"S":"CLOSED"}}}\n'
    receipt = journal.complete_sdk_call(ticket, response, request_id="aws-id", server_date="Thu, 09 Oct 2025 08:53:20 GMT")
    ledger.complete(response, receipt)
    assert len(store.writes) == 3
    restarted, _ = create()
    assert restarted.intent_sha256 == original_id and restarted.reserve() == "settled"
    assert restarted.original_response == response and restarted.original_receipt == receipt
    assert len(store.writes) == 3
    with pytest.raises(ValueError):
        restarted.complete(response, receipt)


@pytest.mark.parametrize("point", ["after-intent", "after-io", "before-receipt", "intent-readback"])
def test_durable_closed_ready_crash_reentry_preserves_unknown_without_new_ticket(monkeypatch, point):
    create, store, native = _durable_closed_ready_case(monkeypatch)
    ledger, journal = create()
    if point == "intent-readback":
        get = store.get
        def ambiguous(bucket, key, **kwargs):
            if store.objects:
                raise TimeoutError("private response lost")
            return get(bucket, key, **kwargs)
        monkeypatch.setattr(store, "get", ambiguous)
        with pytest.raises(TimeoutError):
            ledger.reserve()
        monkeypatch.setattr(store, "get", get)
    else:
        assert ledger.reserve() == "created"
    if point in {"after-io", "before-receipt"}:
        ticket = journal.begin_sdk_call(c.canonical(native), role_session_sha256="2" * 64)
        response = b'{}\n'
        receipt = journal.complete_sdk_call(ticket, response, request_id="aws-id", server_date="Thu, 09 Oct 2025 08:53:20 GMT")
        if point == "before-receipt":
            put = store.put
            def crash(bucket, key, raw):
                if key.endswith("-receipt.json"):
                    raise SystemExit("simulated process death")
                return put(bucket, key, raw)
            monkeypatch.setattr(store, "put", crash)
            with pytest.raises(SystemExit):
                ledger.complete(response, receipt)
    prior_writes = list(store.writes)
    restarted, _ = create()
    assert restarted.intent_sha256 == ledger.intent_sha256 and restarted.reserve() == "unknown"
    assert restarted.uncertainty and restarted.original_response is None
    assert store.writes == prior_writes
    with pytest.raises(ValueError):
        restarted.reserve()


@pytest.mark.parametrize("field", ["prepared_sha256", "role_session_sha256"])
def test_durable_closed_ready_cannot_evade_pending_intent_by_changing_proof_or_session(monkeypatch, field):
    create, store, _ = _durable_closed_ready_case(monkeypatch)
    original, _ = create()
    assert original.reserve() == "created"
    changed, _ = create(**{field: "9" * 64})
    with pytest.raises(ValueError, match="intent collision"):
        changed.reserve()
    assert len(store.writes) == 1 and changed.uncertainty


@pytest.mark.parametrize("collision", ["same", "different", "unknown-committed", "unknown-absent"])
def test_durable_closed_ready_conditional_creation_reconciles_collision_not_io_replay(monkeypatch, collision):
    create, store, _ = _durable_closed_ready_case(monkeypatch)
    ledger, _ = create()
    class Collision(Exception):
        response = {"Error": {"Code": "PreconditionFailed"}}
    def concurrent(bucket, key, raw):
        if collision != "unknown-absent":
            store.objects[key] = raw if collision != "different" else b'{"foreign":true}\n'
        if collision.startswith("unknown"):
            raise TimeoutError("ambiguous write")
        raise Collision()
    monkeypatch.setattr(store, "put", concurrent)
    if collision == "same":
        assert ledger.reserve() == "unknown"
    else:
        with pytest.raises(ValueError):
            ledger.reserve()
    assert ledger.uncertainty
    with pytest.raises(ValueError):
        ledger.reserve()


def _fence_contract_case(*, original_serial=1, probe=False):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    _, owner, _, _ = _adapter_case("closed-ready")
    account = "111122223333"
    fragment = {"fragment_version": 4, "account_id": account, "region": "us-east-2",
        "application_role_arn": f"arn:aws:iam::{account}:role/cnesdata-prod-application", "application_role_name": "cnesdata-prod-application",
        "producer": {"repository": "VINIClUS/infra-ansible", "workflow_path": ".github/workflows/reusable-cnesdata-application-gate.yml",
                     "workflow_sha": "c" * 40, "source_closure_sha256": "a" * 64}, "caller_by_purpose": lc.APPLICATION_CALLERS,
        "provider_arn": f"arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com",
        "lease": {"bucket_arn": "arn:aws:s3:::synthetic-state", "key": "shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json", "kms_key_arn": "synthetic"},
        "evidence": {"bucket_arn": "arn:aws:s3:::synthetic-evidence", "prefix": "cnesdata/prod/evidence/lifecycle/", "kms_key_arn": "synthetic"},
        "delegations": {alias: f"arn:aws:iam::{account}:role/cnesdata-prod-" + suffix for alias, suffix in lc.APPLICATION_DELEGATIONS.items()},
        "trust_sha256": "a" * 64, "policy_sha256": "b" * 64, "enabled_until": c.utc(10000)}
    producer = lc.FENCE_PREPARE_PRODUCER | {"repository": c.REPOSITORY, "source_sha": owner["source_sha"], "workflow_sha": "c" * 40,
        "run_id": owner["run_id"], "run_attempt": owner["run_attempt"], "job_id": 42}
    def origin(name, source, run, digest):
        return {"repository": c.REPOSITORY, "source_sha": source, "run_id": run, "run_attempt": 1, "job_id": 42,
                "artifact_id": 43, "artifact_digest": "sha256:" + "4" * 64, "producer_name": producer["job_name"],
                "step": "applied", "name": name, "sha256": digest, "size": 100}
    carrier, old_raw = _phase_a_carrier_case(serial=original_serial, probe=probe)
    old = {name: c.loads(raw, canonical=True) for name, raw in old_raw.items()}
    old_plan, old_apply = old["envelope.json"]["plan"], old["envelope.json"]["apply"]
    origin_reference = carrier["origin"]
    projection_source_files = [{"path": "infra/opentofu/modules/runtime-iam/promotion.tf", "sha256": "e" * 64}]
    phase_a = {"source_sha": old_plan["source_sha"], "source_closure_sha256": c.sha(c.canonical(projection_source_files)),
        "release_id": old_plan["release"]["release_id"], "canary_id": old_plan["release"]["canary_id"],
        "candidate_sha256": old_plan["release"]["candidate_sha256"], "plan_binary_sha256": old_plan["binary_sha256"],
        "plan_json_sha256": old_plan["json_sha256"], "inputs_sha256": old_plan["inputs_sha256"],
        "plan_receipt": {"plan_binding_sha256": old_apply["plan_binding_sha256"], "consumed_plan_artifact": old_apply["consumed_plan_artifact"]},
        "state": old["checkpoint.json"]["state_after"], "files": {entry["name"]: {
        "repository": origin_reference["repository"], "source_sha": origin_reference["source_sha"],
        "run_id": origin_reference["run_id"], "run_attempt": origin_reference["run_attempt"],
        "job_id": origin_reference["producer_job_id"], "artifact_id": origin_reference["artifact_id"],
        "artifact_digest": origin_reference["artifact_digest"], "producer_name": origin_reference["producer_name"],
        "step": "applied", "name": entry["name"], "sha256": entry["sha256"], "size": entry["size"]}
        for entry in origin_reference["objects"] if entry["name"] in lc.FENCE_PHASE_A_FILES}}
    name = "cnesdata-prod-promotion-fence-operator"
    role = {"schema_version": 1, "role_arn": fragment["delegations"]["fence_operator"], "role_name": name, "role_id": "AROAORIGINAL",
        "policy_name": name + "-gate", "release_id": "r1", "session_name": "promotion-fence-r1", "max_session_duration": 3600,
        "tags": {"ReleaseId": "r1"}, "trust": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"AWS": fragment["application_role_arn"]}, "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:RoleSessionName": "promotion-fence-r1"}}}]},
        "policy": old["checkpoint.json"]["readbacks"][-1]["observed"]["PolicyDocument"]}
    projection = {key: role[key] for key in ("role_arn", "role_name", "role_id", "policy_name", "trust", "policy", "max_session_duration", "tags")}
    role.update(original_projection_sha256=c.sha(c.canonical(projection)), current_projection_sha256=c.sha(c.canonical(projection)))
    checkpoint = {"state": {"lineage": "original-lineage", "serial": 2, "state_sha256": "7" * 64},
        "state_object": {"status": "present", "version_id": "current-version", "etag_sha256": "8" * 64},
        "owner": owner, "purpose": "application-prepare", "plan_sha256": "a" * 64, "readbacks": [], "phase_a_originals": carrier}
    checkpoint_sha = c.sha(c.canonical(checkpoint))
    chain = {"schema_version": 3, "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
        "anchor_sha256": phase_a["files"]["checkpoint.json"]["sha256"], "head_sha256": checkpoint_sha,
        "entries": [{"sequence": 0, "checkpoint_sha256": checkpoint_sha, "previous_checkpoint_sha256": phase_a["files"]["checkpoint.json"]["sha256"],
            "state": checkpoint["state"], "state_object": checkpoint["state_object"], "origin": origin("checkpoint.json", owner["source_sha"], owner["run_id"], checkpoint_sha)}]}
    origin_current = chain["entries"][-1]["origin"]
    origin_current.pop("artifact_id")
    origin_current.pop("artifact_digest")
    origin_current["size"] = len(c.canonical(checkpoint))
    origin_current["step"] = lc.FENCE_PREPARE_PRODUCER["step"]
    documents = {"get_role": {"Role": {"RoleName": name, "Arn": role["role_arn"], "RoleId": role["role_id"], "MaxSessionDuration": 3600,
        "AssumeRolePolicyDocument": role["trust"], "Tags": [{"Key": "ReleaseId", "Value": "r1"}]}},
        "list_role_policies": {"PolicyNames": [name + "-gate"], "IsTruncated": False},
        "list_attached_role_policies": {"AttachedPolicies": [], "IsTruncated": False},
        "get_role_policy": {"RoleName": name, "PolicyName": name + "-gate", "PolicyDocument": role["policy"]}}
    rounds = []
    for observed in (1000, 1010):
        reports = []
        for operation, document in documents.items():
            parameters = {"RoleName": name}
            if operation.startswith("list_"): parameters["MaxItems"] = 100
            if operation == "get_role_policy": parameters["PolicyName"] = name + "-gate"
            reports.append({"service": "iam", "operation": operation, "parameters": parameters,
                "response": document | {"ResponseMetadata": {"RequestId": f"id-{observed}-{operation}", "HTTPStatusCode": 200,
                    "HTTPHeaders": {"date": "Thu, 01 Jan 1970 00:16:40 GMT"}}}})
        rounds.append({"observed_at": observed, "observations": reports})
    payloads = {"checkpoint.json": checkpoint, "approval.json": {"version": 1, "owner": owner, "purpose": "application-prepare",
        "direction": "advance", "plan_sha256": "a" * 64, "inputs_sha256": "b" * 64, "checkpoint_sha256": phase_a["files"]["checkpoint.json"]["sha256"],
        "delta": {"purpose": "application-prepare", "direction": "advance", "mode": "operational", "before": {}, "original": {}, "created": {}, "expected_changes_sha256": "f" * 64},
        "drift_matrix": {}, "readbacks": {"before": [], "after": []}}, "fence-role.json": role,
        "fence-origins.json": {"schema_version": 1, "phase_a": phase_a, "current_source_sha": owner["source_sha"], "current_source_closure_sha256": "b" * 64,
            "current_plan": {"source_sha": owner["source_sha"], "run_id": owner["run_id"], "run_attempt": owner["run_attempt"], "step": "prepare-plan",
                "index_sha256": "d" * 64, "plan_binary_sha256": "a" * 64, "plan_json_sha256": "c" * 64, "inputs_sha256": "b" * 64},
            "projection_source_files": projection_source_files},
        "fence-chain.json": chain, "fence-readbacks.json": {"proof_kind": "iam-readback-and-evaluation", "readbacks": rounds},
        "fence-evaluation.json": {"schema_version": 1, "evaluator_source_sha": producer["workflow_sha"],
            "documents": {key: "e" * 64 for key in ("application_identity", "application_managed", "application_session", "fence_identity", "fence_session", "freeze")},
            "cases": [{"case_id": key, "action": action, "resource": "synthetic-only", "context": {}, "expected": False, "observed": False}
                      for key, action in lc.FENCE_EVALUATION_CASES.items()]}}
    preparation = {"admitted_at": 1000, "deadline": 1900, "observed_at": 1010}
    manifest = {"schema_version": 1, "proof_kind": "iam-readback-and-evaluation", "operation": "closed-ready", "application_purpose": "promotion",
        "context_kind": "promotion", "owner": owner, "caller_binding_sha256": owner["caller_binding_sha256"], "activation_sha256": "1" * 64,
        "application_fragment_sha256": c.sha(c.canonical(fragment)), "producer": producer, "preparation": preparation, "files": [], "outcome": "observed"}
    def encode():
        originals = {name: c.canonical(value) for name, value in payloads.items()}
        manifest["files"] = [{"name": name, "sha256": c.sha(raw), "size": len(raw)} for name, raw in sorted(originals.items())]
        return originals | {"fence-prepared.json": c.canonical(manifest)}, originals
    return payloads, manifest, dict(owner=owner, fragment=fragment, activation_sha256="1" * 64, producer=producer, preparation=preparation,
        predecessor_raw=old_raw["checkpoint.json"], predecessor_reference=carrier["origin"]), encode


@pytest.mark.parametrize("mutation", [None, "old-fragment", "owner-bool", "plan-producer", "source", "extra-file", "missing-original",
    "history-file", "history-hash", "history-valid-hash", "history-role", "chain-anchor", "lineage", "trust", "readbacks", "evaluation",
    "closure-fixed", "closure-other-files"])
def test_fence_package_contract_separates_historical_source_and_current_owner(mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    payloads, manifest, kwargs, encode = _fence_contract_case()
    if mutation == "old-fragment": kwargs["fragment"]["fragment_version"] = 3
    if mutation == "owner-bool": manifest["owner"]["run_attempt"] = True
    if mutation == "plan-producer": manifest["producer"]["workflow_path"] = ".github/workflows/reusable-cnesdata-infra-plan-gate.yml"
    if mutation == "source": payloads["fence-origins.json"]["current_source_sha"] = "9" * 40
    if mutation == "history-file": payloads["fence-origins.json"]["phase_a"]["files"].pop("envelope.json")
    if mutation == "history-hash": payloads["fence-origins.json"]["phase_a"]["plan_receipt"]["consumed_plan_artifact"]["artifact_sha256"] = "not-a-digest"
    if mutation == "history-valid-hash": payloads["fence-origins.json"]["phase_a"]["plan_receipt"]["consumed_plan_artifact"]["artifact_sha256"] = "0" * 64
    if mutation == "history-role":
        role = payloads["fence-role.json"]
        role["policy"] = {"Version": "2012-10-17", "Statement": []}
        projection = {key: role[key] for key in ("role_arn", "role_name", "role_id", "policy_name", "trust", "policy", "max_session_duration", "tags")}
        role["original_projection_sha256"] = role["current_projection_sha256"] = c.sha(c.canonical(projection))
        for round in payloads["fence-readbacks.json"]["readbacks"]:
            next(x for x in round["observations"] if x["operation"] == "get_role_policy")["response"]["PolicyDocument"] = role["policy"]
    if mutation == "chain-anchor":
        payloads["fence-chain.json"]["anchor_sha256"] = "e" * 64
        payloads["fence-chain.json"]["entries"][0]["previous_checkpoint_sha256"] = "e" * 64
    if mutation == "lineage": payloads["fence-chain.json"]["entries"][0]["state"]["lineage"] = "foreign"
    if mutation == "trust": payloads["fence-role.json"]["trust"]["Statement"][0]["Principal"]["AWS"] += "-historical"
    if mutation == "readbacks": payloads["fence-readbacks.json"]["readbacks"] = []
    if mutation == "evaluation": payloads["fence-evaluation.json"]["cases"][0]["observed"] = True
    # Item 4 of the 2026-11-13 amendment: the historical closure commits the traversed projection files.
    if mutation == "closure-fixed": payloads["fence-origins.json"]["phase_a"]["source_closure_sha256"] = "9" * 64
    if mutation == "closure-other-files":
        payloads["fence-origins.json"]["projection_source_files"] = [
            {"path": "infra/opentofu/modules/runtime-iam/promotion.tf", "sha256": "f" * 64}]
    files, originals = encode()
    if mutation == "extra-file": files["state.json"] = b'{}\n'
    if mutation == "missing-original": originals.pop("approval.json")
    if mutation:
        with pytest.raises(ValueError): lc.validate_fence_prepared_package(files, originals=originals, **kwargs)
    else:
        result = lc.validate_fence_prepared_package(files, originals=originals, **kwargs)
        assert result["outcome"] == "observed"
        assert payloads["fence-origins.json"]["phase_a"]["state"] != payloads["checkpoint.json"]["state"]



@pytest.mark.parametrize("mutation", [None, "large-input", "dirty", "stdout", "timeout", "call", "source-write", "descendant"])
def test_fixed_adapter_subprocess_has_no_credentials_and_preserves_original_observation(tmp_path, monkeypatch, mutation):
    import subprocess
    from tools.cnesdata_delivery.application_gate import AdapterJournal, invoke_adapter
    product = tmp_path / "product"
    product.mkdir()
    script = product / "scripts/promotion/promote_api.py"
    script.parent.mkdir(parents=True)
    code = r"""import hashlib, json, os, subprocess, time

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def execute_shared_operation(operation, request, context):
    original = context.read('candidate')
    context.guard()
    MUTATION
    observed = canonical({'fixture_only': True, 'input_sha256': hashlib.sha256(original).hexdigest(),
                          'credentials_absent': all(name not in os.environ for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN'))})
    digest = context.observe('inventory', observed)
    return {'abi_version': 3, 'operation': operation, 'owner_sha256': request['owner']['owner_sha256'],
            'generation': request['owner']['generation'], 'checkpoint_sha256': request['checkpoint_sha256'],
            'observations': [{'kind': 'inventory', 'sha256': digest, 'size': len(observed)}],
            'call_receipts_sha256': hashlib.sha256(canonical([])).hexdigest(), 'pending': [], 'unknown': []}
"""
    actions = {None: "pass", "large-input": "pass", "dirty": "pass", "stdout": "print('unframed product output', flush=True)", "timeout": "time.sleep(10)",
               "call": "context.call('normal', 's3', 'delete_object', {'Bucket': 'caller', 'Key': 'caller'})",
               "source-write": "open(__file__, 'a').write('# changed during execution')",
               "descendant": "subprocess.Popen(['/usr/bin/sleep', '10'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"}
    script.write_text(code.replace("MUTATION", actions[mutation]))
    def git(*args):
        return subprocess.run(["git", *args], cwd=product, check=True, capture_output=True).stdout.decode().strip()
    git("init", "-q")
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "isolated adapter fixture")
    source = git("rev-parse", "HEAD")
    manifest = {"version": 1, "source_sha": source, "files": {"scripts/promotion/promote_api.py": c.sha(script.read_bytes())}}
    request, owner, window, inputs = _adapter_case()
    owner["source_sha"] = request["source_sha"] = request["owner"]["source_sha"] = source
    if mutation == "large-input":
        inputs["candidate"] = b"x" * (2 * 1024**2)
        request["inputs"]["candidate"] = {"size": len(inputs["candidate"]), "sha256": c.sha(inputs["candidate"])}
    class Guard:
        def check(self, seconds=1):
            assert seconds <= 20
    journal = AdapterJournal(c.canonical(request), operation="inventory", owner=owner, window=window, inputs=inputs,
                             activation_sha256=request["activation_sha256"], guard=Guard())
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic-parent-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-parent-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-parent-token")
    if mutation == "dirty":
        script.write_text(script.read_text() + "# dirty before launch")
    args = {"product": product, "source": source, "manifest": manifest, "manifest_sha256": c.sha(c.canonical(manifest)),
            "journal": journal, "timeout": 1 if mutation == "timeout" else 10}
    if mutation and mutation != "large-input":
        with pytest.raises(ValueError):
            invoke_adapter(**args)
    else:
        raw = invoke_adapter(**args)
        result = c.loads(raw, canonical=True)
        observed = c.loads(journal.observation_bytes[result["observations"][0]["sha256"]], canonical=True)
        assert observed["credentials_absent"] is True
        assert observed["input_sha256"] == c.sha(inputs["candidate"])
        assert git("status", "--porcelain", "--ignored", "--untracked-files=all") == ""



@pytest.mark.parametrize("resolution", ["TERMINAL", "CANCEL_BEFORE_SEND"])
@pytest.mark.parametrize("mutation", [None, "role", "metadata", "machine", "dispatch", "member-ref", "generation", "purpose"])
def test_closed_ready_probe_request_is_fresh_exact_member_and_metadata_only(resolution, mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    request, _, _, _ = _adapter_case("closed-ready")
    machine = "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod"
    execution = machine.replace(":stateMachine:", ":execution:") + ":" + "a" * 16
    member = {"dispatch_id": "a" * 16, "request_sha256": "b" * 64, "generation": 3, "initial_state": "RESERVED",
              "execution_ref": execution if resolution == "TERMINAL" else None, "resolution": resolution,
              "proof_sha256": "c" * 64, "observed_at": c.utc(1000), "send_disabled_at": c.utc(999)}
    params, role = {"executionArn": execution, "includedData": "METADATA_ONLY"}, "fence_operator"
    if mutation == "role":
        role = "observer"
    if mutation == "metadata":
        params["includedData"] = "ALL_DATA"
    if mutation == "machine":
        params["executionArn"] = execution.replace(":cnesdata-prod:", ":foreign:")
    if mutation == "dispatch":
        params["executionArn"] = execution[:-16] + "f" * 16
    if mutation == "member-ref":
        member["execution_ref"] = execution + "bad"
    if mutation == "generation":
        member["generation"] = True
    if mutation == "purpose":
        request["operation"] = "inventory"
    args = {"request": request, "role": role, "service": "stepfunctions", "operation": "describe_execution", "parameters": params,
            "account": "111122223333", "control_table_arn": "arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control-plane",
            "machine_arn": machine, "members": [member]}
    if mutation:
        with pytest.raises(ValueError):
            lc.validate_closed_ready_call(**args)
    else:
        assert lc.validate_closed_ready_call(**args) == params


@pytest.mark.parametrize("target", ["fence", "semaphore", "tenant", "eventual", "projection", "other-table"])
def test_closed_ready_dynamodb_read_is_only_strong_fence_and_semaphore(target):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    request, _, _, _ = _adapter_case("closed-ready")
    pk, sk = ("ENV#prod#SEMAPHORE", "UNIT") if target == "semaphore" else ("ENV#prod#FENCE", "FENCE")
    params = {"TableName": "cnesdata-prod-control-plane", "Key": {"pk": {"S": pk}, "sk": {"S": sk}}, "ConsistentRead": True}
    if target == "tenant":
        params["Key"]["pk"]["S"] = "TENANT#private"
    if target == "eventual":
        params["ConsistentRead"] = False
    if target == "projection":
        params["ProjectionExpression"] = "pk"
    if target == "other-table":
        params["TableName"] = "other"
    args = {"request": request, "role": "fence_operator", "service": "dynamodb", "operation": "get_item", "parameters": params,
            "account": "111122223333", "control_table_arn": "arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control-plane",
            "machine_arn": "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod", "members": []}
    if target in {"fence", "semaphore"}:
        assert lc.validate_closed_ready_call(**args) == params
    else:
        with pytest.raises(ValueError):
            lc.validate_closed_ready_call(**args)


@pytest.mark.parametrize("mutation", [None, "input", "output", "execution", "machine", "status"])
def test_closed_ready_probe_response_never_serializes_unexpected_execution_payload(mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    machine = "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod"
    execution = machine.replace(":stateMachine:", ":execution:") + ":" + "a" * 16
    raw = {"executionArn": execution, "stateMachineArn": machine, "name": "a" * 16, "status": "SUCCEEDED",
           "startDate": c.utc(1000), "stopDate": c.utc(1001), "cause": "not exported", "traceHeader": "not exported"}
    if mutation in {"input", "output"}:
        raw[mutation] = "SYNTHETIC_PRIVATE_PAYLOAD_MUST_NOT_APPEAR"
    if mutation == "execution":
        raw["executionArn"] += "wrong"
    if mutation == "machine":
        raw["stateMachineArn"] += "wrong"
    if mutation == "status":
        raw["status"] = "UNKNOWN"
    if mutation:
        with pytest.raises(ValueError) as error:
            lc.closed_ready_probe_response(raw, execution_arn=execution, machine_arn=machine)
        assert "SYNTHETIC_PRIVATE_PAYLOAD_MUST_NOT_APPEAR" not in str(error.value)
    else:
        result = lc.closed_ready_probe_response(raw, execution_arn=execution, machine_arn=machine)
        assert set(result) == {"executionArn", "stateMachineArn", "name", "status", "startDate", "stopDate"}



@pytest.mark.parametrize("name", ["cnesdata-prod", "cnesdata-prod-processor", "cnesdata-prod-x", "cnesdata-production", "foreign"])
def test_fence_scope_admits_only_the_exact_cnesdata_prod_state_machine(name):
    """Correction 2 (6906181994): the real machine is exactly `cnesdata-prod` (step_functions.tf:13, name_prefix)."""
    from tools.cnesdata_delivery import lifecycle_contract as lc, lifecycle_runtime as lr, session_policy
    account = "111122223333"
    machine = f"arn:aws:states:us-east-2:{account}:stateMachine:{name}"
    prefix = machine.replace(":stateMachine:", ":execution:") + ":"
    table = f"arn:aws:dynamodb:us-east-2:{account}:table/cnesdata-prod-control-plane"
    request, _, _, _ = _adapter_case("closed-ready")
    member = {"dispatch_id": "a" * 16, "request_sha256": "b" * 64, "generation": 1, "initial_state": "NOT_SENT",
              "execution_ref": None, "resolution": "CANCEL_BEFORE_SEND", "proof_sha256": "c" * 64,
              "observed_at": c.utc(1200), "send_disabled_at": c.utc(1199)}
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": table},
        {"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": prefix + "*"}]}
    checks = {
        "validator": lambda: lc.validate_closed_ready_call(
            request=request, role="fence_operator", service="stepfunctions", operation="describe_execution",
            parameters={"executionArn": prefix + "a" * 16, "includedData": "METADATA_ONLY"}, account=account,
            control_table_arn=table, machine_arn=machine, members=[member]),
        "scope": lambda: lr.fence_policy_scope({"account_id": account}, policy),
        "session": lambda: session_policy.fence_session_policy(control_table_arn=table, execution_prefix=prefix, deadline=1480),
        "close-validator": lambda: lc.validate_close_drain_call(
            request=_adapter_case("close-drain")[0], role="fence_operator", service="dynamodb", operation="get_item",
            parameters={"TableName": "cnesdata-prod-control-plane", "Key": {"pk": {"S": "ENV#prod#FENCE"}, "sk": {"S": "FENCE"}},
                        "ConsistentRead": True}, account=account, control_table_arn=table, machine_arn=machine),
    }
    for site, check in checks.items():
        if name != "cnesdata-prod":
            with pytest.raises(ValueError):
                check()
            continue
        result = check()
        if site == "scope":
            assert result == {"control_table_arn": table, "execution_prefix": prefix, "machine_arn": machine}


CLOSE_ACCOUNT = "111122223333"
CLOSE_SCOPE = {"account": CLOSE_ACCOUNT,
               "control_table_arn": f"arn:aws:dynamodb:us-east-2:{CLOSE_ACCOUNT}:table/cnesdata-prod-control-plane",
               "machine_arn": f"arn:aws:states:us-east-2:{CLOSE_ACCOUNT}:stateMachine:cnesdata-prod"}
CLOSE_SEMAPHORE = {"pk": {"S": "ENV#prod#SEMAPHORE"}, "sk": {"S": "UNIT"}, "token": {"S": "t-1"},
                   "fence_version": {"N": "3"}, "updated_at": {"S": "2026-11-17T10:00:00Z"}}
CLOSE_ORDER = ("describe_execution", "get_item", "get_item-semaphore", "transact_write_items", "describe_execution",
               "update_item", "get_item")


def _semaphore_check(check, item, names):
    check["ExpressionAttributeNames"] = {f"#v{index}": name for index, name in enumerate(names)}
    check["ConditionExpression"] = " AND ".join(f"#v{index} = :v{index}" if name in item else f"attribute_not_exists(#v{index})"
                                                for index, name in enumerate(names))
    check["ExpressionAttributeValues"] = {f":v{index}": item[name] for index, name in enumerate(names) if name in item}
    return check


def _close_drain_calls(owner_sha256, *, item=CLOSE_SEMAPHORE, variant=0):
    """Concrete product calls rebuilt from the pinned vector: probe, strong reads, close, confirm."""
    import copy
    from fixtures.cnesdata_delivery_lifecycle import CLOSE_DRAIN_CALL_VECTOR as vector
    calls = {call["operation"] + ("-semaphore" if "SEMAPHORE" in c.canonical(call).decode() else ""): copy.deepcopy(call)
             for call in vector["calls"]}
    calls["describe_execution"]["parameters"]["executionArn"] = (
        CLOSE_SCOPE["machine_arn"].replace(":stateMachine:", ":execution:") + ":0123456789abcdef")
    update = copy.deepcopy(vector["close_transaction"]["update"][variant]["Update"])
    concrete = {":changed": {"S": "2026-11-17T10:01:00Z"}, ":entity": {"S": "PROMOTIONFENCE"}, ":expected": {"N": "3"},
                ":membership": {"S": "[]"}, ":membership_sha": {"S": "7" * 64}, ":open": {"S": "OPEN"},
                ":promotion": {"S": owner_sha256}, ":receipt": {"S": "{}"}, ":state": {"S": "CLOSED"}, ":version": {"N": "4"}}
    update["ExpressionAttributeValues"] = {key: concrete[key] for key in update["ExpressionAttributeValues"]}
    check = copy.deepcopy(vector["close_transaction"]["condition_check"][0 if item else 1]["ConditionCheck"])
    if item:
        check = _semaphore_check(check, item, sorted(set(item) - {"pk", "sk"} | {"holder_run_id"}))
    calls["transact_write_items"]["parameters"] = {"TransactItems": [{"Update": update}, {"ConditionCheck": check}]}
    calls["update_item"]["parameters"]["ExpressionAttributeValues"] = {
        ":closed": {"S": "CLOSED"}, ":confirmed": {"S": "2026-11-17T10:01:01Z"}, ":version": {"N": "4"}}
    return calls


def _close_responses(item):
    fence = {"pk": {"S": "ENV#prod#FENCE"}, "sk": {"S": "FENCE"}, "state": {"S": "OPEN"}, "version": {"N": "3"}}
    return {"describe_execution": {"Error": {"Code": "ExecutionDoesNotExist"}}, "get_item": {"Item": fence},
            "get_item-semaphore": {"Item": item} if item else {}, "transact_write_items": {}, "update_item": {}}


def test_close_drain_templates_are_the_pinned_product_vector():
    """Correction 6906038586 item 3: CnesData 2c66f62c close_drain_call_vector.json, sha256 44d0cf91...4b63."""
    from fixtures.cnesdata_delivery_lifecycle import CLOSE_DRAIN_CALL_VECTOR as vector
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert c.sha(c.canonical(vector)) == "44d0cf91a69cd21ff91347887313026402ca19a483391946b046deefe93c4b63"
    expected = {}
    for call in vector["calls"]:
        expected.setdefault(call["operation"], set()).add(c.sha(c.canonical(call)))
    for name, items in vector["close_transaction"].items():
        expected["close_transaction." + name] = {c.sha(c.canonical(item)) for item in items}
    assert lc.CLOSE_DRAIN_TEMPLATES == {key: frozenset(value) for key, value in expected.items()}
    assert lc.FENCE_SDK_OPERATIONS == {
        "closed-ready": {("dynamodb", "get_item"), ("stepfunctions", "describe_execution")},
        "close-drain": {(call["service"], call["operation"]) for call in vector["calls"]}}
    assert vector["role"] == "fence_operator" and vector["execution_arn"].endswith(":execution:cnesdata-prod:<dispatch_id>")


@pytest.mark.parametrize("variant", [0, 1])
@pytest.mark.parametrize("semaphore", ["held", "absent"])
def test_close_drain_calls_admit_the_product_vector_in_close_order(variant, semaphore):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    request, *_ = _adapter_case("close-drain")
    item = CLOSE_SEMAPHORE if semaphore == "held" else None
    calls, responses, history = _close_drain_calls(request["owner"]["owner_sha256"], item=item, variant=variant), _close_responses(item), []
    for name in CLOSE_ORDER:
        call = calls[name]
        assert lc.validate_close_drain_call(request=request, history=history, **call, **CLOSE_SCOPE) == call["parameters"]
        assert lc.validate_fence_call(request=request, history=history, **call, **CLOSE_SCOPE) == call["parameters"]
        history.append({"call": call, "response": responses[name]})


CLOSE_MUTATIONS = {
    "put-item": "transact_write_items", "role": "get_item", "stage-api": "describe_execution", "closed-stage": "describe_execution",
    "machine": "describe_execution", "table": "get_item", "execution-foreign": "describe_execution", "execution-name": "describe_execution",
    "all-data": "describe_execution", "eventual": "get_item", "tenant-key": "get_item", "no-semaphore-read": "transact_write_items",
    "second-close": "transact_write_items", "confirm-first": "update_item", "second-confirm": "update_item",
    "promotion": "transact_write_items", "open-state": "transact_write_items", "entity": "transact_write_items",
    "version-zero": "transact_write_items", "cas-value": "transact_write_items", "cas-missing": "transact_write_items",
    "cas-unsorted": "transact_write_items", "cas-absent-variant": "transact_write_items",
    "cas-held-variant": "transact_write_items", "update-extra": "transact_write_items", "three-items": "transact_write_items",
    "confirm-version": "update_item", "confirm-closed": "update_item", "confirm-untyped": "update_item",
    "closed-ready-request": "describe_execution", "open-value": "transact_write_items",
    "no-read-absent": "transact_write_items"}


@pytest.mark.parametrize("mutation", sorted(CLOSE_MUTATIONS))
def test_close_drain_calls_refuse_anything_outside_the_pinned_close(mutation):
    import copy
    from tools.cnesdata_delivery import lifecycle_contract as lc
    request, *_ = _adapter_case("close-drain")
    item = None if mutation in {"cas-held-variant", "no-read-absent"} else CLOSE_SEMAPHORE
    calls, responses, history = _close_drain_calls(request["owner"]["owner_sha256"], item=item), _close_responses(item), []
    scope = dict(CLOSE_SCOPE)
    order = list(CLOSE_ORDER)
    if mutation in {"no-semaphore-read", "no-read-absent"}: order.remove("get_item-semaphore")
    if mutation == "second-close": order.insert(4, "transact_write_items")
    if mutation == "confirm-first": order.remove("transact_write_items")
    if mutation == "second-confirm": order.insert(6, "update_item")
    target = {"second-close": 4, "second-confirm": 6}.get(mutation, order.index(CLOSE_MUTATIONS[mutation]))
    if mutation == "stage-api": request = _adapter_case("closed-ready")[0] | {"operation": "close-drain"}
    if mutation == "closed-stage": request["stage"]["close"] = 1000
    if mutation == "closed-ready-request": request["operation"] = "closed-ready"
    if mutation == "machine": scope["machine_arn"] += "-x"
    if mutation == "table": scope["control_table_arn"] = scope["control_table_arn"].replace("control-plane", "other")
    for index, name in enumerate(order):
        call = copy.deepcopy(calls[name])
        if index == target:
            parameters, update = call["parameters"], call["parameters"].get("TransactItems", [{}])[0].get("Update", {})
            values = update.get("ExpressionAttributeValues", parameters.get("ExpressionAttributeValues", {}))
            check = call["parameters"].get("TransactItems", [{}, {}])[1].get("ConditionCheck", {})
            if mutation == "put-item": call["operation"] = "put_item"
            if mutation == "role": call["role"] = "observer"
            if mutation == "execution-foreign": parameters["executionArn"] = parameters["executionArn"].replace(":cnesdata-prod:", ":foreign:")
            if mutation == "execution-name": parameters["executionArn"] = parameters["executionArn"][:-1]
            if mutation == "all-data": parameters["includedData"] = "ALL_DATA"
            if mutation == "eventual": parameters["ConsistentRead"] = False
            if mutation == "tenant-key": parameters["Key"]["pk"]["S"] = "TENANT#private"
            if mutation == "promotion": values[":promotion"] = {"S": "5" * 64}
            if mutation == "open-state": values[":state"] = {"S": "OPEN"}
            if mutation == "open-value": values[":open"] = {"S": "CLOSED"}
            if mutation == "entity": values[":entity"] = {"S": "UNITPERMIT"}
            if mutation == "version-zero": values[":version"] = {"N": "0"}
            if mutation == "cas-value": check["ExpressionAttributeValues"][":v2"] = {"S": "t-2"}
            if mutation == "cas-missing": _semaphore_check(check, CLOSE_SEMAPHORE, ["holder_run_id", "token", "updated_at"])
            if mutation == "cas-unsorted": _semaphore_check(check, CLOSE_SEMAPHORE, ["updated_at", "token", "holder_run_id", "fence_version"])
            if mutation == "cas-absent-variant":
                call["parameters"]["TransactItems"][1] = {"ConditionCheck": {key: check[key] for key in ("TableName", "Key")}
                                                          | {"ConditionExpression": "attribute_not_exists(pk)"}}
            if mutation == "cas-held-variant": _semaphore_check(check, CLOSE_SEMAPHORE, sorted(set(CLOSE_SEMAPHORE) - {"pk", "sk"}))
            if mutation == "update-extra": update["ReturnValuesOnConditionCheckFailure"] = "ALL_OLD"
            if mutation == "three-items": parameters["TransactItems"].append(copy.deepcopy(parameters["TransactItems"][1]))
            if mutation == "confirm-version": values[":version"] = {"N": "5"}
            if mutation == "confirm-closed": values[":closed"] = {"S": "OPEN"}
            if mutation == "confirm-untyped": values[":confirmed"] = {"N": "1"}
            with pytest.raises(ValueError):
                lc.validate_close_drain_call(request=request, history=history, **call, **scope)
            return
        assert lc.validate_fence_call(request=request, history=history, **call, **scope) == call["parameters"]
        history.append({"call": call, "response": responses[name]})
    pytest.fail("mutation target not reached")


def _close_role_policy():
    from fixtures.cnesdata_delivery_lifecycle import fence_projection_case
    *_, readbacks = fence_projection_case(probe=True)
    return next(row["observed"]["PolicyDocument"] for row in readbacks if row["operation"] == "get_role_policy")


def test_fence_close_session_policy_is_the_per_item_subset_of_the_fence_operator_role():
    """Decision 4: TransactWriteItems is authorized per item; it is not an IAM action (Service Authorization Reference)."""
    from tools.cnesdata_delivery import session_policy
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    role = _close_role_policy()
    table, prefix = role["Statement"][0]["Resource"], role["Statement"][-1]["Resource"][:-1]
    session = session_policy.fence_close_session_policy(control_table_arn=table, execution_prefix=prefix, deadline=1900)
    encoded = c.canonical(session).decode().strip()
    assert len(encoded) <= 2048 and "TransactWriteItems" not in encoded and "*" not in encoded.replace(prefix + "*", "")
    for statement in session["Statement"]:
        condition = dict(statement["Condition"])
        assert condition.pop("DateLessThan") == {"aws:CurrentTime": c.utc(1900)}
        assert ({"Effect": "Allow", "Action": statement["Action"], "Resource": statement["Resource"]}
                | ({"Condition": condition} if condition else {})) in role["Statement"]
    grants = {("dynamodb:GetItem", "ENV#prod#FENCE"), ("dynamodb:GetItem", "ENV#prod#SEMAPHORE"),
              ("dynamodb:UpdateItem", "ENV#prod#FENCE"), ("dynamodb:ConditionCheckItem", "ENV#prod#SEMAPHORE")}
    live = {"aws:CurrentTime": c.utc(1899)}
    for action in ("dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem", "dynamodb:PutItem",
                   "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:TransactWriteItems"):
        for key in ("ENV#prod#FENCE", "ENV#prod#SEMAPHORE", "TENANT#private"):
            context = live | {"dynamodb:LeadingKeys": [key]}
            assert effective_iam(role, [session], action, table, context) is ((action, key) in grants), (action, key)
            assert effective_iam(role, [session], action, table, context | {"aws:CurrentTime": c.utc(1900)}) is False
    assert effective_iam(role, [session], "states:DescribeExecution", prefix + "0" * 16, live) is True
    assert effective_iam(role, [session], "states:DescribeExecution", prefix + "0" * 16, {"aws:CurrentTime": c.utc(1900)}) is False


@pytest.mark.parametrize("builder", ["fence_session_policy", "fence_close_session_policy"])
@pytest.mark.parametrize("mutation", ["prefix-wildcard", "prefix-colon", "prefix-machine", "table", "deadline-bool"])
def test_fence_close_and_ready_session_policies_reject_non_exact_scope(builder, mutation):
    from tools.cnesdata_delivery import session_policy
    build = getattr(session_policy, builder)
    kwargs = dict(control_table_arn="arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control",
                  execution_prefix="arn:aws:states:us-east-2:111122223333:execution:cnesdata-prod:", deadline=1480)
    build(**kwargs)
    if mutation == "prefix-wildcard": kwargs["execution_prefix"] += "*"
    if mutation == "prefix-colon": kwargs["execution_prefix"] = kwargs["execution_prefix"][:-1]
    if mutation == "prefix-machine": kwargs["execution_prefix"] = kwargs["execution_prefix"].replace("cnesdata-prod:", "cnesdata-prod-x:")
    if mutation == "table": kwargs["control_table_arn"] += "*"
    if mutation == "deadline-bool": kwargs["deadline"] = True
    with pytest.raises(ValueError):
        build(**kwargs)


def _close_drain_broker_case(monkeypatch, *, item=CLOSE_SEMAPHORE):
    """Real shared journal, evidence and broker over a close-drain request; S3, the native SDK and the clock are fakes."""
    from email.utils import formatdate
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag
    request, owner, window, inputs = _adapter_case("close-drain")
    class Guard:
        def check(self, seconds=0): pass
    journal = ag.AdapterJournal(c.canonical(request), operation="close-drain", owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    governance = {"role": "application", "account_id": CLOSE_ACCOUNT, "evidence_bucket": "synthetic-evidence",
                  "evidence_prefix": "cnesdata/prod/evidence/"}
    session = ag._FenceSession(None, "9" * 64, CLOSE_SCOPE, 1900, c.sha(c.canonical(journal._request)), None)
    objects, native, errors = {}, [], {}
    class Evidence:
        def get(self, bucket, key, *, maximum, absent=False):
            return objects.get(key), "etag"
        def put(self, bucket, key, raw):
            assert key not in objects
            objects[key] = raw
    class NativeError(Exception):
        def __init__(self, code, **extra):
            self.response = {"Error": {"Code": code, "Message": "never retained native text"}, **extra,
                             "ResponseMetadata": {"RequestId": "native-error", "HTTPStatusCode": 400,
                                                  "HTTPHeaders": {"date": formatdate(1300, usegmt=True)}}}
    responses = _close_responses(item)
    def sdk(service, operation, **parameters):
        name = operation + ("-semaphore" if "SEMAPHORE" in c.canonical(parameters).decode() and operation == "get_item" else "")
        native.append(name)
        if name in errors:
            raise errors[name]
        if name == "describe_execution":
            raise NativeError("ExecutionDoesNotExist")
        metadata = {"RequestId": "native-" + str(len(native)), "HTTPStatusCode": 200,
                    "HTTPHeaders": {"date": formatdate(1300, usegmt=True)}}
        return responses[name] | {"ResponseMetadata": metadata}
    session.client = SimpleNamespace(call=sdk)
    monkeypatch.setattr(ag.time, "time", lambda: 1300)
    broker = ag.ClosedReadyBroker(Evidence(), governance, journal, session, prepared_sha256="3" * 64, clock=lambda: 1300)
    calls = _close_drain_calls(request["owner"]["owner_sha256"], item=item)
    frames = {name: c.canonical({"kind": "call", **call}) for name, call in calls.items()}
    return ag, journal, broker, frames, native, objects, errors, NativeError


@pytest.mark.parametrize("semaphore", ["held", "absent"])
def test_close_drain_broker_runs_the_product_close_with_one_durable_attempt_per_call(monkeypatch, semaphore):
    """Decision 4: one durable intent, response and receipt per call; writes return only an empty result."""
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    item = CLOSE_SEMAPHORE if semaphore == "held" else None
    ag, journal, broker, frames, native, objects, _, _ = _close_drain_broker_case(monkeypatch, item=item)
    replies = [ag._adapter_message(frames[name], journal) for name in CLOSE_ORDER]
    assert [result for _, result in replies] == [None] * len(CLOSE_ORDER) and native == list(CLOSE_ORDER)
    assert replies[0][0] == replies[4][0] == {"kind": "sdk-error", "code": "ExecutionDoesNotExist"}
    assert replies[3][0] == replies[5][0] == {"kind": "sdk-result", "value": {}}
    assert replies[2][0] == {"kind": "sdk-result", "value": {"Item": item} if item else {}}
    assert len(journal.call_receipts) == len(CLOSE_ORDER) == len(objects) // 3 and not journal.unknown and not broker.uncertainty
    assert all(b"never retained" not in raw for raw in objects.values())
    first = broker.evidence[0]
    intent = c.loads(objects[first._keys["intent"]], canonical=True)
    frame = c.loads(frames["describe_execution"], canonical=True)
    assert intent["operation"] == "close-drain" and intent["call"] == {key: frame[key] for key in frame if key != "kind"}
    request = journal._request
    keys = lr.closed_ready_evidence_keys({"evidence_prefix": "cnesdata/prod/evidence/"}, owner=request["owner"],
        caller=journal._identity, checkpoint_sha256=request["checkpoint_sha256"], sequence=0, operation="close-drain")
    assert first._keys == keys and "/close-drain/sdk-" in keys["intent"]
    assert keys != lr.closed_ready_evidence_keys({"evidence_prefix": "cnesdata/prod/evidence/"}, owner=request["owner"],
        caller=journal._identity, checkpoint_sha256=request["checkpoint_sha256"], sequence=0)


def test_closed_ready_evidence_keys_stay_byte_identical():
    """The prepared evaluation binds the closed-ready intent key; close-drain gets its own namespace and hash."""
    from tools.cnesdata_delivery import lifecycle_contract as lc, lifecycle_runtime as lr
    request, owner, _, _ = _adapter_case("closed-ready")
    arguments = dict(owner=request["owner"], caller=lc.application_identity(owner, required=True),
                     checkpoint_sha256=request["checkpoint_sha256"], sequence=0)
    governance = {"evidence_prefix": "cnesdata/prod/evidence/"}
    keys = lr.closed_ready_evidence_keys(governance, **arguments)
    assert keys == lr.closed_ready_evidence_keys(governance, **arguments, operation="closed-ready")
    assert keys["intent"] == ("cnesdata/prod/evidence/lifecycle/" + "a" * 40
                              + "/41/1/closed-ready/sdk-eee52cd9849f5e15082ab0f2a1f9a1af2d7e5cc4-intent.json")
    close = lr.closed_ready_evidence_keys(governance, **arguments, operation="close-drain")
    assert close["intent"].startswith("cnesdata/prod/evidence/lifecycle/" + "a" * 40 + "/41/1/close-drain/sdk-")
    assert close["intent"].rsplit("/", 1)[1] != keys["intent"].rsplit("/", 1)[1]
    with pytest.raises(ValueError):
        lr.closed_ready_evidence_keys(governance, **arguments, operation="inventory")


R12_ERRORS = {
    "close-conditional": ("transact_write_items", "TransactionCanceledException",
                          {"CancellationReasons": [{"Code": "ConditionalCheckFailed"}, {"Code": "None"}]}),
    "close-conflict": ("transact_write_items", "TransactionCanceledException",
                       {"CancellationReasons": [{"Code": "None"}, {"Code": "TransactionConflict"}]}),
    "confirm-conditional": ("update_item", "ConditionalCheckFailedException", {}),
    "close-throttled": ("transact_write_items", "ThrottlingException", {}),
    "read-throttled": ("get_item-semaphore", "ProvisionedThroughputExceededException", {}),
}


@pytest.mark.parametrize("case", sorted(R12_ERRORS))
def test_close_drain_conflict_poisons_the_journal_and_never_retries_or_returns_sdk_error(monkeypatch, case):
    """R12: a native conflict is recovery, not an adapter result; the intent stays the uncertainty witness."""
    ag, journal, broker, frames, native, objects, errors, NativeError = _close_drain_broker_case(monkeypatch)
    target, code, extra = R12_ERRORS[case]
    errors[target] = NativeError(code, **extra)
    order = list(CLOSE_ORDER[:CLOSE_ORDER.index(target) + 1])
    for name in order[:-1]:
        ag._adapter_message(frames[name], journal)
    settled = len(journal.call_receipts)
    with pytest.raises(ValueError, match="native SDK outcome unknown"):
        ag._adapter_message(frames[target], journal)
    ledger = broker.evidence[-1]
    assert journal._failed and journal.unknown and broker.uncertainty == ledger.uncertainty != []
    assert ledger._keys["intent"] in objects and ledger._keys["response"] not in objects and ledger._keys["receipt"] not in objects
    assert len(journal.call_receipts) == settled and all(b"never retained" not in raw for raw in objects.values())
    with pytest.raises(ValueError):
        ag._adapter_message(frames[target], journal)
    assert native.count(target) == 1


@pytest.mark.parametrize("case", ["close-capacity", "confirm-attributes", "read-capacity", "close-item"])
def test_close_drain_broker_refuses_write_or_read_responses_beyond_the_finite_fields(monkeypatch, case):
    ag, journal, broker, frames, native, objects, errors, _ = _close_drain_broker_case(monkeypatch)
    target, extra = {"close-capacity": ("transact_write_items", {"ConsumedCapacity": [{"TableName": "t"}]}),
                     "confirm-attributes": ("update_item", {"Attributes": {"state": {"S": "CLOSED"}}}),
                     "read-capacity": ("get_item", {"ConsumedCapacity": {"TableName": "t"}}),
                     "close-item": ("transact_write_items", {"Item": {"state": {"S": "CLOSED"}}})}[case]
    original = broker.session.client.call
    def sdk(service, operation, **parameters):
        response = original(service, operation, **parameters)
        return response | extra if native[-1] == target else response
    broker.session.client.call = sdk
    order = list(CLOSE_ORDER[:CLOSE_ORDER.index(target) + 1])
    for name in order[:-1]:
        ag._adapter_message(frames[name], journal)
    with pytest.raises(ValueError, match="finite native DynamoDB response"):
        ag._adapter_message(frames[target], journal)
    assert journal._failed and journal.unknown and broker.uncertainty


@pytest.mark.parametrize("operation", ["closed-ready", "close-drain"])
@pytest.mark.parametrize("call", ["get_item", "update_item", "transact_write_items", "put_item", "delete_item"])
def test_journal_records_only_the_operation_finite_sdk_set_and_write_responses_stay_empty(operation, call):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    request, owner, window, inputs = _adapter_case(operation)
    class Guard:
        def check(self, seconds=0): pass
    journal = ag.AdapterJournal(c.canonical(request), operation=operation, owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    raw = c.canonical({"role": "fence_operator", "service": "dynamodb", "operation": call, "parameters": {}})
    if ("dynamodb", call) not in lc.FENCE_SDK_OPERATIONS[operation]:
        with pytest.raises(ValueError, match="closed SDK journal operation"):
            journal.begin_sdk_call(raw, role_session_sha256="9" * 64)
        return
    from email.utils import formatdate
    ticket = journal.begin_sdk_call(raw, role_session_sha256="9" * 64)
    response = c.canonical({"Item": {"pk": {"S": "ENV#prod#FENCE"}}})
    if call == "get_item":
        assert journal.complete_sdk_call(ticket, response, request_id="r", server_date=formatdate(usegmt=True))
    else:
        with pytest.raises(ValueError, match="SDK response already sanitized"):
            journal.complete_sdk_call(ticket, response, request_id="r", server_date=formatdate(usegmt=True))
        assert journal._failed and journal.unknown


_FREEZE_ACCOUNT = "111122223333"
_FREEZE = {"PolicyName": "cnesdata-budget-freeze", "PolicyArn": f"arn:aws:iam::{_FREEZE_ACCOUNT}:policy/cnesdata-budget-freeze"}


@pytest.mark.parametrize("case, refusal", [
    ("none", None), ("freeze", "freeze=attached"), ("freeze-and-other", "freeze=attached"),
    ("other", "application has no attached policies"), ("foreign-freeze", "application has no attached policies"),
    ("path-freeze", "application has no attached policies"), ("truncated-freeze", "application has no attached policies"),
    ("untyped", "application has no attached policies")])
def test_application_unfrozen_refuses_the_budget_freeze_as_its_own_reason(case, refusal):
    """Queue item 3a: cnesdata-budget-freeze (personal-infra-live#2 6883013198, path /) refuses as freeze=attached."""
    from tools.cnesdata_delivery import session_owner
    other = {"PolicyName": "other", "PolicyArn": f"arn:aws:iam::{_FREEZE_ACCOUNT}:policy/other"}
    attached = {"none": [], "freeze": [_FREEZE], "freeze-and-other": [other, _FREEZE], "other": [other],
                "foreign-freeze": [_FREEZE | {"PolicyArn": _FREEZE["PolicyArn"].replace(_FREEZE_ACCOUNT, "999900001111")}],
                "path-freeze": [_FREEZE | {"PolicyArn": _FREEZE["PolicyArn"].replace(":policy/", ":policy/x/")}],
                "truncated-freeze": [_FREEZE], "untyped": None}[case]
    response = {"IsTruncated": case == "truncated-freeze", "AttachedPolicies": attached}
    if refusal is None:
        assert session_owner.application_unfrozen(response, _FREEZE_ACCOUNT) is None
        return
    with pytest.raises(ValueError, match=refusal):
        session_owner.application_unfrozen(response, _FREEZE_ACCOUNT)


def _close_role_session_case(monkeypatch, mutation=None):
    """Finite close session over the fence SDK boundary fakes; the role carries the promotion_fence_operator grants."""
    from tools.cnesdata_delivery import application_gate as ag
    native_mutations = {"arn", "role-id", "account", "packed", "expiration"}
    ag, args, calls, native = _fence_sdk_boundary_case(monkeypatch, mutation=mutation if mutation in native_mutations else None)
    operation = "closed-ready" if mutation == "closed-ready-prepare" else "close-drain"
    request, owner, window, inputs = _adapter_case(operation)
    class Guard:
        def check(self, seconds=0): pass
    journal = ag.AdapterJournal(c.canonical(request), operation=operation, owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    if mutation == "closed-ready-prepare":
        journal._request["stage"] = _adapter_case("close-drain")[0]["stage"]
    role = args["role"]
    statements = []
    for action, keys in (("GetItem", ["ENV#prod#FENCE", "ENV#prod#SEMAPHORE"]), ("UpdateItem", ["ENV#prod#FENCE"]),
                         ("ConditionCheckItem", ["ENV#prod#SEMAPHORE"])):
        if (mutation, action) not in {("no-write-grant", "UpdateItem"), ("no-check-grant", "ConditionCheckItem")}:
            statements.append({"Effect": "Allow", "Action": "dynamodb:" + action, "Resource": CLOSE_SCOPE["control_table_arn"],
                               "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": keys},
                                             "Null": {"dynamodb:LeadingKeys": "false"}}})
    statements.append({"Effect": "Allow", "Action": "states:DescribeExecution",
                       "Resource": CLOSE_SCOPE["machine_arn"].replace(":stateMachine:", ":execution:") + ":*"})
    role["policy"] = {"Version": "2012-10-17", "Statement": statements}
    scope = dict(CLOSE_SCOPE)
    if mutation == "members-scope": scope["members"] = []
    if mutation == "synthetic-table": scope["control_table_arn"] = scope["control_table_arn"].replace("control-plane", "control")
    stage = journal._request["stage"]
    if mutation == "api-stage": stage.update(close=1000, fixed_deadline=2800, input_deadline=4000, stage="api", admitted_at=1300, deadline=1480)
    if mutation == "closed": stage["close"] = 1000
    if mutation == "deadline": stage["deadline"] = 1899
    if mutation == "late": stage.update(deadline=1340, preparation_deadline=1340)
    if mutation == "future-admission": stage["admitted_at"] = 1301
    args.update(journal=journal, scope=scope, credential_limit=2199 if mutation == "credential" else 3000)
    return ag, args, calls, native


_CLOSE_SESSION_REFUSALS = {"api-stage": "preparation/credential window", "closed": "preparation/credential window",
                           "deadline": "preparation/credential window", "late": "preparation/credential window",
                           "future-admission": "preparation/credential window", "credential": "preparation/credential window",
                           "closed-ready-prepare": "API/credential window", "members-scope": "closed object fields",
                           "synthetic-table": "close-drain pinned get_item template",
                           "no-write-grant": "effective close-write grant", "no-check-grant": "effective close-write grant"}


@pytest.mark.parametrize("mutation", [None, *sorted(_CLOSE_SESSION_REFUSALS), "arn", "role-id", "account", "packed", "expiration"])
def test_finite_close_session_is_the_preparation_window_per_item_policy(monkeypatch, mutation):
    """Decision 4: application-prepare, close/decision unset, deadline = preparation_deadline, per-item grants."""
    from tools.cnesdata_delivery import session_policy
    ag, args, calls, native = _close_role_session_case(monkeypatch, mutation)
    if mutation in _CLOSE_SESSION_REFUSALS:
        with pytest.raises(ValueError, match=_CLOSE_SESSION_REFUSALS[mutation]):
            ag._assume_fence_session(**args)
        assert calls == native == [] and args["operation_session"].calls == []
        return
    if mutation:
        with pytest.raises(ValueError):
            ag._assume_fence_session(**args)
        assert len(calls) == 1
        return
    session = ag._assume_fence_session(**args)
    assert session.scope == CLOSE_SCOPE and session.deadline == 1900 and len(calls) == len(native) == 1
    expected = session_policy.fence_close_session_policy(control_table_arn=CLOSE_SCOPE["control_table_arn"],
        execution_prefix=CLOSE_SCOPE["machine_arn"].replace(":stateMachine:", ":execution:") + ":", deadline=1900)
    assert calls[0][2]["Policy"] == c.canonical(expected).decode().strip() and calls[0][2]["DurationSeconds"] == 900


_CLOSE_OPERATION_IAM = "^close-drain operation session effective IAM$"


def _close_drain_capability_case(monkeypatch, mutation=None):
    """Connected close-drain composition: real prepared producer/codec, real broker; S3/STS/IAM are external fakes."""
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc, lifecycle_runtime as lr
    from tools.cnesdata_delivery.session_owner import Authority
    kwargs, _, fragment = _fence_prepare_package_case(monkeypatch)
    activation = b"original-ext2-payload-bytes"
    kwargs["activation_sha256"] = c.sha(activation)
    files = lr.fence_prepare_package(**kwargs)
    if mutation == "evaluation-scope":
        evaluation = c.loads(files["fence-evaluation.json"], canonical=True)
        next(case for case in evaluation["cases"] if case["case_id"] == "get-fence")["resource"] += "-other"
        files["fence-evaluation.json"] = c.canonical(evaluation)
    prepared = lr.PreparedFence(files)
    # The prepared evaluation is already sealed. The application identity of the capability grants the lease write, as the
    # real role does for the keeper: only the operation inline keeps it away from the operation session.
    from tools.cnesdata_delivery.coordination_lease import KEY
    from tools.cnesdata_delivery.session_owner import _terraform_document_digest
    coordination = c.loads(kwargs["governance"]["application_coordination_policy"].encode())
    lease = f"arn:aws:s3:::{kwargs['governance']['state_bucket']}/{KEY}"
    coordination["Statement"] += [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:DeleteObject"], "Resource": lease},
                                  {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": sorted(fragment["delegations"].values())}]
    kwargs["authority"].pin["document"]["Statement"] += [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": lease},
                                                         {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]
    if mutation == "identity-no-assume":
        coordination["Statement"] = [item for item in coordination["Statement"] if item["Action"] != "sts:AssumeRole"]
    fragment["policy_sha256"] = _terraform_document_digest(coordination)
    kwargs["governance"]["application_coordination_policy"] = c.canonical(coordination).decode().strip()
    owner, pin = kwargs["owner"], kwargs["authority"].pin
    if mutation == "managed-no-assume": pin["document"] = {"Version": "2012-10-17", "Statement": []}
    if mutation == "managed-expired":
        pin["document"]["Statement"].append({"Effect": "Deny", "Action": "*", "Resource": "*",
                                             "Condition": {"DateGreaterThanEquals": {"aws:CurrentTime": c.utc(1300)}}})
    if mutation == "owner": owner = owner | {"generation": owner["generation"] + 1}
    preparation = c.loads(prepared["fence-prepared.json"], canonical=True)["preparation"]
    _, sts_args, sts_calls, _ = _fence_sdk_boundary_case(monkeypatch)
    authority = Authority(pin, 5000.0, None, fragment, "3" * 64)
    api = SimpleNamespace(expiries={(c.REPOSITORY, 81): 6000.0}, digests={(c.REPOSITORY, 81): "2" * 64})
    expirations = ag.close_expirations(authority, api)
    if mutation == "expirations": api.expiries[(c.REPOSITORY, 81)] = 5900.0
    if mutation == "late-artifact": api.expiries[(c.REPOSITORY, 82)], api.digests[(c.REPOSITORY, 82)] = 6100.0, "4" * 64
    inputs = {"activation": activation if mutation != "activation" else b"other", "expirations": expirations}
    window = {"close": None, "fixed_deadline": None, "input_deadline": None, "stage": "application-prepare",
              "admitted_at": preparation["admitted_at"] - (mutation == "admitted") + (mutation == "admitted-later"),
              "deadline": preparation["deadline"] - (mutation == "preparation"),
              "decision": None, "preparation_deadline": preparation["deadline"] - (mutation == "preparation"),
              "sequence": 1, "checkpoint_sha256": c.sha(files["checkpoint.json"]), "windows": MINIMUM_WINDOWS, **lc.application_identity(owner)}
    request = {"abi_version": 3, "operation": "close-drain", "repository": c.REPOSITORY, "source_sha": owner["source_sha"],
               "owner": {key: owner[key] for key in [*lc.OWNER_FIELDS, "owner_sha256"]}, "checkpoint_sha256": window["checkpoint_sha256"],
               "activation_sha256": c.sha(inputs["activation"]),
               "stage": {key: value for key, value in window.items() if key not in lc.application_identity(owner)},
               "inputs": {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in inputs.items()}}
    class Guard:
        def check(self, seconds=0): pass
    journal = ag.AdapterJournal(c.canonical(request), operation="close-drain", owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    governance = {**kwargs["governance"], **sts_args["governance"]}
    if mutation == "delegation":
        governance["application_delegations"] = dict(governance["application_delegations"], fence_operator=governance["application_delegations"]["normal"])
    events = sts_args["operation_session"].events
    if mutation == "operation-exchange": sts_args["operation_session"].error = ValueError("operation session exchange refused")
    attached = {"freeze": [_FREEZE], "attached": [{"PolicyArn": f"arn:aws:iam::{_FREEZE_ACCOUNT}:policy/other"}]}.get(mutation, [])
    class Application:
        def call(self, service, operation, **parameters):
            events.append((service, operation))
            assert service == "iam", "the keeper client never reaches STS or the fence evidence"
            assert operation == "list_attached_role_policies"
            assert parameters == {"RoleName": fragment["application_role_name"], "MaxItems": 100}
            return {"IsTruncated": False, "AttachedPolicies": attached}
    keeper = ag.Keeper.__new__(ag.Keeper)
    keeper._contexts, keeper.lease = [], SimpleNamespace(check=lambda: events.append(("lease", "check")) or {"held": True})
    args = dict(aws=Application(), api=api, governance=governance, authority=authority, journal=journal, keeper=keeper,
                prepared=prepared, credential_limit=3000, operation_session=sts_args["operation_session"], clock=lambda: 1300)
    return ag, args, sts_calls, keeper, journal, events


_CLOSE_CAPABILITY_REFUSALS = {"activation": "activation_sha256", "identity-no-assume": _CLOSE_OPERATION_IAM,
                              "managed-no-assume": _CLOSE_OPERATION_IAM, "managed-expired": _CLOSE_OPERATION_IAM, "preparation": "original preparation is the close stage",
                              "admitted": "original preparation is the close stage", "delegation": "fence_operator delegation",
                              "admitted-later": "original preparation is the close stage", "owner": "prepared current owner",
                              "evaluation-scope": "capability scope recomputed from prepared policy",
                              "expirations": "close-drain authenticated expirations",
                              "late-artifact": "close-drain authenticated expirations",
                              "freeze": "freeze=attached", "attached": "application has no attached policies",
                              "operation-exchange": "^operation session exchange refused$"}


@pytest.mark.parametrize("mutation", [None, *sorted(_CLOSE_CAPABILITY_REFUSALS)])
def test_close_drain_capability_checks_everything_and_rereads_the_freeze_last_before_sts(monkeypatch, mutation):
    """Decision 4 and 3a: every refusal mints no credential, poisons the journal and keeps the lease held."""
    from tools.cnesdata_delivery import session_policy
    ag, args, sts_calls, keeper, journal, events = _close_drain_capability_case(monkeypatch, mutation)
    if mutation:
        with pytest.raises(ValueError, match=_CLOSE_CAPABILITY_REFUSALS[mutation]):
            ag.close_drain_capability(**args)
        assert sts_calls == [] and journal._failed is True and keeper.uncertainty() == [{"kind": "context-failed"}]
        assert not [event for event in events if event[0] == "sts"], "every refusal precedes the operation exchange and the fence STS"
        assert (("iam", "list_attached_role_policies") in events) is (mutation in {"freeze", "attached", "operation-exchange"})
        assert len(args["operation_session"].calls) == (mutation == "operation-exchange")
        return
    broker = ag.close_drain_capability(**args)
    assert type(broker) is ag.ClosedReadyBroker and keeper._contexts == [broker] and keeper.uncertainty() == []
    assert events == [("lease", "check"), ("iam", "list_attached_role_policies"), ("sts", "assume_role_with_web_identity"),
                      ("sts", "get_caller_identity"), ("sts", "assume_role")]
    operation_client = args["operation_session"].client
    assert broker.aws is operation_client and broker.session.evidence is operation_client and broker.aws is not args["aws"]
    assert args["operation_session"].calls == [("close-drain", "promotion-fence-r1", journal._request["stage"])]
    scope = broker.session.scope
    assert set(scope) == {"account", "control_table_arn", "machine_arn"} and broker.session.deadline == 1900
    expected = session_policy.fence_close_session_policy(control_table_arn=scope["control_table_arn"],
        execution_prefix=scope["machine_arn"].replace(":stateMachine:", ":execution:") + ":", deadline=1900)
    assert len(sts_calls) == 1 and sts_calls[0][2]["Policy"] == c.canonical(expected).decode().strip()


def _drift_operation_inline(request, drift):
    from tools.cnesdata_delivery.coordination_lease import KEY
    policy = c.loads(request["Policy"].encode())
    statements = policy["Statement"]
    if drift == "no-lease-deny":
        statements[:] = [item for item in statements if not (item["Effect"] == "Deny" and item.get("Resource", "").endswith(KEY))]
    if drift == "no-name-condition":
        statements[:] = [item for item in statements if "StringNotEquals" not in item.get("Condition", {})]
    if drift == "no-delegation-deny":
        statements[:] = [item for item in statements if "NotResource" not in item]
    if drift == "keeper-prefix":
        for item in statements:
            if item["Effect"] == "Allow" and item["Action"] == "s3:PutObject":
                item["Resource"] = [resource.replace("/close-drain/", "/keeper/") for resource in item["Resource"]]
    if drift == "no-close-drain-put":
        statements[:] = [item for item in statements if item["Action"] != "s3:PutObject" or item["Effect"] == "Deny"]
    return request | {"Policy": c.canonical(policy).decode().strip()}


@pytest.mark.parametrize("drift", ["no-lease-deny", "no-name-condition", "no-delegation-deny", "keeper-prefix", "no-close-drain-put"])
def test_close_drain_capability_refuses_an_operation_inline_the_documents_do_not_bound(monkeypatch, drift):
    """Change 4: effective_iam is a local check over the recomputed documents, before the freeze reread and before any exchange.

    The application identity grants the lease write (the keeper needs it); only the operation inline keeps it away."""
    from tools.cnesdata_delivery import session_policy
    ag, args, sts_calls, keeper, journal, events = _close_drain_capability_case(monkeypatch)
    original = session_policy.application_request
    monkeypatch.setattr(session_policy, "application_request", lambda *a, **kw: _drift_operation_inline(original(*a, **kw), drift))
    with pytest.raises(ValueError, match=_CLOSE_OPERATION_IAM):
        ag.close_drain_capability(**args)
    assert events == [("lease", "check")] and sts_calls == [] and args["operation_session"].calls == []
    assert journal._failed is True and keeper.uncertainty() == [{"kind": "context-failed"}]


def test_close_drain_capability_evaluates_the_inline_the_factory_sends(monkeypatch):
    """The local effective_iam is not a twin: the inline it evaluates is the Policy the exchange carries, byte for byte."""
    from tools.cnesdata_delivery import iam_boundary
    world = _policy_world(monkeypatch)
    seen, original = [], iam_boundary.effective_iam
    monkeypatch.setattr(iam_boundary, "effective_iam",
                        lambda identity, sessions, *rest: seen.append((len(world.minted), sessions)) or original(identity, sessions, *rest))
    world.ag.close_drain_capability(**world.args)
    (restriction,) = world.minted.values()
    inline = c.canonical(c.loads(restriction["Policy"].encode()))
    before_exchange = [sessions for minted, sessions in seen if minted == 0 and len(sessions) == 2]
    assert len(before_exchange) == 6 and all(c.canonical(sessions[1]) == inline for sessions in before_exchange)


@pytest.mark.parametrize("window_change", [{}, {"sequence": 0, "checkpoint_sha256": "a" * 64}])
def test_close_drain_journal_builds_the_request_the_real_capability_admits(monkeypatch, window_change):
    """The request is bound to the keeper window as it is at the prepared event; nothing compares it with the prepared checkpoint."""
    ag, args, sts_calls, keeper, journal, events = _close_drain_capability_case(monkeypatch)
    owner, window = journal._request["owner"] | journal._identity, journal._request["stage"] | journal._identity | window_change
    rebuilt = ag._close_drain_journal(guard=journal._guard, owner=owner, window=window, activation=journal._inputs["activation"],
                                      expirations=journal._inputs["expirations"])
    if not window_change:
        assert c.canonical(rebuilt._request) == c.canonical(journal._request)
    assert rebuilt._request["stage"]["sequence"] == window["sequence"] and rebuilt._request["checkpoint_sha256"] == window["checkpoint_sha256"]
    broker = ag.close_drain_capability(**args | {"journal": rebuilt})
    assert type(broker) is ag.ClosedReadyBroker and keeper._contexts == [broker] and len(sts_calls) == 1


@pytest.mark.parametrize("capability", ["close_drain_capability", "closed_ready_capability"])
def test_fence_capabilities_refuse_the_other_operation_before_any_io(monkeypatch, capability):
    ag, args, sts_calls, keeper, journal, events = _close_drain_capability_case(monkeypatch)
    if capability == "closed_ready_capability":
        args.update(request={}, run={}, guard=None, revisions={})
        args.pop("authority")
    else:
        journal._request = dict(journal._request, operation="closed-ready")
    with pytest.raises(ValueError, match="only; every other operation remains rejected"):
        getattr(ag, capability)(**args)
    assert sts_calls == [] and events == [] and keeper._contexts == []


@pytest.mark.parametrize("case", ["leaf", "decoy", "missing", "root-decoy"])
def test_adapter_child_loads_product_packages_by_authorized_path_with_stub_parents(tmp_path, case):
    """Queue item 3c: cnes_domain/cnes_infra load by authorized path; parent __init__ never runs; no fallback."""
    import subprocess
    from tools.cnesdata_delivery.application_gate import AdapterJournal, invoke_adapter
    product = tmp_path / "product"
    imports = {"leaf": "from cnes_infra.codec import VALUE", "decoy": "from cnes_domain.missing import VALUE",
               "missing": "from cnes_domain.orchestration.absent import VALUE", "root-decoy": "from cnes_domain.missing import VALUE"}
    code = r"""import hashlib, json, sys
IMPORT

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def execute_shared_operation(operation, request, context):
    observed = canonical({'value': VALUE, 'stub_file': getattr(sys.modules.get('cnes_infra'), '__file__', None),
                          'domain_path': list(getattr(sys.modules['cnes_domain'], '__path__', []))})
    digest = context.observe('inventory', observed)
    return {'abi_version': 3, 'operation': operation, 'owner_sha256': request['owner']['owner_sha256'],
            'generation': request['owner']['generation'], 'checkpoint_sha256': request['checkpoint_sha256'],
            'observations': [{'kind': 'inventory', 'sha256': digest, 'size': len(observed)}],
            'call_receipts_sha256': hashlib.sha256(canonical([])).hexdigest(), 'pending': [], 'unknown': []}
"""
    stub = "raise RuntimeError('stub parent __init__ executed')\n"
    files = {"scripts/promotion/promote_api.py": code.replace("IMPORT", imports[case]),
             "packages/cnes_domain/src/cnes_domain/__init__.py": stub,
             "packages/cnes_domain/src/cnes_domain/orchestration/__init__.py": stub,
             "packages/cnes_domain/src/cnes_domain/orchestration/leaf.py": "import json\nVALUE = json.dumps({'leaf': __name__})\n",
             "packages/cnes_infra/src/cnes_infra/__init__.py": stub,
             "packages/cnes_infra/src/cnes_infra/codec.py": "from cnes_domain.orchestration.leaf import VALUE\n",
             "cnes_domain/__init__.py": "", "cnes_domain/missing.py": "VALUE = 'decoy outside the authorized path'\n"}
    if case == "root-decoy":
        files = {name: text for name, text in files.items() if not name.startswith("packages/cnes_domain/")}
    for name, text in files.items():
        (product / name).parent.mkdir(parents=True, exist_ok=True)
        (product / name).write_text(text)
    def git(*args):
        return subprocess.run(["git", *args], cwd=product, check=True, capture_output=True).stdout.decode().strip()
    git("init", "-q")
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "loader fixture")
    source = git("rev-parse", "HEAD")
    manifest = {"version": 1, "source_sha": source, "files": {name: c.sha((product / name).read_bytes()) for name in files}}
    request, owner, window, inputs = _adapter_case()
    owner["source_sha"] = request["source_sha"] = request["owner"]["source_sha"] = source
    class Guard:
        def check(self, seconds=1): pass
    journal = AdapterJournal(c.canonical(request), operation="inventory", owner=owner, window=window, inputs=inputs,
                             activation_sha256=request["activation_sha256"], guard=Guard())
    args = {"product": product, "source": source, "manifest": manifest, "manifest_sha256": c.sha(c.canonical(manifest)),
            "journal": journal, "timeout": 10}
    if case != "leaf":
        with pytest.raises(ValueError, match="adapter child failed|adapter complete result frame"):
            invoke_adapter(**args)
        assert journal.observations == []
        return
    result = c.loads(invoke_adapter(**args), canonical=True)
    observed = c.loads(journal.observation_bytes[result["observations"][0]["sha256"]], canonical=True)
    root = str(product.resolve() / "packages/cnes_domain/src/cnes_domain")
    assert observed == {"value": '{"leaf": "cnes_domain.orchestration.leaf"}', "stub_file": None, "domain_path": [root]}
    assert git("status", "--porcelain", "--ignored", "--untracked-files=all") == ""



def _product_context_request(wrapper, **extra):
    import json
    return (json.dumps({"mode_canary": {"context_manifest": wrapper}, **extra}, ensure_ascii=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.mark.parametrize("vector", [0, 1])
def test_mode_context_wrapper_preserves_ratified_inner_utf8_bytes_not_wrapper_hash(vector):
    from fixtures.cnesdata_delivery_lifecycle import MODE_CONTEXT_CODEC_VECTORS
    from tools.cnesdata_delivery import lifecycle_contract as lc
    original = MODE_CONTEXT_CODEC_VECTORS[vector]
    wrapper = {key: original[key] for key in ("canonical_utf8", "sha256")}
    manifest, raw = lc.decode_mode_context(_product_context_request(wrapper))
    assert raw == original["canonical_utf8"].encode() and c.sha(raw) == original["sha256"]
    assert c.sha(raw) != c.sha(c.canonical(wrapper))
    assert manifest["schema_version"] == 2


@pytest.mark.parametrize("mutation", ["digest", "wrapper-digest", "extra", "string", "object", "null", "duplicate", "spaces", "order", "no-lf", "double-lf", "bom", "float", "nan", "surrogate", "request-size"])
def test_mode_context_wire_rejects_alternate_encodings_and_counts_complete_request(mutation):
    from fixtures.cnesdata_delivery_lifecycle import MODE_CONTEXT_CODEC_VECTORS
    from tools.cnesdata_delivery import lifecycle_contract as lc
    original = MODE_CONTEXT_CODEC_VECTORS[0]
    wrapper = {key: original[key] for key in ("canonical_utf8", "sha256")}
    texts = {"duplicate": '{"a":1,"a":2}\n', "spaces": '{"label": "ação","schema_version":2}\n',
             "order": '{"schema_version":2,"label":"ação"}\n', "no-lf": wrapper["canonical_utf8"].rstrip("\n"),
             "double-lf": wrapper["canonical_utf8"] + "\n", "bom": "\ufeff" + wrapper["canonical_utf8"],
             "float": '{"a":1.5}\n', "nan": '{"a":NaN}\n', "surrogate": '{"a":"\\ud800"}\n'}
    if mutation in texts:
        wrapper["canonical_utf8"] = texts[mutation]
        wrapper["sha256"] = c.sha(texts[mutation].encode())
    if mutation == "digest":
        wrapper["sha256"] = "0" * 64
    if mutation == "wrapper-digest":
        wrapper["sha256"] = c.sha(c.canonical(wrapper))
    if mutation == "extra":
        wrapper["manifest"] = {}
    if mutation == "string":
        wrapper = wrapper["canonical_utf8"]
    if mutation == "object":
        wrapper = {"schema_version": 2}
    if mutation == "null":
        wrapper = None
    raw = _product_context_request(wrapper, **({"other_input": "x" * 131072} if mutation == "request-size" else {}))
    with pytest.raises(ValueError):
        lc.decode_mode_context(raw)



def _mode_semantic_context(application_purpose):
    import json
    _, owner, _, _ = _adapter_case()
    context = "promotion" if application_purpose == "promotion" else "readiness"
    owner.update(application_purpose=application_purpose, context_kind=context)
    originals = {"product_source_sha": owner["source_sha"], "product_source_closure_sha256": "1" * 64,
                 "shared_source_sha": "2" * 40, "shared_source_closure_sha256": "3" * 64, "release_id": "fixture-release",
                 "activation_sha256": "4" * 64, "resources_sha256": "5" * 64, "fixture_manifest_sha256": "6" * 64,
                 "scenario_plan_sha256": "7" * 64, "predecessor_terminal_sha256": "8" * 64,
                 "admitted_at": 1000, "deadline": 1900 if context == "promotion" else 15400}
    manifest = {"schema_version": 2, "context_kind": context,
                "owner": {key: owner[key] for key in ("repository", "run_id", "run_attempt", "generation", "owner_sha256")}, **originals}
    def encode(value):
        raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        return _product_context_request({"canonical_utf8": raw.decode(), "sha256": c.sha(raw)})
    return manifest, originals, owner, encode


@pytest.mark.parametrize("purpose,count", [("promotion", 8), ("mode-readiness-drill", 6)])
def test_complete_mode_context_derives_sessions_from_inner_commitment_and_original_owner(purpose, count):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    manifest, originals, owner, encode = _mode_semantic_context(purpose)
    raw = encode(manifest)
    result = lc.validate_mode_context(raw, owner=owner, application_purpose=purpose, originals=originals)
    assert result["manifest"] == manifest and len(manifest) == 15
    _, original_bytes = lc.decode_mode_context(raw)
    assert result["context_manifest_sha256"] == c.sha(original_bytes)
    sessions = result["delegation_sessions"]
    assert set(sessions) == {"mode_seed", "mode_dispatch", "mode_audit_launch", "mode_observe"}
    assert sum(map(len, sessions.values())) == count
    assert all(names == sorted(set(names)) for names in sessions.values())
    if purpose == "mode-readiness-drill":
        assert sessions["mode_audit_launch"] == []
    for operation, (_, alias, context, phase) in lc.MODE_SESSION_OPERATIONS.items():
        if context != manifest["context_kind"]:
            continue
        binding = {key: manifest[key] for key in ("schema_version", "context_kind", "product_source_sha", "product_source_closure_sha256",
                  "shared_source_sha", "shared_source_closure_sha256", "release_id", "activation_sha256")}
        binding.update({key: owner[key] for key in ("repository", "run_id", "run_attempt", "generation", "owner_sha256")})
        binding.update(operation=operation, phase=phase, context_manifest_sha256=c.sha(original_bytes))
        assert lc.mode_session(binding, purpose)["session_name"] in sessions[alias]


@pytest.mark.parametrize("mutation", ["extra", "owner", "source", "producer", "activation", "resources", "fixture", "scenario", "predecessor", "deadline", "schema-bool", "run-bool", "context", "self-digest", "missing-original", "duration", "caller"])
def test_complete_mode_context_rejects_validly_encoded_but_foreign_semantics(mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    manifest, originals, owner, encode = _mode_semantic_context("promotion")
    fields = {"source": "product_source_sha", "producer": "shared_source_sha", "activation": "activation_sha256", "resources": "resources_sha256",
              "fixture": "fixture_manifest_sha256", "scenario": "scenario_plan_sha256", "predecessor": "predecessor_terminal_sha256"}
    if mutation in fields:
        field = fields[mutation]
        manifest[field] = "9" * len(manifest[field])
    if mutation == "extra":
        manifest["extra"] = True
    if mutation == "owner":
        manifest["owner"]["generation"] += 1
    if mutation == "deadline":
        manifest["deadline"] += 1
    if mutation == "schema-bool":
        manifest["schema_version"] = True
    if mutation == "run-bool":
        manifest["owner"]["run_attempt"] = True
    if mutation == "context":
        manifest["context_kind"] = "readiness"
    if mutation == "self-digest":
        manifest["context_manifest_sha256"] = "0" * 64
    if mutation == "missing-original":
        originals.pop("resources_sha256")
    if mutation == "duration":
        originals["deadline"] = manifest["deadline"] = 1901
    if mutation == "caller":
        owner.update(application_purpose="mode-readiness-drill", context_kind="readiness")
    with pytest.raises(ValueError):
        lc.validate_mode_context(encode(manifest), owner=owner, application_purpose="promotion", originals=originals)


@pytest.mark.parametrize("purpose,predecessor,oversize", [("promotion", None, False), ("mode-readiness-drill", None, False), ("mode-readiness-drill", "8" * 64, True)])
def test_mode_context_preserves_original_predecessor_and_unextended_deadline(purpose, predecessor, oversize):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    manifest, originals, owner, encode = _mode_semantic_context(purpose)
    originals["predecessor_terminal_sha256"] = manifest["predecessor_terminal_sha256"] = predecessor
    if oversize:
        originals["deadline"] = manifest["deadline"] = 15401
    if purpose == "promotion":
        assert lc.validate_mode_context(encode(manifest), owner=owner, application_purpose=purpose, originals=originals)["manifest"]["predecessor_terminal_sha256"] is None
    else:
        with pytest.raises(ValueError):
            lc.validate_mode_context(encode(manifest), owner=owner, application_purpose=purpose, originals=originals)


@pytest.mark.parametrize("field,value", [
    ("product_source_sha", "9" * 40), ("product_source_closure_sha256", "g" * 64),
    ("shared_source_sha", "a" * 39), ("shared_source_closure_sha256", "A" * 64),
    ("release_id", "foreign/release"), ("release_id", "ação"), ("release_id", "r" * 33),
    ("activation_sha256", None), ("resources_sha256", True), ("fixture_manifest_sha256", "0"),
    ("scenario_plan_sha256", []), ("predecessor_terminal_sha256", "bad"),
    ("admitted_at", True), ("admitted_at", 0), ("admitted_at", 1900), ("admitted_at", 1901),
    ("deadline", True), ("deadline", 2**53),
])
def test_mode_context_rejects_malformed_semantics_even_when_original_values_match(field, value):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    manifest, originals, owner, encode = _mode_semantic_context("promotion")
    manifest[field] = originals[field] = value
    with pytest.raises(ValueError):
        lc.validate_mode_context(encode(manifest), owner=owner, application_purpose="promotion", originals=originals)


@pytest.mark.parametrize("mutation", ["original-bool", "owner-extra", "original-extra", "missing-caller", "owner-source", "owner-digest"])
def test_mode_context_rejects_incomplete_or_type_confused_originals(mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    manifest, originals, owner, encode = _mode_semantic_context("promotion")
    if mutation == "original-bool":
        manifest["admitted_at"] = 1
        manifest["deadline"] = originals["deadline"] = 901
        originals["admitted_at"] = True
    if mutation == "owner-extra":
        manifest["owner"]["source_sha"] = owner["source_sha"]
    if mutation == "original-extra":
        originals["authority"] = "caller"
    if mutation == "missing-caller":
        owner.pop("caller_binding_sha256")
    if mutation == "owner-source":
        owner["source_sha"] = "f" * 40
    if mutation == "owner-digest":
        manifest["owner"]["owner_sha256"] = owner["owner_sha256"] = "bad"
    with pytest.raises(ValueError):
        lc.validate_mode_context(encode(manifest), owner=owner, application_purpose="promotion", originals=originals)


@pytest.mark.parametrize("mutation", [None, "running", "failed-step", "skipped-step", "missing-step", "duplicate-step", "pin", "source", "owner", "caller", "schema", "inventory", "step", "private-producer"])
def test_fence_producer_accepts_only_completed_exact_deploy_before_private_reads(mutation):
    import io
    import zipfile
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    from tools.cnesdata_delivery import lifecycle_contract as lc
    _, _, kwargs, encode = _fence_contract_case()
    files, originals = encode()
    if mutation == "private-producer":
        manifest = c.loads(files["fence-prepared.json"], canonical=True)
        manifest["producer"]["job_id"] += 1
        files["fence-prepared.json"] = c.canonical(manifest)
    owner, producer = kwargs["owner"], kwargs["producer"]
    request = {"source_sha": owner["source_sha"], "step": lc.FENCE_PREPARE_PRODUCER["step"],
               "application_purpose": owner["application_purpose"], "caller_binding_sha256": owner["caller_binding_sha256"]}
    governance = {"evidence_prefix": "cnesdata/prod/evidence/", "state_bucket": "synthetic-state", "evidence_bucket": "synthetic", "context_kind": owner["context_kind"],
                  "gate_shas": {"deploy": producer["workflow_sha"]}, "application_fragment": kwargs["fragment"]}
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"], "head_sha": owner["source_sha"],
           "event": "workflow_dispatch", "repository": {"full_name": c.REPOSITORY}, "head_branch": "main",
           "path": ".github/workflows/promote-production.yml", "referenced_workflows": [{
               "path": "VINIClUS/infra-ansible/" + producer["workflow_path"] + "@" + producer["workflow_sha"], "sha": producer["workflow_sha"]}]}
    names = ["Load actual immutable producer from authenticated run", "Verify complete public source and admission proof",
             "Check out authenticated exact product source", "Check out pinned artifact SDK bundle", "Set pinned Node runtime for the artifact SDK",
             "Install checksum-locked protected runtime", "Bridge masked artifact runtime from Node action handler",
             "Repeat source gate then request exact OIDC role", "Execute under CAS watchdog and verify final publication"]
    job = {"id": producer["job_id"], "run_id": run["id"], "run_attempt": run["run_attempt"], "head_sha": run["head_sha"],
           "name": producer["job_name"], "status": "completed", "conclusion": "success", "started_at": c.utc(1000), "completed_at": c.utc(1100),
           "steps": [{"name": n, "number": i + 2, "status": "completed", "conclusion": "success"} for i, n in enumerate(names)]}
    index = {"version": 1, "source_sha": run["head_sha"], "run_id": run["id"], "run_attempt": run["run_attempt"],
             "step": request["step"], "owner_sha256": owner["owner_sha256"], "generation": owner["generation"], **lc.application_identity(owner),
             "files": [{"name": n, "size": len(raw), "sha256": c.sha(raw)} for n, raw in sorted(files.items())]}
    if mutation == "running": job["status"] = "in_progress"
    if mutation == "failed-step": job["steps"][-1]["conclusion"] = "failure"
    if mutation == "skipped-step": job["steps"][-2]["conclusion"] = "skipped"
    if mutation == "missing-step": job["steps"].pop(0)
    if mutation == "duplicate-step": job["steps"].append(dict(job["steps"][0]))
    if mutation == "pin": run["referenced_workflows"][0]["sha"] = "e" * 40
    if mutation == "source": job["head_sha"] = "e" * 40
    if mutation == "owner": index["owner_sha256"] = "e" * 64
    if mutation == "caller": index["caller_binding_sha256"] = "f" * 64
    if mutation == "schema": index["version"] = True
    if mutation == "inventory": index["files"].pop()
    if mutation == "step": index["step"] = "other"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive: archive.writestr("index.json", c.canonical(index))
    raw = output.getvalue()
    reference = {"artifact_id": 4, "artifact_digest": "sha256:" + c.sha(raw), "job_id": job["id"]}
    metadata = {"id": 4, "name": "lifecycle-" + request["step"], "digest": reference["artifact_digest"],
                "workflow_run": {"id": run["id"], "head_sha": run["head_sha"]}, "expired": False, "expires_at": c.utc(2000), "created_at": c.utc(1050)}
    calls = []
    class API:
        def read(self, path, **kw):
            if path.endswith("/zip"): return raw
            if "/artifacts/" in path: return metadata
            if "/jobs/" in path: return job
            return run
    class AWS:
        def get(self, bucket, key, **kw):
            calls.append(key)
            return files[key.rsplit("/", 1)[1]], None
    def consume():
        return lr.fence_prepared_payload(API(), AWS(), governance, request, run, reference, owner=owner, now=1200,
            predecessor_raw=kwargs["predecessor_raw"], predecessor_reference=kwargs["predecessor_reference"])
    if mutation is None:
        assert consume() == files
        assert len(calls) == 8
    else:
        with pytest.raises(ValueError): consume()
        assert len(calls) == (8 if mutation == "private-producer" else 0)


@pytest.mark.parametrize("corrupt", ["response", "receipt", "forged-live"])
def test_durable_closed_ready_rejects_corrupt_originals_and_forged_receipt(monkeypatch, corrupt):
    create, store, native = _durable_closed_ready_case(monkeypatch)
    ledger, journal = create()
    assert ledger.reserve() == "created"
    ticket = journal.begin_sdk_call(c.canonical(native), role_session_sha256="2" * 64)
    response = b'{}\n'
    receipt = journal.complete_sdk_call(ticket, response, request_id="aws-id", server_date="Thu, 09 Oct 2025 08:53:20 GMT")
    if corrupt == "forged-live":
        receipt["request_id"] = "forged"
        with pytest.raises(ValueError, match="original guarded"):
            ledger.complete(response, receipt)
        assert len(store.writes) == 1 and ledger.uncertainty
    else:
        ledger.complete(response, receipt)
        key = next(key for key in store.objects if key.endswith("-" + corrupt + ".json"))
        store.objects[key] = b'{"changed":true}\n'
        restarted, _ = create()
        with pytest.raises(ValueError): restarted.reserve()
        assert restarted.uncertainty and len(store.writes) == 3


def _current_fence_projection_case(mutation=None, serial=2, *, probe=False):
    import copy
    from fixtures.cnesdata_delivery_lifecycle import fence_projection_case
    from tools.cnesdata_delivery import lifecycle_contract as lc
    plan, inputs, state, sources, readbacks = fence_projection_case(probe=probe)
    state["serial"] = serial
    _, _, package, _ = _fence_contract_case(probe=probe)
    owner, fragment = package["owner"], package["fragment"]
    original_sources = dict(sources)
    carrier, old_raw = _phase_a_carrier_case(serial=min(1, serial), probe=probe)
    envelope = c.loads(old_raw["envelope.json"], canonical=True)
    old_checkpoint = c.loads(old_raw["checkpoint.json"], canonical=True)
    old_checkpoint["readbacks"] = readbacks
    if mutation == "old-principal": envelope["plan"]["phase_a_inputs"]["canary_trusted_principal_arn"] += "-foreign"
    if mutation == "old-policy": readbacks[-1]["observed"]["PolicyDocument"] = {"Version": "2012-10-17", "Statement": []}
    for row in readbacks: row["sha256"] = c.sha(c.canonical(row["observed"]))
    ref = carrier["origin"]
    historical = {"envelope": envelope, "checkpoint": old_checkpoint, "predecessor_reference": ref}
    if mutation == "role-update": plan["resource_changes"][0]["change"]["actions"] = ["update"]
    if mutation == "policy-update": plan["resource_changes"][1]["change"]["actions"] = ["update"]
    if mutation == "unknown": plan["resource_changes"][0]["change"]["after_unknown"] = {"arn": True}
    if mutation == "state-role-id": state["resources"][0]["instances"][0]["attributes"]["unique_id"] = "AROAFOREIGN"
    if mutation == "original-source": original_sources["infra/opentofu/modules/runtime-iam/promotion.tf"] += b"# changed source\n"
    if mutation == "lineage": state["lineage"] = "foreign"
    plan_raw, inputs_raw, state_raw = c.canonical(plan), c.canonical(inputs), c.canonical(state)
    current_index = {"version": 1, "source_sha": owner["source_sha"], "run_id": owner["run_id"], "run_attempt": owner["run_attempt"],
        "step": "prepare-plan", "owner_sha256": owner["owner_sha256"], "generation": owner["generation"], **lc.application_identity(owner),
        "files": [{"name": name, "size": len(raw), "sha256": c.sha(raw)} for name, raw in (("plan.json", plan_raw), ("inputs.json", inputs_raw), ("plan.bin", b"current-saved-plan"))]}
    if mutation == "current-index": current_index["files"][0]["sha256"] = "f" * 64
    if mutation == "caller": current_index["caller_binding_sha256"] = "f" * 64
    checkpoint = {"state": c.state_identity(state_raw), "state_object": {"status": "present", "version_id": "v2", "etag_sha256": "e" * 64},
                  "owner": owner, "purpose": "application-prepare", "plan_sha256": c.sha(b"current-saved-plan"), "readbacks": [], "phase_a_originals": carrier}
    if mutation == "checkpoint-owner":
        checkpoint["owner"] = copy.deepcopy(owner)
        checkpoint["owner"]["run_attempt"] = True
    checkpoint_raw = c.canonical(checkpoint)
    old_sha, head_sha = c.sha(c.canonical(old_checkpoint)), c.sha(checkpoint_raw)
    chain = {"schema_version": 3, "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
        "anchor_sha256": old_sha, "head_sha256": head_sha, "entries": [{"sequence": 0, "checkpoint_sha256": head_sha,
            "previous_checkpoint_sha256": "f" * 64 if mutation == "ancestry" else old_sha,
            "state": checkpoint["state"], "state_object": checkpoint["state_object"], "origin": {
                "repository": c.REPOSITORY, "source_sha": owner["source_sha"], "run_id": owner["run_id"], "run_attempt": owner["run_attempt"],
                "job_id": 42, "producer_name": lc.FENCE_PREPARE_PRODUCER["job_name"],
                "step": lc.FENCE_PREPARE_PRODUCER["step"], "name": "checkpoint.json", "sha256": head_sha, "size": len(checkpoint_raw)}}]}
    args = dict(plan_raw=plan_raw, inputs_raw=inputs_raw, state_raw=state_raw, sources=sources, original_sources=original_sources,
        source_sha=owner["source_sha"], activation_source_sha="f" * 40 if mutation == "activation" else owner["source_sha"],
        current_index=current_index, checkpoint=checkpoint, chain=chain, historical=historical, owner=owner, fragment=fragment,
        producer=package["producer"], predecessor_raw=old_raw["checkpoint.json"], predecessor_reference=carrier["origin"])
    return args


@pytest.mark.parametrize("mutation", [None, "activation", "role-update", "policy-update", "unknown", "state-role-id", "old-principal", "old-policy", "original-source", "lineage", "current-index", "caller", "ancestry", "checkpoint-owner"])
def test_current_fence_projection_uses_current_plan_and_original_applied_role(mutation):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    args = _current_fence_projection_case(mutation)
    if mutation:
        with pytest.raises(ValueError): lr.fence_current_role_projection(**args)
    else:
        measured = lr.fence_current_role_projection(**args)
        assert measured["role"]["role_id"] == "AROAORIGINAL"
        assert measured["current_plan"]["source_sha"] == args["owner"]["source_sha"] != args["historical"]["envelope"]["plan"]["source_sha"]
        assert measured["historical_checkpoint_sha256"] == c.sha(c.canonical(args["historical"]["checkpoint"]))
        assert measured["current_state"] == args["checkpoint"]["state"] != args["historical"]["checkpoint"]["state_after"]
        assert measured["role"]["original_projection_sha256"] == measured["role"]["current_projection_sha256"]


@pytest.mark.parametrize("target,field", [
    (target, field) for target in ("manifest-producer", "protected-producer")
    for field in ("run_id", "run_attempt", "job_id")
] + [("approval-owner", field) for field in ("run_id", "run_attempt", "generation")])
def test_fence_package_rejects_boolean_authority_ids(target, field):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    payloads, manifest, kwargs, encode = _fence_contract_case()
    owner = kwargs["owner"]
    owner.update(run_id=1, run_attempt=1, generation=1)
    kwargs["producer"].update(run_id=1, run_attempt=1, job_id=1)
    payloads["fence-origins.json"]["current_plan"].update(run_id=1, run_attempt=1)
    chain = payloads["fence-chain.json"]
    chain["generation"] = 1
    chain["entries"][-1]["origin"].update(run_id=1, run_attempt=1, job_id=1)
    _rebind_fence_checkpoint(chain, payloads["checkpoint.json"])
    files, originals = encode()
    assert lc.validate_fence_prepared_package(files, originals=originals, **kwargs)["outcome"] == "observed"
    if target == "manifest-producer":
        manifest["producer"] = dict(kwargs["producer"], **{field: True})
    elif target == "protected-producer":
        # Both copies agree; independently protected bytes still need a typed schema.
        kwargs["producer"][field] = True
    else:
        payloads["approval.json"]["owner"] = dict(owner, **{field: True})
    files, originals = encode()
    with pytest.raises(ValueError):
        lc.validate_fence_prepared_package(files, originals=originals, **kwargs)


def _rebind_fence_checkpoint(chain, checkpoint):
    raw = c.canonical(checkpoint)
    digest = c.sha(raw)
    chain["head_sha256"] = digest
    entry = chain["entries"][-1]
    entry["checkpoint_sha256"] = digest
    entry["origin"].update(sha256=digest, size=len(raw))


@pytest.mark.parametrize("serial", [0, 1])
def test_fence_package_rejects_boolean_checkpoint_serial(serial):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    payloads, _, kwargs, encode = _fence_contract_case(original_serial=serial)
    checkpoint, chain = payloads["checkpoint.json"], payloads["fence-chain.json"]
    payloads["fence-origins.json"]["phase_a"]["state"]["serial"] = serial
    checkpoint["state"]["serial"] = serial
    _rebind_fence_checkpoint(chain, checkpoint)
    files, originals = encode()
    assert lc.validate_fence_prepared_package(files, originals=originals, **kwargs)["outcome"] == "observed"
    checkpoint["state"] = dict(checkpoint["state"], serial=bool(serial))
    _rebind_fence_checkpoint(chain, checkpoint)
    files, originals = encode()
    with pytest.raises(ValueError):
        lc.validate_fence_prepared_package(files, originals=originals, **kwargs)


@pytest.mark.parametrize("serial", [0, 1])
def test_current_fence_projection_rejects_boolean_checkpoint_serial(serial):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    args = _current_fence_projection_case(serial=serial)
    assert lr.fence_current_role_projection(**args)["current_state"]["serial"] == serial
    args["checkpoint"]["state"] = dict(args["checkpoint"]["state"], serial=bool(serial))
    _rebind_fence_checkpoint(args["chain"], args["checkpoint"])
    with pytest.raises(ValueError, match="fence full current state checkpoint"):
        lr.fence_current_role_projection(**args)


@pytest.mark.parametrize("command", [[], ["preflight"], ["credentials"], ["execute"], ["arbitrary-command"]])
def test_application_module_entry_never_succeeds_without_admission(command):
    import os
    from pathlib import Path
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, "-m", "tools.cnesdata_delivery.application_gate", *command],
        cwd=root, env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, timeout=10)
    assert result.returncode != 0
    assert not result.stdout
    assert b"AWS_ACCESS_KEY_ID" not in result.stderr



def _application_entry_case(monkeypatch, tmp_path):
    import base64
    from pathlib import Path
    from tools.cnesdata_delivery import lifecycle_runtime as lr, session_owner, session_policy
    chain, aws, history_api, store, _, _ = _legacy_history_fixture(monkeypatch, tmp_path)
    current, current_api, run, step, job, _ = _application_caller_fixture(monkeypatch)
    from test_cnesdata_application_closure import ROOT as CLOSURE_ROOT, WORKFLOW, expected_closure, workflow_contents
    gov = chain.gov | current
    from test_cnesdata_product_source_manifest import manifest_world
    inline = gov.pop("application_product_source_manifest")
    manifest_governance, manifest_api, _ = manifest_world(inline, source=run["head_sha"])
    gov["application_product_source_manifest_artifact"] = manifest_governance["application_product_source_manifest_artifact"]
    gov["gate_shas"] = chain.gov["gate_shas"] | current["gate_shas"]
    gov["application_source_closure_sha256"] = expected_closure(lambda path: (CLOSURE_ROOT / path).read_bytes())
    workflow_url = "repos/VINIClUS/infra-ansible/contents/" + WORKFLOW + "?ref=" + gov["gate_shas"]["application"]
    served = {"workflow": (CLOSURE_ROOT / WORKFLOW).read_bytes()}
    step.update(role="application", purpose="application-prepare", input_jobs={})
    gov.update(activation_enabled=True, lifecycle_enabled=True, lifecycle_authority="infra-ansible#55/6755178450",
        lifecycle_steps={"keeper": step})
    contract = Path(__file__).resolve().parents[1] / "docs/cnesdata-delivery-application-lifecycle.md"
    contract_raw = contract.read_bytes()
    gov["lifecycle_contract"] = {"repository": "VINIClUS/infra-ansible", "source_sha": "a" * 40,
        "path": "docs/cnesdata-delivery-application-lifecycle.md", "sha256": c.sha(contract_raw)}
    _, _, package, _ = _fence_contract_case()
    fragment = copy.deepcopy(package["fragment"])
    fragment.update(enabled_until=c.utc(time.time() + 7200))
    fragment["producer"].update(workflow_sha=gov["gate_shas"]["application"], source_closure_sha256=gov["application_source_closure_sha256"])
    gov["roles"]["application"] = fragment["application_role_arn"]
    fragment["lease"].update(bucket_arn="arn:aws:s3:::" + gov["state_bucket"], kms_key_arn=gov["state_kms_key_arn"])
    fragment["evidence"].update(bucket_arn="arn:aws:s3:::" + gov["evidence_bucket"],
        prefix=session_policy._prefix(gov) + "lifecycle/", kms_key_arn=gov["evidence_kms_key_arn"])
    fragment["predecessor_reads"] = gov["predecessor_read"] | {
        "object_arns": ["arn:aws:s3:::" + gov["evidence_bucket"] + "/" + key for key in session_policy.predecessor_keys(gov, gov["predecessor_read"])],
        "policy_sha256": session_owner._terraform_document_digest(session_policy.predecessor_policy(gov, gov["predecessor_read"]))}
    gov.update(application_fragment=fragment, application_delegations=fragment["delegations"],
        application_configuration={"role_name": fragment["application_role_name"], "workflow_sha": fragment["producer"]["workflow_sha"],
        "source_closure_sha256": fragment["producer"]["source_closure_sha256"], "enabled_until": fragment["enabled_until"],
        "delegations": fragment["delegations"], "predecessor_read": gov["predecessor_read"]})
    identity = _current_caller(gov, {"source_sha": run["head_sha"], "run_id": run["id"], "run_attempt": run["run_attempt"]})
    request = {"schema_version": 1, "repository": c.REPOSITORY, "source_sha": run["head_sha"], "step": "keeper", "payloads": {},
        "application_purpose": "promotion", "caller_binding_sha256": identity["caller_binding_sha256"]}
    reads = []
    class API:
        def read(self, path, **kwargs):
            reads.append(path)
            if path == workflow_url:
                return workflow_contents(served["workflow"])
            if "/contents/docs/cnesdata-delivery-application-lifecycle.md?ref=" in path:
                return {"encoding": "base64", "content": base64.b64encode(contract_raw).decode()}
            if f"/actions/artifacts/{manifest_governance['application_product_source_manifest_artifact']['artifact_id']}" in path:
                return manifest_api.read(path, **kwargs)
            if "/actions/runs/44/" in path or "/compare/" in path or "/commits/" in path or "/contents/.github/" in path:
                return current_api.read(path, **kwargs)
            return history_api.read(path, **kwargs)
        def artifact(self, reference, *args, **kwargs):
            if reference["artifact_id"] == manifest_governance["application_product_source_manifest_artifact"]["artifact_id"]:
                return manifest_api.artifact(reference, *args, **kwargs)
            return history_api.artifact(reference, *args, **kwargs)
    monkeypatch.setattr(lr, "GitHub", API)
    monkeypatch.setattr(lr, "AWS", lambda *a, **kw: pytest.fail("public preflight must not construct AWS"))
    def configure():
        raw = c.canonical(request).decode()
        env = {"CNESDATA_DELIVERY_GOVERNANCE": c.canonical(gov, limit=262144).decode(), "REQUEST_DESCRIPTOR": raw,
            "REQUEST_DESCRIPTOR_SHA256": c.sha(raw.encode()), "EXPECTED_SOURCE_SHA": "b" * 40,
            "PURPOSE": "application-prepare", "GITHUB_RUN_ID": "44", "GITHUB_RUN_ATTEMPT": "2",
            "CONTRACT_REPOSITORY": gov["lifecycle_contract"]["repository"], "CONTRACT_SOURCE_SHA": gov["lifecycle_contract"]["source_sha"],
            "CONTRACT_PATH": gov["lifecycle_contract"]["path"], "CONTRACT_SHA256": gov["lifecycle_contract"]["sha256"]}
        for key, value in env.items(): monkeypatch.setenv(key, value)
    configure.served = served
    return gov, request, run, job, configure, store, reads


@pytest.mark.parametrize("mutation", [None, "disabled", "null-fragment", "null-configuration", "old-fragment", "expired-fragment",
    "mixed-source", "mixed-attempt", "wrong-job", "caller-hash", "missing-history", "job-id-bool", "schema-bool", "closure", "manifest-inline", "manifest-hash", "manifest-other-run"])
def test_application_cli_preflight_uses_real_public_admission(monkeypatch, tmp_path, mutation):
    from tools.cnesdata_delivery import application_gate as ag
    gov, request, run, job, configure, store, reads = _application_entry_case(monkeypatch, tmp_path)
    if mutation == "schema-bool": request["schema_version"] = True
    if mutation == "disabled": gov["lifecycle_enabled"] = False
    if mutation == "null-fragment": gov["application_fragment"] = None
    if mutation == "null-configuration": gov["application_configuration"] = None
    if mutation == "old-fragment": gov["application_fragment"]["fragment_version"] = 3
    if mutation == "expired-fragment": gov["application_fragment"]["enabled_until"] = c.utc(time.time() - 1)
    if mutation == "mixed-source": run["head_sha"] = "e" * 40
    if mutation == "mixed-attempt": job["run_attempt"] = 1
    if mutation == "wrong-job": job["name"] = "other / keeper"
    if mutation == "caller-hash": request["caller_binding_sha256"] = "e" * 64
    if mutation == "missing-history": gov.pop("lifecycle_predecessor")
    if mutation == "job-id-bool": job["id"] = True
    if mutation == "closure": configure.served["workflow"] += b"# edited after the pin\n"
    if mutation == "manifest-inline": gov["application_product_source_manifest"] = {"version": 1, "source_sha": "b" * 40, "files": {}}
    if mutation == "manifest-hash": gov["application_product_source_closure_sha256"] = "0" * 64
    if mutation == "manifest-other-run": gov["application_product_source_manifest_artifact"]["run_attempt"] = 9
    configure()
    before = store.get()
    if mutation:
        with pytest.raises((ValueError, KeyError), match="application producer closure" if mutation == "closure" else None):
            ag.main(["preflight"])
    else:
        admitted = ag.main(["preflight"])
        assert admitted[1]["source_sha"] == "b" * 40
        assert admitted[4]["id"] == 44
        assert admitted[0]["authenticated_application_job"] == {"job_id": 9, "producer_name": "promote / keeper",
            "repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 2}
        assert any("/actions/runs/44/attempts/2/jobs" in path for path in reads)
        assert any("/actions/jobs/91" in path for path in reads)
        assert "application_product_source_manifest_artifact" in admitted[0]
        assert admitted[0]["application_product_source_manifest"]["source_sha"] == "b" * 40
        assert any("/actions/artifacts/7001" in path for path in reads)
        assert reads.count("repos/VINIClUS/infra-ansible/contents/.github/workflows/reusable-cnesdata-application-gate.yml?ref="
                           + gov["gate_shas"]["application"]) == 1
    assert store.get() == before



def test_artifact_digests_retain_only_the_authenticated_download_digest():
    """Correction 6906038586 item 1: the digest comes from the same authenticated download, never a new read."""
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    calls = []
    class Inner:
        expiries = {}
        def artifact(self, reference, now, **options):
            calls.append((reference["artifact_id"], now, options))
            if reference["artifact_id"] == 13:
                raise ValueError("artifact metadata")
            self.expiries[reference["repository"], reference["artifact_id"]] = 6000.0
            return {"index.json": b"{}"}
        def read(self, path):
            return "read:" + path
    inner = Inner()
    api = lr.ArtifactDigests(inner)
    reference = {"repository": c.REPOSITORY, "artifact_id": 12, "artifact_digest": "sha256:" + "a" * 64}
    assert api.artifact(reference, 1000, r2=True) == {"index.json": b"{}"}
    with pytest.raises(ValueError, match="artifact metadata"):
        api.artifact(reference | {"artifact_id": 13, "artifact_digest": "sha256:" + "b" * 64}, 1000)
    assert api.digests == {(c.REPOSITORY, 12): "a" * 64} and set(api.digests) == set(api.expiries)
    assert api.expiries is inner.expiries and api.read("repos/x") == "read:repos/x"
    assert calls == [(12, 1000, {"r2": True}), (13, 1000, {})]


@pytest.mark.parametrize("role", ["application", "plan"])
def test_admission_retains_artifact_digests_only_for_the_application_role(monkeypatch, role):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    governance = {"stage_windows": WINDOWS["stages"], "fixed_deadline_seconds": WINDOWS["fixed_deadline_seconds"], "activation_enabled": True, "lifecycle_enabled": True, "lifecycle_authority": "infra-ansible#55/6755178450",
                  "lifecycle_steps": {"keeper": {"role": role, "purpose": "application-prepare", "input_jobs": {}}}}
    request = c.canonical({"schema_version": 1, "repository": c.REPOSITORY, "source_sha": "b" * 40, "step": "keeper",
                           "payloads": {}, "application_purpose": "promotion", "caller_binding_sha256": "c" * 64})
    for key, value in {"CNESDATA_DELIVERY_GOVERNANCE": c.canonical(governance).decode(), "REQUEST_DESCRIPTOR": request.decode(),
                       "REQUEST_DESCRIPTOR_SHA256": c.sha(request), "EXPECTED_SOURCE_SHA": "b" * 40,
                       "PURPOSE": "application-prepare", "GITHUB_RUN_ID": "44", "GITHUB_RUN_ATTEMPT": "2"}.items():
        monkeypatch.setenv(key, value)
    inner, seen = object(), []
    monkeypatch.setattr(lr, "GitHub", lambda: inner)
    def stop(governance, api, *args):
        seen.append(api)
        raise ValueError("stop after GitHub construction")
    monkeypatch.setattr(lr, "source_admission", stop)
    with pytest.raises(ValueError, match="stop after GitHub construction"):
        lr.admission(role)
    if role == "application":
        assert type(seen[0]) is lr.ArtifactDigests and seen[0]._inner is inner
    else:
        assert seen == [inner]


@pytest.mark.parametrize("purpose", ["promotion", "mode-readiness-drill"])
@pytest.mark.parametrize("mutation", [None, "disabled", "null-fragment", "caller", "ref", "branch", "pin", "attempt", "source"])
def test_application_reusable_bootstrap_loads_only_authenticated_pin(monkeypatch, tmp_path, purpose, mutation):
    import base64
    import io
    import json
    from pathlib import Path
    import urllib.request
    import yaml
    from tools.cnesdata_delivery import lifecycle_contract as lc
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/reusable-cnesdata-application-gate.yml").read_text())
    script = workflow["jobs"]["execute"]["steps"][0]["run"]
    source = script.split("<<'PYBOOT'\n", 1)[1].rsplit("\nPYBOOT", 1)[0]
    pin, product = "a" * 40, "b" * 40
    path = "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-application-gate.yml"
    run = {"head_sha": product, "run_attempt": 2, "repository": {"full_name": c.REPOSITORY},
        "event": "workflow_dispatch", "path": lc.APPLICATION_CALLERS[purpose]["workflow_path"],
        "head_branch": "main", "status": "in_progress",
        "referenced_workflows": [{"path": path + "@" + pin, "sha": pin}]}
    gov = {"activation_enabled": True, "lifecycle_enabled": True, "application_purpose": purpose,
        "context_kind": lc.APPLICATION_CONTEXTS[purpose], "application_configuration": {"fixture": True},
        "application_fragment": {"fragment_version": 4}, "gate_shas": {"application": pin}}
    if mutation == "disabled": gov["lifecycle_enabled"] = False
    if mutation == "null-fragment": gov["application_fragment"] = None
    if mutation == "caller": run["path"] = ".github/workflows/untrusted.yml"
    if mutation == "pin": run["referenced_workflows"][0]["path"] = path + "@main"
    if mutation == "attempt": run["run_attempt"] = 1
    if mutation == "source": run["head_sha"] = "c" * 40
    if mutation == "branch": run["head_branch"] = "develop"
    env = {"DELIVERY_ROLE": "application", "GITHUB_REPOSITORY": c.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/develop" if mutation == "ref" else "refs/heads/main", "EXPECTED_SOURCE_SHA": product,
        "GITHUB_RUN_ID": "44", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_TOKEN": "synthetic-http-token",
        "CNESDATA_DELIVERY_GOVERNANCE": c.canonical(gov).decode()}
    for key, value in env.items(): monkeypatch.setenv(key, value)
    calls, downloads = [], {}
    def urlopen(request, timeout):
        calls.append(request.full_url)
        if request.full_url == "https://api.github.com/repos/VINIClUS/CnesData/actions/runs/44/attempts/2":
            response = run
        else:
            prefix = "https://api.github.com/repos/VINIClUS/infra-ansible/contents/tools/cnesdata_delivery/"
            assert request.full_url.startswith(prefix) and request.full_url.endswith("?ref=" + pin)
            name = request.full_url[len(prefix):].split("?", 1)[0]
            raw = ("# source " + name + " at " + pin + "\n").encode()
            downloads[name] = raw
            response = {"type": "file", "size": len(raw), "encoding": "base64", "content": base64.b64encode(raw).decode()}
        return io.BytesIO(json.dumps(response).encode())
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.chdir(tmp_path)
    if mutation:
        with pytest.raises((AssertionError, ValueError, TypeError)):
            exec(compile(source, "application-workflow-bootstrap", "exec"), {})
        assert not downloads
        if mutation in {"disabled", "null-fragment", "ref"}: assert not calls
    else:
        exec(compile(source, "application-workflow-bootstrap", "exec"), {})
        assert "application_gate.py" in downloads
        assert all((tmp_path / "tools/cnesdata_delivery" / name).read_bytes() == raw for name, raw in downloads.items())
        assert len(calls) == len(downloads) + 1



@pytest.mark.parametrize("role", ["plan", "deploy"])
@pytest.mark.parametrize("purpose", ["promotion", "mode-readiness-drill"])
@pytest.mark.parametrize("mutation", [None, "crossed-context", "disabled", "old-fragment", "ref"])
def test_infra_reusable_bootstrap_selects_protected_application_caller(monkeypatch, tmp_path, role, purpose, mutation):
    import base64
    import io
    import json
    from pathlib import Path
    import urllib.request
    import yaml
    from tools.cnesdata_delivery import lifecycle_contract as lc
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / (".github/workflows/reusable-cnesdata-infra-" + role + "-gate.yml")).read_text())
    script = workflow["jobs"]["execute"]["steps"][0]["run"]
    source = script.split("<<'PYBOOT'\n", 1)[1].rsplit("\nPYBOOT", 1)[0]
    pin, product = "a" * 40, "b" * 40
    path = "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-" + role + "-gate.yml"
    run = {"head_sha": product, "run_attempt": 2, "repository": {"full_name": c.REPOSITORY},
        "event": "workflow_dispatch", "path": lc.APPLICATION_CALLERS[purpose]["workflow_path"],
        "referenced_workflows": [{"path": path + "@" + pin, "sha": pin}]}
    gov = {"activation_enabled": True, "lifecycle_enabled": True, "application_purpose": purpose,
        "context_kind": lc.APPLICATION_CONTEXTS[purpose], "application_configuration": {"fixture": True},
        "application_fragment": {"fragment_version": 4}}
    if mutation == "disabled": gov["lifecycle_enabled"] = False
    if mutation == "old-fragment": gov["application_fragment"]["fragment_version"] = 3
    if mutation == "crossed-context": gov["context_kind"] = "readiness" if purpose == "promotion" else "promotion"
    env = {"DELIVERY_ROLE": role, "GITHUB_REPOSITORY": c.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/develop" if mutation == "ref" else "refs/heads/main", "EXPECTED_SOURCE_SHA": product,
        "GITHUB_RUN_ID": "44", "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_TOKEN": "synthetic-http-token", "CNESDATA_DELIVERY_GOVERNANCE": c.canonical(gov).decode(), "PURPOSE": "application-prepare"}
    for key, value in env.items(): monkeypatch.setenv(key, value)
    downloads = []
    def urlopen(request, timeout):
        if request.full_url == "https://api.github.com/repos/VINIClUS/CnesData/actions/runs/44":
            response = run
        else:
            prefix = "https://api.github.com/repos/VINIClUS/infra-ansible/contents/tools/cnesdata_delivery/"
            assert request.full_url.startswith(prefix) and request.full_url.endswith("?ref=" + pin)
            downloads.append(request.full_url)
            response = {"type": "file", "size": 2, "encoding": "base64", "content": base64.b64encode(b"#\n").decode()}
        return io.BytesIO(json.dumps(response).encode())
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.chdir(tmp_path)
    if mutation:
        with pytest.raises((AssertionError, ValueError)):
            exec(compile(source, "infra-workflow-application-caller", "exec"), {})
        assert not downloads
    else:
        exec(compile(source, "infra-workflow-application-caller", "exec"), {})
        assert (tmp_path / "tools/cnesdata_delivery/lifecycle_runtime.py").read_bytes() == b"#\n"
        assert downloads



@pytest.mark.parametrize("mutation", [None, "self-artifact", "old-schema", "job", "step", "producer", "size", "name", "hash", "history-ref"])
def test_fence_chain_current_origin_is_external_artifact_bound(mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    payloads, _, kwargs, encode = _fence_contract_case()
    chain = payloads["fence-chain.json"]
    origin = chain["entries"][-1]["origin"]
    assert "artifact_id" not in origin and "artifact_digest" not in origin
    if mutation == "self-artifact": origin.update(artifact_id=42, artifact_digest="sha256:" + "4" * 64)
    if mutation == "old-schema": chain["schema_version"] = 1
    if mutation == "job": origin["job_id"] += 1
    if mutation == "step": origin["step"] = "other-step"
    if mutation == "producer": origin["producer_name"] = "other / execute"
    if mutation == "size": origin["size"] += 1
    if mutation == "name": origin["name"] = "approval.json"
    if mutation == "hash": origin["sha256"] = "e" * 64
    if mutation == "history-ref": payloads["fence-origins.json"]["phase_a"]["files"]["checkpoint.json"].pop("artifact_digest")
    files, originals = encode()
    if mutation:
        with pytest.raises(ValueError): lc.validate_fence_prepared_package(files, originals=originals, **kwargs)
    else:
        assert lc.validate_fence_prepared_package(files, originals=originals, **kwargs)["outcome"] == "observed"



@pytest.mark.parametrize("mutation", [None, "head-job", "head-size", "old-schema", "archive", "private"])
def test_fence_producer_builds_before_one_upload_and_authenticates_completed_package(monkeypatch, tmp_path, mutation):
    import io
    import zipfile
    from pathlib import Path
    import yaml
    from tools.cnesdata_delivery import lifecycle_runtime as lr, lifecycle_contract as lc
    documents, _, kwargs, encode = _fence_contract_case()
    _, originals = encode()
    files = lr.fence_prepared_files(originals=originals, **kwargs)
    checkpoint_original = files["checkpoint.json"]
    origin = c.loads(files["fence-chain.json"], canonical=True)["entries"][-1]["origin"]
    assert "artifact_id" not in origin and "artifact_digest" not in origin
    if mutation in {"head-job", "head-size", "old-schema"}:
        chain = c.loads(files["fence-chain.json"], canonical=True)
        if mutation == "head-job": chain["entries"][-1]["origin"]["job_id"] += 1
        if mutation == "head-size": chain["entries"][-1]["origin"]["size"] += 1
        if mutation == "old-schema": chain["schema_version"] = 1
        files["fence-chain.json"] = c.canonical(chain)
    owner, producer = kwargs["owner"], kwargs["producer"]
    request = {"source_sha": owner["source_sha"], "step": producer["step"], "application_purpose": "promotion",
        "caller_binding_sha256": owner["caller_binding_sha256"]}
    gov = {"evidence_prefix": "cnesdata/prod/evidence/", "state_bucket": "synthetic-state", "evidence_bucket": "synthetic", "context_kind": "promotion",
           "gate_shas": {"deploy": producer["workflow_sha"]}, "application_fragment": kwargs["fragment"]}
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"], "head_sha": owner["source_sha"], "event": "workflow_dispatch",
        "repository": {"full_name": c.REPOSITORY}, "head_branch": "main", "path": ".github/workflows/promote-production.yml",
        "referenced_workflows": [{"path": "VINIClUS/infra-ansible/" + producer["workflow_path"] + "@" + producer["workflow_sha"],
            "sha": producer["workflow_sha"]}]}
    workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / producer["workflow_path"]).read_text())
    names = [item["name"] for item in workflow["jobs"]["execute"]["steps"]]
    job = {"id": producer["job_id"], "run_id": run["id"], "run_attempt": run["run_attempt"], "head_sha": run["head_sha"],
        "name": producer["job_name"], "status": "in_progress", "conclusion": None, "started_at": c.utc(1000), "completed_at": None,
        "steps": [{"name": name, "number": i + 1, "status": "completed", "conclusion": "success"} for i, name in enumerate(names)]}
    class API:
        archive = None
        metadata = None
        def read(self, path, **kw):
            if path.endswith("/zip"): return self.archive
            if "/artifacts/" in path: return self.metadata
            if "/jobs/" in path: return job
            return run
    class Store:
        def __init__(self): self.objects, self.reads, self.writes = {}, [], []
        def put(self, bucket, key, raw):
            assert key not in self.objects
            self.objects[key] = raw
            self.writes.append(key)
        def get(self, bucket, key, **kw):
            self.reads.append(key)
            return self.objects[key], "etag"
    class Guard:
        def check(self, *args): pass
    api, aws, guard, uploads = API(), Store(), Guard(), []
    def upload(directory, name, actual_guard, temp):
        assert job["status"] == "in_progress" and len(aws.writes) == 8
        assert actual_guard is guard
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("index.json", (directory / "index.json").read_bytes())
        api.archive = buffer.getvalue()
        api.metadata = {"id": 42, "name": name, "digest": "sha256:" + c.sha(api.archive), "workflow_run": {"id": run["id"], "head_sha": run["head_sha"]},
            "expired": False, "expires_at": c.utc(2000), "created_at": c.utc(1050)}
        uploads.append(name)
        return {"id": 42, "digest": api.metadata["digest"]}
    monkeypatch.setattr(runtime, "_upload", upload)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "outputs"))
    lr.publish(aws, gov, request, run, owner, files, api, guard, tmp_path, "applied")
    assert uploads == ["lifecycle-application-prepare-operational"] and len(aws.writes) == 8
    assert files["checkpoint.json"] == checkpoint_original
    original_objects = dict(aws.objects)
    reference = {"artifact_id": 42, "artifact_digest": api.metadata["digest"], "job_id": job["id"]}
    def consume(): return lr.fence_prepared_payload(api, aws, gov, request, run, reference, owner=owner, now=1200,
            predecessor_raw=kwargs["predecessor_raw"], predecessor_reference=kwargs["predecessor_reference"])
    aws.reads.clear()
    with pytest.raises(ValueError): consume()
    assert not aws.reads
    job.update(status="completed", conclusion="success", completed_at=c.utc(1100))
    if mutation == "archive": api.archive += b"changed"
    if mutation == "private":
        key = next(key for key in aws.objects if key.endswith("fence-chain.json"))
        aws.objects[key] += b"changed"
    if mutation:
        with pytest.raises(ValueError): consume()
    else:
        assert consume() == files
        assert aws.objects == original_objects
        assert c.loads(files["fence-chain.json"], canonical=True)["entries"][-1]["origin"] == origin
    assert len(aws.writes) == 8



@pytest.mark.parametrize("case,allowed", [("own", True), ("foreign", False), ("explicit-deny", False),
    ("no-identity", False), ("missing-key", False), ("expired", False), ("equal-time", False),
    ("exact-is-not-glob", False), ("null-key", False), ("empty-key", False)])
def test_live_fence_iam_evaluation_preserves_intersection_and_exact_conditions(case, allowed):
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    arn = "arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control"
    identity = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": arn}]}
    managed = {"Version": "2012-10-17", "Statement": []}
    inline = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": arn,
        "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["ENV#prod#FENCE", "ENV#prod#SEMAPHORE"]},
            "Null": {"dynamodb:LeadingKeys": "false"}, "DateLessThan": {"aws:CurrentTime": "2030-01-01T00:10:00Z"}}}]}
    context = {"dynamodb:LeadingKeys": ["ENV#prod#FENCE"], "aws:CurrentTime": "2030-01-01T00:09:59.999Z"}
    resource = arn
    if case == "foreign": resource += "-foreign"
    if case == "explicit-deny": managed["Statement"].append({"Effect": "Deny", "Action": "dynamodb:*", "Resource": "*"})
    if case == "no-identity": identity["Statement"] = []
    if case == "missing-key": context.pop("dynamodb:LeadingKeys")
    if case == "expired": context["aws:CurrentTime"] = "2030-01-01T00:10:01Z"
    if case == "equal-time": context["aws:CurrentTime"] = "2029-12-31T21:10:00-03:00"
    if case == "null-key": context["dynamodb:LeadingKeys"] = None
    if case == "empty-key": context["dynamodb:LeadingKeys"] = []
    if case == "exact-is-not-glob":
        inline["Statement"][0]["Condition"] = {"StringEquals": {"sts:RoleSessionName": "promotion-fence-*"}}
        context["sts:RoleSessionName"] = "promotion-fence-r1"
    assert effective_iam(identity, [managed, inline], "dynamodb:GetItem", resource, context) is allowed


def test_live_iam_evaluation_refuses_unimplemented_policy_semantics():
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "*",
        "Condition": {"UnexpectedIfExists": {"aws:CurrentTime": "anything"}}}]}
    with pytest.raises(ValueError): effective_iam(policy, [policy], "dynamodb:GetItem", "synthetic", {})


def _phase_a_carrier_case(*, serial=1, probe=False):
    """Complete synthetic historical documents; contains no applied AWS claim."""
    import base64
    from fixtures.cnesdata_plan import packet
    from fixtures.cnesdata_delivery_lifecycle import fence_projection_case
    from tools.cnesdata_delivery import lifecycle_contract as lc
    envelope, _, _ = packet()
    plan = envelope["plan"]
    plan["source_sha"] = plan["producer"]["workflow_sha"] = "9" * 40
    _, _, _, _, readbacks = fence_projection_case(probe=probe)
    source, account, now = plan["source_sha"], "111122223333", c.instant(plan["created_at"])
    role = readbacks[0]["observed"]["Role"]
    release = {"release_id": "original-release", "source_sha": source, "candidate_sha256": "1" * 64,
        "canary_id": "r1", "binding_sha256": "2" * 64, "image_digest": "sha256:" + "3" * 64}
    plan.update(purpose="phase-a", release=release, phase_a_inputs={"image_digest": release["image_digest"],
        "processor_active_unit_task_definition_arn": None, "processor_retained_unit_task_definition_arns": [],
        "canary_storage_enabled": True, "canary_release_id": "r1",
        "canary_trusted_principal_arn": role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"]})
    state = {"lineage": "original-lineage", "serial": serial, "state_sha256": "5" * 64}
    outputs = {"processor_task_definition_arns": {key: f"arn:aws:ecs:us-east-2:{account}:task-definition/cnesdata-prod-processor-{key}:1"
        for key in ("unit", "recovery", "audit")}, "image_digest": release["image_digest"], "active_before": None,
        "retained_before": [], "retained_after": [], "canary_id": "r1", "binding_sha256": release["binding_sha256"],
        "resource_fingerprints": {"fence-role": c.sha(c.canonical(role))},
        "grant_fingerprints": {"fence": c.sha(c.canonical(readbacks[-1]["observed"]["PolicyDocument"]))},
        "route_fingerprints": {"unit": "6" * 64}}
    ecr = {"observation_version": 1, "repository": c.REPOSITORY, "source_sha": source, "purpose": "phase-a",
        "run_id": 2, "run_attempt": 1, "observed_at": c.utc(now + 1), "report": {"repository_sha256": "4" * 64,
        "image_digest": release["image_digest"], "config_digest": "sha256:" + "5" * 64,
        "manifest_sha256": "3" * 64, "blob_digests": ["sha256:" + "5" * 64, "sha256:" + "6" * 64]}}
    drift = {"drift_report_version": 1, "repository": c.REPOSITORY, "source_sha": source, "purpose": "phase-a",
        "run_id": 2, "run_attempt": 1, "ecr_before": ecr, "post_readbacks": readbacks}
    drift_raw = c.canonical(drift)
    checkpoint = {"state_after": state, "state_object": {"status": "present", "version_id": "phase-a-version", "etag_sha256": "7" * 64},
        "outputs": outputs, "readbacks": readbacks, "drift_sha256": c.sha(drift_raw), "operation_completed_at": c.utc(now + 3)}
    checkpoint_raw = c.canonical(checkpoint)
    lease = {"protocol": "s3-cas-v1", "owner_sha256": "8" * 64, "repository": c.REPOSITORY, "run_id": 2, "run_attempt": 1,
        "session_sha256": "9" * 64, "acquired_at": c.utc(now), "released_at": c.utc(now + 4), "ttl_seconds": 120,
        "renew_interval_seconds": 30, "safety_margin_seconds": 17, "acquire_etag_sha256": "a" * 64,
        "release_etag_sha256": "b" * 64, "renewal_count": 0, "checkpoint_sha256": c.sha(checkpoint_raw),
        "evidence_sha256": "c" * 64, "terminal_status": "released"}
    envelope.update(status="applied", plan_binding_sha256=c.sha(c.canonical(plan)), apply={
        "producer": {"workflow_path": ".github/workflows/infra-apply.yml", "workflow_sha": source, "run_id": 2, "run_attempt": 1},
        "consumed_plan_artifact": {"artifact_id": 41, "artifact_sha256": "d" * 64, "run_id": 1, "run_attempt": 1},
        "plan_binding_sha256": c.sha(c.canonical(plan)), "started_at": c.utc(now + 2), "completed_at": c.utc(now + 4),
        "result": "success", "lease": lease, "principal": {"kind": "aws-assumed-role", "account_id": account, "region": "us-east-2",
        "gate": "deploy", "role_arn": f"arn:aws:iam::{account}:role/cnesdata-infra-deploy", "session_sha256": "9" * 64,
        "credential_expires_at": c.utc(now + 3600), "evidence_sha256": "e" * 64},
        "state_after": state | {"outputs_sha256": c.sha(c.canonical(outputs))}, "drift": {"verdict": "pass",
        "evidence_sha256": c.sha(drift_raw), "readback_sha256": c.sha(drift_raw), "observed_at": c.utc(now + 3)}, "outputs": outputs})
    files = {"checkpoint.json": checkpoint_raw, "drift.json": drift_raw, "envelope.json": c.canonical(envelope)}
    origin = {"predecessor_version": 1, "protocol": "legacy-infra", "repository": c.REPOSITORY, "source_sha": source,
        "run_id": 2, "run_attempt": 1, "owner_sha256": "8" * 64, "generation": None, "session_sha256": "9" * 64,
        "checkpoint_sha256": c.sha(checkpoint_raw), "artifact_id": 43, "artifact_digest": "sha256:" + "f" * 64,
        "producer_job_id": 42, "producer_name": "apply / execute", "objects": [
        {"name": name, "sha256": c.sha(raw), "size": len(raw)} for name, raw in sorted(files.items())] + [
        {"name": "lease.json", "sha256": "c" * 64, "size": 1000},
        {"name": "ecr-before.json", "sha256": c.sha(c.canonical(ecr)), "size": len(c.canonical(ecr))}]}
    carrier = {"carrier_version": 1, "origin": origin, "files": [{"name": name, "sha256": c.sha(raw), "size": len(raw),
        "bytes_base64": base64.b64encode(raw).decode()} for name, raw in sorted(files.items())]}
    return carrier, files


@pytest.mark.parametrize("mutation", [None, "bool-version", "extra-file", "base64", "size", "digest", "origin-source",
    "origin-run", "checkpoint-origin", "raw-state", "secret", "raw-limit", "legacy-status", "output-loss"])
def test_phase_a_carrier_preserves_complete_raw_originals_and_rejects_invalid_custody(mutation):
    import base64
    from tools.cnesdata_delivery import lifecycle_contract as lc
    carrier, files = _phase_a_carrier_case()
    if mutation == "bool-version": carrier["carrier_version"] = True
    if mutation == "extra-file": carrier["files"].append(carrier["files"][0])
    if mutation == "base64": carrier["files"][0]["bytes_base64"] += "\n"
    if mutation == "size": carrier["files"][0]["size"] += 1
    if mutation == "digest": carrier["files"][0]["sha256"] = "0" * 64
    if mutation == "origin-source": carrier["origin"]["source_sha"] = "0" * 40
    if mutation == "origin-run": carrier["origin"]["run_id"] = 3
    if mutation == "checkpoint-origin": carrier["origin"]["checkpoint_sha256"] = "0" * 64
    if mutation in {"raw-state", "secret", "raw-limit", "legacy-status", "output-loss"}:
        name = "envelope.json" if mutation == "legacy-status" else "checkpoint.json"
        value = c.loads(files[name], canonical=True)
        if mutation == "raw-state": value["state_after"]["resources"] = []
        if mutation == "secret": value["readbacks"][0]["observed"]["Credentials"] = {"AccessKeyId": "private"}
        if mutation == "raw-limit": value["outputs"]["resource_fingerprints"]["padding"] = "x" * 131072
        if mutation == "legacy-status": value["status"] = "planned"
        if mutation == "output-loss": value.pop("outputs")
        raw = c.canonical(value)
        entry = next(x for x in carrier["files"] if x["name"] == name)
        entry.update(size=len(raw), sha256=c.sha(raw), bytes_base64=base64.b64encode(raw).decode())
        next(x for x in carrier["origin"]["objects"] if x["name"] == name).update(size=len(raw), sha256=c.sha(raw))
    if mutation:
        with pytest.raises(ValueError): lc.phase_a_originals(carrier)
    else:
        result = lc.phase_a_originals(carrier)
        assert result["raw"] == files and result["predecessor_reference"] == carrier["origin"]
        assert result["checkpoint"]["outputs"] == result["envelope"]["apply"]["outputs"]
        assert len(c.canonical(carrier)) < 196608 and sum(map(len, files.values())) < 131072


@pytest.mark.parametrize("mutation", [None, "owner", "predecessor", "version", "carrier", "missing", "guard-after"])
def test_keeper_transport_reads_only_same_run_private_wrapper_with_original_custody(mutation):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    from tools.cnesdata_delivery import lifecycle_contract as lc
    carrier, originals = _phase_a_carrier_case()
    _, owner, _, _ = _adapter_case("closed-ready")
    predecessor = carrier["origin"]
    wrapper = {"version": 2, "owner": owner, "predecessor_sha256": c.sha(c.canonical(predecessor)), "phase_a_originals": carrier}
    if mutation == "owner": wrapper["owner"] = owner | {"run_id": owner["run_id"] + 1}
    if mutation == "predecessor": wrapper["predecessor_sha256"] = "0" * 64
    if mutation == "version": wrapper["version"] = 1
    if mutation == "carrier": wrapper["phase_a_originals"]["files"][0]["bytes_base64"] += "="
    class Store:
        def __init__(self): self.reads = []
        def get(self, bucket, key, *, maximum):
            self.reads.append((bucket, key, maximum))
            if mutation == "missing": raise ValueError("missing keeper transport")
            return c.canonical(wrapper), "original-etag"
    class Guard:
        def __init__(self): self.calls = 0
        def check(self, seconds=0):
            self.calls += 1
            if mutation == "guard-after" and self.calls > 1: raise ValueError("original owner changed")
    store = Store()
    gov = {"evidence_bucket": "synthetic-evidence", "evidence_prefix": "cnesdata/prod/evidence/"}
    args = dict(aws=store, governance=gov, owner=owner, predecessor=predecessor, guard=Guard())
    if mutation:
        with pytest.raises(ValueError): lr.keeper_transport(**args)
    else:
        result = lr.keeper_transport(**args)
        assert result == wrapper and lc.phase_a_originals(result["phase_a_originals"])["raw"] == originals
    assert store.reads == [("synthetic-evidence", f"cnesdata/prod/evidence/lifecycle/{owner['source_sha']}/41/1/keeper/checkpoint.json", 262144)]


class _OperationFactory:
    """Boundary fake of the in-process operation exchange (R20 option C): records its order and hands out the operation client."""
    def __init__(self, client, events=None, error=None):
        self.client, self.events, self.error, self.calls = client, [] if events is None else events, error, []

    def __call__(self, operation, role, stage):
        self.calls.append((operation, role["session_name"], dict(stage)))
        if self.error is not None:
            raise self.error
        self.events.extend([("sts", "assume_role_with_web_identity"), ("sts", "get_caller_identity")])
        return self.client


def _fence_sdk_boundary_case(monkeypatch, *, mutation=None):
    """Synthetic protected admission; fakes only STS/GetCallerIdentity boundaries."""
    from datetime import datetime, timezone
    from tools.cnesdata_delivery import application_gate as ag, aws_boundary, lifecycle_contract as lc
    request, owner, window, inputs = _adapter_case("closed-ready")
    documents, _, package, _ = _fence_contract_case()
    role = copy.deepcopy(documents["fence-role.json"])
    table = "arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control"
    machine = "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod"
    execution = machine.replace(":stateMachine:", ":execution:") + ":" + "a" * 16
    role["policy"] = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": table, "Condition": {
        "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["ENV#prod#FENCE", "ENV#prod#SEMAPHORE"]},
        "Null": {"dynamodb:LeadingKeys": "false"}}},
        {"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": machine.replace(":stateMachine:", ":execution:") + ":*"}]}
    scope = {"account": "111122223333", "control_table_arn": table, "machine_arn": machine, "members": [
        {"dispatch_id": "a" * 16, "request_sha256": "b" * 64, "generation": 1, "initial_state": "NOT_SENT",
        "execution_ref": None, "resolution": "CANCEL_BEFORE_SEND", "proof_sha256": "c" * 64,
        "observed_at": c.utc(1200), "send_disabled_at": c.utc(1199)}]}
    class Guard:
        def check(self, seconds=0): pass
    journal = ag.AdapterJournal(c.canonical(request), operation="closed-ready", owner=owner, window=window, inputs=inputs,
                               activation_sha256=request["activation_sha256"], guard=Guard())
    calls, native_calls, events = [], [], []
    assumed = role["role_arn"].replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + role["session_name"]
    identity = {"Account": "111122223333", "Arn": assumed, "UserId": role["role_id"] + ":" + role["session_name"]}
    if mutation == "arn": identity["Arn"] += "-foreign"
    if mutation == "role-id": identity["UserId"] = "AROAOTHER:" + role["session_name"]
    if mutation == "account": identity["Account"] = "999900001111"
    class Application:
        def call(self, service, operation, **parameters):
            calls.append((service, operation, parameters))
            events.append((service, operation))
            assert (service, operation) == ("sts", "assume_role")
            return {"PackedPolicySize": 101 if mutation == "packed" else 10, "AssumedRoleUser": {
                "Arn": assumed, "AssumedRoleId": role["role_id"] + ":" + role["session_name"]}, "Credentials": {
                "AccessKeyId": "synthetic-key", "SecretAccessKey": "synthetic-secret", "SessionToken": "synthetic-token",
                "Expiration": datetime.fromtimestamp(2201 if mutation == "expiration" else 2200, timezone.utc)}}
    class Delegated:
        def __init__(self, governance, *, credentials):
            assert set(credentials) == {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
            self.identity = self.call("sts", "get_caller_identity")
        def call(self, service, operation, **parameters):
            native_calls.append((service, operation, parameters))
            assert (service, operation) == ("sts", "get_caller_identity")
            return dict(identity)
    monkeypatch.setattr(aws_boundary, "AWS", Delegated)
    monkeypatch.setattr(ag.time, "time", lambda: 1300)
    if mutation == "expired-window": journal._request["stage"]["deadline"] = 1300
    if mutation == "no-probe-grant": role["policy"]["Statement"].pop()
    governance = {"role": "application", "account_id": "111122223333", "roles": {"application": package["fragment"]["application_role_arn"]},
        "application_delegations": package["fragment"]["delegations"], "evidence_bucket": "synthetic-evidence", "evidence_prefix": "cnesdata/prod/evidence/"}
    args = dict(operation_session=_OperationFactory(Application(), events), governance=governance, role=role, scope=scope,
                journal=journal, prepared_sha256="3" * 64, credential_limit=3000, clock=lambda: 1300)
    return ag, args, calls, native_calls


@pytest.mark.parametrize("mutation", [None, "arn", "role-id", "account", "packed", "expiration", "expired-window", "no-probe-grant"])
def test_finite_fence_session_requires_exact_sts_and_native_identity(monkeypatch, mutation):
    ag, args, calls, native = _fence_sdk_boundary_case(monkeypatch, mutation=mutation)
    if mutation:
        with pytest.raises(ValueError): ag._assume_fence_session(**args)
    else:
        session = ag._assume_fence_session(**args)
        assert session.scope == args["scope"] and session.deadline == 1480 and session.evidence is args["operation_session"].client
        c.digest(session.commitment)
    if mutation in {"expired-window", "no-probe-grant"}:
        assert calls == native == [] and args["operation_session"].calls == []
    else:
        assert len(calls) == 1 and len(args["operation_session"].calls) == 1
        params = calls[0][2]
        assert set(params) == {"RoleArn", "RoleSessionName", "DurationSeconds", "Policy"}
        assert params["RoleArn"] == args["role"]["role_arn"] and params["RoleSessionName"] == "promotion-fence-r1"
        assert params["DurationSeconds"] == 900 and len(params["Policy"]) <= 2048
        assert not {"AccessKeyId", "SecretAccessKey", "SessionToken"} & set(params)
        assert len(native) == (0 if mutation in {"packed", "expiration"} else 1)


@pytest.mark.parametrize("operation", ["closed-ready", "close-drain"])
def test_fence_session_exchanges_the_operation_session_right_before_the_fence_sts(monkeypatch, operation):
    """R20 option C: the operation client is the only STS caller and the evidence client; the keeper client is no parameter."""
    import inspect
    ag, args, calls, native = (_fence_sdk_boundary_case if operation == "closed-ready" else _close_role_session_case)(monkeypatch)
    factory = args["operation_session"]
    assert "aws" not in inspect.signature(ag._assume_fence_session).parameters
    session = ag._assume_fence_session(**args)
    assert factory.calls == [(operation, "promotion-fence-r1", args["journal"]._request["stage"])]
    assert factory.events == [("sts", "assume_role_with_web_identity"), ("sts", "get_caller_identity"), ("sts", "assume_role")]
    assert session.evidence is factory.client and len(calls) == 1


@pytest.mark.parametrize("operation", ["closed-ready", "close-drain"])
def test_fence_session_mints_no_fence_credential_when_the_operation_exchange_fails(monkeypatch, operation):
    """R21: a refused second web-identity exchange closes before the fence STS; the capability poisons the journal."""
    ag, args, calls, native = (_fence_sdk_boundary_case if operation == "closed-ready" else _close_role_session_case)(monkeypatch)
    args["operation_session"].error = ValueError("operation session exchange refused")
    with pytest.raises(ValueError, match="^operation session exchange refused$"):
        ag._assume_fence_session(**args)
    assert calls == native == [] and len(args["operation_session"].calls) == 1


@pytest.mark.parametrize("operation, elapsed, credential_limit", [("closed-ready", 141, 3000), ("close-drain", 571, 3000),
                                                                  ("close-drain", 401, 2300)])
def test_fence_session_judges_the_window_again_after_the_operation_exchange(monkeypatch, operation, elapsed, credential_limit):
    """The exchange spends tens of seconds (token, STS, GetCallerIdentity): the window and the credential are rechecked after it."""
    ag, args, calls, native = (_fence_sdk_boundary_case if operation == "closed-ready" else _close_role_session_case)(monkeypatch)
    now = [1300]
    class Slow(_OperationFactory):
        def __call__(self, *arguments):
            now[0] += elapsed
            return super().__call__(*arguments)
    args.update(clock=lambda: now[0], credential_limit=credential_limit,
                operation_session=Slow(args["operation_session"].client, args["operation_session"].events))
    with pytest.raises(ValueError, match="^fence original window after operation session$"):
        ag._assume_fence_session(**args)
    assert calls == native == [] and len(args["operation_session"].calls) == 1


@pytest.mark.parametrize("operation", ["closed-ready", "close-drain"])
@pytest.mark.parametrize("edge, accepted", [("deadline-1", True), ("deadline", False), ("limit", True), ("limit-1", False)])
def test_fence_session_window_and_credential_limit_are_exact_after_the_operation_exchange(monkeypatch, operation, edge, accepted):
    """The recheck keeps the strict 40 s margin to the deadline and the inclusive 900 s credential limit of the first check."""
    ag, args, calls, native = (_fence_sdk_boundary_case if operation == "closed-ready" else _close_role_session_case)(monkeypatch)
    stage = args["journal"]._request["stage"]
    deadline = stage["preparation_deadline"] if operation == "close-drain" else stage["deadline"]
    elapsed = {"deadline-1": deadline - 41 - 1300, "deadline": deadline - 40 - 1300}.get(edge, 10)
    limit = {"limit": 1300 + elapsed + 900, "limit-1": 1300 + elapsed + 899}.get(edge, 3000)
    now = [1300]
    class Slow(_OperationFactory):
        def __call__(self, *arguments):
            now[0] += elapsed
            return super().__call__(*arguments)
    args.update(clock=lambda: now[0], credential_limit=limit,
                operation_session=Slow(args["operation_session"].client, args["operation_session"].events))
    if accepted:
        ag._assume_fence_session(**args)
        assert len(calls) == 1
    else:
        with pytest.raises(ValueError, match="^fence original window after operation session$"):
            ag._assume_fence_session(**args)
        assert calls == native == []
    assert len(args["operation_session"].calls) == 1


@pytest.mark.parametrize("operation", ["closed-ready", "close-drain"])
@pytest.mark.parametrize("guard, message", [("journal-failed", "^adapter context failed; original recovery required$"),
                                            ("window-guard", "^guard window$")])
def test_fence_session_checks_the_journal_guards_before_the_operation_exchange(monkeypatch, operation, guard, message):
    """The exchange is the first credential mint of the stage: a failed journal or an expired guard refuses before it."""
    ag, args, calls, native = (_fence_sdk_boundary_case if operation == "closed-ready" else _close_role_session_case)(monkeypatch)
    if guard == "journal-failed":
        args["journal"]._failed = True
    else:
        class Expired:
            def check(self, seconds=0):
                c.require(seconds != 40, "guard window")
        args["journal"]._guard = Expired()
    with pytest.raises(ValueError, match=message):
        ag._assume_fence_session(**args)
    assert args["operation_session"].calls == [] and calls == native == []


@pytest.mark.parametrize("case", ["ddb", "sfn", "absent", "foreign", "eventual", "timeout", "lost-receipt", "private-response", "terminal-absent"])
def test_closed_ready_ipc_broker_uses_one_durable_native_attempt(monkeypatch, case):
    from email.utils import formatdate
    ag, args, _, _ = _fence_sdk_boundary_case(monkeypatch)
    if case == "terminal-absent":
        member = args["scope"]["members"][0]
        member.update(resolution="TERMINAL", execution_ref=args["scope"]["machine_arn"].replace(":stateMachine:", ":execution:") + ":" + member["dispatch_id"])
    session = ag._assume_fence_session(**args)
    journal, native, events = args["journal"], [], []
    class Evidence:
        def __init__(self): self.objects = {}
        def get(self, bucket, key, *, maximum, absent=False):
            return self.objects.get(key), "etag"
        def put(self, bucket, key, raw):
            assert key not in self.objects
            events.append(key.rsplit("-", 1)[1])
            if case == "lost-receipt" and key.endswith("-receipt.json"):
                raise TimeoutError("external S3 response lost")
            self.objects[key] = raw
    evidence = Evidence()
    metadata = {"RequestId": "native-id", "HTTPStatusCode": 200, "HTTPHeaders": {"date": formatdate(1300, usegmt=True)}}
    execution = args["scope"]["machine_arn"].replace(":stateMachine:", ":execution:") + ":" + "a" * 16
    class NativeError(Exception):
        response = {"Error": {"Code": "ExecutionDoesNotExist", "Message": "never retained native text"},
                    "ResponseMetadata": metadata | {"HTTPStatusCode": 400}}
    def sdk(service, operation, **parameters):
        native.append((service, operation, parameters))
        assert events == ["intent.json"]
        events.append("sdk")
        if case == "timeout": raise TimeoutError("late SDK response")
        if case in {"absent", "terminal-absent"}: raise NativeError()
        if service == "dynamodb":
            return {"Item": {"pk": {"S": "ENV#prod#FENCE"}, "state": {"S": "CLOSED"}}, "ResponseMetadata": metadata}
        result = {"executionArn": execution, "stateMachineArn": args["scope"]["machine_arn"], "name": "a" * 16,
                  "status": "SUCCEEDED", "startDate": c.utc(1200), "stopDate": c.utc(1250), "ResponseMetadata": metadata}
        if case == "private-response": result["input"] = "private execution input"
        return result
    session.client.call = sdk
    broker = ag.ClosedReadyBroker(evidence, args["governance"], journal, session, prepared_sha256="3" * 64)
    frame = {"kind": "call", "role": "fence_operator", "service": "dynamodb", "operation": "get_item", "parameters": {
        "TableName": "cnesdata-prod-control", "Key": {"pk": {"S": "ENV#prod#FENCE"}, "sk": {"S": "FENCE"}}, "ConsistentRead": True}}
    if case in {"sfn", "absent", "private-response", "terminal-absent"}:
        frame.update(service="stepfunctions", operation="describe_execution", parameters={"executionArn": execution, "includedData": "METADATA_ONLY"})
    if case == "foreign": frame["parameters"]["TableName"] += "-foreign"
    if case == "eventual": frame["parameters"]["ConsistentRead"] = False
    if case in {"ddb", "sfn", "absent"}:
        reply, result = ag._adapter_message(c.canonical(frame), journal)
        assert result is None and reply["kind"] == ("sdk-error" if case == "absent" else "sdk-result")
        assert events == ["intent.json", "sdk", "response.json", "receipt.json"]
        assert len(journal.call_receipts) == 1 and not journal.unknown and not broker.uncertainty
        assert all(b"never retained" not in raw and b"Credentials" not in raw for raw in evidence.objects.values())
    else:
        with pytest.raises((ValueError, TimeoutError)): ag._adapter_message(c.canonical(frame), journal)
        if case in {"foreign", "eventual"}:
            assert native == events == [] and evidence.objects == {}
        else:
            assert len(native) == 1 and broker.uncertainty and journal.unknown
            with pytest.raises(ValueError): ag._adapter_message(c.canonical(frame), journal)
            assert len(native) == 1


def _ordinal_broker_case(monkeypatch, *, source=None):
    """Real shared broker; only S3/STS/native SDK and clock boundaries are fake."""
    from email.utils import formatdate
    ag, args, _, _ = _fence_sdk_boundary_case(monkeypatch)
    journal = args["journal"]
    if source is not None:
        journal._request["source_sha"] = journal._request["owner"]["source_sha"] = source
    session = ag._assume_fence_session(**args)
    events, calls = [], []
    class Evidence:
        def __init__(self): self.objects = {}
        def get(self, bucket, key, *, maximum, absent=False):
            events.append(("get", key))
            return self.objects.get(key), "etag"
        def put(self, bucket, key, raw):
            assert key not in self.objects
            events.append(("put", key))
            self.objects[key] = raw
    evidence = Evidence()
    execution = session.scope["machine_arn"].replace(":stateMachine:", ":execution:") + ":" + "a" * 16
    def native(service, operation, **parameters):
        ordinal = len(calls)
        ledger = journal._durable_active
        assert ledger._state == "created" and ledger._reserved and ledger._sequence == ordinal
        assert events[-1] == ("get", ledger._keys["intent"])
        if ordinal:
            previous = journal._broker.evidence[ordinal - 1]
            assert previous._state == "settled"
            assert c.sha(evidence.objects[previous._keys["receipt"]]) == ledger._previous
        calls.append((service, operation, parameters))
        events.append(("sdk", ordinal))
        metadata = {"RequestId": "native-" + str(ordinal), "HTTPStatusCode": 200,
                    "HTTPHeaders": {"date": formatdate(1300, usegmt=True)}}
        if service == "dynamodb":
            return {"Item": parameters["Key"] | {"sample": {"N": str(ordinal)}}, "ResponseMetadata": metadata}
        return {"executionArn": execution, "stateMachineArn": session.scope["machine_arn"], "name": "a" * 16,
                "status": "SUCCEEDED", "startDate": c.utc(1200), "stopDate": c.utc(1250), "ResponseMetadata": metadata}
    session.client.call = native
    broker = ag.ClosedReadyBroker(evidence, args["governance"], journal, session, prepared_sha256="3" * 64)
    fence = {"role": "fence_operator", "service": "dynamodb", "operation": "get_item", "parameters": {
        "TableName": "cnesdata-prod-control", "Key": {"pk": {"S": "ENV#prod#FENCE"}, "sk": {"S": "FENCE"}}, "ConsistentRead": True}}
    semaphore = copy.deepcopy(fence)
    semaphore["parameters"]["Key"] = {"pk": {"S": "ENV#prod#SEMAPHORE"}, "sk": {"S": "UNIT"}}
    probe = {"role": "fence_operator", "service": "stepfunctions", "operation": "describe_execution", "parameters": {
        "executionArn": execution, "includedData": "METADATA_ONLY"}}
    return ag, args, broker, evidence, events, calls, [fence, semaphore, fence, semaphore, probe, fence, semaphore]


def test_durable_ordinal_original_fence_sem_sequence_is_fresh(monkeypatch):
    # Reproduces the immutable producer sequence, not product integration proof.
    ag, args, broker, evidence, events, calls, sequence = _ordinal_broker_case(monkeypatch)
    journal = args["journal"]
    original_window = copy.deepcopy(journal._request["stage"])
    replies = [ag._adapter_message(c.canonical({"kind": "call"} | call), journal)[0] for call in sequence]
    assert calls == [(call["service"], call["operation"], call["parameters"]) for call in sequence]
    assert [receipt["sequence"] for receipt in journal.call_receipts] == list(range(7))
    assert len({receipt["request_id"] for receipt in journal.call_receipts}) == 7
    assert [replies[index]["value"]["Item"]["sample"]["N"] for index in (0, 2, 5)] == ["0", "2", "5"]
    previous = None
    for index, ledger in enumerate(broker.evidence):
        intent = c.loads(evidence.objects[ledger._keys["intent"]], canonical=True)
        assert intent["schema_version"] == 2 and intent["sequence"] == index and intent["previous_receipt_sha256"] == previous
        previous = c.sha(evidence.objects[ledger._keys["receipt"]])
    assert journal._durable_count == 7 and journal._durable_last == previous
    assert journal._request["stage"] == original_window and broker.session.deadline == 1480


@pytest.mark.parametrize("change", ["same", "call", "parameters", "session", "prepared", "activation", "request"])
def test_durable_ordinal_restart_zero_cannot_reorder_or_evade(monkeypatch, change):
    ag, args, broker, evidence, _, calls, sequence = _ordinal_broker_case(monkeypatch)
    broker.call(**sequence[0])
    def lost(*args, **kwargs): raise TimeoutError("native response lost")
    broker.session.client.call = lost
    with pytest.raises(ValueError, match="native SDK outcome unknown"): broker.call(**sequence[1])
    original_objects = dict(evidence.objects)
    original_journal = args["journal"]
    request = copy.deepcopy(original_journal._request)
    if change == "activation": request["activation_sha256"] = "d" * 64
    # Construct a genuinely new shared journal: no counter restoration.
    _, owner, window, inputs = _adapter_case("closed-ready")
    if change == "request":
        inputs["membership"] = c.canonical({"fixture": "different request"})
        request["inputs"]["membership"] = {"sha256": c.sha(inputs["membership"]), "size": len(inputs["membership"])}
    restarted = ag.AdapterJournal(c.canonical(request), operation="closed-ready", owner=owner, window=window,
        inputs=inputs, activation_sha256=request["activation_sha256"], guard=original_journal._guard)
    args["journal"] = restarted
    session = ag._assume_fence_session(**args)
    session.client.call = lambda *a, **kw: pytest.fail("restart executed native SDK")
    if change == "session": session.commitment = "d" * 64
    restarted_broker = ag.ClosedReadyBroker(evidence, args["governance"], restarted, session,
                                           prepared_sha256=("d" if change == "prepared" else "3") * 64)
    first = copy.deepcopy(sequence[1] if change == "call" else sequence[0])
    if change == "parameters": first["parameters"]["TableName"] = args["scope"]["control_table_arn"]
    with pytest.raises(ValueError): restarted_broker.call(**first)
    assert evidence.objects == original_objects and restarted._durable_count == 0 and restarted._durable_last is None
    assert len(calls) == 1


@pytest.mark.parametrize("point", ["memory", "response-write", "response-read", "receipt-write", "receipt-read", "sequence", "previous"])
def test_durable_ordinal_never_advances_before_exact_persistence(monkeypatch, point):
    create, store, native = _durable_closed_ready_case(monkeypatch)
    ledger, journal = create()
    assert ledger.reserve() == "created"
    ticket = journal.begin_sdk_call(c.canonical(native), role_session_sha256="2" * 64)
    response = b'{}\n'
    receipt = journal.complete_sdk_call(ticket, response, request_id="native", server_date="Thu, 09 Oct 2025 08:53:20 GMT")
    if point == "sequence": receipt["sequence"] = False  # equals 0 in Python; type must still reject.
    if point == "previous": journal._durable_last = "e" * 64
    for name, suffix in (("response", "response.json"), ("receipt", "receipt.json")):
        if point == name + "-write":
            original = store.put
            def put(bucket, key, raw, original=original, suffix=suffix):
                if key.endswith(suffix): raise TimeoutError("write response lost")
                return original(bucket, key, raw)
            monkeypatch.setattr(store, "put", put)
        if point == name + "-read":
            original = store.get
            def get(bucket, key, original=original, suffix=suffix, **kwargs):
                if key.endswith(suffix): raise TimeoutError("readback lost")
                return original(bucket, key, **kwargs)
            monkeypatch.setattr(store, "get", get)
    if point != "memory":
        with pytest.raises((ValueError, TimeoutError)): ledger.complete(response, receipt)
        assert journal.unknown and journal._failed
    assert journal._durable_count == 0
    with pytest.raises(ValueError): journal._next_durable()
    with pytest.raises(ValueError): journal.begin_sdk_call(c.canonical(native), role_session_sha256="2" * 64)
    with pytest.raises(ValueError): journal.observe("closed-ready", b'{"fixture":true}\n')
    with pytest.raises(ValueError): journal.validate_result(b'{}\n')


@pytest.mark.parametrize("count", [True, -1, 1, 8192])
def test_durable_ordinal_rejects_invalid_or_skipped_counter_before_io(monkeypatch, count):
    create, store, _ = _durable_closed_ready_case(monkeypatch)
    ledger, journal = create()
    journal._durable_count = count
    with pytest.raises(ValueError): ledger.reserve()
    assert store.objects == {} and store.writes == []


def test_durable_ordinal_last_allowed_and_first_disallowed_without_native_io(monkeypatch):
    create, store, _ = _durable_closed_ready_case(monkeypatch)
    _, journal = create()
    # Unit boundary only: emulate size, never fabricate these as SDK receipts.
    journal._call_receipts = [None] * 8191
    journal._durable_count, journal._durable_last = 8191, "e" * 64
    assert journal._next_durable() == (8191, "e" * 64)
    journal._call_receipts.append(None)
    journal._durable_count = 8192
    with pytest.raises(ValueError): journal._next_durable()
    assert store.objects == {} and store.writes == []


@pytest.mark.parametrize("mutation", ["prefix-collision", "schema1", "sequence-bool", "wrapper-hash", "call"])
def test_durable_ordinal_original_bytes_reject_rebound_history(monkeypatch, mutation):
    create, store, native = _durable_closed_ready_case(monkeypatch)
    ledger, journal = create()
    assert ledger.reserve() == "created"
    ticket = journal.begin_sdk_call(c.canonical(native), role_session_sha256="2" * 64)
    response = b'{}\n'
    receipt = journal.complete_sdk_call(ticket, response, request_id="native", server_date="Thu, 09 Oct 2025 08:53:20 GMT")
    ledger.complete(response, receipt)
    original = dict(store.objects)
    restarted, _ = create(**({"prepared_sha256": "e" * 64} if mutation == "prefix-collision" else {}))
    if mutation in {"schema1", "call"}:
        intent = c.loads(store.objects[ledger._keys["intent"]], canonical=True)
        if mutation == "schema1": intent["schema_version"] = 1
        else: intent["call"]["parameters"]["Key"]["pk"]["S"] = "ENV#prod#SEMAPHORE"
        store.objects[ledger._keys["intent"]] = c.canonical(intent)
    if mutation in {"sequence-bool", "wrapper-hash"}:
        wrapper = c.loads(store.objects[ledger._keys["receipt"]], canonical=True)
        if mutation == "sequence-bool": wrapper["call_receipt"]["sequence"] = False
        else: wrapper["intent_sha256"] = "e" * 64
        store.objects[ledger._keys["receipt"]] = c.canonical(wrapper)
    # Force the shortened filename collision; complete intent is still compared.
    restarted._keys = dict(ledger._keys)
    with pytest.raises(ValueError): restarted.reserve()
    assert restarted.uncertainty and restarted._journal._failed
    assert len(store.writes) == 3 and all(key in store.objects for key in original)


def test_readonly_evidence_snapshot_has_no_clock_guard_io_or_mutable_alias(monkeypatch):
    ag, args, broker, evidence, events, _, sequence = _ordinal_broker_case(monkeypatch)
    broker.call(**sequence[0])
    journal = args["journal"]
    before = (list(events), journal._durable_count, journal._durable_last, copy.deepcopy(journal._request))
    def forbidden(*args, **kwargs): pytest.fail("snapshot performed effect or sampled clock")
    monkeypatch.setattr(journal._guard, "check", forbidden)
    monkeypatch.setattr(ag.time, "time", forbidden)
    monkeypatch.setattr(ag.time, "monotonic_ns", forbidden)
    snapshot, raw = ag._adapter_message(c.canonical({"kind": "evidence-snapshot"}), journal)
    assert raw is None and set(snapshot) == {"call_receipts_sha256", "pending", "unknown"}
    snapshot["unknown"].append({"kind": "sdk-call", "reference_sha256": "e" * 64})
    assert not journal.unknown
    assert before == (events, journal._durable_count, journal._durable_last, journal._request)
    with pytest.raises(ValueError): ag._adapter_message(c.canonical({"kind": "evidence-snapshot", "args": []}), journal)


@pytest.mark.parametrize("mutation", [None, "stale", "later-call", "invented", "copy"])
def test_adapter_subprocess_uses_original_sdk_receipt_snapshot(tmp_path, monkeypatch, mutation):
    import subprocess
    product = tmp_path / "product"
    script = product / "scripts/promotion/promote_api.py"
    script.parent.mkdir(parents=True)
    code = r'''import hashlib, json, os
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
def execute_shared_operation(operation, request, context):
    assert all(name not in os.environ for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN'))
    fence = {'TableName': 'cnesdata-prod-control', 'Key': {'pk': {'S': 'ENV#prod#FENCE'}, 'sk': {'S': 'FENCE'}}, 'ConsistentRead': True}
    sem = {'TableName': 'cnesdata-prod-control', 'Key': {'pk': {'S': 'ENV#prod#SEMAPHORE'}, 'sk': {'S': 'UNIT'}}, 'ConsistentRead': True}
    initial = context.evidence_snapshot()
    observed = []
    for params in (fence, sem, fence, sem):
        observed.append(context.call('fence_operator', 'dynamodb', 'get_item', params))
    observed.append(context.call('fence_operator', 'stepfunctions', 'describe_execution', {
        'executionArn': 'arn:aws:states:us-east-2:111122223333:execution:cnesdata-prod:' + 'a' * 16, 'includedData': 'METADATA_ONLY'}))
    for params in (fence, sem):
        observed.append(context.call('fence_operator', 'dynamodb', 'get_item', params))
    raw = canonical({'fixture_only': True, 'observed': observed})
    digest = context.observe('closed-ready', raw)
    snapshot = context.evidence_snapshot()
    MUTATION
    return {'abi_version': 3, 'operation': operation, 'owner_sha256': request['owner']['owner_sha256'],
        'generation': request['owner']['generation'], 'checkpoint_sha256': request['checkpoint_sha256'],
        'observations': [{'kind': 'closed-ready', 'sha256': digest, 'size': len(raw)}], **snapshot}
'''
    action = {None: "pass", "stale": "snapshot = initial", "invented": "snapshot['call_receipts_sha256'] = 'e' * 64",
              "later-call": "context.call('fence_operator', 'dynamodb', 'get_item', fence)",
              "copy": "snapshot['unknown'].append({'kind':'sdk-call', 'reference_sha256':'e'*64}); snapshot = context.evidence_snapshot()"}[mutation]
    script.write_text(code.replace("MUTATION", action))
    def git(*args):
        return subprocess.run(["git", *args], cwd=product, check=True, capture_output=True).stdout.decode().strip()
    git("init", "-q")
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "original subprocess SDK fixture")
    source = git("rev-parse", "HEAD")
    ag, args, broker, evidence, events, calls, _ = _ordinal_broker_case(monkeypatch, source=source)
    manifest = {"version": 1, "source_sha": source, "files": {"scripts/promotion/promote_api.py": c.sha(script.read_bytes())}}
    invoke = dict(product=product, source=source, manifest=manifest, manifest_sha256=c.sha(c.canonical(manifest)),
                  journal=args["journal"], timeout=10)
    if mutation in {"stale", "later-call", "invented"}:
        with pytest.raises(ValueError): ag.invoke_adapter(**invoke)
    else:
        raw = ag.invoke_adapter(**invoke)
        result = c.loads(raw, canonical=True)
        assert result["call_receipts_sha256"] == c.sha(c.canonical(args["journal"].call_receipts))
        assert not result["unknown"] and not result["pending"] and len(calls) == 7
        assert args["journal"].validate_result(raw) is raw


def test_readonly_snapshot_does_not_clear_poison_or_allow_omitted_unknown(monkeypatch):
    ag, args, broker, _, _, _, sequence = _ordinal_broker_case(monkeypatch)
    journal = args["journal"]
    def lost(*args, **kwargs): raise TimeoutError("native response lost")
    broker.session.client.call = lost
    with pytest.raises(ValueError, match="native SDK outcome unknown"): broker.call(**sequence[0])
    before = (journal._durable_count, journal._durable_last, journal._inflight, journal._request.copy())
    snapshot = journal.evidence_snapshot()
    assert snapshot["unknown"] and snapshot["pending"] and journal._failed
    snapshot["unknown"].clear()
    snapshot["pending"].clear()
    with pytest.raises(ValueError): broker.call(**sequence[0])
    with pytest.raises(ValueError): journal.validate_result(c.canonical(snapshot))
    assert before == (journal._durable_count, journal._durable_last, journal._inflight, journal._request)
    assert journal.unknown and journal.pending and journal._failed


@pytest.mark.parametrize("kind", ["initial", "established"])
@pytest.mark.parametrize("mutation", [None, "gap", "old-source", "wrong-owner", "zip", "anchor", "carrier", "ambiguous"])
def test_current_checkpoint_transport_authenticates_real_same_run_publications(kind, mutation):
    import io
    import zipfile
    from tools.cnesdata_delivery import lifecycle_runtime as lr, lifecycle_contract as lc
    documents, _, args, _ = _fence_contract_case()
    owner, producer = args["owner"], args["producer"]
    baseline, predecessor = args["predecessor_raw"], args["predecessor_reference"]
    checkpoint = copy.deepcopy(documents["checkpoint.json"])
    if kind == "established":
        # Synthetic authenticated predecessor reference; transport below still
        # uses real current artifact/ZIP/index/private-byte validators.
        store, terminal = _terminal_fixture(current_caller=True, carrier=checkpoint["phase_a_originals"])
        released = store.get()[0]
        previous = c.loads(terminal["checkpoint.json"], canonical=True)
        previous["state"]["serial"] = 3
        baseline = c.canonical(previous)
        predecessor = {"predecessor_version": 1, "protocol": "lifecycle", "repository": c.REPOSITORY,
            **{key: released[key] for key in ("source_sha", "run_id", "run_attempt", "generation", "session_sha256")},
            "owner_sha256": c.sha(released["owner"].encode()), "checkpoint_sha256": c.sha(baseline),
            "artifact_id": 41, "artifact_digest": "sha256:" + "4" * 64, "producer_job_id": 42, "producer_name": "promotion / keeper",
            "objects": [{"name": name, "sha256": c.sha(raw), "size": len(raw)} for name, raw in
                        sorted((terminal | {"checkpoint.json": baseline}).items())]}
        checkpoint["state"]["serial"] = 5
    prior_checkpoint = copy.deepcopy(checkpoint)
    prior_checkpoint["state"]["serial"] -= 1
    prior_raw = c.canonical(prior_checkpoint)
    current_raw = c.canonical(checkpoint)
    approval = copy.deepcopy(documents["approval.json"])
    prior_approval = copy.deepcopy(approval)
    prior_approval["checkpoint_sha256"] = c.sha(baseline)
    approval["checkpoint_sha256"] = c.sha(prior_raw)
    if mutation == "gap": approval["checkpoint_sha256"] = "d" * 64
    request = {"source_sha": owner["source_sha"], "step": producer["step"],
               "application_purpose": owner["application_purpose"], "caller_binding_sha256": owner["caller_binding_sha256"]}
    catalog = {"initial-plan": {"role": "plan", "historical_entry": True, "job_name": "Initial plan"},
               "earlier-deploy": {"role": "deploy", "job_name": "Earlier deploy", "purpose": "application-prepare", "direction": "advance", "mode": "operational"}}
    governance = {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "synthetic", "context_kind": "promotion", "lifecycle_steps": catalog}
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"], "head_sha": owner["source_sha"],
           "event": "workflow_dispatch", "repository": {"full_name": c.REPOSITORY}, "path": ".github/workflows/promote-production.yml"}
    root = f"repos/{c.REPOSITORY}"
    jobs, artifacts, responses, objects = [], [], {}, {}
    for number, (step_name, files) in enumerate((("initial-plan", {"checkpoint.json": baseline}),
            ("earlier-deploy", {"checkpoint.json": prior_raw, "approval.json": c.canonical(prior_approval)})), 1):
        if mutation == "anchor" and number == 1: files["checkpoint.json"] = prior_raw
        if mutation == "carrier" and number == 2:
            altered = c.loads(files["checkpoint.json"], canonical=True)
            altered["phase_a_originals"]["origin"]["source_sha"] = "d" * 40
            files["checkpoint.json"] = c.canonical(altered)
        job = {"id": number, "run_id": run["id"], "run_attempt": run["run_attempt"], "head_sha": run["head_sha"],
               "name": catalog[step_name]["job_name"], "status": "completed", "conclusion": "success",
               "started_at": c.utc(1000), "completed_at": c.utc(1100)}
        if mutation == "old-source" and number == 2: job["head_sha"] = "d" * 40
        jobs.append(job)
        index = {"version": 1, "source_sha": owner["source_sha"], "run_id": owner["run_id"], "run_attempt": owner["run_attempt"],
                 "step": step_name, "owner_sha256": owner["owner_sha256"], "generation": owner["generation"], **lc.application_identity(owner),
                 "files": [{"name": name, "size": len(raw), "sha256": c.sha(raw)} for name, raw in sorted(files.items())]}
        if mutation == "wrong-owner" and number == 2: index["owner_sha256"] = "f" * 64
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as output: output.writestr("index.json", c.canonical(index))
        raw = archive.getvalue()
        metadata = {"id": number, "name": "lifecycle-" + step_name, "digest": "sha256:" + c.sha(raw),
                    "workflow_run": {"id": run["id"], "head_sha": run["head_sha"]}, "expired": False,
                    "expires_at": c.utc(2000), "created_at": c.utc(1050)}
        artifacts.append(metadata)
        responses[root + f"/actions/jobs/{number}"] = job
        responses[root + f"/actions/artifacts/{number}"] = metadata
        responses[root + f"/actions/artifacts/{number}/zip"] = raw + (b"bad" if mutation == "zip" else b"")
        for name, value in files.items():
            objects[lr.namespace(governance, request, run, step_name) + name] = value
    if mutation == "ambiguous": artifacts.append(artifacts[0] | {"id": 3})
    responses[root + f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}"] = run
    responses[root + f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100&page=1"] = {"jobs": jobs, "total_count": len(jobs)}
    responses[root + f"/actions/runs/{run['id']}/artifacts?per_page=100&page=1"] = {"artifacts": artifacts, "total_count": len(artifacts)}
    reads = []
    class API:
        def read(self, path, **kwargs): return responses[path]
    class AWS:
        def get(self, bucket, key, **kwargs):
            assert f"/lifecycle/{owner['source_sha']}/{owner['run_id']}/{owner['run_attempt']}/" in key
            reads.append(key)
            return objects[key], None
    class Guard:
        def check(self, seconds=0): assert seconds <= 20
    def transport():
        return lr.current_checkpoint_chain(API(), AWS(), governance, request, run, owner=owner, predecessor=predecessor,
            current_raw=current_raw, approval_raw=c.canonical(approval), previous_raw=prior_raw, producer=producer, guard=Guard(), now=1200)
    if mutation:
        with pytest.raises(ValueError): transport()
    else:
        chain, original = transport()
        assert original == baseline and chain["anchor_sha256"] == c.sha(baseline)
        assert [entry["checkpoint_sha256"] for entry in chain["entries"]] == [c.sha(prior_raw), c.sha(current_raw)]
        assert len(reads) == 3


@pytest.mark.parametrize("kind", ["initial", "established"])
@pytest.mark.parametrize("mutation", [None, "noop", "phase-a-anchor", "reference-hash", "approval", "relabel", "gap", "schema2"])
def test_fence_chain_binds_actual_predecessor_and_post_apply_head(kind, mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    documents, _, args, encode = _fence_contract_case()
    carrier = documents["checkpoint.json"]["phase_a_originals"]
    originals = lc.phase_a_originals(carrier)
    predecessor_raw, predecessor = originals["raw"]["checkpoint.json"], carrier["origin"]
    if kind == "established":
        store, terminal = _terminal_fixture(current_caller=True)
        released = store.get()[0]
        previous = c.loads(terminal["checkpoint.json"], canonical=True)
        previous["state"]["lineage"] = originals["checkpoint"]["state_after"]["lineage"]
        previous["state"]["serial"] = 3
        predecessor_raw = c.canonical(previous)
        predecessor = {"predecessor_version": 1, "protocol": "lifecycle", "repository": c.REPOSITORY,
            **{key: released[key] for key in ("source_sha", "run_id", "run_attempt", "generation", "session_sha256")},
            "owner_sha256": c.sha(released["owner"].encode()), "checkpoint_sha256": c.sha(predecessor_raw),
            "artifact_id": 41, "artifact_digest": "sha256:" + "4" * 64, "producer_job_id": 42, "producer_name": "promotion / keeper",
            "objects": [{"name": name, "sha256": c.sha(raw), "size": len(raw)} for name, raw in
                        sorted((terminal | {"checkpoint.json": predecessor_raw}).items())]}
    baseline = c.loads(predecessor_raw, canonical=True)
    before = baseline["state_after"] if kind == "initial" else baseline["state"]
    checkpoint, chain = documents["checkpoint.json"], documents["fence-chain.json"]
    checkpoint["state"] = dict(before) if mutation == "noop" else before | {"serial": before["serial"] + 1, "state_sha256": "8" * 64}
    checkpoint["state_object"] = dict(baseline["state_object"]) if mutation == "noop" else {
        "status": "present", "version_id": "new-post-apply-version", "etag_sha256": "7" * 64}
    chain.update(schema_version=3, anchor_sha256=c.sha(predecessor_raw))
    chain["entries"][0].update(previous_checkpoint_sha256=chain["anchor_sha256"], state=checkpoint["state"], state_object=checkpoint["state_object"])
    documents["approval.json"]["checkpoint_sha256"] = chain["anchor_sha256"]
    args.update(predecessor_raw=predecessor_raw, predecessor_reference=predecessor)
    if mutation == "phase-a-anchor" and kind == "established":
        chain["anchor_sha256"] = carrier["origin"]["checkpoint_sha256"]
        chain["entries"][0]["previous_checkpoint_sha256"] = chain["anchor_sha256"]
    if mutation == "reference-hash":
        chain["anchor_sha256"] = c.sha(c.canonical(predecessor))
        chain["entries"][0]["previous_checkpoint_sha256"] = chain["anchor_sha256"]
    if mutation == "approval": documents["approval.json"]["checkpoint_sha256"] = "6" * 64
    if mutation == "relabel": chain["entries"][0]["origin"]["source_sha"] = predecessor["source_sha"]
    if mutation == "gap": chain["entries"][0]["previous_checkpoint_sha256"] = "5" * 64
    if mutation == "schema2": chain["schema_version"] = 2
    _rebind_fence_checkpoint(chain, checkpoint)
    files, original = encode()
    if mutation not in {None, "noop"} and not (kind == "initial" and mutation == "phase-a-anchor"):
        with pytest.raises(ValueError): lc.validate_fence_prepared_package(files, originals=original, **args)
    else:
        assert lc.validate_fence_prepared_package(files, originals=original, **args)["outcome"] == "observed"
        assert chain["head_sha256"] != chain["anchor_sha256"]


def test_complete_phase_a_carrier_feeds_real_fence_projection_within_all_caps():
    from tools.cnesdata_delivery import lifecycle_runtime as lr, lifecycle_contract as lc
    args = _current_fence_projection_case(probe=True)
    result = lr.fence_current_role_projection(**args)
    assert any(item["Action"] == "states:DescribeExecution" for item in result["role"]["policy"]["Statement"])
    carrier = args["checkpoint"]["phase_a_originals"]
    original = lc.phase_a_originals(carrier)
    assert original["checkpoint"]["outputs"]["processor_task_definition_arns"]
    assert original["checkpoint"]["outputs"]["grant_fingerprints"]
    wrapper = {"version": 2, "owner": args["owner"], "predecessor_sha256": c.sha(c.canonical(args["predecessor_reference"])),
               "phase_a_originals": carrier}
    _, terminal = _terminal_fixture(current_caller=True, carrier=carrier)
    assert sum(map(len, original["raw"].values())) <= 131072
    assert len(c.canonical(carrier)) <= 196608
    assert len(c.canonical(wrapper)) <= 262144 and len(terminal["checkpoint.json"]) <= 262144
    assert c.loads(terminal["checkpoint.json"], canonical=True)["phase_a_originals"] == carrier


class _HistoricalSourceAPI:
    """External GitHub fake for the pinned historical source reader (amendment 2026-11-13 item 4)."""
    def __init__(self, source, current, files, *, status="ahead", truncated=False):
        import base64
        import hashlib
        self.source, self.current, self.files, self.status, self.truncated = source, current, dict(files), status, truncated
        self.blob = lambda raw: hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()
        self.contents = {path: {"type": "file", "path": path, "size": len(raw), "encoding": "base64",
                                "sha": self.blob(raw), "content": base64.b64encode(raw).decode()} for path, raw in self.files.items()}
        self.calls = []

    def read(self, path, **_):
        self.calls.append(path)
        if path == f"repos/{c.REPOSITORY}/compare/{self.source}...{self.current}":
            return {"status": self.status, "merge_base_commit": {"sha": self.source}}
        if path == f"repos/{c.REPOSITORY}/git/trees/{self.source}?recursive=1":
            return {"sha": "f" * 40, "truncated": self.truncated, "tree": [
                {"path": name, "type": "blob", "mode": "100644", "sha": self.blob(raw), "size": len(raw)} for name, raw in self.files.items()]}
        prefix = f"repos/{c.REPOSITORY}/contents/"
        assert path.startswith(prefix) and path.endswith("?ref=" + self.source), path
        return self.contents[path[len(prefix):-len("?ref=" + self.source)]]


def _historical_sources_case():
    carrier, raw = _phase_a_carrier_case()
    source = carrier["origin"]["source_sha"]
    files = {"infra/opentofu/modules/runtime-iam/promotion.tf": b'resource "aws_iam_role" "x" {}\n',
             "infra/opentofu/env/prod/main.tf": b'module "runtime_iam" {}\n'}
    return carrier, source, files


@pytest.mark.parametrize("mutation", [None, "diverged", "merge-base", "truncated", "blob-sha", "content", "type",
                                      "large", "too-many", "unsorted", "path", "absent-selected"])
def test_historical_sources_reads_exact_phase_a_commit_by_path(mutation):
    from tools.cnesdata_delivery.lifecycle_runtime import historical_sources
    carrier, source, files = _historical_sources_case()
    current = "a" * 40
    api = _HistoricalSourceAPI(source, current, files, status="diverged" if mutation == "diverged" else "ahead",
                               truncated=mutation == "truncated")
    paths = sorted([*files, "infra/opentofu/modules/runtime-iam/new.tf"])
    if mutation == "merge-base":
        original = api.read
        api.read = lambda path, **kw: (original(path) | {"merge_base_commit": {"sha": "b" * 40}}) if "/compare/" in path else original(path)
    if mutation == "blob-sha": api.contents[paths[0]]["sha"] = "0" * 40
    if mutation == "content": api.contents[paths[0]]["content"] = __import__("base64").b64encode(b"tampered\n").decode()
    if mutation == "type": api.contents[paths[0]]["type"] = "symlink"
    if mutation == "large":
        big = b"#" * (256 * 1024 + 1)
        api = _HistoricalSourceAPI(source, current, {**files, paths[0]: big})
    if mutation == "too-many": paths = [f"infra/opentofu/modules/runtime-iam/f{i:02d}.tf" for i in range(65)]
    if mutation == "unsorted": paths = list(reversed(paths))
    if mutation == "path": paths = ["infra/opentofu/../secrets.tf"]
    if mutation == "absent-selected":
        # A historical inventory without a path is absence only via the complete tree, never via a failed read.
        api.files.pop(paths[0])
        api.contents.pop(paths[0])
    if mutation in {None, "absent-selected"}:
        result = historical_sources(api, carrier, current_source=current, paths=paths)
        expected = dict(files)
        expected.pop(paths[0]) if mutation else None
        assert result == expected
        assert "infra/opentofu/modules/runtime-iam/new.tf" not in result
        assert api.calls[0].endswith(f"/compare/{source}...{current}")
    else:
        with pytest.raises(ValueError):
            historical_sources(api, carrier, current_source=current, paths=paths)


@pytest.mark.parametrize("count", [8, 9])
def test_historical_sources_total_is_capped_at_two_mebibytes(count):
    from tools.cnesdata_delivery.lifecycle_runtime import historical_sources
    carrier, source, _ = _historical_sources_case()
    files = {f"infra/opentofu/modules/runtime-iam/f{i}.tf": bytes([65 + i]) * (256 * 1024) for i in range(count)}
    api = _HistoricalSourceAPI(source, "a" * 40, files)
    if count == 8:
        assert historical_sources(api, carrier, current_source="a" * 40, paths=sorted(files)) == files
        return
    with pytest.raises(ValueError, match="historical source total"):
        historical_sources(api, carrier, current_source="a" * 40, paths=sorted(files))


def test_historical_sources_binds_contents_blob_to_the_tree_entry_sha():
    from tools.cnesdata_delivery.lifecycle_runtime import historical_sources
    carrier, source, files = _historical_sources_case()
    api = _HistoricalSourceAPI(source, "a" * 40, files)
    original = api.read
    def read(path, **kw):
        value = original(path, **kw)
        if "/git/trees/" in path:
            value["tree"] = [entry | {"sha": "e" * 40} for entry in value["tree"]]
        return value
    api.read = read
    with pytest.raises(ValueError, match="historical source blob sha1"):
        historical_sources(api, carrier, current_source="a" * 40, paths=sorted(files))


def test_historical_sources_pins_phase_a_source_from_authenticated_carrier():
    from tools.cnesdata_delivery.lifecycle_runtime import historical_sources
    carrier, source, files = _historical_sources_case()
    forged = c.loads(c.canonical(carrier), canonical=True)
    forged["origin"]["source_sha"] = "b" * 40
    with pytest.raises(ValueError):
        historical_sources(_HistoricalSourceAPI("b" * 40, "a" * 40, files), forged, current_source="a" * 40, paths=sorted(files))


def _producer_jobs_case(source="a" * 40, *, runner="runner-7"):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    steps = [{"name": name, "number": number, "status": "completed", "conclusion": "success"}
             for number, name in enumerate(lc.FENCE_PREPARE_STEPS[:-1], start=1)]
    steps.append({"name": lc.FENCE_PREPARE_STEPS[-1], "number": len(steps) + 1, "status": "in_progress", "conclusion": None})
    job = {"id": 4242, "name": lc.FENCE_PREPARE_PRODUCER["job_name"], "status": "in_progress", "head_sha": source,
           "runner_name": runner, "steps": steps, "run_id": 7, "run_attempt": 2}
    other = {"id": 11, "name": "application-prepare-operational / audit", "status": "completed", "head_sha": source,
             "runner_name": "other", "steps": [], "run_id": 7, "run_attempt": 2}
    return [other, job]


class _JobsAPI:
    def __init__(self, jobs, *, total=None):
        self.jobs, self.total, self.calls = jobs, len(jobs) if total is None else total, []

    def read(self, path, **_):
        self.calls.append(path)
        assert path.startswith(f"repos/{c.REPOSITORY}/actions/runs/7/attempts/2/jobs?per_page=100&page=")
        page = int(path.rsplit("=", 1)[1])
        return {"total_count": self.total, "jobs": self.jobs[(page - 1) * 100:page * 100]}


@pytest.mark.parametrize("mutation", [None, "zero", "two", "runner-absent", "runner-other", "status", "head", "gate-done",
                                      "prior-failed", "prior-order", "prior-missing", "incomplete-inventory"])
def test_fence_producer_job_requires_single_running_gate_on_this_runner(monkeypatch, mutation):
    from tools.cnesdata_delivery.lifecycle_runtime import fence_producer_job
    jobs = _producer_jobs_case()
    job = jobs[1]
    monkeypatch.setenv("RUNNER_NAME", "runner-7")
    total = None
    if mutation == "zero": jobs.pop(1)
    if mutation == "two": jobs.append(dict(job, id=4243))
    if mutation == "runner-absent": monkeypatch.delenv("RUNNER_NAME")
    if mutation == "runner-other": job["runner_name"] = "runner-8"
    if mutation == "status": job["status"] = "completed"
    if mutation == "head": job["head_sha"] = "b" * 40
    if mutation == "gate-done": job["steps"][-1].update(status="completed", conclusion="success")
    if mutation == "prior-failed": job["steps"][3]["conclusion"] = "failure"
    if mutation == "prior-order": job["steps"][2]["number"], job["steps"][3]["number"] = 4, 3
    if mutation == "prior-missing": job["steps"].pop(5)
    if mutation == "incomplete-inventory": total = 3
    api = _JobsAPI(jobs, total=total)
    run = {"id": 7, "run_attempt": 2, "head_sha": "a" * 40}
    if mutation is None:
        assert fence_producer_job(api, run, "a" * 40)["id"] == 4242
    else:
        with pytest.raises((ValueError, KeyError)):
            fence_producer_job(api, run, "a" * 40)


def test_fence_consumer_and_producer_share_the_nine_named_steps():
    import inspect
    from tools.cnesdata_delivery import lifecycle_contract as lc, lifecycle_runtime as lr
    assert len(lc.FENCE_PREPARE_STEPS) == 9 and lc.FENCE_PREPARE_STEPS[-1] == lc.FENCE_PREPARE_PRODUCER["step_name"]
    source = inspect.getsource(lr.fence_prepared_payload)
    assert "FENCE_PREPARE_STEPS" in source and "Install checksum-locked protected runtime" not in source


def test_fence_sts_policy_is_the_single_pure_fence_session_policy(monkeypatch):
    from tools.cnesdata_delivery import session_policy
    ag, args, calls, _ = _fence_sdk_boundary_case(monkeypatch)
    ag._assume_fence_session(**args)
    scope, deadline = args["scope"], args["journal"]._request["stage"]["deadline"]
    expected = session_policy.fence_session_policy(
        control_table_arn=scope["control_table_arn"],
        execution_prefix=scope["machine_arn"].replace(":stateMachine:", ":execution:") + ":", deadline=deadline)
    assert calls[0][2]["Policy"] == c.canonical(expected).decode().strip()
    assert expected["Statement"][0]["Condition"]["DateLessThan"] == {"aws:CurrentTime": c.utc(deadline)}


@pytest.mark.parametrize("mutation", ["prefix-wildcard", "prefix-colon", "table", "deadline-bool"])
def test_fence_session_policy_rejects_non_exact_scope(mutation):
    from tools.cnesdata_delivery import session_policy
    kwargs = dict(control_table_arn="arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control",
                  execution_prefix="arn:aws:states:us-east-2:111122223333:execution:cnesdata-prod:", deadline=1480)
    session_policy.fence_session_policy(**kwargs)
    if mutation == "prefix-wildcard": kwargs["execution_prefix"] += "*"
    if mutation == "prefix-colon": kwargs["execution_prefix"] = kwargs["execution_prefix"][:-1]
    if mutation == "table": kwargs["control_table_arn"] += "*"
    if mutation == "deadline-bool": kwargs["deadline"] = True
    with pytest.raises(ValueError):
        session_policy.fence_session_policy(**kwargs)


def _fence_prepare_package_case(monkeypatch, mutation=None):
    """Synthetic producer composition; GitHub and IAM are external fakes, nothing here is applied evidence."""
    import base64
    import hashlib
    from email.utils import formatdate
    from types import SimpleNamespace
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.session_owner import _terraform_document_digest
    args = _current_fence_projection_case(probe=True)
    owner, fragment, carrier = args["owner"], copy.deepcopy(args["fragment"]), args["checkpoint"]["phase_a_originals"]
    account, role_name = "111122223333", "cnesdata-prod-promotion-fence-operator"
    fence_arn = fragment["delegations"]["fence_operator"]
    lifecycle = "arn:aws:s3:::synthetic-evidence/cnesdata/prod/evidence/lifecycle/"
    coordination = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": fence_arn},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": lifecycle + ("*" if mutation != "evaluation" else "keeper/*")}]}
    managed = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": fence_arn}]}
    fragment["policy_sha256"] = _terraform_document_digest(coordination)
    pin = {"document": managed, "document_sha256": c.sha(c.canonical(managed)), "frozen_until": c.utc(5000)}
    governance = {"account_id": account, "evidence_bucket": "synthetic-evidence", "evidence_prefix": "cnesdata/prod/evidence/",
        "state_bucket": "synthetic-state", "evidence_kms_key_arn": "arn:aws:kms:us-east-2:111122223333:key/synthetic",
        "gate_shas": {"deploy": "c" * 40}, "source_closure": {"infra/opentofu/env/prod/main.tf": "1" * 64},
        "application_coordination_policy": c.canonical(coordination).decode().strip(),
        "application_delegations": fragment["delegations"], "roles": {"application": fragment["application_role_arn"]}}
    history = lc.phase_a_originals(carrier)
    previous_raw = history["raw"]["checkpoint.json"]
    checkpoint_raw = c.canonical(args["checkpoint"])
    approval = {"version": 1, "owner": owner, "purpose": "application-prepare", "direction": "advance",
        "plan_sha256": args["checkpoint"]["plan_sha256"], "inputs_sha256": c.sha(args["inputs_raw"]), "checkpoint_sha256": c.sha(previous_raw),
        "delta": {"purpose": "application-prepare", "direction": "advance", "mode": "operational", "before": {}, "original": {},
                  "created": {}, "expected_changes_sha256": "f" * 64}, "drift_matrix": {}, "readbacks": {"before": [], "after": []}}
    request = {"source_sha": owner["source_sha"], "step": lc.FENCE_PREPARE_PRODUCER["step"],
               "application_purpose": "promotion", "caller_binding_sha256": owner["caller_binding_sha256"]}
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"], "head_sha": owner["source_sha"]}
    jobs = _producer_jobs_case(owner["source_sha"])
    monkeypatch.setenv("RUNNER_NAME", "runner-7" if mutation != "runner" else "runner-8")
    historical_source = carrier["origin"]["source_sha"]
    blob = lambda raw: hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()
    old_sources = dict(args["original_sources"])
    if mutation == "historical-source":
        old_sources["infra/opentofu/modules/runtime-iam/promotion.tf"] += b"# drift\n"
    calls = []
    class API:
        def read(self, path, **_):
            calls.append(("github", path))
            root = f"repos/{c.REPOSITORY}/"
            if "/jobs?per_page=100&page=" in path:
                return {"total_count": len(jobs), "jobs": jobs}
            if path == root + f"compare/{historical_source}...{owner['source_sha']}":
                return {"status": "ahead", "merge_base_commit": {"sha": historical_source}}
            if path == root + f"git/trees/{historical_source}?recursive=1":
                return {"truncated": False, "tree": [{"path": k, "type": "blob", "mode": "100644", "sha": blob(v)} for k, v in old_sources.items()]}
            name = path.removeprefix(root + "contents/").removesuffix("?ref=" + historical_source)
            raw = old_sources[name]
            return {"type": "file", "path": name, "encoding": "base64", "size": len(raw), "sha": blob(raw), "content": base64.b64encode(raw).decode()}
    now = [1000.0]
    observed_role = copy.deepcopy(next(r["observed"] for r in history["checkpoint"]["readbacks"] if r["operation"] == "get_role"))
    observed_policy = copy.deepcopy(next(r["observed"] for r in history["checkpoint"]["readbacks"] if r["operation"] == "get_role_policy"))
    responses = {"get_role": observed_role, "list_role_policies": {"PolicyNames": [role_name + "-gate"], "IsTruncated": False},
                 "list_attached_role_policies": {"AttachedPolicies": [], "IsTruncated": False}, "get_role_policy": observed_policy}
    class AWS:
        def call(self, service, operation, **parameters):
            calls.append((service, operation))
            assert service == "iam" and parameters["RoleName"] == role_name
            now[0] += 0.5
            body = copy.deepcopy(responses[operation])
            if mutation == "readback" and operation == "get_role" and len([x for x in calls if x[1] == "get_role"]) == 2:
                body["Role"]["RoleId"] = "AROAREPLACED"
            return body | {"ResponseMetadata": {"RequestId": f"req-{len(calls)}", "HTTPStatusCode": 200,
                                                "HTTPHeaders": {"date": formatdate(now[0], usegmt=True)}}}
    class Guard:
        window = {"admitted_at": 1000, "preparation_deadline": 1900, "windows": MINIMUM_WINDOWS}
        def check(self, seconds=0): pass
    kwargs = dict(api=API(), aws=AWS(), governance=governance, request=request, run=run, owner=owner, guard=Guard(),
        authority=SimpleNamespace(application_fragment=fragment, pin=pin), predecessor=carrier["origin"], carrier=carrier,
        plan_index=args["current_index"], plan_raw=args["plan_raw"], inputs_raw=args["inputs_raw"], terraform_raw=args["inputs_raw"],
        approval_raw=c.canonical(approval), previous_raw=previous_raw, checkpoint_raw=checkpoint_raw, state_raw=args["state_raw"],
        sources=args["sources"], activation_sha256="1" * 64, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    return kwargs, calls, fragment


def test_fence_evaluation_binds_shared_table_and_strictly_precedes_freeze(monkeypatch):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    kwargs, _, _ = _fence_prepare_package_case(monkeypatch)
    scope_of, documents_of, seen = lr.fence_evaluation_scope, lr.fence_evaluation_documents, {}
    def scope_spy(**arguments):
        seen["scope"] = arguments
        return scope_of(**arguments)
    def documents_spy(**arguments):
        seen["documents"] = arguments
        return documents_of(**arguments)
    monkeypatch.setattr(lr, "fence_evaluation_scope", scope_spy)
    monkeypatch.setattr(lr, "fence_evaluation_documents", documents_spy)
    lr.fence_prepare_package(**kwargs)
    scope = seen["scope"]
    with pytest.raises(ValueError, match="fence table equals authenticated shared output"):
        scope_of(**scope | {"control_table_arn": scope["control_table_arn"] + "-other"})
    documents = seen["documents"]
    frozen = int(min(c.instant(documents["pin"]["frozen_until"]), c.instant(documents["fragment"]["enabled_until"])))
    assert documents_of(**documents | {"observed_at": frozen - 1})["freeze"]["frozen_until"] == c.utc(frozen)
    with pytest.raises(ValueError, match="fence evaluation before freeze"):
        documents_of(**documents | {"observed_at": frozen})


_IDENTITY_REFUSALS = {"absent": "protected application coordination policy",
                      "oversized": "protected application coordination policy",
                      "commitment": "application coordination policy commitment",
                      "version": "application coordination statements", "statements": "application coordination statements",
                      "predecessor-missing": "application predecessor policy composition",
                      "predecessor-unexpected": "application predecessor policy composition"}


@pytest.mark.parametrize("mutation", [None, *_IDENTITY_REFUSALS])
def test_application_identity_document_checks_protected_policy_offline(mutation):
    from tools.cnesdata_delivery import session_owner
    statement = {"Effect": "Allow", "Action": "sts:AssumeRole",
                 "Resource": "arn:aws:iam::111122223333:role/cnesdata-prod-promotion-fence-operator"}
    coordination = {"Version": "2008-10-17" if mutation == "version" else "2012-10-17",
                    "Statement": [] if mutation == "statements" else [statement]}
    raw = c.canonical(coordination).decode().strip()
    governance = {"application_coordination_policy": raw + " " * 65536 if mutation == "oversized" else raw}
    fragment = {"policy_sha256": "0" * 64 if mutation == "commitment" else session_owner._terraform_document_digest(coordination)}
    if mutation == "absent": governance.pop("application_coordination_policy")
    if mutation == "predecessor-missing": fragment["predecessor_reads"] = {"policy_sha256": "1" * 64}
    if mutation == "predecessor-unexpected": governance["predecessor_read"] = {}
    if mutation is None:
        assert session_owner.application_identity_document(governance, fragment) == {"Version": "2012-10-17", "Statement": [statement]}
        return
    with pytest.raises(ValueError, match=_IDENTITY_REFUSALS[mutation]):
        session_owner.application_identity_document(governance, fragment)


@pytest.mark.parametrize("mutation", [None, "runner", "historical-source", "readback", "evaluation"])
def test_fence_prepare_package_produces_eight_files_the_consumer_codec_accepts(monkeypatch, mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc, lifecycle_runtime as lr
    kwargs, calls, fragment = _fence_prepare_package_case(monkeypatch, mutation)
    if mutation:
        with pytest.raises(ValueError):
            lr.fence_prepare_package(**kwargs)
        if mutation == "runner":
            assert all(kind == "github" for kind, _ in calls) and len(calls) == 1
        return
    files = lr.fence_prepare_package(**kwargs)
    assert set(files) == lc.FENCE_PREPARE_FILES
    manifest = c.loads(files["fence-prepared.json"], canonical=True)
    assert manifest["producer"]["job_id"] == 4242 and manifest["outcome"] == "observed"
    origins = c.loads(files["fence-origins.json"], canonical=True)
    assert origins["phase_a"]["source_closure_sha256"] == c.sha(c.canonical(origins["projection_source_files"]))
    evaluation = c.loads(files["fence-evaluation.json"], canonical=True)
    assert all(case["observed"] is case["expected"] for case in evaluation["cases"])
    assert len([1 for kind, _ in calls if kind == "iam"]) == 8
    lc.validate_fence_prepared_package(files, owner=kwargs["owner"], fragment=fragment, activation_sha256="1" * 64,
        producer=manifest["producer"], preparation=manifest["preparation"],
        originals={name: raw for name, raw in files.items() if name != "fence-prepared.json"},
        predecessor_raw=kwargs["previous_raw"], predecessor_reference=kwargs["predecessor"])


@pytest.mark.parametrize("mutation,message", [
    (None, None),
    ("index-attempt", "fence current plan owner/caller"),
    ("index-plan", "fence applied current saved-plan commitment"),
    ("index-inputs", "fence original current plan/input bytes"),
    ("previous", "current deploy immediate predecessor bytes"),
    ("predecessor", "fence initial original Phase A checkpoint"),
])
def test_fence_prepare_package_connects_index_chain_and_predecessor_without_new_sources(monkeypatch, mutation, message):
    """Amendment 2026-11-13 item 6: current_index is the plan index read by private_payload, chain/predecessor_raw
    the pair returned by current_checkpoint_chain, predecessor_reference the authenticate_predecessor reference.
    A mismatch in any of them refuses before the first IAM call; nothing else is read."""
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    kwargs, calls, _ = _fence_prepare_package_case(monkeypatch)
    index = copy.deepcopy(kwargs["plan_index"])
    if mutation == "index-attempt":
        index["run_attempt"] += 1
    if mutation in {"index-plan", "index-inputs"}:
        name = "plan.bin" if mutation == "index-plan" else "inputs.json"
        next(item for item in index["files"] if item["name"] == name)["sha256"] = "0" * 64
    kwargs["plan_index"] = index
    if mutation == "previous":
        kwargs["previous_raw"] += b" "
    if mutation == "predecessor":
        kwargs["predecessor"] = dict(kwargs["predecessor"], artifact_digest="sha256:" + "0" * 64)
    if mutation:
        with pytest.raises(ValueError, match=message):
            lr.fence_prepare_package(**kwargs)
        assert [kind for kind, _ in calls if kind != "github"] == []
        return
    files = lr.fence_prepare_package(**kwargs)
    origins = c.loads(files["fence-origins.json"], canonical=True)
    assert origins["current_plan"]["index_sha256"] == c.sha(c.canonical(kwargs["plan_index"]))
    assert origins["current_plan"]["step"] == kwargs["plan_index"]["step"]
    plan_bin = next(item for item in kwargs["plan_index"]["files"] if item["name"] == "plan.bin")
    assert origins["current_plan"]["plan_binary_sha256"] == plan_bin["sha256"]
    chain = c.loads(files["fence-chain.json"], canonical=True)
    assert chain["anchor_sha256"] == kwargs["predecessor"]["checkpoint_sha256"] == c.sha(kwargs["previous_raw"])
    assert chain["head_sha256"] == c.sha(kwargs["checkpoint_raw"])
    assert chain["entries"][-1]["previous_checkpoint_sha256"] == c.sha(kwargs["previous_raw"])
    # No new source: GitHub reads are the producer job inventory and the pinned historical reader only.
    historical = kwargs["carrier"]["origin"]["source_sha"]
    root = f"repos/{c.REPOSITORY}/"
    for kind, path in calls:
        assert kind in {"github", "iam"}
        if kind == "github":
            assert ("/jobs?per_page=100&page=" in path or path.startswith(root + "compare/" + historical + "...")
                    or path == root + f"git/trees/{historical}?recursive=1" or path.endswith("?ref=" + historical)), path


def _closed_ready_capability_case(monkeypatch, mutation=None):
    """Connected item-7 composition: real prepared producer/codec, real broker; GitHub/S3/STS are external fakes."""
    import io
    import zipfile
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc, lifecycle_runtime as lr
    kwargs, _, _ = _fence_prepare_package_case(monkeypatch)
    activation = b"original-ext2-payload-bytes"
    kwargs["activation_sha256"] = c.sha(activation)
    if mutation == "frozen":
        # Positive variant: the freeze falls between observed_at and observed_at + 180.
        kwargs["authority"].pin["frozen_until"] = c.utc(1100)
    if mutation == "session-document":
        # A producer whose evaluated fence session differs beyond DateLessThan (one more leading key):
        # the package stays internally consistent, the evaluation still passes, only item 3 can tell.
        from tools.cnesdata_delivery import session_policy
        shared = session_policy.fence_session_policy
        def drifted(**arguments):
            policy = shared(**arguments)
            policy["Statement"][0]["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"].append("ENV#prod#DRIFT")
            return policy
        monkeypatch.setattr(session_policy, "fence_session_policy", drifted)
        files = lr.fence_prepare_package(**kwargs)
        monkeypatch.setattr(session_policy, "fence_session_policy", shared)
    else:
        files = lr.fence_prepare_package(**kwargs)
    prepared = lr.PreparedFence(files)
    owner, carrier = kwargs["owner"], kwargs["carrier"]
    ag_mod, sts_args, sts_calls, _ = _fence_sdk_boundary_case(monkeypatch)
    scope = sts_args["scope"]
    b_checkpoint = {"state": {"lineage": "original-lineage", "serial": 3, "state_sha256": "6" * 64},
        "state_object": {"status": "present", "version_id": "v3", "etag_sha256": "5" * 64}, "owner": owner, "purpose": "phase-b",
        "plan_sha256": "9" * 64, "readbacks": [{"service": "stepfunctions", "operation": "describe_state_machine",
            "observed": {"stateMachineArn": scope["machine_arn"] + ("-other" if mutation == "machine" else ""), "status": "ACTIVE"}}],
        "phase_a_originals": carrier}
    b_approval = {"version": 1, "owner": owner, "purpose": "phase-b", "direction": "advance", "plan_sha256": "9" * 64,
        "inputs_sha256": "8" * 64, "checkpoint_sha256": "0" * 64 if mutation == "ancestry" else c.sha(files["checkpoint.json"]),
        "delta": {"purpose": "phase-b", "direction": "advance", "mode": "initial", "before": {}}, "drift_matrix": {},
        "readbacks": {"before": [], "after": []}}
    b_files = {"checkpoint.json": c.canonical(b_checkpoint), "approval.json": c.canonical(b_approval)}
    members = scope["members"]
    membership = {"frozen_membership_sha256": c.sha(c.canonical(members)), "members": members}
    close_raw = c.canonical({"version": 2, "kind": "close-drain", "common": {"activation_sha256": c.sha(activation)}, "fence": {},
                             "close_confirmed_at": c.utc(1000), "drain_observed_at": c.utc(1010), "members": members,
                             "frozen_membership_sha256": membership["frozen_membership_sha256"], "proofs": [], "permit": None,
                             "input_expirations": [], "fixed_deadline": c.utc(2800), "decision": None,
                             "windows": MINIMUM_WINDOWS})
    if mutation == "membership": membership["frozen_membership_sha256"] = "0" * 64
    prepared_at = c.loads(prepared["fence-prepared.json"], canonical=True)["preparation"]["admitted_at"]
    admitted = prepared_at if mutation == "admitted" else 1300
    revisions = {mode: f"arn:aws:ecs:us-east-2:111122223333:task-definition/cnesdata-prod-processor-{mode}:1"
                 for mode in ("unit", "recovery", "audit")}
    given = dict(revisions, unit=revisions["unit"][:-1] + "2") if mutation == "foreign-revision" else revisions
    built = dict(b_files, **{"approval.json": c.canonical(b_approval | {"checkpoint_sha256": c.sha(files["checkpoint.json"])})})
    evidence = ag.api_phase_b_evidence(close_raw=close_raw, prepared=prepared, published=built, admitted_at=1300, revisions=given,
                                       moments={"artifact_created_at": c.utc(1200), "job_completed_at": c.utc(1250)})
    if mutation and mutation.startswith("byte:"):
        value = c.loads(evidence, canonical=True)
        *parents, leaf = mutation.removeprefix("byte:").split(".")
        target = value
        for key in parents:
            target = target[key]
        target[leaf] = _flip(target[leaf])
        evidence = c.canonical(value)
    inputs = {"activation": activation if mutation != "activation" else b"other", "close-drain": close_raw,
              "phase-b": b_files["checkpoint.json"] if mutation == "lifecycle-phase-b" else evidence,
              "membership": c.canonical(membership)}
    window = {"close": 1000, "fixed_deadline": 2800, "input_deadline": 4000, "stage": "api",
              "admitted_at": admitted, "deadline": 1480,
              "decision": None, "preparation_deadline": 1900 if mutation != "preparation" else 1899, "sequence": 2,
              "checkpoint_sha256": c.sha(b_files["checkpoint.json"]), "windows": MINIMUM_WINDOWS, **lc.application_identity(owner)}
    request = {"abi_version": 3, "operation": "closed-ready", "repository": c.REPOSITORY, "source_sha": owner["source_sha"],
               "owner": {key: owner[key] for key in [*lc.OWNER_FIELDS, "owner_sha256"]}, "checkpoint_sha256": window["checkpoint_sha256"],
               "activation_sha256": c.sha(inputs["activation"]),
               "stage": {key: value for key, value in window.items() if key not in lc.application_identity(owner)},
               "inputs": {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in inputs.items()}}
    class Guard:
        def check(self, seconds=0): pass
    journal = ag.AdapterJournal(c.canonical(request), operation="closed-ready", owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    governance = dict(sts_args["governance"])
    if mutation == "delegation":
        governance["application_delegations"] = dict(governance["application_delegations"], fence_operator=governance["application_delegations"]["normal"])
    governance["context_kind"] = "promotion"
    governance["lifecycle_steps"] = {"phase-b-advance": {"role": "deploy", "purpose": "phase-b", "direction": "advance", "mode": "operational", "job_name": "phase-b / execute"}}
    if mutation == "two-steps":
        governance["lifecycle_steps"]["phase-b-advance-twin"] = dict(governance["lifecycle_steps"]["phase-b-advance"])
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"], "head_sha": owner["source_sha"]}
    root = f"repos/{c.REPOSITORY}"
    index = {"version": 1, "source_sha": owner["source_sha"], "run_id": owner["run_id"], "run_attempt": owner["run_attempt"],
             "step": "phase-b-advance", "owner_sha256": owner["owner_sha256"], "generation": owner["generation"], **lc.application_identity(owner),
             "files": [{"name": name, "size": len(raw), "sha256": c.sha(raw)} for name, raw in sorted(b_files.items())]}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(zipfile.ZipInfo("index.json", date_time=(2026, 1, 1, 0, 0, 0)), c.canonical(index))
    job = {"id": 77, "run_id": run["id"], "run_attempt": run["run_attempt"], "head_sha": run["head_sha"], "name": "phase-b / execute",
           "status": "completed", "conclusion": "success", "started_at": c.utc(1100), "completed_at": c.utc(1250)}
    metadata = {"id": 78, "name": "lifecycle-phase-b-advance", "digest": "sha256:" + c.sha(archive.getvalue()),
                "workflow_run": {"id": run["id"], "head_sha": run["head_sha"]}, "expired": False, "expires_at": c.utc(9000), "created_at": c.utc(1200)}
    responses = {root + "/actions/jobs/77": job, root + "/actions/artifacts/78": metadata, root + "/actions/artifacts/78/zip": archive.getvalue(),
                 root + f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100&page=1": {"jobs": [job], "total_count": 1},
                 root + f"/actions/runs/{run['id']}/artifacts?per_page=100&page=1": {
                     "artifacts": [metadata, metadata | {"id": 79}] if mutation == "two-candidates" else [metadata],
                     "total_count": 2 if mutation == "two-candidates" else 1},
                 root + f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}": run | {"event": "workflow_dispatch",
                     "repository": {"full_name": c.REPOSITORY}, "path": ".github/workflows/promote-production.yml"}}
    class API:
        def read(self, path, **kw): return responses[path]
    req = {"source_sha": owner["source_sha"], "step": "closed-ready", "application_purpose": "promotion", "caller_binding_sha256": owner["caller_binding_sha256"]}
    objects = {lr.namespace(governance | {"evidence_prefix": "cnesdata/prod/evidence/"}, req, run, "phase-b-advance") + name: raw for name, raw in b_files.items()}
    class Store:
        def get(self, bucket, key, **kw): return objects[key], None
        def call(self, *args, **kw): raise AssertionError("the keeper client never reaches STS or the fence evidence")
    keeper = ag.Keeper.__new__(ag.Keeper)
    drained = c.canonical(c.loads(close_raw, canonical=True) | {"drain_observed_at": c.utc(1011)}) if mutation == "foreign-close" else close_raw
    keeper._contexts, keeper.lease = [_journal_with(observations=[("close-drain", drained)])], SimpleNamespace(check=lambda: {"held": True})
    args = dict(aws=Store(), api=API(), governance=governance, request=req, run=run, journal=journal, keeper=keeper,
                prepared=prepared, credential_limit=3000, guard=Guard(), operation_session=sts_args["operation_session"],
                revisions=revisions, clock=lambda: 1300)
    return ag, args, sts_calls, keeper, journal


_CAPABILITY_REFUSALS = {"session-document": "except DateLessThan", "admitted": "original preparation before API stage",
                        "two-steps": "unique protected phase-b advance step",
                        "two-candidates": "unique phase-b publication in job interval"}


@pytest.mark.parametrize("mutation", [None, "activation", "preparation", "delegation", "ancestry", "machine", "membership",
                                      "session-document", "admitted", "two-steps", "two-candidates"])
def test_closed_ready_capability_checks_everything_before_sts(monkeypatch, mutation):
    ag, args, sts_calls, keeper, journal = _closed_ready_capability_case(monkeypatch, mutation)
    if mutation:
        expected = _CAPABILITY_REFUSALS.get(mutation)
        with pytest.raises(ValueError, match=expected):
            ag.closed_ready_capability(**args)
        assert sts_calls == [] and journal._failed is True and args["operation_session"].calls == []
        assert keeper.uncertainty() == [{"kind": "context-failed"}]
        return
    broker = ag.closed_ready_capability(**args)
    assert type(broker) is ag.ClosedReadyBroker and keeper._contexts[1:] == [broker]
    assert len(sts_calls) == 1 and sts_calls[0][2]["RoleSessionName"] == "promotion-fence-r1"
    assert args["operation_session"].calls == [("closed-ready", "promotion-fence-r1", journal._request["stage"])]
    assert broker.aws is args["operation_session"].client is broker.session.evidence and broker.aws is not args["aws"]
    assert keeper.uncertainty() == []


def test_closed_ready_capability_rebuilds_the_prepared_session_at_the_freeze_deadline(monkeypatch):
    """Item 3, frozen branch: min(observed_at + 180, frozen_until) resolves to frozen_until and still matches."""
    from tools.cnesdata_delivery import session_policy
    ag, args, sts_calls, keeper, journal = _closed_ready_capability_case(monkeypatch, "frozen")
    prepared = args["prepared"]
    manifest = c.loads(prepared["fence-prepared.json"], canonical=True)
    assert manifest["preparation"]["observed_at"] < 1100 < manifest["preparation"]["observed_at"] + 180
    evaluation = c.loads(prepared["fence-evaluation.json"], canonical=True)
    cases = {case["case_id"]: case for case in evaluation["cases"]}
    assert cases["freeze-expired"]["context"]["aws:CurrentTime"] == c.utc(1100)
    role = c.loads(prepared["fence-role.json"], canonical=True)
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    derived = lr.fence_policy_scope(args["governance"], role["policy"])
    at_freeze = session_policy.fence_session_policy(control_table_arn=derived["control_table_arn"],
        execution_prefix=derived["execution_prefix"], deadline=1100)
    assert evaluation["documents"]["fence_session"] == c.sha(c.canonical(at_freeze))
    broker = ag.closed_ready_capability(**args)
    assert type(broker) is ag.ClosedReadyBroker and len(sts_calls) == 1 and keeper.uncertainty() == []

def test_fence_scope_has_one_derivation_shared_by_prepare_and_capability(monkeypatch):
    """Amendment 2026-11-13 item 2: the capability recomputes the scope from the same policy with the same symbol."""
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    original, seen = lr.fence_policy_scope, []
    def spy(governance, policy):
        result = original(governance, policy)
        seen.append((c.sha(c.canonical(policy)), dict(result)))
        return result
    monkeypatch.setattr(lr, "fence_policy_scope", spy)
    ag, args, sts_calls, _, _ = _closed_ready_capability_case(monkeypatch)
    assert len(seen) == 1, "prepare derives the scope once, through the shared symbol"
    role = c.loads(args["prepared"]["fence-role.json"], canonical=True)
    assert seen[0][0] == c.sha(c.canonical(role["policy"]))
    ag.closed_ready_capability(**args)
    assert len(seen) == 2 and seen[1] == seen[0] and len(sts_calls) == 1
    derived = seen[0][1]
    assert set(derived) == {"control_table_arn", "execution_prefix", "machine_arn"}
    cases = {case["case_id"]: case["resource"] for case in c.loads(args["prepared"]["fence-evaluation.json"], canonical=True)["cases"]}
    assert cases["get-fence"] == derived["control_table_arn"] and cases["probe-own"] == derived["execution_prefix"] + "0" * 16
    assert derived["machine_arn"] == derived["execution_prefix"].replace(":execution:", ":stateMachine:")[:-1]


def test_closed_ready_capability_recusa_o_checkpoint_do_lifecycle_como_evidencia_phase_b(monkeypatch):
    """P13 decision 1: the adapter input phase-b is the product Phase B evidence, never the lifecycle checkpoint.json."""
    ag, args, sts_calls, keeper, journal = _closed_ready_capability_case(monkeypatch, "lifecycle-phase-b")
    assert journal._inputs["phase-b"] == c.canonical(c.loads(journal._inputs["phase-b"], canonical=True))
    with pytest.raises(ValueError, match="API phase-b evidence"):
        ag.closed_ready_capability(**args)
    assert sts_calls == [] and journal._failed is True


def test_closed_ready_capability_recusa_close_drain_que_nao_e_a_observacao_do_keeper(monkeypatch):
    ag, args, sts_calls, keeper, journal = _closed_ready_capability_case(monkeypatch, "foreign-close")
    with pytest.raises(ValueError, match="closed-ready close-drain is the keeper observation"):
        ag.closed_ready_capability(**args)
    assert sts_calls == [] and journal._failed is True


def test_closed_ready_capability_recusa_revisao_de_rota_fora_do_carrier_do_plano(monkeypatch):
    """A well-formed foreign task revision in phase-b is refused: revisions bind to the authenticated plan carrier."""
    ag, args, sts_calls, keeper, journal = _closed_ready_capability_case(monkeypatch, "foreign-revision")
    with pytest.raises(ValueError, match="API phase-b evidence"):
        ag.closed_ready_capability(**args)
    assert sts_calls == [] and journal._failed is True


def _phase_b_material(**changes):
    """Keeper originals for the phase-b builder over the dispatcher ClosedReady fixture (drain 760, API stage 960..1140)."""
    from types import SimpleNamespace
    from test_personal_platform_dispatcher import closed_ready_fixture
    from tools.cnesdata_delivery import application_gate as ag
    g, _, gov, _, _, close, phase, ready, _ = closed_ready_fixture()
    release, machine = gov["binding"]["release"], phase["routes"]["state_machine_arn"]

    def checkpoint(serial, version, **extra):
        return {"state": {"lineage": "original-lineage", "serial": serial, "state_sha256": c.sha(b"%d" % serial)},
                "state_object": {"status": "present", "version_id": version, "etag_sha256": "4" * 64}} | extra
    prepared = checkpoint(3, "before-version", purpose="application-prepare")
    after = checkpoint(4, "after-version", purpose="phase-b", plan_sha256="5" * 64, readbacks=[
        {"service": "stepfunctions", "operation": "describe_state_machine", "observed": {"stateMachineArn": machine, "status": "ACTIVE"}}])
    approval = {"checkpoint_sha256": c.sha(c.canonical(prepared)), "plan_sha256": "5" * 64,
                "delta": {"purpose": "phase-b", "direction": "advance", "mode": "initial", "before": {}}}
    world = SimpleNamespace(g=g, gov=gov, close=close, ready=ready, release=release, prepared=prepared, after=after,
                            approval=approval, moments={"artifact_created_at": c.utc(940), "job_completed_at": c.utc(950)},
                            admitted_at=960, revisions={mode: release[mode + "_revision"] for mode in ag.ROUTE_REVISIONS})
    for name, change in changes.items():
        change(world)
    world.arguments = {"close_raw": g.canonical(world.close), "prepared": {"checkpoint.json": c.canonical(world.prepared)},
                       "published": {"checkpoint.json": c.canonical(world.after), "approval.json": c.canonical(world.approval)},
                       "moments": world.moments, "admitted_at": world.admitted_at, "revisions": world.revisions}
    return world


PRODUCT_CLOSED_READY_ORIGIN = {
    "commit": "c7b1ece1b030073570a63f8327b7c9bb13142acb",
    "scripts/promotion/promote_ready.py": "940dbb3f889c4d846eccc523dfdc40346e78ecd838dbc626ab1ccf7695c0eae2",
    "scripts/promotion/_closed_ready.py": "c2b9e1111e297f7b84f047bc1e2e7117c07ee8a7bd3064b87f7d7bd0f658b25b",
    "scripts/promotion/_adapter_abi.py": "c485be2e93de45b2093fa74fbe6a60397b6a14067bfa917343a4a4a272748cee",
    "scripts/promotion/_stage_windows.py": "2a8ae63dccf35b32d2954384c3ada2a7c6d393113f04d7e4924fd860c75fa412"}
VENDORED_CLOSED_READY_SHA256 = "6abda86ea52acde970817ff449f41a114b0c51691e141e465b1876f0dc5b7c32"


def _product_closed_ready_fields(inputs, *, activation_sha256, windows, admitted, deadline):
    """Vendored from CnesData c7b1ece1: promote_ready.closed_ready field checks (_adapter_abi document/closed/versioned/
    close_drain_document/frozen_members, membership and binding), _stage_windows governed_windows/later_seconds and
    _closed_ready.build_closed_ready kind/close_hash/common/stage_deadline."""
    import json
    from datetime import datetime
    from test_cnesdata_stage_events import (PRODUCT_CLOSE_DRAIN_FIELDS, PRODUCT_FROZEN_MEMBER_FIELDS, PRODUCT_MEMBERSHIP_FIELDS,
                                            PRODUCT_PHASE_B_FIELDS)
    bounds = {"phase-b": (360, 720), "api": (180, 360), "static": (180, 360), "unit": (120, 360),
              "phase-c-recovery": (240, 660), "phase-c-audit": (240, 660), "final": (60, 180)}

    def canonical(value):
        return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")

    def constant(token):
        raise ValueError(f"json=noninteger value={token}")

    def document(raw, name):
        try:
            value = json.loads(raw.decode("utf-8"), parse_constant=constant, parse_float=constant)
        except ValueError as error:
            raise ValueError(f"input=encoding name={name}") from error
        if canonical(value) != raw:
            raise ValueError(f"input=canonical name={name}")
        return value

    def closed(value, fields, name):
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError(f"closed_ready=fields name={name}")
        return value

    def versioned(raw, name, fields):
        value = closed(document(raw, name), fields, name)
        if type(value["version"]) is not int or value["version"] != 1 or value["kind"] != name:
            raise ValueError(f"closed_ready=kind name={name}")
        return value

    def governed_windows(value):
        if not isinstance(value, dict) or set(value) != {"stages", "fixed_deadline_seconds"}:
            raise ValueError("windows=fields")
        stages, fixed = value["stages"], value["fixed_deadline_seconds"]
        if not isinstance(stages, dict) or set(stages) != set(bounds):
            raise ValueError("windows=stages")
        for name, (low, high) in bounds.items():
            if type(stages[name]) is not int or not low <= stages[name] <= high:
                raise ValueError(f"windows=stage stage={name} value={stages[name]} min={low} max={high}")
        if sum(stages.values()) > 1830:
            raise ValueError(f"windows=sum sum={sum(stages.values())} ceiling=1830")
        if type(fixed) is not int or fixed != sum(stages.values()) + 420:
            raise ValueError(f"windows=fixed value={fixed} expected={sum(stages.values()) + 420}")
        return value

    def close_drain_document(raw):
        value = closed(document(raw, "close-drain"), PRODUCT_CLOSE_DRAIN_FIELDS, "close-drain")
        if type(value["version"]) is not int or value["version"] != 2 or value["kind"] != "close-drain":
            raise ValueError("closed_ready=kind name=close-drain")
        if governed_windows(value["windows"]) != windows:
            raise ValueError("closed_ready=windows")
        return value

    def moment(text):
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    close = close_drain_document(inputs["close-drain"])
    phase = versioned(inputs["phase-b"], "phase-b", PRODUCT_PHASE_B_FIELDS)
    membership = closed(document(inputs["membership"], "membership"), PRODUCT_MEMBERSHIP_FIELDS, "membership")
    if not isinstance(membership["members"], list) or membership["frozen_membership_sha256"] != c.sha(canonical(membership["members"])):
        raise ValueError("closed_ready=membership_commitment")
    members = [closed(member, PRODUCT_FROZEN_MEMBER_FIELDS, "member") for member in membership["members"]]
    if (members, c.sha(canonical(members))) != (close["members"], close["frozen_membership_sha256"]):
        raise ValueError("closed_ready=membership")
    common = close["common"]
    if (phase["close_drain_sha256"] != c.sha(inputs["close-drain"]) or not isinstance(common, dict)
            or common.get("activation_sha256") != activation_sha256):
        raise ValueError("closed_ready=binding")
    if phase["close_drain_sha256"] != c.sha(canonical(close)):
        raise ValueError("closed_ready=close_hash")
    if common != phase["common"]:
        raise ValueError("closed_ready=original_exclusion")
    stages, order = close["windows"]["stages"], list(bounds)
    api, later = stages["api"], sum(stages[name] for name in order[order.index("api") + 1:])
    fixed, after = moment(close["fixed_deadline"]), moment(phase["observed_at"])
    if not (after <= admitted < deadline <= min(fixed, admitted + api) and fixed - admitted >= api + later + 420):
        raise ValueError("closed_ready=stage_deadline")
    return phase


def test_copia_vendorizada_do_closed_ready_do_produto_so_muda_junto_com_a_origem_registrada():
    """infra-ansible CI cannot import CnesData: a refresh of the vendored check updates its origin and this digest together."""
    import inspect
    assert set(PRODUCT_CLOSED_READY_ORIGIN) == {"commit", "scripts/promotion/promote_ready.py", "scripts/promotion/_closed_ready.py",
                                                "scripts/promotion/_adapter_abi.py", "scripts/promotion/_stage_windows.py"}
    assert c.sha(inspect.getsource(_product_closed_ready_fields).encode()) == VENDORED_CLOSED_READY_SHA256


def _product_inputs(world, phase_raw):
    from tools.cnesdata_delivery import application_gate as ag
    close_raw = world.arguments["close_raw"]
    return {"close-drain": close_raw, "phase-b": phase_raw, "membership": ag._frozen_membership(close_raw)}


def test_produto_recusa_o_checkpoint_do_lifecycle_que_a_base_pinava_como_phase_b():
    """The base pin (inputs["phase-b"] == B checkpoint.json) is refused by the product closed-ready field check."""
    world = _phase_b_material()
    with pytest.raises(ValueError, match="^closed_ready=fields name=phase-b$"):
        _product_closed_ready_fields(_product_inputs(world, world.arguments["published"]["checkpoint.json"]),
                                     activation_sha256=world.close["common"]["activation_sha256"], windows=WINDOWS,
                                     admitted=960, deadline=1140)


def test_bytes_phase_b_do_keeper_passam_na_checagem_de_campos_do_closed_ready_do_produto():
    from tools.cnesdata_delivery import application_gate as ag
    world = _phase_b_material()
    raw = ag.api_phase_b_evidence(**world.arguments)
    phase = _product_closed_ready_fields(_product_inputs(world, raw), activation_sha256=world.close["common"]["activation_sha256"],
                                         windows=WINDOWS, admitted=960, deadline=1140)
    assert phase["observed_at"] == c.utc(950) and phase["apply_sha256"] == c.sha(world.arguments["published"]["checkpoint.json"])
    assert phase["audit_sha256"] == c.sha(world.arguments["published"]["approval.json"])


API_179 = {"stages": WINDOWS["stages"] | {"api": 179}, "fixed_deadline_seconds": 2069}
ABSENT = object()


@pytest.mark.parametrize(("change", "windows", "reason"), [
    pytest.param({"version": 1}, WINDOWS, "^closed_ready=kind name=close-drain$", id="close-drain-v1"),
    pytest.param({"windows": ABSENT}, WINDOWS, "^closed_ready=fields name=close-drain$", id="close-drain-v2-sem-janelas"),
    pytest.param({}, MINIMUM_WINDOWS, "^closed_ready=windows$", id="janelas-diferentes-das-do-request"),
    pytest.param({"windows": API_179}, API_179, "^windows=stage stage=api value=179 min=180 max=360$", id="api-abaixo-do-minimo"),
])
def test_closed_ready_do_produto_so_aceita_close_drain_v2_com_as_janelas_governadas_do_request(change, windows, reason):
    world = _phase_b_material()
    close = {key: value for key, value in (world.close | change).items() if value is not ABSENT}
    inputs = {"close-drain": world.g.canonical(close), "phase-b": b"", "membership": b""}
    with pytest.raises(ValueError, match=reason):
        _product_closed_ready_fields(inputs, activation_sha256=close["common"]["activation_sha256"], windows=windows,
                                     admitted=960, deadline=1140)


def test_evidencia_phase_b_do_keeper_passa_no_validate_closed_ready_do_host_gate():
    """The keeper-built phase-b.json is accepted by the real host gate ClosedReady verifier, value by value."""
    from tools.cnesdata_delivery import application_gate as ag
    world = _phase_b_material()
    g, ready, close_raw = world.g, world.ready, world.arguments["close_raw"]
    raw = ag.api_phase_b_evidence(**world.arguments)
    ready["close_drain_sha256"], ready["phase_b_sha256"] = g.sha(close_raw), g.sha(raw)
    files = {"close-drain.json": close_raw, "phase-b.json": raw, "closed-ready.json": g.canonical(ready)}
    _, accepted, _ = g.validate_closed_ready(files, world.gov["binding"], 1000)
    assert g.canonical(accepted) == raw and accepted["routes"]["unit_revision"] == world.release["unit_revision"]


def test_api_phase_b_evidence_recusa_o_modo_established_antes_de_montar_qualquer_campo():
    from tools.cnesdata_delivery import application_gate as ag
    approval = c.canonical({"delta": {"purpose": "phase-b", "direction": "advance", "mode": "established"}})
    with pytest.raises(ValueError, match="^phase_b=established_mode_unsupported$"):
        ag.api_phase_b_evidence(close_raw=b"not-json", prepared={}, published={"checkpoint.json": b"", "approval.json": approval},
                                moments={}, admitted_at=0, revisions={})


@pytest.mark.parametrize("created, completed, expected", [
    (940, 950, 950), (760, 1000, 760), (900, 960, 960), (900, 961, 900), (759, 961, None), (700, 759, None)])
def test_observed_at_e_o_carimbo_autenticado_mais_recente_entre_o_drain_e_a_admissao_do_api(created, completed, expected):
    """Drain 760 and API admission 960 are both inclusive; with no B timestamp inside them the builder refuses."""
    from tools.cnesdata_delivery import application_gate as ag
    world = _phase_b_material(moments=lambda w: setattr(w, "moments", {"artifact_created_at": c.utc(created),
                                                                       "job_completed_at": c.utc(completed)}))
    if expected is None:
        with pytest.raises(ValueError, match="^phase_b=observed_at_bounds$"):
            ag.api_phase_b_evidence(**world.arguments)
        return
    assert c.loads(ag.api_phase_b_evidence(**world.arguments), canonical=True)["observed_at"] == c.utc(expected)


def _set(path, value):
    def change(world):
        target = world
        for key in path[:-1]:
            target = getattr(target, key) if type(target) is not dict else target[key]
        target[path[-1]] = value
    return change


_BUILDER_REFUSALS = {
    "mode": ({"m": _set(("approval", "delta", "mode"), "operational")}, "phase_b=mode"),
    "ancestry": ({"m": _set(("approval", "checkpoint_sha256"), "0" * 64)}, "phase_b=ancestry"),
    "plan": ({"m": _set(("approval", "plan_sha256"), "0" * 64)}, "phase_b=ancestry"),
    "purpose": ({"m": _set(("after", "purpose"), "application-prepare")}, "phase_b=ancestry"),
    "serial": ({"m": _set(("after", "state", "serial"), 3)}, "phase_b=checkpoint_not_advanced"),
    "version": ({"m": _set(("after", "state_object", "version_id"), "before-version")}, "phase_b=checkpoint_not_advanced"),
    "lineage": ({"m": _set(("after", "state", "lineage"), "other-lineage")}, "phase_b=checkpoint_not_advanced"),
    "readback-absent": ({"m": _set(("after", "readbacks"), [])}, "phase_b=state_machine_readback"),
    "readback-arn": ({"m": lambda w: w.after["readbacks"][0]["observed"].update(stateMachineArn="arn:aws:states:x")},
                     "phase_b=state_machine_readback"),
    "revisions-missing": ({"m": lambda w: w.revisions.pop("audit")}, "phase_b=revisions"),
    "revisions-form": ({"m": _set(("revisions", "unit"), "arn:aws:ecs:us-east-2:1:task-definition/x:1")}, "phase_b=revisions"),
    "initial-updates-machine": ({"m": _set(("approval", "delta", "before"),
                                           {"module.processing.aws_sfn_state_machine.processor[0]": {"definition": "{}"}})},
                                "phase_b=initial_requires_absent_state_machine"),
    "initial-before-absent": ({"m": lambda w: w.approval["delta"].pop("before")}, "phase_b=initial_requires_absent_state_machine"),
}


@pytest.mark.parametrize("case", sorted(_BUILDER_REFUSALS))
def test_api_phase_b_evidence_confere_b_checkpoint_aprovacao_e_close_drain_antes_de_devolver_bytes(case):
    from tools.cnesdata_delivery import application_gate as ag
    changes, reason = _BUILDER_REFUSALS[case]
    with pytest.raises(ValueError, match=f"^{reason}$"):
        ag.api_phase_b_evidence(**_phase_b_material(**changes).arguments)


def _flip(value):
    return value + 1 if type(value) is int else value[:-1] + ("0" if value[-1] != "0" else "1")


_DERIVED_FIELDS = [("common", "activation_sha256"), ("close_drain_sha256",), ("before", "lineage"), ("before", "serial"),
                   ("before", "state_sha256"), ("before", "object_version"), ("after", "lineage"), ("after", "serial"),
                   ("after", "state_sha256"), ("after", "object_version"), ("plan_sha256",), ("audit_sha256",),
                   ("apply_sha256",), ("routes", "mode"), ("routes", "state_machine_arn"),
                   ("routes", "unit_environment_state_machine_arn"), ("routes", "recovery_environment_state_machine_arn"),
                   ("routes", "unit_revision"), ("routes", "recovery_revision"), ("routes", "audit_revision"), ("observed_at",)]


@pytest.mark.parametrize("path", _DERIVED_FIELDS, ids=".".join)
def test_cada_campo_derivado_do_phase_b_alterado_em_um_byte_e_recusado_pela_capability(monkeypatch, path):
    ag, args, sts_calls, keeper, journal = _closed_ready_capability_case(monkeypatch, "byte:" + ".".join(path))
    with pytest.raises(ValueError, match="^API phase-b evidence$"):
        ag.closed_ready_capability(**args)
    assert sts_calls == [] and journal._failed is True


def test_arquivo_do_closure_cabe_no_teto_de_256kib():
    """N16 guard (P14-P17): every APPLICATION_CLOSURE_PATHS file stays within the application_source_closure limit."""
    from pathlib import Path
    from tools.cnesdata_delivery import lifecycle_contract as lc
    root = Path(__file__).resolve().parents[1]
    sizes = {path: len((root / path).read_bytes()) for path in lc.APPLICATION_CLOSURE_PATHS}
    assert {path: size for path, size in sizes.items() if size > 256 * 1024} == {}
    lc.application_source_closure(lambda path: (root / path).read_bytes())


@pytest.mark.parametrize("operation", ["inventory"])
def test_closed_ready_capability_rejects_every_other_operation(monkeypatch, operation):
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr
    request, owner, window, inputs = _adapter_case(operation)
    class Guard:
        def check(self, seconds=0): pass
    journal = ag.AdapterJournal(c.canonical(request), operation=operation, owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    keeper = ag.Keeper.__new__(ag.Keeper)
    keeper._contexts, keeper.lease = [], SimpleNamespace(check=lambda: {})
    with pytest.raises(ValueError, match="closed-ready only"):
        ag.closed_ready_capability(aws=None, api=None, governance={}, request={}, run={}, journal=journal, keeper=keeper,
                                   prepared=lr.PreparedFence(), credential_limit=3000, guard=Guard(), operation_session=None,
                                   revisions={})


@pytest.mark.parametrize("mutation", ["empty", "missing-one", "unknown-type", "duplicate", "unlabelled", "extra-fact",
                                      "caller-assessment", "free-callable"])
def test_keeper_terminal_proof_only_through_closed_validator_registry(mutation):
    import inspect
    from tools.cnesdata_delivery.application_gate import Keeper
    if mutation == "free-callable":
        assert "authenticate_terminal" not in inspect.signature(Keeper).parameters
        with pytest.raises(TypeError):
            Keeper(None, {"lifecycle_version": 1}, None, api=None, governance=None, authenticate_terminal=lambda *a: {})
        return
    keeper, store = _accepted_terminal_case()
    before = store.get()
    reference = _terminal_reference(keeper)
    if mutation == "empty": keeper._terminal_validators.clear()
    if mutation == "missing-one": keeper._terminal_validators.pop("quiescence")
    if mutation in {"unknown-type", "duplicate", "unlabelled"}:
        kind, label = {"unknown-type": ("assessment", "x"), "duplicate": ("unit", "x"), "unlabelled": ("unit", "")}[mutation]
        if mutation == "unlabelled": keeper._terminal_validators.pop("unit")
        with pytest.raises(ValueError, match="closed terminal validator registry"):
            keeper.register_terminal_validator(kind, lambda *a, **k: {}, label=label)
        return
    if mutation == "extra-fact":
        label, original = keeper._terminal_validators["routing"]
        keeper._terminal_validators["routing"] = (label, lambda *a, **k: original(*a, **k) | {"facts": {"fence": "OPEN", "routes_match": True, "accepted": True}})
    if mutation == "caller-assessment":
        reference["assessment"] = {"kind": "accepted-open"}
    with pytest.raises(ValueError):
        keeper.finish(reference)
    assert store.get() == before and store.get()[0]["status"] != "released"


def test_keeper_terminal_validators_receive_registered_journal_observations():
    keeper, _ = _accepted_terminal_case()
    raw = b'{"observed":true}\n'
    journal = _journal_with(observations=[("routing", raw)])
    keeper.attach(journal)
    seen = []
    label, original = keeper._terminal_validators["routing"]
    keeper._terminal_validators["routing"] = (label, lambda source, **kw: seen.append(kw["observations"]) or original(source, **kw))
    files = keeper.finish(_terminal_reference(keeper))
    assert seen == [{c.sha(raw): raw}]
    assert c.loads(files["terminal.json"], canonical=True)["promotion_status"] == "accepted"


def _routing_bytes(routes_match):
    return c.canonical({"version": 1, "kind": "routing", "fence": "OPEN", "routes_match": routes_match})


def _latest_routing_case(*journals):
    """Real routing validator over keeper journals; the other kinds keep their SYNTHETIC validators."""
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    keeper, store = _accepted_terminal_case()
    for journal in journals:
        keeper.attach(journal)
    keeper._terminal_validators["routing"] = ("real-routing", ag.routing_terminal_validator)
    record = keeper.lease.check()
    def proof(raw):
        reference = _terminal_reference(keeper)
        reference["sources"]["routing"] = {"routing": c.sha(raw)}
        return keeper._terminal_proof(reference, lc.owner_binding(record), record["lifecycle"])
    return keeper, proof


def test_terminal_proof_reads_only_the_latest_observation_of_each_kind():
    """Disposition (3d) of 6963008338: a stale, well-formed observation of the same kind is not a source."""
    older, newer = _routing_bytes(True), _routing_bytes(False)
    _, proof = _latest_routing_case(_journal_with(observations=[("routing", older), ("routing", newer)]))
    with pytest.raises(ValueError, match="terminal source role=routing"):
        proof(older)
    assert proof(newer)["assessment"]["routes_match"] is False


def test_terminal_proof_orders_journals_by_attach_and_counts_a_broker_once():
    from tools.cnesdata_delivery import application_gate as ag
    older, newer = _routing_bytes(True), _routing_bytes(False)
    first = _journal_with(observations=[("routing", older)])
    second = _journal_with(observations=[("routing", newer)])
    broker = ag.ClosedReadyBroker.__new__(ag.ClosedReadyBroker)
    broker.journal, broker._uncertainty = first, []
    _, proof = _latest_routing_case(first, second, broker)
    with pytest.raises(ValueError, match="terminal source role=routing"):
        proof(older)
    assert proof(newer)["assessment"]["routes_match"] is False


def test_terminal_proof_ignores_bytes_without_a_registered_observation():
    raw = _routing_bytes(True)
    journal = _journal_with()
    journal._observation_bytes = {c.sha(raw): raw}
    _, proof = _latest_routing_case(journal)
    with pytest.raises(ValueError, match="terminal source role=routing"):
        proof(raw)


GOVERNANCE_RELEASE = {"release_id": "synthetic-release", "source_sha": "b" * 40, "candidate_sha256": "1" * 64,
                      "canary_id": "0123456789abcdef0123456789abcdef", "binding_sha256": "2" * 64,
                      "image_digest": "sha256:" + "3" * 64}


def test_application_release_sha256_hashes_the_closed_governance_release():
    """6974253889 section 1: the opaque owner release_sha256 is sha256(canonical(closed six-field release))."""
    from tools.cnesdata_delivery import application_gate as ag
    assert ag.application_release_sha256({"release": GOVERNANCE_RELEASE}) == c.sha(c.canonical(GOVERNANCE_RELEASE))
    assert ag.application_release_sha256({"release": dict(reversed(GOVERNANCE_RELEASE.items()))}) == c.sha(c.canonical(GOVERNANCE_RELEASE))


@pytest.mark.parametrize("mutation", ["absent", "none", "list", "missing-field", "extra-field"])
def test_application_release_sha256_refuses_a_governance_without_the_closed_release(mutation):
    from tools.cnesdata_delivery import application_gate as ag
    governance = {"release": dict(GOVERNANCE_RELEASE)}
    if mutation == "absent": governance.pop("release")
    if mutation == "none": governance["release"] = None
    if mutation == "list": governance["release"] = list(GOVERNANCE_RELEASE.values())
    if mutation == "missing-field": governance["release"].pop("image_digest")
    if mutation == "extra-field": governance["release"]["note"] = "x"
    with pytest.raises(ValueError, match="^application governance release$"):
        ag.application_release_sha256(governance)


def _keeper_loop_case():
    """Real Keeper/Lease/transition chain at application-prepare; the event producer and handlers are external fakes."""
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    keeper, store = _prepare_stage_keeper()
    keeper.finish = lambda reference: pytest.fail("the stage loop never finishes the keeper")
    handled, seen, slept = [], [], []
    def advance(current, **changes):
        record = current.lease.check()["lifecycle"]
        current.lease.checkpoint(record | {"sequence": record["sequence"] + 1} | changes)
    def prepared(current, reference):
        handled.append(("prepared", reference))
        advance(current, close=1000, fixed_deadline=2800, input_deadline=4000, stage="phase-b", admitted_at=1000,
                deadline=1360, checkpoint_sha256="e" * 64)
    def phase_b(current, reference):
        handled.append(("phase-b", reference))
        advance(current, stage="api", admitted_at=1000, deadline=1180, checkpoint_sha256="f" * 64)
    def host(current, reference):
        handled.append(("host", reference))
        advance(current, stage="static", admitted_at=1010, deadline=1190)
    events = {"application-prepare": [None, {"kind": "prepared", "reference": {"fixture": "prepared"}}],
              "phase-b": [{"kind": "phase-b", "reference": {"fixture": "phase-b"}}],
              "api": [None, {"kind": "host", "reference": {"fixture": "host"}}]}
    def next_event(window):
        seen.append(window["stage"])
        if window["stage"] not in lc.STAGE_TRIGGERS:
            raise ValueError(f"stage trigger not connected stage={window['stage']}")
        return events[window["stage"]].pop(0)
    run = lambda **changes: ag.keeper_loop(keeper, **({"next_event": next_event, "handlers": {"prepared": prepared, "phase-b": phase_b, "host": host},
                                                      "sleep": slept.append} | changes))
    return ag, keeper, store, run, seen, handled, slept


def test_keeper_loop_despacha_cada_gatilho_e_para_no_estagio_static():
    ag, keeper, store, run, seen, handled, slept = _keeper_loop_case()
    with pytest.raises(ValueError, match="^stage trigger not connected stage=static$"):
        run()
    assert handled == [("prepared", {"fixture": "prepared"}), ("phase-b", {"fixture": "phase-b"}),
                       ("host", {"fixture": "host"})] and slept == [5, 5]
    assert seen == ["application-prepare", "application-prepare", "phase-b", "api", "api", "static"]
    record = store.get()[0]
    assert record["status"] == "held" and record["lifecycle"]["stage"] == "static" and keeper.uncertainty() == []


def test_keeper_loop_has_no_publish_parameter_and_returns_only_by_exception():
    import inspect
    from tools.cnesdata_delivery import application_gate as ag
    assert list(inspect.signature(ag.keeper_loop).parameters) == ["keeper", "next_event", "handlers", "poll", "sleep"]
    assert ag.KEEPER_EVENTS == ("prepared", "phase-b", "host")


@pytest.mark.parametrize("names", [(), ("prepared",), ("phase-b",), ("prepared", "phase-b"), ("prepared", "host"),
                                   ("prepared", "phase-b", "host", "closed-ready"), ("prepared", "phase-b", "host", "terminal")])
def test_keeper_loop_conecta_so_os_tres_gatilhos_de_estagio(names):
    ag, keeper, store, run, _, _, _ = _keeper_loop_case()
    with pytest.raises(ValueError, match="closed keeper handlers"):
        run(handlers={name: None for name in names}, next_event=lambda window: pytest.fail("no event before handler check"))
    assert store.get()[0]["lifecycle"]["stage"] == "application-prepare"


@pytest.mark.parametrize("event, message", [({"kind": "closed-ready", "reference": {}}, "closed keeper event"),
                                            ({"kind": "terminal", "reference": {}}, "closed keeper event"),
                                            ({"kind": "static", "reference": {}}, "closed keeper event"),
                                            ({"kind": "advance", "reference": {}}, "closed keeper event"),
                                            ({"kind": "prepared"}, "closed object fields"),
                                            ({"kind": "prepared", "reference": {}, "extra": 1}, "closed object fields")])
def test_keeper_loop_refuses_events_outside_the_stage_triggers(event, message):
    ag, keeper, store, run, _, handled, _ = _keeper_loop_case()
    with pytest.raises(ValueError, match=message):
        run(next_event=lambda window: event, handlers={"prepared": lambda *a: pytest.fail("no dispatch"),
                                                       "phase-b": lambda *a: pytest.fail("no dispatch"),
                                                       "host": lambda *a: pytest.fail("no dispatch")})
    assert store.get()[0]["status"] == "held" and handled == []


def test_keeper_loop_handler_failure_holds_the_lease_and_keeps_the_uncertainty():
    ag, keeper, store, run, _, _, _ = _keeper_loop_case()
    def failing(current, reference):
        journal = _journal_with()
        current.attach(journal)
        journal._failed = True
        raise ValueError("close-drain capability refused before STS")
    with pytest.raises(ValueError, match="capability refused"):
        run(handlers={"prepared": failing, "phase-b": failing, "host": failing})
    assert store.get()[0]["status"] == "held" and keeper.uncertainty() == [{"kind": "context-failed"}]
    assert store.get()[0]["lifecycle"]["stage"] == "application-prepare"


def test_keeper_guard_renews_lease_during_quiet_adapter_run():
    """A quiet child only gets the five-second journal.guard(); each one is a keeper tick."""
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store = _accepted_terminal_case()
    moments = iter(range(1000, 1000 + 5 * 200, 5))
    now = [1000]
    def advance():
        now[0] = next(moments)
        return now[0]
    keeper.monotonic = keeper.lease.monotonic = lambda: now[0]
    keeper.clock = keeper.lease.clock = lambda: now[0]
    guard = ag.KeeperGuard(keeper)
    before = store.get()[0]["expires_at"]
    for _ in range(120):  # 600 quiet seconds, twice the 300s TTL.
        advance()
        guard.check()
    record = store.get()[0]
    assert record["status"] == "held" and record["expires_at"] > before + 500 and record["expires_at"] > now[0] + 200
    with pytest.raises(ValueError, match="bounded guard reservation"):
        guard.check(908)


def test_run_closed_ready_admite_a_capability_e_so_entao_mede_o_tempo_do_child(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag
    ag_mod, args, sts_calls, _, journal = _closed_ready_capability_case(monkeypatch)
    keeper, _ = _accepted_terminal_case()
    order = []
    def capability(*, journal, keeper, guard):
        assert type(guard) is ag.KeeperGuard and journal._guard is guard and any(item is journal for item in keeper._contexts)
        order.append("capability")
        journal._broker = ag.ClosedReadyBroker.__new__(ag.ClosedReadyBroker)
    seen = {}
    monkeypatch.setattr(ag, "invoke_adapter", lambda **kwargs: order.append("adapter") or seen.update(kwargs) or kwargs["journal"])
    request_raw = c.canonical(journal._request)
    result = ag.run_closed_ready(keeper=keeper, request_raw=request_raw, owner=journal._request["owner"] | journal._identity,
        window=journal._request["stage"] | journal._identity, inputs=journal._inputs, activation_sha256=journal._request["activation_sha256"],
        capability=capability, product="product", source=journal._request["source_sha"], manifest={}, manifest_sha256="0" * 64,
        seconds=lambda: order.append("seconds") or 117)
    assert order == ["capability", "seconds", "adapter"] and type(result) is ag.AdapterJournal and seen["timeout"] == 117
    def refusing(*, journal, keeper, guard):
        journal._failed = True
        raise ValueError("capability refused")
    order.clear()
    with pytest.raises(ValueError, match="capability refused"):
        ag.run_closed_ready(keeper=keeper, request_raw=request_raw, owner=journal._request["owner"] | journal._identity,
            window=journal._request["stage"] | journal._identity, inputs=journal._inputs,
            activation_sha256=journal._request["activation_sha256"], capability=refusing, product="product",
            source=journal._request["source_sha"], manifest={}, manifest_sha256="0" * 64,
            seconds=lambda: pytest.fail("no capacity sample before the capability"))
    assert order == [] and {"kind": "context-failed"} in keeper.uncertainty()


@pytest.mark.parametrize("validators,events,message", [
    ({"quiescence": object()}, None, "terminal validator unavailable; lifecycle disabled"),
    ({"quiescence": object(), "routing": object(), "foreign": object()}, None, "terminal validator unavailable"),
    (None, "not-callable", "keeper event producer not connected; lifecycle disabled"),
])
def test_execute_refuses_an_incomplete_registry_or_event_source_before_any_effect(monkeypatch, validators, events, message):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr
    assert set(ag.TERMINAL_VALIDATORS) == SIX_VALIDATORS and ag.KEEPER_EVENT_SOURCE is ag.stage_event_source
    monkeypatch.setattr(lr, "AWS", lambda *a, **kw: pytest.fail("execute must refuse before AWS"))
    monkeypatch.setattr(lr, "S3LeaseStore", lambda *a, **kw: pytest.fail("execute must refuse before the lease store"))
    monkeypatch.setattr(lr, "oidc_credentials", lambda *a, **kw: pytest.fail("execute must refuse before STS"))
    monkeypatch.setattr(ag, "Keeper", lambda *a, **kw: pytest.fail("execute must refuse before the keeper"))
    monkeypatch.setattr(ag, "authenticate_adapter_closure", lambda *a: pytest.fail("enablement precedes adapter reads"))
    with pytest.raises(ValueError, match=message):
        ag.execute(({}, {"source_sha": "b" * 40}, {}, None, {}, {}), validators=validators, event_source=events)


def test_application_main_execute_hands_the_admitted_tuple_to_execute(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr, session_owner
    admitted, handed = ({}, {"source_sha": "b" * 40}, {}, None, {}, {}), []
    monkeypatch.setattr(lr, "admission", lambda role: admitted)
    monkeypatch.setattr(session_owner, "application_fragment", lambda governance, now: None)
    monkeypatch.setattr(ag, "verify_source_closure", lambda governance, api: None)
    monkeypatch.setattr(ag, "execute", lambda *args, **kwargs: handed.append((args, kwargs)))
    ag.main(["execute"])
    assert handed == [((admitted,), {})]


class _Stop(Exception):
    pass


def _execute_case(monkeypatch, *, release=True, expiration="auto", authority_ttl=5000, enabled_ttl=9000, identity=None):
    """The composition of execute over boundary fakes: every effect is a recorded call, the order is the contract."""
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr, session_owner
    from tools.cnesdata_delivery.session_owner import Authority
    now = int(time.time())
    calls = []
    caller = {"application_purpose": "promotion", "context_kind": "promotion", "repository": c.REPOSITORY, "source_sha": "b" * 40}
    governance = {"application_product_source_manifest": {"fixture": "manifest"}, "application_product_source_closure_sha256": "0" * 64,
                  "authenticated_application_caller": caller, "account_id": "111122223333"}
    if release: governance["release"] = dict(GOVERNANCE_RELEASE)
    request, run, api = {"source_sha": "b" * 40, "step": "execute"}, {"id": 4242, "run_attempt": 1}, SimpleNamespace(marker="api")
    role = "arn:aws:iam::111122223333:role/cnesdata-prod-application"
    fragment = {"application_role_arn": role, "enabled_until": c.utc(now + enabled_ttl)}
    authority = Authority({"role_arn": role, "frozen_until": c.utc(now + 9500)}, float(now + authority_ttl), None, fragment, "3" * 64)
    if expiration == "auto": monkeypatch.setenv("AWS_CREDENTIAL_EXPIRATION", c.utc(now + 7000))
    elif expiration is None: monkeypatch.delenv("AWS_CREDENTIAL_EXPIRATION", raising=False)
    else: monkeypatch.setenv("AWS_CREDENTIAL_EXPIRATION", expiration)
    def record(name, result=None):
        def spy(*args, **kwargs):
            calls.append((name, args, kwargs))
            if isinstance(result, Exception): raise result
            return result() if callable(result) else result
        return spy
    monkeypatch.setattr(ag, "authenticate_adapter_closure", record("closure"))
    monkeypatch.setattr(session_owner, "authenticate_lifecycle", record("authority", authority))
    arn = "arn:aws:sts::111122223333:assumed-role/cnesdata-prod-application/cnesdata-4242-1"
    fake_aws = SimpleNamespace(identity={"Account": "111122223333", "Arn": arn, "UserId": "AROAFIXTURE:cnesdata-4242-1"} | (identity or {}))
    monkeypatch.setattr(lr, "AWS", record("aws", fake_aws))
    monkeypatch.setattr(session_owner, "verify_application", record("readback", {"role_id": "AROAFIXTURE"}))
    monkeypatch.setattr(lr, "S3LeaseStore", record("store", "lease-store"))
    class FakeKeeper:
        def __init__(self, store, binding, previous, **kwargs):
            calls.append(("keeper", (store, binding, previous), kwargs))
            self.clock = lambda: 1000.4
        def acquire(self, **kwargs):
            calls.append(("acquire", (), kwargs))
            return {"owner": "acquired"}
    monkeypatch.setattr(ag, "Keeper", FakeKeeper)
    monkeypatch.setattr(ag, "register_terminal_validators", record("register"))
    monkeypatch.setattr(ag, "stage_handlers", record("handlers", {"prepared": "h1", "phase-b": "h2", "host": "h3"}))
    monkeypatch.setattr(ag, "keeper_loop", record("loop", _Stop("loop reached")))
    return ag, (governance, request, {}, api, run, {}), calls, SimpleNamespace(authority=authority, aws=fake_aws, now=now, api=api,
                                                                              run=run, request=request)


def test_execute_composes_the_keeper_in_the_ratified_order_and_runs_the_stage_loop(monkeypatch):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    ag, admitted, calls, world = _execute_case(monkeypatch)
    governance = admitted[0]
    factory = []
    def event_source(**kwargs):
        calls.append(("events", (), kwargs))
        return "next-event"
    validators = {"quiescence": ("synthetic-quiescence", object()), "routing": ("synthetic-routing", object())}
    with pytest.raises(_Stop, match="loop reached"):
        ag.execute(admitted, validators=validators, event_source=event_source, product="product")
    assert [name for name, _, _ in calls] == ["closure", "authority", "aws", "readback", "store", "keeper", "register", "acquire",
                                              "events", "handlers", "loop"]
    by_name = {name: (args, kwargs) for name, args, kwargs in calls}
    assert by_name["closure"][0] == ("product", "b" * 40, {"fixture": "manifest"}, "0" * 64)
    assert by_name["authority"][0][:5] == (governance, world.api, "b" * 40, "application", "application-prepare")
    assert abs(by_name["authority"][0][5] - time.time()) < 60
    assert by_name["aws"][0] == (governance,) and by_name["store"][0] == (world.aws,)
    caller = governance["authenticated_application_caller"]
    session = c.sha(c.canonical({"principal": world.aws.identity["Arn"], "run_id": 4242, "run_attempt": 1, "gate": "application"}))
    (store, binding, previous), keeper_kwargs = by_name["keeper"]
    assert store == "lease-store" and callable(previous)
    assert binding == {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 4242, "run_attempt": 1,
                       "session_sha256": session, "release_sha256": c.sha(c.canonical(GOVERNANCE_RELEASE)), "lifecycle_version": 1,
                       "application_purpose": "promotion", "context_kind": "promotion", "caller_binding_sha256": c.sha(c.canonical(caller))}
    assert keeper_kwargs == {"api": world.api, "governance": governance, "evidence_aws": world.aws}
    assert by_name["register"][0][1] is validators and by_name["acquire"][1] == {"preparation_deadline": 1000 + 900}
    events_kwargs = by_name["events"][1]
    assert set(events_kwargs) == {"api", "governance", "run", "owner", "guard", "clock"} and events_kwargs["owner"] == {"owner": "acquired"}
    assert type(events_kwargs["guard"]) is ag.KeeperGuard and events_kwargs["run"] == world.run and events_kwargs["clock"]() == 1000.4
    handler_kwargs = by_name["handlers"][1]
    assert set(handler_kwargs) == {"keeper", "aws", "api", "governance", "request", "run", "authority", "product", "credential_limit",
                                   "operation_session", "clock"}
    assert callable(handler_kwargs["operation_session"]) and handler_kwargs["operation_session"] is not world.aws
    assert handler_kwargs["authority"] is world.authority and handler_kwargs["product"] == "product"
    assert handler_kwargs["credential_limit"] == world.now + 5000 and handler_kwargs["clock"]() == 1000.4
    assert by_name["loop"][0][0] is by_name["register"][0][0] and by_name["loop"][1] == {"next_event": "next-event", "handlers": {"prepared": "h1", "phase-b": "h2", "host": "h3"}}
    assert by_name["readback"][1] == {"clock": time.time, "include_documents": True}


@pytest.mark.parametrize("authority_ttl, enabled_ttl, expiration_ttl, expected", [(5000, 9000, 7000, 5000), (9000, 4000, 7000, 4000),
                                                                                  (9000, 9500, 3000, 3000)])
def test_execute_credential_limit_is_the_earliest_of_the_session_proof_and_fragment(monkeypatch, authority_ttl, enabled_ttl,
                                                                                    expiration_ttl, expected):
    from tools.cnesdata_delivery import application_gate as ag
    ag_mod, admitted, calls, world = _execute_case(monkeypatch, authority_ttl=authority_ttl, enabled_ttl=enabled_ttl,
                                                   expiration=c.utc(int(time.time()) + expiration_ttl))
    with pytest.raises(_Stop):
        ag.execute(admitted, event_source=lambda **kwargs: "next-event", product="product")
    credential_limit = next(kwargs["credential_limit"] for name, _, kwargs in calls if name == "handlers")
    assert abs(credential_limit - (world.now + expected)) <= 2


@pytest.mark.parametrize("mutation, message", [("no-release", "application governance release"),
                                               ("no-expiration", "application credential expiration"),
                                               ("expired", "application credential expiration"),
                                               ("identity", "original bootstrap GetCallerIdentity")])
def test_execute_refuses_before_the_next_effect(monkeypatch, mutation, message):
    from tools.cnesdata_delivery import application_gate as ag
    options = {"no-release": {"release": False}, "no-expiration": {"expiration": None},
               "expired": {"expiration": c.utc(int(time.time()) - 5)}, "identity": {"identity": {"UserId": "AROAother:cnesdata-4242-1"}}}
    ag_mod, admitted, calls, world = _execute_case(monkeypatch, **options[mutation])
    with pytest.raises(ValueError, match=message):
        ag.execute(admitted, event_source=lambda **kwargs: pytest.fail("no event source before the keeper"), product="product")
    names = [name for name, _, _ in calls]
    expected = {"no-release": [], "no-expiration": ["closure", "authority"], "expired": ["closure", "authority"],
                "identity": ["closure", "authority", "aws", "readback"]}[mutation]
    assert names == expected


def test_execute_refuses_a_credential_expiring_exactly_now(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag
    with monkeypatch.context() as pinned:
        pinned.setattr(ag.time, "time", lambda: 1_800_000_000.0)
        ag_mod, admitted, calls, world = _execute_case(pinned, expiration=c.utc(1_800_000_000))
        with pytest.raises(ValueError, match="application credential expiration"):
            ag.execute(admitted, event_source=lambda **kwargs: pytest.fail("no event source before the keeper"), product="product")
    assert [name for name, _, _ in calls] == ["closure", "authority"]


def _operation_factory_case(monkeypatch, *, expiry_delta=0, identity_change=None):
    """The factory execute hands to the stage handlers, over fakes of the token endpoint, STS and AWS construction only."""
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from tools.cnesdata_delivery import lifecycle_runtime as lr, session_policy
    ag, admitted, calls, world = _execute_case(monkeypatch)
    with pytest.raises(_Stop):
        ag.execute(admitted, event_source=lambda **kwargs: "next-event", product="product")
    factory = next(kwargs["operation_session"] for name, _, kwargs in calls if name == "handlers")
    stage, seen = {"deadline": 1900}, []
    client = SimpleNamespace(identity=dict(world.aws.identity) | (identity_change or {}))
    credentials = {"AccessKeyId": "synthetic-operation-key", "Expiration": datetime.fromtimestamp(1900 + expiry_delta, timezone.utc)}
    monkeypatch.setattr(session_policy, "application_request",
                        lambda *a, **kw: seen.append(("request", a, kw)) or {"Policy": "inline-policy", "PolicyArns": []})
    monkeypatch.setattr(lr, "oidc_credentials", lambda *a, **kw: seen.append(("oidc", a, kw)) or credentials)
    monkeypatch.setattr(lr, "AWS", lambda governance, *, credentials: seen.append(("aws", governance, credentials)) or client)
    monkeypatch.setattr(lr, "export_credentials", lambda value: pytest.fail("operation credentials are never exported"))
    return factory, admitted, world, stage, seen, client, credentials


@pytest.mark.parametrize("operation", ["close-drain", "closed-ready"])
def test_operation_session_factory_mints_the_exact_delegation_in_process_and_never_exports(monkeypatch, operation):
    """R20 option C: a second web-identity exchange of the same job, 900 s, in memory, nominal to the fence role session."""
    factory, admitted, world, stage, seen, client, credentials = _operation_factory_case(monkeypatch)
    environment = dict(os.environ)
    assert factory(operation, {"session_name": "promotion-fence-r1"}, stage) is client
    assert dict(os.environ) == environment
    governance = admitted[0]
    assert [item[0] for item in seen] == ["request", "oidc", "aws"]
    assert seen[0][1:] == ((governance, "b" * 40, 4242, 1, operation),
                           {"application_purpose": "promotion", "delegations": ("fence_operator",),
                            "sessions": {"fence_operator": "promotion-fence-r1"}})
    assert seen[1][1:] == ((governance, "application", {"Policy": "inline-policy", "PolicyArns": []}, world.run), {"duration": 900})
    assert seen[2][1:] == (governance, credentials)


@pytest.mark.parametrize("operation", ["keeper", "inventory", "retire-static", "terminal", "other", "promotion", ""])
def test_operation_session_factory_serves_only_the_two_fence_operations(monkeypatch, operation):
    factory, admitted, world, stage, seen, client, credentials = _operation_factory_case(monkeypatch)
    with pytest.raises(ValueError, match="^operation session operation$"):
        factory(operation, {"session_name": "promotion-fence-r1"}, stage)
    assert seen == []


@pytest.mark.parametrize("change", [{"Account": "999900001111"}, {"UserId": "AROAother:cnesdata-4242-1"},
                                    {"Arn": "arn:aws:sts::111122223333:assumed-role/cnesdata-prod-application/cnesdata-4242-2"}])
def test_operation_session_factory_requires_the_keeper_identity(monkeypatch, change):
    """Same account, role, role id and session name as the keeper: the second exchange can only be the same job."""
    factory, admitted, world, stage, seen, client, credentials = _operation_factory_case(monkeypatch, identity_change=change)
    with pytest.raises(ValueError, match="^operation session identity$"):
        factory("close-drain", {"session_name": "promotion-fence-r1"}, stage)
    assert [item[0] for item in seen] == ["request", "oidc", "aws"]


@pytest.mark.parametrize("delta, accepted", [(0, True), (1, True), (-0.5, False), (-1, False), (-600, False)])
def test_operation_session_factory_requires_the_credential_to_outlive_the_stage_deadline(monkeypatch, delta, accepted):
    """No tolerance: the event at acquire + 0 gets Expiration == deadline and is admitted; one instant less refuses."""
    factory, admitted, world, stage, seen, client, credentials = _operation_factory_case(monkeypatch, expiry_delta=delta)
    if accepted:
        assert factory("close-drain", {"session_name": "promotion-fence-r1"}, stage) is client
        return
    with pytest.raises(ValueError, match="^operation session expiration$"):
        factory("close-drain", {"session_name": "promotion-fence-r1"}, stage)


class _PolicyEnforcedAWS:
    """Boundary fake that authorises STS AssumeRole and S3 writes with effective_iam over the documents it was minted with."""
    def __init__(self, name, identity, documents, objects, writes, backend):
        self.name, self.identity, self.documents = name, identity, documents
        self.objects, self.writes, self.backend, self.attempts = objects, writes, backend, []

    def _authorise(self, action, resource, context=None):
        from tools.cnesdata_delivery.iam_boundary import effective_iam
        self.attempts.append((action, resource))
        identity_document, *sessions = self.documents
        if not effective_iam(identity_document, sessions, action, resource, {"aws:CurrentTime": c.utc(1300)} | (context or {})):
            raise PermissionError(f"AccessDenied name={self.name} action={action}")

    def call(self, service, operation, **parameters):
        if (service, operation) == ("sts", "assume_role"):
            self._authorise("sts:AssumeRole", parameters["RoleArn"], {"sts:RoleSessionName": parameters["RoleSessionName"]})
        return self.backend(service, operation, **parameters)

    def get(self, bucket, key, *, maximum, absent=False):
        return self.objects.get(key), "etag"

    def put(self, bucket, key, raw):
        self._authorise("s3:PutObject", f"arn:aws:s3:::{bucket}/{key}")
        assert key not in self.objects
        self.objects[key] = raw
        self.writes.append((self.name, key))


def _policy_world(monkeypatch, *, real_factory=True):
    """close_drain_capability over the real operation factory and the real session policies; effective_iam is the only authority."""
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from tools.cnesdata_delivery import lifecycle_runtime as lr, session_owner, session_policy
    ag, args, sts_calls, keeper, journal, events = _close_drain_capability_case(monkeypatch)
    governance, authority = args["governance"], args["authority"]
    owner = journal._request["owner"] | journal._identity
    identity = {"Account": "111122223333", "Arn": "arn:aws:sts::111122223333:assumed-role/cnesdata-prod-application/cnesdata-4242-1",
                "UserId": "AROAFIXTURE:cnesdata-4242-1"}
    base = [session_owner.application_identity_document(governance, authority.application_fragment), authority.pin["document"]]
    objects, writes, minted = {}, [], {}
    keeper_request = session_policy.application_request(governance, owner["source_sha"], owner["run_id"], owner["run_attempt"],
                                                        "keeper", application_purpose="promotion")
    keeper_client = _PolicyEnforcedAWS("keeper", identity, base + [c.loads(keeper_request["Policy"].encode())], objects, writes,
                                       args["aws"].call)
    world = SimpleNamespace(ag=ag, args=args, sts_calls=sts_calls, keeper=keeper, journal=journal, events=events, owner=owner,
                            keeper_client=keeper_client, objects=objects, writes=writes, minted=minted, identity=identity,
                            operation_clients=[], governance=governance)
    args["aws"] = keeper_client
    backend = args["operation_session"].client.call
    if not real_factory:
        return world
    with monkeypatch.context() as inner:
        ag_, admitted, calls, execute_world = _execute_case(inner)
        with pytest.raises(_Stop):
            ag.execute(admitted, event_source=lambda **kwargs: "next-event", product="product")
        factory = next(kwargs["operation_session"] for name, _, kwargs in calls if name == "handlers")
        admitted[0].update(governance)
        admitted[1]["source_sha"] = owner["source_sha"]
        execute_world.run.update(id=owner["run_id"], run_attempt=owner["run_attempt"])
        execute_world.aws.identity.update(identity)
    def oidc(governance_, role, restriction, run, *, duration):
        assert (role, duration) == ("application", 900)
        key = f"synthetic-operation-key-{len(minted)}"
        minted[key] = restriction
        return {"AccessKeyId": key, "Expiration": datetime.fromtimestamp(1300 + 900, timezone.utc)}
    def build(governance_, *, credentials):
        client = _PolicyEnforcedAWS("operation", identity, base + [c.loads(minted[credentials["AccessKeyId"]]["Policy"].encode())],
                                    objects, writes, backend)
        world.operation_clients.append(client)
        return client
    monkeypatch.setattr(lr, "oidc_credentials", oidc)
    monkeypatch.setattr(lr, "AWS", build)
    monkeypatch.setattr(lr, "export_credentials", lambda value: pytest.fail("operation credentials are never exported"))
    args["operation_session"] = factory
    return world


def test_the_keeper_session_cannot_assume_the_fence_nor_write_the_close_drain_evidence(monkeypatch):
    """R20 and R20-b at b911e2a2: the documents the keeper session carries deny both effects the capability needs."""
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    world = _policy_world(monkeypatch, real_factory=False)
    role = c.loads(world.args["prepared"]["fence-role.json"], canonical=True)
    keys = lr.closed_ready_evidence_keys(world.governance, owner=world.journal._request["owner"], caller=world.journal._identity,
        checkpoint_sha256=world.journal._request["checkpoint_sha256"], sequence=0, operation="close-drain")
    with pytest.raises(PermissionError, match="action=sts:AssumeRole"):
        world.keeper_client.call("sts", "assume_role", RoleArn=role["role_arn"], RoleSessionName=role["session_name"],
                                 DurationSeconds=900, Policy="{}")
    with pytest.raises(PermissionError, match="action=s3:PutObject"):
        world.keeper_client.put("synthetic-evidence", keys["intent"], b"{}")
    assert world.writes == [] and world.sts_calls == []


def test_close_drain_evidence_and_fence_sts_run_under_the_real_session_policies(monkeypatch):
    """R20 and R20-b closed: the real factory request lets the operation client assume the fence and write under close-drain/;
    every S3 write there goes through that client and the keeper client is never asked."""
    from types import SimpleNamespace
    from email.utils import formatdate
    world = _policy_world(monkeypatch)
    ag, journal = world.ag, world.journal
    broker = ag.close_drain_capability(**world.args)
    (operation,) = world.operation_clients
    role = c.loads(world.args["prepared"]["fence-role.json"], canonical=True)
    assert [call[2]["RoleSessionName"] for call in world.sts_calls] == [role["session_name"]] and broker.aws is operation
    class NativeError(Exception):
        response = {"Error": {"Code": "ExecutionDoesNotExist", "Message": "never retained"}, "ResponseMetadata": {
            "RequestId": "native-error", "HTTPStatusCode": 400, "HTTPHeaders": {"date": formatdate(1300, usegmt=True)}}}
    def sdk(service, operation_name, **parameters):
        raise NativeError()
    broker.session.client = SimpleNamespace(call=sdk)
    frame = _close_drain_calls(journal._request["owner"]["owner_sha256"])["describe_execution"]
    frame["parameters"]["executionArn"] = broker.session.scope["machine_arn"].replace(":stateMachine:", ":execution:") + ":0123456789abcdef"
    reply, result = ag._adapter_message(c.canonical({"kind": "call", **frame}), journal)
    assert reply == {"kind": "sdk-error", "code": "ExecutionDoesNotExist"} and result is None
    assert [who for who, _ in world.writes] == ["operation"] * 3 and len(world.objects) == 3
    assert all("/close-drain/sdk-" in key for _, key in world.writes)
    assert world.keeper_client.attempts == [] and world.keeper.uncertainty() == []


@pytest.mark.parametrize("operation", ["closed-ready", "close-drain"])
def test_operation_session_request_of_closed_ready_is_the_application_session_the_prepared_package_evaluated(monkeypatch, operation):
    """Q2: the inline policy the factory sends is byte for byte the evaluated application_session document."""
    from tools.cnesdata_delivery import session_policy
    world = _policy_world(monkeypatch)
    role = c.loads(world.args["prepared"]["fence-role.json"], canonical=True)
    evaluation = c.loads(world.args["prepared"]["fence-evaluation.json"], canonical=True)
    world.args["operation_session"](operation, role, {"deadline": 1900})
    (restriction,) = world.minted.values()
    inline = c.loads(restriction["Policy"].encode())
    assert (c.sha(c.canonical(inline)) == evaluation["documents"]["application_session"]) is (operation == "closed-ready")
    owner = world.owner
    assert restriction == session_policy.application_request(world.governance, owner["source_sha"], owner["run_id"], owner["run_attempt"],
        operation, application_purpose="promotion", delegations=("fence_operator",), sessions={"fence_operator": role["session_name"]})


@pytest.mark.parametrize("expires, proof, enabled, seconds, accepted", [
    (2000, 3000, 3000, 0, True), (2000, 2000, 2000, 0, True), (2000, 3000, 2000, 0, True), (2000, 3000, 1999, 0, False),
    (2000, 1999, 3000, 0, False), (2000, 3000, 3000, 1000, False), (2000, 3000, 3000, 999, True)])
def test_shared_session_guard_is_bounded_by_the_proof_and_by_the_fragment_enabled_until(monkeypatch, expires, proof, enabled, seconds, accepted):
    """Nit 2 of 6981675627: the guard credentials and execute share is bounded by min(proof expiry, enabled_until)."""
    from types import SimpleNamespace
    from tools.cnesdata_delivery import application_gate as ag, session_owner
    from tools.cnesdata_delivery.session_owner import Authority
    monkeypatch.setattr(ag.time, "time", lambda: 1000.0)
    monkeypatch.setattr(session_owner, "verify_application", lambda *a, **kw: {"role_id": "AROAFIXTURE"})
    role = "arn:aws:iam::111122223333:role/cnesdata-prod-application"
    arn = "arn:aws:sts::111122223333:assumed-role/cnesdata-prod-application/cnesdata-4242-1"
    client = SimpleNamespace(identity={"Account": "111122223333", "Arn": arn, "UserId": "AROAFIXTURE:cnesdata-4242-1"})
    authority = Authority({}, float(proof), None, {"application_role_arn": role, "enabled_until": c.utc(enabled)}, "3" * 64)
    guard = ag._verify_session(client, {"account_id": "111122223333"}, authority, {"id": 4242, "run_attempt": 1}, float(expires))
    if accepted:
        guard.check(seconds)
        return
    with pytest.raises(ValueError, match="^original bootstrap credential/freeze window$"):
        guard.check(seconds)


def test_capability_e_dispatch_so_tem_os_call_sites_fechados_alcancaveis_por_main_execute():
    """Static proof: the only production path to the keeper is main -> execute(admitted); every other site is internal."""
    import ast
    from pathlib import Path
    from tools.cnesdata_delivery import application_gate as ag
    root = Path(__file__).resolve().parents[1]
    guarded = {"keeper_loop", "run_closed_ready", "closed_ready_capability", "KeeperGuard", "Keeper", "_assume_fence_session",
               "ClosedReadyBroker", "stage_event_source", "infra_expiration_bound", "close_window", "api_window",
               "close_expirations", "close_drain_capability", "register_terminal_validator", "routing_terminal_validator",
               "static_terminal_validator", "membership_terminal_validator", "quiescence_terminal_validator",
               "host_terminal_validator", "decision_terminal_validator", "publish_static_closed_ready",
               "static_session", "static_sessions", "s3_body_bytes", "s3_put_body", "s3_body_value", "static_plan",
               "validate_static_call", "stage_handlers", "static_window", "publish_closed_ready"}
    sites, gate_execute = set(), []
    for path in sorted((root / "tools").rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        relative = path.relative_to(root).as_posix()
        def visit(node, scope):
            for child in ast.iter_child_nodes(node):
                inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else scope
                if isinstance(child, ast.Call):
                    func = child.func
                    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
                    if name in guarded:
                        sites.add((relative, scope, name))
                    if relative.endswith("application_gate.py") and isinstance(func, ast.Name) and func.id == "execute":
                        gate_execute.append((scope, child))
                if isinstance(child, ast.ImportFrom) and (child.module or "").endswith("application_gate"):
                    assert not {alias.name for alias in child.names} & (guarded | {"execute"}), (relative, ast.dump(child))
                if (isinstance(child, ast.Attribute) and child.attr in guarded | {"execute", "TERMINAL_VALIDATORS", "KEEPER_EVENT_SOURCE"}
                        and isinstance(child.value, ast.Name) and child.value.id in {"application_gate", "ag"}):
                    pytest.fail(f"{relative}: application_gate.{child.attr} referenced outside the gate")
                visit(child, inner)
        visit(tree, "<module>")
    gate = "tools/cnesdata_delivery/application_gate.py"
    assert sites == {
        (gate, "run_closed_ready", "KeeperGuard"),
        (gate, "closed_ready_capability", "_assume_fence_session"),
        (gate, "closed_ready_capability", "ClosedReadyBroker"),
        (gate, "close_expirations", "infra_expiration_bound"),      # close_expirations has no production caller
        (gate, "close_drain_capability", "close_expirations"),      # close_drain_capability has no production caller
        (gate, "close_drain_capability", "_assume_fence_session"),
        (gate, "close_drain_capability", "ClosedReadyBroker"),
        (gate, "register_terminal_validators", "register_terminal_validator"),  # no production caller of the registration
        (gate, "_quiescence_validator", "quiescence_terminal_validator"),      # registry providers, built per keeper
        (gate, "validator", "KeeperGuard"),                                     # lazy host/decision validators
        (gate, "validator", "host_terminal_validator"),
        (gate, "validator", "decision_terminal_validator"),
        (gate, "execute", "Keeper"),                                            # the one production path: main -> execute
        (gate, "execute", "KeeperGuard"),
        (gate, "execute", "stage_handlers"),
        (gate, "execute", "keeper_loop"),
        (gate, "prepared", "KeeperGuard"),                                      # stage_handlers' own handlers
        (gate, "prepared", "close_expirations"),
        (gate, "prepared", "close_drain_capability"),
        (gate, "prepared", "infra_expiration_bound"),
        (gate, "prepared", "close_window"),
        (gate, "phase_b", "KeeperGuard"),
        (gate, "phase_b", "api_window"),
        (gate, "closed_ready", "run_closed_ready"),
        (gate, "capability", "closed_ready_capability"),
        (gate, "closed_ready", "publish_closed_ready"),
        (gate, "publish_closed_ready", "KeeperGuard"),
        (gate, "host", "KeeperGuard"),
        (gate, "host", "static_window"),
        ("tools/cnesdata_delivery/lifecycle_contract.py", "static_sessions", "static_session"),  # no production caller
        ("tools/cnesdata_delivery/lifecycle_contract.py", "s3_put_body", "s3_body_bytes"),  # s3_put_body has none either
        ("tools/cnesdata_delivery/lifecycle_contract.py", "_static_put", "s3_put_body"),  # only via validate_static_call
        ("tools/cnesdata_delivery/lifecycle_contract.py", "validate_static_call", "static_plan"),  # no production caller
    }, sites
    assert [scope for scope, _ in gate_execute] == ["main"]
    call = gate_execute[0][1]
    assert [arg.id for arg in call.args] == ["admitted"] and call.keywords == []
    assert set(ag.TERMINAL_VALIDATORS) == SIX_VALIDATORS and ag.KEEPER_EVENT_SOURCE is ag.stage_event_source


TERMINAL_MEMBER_IDENTITY = ("dispatch_id", "request_sha256", "generation", "initial_state", "execution_ref", "resolution")


def _synthetic_terminal_vectors(**changes):
    """SYNTHETIC labelled terminal vectors (6861676353 item 8, decision 6); not product bytes or live acceptance.

    routing and terminal-readback have no product handler (R3): their shapes are infra-defined.
    close-drain and closed-ready follow host_gate.validate_closed_ready; publication follows CnesData
    9cdd452f scripts/promotion/_api_static_records.py publication_record.
    """
    members = [
        {"dispatch_id": "0123456789abcdef", "request_sha256": "1" * 64, "generation": 1, "initial_state": "ACKNOWLEDGED",
         "execution_ref": "arn:aws:states:us-east-2:111122223333:execution:cnesdata-prod:0123456789abcdef",
         "resolution": "TERMINAL", "proof_sha256": "2" * 64, "observed_at": c.utc(990), "send_disabled_at": c.utc(980)},
        {"dispatch_id": "fedcba9876543210", "request_sha256": "3" * 64, "generation": 1, "initial_state": "NOT_SENT",
         "execution_ref": None, "resolution": "CANCEL_BEFORE_SEND", "proof_sha256": "4" * 64, "observed_at": c.utc(990),
         "send_disabled_at": c.utc(980)},
        {"dispatch_id": "ffffffffffffffff", "request_sha256": "a" * 64, "generation": 1, "initial_state": "OUTCOME_UNKNOWN",
         "execution_ref": None, "resolution": "ABSENT_PROVEN", "proof_sha256": "b" * 64, "observed_at": c.utc(990),
         "send_disabled_at": c.utc(980)}]
    close = {"version": 2, "kind": "close-drain", "common": {}, "fence": {}, "close_confirmed_at": c.utc(1000),
             "drain_observed_at": c.utc(1000), "frozen_membership_sha256": c.sha(c.canonical(members)), "members": members,
             "proofs": [], "permit": None, "fixed_deadline": c.utc(2800), "decision": None, "windows": MINIMUM_WINDOWS,
             "input_expirations": [{"kind": "envelope", "object_sha256": "5" * 64, "expires_at": c.utc(2800)}]}
    caller = {"repository": "VINIClUS/CnesData", "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1}
    common = {"repository": "VINIClUS/CnesData", "release_id": "synthetic-release", "source_sha": "b" * 40,
              "candidate_sha256": "6" * 64, "canary_id": "0123456789abcdef0123456789abcdef", "activation_sha256": "7" * 64,
              "promotion_id": "synthetic-promotion", "promotion_generation": 2, "caller": caller}
    ready = {"version": 1, "kind": "closed-ready", "common": common, "close_drain_sha256": c.sha(c.canonical(close)),
             "phase_b_sha256": "8" * 64, "fence": {}, "permit": None, "members": members, "proofs": [],
             "observed_at": c.utc(1000), "exclusion": {}, "stage": {}, "decision": None}
    vectors = {
        "close-drain": close, "closed-ready": ready,
        "routing": {"version": 1, "kind": "routing", "fence": "OPEN", "routes_match": True},
        "terminal": {"version": 1, "kind": "terminal", "members": [{k: m[k] for k in TERMINAL_MEMBER_IDENTITY} for m in members],
                     "quiescent": True, "state_clean": True, "pending": [], "unknown": [], "observed_at": c.utc(1000)},
        "publication": {"schema": "cnesdata.static-publication/v1", "plan_sha256": "9" * 64,
                        "closed_ready_sha256": c.sha(c.canonical(ready)), "uploaded": [["index.html", "v1"]],
                        "already_published": [], "invalidation_id": "SYNTHETICINVALIDATION"}}
    for name, change in changes.items():
        change(vectors[name])
    return vectors


def _journal_observations(vectors):
    raws = {name: c.canonical(value) for name, value in vectors.items()}
    return {name: c.sha(raw) for name, raw in raws.items()}, {c.sha(raw): raw for raw in raws.values()}


OBSERVATION_VALIDATORS = ("routing", "static", "membership", "quiescence")


def _observation_validator(kind, uncertainty=lambda: []):
    from tools.cnesdata_delivery import application_gate as ag
    if kind == "quiescence":
        return ag.quiescence_terminal_validator(uncertainty)
    return getattr(ag, kind + "_terminal_validator")


def _validate(kind, vectors=None, *, source=None, observations=None, validator=None, window=None):
    from tools.cnesdata_delivery import application_gate as ag
    digests, journal = _journal_observations(vectors or _synthetic_terminal_vectors())
    source = {role: digests[role] for role in ag.TERMINAL_SOURCE_ROLES[kind].split()} if source is None else source
    validator = _observation_validator(kind) if validator is None else validator
    return validator(source, owner={"owner_sha256": "a" * 64}, window=window or {"stage": "final"},
                     observations=journal if observations is None else observations), source


def test_routing_validator_reports_the_routing_journal_observation_facts():
    result, source = _validate("routing")
    assert result == {"sha256": c.sha(c.canonical(source)), "facts": {"fence": "OPEN", "routes_match": True}}
    closed = _synthetic_terminal_vectors(routing=lambda value: value.update(fence="CLOSED", routes_match=False))
    assert _validate("routing", closed)[0]["facts"] == {"fence": "CLOSED", "routes_match": False}


@pytest.mark.parametrize("mutation", ["fence-value", "routes-type", "version", "version-bool", "extra-field", "missing-field",
                                      "kind"])
def test_routing_validator_refuses_malformed_routing_observation(mutation):
    def change(value):
        if mutation == "version-bool": value["version"] = True
        if mutation == "fence-value": value["fence"] = "HALF"
        if mutation == "routes-type": value["routes_match"] = "true"
        if mutation == "version": value["version"] = 2
        if mutation == "extra-field": value["accepted"] = True
        if mutation == "missing-field": value.pop("routes_match")
        if mutation == "kind": value["kind"] = "reopen"
    with pytest.raises(ValueError):
        _validate("routing", _synthetic_terminal_vectors(routing=change))


def test_static_validator_binds_publication_to_the_closed_ready_journal_observation():
    result, source = _validate("static")
    assert set(source) == {"publication", "closed-ready"}
    assert result == {"sha256": c.sha(c.canonical(source)), "facts": {"accepted": True}}


@pytest.mark.parametrize("mutation", ["closed-ready-binding", "schema", "extra-field", "plan-digest", "ready-version",
                                      "ready-extra-field"])
def test_static_validator_refuses_unbound_or_malformed_publication(mutation):
    changes = {
        "closed-ready-binding": {"publication": lambda value: value.update(closed_ready_sha256="f" * 64)},
        "schema": {"publication": lambda value: value.update(schema="cnesdata.static-publication/v2")},
        "extra-field": {"publication": lambda value: value.update(accepted=True)},
        "plan-digest": {"publication": lambda value: value.update(plan_sha256="not-a-digest")},
        "ready-version": {"closed-ready": lambda value: value.update(version=2)},
        "ready-extra-field": {"closed-ready": lambda value: value.update(accepted=True)},
    }[mutation]
    vectors = _synthetic_terminal_vectors(**changes)
    if mutation.startswith("ready"):  # Keep the publication bound to the mutated closed-ready bytes.
        vectors["publication"]["closed_ready_sha256"] = c.sha(c.canonical(vectors["closed-ready"]))
    with pytest.raises(ValueError):
        _validate("static", vectors)


def test_membership_validator_compares_frozen_close_drain_members_with_terminal_readback():
    result, source = _validate("membership")
    assert set(source) == {"close-drain", "terminal"}
    assert result == {"sha256": c.sha(c.canonical(source)), "facts": {"resolved": True}}
    empty = _synthetic_terminal_vectors(**{"close-drain": lambda value: value.update(
        members=[], frozen_membership_sha256=c.sha(c.canonical([])))}, terminal=lambda value: value.update(members=[]))
    assert _validate("membership", empty)[0]["facts"] == {"resolved": True}


@pytest.mark.parametrize("mutation", ["omitted", "added", "rebound", "reordered", "unresolved-both"])
def test_membership_validator_reports_unresolved_or_changed_membership(mutation):
    def readback(value):
        members = value["members"]
        if mutation == "omitted": members.pop()
        if mutation == "added": members.append(dict(members[0], dispatch_id="aaaaaaaaaaaaaaaa"))
        if mutation == "rebound": members[0]["resolution"] = "ABSENT_PROVEN"
        if mutation == "reordered": members.reverse()
        if mutation == "unresolved-both": members[0]["resolution"] = "OUTCOME_UNKNOWN"
    def frozen(value):
        if mutation == "unresolved-both":
            value["members"][0]["resolution"] = "OUTCOME_UNKNOWN"
            value["frozen_membership_sha256"] = c.sha(c.canonical(value["members"]))
    vectors = _synthetic_terminal_vectors(terminal=readback, **{"close-drain": frozen})
    assert _validate("membership", vectors)[0]["facts"] == {"resolved": False}


@pytest.mark.parametrize("mutation", ["frozen-commitment", "frozen-member-field", "readback-member-field", "frozen-type",
                                      "readback-type", "close-kind", "readback-extra-field"])
def test_membership_validator_refuses_malformed_membership_bytes(mutation):
    def close(value):
        if mutation == "frozen-commitment": value["frozen_membership_sha256"] = "f" * 64
        if mutation == "frozen-member-field": value["members"][0]["extra"] = 1
        if mutation == "frozen-type": value.update(members={}, frozen_membership_sha256=c.sha(c.canonical({})))
        if mutation == "close-kind": value["kind"] = "closed-ready"
        if mutation == "frozen-member-field":
            value["frozen_membership_sha256"] = c.sha(c.canonical(value["members"]))
    def readback(value):
        if mutation == "readback-member-field": value["members"][0]["proof_sha256"] = "2" * 64
        if mutation == "readback-type": value["members"] = {}
        if mutation == "readback-extra-field": value["fence"] = "OPEN"
    with pytest.raises(ValueError):
        _validate("membership", _synthetic_terminal_vectors(terminal=readback, **{"close-drain": close}))


TERMINAL_VARIANTS = {"routing": lambda value: value.update(fence="CLOSED"),
                     "publication": lambda value: value.update(invalidation_id="OTHER"),
                     "closed-ready": lambda value: value.update(observed_at=c.utc(999)),
                     "close-drain": lambda value: value.update(drain_observed_at=c.utc(1001)),
                     "terminal": lambda value: value.update(observed_at=c.utc(999))}


@pytest.mark.parametrize("kind", ["routing", "static", "membership", "quiescence"])
@pytest.mark.parametrize("mutation", ["absent", "digest-mismatch", "cross-kind", "extra-role", "missing-role", "string",
                                      "malformed-digest", "unhashable-digest", "non-canonical", "mapping-observations"])
def test_terminal_validator_reads_only_journal_observation_bytes_of_its_own_kind(kind, mutation):
    from tools.cnesdata_delivery import application_gate as ag
    digests, journal = _journal_observations(_synthetic_terminal_vectors())
    roles = ag.TERMINAL_SOURCE_ROLES[kind].split()
    for role in roles:
        source = {name: digests[name] for name in roles}
        observations = dict(journal)
        if mutation == "absent": observations.pop(source[role])
        if mutation == "digest-mismatch":  # Valid same-kind bytes under the original digest.
            other, raws = _journal_observations(_synthetic_terminal_vectors(**{role: TERMINAL_VARIANTS[role]}))
            observations[source[role]] = raws[other[role]]
        if mutation == "cross-kind":
            source[role] = digests["closed-ready" if role != "closed-ready" else "routing"]
        if mutation == "extra-role": source["facts"] = digests["routing"]
        if mutation == "missing-role": source.pop(role)
        if mutation == "string": source = source[role]
        if mutation == "malformed-digest": source[role] = source[role].upper()
        if mutation == "unhashable-digest": source[role] = [source[role]]
        if mutation == "non-canonical":  # Same object, indented bytes, under their own digest.
            raw = json.dumps(c.loads(observations.pop(source[role]), canonical=True), indent=1).encode() + b"\n"
            source[role] = c.sha(raw)
            observations[source[role]] = raw
        if mutation == "mapping-observations": observations = types.MappingProxyType(observations)
        with pytest.raises(ValueError):
            _validate(kind, source=source, observations=observations)


def test_quiescence_validator_reports_terminal_readback_and_keeper_uncertainty():
    from tools.cnesdata_delivery import application_gate as ag
    held = []
    validator = ag.quiescence_terminal_validator(lambda: list(held))
    result, source = _validate("quiescence", validator=validator)
    assert set(source) == {"terminal"}
    assert result == {"sha256": c.sha(c.canonical(source)), "facts": {
        "quiescent": True, "state_clean": True, "pending": [], "unknown": [], "observed_at": 1000}}
    held.append({"kind": "sdk-call", "reference_sha256": "f" * 64})
    noisy = _synthetic_terminal_vectors(terminal=lambda value: value.update(
        quiescent=False, state_clean=False, pending=["intent"], unknown=["late-effect"], observed_at=c.utc(1234)))
    assert _validate("quiescence", noisy, validator=validator)[0]["facts"] == {
        "quiescent": False, "state_clean": False, "pending": ["intent"],
        "unknown": ["late-effect", {"kind": "sdk-call", "reference_sha256": "f" * 64}], "observed_at": 1234}


@pytest.mark.parametrize("mutation", ["quiescent-type", "state-clean-type", "pending-type", "unknown-type", "observed-format",
                                      "uncertainty-type", "factory-uncallable", "extra-field", "kind"])
def test_quiescence_validator_refuses_malformed_readback_or_uncertainty(mutation):
    from tools.cnesdata_delivery import application_gate as ag
    if mutation == "factory-uncallable":
        with pytest.raises(ValueError, match="keeper uncertainty source"):
            ag.quiescence_terminal_validator([])
        return
    def change(value):
        if mutation == "quiescent-type": value["quiescent"] = 1
        if mutation == "state-clean-type": value["state_clean"] = "true"
        if mutation == "pending-type": value["pending"] = {}
        if mutation == "unknown-type": value["unknown"] = None
        if mutation == "observed-format": value["observed_at"] = "1970-01-01T00:16:40+00:00"
        if mutation == "extra-field": value["fence"] = "OPEN"
        if mutation == "kind": value["kind"] = "routing"
    validator = ag.quiescence_terminal_validator((lambda: ()) if mutation == "uncertainty-type" else (lambda: []))
    with pytest.raises(ValueError):
        _validate("quiescence", _synthetic_terminal_vectors(terminal=change), validator=validator)


def _observation_terminal_case(vectors=None):
    """Real observation validators replace the SYNTHETIC ones; unit/recovery/audit/host stay SYNTHETIC labelled."""
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store = _accepted_terminal_case()
    digests, raws = _journal_observations(vectors or _synthetic_terminal_vectors())
    journal = _journal_with()
    journal._observations = [{"kind": name, "sha256": digest, "size": len(raws[digest])} for name, digest in digests.items()]
    journal._observation_bytes = raws
    keeper.attach(journal)
    reference = _terminal_reference(keeper)
    for kind in OBSERVATION_VALIDATORS:
        keeper._terminal_validators.pop(kind)
        keeper.register_terminal_validator(kind, _observation_validator(kind, keeper.uncertainty), label="observation-" + kind)
        reference["sources"][kind] = {role: digests[role] for role in ag.TERMINAL_SOURCE_ROLES[kind].split()}
    return keeper, store, reference, journal


def test_keeper_finish_accepts_through_registered_observation_validators():
    keeper, store, reference, _ = _observation_terminal_case()
    files = keeper.finish(reference)
    terminal = c.loads(files["terminal.json"], canonical=True)
    checkpoint = c.loads(files["checkpoint.json"], canonical=True)
    assert terminal["promotion_status"] == "accepted" and store.get()[0]["status"] == "released"
    assert terminal["assessment"] | {"accepted_modes": []} == {
        "kind": "accepted-open", "fence": "OPEN", "routes_match": True, "state_clean": True, "quiescent": True,
        "pending": [], "unknown": [], "observed_at": 1000, "accepted_modes": []}
    for kind in ("routing", "static", "membership", "quiescence"):
        assert checkpoint["inputs"][kind] == c.sha(c.canonical(reference["sources"][kind]))


@pytest.mark.parametrize("mutation", ["routing-closed", "routes-mismatch", "unresolved", "stale", "pending", "unattached",
                                      "foreign-publication"])
def test_keeper_finish_refuses_when_observation_validators_report_failure(mutation):
    changes = {
        "routing-closed": {"routing": lambda value: value.update(fence="CLOSED")},
        "routes-mismatch": {"routing": lambda value: value.update(routes_match=False)},
        "unresolved": {"terminal": lambda value: value["members"].pop()},
        "stale": {"terminal": lambda value: value.update(observed_at=c.utc(969))},
        "pending": {"terminal": lambda value: value.update(pending=["intent"])},
        "foreign-publication": {"publication": lambda value: value.update(closed_ready_sha256="f" * 64)},
    }.get(mutation, {})
    keeper, store, reference, journal = _observation_terminal_case(_synthetic_terminal_vectors(**changes))
    if mutation == "unattached":
        journal._observation_bytes = {}
    before = store.get()
    with pytest.raises(ValueError):
        keeper.finish(reference)
    assert store.get() == before and store.get()[0]["status"] == "held"


def _synthetic_terminal_artifacts(vectors, **changes):
    """SYNTHETIC labelled authenticated bytes: host-handoff follows host_gate.py public handoff (version 1),
    recovery-decision follows host_gate.validate_recovery_decision. Not product bytes or live acceptance."""
    artifacts = {
        "host-handoff": {"version": 1, "kind": "host-handoff", "caller": dict(vectors["closed-ready"]["common"]["caller"]),
                         "producer_sha": "c" * 40, "closed_ready_sha256": c.sha(c.canonical(vectors["closed-ready"])),
                         "original_request_sha256": "1" * 64, "status": "accepted", "response_sha256": "2" * 64,
                         "proof_sha256": "3" * 64, "receipt_sha256": "4" * 64, "witness_sha256": None,
                         "operation_id": "5" * 64, "binding_sha256": "6" * 64, "generation": 2,
                         "recovery_decision": None, "recovery_proof_sha256": None},
        "recovery-decision": {"version": 1, "operation_id": "5" * 64, "binding_sha256": "6" * 64, "generation": 2,
                              "choice_at": c.utc(1000), "choice_monotonic_ms": 5, "clock_boot_id": "synthetic-boot",
                              "fixed_deadline": c.utc(2800), "recovery_deadline": c.utc(1420), "allocated_seconds": 420,
                              "convergence_budget_seconds": 300, "finalization_budget_seconds": 60,
                              "uncertainty_budget_seconds": 60, "checkpoint_sha256": "7" * 64}}
    for name, change in changes.items():
        change(artifacts[name])
    return {name: c.canonical(value) for name, value in artifacts.items()}


RECOVERY_WINDOW = {"stage": "recovery", "fixed_deadline": 2800,
                   "decision": {"choice_at": 1000, "deadline": 1420, "checkpoint_sha256": "e" * 64}}


def _validate_artifact(kind, *, vectors=None, artifacts=None, source=None, window=None, observations=None):
    from tools.cnesdata_delivery import application_gate as ag
    vectors = vectors or _synthetic_terminal_vectors()
    artifacts = artifacts or _synthetic_terminal_artifacts(vectors)
    digests, journal = _journal_observations(vectors)
    role = {"host": "host-handoff", "decision": "recovery-decision"}[kind]
    validator = getattr(ag, kind + "_terminal_validator")(artifacts[role])
    if source is None:
        source = {name: c.sha(artifacts[name]) if name == role else digests[name] for name in ag.TERMINAL_SOURCE_ROLES[kind].split()}
    return validator(source, owner={"owner_sha256": "a" * 64}, window=window or RECOVERY_WINDOW,
                     observations=journal if observations is None else observations), source


@pytest.mark.parametrize("status,accepted", [("accepted", True), ("rolled_back", False), ("recovery_required", False)])
def test_host_validator_reports_authenticated_handoff_status_bound_to_closed_ready(status, accepted):
    vectors = _synthetic_terminal_vectors()
    artifacts = _synthetic_terminal_artifacts(vectors, **{"host-handoff": lambda value: value.update(status=status)})
    result, source = _validate_artifact("host", vectors=vectors, artifacts=artifacts)
    assert set(source) == {"host-handoff", "closed-ready"}
    assert result == {"sha256": c.sha(c.canonical(source)), "facts": {"accepted": accepted}}


@pytest.mark.parametrize("mutation", ["status", "closed-ready-binding", "caller", "extra-field", "kind", "version",
                                      "ready-common-field", "ready-version", "factory-text"])
def test_host_validator_refuses_unbound_or_malformed_handoff(mutation):
    from tools.cnesdata_delivery import application_gate as ag
    if mutation == "factory-text":
        with pytest.raises(ValueError, match="authenticated host handoff bytes"):
            ag.host_terminal_validator("{}")
        return
    def handoff(value):
        if mutation == "status": value["status"] = "unknown"
        if mutation == "closed-ready-binding": value["closed_ready_sha256"] = "f" * 64
        if mutation == "caller": value["caller"]["run_attempt"] = 2
        if mutation == "extra-field": value["accepted"] = True
        if mutation == "kind": value["kind"] = "closed-ready"
        if mutation == "version": value["version"] = 2
    ready = {"ready-common-field": lambda value: value["common"].update(extra=1),
             "ready-version": lambda value: value.update(version=2)}
    vectors = _synthetic_terminal_vectors(**{"closed-ready": ready[mutation]} if mutation in ready else {})
    artifacts = _synthetic_terminal_artifacts(vectors, **{"host-handoff": handoff})
    with pytest.raises(ValueError):
        _validate_artifact("host", vectors=vectors, artifacts=artifacts)


def test_decision_validator_binds_authenticated_recovery_decision_to_the_lease_decision():
    result, source = _validate_artifact("decision")
    assert set(source) == {"recovery-decision"}
    assert result == {"sha256": c.sha(c.canonical(source)), "facts": {}}


@pytest.mark.parametrize("mutation", ["no-decision", "choice", "deadline", "fixed", "extra-field", "version", "version-bool",
                                      "missing-field", "factory-text"])
def test_decision_validator_refuses_unbound_or_malformed_recovery_decision(mutation):
    from tools.cnesdata_delivery import application_gate as ag
    if mutation == "factory-text":
        with pytest.raises(ValueError, match="authenticated recovery decision bytes"):
            ag.decision_terminal_validator("{}")
        return
    window = copy.deepcopy(RECOVERY_WINDOW)
    if mutation == "no-decision": window["decision"] = None
    if mutation == "choice": window["decision"]["choice_at"] = 1001
    if mutation == "deadline": window["decision"]["deadline"] = 1419
    if mutation == "fixed": window["fixed_deadline"] = 2799
    def decision(value):
        if mutation == "extra-field": value["accepted"] = True
        if mutation == "version": value["version"] = 2
        if mutation == "version-bool": value["version"] = True
        if mutation == "missing-field": value.pop("clock_boot_id")
    vectors = _synthetic_terminal_vectors()
    with pytest.raises(ValueError):
        _validate_artifact("decision", artifacts=_synthetic_terminal_artifacts(vectors, **{"recovery-decision": decision}),
                           window=window)


@pytest.mark.parametrize("kind", ["host", "decision"])
@pytest.mark.parametrize("mutation", ["journal-substitution", "foreign-digest", "extra-role", "missing-role", "string"])
def test_artifact_validator_reads_artifact_roles_only_from_authenticated_bytes(kind, mutation):
    from tools.cnesdata_delivery import application_gate as ag
    vectors = _synthetic_terminal_vectors()
    artifacts = _synthetic_terminal_artifacts(vectors)
    role = {"host": "host-handoff", "decision": "recovery-decision"}[kind]
    digests, journal = _journal_observations(vectors)
    source = {name: c.sha(artifacts[name]) if name == role else digests[name] for name in ag.TERMINAL_SOURCE_ROLES[kind].split()}
    observations = dict(journal)
    if mutation == "journal-substitution":  # Original bytes in the journal, other bytes authenticated by the caller.
        observations[source[role]] = artifacts[role]
        artifacts = dict(artifacts, **{role: artifacts[role].replace(b'"generation":2', b'"generation":3')})
    if mutation == "foreign-digest": source[role] = "f" * 64
    if mutation == "extra-role": source["facts"] = digests["routing"]
    if mutation == "missing-role": source.pop(role)
    if mutation == "string": source = source[role]
    with pytest.raises(ValueError):
        _validate_artifact(kind, vectors=vectors, artifacts=artifacts, source=source, observations=observations)


def test_keeper_finish_accepts_with_authenticated_host_handoff_validator():
    from tools.cnesdata_delivery import application_gate as ag
    vectors = _synthetic_terminal_vectors()
    artifacts = _synthetic_terminal_artifacts(vectors)
    keeper, store, reference, _ = _observation_terminal_case(vectors)
    digests = _journal_observations(vectors)[0]
    keeper._terminal_validators.pop("host")
    keeper.register_terminal_validator("host", ag.host_terminal_validator(artifacts["host-handoff"]), label="artifact-host")
    reference["sources"]["host"] = {"host-handoff": c.sha(artifacts["host-handoff"]), "closed-ready": digests["closed-ready"]}
    files = keeper.finish(reference)
    assert c.loads(files["terminal.json"], canonical=True)["promotion_status"] == "accepted"
    assert c.loads(files["checkpoint.json"], canonical=True)["inputs"]["host"] == c.sha(c.canonical(reference["sources"]["host"]))


HOST_REUSABLE_SHA = "e" * 40  # SYNTHETIC: the production caller reads producer_sha from the run, never from a literal
HOST_JOB_STEPS = ("Repeat source gate before OIDC and exchange exactly three SSH frames",
                  "Publish only the closed public handoff projection",
                  "Fail only after the original recovery handoff is available")
SIX_VALIDATORS = {"routing", "static", "membership", "quiescence", "host", "decision"}
HOST_OWNER = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1}


def _zip_bytes(members, total=None):
    import io
    import zipfile
    out = io.BytesIO()
    comment = b"x" * (total - len(_zip_bytes(members))) if total else b""
    with zipfile.ZipFile(out, "w") as archive:
        for name, raw, *mode in members:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = (mode[0] << 16) if mode else 0
            archive.writestr(info, raw)
        archive.comment = comment
    return out.getvalue()


class _HostWorld:
    """SYNTHETIC GitHub run 44/1: host-gate job and cnesdata-host-handoff artifact (consumer shape of CnesData 9cdd452f)."""
    def __init__(self, mutation=None, handoff=None):
        vectors = _synthetic_terminal_vectors()
        value = c.loads(_synthetic_terminal_artifacts(vectors)["host-handoff"], canonical=True) | {"producer_sha": HOST_REUSABLE_SHA}
        value.update(handoff or {})
        self.raw = c.canonical(value)
        self.archive = _zip_bytes([("host-handoff.json", self.raw)])
        root, run_id = f"repos/{c.REPOSITORY}/actions", 44
        steps = [{"name": name, "number": number, "status": "completed", "conclusion": conclusion}
                 for number, (name, conclusion) in enumerate(zip(HOST_JOB_STEPS, ("success", "success", "skipped")), 2)]
        self.job = {"id": 77, "run_id": run_id, "run_attempt": 1, "head_sha": "b" * 40, "name": "host-gate / execute", "status": "completed",
                    "conclusion": "success", "started_at": c.utc(1100), "completed_at": c.utc(1250), "steps": steps}
        self.meta = {"id": 78, "name": "cnesdata-host-handoff-44-1", "digest": "sha256:" + c.sha(self.archive), "expired": False,
                     "workflow_run": {"id": run_id, "head_sha": "b" * 40}, "created_at": c.utc(1200)}
        self.run = {"id": run_id, "run_attempt": 1, "head_sha": "b" * 40, "referenced_workflows": [
            {"path": "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-host-deploy-gate.yml@" + HOST_REUSABLE_SHA,
             "sha": HOST_REUSABLE_SHA}]}
        self.jobs, self.total_jobs, self.artifacts, self.total_artifacts = [self.job], None, [self.meta], None
        self.reads, self.log = [], []
        self.root = root
        getattr(self, "_" + mutation.replace("-", "_"))() if mutation else None
        self.responses = {
            root + "/runs/44/attempts/1": self.run,
            root + "/runs/44/attempts/1/jobs?per_page=100&page=1": {
                "jobs": self.jobs, "total_count": len(self.jobs) if self.total_jobs is None else self.total_jobs},
            root + "/runs/44/artifacts?per_page=100&page=1": {
                "artifacts": self.artifacts, "total_count": len(self.artifacts) if self.total_artifacts is None else self.total_artifacts},
            root + "/artifacts/78/zip": self.archive}

    def read(self, path, *, raw=False, maximum=192 * 1024**2):
        self.reads.append(path)
        self.log.append(("read", path))
        assert raw is path.endswith("/zip"), "only the artifact zip is read raw"
        value = self.responses[path]
        assert not raw or len(value) <= maximum, "oversized archive must be refused by the read bound"
        return value

    def _run_attempt(self): self.run["run_attempt"] = 2
    def _run_source(self): self.run["head_sha"] = "a" * 40
    def _reusable_missing(self): self.run["referenced_workflows"] = []
    def _reusable_twice(self): self.run["referenced_workflows"] = self.run["referenced_workflows"] * 2
    def _reusable_path(self): self.run["referenced_workflows"][0]["path"] = self.run["referenced_workflows"][0]["path"][:-1] + "f"
    def _job_missing(self): self.jobs = []
    def _job_twice(self): self.jobs = [self.job, self.job | {"id": 80}]
    def _job_incomplete(self): self.total_jobs = 2
    def _job_run(self): self.job["run_id"] = 45
    def _job_attempt(self): self.job["run_attempt"] = 2
    def _job_source(self): self.job["head_sha"] = "a" * 40
    def _job_status(self): self.job["status"] = "in_progress"
    def _job_conclusion(self): self.job["conclusion"] = "cancelled"
    def _step_missing(self): self.job["steps"].pop(0)
    def _step_order(self): self.job["steps"][0]["number"] = 9
    def _step_order_gate_handoff(self): self.job["steps"][0]["number"] = self.job["steps"][1]["number"]
    def _step_order_handoff_final(self): self.job["steps"][1]["number"] = self.job["steps"][2]["number"]
    def _jobs_at_limit(self): self.jobs = [self.job | {"id": 1000 + n, "name": "other"} for n in range(99)] + [self.job]
    def _jobs_over_limit(self): self.jobs = [self.job | {"id": 1000 + n, "name": "other"} for n in range(100)] + [self.job]
    def _artifacts_at_limit(self):
        self.artifacts = [self.meta | {"id": 2000 + n, "name": "other"} for n in range(99)] + [self.meta]
    def _artifacts_over_limit(self):
        self.artifacts = [self.meta | {"id": 2000 + n, "name": "other"} for n in range(100)] + [self.meta]
    def _step_gate(self): self.job["steps"][0]["conclusion"] = "failure"
    def _step_handoff(self): self.job["steps"][1]["conclusion"] = "skipped"
    def _final_step(self): self.job["steps"][2]["conclusion"] = "failure"
    def _final_step_failed_job(self): self.job["conclusion"] = "failure"
    def _artifact_missing(self): self.artifacts = []
    def _artifact_twice(self): self.artifacts = [self.meta, self.meta | {"id": 79}]
    def _artifact_incomplete(self): self.total_artifacts = 2
    def _artifact_name(self): self.meta["name"] = "cnesdata-host-handoff-44-2"
    def _artifact_expired(self): self.meta["expired"] = True
    def _artifact_run(self): self.meta["workflow_run"]["id"] = 45
    def _artifact_source(self): self.meta["workflow_run"]["head_sha"] = "a" * 40
    def _artifact_at_job_start(self): self.meta["created_at"] = c.utc(1100)
    def _artifact_after_job(self): self.meta["created_at"] = c.utc(1251)
    def _digest(self): self.meta["digest"] = "sha256:" + "0" * 64
    def _member_name(self): self._replace([("other.json", self.raw)])
    def _member_twice(self): self._replace([("host-handoff.json", self.raw), ("extra.json", b"{}")])
    def _member_empty(self): self._replace([("host-handoff.json", b"")])
    def _member_large(self): self._replace([("host-handoff.json", self.raw + b" " * 32768)])
    def _member_regular_file(self):
        import stat
        self._replace([("host-handoff.json", self.raw, stat.S_IFREG | 0o644)])

    def _member_symlink(self):
        import stat
        self._replace([("host-handoff.json", self.raw, stat.S_IFLNK | 0o777)])

    def _member_one_byte(self): self._replace([("host-handoff.json", b"x")])

    def _member_encrypted(self):
        packed = bytearray(self.archive)
        packed[packed.index(b"PK\x01\x02") + 8] |= 1
        self.archive = bytes(packed)
        self.meta["digest"] = "sha256:" + c.sha(self.archive)

    def _artifact_at_job_end(self): self.meta["created_at"] = self.job["completed_at"]

    def _member_over_by_one(self): self._replace([("host-handoff.json", self.raw + b" " * (32769 - len(self.raw)))])
    def _member_at_limit(self): self._rewrite(pad="x" * (32768 - len(c.canonical(c.loads(self.raw, canonical=True) | {"pad": ""}))))
    def _archive_at_limit(self): self._replace([("host-handoff.json", self.raw)], total=65536)
    def _archive_over_by_one(self): self._replace([("host-handoff.json", self.raw)], total=65537)
    def _noncanonical(self): self._replace([("host-handoff.json", b'{ "kind": "host-handoff" }\n')])
    def _archive_large(self): self._replace([("host-handoff.json", self.raw), ("pad.bin", bytes(range(256)) * 300)])
    def _producer(self): self._rewrite(producer_sha="f" * 40)
    def _caller_run(self): self._rewrite(caller=dict(HOST_OWNER, run_id=45))
    def _caller_attempt(self): self._rewrite(caller=dict(HOST_OWNER, run_attempt=2))
    def _caller_source(self): self._rewrite(caller=dict(HOST_OWNER, source_sha="a" * 40))
    def _caller_repository(self): self._rewrite(caller=dict(HOST_OWNER, repository="VINIClUS/other"))

    def _replace(self, members, total=None):
        self.archive = _zip_bytes(members, total)
        self.meta["digest"] = "sha256:" + c.sha(self.archive)

    def _rewrite(self, **changes):
        self.raw = c.canonical(c.loads(self.raw, canonical=True) | changes)
        self._replace([("host-handoff.json", self.raw)])


class _NoGuard:
    def __init__(self, log=None): self.checks, self.log = [], log if log is not None else []
    def check(self, seconds=0): self.checks.append(seconds), self.log.append(("check", seconds))


def test_host_handoff_caller_authenticates_the_original_public_artifact():
    from tools.cnesdata_delivery import application_gate as ag
    world = _HostWorld()
    guard = _NoGuard(world.log)
    assert ag.authenticate_host_handoff(world, dict(HOST_OWNER), guard=guard) == world.raw
    assert world.reads[0].endswith("/runs/44/attempts/1") and world.reads[-1].endswith("/artifacts/78/zip")
    expected = []
    for path in world.reads:
        expected += [("check", 20), ("read", path), ("check", 0)]
    assert world.log == expected and len(world.reads) == 4


def test_host_handoff_caller_accepts_a_regular_file_member_with_unix_mode():
    from tools.cnesdata_delivery import application_gate as ag
    world = _HostWorld("member-regular-file")
    assert world.archive != _zip_bytes([("host-handoff.json", world.raw)])
    assert ag.authenticate_host_handoff(world, dict(HOST_OWNER), guard=_NoGuard()) == world.raw


def test_host_handoff_caller_sends_a_one_byte_member_to_the_canonical_check_not_the_size_refusal():
    from tools.cnesdata_delivery import application_gate as ag
    with pytest.raises(Exception) as refusal:
        ag.authenticate_host_handoff(_HostWorld("member-one-byte"), dict(HOST_OWNER), guard=_NoGuard())
    assert "host handoff member size" not in str(refusal.value)


@pytest.mark.parametrize("mutation", ["jobs-at-limit", "artifacts-at-limit", "member-at-limit", "archive-at-limit",
                                      "artifact-at-job-end"])
def test_host_handoff_caller_accepts_each_inventory_and_size_exactly_at_its_limit(mutation):
    from tools.cnesdata_delivery import application_gate as ag
    world = _HostWorld(mutation)
    assert {"jobs-at-limit": len(world.jobs) == 100, "artifacts-at-limit": len(world.artifacts) == 100,
            "member-at-limit": len(world.raw) == 32768, "archive-at-limit": len(world.archive) == 65536,
            "artifact-at-job-end": world.meta["created_at"] == world.job["completed_at"]}[mutation]
    assert ag.authenticate_host_handoff(world, dict(HOST_OWNER), guard=_NoGuard()) == world.raw


def test_host_handoff_caller_accepts_the_failed_job_of_a_recovery_handoff():
    from tools.cnesdata_delivery import application_gate as ag
    world = _HostWorld("final-step-failed-job", handoff={"status": "recovery_required"})
    world.job["steps"][2]["conclusion"] = "failure"
    assert ag.authenticate_host_handoff(world, dict(HOST_OWNER), guard=_NoGuard()) == world.raw


_HOST_HANDOFF_REFUSALS = {
    "run-attempt": "host handoff run", "run-source": "host handoff run", "reusable-missing": "host handoff reusable",
    "reusable-twice": "host handoff reusable", "reusable-path": "host handoff reusable",
    "job-missing": "host handoff job inventory", "job-twice": "host handoff job inventory",
    "job-incomplete": "host handoff job inventory", "job-run": "host handoff job identity",
    "job-attempt": "host handoff job identity", "job-source": "host handoff job identity",
    "jobs-over-limit": "host handoff job inventory", "artifacts-over-limit": "host handoff artifact inventory",
    "step-order-gate-handoff": "host handoff job steps", "step-order-handoff-final": "host handoff job steps",
    "member-over-by-one": "host handoff member size", "member-symlink": "host handoff member",
    "member-encrypted": "host handoff member", "archive-over-by-one": "oversized archive|host handoff digest",
    "job-status": "host handoff job identity", "job-conclusion": "host handoff job identity",
    "step-missing": "host handoff job steps", "step-order": "host handoff job steps", "step-gate": "host handoff job steps",
    "step-handoff": "host handoff job steps", "final-step": "host handoff job steps",
    "final-step-failed-job": "host handoff job steps", "artifact-missing": "host handoff artifact unique",
    "artifact-twice": "host handoff artifact unique", "artifact-incomplete": "host handoff artifact inventory",
    "artifact-name": "host handoff artifact unique", "artifact-expired": "host handoff artifact identity",
    "artifact-run": "host handoff artifact identity", "artifact-source": "host handoff artifact identity",
    "artifact-at-job-start": "host handoff artifact identity", "artifact-after-job": "host handoff artifact identity",
    "digest": "host handoff digest", "member-name": "host handoff member", "member-twice": "host handoff member",
    "member-empty": "host handoff member", "member-large": "host handoff member", "noncanonical": "noncanonical JSON bytes",
    "archive-large": "oversized archive|host handoff digest", "producer": "host handoff producer/caller",
    "caller-run": "host handoff producer/caller", "caller-attempt": "host handoff producer/caller",
    "caller-source": "host handoff producer/caller",
    "caller-repository": "host handoff producer/caller"}


@pytest.mark.parametrize("mutation", sorted(_HOST_HANDOFF_REFUSALS))
def test_host_handoff_caller_refuses_anything_but_the_original_public_artifact(mutation):
    from tools.cnesdata_delivery import application_gate as ag
    handoff = {"recovery_decision": None} if mutation != "final-step-failed-job" else {}
    world = _HostWorld(mutation, handoff=handoff)
    with pytest.raises((ValueError, AssertionError), match=_HOST_HANDOFF_REFUSALS[mutation]):
        ag.authenticate_host_handoff(world, dict(HOST_OWNER), guard=_NoGuard())


def test_register_terminal_validators_accepts_the_whole_closed_kind_set():
    from tools.cnesdata_delivery import application_gate as ag
    keeper, _ = _accepted_terminal_case()
    keeper._terminal_validators.clear()
    registry = {kind: ("label-" + kind, lambda current: (lambda source, **kw: None)) for kind in ag.TERMINAL_VALIDATOR_FACTS}
    ag.register_terminal_validators(keeper, registry)
    assert set(keeper._terminal_validators) == set(ag.TERMINAL_VALIDATOR_FACTS)


@pytest.mark.parametrize("mutation", ["keeper-type", "registry-type", "unknown-kind"])
def test_register_terminal_validators_refuses_a_foreign_keeper_registry_or_kind(mutation):
    from tools.cnesdata_delivery import application_gate as ag
    keeper, _ = _accepted_terminal_case()
    keeper._terminal_validators.clear()
    registry = {"routing": ("synthetic-routing", ag.TERMINAL_VALIDATORS["routing"][1])}
    if mutation == "keeper-type": keeper = object()
    if mutation == "registry-type": registry = list(registry)
    if mutation == "unknown-kind": registry["foreign"] = registry["routing"]
    with pytest.raises(ValueError, match="terminal validator registry"):
        ag.register_terminal_validators(keeper, registry)


def test_production_terminal_validator_registry_is_the_six_synthetic_kinds():
    from tools.cnesdata_delivery import application_gate as ag
    assert set(ag.TERMINAL_VALIDATORS) == SIX_VALIDATORS
    assert all(type(label) is str and label.startswith("synthetic-") and callable(provider)
               for label, provider in ag.TERMINAL_VALIDATORS.values())
    keeper, _ = _accepted_terminal_case()
    keeper._terminal_validators.clear()
    ag.register_terminal_validators(keeper, ag.TERMINAL_VALIDATORS)
    assert set(keeper._terminal_validators) == SIX_VALIDATORS
    assert {kind: label for kind, (label, _) in keeper._terminal_validators.items()} == {
        kind: label for kind, (label, _) in ag.TERMINAL_VALIDATORS.items()}
    with pytest.raises(ValueError, match="closed terminal validator registry"):
        ag.register_terminal_validators(keeper, ag.TERMINAL_VALIDATORS)


def test_registered_quiescence_validator_reads_the_keeper_uncertainty_at_invocation():
    from tools.cnesdata_delivery import application_gate as ag
    keeper, _ = _accepted_terminal_case()
    keeper._terminal_validators.clear()
    ag.register_terminal_validators(keeper, ag.TERMINAL_VALIDATORS)
    vectors = _synthetic_terminal_vectors()
    digests, observations = _journal_observations(vectors)
    journal = _journal_with(observations=[("terminal", c.canonical(vectors["terminal"]))])
    keeper.attach(journal)
    validator = keeper._terminal_validators["quiescence"][1]
    source = {"terminal": digests["terminal"]}
    assert validator(source, owner={}, window={}, observations=observations)["facts"]["unknown"] == []
    journal._unknown.append({"kind": "late"})
    assert validator(source, owner={}, window={}, observations=observations)["facts"]["unknown"] == [{"kind": "late"}]


def _lazy_case(monkeypatch, *, mutation=None, handoff=None):
    from tools.cnesdata_delivery import application_gate as ag
    vectors = _synthetic_terminal_vectors()
    world = _HostWorld(mutation, handoff=handoff)
    keeper, _ = _accepted_terminal_case()
    keeper.api = world
    keeper._terminal_validators.clear()
    ag.register_terminal_validators(keeper, ag.TERMINAL_VALIDATORS)
    order = []
    for name in ("host_terminal_validator", "decision_terminal_validator"):
        original = getattr(ag, name)
        monkeypatch.setattr(ag, name, lambda raw, _original=original, _name=name: order.append((_name, raw)) or _original(raw))
    return ag, vectors, world, keeper, order


def test_registered_host_validator_authenticates_the_handoff_before_building_the_factory(monkeypatch):
    ag, vectors, world, keeper, order = _lazy_case(monkeypatch)
    assert world.reads == [] and order == []  # Registration never reads the host run.
    digests, observations = _journal_observations(vectors)
    source = {"host-handoff": c.sha(world.raw), "closed-ready": digests["closed-ready"]}
    original = world.read
    world.read = lambda path, **kw: order.append(("read", path)) or original(path, **kw)
    result = keeper._terminal_validators["host"][1](source, owner=dict(HOST_OWNER), window={"stage": "final"}, observations=observations)
    assert result["facts"] == {"accepted": True}
    kinds = [item[0] for item in order]
    assert kinds[-1] == "host_terminal_validator" and set(kinds[:-1]) == {"read"} and len(kinds) == len(world.reads) + 1
    assert order[-1][1] == world.raw


def test_registered_host_validator_never_builds_the_factory_for_an_unauthenticated_handoff(monkeypatch):
    ag, vectors, world, keeper, order = _lazy_case(monkeypatch, mutation="digest")
    digests, observations = _journal_observations(vectors)
    source = {"host-handoff": c.sha(world.raw), "closed-ready": digests["closed-ready"]}
    with pytest.raises(ValueError, match="host handoff digest"):
        keeper._terminal_validators["host"][1](source, owner=dict(HOST_OWNER), window={"stage": "final"}, observations=observations)
    assert order == []


def test_registered_host_validator_refuses_a_source_that_is_not_the_authenticated_bytes(monkeypatch):
    ag, vectors, world, keeper, order = _lazy_case(monkeypatch)
    digests, observations = _journal_observations(vectors)
    source = {"host-handoff": "f" * 64, "closed-ready": digests["closed-ready"]}
    with pytest.raises(ValueError, match="terminal source role=host-handoff"):
        keeper._terminal_validators["host"][1](source, owner=dict(HOST_OWNER), window={"stage": "final"}, observations=observations)


def test_registered_decision_validator_binds_the_canonical_recovery_decision_of_the_handoff(monkeypatch):
    vectors = _synthetic_terminal_vectors()
    decision = c.loads(_synthetic_terminal_artifacts(vectors)["recovery-decision"], canonical=True)
    ag, vectors, world, keeper, order = _lazy_case(monkeypatch, handoff={"status": "recovery_required", "recovery_decision": decision})
    window = copy.deepcopy(RECOVERY_WINDOW)
    source = {"recovery-decision": c.sha(c.canonical(decision))}
    result = keeper._terminal_validators["decision"][1](source, owner=dict(HOST_OWNER), window=window, observations={})
    assert result == {"sha256": c.sha(c.canonical(source)), "facts": {}}
    assert order == [("decision_terminal_validator", c.canonical(decision))]
    source = {"recovery-decision": "f" * 64}
    with pytest.raises(ValueError, match="terminal source role=recovery-decision"):
        keeper._terminal_validators["decision"][1](source, owner=dict(HOST_OWNER), window=window, observations={})


def test_registered_decision_validator_refuses_a_handoff_without_a_recovery_decision(monkeypatch):
    ag, vectors, world, keeper, order = _lazy_case(monkeypatch)
    with pytest.raises(ValueError, match="host handoff recovery decision"):
        keeper._terminal_validators["decision"][1]({"recovery-decision": "f" * 64}, owner=dict(HOST_OWNER),
                                                   window=copy.deepcopy(RECOVERY_WINDOW), observations={})
    assert order == []


def _recovery_terminal_case(vectors, artifacts):
    """failed-closed-quiescent through the real decision/routing/membership/quiescence validators; SYNTHETIC restoration."""
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store, reference, _ = _observation_terminal_case(vectors)
    window = store.get()[0]["lifecycle"]
    keeper.lease.checkpoint(window | {"sequence": window["sequence"] + 1, "stage": "recovery", "deadline": 1300,
                                      "decision": {"choice_at": 1000, "deadline": 1420, "checkpoint_sha256": window["checkpoint_sha256"]}})
    proof = keeper._synthetic_terminal_proof
    proof["assessment"].update(kind="failed-closed-quiescent", fence="CLOSED", accepted_modes=[],
                               restoration={k: True for k in ("unit", "recovery", "audit", "api", "static", "first_static_absent")})
    proof["inputs"] = {name: "e" * 64 for name in ("decision", "restoration", "routing", "membership", "quiescence")}
    keeper._terminal_validators.pop("decision")
    keeper.register_terminal_validator("decision", ag.decision_terminal_validator(artifacts["recovery-decision"]),
                                       label="artifact-decision")
    sources = {kind: reference["sources"][kind] for kind in ("routing", "membership", "quiescence")}
    sources |= {"restoration": "synthetic-restoration", "decision": {"recovery-decision": c.sha(artifacts["recovery-decision"])}}
    return keeper, store, {"kind": "failed-closed-quiescent", "checkpoint_raw": reference["checkpoint_raw"], "sources": sources}


@pytest.mark.parametrize("mutation", [None, "foreign-decision", "routing-open"])
def test_keeper_finish_records_recovery_failure_through_the_decision_validator(mutation):
    vectors = _synthetic_terminal_vectors(routing=lambda value: value.update(fence="OPEN" if mutation == "routing-open" else "CLOSED"))
    artifacts = _synthetic_terminal_artifacts(vectors, **{"recovery-decision": lambda value: value.update(
        choice_at=c.utc(1001) if mutation == "foreign-decision" else value["choice_at"])})
    keeper, store, reference = _recovery_terminal_case(vectors, artifacts)
    if mutation is None:
        terminal = c.loads(keeper.finish(reference)["terminal.json"], canonical=True)
        assert terminal["promotion_status"] == "failed" and store.get()[0]["status"] == "released"
        return
    with pytest.raises(ValueError):
        keeper.finish(reference)
    assert store.get()[0]["status"] == "held"


def test_artifact_roles_never_fall_back_to_journal_bytes():
    from tools.cnesdata_delivery import application_gate as ag
    vectors = _synthetic_terminal_vectors()
    artifacts = _synthetic_terminal_artifacts(vectors)
    digests, journal = _journal_observations(vectors)
    observations = dict(journal, **{c.sha(raw): raw for raw in artifacts.values()})
    for kind, role in (("host", "host-handoff"), ("decision", "recovery-decision")):
        source = {name: c.sha(artifacts[name]) if name == role else digests[name] for name in ag.TERMINAL_SOURCE_ROLES[kind].split()}
        with pytest.raises(ValueError, match="terminal source role=" + role):
            ag._terminal_sources(kind, source, observations)


def test_membership_validator_refuses_readback_larger_than_the_journal_observation_bound():
    def grow(value):  # Valid members only; the canonical readback exceeds 1 MiB.
        extra = [{"dispatch_id": f"{index:016x}", "request_sha256": "c" * 64, "generation": 1, "initial_state": "NOT_SENT",
                  "execution_ref": None, "resolution": "CANCEL_BEFORE_SEND", "proof_sha256": "d" * 64,
                  "observed_at": c.utc(990), "send_disabled_at": c.utc(980)} for index in range(5000)]
        value["members"].extend(extra)
        value["frozen_membership_sha256"] = c.sha(c.canonical(value["members"], limit=4 * 1024**2))
    vectors = _synthetic_terminal_vectors(**{"close-drain": grow})
    vectors["terminal"]["members"] = [{k: m[k] for k in TERMINAL_MEMBER_IDENTITY} for m in vectors["close-drain"]["members"]]
    raws = {name: c.canonical(value, limit=4 * 1024**2) for name, value in vectors.items()}
    assert len(raws["close-drain"]) > 1024**2
    observations = {c.sha(raw): raw for raw in raws.values()}
    source = {"close-drain": c.sha(raws["close-drain"]), "terminal": c.sha(raws["terminal"])}
    with pytest.raises(ValueError, match="JSON size"):
        _validate("membership", source=source, observations=observations)


@pytest.mark.parametrize("fence", ["HALF", "AJAR", "open", ""])
def test_routing_validator_refuses_fence_outside_the_closed_set(fence):
    with pytest.raises(ValueError, match="terminal routing facts"):
        _validate("routing", _synthetic_terminal_vectors(routing=lambda value: value.update(fence=fence)))


@pytest.mark.parametrize("resolution", ["OUTCOME_UNKNOWN", "PENDING", "terminal"])
def test_membership_validator_reports_resolution_outside_the_closed_set_as_unresolved(resolution):
    def both(value):
        value["members"][0]["resolution"] = resolution
        if "frozen_membership_sha256" in value:
            value["frozen_membership_sha256"] = c.sha(c.canonical(value["members"]))
    vectors = _synthetic_terminal_vectors(terminal=both, **{"close-drain": both})
    assert _validate("membership", vectors)[0]["facts"] == {"resolved": False}


@pytest.mark.parametrize("status", ["unknown", "x", "ACCEPTED"])
def test_host_validator_refuses_status_outside_the_closed_set(status):
    vectors = _synthetic_terminal_vectors()
    artifacts = _synthetic_terminal_artifacts(vectors, **{"host-handoff": lambda value: value.update(status=status)})
    with pytest.raises(ValueError, match="terminal host handoff binding"):
        _validate_artifact("host", vectors=vectors, artifacts=artifacts)


@pytest.mark.parametrize("mutation", ["final-generation-bool", "frozen-generation-bool", "generation-text", "dispatch-int",
                                      "request-null", "initial-list", "execution-int", "resolution-list",
                                      "final-resolution-list"])
def test_membership_validator_refuses_identity_fields_of_the_wrong_type(mutation):
    field, value, where = {
        "final-generation-bool": ("generation", True, "final"), "frozen-generation-bool": ("generation", True, "frozen"),
        "generation-text": ("generation", "1", "both"), "dispatch-int": ("dispatch_id", 1, "both"),
        "request-null": ("request_sha256", None, "both"), "initial-list": ("initial_state", ["NOT_SENT"], "both"),
        "execution-int": ("execution_ref", 1, "both"), "resolution-list": ("resolution", ["TERMINAL"], "both"),
        "final-resolution-list": ("resolution", ["TERMINAL"], "final"),
    }[mutation]
    def frozen(close):
        if where in {"frozen", "both"}:
            close["members"][0][field] = value
            close["frozen_membership_sha256"] = c.sha(c.canonical(close["members"]))
    def final(readback):
        if where in {"final", "both"}:
            readback["members"][0][field] = value
    with pytest.raises(ValueError, match="terminal member identity types"):
        _validate("membership", _synthetic_terminal_vectors(terminal=final, **{"close-drain": frozen}))


@pytest.mark.parametrize("change", [
    {"uploaded": []}, {"already_published": ["assets/app.js"]}, {"invalidation_id": None},
    {"uploaded": [["index.html", "v1"], ["assets/app.js", "v2"]]}])
def test_static_validator_accepts_the_product_publication_shapes(change):
    vectors = _synthetic_terminal_vectors(publication=lambda value: value.update(change))
    assert _validate("static", vectors)[0]["facts"] == {"accepted": True}


@pytest.mark.parametrize("change", [
    {"uploaded": {}}, {"uploaded": ["index.html"]}, {"uploaded": ["v1"]}, {"uploaded": [{"key": "index.html", "version": "v1"}]},
    {"uploaded": [["index.html"]]}, {"uploaded": [["index.html", 1]]},
    {"uploaded": [["index.html", "v1", "extra"]]}, {"already_published": "index.html"}, {"already_published": [1]},
    {"invalidation_id": 7}, {"invalidation_id": ["SYNTHETICINVALIDATION"]}])
def test_static_validator_refuses_publication_fields_of_the_wrong_type(change):
    vectors = _synthetic_terminal_vectors(publication=lambda value: value.update(change))
    with pytest.raises(ValueError, match="terminal static publication types"):
        _validate("static", vectors)


# Second slice PR-E (amendment 6886977054 decision 5 and queue items 3e/3f): static stage ABI.
def _static_binding(**changes):
    from fixtures.cnesdata_delivery_lifecycle import STATIC_SESSION_VECTOR
    return copy.deepcopy(STATIC_SESSION_VECTOR["binding"]) | changes


def test_retire_static_abi_row_is_decision_5_with_no_admitted_stage_r16():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert lc.ADAPTER_INPUTS["retire-static"] == "static-plan inventory publication routing"
    assert lc.ADAPTER_STAGES["retire-static"] == set()
    assert lc.ADAPTER_OBSERVATIONS["retire-static"] == "retirement"
    assert set(lc.ADAPTER_INPUTS) == set(lc.ADAPTER_STAGES) == set(lc.ADAPTER_OBSERVATIONS)


@pytest.mark.parametrize("stage", ["application-prepare", "phase-b", "api", "static", "unit", "phase-c-recovery",
                                   "phase-c-audit", "final", "recovery"])
def test_retire_static_request_refuses_every_stage_r16(stage):
    """6963763481 decision 1: in this slice retire-static is admitted in no stage, not even final."""
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.application_gate import AdapterJournal
    request, owner, window, inputs = _adapter_case("retire-static")
    window["stage"] = request["stage"]["stage"] = stage
    with pytest.raises(ValueError, match="adapter original stage"):
        lc.validate_adapter_request(c.canonical(request), operation="retire-static", owner=owner, window=window,
                                    inputs=inputs, activation_sha256=request["activation_sha256"])
    with pytest.raises(ValueError, match="adapter original stage"):
        AdapterJournal(c.canonical(request), operation="retire-static", owner=owner, window=window, inputs=inputs,
                       activation_sha256=request["activation_sha256"], guard=_QuietGuard())


@pytest.mark.parametrize("kind", ["retirement", "publication", "routing", "terminal"])
def test_retire_static_result_takes_only_the_retirement_observation(kind):
    """No stage admits retire-static (R16), so no journal exists; the result codec still closes the observation."""
    from tools.cnesdata_delivery import lifecycle_contract as lc
    request = _adapter_case("retire-static")[0]
    raw = c.canonical({"fixture_only": "retirement"})
    observations = [{"kind": kind, "sha256": c.sha(raw), "size": len(raw)}]
    result = {"abi_version": 3, "operation": "retire-static", "owner_sha256": request["owner"]["owner_sha256"],
              "generation": request["owner"]["generation"], "checkpoint_sha256": request["checkpoint_sha256"],
              "observations": observations, "call_receipts_sha256": c.sha(c.canonical([])), "pending": [], "unknown": []}
    args = {"request": request, "observations": observations, "call_receipts": [], "pending": [], "unknown": []}
    if kind == "retirement":
        assert lc.validate_adapter_result(c.canonical(result), **args) == result
    else:
        with pytest.raises(ValueError, match="adapter operation observation"):
            lc.validate_adapter_result(c.canonical(result), **args)


def test_static_session_names_equal_the_498_tofu_vector():
    from pathlib import Path
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from fixtures.cnesdata_delivery_lifecycle import STATIC_PROMOTION_SOURCE_SHA256, STATIC_SESSION_VECTOR as vector
    source = Path(__file__).resolve().parent / "fixtures/cnesdata_delivery_sources/infra/opentofu/modules/runtime-iam/static-promotion.tf"
    assert c.sha(source.read_bytes()) == STATIC_PROMOTION_SOURCE_SHA256
    binding = _static_binding()
    assert lc.static_session(binding, "inventory") == vector["sessions"]["observer"][0]
    assert [lc.static_session(binding, operation) for operation in ("publish", "retire")] == vector["sessions"]["normal"]
    assert lc.static_session(_static_binding(static_plan_sha256=None), "inventory") == vector["sessions"]["observer"][0]
    assert lc.static_session(_static_binding(static_plan_sha256="d" * 64), "inventory") == vector["sessions"]["observer"][0]
    assert lc.static_session(_static_binding(static_plan_sha256="d" * 64), "retire") != vector["sessions"]["normal"][1]
    assert binding == _static_binding()


def test_static_sessions_admit_the_observer_in_static_and_retire_only_as_normal():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.session_policy import application_request
    from fixtures.cnesdata_delivery_lifecycle import STATIC_SESSION_VECTOR as vector
    observer, (publish, retire) = vector["sessions"]["observer"][0], vector["sessions"]["normal"]
    sessions = {operation: lc.static_sessions(_static_binding(), operation)
                for operation in ("inventory", "publish-static", "retire-static")}
    assert sessions == {"inventory": {"observer": observer}, "publish-static": {"normal": publish, "observer": observer},
                        "retire-static": {"normal": retire}}
    roles = {alias: "arn:aws:iam::111122223333:role/cnesdata-prod-" + suffix for alias, suffix in lc.APPLICATION_DELEGATIONS.items()}
    governance = {"account_id": "111122223333", "state_bucket": "synthetic-state", "evidence_bucket": "synthetic-evidence",
                  "evidence_prefix": "cnesdata/prod/evidence/", "application_delegations": roles,
                  "evidence_kms_key_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000002",
                  "roles": {"application": "arn:aws:iam::111122223333:role/cnesdata-prod-application"}}
    for operation, chosen in sessions.items():
        request = application_request(governance, "b" * 40, 44, 1, operation, application_purpose="promotion",
                                      delegations=sorted(chosen), sessions=chosen)
        statements = json.loads(request["Policy"])["Statement"]
        assert {(statement["Resource"], statement["Condition"]["StringNotEquals"]["sts:RoleSessionName"]) for statement in statements
                if "StringNotEquals" in statement.get("Condition", {})} == {(roles[alias], name) for alias, name in chosen.items()}
    for operation in ("rollback-api-static", "closed-ready", "close-drain", "reopen", "terminal-readback", "publish"):
        with pytest.raises(ValueError, match="closed static session operation"):
            lc.static_sessions(_static_binding(), operation)


@pytest.mark.parametrize("operation", ["inventory", "publish", "retire"])
@pytest.mark.parametrize("mutation", [
    "extra-field", "missing-field", "release-upper", "release-long", "release-hyphen-end", "run-zero", "run-bool", "run-string",
    "attempt-zero", "generation-zero", "product-short", "shared-upper", "plan-short", "plan-null", "operation",
    "release-hyphen-start", "release-int", "run-over-int53"])
def test_static_session_refuses_bindings_outside_the_498_contract(operation, mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    binding = _static_binding()
    changes = {"release-upper": {"release_id": "R0123"}, "release-long": {"release_id": "r" * 33},
               "release-hyphen-end": {"release_id": "r0123-"}, "run-zero": {"run_id": 0}, "run-bool": {"run_id": True},
               "run-string": {"run_id": "42448000000"}, "attempt-zero": {"run_attempt": 0}, "generation-zero": {"generation": 0},
               "product-short": {"product_source_sha": "a" * 39}, "shared-upper": {"shared_source_sha": "B" * 40},
               "plan-short": {"static_plan_sha256": "c" * 63}, "plan-null": {"static_plan_sha256": None},
               "release-hyphen-start": {"release_id": "-r0123"}, "release-int": {"release_id": 123},
               "run-over-int53": {"run_id": 2**53}}
    if mutation == "extra-field":
        binding["operation"] = operation
    elif mutation == "missing-field":
        binding.pop("generation")
    elif mutation == "operation":
        operation = {"inventory": "i", "publish": "publish-static", "retire": "rollback"}[operation]
    else:
        binding |= changes[mutation]
    if mutation in {"plan-short", "plan-null"} and operation == "inventory":
        if mutation == "plan-null":
            assert lc.static_session(binding, operation).startswith("sp-i-")
            return
    with pytest.raises(ValueError):
        lc.static_session(binding, operation)


@pytest.mark.parametrize("operation", ["inventory", "publish", "retire"])
@pytest.mark.parametrize("release_id", ["r", "0", "a-b", "r" * 32])
def test_static_session_admits_the_498_release_id_bounds(operation, release_id):
    import re
    from tools.cnesdata_delivery import lifecycle_contract as lc
    prefix = "sp-" + {"inventory": "i"}.get(operation, operation) + "-"
    assert re.fullmatch(re.escape(prefix) + "[0-9a-f]{40}", lc.static_session(_static_binding(release_id=release_id), operation))


class _QuietGuard:
    def check(self, seconds=1):
        pass


def _static_journal(operation, *, inputs=None):
    from tools.cnesdata_delivery.application_gate import AdapterJournal
    request, owner, window, original = _adapter_case(operation)
    original.update(inputs or {})
    request["inputs"] = {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in original.items()}
    return AdapterJournal(c.canonical(request), operation=operation, owner=owner, window=window, inputs=original,
                          activation_sha256=request["activation_sha256"], guard=_QuietGuard())


def _publish_static_case(*, receipt=lambda value: None, ready=(("closed-ready",),), broker=False, other=None):
    """Item 6: one closed-ready journal per entry of `ready`, each observing the listed kinds of the SYNTHETIC
    closed-ready bytes (the second journal observes other bytes); the publish-static host-receipt is the
    SYNTHETIC host handoff v1 bound to the first."""
    from tools.cnesdata_delivery.application_gate import ClosedReadyBroker, Keeper
    keeper = Keeper(None, {"lifecycle_version": 1}, None, api=None, governance=None)
    vectors = _synthetic_terminal_vectors()
    ready_raw = c.canonical(vectors["closed-ready"])
    for index, kinds in enumerate(ready):
        journal = _static_journal("closed-ready")
        for kind in kinds:
            journal.observe(kind, ready_raw if index == 0 else c.canonical(vectors["closed-ready"] | {"observed_at": c.utc(1001)}))
        keeper.attach(journal)
        if broker:
            wrapper = ClosedReadyBroker.__new__(ClosedReadyBroker)
            wrapper.journal, wrapper.evidence = journal, []
            keeper.attach(wrapper)
    if other is not None:
        journal = _static_journal(other)
        journal.observe({"close-drain": "close-drain", "inventory": "inventory"}[other], ready_raw)
        keeper.attach(journal)
    handoff = json.loads(_synthetic_terminal_artifacts(vectors)["host-handoff"])
    raw = receipt(handoff)
    publish = _static_journal("publish-static", inputs={"host-receipt": raw if type(raw) is bytes else c.canonical(handoff)})
    return keeper, publish, c.sha(ready_raw)


@pytest.mark.parametrize("broker", [False, True])
def test_publish_static_binds_the_host_receipt_to_the_single_closed_ready_observation(broker):
    from tools.cnesdata_delivery import application_gate as ag
    keeper, publish, digest = _publish_static_case(broker=broker)
    assert ag.publish_static_closed_ready(publish, keeper) == digest
    assert publish._failed is False and not any(item is publish for item in keeper._contexts)


@pytest.mark.parametrize("mutation", ["digest", "absent", "two-in-one-journal", "two-journals", "other-kind-close-drain",
                                      "other-kind-inventory", "observed-under-other-kind"])
def test_publish_static_refuses_without_exactly_one_matching_closed_ready_observation(mutation):
    from tools.cnesdata_delivery import application_gate as ag
    case = {"digest": {"receipt": lambda value: value.update(closed_ready_sha256="9" * 64)},
            "absent": {"ready": ()}, "two-in-one-journal": {"ready": (("closed-ready", "closed-ready"),)},
            "two-journals": {"ready": (("closed-ready",), ("closed-ready",))},
            "other-kind-close-drain": {"ready": (), "other": "close-drain"},
            "other-kind-inventory": {"ready": (), "other": "inventory"},
            "observed-under-other-kind": {"ready": (("closed-ready",),), "other": "close-drain",
                                          "receipt": lambda value: value.update(closed_ready_sha256="9" * 64)}}[mutation]
    keeper, publish, _ = _publish_static_case(**case)
    with pytest.raises(ValueError, match="publish-static host-receipt closed-ready binding"):
        ag.publish_static_closed_ready(publish, keeper)
    assert publish._failed is True and any(item is publish for item in keeper._contexts)


@pytest.mark.parametrize("mutation", ["extra-field", "missing-field", "version", "version-bool", "kind", "noncanonical",
                                      "not-json", "list", "oversized"])
def test_publish_static_refuses_a_host_receipt_outside_the_v1_handoff(mutation):
    from tools.cnesdata_delivery import application_gate as ag
    def receipt(value):
        if mutation == "extra-field": value["accepted"] = True
        if mutation == "missing-field": value.pop("producer_sha")
        if mutation == "version": value["version"] = 2
        if mutation == "version-bool": value["version"] = True
        if mutation == "kind": value["kind"] = "closed-ready"
        if mutation == "noncanonical": return c.canonical(value) + b" "
        if mutation == "not-json": return b"host-handoff\n"
        if mutation == "list": return c.canonical([value])
        if mutation == "oversized": value["operation_id"] = "x" * 1024**2
    keeper, publish, _ = _publish_static_case(receipt=receipt)
    with pytest.raises(ValueError):
        ag.publish_static_closed_ready(publish, keeper)
    assert publish._failed is True


@pytest.mark.parametrize("operation", ["closed-ready", "close-drain", "inventory"])
def test_publish_static_binding_takes_only_a_publish_static_journal_and_the_keeper(operation):
    from tools.cnesdata_delivery import application_gate as ag
    keeper, publish, _ = _publish_static_case()
    journal = _static_journal(operation)
    with pytest.raises(ValueError, match="publish-static original journal/keeper"):
        ag.publish_static_closed_ready(journal, keeper)
    with pytest.raises(ValueError, match="publish-static original journal/keeper"):
        ag.publish_static_closed_ready(publish, object())
    with pytest.raises(ValueError, match="publish-static original journal/keeper"):
        ag.publish_static_closed_ready(publish._request, keeper)


@pytest.mark.parametrize("held", ["closed-ready-failed", "closed-ready-pending", "other-context-failed", "inflight"])
def test_publish_static_refuses_while_the_keeper_holds_sdk_uncertainty(held):
    from tools.cnesdata_delivery import application_gate as ag
    keeper, publish, _ = _publish_static_case()
    source = keeper._contexts[0]
    if held == "closed-ready-failed":
        source._failed = True
    if held == "closed-ready-pending":
        source._pending.append({"kind": "sdk-pending"})
    if held == "inflight":
        source._inflight = {"kind": "sdk-inflight"}
    if held == "other-context-failed":
        other = _static_journal("close-drain")
        other._failed = True
        keeper.attach(other)
    with pytest.raises(ValueError, match="publish-static keeper uncertainty"):
        ag.publish_static_closed_ready(publish, keeper)
    assert publish._failed is True and any(item is publish for item in keeper._contexts)


def _static_promotion_source():
    """Pinned #498 static-promotion.tf text and the bucket ARN its name_prefix validation fixes."""
    import re
    from pathlib import Path
    from fixtures.cnesdata_delivery_lifecycle import STATIC_PROMOTION_SOURCE_SHA256
    raw = (Path(__file__).resolve().parent
           / "fixtures/cnesdata_delivery_sources/infra/opentofu/modules/runtime-iam/static-promotion.tf").read_bytes()
    assert c.sha(raw) == STATIC_PROMOTION_SOURCE_SHA256
    source = raw.decode()
    return source, "arn:aws:s3:::" + re.search(r'var\.name_prefix ==\s*"([a-z0-9-]+)"', source).group(1) + "-static-web"


def _static_policies(bucket, plan):
    """#498 locals.static_policies normal/observer as jsonencode text; checked against tofu renderings by digest."""
    expiry = {"DateLessThan": {"aws:CurrentTime": plan["enabled_until"]}}
    resources = [bucket + "/" + key for key in plan["candidate_keys"]]
    normal = [{"Effect": "Allow", "Action": action, "Resource": resources, "Condition": expiry}
              for action in ("s3:PutObject", "s3:GetObject")]
    normal.append({"Effect": "Allow", "Action": ["cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"],
                   "Resource": plan["distribution_arn"], "Condition": expiry})
    normal += [{"Effect": "Allow", "Action": "s3:DeleteObjectVersion", "Resource": bucket + "/" + ref["key"],
                "Condition": expiry | {"StringEquals": {"s3:VersionId": ref["version_id"]}}}
               for ref in plan["retire_versions"]]
    observer = [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListMultipartUploadParts"],
                 "Resource": [bucket + "/assets/*", bucket + "/index.html", bucket + "/theme-init.js"]},
                {"Effect": "Allow", "Action": ["s3:ListBucketVersions", "s3:ListBucketMultipartUploads"], "Resource": bucket},
                {"Effect": "Allow", "Action": "cloudfront:GetInvalidation", "Resource": plan["distribution_arn"]}]
    return {alias: json.dumps({"Version": "2012-10-17", "Statement": statements}, sort_keys=True, separators=(",", ":"))
            for alias, statements in (("normal", normal), ("observer", observer))}


def _retire_static_plan_bound():
    """Decision 5: largest retire_versions count #498 admits, from the pinned source's policy size rule."""
    import re
    from fixtures.cnesdata_delivery_lifecycle import STATIC_MINIMAL_NORMAL_POLICY, STATIC_VERSION_CHARS
    source, bucket = _static_promotion_source()
    limit = int(re.fullmatch(r"(?s).*\}\)\) : length\(policy\) <= (\d+)\]\),.*", source).group(1))

    def normal(count):
        return _static_policies(bucket, {
            "candidate_keys": ["assets/a"], "enabled_until": "2027-02-12T00:00:00Z",
            "distribution_arn": "arn:aws:cloudfront::111122223333:distribution/A",
            "retire_versions": [{"key": "assets/a", "version_id": version} for version in STATIC_VERSION_CHARS[:count]]})["normal"]
    for count, rendered in STATIC_MINIMAL_NORMAL_POLICY.items():
        assert {"sha256": c.sha(normal(count).encode()), "length": len(normal(count))} == rendered, count
    count = 0
    while count < len(STATIC_VERSION_CHARS) and len(normal(count + 1)) <= limit:
        count += 1
    assert count < len(STATIC_VERSION_CHARS), "the size rule, not the one-char version id space, bounds the plan"
    assert STATIC_MINIMAL_NORMAL_POLICY[count]["length"] <= limit < STATIC_MINIMAL_NORMAL_POLICY[count + 1]["length"]
    return count


def _retire_static_deletes(latency, *, plan, durable, watchdog):
    """Deletes completed in `final` (reopen and finish take 0 s) by the only SDK broker shape that exists.

    Each AWS op takes `latency`. Fence STS: +40 before, +20 after (application_gate.py:717-724, :775). Per call
    (ClosedReadyBroker.call): +20 before and after the reservation (:1146, :1160); durable evidence is 5 S3 ops in
    reserve() and 4 in complete() (:1070-1112), each after guard.check(20) (:1022, :1030), as is the native call
    (:1161). watchdog=True: the guard is LifecycleWatchdog.check -> lc.phase_capacity(max(20, s)); False: KeeperGuard
    (no capacity check).
    """
    from tools.cnesdata_delivery import lifecycle_contract as lc
    window = dict(_adapter_case("retire-static")[2])
    window["deadline"] = window["admitted_at"] + lc.STAGES["final"][0]
    clock = {"now": float(window["admitted_at"])}
    credential = clock["now"] + 900

    def op(reserve=True):
        if reserve and watchdog:
            lc.phase_capacity(window, now=clock["now"], credential_deadline=credential, operation_seconds=20)
        clock["now"] += latency

    def within(seconds):
        c.require(clock["now"] + seconds < window["deadline"], "budget")
    done = 0
    try:
        within(40), op(reserve=False), within(20)
        while done < plan:
            within(20)
            for _ in range(5 if durable else 0):
                op()
            within(20)
            for _ in range(5 if durable else 1):
                op()
            c.require(clock["now"] < window["deadline"], "budget")
            done += 1
    except ValueError:
        pass
    return done


def test_retire_static_does_not_fit_the_final_budget_for_the_largest_498_plan_in_the_worst_case():
    """R16 (decision 5): pins the stop condition reported before merge; retire-static stays without call site."""
    import inspect
    from tools.cnesdata_delivery import aws_boundary, lifecycle_contract as lc
    plan = _retire_static_plan_bound()
    worst = inspect.signature(aws_boundary.bounded).parameters["timeout"].default
    variants = [(durable, watchdog) for durable in (True, False) for watchdog in (True, False)]
    assert {(d, w): _retire_static_deletes(worst, plan=plan, durable=d, watchdog=w) for d, w in variants} == {
        (True, True): 0, (True, False): 0, (False, True): 0, (False, False): 1}
    assert {(d, w): _retire_static_deletes(1, plan=plan, durable=d, watchdog=w) for d, w in variants} == {
        (True, True): 0, (True, False): 4, (False, True): 2, (False, False): 39}
    thresholds = {}
    for durable, watchdog in variants:
        low, high = 0.0, float(worst)
        assert _retire_static_deletes(low, plan=plan, durable=durable, watchdog=watchdog) == plan
        for _ in range(40):
            middle = (low + high) / 2
            fits = _retire_static_deletes(middle, plan=plan, durable=durable, watchdog=watchdog) == plan
            low, high = (middle, high) if fits else (low, middle)
        thresholds[durable, watchdog] = low
    # Closed forms over the 60 s of decision 5: (60 - 20 [- 37]) / (AWS ops before the last capacity check).
    assert lc.STAGES["final"][0] == 60
    assert thresholds == {
        (True, True): pytest.approx((60 - 20 - 37) / (1 + 10 * (plan - 1) + 9), abs=1e-6),
        (True, False): pytest.approx((60 - 20) / (1 + 10 * (plan - 1) + 5), abs=1e-6),
        (False, True): pytest.approx((60 - 20 - 37) / (1 + (plan - 1)), abs=1e-6),
        (False, False): pytest.approx((60 - 20) / (1 + (plan - 1)), abs=1e-6)}
    assert max(thresholds.values()) < 1


def test_498_static_policies_evaluate_on_source_to_the_static_stage_calls():
    """R4 after PR-R: iam_boundary.effective_iam over the #498 source policies, never the applied IAM.

    No static session policy exists, so the identity document is its own session. HeadObject is s3:GetObject.
    """
    from fixtures.cnesdata_delivery_lifecycle import STATIC_POLICY_VECTOR, STATIC_PROMOTION_VECTOR as plan
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    _, bucket = _static_promotion_source()
    texts = _static_policies(bucket, plan)
    assert {alias: {"sha256": c.sha(text.encode()), "length": len(text)} for alias, text in texts.items()} == STATIC_POLICY_VECTOR
    policies = {alias: json.loads(text) for alias, text in texts.items()}
    distribution, old = plan["distribution_arn"], bucket + "/assets/old.js"

    def allowed(alias, action, resource, now="2027-02-11T23:59:59Z", **context):
        policy = policies[alias]
        return effective_iam(policy, [policy], action, resource, {"aws:CurrentTime": now} | context)
    observer = [("s3:GetObject", bucket + "/assets/app.js"), ("s3:GetObject", bucket + "/index.html"),
                ("s3:GetObjectVersion", bucket + "/theme-init.js"), ("s3:ListMultipartUploadParts", bucket + "/assets/x/y.js"),
                ("s3:ListBucketVersions", bucket), ("s3:ListBucketMultipartUploads", bucket),
                ("cloudfront:GetInvalidation", distribution)]
    assert all(allowed("observer", *case) for case in observer)
    assert all(allowed("observer", *case, now="2099-01-01T00:00:00Z") for case in observer)
    for action, resource in [("s3:PutObject", bucket + "/index.html"), ("s3:DeleteObjectVersion", old), ("s3:DeleteObject", old),
                             ("s3:AbortMultipartUpload", bucket + "/assets/a"), ("cloudfront:CreateInvalidation", distribution),
                             ("s3:GetObject", bucket + "/other.html"), ("s3:ListBucketVersions", bucket + "/assets/a")]:
        assert not allowed("observer", action, resource, **{"s3:VersionId": "Older-4"}), (action, resource)
    normal = [(action, bucket + "/" + key, {}) for key in plan["candidate_keys"] for action in ("s3:PutObject", "s3:GetObject")]
    normal += [(action, distribution, {}) for action in ("cloudfront:CreateInvalidation", "cloudfront:GetInvalidation")]
    normal += [("s3:DeleteObjectVersion", bucket + "/" + ref["key"], {"s3:VersionId": ref["version_id"]})
               for ref in plan["retire_versions"]]
    assert all(allowed("normal", action, resource, **context) for action, resource, context in normal)
    assert not any(allowed("normal", action, resource, now=plan["enabled_until"], **context) for action, resource, context in normal)
    for action, resource, context in [
            ("s3:PutObject", old, {}), ("s3:GetObject", old, {}), ("s3:DeleteObjectVersion", old, {}),
            ("s3:DeleteObjectVersion", old, {"s3:VersionId": "Prev.Index_1"}),
            ("s3:DeleteObjectVersion", bucket + "/index.html", {"s3:VersionId": "Prev.Index_1"}),
            ("s3:DeleteObjectVersion", bucket + "/assets/app.js", {"s3:VersionId": "Older-4"}),
            ("s3:DeleteObject", old, {"s3:VersionId": "Older-4"}), ("s3:ListBucketVersions", bucket, {}),
            ("s3:GetObjectVersion", bucket + "/index.html", {"s3:VersionId": "Prev.Index_1"})]:
        assert not allowed("normal", action, resource, **context), (action, resource, context)


def _b64(raw):
    import base64
    return base64.b64encode(raw).decode("ascii")


@pytest.mark.parametrize("raw", [b"", b"a", b"\x00\xff" * 10, bytes(range(256))])
def test_s3_body_crosses_the_broker_as_canonical_standard_base64(raw):
    import hashlib
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert lc.s3_body_bytes({"base64": _b64(raw)}) == raw
    parameters = {"Bucket": "b", "Key": "index.html", "Body": {"base64": _b64(raw)}, "ChecksumSHA256": _b64(hashlib.sha256(raw).digest())}
    assert lc.s3_put_body(parameters) == raw


@pytest.mark.parametrize("body", [b"QQ==", "QQ", "QR==", "QQ==\n", " QQ==", "Q Q==", "-_8=", "+/8", "QQ==QQ==", "QUI=" + "é",
                                  None, 7, ["QQ=="]])
def test_s3_body_refuses_anything_but_one_canonical_padded_base64_text(body):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    with pytest.raises(ValueError, match="S3 Body"):
        lc.s3_body_bytes({"base64": body})


@pytest.mark.parametrize("body", [None, "QQ==", {}, {"base64": "QQ==", "encoding": "base64"}, {"b64": "QQ=="}])
def test_s3_body_is_a_closed_single_field_object(body):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    with pytest.raises(ValueError):
        lc.s3_body_bytes(body)


@pytest.mark.parametrize("mutation", ["checksum-other", "checksum-hex", "checksum-of-text", "checksum-missing", "checksum-none",
                                      "body-missing", "body-invalid", "not-dict"])
def test_s3_put_body_binds_checksum_sha256_to_the_decoded_bytes(mutation):
    import hashlib
    from tools.cnesdata_delivery import lifecycle_contract as lc
    raw = b"console.log(1)\n"
    parameters = {"Bucket": "b", "Key": "assets/app.js", "Body": {"base64": _b64(raw)}, "ChecksumSHA256": _b64(hashlib.sha256(raw).digest())}
    if mutation == "checksum-other": parameters["ChecksumSHA256"] = _b64(hashlib.sha256(raw + b" ").digest())
    if mutation == "checksum-hex": parameters["ChecksumSHA256"] = hashlib.sha256(raw).hexdigest()
    if mutation == "checksum-of-text": parameters["ChecksumSHA256"] = _b64(hashlib.sha256(_b64(raw).encode()).digest())
    if mutation == "checksum-missing": parameters.pop("ChecksumSHA256")
    if mutation == "checksum-none": parameters["ChecksumSHA256"] = None
    if mutation == "body-missing": parameters.pop("Body")
    if mutation == "body-invalid": parameters["Body"] = {"base64": "QR=="}
    if mutation == "not-dict": parameters = [parameters]
    with pytest.raises(ValueError, match="S3 Body"):
        lc.s3_put_body(parameters)


class _Stream:
    def __init__(self, raw, step=None, kind=bytes):
        self.raw, self.step, self.kind, self.reads = raw, step, kind, []

    def read(self, amount):
        assert not self.reads or self.reads[-1] is not None, "read after EOF"
        size = amount if self.step is None else min(amount, self.step)
        chunk, self.raw = self.raw[:size], self.raw[size:]
        self.reads.append(amount if chunk else None)
        return self.kind(chunk)


@pytest.mark.parametrize("step", [None, 1, 3])
@pytest.mark.parametrize("raw", [b"", b"x", b"\x00" * 9, bytes(range(10))])
def test_s3_body_value_reads_at_most_the_bound_and_returns_base64(raw, step):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    stream = _Stream(raw, step)
    assert lc.s3_body_value(stream, maximum=10) == {"base64": _b64(raw)}
    amounts = [amount for amount in stream.reads if amount is not None]
    assert stream.raw == b"" and all(1 <= amount <= 11 for amount in amounts)


@pytest.mark.parametrize("raw", [b"", b"z"])
def test_s3_body_value_admits_a_zero_bound_for_an_empty_body_only(raw):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    if raw:
        with pytest.raises(ValueError, match="S3 Body bound"):
            lc.s3_body_value(_Stream(raw), maximum=0)
    else:
        assert lc.s3_body_value(_Stream(raw), maximum=0) == {"base64": ""}


@pytest.mark.parametrize("step", [None, 1, 4])
def test_s3_body_value_refuses_one_byte_past_the_bound_without_reading_further(step):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    stream = _Stream(b"y" * 64, step)
    with pytest.raises(ValueError, match="S3 Body bound"):
        lc.s3_body_value(stream, maximum=10)
    assert len(stream.raw) == 64 - 11


@pytest.mark.parametrize("case", ["str-chunk", "bytearray-chunk", "maximum-negative", "maximum-bool", "maximum-float"])
def test_s3_body_value_refuses_non_bytes_chunks_and_unbounded_reads(case):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    stream = _Stream(b"abc", kind={"str-chunk": lambda raw: raw.decode(), "bytearray-chunk": bytearray}.get(case, bytes))
    maximum = {"maximum-negative": -1, "maximum-bool": True, "maximum-float": 10.0}.get(case, 10)
    with pytest.raises(ValueError):
        lc.s3_body_value(stream, maximum=maximum)


_STATIC_BUCKET = "example-static-web"


def _static_plan_value(bucket=_STATIC_BUCKET, **changes):
    """SYNTHETIC cnesdata.static-plan/v1 (CnesData 9cdd452f _api_static_records.static_plan) over STATIC_PROMOTION_VECTOR."""
    from fixtures.cnesdata_delivery_lifecycle import STATIC_PROMOTION_VECTOR as vector
    value = {"schema": "cnesdata.static-plan/v1", "bucket": bucket, "distribution_arn": vector["distribution_arn"],
             "inventory_sha256": "d" * 64, "candidate_keys": list(vector["candidate_keys"]),
             "rollback_versions": copy.deepcopy(vector["rollback_versions"]),
             "retire_versions": copy.deepcopy(vector["retire_versions"]), "multipart_keys": []}
    return value | changes


def _static_product_calls(bucket=_STATIC_BUCKET):
    """SYNTHETIC calls in the CnesData 9cdd452f publish_dashboard.py wire form: ListObjectVersions :342-348, HeadObject
    :354-357, ListMultipartUploads and ListParts :363-371, PutObject :378-389, GetObject :400-402, CreateInvalidation
    :428-440. DeleteObject has no product handler (R3): its shape is 6963763481 decision 2."""
    import hashlib
    body = b"console.log(1)\n"
    observer = [("observer", "s3", "ListObjectVersions", {"Bucket": bucket}),
                ("observer", "s3", "ListObjectVersions", {"Bucket": bucket, "KeyMarker": "assets/app.js",
                                                          "VersionIdMarker": "Prev.Index_1"}),
                ("observer", "s3", "HeadObject", {"Bucket": bucket, "Key": "index.html", "VersionId": "Prev.Index_1",
                                                  "ChecksumMode": "ENABLED"}),
                ("observer", "s3", "ListMultipartUploads", {"Bucket": bucket}),
                ("observer", "s3", "ListParts", {"Bucket": bucket, "Key": "assets/big.js", "UploadId": "upload-1"})]

    def put(key, **extra):
        return ("normal", "s3", "PutObject", {"Bucket": bucket, "Key": key, "Body": {"base64": _b64(body)},
                "ContentType": "text/javascript", "CacheControl": "public, max-age=31536000, immutable",
                "ChecksumSHA256": _b64(hashlib.sha256(body).digest())} | extra)
    normal = [put("assets/app.js", IfNoneMatch="*"), put("index.html"), put("theme-init.js"),
              ("normal", "s3", "GetObject", {"Bucket": bucket, "Key": "assets/app.js"}),
              ("normal", "cloudfront", "CreateInvalidation", {"DistributionId": "E2SYNTHETIC0", "InvalidationBatch": {
                  "Paths": {"Quantity": 2, "Items": ["/index.html", "/theme-init.js"]}, "CallerReference": "0f" * 16}})]
    retire = [("normal", "s3", "DeleteObject", {"Bucket": bucket, "Key": ref["key"], "VersionId": ref["version_id"]})
              for ref in _static_plan_value()["retire_versions"]]
    return {"inventory": observer, "publish-static": observer + normal, "retire-static": retire}


def _static_call(operation, call, plan="vector", bucket=_STATIC_BUCKET):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    role, service, name, parameters = call
    if plan == "vector":
        plan = None if operation == "inventory" else lc.static_plan(c.canonical(_static_plan_value(bucket)), bucket=bucket)
    return lc.validate_static_call(request={"operation": operation}, role=role, service=service, operation=name,
                                   parameters=parameters, bucket=bucket, plan=plan)


def test_static_sdk_catalogue_is_the_closed_product_wire_form_r17():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert lc.STATIC_SDK_METHODS == {
        ("s3", "ListObjectVersions"): "list_object_versions", ("s3", "HeadObject"): "head_object",
        ("s3", "ListMultipartUploads"): "list_multipart_uploads", ("s3", "ListParts"): "list_parts",
        ("s3", "PutObject"): "put_object", ("s3", "GetObject"): "get_object",
        ("cloudfront", "CreateInvalidation"): "create_invalidation", ("s3", "DeleteObject"): "delete_object"}
    observer = {("observer", "s3", name) for name in ("ListObjectVersions", "HeadObject", "ListMultipartUploads", "ListParts")}
    assert lc.STATIC_SDK_OPERATIONS == {
        "inventory": observer,
        "publish-static": observer | {("normal", "s3", "PutObject"), ("normal", "s3", "GetObject"),
                                      ("normal", "cloudfront", "CreateInvalidation")},
        "retire-static": {("normal", "s3", "DeleteObject")}}
    assert all(role in lc.STATIC_SESSION_OPERATIONS[operation] for operation, calls in lc.STATIC_SDK_OPERATIONS.items()
               for role, _, _ in calls)


@pytest.mark.parametrize("operation", ["inventory", "publish-static", "retire-static"])
def test_static_call_admits_every_product_call_and_returns_the_boto3_method(operation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    for call in _static_product_calls()[operation]:
        assert _static_call(operation, call) == lc.STATIC_SDK_METHODS[call[1], call[2]], call


@pytest.mark.parametrize("operation,call", [
    ("publish-static", ("normal", "s3", "put_object")), ("publish-static", ("normal", "s3", "PutObjectAcl")),
    ("publish-static", ("normal", "s3", "DeleteObject")), ("publish-static", ("normal", "s3", "DeleteObjects")),
    ("publish-static", ("normal", "s3", "CopyObject")), ("publish-static", ("normal", "cloudfront", "GetInvalidation")),
    ("publish-static", ("observer", "s3", "PutObject")), ("publish-static", ("normal", "s3", "CreateInvalidation")),
    ("publish-static", ("recovery", "s3", "GetObject")), ("inventory", ("normal", "s3", "ListObjectVersions")),
    ("inventory", ("observer", "s3", "GetObject")), ("inventory", ("normal", "s3", "PutObject")),
    ("retire-static", ("normal", "s3", "DeleteObjects")), ("retire-static", ("normal", "s3", "delete_object")),
    ("retire-static", ("observer", "s3", "HeadObject")), ("retire-static", ("normal", "s3", "PutObject")),
    ("rollback-api-static", ("recovery", "s3", "CopyObject")), ("closed-ready", ("observer", "s3", "HeadObject"))])
def test_static_call_refuses_names_outside_the_closed_map_r17(operation, call):
    parameters = {"Bucket": _STATIC_BUCKET, "Key": "index.html"}
    with pytest.raises(ValueError, match="closed static SDK operation"):
        _static_call(operation, (*call, parameters))


def _static_mutations():
    def at(operation, index, change):
        return operation, index, change
    def pop(key):
        return lambda p: p.pop(key)
    def put(**values):
        return lambda p: p.update(values)
    def batch(**values):
        return lambda p: p["InvalidationBatch"].update(values)
    return {
        "lov-bucket": at("inventory", 0, put(Bucket="other-static-web")), "lov-prefix": at("inventory", 0, put(Prefix="assets/")),
        "lov-marker-half": at("inventory", 1, pop("VersionIdMarker")), "lov-marker-int": at("inventory", 1, put(KeyMarker=7)),
        "lov-marker-empty": at("inventory", 1, put(KeyMarker="")),
        "head-checksum-mode": at("inventory", 2, put(ChecksumMode="DISABLED")), "head-no-checksum": at("inventory", 2, pop("ChecksumMode")),
        "head-no-version": at("inventory", 2, pop("VersionId")), "head-version-null": at("inventory", 2, put(VersionId="null")),
        "head-version-charset": at("inventory", 2, put(VersionId="v 1")), "head-key-outside": at("inventory", 2, put(Key="robots.txt")),
        "head-key-dotdot": at("inventory", 2, put(Key="assets/../index.html")), "head-key-empty-segment": at("inventory", 2, put(Key="assets//a.js")),
        "head-extra": at("inventory", 2, put(Range="bytes=0-1")), "lmu-extra": at("inventory", 3, put(Prefix="assets/")),
        "parts-no-upload": at("inventory", 4, pop("UploadId")), "parts-upload-empty": at("inventory", 4, put(UploadId="")),
        "parts-key-outside": at("inventory", 4, put(Key="logs/a")), "parts-extra": at("inventory", 4, put(MaxParts=1000)),
        "put-key-not-candidate": at("publish-static", 5, put(Key="assets/old.js")), "put-bucket": at("publish-static", 5, put(Bucket="other")),
        "put-asset-without-if-none-match": at("publish-static", 5, pop("IfNoneMatch")),
        "put-if-none-match-value": at("publish-static", 5, put(IfNoneMatch="etag")),
        "put-entrypoint-if-none-match": at("publish-static", 6, put(IfNoneMatch="*")),
        "put-checksum": at("publish-static", 6, put(ChecksumSHA256=_b64(b"\x00" * 32))),
        "put-body": at("publish-static", 6, put(Body={"base64": "QR=="})), "put-no-content-type": at("publish-static", 6, pop("ContentType")),
        "put-content-type-empty": at("publish-static", 6, put(ContentType="")), "put-cache-control-int": at("publish-static", 6, put(CacheControl=3600)),
        "put-extra-acl": at("publish-static", 6, put(ACL="public-read")),
        "get-key-not-candidate": at("publish-static", 8, put(Key="assets/old.js")), "get-version": at("publish-static", 8, put(VersionId="Older-4")),
        "get-bucket": at("publish-static", 8, put(Bucket="other")),
        "inv-distribution": at("publish-static", 9, put(DistributionId="E2OTHER")),
        "inv-quantity": at("publish-static", 9, lambda p: p["InvalidationBatch"]["Paths"].update(Quantity=1)),
        "inv-paths": at("publish-static", 9, lambda p: p["InvalidationBatch"]["Paths"].update(Items=["/*"])),
        "inv-paths-order": at("publish-static", 9, lambda p: p["InvalidationBatch"]["Paths"].update(Items=["/theme-init.js", "/index.html"])),
        "inv-reference-short": at("publish-static", 9, batch(CallerReference="0f" * 15)),
        "inv-reference-upper": at("publish-static", 9, batch(CallerReference="0F" * 16)),
        "inv-batch-extra": at("publish-static", 9, batch(Comment="x")), "inv-extra": at("publish-static", 9, put(Bucket=_STATIC_BUCKET)),
        "delete-rollback-ref": at("retire-static", 0, put(Key="index.html", VersionId="Prev.Index_1")),
        "delete-swapped-version": at("retire-static", 0, put(VersionId="Prev+Theme=2")),
        "delete-other-key": at("retire-static", 0, put(Key="assets/app.js")), "delete-no-version": at("retire-static", 0, pop("VersionId")),
        "delete-bucket": at("retire-static", 0, put(Bucket="other")), "delete-extra": at("retire-static", 0, put(MFA="x 1")),
    }


@pytest.mark.parametrize("mutation", list(_static_mutations()))
def test_static_call_binds_every_parameter_to_the_bucket_and_plan(mutation):
    operation, index, change = _static_mutations()[mutation]
    call = copy.deepcopy(_static_product_calls()[operation][index])
    change(call[3])
    with pytest.raises(ValueError):
        _static_call(operation, call)


@pytest.mark.parametrize("operation,plan", [("inventory", "plan"), ("publish-static", None), ("retire-static", None),
                                            ("publish-static", "raw"), ("retire-static", "other-bucket")])
def test_static_call_takes_a_decoded_plan_of_the_same_bucket_except_for_inventory(operation, plan):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    value = {"plan": lc.static_plan(c.canonical(_static_plan_value()), bucket=_STATIC_BUCKET), None: None,
             "raw": c.canonical(_static_plan_value()), "other-bucket": _static_plan_value("other-static-web")}[plan]
    with pytest.raises(ValueError):
        _static_call(operation, _static_product_calls()[operation][-1], plan=value)


def test_static_plan_admits_the_product_plan_and_the_498_bounds():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert lc.static_plan(c.canonical(_static_plan_value()), bucket=_STATIC_BUCKET) == _static_plan_value()
    product = _static_plan_value(rollback_versions=[], retire_versions=[], multipart_keys=["assets/big.js"])
    assert lc.static_plan(c.canonical(product), bucket=_STATIC_BUCKET) == product


@pytest.mark.parametrize("mutation", [
    "schema", "bucket", "extra", "missing", "noncanonical", "distribution-lower", "distribution-account", "inventory-short",
    "candidates-empty", "candidates-unsorted", "candidates-duplicate", "candidate-outside", "candidate-dotdot",
    "candidate-dot", "candidate-empty-segment", "candidate-int", "multipart-unsorted", "multipart-outside",
    "rollback-one", "rollback-order", "rollback-other-key", "ref-extra", "ref-version-null", "ref-version-charset",
    "ref-version-empty", "retire-duplicate", "retire-in-rollback", "retire-key-outside", "retire-not-list"])
def test_static_plan_refuses_anything_outside_the_498_contract(mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    value = _static_plan_value()
    index = {"key": "index.html", "version_id": "Prev.Index_1"}
    changes = {
        "schema": {"schema": "cnesdata.static-plan/v2"}, "bucket": {"bucket": "other-static-web"}, "extra": {"retire": []},
        "distribution-lower": {"distribution_arn": "arn:aws:cloudfront::111122223333:distribution/e2synthetic0"},
        "distribution-account": {"distribution_arn": "arn:aws:cloudfront::11112222333:distribution/E2SYNTHETIC0"},
        "inventory-short": {"inventory_sha256": "d" * 63}, "candidates-empty": {"candidate_keys": []},
        "candidates-unsorted": {"candidate_keys": ["index.html", "assets/app.js"]},
        "candidates-duplicate": {"candidate_keys": ["index.html", "index.html"]}, "candidate-outside": {"candidate_keys": ["robots.txt"]},
        "candidate-dotdot": {"candidate_keys": ["assets/../x"]}, "candidate-dot": {"candidate_keys": ["assets/./x"]},
        "candidate-empty-segment": {"candidate_keys": ["assets//x"]}, "candidate-int": {"candidate_keys": [7]},
        "multipart-unsorted": {"multipart_keys": ["assets/b", "assets/a"]}, "multipart-outside": {"multipart_keys": ["tmp/a"]},
        "rollback-one": {"rollback_versions": [index]},
        "rollback-order": {"rollback_versions": list(reversed(value["rollback_versions"]))},
        "rollback-other-key": {"rollback_versions": [index, {"key": "assets/app.js", "version_id": "Prev+Theme=2"}]},
        "ref-extra": {"retire_versions": [value["retire_versions"][0] | {"sha256": None}]},
        "ref-version-null": {"retire_versions": [{"key": "assets/old.js", "version_id": "null"}]},
        "ref-version-charset": {"retire_versions": [{"key": "assets/old.js", "version_id": "v 1"}]},
        "ref-version-empty": {"retire_versions": [{"key": "assets/old.js", "version_id": ""}]},
        "retire-duplicate": {"retire_versions": value["retire_versions"][:1] * 2},
        "retire-in-rollback": {"retire_versions": [index]},
        "retire-key-outside": {"retire_versions": [{"key": "old.js", "version_id": "Older-4"}]},
        "retire-not-list": {"retire_versions": {"assets/old.js": "Older-4"}}}
    if mutation == "missing":
        value.pop("multipart_keys")
    elif mutation != "noncanonical":
        value |= changes[mutation]
    raw = c.canonical(value) + (b" " if mutation == "noncanonical" else b"")
    with pytest.raises(ValueError):
        lc.static_plan(raw, bucket=_STATIC_BUCKET)


# AWS Service Authorization Reference (Amazon S3, Amazon CloudFront): the IAM action each R17 wire call needs.
_STATIC_IAM_ACTIONS = {
    "ListObjectVersions": ("s3:ListBucketVersions", "bucket"), "HeadObject": ("s3:GetObjectVersion", "object"),
    "ListMultipartUploads": ("s3:ListBucketMultipartUploads", "bucket"), "ListParts": ("s3:ListMultipartUploadParts", "object"),
    "PutObject": ("s3:PutObject", "object"), "GetObject": ("s3:GetObject", "object"),
    "CreateInvalidation": ("cloudfront:CreateInvalidation", "distribution"), "DeleteObject": ("s3:DeleteObjectVersion", "object"),
}


def test_every_validated_static_call_is_allowed_by_its_498_role_on_source_r17():
    """6963763481 decision 2: DeleteObject with VersionId needs s3:DeleteObjectVersion, granted per version to normal.

    HeadObject and DeleteObject always carry VersionId in the catalogue, so they need the *Version actions.
    """
    from fixtures.cnesdata_delivery_lifecycle import STATIC_PROMOTION_VECTOR as vector
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    _, bucket_arn = _static_promotion_source()
    bucket = bucket_arn.removeprefix("arn:aws:s3:::")
    policies = {alias: json.loads(text) for alias, text in _static_policies(bucket_arn, vector).items()}
    plan = lc.static_plan(c.canonical(_static_plan_value(bucket)), bucket=bucket)

    def allowed(role, action, resource, version=None, now="2027-02-11T23:59:59Z"):
        context = {"aws:CurrentTime": now} | ({"s3:VersionId": version} if version is not None else {})
        return effective_iam(policies[role], [policies[role]], action, resource, context)
    checked = set()
    for operation, calls in _static_product_calls(bucket).items():
        for role, service, name, parameters in calls:
            _static_call(operation, (role, service, name, parameters), plan=None if operation == "inventory" else plan,
                         bucket=bucket)
            action, kind = _STATIC_IAM_ACTIONS[name]
            resource = {"bucket": bucket_arn, "distribution": vector["distribution_arn"],
                        "object": bucket_arn + "/" + parameters.get("Key", "")}[kind]
            assert allowed(role, action, resource, parameters.get("VersionId")), (operation, name, parameters)
            checked.add((role, service, name))
    assert checked == set().union(*lc.STATIC_SDK_OPERATIONS.values())
    old = bucket_arn + "/assets/old.js"
    for ref in vector["retire_versions"]:
        assert allowed("normal", "s3:DeleteObjectVersion", bucket_arn + "/" + ref["key"], ref["version_id"])
        assert not allowed("normal", "s3:DeleteObject", bucket_arn + "/" + ref["key"], ref["version_id"])
        assert not allowed("observer", "s3:DeleteObjectVersion", bucket_arn + "/" + ref["key"], ref["version_id"])
        assert not allowed("normal", "s3:DeleteObjectVersion", bucket_arn + "/" + ref["key"], ref["version_id"],
                           now=vector["enabled_until"])
    for version in ("Prev.Index_1", "Prev+Theme=2", None):
        assert not allowed("normal", "s3:DeleteObjectVersion", old, version)


@pytest.mark.parametrize("case", ["key-1024", "version-1024", "marker-1024", "content-type-256"])
def test_static_call_admits_the_upper_bounds(case):
    calls = _static_product_calls()
    operation, index, change = {
        "key-1024": ("inventory", 2, {"Key": "assets/" + "a" * 1017}),
        "version-1024": ("inventory", 2, {"VersionId": "v" * 1024}),
        "marker-1024": ("inventory", 1, {"KeyMarker": "k" * 1024}),
        "content-type-256": ("publish-static", 6, {"ContentType": "t" * 256})}[case]
    role, service, name, parameters = copy.deepcopy(calls[operation][index])
    assert _static_call(operation, (role, service, name, parameters | change))


@pytest.mark.parametrize("case", ["key-1025", "key-space", "key-suffix", "version-1025", "marker-1025", "content-type-257",
                                  "cache-control-257", "head-bucket", "role-list", "parameters-list", "inventory-bucket-empty",
                                  "inventory-bucket-none"])
def test_static_call_refuses_past_the_bounds_and_types(case):
    calls = _static_product_calls()
    operation, index, change = {
        "key-1025": ("inventory", 2, {"Key": "assets/" + "a" * 1018}), "key-space": ("inventory", 2, {"Key": "assets/a b.js"}),
        "key-suffix": ("inventory", 2, {"Key": "index.html.bak"}), "version-1025": ("inventory", 2, {"VersionId": "v" * 1025}),
        "marker-1025": ("inventory", 1, {"KeyMarker": "k" * 1025}),
        "content-type-257": ("publish-static", 6, {"ContentType": "t" * 257}),
        "cache-control-257": ("publish-static", 6, {"CacheControl": "c" * 257}),
        "head-bucket": ("inventory", 2, {"Bucket": "other-static-web"})}.get(case, ("inventory", 0, {}))
    role, service, name, parameters = copy.deepcopy(calls[operation][index])
    parameters |= change
    bucket = {"inventory-bucket-empty": "", "inventory-bucket-none": None}.get(case, _STATIC_BUCKET)
    if case.startswith("inventory-bucket"):
        parameters["Bucket"] = bucket
    if case == "role-list":
        role = [role]
    if case == "parameters-list":
        parameters = [parameters]
    with pytest.raises(ValueError):
        _static_call(operation, (role, service, name, parameters), bucket=bucket)


@pytest.mark.parametrize("case", ["distribution-unicode-digits", "oversized", "bucket-str-subclass", "key-space", "key-1025"])
def test_static_plan_refuses_unicode_digits_oversize_and_non_str_buckets(case):
    from tools.cnesdata_delivery import lifecycle_contract as lc

    class Bucket(str):
        pass
    value = _static_plan_value()
    if case == "distribution-unicode-digits":
        value["distribution_arn"] = "arn:aws:cloudfront::" + "١" * 12 + ":distribution/E2SYNTHETIC0"
    if case == "oversized":
        value["candidate_keys"] = sorted("assets/k%06d.js" % index for index in range(70000))
    if case == "key-space":
        value["candidate_keys"] = ["assets/a b.js"]
    if case == "key-1025":
        value["candidate_keys"] = ["assets/" + "a" * 1018]
    bucket = Bucket(_STATIC_BUCKET) if case == "bucket-str-subclass" else _STATIC_BUCKET
    with pytest.raises(ValueError):
        lc.static_plan(c.canonical(value, limit=8 * 1024**2) if case == "oversized" else c.canonical(value), bucket=bucket)


def _terminal_window_case(kind):
    from tools.cnesdata_delivery import application_gate as ag
    if kind == "failed-prepare-quiescent":
        keeper, store = _prepare_stage_keeper()
    else:
        keeper, store = _accepted_terminal_case()
        if kind == "failed-closed-quiescent":
            value = store.get()[0]
            value["lifecycle"] |= {"stage": "recovery", "decision": {"choice_at": 1100, "deadline": 1520, "checkpoint_sha256": "9" * 64}}
            store.value = value
    keeper._terminal_validators = {}
    ag.register_terminal_validators(keeper, ag.TERMINAL_VALIDATORS)
    return ag, keeper, store


@pytest.mark.parametrize("kind, missing", [("accepted-open", {"unit", "recovery", "audit"}), ("failed-closed-quiescent", {"restoration"}),
                                          ("failed-prepare-quiescent", {"restoration"})])
def test_r15_the_production_registry_closes_no_terminal_kind(kind, missing):
    """The registry has no unit/recovery/audit/restoration validator: finish refuses every terminal kind, so API is the only end."""
    ag, keeper, store = _terminal_window_case(kind)
    window = store.get()[0]["lifecycle"]
    required = ag._terminal_required(kind, window)
    assert required - set(ag.TERMINAL_VALIDATORS) == missing
    before = store.get()
    with pytest.raises(ValueError, match="^terminal validator unavailable; lifecycle disabled$"):
        keeper.finish({"kind": kind, "checkpoint_raw": b"{}", "sources": {name: "synthetic-" + name for name in required}})
    assert store.get() == before and before[0]["status"] == "held"
