"""Offline legacy original checkpoint -> continuous lifecycle owner entry."""
import copy
import time

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


def test_original_legacy_checkpoint_enters_new_keeper_without_relabeling(monkeypatch, tmp_path):
    from tools.cnesdata_delivery.application_gate import authenticated_previous
    chain, aws, api, store, previous, reference = _legacy_history_fixture(monkeypatch, tmp_path)
    original = copy.deepcopy(previous)
    reads = []
    def authenticate(value):
        reads.append(copy.deepcopy(value))
        return authenticated_previous(aws, api, chain.gov, value)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
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
        "predecessor_sha256": "a" * 64, **lc.application_identity(binding)})
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


def _journal_with(*, pending=(), unknown=(), inflight=None, failed=False):
    from tools.cnesdata_delivery.application_gate import AdapterJournal
    journal = AdapterJournal.__new__(AdapterJournal)
    journal._pending, journal._unknown, journal._inflight, journal._failed = list(pending), list(unknown), inflight, failed
    journal._observation_bytes = {}
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
    for stage, (duration, _) in lc.STAGES.items():
        window = window | {"sequence": window["sequence"] + 1, "close": 1000, "fixed_deadline": 2800,
                           "input_deadline": 3000, "stage": stage, "admitted_at": 1000, "deadline": 1000 + duration,
                           "checkpoint_sha256": c.sha(c.canonical(checkpoint))}
        keeper.lease.checkpoint(window)
    proof.update(assessment={"kind": "accepted-open", "fence": "OPEN", "accepted_modes": ["unit", "recovery", "audit"],
                             "routes_match": True, "state_clean": True, "quiescent": True, "pending": [], "unknown": [], "observed_at": 1000},
                 checkpoint=checkpoint,
                 inputs={name: "e" * 64 for name in ("unit", "recovery", "audit", "host", "static", "routing", "membership", "quiescence")})
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
    for stage, (duration, _) in lc.STAGES.items():
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
    for stage, (duration, _) in ([] if prepare_failure else lc.STAGES.items()):
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
    governance = {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "evidence",
                  "gate_shas": {"application": "a" * 40}, "lifecycle_terminal_job": "promotion / keeper"}
    run = {"id": 44, "run_attempt": 1, "head_sha": "b" * 40, "event": "workflow_dispatch",
           "repository": {"full_name": c.REPOSITORY}, "path": ".github/workflows/promote-production.yml",
           "status": "in_progress", "conclusion": None, "head_branch": "develop",
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


@pytest.mark.parametrize("application_purpose", ["promotion", "mode-readiness-drill"])
@pytest.mark.parametrize("mutation", [None, "missing", "incomplete", "tampered"])
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
               "release_sha256": "c" * 64, "session_sha256": "f" * 64, "lifecycle_version": 1}
    binding |= _current_caller(governance, binding, application_purpose)
    keeper = Keeper(store, binding,
                    lambda value: authenticated_previous(aws, api, governance, value),
                    api=api, governance=governance, evidence_aws=aws, clock=lambda: 1100, monotonic=lambda: 1100)
    if mutation is not None:
        if mutation == "missing": governance.pop("lifecycle_predecessor")
        if mutation == "incomplete": reference.pop("objects")
        if mutation == "tampered": reference["objects"][0]["sha256"] = "0" * 64
        before = store.get()
        writes = store.writes
        monkeypatch.setattr(keeper.lease, "acquire", lambda: pytest.fail("invalid history reached Lease.acquire"))
        with pytest.raises((ValueError, KeyError)):
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


@pytest.mark.parametrize("mutation", [None, "generation", "job", "checkpoint-bytes", "current-run", "entry-replay"])
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
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    binding |= _current_caller(chain.gov, binding)
    keeper = Keeper(store, binding, lambda value: authenticated_previous(aws, api, chain.gov, value), api=api, governance=chain.gov)
    before = store.get()
    if mutation in {"generation", "job", "checkpoint-bytes"}:
        with pytest.raises(ValueError): keeper.acquire(preparation_deadline=int(time.time()) + 900)
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
    run = {"id": 44, "run_attempt": 2, "head_sha": "b" * 40, "head_branch": "develop",
           "repository": {"full_name": c.REPOSITORY}, "event": "workflow_dispatch", "path": caller["workflow_path"],
           "status": "in_progress", "referenced_workflows": [{"path": shared, "sha": role_pin}]}
    step = {"caller_job": "promote", "producer_job": "keeper", "job_name": "promote / keeper",
            "admission_steps": ["Authenticate original caller", "Issue credentials"]}
    job = {"id": 9, "run_id": 44, "run_attempt": 2, "head_sha": "b" * 40, "name": "promote / keeper",
           "status": "in_progress", "conclusion": None,
           "steps": [{"name": "Authenticate original caller", "status": "in_progress"}]}
    claims = {"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com",
              "sub": f"repo:{c.REPOSITORY}:environment:production:job_workflow_ref:{shared}",
              "repository": c.REPOSITORY, "ref": "refs/heads/develop", "environment": "production",
              "job_workflow_ref": shared, "workflow_ref": c.REPOSITORY + "/" + caller["workflow_path"] + "@refs/heads/develop",
              "workflow_sha": "b" * 40, "sha": "b" * 40, "event_name": "workflow_dispatch", "run_id": "44", "run_attempt": "2"}
    class API:
        def read(self, path, **kwargs):
            if "/contents/" in path: return {"encoding": "base64", "content": base64.b64encode(self.raw).decode()}
            if "/compare/" in path: return {"status": "identical"}
            if "/check-runs" in path: return {"check_runs": [{"name": "CI", "head_sha": "b" * 40, "conclusion": "success"}]}
            if "/jobs?" in path: return {"total_count": 1, "jobs": [job]}
            return run
    api = API(); api.raw = raw
    for key, value in {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/develop",
                       "GITHUB_REPOSITORY": c.REPOSITORY, "GITHUB_JOB": "keeper",
                       "GITHUB_WORKFLOW_REF": claims["workflow_ref"], "GITHUB_WORKFLOW_SHA": "b" * 40}.items():
        monkeypatch.setenv(key, value)
    return gov, api, run, step, job, claims


@pytest.mark.parametrize("role", ["application", "plan", "deploy"])
@pytest.mark.parametrize("purpose", ["promotion", "mode-readiness-drill"])
@pytest.mark.parametrize("mutation", [None, "crossed-workflow", "source-bytes", "wrong-uses", "job-attempt", "job-step", "job-name", "job-step-config", "context", "manifest", "env-workflow"])
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


@pytest.mark.parametrize("mutation", [None, "workflow", "sha", "event", "environment", "attempt", "caller-missing"])
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
    if mutation == "workflow": claims["workflow_ref"] = c.REPOSITORY + "/.github/workflows/other.yml@refs/heads/develop"
    if mutation == "sha": claims["sha"] = "c" * 40
    if mutation == "event": claims["event_name"] = "push"
    if mutation == "environment": claims["environment"] = "staging"
    if mutation == "attempt": claims["run_attempt"] = "1"
    if mutation == "caller-missing": gov.pop("authenticated_application_caller")
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
               "application_purpose": "promotion", "context_kind": "promotion", "caller_binding_sha256": "c" * 64}
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



def _adapter_case(operation="inventory"):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    owner = {"repository": c.REPOSITORY, "source_sha": "a" * 40, "run_id": 41, "run_attempt": 1,
             "release_sha256": "b" * 64, "generation": 2, "session_sha256": "c" * 64, "owner_sha256": "d" * 64,
             "application_purpose": "promotion", "context_kind": "promotion", "caller_binding_sha256": "e" * 64}
    window = {"close": None, "fixed_deadline": None, "input_deadline": None, "stage": "application-prepare",
              "admitted_at": 1000, "deadline": 1900, "decision": None, "preparation_deadline": 1900,
              "sequence": 1, "checkpoint_sha256": "f" * 64, **lc.application_identity(owner)}
    names = {"inventory": ("candidate", "dashboard-artifact", "archive", "static-baseline"),
             "closed-ready": ("activation", "close-drain", "phase-b", "membership")}[operation]
    if operation == "closed-ready":
        window.update(close=1000, fixed_deadline=2800, input_deadline=4000, stage="api", admitted_at=1300, deadline=1480)
    inputs = {name: c.canonical({"fixture_only": name}) for name in names}
    request = {"abi_version": 2, "operation": operation, "repository": c.REPOSITORY, "source_sha": owner["source_sha"],
               "owner": {key: owner[key] for key in [*lc.OWNER_FIELDS, "owner_sha256"]},
               "checkpoint_sha256": window["checkpoint_sha256"], "activation_sha256": "1" * 64,
               "stage": {key: value for key, value in window.items() if key not in lc.application_identity(owner)},
               "inputs": {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in inputs.items()}}
    return request, owner, window, inputs


@pytest.mark.parametrize("operation", ["inventory", "closed-ready"])
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
    result = {"abi_version": 2, "operation": "inventory", "owner_sha256": request["owner"]["owner_sha256"],
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
    result = {"abi_version": 2, "operation": "inventory", "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
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
    result = {"abi_version": 2, "operation": "closed-ready", "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
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
             "machine_arn": "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod-processor", "members": []}
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
    return {'abi_version': 2, 'operation': operation, 'owner_sha256': request['owner']['owner_sha256'],
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
    machine = "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod-processor"
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
        params["executionArn"] = execution.replace("cnesdata-prod-processor", "foreign")
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
            "machine_arn": "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod-processor", "members": []}
    if target in {"fence", "semaphore"}:
        assert lc.validate_closed_ready_call(**args) == params
    else:
        with pytest.raises(ValueError):
            lc.validate_closed_ready_call(**args)


@pytest.mark.parametrize("mutation", [None, "input", "output", "execution", "machine", "status"])
def test_closed_ready_probe_response_never_serializes_unexpected_execution_payload(mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    machine = "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod-processor"
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
    governance = {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "synthetic", "context_kind": owner["context_kind"],
                  "gate_shas": {"deploy": producer["workflow_sha"]}, "application_fragment": kwargs["fragment"]}
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"], "head_sha": owner["source_sha"],
           "event": "workflow_dispatch", "repository": {"full_name": c.REPOSITORY}, "head_branch": "develop",
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
    gov = chain.gov | current
    gov["gate_shas"] = chain.gov["gate_shas"] | current["gate_shas"]
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
            if "/contents/docs/cnesdata-delivery-application-lifecycle.md?ref=" in path:
                return {"encoding": "base64", "content": base64.b64encode(contract_raw).decode()}
            if "/actions/runs/44/" in path or "/compare/" in path or "/commits/" in path or "/contents/.github/" in path:
                return current_api.read(path, **kwargs)
            return history_api.read(path, **kwargs)
        def artifact(self, *args, **kwargs):
            return history_api.artifact(*args, **kwargs)
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
    return gov, request, run, job, configure, store, reads


@pytest.mark.parametrize("mutation", [None, "disabled", "null-fragment", "null-configuration", "old-fragment", "expired-fragment",
    "mixed-source", "mixed-attempt", "wrong-job", "caller-hash", "missing-history", "job-id-bool", "schema-bool"])
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
    configure()
    before = store.get()
    if mutation:
        with pytest.raises((ValueError, KeyError)):
            ag.main(["preflight"])
    else:
        admitted = ag.main(["preflight"])
        assert admitted[1]["source_sha"] == "b" * 40
        assert admitted[4]["id"] == 44
        assert admitted[0]["authenticated_application_job"] == {"job_id": 9, "producer_name": "promote / keeper",
            "repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 2}
        assert any("/actions/runs/44/attempts/2/jobs" in path for path in reads)
        assert any("/actions/jobs/91" in path for path in reads)
    assert store.get() == before



@pytest.mark.parametrize("purpose", ["promotion", "mode-readiness-drill"])
@pytest.mark.parametrize("mutation", [None, "disabled", "null-fragment", "caller", "ref", "pin", "attempt", "source"])
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
        "head_branch": "develop", "status": "in_progress",
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
    env = {"DELIVERY_ROLE": "application", "GITHUB_REPOSITORY": c.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main" if mutation == "ref" else "refs/heads/develop", "EXPECTED_SOURCE_SHA": product,
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
@pytest.mark.parametrize("job", ["validate", "execute"])
@pytest.mark.parametrize("purpose", ["promotion", "mode-readiness-drill"])
@pytest.mark.parametrize("mutation", [None, "crossed-context", "disabled", "old-fragment"])
def test_infra_reusable_bootstrap_selects_protected_application_caller(monkeypatch, tmp_path, role, job, purpose, mutation):
    import base64
    import io
    import json
    from pathlib import Path
    import urllib.request
    import yaml
    from tools.cnesdata_delivery import lifecycle_contract as lc
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / (".github/workflows/reusable-cnesdata-infra-" + role + "-gate.yml")).read_text())
    script = workflow["jobs"][job]["steps"][0]["run"]
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
        "GITHUB_REF": "refs/heads/develop", "EXPECTED_SOURCE_SHA": product, "GITHUB_RUN_ID": "44", "GITHUB_RUN_ATTEMPT": "2",
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
    gov = {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "synthetic", "context_kind": "promotion",
           "gate_shas": {"deploy": producer["workflow_sha"]}, "application_fragment": kwargs["fragment"]}
    run = {"id": owner["run_id"], "run_attempt": owner["run_attempt"], "head_sha": owner["source_sha"], "event": "workflow_dispatch",
        "repository": {"full_name": c.REPOSITORY}, "head_branch": "develop", "path": ".github/workflows/promote-production.yml",
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


def _fence_sdk_boundary_case(monkeypatch, *, mutation=None):
    """Synthetic protected admission; fakes only STS/GetCallerIdentity boundaries."""
    from datetime import datetime, timezone
    from tools.cnesdata_delivery import application_gate as ag, aws_boundary, lifecycle_contract as lc
    request, owner, window, inputs = _adapter_case("closed-ready")
    documents, _, package, _ = _fence_contract_case()
    role = copy.deepcopy(documents["fence-role.json"])
    table = "arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control"
    machine = "arn:aws:states:us-east-2:111122223333:stateMachine:cnesdata-prod-processor"
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
    calls, native_calls = [], []
    assumed = role["role_arn"].replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + role["session_name"]
    identity = {"Account": "111122223333", "Arn": assumed, "UserId": role["role_id"] + ":" + role["session_name"]}
    if mutation == "arn": identity["Arn"] += "-foreign"
    if mutation == "role-id": identity["UserId"] = "AROAOTHER:" + role["session_name"]
    if mutation == "account": identity["Account"] = "999900001111"
    class Application:
        def call(self, service, operation, **parameters):
            calls.append((service, operation, parameters))
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
    args = dict(aws=Application(), governance=governance, role=role, scope=scope, journal=journal,
                prepared_sha256="3" * 64, credential_limit=3000, clock=lambda: 1300)
    return ag, args, calls, native_calls


@pytest.mark.parametrize("mutation", [None, "arn", "role-id", "account", "packed", "expiration", "expired-window", "no-probe-grant"])
def test_finite_fence_session_requires_exact_sts_and_native_identity(monkeypatch, mutation):
    ag, args, calls, native = _fence_sdk_boundary_case(monkeypatch, mutation=mutation)
    if mutation:
        with pytest.raises(ValueError): ag._assume_fence_session(**args)
    else:
        session = ag._assume_fence_session(**args)
        assert session.scope == args["scope"] and session.deadline == 1480
        c.digest(session.commitment)
    if mutation in {"expired-window", "no-probe-grant"}:
        assert calls == native == []
    else:
        assert len(calls) == 1
        params = calls[0][2]
        assert set(params) == {"RoleArn", "RoleSessionName", "DurationSeconds", "Policy"}
        assert params["RoleArn"] == args["role"]["role_arn"] and params["RoleSessionName"] == "promotion-fence-r1"
        assert params["DurationSeconds"] == 900 and len(params["Policy"]) <= 2048
        assert not {"AccessKeyId", "SecretAccessKey", "SessionToken"} & set(params)
        assert len(native) == (0 if mutation in {"packed", "expiration"} else 1)


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
        'executionArn': 'arn:aws:states:us-east-2:111122223333:execution:cnesdata-prod-processor:' + 'a' * 16, 'includedData': 'METADATA_ONLY'}))
    for params in (fence, sem):
        observed.append(context.call('fence_operator', 'dynamodb', 'get_item', params))
    raw = canonical({'fixture_only': True, 'observed': observed})
    digest = context.observe('closed-ready', raw)
    snapshot = context.evidence_snapshot()
    MUTATION
    return {'abi_version': 2, 'operation': operation, 'owner_sha256': request['owner']['owner_sha256'],
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
                  execution_prefix="arn:aws:states:us-east-2:111122223333:execution:cnesdata-prod-processor:", deadline=1480)
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
        window = {"admitted_at": 1000, "preparation_deadline": 1900}
        def check(self, seconds=0): pass
    kwargs = dict(api=API(), aws=AWS(), governance=governance, request=request, run=run, owner=owner, guard=Guard(),
        authority=SimpleNamespace(application_fragment=fragment, pin=pin), predecessor=carrier["origin"], carrier=carrier,
        plan_index=args["current_index"], plan_raw=args["plan_raw"], inputs_raw=args["inputs_raw"], terraform_raw=args["inputs_raw"],
        approval_raw=c.canonical(approval), previous_raw=previous_raw, checkpoint_raw=checkpoint_raw, state_raw=args["state_raw"],
        sources=args["sources"], activation_sha256="1" * 64, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    return kwargs, calls, fragment


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
        "delta": {}, "drift_matrix": {}, "readbacks": {"before": [], "after": []}}
    b_files = {"checkpoint.json": c.canonical(b_checkpoint), "approval.json": c.canonical(b_approval)}
    members = scope["members"]
    membership = {"frozen_membership_sha256": c.sha(c.canonical(members)), "members": members}
    if mutation == "membership": membership["frozen_membership_sha256"] = "0" * 64
    inputs = {"activation": activation if mutation != "activation" else b"other", "close-drain": c.canonical({"fixture_only": "close"}),
              "phase-b": b_files["checkpoint.json"], "membership": c.canonical(membership)}
    window = {"close": 1000, "fixed_deadline": 2800, "input_deadline": 4000, "stage": "api", "admitted_at": 1300, "deadline": 1480,
              "decision": None, "preparation_deadline": 1900 if mutation != "preparation" else 1899, "sequence": 2,
              "checkpoint_sha256": c.sha(b_files["checkpoint.json"]), **lc.application_identity(owner)}
    request = {"abi_version": 2, "operation": "closed-ready", "repository": c.REPOSITORY, "source_sha": owner["source_sha"],
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
                 root + f"/actions/runs/{run['id']}/artifacts?per_page=100&page=1": {"artifacts": [metadata], "total_count": 1},
                 root + f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}": run | {"event": "workflow_dispatch",
                     "repository": {"full_name": c.REPOSITORY}, "path": ".github/workflows/promote-production.yml"}}
    class API:
        def read(self, path, **kw): return responses[path]
    req = {"source_sha": owner["source_sha"], "step": "closed-ready", "application_purpose": "promotion", "caller_binding_sha256": owner["caller_binding_sha256"]}
    objects = {lr.namespace(governance | {"evidence_prefix": "cnesdata/prod/evidence/"}, req, run, "phase-b-advance") + name: raw for name, raw in b_files.items()}
    class Store:
        def get(self, bucket, key, **kw): return objects[key], None
        def call(self, *args, **kw): return sts_args["aws"].call(*args, **kw)
    keeper = ag.Keeper.__new__(ag.Keeper)
    keeper._contexts, keeper.lease = [], SimpleNamespace(check=lambda: {"held": True})
    args = dict(aws=Store(), api=API(), governance=governance, request=req, run=run, journal=journal, keeper=keeper,
                prepared=prepared, credential_limit=3000, guard=Guard(), clock=lambda: 1300)
    return ag, args, sts_calls, keeper, journal


@pytest.mark.parametrize("mutation", [None, "activation", "preparation", "delegation", "ancestry", "machine", "membership",
                                      "session-document"])
def test_closed_ready_capability_checks_everything_before_sts(monkeypatch, mutation):
    ag, args, sts_calls, keeper, journal = _closed_ready_capability_case(monkeypatch, mutation)
    if mutation:
        expected = "except DateLessThan" if mutation == "session-document" else None
        with pytest.raises(ValueError, match=expected):
            ag.closed_ready_capability(**args)
        assert sts_calls == [] and journal._failed is True
        assert keeper.uncertainty() == [{"kind": "context-failed"}]
        return
    broker = ag.closed_ready_capability(**args)
    assert type(broker) is ag.ClosedReadyBroker and keeper._contexts == [broker]
    assert len(sts_calls) == 1 and sts_calls[0][2]["RoleSessionName"] == "promotion-fence-r1"
    assert keeper.uncertainty() == []


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
                                   prepared=lr.PreparedFence(), credential_limit=3000, guard=Guard())


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
    journal = _journal_with()
    journal._observation_bytes = {"a" * 64: b'{"observed":true}\n'}
    keeper.attach(journal)
    seen = []
    label, original = keeper._terminal_validators["routing"]
    keeper._terminal_validators["routing"] = (label, lambda source, **kw: seen.append(kw["observations"]) or original(source, **kw))
    files = keeper.finish(_terminal_reference(keeper))
    assert seen == [{"a" * 64: b'{"observed":true}\n'}]
    assert c.loads(files["terminal.json"], canonical=True)["promotion_status"] == "accepted"


def _keeper_loop_case(*, attach=None):
    """Connected keeper loop over the real Keeper/Lease/finish chain.

    The API window is reached only through keeper.lease.checkpoint validated by
    checkpoint_transition (inside _accepted_terminal_case); the event producer,
    publication and closed-ready handler are external fakes. Terminal validators
    are the SYNTHETIC labelled ones (item 8).
    """
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store = _accepted_terminal_case()
    reference = _terminal_reference(keeper)
    events = [{"kind": "closed-ready", "reference": {"fixture": "closed-ready"}}, None, {"kind": "terminal", "reference": reference}]
    seen, handled, published, slept = [], [], [], []
    def next_event(window):
        seen.append(window["stage"])
        return events.pop(0)
    def handler(current, event_reference):
        assert current is keeper and event_reference == {"fixture": "closed-ready"}
        handled.append(event_reference)
        if attach is not None:
            current.attach(attach)
    run = lambda: ag.keeper_loop(keeper, next_event=next_event, handlers={"closed-ready": handler},
                                 publish=lambda files: published.append(files) or "receipt", sleep=slept.append)
    return ag, keeper, store, run, seen, handled, published, slept


def test_keeper_loop_dispatches_closed_ready_then_publishes_original_terminal():
    ag, keeper, store, run, seen, handled, published, slept = _keeper_loop_case(attach=_journal_with())
    assert run() == "receipt"
    assert handled == [{"fixture": "closed-ready"}] and slept == [5] and seen[0] == "final"
    assert store.get()[0]["status"] == "released" and len(published) == 1
    assert set(published[0]) == {"checkpoint.json", "terminal.json", "lease.json"}
    assert c.loads(published[0]["terminal.json"], canonical=True)["promotion_status"] == "accepted"


@pytest.mark.parametrize("context", ["pending", "unknown", "inflight", "failed"])
def test_keeper_loop_keeps_lease_held_while_dispatch_is_uncertain(context):
    journal = _journal_with(**{"pending": {"pending": [{"kind": "intent"}]}, "unknown": {"unknown": [{"kind": "lost"}]},
                               "inflight": {"inflight": {"kind": "call"}}, "failed": {"failed": True}}[context])
    ag, keeper, store, run, _, handled, published, _ = _keeper_loop_case(attach=journal)
    with pytest.raises(ValueError, match="unresolved SDK uncertainty; lease remains held"):
        run()
    assert handled and published == [] and store.get()[0]["status"] == "held"


def test_keeper_loop_capability_failure_holds_lease_and_never_publishes():
    ag, keeper, store, _, _, _, published, _ = _keeper_loop_case()
    def failing(current, reference):
        journal = _journal_with()
        current.attach(journal)
        journal._failed = True
        raise ValueError("closed-ready capability refused before STS")
    events = [{"kind": "closed-ready", "reference": {}}, {"kind": "terminal", "reference": {}}]
    with pytest.raises(ValueError, match="capability refused"):
        ag.keeper_loop(keeper, next_event=lambda window: events.pop(0), handlers={"closed-ready": failing},
                       publish=published.append, sleep=lambda s: None)
    assert store.get()[0]["status"] == "held" and published == [] and keeper.uncertainty() == [{"kind": "context-failed"}]
    with pytest.raises(ValueError, match="unresolved SDK uncertainty"):
        keeper.finish(_terminal_reference(keeper))


@pytest.mark.parametrize("event", [{"kind": "advance", "reference": {}}, {"kind": "close-drain", "reference": {}},
                                   {"kind": "terminal"}, {"kind": "terminal", "reference": {}, "extra": 1}])
def test_keeper_loop_refuses_stage_advancement_and_open_events(event):
    ag, keeper, store, _, _, _, published, _ = _keeper_loop_case()
    with pytest.raises(ValueError):
        ag.keeper_loop(keeper, next_event=lambda window: event, handlers={"closed-ready": lambda *a: pytest.fail("no dispatch")},
                       publish=published.append, sleep=lambda s: None)
    assert store.get()[0]["status"] == "held" and published == []


@pytest.mark.parametrize("handlers", [{}, {"closed-ready": None, "close-drain": None}, {"close-drain": None}])
def test_keeper_loop_connects_only_closed_ready(handlers):
    ag, keeper, store, _, _, _, _, _ = _keeper_loop_case()
    with pytest.raises(ValueError, match="closed keeper handlers"):
        ag.keeper_loop(keeper, next_event=lambda window: pytest.fail("no event before handler check"), handlers=handlers,
                       publish=None, sleep=None)


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


def test_run_closed_ready_admits_capability_before_any_adapter_child(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag
    ag_mod, args, sts_calls, _, journal = _closed_ready_capability_case(monkeypatch)
    keeper, _ = _accepted_terminal_case()
    order = []
    def capability(*, journal, keeper, guard):
        assert type(guard) is ag.KeeperGuard and journal._guard is guard and any(item is journal for item in keeper._contexts)
        order.append("capability")
        journal._broker = ag.ClosedReadyBroker.__new__(ag.ClosedReadyBroker)
    monkeypatch.setattr(ag, "invoke_adapter", lambda **kwargs: order.append("adapter") or kwargs["journal"])
    request_raw = c.canonical(journal._request)
    result = ag.run_closed_ready(keeper=keeper, request_raw=request_raw, owner=journal._request["owner"] | journal._identity,
        window=journal._request["stage"] | journal._identity, inputs=journal._inputs, activation_sha256=journal._request["activation_sha256"],
        capability=capability, product="product", source=journal._request["source_sha"], manifest={}, manifest_sha256="0" * 64, timeout=120)
    assert order == ["capability", "adapter"] and type(result) is ag.AdapterJournal
    def refusing(*, journal, keeper, guard):
        journal._failed = True
        raise ValueError("capability refused")
    order.clear()
    with pytest.raises(ValueError, match="capability refused"):
        ag.run_closed_ready(keeper=keeper, request_raw=request_raw, owner=journal._request["owner"] | journal._identity,
            window=journal._request["stage"] | journal._identity, inputs=journal._inputs,
            activation_sha256=journal._request["activation_sha256"], capability=refusing, product="product",
            source=journal._request["source_sha"], manifest={}, manifest_sha256="0" * 64, timeout=120)
    assert order == [] and {"kind": "context-failed"} in keeper.uncertainty()


@pytest.mark.parametrize("validators,events,message", [
    (None, None, "terminal validator unavailable; lifecycle disabled"),
    ({"quiescence": object()}, None, "terminal validator unavailable; lifecycle disabled"),
    ({"quiescence": object(), "routing": object(), "foreign": object()}, None, "terminal validator unavailable"),
    ({"quiescence": object(), "routing": object()}, None, "keeper event producer not connected; lifecycle disabled"),
])
def test_execute_is_disabled_by_default_before_any_aws_lease_or_sts(monkeypatch, validators, events, message):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr
    assert ag.TERMINAL_VALIDATORS == {} and ag.KEEPER_EVENT_SOURCE is None
    monkeypatch.setattr(lr, "AWS", lambda *a, **kw: pytest.fail("execute must refuse before AWS"))
    monkeypatch.setattr(lr, "S3LeaseStore", lambda *a, **kw: pytest.fail("execute must refuse before the lease store"))
    monkeypatch.setattr(lr, "oidc_credentials", lambda *a, **kw: pytest.fail("execute must refuse before STS"))
    monkeypatch.setattr(ag, "Keeper", lambda *a, **kw: pytest.fail("execute must refuse before the keeper"))
    monkeypatch.setattr(ag, "authenticate_adapter_closure", lambda *a: pytest.fail("enablement precedes adapter reads"))
    with pytest.raises(ValueError, match=message):
        ag.execute(({}, {"source_sha": "b" * 40}, {}, None, {}, {}), validators=validators, event_source=events)


def test_application_main_execute_reaches_only_the_disabled_execute(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr, session_owner
    admitted = ({}, {"source_sha": "b" * 40}, {}, None, {}, {})
    monkeypatch.setattr(lr, "admission", lambda role: admitted)
    monkeypatch.setattr(session_owner, "application_fragment", lambda governance, now: None)
    monkeypatch.setattr(lr, "AWS", lambda *a, **kw: pytest.fail("execute must refuse before AWS"))
    with pytest.raises(ValueError, match="terminal validator unavailable; lifecycle disabled"):
        ag.main(["execute"])
