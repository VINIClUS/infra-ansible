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
    history = {key: value for key, value in chain.objects.items() if "/1/1/planned/" in key[1]}
    owner = keeper.acquire(preparation_deadline=int(time.time()) + 900)
    assert {key: value for key, value in chain.objects.items() if "/1/1/planned/" in key[1]} == history
    monkeypatch.setattr(aws, "get_state", state_reader)
    current, _ = store.get()
    assert reads == [original, original]
    assert owner["generation"] == 1 and owner["run_id"] == 44
    assert keeper.predecessor["lease"]["run_id"] == 1
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


@pytest.mark.parametrize("mutation", [None, "name", "attempt", "source", "created", "bytes", "status"])
def test_lifecycle_input_authenticates_original_completed_job_and_archive(mutation):
    import io
    import zipfile
    from tools.cnesdata_delivery.provenance import lifecycle_artifact
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("index.json", c.canonical({"version": 1}))
    raw = output.getvalue()
    run = {"id": 44, "run_attempt": 2, "head_sha": "b" * 40, "event": "workflow_dispatch",
           "repository": {"full_name": c.REPOSITORY}, "path": ".github/workflows/promote-production.yml"}
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
            artifact_name="lifecycle-phase-b-apply")
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
        chain.runs[c.REPOSITORY, 1]["conclusion"] = "failure"
    else:
        key = next(key for key in chain.objects if "/1/1/planned/" in key[1] and key[1].endswith("checkpoint.json"))
        raw, version = chain.objects[key]
        chain.objects[key] = (raw + b"changed", version)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    binding |= _current_caller(chain.gov, binding)
    keeper = Keeper(store, binding, lambda previous: authenticated_previous(aws, api, chain.gov, previous), api=api, governance=chain.gov)
    with pytest.raises(ValueError):
        keeper.acquire(preparation_deadline=int(time.time()) + 900)
    assert store.get() == (original, etag)


def _admitted_terminal_keeper(store, binding, historical, proof):
    """Terminal unit setup only; real historical admission is tested separately."""
    from tools.cnesdata_delivery import lifecycle_contract as lc
    keeper = Keeper(store, binding, lambda previous: pytest.fail("terminal fixture must not enter history"),
                    api=None, governance=None, authenticate_terminal=lambda reference, owner, window: proof,
                    clock=lambda: 1000, monotonic=lambda: 1000)
    previous = store.get()[0]
    keeper.predecessor = {"lease": previous, "checkpoint": historical, "raw": c.canonical(historical)}
    keeper.lease.previous_success = lambda previous: True  # Test-only already-admitted lease setup.
    keeper.lease.acquire()
    keeper.lease.checkpoint({"sequence": 0, "preparation_deadline": 1900, "close": None,
        "fixed_deadline": None, "input_deadline": None, "stage": "application-prepare", "admitted_at": 1000,
        "deadline": 1900, "decision": None, "checkpoint_sha256": c.sha(c.canonical(historical)),
        "predecessor_sha256": "a" * 64, **lc.application_identity(binding)})
    keeper.last_renewed = 1000
    return keeper, lc.owner_binding(keeper.lease.check())


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
    historical = {"state_after": {"lineage": "prior", "serial": 1, "state_sha256": "a" * 64}, "state_object": {"VersionId": "prior"}}
    store = Store()
    store.put({"status": "released", "checkpoint_sha256": c.sha(c.canonical(historical)), "run_id": 1}, None)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    proof = {}
    keeper, owner = _admitted_terminal_keeper(store, binding, historical, proof)
    checkpoint = {"owner": owner, "state": historical["state_after"], "state_object": historical["state_object"]}
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
        with pytest.raises(ValueError): keeper.finish({"artifact_id": 1})

        assert store.get() == before
    else:
        files = keeper.finish({"artifact_id": 1})
        terminal = c.loads(files["terminal.json"], canonical=True)
        assert terminal["promotion_status"] == "accepted"
        assert terminal["coordination_status"] == "quiescent-released"
        assert store.get()[0]["status"] == "released"
        assert store.get()[0]["checkpoint_sha256"] == c.sha(files["checkpoint.json"])
        assert c.loads(files["lease.json"], canonical=True)["generation"] == 1
        with pytest.raises(ValueError): keeper.finish({"artifact_id": 1})


def _terminal_fixture(*, failed=False, prepare_failure=False, current_caller=False):
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
    historical = {"state_after": {"lineage": "prior", "serial": 1, "state_sha256": "a" * 64},
                  "state_object": {"status": "present", "version_id": "prior", "etag_sha256": "f" * 64}}
    store = Store()
    store.put({"status": "released", "checkpoint_sha256": c.sha(c.canonical(historical)), "run_id": 1}, None)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": "c" * 64, "session_sha256": "d" * 64, "lifecycle_version": 1}
    if current_caller:
        binding |= _current_caller({}, binding)
    proof = {}
    keeper, owner = _admitted_terminal_keeper(store, binding, historical, proof)
    checkpoint = {"owner": owner, "state": historical["state_after"], "state_object": historical["state_object"]}
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
    files = keeper.finish({"artifact_id": 1})
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
            assert bucket == "evidence" and key.startswith("cnesdata/prod/evidence/lifecycle/" + "b" * 40 + "/44/1/terminal/")
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
                    api=api, governance=governance, clock=lambda: 1100, monotonic=lambda: 1100)
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
    assert objects == original_bytes


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
    from fixtures.cnesdata_session_chain import OwnerChain
    from tools.cnesdata_delivery.session_policy import predecessor_keys
    chain = OwnerChain(monkeypatch, tmp_path)
    runtime.execute("plan")
    chain.planned()
    aws, original_api = runtime.AWS(chain.gov | {"role": "plan"}), GitHub()
    store = S3LeaseStore(aws)
    previous, _ = store.get()
    authenticated = runtime.previous_success(aws, original_api, chain.gov, previous, details=True)
    selector = {"protocol": "legacy-infra", "source_sha": authenticated["envelope"]["plan"]["source_sha"], "run_id": 1, "run_attempt": 1,
                "status": "planned", "purpose": "acm-certificate"}
    reference = {"predecessor_version": 1, "protocol": "legacy-infra", "repository": c.REPOSITORY,
                 "source_sha": authenticated["envelope"]["plan"]["source_sha"], "run_id": 1, "run_attempt": 1,
                 "owner_sha256": c.sha(previous["owner"].encode()), "generation": previous.get("generation"),
                 "session_sha256": previous["session_sha256"], "checkpoint_sha256": previous["checkpoint_sha256"],
                 "artifact_id": authenticated["artifact_id"], "artifact_digest": authenticated["artifact_digest"],
                 "producer_job_id": 91, "producer_name": "plan / execute", "objects": []}
    for key in predecessor_keys(chain.gov, selector):
        raw, _ = aws.get(chain.gov["evidence_bucket"], key)
        reference["objects"].append({"name": key.rsplit("/", 1)[1], "sha256": c.sha(raw), "size": len(raw)})
    chain.gov.update(predecessor_read=selector, lifecycle_predecessor=reference)
    class API:
        def read(self, path, **kwargs):
            if path.endswith("/jobs/91"):
                return {"run_id": 1, "run_attempt": 1, "head_sha": authenticated["envelope"]["plan"]["source_sha"], "name": "plan / execute",
                        "status": "completed", "conclusion": "failure" if job_failed else "success",
                        "started_at": c.utc(chain.now - 5), "completed_at": c.utc(chain.now + 5)}
            return original_api.read(path, **kwargs)
        def artifact(self, *args, **kwargs):
            return original_api.artifact(*args, **kwargs)
    api = API()
    return chain, aws, api, store, previous, reference


@pytest.mark.parametrize("mutation", [None, "generation", "job", "checkpoint-bytes", "current-run", "entry-replay"])
def test_original_receipt_governs_keeper_and_exact_first_plan_checkpoint(monkeypatch, tmp_path, mutation):
    from tools.cnesdata_delivery.application_gate import authenticated_previous
    from tools.cnesdata_delivery.lifecycle_runtime import authenticate_predecessor, historical_checkpoint
    chain, aws, api, store, previous, reference = _legacy_history_fixture(monkeypatch, tmp_path, job_failed=mutation == "job")
    if mutation == "generation": reference["generation"] = 5
    if mutation == "checkpoint-bytes":
        key = next(k for k in chain.objects if "/1/1/planned/" in k[1] and k[1].endswith("checkpoint.json"))
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
    if mutation == "current-run": record.update(run_id=1, run_attempt=1)
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
    if mutation == "same-run": current["id"] = 1
    assert callable(getattr(lifecycle_runtime, "authenticate_application_predecessor", None)), "public history required before STS"
    before = store.get()
    if mutation is None:
        assert lifecycle_runtime.authenticate_application_predecessor(api, chain.gov, current) == reference
        assert reference["protocol"] == "legacy-infra" and chain.gov["predecessor_read"]["purpose"] == "acm-certificate"
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


def _fence_contract_case():
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
    phase_a = {"source_sha": "9" * 40, "source_closure_sha256": "9" * 64, "release_id": "original-release", "canary_id": "r1",
        "candidate_sha256": "1" * 64, "plan_binary_sha256": "2" * 64, "plan_json_sha256": "3" * 64, "inputs_sha256": "4" * 64,
        "plan_receipt": {"plan_binding_sha256": "a" * 64, "consumed_plan_artifact": {
            "artifact_id": 41, "artifact_sha256": "b" * 64, "run_id": 6, "run_attempt": 1}},
        "state": {"lineage": "original-lineage", "serial": 1, "state_sha256": "5" * 64},
        "files": {name: origin(name, "9" * 40, 7, "6" * 64) for name in lc.FENCE_PHASE_A_FILES}}
    name = "cnesdata-prod-promotion-fence-operator"
    role = {"schema_version": 1, "role_arn": fragment["delegations"]["fence_operator"], "role_name": name, "role_id": "AROAORIGINAL",
        "policy_name": name + "-gate", "release_id": "r1", "session_name": "promotion-fence-r1", "max_session_duration": 3600,
        "tags": {"ReleaseId": "r1"}, "trust": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"AWS": fragment["application_role_arn"]}, "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:RoleSessionName": "promotion-fence-r1"}}}]},
        "policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}}
    projection = {key: role[key] for key in ("role_arn", "role_name", "role_id", "policy_name", "trust", "policy", "max_session_duration", "tags")}
    role.update(original_projection_sha256=c.sha(c.canonical(projection)), current_projection_sha256=c.sha(c.canonical(projection)))
    checkpoint = {"state": {"lineage": "original-lineage", "serial": 2, "state_sha256": "7" * 64},
        "state_object": {"status": "present", "version_id": "current-version", "etag_sha256": "8" * 64},
        "owner": owner, "purpose": "application-prepare", "plan_sha256": "a" * 64, "readbacks": []}
    checkpoint_sha = c.sha(c.canonical(checkpoint))
    chain = {"schema_version": 1, "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
        "anchor_sha256": phase_a["files"]["checkpoint.json"]["sha256"], "head_sha256": checkpoint_sha,
        "entries": [{"sequence": 0, "checkpoint_sha256": checkpoint_sha, "previous_checkpoint_sha256": phase_a["files"]["checkpoint.json"]["sha256"],
            "state": checkpoint["state"], "state_object": checkpoint["state_object"], "origin": origin("checkpoint.json", owner["source_sha"], owner["run_id"], checkpoint_sha)}]}
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
        "direction": "advance", "plan_sha256": "a" * 64, "inputs_sha256": "b" * 64, "checkpoint_sha256": "6" * 64,
        "delta": {"purpose": "application-prepare", "direction": "advance", "mode": "operational", "before": {}, "original": {}, "created": {}, "expected_changes_sha256": "f" * 64},
        "drift_matrix": {}, "readbacks": {"before": [], "after": []}}, "fence-role.json": role,
        "fence-origins.json": {"schema_version": 1, "phase_a": phase_a, "current_source_sha": owner["source_sha"], "current_source_closure_sha256": "b" * 64,
            "current_plan": {"source_sha": owner["source_sha"], "run_id": owner["run_id"], "run_attempt": owner["run_attempt"], "step": "prepare-plan",
                "index_sha256": "d" * 64, "plan_binary_sha256": "a" * 64, "plan_json_sha256": "c" * 64, "inputs_sha256": "b" * 64},
            "projection_source_files": [{"path": "infra/opentofu/modules/runtime-iam/promotion.tf", "sha256": "e" * 64}]},
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
    return payloads, manifest, dict(owner=owner, fragment=fragment, activation_sha256="1" * 64, producer=producer, preparation=preparation), encode


@pytest.mark.parametrize("mutation", [None, "old-fragment", "owner-bool", "plan-producer", "source", "extra-file", "missing-original",
    "history-file", "history-hash", "chain-anchor", "lineage", "trust", "readbacks", "evaluation"])
def test_fence_package_contract_separates_historical_source_and_current_owner(mutation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    payloads, manifest, kwargs, encode = _fence_contract_case()
    if mutation == "old-fragment": kwargs["fragment"]["fragment_version"] = 3
    if mutation == "owner-bool": manifest["owner"]["run_attempt"] = True
    if mutation == "plan-producer": manifest["producer"]["workflow_path"] = ".github/workflows/reusable-cnesdata-infra-plan-gate.yml"
    if mutation == "source": payloads["fence-origins.json"]["current_source_sha"] = "9" * 40
    if mutation == "history-file": payloads["fence-origins.json"]["phase_a"]["files"].pop("envelope.json")
    if mutation == "history-hash": payloads["fence-origins.json"]["phase_a"]["plan_receipt"]["consumed_plan_artifact"]["artifact_sha256"] = "not-a-digest"
    if mutation == "chain-anchor":
        payloads["fence-chain.json"]["anchor_sha256"] = "e" * 64
        payloads["fence-chain.json"]["entries"][0]["previous_checkpoint_sha256"] = "e" * 64
    if mutation == "lineage": payloads["fence-chain.json"]["entries"][0]["state"]["lineage"] = "foreign"
    if mutation == "trust": payloads["fence-role.json"]["trust"]["Statement"][0]["Principal"]["AWS"] += "-historical"
    if mutation == "readbacks": payloads["fence-readbacks.json"]["readbacks"] = []
    if mutation == "evaluation": payloads["fence-evaluation.json"]["cases"][0]["observed"] = True
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
                  "gate_shas": {"deploy": producer["workflow_sha"]}}
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
        return lr.fence_prepared_payload(API(), AWS(), governance, request, run, reference, owner=owner, now=1200)
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


def _current_fence_projection_case(mutation=None, serial=2):
    import copy
    from fixtures.cnesdata_delivery_lifecycle import fence_projection_case
    from tools.cnesdata_delivery import lifecycle_contract as lc
    plan, inputs, state, sources, readbacks = fence_projection_case()
    state["serial"] = serial
    _, _, package, _ = _fence_contract_case()
    owner, fragment = package["owner"], package["fragment"]
    original_sources = dict(sources)
    envelope = {"status": "applied", "plan": {"source_sha": "9" * 40, "purpose": "phase-a", "release": {
        "release_id": "release-original", "canary_id": "r1", "candidate_sha256": "1" * 64},
        "phase_a_inputs": {"canary_release_id": "r1", "canary_trusted_principal_arn": fragment["application_role_arn"], "canary_storage_enabled": True}},
        "apply": {"result": "success"}}
    old_checkpoint = {"state_after": {"lineage": "original-lineage", "serial": min(1, serial), "state_sha256": "5" * 64}, "readbacks": readbacks}
    if mutation == "old-principal": envelope["plan"]["phase_a_inputs"]["canary_trusted_principal_arn"] += "-foreign"
    if mutation == "old-policy": readbacks[-1]["observed"]["PolicyDocument"] = {"Version": "2012-10-17", "Statement": []}
    for row in readbacks: row["sha256"] = c.sha(c.canonical(row["observed"]))
    ref = {"protocol": "legacy-infra", "source_sha": "9" * 40, "objects": [
        {"name": "envelope.json", "sha256": c.sha(c.canonical(envelope)), "size": len(c.canonical(envelope))},
        {"name": "checkpoint.json", "sha256": c.sha(c.canonical(old_checkpoint)), "size": len(c.canonical(old_checkpoint))}]}
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
                  "owner": owner, "purpose": "application-prepare", "plan_sha256": c.sha(b"current-saved-plan"), "readbacks": []}
    if mutation == "checkpoint-owner":
        checkpoint["owner"] = copy.deepcopy(owner)
        checkpoint["owner"]["run_attempt"] = True
    checkpoint_raw = c.canonical(checkpoint)
    old_sha, head_sha = c.sha(c.canonical(old_checkpoint)), c.sha(checkpoint_raw)
    chain = {"schema_version": 1, "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
        "anchor_sha256": old_sha, "head_sha256": head_sha, "entries": [{"sequence": 0, "checkpoint_sha256": head_sha,
            "previous_checkpoint_sha256": "f" * 64 if mutation == "ancestry" else old_sha,
            "state": checkpoint["state"], "state_object": checkpoint["state_object"], "origin": {
                "repository": c.REPOSITORY, "source_sha": owner["source_sha"], "run_id": owner["run_id"], "run_attempt": owner["run_attempt"],
                "job_id": 42, "artifact_id": 43, "artifact_digest": "sha256:" + "4" * 64, "producer_name": "prepare / execute",
                "step": "prepare", "name": "checkpoint.json", "sha256": head_sha, "size": len(checkpoint_raw)}}]}
    args = dict(plan_raw=plan_raw, inputs_raw=inputs_raw, state_raw=state_raw, sources=sources, original_sources=original_sources,
        source_sha=owner["source_sha"], activation_source_sha="f" * 40 if mutation == "activation" else owner["source_sha"],
        current_index=current_index, checkpoint=checkpoint, chain=chain, historical=historical, owner=owner, fragment=fragment)
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
    chain["entries"][-1]["origin"].update(run_id=1, run_attempt=1)
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
    payloads, _, kwargs, encode = _fence_contract_case()
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
