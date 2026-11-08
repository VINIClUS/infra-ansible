"""P1/P2 regressions over the real gate with offline HTTP/SDK/process boundaries."""
import copy
import io
import shutil
import time
from email.utils import formatdate
from types import SimpleNamespace

import pytest
from fixtures.cnesdata_session_chain import OwnerChain
from fixtures.cnesdata_outputs import fixture
from tools.cnesdata_delivery import contract as c, runtime
from tools.cnesdata_delivery.aws_boundary import AWS

KEY = "cnesdata/prod/opentofu.tfstate"
MODES = ("unit", "recovery", "audit")
REVISIONS = {mode: f"arn:aws:ecs:us-east-2:111122223333:task-definition/processor-{mode}:2" for mode in MODES}


def saved(revisions=REVISIONS):
    return {"variables": {f"scheduler_{mode}_task_definition_arn": {"value": revisions[mode]} for mode in ("recovery", "audit")}}


def prior(revisions=REVISIONS):
    return {"lineage": "original", "serial": 3, "outputs": {"processor_task_definition_arns": {"value": revisions}}, "resources": []}


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_scheduler_rejects_stale_routes_even_when_candidate_and_drift_agree(mode):
    plan = saved()
    plan["variables"][f"scheduler_{mode}_task_definition_arn"]["value"] = REVISIONS[mode].replace(":2", ":1")
    plan["output_changes"] = {"processor_task_definition_arns": {"after": {m: a.replace(":2", ":3") for m, a in REVISIONS.items()}}}
    with pytest.raises(ValueError, match="scheduler"):
        c.scheduler_preflight(plan, prior())


def test_scheduler_uses_prior_state_and_resolved_defaults():
    plan = saved()
    plan["output_changes"] = {"processor_task_definition_arns": {"after": {m: a.replace(":2", ":3") for m, a in REVISIONS.items()}}}
    c.scheduler_preflight(plan, prior())


@pytest.mark.parametrize("output", [None, {}, {"unit": REVISIONS["unit"]}, {"unit": "unknown", "recovery": REVISIONS["recovery"], "audit": REVISIONS["audit"]}])
def test_scheduler_partial_unknown_or_missing_established_output_refused(output):
    state = prior(output)
    state["resources"] = [{"mode": "managed", "type": "aws_ecs_task_definition", "instances": [{"attributes": {"arn": REVISIONS["unit"]}}]}]
    with pytest.raises(ValueError, match="scheduler"):
        c.scheduler_preflight(saved(), state)


@pytest.mark.parametrize("output", ["absent", None, {}])
def test_first_phase_a_after_bootstrap_accepts_only_null_resolved_inputs(output):
    state = prior(output)
    if output == "absent":
        state["outputs"] = {}
    c.scheduler_preflight(saved({"recovery": None, "audit": None}), state)
    with pytest.raises(ValueError, match="scheduler"):
        c.scheduler_preflight(saved(), state)


@pytest.mark.parametrize("kind", ["aws_ecs_task_definition", "aws_scheduler_schedule"])
def test_missing_output_cannot_hide_existing_revisions_or_schedulers(kind):
    state = prior(None)
    state["resources"] = [{"mode": "managed", "type": kind, "instances": [{"attributes": {}}]}]
    with pytest.raises(ValueError, match="scheduler"):
        c.scheduler_preflight(saved({"recovery": None, "audit": None}), state)


@pytest.mark.parametrize("variables", [{}, {"scheduler_recovery_task_definition_arn": {"value": None}}, {"scheduler_recovery_task_definition_arn": {}, "scheduler_audit_task_definition_arn": {"value": None}}])
def test_unresolved_scheduler_variables_are_not_caller_defaults(variables):
    with pytest.raises(ValueError, match="scheduler"):
        c.scheduler_preflight({"variables": variables}, None)


@pytest.mark.parametrize("version", [None, "", "null"])
def test_existing_state_without_real_version_refused(version):
    aws = AWS.__new__(AWS)
    aws.governance = {"state_bucket": "state", "account_id": "111122223333"}
    aws.call = lambda *args, **kwargs: {"Body": io.BytesIO(b"state"), "ETag": "same", "ContentLength": 5, "VersionId": version}
    with pytest.raises(ValueError, match="version"):
        aws.get_state()


def test_same_getobject_preserves_actual_version_and_etag_commitment():
    aws = AWS.__new__(AWS)
    aws.governance = {"state_bucket": "state", "account_id": "111122223333"}
    calls = []
    def get(service, operation, **kwargs):
        calls.append((service, operation, kwargs))
        return {"Body": io.BytesIO(b"same"), "ETag": "same", "ContentLength": 4, "VersionId": "V17" if len(calls) == 1 else "V18"}
    aws.call = get
    raw1, meta1 = aws.get_state()
    raw2, meta2 = aws.get_state()
    assert raw1 == raw2 == b"same"
    assert meta1 == {"status": "present", "version_id": "V17", "etag_sha256": c.sha(b"same")}
    assert meta2 == meta1 | {"version_id": "V18"}
    assert len(calls) == 2
    assert calls[0] == ("s3", "get_object", {"Bucket": "state", "Key": KEY, "ExpectedBucketOwner": "111122223333"})


def test_true_initial_absence_has_closed_marker():
    aws = AWS.__new__(AWS)
    aws.governance = {"state_bucket": "state", "account_id": "111122223333"}
    def missing(*args, **kwargs):
        error = ValueError("missing")
        error.response = {"Error": {"Code": "NoSuchKey"}}
        raise error
    aws.call = missing
    assert aws.get_state(absent=True) == (None, {"status": "absent", "version_id": None, "etag_sha256": None})
    with pytest.raises(ValueError):
        aws.get_state()


class CheckpointChain(OwnerChain):
    """Retain real producer gates; simulate only external observation/processes."""
    def __init__(self, monkeypatch, root, *, established=False):
        self.version, self.failure = "V17", False
        super().__init__(monkeypatch, root)
        self.final_state, _, self.certificate, _, _ = fixture()
        attrs = self.final_state["resources"][0]["instances"][0]["attributes"]
        plan = c.loads(self.plan_files["plan.json"], state=True)
        plan["resource_changes"][0]["change"]["after"] = attrs
        plan.update(saved() if established else saved({"recovery": None, "audit": None}))
        self.plan_files["plan.json"] = c.canonical(plan)
        self.expected = {"Table": attrs}
        self.gov["readbacks"] = [{"service": "dynamodb", "operation": "describe_table", "parameters": {"TableName": "fixture"}, "expected_sha256": c.sha(c.canonical(self.expected))}]
        self.gov["drift_matrix"]["after"] = [{"address": "aws_acm_certificate.static_web", "attribute": name, "readback": 0, "path": ["Table", name], "encoding": "identity"} for name in attrs]
        if established:
            self.final_state.update(lineage="original", serial=4)
            self.objects[self.gov["state_bucket"], KEY] = c.canonical(prior()), "same-etag"
        monkeypatch.setattr(runtime.subprocess, "Popen", self.process)
        self.configure("plan", 1)

    def sdk(self, service, operation, parameters):
        if service == "dynamodb" and hasattr(self, "expected"):
            return self.expected | {"ResponseMetadata": {"HTTPHeaders": {"date": formatdate(time.time(), usegmt=True)}, "RequestId": "checkpoint-readback"}}
        if service == "acm":
            return {"Certificate": self.certificate, "ResponseMetadata": {"HTTPHeaders": {"date": formatdate(time.time(), usegmt=True)}, "RequestId": "checkpoint-acm"}}
        result = super().sdk(service, operation, parameters)
        if service == "s3" and operation == "get_object" and parameters["Key"] == KEY:
            result["VersionId"] = self.version
        return result

    def process(self, command, **kwargs):
        if len(command) > 1 and command[1] == "apply":
            self.commands.append(list(command))
            attempt = [c.loads(raw) for (_, key), (raw, _) in self.objects.items() if key.endswith("/2/1/applied/attempt.json")]
            assert len(attempt) == 1
            assert attempt[0]["state_object_before"]["version_id"] == ("V17" if self.established else None)
            time.sleep(1.1)  # utc commitments have whole-second precision, as in the existing composed witness.
            self.objects[self.gov["state_bucket"], KEY] = c.canonical(self.final_state), "applied-etag"
            self.version = "V18"
            return SimpleNamespace(pid=1 << 30, returncode=1 if self.failure else 0, poll=lambda: 1 if self.failure else 0)
        return super().process(command, **kwargs)

    def plan_and_admit(self):
        self.established = (self.gov["state_bucket"], KEY) in self.objects
        runtime.execute("plan")
        self.reference = self.planned()
        shutil.rmtree(self.product / "infra/opentofu/env/prod/.terraform")
        self.configure("deploy", 2, self.reference)


def applies(chain):
    return [cmd for cmd in chain.commands if len(cmd) > 1 and cmd[1] == "apply"]


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_composed_stale_scheduler_stops_before_apply(monkeypatch, tmp_path, mode):
    chain = CheckpointChain(monkeypatch, tmp_path, established=True)
    plan = c.loads(chain.plan_files["plan.json"], state=True)
    plan["variables"][f"scheduler_{mode}_task_definition_arn"]["value"] = REVISIONS[mode].replace(":2", ":1")
    chain.plan_files["plan.json"] = c.canonical(plan)
    chain.plan_and_admit()
    with pytest.raises(ValueError, match="scheduler"):
        runtime.execute("deploy")
    assert not applies(chain)


def test_composed_same_bytes_etag_new_version_stops_apply(monkeypatch, tmp_path):
    chain = CheckpointChain(monkeypatch, tmp_path, established=True)
    chain.plan_and_admit()
    chain.version = "V18"
    with pytest.raises(ValueError, match="version|checkpoint"):
        runtime.execute("deploy")
    assert not applies(chain)


@pytest.mark.parametrize("established", [False, True])
def test_composed_exact_version_applies_once_and_retry_is_read_only(monkeypatch, tmp_path, established):
    chain = CheckpointChain(monkeypatch, tmp_path, established=established)
    chain.plan_and_admit()
    runtime.execute("deploy")
    assert len(applies(chain)) == 1
    chain.runs[c.REPOSITORY, 2].update(status="completed", conclusion="success")
    commands, objects = copy.deepcopy(chain.commands), copy.deepcopy(chain.objects)
    runtime.execute("deploy")
    assert chain.commands == commands and chain.objects == objects
    chain.version = "V19"
    with pytest.raises(ValueError, match="version|checkpoint"):
        runtime.execute("deploy")
    assert chain.commands == commands and chain.objects == objects


def test_partial_apply_retains_durable_original_state_version(monkeypatch, tmp_path):
    chain = CheckpointChain(monkeypatch, tmp_path, established=True)
    chain.plan_and_admit()
    chain.failure = True
    with pytest.raises(ValueError):
        runtime.execute("deploy")
    assert len(applies(chain)) == 1
    attempt = [c.loads(raw) for (_, key), (raw, _) in chain.objects.items() if key.endswith("/2/1/applied/attempt.json")][0]
    assert attempt["state_object_before"]["version_id"] == "V17"
    checkpoint = [c.loads(raw) for (_, key), (raw, _) in chain.objects.items() if key.endswith("/1/1/planned/checkpoint.json")][0]
    assert checkpoint["state_object"]["version_id"] == "V17"
    assert not any(key.endswith("/2/1/applied/checkpoint.json") for _, key in chain.objects)
    assert not any(len(cmd) > 1 and cmd[1] in {"restore", "import"} for cmd in chain.commands)


@pytest.mark.parametrize("member", ["checkpoint.json", "lease.json"])
def test_swapped_original_checkpoint_or_lease_stops_before_apply(monkeypatch, tmp_path, member):
    chain = CheckpointChain(monkeypatch, tmp_path, established=True)
    chain.plan_and_admit()
    key = next(key for bucket, key in chain.objects if key.endswith("/1/1/planned/" + member))
    raw, etag = chain.objects[chain.gov["evidence_bucket"], key]
    chain.objects[chain.gov["evidence_bucket"], key] = raw + b" ", etag
    with pytest.raises(ValueError, match="checkpoint|lease|recovery_required"):
        runtime.execute("deploy")
    assert not applies(chain)


def test_first_phase_a_after_bootstrap_reaches_exact_apply_with_null_defaults(monkeypatch, tmp_path):
    chain = OwnerChain(monkeypatch, tmp_path, purpose="phase-a")
    chain.objects[chain.gov["state_bucket"], KEY] = c.canonical({"lineage": "bootstrap", "serial": 1,
        "resources": [], "outputs": {"cloudfront_distribution_id": {"value": "previous-bootstrap"}}}), "bootstrap-etag"
    runtime.execute("plan")
    reference = chain.planned()
    shutil.rmtree(chain.product / "infra/opentofu/env/prod/.terraform")
    chain.configure("deploy", 2, reference)
    original = chain.process
    def process(command, **kwargs):
        if len(command) > 1 and command[1] == "apply":
            chain.commands.append(list(command))
            raise RuntimeError("reached exact initial Phase A apply boundary")
        return original(command, **kwargs)
    monkeypatch.setattr(runtime.subprocess, "Popen", process)
    with pytest.raises(RuntimeError, match="reached exact initial Phase A"):
        runtime.execute("deploy")
    assert len(applies(chain)) == 1


def test_state_version_changed_during_init_is_refused_before_child(monkeypatch, tmp_path):
    chain = CheckpointChain(monkeypatch, tmp_path, established=True)
    chain.plan_and_admit()
    original = chain.process
    def process(command, **kwargs):
        result = original(command, **kwargs)
        if len(command) > 1 and command[1] == "init":
            chain.version = "V18"
        return result
    monkeypatch.setattr(runtime.subprocess, "Popen", process)
    with pytest.raises(ValueError, match="version|checkpoint"):
        runtime.execute("deploy")
    assert not applies(chain)


def test_original_receipt_bound_to_another_index_is_refused(monkeypatch, tmp_path):
    chain = CheckpointChain(monkeypatch, tmp_path, established=True)
    chain.plan_and_admit()
    record_key = next(key for key, value in chain.artifacts.items() if value[1]["name"] == "cnesdata-planned-receipt-1-1")
    reference, metadata, members, _ = chain.artifacts.pop(record_key)
    receipt = c.loads(members["receipt.json"], canonical=True)
    wrong = next(value[0] for value in chain.artifacts.values() if value[1]["name"] == "fixture")
    receipt.update(index_artifact_id=wrong["artifact_id"], index_artifact_digest=wrong["artifact_digest"])
    chain.add_artifact(1, {"receipt.json": c.canonical(receipt)}, reference["workflow_path"], name=metadata["name"])
    with pytest.raises(ValueError, match="receipt|index|recovery_required"):
        runtime.execute("deploy")
    assert not applies(chain)


def test_actual_state_metadata_missing_cannot_reach_apply(monkeypatch, tmp_path):
    chain = CheckpointChain(monkeypatch, tmp_path, established=True)
    chain.plan_and_admit()
    original = chain.sdk
    def sdk(service, operation, parameters):
        result = original(service, operation, parameters)
        if service == "s3" and operation == "get_object" and parameters["Key"] == KEY:
            result.pop("VersionId")
        return result
    chain.sdk = sdk
    with pytest.raises(ValueError, match="version"):
        runtime.execute("deploy")
    assert not applies(chain)


@pytest.mark.parametrize("member", ["checkpoint.json", "lease.json"])
def test_original_planned_checkpoint_is_independently_authenticated(monkeypatch, tmp_path, member):
    chain = CheckpointChain(monkeypatch, tmp_path, established=True)
    chain.plan_and_admit()
    governance, descriptor, api, _, _, _, index = runtime.admission("deploy")
    aws = AWS(governance)
    prefix = runtime._prefix(governance, "a" * 40, 1, 1, "planned")
    envelope_raw, _ = aws.get(governance["evidence_bucket"], prefix + "envelope.json")
    envelope = c.loads(envelope_raw, canonical=True)
    checkpoint = runtime._planned_checkpoint(aws, api, governance, index, descriptor["payload_artifact"], envelope)
    assert checkpoint["state_object"]["version_id"] == "V17"
    # Replace private history without changing its authenticated external receipt.
    raw, etag = chain.objects[governance["evidence_bucket"], prefix + member]
    chain.objects[governance["evidence_bucket"], prefix + member] = raw + b" ", etag
    with pytest.raises(ValueError, match="original planned checkpoint|original planned lease"):
        runtime._planned_checkpoint(aws, api, governance, index, descriptor["payload_artifact"], envelope)
    assert not applies(chain)
