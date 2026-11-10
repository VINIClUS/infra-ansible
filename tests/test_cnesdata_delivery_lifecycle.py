"""Continuous original owner, bounded phases and exact checkpoint transitions."""
import copy
import importlib

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.coordination_lease import Lease


class Store:
    def __init__(self):
        self.value, self.etag = None, None
        self.writes = 0

    def get(self):
        return copy.deepcopy(self.value), self.etag

    def put(self, value, etag):
        assert etag == self.etag
        self.writes += 1
        self.etag = str(self.writes)
        self.value = copy.deepcopy(value)
        return self.etag


def api():
    spec = importlib.util.find_spec("tools.cnesdata_delivery.lifecycle_contract")
    assert spec is not None, "lifecycle contract missing"
    return importlib.import_module(spec.name)


def held():
    store, now = Store(), [1000]
    binding = {"repository": c.REPOSITORY, "run_id": 41, "run_attempt": 1,
               "session_sha256": "a" * 64, "source_sha": "b" * 40,
               "release_sha256": "c" * 64, "lifecycle_version": 1}
    lease = Lease(store, binding, clock=lambda: now[0], token="private-owner").acquire()
    return store, now, lease


def test_delegate_tracks_same_owner_across_writer_renewal_without_writing():
    m = api()
    store, now, keeper = held()
    view = m.DelegatedLeaseView(store, m.owner_binding(store.value), clock=lambda: now[0])
    view.check()
    now[0] += 40
    keeper.renew()
    assert view.check()["generation"] == 1
    assert store.writes == 2
    assert not hasattr(view, "acquire") and not hasattr(view, "release")
    store.value["run_attempt"] = 2
    with pytest.raises(ValueError, match="owner"):
        view.check()


def test_generation_is_cas_persisted_and_never_caller_selected():
    api()
    store, now, keeper = held()
    assert store.value["generation"] == 1
    keeper.release("d" * 64)
    next_owner = Lease(store, {k: v for k, v in keeper.binding.items() if k != "generation"},
                       clock=lambda: now[0], previous_success=lambda _: True)
    next_owner.acquire()
    assert store.value["generation"] == 2
    with pytest.raises(ValueError):
        Lease(store, keeper.binding, clock=lambda: now[0]).acquire()


def test_original_phase_deadlines_and_recovery_are_not_rearmed():
    m = api()
    window = {"close": 1000, "fixed_deadline": 2800, "input_deadline": 2900,
              "stage": "api", "admitted_at": 1100, "deadline": 1280,
              "decision": None}
    m.phase_capacity(window, now=1100, credential_deadline=4000, operation_seconds=20)
    with pytest.raises(ValueError):
        m.phase_capacity(window, now=1275, credential_deadline=4000, operation_seconds=20)
    window["fixed_deadline"] = 3000
    with pytest.raises(ValueError):
        m.phase_capacity(window, now=1100, credential_deadline=4000, operation_seconds=20)


def test_unit_closed_cannot_release_keeper():
    m = api()
    terminal = {"kind": "accepted-open", "fence": "CLOSED", "accepted_modes": ["unit"],
                "routes_match": True, "state_clean": True, "quiescent": True,
                "pending": [], "unknown": [], "observed_at": 1200}
    with pytest.raises(ValueError):
        m.terminal_result(terminal, now=1201, deadline=2800)
    terminal.update(fence="OPEN", accepted_modes=["unit", "recovery", "audit"])
    assert m.terminal_result(terminal, now=1201, deadline=2800) == "accepted"
    terminal["unknown"] = ["late-aws-request"]
    with pytest.raises(ValueError):
        m.terminal_result(terminal, now=1201, deadline=2800)


def change(address, before, after, actions):
    return {"address": address, "mode": "managed", "type": address.split(".")[-2],
            "change": {"before": before, "after": after, "actions": actions, "after_unknown": {}}}


def test_c_initial_inverse_rejects_preexisting_resources_and_other_modes():
    m = api()
    address = 'module.schedulers.aws_scheduler_schedule.mode["recovery"]'
    before = {"name": "cnesdata-prod-recovery", "arn": "arn:aws:scheduler:us-east-2:111122223333:schedule/cnesdata-prod-recovery/cnesdata-prod-recovery"}
    plan = {"resource_changes": [change(address, before, None, ["delete"])]}
    approval = {"purpose": "phase-c-recovery", "direction": "converge", "mode": "initial",
                "before": {address: before}, "original": {}, "created": {address: before},
                "expected_changes_sha256": c.sha(c.canonical(plan["resource_changes"]))}
    m.validate_delta(plan, approval)
    approval["original"][address] = before
    with pytest.raises(ValueError, match="original"):
        m.validate_delta(plan, approval)
    approval["original"] = {}
    plan["resource_changes"][0]["address"] = address.replace('"recovery"', '"audit"')
    approval["expected_changes_sha256"] = c.sha(c.canonical(plan["resource_changes"]))
    with pytest.raises(ValueError):
        m.validate_delta(plan, approval)


def test_b_established_cannot_update_iam_or_task_revision():
    m = api()
    address = 'module.processing.aws_sfn_state_machine.processor[0]'
    before = {"definition": '{"TaskDefinition":"unit:1"}', "role_arn": "role"}
    after = before | {"definition": '{"TaskDefinition":"unit:2"}'}
    plan = {"resource_changes": [change(address, before, after, ["update"])]}
    approval = {"purpose": "phase-b", "direction": "advance", "mode": "established",
                "before": {address: before}, "original": {address: before}, "created": {},
                "expected_changes_sha256": c.sha(c.canonical(plan["resource_changes"]))}
    m.validate_delta(plan, approval)
    plan["resource_changes"][0]["change"]["after"]["role_arn"] = "other-role"
    approval["expected_changes_sha256"] = c.sha(c.canonical(plan["resource_changes"]))
    with pytest.raises(ValueError, match="invariant"):
        m.validate_delta(plan, approval)


def test_exact_inverse_session_fits_seven_native_resources_and_preserves_boundaries():
    import json
    from tools.cnesdata_delivery.session_policy import lifecycle_request
    from fixtures.cnesdata_iam_evaluation import effective
    governance = {"account_id": "111122223333", "state_bucket": "cnesdata-prod-state-111122223333",
        "evidence_bucket": "cnesdata-prod-evidence-111122223333", "evidence_prefix": "cnesdata/prod/delivery/",
        "evidence_kms_key_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000001",
        "roles": {"deploy": "arn:aws:iam::111122223333:role/cnesdata-prod-infra-deploy"}}
    resources = [f"arn:aws:{service}:us-east-2:111122223333:{resource}" for service, resource in [
        ("scheduler", "schedule/cnesdata-prod/cnesdata-prod-audit"),
        ("scheduler", "schedule-group/cnesdata-prod-audit"),
        ("events", "rule/cnesdata-prod-audit-failed"),
        ("events", "rule/cnesdata-prod-audit-stopped"),
        ("cloudwatch", "alarm:cnesdata-prod-audit-deadline"),
        ("cloudwatch", "alarm:cnesdata-prod-audit-failure"),
        ("cloudwatch", "alarm:cnesdata-prod-audit-dlq")]]
    request = lifecycle_request(governance, "a" * 40, 12345678901, 12, "deploy", "phase-c-audit-converge",
        direction="converge", delete_resources=resources)
    assert len(request["Policy"]) + len(request["PolicyArns"][0]["arn"]) <= 2048
    session = json.loads(request["Policy"])
    denies = [s for s in session["Statement"] if "NotResource" in s]
    assert denies[0]["NotResource"] == resources
    allow = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    # No new allow is inferred from a denied-resource exception; managed policy remains necessary.
    assert effective(allow, allow, session, "scheduler:DeleteSchedule", resources[0])
    assert not effective(allow, allow, session, "scheduler:DeleteSchedule", resources[0] + "-foreign")
    lease = "arn:aws:s3:::" + governance["state_bucket"] + "/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"
    assert not effective(allow, allow, session, "s3:PutObject", lease)
    assert not effective(allow, allow, session, "s3:DeleteObject", lease)


class ReadbackAWS:
    def __init__(self, responses):
        self.responses, self.calls = iter(responses), []

    def call(self, service, operation, **parameters):
        self.calls.append((service, operation, parameters))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)


class ReadbackGuard:
    def __init__(self):
        self.checks = 0

    def check(self, operation_seconds=1):
        self.checks += 1


def scheduler_inventory(names):
    return {"service": "scheduler", "operation": "list_schedules",
            "parameters": {"GroupName": "cnesdata-prod-audit"}, "absent": False,
            "members": names}


def test_scheduler_group_inventory_follows_every_page_and_rejects_unknown_members():
    from tools.cnesdata_delivery.lifecycle_runtime import readbacks
    pages = [{"Schedules": [{"Name": "cnesdata-prod-audit", "GroupName": "cnesdata-prod-audit"}], "NextToken": "next"},
             {"Schedules": [{"Name": "foreign", "GroupName": "cnesdata-prod-audit"}]}]
    aws, guard = ReadbackAWS(pages), ReadbackGuard()
    with pytest.raises(ValueError, match="unknown schedule"):
        readbacks(aws, [scheduler_inventory(["cnesdata-prod-audit"])], guard)
    assert aws.calls[-1][2]["NextToken"] == "next"
    assert guard.checks >= 4


def test_scheduler_group_inventory_rejects_duplicate_pages_and_unknown_group():
    from tools.cnesdata_delivery.lifecycle_runtime import readbacks
    entry = {"Name": "cnesdata-prod-audit", "GroupName": "cnesdata-prod-audit"}
    with pytest.raises(ValueError, match="duplicate schedule"):
        readbacks(ReadbackAWS([{"Schedules": [entry], "NextToken": "next"}, {"Schedules": [entry]}]),
                  [scheduler_inventory([entry["Name"]])], ReadbackGuard())
    with pytest.raises(ValueError, match="unknown schedule"):
        readbacks(ReadbackAWS([{"Schedules": [entry | {"GroupName": "other"}]}]),
                  [scheduler_inventory([entry["Name"]])], ReadbackGuard())


def test_scheduler_empty_group_proof_and_pending_state_remain_distinct():
    from tools.cnesdata_delivery.lifecycle_runtime import readbacks
    value = readbacks(ReadbackAWS([{"Schedules": []}]), [scheduler_inventory([])], ReadbackGuard())
    assert value[0]["observed"] == {"Schedules": []}
    spec = {"service": "scheduler", "operation": "get_schedule_group",
            "parameters": {"Name": "cnesdata-prod-audit"}, "absent": False}
    with pytest.raises(ValueError, match="DELETING"):
        readbacks(ReadbackAWS([{"State": "DELETING"}]), [spec], ReadbackGuard())


def test_checkpoint_cannot_rearm_same_stage_or_skip_normal_phase():
    m = api()
    window = {"sequence": 1, "preparation_deadline": 1500, "close": 1000, "fixed_deadline": 2800,
              "input_deadline": 3000, "stage": "phase-b", "admitted_at": 1000, "deadline": 1360,
              "decision": None, "checkpoint_sha256": "a" * 64}
    for changed in ({"admitted_at": 1010, "deadline": 1370}, {"stage": "unit"}, {"stage": "application-prepare"}):
        with pytest.raises(ValueError):
            m.checkpoint_transition(window, window | {"sequence": 2} | changed)
    m.checkpoint_transition(window, window | {"sequence": 2, "checkpoint_sha256": "b" * 64})
    m.checkpoint_transition(window, window | {"sequence": 2, "stage": "api", "admitted_at": 1100, "deadline": 1280})


def test_full_infrastructure_closure_authenticates_asl_and_rejects_omission_or_edit(tmp_path):
    import subprocess
    from tools.cnesdata_delivery.lifecycle_runtime import authenticate_infrastructure_closure
    def git(*args):
        return subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True).stdout.decode().strip()
    git("init", "-q")
    files = {"infra/opentofu/env/prod/main.tf": b'module "processing" { source = "../../modules/processing" }',
             "infra/opentofu/modules/processing/main.tf": b'locals { definition = file("${path.module}/state_machine.asl.json") }',
             "infra/opentofu/modules/processing/state_machine.asl.json": b'{"StartAt":"Unit","States":{}}'}
    for name, raw in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    git("add", "infra")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "original closure")
    source = git("rev-parse", "HEAD")
    closure = {name: c.sha(raw) for name, raw in files.items()}
    assert authenticate_infrastructure_closure(tmp_path, source, closure) == files
    missing = dict(closure)
    missing.pop("infra/opentofu/modules/processing/state_machine.asl.json")
    with pytest.raises(ValueError, match="inventory"):
        authenticate_infrastructure_closure(tmp_path, source, missing)
    (tmp_path / "infra/opentofu/modules/processing/state_machine.asl.json").write_bytes(b"changed")
    with pytest.raises(ValueError, match="dirty"):
        authenticate_infrastructure_closure(tmp_path, source, closure)


def test_inverse_update_restores_original_revision_and_accepts_known_nested_masks():
    m = api()
    address = 'module.schedulers.aws_scheduler_schedule.mode["audit"]'
    original = {"name": "cnesdata-prod-audit", "target": [{"arn": "own-cluster", "ecs_parameters": [{"task_definition_arn": "audit:1", "task_count": 1}]}]}
    current = copy.deepcopy(original)
    current["target"][0]["ecs_parameters"][0]["task_definition_arn"] = "audit:2"
    row = change(address, current, copy.deepcopy(original), ["update"])
    row["change"]["after_unknown"] = {"target": [{"ecs_parameters": [{"task_definition_arn": False}]}]}
    approval = {"purpose": "phase-c-audit", "direction": "converge", "mode": "established",
                "before": {address: current}, "original": {address: original}, "created": {},
                "expected_changes_sha256": c.sha(c.canonical([row]))}
    m.validate_delta({"resource_changes": [row]}, approval)
    row["change"]["after"]["target"][0]["ecs_parameters"][0]["task_definition_arn"] = "audit:3"
    approval["expected_changes_sha256"] = c.sha(c.canonical([row]))
    with pytest.raises(ValueError, match="original resource restoration"):
        m.validate_delta({"resource_changes": [row]}, approval)
    row["change"]["after"] = copy.deepcopy(original)
    row["change"]["after_unknown"]["target"][0]["ecs_parameters"][0]["task_definition_arn"] = True
    approval["expected_changes_sha256"] = c.sha(c.canonical([row]))
    with pytest.raises(ValueError, match="unknown"):
        m.validate_delta({"resource_changes": [row]}, approval)


def test_delegate_admits_full_process_timeout_before_start(monkeypatch, tmp_path):
    from tools.cnesdata_delivery.lifecycle_runtime import LifecycleWatchdog
    from tools.cnesdata_delivery.coordination_lease import Watchdog
    window = {"sequence": 1, "preparation_deadline": 1500, "close": 1000, "fixed_deadline": 2800,
              "input_deadline": 3000, "stage": "phase-b", "admitted_at": 1000, "deadline": 1360,
              "decision": None, "checkpoint_sha256": "a" * 64}
    class View:
        def check(self):
            return {"lifecycle": window}
    started = []
    monkeypatch.setattr(Watchdog, "run", lambda self, command, **kwargs: started.append(command))
    guard = LifecycleWatchdog(View(), window, 5000, clock=lambda: 1050, monotonic=lambda: 1050)
    with pytest.raises(ValueError, match="phase remaining capacity"):
        guard.run(["tofu", "apply"], cwd=tmp_path, env={}, output=tmp_path / "private.log", timeout=300)
    assert started == []
    guard.run(["tofu", "apply"], cwd=tmp_path, env={}, output=tmp_path / "private.log", timeout=120)
    assert started == [["tofu", "apply"]]


def test_native_sfn_computed_outputs_are_distinct_from_unknown_authority():
    m = api()
    before = {"name": "cnesdata-prod", "definition": "old", "role_arn": "own-role", "revision_id": "revision-1"}
    after = before | {"definition": "new", "revision_id": None}
    row = change(m.STATE_MACHINE, before, after, ["update"])
    row["change"]["after_unknown"] = {"revision_id": True}
    approval = {"purpose": "phase-b", "direction": "advance", "mode": "established",
                "before": {m.STATE_MACHINE: before}, "original": {m.STATE_MACHINE: before}, "created": {},
                "expected_changes_sha256": c.sha(c.canonical([row]))}
    m.validate_delta({"resource_changes": [row]}, approval)
    row["change"]["after_unknown"]["role_arn"] = True
    approval["expected_changes_sha256"] = c.sha(c.canonical([row]))
    with pytest.raises(ValueError, match="unknown"):
        m.validate_delta({"resource_changes": [row]}, approval)


@pytest.mark.parametrize("noop", [False, True])
def test_mode_prepare_source_resolver_binds_all_four_policies_even_noop(noop):
    from fixtures.cnesdata_delivery_lifecycle import mode_source_case
    from tools.cnesdata_delivery.iam_boundary import prepare
    plan, sources, inputs = mode_source_case()
    if noop:
        for row in plan["resource_changes"]:
            row["change"].update(actions=["no-op"], before=copy.deepcopy(row["change"]["after"]))
    resolver = prepare(plan, inputs, "111122223333", "application-prepare", sources, mode="mode-canary")
    assert len(resolver.traces) == 4
    for address in resolver.traces:
        assert resolver.role_producer(address) == address.replace("aws_iam_role_policy", "aws_iam_role")
        assert resolver.policy(address)["Statement"][0]["Effect"] == "Deny"


@pytest.mark.parametrize("step_change,delta_change,allowed", [
    ({"mode": "mode-canary"}, {}, False),
    ({"mode": "mode-canary"}, {"mode": "mode-canary"}, False),
    ({"mode": "observer-bootstrap"}, {}, False),
    ({"purpose": "phase-b"}, {}, False),
    ({"direction": "converge"}, {}, False),
    ({}, {}, True),
])
def test_execute_binds_protected_step_to_original_approval_before_apply(tmp_path, monkeypatch, step_change, delta_change, allowed):
    """Real execute, delta and source gates; only external IO is replaced."""
    import json
    from pathlib import Path
    from types import SimpleNamespace
    from fixtures.cnesdata_delivery_lifecycle import mode_source_case
    from tools.cnesdata_delivery import lifecycle_contract as lc, lifecycle_runtime as lr, iam_boundary, session_owner, runtime
    plan, sources, inputs = mode_source_case()
    plan["resource_changes"] = [row for row in plan["resource_changes"] if ".mode_seed[0]" in row["address"]]
    configured = plan["configuration"]["root_module"]["module_calls"]["runtime_iam"]["module"]["resources"]
    plan["configuration"]["root_module"]["module_calls"]["runtime_iam"]["module"]["resources"] = [
        row for row in configured if row["address"].endswith(".mode_seed")]
    plan = json.loads(json.dumps(plan).replace("mode_seed", "static_normal"))
    sources["infra/opentofu/modules/runtime-iam/static-promotion.tf"] = sources.pop(
        "infra/opentofu/modules/runtime-iam/mode-canary.tf").replace(b"mode_seed", b"static_normal")
    step = {"purpose": "application-prepare", "mode": "operational", "direction": "advance",
            "input_jobs": {"prepared": {"step": "prepared"}}, **step_change}
    store, _, _ = held()
    purpose = "mode-readiness-drill" if step["mode"] == "mode-canary" else "promotion"
    store.value.update(application_purpose=purpose, context_kind=lc.APPLICATION_CONTEXTS[purpose], caller_binding_sha256="e" * 64)
    owner = lc.owner_binding(store.value)
    raw_state = c.canonical({"lineage": "fixture", "serial": 1, "resources": []})
    state_object = {"version_id": "fixture"}
    payload = {"plan.bin": b"synthetic-plan", "plan.json": c.canonical(plan), "inputs.json": c.canonical(inputs),
               "checkpoint.json": c.canonical({"owner": owner, "state": c.state_identity(raw_state), "state_object": state_object})}
    approval = {"version": 1, "owner": owner, "purpose": step["purpose"], "direction": step["direction"],
                "plan_sha256": c.sha(payload["plan.bin"]), "inputs_sha256": c.sha(payload["inputs.json"]),
                "checkpoint_sha256": c.sha(payload["checkpoint.json"]), "readbacks": {"before": [], "after": []}, "drift_matrix": {},
                "delta": {"purpose": "application-prepare", "direction": "advance", "mode": "operational", "before": {},
                          "original": {}, "created": {}, "expected_changes_sha256": c.sha(c.canonical(plan["resource_changes"])), **delta_change}}
    payload["approval.json"] = c.canonical(approval)
    store.value["lifecycle"] = {"checkpoint_sha256": c.sha(payload["checkpoint.json"])}
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "product/infra/opentofu/env/prod"
    (root / ".terraform").mkdir(parents=True)
    (root / ".terraform.lock.hcl").write_bytes(b"fixture-lock")
    (root / ".terraform/terraform.tfstate").write_bytes(c.canonical({"backend": {"type": "s3", "config": {}}}))
    tofu = tmp_path / "fixture-tofu"
    tofu.write_bytes(b"never-executed")
    governance = {"context_kind": owner["context_kind"], "account_id": "111122223333", "source_closure": {}, "cost": {},
                  "baseline": {"toolchain": {"opentofu": {"binary_sha256": c.sha(tofu.read_bytes())},
                                             "lock_sha256": c.sha((root / ".terraform.lock.hcl").read_bytes())},
                               "cost_context": {}, "cost_evidence": {}, "cost_manifest": {},
                               "backend": {"configuration": {"type": "s3", "workspace": "default"}}}}
    request = {"source_sha": owner["source_sha"], "application_purpose": purpose, "caller_binding_sha256": owner["caller_binding_sha256"]}
    monkeypatch.setattr(lr, "admission", lambda role: (governance, request, step, None,
        {"id": owner["run_id"], "run_attempt": owner["run_attempt"]}, {"prepared": {}}))
    monkeypatch.setattr(lr, "AWS", lambda _: SimpleNamespace(get_state=lambda: (raw_state, state_object)))
    monkeypatch.setattr(lr, "S3LeaseStore", lambda _: store)
    monkeypatch.setattr(session_owner, "authenticate_lifecycle", lambda *args: {})
    monkeypatch.setattr(session_owner, "verify_managed", lambda *args: None)
    monkeypatch.setenv("AWS_CREDENTIAL_EXPIRATION", "2030-01-01T00:00:00Z")
    monkeypatch.setattr(lr, "private_payload", lambda *args, **kwargs: ({"step": "prepared", "owner_sha256": owner["owner_sha256"],
        "generation": owner["generation"]}, payload))
    monkeypatch.setattr(lr.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=owner["source_sha"]))
    monkeypatch.setattr(lr, "authenticate_infrastructure_closure", lambda *args: None)
    monkeypatch.setattr(iam_boundary, "authenticate_sources", lambda *args: sources)
    monkeypatch.setattr(lr.shutil, "which", lambda _: str(tofu))
    monkeypatch.setattr(runtime, "_environment", lambda: {})
    monkeypatch.setattr(c, "validate_cost", lambda *args, **kwargs: None)
    monkeypatch.setattr(c, "drift_coverage", lambda *args, **kwargs: None)
    commands = []
    class ApplyBoundary(Exception):
        pass
    class Guard:
        window = store.value["lifecycle"]
        def check(self, *args):
            pass
        def run(self, command, **kwargs):
            commands.append(command[1])
            if command[1] == "apply":
                raise ApplyBoundary()
            if command[1] == "show":
                Path(kwargs["output"]).write_bytes(payload["plan.json"])
    monkeypatch.setattr(lr, "LifecycleWatchdog", lambda *args: Guard())
    if allowed:
        with pytest.raises(ApplyBoundary):
            lr.execute("deploy")
        assert commands == ["init", "show", "apply"]
    else:
        expected_error = ("mode-canary executable oracle unavailable" if step["mode"] == approval["delta"]["mode"]
                          else "independent protected step discriminants")
        if any(step[key] != approval["delta"][key] for key in ("purpose", "direction")):
            expected_error = "independent protected step discriminants"
        with pytest.raises(ValueError, match=expected_error):
            lr.execute("deploy")
        assert commands == ["init"]


@pytest.mark.parametrize("mutation", [None, "role-replaced", "trust", "policy", "extra-inline", "attached", "truncated",
                                      "boundary", "metadata", "stale-date", "guard", "expired", "spacing", "fractional-spacing"])
def test_fence_prepared_role_readbacks_are_finite_original_and_do_not_admit_sts(mutation):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    name = "cnesdata-prod-promotion-fence-operator"
    expected = {"role": {"Role": {"RoleName": name, "Arn": "arn:aws:iam::111122223333:role/" + name,
                "RoleId": "AROAORIGINAL", "MaxSessionDuration": 3600,
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111122223333:role/cnesdata-prod-application"},
                    "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:RoleSessionName": "promotion-fence-r1"}}}]}}},
                "policy": {"RoleName": name, "PolicyName": name + "-gate", "PolicyDocument": {
                    "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:GetItem",
                        "Resource": "arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control",
                        "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["ENV#prod#FENCE", "ENV#prod#SEMAPHORE"]},
                                      "Null": {"dynamodb:LeadingKeys": "false"}}}]}}}
    calls, guarded, now = [], [], [1000]
    if mutation == "fractional-spacing":
        now[0] = 1000.75
    class Guard:
        def check(self, seconds=1):
            guarded.append(seconds)
            if mutation == "guard" and calls:
                raise ValueError("original owner changed")
    class AWS:
        def call(self, service, operation, **parameters):
            calls.append((service, operation, parameters))
            assert service == "iam"
            values = {"get_role": expected["role"], "get_role_policy": expected["policy"],
                      "list_role_policies": {"PolicyNames": [name + "-gate"], "IsTruncated": False},
                      "list_attached_role_policies": {"AttachedPolicies": [], "IsTruncated": False}}
            result = copy.deepcopy(values[operation]) | {"ResponseMetadata": {"RequestId": "original-" + str(len(calls)),
                "HTTPHeaders": {"date": "Thu, 01 Jan 1970 00:16:40 GMT"}, "HTTPStatusCode": 200}}
            if mutation == "role-replaced" and len(calls) == 5:
                result["Role"]["RoleId"] = "AROAFOREIGN"
            if mutation == "trust" and operation == "get_role":
                result["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::111122223333:root"
            if mutation == "boundary" and operation == "get_role":
                result["Role"]["PermissionsBoundary"] = {"PermissionsBoundaryArn": "foreign"}
            if mutation == "policy" and operation == "get_role_policy":
                result["PolicyDocument"]["Statement"][0]["Resource"] = "*"
            if mutation == "extra-inline" and operation == "list_role_policies":
                result["PolicyNames"].append("foreign")
            if mutation == "attached" and operation == "list_attached_role_policies":
                result["AttachedPolicies"] = [{"PolicyArn": "foreign", "PolicyName": "foreign"}]
            if mutation == "truncated" and operation.startswith("list_"):
                result["IsTruncated"] = True
            if mutation == "metadata":
                result.pop("ResponseMetadata")
            if mutation == "stale-date":
                result["ResponseMetadata"]["HTTPHeaders"]["date"] = "Thu, 01 Jan 1970 00:00:00 GMT"
            if mutation == "expired":
                now[0] = 1900
            return result
    kwargs = dict(account="111122223333", expected=expected, preparation_admitted_at=1000,
        preparation_deadline=1900, guard=Guard(), clock=lambda: now[0],
        sleep=lambda duration: now.__setitem__(0, now[0] + (0 if mutation == "spacing" else 9.5 if mutation == "fractional-spacing" else duration)))
    if mutation:
        with pytest.raises(ValueError):
            lr.fence_role_readbacks(AWS(), **kwargs)
        assert all(row[0] == "iam" for row in calls)
        return
    result = lr.fence_role_readbacks(AWS(), **kwargs)
    assert len(calls) == 8 and all(row[0] == "iam" for row in calls)
    assert result["proof_kind"] == "iam-readback-and-evaluation" and len(result["readbacks"]) == 2
    assert [row["observed_at"] for row in result["readbacks"]] == [1000, 1010]
    assert result["readbacks"][0]["observations"][0]["response"]["ResponseMetadata"]["RequestId"] == "original-1"
    assert len(guarded) >= 16
    assert all(row[2]["RoleName"] == name for row in calls)


@pytest.mark.parametrize("mutation", ["purpose", "mode", "fallback", "missing", "mixed", "unknown", "input", "input-absent", "policy", "configuration", "role"])
def test_mode_prepare_source_boundary_rejects_crossed_or_incomplete_authority(mutation):
    from fixtures.cnesdata_delivery_lifecycle import mode_source_case
    from tools.cnesdata_delivery.iam_boundary import prepare
    plan, sources, inputs = mode_source_case()
    purpose, mode = "application-prepare", "mode-canary"
    policy = next(r for r in plan["resource_changes"] if r["type"] == "aws_iam_role_policy")
    if mutation == "purpose":
        purpose = "phase-a"
    if mutation == "mode":
        mode = "operational"
    if mutation == "fallback":
        sources["infra/opentofu/modules/runtime-iam/canary.tf"] = sources.pop("infra/opentofu/modules/runtime-iam/mode-canary.tf")
    if mutation == "missing":
        plan["resource_changes"].remove(policy)
    if mutation == "mixed":
        plan["resource_changes"].append({**copy.deepcopy(policy), "address": "module.runtime_iam.aws_iam_role_policy.static_normal[0]"})
    if mutation == "unknown":
        policy["change"]["after_unknown"]["policy"] = True
    if mutation == "input":
        inputs["mode_canary"] = {"fixture_only": False}
    if mutation == "input-absent":
        plan["variables"].pop("mode_canary")
    if mutation == "configuration":
        configured = plan["configuration"]["root_module"]["module_calls"]["runtime_iam"]["module"]["resources"]
        next(r for r in configured if r["address"] == "aws_iam_role_policy.mode_seed")["expressions"]["policy"] = {"constant_value": "wrong"}
    if mutation == "policy":
        policy["change"]["after"]["policy"] = '{"Version":"2012-10-17","Statement":[]}'
    if mutation == "role":
        path = "infra/opentofu/modules/runtime-iam/mode-canary.tf"
        sources[path] = sources[path].replace(b'role = aws_iam_role.mode_seed[0].name', b'role = aws_iam_role.mode_dispatch[0].name')
        configured = plan["configuration"]["root_module"]["module_calls"]["runtime_iam"]["module"]["resources"]
        next(r for r in configured if r["address"] == "aws_iam_role_policy.mode_seed")["expressions"]["role"] = {"references": ["aws_iam_role.mode_dispatch[0].name"]}
    with pytest.raises(ValueError):
        prepare(plan, inputs, "111122223333", purpose, sources, mode=mode)


@pytest.mark.parametrize("stage", ["initial", "established"])
@pytest.mark.parametrize("mutation", [None, "delete", "replace", "import", "missing", "extra", "duplicate", "unknown", "baseline", "mixed-stage", "noop"])
def test_mode_prepare_eight_address_delta_is_closed_before_source_evaluation(stage, mutation):
    from fixtures.cnesdata_delivery_lifecycle import mode_source_case
    from tools.cnesdata_delivery import lifecycle_contract as lc
    plan, _, _ = mode_source_case()
    before = {}
    if stage == "established":
        for row in plan["resource_changes"]:
            old = copy.deepcopy(row["change"]["after"])
            before[row["address"]] = old
            row["change"].update(actions=["update"], before=old)
    row = plan["resource_changes"][0]
    if mutation == "delete":
        row["change"]["actions"] = ["delete"]
    if mutation == "replace":
        row["change"]["actions"] = ["delete", "create"]
    if mutation == "import":
        row["change"]["importing"] = {"id": "other"}
    if mutation == "missing":
        plan["resource_changes"].pop()
    if mutation == "extra":
        plan["resource_changes"].append({**copy.deepcopy(row), "address": "module.runtime_iam.aws_iam_role.other[0]"})
    if mutation == "duplicate":
        plan["resource_changes"].append(copy.deepcopy(row))
    if mutation == "unknown":
        row["change"]["after_unknown"]["assume_role_policy"] = True
    if mutation == "baseline":
        before[row["address"]] = {"name": "wrong"}
    if mutation == "mixed-stage":
        row["change"]["actions"] = ["update"] if stage == "initial" else ["create"]
    if mutation == "noop":
        row["change"]["actions"] = ["no-op"]
        row["change"]["before"] = {"name": "hidden-diff"}
        before[row["address"]] = row["change"]["before"]
    if mutation is None:
        assert lc.validate_mode_canary_delta(plan, before, stage=stage) == {r["address"] for r in plan["resource_changes"]}
    else:
        with pytest.raises(ValueError):
            lc.validate_mode_canary_delta(plan, before, stage=stage)


def test_mode_prepare_requires_all_other_resources_to_be_true_noops():
    from fixtures.cnesdata_delivery_lifecycle import mode_source_case
    from tools.cnesdata_delivery import lifecycle_contract as lc
    plan, _, _ = mode_source_case()
    other = {"address": "module.processing.aws_sfn_state_machine.processor[0]", "mode": "managed", "type": "aws_sfn_state_machine",
             "change": {"actions": ["no-op"], "before": {"definition": "old"}, "after": {"definition": "old"}, "after_unknown": {}}}
    plan["resource_changes"].append(other)
    before = {other["address"]: other["change"]["before"]}
    assert len(lc.validate_mode_canary_delta(plan, before, stage="initial")) == 8
    other["change"]["after"]["definition"] = "new"
    with pytest.raises(ValueError, match="mode.*noop"):
        lc.validate_mode_canary_delta(plan, before, stage="initial")



def test_native_mode_prepare_reads_exact_source_and_eight_address_plan():
    """Native mock plan is a grammar/structure fixture, not a domain capability."""
    import json
    import shutil
    from fixtures.cnesdata_delivery_lifecycle import mode_source_case
    from fixtures.cnesdata_delivery_roles_anywhere.native import Native, ROOT
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.iam_boundary import prepare
    harness = Native()
    try:
        _, sources, inputs = mode_source_case()
        for name, raw in sources.items():
            path = harness.base / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        root = harness.base / "infra/opentofu/env/prod"
        (root / "providers.tf").write_text('terraform {\n required_providers {\n aws = { source = "hashicorp/aws", version = "6.54.0" }\n }\n}\nprovider "aws" { region = "us-east-2" }')
        (root / "variables.tf").write_text('variable "mode_canary" { type = any }\nvariable "shared_outputs" { type = any }')
        shutil.copy2(ROOT / ".terraform.lock.hcl", root / ".terraform.lock.hcl")
        (root / "inputs.tfvars.json").write_text(json.dumps(inputs | {"shared_outputs": {"account_id": "111122223333"}}))
        (root / "contract.tftest.hcl").write_text('mock_provider "aws" {}\nrun "contract" { command = plan }')
        init = harness.run(root, "init", "-backend=false", "-input=false", "-lockfile=readonly")
        assert init.returncode == 0, init.stdout + init.stderr
        result = harness.run(root, "test", "-json", "-verbose", "-var-file=inputs.tfvars.json")
        assert result.returncode == 0, result.stdout + result.stderr
        events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        plan, = [event["test_plan"] for event in events if "test_plan" in event]
        import os
        evidence = os.environ.get("CNESDATA_MODE_EVIDENCE_DIR")
        if evidence:
            from pathlib import Path
            Path(evidence).mkdir(parents=True, exist_ok=True)
            (Path(evidence) / "native-mode-source-plan.json").write_text(json.dumps(plan, sort_keys=True, indent=2))
        assert len(lc.validate_mode_canary_delta(plan, {}, stage="initial")) == 8
        resolver = prepare(plan, inputs, "111122223333", "application-prepare", sources, mode="mode-canary")
        assert len(resolver.traces) == 4
    finally:
        harness.temp.cleanup()



def _mode_readback_case():
    from tools.cnesdata_delivery.iam_source import MODE_POLICIES
    expected, responses = {}, []
    for address in sorted(MODE_POLICIES):
        alias = address.split(".")[-1].removesuffix("[0]")
        name = "cnesdata-prod-" + alias.replace("_", "-")
        role = {"Role": {"RoleName": name, "Arn": "arn:aws:iam::111122223333:role/" + name,
                         "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}, "MaxSessionDuration": 3600}}
        policy = {"RoleName": name, "PolicyName": name + "-runtime", "PolicyDocument": {"Version": "2012-10-17", "Statement": []}}
        expected[alias] = {"role": role, "policy": policy}
        responses.extend([role, policy])
    return expected, responses


@pytest.mark.parametrize("mutation", [None, "second-role", "second-policy", "absent", "wrong-role", "missing", "deadline", "spacing", "guard"])
def test_mode_readback_producer_is_finite_identical_and_inside_original_deadline(mutation):
    from tools.cnesdata_delivery.lifecycle_runtime import mode_canary_readbacks
    expected, responses = _mode_readback_case()
    clock, sleeps = [1000.0], []
    responses = copy.deepcopy(responses + responses)
    if mutation == "second-role":
        responses[8]["Role"]["MaxSessionDuration"] = 7200
    if mutation == "second-policy":
        responses[9]["PolicyDocument"]["Statement"] = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    if mutation == "absent":
        responses[3] = RuntimeError("unknown IAM readback")
    if mutation == "wrong-role":
        expected["mode_seed"]["role"]["Role"]["Arn"] = "arn:aws:iam::999999999999:role/other"
    if mutation == "missing":
        expected.pop("mode_seed")
    aws, guard = ReadbackAWS(responses), ReadbackGuard()
    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += 5 if mutation == "spacing" else 10
        if mutation == "guard":
            def lost(*args):
                raise ValueError("keeper lost")
            guard.check = lost
    kwargs = {"account": "111122223333", "expected": expected, "preparation_admitted_at": 990,
              "preparation_deadline": 1005 if mutation == "deadline" else 1200,
              "guard": guard, "clock": lambda: clock[0], "sleep": sleep}
    if mutation:
        with pytest.raises((ValueError, RuntimeError)):
            mode_canary_readbacks(aws, **kwargs)
        if mutation in {"wrong-role", "missing"}:
            assert aws.calls == []
        assert len(aws.calls) <= 16
    else:
        proof = mode_canary_readbacks(aws, **kwargs)
        assert proof["proof_kind"] == "iam-readback-and-evaluation"
        assert [r["observed_at"] for r in proof["readbacks"]] == [1000, 1010]
        assert proof["readbacks"][0]["observations"] == proof["readbacks"][1]["observations"]
        assert sleeps == [10] and len(aws.calls) == 16 and guard.checks >= 32
        assert all(service == "iam" and operation in {"get_role", "get_role_policy"} for service, operation, _ in aws.calls)



@pytest.mark.parametrize("alias", ["static_observer", "static_normal", "static_recovery"])
def test_application_prepare_role_chain_uses_selected_static_inventory(alias):
    import json
    from fixtures.cnesdata_delivery_lifecycle import mode_source_case
    from tools.cnesdata_delivery.iam_boundary import prepare
    plan, sources, inputs = mode_source_case()
    selected = [r for r in plan["resource_changes"] if ".mode_seed[0]" in r["address"]]
    configured = plan["configuration"]["root_module"]["module_calls"]["runtime_iam"]["module"]["resources"]
    plan["configuration"]["root_module"]["module_calls"]["runtime_iam"]["module"]["resources"] = [r for r in configured if r["address"].endswith(".mode_seed")]
    plan["resource_changes"] = selected
    plan = json.loads(json.dumps(plan).replace("mode_seed", alias))
    sources["infra/opentofu/modules/runtime-iam/static-promotion.tf"] = sources.pop("infra/opentofu/modules/runtime-iam/mode-canary.tf").replace(b"mode_seed", alias.encode())
    resolver = prepare(plan, inputs, "111122223333", "application-prepare", sources, mode="operational")
    address = "module.runtime_iam.aws_iam_role_policy." + alias + "[0]"
    assert resolver.role_producer(address) == address.replace("aws_iam_role_policy", "aws_iam_role")
