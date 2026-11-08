"""Adversarial offline delivery cases; fixtures never represent production proof."""
import copy
import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="module")
def contract():
    assert (ROOT / "tools/cnesdata_delivery/contract.py").is_file(), "contract gate absent"
    return importlib.import_module("tools.cnesdata_delivery.contract")


@pytest.mark.parametrize("raw,expected", [
    (b"0", b"0\n"), (b"-0", b"0\n"), (b"1.2300", b"1.23\n"),
    (b"1e-3", b"0.001\n"), (b"1e-7", b"0.0000001\n"),
    ('{"z":-0.00,"a":[1e3,0.0100,12345678901234567890.123400],"u":"á"}'.encode(),
     '{"a":[1000,0.01,12345678901234567890.1234],"u":"á","z":0}\n'.encode()),
])
def test_exact_decimal_state_vectors(contract, raw, expected):
    assert contract.canonical(contract.loads(raw, state=True)) == expected


@pytest.mark.parametrize("raw", [b'{"a":1,"a":1}', b"NaN", b"Infinity", b"\xef\xbb\xbf{}",
    b"1e999999999", b"-0e999999999", b'"\\ud800"', b"{} {}"])
def test_unsafe_json_fails_closed(contract, raw):
    with pytest.raises(ValueError):
        contract.canonical(contract.loads(raw, state=True))


def test_canonical_bytes_are_admitted_exactly(contract):
    assert contract.loads(b'{}\n', canonical=True) == {}
    with pytest.raises(ValueError):
        contract.loads(b'{}', canonical=True)
    assert contract.sha(contract.canonical({})) == "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"


@pytest.mark.parametrize("amount,total,ok", [("8.00", "14.99", True), ("8.01", "14.99", False),
    ("8.00", "15.00", False), ("8.00", "15.01", False), (8, "14.00", False)])
def test_cost_freeze_decimal_boundary(contract, amount, total, ok):
    if ok:
        contract.budget(amount, total, "0.00")
    else:
        with pytest.raises(ValueError):
            contract.budget(amount, total, "0.00")


def test_package_rejects_tamper_and_extra_members(contract):
    files = {"plan.bin": b"binary", "plan.json": b'{"resource_changes":[]}', "inputs.tfvars.json": b"{}\n"}
    entries = [{"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
               for name, data in sorted(files.items())]
    package = {"files": entries, "aggregate_sha256": contract.sha(contract.canonical(entries))}
    contract.verify_package(package, files)
    for mutated in [files | {"plan.bin": b"changed"}, files | {"extra": b"secret"}]:
        with pytest.raises(ValueError):
            contract.verify_package(package, mutated)


@pytest.mark.parametrize("change", [
    {"address": "aws_s3_bucket.x", "change": {"actions": ["delete"], "before": {}, "after": None}},
    {"address": "aws_s3_bucket.x", "change": {"actions": ["delete", "create"], "before": {}, "after": {}}},
    {"address": "aws_acm_certificate.static_web", "change": {"actions": ["create"], "after": {"password": "secret"}}},
])
def test_destructive_replacement_and_secret_plan_rejected(contract, change):
    with pytest.raises(ValueError):
        contract.validate_delta({"resource_changes": [change]}, "acm-certificate")


def test_phase_a_a2_recomputed_from_real_candidate(contract):
    candidate = {"repository": "VINIClUS/CnesData", "release_id": "candidate-immutable",
                 "source_sha": "a" * 40}
    result = contract.canary_binding(candidate, contract.sha(contract.canonical(candidate)))
    assert result["canary_id"] == result["binding_sha256"][:32]
    assert result != contract.canary_binding(candidate | {"release_id": "another"}, "b" * 64)


@pytest.fixture(scope="module")
def provenance():
    assert (ROOT / "tools/cnesdata_delivery/provenance.py").is_file(), "source gate absent"
    return importlib.import_module("tools.cnesdata_delivery.provenance")


@pytest.mark.parametrize("field,bad", [("repository", "foreign/CnesData"), ("ref", "refs/heads/evil"),
    ("event", "pull_request"), ("workflow_path", ".github/workflows/other.yml"),
    ("source_sha", "f" * 40), ("role", "deploy")])
def test_source_denied_before_credential_callback(provenance, field, bad):
    expected = {"repository": "VINIClUS/CnesData", "ref": "refs/heads/develop", "event": "workflow_dispatch",
                "workflow_path": ".github/workflows/infra-plan.yml", "source_sha": "a" * 40, "role": "plan"}
    calls = []
    with pytest.raises(ValueError):
        provenance.admit_source(expected | {field: bad}, expected, lambda: calls.append("OIDC"))
    assert calls == []


def test_reusable_sha_comes_from_authenticated_run_not_caller(provenance):
    workflow = "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-plan-gate.yml"
    run = {"referenced_workflows": [{"path": workflow + "@" + "b" * 40, "sha": "b" * 40}]}
    assert provenance.producer_sha(run, "plan") == "b" * 40
    run["referenced_workflows"][0]["path"] = workflow + "@main"
    with pytest.raises(ValueError):
        provenance.producer_sha(run, "plan")


def test_actionlint_executes_pinned_workflows():
    import shutil
    import subprocess
    binary = shutil.which("actionlint")
    assert binary, "pinned actionlint required; never skip"
    version = subprocess.run([binary, "-version"], text=True, capture_output=True, check=True)
    assert version.stdout.splitlines()[0] == "1.7.7"
    subprocess.run([binary, *[str(ROOT / f".github/workflows/reusable-cnesdata-infra-{gate}-gate.yml")
                             for gate in ("plan", "deploy")]], check=True)


def test_purpose_cost_pre_requires_real_guardrail_context(contract):
    from fixtures.cnesdata_cost import fixture
    cost, stage, evidence, manifest = fixture(False)
    contract.validate_cost(cost, purpose="bootstrap", stage=stage, evidence=evidence, manifest=manifest, now=1794053700)
    for context in [None, stage | {"stage": "active"}]:
        with pytest.raises(ValueError):
            contract.validate_cost(cost, purpose="bootstrap", stage=context, evidence=evidence, manifest=manifest, now=1794053700)
    with pytest.raises(ValueError):
        contract.validate_cost(cost, purpose="phase-a", stage=stage, evidence=evidence, manifest=manifest, now=1794053700)


@pytest.mark.parametrize("mutation", ["unbound", "credits", "guardrail", "stale", "wrong-binding", "aggregate", "paid"])
def test_cost_purpose_scope_rejects_lie_or_missing_measurement(contract, mutation):
    from fixtures.cnesdata_cost import fixture
    cost, stage, evidence, manifest = fixture(mutation in {"wrong-binding", "stale"})
    purpose = "phase-a" if cost["scope"] == "active" else "bootstrap"
    if mutation == "unbound":
        cost.pop("unbound_monthly_usd")
    elif mutation == "credits":
        manifest["credits_usd"] = "1.00"
    elif mutation == "guardrail":
        cost["dns"] = "enabled"
    elif mutation == "stale":
        cost["cloudfront"]["expires_at"] = "2026-11-07T11:00:00Z"
    elif mutation == "wrong-binding":
        stage["cloudfront"] = stage["cloudfront"] | {"distribution_sha256": "f" * 64}
    elif mutation == "aggregate":
        cost["aggregate_monthly_usd"] = "15.00"
    else:
        cost["paid_actions_limit_usd"] = "1.00"
    with pytest.raises(ValueError):
        contract.validate_cost(cost, purpose=purpose, stage=stage, evidence=evidence, manifest=manifest, now=1794053700)


def graph_case(contract):
    policy = "module.runtime_iam.aws_iam_role_policy.canary_task[0]"
    role = "module.runtime_iam.aws_iam_role.canary_task[0]"
    table = "module.processing.aws_dynamodb_table.canary[0]"
    refs = ["var.canary_release", "var.canary_table_arn"]
    config = {"root_module": {"module_calls": {"runtime_iam": {"module": {"resources": [
        {"address": "aws_iam_role_policy.canary_task", "expressions": {"policy": {"references": refs},
            "role": {"references": ["aws_iam_role.canary_task[0].id", "aws_iam_role.canary_task"]}}}]}}}}}
    changes = [{"address": policy, "type": "aws_iam_role_policy", "change": {"actions": ["create"], "before": None,
        "after": {"name": "canary", "role": None, "policy": None}, "after_unknown": {"id": True, "role": True, "policy": True}}},
        {"address": role, "type": "aws_iam_role", "change": {"actions": ["create"], "after": {"name": "cnesdata-prod-canary-task"}, "after_unknown": {"id": True}}},
        {"address": table, "type": "aws_dynamodb_table", "change": {"actions": ["create"], "after": {"name": "cnesdata-canary"}}}]
    plan = {"configuration": config, "resource_changes": changes}
    files = {"infra/opentofu/modules/runtime-iam/canary.tf": b"audited synthetic source\n"}
    approved = {"source_files": [{"path": name, "sha256": contract.sha(data)} for name, data in files.items()],
                "configuration_sha256": contract.sha(contract.canonical(config)), "known_policies": {},
                "unknown_policies": [{"address": policy, "references": refs, "producers": [table, role], "before_policy_sha256": None}]}
    return plan, approved, files


def test_unknown_role_id_requires_actual_known_name_producer(contract):
    plan, approved, files = graph_case(contract)
    result = contract.validate_graph(plan, approved, files)
    assert result["governance_sha256"] == contract.sha(contract.canonical(approved))
    plan["resource_changes"][1]["change"]["after_unknown"]["name"] = True
    with pytest.raises(ValueError):
        contract.validate_graph(plan, approved, files)


@pytest.mark.parametrize("mutation", ["source", "expression", "producer", "before", "extra-unknown"])
def test_unknown_iam_cannot_widen_via_self_asserted_graph(contract, mutation):
    plan, approved, files = graph_case(contract)
    if mutation == "source":
        files[next(iter(files))] = b"tamper"
    elif mutation == "expression":
        plan["configuration"]["root_module"]["module_calls"]["runtime_iam"]["module"]["resources"][0]["expressions"]["policy"]["references"] = ["foreign"]
    elif mutation == "producer":
        plan["resource_changes"].pop()
    elif mutation == "before":
        plan["resource_changes"][0]["change"]["before"] = {"policy": '{"Statement":[]}'}
    else:
        plan["resource_changes"][0]["change"]["after_unknown"]["role"] = False
        plan["resource_changes"][0]["change"]["after_unknown"]["other"] = True
    with pytest.raises(ValueError):
        contract.validate_graph(plan, approved, files)


def test_known_policy_does_not_excuse_unbound_new_role(contract):
    plan, approved, files = graph_case(contract)
    value = {"Version": "2012-10-17", "Statement": []}
    plan["resource_changes"][0]["change"]["after"]["policy"] = json.dumps(value)
    plan["resource_changes"][0]["change"]["after_unknown"]["policy"] = False
    address = plan["resource_changes"][0]["address"]
    approved["known_policies"][address] = contract.sha(contract.canonical(value))
    assert contract.validate_graph(plan, approved, files)["governance_sha256"]
    approved["unknown_policies"] = []
    with pytest.raises(ValueError):
        contract.validate_graph(plan, approved, files)


def test_complete_planned_a3_uses_independent_baseline(contract):
    from fixtures.cnesdata_plan import packet
    envelope, files, baseline = packet()
    plan = contract.validate_envelope(envelope, files, baseline, 1794053700, "a" * 40)
    assert plan["source_sha"] == "a" * 40
    assert envelope["plan_binding_sha256"] == contract.sha(contract.canonical(plan))


@pytest.mark.parametrize("mutation", ["source", "workspace", "dependency", "expiry", "mix", "policy", "state", "binding", "version"])
def test_complete_plan_rejects_mixing_even_after_self_rehash(contract, mutation):
    from fixtures.cnesdata_plan import packet
    envelope, files, baseline = packet()
    plan = envelope["plan"]
    if mutation == "source":
        plan["source_sha"] = "b" * 40
    elif mutation == "workspace":
        plan["backend"]["configuration"]["workspace"] = "other"
        plan["backend"]["identity_sha256"] = contract.sha(contract.canonical(plan["backend"]["configuration"]))
    elif mutation == "dependency":
        plan["dependencies"][0]["source_sha"] = "f" * 40
    elif mutation == "expiry":
        plan["expires_at"] = "2026-11-07T12:01:00Z"
    elif mutation == "mix":
        files["plan.bin"] = b"another-attempt"
    elif mutation == "policy":
        plan["policy"]["plan_json_sha256"] = "0" * 64
    elif mutation == "state":
        plan["state_before"]["serial"] = 1
    elif mutation == "version":
        envelope["schema_version"] = True
    envelope["plan_binding_sha256"] = contract.sha(contract.canonical(plan)) if mutation != "binding" else "0" * 64
    with pytest.raises(ValueError):
        contract.validate_envelope(envelope, files, baseline, 1794053700, "a" * 40)


def test_cli_closes_before_any_aws_when_governance_missing(monkeypatch):
    from tools.cnesdata_delivery import runtime
    calls = []
    monkeypatch.delenv("CNESDATA_DELIVERY_GOVERNANCE", raising=False)
    monkeypatch.setattr(runtime, "AWS", lambda value: calls.append("AWS"))
    with pytest.raises(ValueError):
        runtime.execute("deploy")
    assert calls == []


@pytest.mark.parametrize("value", ["arn:aws:iam::111122223333:role/private", "https://bucket.invalid/?X-Amz-Signature=secret",
                                   "-----BEGIN PRIVATE KEY-----", "AKIAABCDEFGHIJKLMNOP", "subnet-12345678"])
def test_public_transport_rejects_private_material(contract, value):
    with pytest.raises(ValueError):
        contract.public_safe({"measurement": {"unexpected": value}})


def test_public_transport_allows_only_commitments(contract):
    contract.public_safe({"repository": "VINIClUS/CnesData", "source_sha": "a" * 40,
                          "cost": {"product_monthly_usd": "4.00"}, "distribution_sha256": "b" * 64})


@pytest.fixture(scope="module")
def outputs():
    assert (ROOT / "tools/cnesdata_delivery/outputs.py").is_file(), "normative outputs absent"
    return importlib.import_module("tools.cnesdata_delivery.outputs")


def test_targeted_acm_projects_real_record_without_evaluating_other_root_outputs(outputs):
    from fixtures.cnesdata_outputs import ACCOUNT, CERT, fixture
    state, api, _, _, record = fixture()
    result = outputs.acm(state, api, ACCOUNT)
    assert result == {"acm_certificate_arn": CERT, "acm_dns_validation_records": [record]}


@pytest.mark.parametrize("mutation", ["other-domain", "wrong-record", "expired", "dns-long", "dns-label", "whitespace", "wrong-account"])
def test_acm_never_synthesizes_or_normalizes_provider_record(outputs, mutation):
    from fixtures.cnesdata_outputs import ACCOUNT, fixture
    state, api, certificate, _, _ = fixture()
    if mutation == "other-domain":
        certificate["SubjectAlternativeNames"].append("foreign.example")
    elif mutation == "wrong-record":
        certificate["DomainValidationOptions"][0]["ResourceRecord"]["Value"] = "another.example."
    elif mutation == "expired":
        certificate["Status"] = "EXPIRED"
    elif mutation == "dns-long":
        state["resources"][0]["instances"][0]["attributes"]["domain_validation_options"][0]["resource_record_name"] = "a" * 64 + ".cnesdata.com.br."
    elif mutation == "dns-label":
        state["resources"][0]["instances"][0]["attributes"]["domain_validation_options"][0]["resource_record_value"] = "-bad.example."
    elif mutation == "whitespace":
        state["resources"][0]["instances"][0]["attributes"]["domain_validation_options"][0]["resource_record_value"] += " "
    else:
        ACCOUNT = "999988887777"
    with pytest.raises(ValueError):
        outputs.acm(state, api, ACCOUNT)


def test_bootstrap_projects_only_direct_observed_distribution_waf_tuple(outputs):
    from fixtures.cnesdata_outputs import ACCOUNT, DIST, WAF, fixture
    state, api, _, distribution, _ = fixture(True)
    result = outputs.bootstrap(state, api, ACCOUNT)
    assert result["cloudfront_distribution_id"] == distribution["Id"]
    assert result["free_subscription_binding_input"] == {"distribution_arn": DIST, "web_acl_arn": WAF}
    assert result["bootstrap_invariants"]["schedulers"] == {"recovery": None, "audit": None}
    distribution["Status"] = "InProgress"
    with pytest.raises(ValueError):
        outputs.bootstrap(state, api, ACCOUNT)


def test_sdk_s3_cas_uses_owner_kms_and_exact_precondition():
    from tools.cnesdata_delivery.aws_boundary import AWS
    client = object.__new__(AWS)
    client.governance = {"account_id": "111122223333", "evidence_kms_key_arn": "synthetic-kms"}
    calls = []
    client.call = lambda service, operation, **kwargs: calls.append((service, operation, kwargs)) or {"ETag": '"opaque"'}
    assert client.put("synthetic", "exact/key", b"data") == '"opaque"'
    assert calls[0][2]["IfNoneMatch"] == "*" and "IfMatch" not in calls[0][2]
    assert calls[0][2]["ExpectedBucketOwner"] == "111122223333"
    assert calls[0][2]["ServerSideEncryption"] == "aws:kms"
    client.put("synthetic", "exact/key", b"renew", etag='"opaque"')
    assert calls[1][2]["IfMatch"] == '"opaque"' and "IfNoneMatch" not in calls[1][2]


@pytest.mark.parametrize("kind", ["duplicate", "traversal", "symlink", "directory"])
def test_archive_guard_precedes_content_hash(kind):
    import io
    import warnings
    import zipfile
    from tools.cnesdata_delivery.provenance import unzip
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        if kind == "duplicate":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                archive.writestr("x", b"a")
                archive.writestr("x", b"b")
        elif kind == "traversal":
            archive.writestr("../escape", b"a")
        elif kind == "directory":
            archive.writestr("dir/", b"")
        else:
            entry = zipfile.ZipInfo("link")
            entry.create_system = 3
            entry.external_attr = 0o120777 << 16
            archive.writestr(entry, "target")
    with pytest.raises(ValueError):
        unzip(output.getvalue())


def artifact_inventory(contract):
    purposes = sorted({"backend", "policy", "cost", "drift", "shared-outputs", "toolchain"})
    references = {purpose: {"repository": "VINIClUS/infra-ansible", "artifact_id": index + 1}
                  for index, purpose in enumerate(purposes)}
    class API:
        def __init__(self):
            self.members = {"prior.json": b"actual prior bytes", "report.txt": b"other member"}
            self.expiries = {}

        def artifact(self, reference, now, **kwargs):
            self.expiries[reference["repository"], reference["artifact_id"]] = contract.instant("2026-11-07T13:00:00Z")
            return self.members
    api = API()
    content = [{"name": name, "size": len(value), "sha256": contract.sha(value)} for name, value in sorted(api.members.items())]
    entries = [{"purpose": purpose, "reference": references[purpose], "expires_at": "2026-11-07T13:00:00Z",
                "content_sha256": contract.sha(contract.canonical(content))} for purpose in purposes]
    return entries, {"artifact_purposes": purposes, "artifact_references": references}, api


def test_all_prior_regular_members_are_bound(contract, provenance):
    entries, governance, api = artifact_inventory(contract)
    provenance.validate_artifact_set(entries, governance, api, 1794053700, "2026-11-07T13:00:00Z")


@pytest.mark.parametrize("mutation", ["empty", "omit-purpose", "swap", "extra-purpose", "changed-member", "extra-member", "omitted-member"])
def test_prior_artifacts_cannot_drop_or_select_content(contract, provenance, mutation):
    entries, governance, api = artifact_inventory(contract)
    if mutation == "empty":
        entries = []
    elif mutation == "omit-purpose":
        entries.pop()
    elif mutation == "swap":
        entries[0]["purpose"] = entries[1]["purpose"]
    elif mutation == "extra-purpose":
        entries.append(entries[0] | {"purpose": "unapproved"})
    elif mutation == "changed-member":
        api.members["prior.json"] = b"different bytes"
    elif mutation == "extra-member":
        api.members["extra.txt"] = b"not counted"
    else:
        api.members.pop("report.txt")
    with pytest.raises(ValueError):
        provenance.validate_artifact_set(entries, governance, api, 1794053700, "2026-11-07T13:00:00Z")


@pytest.mark.parametrize("mutation", [None, "local", "bucket", "key", "endpoint", "profile", "workspace"])
def test_effective_backend_is_not_inferred_from_init_exit_zero(contract, mutation):
    from fixtures.cnesdata_plan import packet
    _, _, baseline = packet()
    expected = baseline["backend"]["configuration"]
    actual = {"backend": {"type": "s3", "config": {key: value for key, value in expected.items() if key not in {"type", "workspace"}}}}
    workspace = "default"
    if mutation == "local":
        actual["backend"]["type"] = "local"
    elif mutation == "bucket":
        actual["backend"]["config"]["bucket"] = "other-state"
    elif mutation == "key":
        actual["backend"]["config"]["key"] = "shared/cnesdata-delivery/prod/opentofu.tfstate"
    elif mutation == "endpoint":
        actual["backend"]["config"]["endpoints"] = {"s3": "https://unapproved.invalid"}
    elif mutation == "profile":
        actual["backend"]["config"]["profile"] = "unapproved"
    elif mutation == "workspace":
        workspace = "prod"
    if mutation is None:
        contract.effective_backend(actual, workspace, expected)
    else:
        with pytest.raises(ValueError):
            contract.effective_backend(actual, workspace, expected)


def test_artifact_sdk_multiline_outputs_are_read_without_exposing_credentials(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from tools.cnesdata_delivery import runtime
    monkeypatch.chdir(tmp_path)
    bundle = tmp_path / ".delivery-uploader/dist/upload/index.js"
    bundle.parent.mkdir(parents=True)
    bundle.write_text("synthetic SDK boundary")
    monkeypatch.setattr(runtime.subprocess, "run", lambda args, **kwargs: SimpleNamespace(stdout=(runtime.UPLOAD_SHA if args[0] == "git" else "v24.11.1") + "\n"))
    monkeypatch.setenv("AWS_SESSION_TOKEN", "must-not-reach-uploader")
    monkeypatch.setenv("CNESDATA_DELIVERY_GOVERNANCE", "private-governance")
    monkeypatch.setenv("GITHUB_TOKEN", "private-api-token")
    monkeypatch.setenv("GITHUB_ENV", str(tmp_path / "shared-credential-file"))
    for name in ("ACTIONS_RUNTIME_URL", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL"):
        monkeypatch.setenv(name, "handler-" + name)
    class Publisher:
        finalizing = False

        def run(self, command, **kwargs):
            assert not any(key.startswith("AWS_") for key in kwargs["env"])
            assert "CNESDATA_DELIVERY_GOVERNANCE" not in kwargs["env"]
            assert "GITHUB_TOKEN" not in kwargs["env"]
            assert kwargs["env"]["GITHUB_ENV"] != str(tmp_path / "shared-credential-file")
            assert Path(kwargs["env"]["GITHUB_ENV"]).read_bytes() == b""
            assert kwargs["env"]["ACTIONS_RUNTIME_TOKEN"] == "handler-ACTIONS_RUNTIME_TOKEN"
            assert kwargs["env"]["INPUT_ARCHIVE"] == "true"
            assert Path(kwargs["env"]["GITHUB_OUTPUT"]).is_file()
            Path(kwargs["env"]["GITHUB_OUTPUT"]).write_text(
                "artifact-id<<ghadelimiter_one\n123\nghadelimiter_one\n"
                "artifact-digest<<ghadelimiter_two\n" + "a" * 64 + "\nghadelimiter_two\n")
    result = runtime._upload(tmp_path, "model", Publisher(), tmp_path)
    assert result == {"id": 123, "digest": "sha256:" + "a" * 64}


@pytest.mark.parametrize("role", ["plan", "deploy"])
def test_real_workflow_bridges_node_handler_runtime_before_credentials(role):
    import yaml
    workflow = yaml.safe_load((ROOT / ".github/workflows" / f"reusable-cnesdata-infra-{role}-gate.yml").read_text())
    steps = workflow["jobs"]["execute"]["steps"]
    bridges = [(index, step) for index, step in enumerate(steps) if step.get("uses", "").startswith("actions/github-script@")]
    assert len(bridges) == 1
    index, bridge = bridges[0]
    assert bridge["uses"] == "actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd"
    script = bridge["with"]["script"]
    for name in ("ACTIONS_RUNTIME_URL", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL"):
        assert '"' + name + '"' in script
    assert "const value = process.env[name]" in script
    assert "if (!value) throw" in script
    assert script.index("core.setSecret(value)") < script.index("core.exportVariable(name, value)")
    assert index < next(i for i, step in enumerate(steps) if step.get("run", "").endswith(" credentials"))
    assert index < next(i for i, step in enumerate(steps) if step.get("run", "").endswith(" execute"))


def test_publisher_missing_handler_runtime_fails_before_subprocess(monkeypatch):
    from tools.cnesdata_delivery import runtime
    monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)
    monkeypatch.setattr(runtime.subprocess, "run", lambda *args, **kwargs: pytest.fail("runtime bridge must be checked first"))
    with pytest.raises(ValueError, match="runtime bridge missing"):
        runtime._publisher_ready()


def test_product_process_remains_visible_to_runner_cleanup(monkeypatch):
    from tools.cnesdata_delivery import runtime
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(name, "temporary")
    monkeypatch.setenv("RUNNER_TRACKING_ID", "runner-owned")
    assert runtime._environment()["RUNNER_TRACKING_ID"] == "runner-owned"


@pytest.mark.parametrize("mutation", [None, "known", "extra", "missing", "output"])
def test_post_apply_state_resolves_only_saved_plan_unknowns(contract, mutation):
    expected = {"name": "approved", "arn": None, "nested": {"known": "fixed", "computed": None}}
    plan = {"resource_changes": [{"mode": "managed", "address": "aws_example.test",
        "change": {"actions": ["create"], "after": expected, "after_unknown": {"arn": True, "nested": {"computed": True}}}}],
        "output_changes": {"result": {"after": "fixed", "after_unknown": False}}}
    attributes = {"name": "approved", "arn": "resolved", "nested": {"known": "fixed", "computed": "resolved"}}
    state = {"resources": [{"mode": "managed", "type": "aws_example", "name": "test",
        "instances": [{"attributes": attributes}]}], "outputs": {"result": {"value": "fixed"}}}
    if mutation == "known":
        attributes["nested"]["known"] = "widened"
    elif mutation == "extra":
        attributes["unplanned"] = "value"
    elif mutation == "missing":
        state["resources"] = []
    elif mutation == "output":
        state["outputs"]["result"]["value"] = "different"
    if mutation is None:
        contract.applied_state(plan, state)
    else:
        with pytest.raises(ValueError):
            contract.applied_state(plan, state)


def test_applied_state_uses_lossless_count_and_foreach_indices(contract):
    plan = contract.loads(b'{"resource_changes":[{"mode":"managed","address":"aws_example.test[0]","change":{"after":{"name":"count"},"after_unknown":{}}},{"mode":"managed","address":"aws_example.other[\\"key\\"]","change":{"after":{"name":"foreach"},"after_unknown":{}}}]}', state=True)
    state = contract.loads(b'{"resources":[{"mode":"managed","type":"aws_example","name":"test","instances":[{"index_key":0,"attributes":{"name":"count"}}]},{"mode":"managed","type":"aws_example","name":"other","instances":[{"index_key":"key","attributes":{"name":"foreach"}}]}]}', state=True)
    contract.applied_state(plan, state)


def test_bootstrap_accepts_only_issued_same_certificate_with_unchanged_pending_state(outputs, contract):
    from fixtures.cnesdata_outputs import ACCOUNT, CERT, fixture
    state, api, observed, _, _ = fixture()
    state["resources"][0]["instances"][0]["attributes"]["status"] = "PENDING_VALIDATION"
    raw = contract.canonical(state)
    checkpoint = {"stage": "bootstrap-initial", "source_sha": "a" * 40, "expires_at": "2026-11-07T13:00:00Z",
        "state_before_sha256": contract.state_identity(raw)["state_sha256"], "certificate_arn": CERT}
    with pytest.raises(ValueError, match="certificate status"):
        outputs.initial_stage(raw, checkpoint, "a" * 40, api, ACCOUNT, 1794053700)
    observed["Status"] = "ISSUED"
    outputs.initial_stage(raw, checkpoint, "a" * 40, api, ACCOUNT, 1794053700)
    assert contract.canonical(state) == raw
    observed["CertificateArn"] = CERT + "-different"
    with pytest.raises(ValueError):
        outputs.initial_stage(raw, checkpoint, "a" * 40, api, ACCOUNT, 1794053700)


def test_apply_has_no_plan_subprocess():
    from tools.cnesdata_delivery import runtime
    import inspect
    source = inspect.getsource(runtime.execute)
    assert '"-refresh-only"' not in source
    assert 'command = [tofu, "apply", "-input=false", "-lock-timeout=20s", str(temp / "plan.bin")]' in source


@pytest.mark.parametrize("mutation", [None, "missing", "unknown", "source", "functional"])
def test_drift_requires_complete_source_bound_live_field_coverage(contract, mutation):
    change = {"before": {"name": "approved"}, "after": {"name": "approved"}}
    plan = {"resource_changes": [{"mode": "managed", "address": "aws_example.test", "change": change}]}
    reports = [{"observed": {"Name": "approved"}}]
    row = {"address": "aws_example.test", "attribute": "name", "readback": 0, "path": ["Name"], "encoding": "identity"}
    matrix = {"matrix_version": 1, "source_sha": "a" * 40, "purpose": "bootstrap", "before": [row], "after": [row]}
    if mutation == "missing":
        matrix["before"] = []
    elif mutation == "unknown":
        row["attribute"] = "unapproved"
    elif mutation == "source":
        matrix["source_sha"] = "b" * 40
    elif mutation == "functional":
        reports[0]["observed"]["Name"] = "different"
    if mutation is None:
        contract.drift_coverage(plan, reports, matrix, "a" * 40, "bootstrap", "before")
    else:
        with pytest.raises(ValueError):
            contract.drift_coverage(plan, reports, matrix, "a" * 40, "bootstrap", "before")


def test_r2_candidate_preserves_existing_canonical_number_spelling(contract):
    raw = b'{"measurement":1e-07,"repository":"VINIClUS/CnesData"}\n'
    assert contract.r2_candidate(raw)["measurement"] == 1e-7
    with pytest.raises(ValueError, match="R2 canonical"):
        contract.r2_candidate(raw.replace(b"1e-07", b"0.0000001"))


@pytest.mark.parametrize("mutation", [None, "state", "coordination", "binding"])
def test_completed_retry_reads_original_receipt_without_mutation(monkeypatch, tmp_path, contract, mutation):
    from types import SimpleNamespace
    from tools.cnesdata_delivery import runtime, outputs
    raw = contract.canonical({"lineage": "synthetic", "serial": 2, "resources": [], "outputs": {}})
    identity = contract.state_identity(raw)
    plan = {"purpose": "acm-certificate"}
    original = {"status": "applied", "plan_binding_sha256": "a" * 64, "plan": plan,
                "apply": {"producer": {"run_id": 12}, "state_after": identity, "outputs": {"exact": "original"}}}
    lease_reads = []
    def get_lease():
        lease_reads.append(1)
        return {"status": "released"}, "changed" if mutation == "coordination" and len(lease_reads) > 1 else "etag"
    lease = SimpleNamespace(store=SimpleNamespace(get=get_lease))
    result = {"envelope": original, "artifact_id": 100, "artifact_digest": "sha256:" + "b" * 64}
    monkeypatch.setattr(runtime, "previous_success", lambda *args, **kwargs: result)
    monkeypatch.setattr(contract, "validate_envelope", lambda *args, **kwargs: plan)
    monkeypatch.setattr(contract, "applied_state", lambda *args: None)
    monkeypatch.setattr(contract, "drift_coverage", lambda *args: None)
    monkeypatch.setattr(runtime, "_readbacks", lambda *args: [])
    monkeypatch.setattr(outputs, "acm", lambda *args: {"exact": "original"})
    monkeypatch.setattr(runtime.subprocess, "run", lambda *args, **kwargs: pytest.fail("retry cannot launch product child"))
    aws = SimpleNamespace(get=lambda *args: (raw + b" " if mutation == "state" else raw, None))
    if mutation == "state":
        original["apply"]["state_after"] = identity | {"serial": 3}
    requested = {"plan": plan, "plan_binding_sha256": "c" * 64 if mutation == "binding" else "a" * 64}
    output = tmp_path / "outputs"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    governance = {"state_bucket": "synthetic", "account_id": "111122223333", "drift_matrix": {}}
    if mutation in {"state", "coordination"}:
        with pytest.raises(ValueError):
            runtime._reuse_completed(aws, None, governance, lease, requested, {"plan.json": b"{}"}, {}, "d" * 40, "acm-certificate")
        assert not output.exists()
    else:
        reused = runtime._reuse_completed(aws, None, governance, lease, requested, {"plan.json": b"{}"}, {}, "d" * 40, "acm-certificate")
        assert reused is (mutation is None)
        if reused:
            assert output.read_text().splitlines() == ["evidence_run_id=12", "evidence_artifact_id=100",
                "evidence_artifact_digest=sha256:" + "b" * 64, "evidence_status=applied"]
