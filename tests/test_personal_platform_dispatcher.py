"""Offline boundary tests; these fixtures are never operational host evidence."""

import importlib
import io
import struct
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def runtime():
    try:
        return importlib.import_module("tools.cnesdata_delivery.host_gate")
    except ModuleNotFoundError:
        pytest.fail("EXT3 bounded host runtime is absent")


H = "a" * 64
SHA = "b" * 40


def manifest(action="deploy"):
    return {
        "project": "cnesdata",
        "source_repository": "VINIClUS/CnesData",
        "source_sha": SHA,
        "expires_at": "2030-01-01T00:00:00Z",
        "platform_plan": {
            "evidence_id": "object/version",
            "evidence_sha256": H,
            "inventory_sha256": H,
            "dependencies_sha256": H,
            "host_preflight_sha256": H,
            "host_key_fingerprint": "SHA256:host",
        },
        "images": {"api": "ghcr.io/viniclus/cnesdata@sha256:" + H},
        "compose_sha256": H,
        "config_sha256": H,
        "requested_action": action,
    }


def envelope(value=None):
    return {
        "schema_version": 1,
        "ci_evidence": {
            "repository": "VINIClUS/CnesData",
            "workflow": "ci.yml",
            "run_id": 1,
            "artifact_id": 2,
            "artifact_digest": "sha256:" + H,
        },
        "release_manifest": value or manifest(),
    }


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for name, data, kind in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            item.linkname = "compose.yml" if kind == tarfile.SYMTYPE else ""
            tar.addfile(item, io.BytesIO(data) if item.size else None)
    return stream.getvalue()


def good_archive():
    g = runtime()
    value = manifest()
    compose, config = b"services: {}\n", b"{}\n"
    value["compose_sha256"], value["config_sha256"] = g.sha(compose), g.sha(config)
    data = archive(
        [
            (n, b, tarfile.REGTYPE)
            for n, b in [
                ("release-manifest.json", g.canonical(value)),
                ("compose.yml", compose),
                ("config.json", config),
            ]
        ]
    )
    return value, data


def frame(data):
    return struct.pack(">Q", len(data)) + data


def test_exact_three_frames_and_token_is_redacted_and_erasable():
    g = runtime()
    value, data = good_archive()
    request = g.read_request(
        io.BytesIO(frame(g.canonical(envelope(value))) + frame(data) + frame(b"secret"))
    )
    assert request.archive == data
    assert request.token == bytearray(b"secret")
    assert "secret" not in repr(request)
    request.erase()
    assert request.token == bytearray(6)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\0" * 7,
        frame(b""),
        struct.pack(">Q", 65537),
        frame(b"{}") + frame(b"x") + frame(b"token") + b"extra",
    ],
)
def test_framing_rejects_before_unbounded_reads(data):
    with pytest.raises(ValueError):
        runtime().read_request(io.BytesIO(data))


@pytest.mark.parametrize("token", [b"a b", b"a\0b", b"a\nb", b"a\rb", b"a\x7fb"])
def test_token_control_bytes_rejected(token):
    g = runtime()
    with pytest.raises(ValueError):
        g.read_request(io.BytesIO(frame(b"{}") + frame(b"x") + frame(token)))


def test_closed_envelope_allowlist_is_trusted_configuration():
    g = runtime()
    value = envelope()
    g.validate_envelope(
        value, workflows={"ci.yml"}, images={"ghcr.io/viniclus/cnesdata"}, now=0
    )
    value["ci_evidence"]["run_id"] = True
    with pytest.raises(ValueError):
        g.validate_envelope(
            value, workflows={"ci.yml"}, images={"ghcr.io/viniclus/cnesdata"}, now=0
        )
    value = envelope()
    value["release_manifest"]["images"]["api"] = "ghcr.io/viniclus/cnesdata:latest"
    with pytest.raises(ValueError):
        g.validate_envelope(
            value, workflows={"ci.yml"}, images={"ghcr.io/viniclus/cnesdata"}, now=0
        )


def test_json_rejects_duplicate_float_depth_and_unknown_fields():
    g = runtime()
    for data in [
        b'{"a":1,"a":2}',
        b'{"a":1.0}',
        b'"\\ud800"',
        b"[" * 17 + b"0" + b"]" * 17,
    ]:
        with pytest.raises(ValueError):
            g.host_json(data)
    value = envelope()
    value["override"] = "untrusted"
    with pytest.raises(ValueError):
        g.validate_envelope(value, workflows={"ci.yml"}, images=set(), now=0)


def test_archive_hash_and_manifest_are_exact_before_staging(tmp_path):
    g = runtime()
    value, data = good_archive()
    files = g.inspect_archive(data, value, g.sha(data))
    assert set(files) == {"release-manifest.json", "compose.yml", "config.json"}
    staged = g.stage_archive(tmp_path, files)
    assert (staged / "compose.yml").read_bytes() == files["compose.yml"]
    assert staged.stat().st_mode & 0o777 == 0o700
    assert (staged / "compose.yml").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        g.inspect_archive(data, value, "0" * 64)
    value["source_sha"] = "c" * 40
    with pytest.raises(ValueError):
        g.inspect_archive(data, value, g.sha(data))


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../escape", tarfile.REGTYPE),
        ("/absolute", tarfile.REGTYPE),
        ("C:drive", tarfile.REGTYPE),
        ("compose.yml", tarfile.SYMTYPE),
        ("compose.yml", tarfile.DIRTYPE),
        ("compose.yml", tarfile.FIFOTYPE),
        ("extra", tarfile.REGTYPE),
    ],
)
def test_hostile_archive_members_never_extract(name, kind):
    g = runtime()
    value, _ = good_archive()
    data = archive([(name, b"evil", kind)])
    with pytest.raises(ValueError):
        g.inspect_archive(data, value, g.sha(data))


def test_archive_duplicate_and_size_bomb_fail_closed():
    g = runtime()
    value, _ = good_archive()
    for entries in [
        [("compose.yml", b"x", tarfile.REGTYPE)] * 2,
        [("compose.yml", b"x" * (1024**2 + 1), tarfile.REGTYPE)],
    ]:
        data = archive(entries)
        with pytest.raises(ValueError):
            g.inspect_archive(data, value, g.sha(data))


def test_compose_policy_denies_cross_tenant_and_unbounded_runtime():
    g = runtime()
    base = {
        "services": {
            "api": {
                "image": "ghcr.io/viniclus/cnesdata@sha256:" + H,
                "ports": [
                    {"host_ip": "127.0.0.1", "published": "18081", "target": 8000}
                ],
                "networks": {"cnesdata": {}},
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "mem_limit": "512m",
                "cpus": "0.5",
                "pids_limit": 128,
                "logging": {
                    "driver": "json-file",
                    "options": {"max-size": "10m", "max-file": "3"},
                },
                "healthcheck": {"test": ["CMD", "true"]},
            }
        },
        "networks": {"cnesdata": {"name": "cnesdata"}},
    }
    g.validate_compose(base, base["services"]["api"]["image"], 18081)
    import copy

    for key, value in [
        ("privileged", True),
        ("network_mode", "host"),
        ("volumes", ["/var/run/docker.sock:/socket"]),
        ("build", "."),
        ("networks", {"limnopulse": {}}),
        ("ports", ["0.0.0.0:8080:8000"]),
    ]:
        wrong = copy.deepcopy(base)
        wrong["services"]["api"][key] = value
        with pytest.raises(ValueError):
            g.validate_compose(wrong, base["services"]["api"]["image"], 18081)


def test_live_attempt_checks_do_not_accept_latest_or_ambiguous_boundaries():
    from test_personal_platform_deployer import binding

    g = runtime()
    b = binding()
    ref = b["ci_artifact"]["producer"]
    run = {
        "id": 12,
        "run_attempt": 1,
        "repository": {"full_name": "VINIClUS/CnesData"},
        "head_sha": SHA,
        "path": ref["workflow_path"],
        "status": "completed",
        "conclusion": "success",
        "run_started_at": "1970-01-01T00:14:00Z",
        "updated_at": "1970-01-01T00:16:00Z",
    }
    g.verify_run(run, ref)
    run["run_attempt"] = 2
    with pytest.raises(ValueError):
        g.verify_run(run, ref)


def test_host_response_rejects_nonce_mix_late_arrival_and_digest_tamper(tmp_path):
    from test_personal_platform_deployer import operation

    g, clock, op = operation(tmp_path)
    op.transition("VERIFIED")
    op.transition("ACCEPTED")
    raw = op.seal(
        H,
        g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600]),
        lambda: {"checked_processes": [], "all_absent_or_send_disabled": True},
    )
    g.accept_response(
        raw,
        binding=op.record["binding"],
        channel_nonce=H,
        now=1001,
        fixed_deadline=2800,
    )
    with pytest.raises(ValueError):
        g.accept_response(
            raw,
            binding=op.record["binding"],
            channel_nonce="f" * 64,
            now=1001,
            fixed_deadline=2800,
        )
    with pytest.raises(ValueError):
        g.accept_response(
            raw,
            binding=op.record["binding"],
            channel_nonce=H,
            now=1301,
            fixed_deadline=2800,
        )
    value = g.host_json(raw)
    value["receipt"]["observed_at"] = "1970-01-01T00:16:39Z"
    with pytest.raises(ValueError):
        g.accept_response(
            g.canonical(value),
            binding=op.record["binding"],
            channel_nonce=H,
            now=1001,
            fixed_deadline=2800,
        )


def test_host_workflow_has_only_ratified_interface_and_no_pr_credentials():
    import yaml

    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load(
        (root / ".github/workflows/reusable-cnesdata-host-deploy-gate.yml").read_text()
    )
    call = workflow["on"]["workflow_call"]
    assert set(call["inputs"]) == {
        "plan_evidence_id",
        "plan_evidence_digest",
        "plan_run_id",
        "artifact_id",
        "artifact_digest",
    }
    assert all(
        v == {"required": True, "type": "string"} for v in call["inputs"].values()
    )
    assert set(call["outputs"]) == {
        "status",
        "host_evidence_version",
        "host_evidence_sha256",
        "platform_evidence_version",
        "platform_evidence_sha256",
    }
    assert set(call["secrets"]) == {"host_governance"}
    assert workflow["permissions"] == {}
    assert "id-token" not in workflow["jobs"]["preflight"]["permissions"]
    assert workflow["jobs"]["execute"]["needs"] == "preflight"
    assert set(workflow["on"]) == {"workflow_call"}
    text = (
        root / ".github/workflows/reusable-cnesdata-host-deploy-gate.yml"
    ).read_text()
    assert "secrets: inherit" not in text and "self-hosted" not in text
    assert 'core.getInput("github-token"' in text and "input:" in text
    steps = workflow["jobs"]["execute"]["steps"]
    upload = next(i for i, s in enumerate(steps) if s.get("id") == "handoff")
    gate = next(i for i, s in enumerate(steps) if s.get("id") == "gate")
    assert gate < upload < len(steps) - 1
    assert "result.status !== 2" in steps[gate]["with"]["script"]
    assert (
        steps[upload]["with"]["path"]
        == "${{ runner.temp }}/cnesdata-host-public/host-handoff.json"
    )
    assert steps[upload]["with"]["overwrite"] is False
    assert steps[-1]["run"] == "exit 1" and "status != 'accepted'" in steps[-1]["if"]


def authenticated_fixture(tmp_path, monkeypatch):
    import base64
    import copy
    import zipfile

    from test_personal_platform_deployer import binding

    g = runtime()
    source_path = Path(g.__file__)
    (tmp_path / "host_gate.py").write_bytes(source_path.read_bytes())
    (tmp_path / "contract.py").write_bytes(
        source_path.with_name("contract.py").read_bytes()
    )
    (tmp_path / "contract.py").chmod(0o600)
    monkeypatch.setattr(g, "__file__", str(tmp_path / "host_gate.py"))
    manifest_value, tar = good_archive()
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as z:
        z.writestr("release.tar.gz", tar)
    raw = zipped.getvalue()
    outer = envelope(manifest_value)
    outer["ci_evidence"].update(
        run_id=12, artifact_id=20, artifact_digest="sha256:" + g.sha(raw)
    )
    b = binding()
    b["platform"].update(manifest_value["platform_plan"])
    b["caller"]["run_id"] = 11
    b["ci_artifact"]["producer"] = copy.deepcopy(b["ci_artifact"]["producer"])
    b["ci_artifact"]["producer"].update(
        run_id=12, workflow_path=".github/workflows/ci.yml"
    )
    b["ci_artifact"].update(
        created_at="2029-12-31T23:01:00Z",
        expires_at="2030-01-01T00:00:00Z",
        artifact_digest="sha256:" + g.sha(raw),
    )
    b["requested_action"] = "validate"
    manifest_value["requested_action"] = "validate"
    # Rebuild archive after the manifest's requested action changes.
    files = g.inspect_archive(tar, good_archive()[0], g.sha(tar))
    tar = archive(
        [
            (
                name,
                g.canonical(manifest_value)
                if name == "release-manifest.json"
                else data,
                tarfile.REGTYPE,
            )
            for name, data in files.items()
        ]
    )
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as z:
        z.writestr("release.tar.gz", tar)
    raw = zipped.getvalue()
    outer["ci_evidence"]["artifact_digest"] = b["ci_artifact"]["artifact_digest"] = (
        "sha256:" + g.sha(raw)
    )
    b["original_bytes"].update(
        envelope_sha256=g.sha(g.canonical(outer)),
        manifest_sha256=g.sha(g.canonical(manifest_value)),
        archive_sha256=g.sha(tar),
        compose_sha256=manifest_value["compose_sha256"],
        config_sha256=manifest_value["config_sha256"],
    )
    for expiry in b["expires"]:
        expiry["expires_at"] = "2030-01-01T00:00:00Z"
    source = b"original owner governance"
    b["approval"]["governance_sha256"] = g.sha(source)
    gov = {
        "binding": b,
        "workflows": ["ci.yml"],
        "images": ["ghcr.io/viniclus/cnesdata"],
        "required_checks": [{"name": "CI", "app_id": 99}],
        "archive_member": "release.tar.gz",
        "source_files": [
            {
                "repository": "VINIClUS/infra-ansible",
                "source_sha": SHA,
                "path": "governance.json",
                "sha256": g.sha(source),
            }
        ],
    }
    cf = {
        "plan": "FREE",
        "status": "ACTIVE",
        "subscription_sha256": H,
        "distribution_sha256": H,
        "waf_binding_sha256": H,
        "observed_at": "2029-12-31T23:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
    }
    stage = {
        "stage": "active",
        "source_sha": SHA,
        "checkpoint_sha256": H,
        "target_sha256": H,
        "cloudfront": cf,
    }
    financial = {
        "source_sha": SHA,
        "gross": True,
        "credits_usd": "0.00",
        "calculated_at": "2029-12-31T23:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "components": [
            {
                "category": category,
                "scope": "product",
                "monthly_usd": "1.00",
                "unbound": False,
            }
            for category in (
                "kms-encryption",
                "kms-signing",
                "s3-requests-versions-logs",
                "cloudfront-waf",
            )
        ],
    }
    cost = {
        "verdict": "pass",
        "manifest_sha256": g.sha(g.canonical(financial)),
        "product_monthly_usd": "4.00",
        "aggregate_monthly_usd": "4.00",
        "paid_actions_limit_usd": "0.00",
        "calculated_at": financial["calculated_at"],
        "expires_at": financial["expires_at"],
        "scope": "active",
        "cloudfront": cf,
    }
    measured = {
        "check_id": "cost-ledger-purpose-scope",
        "source_sha": SHA,
        "measurement": {
            "cost": dict(cost),
            "checkpoint": stage,
            "manifest_sha256": cost["manifest_sha256"],
        },
    }
    cost["evidence_sha256"] = g.sha(g.canonical(measured))
    gov["cost_handoff"] = {
        "cost": cost,
        "stage": stage,
        "evidence": measured,
        "manifest": financial,
    }
    gov["runtime_contract_sha256"] = g.sha(
        Path(g.__file__).with_name("contract.py").read_bytes()
    )
    next(e for e in b["expires"] if e["name"] == "cost")["source_sha256"] = g.sha(
        g.canonical(cost)
    )
    caller = {
        "id": 11,
        "run_attempt": 1,
        "repository": {"full_name": "VINIClUS/CnesData"},
        "head_sha": SHA,
        "path": ".github/workflows/deploy.yml",
        "event": "workflow_dispatch",
        "head_branch": "develop",
        "status": "in_progress",
        "referenced_workflows": [
            {
                "sha": SHA,
                "path": "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-host-deploy-gate.yml@"
                + SHA,
            }
        ],
    }
    producer = {
        "id": 12,
        "run_attempt": 1,
        "repository": {"full_name": "VINIClUS/CnesData"},
        "head_sha": SHA,
        "path": ".github/workflows/ci.yml",
        "status": "completed",
        "conclusion": "success",
        "run_started_at": "2029-12-31T23:00:00Z",
        "updated_at": "2029-12-31T23:02:00Z",
    }
    metadata = {
        "id": 20,
        "digest": "sha256:" + g.sha(raw),
        "expired": False,
        "workflow_run": {"id": 12, "head_sha": SHA},
        "created_at": b["ci_artifact"]["created_at"],
        "expires_at": b["ci_artifact"]["expires_at"],
    }
    responses = {
        "repos/VINIClUS/CnesData/actions/runs/11/attempts/1": caller,
        "repos/VINIClUS/CnesData/actions/runs/12/attempts/1": producer,
        "repos/VINIClUS/CnesData/compare/" + SHA + "...develop": {
            "status": "ahead",
            "merge_base_commit": {"sha": SHA},
        },
        "repos/VINIClUS/CnesData/commits/" + SHA + "/check-runs?per_page=100": {
            "total_count": 1,
            "check_runs": [
                {
                    "name": "CI",
                    "app": {"id": 99},
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": SHA,
                }
            ],
        },
        "repos/VINIClUS/infra-ansible/contents/governance.json?ref=" + SHA: {
            "type": "file",
            "size": len(source),
            "content": base64.b64encode(source).decode(),
        },
        "repos/VINIClUS/CnesData/actions/artifacts/20": metadata,
        "repos/VINIClUS/CnesData/actions/artifacts/20/zip": raw,
    }

    class API:
        def read(self, path, **kwargs):
            return copy.deepcopy(responses[path])

    return (
        g.Request(outer, g.canonical(outer), tar, bytearray(b"fixture-token")),
        gov,
        API(),
        responses,
    )


def test_complete_original_source_admission_checks_real_archive_bytes(
    tmp_path, monkeypatch
):
    g = runtime()
    request, gov, api, _ = authenticated_fixture(tmp_path, monkeypatch)
    b, files = g.authenticate_request(
        request, gov, api, g.instant("2029-12-31T23:03:00Z")
    )
    assert b == gov["binding"]
    assert set(files) == {"release-manifest.json", "compose.yml", "config.json"}


@pytest.mark.parametrize(
    "mutation",
    [
        "attempt",
        "mutable-pin",
        "wrong-source",
        "expired",
        "boundary-time",
        "zip-tamper",
    ],
)
def test_live_source_counterexamples_reject_before_any_credential_call(
    mutation, tmp_path, monkeypatch
):
    g = runtime()
    request, gov, api, responses = authenticated_fixture(tmp_path, monkeypatch)
    producer = responses["repos/VINIClUS/CnesData/actions/runs/12/attempts/1"]
    metadata = responses["repos/VINIClUS/CnesData/actions/artifacts/20"]
    if mutation == "attempt":
        producer["run_attempt"] = 2
    elif mutation == "mutable-pin":
        responses["repos/VINIClUS/CnesData/actions/runs/11/attempts/1"][
            "referenced_workflows"
        ][0][
            "path"
        ] = "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-host-deploy-gate.yml@main"
    elif mutation == "wrong-source":
        producer["head_sha"] = "d" * 40
    elif mutation == "expired":
        metadata["expired"] = True
    elif mutation == "boundary-time":
        producer["run_started_at"] = metadata["created_at"]
    else:
        responses["repos/VINIClUS/CnesData/actions/artifacts/20/zip"] += b"tamper"
    with pytest.raises(ValueError):
        g.authenticate_request(request, gov, api, g.instant("2029-12-31T23:03:00Z"))


def test_missing_original_closed_ready_consumer_blocks_mutation_before_credentials():
    from test_personal_platform_deployer import binding

    g = runtime()
    b = binding()
    g.admit_physical_action(b)
    for action in ("deploy", "rollback-previous"):
        b["requested_action"] = action
        with pytest.raises(ValueError, match="ClosedReady"):
            g.admit_physical_action(b)


def closed_ready_fixture():
    """Synthetic ORIGINAL producer output, transported through the real verifier."""
    import base64
    import copy
    import zipfile

    from test_personal_platform_deployer import binding
    from test_personal_platform_lease import Clock

    g, clock, b = runtime(), Clock(), binding()
    b["caller"]["workflow_path"] = ".github/workflows/promote-production.yml"
    b["requested_action"] = "deploy"
    b["release"] = {
        "repository": "VINIClUS/CnesData",
        "release_id": "fixture",
        "source_sha": SHA,
        "candidate_sha256": H,
        "canary_id": "a" * 32,
        "binding_sha256": H,
        "activation_sha256": H,
        "signature_sha256": H,
        "phase_a_evidence_sha256": H,
        "ecr_image_digest": "sha256:" + H,
        **{
            k + "_revision": "arn:aws:states:us-east-1:111111111111:stateMachine:"
            + k
            + ":1"
            for k in ("unit", "recovery", "audit")
        },
    }
    common = {
        k: b["release"][k]
        for k in (
            "repository",
            "release_id",
            "source_sha",
            "candidate_sha256",
            "canary_id",
            "activation_sha256",
        )
    }
    common.update(
        promotion_id="promotion-fixture",
        promotion_generation=4,
        caller=copy.deepcopy(b["caller"]),
    )
    fence = {
        "environment": "prod",
        "state": "CLOSED",
        "promotion_id": common["promotion_id"],
        "version": 7,
        "changed_at": g.utc(660),
    }
    proof = b"synthetic original executor terminal and send-disabled observation"
    members = [
        {
            "dispatch_id": "a" * 16,
            "request_sha256": H,
            "generation": 3,
            "initial_state": "ACKNOWLEDGED",
            "execution_ref": "arn:aws:states:us-east-1:111111111111:execution:fixture:run",
            "resolution": "TERMINAL",
            "proof_sha256": g.sha(proof),
            "observed_at": g.utc(750),
            "send_disabled_at": g.utc(750),
        }
    ]
    proofs = [
        {"sha256": g.sha(proof), "bytes_base64": base64.b64encode(proof).decode()}
    ]
    close = {
        "version": 1,
        "kind": "close-drain",
        "common": copy.deepcopy(common),
        "fence": copy.deepcopy(fence),
        "close_confirmed_at": g.utc(660),
        "drain_observed_at": g.utc(760),
        "frozen_membership_sha256": g.sha(g.canonical(members)),
        "members": copy.deepcopy(members),
        "proofs": proofs,
        "permit": None,
        "input_expirations": [
            {
                "kind": e["name"],
                "object_sha256": e["source_sha256"],
                "expires_at": e["expires_at"],
            }
            for e in b["expires"]
        ],
        "fixed_deadline": g.utc(2460),
        "decision": None,
    }
    checkpoint = {
        "lineage": "original-lineage",
        "serial": 3,
        "state_sha256": H,
        "object_version": "original-version",
    }
    machine = "arn:aws:states:us-east-1:111111111111:stateMachine:processor"
    phase = {
        "version": 1,
        "kind": "phase-b",
        "common": copy.deepcopy(common),
        "close_drain_sha256": H,
        "before": checkpoint,
        "after": {**checkpoint, "serial": 4, "object_version": "after-version"},
        "plan_sha256": H,
        "audit_sha256": H,
        "apply_sha256": H,
        "routes": {
            "mode": "initial",
            "state_machine_arn": machine,
            "unit_revision": b["release"]["unit_revision"],
            "recovery_revision": b["release"]["recovery_revision"],
            "audit_revision": b["release"]["audit_revision"],
            "unit_environment_state_machine_arn": machine,
            "recovery_environment_state_machine_arn": machine,
        },
        "observed_at": g.utc(950),
    }
    ready = {
        "version": 1,
        "kind": "closed-ready",
        "common": copy.deepcopy(common),
        "close_drain_sha256": H,
        "phase_b_sha256": H,
        "fence": copy.deepcopy(fence),
        "permit": None,
        "members": copy.deepcopy(members),
        "proofs": copy.deepcopy(proofs),
        "observed_at": g.utc(960),
        "exclusion": {
            "owner": copy.deepcopy(b["caller"]),
            "generation": 4,
            "membership_sha256": g.sha(g.canonical(members)),
            "acquired_at": g.utc(650),
            "observed_at": g.utc(960),
        },
        "stage": {
            "name": "api",
            "admitted_at": g.utc(960),
            "deadline": g.utc(1140),
            "later_seconds": 840,
        },
        "decision": None,
    }
    for member in ready["members"]:
        member["observed_at"] = member["send_disabled_at"] = g.utc(955)
    ready["exclusion"]["membership_sha256"] = g.sha(g.canonical(ready["members"]))
    paths = [
        b["caller"]["workflow_path"],
        "scripts/promotion/environment_gate.py",
        "scripts/promotion/phase_b.py",
        "scripts/promotion/verify_routes.py",
        "scripts/promotion/promote_api.py",
    ]
    source = b"synthetic approved source closure"
    gov = {
        "binding": b,
        "source_files": [
            {
                "repository": "VINIClUS/CnesData",
                "source_sha": SHA,
                "path": p,
                "sha256": g.sha(source),
            }
            for p in paths
        ],
    }
    prefix = "repos/VINIClUS/CnesData/"
    run = {
        "id": 12,
        "run_attempt": 1,
        "repository": {"full_name": "VINIClUS/CnesData", "id": 100},
        "head_repository": {"id": 100},
        "head_sha": SHA,
        "path": b["caller"]["workflow_path"],
        "event": "workflow_dispatch",
        "head_branch": "develop",
        "status": "in_progress",
        "run_started_at": g.utc(640),
    }
    job = {
        "id": 55,
        "name": "closed-ready",
        "run_id": 12,
        "run_attempt": 1,
        "head_sha": SHA,
        "status": "completed",
        "conclusion": "success",
        "started_at": g.utc(650),
        "completed_at": g.utc(980),
    }
    name = "cnesdata-closed-ready-12-1"
    meta = {
        "id": 66,
        "name": name,
        "expired": False,
        "digest": "sha256:" + H,
        "created_at": g.utc(970),
        "expires_at": g.utc(3600),
        "workflow_run": {
            "id": 12,
            "repository_id": 100,
            "head_repository_id": 100,
            "head_sha": SHA,
            "head_branch": "develop",
        },
    }
    responses = {
        prefix + "actions/runs/12/attempts/1": run,
        prefix + "actions/runs/12/attempts/1/jobs?per_page=100": {
            "total_count": 1,
            "jobs": [job],
        },
        prefix + "actions/runs/12/artifacts?name=" + name + "&per_page=100": {
            "total_count": 1,
            "artifacts": [meta],
        },
        prefix + "actions/artifacts/66": meta,
        **{
            prefix + "contents/" + p + "?ref=" + SHA: {
                "type": "file",
                "size": len(source),
                "content": base64.b64encode(source).decode(),
            }
            for p in paths
        },
    }

    def pack():
        raw_close = g.canonical(close)
        phase["close_drain_sha256"] = ready["close_drain_sha256"] = g.sha(raw_close)
        raw_phase = g.canonical(phase)
        ready["phase_b_sha256"] = g.sha(raw_phase)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as z:
            for member, raw in (
                ("close-drain.json", raw_close),
                ("phase-b.json", raw_phase),
                ("closed-ready.json", g.canonical(ready)),
            ):
                z.writestr(member, raw)
        payload = stream.getvalue()
        meta["digest"] = "sha256:" + g.sha(payload)
        responses[prefix + "actions/artifacts/66/zip"] = payload

    class API:
        def read(self, path, **kwargs):
            return copy.deepcopy(responses[path])

    pack()
    return g, clock, gov, API(), responses, close, phase, ready, pack


def test_original_closed_ready_admits_host_without_future_open(tmp_path):
    from test_personal_platform_lease import owner

    g, clock, gov, api, _, _, _, ready, _ = closed_ready_fixture()
    admission = g.admit_physical_action(gov["binding"], gov, api, clock)
    window = admission.window(clock)
    assert window.fixed_deadline == 2460
    assert window.stage_deadline == 1140
    lease = g.HostLease(tmp_path, clock)
    token, snapshot = lease.acquire(owner(), H)
    b = dict(
        gov["binding"],
        initial_generation=snapshot["lease"]["generation"],
        lease_owner_sha256=g.sha(token),
    )
    op = g.Operation(lease, token, snapshot, b, {"fixture": b"original"})
    op.bind_closed_ready(admission)
    g.Watchdog(op, window).tick()
    assert op.record["close_confirmed_at"] is None
    assert g.host_json(g.read_private(op.directory / "closed-ready-binding.json"))[
        "closed_ready_sha256"
    ] == g.sha(g.canonical(ready))
    with pytest.raises(ValueError, match="immutable|bound"):
        op.bind_closed_ready(admission)


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-attempt",
        "wrong-job",
        "wrong-source",
        "wrong-generation",
        "wrong-binding",
        "duplicate-artifact",
        "artifact-interval",
        "artifact-expired",
        "tampered-zip",
        "missing-source",
        "membership-omitted",
        "pending",
        "permit",
        "route",
        "checkpoint",
        "late-send",
        "late-handoff",
        "deadline",
        "fixed-expiry",
    ],
)
def test_closed_ready_counterexamples_refuse_before_effect(mutation):
    g, clock, gov, api, responses, close, phase, ready, pack = closed_ready_fixture()
    prefix = "repos/VINIClUS/CnesData/"
    if mutation == "wrong-attempt":
        responses[prefix + "actions/runs/12/attempts/1"]["run_attempt"] = 2
    elif mutation == "wrong-job":
        responses[prefix + "actions/runs/12/attempts/1/jobs?per_page=100"]["jobs"][0][
            "name"
        ] = "other"
    elif mutation == "wrong-source":
        responses[prefix + "actions/runs/12/attempts/1"]["head_sha"] = "c" * 40
    elif mutation == "wrong-generation":
        ready["exclusion"]["generation"] += 1
    elif mutation == "wrong-binding":
        ready["common"]["candidate_sha256"] = "b" * 64
    elif mutation == "duplicate-artifact":
        responses[
            prefix
            + "actions/runs/12/artifacts?name=cnesdata-closed-ready-12-1&per_page=100"
        ]["total_count"] = 2
    elif mutation == "artifact-interval":
        responses[prefix + "actions/artifacts/66"]["created_at"] = g.utc(650)
    elif mutation == "artifact-expired":
        responses[prefix + "actions/artifacts/66"]["expired"] = True
    elif mutation == "missing-source":
        gov["source_files"].pop()
    elif mutation == "membership-omitted":
        ready["members"] = []
    elif mutation == "pending":
        ready["members"][0]["resolution"] = "OUTCOME_UNKNOWN"
    elif mutation == "permit":
        ready["permit"] = {"holder": "busy"}
    elif mutation == "route":
        phase["routes"]["unit_environment_state_machine_arn"] += "wrong"
    elif mutation == "checkpoint":
        phase["after"]["serial"] = phase["before"]["serial"]
    elif mutation == "late-send":
        ready["members"][0]["send_disabled_at"] = g.utc(1001)
    elif mutation == "late-handoff":
        clock.advance(1410)  # close+1750, fresh lease would still have300.
    elif mutation == "deadline":
        clock.advance(110)
    elif mutation == "fixed-expiry":
        close["fixed_deadline"] = g.utc(1100)
    pack()
    if mutation == "tampered-zip":
        responses[prefix + "actions/artifacts/66/zip"] += b"tamper"
    with pytest.raises(ValueError):
        g.admit_physical_action(gov["binding"], gov, api, clock)
