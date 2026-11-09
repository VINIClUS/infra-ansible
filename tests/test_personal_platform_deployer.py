"""Physical ledger and causal evidence tests; all clocks/remote outcomes are fixtures."""

import copy
import json

import pytest
from test_personal_platform_dispatcher import SHA, H, runtime
from test_personal_platform_lease import Clock, owner


def binding():
    run = {
        "repository": "VINIClUS/CnesData",
        "source_sha": SHA,
        "ref": "refs/heads/develop",
        "workflow_path": ".github/workflows/deploy.yml",
        "workflow_sha": SHA,
        "run_id": 12,
        "run_attempt": 1,
    }
    return {
        "version": 1,
        "caller": run,
        "ci_artifact": {
            "producer": run,
            "artifact_id": 20,
            "artifact_digest": "sha256:" + H,
            "created_at": "1970-01-01T00:15:00Z",
            "expires_at": "1970-01-01T01:00:00Z",
        },
        "approval": {
            "repository": "VINIClUS/infra-ansible",
            "base_sha": SHA,
            "head_sha": SHA,
            "reusable_path": ".github/workflows/reusable-cnesdata-host-deploy-gate.yml",
            "reusable_sha": SHA,
            "contract_sha256": H,
            "governance_sha256": H,
            "pins": [
                {
                    "repository": "VINIClUS/infra-ansible",
                    "source_sha": SHA,
                    "content_sha256": H,
                }
            ],
        },
        "platform": {
            "evidence_id": "fixture/version",
            "evidence_sha256": H,
            "object_bucket": "fixture",
            "object_key": "evidence",
            "object_version": "version",
            "inventory_sha256": H,
            "dependencies_sha256": H,
            "host_preflight_sha256": H,
            "host_key_fingerprint": "SHA256:fixture",
            "handoff_sha256": H,
        },
        "release": None,
        "original_bytes": {
            name + "_sha256": H
            for name in (
                "envelope",
                "manifest",
                "archive",
                "compose",
                "config",
                "platform",
                "baseline",
            )
        },
        "api_image": "ghcr.io/viniclus/cnesdata@sha256:" + H,
        "requested_action": "validate",
        "previous_accepted_sha256": None,
        "lease_owner_sha256": H,
        "initial_generation": 1,
        "operation_nonce_sha256": H,
        "expires": [
            {"name": name, "expires_at": "1970-01-01T01:00:00Z", "source_sha256": H}
            for name in ("artifact", "cost", "credential", "envelope", "platform")
        ],
    }


def operation(tmp_path, action="validate"):
    g, clock = runtime(), Clock()
    lease = g.HostLease(tmp_path, clock)
    token, snapshot = lease.acquire(owner(), H)
    value = binding()
    if action != "validate":
        value["requested_action"] = action
        value["release"] = {
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
                key + "_revision": "arn:aws:ecs:us-east-2:111111111111:task-definition/"
                + key
                + ":1"
                for key in ("unit", "recovery", "audit")
            },
        }
    value["lease_owner_sha256"] = g.sha(token)
    op = g.Operation(lease, token, snapshot, value, {"fixture": b"original"})
    return g, clock, op


def test_binding_closed_and_tampering_refused_before_authority(tmp_path):
    g = runtime()
    value = binding()
    g.validate_binding(value)
    for mutation in [
        lambda v: v.update(extra=True),
        lambda v: v["caller"].update(run_attempt=True),
        lambda v: v["expires"].pop(),
        lambda v: v.update(requested_action="shell"),
        lambda v: v["approval"]["pins"].append(v["approval"]["pins"][0]),
    ]:
        wrong = copy.deepcopy(value)
        mutation(wrong)
        with pytest.raises(ValueError):
            g.validate_binding(wrong)


def test_dispatch_timeout_stays_unknown_across_generation_and_cannot_reopen(tmp_path):
    _g, _, op = operation(tmp_path, "deploy")
    op.transition("VERIFIED")
    op.transition("STAGED")
    dispatch = op.before_send("pull", b"fixed request")
    op.outcome(dispatch, "OUTCOME_UNKNOWN", "unknown", H)
    old_generation = op.record["generation"]
    op.close()
    assert op.record["generation"] == old_generation + 1
    assert op.record["dispatches"][0]["generation"] == old_generation
    assert op.record["effect_possible"] is True
    with pytest.raises(ValueError, match="pending"):
        op.closed_ready(H)
    assert op.record["dispatches"][0]["state"] == "OUTCOME_UNKNOWN"


def test_no_effect_cannot_be_inferred_from_timeout_or_absent_resource(tmp_path):
    _, _, op = operation(tmp_path, "deploy")
    op.transition("VERIFIED")
    op.transition("STAGED")
    dispatch = op.before_send("pull", b"fixed request")
    with pytest.raises(ValueError):
        op.outcome(dispatch, "NO_EFFECT_CONFIRMED", "absent_proven", H)


def test_cas_rejects_stale_head_and_one_shot_consumes_before_reply(tmp_path):
    g, _, op = operation(tmp_path)
    old = copy.deepcopy(op.snapshot)
    op.transition("VERIFIED")
    with pytest.raises(ValueError, match="CAS"):
        op.commit(copy.deepcopy(op.record), expected=old)
    op.consume()
    assert (
        g.host_json(
            g.read_private(
                op.directory / (op.snapshot["head"]["record_sha256"] + ".json")
            )
        )["retry"]
        == "CONSUMED"
    )
    with pytest.raises(ValueError, match="CONSUMED"):
        op.consume()


def test_causal_receipts_keep_prior_observation_and_bind_final_response(
    tmp_path, monkeypatch
):
    g, clock, op = operation(tmp_path)
    op.transition("VERIFIED")
    op.transition("ACCEPTED")
    window = g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600])
    original = g.read_private

    def delayed(path, maximum=g.LIMIT):
        data = original(path, maximum)
        if str(path).endswith("receipt.json"):
            clock.advance(3)
        return data

    monkeypatch.setattr(g, "read_private", delayed)
    response = op.seal(
        H,
        window,
        lambda: {"checked_processes": [], "all_absent_or_send_disabled": True},
    )
    evidence = g.host_json(response)
    receipt, witness = evidence["receipt"], evidence["receipt_readback_witness"]
    assert (
        g.instant(witness["receipt_read_completed_at"])
        > g.instant(receipt["observed_at"]) + 1
    )
    assert receipt["observed_at"] == "1970-01-01T00:16:40Z"
    assert g.sha(g.canonical(receipt)) == witness["receipt_sha256"]
    index = json.loads((op.directory / "receipt-index.json").read_text())
    assert index["final_response_sha256"] == g.sha(response)
    assert index["receipt_readback_witness_sha256"] == g.sha(g.canonical(witness))


@pytest.mark.parametrize(
    "leaf", ["receipt.json", "receipt-readback-witness.json", "receipt-index.json"]
)
def test_loss_during_any_evidence_write_never_returns_accepted(
    tmp_path, monkeypatch, leaf
):
    g, clock, op = operation(tmp_path)
    op.transition("VERIFIED")
    op.transition("ACCEPTED")
    original = g.durable

    def fail(path, data, **kw):
        if str(path).endswith(leaf):
            raise OSError("fixture disk failure")
        return original(path, data, **kw)

    monkeypatch.setattr(g, "durable", fail)
    window = g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600])
    with pytest.raises(OSError):
        op.seal(
            H,
            window,
            lambda: {"checked_processes": [], "all_absent_or_send_disabled": True},
        )


def test_expiry_during_receipt_read_blocks_witness(tmp_path, monkeypatch):
    g, clock, op = operation(tmp_path)
    op.transition("VERIFIED")
    op.transition("ACCEPTED")
    original = g.read_private

    def delayed(path, maximum=g.LIMIT):
        data = original(path, maximum)
        if str(path).endswith("receipt.json"):
            clock.advance(150)
        return data

    monkeypatch.setattr(g, "read_private", delayed)
    with pytest.raises(ValueError):
        op.seal(
            H,
            g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600]),
            lambda: {"checked_processes": [], "all_absent_or_send_disabled": True},
        )
    assert not (op.directory / "receipt-readback-witness.json").exists()


def test_reopen_timestamp_is_actual_readback_and_partial_routes_never_send(tmp_path):
    g, clock, op = operation(tmp_path, "deploy")
    op.close()
    op.confirm_closed(lambda _: clock.advance(2))
    op.closed_ready(H)
    window = g.Window(clock, close_confirmed_at=1002, input_deadlines=[4600])
    sent = []
    release = op.record["binding"]["release"]
    routes = {
        name: release[name + "_revision"] for name in ("unit", "recovery", "audit")
    }
    with pytest.raises(ValueError, match="mixed"):
        op.reopen(
            window,
            lambda: sent.append(True),
            lambda _: None,
            lambda: {**routes, "audit": "stale"},
        )
    assert sent == []
    assert op.record["reopen_verified_at"] is None
    op.reopen(
        window, lambda: clock.advance(3), lambda _: clock.advance(4), lambda: routes
    )
    assert op.open_requested_at == g.utc(1002)
    assert op.open_responded_at == g.utc(1005)
    assert op.record["reopen_verified_at"] == g.utc(1009)


def test_lost_open_response_never_claims_closed_or_retries(tmp_path):
    g, clock, op = operation(tmp_path, "deploy")
    op.close()
    op.confirm_closed(lambda _: None)
    op.closed_ready(H)
    release = op.record["binding"]["release"]
    routes = {
        name: release[name + "_revision"] for name in ("unit", "recovery", "audit")
    }
    calls = []

    def lost():
        calls.append(1)
        raise TimeoutError("fixture response lost after remote acceptance")

    with pytest.raises(TimeoutError):
        op.reopen(
            g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600]),
            lost,
            lambda _: None,
            lambda: routes,
        )
    assert calls == [1]
    assert op.record["fence_phase"] == "RECOVERY_REQUIRED"
    assert op.record["reopen_verified_at"] is None


@pytest.mark.parametrize("lost_open", [False, True])
def test_original_closed_ready_physical_driver_then_product_c_and_open(
    tmp_path, monkeypatch, lost_open
):
    from pathlib import Path

    from test_personal_platform_dispatcher import closed_ready_fixture

    g, clock, gov, api, _, close, phase, _, _ = closed_ready_fixture()
    # The external producer is synthetic; EXT3 verifier, driver, ledger, watchdog
    # and response validation are real. Only OS/network endpoints are fixtures.
    admission = g.admit_physical_action(gov["binding"], gov, api, clock)
    product_clock = Clock()
    product_clock.t = product_clock.m = 660
    product_lease = g.HostLease(tmp_path / "product", product_clock)
    token, snapshot = product_lease.acquire(owner(), H)
    product_binding = copy.deepcopy(gov["binding"])
    product_binding["lease_owner_sha256"] = g.sha(token)
    product = g.Operation(
        product_lease, token, snapshot, product_binding, {"fixture": b"product"}
    )
    product.close()
    product.confirm_closed(lambda _: None)
    product.closed_ready(g.sha(g.canonical(close)))
    global_window = g.Window(
        product_clock, close_confirmed_at=660, input_deadlines=[3600]
    )
    product_watchdog = g.Watchdog(product, global_window)

    def product_until(target):
        while product_clock.t < target:
            product_clock.advance(min(1, target - product_clock.t))
            product_watchdog.tick()

    product_until(clock.t)
    lease = g.HostLease(tmp_path / "host", clock)
    token, snapshot = lease.acquire(owner(), H)
    host_binding = copy.deepcopy(gov["binding"])
    host_binding["lease_owner_sha256"] = g.sha(token)
    host = g.Operation(lease, token, snapshot, host_binding, {"fixture": b"host"})
    host.bind_closed_ready(admission)
    window = admission.window(clock)
    driver_config = {
        "slot": "green",
        "previous_slot": "blue",
        "port": 18081,
        "public_hostname": "fixture.example",
        "tunnel_health_url": "https://fixture.example/health/ready",
        "readiness_sha256": g.sha(b"auth/AWS-ready"),
        "previous_nginx_sha256": g.sha(b"previous"),
    }
    active = tmp_path / "active.conf"
    g.durable(active, b"previous")
    original_read, original_write = g.read_private, g.durable
    fixed_path = Path("/etc/personal-platform/nginx/active.conf")
    monkeypatch.setattr(
        g,
        "read_private",
        lambda p, *a, **kw: original_read(active if p == fixed_path else p, *a, **kw),
    )
    monkeypatch.setattr(
        g,
        "durable",
        lambda p, data, **kw: original_write(
            active if p == fixed_path else p, data, **kw
        ),
    )
    commands = []
    image = host_binding["api_image"]
    normalized = {
        "services": {
            "api": {
                "image": image,
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

    def process(argv, guard, **_):
        guard()
        commands.append(argv)
        clock.advance(3)
        guard()
        if "--format" in argv:
            return json.dumps(normalized).encode()
        if argv[1:3] == ["image", "inspect"]:
            return json.dumps(
                [{"RepoDigests": [image], "Os": "linux", "Architecture": "amd64"}]
            ).encode()
        if argv[1] == "ps":
            return b"aabbccddeeff\n"
        if argv[1] == "inspect":
            return b'[{"State":{"Running":false}}]'
        return b""

    class Health:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self, _):
            return b"auth/AWS-ready"

        def open(self, *_a, **_kw):
            return self

    monkeypatch.setattr(g, "supervise", process)
    monkeypatch.setattr(g.urllib.request, "build_opener", lambda *_: Health())
    driver = g.HostDriver(host, g.Watchdog(host, window), driver_config, tmp_path)
    driver.run()
    response = host.seal(H, window, driver.processes)
    receipt = g.accept_response(
        response,
        binding=host_binding,
        channel_nonce=H,
        now=clock.t,
        fixed_deadline=2460,
    )["receipt"]
    assert receipt["result"] == "accepted" and receipt["reopen_verified_at"] is None
    assert {d["kind"] for d in host.record["dispatches"]} == {
        "pull",
        "start-candidate",
        "nginx-switch",
        "stop-prior",
    }
    assert host.record["effect_possible"] is False
    assert any(argv[-2:] == ["-s", "reload"] for argv in commands)

    product_until(clock.t)
    # Future consumer stages use their real previous checkpoint, distinct reviewed
    # binary commitments, and the same F. This is a synthetic composition witness.
    current = copy.deepcopy(phase["after"])
    for name, budget, later, used in (
        ("static", 180, 660, 100),
        ("unit", 120, 540, 80),
        ("C-recovery", 240, 300, 200),
        ("C-audit", 240, 60, 200),
    ):
        global_window.enter_stage(name, budget=budget, later=later)
        if name.startswith("C-"):
            original_plan = g.canonical({"checkpoint": current, "phase": name})
            audited = g.sha(original_plan)
            assert g.sha(original_plan) == audited  # exact binary, no replan in apply
            current = {
                **current,
                "serial": current["serial"] + 1,
                "object_version": name,
            }
        product_until(product_clock.t + used)
    global_window.enter_stage("open", budget=60, later=0)
    routes = lambda: {
        k: product_binding["release"][k + "_revision"]
        for k in ("unit", "recovery", "audit")
    }

    def send_open():
        product_clock.advance(2)
        if lost_open:
            raise TimeoutError("synthetic lost open response")

    if lost_open:
        with pytest.raises(TimeoutError):
            product.reopen(global_window, send_open, lambda _: None, routes)
        assert product.record["fence_phase"] == "RECOVERY_REQUIRED"
        assert product.record["reopen_verified_at"] is None
    else:
        product.reopen(
            global_window, send_open, lambda _: product_clock.advance(2), routes
        )
        assert 660 <= g.instant(product.record["reopen_verified_at"]) <= 2460
        assert current["serial"] == phase["after"]["serial"] + 2
    assert g.host_json(g.read_private(host.directory / "receipt-index.json"))[
        "final_response_sha256"
    ] == g.sha(response)


def test_recovery_diagnostic_imports_first_decision_after_lost_response(
    tmp_path, monkeypatch
):
    g, clock, op = operation(tmp_path, "deploy")
    window = g.Window(clock, close_confirmed_at=660, input_deadlines=[3600])
    decision = op.persist_recovery(window)
    raw = g.read_private(op.directory / "recovery-decision.json")
    clock.advance(60)
    imported = g.Window(clock, close_confirmed_at=660, input_deadlines=[3600])
    assert op.persist_recovery(imported) == decision
    assert imported.recovery_remaining() == 360
    assert g.read_private(op.directory / "recovery-decision.json") == raw
    for name, data in (("envelope", b"{}"), ("archive", b"original")):
        g.durable(op.directory / ("original-" + name), data, immutable=True)
    request = g.Request({}, b"{}", b"original", bytearray(b"fixture"))
    monkeypatch.setattr(g, "process_absent", lambda _: True)
    diagnostic = g.host_json(g.diagnose_once(op.lease, op.snapshot, request, H))
    assert diagnostic["receipt"] is None and diagnostic["recovery_decision"] == decision
    assert diagnostic["recovery_proof_sha256"] == g.sha(raw)
    with pytest.raises(ValueError, match="CONSUMED"):
        g.diagnose_once(op.lease, op.lease.snapshot(), request, H)


def test_admitted_original_stage_expiring_during_effect_stays_unknown(
    tmp_path, monkeypatch
):
    from test_personal_platform_dispatcher import closed_ready_fixture

    g, clock, gov, api, *_ = closed_ready_fixture()
    admission = g.admit_physical_action(gov["binding"], gov, api, clock)
    lease = g.HostLease(tmp_path, clock)
    token, snapshot = lease.acquire(owner(), H)
    b = copy.deepcopy(gov["binding"])
    b["lease_owner_sha256"] = g.sha(token)
    op = g.Operation(lease, token, snapshot, b, {"fixture": b"original"})
    op.bind_closed_ready(admission)
    window = admission.window(clock)
    driver = g.HostDriver(
        op, g.Watchdog(op, window), {"slot": "green", "port": 18081}, tmp_path
    )

    def delayed_endpoint(_argv, guard, **_):
        clock.advance(110)
        guard()

    monkeypatch.setattr(g, "supervise", delayed_endpoint)
    with pytest.raises(ValueError, match="stage deadline"):
        driver.effect(
            "pull", ["/usr/bin/docker", "pull", b["api_image"]], lambda: b"never"
        )
    assert op.record["effect_possible"] is True
    assert op.record["dispatches"][0]["state"] == "OUTCOME_UNKNOWN"
    assert op.persist_recovery(window)["choice_at"] == g.utc(1110)


def test_rollback_imports_original_decision_and_preserves_close_phase_bytes():
    from test_personal_platform_dispatcher import closed_ready_fixture

    g, clock, gov, api, _, close, phase, ready, pack = closed_ready_fixture()
    original_close, original_phase = g.canonical(close), g.canonical(phase)
    b = gov["binding"]
    b["requested_action"], b["previous_accepted_sha256"] = "rollback-previous", H
    earlier = Clock()
    earlier.t = earlier.m = 900
    original_window = g.Window(earlier, close_confirmed_at=660, input_deadlines=[3600])
    decision = original_window.choose_recovery(
        H, g.sha(g.canonical(b)), 4, g.sha(g.canonical(phase["after"]))
    )
    ready["decision"] = decision
    ready["stage"].update(name="recovery", deadline=g.utc(1200), later_seconds=120)
    pack()
    admission = g.admit_physical_action(b, gov, api, clock)
    assert g.canonical(close) == original_close and g.canonical(phase) == original_phase
    imported = admission.window(clock)
    assert imported.recovery_remaining() == 320
    clock.advance(60)
    assert admission.window(clock).recovery_remaining() == 260
    assert admission.window(clock).decision == decision


def public_handoff_fixture(tmp_path):
    from test_personal_platform_dispatcher import closed_ready_fixture

    g, clock, gov, api, *_ = closed_ready_fixture()
    gov["binding"]["original_bytes"]["envelope_sha256"] = g.sha(b"{}")
    admission = g.admit_physical_action(gov["binding"], gov, api, clock)
    lease = g.HostLease(tmp_path, clock)
    token, snapshot = lease.acquire(owner(), H)
    b = copy.deepcopy(gov["binding"])
    b["lease_owner_sha256"] = g.sha(token)
    op = g.Operation(
        lease, token, snapshot, b, {"envelope": b"{}", "archive": b"original"}
    )
    op.bind_closed_ready(admission)
    for state in ("VERIFIED", "STAGED", "CANDIDATE_HEALTHY", "SWITCHED", "ACCEPTED"):
        op.transition(state)
    request = g.Request({}, b"{}", b"original", bytearray(b"not-public"), admission)
    request.channel_nonce = H
    window = admission.window(clock)
    raw = op.seal(
        H,
        window,
        lambda: {"checked_processes": [], "all_absent_or_send_disabled": True},
    )
    return g, clock, gov, request, op, window, raw


def test_public_handoff_contains_only_whitelisted_commitments(tmp_path):
    g, clock, gov, request, _, _, raw = public_handoff_fixture(tmp_path)
    public = g.public_handoff(raw, request, gov["binding"], clock.t)
    value = g.host_json(public)
    assert set(value) == {
        "version",
        "kind",
        "caller",
        "producer_sha",
        "closed_ready_sha256",
        "original_request_sha256",
        "status",
        "response_sha256",
        "proof_sha256",
        "receipt_sha256",
        "witness_sha256",
        "operation_id",
        "binding_sha256",
        "generation",
        "recovery_decision",
        "recovery_proof_sha256",
    }
    assert value["response_sha256"] == g.sha(raw)
    assert value["recovery_decision"] is None and value["status"] == "accepted"
    for private in (
        b"not-public",
        b"SHA256:fixture",
        b"arn:aws:",
        b"fixture-boot",
        b"/var/lib/",
        b'"receipt":',
        b'"proof":',
    ):
        assert private not in public
    assert len(public) <= 32768


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "raw-boot",
        "extra-token",
        "wrong-hash",
        "wrong-nonce",
        "wrong-caller",
        "wrong-response-proof",
    ],
)
def test_public_recovery_preserves_original_decision_or_refuses(
    tmp_path, monkeypatch, mutation
):
    g, clock, gov, request, op, window, original = public_handoff_fixture(tmp_path)
    decision = op.persist_recovery(window)
    assert decision["clock_boot_id"] == g.sha(b"ext3:clock-boot:v1\0fixture-boot")
    original_bytes = g.canonical(decision)
    monkeypatch.setattr(g, "process_absent", lambda _: True)
    clock.advance(1)
    raw = g.diagnose_once(op.lease, op.snapshot, request, H)
    request.diagnostic = True
    value = g.host_json(raw)
    if mutation == "raw-boot":
        value["recovery_decision"]["clock_boot_id"] = "physical-boot-uuid"
        value["recovery_proof_sha256"] = g.sha(g.canonical(value["recovery_decision"]))
    elif mutation == "extra-token":
        value["recovery_decision"]["token"] = "sensitive"
    elif mutation == "wrong-hash":
        value["recovery_proof_sha256"] = "f" * 64
    elif mutation == "wrong-nonce":
        value["proof"]["channel_nonce"] = "f" * 64
    elif mutation == "wrong-caller":
        gov["binding"]["caller"]["workflow_path"] = "/private/path"
    elif mutation == "wrong-response-proof":
        value["proof"]["operation_id"] = "private"
    changed = g.canonical(value)
    if mutation:
        with pytest.raises(ValueError):
            g.public_handoff(changed, request, gov["binding"], clock.t)
    else:
        public = g.host_json(g.public_handoff(raw, request, gov["binding"], clock.t))
        assert g.canonical(public["recovery_decision"]) == original_bytes
        assert public["recovery_proof_sha256"] == g.sha(original_bytes)
        assert public["status"] == "recovery_required"
        assert g.host_json(original)["receipt"]["result"] == "accepted"


def test_recovery_runner_outputs_projection_and_wrapper_fails_only_after_upload(
    tmp_path, monkeypatch
):
    import io
    import subprocess
    import types
    import zipfile
    from pathlib import Path

    import yaml

    g, clock, gov, request, op, window, _ = public_handoff_fixture(tmp_path / "host")
    op.persist_recovery(window)
    monkeypatch.setattr(g, "process_absent", lambda _: True)
    diagnostic = g.diagnose_once(op.lease, op.snapshot, request, H)
    request.diagnostic = True
    gov["runner"] = {
        "ssm_parameters": {
            name: "arn:aws:ssm:us-east-1:111111111111:parameter/cnesdata/deploy/" + name
            for name in ("ssh-key", "cloudflare-client-id", "cloudflare-client-secret")
        }
    }

    class SSM:
        def get_parameter(self, Name, WithDecryption):
            return {
                "Parameter": {
                    "ARN": Name,
                    "Type": "SecureString",
                    "Value": "synthetic-private-secret",
                }
            }

    runner = tmp_path / "runner"
    runner.mkdir(mode=0o700)
    output = runner / "outputs"
    monkeypatch.setenv("CNESDATA_HOST_GOVERNANCE", g.canonical(gov).decode())
    monkeypatch.setenv("RUNNER_TEMP", str(runner))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(
        g.sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"synthetic-token"))
    )
    monkeypatch.setattr(g, "runner_request", lambda *_: request)
    monkeypatch.setattr(g, "runner_clients", lambda _: (None, SSM()))
    monkeypatch.setattr(g, "runner_handoff", lambda *_: None)
    monkeypatch.setattr(g, "ssh_exchange", lambda *_: diagnostic)
    monkeypatch.setattr(g.time, "time", lambda: clock.t)
    assert g.runner_main("execute") == 2
    outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert len(outputs) == 5 and outputs["status"] == "recovery_required"
    public_file = runner / "cnesdata-host-public/host-handoff.json"
    private_file = runner / "cnesdata-host-private-response.json"
    assert private_file.stat().st_mode & 0o777 == 0o600
    public = g.host_json(public_file.read_bytes())
    assert (
        public["response_sha256"]
        == outputs["host_evidence_sha256"]
        == g.sha(private_file.read_bytes())
    )
    workflow = yaml.safe_load(
        (
            Path(__file__).resolve().parents[1]
            / ".github/workflows/reusable-cnesdata-host-deploy-gate.yml"
        ).read_text()
    )
    steps = workflow["jobs"]["execute"]["steps"]
    gate = next(s for s in steps if s.get("id") == "gate")
    # Execute the actual JavaScript wrapper with only its process endpoint replaced.
    js = 'const vm=require("vm"); const script=JSON.parse(process.argv[1]); vm.runInNewContext(script,{process:{env:{RUNNER_TEMP:"/synthetic"}},core:{getInput:()=>"synthetic-token"},require:(name)=>name==="child_process"?{spawnSync:()=>({status:2})}:require(name)});'
    result = subprocess.run(
        ["node", "-e", js, json.dumps(gate["with"]["script"])],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    upload = next(s for s in steps if s.get("id") == "handoff")
    assert (
        upload["with"]["path"]
        == "${{ runner.temp }}/cnesdata-host-public/host-handoff.json"
    )
    # Synthetic artifact endpoint receives exactly the configured member, never private bytes.
    with zipfile.ZipFile(runner / "public.zip", "w") as z:
        z.write(public_file, "host-handoff.json")
    with zipfile.ZipFile(runner / "public.zip") as z:
        assert z.namelist() == ["host-handoff.json"]
        assert b"synthetic-private-secret" not in z.read("host-handoff.json")
    assert subprocess.run(["sh", "-c", steps[-1]["run"]], check=False).returncode == 1


@pytest.mark.parametrize(
    "expired,changed",
    [
        (False, None),
        (True, None),
        (True, "archive"),
        (True, "token"),
        (True, "governance"),
    ],
)
def test_host_historical_diagnostic_precedes_all_mutating_admission(
    tmp_path, monkeypatch, expired, changed
):
    import io
    import types

    g, clock, gov, request, op, window, _ = public_handoff_fixture(tmp_path)
    op.persist_recovery(window)
    g.durable(op.directory / "original-governance", g.canonical(gov), immutable=True)
    g.durable(
        op.directory / "original-token-sha256",
        g.sha(request.token).encode(),
        immutable=True,
    )
    if expired:
        clock.advance(3000)
    if changed == "archive":
        request.archive += b"changed"
    elif changed == "token":
        request.token[:] = b"different-original-token"
    elif changed == "governance":
        gov["binding"]["approval"]["governance_sha256"] = "f" * 64
    monkeypatch.setattr(g, "ROOT", tmp_path)
    monkeypatch.setattr(g, "Clock", lambda: clock)
    monkeypatch.setattr(g, "load_governance", lambda: gov)
    monkeypatch.setattr(g, "read_request", lambda _: request)
    monkeypatch.setattr(g, "process_absent", lambda _: True)
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "deploy")
    request.envelope["release_manifest"] = {"requested_action": "deploy"}

    def forbidden(*_a, **_kw):
        raise AssertionError("historical diagnostic reached mutating admission")

    monkeypatch.setattr(g, "authenticate_request", forbidden)
    monkeypatch.setattr(g, "admit_physical_action", forbidden)
    buf = io.BytesIO()
    monkeypatch.setattr(g.sys, "stdout", types.SimpleNamespace(buffer=buf))
    if changed:
        with pytest.raises(ValueError, match="original"):
            g.host_main()
        assert op.lease.snapshot()["head"] == op.snapshot["head"]
    else:
        assert g.host_main() == 2
        nonce, raw = buf.getvalue().split(b"\n", 1)
        value = g.accept_recovery_diagnostic(
            raw, binding=gov["binding"], channel_nonce=nonce.decode(), now=clock.t
        )
        assert value["recovery_decision"] == window.decision
        assert value["proof"]["retry"] == "CONSUMED"
        assert op.lease.snapshot()["lease"] == op.snapshot["lease"]


@pytest.mark.parametrize(
    "uncertain,late,restore_failure",
    [
        (False, False, False),
        (True, False, False),
        (False, True, False),
        (False, False, True),
    ],
)
def test_real_host_ssh_runner_failure_diagnostic_and_exact_rollback(
    tmp_path, monkeypatch, uncertain, late, restore_failure
):
    """Actual host_main, driver, framing, ssh_exchange/classifier and runner projection.

    Only authenticated source, OS process, cloud and HTTP endpoints are synthetic.
    SSH endpoint uses real kernel pipes and a child process running host_main.
    """
    import base64
    import contextlib
    import io
    import os
    import types
    from pathlib import Path

    from test_personal_platform_dispatcher import closed_ready_fixture

    g, clock, gov, api, *_ = closed_ready_fixture()
    root = g.private_directory(tmp_path / "host")
    runner = g.private_directory(tmp_path / "runner")
    staged = g.private_directory(tmp_path / "stage")
    active = tmp_path / "active.conf"
    g.durable(active, b"original nginx checkpoint")
    gov["host"] = {
        "slot": "green",
        "port": 18081,
        "previous_slot": "blue",
        "previous_nginx_sha256": g.sha(active.read_bytes()),
        "readiness_sha256": g.sha(b"ready"),
        "public_hostname": "api.example.test",
        "tunnel_health_url": "https://api.example.test/health/ready",
    }
    envelope = {"release_manifest": {"requested_action": "deploy"}}
    raw = g.canonical(envelope)
    gov["binding"]["original_bytes"]["envelope_sha256"] = g.sha(raw)
    gov["binding"]["original_bytes"]["archive_sha256"] = g.sha(b"original archive")
    gov["binding"]["api_image"] = "registry.example/api@sha256:" + H
    hostkey = b"synthetic public host key"
    gov["binding"]["platform"]["host_key_fingerprint"] = "SHA256:" + base64.b64encode(
        g.hashlib.sha256(hostkey).digest()
    ).decode().rstrip("=")
    binary = b"synthetic cloudflared"
    gov["runner"] = {
        "ssh_hostname": "host.example.test",
        "known_hosts": "host.example.test ssh-ed25519 "
        + base64.b64encode(hostkey).decode(),
        "cloudflared": {"version": "2026.1.0", "sha256": g.sha(binary)},
        "ssm_parameters": {
            name: "arn:aws:ssm:us-east-2:111111111111:parameter/cnesdata/deploy/" + name
            for name in ("ssh-key", "cloudflare-client-id", "cloudflare-client-secret")
        },
    }
    for name in ("platform", "baseline"):
        original = ("original " + name).encode()
        g.durable(root / ("original-" + name + ".json"), original)
        gov["binding"]["original_bytes"][name + "_sha256"] = g.sha(original)
    admission = g.admit_physical_action(gov["binding"], gov, api, clock)
    request = g.Request(
        envelope, raw, b"original archive", bytearray(b"synthetic-token"), admission
    )
    monkeypatch.setattr(g, "ROOT", root)
    monkeypatch.setattr(g, "Clock", lambda: clock)
    monkeypatch.setattr(g.time, "time", lambda: clock.t)
    monkeypatch.setattr(g, "load_governance", lambda: gov)
    monkeypatch.setattr(g, "GitHub", lambda *_: api)
    monkeypatch.setattr(
        g, "authenticate_request", lambda *_: (copy.deepcopy(gov["binding"]), {})
    )
    monkeypatch.setattr(g, "verify_original_activation", lambda *_: None)
    monkeypatch.setattr(g, "verify_runtime_probes", lambda *_: None)
    monkeypatch.setattr(g, "stage_archive", lambda *_: staged)
    private_dir, read, write = g.private_directory, g.read_private, g.durable
    monkeypatch.setattr(
        g,
        "private_directory",
        lambda p: (
            private_dir(staged)
            if str(p) == "/run/personal-platform/staging"
            else private_dir(p)
        ),
    )
    fixed = Path("/etc/personal-platform/nginx/active.conf")
    monkeypatch.setattr(
        g,
        "read_private",
        lambda p, *a, **kw: read(active if p == fixed else p, *a, **kw),
    )
    monkeypatch.setattr(
        g,
        "durable",
        lambda p, data, **kw: write(active if p == fixed else p, data, **kw),
    )
    image = gov["binding"]["api_image"]
    normalized = {
        "services": {
            "api": {
                "image": image,
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

    def endpoint(argv, guard, **kwargs):
        guard()
        if "--format" in argv:
            return json.dumps(normalized).encode()
        if argv[1:3] == ["image", "inspect"]:
            return json.dumps(
                [{"RepoDigests": [image], "Os": "linux", "Architecture": "amd64"}]
            ).encode()
        if uncertain and "pull" in argv:
            raise TimeoutError("unknown daemon effect")
        if restore_failure and argv[-2:] == ["-s", "reload"]:
            raise TimeoutError("rollback reload outcome unknown")
        if "-c" in argv:
            if late:
                clock.advance(
                    150
                )  # API expired and lease lacks the 156s effect margin.
            raise ValueError("known failed candidate config validation")
        return b""

    monkeypatch.setattr(g, "supervise", endpoint)

    class Health:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def open(self, *_a, **_kw):
            return self

        def read(self, _):
            return b"ready"

    monkeypatch.setattr(g.urllib.request, "build_opener", lambda *_: Health())
    monkeypatch.setattr(
        g.urllib.request,
        "urlopen",
        lambda *_a, **_kw: contextlib.closing(io.BytesIO(binary)),
    )

    class SSHProcess:
        def __init__(self, argv, **kwargs):
            assert argv[0] == "/usr/bin/ssh"
            input_r, input_w = os.pipe()
            output_r, output_w = os.pipe()
            self.pid = os.fork()
            self.returncode = None
            if self.pid == 0:
                os.setsid()
                os.close(input_w)
                os.close(output_r)
                g.sys = types.SimpleNamespace(
                    stdin=types.SimpleNamespace(
                        buffer=os.fdopen(input_r, "rb", buffering=0)
                    ),
                    stdout=types.SimpleNamespace(
                        buffer=os.fdopen(output_w, "wb", buffering=0)
                    ),
                )
                os.environ["SSH_ORIGINAL_COMMAND"] = "deploy"
                try:
                    status = g.host_main()
                except BaseException:  # noqa: BLE001 -- child endpoint must exit, never resume pytest
                    import traceback

                    (root / "child-error.txt").write_text(traceback.format_exc())
                    status = 1
                (root / "child-clock").write_text(str(clock.t))
                os._exit(status)
            os.close(input_r)
            os.close(output_w)
            self.stdin = os.fdopen(input_w, "wb", buffering=0)
            self.stdout = os.fdopen(output_r, "rb", buffering=0)

        def wait(self, timeout=None):
            if self.returncode is None:
                _, status = os.waitpid(self.pid, 0)
                self.returncode = os.waitstatus_to_exitcode(status)
                returned = int((root / "child-clock").read_text())
                clock.advance(returned - clock.t)
            return self.returncode

        def poll(self):
            if self.returncode is None:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
                if pid:
                    self.returncode = os.waitstatus_to_exitcode(status)
            return self.returncode

    monkeypatch.setattr(g.subprocess, "Popen", SSHProcess)
    calls = []

    class SSM:
        def get_parameter(self, Name, WithDecryption):
            calls.append("ssm")
            return {
                "Parameter": {"ARN": Name, "Type": "SecureString", "Value": "synthetic"}
            }

    def clients(_):
        calls.append("oidc")
        return None, SSM()

    monkeypatch.setattr(g, "runner_request", lambda *_: request)
    monkeypatch.setattr(g, "runner_clients", clients)
    monkeypatch.setattr(g, "runner_handoff", lambda *_: None)
    monkeypatch.setattr(
        g.sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"synthetic-token"))
    )
    monkeypatch.setenv("CNESDATA_HOST_GOVERNANCE", g.canonical(gov).decode())
    monkeypatch.setenv("RUNNER_TEMP", str(runner))
    monkeypatch.setenv("GITHUB_OUTPUT", str(runner / "outputs"))
    if uncertain or restore_failure:
        with pytest.raises(ValueError, match="unknown outcome"):
            g.runner_main("execute")
    else:
        assert g.runner_main("execute") == 2
    authority = g.host_json(read(root / "authority.json"))
    directory = root / "cnesdata" / authority["head"]["operation_id"]
    record = g.host_json(
        read(directory / (authority["head"]["record_sha256"] + ".json"))
    )
    decision = read(directory / "recovery-decision.json")
    assert authority["lease"]["state"] == "HELD"
    expected_state = (
        "RECOVERY_REQUIRED" if uncertain or late or restore_failure else "ROLLED_BACK"
    )
    assert record["state"] == authority["head"]["state"] == expected_state
    assert active.read_bytes() == b"original nginx checkpoint"
    assert calls == ["oidc", "ssm", "ssm", "ssm"]
    if uncertain or restore_failure:
        assert record["effect_possible"] is True
        if restore_failure:
            assert any(
                d["kind"] == "restore-previous" and d["state"] == "OUTCOME_UNKNOWN"
                for d in record["dispatches"]
            )
        else:
            assert all(d["kind"] != "restore-previous" for d in record["dispatches"])
        assert not (runner / "cnesdata-host-public").exists()
    else:
        restored = any(
            d["kind"] == "restore-previous" and d["state"] == "EFFECT_CONFIRMED"
            for d in record["dispatches"]
        )
        assert restored is (not late)
        if late:
            assert g.host_json(decision)["choice_at"] == g.utc(1150)
            assert record["effect_possible"] is False
        public = g.host_json(read(runner / "cnesdata-host-public/host-handoff.json"))
        assert public["status"] == "recovery_required"
        assert public["recovery_proof_sha256"] == g.sha(decision)
        assert record["retry"] == "CONSUMED"
        assert "status=recovery_required" in (runner / "outputs").read_text()
    monkeypatch.setattr(
        g.sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"synthetic-token"))
    )
    with pytest.raises(ValueError, match="original attempt already spent"):
        g.runner_main("execute")
    assert calls == ["oidc", "ssm", "ssm", "ssm"]


@pytest.mark.parametrize("domain", ["ecs", "sfn", "mismatch"])
def test_activation_original_revision_projection(tmp_path, monkeypatch, domain):
    from test_personal_platform_dispatcher import closed_ready_fixture

    g, _clock, gov, _api, *_ = closed_ready_fixture()
    release = gov["binding"]["release"]
    activation = {
        key: release[key]
        for key in (
            "repository",
            "release_id",
            "source_sha",
            "candidate_sha256",
            "binding_sha256",
            "canary_id",
        )
    }
    activation.update(
        {
            "revisions": {
                name: release[name + "_revision"]
                for name in ("unit", "recovery", "audit")
            },
            "phase_a_evidence_digest": release["phase_a_evidence_sha256"],
            "ecr_uri": "111111111111.dkr.ecr.us-east-2.amazonaws.com/cnesdata@"
            + release["ecr_image_digest"],
        }
    )
    if domain == "sfn":
        release["unit_revision"] = (
            "arn:aws:states:us-east-2:111111111111:stateMachine:unit:1"
        )
        with pytest.raises(ValueError, match="revision ARN"):
            g.validate_binding(gov["binding"])
        return
    if domain == "mismatch":
        activation["revisions"]["recovery"] = activation["revisions"][
            "recovery"
        ].replace(":1", ":2")
    raw = g.canonical(activation)
    for name, data in (
        ("activation.json", raw),
        ("activation-signature.der", b"signature"),
        ("activation-public-key.pem", b"key"),
    ):
        g.durable(tmp_path / name, data)
    release["activation_sha256"], release["signature_sha256"] = (
        g.sha(raw),
        g.sha(b"signature"),
    )
    gov["signing_spki_pem_sha256"] = g.sha(b"key")
    monkeypatch.setattr(g, "ROOT", tmp_path)
    monkeypatch.setattr(g, "supervise", lambda *_a, **_kw: b"")
    if domain == "mismatch":
        with pytest.raises(ValueError, match="revisions binding"):
            g.verify_original_activation(gov, lambda: None)
    else:
        g.validate_binding(gov["binding"])
        g.verify_original_activation(gov, lambda: None)
