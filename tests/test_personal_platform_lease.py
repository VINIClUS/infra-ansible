"""Physical lease and bounded-time oracles, using local files and synthetic time."""

import pytest
from test_personal_platform_dispatcher import H, runtime


class Clock:
    def __init__(self):
        self.t = 1000
        self.m = 1000
        self.boot_id = "fixture-boot"

    def wall(self):
        return self.t

    def mono(self):
        return self.m

    def advance(self, seconds):
        self.t += seconds
        self.m += seconds


def test_authenticated_https_date_shortens_effect_margin(monkeypatch):
    from email.utils import formatdate

    g = runtime()
    clock = g.Clock()
    monkeypatch.setattr(clock, "wall", lambda: 1000)
    monkeypatch.setattr(clock, "mono", lambda: 1000)

    class Response:
        def __init__(self):
            self.headers = {"Date": formatdate(1010, usegmt=True)}

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self, _):
            return b"{}"

        def open(self, *_a, **_kw):
            return self

    monkeypatch.setattr(g.urllib.request, "build_opener", lambda *_: Response())
    assert (
        g.GitHub(bytearray(b"synthetic"), clock).read(
            "repos/VINIClUS/CnesData/actions/runs/1"
        )
        == {}
    )
    assert clock.upper() == 1011
    window = g.Window(clock, close_confirmed_at=660, input_deadlines=[3600])
    window.stage_deadline = 1045
    with pytest.raises(ValueError, match="stage deadline"):
        window.guard(lease_expires_at=1300)
    clock.observe(1000, 1000, 1000)
    assert clock.upper() == 1011  # a later convenient sample cannot restore time
    with pytest.raises(ValueError, match="skew"):
        clock.observe(1040, 1000, 1000)
    monkeypatch.setattr(clock, "wall", lambda: 1002)
    with pytest.raises(ValueError, match="discontinuity"):
        clock.upper()


def test_renewal_latch_allows_only_recording_first_recovery_decision():
    g, clock = runtime(), Clock()
    window = g.Window(clock, close_confirmed_at=660, input_deadlines=[3600])
    window.fail("renewal failed or ambiguous")
    decision = window.choose_recovery(H, H, 1, H)
    assert decision["choice_at"] == g.utc(1000)
    clock.advance(30)
    assert window.choose_recovery(H, H, 1, H) == decision
    with pytest.raises(ValueError, match="renewal"):
        window.guard(lease_expires_at=1330)


def owner():
    return {
        "class": "human",
        "process": {
            "boot_id": "fixture-boot",
            "pid": 123,
            "start_ticks": 7,
            "invocation_id": None,
        },
        "workflow": None,
        "human_session_commitment": H,
        "systemd_invocation": None,
    }


def test_single_authority_atomic_snapshot_and_no_expiry_takeover(tmp_path):
    g = runtime()
    clock = Clock()
    lease = g.HostLease(tmp_path, clock)
    token, first = lease.acquire(owner(), H)
    assert first["lease"]["expires_at"] == g.utc(1300)
    assert first["head"] is None
    assert set(first["lease"]) == {
        "version",
        "state",
        "revision",
        "generation",
        "owner",
        "owner_token_sha256",
        "operation_id",
        "acquired_at",
        "renewed_at",
        "expires_at",
        "checkpoint_sha256",
        "recovery_proof_sha256",
    }
    assert token.hex() not in (tmp_path / "authority.json").read_text()
    clock.advance(301)
    with pytest.raises(ValueError, match="recovery"):
        lease.acquire(owner(), H)
    assert lease.snapshot() == first


def test_renew_requires_current_hash_revision_generation_and_actual_readback(tmp_path):
    g = runtime()
    clock = Clock()
    lease = g.HostLease(tmp_path, clock)
    token, first = lease.acquire(owner(), H)
    clock.advance(60)
    second = lease.renew(token, first)
    assert second["lease"]["expires_at"] == g.utc(1360)
    assert second["lease"]["generation"] == first["lease"]["generation"]
    assert second["revision"] == first["revision"] + 1
    with pytest.raises(ValueError, match="CAS"):
        lease.renew(token, first)
    with pytest.raises(ValueError):
        lease.renew(b"wrong", second)


def test_symlink_and_insecure_store_refused(tmp_path):
    g = runtime()
    root = tmp_path / "root"
    root.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        g.HostLease(root, Clock())


def test_fixed_budget_is_independent_of_current_300_second_lease():
    g = runtime()
    clock = Clock()
    window = g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600])
    window.enter_stage("phase-b", budget=240, later=1020)
    window.guard(lease_expires_at=1300)
    clock.advance(60)
    window.guard(lease_expires_at=1360)
    assert window.fixed_deadline == 2800
    assert window.stage_deadline == 1240


@pytest.mark.parametrize(
    "remaining,accepted", [(156, False), (157, True), (155, False)]
)
def test_lease_guard_is_strict_and_uses_confirmed_expiry(remaining, accepted):
    g = runtime()
    clock = Clock()
    window = g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600])
    if accepted:
        window.guard(lease_expires_at=1000 + remaining)
    else:
        with pytest.raises(ValueError):
            window.guard(lease_expires_at=1000 + remaining)


def test_failed_renewal_latches_despite_future_schedule_and_window():
    g = runtime()
    clock = Clock()
    window = g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600])
    clock.advance(200)
    window.fail("ambiguous renewal")
    with pytest.raises(ValueError, match="ambiguous renewal"):
        window.guard(lease_expires_at=1420)


def test_stage_walltime_and_fixed_inputs_never_reset():
    g = runtime()
    clock = Clock()
    window = g.Window(clock, close_confirmed_at=1000, input_deadlines=[2700, 4600])
    assert window.fixed_deadline == 2700
    window.enter_stage("candidate", budget=180, later=100)
    clock.advance(145)
    with pytest.raises(ValueError, match="stage"):
        window.guard(lease_expires_at=1600)
    assert window.stage_deadline == 1180


def test_recovery_420_is_allocated_once_and_consumes_elapsed_walltime():
    g = runtime()
    clock = Clock()
    window = g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600])
    decision = window.choose_recovery(H, H, 1, H)
    assert decision["recovery_deadline"] == g.utc(1420)
    clock.advance(120)
    window.recovery_guard(
        convergence_remaining=180,
        finalization_remaining=60,
        uncertainty_remaining=60,
        lease_expires_at=1500,
    )
    assert window.recovery_remaining() == 300
    assert window.choose_recovery(H, H, 1, H) == decision
    clock.advance(181)
    with pytest.raises(ValueError):
        window.recovery_guard(
            convergence_remaining=0,
            finalization_remaining=60,
            uncertainty_remaining=60,
            lease_expires_at=1700,
        )
    with pytest.raises(ValueError):
        window.enter_stage("promotion-again", budget=1, later=0)


@pytest.mark.parametrize("change", ["boot", "wall", "monotonic"])
def test_clock_discontinuity_blocks_success(change):
    g = runtime()
    clock = Clock()
    window = g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600])
    if change == "boot":
        clock.boot_id = "reboot"
    elif change == "wall":
        clock.t += 31
    else:
        clock.m -= 1
    with pytest.raises(ValueError, match="clock"):
        window.guard(lease_expires_at=1600)


def test_numeric_1800_second_witness_uses_only_observed_renewals():
    g, clock = runtime(), Clock()
    window = g.Window(clock, close_confirmed_at=1000, input_deadlines=[4600])
    expiry = 1300
    stages = [
        (120, 1260),
        (240, 1020),
        (180, 840),
        (180, 660),
        (120, 540),
        (240, 300),
        (240, 60),
        (60, 0),
    ]
    for index, (budget, later) in enumerate(stages):
        window.enter_stage(str(index), budget=budget, later=later)
        # Bounded calls stop 36 seconds before the stage ceiling; remaining
        # walltime is a pause, not authorization for another full request.
        for _ in range(budget):
            if (clock.t - 1000) % 60 == 0:
                expiry = clock.t + 300
            if window.stage_deadline - clock.t >= 36:
                window.guard(lease_expires_at=expiry)
            clock.advance(1)
    assert clock.t == 2380
    assert window.fixed_deadline - clock.t == 420


@pytest.mark.parametrize("action", ["validate", "deploy"])
def test_workflow_renew_cross_app_workflow_transfer_preserves_release(
    tmp_path, monkeypatch, action
):
    import contextlib
    import copy
    import io
    import json
    from pathlib import Path

    from test_personal_platform_deployer import binding

    g, clock = runtime(), Clock()
    lease = g.HostLease(tmp_path / "authority", clock)
    from test_personal_platform_dispatcher import closed_ready_fixture

    b = binding() if action == "validate" else closed_ready_fixture()[2]["binding"]
    old = owner()
    old.update(
        {"class": "workflow", "workflow": b["caller"], "human_session_commitment": None}
    )
    token, first = lease.acquire(old, H)
    b["lease_owner_sha256"] = g.sha(token)
    op = g.Operation(lease, token, first, b, {"fixture": b"original"})
    op.transition("VERIFIED")
    if action == "deploy":
        for state in ("STAGED", "CANDIDATE_HEALTHY", "SWITCHED"):
            op.transition(state)
    op.transition("ACCEPTED")
    accepted = None if action == "validate" else op.snapshot["head"]["record_sha256"]
    # Administrative renewal must retain the exact accepted deployment pointer.
    lease.release(
        token, op.snapshot, op.snapshot["head"]["record_sha256"], lambda: True
    )
    invocations = iter(("renew-cnesdata", "renew-limnopulse", "next-deploy"))
    identity = {
        "boot_id": "fixture-boot",
        "pid": 11,
        "start_ticks": 2,
        "invocation_id": next(invocations),
    }
    calls = []

    class API:
        def read(self, path):
            calls.append(path)
            return {
                "id": 12,
                "run_attempt": 1,
                "repository": {"full_name": "VINIClUS/CnesData"},
                "head_sha": b["caller"]["source_sha"],
                "path": b["caller"]["workflow_path"],
                "status": "completed",
                "conclusion": "success",
            }

    require, read, directory = g.require, g.read_private, g.private_directory
    monkeypatch.setattr(
        g,
        "require",
        lambda c, r: require(True if r == "root credential renewal" else c, r),
    )
    monkeypatch.setattr(
        g,
        "read_private",
        lambda p, *a, **kw: (
            b"certificate"
            if str(p).startswith("/etc/personal-platform/ra/")
            else read(p, *a, **kw)
        ),
    )
    monkeypatch.setattr(
        g,
        "private_directory",
        lambda p: (
            directory(tmp_path / "credentials" / Path(p).name)
            if str(p).startswith("/run/personal-platform/credentials/")
            else directory(p)
        ),
    )
    monkeypatch.setattr(g, "Clock", lambda: clock)
    monkeypatch.setattr(g, "HostLease", lambda: lease)
    monkeypatch.setattr(g, "ROOT", lease.root)
    monkeypatch.setattr(g, "GitHub", lambda *_: API())
    monkeypatch.setattr(g, "process_identity", lambda: copy.deepcopy(identity))
    monkeypatch.setattr(g, "process_absent", lambda _: True)
    health = b"healthy"
    monkeypatch.setattr(
        g.urllib.request,
        "urlopen",
        lambda *_a, **_k: contextlib.closing(io.BytesIO(health)),
    )
    for app in ("cnesdata", "limnopulse"):
        inspections = iter(("old", "new"))

        def supervise(argv, guard, app=app, inspections=inspections, **kwargs):
            guard()
            calls.append(argv[0])
            if "credential-process" in argv:
                return g.canonical(
                    {
                        "Version": 1,
                        "AccessKeyId": "ASIAfixture",
                        "SecretAccessKey": "fixture",
                        "SessionToken": "fixture",
                        "Expiration": g.utc(3600),
                    }
                )
            if "inspect" in argv:
                return json.dumps(
                    [
                        {
                            "Config": {
                                "Labels": {"com.docker.compose.project": app + "-blue"}
                            },
                            "State": {"StartedAt": next(inspections), "Running": True},
                        }
                    ]
                ).encode()
            return b""

        monkeypatch.setattr(g, "supervise", supervise)
        c = {
            "application": app,
            "certificate": "/etc/personal-platform/ra/" + app + "/certificate.pem",
            "private_key": "/etc/personal-platform/ra/" + app + "/private-key.pem",
            "trust_anchor_arn": "fixture",
            "profile_arn": "fixture",
            "role_arn": "fixture",
            "duration_seconds": 3600,
            "container_id": "a" * 12,
            "health_url": "http://127.0.0.1:18081/health/ready",
            "readiness_sha256": g.sha(health),
        }
        g.renew_application_credentials({"credentials": c})
        assert lease.snapshot()["lease"]["state"] == "RELEASED"
        identity["invocation_id"] = next(invocations)
    prior = lease.snapshot()["lease"]
    with pytest.raises(ValueError, match="same invocation"):
        g.prior_owner_terminal(
            lease.root,
            prior,
            API(),
            {"invocation_id": prior["owner"]["systemd_invocation"]},
        )
    original_checkpoint = (
        lease.root / "checkpoints" / (prior["checkpoint_sha256"] + ".json")
    )
    original_raw = original_checkpoint.read_bytes()
    original_checkpoint.write_bytes(original_raw + b" ")
    with pytest.raises(ValueError, match="digest"):
        g.prior_owner_terminal(lease.root, prior, API())
    original_checkpoint.write_bytes(original_raw)
    assert g.accepted_release(lease.root, prior["checkpoint_sha256"]) == accepted
    b["previous_accepted_sha256"] = accepted
    assert g.prior_terminal(prior, b, API())
    # Live prior process and repeated invocation cannot acquire even a released lease.
    monkeypatch.setattr(g, "process_absent", lambda _: False)
    with pytest.raises(ValueError, match="process"):
        g.prior_terminal(prior, b, API())
    monkeypatch.setattr(g, "process_absent", lambda _: True)
    wrong = copy.deepcopy(b)
    wrong["previous_accepted_sha256"] = H
    with pytest.raises(ValueError, match="accepted"):
        g.prior_terminal(prior, wrong, API())
    token, snapshot = lease.acquire(
        old, H, terminal_proof=lambda p: g.prior_terminal(p, b, API())
    )
    assert snapshot["lease"]["generation"] == 4
    assert sum("actions/runs/" in c for c in calls) == 1


def test_human_transfer_requires_retained_reviewed_session_end(tmp_path, monkeypatch):
    from test_personal_platform_deployer import operation

    g, clock, op = operation(tmp_path)
    op.transition("VERIFIED")
    op.transition("ACCEPTED")
    checkpoint = op.snapshot["head"]["record_sha256"]
    monkeypatch.setattr(g, "ROOT", tmp_path)
    monkeypatch.setattr(g, "process_absent", lambda _: True)
    released = op.lease.release(op.token, op.snapshot, checkpoint, lambda: True)
    with pytest.raises(ValueError):
        g.prior_terminal(released["lease"], op.record["binding"], None)
    clock.advance(400)
    original_require = g.require
    monkeypatch.setattr(
        g,
        "require",
        lambda c, r: original_require(True if r == "root recovery only" else c, r),
    )
    observation = {
        "process_absent": True,
        "owner_terminal": True,
        "checkpoint_sha256": checkpoint,
        "proof_sha256": H,
    }
    recovered = op.lease.recover_stale(released, lambda _: observation)
    assert g.prior_terminal(recovered["lease"], op.record["binding"], None)
    assert (
        op.lease.snapshot()["lease"]["generation"]
        == released["lease"]["generation"] + 1
    )
    monkeypatch.setattr(g, "process_absent", lambda _: False)
    with pytest.raises(ValueError, match="process"):
        g.prior_terminal(recovered["lease"], op.record["binding"], None)
