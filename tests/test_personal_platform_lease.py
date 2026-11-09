"""Physical lease and bounded-time oracles, using local files and synthetic time."""
import copy

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


def owner():
    return {"class": "human", "process": {"boot_id": "fixture-boot", "pid": 123,
            "start_ticks": 7, "invocation_id": None}, "workflow": None,
            "human_session_commitment": H, "systemd_invocation": None}


def test_single_authority_atomic_snapshot_and_no_expiry_takeover(tmp_path):
    g = runtime()
    clock = Clock()
    lease = g.HostLease(tmp_path, clock)
    token, first = lease.acquire(owner(), H)
    assert first["lease"]["expires_at"] == g.utc(1300)
    assert first["head"] is None
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


@pytest.mark.parametrize("remaining,accepted", [(156, False), (157, True), (155, False)])
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
    window.recovery_guard(convergence_remaining=180, finalization_remaining=60,
                          uncertainty_remaining=60, lease_expires_at=1500)
    assert window.recovery_remaining() == 300
    assert window.choose_recovery(H, H, 1, H) == decision
    clock.advance(181)
    with pytest.raises(ValueError):
        window.recovery_guard(convergence_remaining=0, finalization_remaining=60,
                              uncertainty_remaining=60, lease_expires_at=1700)
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
