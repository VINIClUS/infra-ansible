"""Real temporary-file faults; systemd/nft are boundary fixtures, never host calls."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "roles/network_router/files/router-recovery.py"


@pytest.fixture
def recovery():
    assert SOURCE.exists(), "bounded atomic recovery implementation is missing"
    spec = importlib.util.spec_from_file_location("router_recovery", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path, data, mode=0o755):
    path.write_bytes(data)
    path.chmod(mode)
    return path


def test_interrupted_staging_never_replaces_complete_previous_image(recovery, tmp_path):
    source = write(tmp_path / "current", b"current\n" * 400)
    target = write(tmp_path / "previous", b"older complete image\n")
    code = """
import importlib.util, os, resource, sys
from pathlib import Path
s=importlib.util.spec_from_file_location('r',sys.argv[1]);r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
resource.setrlimit(resource.RLIMIT_FSIZE,(128,128))
r.atomic_copy(Path(sys.argv[2]),Path(sys.argv[3]),r.digest(Path(sys.argv[2]).read_bytes()),None,os.getuid(),os.getgid())
"""
    result = subprocess.run([sys.executable, "-B", "-c", code, str(SOURCE), str(source), str(target)],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert target.read_bytes() == b"older complete image\n"
    assert source.read_bytes() == b"current\n" * 400
    assert sorted(p.name for p in tmp_path.iterdir()) == ["current", "previous"]


def test_failed_atomic_replace_preserves_live_and_retry_preserves_metadata(recovery, tmp_path, monkeypatch):
    source = write(tmp_path / "backup", b"before" * 300)
    target = write(tmp_path / "live", b"desired" * 300)
    os.utime(source, ns=(1_700_000_000_000_000_000, 1_700_000_001_000_000_000))
    expected = recovery.digest(source.read_bytes())
    allowed = [recovery.digest(target.read_bytes()), expected]
    replace = recovery.os.replace
    monkeypatch.setattr(recovery.os, "replace", lambda *_: (_ for _ in ()).throw(OSError("replace fault")))
    with pytest.raises(OSError, match="replace fault"):
        recovery.atomic_copy(source, target, expected, allowed, os.getuid(), os.getgid())
    assert target.read_bytes() == b"desired" * 300
    monkeypatch.setattr(recovery.os, "replace", replace)
    recovery.atomic_copy(source, target, expected, allowed, os.getuid(), os.getgid())
    assert target.read_bytes() == b"before" * 300
    assert target.stat().st_mode & 0o777 == 0o755
    assert target.stat().st_uid == os.getuid() and target.stat().st_gid == os.getgid()
    assert target.stat().st_mtime_ns == 1_700_000_001_000_000_000
    recovery.atomic_copy(source, target, expected, allowed, os.getuid(), os.getgid())
    assert target.read_bytes() == b"before" * 300


def test_atomic_restore_refuses_foreign_content_and_links(recovery, tmp_path):
    source = write(tmp_path / "backup", b"before", 0o600)
    target = write(tmp_path / "live", b"foreign", 0o600)
    with pytest.raises(ValueError):
        recovery.atomic_copy(source, target, recovery.digest(b"before"), [recovery.digest(b"desired")],
                             os.getuid(), os.getgid())
    assert target.read_bytes() == b"foreign"
    target.unlink()
    target.symlink_to(source)
    with pytest.raises((ValueError, OSError)):
        recovery.atomic_copy(source, target, recovery.digest(b"before"), None, os.getuid(), os.getgid())
    assert target.is_symlink()


class NativeFixture:
    """Exact unit states; only the real helper decides success/failure."""
    def __init__(self):
        self.calls = []
        self.states = []
        self.active_timer = False
        self.native_failure = False
        self.runtime = {"nftables": [{"table": {"family": "inet", "name": "filter", "handle": 1}}]}

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[:2] == ["systemctl", "stop"]:
            assert argv[2].endswith(".timer"), "must never kill a restoration service"
            self.active_timer = False
            return ""
        if argv[:2] == ["systemctl", "show"]:
            if argv[2].endswith(".timer"):
                return "ActiveState=" + ("active" if self.active_timer else "inactive") + "\nJob=0\n"
            if self.states:
                state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
                return state
            return "LoadState=not-found\nActiveState=inactive\nSubState=dead\nJob=0\nInvocationID=\nExecMainStartTimestampMonotonic=0\nResult=success\nExecMainStatus=0\n"
        if argv[0] == "systemd-run":
            self.active_timer = True
            return ""
        if argv == ["nft", "-j", "list", "ruleset"]:
            return json.dumps(self.runtime)
        if argv[0] in ["nft", "netplan", "networkctl"]:
            if self.native_failure:
                raise RuntimeError("native failure")
            return ""
        raise AssertionError(argv)


@pytest.fixture
def operation(recovery, tmp_path):
    native = NativeFixture()
    config = {"current": write(tmp_path / "current", b"before" * 400),
              "previous": write(tmp_path / "previous", b"old backup"),
              "candidate": write(tmp_path / "candidate", b"desired" * 400, 0o600),
              "unit": "network-router-deadman", "reload": [["nft", "-f", str(tmp_path / "current")]]}
    engine = recovery.Recovery("nft", config, tmp_path / "state", os.getuid(), os.getgid(), native,
                               sleep=lambda _: None, polls=3)
    return engine, native, config


def test_snapshot_failure_never_arms_and_cannot_restore_stale_previous(recovery, operation, monkeypatch):
    engine, native, config = operation
    monkeypatch.setattr(recovery, "atomic_copy", lambda *_a, **_k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        engine.arm(5)
    assert not any(a[0] == "systemd-run" for a in native.calls)
    with pytest.raises((ValueError, FileNotFoundError)):
        engine.recover()
    assert config["current"].read_bytes() == b"before" * 400
    assert config["previous"].read_bytes() == b"old backup"


def test_real_snapshot_write_fault_leaves_staging_without_apply_authority(recovery, operation, monkeypatch):
    import resource
    import signal
    engine, native, config = operation
    original = recovery.atomic_copy
    def interrupted(*args, **kwargs):
        limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        previous_signal = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (128, limit[1]))
            return original(*args, **kwargs)
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, limit)
            signal.signal(signal.SIGXFSZ, previous_signal)
    monkeypatch.setattr(recovery, "atomic_copy", interrupted)
    with pytest.raises(OSError):
        engine.arm(5)
    assert config["previous"].read_bytes() == b"old backup"
    assert config["current"].read_bytes() == b"before" * 400
    assert not any(a[0] == "systemd-run" for a in native.calls)
    with pytest.raises(ValueError):
        engine.apply()
    with pytest.raises(ValueError):
        engine.restore()


def test_armed_apply_and_finalize_verify_actual_persistent_and_loaded_state(operation):
    engine, native, config = operation
    engine.arm(5)
    engine.apply()
    assert config["previous"].read_bytes() == b"before" * 400
    assert config["current"].read_bytes() == b"desired" * 400
    assert config["current"].stat().st_mode & 0o777 == 0o755
    engine.finalize()
    assert json.loads(engine.state.read_text())["phase"] == "confirmed"
    assert not native.active_timer


@pytest.mark.parametrize("event", [
    "ActiveState=activating\nSubState=start\nJob=42\nInvocationID=abc\nExecMainStartTimestampMonotonic=4\n",
    "ActiveState=inactive\nSubState=dead\nJob=42\nInvocationID=\nExecMainStartTimestampMonotonic=0\n",
])
def test_queued_or_started_recovery_is_waited_for_and_never_accepted(operation, event):
    engine, native, _ = operation
    engine.arm(5)
    engine.apply()
    native.states = [event, "ActiveState=active\nSubState=exited\nJob=0\nInvocationID=abc\nExecMainStartTimestampMonotonic=4\nResult=success\nExecMainStatus=0\n"]
    with pytest.raises(ValueError, match="recovery"):
        engine.finalize()
    assert json.loads(engine.state.read_text())["phase"] != "confirmed"
    assert not any(a[:3] == ["systemctl", "stop", "network-router-deadman.service"] for a in native.calls)


def test_recovery_timeout_leaves_running_service_uninterrupted(operation):
    engine, native, config = operation
    engine.arm(5)
    engine.apply()
    native.states = ["ActiveState=activating\nSubState=start\nJob=42\nInvocationID=abc\nExecMainStartTimestampMonotonic=4\n"]
    with pytest.raises(ValueError, match="running"):
        engine.recover()
    assert config["current"].read_bytes() == b"desired" * 400


def test_failed_native_restore_is_repeatable_and_no_apply_follows_expired_attempt(operation):
    engine, native, config = operation
    engine.arm(5)
    engine.apply()
    native.native_failure = True
    with pytest.raises(RuntimeError):
        engine.restore()
    assert config["current"].read_bytes() == b"before" * 400
    native.native_failure = False
    engine.restore()
    assert json.loads(engine.state.read_text())["phase"] == "restored"
    with pytest.raises(ValueError):
        engine.apply()


def test_finalizer_detects_runtime_drift_after_timer_finalization(operation):
    engine, native, _ = operation
    engine.arm(5)
    engine.apply()
    native.runtime["nftables"].append({"table": {"family": "ip", "name": "foreign"}})
    with pytest.raises(ValueError, match="loaded"):
        engine.finalize()


def test_corrupt_snapshot_after_arming_prevents_any_firewall_apply(operation):
    engine, native, config = operation
    engine.arm(5)
    config["previous"].write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="preimage"):
        engine.apply()
    assert config["current"].read_bytes() == b"before" * 400
    assert not any(a[0] == "nft" for a in native.calls)


def test_directory_sync_failure_after_replace_keeps_a_complete_retryable_image(recovery, tmp_path, monkeypatch):
    import stat
    source = write(tmp_path / "backup", b"before" * 400, 0o600)
    target = write(tmp_path / "live", b"desired" * 400, 0o600)
    expected = recovery.digest(source.read_bytes())
    allowed = [expected, recovery.digest(target.read_bytes())]
    sync = recovery.os.fsync
    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory sync fault")
        sync(fd)
    monkeypatch.setattr(recovery.os, "fsync", fail_directory)
    with pytest.raises(OSError, match="directory sync"):
        recovery.atomic_copy(source, target, expected, allowed, os.getuid(), os.getgid())
    assert target.read_bytes() == b"before" * 400
    monkeypatch.setattr(recovery.os, "fsync", sync)
    recovery.atomic_copy(source, target, expected, allowed, os.getuid(), os.getgid())
    assert target.read_bytes() == b"before" * 400


def test_netplan_restore_retries_generation_failure_and_preserves_0600(recovery, tmp_path):
    native = NativeFixture()
    config = {"current": write(tmp_path / "current", b"before" * 300, 0o600),
              "previous": tmp_path / "before", "unit": "samba-ad-router-policy-netplan-deadman",
              "reload": [["netplan", "generate"], ["networkctl", "reload"]]}
    engine = recovery.Recovery("netplan", config, tmp_path / "state", os.getuid(), os.getgid(), native,
                               sleep=lambda _: None, polls=3)
    engine.arm(15, recovery.digest(b"before" * 300), recovery.digest(b"desired" * 300))
    write(config["current"], b"desired" * 300, 0o600)
    native.native_failure = True
    with pytest.raises(RuntimeError):
        engine.restore()
    assert config["current"].read_bytes() == b"before" * 300
    native.native_failure = False
    engine.recover()
    assert config["current"].read_bytes() == b"before" * 300
    assert config["current"].stat().st_mode & 0o777 == 0o600
    assert ["networkctl", "reload"] in native.calls
    with pytest.raises(ValueError, match="recovery"):
        engine.finalize()


@pytest.mark.parametrize("ran", [False, True])
def test_netplan_finalization_requires_quiescent_pair_and_final_desired_file(recovery, tmp_path, ran):
    native = NativeFixture()
    config = {"current": write(tmp_path / "current", b"before", 0o600),
              "previous": tmp_path / "before", "unit": "samba-ad-router-policy-netplan-deadman",
              "reload": [["netplan", "generate"], ["networkctl", "reload"]]}
    engine = recovery.Recovery("netplan", config, tmp_path / "state", os.getuid(), os.getgid(), native,
                               sleep=lambda _: None, polls=3)
    engine.arm(15, recovery.digest(b"before"), recovery.digest(b"desired"))
    write(config["current"], b"desired", 0o600)
    if ran:
        native.states = ["ActiveState=active\nSubState=exited\nJob=0\nInvocationID=abc\nExecMainStartTimestampMonotonic=4\nResult=success\nExecMainStatus=0\n"]
        with pytest.raises(ValueError, match="recovery"):
            engine.finalize()
    else:
        engine.finalize()
        assert json.loads(engine.state.read_text())["phase"] == "confirmed"
    assert not native.active_timer
    assert config["current"].read_bytes() == b"desired"


def test_runtime_counters_and_handles_do_not_falsely_fail_final_readback(operation):
    engine, native, _ = operation
    native.runtime["nftables"].append({"counter": {"name": "test", "handle": 3, "packets": 0, "bytes": 0}})
    engine.arm(5)
    engine.apply()
    native.runtime["nftables"][-1]["counter"].update({"handle": 12, "packets": 99, "bytes": 8000})
    engine.finalize()
    assert json.loads(engine.state.read_text())["phase"] == "confirmed"
