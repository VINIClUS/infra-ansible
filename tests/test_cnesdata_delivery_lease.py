"""CAS and watchdog oracle with deterministic time; no S3/AWS credentials."""
import copy
import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class Store:
    def __init__(self):
        self.value = None
        self.etag = None
        self.writes = 0
        self.fail = False

    def get(self):
        return copy.deepcopy(self.value), self.etag

    def put(self, value, etag):
        if self.fail or etag != self.etag:
            raise ValueError("CAS conflict")
        self.writes += 1
        self.etag = str(self.writes)
        self.value = copy.deepcopy(value)
        return self.etag


@pytest.fixture(scope="module")
def module():
    assert (ROOT / "tools/cnesdata_delivery/coordination_lease.py").is_file(), "lease absent"
    return importlib.import_module("tools.cnesdata_delivery.coordination_lease")


def lease(module, store, now):
    return module.Lease(store, {"repository": "VINIClUS/CnesData", "run_id": 11,
        "run_attempt": 1, "session_sha256": "a" * 64}, clock=lambda: now[0], token="owner")


def test_lease_cas_race_and_ttl_never_takeover(module):
    store, now = Store(), [1000]
    owner, rival = lease(module, store, now), lease(module, store, now)
    owner.acquire()
    with pytest.raises(ValueError):
        rival.acquire()
    now[0] += 301
    with pytest.raises(ValueError):
        rival.acquire()
    assert store.writes == 1


def test_renew_failure_and_foreign_owner_prevent_next_mutation(module):
    store, now = Store(), [1000]
    owner = lease(module, store, now)
    owner.acquire()
    now[0] += 60
    owner.renew()
    store.fail = True
    with pytest.raises(ValueError):
        owner.renew()
    with pytest.raises(ValueError):
        owner.check()
    assert store.writes == 2


def test_release_preserves_checkpoint_and_cannot_release_stolen_lease(module):
    store, now = Store(), [1000]
    owner = lease(module, store, now)
    owner.acquire()
    store.value["owner"] = "thief"
    with pytest.raises(ValueError):
        owner.release("a" * 64)
    assert store.writes == 1


def test_watchdog_cancel_and_fixed_capacity_fail_before_operation(module):
    store, now = Store(), [1000]
    owner = lease(module, store, now)
    owner.acquire()
    watchdog = module.Watchdog(owner, fixed_deadline=4000, credential_deadline=4000,
                                monotonic=lambda: now[0])
    watchdog.admit()
    watchdog.cancelled = True
    with pytest.raises(ValueError):
        watchdog.admit()
    watchdog.cancelled = False
    watchdog.fixed_deadline = 2979
    with pytest.raises(ValueError):
        watchdog.admit()


def test_server_clock_uncertainty_is_not_execution_time(module):
    assert module.mapped_deadline(4000, 100, 101, 2000, 2000) == 2069
    for values in [(4000, 100, 121, 2000, 2000), (4000, 100, 101, 2000, 2031)]:
        with pytest.raises(ValueError):
            module.mapped_deadline(*values)


def test_watchdog_controls_real_child_and_cancellation(module, tmp_path):
    import os
    import threading
    import time
    store = Store()
    binding = {"repository": "VINIClUS/CnesData", "run_id": 11, "run_attempt": 1, "session_sha256": "a" * 64}
    owner = module.Lease(store, binding, clock=time.time, monotonic=time.monotonic).acquire()
    watchdog = module.Watchdog(owner, fixed_deadline=time.monotonic() + 4000, credential_deadline=time.monotonic() + 4000)
    result = watchdog.run([sys.executable, "-c", "print('private')"], cwd=tmp_path,
                          env={"PATH": os.defpath}, output=tmp_path / "success.log")
    assert result["process_group_empty"] is True
    timer = threading.Timer(0.1, lambda: setattr(watchdog, "cancelled", True))
    timer.start()
    try:
        with pytest.raises(ValueError):
            watchdog.run([sys.executable, "-c", "import time;time.sleep(30)"], cwd=tmp_path,
                         env={"PATH": os.defpath}, output=tmp_path / "cancel.log")
    finally:
        timer.cancel()
    assert store.value["status"] == "held"  # no blind cleanup release after cancellation
