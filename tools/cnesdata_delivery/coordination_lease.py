"""Owner-token S3 CAS, conservative deadlines and process-group watchdog.

TTL is never takeover. A failed/ambiguous lease is retained for reviewed recovery.
"""
import os
import secrets
import signal
import subprocess
import time

from tools.cnesdata_delivery.contract import canonical, digest, require, sha, utc

KEY = "shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"


def mapped_deadline(expiry, sent, received, server_date, local_utc):
    require(0 <= received - sent <= 20 and abs(local_utc - server_date) <= 30, "clock uncertainty")
    return received + max(0, expiry - server_date - (received - sent) - 31)


class Lease:
    def __init__(self, store, binding, *, clock=time.time, monotonic=None, token=None, previous_success=None):
        self.store, self.binding = store, binding
        self.clock, self.monotonic = clock, monotonic or clock
        self.token = token or secrets.token_hex(32)
        self.previous_success = previous_success or (lambda previous: False)
        self.etag = None
        self.failed = False
        self.deadline = 0
        self.renewals = []
        self.acquire_event = None
        self.release_event = None
        self.acquired_at = None

    def _event(self, previous, current, expires):
        return {"requested_at": getattr(self.store, "cas_requested_at", utc(self.clock())),
                "responded_at": getattr(self.store, "cas_responded_at", utc(self.clock())),
                "previous_etag_sha256": sha(str(previous).encode()) if previous is not None else None,
                "etag_sha256": sha(str(current).encode()), "expires_at": utc(expires),
                "request_id_sha256": sha(str(self.store.request_id if hasattr(self.store, "request_id") else "offline-fixture").encode())}

    def acquire(self):
        value, etag = self.store.get()
        require(value is None or (value.get("status") == "released" and self.previous_success(value)), "held/recovery_required")
        now = self.clock()
        data = self.binding | {"owner": self.token, "status": "held", "expires_at": int(now + 300)}
        self.etag = self.store.put(data, etag)
        observed, observed_etag = self.store.get()
        require(observed == data and observed_etag == self.etag, "acquire readback")
        self.deadline = self.store.deadline(data["expires_at"]) if hasattr(self.store, "deadline") else self.monotonic() + max(0, data["expires_at"] - self.clock() - 31)
        self.acquired_at = utc(now)
        self.acquire_event = self._event(etag, self.etag, data["expires_at"])
        return self

    def check(self):
        require(not self.failed and self.etag is not None and self.monotonic() + 157 < self.deadline, "lease safety margin plus IO/termination budget")
        value, etag = self.store.get()
        require(value is not None and value.get("owner") == self.token and etag == self.etag
                and value.get("status") == "held" and value.get("expires_at", 0) > self.clock() + 120
                and all(value.get(k) == v for k, v in self.binding.items()), "foreign/expired lease")
        return value

    def renew(self):
        try:
            value = self.check()
            previous = self.etag
            value["expires_at"] = int(self.clock() + 300)
            self.etag = self.store.put(value, previous)
            observed, observed_etag = self.store.get()
            require(observed == value and observed_etag == self.etag, "renew readback")
            self.deadline = self.store.deadline(value["expires_at"]) if hasattr(self.store, "deadline") else self.monotonic() + max(0, value["expires_at"] - self.clock() - 31)
            self.renewals.append(self._event(previous, self.etag, value["expires_at"]))
        except Exception:
            self.failed = True
            raise

    def release(self, checkpoint):
        value = self.check()
        previous = self.etag
        value |= {"status": "released", "checkpoint_sha256": digest(checkpoint)}
        self.etag = self.store.put(value, previous)
        observed, etag = self.store.get()
        require(observed == value and etag == self.etag, "release readback")
        self.release_event = self._event(previous, self.etag, value["expires_at"])
        return self.release_event

    def evidence(self, checkpoint, child):
        require(self.release_event is not None, "no release proof")
        # Frozen at release; NEVER include final envelope/index/publication observations.
        return {"protocol": "s3-cas-v1", "owner_sha256": sha(self.token.encode()),
                **self.binding, "acquire": self.acquire_event, "renewals": self.renewals,
                "release": self.release_event, "watchdog_until_release": child,
                "checkpoint_sha256": digest(checkpoint)}


class Watchdog:
    def __init__(self, lease, *, fixed_deadline, credential_deadline, monotonic=time.monotonic):
        self.lease, self.monotonic = lease, monotonic
        self.fixed_deadline, self.credential_deadline = fixed_deadline, credential_deadline
        self.cancelled = False
        self.started = None
        self.stopped = None
        self.last_renewal = monotonic()
        self.finalizing = False

    def check(self):
        now = self.monotonic()
        require(not hasattr(self, "finalization_deadline") or now < self.finalization_deadline, "R1 finalization deadline")
        require(not self.cancelled and now + 120 < min(self.fixed_deadline, self.credential_deadline), "watchdog cancelled/expiry")
        if self.finalizing:
            value, etag = self.lease.store.get()
            require(value.get("status") == "released" and value.get("owner") == self.lease.token
                    and etag == self.lease.etag, "finalization ownership")
            return
        if now - self.last_renewal >= 39:
            self.lease.renew()
            self.last_renewal = self.monotonic()
        self.lease.check()

    def admit(self):
        self.check()
        require(min(self.fixed_deadline, self.credential_deadline) - self.monotonic() >= 1980, "execution capacity")

    def run(self, command, *, cwd, env, output, timeout=1800, mutating=True):
        self.admit() if mutating else self.check()
        require(timeout <= 1800, "command execution bound")
        self.started = utc(time.time())
        started = self.monotonic()
        previous_handlers = {}
        import threading
        termination_lock = threading.Lock()
        child = None
        def terminate():
            with termination_lock:
                if child is not None and not self._empty(child.pid):
                    self._terminate(child)
        def abort():
            self.cancelled = True
            terminate()
        def cancel(signum, frame):
            self.cancelled = True
            threading.Thread(target=terminate, daemon=True).start()
        for name in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[name] = signal.signal(name, cancel)
        timer = None
        try:
            with open(output, "xb") as stream:
                child = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                         stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                timer = threading.Timer(timeout, abort)
                timer.daemon = True
                timer.start()
                while child.poll() is None:
                    self.check()
                    require(self.monotonic() - started < timeout, "command deadline")
                    time.sleep(0.25)
                require(child.returncode == 0, "private command failed; recovery_required")
            self.check()
            self.stopped = utc(time.time())
            if not self._empty(child.pid):
                terminate()
            require(self._empty(child.pid), "descendant process still alive")
            return {"started_at": self.lease.acquired_at, "child_started_at": self.started,
                    "child_stopped_at": self.stopped, "child_exit_code": 0, "process_group_empty": self._empty(child.pid)}
        finally:
            if timer is not None:
                timer.cancel()
            if child is not None and not self._empty(child.pid):
                terminate()
            for name, handler in previous_handlers.items():
                signal.signal(name, handler)

    @staticmethod
    def _empty(pid):
        try:
            os.killpg(pid, 0)
            return False
        except ProcessLookupError:
            return True

    @classmethod
    def _terminate(cls, child):
        for sig, delay in ((signal.SIGINT, 10), (signal.SIGTERM, 5), (signal.SIGKILL, 0)):
            if cls._empty(child.pid):
                break
            os.killpg(child.pid, sig)
            try:
                child.wait(timeout=delay)
            except subprocess.TimeoutExpired:
                pass
        require(cls._empty(child.pid), "process group not terminated; retain lease")
