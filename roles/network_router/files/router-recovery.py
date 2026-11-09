"""Fixed-path router recovery. No caller-supplied paths or commands in the CLI.

Atomic files prevent interrupted copies from invalidating either complete image.
The state is transient: reboot or an unconfirmed attempt requires operator review.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time


HELPER = "/usr/local/sbin/network-router-recovery.py"
STATE = Path("/run/network-router-recovery")
CONFIG = {
    "nft": {"current": Path("/etc/nftables.conf"), "previous": Path("/etc/nftables.conf.prev"),
            "candidate": Path("/etc/nftables.conf.candidate"), "unit": "network-router-deadman",
            "reload": [["nft", "-f", "/etc/nftables.conf"]]},
    "netplan": {"current": Path("/etc/netplan/90-network-router.yaml"),
                "previous": STATE / "netplan.before", "unit": "samba-ad-router-policy-netplan-deadman",
                "reload": [["netplan", "generate"], ["networkctl", "reload"]]},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, uid, gid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_NOATIME", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 16 * 1024 * 1024,
                "unsafe recovery file")
        require((info.st_uid, info.st_gid) == (uid, gid) and not info.st_mode & 0o022,
                "unsafe recovery ownership or mode")
        data = stream.read()
        require(identity(os.fstat(stream.fileno())) == identity(info)
                and identity(path.lstat()) == identity(info), "recovery file changed while read")
    return data, info


def publish(data, target, metadata, uid, gid, previous):
    """Publish in the target directory; a failed write/replace leaves target intact."""
    fd, name = tempfile.mkstemp(prefix="." + target.name + ".", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            os.utime(stream.fileno(), ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
            os.fsync(stream.fileno())
        staged, info = read_file(temporary, uid, gid)
        require(staged == data and stat.S_IMODE(info.st_mode) == stat.S_IMODE(metadata.st_mode)
                and info.st_mtime_ns == metadata.st_mtime_ns, "incomplete staged image")
        if previous is None:
            require(not os.path.lexists(target), "target appeared during staging")
        else:
            current = read_file(target, uid, gid)
            require(current[0] == previous[0] and identity(current[1]) == identity(previous[1]),
                    "target changed during staging")
        os.replace(temporary, target)
        directory = os.open(target.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_copy(source, target, source_hash, target_hashes, uid, gid, metadata=None):
    data, info = read_file(source, uid, gid)
    require(digest(data) == source_hash, "preimage hash mismatch")
    previous = read_file(target, uid, gid) if os.path.lexists(target) else None
    if target_hashes is not None:
        require(previous is not None and digest(previous[0]) in target_hashes, "foreign target content")
    publish(data, target, info if metadata is None else metadata, uid, gid, previous)
    require(digest(read_file(target, uid, gid)[0]) == source_hash, "published image mismatch")


def native(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=120).stdout


def semantic_fingerprint(text):
    def normalize(value):
        if isinstance(value, list):
            return [normalize(x) for x in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            if key == "counter" and isinstance(item, dict):
                item = {k: v for k, v in item.items() if k not in ["packets", "bytes"]}
            result[key] = normalize(item)
        return result
    items = []
    for item in json.loads(text)["nftables"]:
        if set(item) == {"metainfo"}:
            continue
        item = normalize(item)
        for kind in ["table", "chain", "rule", "set", "map", "counter"]:
            if kind in item:
                for field in ["handle", "index", "position"]:
                    item[kind].pop(field, None)
                if kind == "counter":
                    for field in ["packets", "bytes"]:
                        item[kind].pop(field, None)
        items.append(item)
    return digest(json.dumps(items, sort_keys=True, separators=(",", ":")).encode())


class Recovery:
    def __init__(self, kind, config, directory=STATE, uid=0, gid=0, run=native,
                 sleep=time.sleep, polls=60):
        self.kind, self.config, self.directory = kind, config, directory
        self.uid, self.gid, self.run, self.sleep, self.polls = uid, gid, run, sleep, polls
        self.state = directory / (kind + ".json")

    @contextlib.contextmanager
    def locked(self):
        self.directory.mkdir(mode=0o700, exist_ok=True)
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                and (info.st_uid, info.st_gid) == (self.uid, self.gid), "unsafe recovery directory")
        fd = os.open(self.directory / (self.kind + ".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and (info.st_uid, info.st_gid) == (self.uid, self.gid)
                    and stat.S_IMODE(info.st_mode) == 0o600, "unsafe recovery lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def load(self):
        data, info = read_file(self.state, self.uid, self.gid)
        require(stat.S_IMODE(info.st_mode) == 0o600, "unsafe state mode")
        state = json.loads(data)
        require(state["kind"] == self.kind, "wrong recovery state")
        return state

    def save(self, state):
        # Metadata from a private empty file avoids a second, weaker write path.
        fd, name = tempfile.mkstemp(dir=self.directory, prefix=".state-")
        try:
            metadata = os.fstat(fd)
            previous = read_file(self.state, self.uid, self.gid) if os.path.lexists(self.state) else None
            publish((json.dumps(state, sort_keys=True) + "\n").encode(), self.state, metadata,
                    self.uid, self.gid, previous)
        finally:
            os.close(fd)
            os.unlink(name)

    def show(self, suffix):
        text = self.run(["systemctl", "show", self.config["unit"] + suffix,
                         "--property=LoadState,ActiveState,SubState,Job,InvocationID,"
                         "ExecMainStartTimestampMonotonic,Result,ExecMainStatus"])
        state = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        required = {"LoadState", "ActiveState", "SubState", "Job", "InvocationID"}
        if suffix == ".service":
            required |= {"ExecMainStartTimestampMonotonic"}
        require(required <= state.keys(), "incomplete recovery unit readback")
        require(state["LoadState"] in ["loaded", "not-found"], "unknown recovery load state")
        require(state["ActiveState"] in ["active", "inactive", "failed", "activating",
                                         "deactivating", "reloading"], "unknown recovery active state")
        substates = (["dead", "waiting", "running", "elapsed", "failed"] if suffix == ".timer"
                     else ["dead", "failed", "exited", "running", "condition", "start-pre", "start",
                           "start-post", "stop", "stop-post", "stop-sigterm", "stop-sigkill",
                           "final-sigterm", "final-sigkill"])
        require(state["SubState"] in substates, "unknown recovery unit substate")
        if state["LoadState"] == "not-found":
            require(state["ActiveState"] == "inactive" and state["SubState"] == "dead"
                    and state["Job"] in ["", "0"] and not state["InvocationID"]
                    and state.get("ExecMainStartTimestampMonotonic", "0") == "0",
                    "inconsistent absent recovery unit")
        return state

    @staticmethod
    def pending(state):
        return (state.get("Job", "0") not in ["", "0"]
                or state.get("ActiveState") in ["activating", "deactivating", "reloading"]
                or state.get("SubState") in ["running", "start", "start-pre", "start-post", "stop", "stop-post"])

    @staticmethod
    def started(state):
        return (Recovery.pending(state) or bool(state.get("InvocationID"))
                or state.get("ExecMainStartTimestampMonotonic", "0") != "0"
                or state.get("ActiveState") in ["active", "failed"])

    def close_timer(self):
        # Stop only the timer. A queued or running restoration must finish itself.
        timer = self.show(".timer")  # Failed/unknown show never proves absence.
        if timer["LoadState"] != "not-found":
            try:
                self.run(["systemctl", "stop", self.config["unit"] + ".timer"])
            except subprocess.CalledProcessError as error:
                # systemd v257 maps NoSuchUnit to EXIT_NOTINSTALLED (5).
                # It may have collected this transient timer after our query.
                if error.returncode != 5:
                    raise
                timer = self.show(".timer")
                if timer["LoadState"] != "not-found":
                    raise
            else:
                timer = self.show(".timer")
        require(timer.get("ActiveState") == "inactive" and not self.pending(timer), "timer not stopped")
        seen = False
        for _ in range(self.polls):
            service = self.show(".service")
            seen = seen or self.started(service)
            if not self.pending(service):
                return seen
            self.sleep(1)
        raise ValueError("recovery still running; left uninterrupted")

    def arm(self, minutes, before=None, desired=None):
        require(2 <= minutes <= 30, "invalid deadman duration")
        with self.locked():
            if self.state.exists():
                require(self.load()["phase"] == "confirmed", "previous attempt requires review")
            timer, service = self.show(".timer"), self.show(".service")
            require(timer.get("ActiveState") == "inactive" and not self.pending(timer)
                    and not self.started(service), "recovery unit collision")
            data, info = read_file(self.config["current"], self.uid, self.gid)
            actual = digest(data)
            if self.kind == "nft":
                candidate, candidate_info = read_file(self.config["candidate"], self.uid, self.gid)
                require(stat.S_IMODE(candidate_info.st_mode) == 0o600, "unsafe candidate mode")
                desired = digest(candidate)
            else:
                require(actual == before and stat.S_IMODE(info.st_mode) == 0o600, "netplan preimage mismatch")
                require(bool(re.fullmatch("[0-9a-f]{64}", desired or "")), "invalid desired hash")
            # Invalidate any earlier confirmed operation before touching its previous image.
            # The staging phase grants neither restore nor apply authority.
            state = {"kind": self.kind, "phase": "staging", "before": actual, "desired": desired}
            self.save(state)
            atomic_copy(self.config["current"], self.config["previous"], actual, None, self.uid, self.gid)
            require(read_file(self.config["current"], self.uid, self.gid)[0] == data, "preimage changed")
            state["phase"] = "prepared"
            self.save(state)
            self.run(["systemd-run", "--unit=" + self.config["unit"], "--on-active=" + str(minutes) + "min",
                      "--property=Type=oneshot", "--property=RemainAfterExit=yes",
                      "/usr/bin/python3", HELPER, self.kind, "restore"])
            require(self.show(".timer").get("ActiveState") == "active", "deadman not armed")
            state["phase"] = "armed"
            self.save(state)

    def apply(self):
        require(self.kind == "nft", "only the role applies nft")
        with self.locked():
            state = self.load()
            require(state["phase"] == "armed" and not self.started(self.show(".service"))
                    and self.show(".timer").get("ActiveState") == "active", "attempt no longer armed")
            require(digest(read_file(self.config["previous"], self.uid, self.gid)[0]) == state["before"],
                    "complete bound preimage is unavailable")
            _, info = read_file(self.config["current"], self.uid, self.gid)
            atomic_copy(self.config["candidate"], self.config["current"], state["desired"],
                        [state["before"]], self.uid, self.gid, metadata=info)
            self.run(self.config["reload"][0])
            state["loaded"] = semantic_fingerprint(self.run(["nft", "-j", "list", "ruleset"]))
            state["phase"] = "applied"
            self.save(state)

    def restore(self, confirmed=False):
        with self.locked():
            state = self.load()
            allowed = ["prepared", "armed", "applied", "restoring", "restored"]
            require(state["phase"] in allowed or (confirmed and state["phase"] == "confirmed"),
                    "attempt is not recoverable")
            state["phase"] = "restoring"
            self.save(state)
            atomic_copy(self.config["previous"], self.config["current"], state["before"],
                        [state["before"], state["desired"]], self.uid, self.gid)
            for command in self.config["reload"]:
                self.run(command)
            state["phase"] = "restored"
            self.save(state)

    def recover(self):
        self.load()  # Never restore a stale .prev after staging failed.
        self.close_timer()  # Never compete with a running restoration.
        self.restore(confirmed=True)  # Also covers a failed post-finalization role assertion.

    def finalize(self):
        ran = self.close_timer()
        with self.locked():
            state = self.load()
            require(not ran and state["phase"] == ("applied" if self.kind == "nft" else "armed"),
                    "recovery ran or attempt incomplete; attempt failed")
            require(digest(read_file(self.config["current"], self.uid, self.gid)[0]) == state["desired"],
                    "final persistent file mismatch")
            if self.kind == "nft":
                require(semantic_fingerprint(self.run(["nft", "-j", "list", "ruleset"])) == state["loaded"],
                        "final loaded ruleset mismatch")
            state["phase"] = "confirmed"
            self.save(state)


def main():
    try:
        kind, action, *args = sys.argv[1:]
        require(kind in CONFIG and action in ["arm", "apply", "restore", "recover", "finalize"], "invalid action")
        recovery = Recovery(kind, CONFIG[kind])
        if action == "arm":
            if kind == "nft":
                require(len(args) == 1, "invalid nft arm arguments")
                recovery.arm(int(args[0]))
            else:
                require(len(args) == 2, "invalid netplan arm arguments")
                recovery.arm(15, *args)
        else:
            require(not args, "unexpected arguments")
            getattr(recovery, action)()
        print('{"verified":true}')
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print("Router recovery operation failed; inspect owned state and units; values suppressed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
