"""EXT3 v1 host boundary. Standard library only; no checkout imports on the VPS.

All operational paths are fixed by root-owned configuration. Local tests exercise
the same file/clock/process boundaries; fixture assertions are not live evidence.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import contextlib
import copy
import dataclasses
import datetime as dt
import fcntl
import gzip
import hashlib
import hmac
import importlib.util
import io
import json
import os
import re
import secrets
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path("/var/lib/personal-platform/deployments")
CONFIG = Path("/etc/personal-platform/host-gate.json")
LIMIT = 16 * 1024**2
REPOSITORY = "VINIClUS/CnesData"
HOST_STATES = {
    "RECEIVED",
    "VERIFIED",
    "STAGED",
    "CANDIDATE_HEALTHY",
    "SWITCHED",
    "ACCEPTED",
    "ROLLED_BACK",
    "FAILED",
    "RECOVERY_REQUIRED",
}
FENCE_PHASES = {
    "OPEN",
    "CLOSING",
    "CLOSED_DRAINING",
    "CLOSED_READY",
    "REOPENING",
    "OPEN_VERIFIED",
    "RECOVERY_REQUIRED",
}
DISPATCH_STATES = {
    "NOT_SENT",
    "SEND_PENDING",
    "ACKNOWLEDGED",
    "EFFECT_CONFIRMED",
    "NO_EFFECT_CONFIRMED",
    "OUTCOME_UNKNOWN",
}
EFFECTS = {
    "pull",
    "start-candidate",
    "nginx-switch",
    "stop-prior",
    "restore-previous",
    "credential-reload",
    "external-product-dispatch",
}
ACTIONS = {"validate", "deploy", "rollback-previous"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def closed(value, fields):
    names = set(fields.split()) if isinstance(fields, str) else set(fields)
    require(type(value) is dict and set(value) == names, "closed object fields")
    return value


def integer(value, minimum=0, maximum=2**53 - 1):
    require(type(value) is int and minimum <= value <= maximum, "integer range")
    return value


def digest(value, length=64):
    require(
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value),
        "digest",
    )
    return value


def opaque(value):
    require(
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= 256
        and not any(ord(c) < 32 or ord(c) == 127 for c in value),
        "opaque string",
    )
    return value


def instant(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value),
        "UTC instant",
    )
    return (
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=dt.UTC)
        .timestamp()
    )


def utc(value):
    return dt.datetime.fromtimestamp(value, dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tree(value, depth=0):
    require(depth <= 16, "JSON depth")
    if type(value) is dict:
        require(len(value) <= 64, "JSON member count")
        for key, child in value.items():
            require(isinstance(key, str), "JSON key")
            key.encode("utf-8", "strict")
            _tree(child, depth + 1)
    elif type(value) is list:
        require(len(value) <= 1024, "JSON array count")
        for child in value:
            _tree(child, depth + 1)
    elif isinstance(value, str):
        value.encode("utf-8", "strict")
    else:
        require(value is None or type(value) in {int, bool}, "JSON scalar")


def canonical(value):
    _tree(value)
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def host_json(raw, maximum=LIMIT):
    require(0 < len(raw) <= maximum, "JSON size")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("JSON number")

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_float=invalid,
            parse_constant=invalid,
        )
        _tree(value)
        return value
    except (UnicodeError, RecursionError) as error:
        raise ValueError("JSON encoding/depth") from error


@dataclasses.dataclass(repr=False)
class Request:
    envelope: dict
    envelope_bytes: bytes
    archive: bytes
    token: bytearray
    admission: ClosedReady | None = None
    diagnostic: bool = False
    channel_nonce: str | None = None

    def erase(self):
        self.token[:] = b"\0" * len(self.token)


def _exact(stream, size):
    parts = bytearray()
    while len(parts) < size:
        part = stream.read(min(65536, size - len(parts)))
        require(bool(part), "truncated frame")
        parts.extend(part)
    return bytes(parts)


def read_request(stream):
    frames = []
    for maximum in (65536, LIMIT, 16384):
        size = struct.unpack(">Q", _exact(stream, 8))[0]
        require(0 < size <= maximum, "frame length")
        frames.append(_exact(stream, size))
    require(stream.read(1) == b"", "fourth frame/trailing byte")
    token = bytearray(frames[2])
    try:
        require(all(32 < c < 127 for c in token), "token controls")
        value = host_json(frames[0], 65536)
        require(canonical(value) == frames[0], "noncanonical envelope")
        return Request(value, frames[0], frames[1], token)
    except BaseException:
        token[:] = b"\0" * len(token)
        raise


def validate_envelope(value, *, workflows, images, now):
    closed(value, "schema_version ci_evidence release_manifest")
    require(
        type(value["schema_version"]) is int and value["schema_version"] == 1,
        "envelope version",
    )
    ci = closed(
        value["ci_evidence"], "repository workflow run_id artifact_id artifact_digest"
    )
    require(
        ci["repository"] == REPOSITORY and ci["workflow"] in workflows,
        "producer allowlist",
    )
    integer(ci["run_id"], 1)
    integer(ci["artifact_id"], 1)
    require(
        ci["artifact_digest"]
        == "sha256:" + digest(ci["artifact_digest"].removeprefix("sha256:")),
        "artifact hash",
    )
    m = value["release_manifest"]
    fields = {
        "project",
        "source_repository",
        "source_sha",
        "expires_at",
        "platform_plan",
        "images",
        "compose_sha256",
        "config_sha256",
        "requested_action",
    }
    if "static_release" in m:
        fields.add("static_release")
        opaque(m["static_release"])
    closed(m, fields)
    require(
        m["project"] == "cnesdata" and m["source_repository"] == REPOSITORY, "tenant"
    )
    digest(m["source_sha"], 40)
    require(instant(m["expires_at"]) > now, "expired envelope")
    require(m["requested_action"] in ACTIONS, "action")
    closed(m["images"], "api")
    image = m["images"]["api"].split("@sha256:")
    require(len(image) == 2 and image[0] in images, "immutable image allowlist")
    digest(image[1])
    for field in ("compose_sha256", "config_sha256"):
        digest(m[field])
    plan = closed(
        m["platform_plan"],
        "evidence_id evidence_sha256 inventory_sha256 dependencies_sha256 host_preflight_sha256 host_key_fingerprint",
    )
    for field in plan:
        digest(plan[field]) if field.endswith("sha256") else opaque(plan[field])
    return m


def inspect_archive(raw, manifest, expected):
    require(len(raw) <= LIMIT and sha(raw) == digest(expected), "archive hash/size")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            unpacked = compressed.read(LIMIT + 1)
            require(len(unpacked) <= LIMIT, "archive expansion")
        result = {}
        limits = {
            "release-manifest.json": 65536,
            "compose.yml": 1024**2,
            "config.json": LIMIT,
        }
        with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as tar:
            for item in tar:
                require(
                    item.name in limits
                    and item.name not in result
                    and item.type == tarfile.REGTYPE
                    and not item.pax_headers
                    and not item.linkname,
                    "archive member",
                )
                require(0 < item.size <= limits[item.name], "archive member size")
                # Reject GNU/PAX extension records even if tarfile silently consumes them.
                require(
                    item.offset == item.offset_data - 512, "archive extension header"
                )
                file = tar.extractfile(item)
                if file is None:
                    raise ValueError("archive file")
                data = file.read(item.size + 1)
                require(len(data) == item.size, "archive truncated")
                result[item.name] = data
            require(set(result) == set(limits), "archive file set")
            tail = unpacked[tar.offset :]
            require(len(tail) >= 1024 and not any(tail), "archive trailing payload")
        require(
            result["release-manifest.json"] == canonical(manifest), "embedded manifest"
        )
        require(
            sha(result["compose.yml"]) == manifest["compose_sha256"]
            and sha(result["config.json"]) == manifest["config_sha256"],
            "configuration digest",
        )
        return result
    except (OSError, EOFError, tarfile.TarError) as error:
        raise ValueError("archive invalid") from error


def private_directory(path):
    path = Path(path)
    require(not path.is_symlink(), "symlink directory")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_mode & 0o077 == 0,
        "insecure directory",
    )
    return path


def read_private(path, maximum=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and info.st_mode & 0o077 == 0,
            "insecure file",
        )
        data = file.read(maximum + 1)
        require(len(data) <= maximum, "file bound")
        return data


def durable(path, data, *, immutable=False):
    path = Path(path)
    private_directory(path.parent)
    temp = path.parent / (".write-" + secrets.token_hex(16))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        if immutable:
            os.link(temp, path, follow_symlinks=False)
            temp.unlink()
        else:
            os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        require(read_private(path, maximum=len(data)) == data, "physical readback")
    finally:
        temp.unlink(missing_ok=True)


def stage_archive(parent, files):
    parent = private_directory(parent)
    staged = Path(tempfile.mkdtemp(prefix="stage-", dir=parent))
    try:
        require(
            set(files) == {"release-manifest.json", "compose.yml", "config.json"},
            "staging files",
        )
        for name, data in files.items():
            durable(staged / name, data, immutable=True)
        return staged
    except BaseException:
        shutil.rmtree(staged)
        raise


class Clock:
    def __init__(self):
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.time_samples = []
        self.clock_reference = None

    def wall(self):
        return time.time()

    def mono(self):
        return time.monotonic()

    def observe(self, server, started, returned):
        require(0 <= returned - started <= 20, "authenticated clock RTT")
        require(abs(self.wall() - server) <= 30, "authenticated clock skew")
        self._continuous()
        self.clock_reference = (self.wall(), returned)
        # Date is quantized to seconds. Its receipt interval includes the whole RTT.
        self.time_samples.append((server + 1 + returned - started, returned))
        require(len(self.time_samples) <= 1024, "clock sample bound")

    def upper(self):
        require(self.time_samples, "authenticated clock unavailable")
        self._continuous()
        now = self.mono()
        return max(
            self.wall(), *(value + now - sample for value, sample in self.time_samples)
        )

    def _continuous(self):
        if self.clock_reference is not None:
            wall, mono = self.clock_reference
            require(
                self.mono() >= mono
                and abs(self.wall() - wall - (self.mono() - mono)) <= 1,
                "authenticated clock discontinuity",
            )


class Window:
    """Fixed original-input fence budget AND independent last-observed lease guard."""

    def __init__(
        self, clock, *, close_confirmed_at=None, input_deadlines, host_started_at=None
    ):
        require(bool(input_deadlines), "original input deadlines")
        require(
            (close_confirmed_at is None) != (host_started_at is None),
            "one actual clock anchor",
        )
        self.clock = clock
        self.start_wall, self.start_mono = clock.wall(), clock.mono()
        self.last_mono = self.start_mono
        self.boot_id = clock.boot_id
        self.promotion_window = close_confirmed_at is not None
        anchor = close_confirmed_at if self.promotion_window else host_started_at
        if anchor is None:
            raise ValueError("missing observed clock anchor")
        self.fixed_deadline = min(anchor + 1800, *input_deadlines)
        self.stage_deadline = self.fixed_deadline
        self.failure = None
        self.decision = None
        self.later_seconds = None

    def now(self, *, diagnostic=False):
        mono = self.clock.mono()
        expected = self.start_wall + mono - self.start_mono
        if (
            self.clock.boot_id != self.boot_id
            or mono < self.last_mono
            or abs(self.clock.wall() - expected) > 1
        ):
            self.fail("clock discontinuity")
        self.last_mono = mono
        require(
            self.failure is None
            or (diagnostic and self.failure == "renewal failed or ambiguous"),
            self.failure or "latched failure",
        )
        upper = (
            self.clock.upper()
            if getattr(self.clock, "time_samples", None)
            else self.clock.wall()
        )
        return max(expected, self.clock.wall(), upper)

    def fail(self, reason):
        self.failure = self.failure or reason

    def shorten(self, deadline):
        self.fixed_deadline = min(self.fixed_deadline, deadline)

    def enter_stage(self, name, *, budget, later):
        require(self.decision is None, "irreversible recovery decision")
        require(budget > 0 and later >= 0, "stage budget")
        now = self.now()
        require(self.fixed_deadline - now >= budget + later + 420, "fixed budget")
        self.stage_deadline = min(self.fixed_deadline, now + budget)

    def guard(self, *, lease_expires_at, request=20, termination=15, tick=1):
        now = self.now()
        require(
            0 < request <= 20 and 0 <= termination <= 15 and 0 < tick <= 1,
            "bounded effect",
        )
        require(
            lease_expires_at - now > 120 + request + termination + tick,
            "current lease margin",
        )
        require(
            now + request + termination + tick <= self.stage_deadline, "stage deadline"
        )
        require(now <= self.fixed_deadline, "fixed deadline")
        if self.later_seconds is not None:
            ceiling = (
                self.fixed_deadline
                if self.decision is None
                else min(
                    self.fixed_deadline, instant(self.decision["recovery_deadline"])
                )
            )
            reserve = 420 if self.decision is None else 0
            require(
                ceiling - now
                >= max(0, self.stage_deadline - now) + self.later_seconds + reserve,
                "remaining promotion/recovery budget",
            )
        return now

    def choose_recovery(self, operation, binding, generation, checkpoint):
        if self.decision is None:
            now = self.now(diagnostic=True)
            deadline = min(self.fixed_deadline, now + 420)
            self.decision = {
                "version": 1,
                "operation_id": digest(operation),
                "binding_sha256": digest(binding),
                "generation": integer(generation),
                "choice_at": utc(now),
                "choice_monotonic_ms": int(self.clock.mono() * 1000),
                "clock_boot_id": sha(b"ext3:clock-boot:v1\0" + self.boot_id.encode()),
                "fixed_deadline": utc(self.fixed_deadline),
                "recovery_deadline": utc(deadline),
                "allocated_seconds": max(0, int(deadline - now)),
                "convergence_budget_seconds": 300,
                "finalization_budget_seconds": 60,
                "uncertainty_budget_seconds": 60,
                "checkpoint_sha256": digest(checkpoint),
            }
            self.stage_deadline = deadline
        return copy.deepcopy(self.decision)

    def import_recovery(self, decision):
        validate_recovery_decision(decision)
        require(
            self.decision is None or self.decision == decision,
            "immutable recovery decision",
        )
        self.decision = copy.deepcopy(decision)
        self.fixed_deadline = min(
            self.fixed_deadline, instant(decision["fixed_deadline"])
        )
        self.stage_deadline = min(
            self.fixed_deadline,
            instant(decision["recovery_deadline"]),
            instant(decision["choice_at"]) + 300,
        )
        self.later_seconds = 120

    def recovery_remaining(self):
        if self.decision is None:
            raise ValueError("recovery not chosen")
        return instant(self.decision["recovery_deadline"]) - self.now()

    def recovery_guard(
        self,
        *,
        convergence_remaining,
        finalization_remaining,
        uncertainty_remaining,
        lease_expires_at,
    ):
        values = (convergence_remaining, finalization_remaining, uncertainty_remaining)
        require(
            all(v >= 0 for v in values) and self.recovery_remaining() >= sum(values),
            "recovery budget consumed",
        )
        self.guard(lease_expires_at=lease_expires_at)


def process_identity(pid=None):
    pid = pid or os.getpid()
    text = Path(f"/proc/{pid}/stat").read_text()
    return {
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "pid": pid,
        "start_ticks": int(text[text.rfind(")") + 2 :].split()[19]),
        "invocation_id": os.environ.get("INVOCATION_ID"),
    }


def validate_owner(owner):
    closed(owner, "class process workflow human_session_commitment systemd_invocation")
    p = closed(owner["process"], "boot_id pid start_ticks invocation_id")
    opaque(p["boot_id"])
    integer(p["pid"], 1)
    integer(p["start_ticks"])
    if p["invocation_id"] is not None:
        opaque(p["invocation_id"])
    arms = {
        "workflow": "workflow",
        "human": "human_session_commitment",
        "systemd": "systemd_invocation",
    }
    require(owner["class"] in arms, "owner class")
    for arm in arms.values():
        require(
            (owner[arm] is not None) == (arm == arms[owner["class"]]), "owner union"
        )
    if owner["class"] == "human":
        digest(owner["human_session_commitment"])
    if owner["class"] == "systemd":
        require(owner["systemd_invocation"] == p["invocation_id"], "systemd invocation")


class HostLease:
    """One physical lock/snapshot for all applications and administrative owners."""

    def __init__(self, root=ROOT, clock=None):
        self.root = private_directory(root)
        self.clock = clock or Clock()

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(
            self.root / "authority.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        try:
            require(
                os.fstat(fd).st_nlink == 1 and os.fstat(fd).st_uid == os.geteuid(),
                "lock identity",
            )
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def snapshot(self):
        path = self.root / "authority.json"
        if not path.exists() and not path.is_symlink():
            return {"version": 1, "revision": 0, "lease": None, "head": None}
        value = host_json(read_private(path))
        closed(value, "version revision lease head")
        require(
            type(value["version"]) is int and value["version"] == 1, "authority version"
        )
        integer(value["revision"])
        return value

    def _commit(self, value):
        durable(self.root / "authority.json", canonical(value))
        require(self.snapshot() == value, "authority readback")
        return copy.deepcopy(value)

    def _check(self, token, expected):
        current = self.snapshot()
        require(current == expected, "CAS authority changed")
        lease = current["lease"]
        require(
            lease
            and lease["state"] == "HELD"
            and hmac.compare_digest(sha(token), lease["owner_token_sha256"]),
            "lease owner",
        )
        require(
            self.clock.wall() < instant(lease["expires_at"]),
            "lease expired recovery required",
        )
        return copy.deepcopy(current)

    def acquire(self, owner, operation_id, *, terminal_proof=None):
        validate_owner(owner)
        digest(operation_id)
        with self.locked():
            current = self.snapshot()
            prior = current["lease"]
            if prior is not None:
                require(
                    prior["state"] == "RELEASED" and terminal_proof is not None,
                    "prior authority requires reviewed recovery",
                )
                if terminal_proof is None:
                    raise ValueError("terminal proof missing")
                require(
                    terminal_proof(prior), "authenticated prior terminal checkpoint"
                )
            now, token = self.clock.wall(), secrets.token_bytes(32)
            generation = 1 if prior is None else prior["generation"] + 1
            lease = {
                "version": 1,
                "state": "HELD",
                "revision": 0,
                "generation": generation,
                "owner": copy.deepcopy(owner),
                "owner_token_sha256": sha(token),
                "operation_id": operation_id,
                "acquired_at": utc(now),
                "renewed_at": utc(now),
                "expires_at": utc(now + 300),
                # Retain the preceding checkpoint through administrative ownership;
                # the fixed LeaseRecord schema needs no additional pointer field.
                "checkpoint_sha256": prior["checkpoint_sha256"] if prior else None,
                "recovery_proof_sha256": None,
            }
            return token, self._commit(
                {
                    "version": 1,
                    "revision": current["revision"] + 1,
                    "lease": lease,
                    "head": None,
                }
            )

    def renew(self, token, expected):
        with self.locked():
            current = self._check(token, expected)
            lease = current["lease"]
            now = self.clock.wall()
            require(
                instant(lease["expires_at"]) - now > 156, "renewal current lease margin"
            )
            lease.update(
                revision=lease["revision"] + 1,
                renewed_at=utc(now),
                expires_at=utc(now + 300),
            )
            current["revision"] += 1
            return self._commit(current)

    def release(self, token, expected, checkpoint, physical_terminal):
        with self.locked():
            current = self._check(token, expected)
            require(physical_terminal(), "workers not proven terminal")
            if current["head"] is not None:
                record = find_record(self.root, checkpoint)
                require(
                    record["state"] in {"ACCEPTED", "ROLLED_BACK"}
                    and not record["effect_possible"],
                    "release terminal record",
                )
            current["lease"].update(
                state="RELEASED",
                checkpoint_sha256=digest(checkpoint),
                revision=current["lease"]["revision"] + 1,
            )
            current["revision"] += 1
            return self._commit(current)

    def recover_stale(self, expected, proof):
        """Root-only reviewed recovery; the proof reader observes OS and original owner."""
        require(os.geteuid() == 0, "root recovery only")
        with self.locked():
            require(self.snapshot() == expected, "CAS recovery")
            observed = proof(expected)
            closed(
                observed, "process_absent owner_terminal checkpoint_sha256 proof_sha256"
            )
            require(
                observed["process_absent"] is True
                and observed["owner_terminal"] is True,
                "stale proof",
            )
            require(self.snapshot() == expected, "CAS recovery proof race")
            digest(observed["checkpoint_sha256"])
            digest(observed["proof_sha256"])
            # Retain the reviewed observation itself so a later owner can verify
            # session termination without reasserting it from the elapsed TTL.
            recovery = canonical(
                {
                    "version": 1,
                    "prior_authority_sha256": sha(canonical(expected)),
                    "owner": expected["lease"]["owner"],
                    "owner_token_sha256": expected["lease"]["owner_token_sha256"],
                    "generation": expected["lease"]["generation"] + 1,
                    "observation": observed,
                }
            )
            durable(
                private_directory(self.root / "recovery-proofs")
                / (sha(recovery) + ".json"),
                recovery,
                immutable=True,
            )
            value = copy.deepcopy(expected)
            value["lease"].update(
                state="RELEASED",
                checkpoint_sha256=digest(observed["checkpoint_sha256"]),
                recovery_proof_sha256=sha(recovery),
                generation=value["lease"]["generation"] + 1,
                revision=value["lease"]["revision"] + 1,
            )
            value["revision"] += 1
            return self._commit(value)


def run_ref(value):
    closed(
        value, "repository source_sha ref workflow_path workflow_sha run_id run_attempt"
    )
    for key in ("source_sha", "workflow_sha"):
        digest(value[key], 40)
    for key in ("run_id", "run_attempt"):
        integer(value[key], 1)
    for key in ("repository", "ref", "workflow_path"):
        opaque(value[key])


def validate_binding(b):
    closed(
        b,
        "version caller ci_artifact approval platform release original_bytes api_image requested_action previous_accepted_sha256 lease_owner_sha256 initial_generation operation_nonce_sha256 expires",
    )
    require(type(b["version"]) is int and b["version"] == 1, "binding version")
    run_ref(b["caller"])
    require(
        b["caller"]["repository"] == REPOSITORY
        and b["caller"]["ref"] == "refs/heads/develop",
        "caller source",
    )
    art = closed(
        b["ci_artifact"], "producer artifact_id artifact_digest created_at expires_at"
    )
    run_ref(art["producer"])
    require(art["producer"]["repository"] == REPOSITORY, "producer tenant")
    integer(art["artifact_id"], 1)
    require(
        art["artifact_digest"]
        == "sha256:" + digest(art["artifact_digest"].removeprefix("sha256:")),
        "artifact digest",
    )
    require(
        instant(art["created_at"]) < instant(art["expires_at"]), "artifact validity"
    )
    approval = closed(
        b["approval"],
        "repository base_sha head_sha reusable_path reusable_sha contract_sha256 governance_sha256 pins",
    )
    require(
        approval["repository"] == "VINIClUS/infra-ansible"
        and approval["reusable_path"]
        == ".github/workflows/reusable-cnesdata-host-deploy-gate.yml",
        "producer approval",
    )
    for key in ("base_sha", "head_sha", "reusable_sha"):
        digest(approval[key], 40)
    for key in ("contract_sha256", "governance_sha256"):
        digest(approval[key])
    require(type(approval["pins"]) is list and 0 < len(approval["pins"]) <= 32, "pins")
    pins = []
    for pin in approval["pins"]:
        closed(pin, "repository source_sha content_sha256")
        pins.append((opaque(pin["repository"]), digest(pin["source_sha"], 40)))
        digest(pin["content_sha256"])
    require(pins == sorted(set(pins)), "unique sorted pins")
    platform = closed(
        b["platform"],
        "evidence_id evidence_sha256 object_bucket object_key object_version inventory_sha256 dependencies_sha256 host_preflight_sha256 host_key_fingerprint handoff_sha256",
    )
    for key, value in platform.items():
        digest(value) if key.endswith("sha256") else opaque(value)
    release = b["release"]
    if release is not None:
        closed(
            release,
            "repository release_id source_sha candidate_sha256 canary_id binding_sha256 activation_sha256 signature_sha256 phase_a_evidence_sha256 ecr_image_digest unit_revision recovery_revision audit_revision",
        )
        require(release["repository"] == REPOSITORY, "release tenant")
        for key, value in release.items():
            if key == "source_sha":
                digest(value, 40)
            elif key == "canary_id":
                digest(value, 32)
            elif key.endswith("sha256"):
                digest(value)
            else:
                opaque(value)
        require(
            all(
                re.fullmatch(
                    r"arn:aws:ecs:us-east-2:\d{12}:task-definition/[A-Za-z0-9_-]{1,255}:[1-9][0-9]{0,9}",
                    release[key],
                )
                for key in ("unit_revision", "recovery_revision", "audit_revision")
            ),
            "literal revision ARN",
        )
    original = closed(
        b["original_bytes"],
        "envelope_sha256 manifest_sha256 archive_sha256 compose_sha256 config_sha256 platform_sha256 baseline_sha256",
    )
    for value in original.values():
        digest(value)
    require(
        re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", b["api_image"]),
        "image digest",
    )
    require(b["requested_action"] in ACTIONS, "binding action")
    require(
        release is not None or b["requested_action"] == "validate",
        "activation required",
    )
    if b["previous_accepted_sha256"] is not None:
        digest(b["previous_accepted_sha256"])
    require(
        b["requested_action"] != "rollback-previous"
        or b["previous_accepted_sha256"] is not None,
        "rollback checkpoint",
    )
    digest(b["lease_owner_sha256"])
    digest(b["operation_nonce_sha256"])
    integer(b["initial_generation"])
    require(type(b["expires"]) is list, "expiry list")
    names = []
    for expiry in b["expires"]:
        closed(expiry, "name expires_at source_sha256")
        names.append(expiry["name"])
        instant(expiry["expires_at"])
        digest(expiry["source_sha256"])
    require(
        names == sorted(set(names))
        and set(names)
        in (
            {"envelope", "artifact", "platform", "cost", "credential"},
            {"envelope", "artifact", "platform", "cost", "credential", "activation"},
        ),
        "expiry coverage",
    )
    return b


def validate_record(r):
    closed(
        r,
        "version operation_id nonce_sha256 generation revision binding_sha256 binding state fence_phase retry accepted effect_confirmed effect_possible dispatches previous_accepted_sha256 close_confirmed_at reopen_verified_at",
    )
    validate_binding(r["binding"])
    require(
        r["state"] in HOST_STATES
        and r["fence_phase"] in FENCE_PHASES
        and r["retry"] in {"UNAVAILABLE", "AVAILABLE", "CONSUMED"},
        "record union",
    )
    require(
        r["binding_sha256"] == sha(canonical(r["binding"]))
        and r["nonce_sha256"] == r["binding"]["operation_nonce_sha256"]
        and r["operation_id"]
        == sha(b"ext3:host-operation:v1\0" + canonical(r["binding"])),
        "record binding",
    )
    integer(r["generation"])
    integer(r["revision"])
    require(
        all(
            type(r[k]) is bool
            for k in ("accepted", "effect_confirmed", "effect_possible")
        ),
        "record facts",
    )
    require(
        type(r["dispatches"]) is list and len(r["dispatches"]) <= 128, "dispatch bound"
    )
    ids = []
    for d in r["dispatches"]:
        closed(
            d,
            "id kind generation binding_sha256 nonce_sha256 request_sha256 state origin external_ref outcome proof_sha256",
        )
        ids.append(digest(d["id"]))
        for key in ("binding_sha256", "nonce_sha256", "request_sha256"):
            digest(d[key])
        require(
            d["binding_sha256"] == r["binding_sha256"]
            and d["nonce_sha256"] == r["nonce_sha256"],
            "dispatch binding",
        )
        integer(d["generation"])
        require(
            d["kind"] in EFFECTS
            and d["state"] in DISPATCH_STATES
            and d["origin"] in {"host", "product"}
            and d["outcome"]
            in {"pending", "running", "terminal", "absent_proven", "unknown"},
            "dispatch union",
        )
        require(
            (d["origin"] == "product") == (d["kind"] == "external-product-dispatch"),
            "dispatch owner",
        )
        if d["external_ref"] is not None:
            opaque(d["external_ref"])
        if d["proof_sha256"] is not None:
            digest(d["proof_sha256"])
    require(ids == sorted(set(ids)), "dispatch set")
    for field in ("close_confirmed_at", "reopen_verified_at"):
        if r[field] is not None:
            instant(r[field])


class Operation:
    def __init__(self, lease, token, snapshot, binding, originals):
        self.lease, self.token, self.snapshot = lease, token, snapshot
        validate_binding(binding)
        require(
            binding["lease_owner_sha256"] == sha(token)
            and binding["initial_generation"] == snapshot["lease"]["generation"],
            "binding lease",
        )
        opid = sha(b"ext3:host-operation:v1\0" + canonical(binding))
        self.directory = private_directory(lease.root / "cnesdata" / opid)
        for name, data in originals.items():
            require(re.fullmatch(r"[a-z0-9-]{1,64}", name), "original filename")
            durable(self.directory / ("original-" + name), data, immutable=True)
        r = {
            "version": 1,
            "operation_id": opid,
            "nonce_sha256": binding["operation_nonce_sha256"],
            "generation": binding["initial_generation"],
            "revision": 0,
            "binding_sha256": sha(canonical(binding)),
            "binding": copy.deepcopy(binding),
            "state": "RECEIVED",
            "fence_phase": "OPEN",
            "retry": "AVAILABLE",
            "accepted": True,
            "effect_confirmed": False,
            "effect_possible": False,
            "dispatches": [],
            "previous_accepted_sha256": binding["previous_accepted_sha256"],
            "close_confirmed_at": None,
            "reopen_verified_at": None,
        }
        self.record = r
        self.commit(r)

    @classmethod
    def resume_readonly(cls, lease, token, expected, original_binding):
        """Never construct fresh binding/nonces on retry; caller still authenticates original bytes."""
        self = cls.__new__(cls)
        self.lease, self.token, self.snapshot = lease, token, expected
        head = expected["head"]
        require(head is not None, "missing operation")
        self.directory = private_directory(
            lease.root / "cnesdata" / head["operation_id"]
        )
        self.record = host_json(
            read_private(self.directory / (head["record_sha256"] + ".json"))
        )
        validate_record(self.record)
        require(self.record["binding"] == original_binding, "retry original binding")
        self.consume()
        return self

    def commit(self, record, *, expected=None):
        expected = expected or self.snapshot
        with self.lease.locked():
            value = self.lease._check(self.token, expected)
            if value["head"] is not None:
                previous = host_json(
                    read_private(
                        self.directory / (value["head"]["record_sha256"] + ".json")
                    )
                )
                validate_record(previous)
                require(
                    previous["binding"] == record["binding"]
                    and previous["operation_id"] == record["operation_id"],
                    "CAS binding",
                )
            record = copy.deepcopy(record)
            record["revision"] = (value["head"]["revision"] + 1) if value["head"] else 0
            validate_record(record)
            raw = canonical(record)
            commitment = sha(raw)
            durable(self.directory / (commitment + ".json"), raw, immutable=True)
            head = {
                "version": 1,
                "generation": record["generation"],
                "revision": record["revision"],
                "record_sha256": commitment,
                "operation_id": record["operation_id"],
                "state": record["state"],
                "fence_phase": record["fence_phase"],
                "lease_owner_sha256": sha(self.token),
                "previous_accepted_sha256": record["previous_accepted_sha256"],
            }
            value["head"] = head
            value["lease"]["operation_id"] = record["operation_id"]
            value["lease"]["generation"] = record["generation"]
            value["lease"]["revision"] += 1
            value["revision"] += 1
            self.snapshot = self.lease._commit(value)
            self.record = record
            return copy.deepcopy(record)

    def transition(self, state):
        require(state in HOST_STATES, "host state")
        edges = {
            "RECEIVED": {"VERIFIED"},
            "VERIFIED": {"STAGED"},
            "STAGED": {"CANDIDATE_HEALTHY"},
            "CANDIDATE_HEALTHY": {"SWITCHED"},
            "SWITCHED": {"ACCEPTED"},
        }
        if self.record["binding"]["requested_action"] == "validate":
            edges["VERIFIED"] = {"ACCEPTED"}
        require(
            state in edges.get(self.record["state"], set())
            or state == "RECOVERY_REQUIRED"
            or (
                state == "FAILED"
                and not self.record["effect_possible"]
                and not self.record["effect_confirmed"]
            )
            or (
                state == "ROLLED_BACK"
                and self.record["effect_confirmed"]
                and not self.record["effect_possible"]
            ),
            "host transition",
        )
        r = copy.deepcopy(self.record)
        r["state"] = state
        if state == "RECOVERY_REQUIRED":
            r["fence_phase"] = "RECOVERY_REQUIRED"
        return self.commit(r)

    def bind_closed_ready(self, admission):
        """Commit original product evidence to the actual physical CAS, never a forecast."""
        with self.lease.locked():
            self.lease._check(self.token, self.snapshot)
            require(
                not (self.directory / "closed-ready-binding.json").exists(),
                "ClosedReady already bound",
            )
            for name, raw in admission.original.items():
                durable(self.directory / ("product-" + name), raw, immutable=True)
            value = {
                "closed_ready_sha256": sha(admission.original["closed-ready.json"]),
                "artifact_id": admission.artifact["id"],
                "artifact_digest": admission.artifact["digest"],
                "initial_generation": self.snapshot["lease"]["generation"],
                "head_sha256": sha(canonical(self.snapshot["head"])),
                "binding_sha256": self.record["binding_sha256"],
                "operation_id": self.record["operation_id"],
            }
            raw = canonical(value)
            durable(self.directory / "closed-ready-binding.json", raw, immutable=True)
            require(
                read_private(self.directory / "closed-ready-binding.json") == raw,
                "ClosedReady physical readback",
            )
            self.closed_ready_binding_sha256 = sha(raw)
            self.check_closed_ready()

    def check_closed_ready(self):
        commitment = getattr(self, "closed_ready_binding_sha256", None)
        if commitment is None:
            return
        raw = read_private(self.directory / "closed-ready-binding.json")
        value = host_json(raw)
        require(
            sha(raw) == commitment
            and value["binding_sha256"] == self.record["binding_sha256"]
            and value["operation_id"] == self.record["operation_id"]
            and value["initial_generation"]
            == self.record["generation"]
            == self.snapshot["lease"]["generation"],
            "ClosedReady stale binding/generation",
        )
        require(
            sha(read_private(self.directory / "product-closed-ready.json"))
            == value["closed_ready_sha256"],
            "ClosedReady original changed",
        )

    def persist_recovery(self, window):
        """The existing private diagnostic owns the first decision; later readers import it."""
        path = self.directory / "recovery-decision.json"
        if path.exists():
            decision = validate_recovery_decision(host_json(read_private(path)))
            window.import_recovery(decision)
            return decision
        if window.decision is None:
            decision = window.choose_recovery(
                self.record["operation_id"],
                self.record["binding_sha256"],
                self.record["generation"],
                self.snapshot["head"]["record_sha256"],
            )
        else:
            decision = window.decision
        raw = canonical(decision)
        durable(path, raw, immutable=True)
        require(read_private(path) == raw, "recovery decision readback")
        with self.lease.locked():
            current = self.lease._check(self.token, self.snapshot)
            current["lease"]["recovery_proof_sha256"] = sha(raw)
            current["lease"]["revision"] += 1
            current["revision"] += 1
            self.snapshot = self.lease._commit(current)
        return decision

    def before_send(self, kind, request, *, external_ref=None):
        self.check_closed_ready()
        require(
            self.record["binding"]["requested_action"] != "validate",
            "validate has no effects",
        )
        require(
            self.record["state"] not in {"FAILED", "RECOVERY_REQUIRED", "ROLLED_BACK"}
            and not self.record["effect_possible"]
            and self.record["retry"] != "CONSUMED",
            "send authority",
        )
        require(
            kind in EFFECTS and len(self.record["dispatches"]) < 128,
            "dispatch bound/kind",
        )
        r = copy.deepcopy(self.record)
        request_sha = sha(request)
        ident = sha(canonical([r["operation_id"], len(r["dispatches"]), request_sha]))
        r["dispatches"].append(
            {
                "id": ident,
                "kind": kind,
                "generation": r["generation"],
                "binding_sha256": r["binding_sha256"],
                "nonce_sha256": r["nonce_sha256"],
                "request_sha256": request_sha,
                "state": "SEND_PENDING",
                "origin": "product" if external_ref else "host",
                "external_ref": external_ref,
                "outcome": "pending",
                "proof_sha256": None,
            }
        )
        r["dispatches"].sort(key=lambda d: d["id"])
        r["effect_possible"] = True
        self.commit(r)
        return ident

    def outcome(self, ident, state, outcome, proof):
        require(
            state in {"ACKNOWLEDGED", "EFFECT_CONFIRMED", "OUTCOME_UNKNOWN"},
            "cannot infer no effect after send",
        )
        r = copy.deepcopy(self.record)
        matches = [d for d in r["dispatches"] if d["id"] == ident]
        require(
            len(matches) == 1 and matches[0]["generation"] == r["generation"],
            "old callback observation only",
        )
        d = matches[0]
        require(
            d["state"] in {"SEND_PENDING", "ACKNOWLEDGED", "OUTCOME_UNKNOWN"},
            "terminal dispatch",
        )
        d.update(state=state, outcome=outcome, proof_sha256=digest(proof))
        r["effect_confirmed"] |= state == "EFFECT_CONFIRMED"
        r["effect_possible"] = any(
            item["state"] not in {"EFFECT_CONFIRMED", "NO_EFFECT_CONFIRMED"}
            or item["outcome"] not in {"terminal", "absent_proven"}
            for item in r["dispatches"]
        )
        return self.commit(r)

    def close(self):
        require(self.record["fence_phase"] == "OPEN", "close once")
        r = copy.deepcopy(self.record)
        r["fence_phase"], r["generation"] = "CLOSING", r["generation"] + 1
        return self.commit(r)

    def confirm_closed(self, readback):
        require(self.record["fence_phase"] == "CLOSING", "close state")
        readback(self.record)
        r = copy.deepcopy(self.record)
        r.update(
            fence_phase="CLOSED_DRAINING",
            close_confirmed_at=utc(self.lease.clock.wall()),
        )
        return self.commit(r)

    def closed_ready(self, proof):
        require(
            not self.record["effect_possible"]
            and all(
                d["outcome"] in {"terminal", "absent_proven"}
                for d in self.record["dispatches"]
            ),
            "pending dispatch membership",
        )
        require(
            self.record["fence_phase"] == "CLOSED_DRAINING", "closed readback required"
        )
        digest(proof)
        r = copy.deepcopy(self.record)
        r["fence_phase"] = "CLOSED_READY"
        return self.commit(r)

    def consume(self):
        require(
            self.record["retry"] == "AVAILABLE",
            "one-shot CONSUMED/unavailable; reviewed recovery required",
        )
        r = copy.deepcopy(self.record)
        r["retry"] = "CONSUMED"
        return self.commit(r)

    def reopen(self, window, open_boundary, readback, route_reader):
        """Owner-provided original product boundary; never a host AWS capability."""
        require(window.promotion_window, "actual product close observation required")
        require(
            self.record["fence_phase"] == "CLOSED_READY"
            and not self.record["effect_possible"],
            "pending or non-ready fence",
        )
        routes = route_reader()
        release = self.record["binding"]["release"]
        require(
            release is not None
            and routes
            == {
                name: release[name + "_revision"]
                for name in ("unit", "recovery", "audit")
            },
            "partial/mixed release routes",
        )
        window.guard(lease_expires_at=instant(self.snapshot["lease"]["expires_at"]))
        r = copy.deepcopy(self.record)
        r["generation"] += 1
        r["fence_phase"] = "REOPENING"
        self.commit(r)
        self.open_requested_at = utc(self.lease.clock.wall())
        try:
            open_boundary()
            self.open_responded_at = utc(self.lease.clock.wall())
            readback(self.record)
            observed = self.lease.clock.wall()
            window.guard(lease_expires_at=instant(self.snapshot["lease"]["expires_at"]))
            require(
                observed <= instant(self.record["close_confirmed_at"]) + 1800,
                "reopen outside fence window",
            )
            r = copy.deepcopy(self.record)
            r["fence_phase"] = "OPEN_VERIFIED"
            r["reopen_verified_at"] = utc(observed)
            return self.commit(r)
        except BaseException:
            # An open response may be lost. Do not assert CLOSED or auto-close.
            with contextlib.suppress(Exception):
                self.transition("RECOVERY_REQUIRED")
            raise

    def seal(self, channel_nonce, window, process_reader):
        digest(channel_nonce)
        # Keep the same authority lock throughout observation and all durable evidence.
        with self.lease.locked():
            self.lease._check(self.token, self.snapshot)
            guard = lambda: window.guard(
                lease_expires_at=instant(self.snapshot["lease"]["expires_at"])
            )
            guard()
            require(self.lease.snapshot() == self.snapshot, "CAS seal")
            head = self.snapshot["head"]
            raw_record = read_private(
                self.directory / (head["record_sha256"] + ".json")
            )
            require(
                sha(raw_record) == head["record_sha256"], "record physical readback"
            )
            observed_at = utc(self.lease.clock.wall())
            h = sha(canonical(head))
            processes = closed(
                process_reader(), "checked_processes all_absent_or_send_disabled"
            )
            require(
                processes["all_absent_or_send_disabled"] is True
                or self.record["effect_possible"],
                "physical send boundary",
            )
            pp = {
                "version": 1,
                "head_sha256": h,
                "generation": head["generation"],
                "revision": head["revision"],
                "boundary_pin_sha256": self.record["binding"]["approval"][
                    "contract_sha256"
                ],
                **processes,
                "dispatch_set_sha256": sha(canonical(self.record["dispatches"])),
                "checked_at": observed_at,
                "closed_ready_binding_sha256": getattr(
                    self, "closed_ready_binding_sha256", None
                ),
            }
            durable(
                self.directory / ("process-proof-" + sha(canonical(pp)) + ".json"),
                canonical(pp),
                immutable=True,
            )
            r = self.record
            result = (
                "effect_possible"
                if r["effect_possible"]
                else "effect_confirmed"
                if r["effect_confirmed"]
                else "no_dispatch"
            )
            proof = {
                "version": 1,
                "channel_nonce": channel_nonce,
                "operation_nonce_sha256": r["nonce_sha256"],
                "operation_id": r["operation_id"],
                "binding_sha256": r["binding_sha256"],
                "host_key_fingerprint": r["binding"]["platform"][
                    "host_key_fingerprint"
                ],
                "head_sha256": h,
                "generation": head["generation"],
                "revision": head["revision"],
                "process_proof_sha256": sha(canonical(pp)),
                "result": result,
                "accepted": r["accepted"],
                "effect_confirmed": r["effect_confirmed"],
                "effect_possible": r["effect_possible"],
                "observed_at": observed_at,
                "retry": r["retry"],
            }
            receipt = {
                "version": 1,
                "operation_id": r["operation_id"],
                "binding_sha256": r["binding_sha256"],
                "generation": head["generation"],
                "revision": head["revision"],
                "head_sha256": h,
                "accepted": r["accepted"],
                "effect_confirmed": r["effect_confirmed"],
                "effect_possible": r["effect_possible"],
                "result": {
                    "ACCEPTED": "accepted",
                    "ROLLED_BACK": "rolled_back",
                    "FAILED": "failed",
                }.get(r["state"], "recovery_required"),
                "dispatch_set_sha256": pp["dispatch_set_sha256"],
                "previous_accepted_sha256": r["previous_accepted_sha256"],
                "current_accepted_sha256": head["record_sha256"]
                if r["state"] == "ACCEPTED"
                and r["binding"]["requested_action"] != "validate"
                else r["previous_accepted_sha256"],
                "close_confirmed_at": r["close_confirmed_at"],
                "open_requested_at": getattr(self, "open_requested_at", None),
                "open_responded_at": getattr(self, "open_responded_at", None),
                "reopen_verified_at": r["reopen_verified_at"],
                "observed_at": observed_at,
                "proof_sha256": sha(canonical(proof)),
            }
            e = canonical(receipt)
            guard()
            durable(self.directory / "receipt.json", e, immutable=True)
            start = utc(self.lease.clock.wall())
            require(
                read_private(self.directory / "receipt.json") == e, "receipt readback"
            )
            end = utc(self.lease.clock.wall())
            guard()
            witness = {
                "version": 1,
                "operation_id": r["operation_id"],
                "binding_sha256": r["binding_sha256"],
                "generation": head["generation"],
                "revision": head["revision"],
                "head_sha256": h,
                "receipt_sha256": sha(e),
                "receipt_read_started_at": start,
                "receipt_read_completed_at": end,
                "lease_owner_sha256": sha(self.token),
                "lease_snapshot_sha256": sha(canonical(self.snapshot)),
                "lease_expires_at": self.snapshot["lease"]["expires_at"],
                "channel_nonce": channel_nonce,
                "operation_nonce_sha256": r["nonce_sha256"],
                "result": "verified",
            }
            w = canonical(witness)
            durable(self.directory / "receipt-readback-witness.json", w, immutable=True)
            guard()
            response = canonical(
                {
                    "proof": proof,
                    "receipt": receipt,
                    "receipt_readback_witness": witness,
                    "recovery_decision": window.decision,
                    "recovery_proof_sha256": sha(canonical(window.decision))
                    if window.decision is not None
                    else None,
                }
            )
            require(len(response) <= 65536, "response size")
            index = {
                "version": 1,
                "operation_id": r["operation_id"],
                "binding_sha256": r["binding_sha256"],
                "record_sha256": head["record_sha256"],
                "receipt_sha256": sha(e),
                "receipt_readback_witness_sha256": sha(w),
                "final_response_sha256": sha(response),
            }
            durable(
                self.directory / "receipt-index.json", canonical(index), immutable=True
            )
            require(
                read_private(self.directory / "receipt-readback-witness.json") == w
                and read_private(self.directory / "receipt-index.json")
                == canonical(index),
                "posterior witness",
            )
            guard()
            require(self.lease.snapshot() == self.snapshot, "CAS final response")
            return response


class Watchdog:
    def __init__(self, operation, window):
        self.operation, self.window = operation, window

    def tick(self):
        op = self.operation
        op.check_closed_ready()
        self.window.guard(lease_expires_at=instant(op.snapshot["lease"]["expires_at"]))
        require(op.lease.snapshot() == op.snapshot, "CAS watchdog")
        if self.window.now() - instant(op.snapshot["lease"]["renewed_at"]) >= 60:
            try:
                snapshot = op.lease.renew(op.token, op.snapshot)
                require(op.lease.snapshot() == snapshot, "renewal readback")
                op.snapshot = snapshot
            except BaseException:
                self.window.fail("renewal failed or ambiguous")
                raise


def _group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def stop_group(process):
    deadline = time.monotonic() + 15
    for sig, seconds in ((signal.SIGINT, 10), (signal.SIGTERM, 5), (signal.SIGKILL, 0)):
        if not _group_alive(process.pid):
            break
        os.killpg(process.pid, sig)
        end = min(deadline, time.monotonic() + seconds)
        while time.monotonic() < end:
            process.poll()
            if not _group_alive(process.pid):
                break
            time.sleep(0.05)
    process.wait(timeout=max(0.1, deadline - time.monotonic()))
    require(
        not _group_alive(process.pid) and time.monotonic() <= deadline + 0.1,
        "process group termination unproved",
    )


def supervise(argv, guard, *, timeout=20, env=None, stdin=None):
    """No shell, no retries, each continuation guarded, all descendants killed on failure."""
    require(0 < timeout <= 20 and argv and isinstance(argv, list), "process budget")
    guard()
    # Temporary files avoid pipe deadlocks and never expose child output in errors/logs.
    with (
        tempfile.TemporaryFile() as output,
        tempfile.TemporaryFile() as errors,
        tempfile.TemporaryFile() as input_file,
    ):
        if stdin is not None:
            input_file.write(stdin)
            input_file.seek(0)
        process = subprocess.Popen(
            argv,
            stdin=input_file,
            stdout=output,
            stderr=errors,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
        start = time.monotonic()
        try:
            while process.poll() is None:
                guard()
                require(time.monotonic() - start < timeout, "process request timeout")
                require(
                    output.tell() <= LIMIT and errors.tell() <= LIMIT,
                    "process output bound",
                )
                time.sleep(0.1)
            guard()
            require(process.returncode == 0, "fixed process failed")
            require(not _group_alive(process.pid), "surviving process group")
            output.seek(0)
            result = output.read(LIMIT + 1)
            require(len(result) <= LIMIT, "process output bound")
            return result
        except BaseException:
            stop_group(process)
            raise


RUNTIME_IDENTITIES = ("unit", "recovery", "API")


def runtime_probe_set(probes):
    require(set(probes) == set(RUNTIME_IDENTITIES), "exactly three runtime identities")
    return probes


@contextlib.contextmanager
def credential_directory(root, app):
    require(app in {"cnesdata", "limnopulse"}, "credential tenant")
    directory = Path(tempfile.mkdtemp(prefix=app + "-", dir=private_directory(root)))
    try:
        yield directory
    finally:
        shutil.rmtree(directory)


def write_credentials(directory, credentials, *, now):
    closed(credentials, "AccessKeyId SecretAccessKey SessionToken Expiration")
    require(
        credentials["AccessKeyId"].startswith("ASIA") and credentials["SessionToken"],
        "temporary credentials only",
    )
    expires = instant(credentials["Expiration"])
    require(now + 156 < expires <= now + 3600, "credential lifetime")
    for value in credentials.values():
        require(
            isinstance(value, str) and "\n" not in value and "\r" not in value,
            "credential field",
        )
    raw = (
        "[default]\naws_access_key_id="
        + credentials["AccessKeyId"]
        + "\naws_secret_access_key="
        + credentials["SecretAccessKey"]
        + "\naws_session_token="
        + credentials["SessionToken"]
        + "\n"
    ).encode()
    durable(Path(directory) / "credentials", raw)
    os.chmod(Path(directory) / "credentials", 0o400)
    durable(Path(directory) / "expiration", (credentials["Expiration"] + "\n").encode())
    return expires


def verify_run(run, reference, *, caller=False):
    run_ref(reference)
    require(
        run["id"] == reference["run_id"]
        and run["run_attempt"] == reference["run_attempt"]
        and run["repository"]["full_name"] == reference["repository"]
        and run["head_sha"] == reference["source_sha"] == reference["workflow_sha"]
        and run["path"].split("@")[0] == reference["workflow_path"],
        "live run/source/attempt",
    )
    if caller:
        require(
            run["event"] == "workflow_dispatch"
            and run["head_branch"] == "develop"
            and run["status"] == "in_progress",
            "manual current caller",
        )
    else:
        require(
            run["status"] == "completed" and run["conclusion"] == "success",
            "producer success",
        )


class GitHub:
    def __init__(self, token, clock=None):
        self.token, self.clock = token, clock or Clock()

    def read(self, path, *, raw=False, maximum=2 * 1024**2):
        require(
            path.startswith("repos/")
            and not any(v in path for v in ("..", "://", "\n", "\r")),
            "GitHub fixed host path",
        )

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        request = urllib.request.Request(
            "https://api.github.com/" + path,
            headers={
                **(
                    {"Authorization": "Bearer " + self.token.decode("ascii")}
                    if self.token
                    else {}
                ),
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        start = self.clock.mono()
        try:
            response = urllib.request.build_opener(NoRedirect).open(request, timeout=20)
        except urllib.error.HTTPError as error:
            require(raw and error.code in {301, 302, 303, 307}, "GitHub response")
            target = urllib.parse.urlparse(error.headers.get("Location", ""))
            require(
                target.scheme == "https"
                and target.hostname
                and not target.username
                and not target.password
                and (
                    target.hostname.endswith(".blob.core.windows.net")
                    or target.hostname.endswith(".actions.githubusercontent.com")
                ),
                "artifact redirect",
            )
            response = urllib.request.build_opener(NoRedirect).open(
                target.geturl(), timeout=20
            )
        with response:
            server = parsedate_to_datetime(response.headers["Date"]).timestamp()
            data = response.read(maximum + 1)
        require(
            len(data) <= maximum
            and self.clock.mono() - start <= 20
            and abs(self.clock.wall() - server) <= 30,
            "GitHub bound/time",
        )
        self.clock.observe(server, start, self.clock.mono())
        return data if raw else host_json(data, maximum)


def authenticate_request(request, governance, api, now):
    """Authenticate original owner-selected files, run/attempts and actual source.

    Governance is root-owned on the host or protected by the manual environment
    on the gate. Neither frames nor workflow inputs may select this configuration.
    """
    b = validate_binding(copy.deepcopy(governance["binding"]))
    verify_cost_handoff(governance, now)
    m = validate_envelope(
        request.envelope,
        workflows=set(governance["workflows"]),
        images=set(governance["images"]),
        now=now,
    )
    require(instant(m["expires_at"]) <= now + 86400, "envelope maximum lifetime")
    require(
        m["source_sha"] == b["caller"]["source_sha"]
        and m["requested_action"] == b["requested_action"]
        and m["images"]["api"] == b["api_image"],
        "governed release binding",
    )
    require(
        all(
            m["platform_plan"][key] == b["platform"][key] for key in m["platform_plan"]
        ),
        "platform binding",
    )
    for expiry in b["expires"]:
        require(now + 156 < instant(expiry["expires_at"]), "original input expired")
    original = b["original_bytes"]
    require(
        sha(request.envelope_bytes) == original["envelope_sha256"]
        and sha(canonical(m)) == original["manifest_sha256"]
        and sha(request.archive) == original["archive_sha256"]
        and m["compose_sha256"] == original["compose_sha256"]
        and m["config_sha256"] == original["config_sha256"],
        "original bytes mismatch",
    )
    caller = b["caller"]
    run = api.read(
        f"repos/{REPOSITORY}/actions/runs/{caller['run_id']}/attempts/{caller['run_attempt']}"
    )
    verify_run(run, caller, caller=True)
    path = b["approval"]["repository"] + "/" + b["approval"]["reusable_path"]
    refs = [
        r
        for r in run.get("referenced_workflows", [])
        if r["path"].startswith(path + "@")
    ]
    require(
        len(refs) == 1
        and refs[0]["sha"] == b["approval"]["reusable_sha"]
        and refs[0]["path"] == path + "@" + refs[0]["sha"]
        and "ref" not in refs[0],
        "actual immutable reusable",
    )
    compare = api.read(f"repos/{REPOSITORY}/compare/{caller['source_sha']}...develop")
    require(
        compare["status"] in {"identical", "ahead"}
        and compare["merge_base_commit"]["sha"] == caller["source_sha"],
        "develop containment",
    )
    checks = api.read(
        f"repos/{REPOSITORY}/commits/{caller['source_sha']}/check-runs?per_page=100"
    )
    require(checks["total_count"] <= 100, "check pagination bound")
    for required in governance["required_checks"]:
        found = [
            c
            for c in checks["check_runs"]
            if c["name"] == required["name"] and c["app"]["id"] == required["app_id"]
        ]
        require(
            len(found) == 1
            and found[0]["status"] == "completed"
            and found[0]["conclusion"] == "success"
            and found[0]["head_sha"] == caller["source_sha"],
            "required source check",
        )
    require(governance["required_checks"], "required checks absent")
    for source in governance["source_files"]:
        closed(source, "repository source_sha path sha256")
        require(
            (source["repository"], source["source_sha"])
            in {(p["repository"], p["source_sha"]) for p in b["approval"]["pins"]},
            "source pin",
        )
        require(
            not source["path"].startswith("/")
            and ".." not in source["path"].split("/"),
            "source path",
        )
        obj = api.read(
            f"repos/{source['repository']}/contents/{source['path']}?ref={source['source_sha']}"
        )
        require(
            obj["type"] == "file"
            and obj["size"] <= 1024**2
            and sha(base64.b64decode(obj["content"])) == digest(source["sha256"]),
            "actual source bytes",
        )
    require(governance["source_files"], "source closure absent")
    art = b["ci_artifact"]
    producer = art["producer"]
    ci = request.envelope["ci_evidence"]
    require(
        ci["run_id"] == producer["run_id"]
        and ci["artifact_id"] == art["artifact_id"]
        and ci["artifact_digest"] == art["artifact_digest"],
        "CI artifact binding",
    )
    run = api.read(
        f"repos/{REPOSITORY}/actions/runs/{producer['run_id']}/attempts/{producer['run_attempt']}"
    )
    verify_run(run, producer)
    metadata = api.read(f"repos/{REPOSITORY}/actions/artifacts/{art['artifact_id']}")
    require(
        metadata["id"] == art["artifact_id"]
        and metadata["digest"] == art["artifact_digest"]
        and metadata["expired"] is False
        and metadata["workflow_run"]["id"] == producer["run_id"]
        and metadata["workflow_run"]["head_sha"] == producer["source_sha"]
        and metadata["created_at"] == art["created_at"]
        and metadata["expires_at"] == art["expires_at"]
        and instant(run["run_started_at"])
        < instant(art["created_at"])
        < instant(run["updated_at"]),
        "artifact original attempt",
    )
    raw = api.read(
        f"repos/{REPOSITORY}/actions/artifacts/{art['artifact_id']}/zip",
        raw=True,
        maximum=LIMIT,
    )
    require("sha256:" + sha(raw) == art["artifact_digest"], "artifact byte digest")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        require(len(members) == 1, "artifact exact member set")
        member = members[0]
        require(
            member.filename == governance["archive_member"]
            and "/" not in member.filename
            and member.file_size <= LIMIT
            and not member.is_dir()
            and stat.S_IFMT(member.external_attr >> 16) in {0, stat.S_IFREG},
            "artifact member",
        )
        with archive.open(member) as stream:
            require(
                stream.read(LIMIT + 1) == request.archive,
                "artifact/archive byte identity",
            )
    return b, inspect_archive(request.archive, m, original["archive_sha256"])


def verify_cost_handoff(governance, now):
    """Reuse the integrated EXT1 validator in the explicitly shipped closure."""
    path = Path(__file__).with_name("contract.py")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        require(
            stat.S_ISREG(info.st_mode) and info.st_mode & 0o022 == 0,
            "immutable contract source",
        )
        raw = file.read(262145)
    require(
        len(raw) <= 262144 and sha(raw) == governance["runtime_contract_sha256"],
        "cost validator source pin",
    )
    spec = importlib.util.spec_from_file_location("ext3_owner_contract", path)
    if spec is None or spec.loader is None:
        raise ValueError("cost validator unavailable")
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec"), module.__dict__)  # noqa: S102 -- execute only the exact hash-verified installed EXT1 source
    handoff = closed(governance["cost_handoff"], "cost stage evidence manifest")
    b = governance["binding"]
    require(
        handoff["stage"]["source_sha"] == b["caller"]["source_sha"],
        "cost source binding",
    )
    expiry = next(e for e in b["expires"] if e["name"] == "cost")
    require(
        sha(canonical(handoff["cost"])) == expiry["source_sha256"]
        and handoff["cost"]["expires_at"] == expiry["expires_at"],
        "original cost bytes/expiry",
    )
    module.validate_cost(
        handoff["cost"],
        purpose="phase-a",
        stage=handoff["stage"],
        evidence=handoff["evidence"],
        manifest=handoff["manifest"],
        now=now,
    )


def validate_compose(config, image, port, config_path=None):
    require(
        set(config) <= {"name", "services", "networks"}
        and set(config["services"]) == {"api"},
        "compose service scope",
    )
    service = config["services"]["api"]
    require(
        set(service)
        <= {
            "image",
            "ports",
            "networks",
            "read_only",
            "cap_drop",
            "security_opt",
            "mem_limit",
            "cpus",
            "pids_limit",
            "logging",
            "healthcheck",
            "environment",
            "restart",
            "init",
            "user",
            "labels",
            "name",
            "volumes",
        },
        "compose forbidden capability",
    )
    for mount in service.get("volumes", []):
        require(
            isinstance(mount, dict)
            and set(mount) <= {"type", "source", "target", "read_only", "bind"}
            and mount.get("type") == "bind"
            and mount.get("read_only") is True,
            "readonly own mount",
        )
        own = {
            ("/run/personal-platform/credentials/cnesdata/current", "/run/credentials")
        }
        if config_path is not None:
            own.add((str(config_path), "/run/config/config.json"))
        require((mount.get("source"), mount.get("target")) in own, "cross-tenant mount")
    environment = service.get("environment", {})
    require(isinstance(environment, dict), "normalized environment")
    for name, value in environment.items():
        if name.startswith(("AWS_", "DOCKER_", "SSH_", "LD_", "PYTHON")):
            require(
                name == "AWS_SHARED_CREDENTIALS_FILE"
                and value == "/run/credentials/credentials",
                "runtime environment authority",
            )
    require(
        service["image"] == image
        and service["read_only"] is True
        and service["cap_drop"] == ["ALL"]
        and service["security_opt"] == ["no-new-privileges:true"],
        "compose privilege",
    )
    require(
        set(service["networks"]) == {"cnesdata"}
        and set(config["networks"]) == {"cnesdata"}
        and config["networks"]["cnesdata"] == {"name": "cnesdata"},
        "compose tenant network",
    )
    ports = service["ports"]
    require(
        type(ports) is list
        and len(ports) == 1
        and isinstance(ports[0], dict)
        and set(ports[0]) <= {"host_ip", "published", "target", "protocol", "mode"}
        and ports[0]["host_ip"] == "127.0.0.1"
        and str(ports[0]["published"]) == str(port)
        and ports[0]["target"] == 8000
        and ports[0].get("protocol", "tcp") == "tcp",
        "compose loopback",
    )
    require(
        service["mem_limit"]
        and service["cpus"]
        and 0 < integer(service["pids_limit"], 1) <= 512,
        "resource bounds",
    )
    require(
        service["logging"]
        == {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
        "log bounds",
    )
    require(
        service["healthcheck"].get("test")
        and not service["healthcheck"].get("disable"),
        "health required",
    )
    return config


def accept_response(raw, *, binding, channel_nonce, now, fixed_deadline):
    value = host_json(raw, 65536)
    require(canonical(value) == raw, "canonical response")
    closed(
        value,
        "proof receipt receipt_readback_witness recovery_decision recovery_proof_sha256",
    )
    decision = value["recovery_decision"]
    if decision is None:
        require(value["recovery_proof_sha256"] is None, "no invented recovery proof")
    else:
        validate_recovery_decision(decision)
        require(
            value["recovery_proof_sha256"] == sha(canonical(decision))
            and instant(decision["fixed_deadline"]) <= fixed_deadline
            and now <= instant(decision["recovery_deadline"]),
            "original response recovery decision",
        )
    p, e, w = value["proof"], value["receipt"], value["receipt_readback_witness"]
    closed(
        p,
        "version channel_nonce operation_nonce_sha256 operation_id binding_sha256 host_key_fingerprint head_sha256 generation revision process_proof_sha256 result accepted effect_confirmed effect_possible observed_at retry",
    )
    closed(
        e,
        "version operation_id binding_sha256 generation revision head_sha256 accepted effect_confirmed effect_possible result dispatch_set_sha256 previous_accepted_sha256 current_accepted_sha256 close_confirmed_at open_requested_at open_responded_at reopen_verified_at observed_at proof_sha256",
    )
    closed(
        w,
        "version operation_id binding_sha256 generation revision head_sha256 receipt_sha256 receipt_read_started_at receipt_read_completed_at lease_owner_sha256 lease_snapshot_sha256 lease_expires_at channel_nonce operation_nonce_sha256 result",
    )
    validate_binding(binding)
    opid = sha(b"ext3:host-operation:v1\0" + canonical(binding))
    for obj in (p, e, w):
        require(
            type(obj["version"]) is int
            and obj["version"] == 1
            and obj["operation_id"] == opid
            and obj["binding_sha256"] == sha(canonical(binding))
            and obj["head_sha256"] == p["head_sha256"]
            and obj["revision"] == p["revision"]
            and obj["generation"] == p["generation"],
            "response binding/head",
        )
    require(
        p["channel_nonce"] == w["channel_nonce"] == channel_nonce
        and p["operation_nonce_sha256"]
        == w["operation_nonce_sha256"]
        == binding["operation_nonce_sha256"]
        and p["host_key_fingerprint"] == binding["platform"]["host_key_fingerprint"]
        and w["lease_owner_sha256"] == binding["lease_owner_sha256"],
        "authenticated channel/owner",
    )
    require(
        e["proof_sha256"] == sha(canonical(p))
        and w["receipt_sha256"] == sha(canonical(e))
        and w["result"] == "verified",
        "response commitments",
    )
    require(
        instant(e["observed_at"])
        == instant(p["observed_at"])
        <= instant(w["receipt_read_started_at"])
        <= instant(w["receipt_read_completed_at"])
        <= now
        < instant(w["lease_expires_at"])
        and now <= fixed_deadline,
        "causal arrival/lease",
    )
    require(
        all(now < instant(expiry["expires_at"]) for expiry in binding["expires"]),
        "original expiry at arrival",
    )
    require(
        p["accepted"] is True
        and e["accepted"] is True
        and p["effect_possible"] is False
        and e["effect_possible"] is False
        and e["result"]
        == (
            "rolled_back"
            if binding["requested_action"] == "rollback-previous"
            else "accepted"
        ),
        "host completion",
    )
    if e["close_confirmed_at"] is not None:
        require(
            e["reopen_verified_at"] is not None
            and e["open_requested_at"] is not None
            and instant(e["close_confirmed_at"])
            <= instant(e["open_requested_at"])
            <= instant(e["open_responded_at"])
            <= instant(e["reopen_verified_at"])
            <= instant(e["close_confirmed_at"]) + 1800,
            "actual reopen window",
        )
    return value


def accept_recovery_diagnostic(raw, *, binding, channel_nonce, now):
    """Authenticated read-only result; it cannot turn a prior receipt into new success."""
    value = host_json(raw, 65536)
    require(canonical(value) == raw, "canonical diagnostic")
    closed(
        value,
        "proof receipt receipt_readback_witness recovery_decision recovery_proof_sha256",
    )
    p = closed(
        value["proof"],
        "version channel_nonce operation_nonce_sha256 operation_id binding_sha256 host_key_fingerprint head_sha256 generation revision process_proof_sha256 result accepted effect_confirmed effect_possible observed_at retry",
    )
    require(
        p["version"] == 1
        and p["channel_nonce"] == channel_nonce
        and p["host_key_fingerprint"] == binding["platform"]["host_key_fingerprint"]
        and p["retry"] == "CONSUMED"
        and instant(p["observed_at"]) <= now,
        "original diagnostic channel",
    )
    for key in (
        "operation_nonce_sha256",
        "operation_id",
        "binding_sha256",
        "head_sha256",
        "process_proof_sha256",
    ):
        digest(p[key])
    integer(p["generation"])
    integer(p["revision"])
    decision = value["recovery_decision"]
    if decision is None:
        require(
            value["recovery_proof_sha256"] is None, "no invented diagnostic decision"
        )
    else:
        validate_recovery_decision(decision)
        require(
            value["recovery_proof_sha256"] == sha(canonical(decision))
            and instant(decision["choice_at"]) <= now,
            "original diagnostic recovery hash/time",
        )
    require(
        value["receipt"] is not None or decision is not None,
        "missing original diagnostic",
    )
    if value["receipt"] is not None:
        e, w = value["receipt"], value["receipt_readback_witness"]
        require(
            w is not None
            and e["operation_id"] == w["operation_id"] == p["operation_id"]
            and e["binding_sha256"] == w["binding_sha256"] == p["binding_sha256"]
            and w["receipt_sha256"] == sha(canonical(e)),
            "historical diagnostic commitments",
        )
    else:
        require(
            value["receipt_readback_witness"] is None,
            "witness without original receipt",
        )
    return value


def public_handoff(response, request, binding, now):
    """Closed NON-sensitive projection. Never upload the private SSH response."""
    require(
        request.admission is not None and request.channel_nonce is not None,
        "original handoff context",
    )
    if request.admission is None:
        raise ValueError("ClosedReady handoff missing")
    value = host_json(response, 65536)
    caller = copy.deepcopy(binding["caller"])
    run_ref(caller)
    require(
        caller["repository"] == REPOSITORY
        and caller["ref"] == "refs/heads/develop"
        and caller["workflow_path"] == ".github/workflows/promote-production.yml"
        and caller == request.admission.ready["common"]["caller"],
        "public caller whitelist",
    )
    require(
        sha(request.envelope_bytes) == binding["original_bytes"]["envelope_sha256"],
        "original request commitment",
    )
    if request.diagnostic:
        accept_recovery_diagnostic(
            response, binding=binding, channel_nonce=request.channel_nonce, now=now
        )
        status = "recovery_required"
    else:
        physical = copy.deepcopy(binding)
        physical["operation_nonce_sha256"] = value["proof"]["operation_nonce_sha256"]
        physical["lease_owner_sha256"] = value["receipt_readback_witness"][
            "lease_owner_sha256"
        ]
        physical["initial_generation"] = value["proof"]["generation"]
        accept_response(
            response,
            binding=physical,
            channel_nonce=request.channel_nonce,
            now=now,
            fixed_deadline=instant(request.admission.close["fixed_deadline"]),
        )
        status = value["receipt"]["result"]
    decision = value["recovery_decision"]
    if request.diagnostic:
        require(
            decision is not None, "no original decision; public handoff unavailable"
        )
    if decision is not None:
        validate_recovery_decision(decision)
        imported = request.admission.ready["decision"]
        require(
            decision == imported
            if imported is not None
            else decision["operation_id"] == value["proof"]["operation_id"]
            and decision["binding_sha256"] == value["proof"]["binding_sha256"]
            and decision["generation"] == value["proof"]["generation"],
            "original recovery operation binding",
        )
        # This is the ORIGINAL safe identifier, not a redaction/re-hash of a
        # sensitive decision. An old raw boot UUID must fail closed here.
        digest(decision["clock_boot_id"])
        for key in (
            "version",
            "generation",
            "choice_monotonic_ms",
            "allocated_seconds",
            "convergence_budget_seconds",
            "finalization_budget_seconds",
            "uncertainty_budget_seconds",
        ):
            integer(decision[key])
    require(status in {"accepted", "rolled_back", "recovery_required"}, "public status")
    result = {
        "version": 1,
        "kind": "host-handoff",
        "caller": caller,
        "producer_sha": digest(binding["approval"]["reusable_sha"], 40),
        "closed_ready_sha256": sha(request.admission.original["closed-ready.json"]),
        "original_request_sha256": sha(request.envelope_bytes),
        "status": status,
        "response_sha256": sha(response),
        "proof_sha256": sha(canonical(value["proof"])),
        "receipt_sha256": sha(canonical(value["receipt"]))
        if value["receipt"] is not None
        else None,
        "witness_sha256": sha(canonical(value["receipt_readback_witness"]))
        if value["receipt_readback_witness"] is not None
        else None,
        "operation_id": digest(value["proof"]["operation_id"]),
        "binding_sha256": digest(value["proof"]["binding_sha256"]),
        "generation": integer(value["proof"]["generation"]),
        "recovery_decision": decision,
        "recovery_proof_sha256": value["recovery_proof_sha256"],
    }
    raw = canonical(result)
    require(len(raw) <= 32768, "public handoff bound")
    return raw


class HostDriver:
    """Fixed CnesData commands; configuration selects identities, never executable code."""

    def __init__(self, operation, watchdog, configuration, staged):
        self.op, self.watchdog, self.config, self.staged = (
            operation,
            watchdog,
            configuration,
            staged,
        )
        self.env = {"PATH": "/usr/bin:/bin", "HOME": "/run/personal-platform"}
        self.project = "cnesdata-" + configuration["slot"]
        require(configuration["slot"] in {"blue", "green"}, "deployment slot")
        require(configuration["port"] in {18081, 18082}, "loopback alternate port")
        self.compose = [
            "/usr/bin/docker",
            "compose",
            "--project-name",
            self.project,
            "--file",
            str(staged / "compose.yml"),
        ]
        self.workers = []

    def read(self, argv):
        return supervise(argv, self.watchdog.tick, env=self.env)

    def effect(self, kind, argv, readback):
        self.watchdog.tick()
        ident = self.op.before_send(kind, canonical(argv))
        try:
            self.read(argv)
            proof = readback()
            self.watchdog.tick()
            self.op.outcome(ident, "EFFECT_CONFIRMED", "terminal", sha(proof))
        except BaseException:
            # Even an exited Docker client may have left a daemon request in flight.
            # Preserve membership and never infer cancellation from process death.
            with contextlib.suppress(Exception):
                self.op.outcome(
                    ident,
                    "OUTCOME_UNKNOWN",
                    "unknown",
                    sha(b"unconfirmed fixed command"),
                )
                self.op.transition("RECOVERY_REQUIRED")
            raise

    def health(self, *, tunnel=False):
        url = (
            self.config["tunnel_health_url"]
            if tunnel
            else f"http://127.0.0.1:{self.config['port']}/health/ready"
        )
        parsed = urllib.parse.urlparse(url)
        require(
            (
                tunnel
                and parsed.scheme == "https"
                and parsed.hostname == self.config["public_hostname"]
            )
            or (not tunnel and parsed.hostname == "127.0.0.1"),
            "fixed health destination",
        )
        self.watchdog.tick()
        start = time.monotonic()

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        with urllib.request.build_opener(NoRedirect).open(url, timeout=20) as response:
            require(response.status == 200, "health response")
            raw = response.read(65537)
        require(len(raw) <= 65536 and time.monotonic() - start <= 20, "health bound")
        self.watchdog.tick()
        # Expected authenticated readiness bytes are part of the exact config.
        # Merely receiving HTTP 200 is insufficient to prove auth/AWS readiness.
        require(
            sha(raw) == self.config["readiness_sha256"], "auth/AWS readiness readback"
        )
        return raw

    def image_readback(self):
        raw = self.read(
            [
                "/usr/bin/docker",
                "image",
                "inspect",
                self.op.record["binding"]["api_image"],
            ]
        )
        images = json.loads(raw)
        require(
            len(images) == 1
            and self.op.record["binding"]["api_image"] in images[0]["RepoDigests"]
            and images[0]["Os"] == "linux"
            and images[0]["Architecture"] == "amd64",
            "OCI readback",
        )
        return raw

    def processes(self):
        # The helper is the sole sending boundary, supervised children have reaped
        # process groups, and the lock excludes any new send during sealing.
        require(
            not self.op.record["effect_possible"], "unresolved worker/daemon request"
        )
        return {
            "checked_processes": [process_identity()],
            "all_absent_or_send_disabled": True,
        }

    def run(self):
        normalized = self.read(
            self.compose + ["config", "--format", "json", "--no-interpolate"]
        )
        validate_compose(
            json.loads(normalized),
            self.op.record["binding"]["api_image"],
            self.config["port"],
            self.staged / "config.json",
        )
        self.op.transition("VERIFIED")
        if self.op.record["binding"]["requested_action"] == "validate":
            self.op.transition("ACCEPTED")
            return
        if self.op.record["binding"]["requested_action"] == "rollback-previous":
            binding = self.op.record["binding"]
            prior = find_record(self.op.lease.root, binding["previous_accepted_sha256"])
            require(
                prior["state"] == "ACCEPTED" and prior["effect_possible"] is False,
                "rollback accepted checkpoint",
            )
            require(
                prior["binding"]["api_image"] == binding["api_image"]
                and all(
                    prior["binding"]["original_bytes"][name]
                    == binding["original_bytes"][name]
                    for name in ("compose_sha256", "config_sha256")
                ),
                "rollback exact previous release",
            )
        require(
            self.config["slot"] != self.config["previous_slot"],
            "alternate candidate required",
        )
        previous = read_private(Path("/etc/personal-platform/nginx/active.conf"))
        require(
            sha(previous) == self.config["previous_nginx_sha256"],
            "previous nginx exact checkpoint",
        )
        durable(self.op.directory / "previous-nginx.conf", previous, immutable=True)
        self.op.transition("STAGED")
        self.effect(
            "pull", self.compose + ["pull", "--quiet", "api"], self.image_readback
        )
        self.effect(
            "start-candidate",
            self.compose + ["up", "-d", "--no-build", "--pull", "never", "api"],
            self.health,
        )
        self.op.transition("CANDIDATE_HEALTHY")
        candidate = render_nginx(self.config["port"], self.config["public_hostname"])
        durable(
            self.op.directory / "candidate-nginx.conf",
            b"events {}\nhttp {\n" + candidate + b"\n}\n",
            immutable=True,
        )
        self.read(
            [
                "/usr/sbin/nginx",
                "-t",
                "-c",
                str(self.op.directory / "candidate-nginx.conf"),
            ]
        )
        self.watchdog.tick()
        ident = self.op.before_send("nginx-switch", candidate)
        try:
            durable(Path("/etc/personal-platform/nginx/active.conf"), candidate)
            self.read(["/usr/sbin/nginx", "-t"])
            self.read(["/usr/sbin/nginx", "-s", "reload"])
            self.health(tunnel=True)
            require(
                read_private(Path("/etc/personal-platform/nginx/active.conf"))
                == candidate,
                "nginx switch readback",
            )
            self.op.outcome(ident, "EFFECT_CONFIRMED", "terminal", sha(candidate))
            self.op.transition("SWITCHED")
        except BaseException:
            with contextlib.suppress(Exception):
                self.op.outcome(
                    ident,
                    "OUTCOME_UNKNOWN",
                    "unknown",
                    sha(b"nginx response uncertain"),
                )
                self.op.transition("RECOVERY_REQUIRED")
            raise
        # Stopping the old stack is independently recorded and must read back.
        prior = self.config["previous_slot"]
        require(prior in {"blue", "green"}, "previous slot")
        old_project = "cnesdata-" + prior
        ids = (
            self.read(
                [
                    "/usr/bin/docker",
                    "ps",
                    "-aq",
                    "--filter",
                    "label=com.docker.compose.project=" + old_project,
                ]
            )
            .decode()
            .split()
        )
        require(
            len(ids) <= 1
            and all(re.fullmatch("[0-9a-f]{12,64}", ident) for ident in ids),
            "prior container scope",
        )
        if ids:

            def stopped():
                raw = self.read(["/usr/bin/docker", "inspect", ids[0]])
                require(
                    json.loads(raw)[0]["State"]["Running"] is False,
                    "prior stopped readback",
                )
                return raw

            self.effect(
                "stop-prior",
                ["/usr/bin/docker", "stop", "--time", "10", ids[0]],
                stopped,
            )
        self.op.transition(
            "ROLLED_BACK"
            if self.op.record["binding"]["requested_action"] == "rollback-previous"
            else "ACCEPTED"
        )

    def restore_previous(self):
        """Only known terminal effects can take the exact checkpoint rollback path."""
        require(
            not self.op.record["effect_possible"],
            "uncertain effect cannot auto-rollback",
        )
        previous = read_private(self.op.directory / "previous-nginx.conf")
        require(
            sha(previous) == self.config["previous_nginx_sha256"],
            "rollback exact checkpoint",
        )
        self.watchdog.tick()
        ident = self.op.before_send("restore-previous", previous)
        try:
            durable(Path("/etc/personal-platform/nginx/active.conf"), previous)
            self.read(["/usr/sbin/nginx", "-t"])
            self.read(["/usr/sbin/nginx", "-s", "reload"])
            require(
                read_private(Path("/etc/personal-platform/nginx/active.conf"))
                == previous,
                "rollback physical bytes",
            )
            self.health(tunnel=True)
            self.op.outcome(ident, "EFFECT_CONFIRMED", "terminal", sha(previous))
            self.op.transition("ROLLED_BACK")
        except BaseException:
            with contextlib.suppress(Exception):
                self.op.outcome(
                    ident, "OUTCOME_UNKNOWN", "unknown", sha(b"rollback unconfirmed")
                )
                self.op.transition("RECOVERY_REQUIRED")
            raise


def verify_original_activation(governance, guard):
    """Verify exact retained EXT2 bytes locally; this never grants signing access."""
    binding = governance["binding"]
    if binding["requested_action"] == "validate":
        return
    release = binding["release"]
    raw = read_private(ROOT / "activation.json", 65536)
    signature = read_private(ROOT / "activation-signature.der", 128)
    spki = read_private(ROOT / "activation-public-key.pem", 8192)
    require(
        sha(raw) == release["activation_sha256"]
        and sha(signature) == release["signature_sha256"]
        and sha(spki) == governance["signing_spki_pem_sha256"],
        "original activation/signature/key",
    )
    # Public key bytes are independently pinned by the owner, not transported by
    # the purported signer inside the same untrusted artifact.
    supervise(
        [
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(ROOT / "activation-public-key.pem"),
            "-signature",
            str(ROOT / "activation-signature.der"),
            str(ROOT / "activation.json"),
        ],
        guard,
        env={"PATH": "/usr/bin:/bin"},
    )
    activation = host_json(raw)
    require(
        all(
            activation[key] == release[key]
            for key in (
                "repository",
                "release_id",
                "source_sha",
                "candidate_sha256",
                "binding_sha256",
                "canary_id",
            )
        )
        and activation["revisions"]
        == {name: release[name + "_revision"] for name in ("unit", "recovery", "audit")}
        and activation["phase_a_evidence_digest"] == release["phase_a_evidence_sha256"]
        and activation["ecr_uri"].endswith("@" + release["ecr_image_digest"]),
        "activation candidate/revisions binding",
    )


def verify_runtime_probes(governance, guard):
    """Use the three original temporary credential files; never perform AssumeRole."""
    probes = runtime_probe_set(governance["runtime_probes"])
    for name in RUNTIME_IDENTITIES:
        probe = closed(probes[name], "role_arn credential_path expires_at bucket key")
        path = Path(probe["credential_path"])
        require(
            path.is_absolute()
            and path.parent == Path("/run/personal-platform/probes")
            and path.name == name + ".credentials",
            "original runtime credential carrier",
        )
        read_private(path, 16384)
        require(
            time.time() + 156 < instant(probe["expires_at"]), "probe credential expiry"
        )
        env = {
            "PATH": "/usr/bin:/bin",
            "AWS_SHARED_CREDENTIALS_FILE": str(path),
            "AWS_CONFIG_FILE": "/dev/null",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_MAX_ATTEMPTS": "1",
            "AWS_PAGER": "",
        }
        identity = json.loads(
            supervise(
                ["/usr/bin/aws", "sts", "get-caller-identity", "--output", "json"],
                guard,
                env=env,
            )
        )
        role = probe["role_arn"].split(":role/")[1]
        require(
            identity["Arn"].startswith(
                probe["role_arn"]
                .replace(":iam:", ":sts:")
                .replace(":role/" + role, ":assumed-role/" + role + "/")
            ),
            "actual runtime assume identity",
        )
        missing_object_probe(
            path, probe["bucket"], probe["key"], governance["region"], guard
        )


def missing_object_probe(path, bucket, key, region, guard):
    """A real signed GET, no list grant and no false 403-as-absence result."""
    require(
        re.fullmatch(r"[a-z0-9-]{3,63}", bucket)
        and re.fullmatch(r"[a-z0-9-]+", region)
        and key.startswith("cnesdata/")
        and ".." not in key.split("/"),
        "fixed missing probe destination",
    )
    parser = configparser.ConfigParser()
    parser.read_string(read_private(path, 16384).decode())
    credentials = parser["default"]
    access = credentials["aws_access_key_id"]
    secret = credentials["aws_secret_access_key"]
    token = credentials["aws_session_token"]
    require(access.startswith("ASIA") and token, "temporary original probe session")
    now = dt.datetime.now(dt.UTC)
    timestamp, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    host = f"{bucket}.s3.{region}.amazonaws.com"
    uri = "/" + urllib.parse.quote(key, safe="/~")
    payload = sha(b"")
    headers = {
        "host": host,
        "x-amz-content-sha256": payload,
        "x-amz-date": timestamp,
        "x-amz-security-token": token,
    }
    signed = ";".join(sorted(headers))
    request_bytes = (
        "GET\n"
        + uri
        + "\n\n"
        + "".join(k + ":" + headers[k] + "\n" for k in sorted(headers))
        + "\n"
        + signed
        + "\n"
        + payload
    ).encode()
    scope = f"{day}/{region}/s3/aws4_request"
    string = "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + sha(request_bytes)
    signing = ("AWS4" + secret).encode()
    for component in (day, region, "s3", "aws4_request"):
        signing = hmac.new(signing, component.encode(), hashlib.sha256).digest()
    signature = hmac.new(signing, string.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={signature}"
    )
    guard()
    start = time.monotonic()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    try:
        with urllib.request.build_opener(NoRedirect).open(
            urllib.request.Request("https://" + host + uri, headers=headers), timeout=20
        ):
            raise ValueError("missing probe unexpectedly exists")
    except urllib.error.HTTPError as error:
        body = error.read(65537)
        require(
            error.code == 404
            and len(body) <= 65536
            and ET.fromstring(body).findtext("Code") == "NoSuchKey",
            "typed missing-object result",
        )
    require(time.monotonic() - start <= 20, "probe request budget")
    guard()


def renew_application_credentials(governance):
    """Root-only autonomous renewer; no fourth SSH action and no static fallback."""
    require(os.geteuid() == 0, "root credential renewal")
    c = closed(
        governance["credentials"],
        "application certificate private_key trust_anchor_arn profile_arn role_arn duration_seconds container_id health_url readiness_sha256",
    )
    app = c["application"]
    require(
        app in {"cnesdata", "limnopulse"}
        and 156 < integer(c["duration_seconds"], 157) <= 3600,
        "RA application/lifetime",
    )
    for name in ("certificate", "private_key"):
        path = Path(c[name])
        require(
            path.parent == Path("/etc/personal-platform/ra") / app
            and path.name in {"certificate.pem", "private-key.pem"},
            "isolated RA identity",
        )
        read_private(path, 16384)
    require(
        re.fullmatch("[0-9a-f]{12,64}", c["container_id"]), "fixed credential client"
    )
    clock, lease = Clock(), HostLease()
    identity = process_identity()
    require(identity["invocation_id"] is not None, "systemd renewal invocation")
    owner = {
        "class": "systemd",
        "process": identity,
        "workflow": None,
        "human_session_commitment": None,
        "systemd_invocation": identity["invocation_id"],
    }

    def terminal(prior):
        prior_owner_terminal(lease.root, prior, GitHub(bytearray(), clock), identity)
        return True

    token, snapshot = lease.acquire(owner, sha(canonical(c)), terminal_proof=terminal)
    window = Window(
        clock, host_started_at=clock.wall(), input_deadlines=[clock.wall() + 1800]
    )

    def guard():
        nonlocal snapshot
        try:
            window.guard(lease_expires_at=instant(snapshot["lease"]["expires_at"]))
            require(lease.snapshot() == snapshot, "credential owner CAS")
            if clock.wall() - instant(snapshot["lease"]["renewed_at"]) >= 60:
                snapshot = lease.renew(token, snapshot)
        except BaseException:
            window.fail("credential renewal authority lost")
            raise

    root = private_directory(Path("/run/personal-platform/credentials") / app)
    with credential_directory(root, app) as temporary:
        raw = supervise(
            [
                "/usr/local/bin/aws_signing_helper",
                "credential-process",
                "--certificate",
                c["certificate"],
                "--private-key",
                c["private_key"],
                "--trust-anchor-arn",
                c["trust_anchor_arn"],
                "--profile-arn",
                c["profile_arn"],
                "--role-arn",
                c["role_arn"],
                "--session-duration",
                str(c["duration_seconds"]),
            ],
            guard,
            env={"PATH": "/usr/bin:/bin"},
        )
        credentials = host_json(raw, 16384)
        require(credentials.pop("Version", None) == 1, "RA helper credential format")
        expires = write_credentials(temporary, credentials, now=clock.wall())
        current = private_directory(root / "current")
        previous = (
            read_private(current / "credentials", 16384)
            if (current / "credentials").exists()
            else None
        )
        try:
            guard()
            durable(
                current / "credentials", read_private(temporary / "credentials", 16384)
            )
            os.chmod(current / "credentials", 0o400)
            durable(current / "expiration", read_private(temporary / "expiration", 128))
            # Replacement, not a signal-only refresh, proves the long-lived
            # process cannot retain its prior SDK session in memory.
            before = json.loads(
                supervise(["/usr/bin/docker", "inspect", c["container_id"]], guard)
            )[0]
            require(
                before["Config"]["Labels"]["com.docker.compose.project"].startswith(
                    app + "-"
                ),
                "credential client tenant",
            )
            supervise(
                ["/usr/bin/docker", "restart", "--time", "10", c["container_id"]], guard
            )
            after = json.loads(
                supervise(["/usr/bin/docker", "inspect", c["container_id"]], guard)
            )[0]
            require(
                after["State"]["StartedAt"] != before["State"]["StartedAt"]
                and after["State"]["Running"] is True,
                "old credential client not replaced",
            )
            require(
                c["health_url"].startswith("http://127.0.0.1:"),
                "local credential health",
            )
            guard()
            with urllib.request.urlopen(c["health_url"], timeout=20) as response:
                health = response.read(65537)
            guard()
            require(
                len(health) <= 65536
                and sha(health) == c["readiness_sha256"]
                and clock.wall() + 156 < expires,
                "replacement credential health",
            )
            checkpoint = canonical(
                {
                    "version": 1,
                    "kind": "credential-renewal",
                    "application": app,
                    "owner": owner,
                    "operation_id": snapshot["lease"]["operation_id"],
                    "generation": snapshot["lease"]["generation"],
                    "accepted_record_sha256": accepted_release(
                        lease.root, snapshot["lease"]["checkpoint_sha256"]
                    ),
                    "previous_checkpoint_sha256": snapshot["lease"][
                        "checkpoint_sha256"
                    ],
                    "readiness_sha256": sha(health),
                    "quiescent": True,
                }
            )
            durable(
                private_directory(lease.root / "checkpoints")
                / (sha(checkpoint) + ".json"),
                checkpoint,
                immutable=True,
            )
            lease.release(token, snapshot, sha(checkpoint), lambda: True)
        except BaseException:
            if previous is not None:
                # Preserve the preceding session bytes for reviewed recovery,
                # without claiming the old process or remote outcome is valid.
                durable(root / "previous-credentials", previous)
                os.chmod(root / "previous-credentials", 0o400)
            raise


def render_nginx(port, hostname):
    require(
        port in {18081, 18082} and re.fullmatch(r"[a-z0-9.-]+", hostname),
        "nginx fixed destination",
    )
    return (
        f"server {{ listen 127.0.0.1:8080; server_name {hostname};\n"
        "  set_real_ip_from 127.0.0.1;\n  real_ip_header CF-Connecting-IP;\n"
        "  real_ip_recursive off;\n  server_tokens off;\n"
        f"    location / {{ proxy_pass http://127.0.0.1:{port};\n"
        "      proxy_set_header Host $host;\n      proxy_set_header X-Real-IP $remote_addr;\n"
        "      proxy_set_header X-Forwarded-For $remote_addr;\n"
        '      proxy_set_header CF-Connecting-IP "";\n'
        "      proxy_connect_timeout 5s; proxy_read_timeout 20s;\n"
        "    }\n}\n"
    ).encode()


def load_governance(path=CONFIG):
    require(os.geteuid() == 0, "root boundary required")
    value = host_json(read_private(path))
    require(value.get("enabled") is True, "host delivery disabled")
    validate_binding(value["binding"])
    require(
        value["runtime_sha256"] == sha(Path(__file__).read_bytes()),
        "installed runtime pin",
    )
    return value


def process_absent(identity):
    try:
        current = process_identity(identity["pid"])
    except (FileNotFoundError, ProcessLookupError):
        return True
    return (current["boot_id"], current["start_ticks"]) != (
        identity["boot_id"],
        identity["start_ticks"],
    )


def find_record(root, commitment):
    digest(commitment)
    candidates = list((Path(root) / "cnesdata").iterdir())
    require(len(candidates) <= 1024, "ledger lookup bound")
    found = []
    for directory in candidates:
        require(not directory.is_symlink(), "ledger path symlink")
        if directory.is_dir() and (directory / (commitment + ".json")).exists():
            raw = read_private(directory / (commitment + ".json"))
            require(sha(raw) == commitment, "checkpoint byte digest")
            found.append(host_json(raw))
    require(len(found) == 1, "unique previous checkpoint")
    validate_record(found[0])
    return found[0]


def accepted_release(root, checkpoint):
    """Read the release pointer independently of the current administrative owner."""
    if checkpoint is None:
        return None
    digest(checkpoint)
    administrative = Path(root) / "checkpoints" / (checkpoint + ".json")
    if administrative.exists():
        raw = read_private(administrative)
        require(sha(raw) == checkpoint, "administrative checkpoint digest")
        accepted = host_json(raw)["accepted_record_sha256"]
        if accepted is not None:
            record = find_record(root, accepted)
            require(
                record["state"] in {"ACCEPTED", "ROLLED_BACK"}
                and not record["effect_possible"],
                "accepted release record",
            )
        return accepted
    record = find_record(root, checkpoint)
    require(
        record["state"] in {"ACCEPTED", "ROLLED_BACK"}
        and not record["effect_possible"],
        "accepted release record",
    )
    return (
        record["previous_accepted_sha256"]
        if record["binding"]["requested_action"] == "validate"
        else checkpoint
    )


def prior_owner_terminal(root, lease, api, identity=None):
    """Dispatch terminal proof by owner; TTL alone never conveys authority."""
    require(lease["state"] == "RELEASED", "prior owner not released")
    owner = lease["owner"]
    validate_owner(owner)
    require(process_absent(owner["process"]), "previous owner process still present")
    commitment = lease["recovery_proof_sha256"]
    reviewed_path = Path(root) / "recovery-proofs" / (str(commitment) + ".json")
    if commitment is not None and reviewed_path.exists():
        digest(commitment)
        raw = read_private(reviewed_path)
        require(sha(raw) == commitment, "reviewed session proof digest")
        proof = closed(
            host_json(raw),
            "version prior_authority_sha256 owner owner_token_sha256 generation observation",
        )
        observed = closed(
            proof["observation"],
            "process_absent owner_terminal checkpoint_sha256 proof_sha256",
        )
        require(
            proof["version"] == 1
            and proof["owner"] == owner
            and proof["owner_token_sha256"] == lease["owner_token_sha256"]
            and proof["generation"] == lease["generation"]
            and observed["process_absent"] is True
            and observed["owner_terminal"] is True
            and observed["checkpoint_sha256"] == lease["checkpoint_sha256"],
            "reviewed owner terminal checkpoint",
        )
        digest(proof["prior_authority_sha256"])
        digest(observed["proof_sha256"])
        return accepted_release(root, lease["checkpoint_sha256"])
    if owner["class"] == "workflow":
        record = find_record(root, lease["checkpoint_sha256"])
        require(
            record["binding"]["caller"] == owner["workflow"]
            and record["operation_id"] == lease["operation_id"]
            and record["generation"] == lease["generation"]
            and record["binding"]["lease_owner_sha256"] == lease["owner_token_sha256"]
            and record["state"] in {"ACCEPTED", "ROLLED_BACK"}
            and not record["effect_possible"],
            "workflow terminal checkpoint",
        )
        accepted = (
            record["previous_accepted_sha256"]
            if record["binding"]["requested_action"] == "validate"
            else lease["checkpoint_sha256"]
        )
        ref = owner["workflow"]
        verify_run(
            api.read(
                f"repos/{ref['repository']}/actions/runs/{ref['run_id']}/attempts/{ref['run_attempt']}"
            ),
            ref,
        )
    elif owner["class"] == "systemd":
        checkpoint = digest(lease["checkpoint_sha256"])
        raw = read_private(Path(root) / "checkpoints" / (checkpoint + ".json"))
        require(sha(raw) == checkpoint, "administrative checkpoint digest")
        value = closed(
            host_json(raw),
            "version kind application owner operation_id generation accepted_record_sha256 previous_checkpoint_sha256 readiness_sha256 quiescent",
        )
        require(
            value["version"] == 1
            and value["kind"] == "credential-renewal"
            and value["application"] in {"cnesdata", "limnopulse"}
            and value["owner"] == owner
            and value["operation_id"] == lease["operation_id"]
            and value["generation"] == lease["generation"]
            and value["quiescent"] is True,
            "administrative terminal checkpoint",
        )
        digest(value["readiness_sha256"])
        accepted = accepted_release(root, value["previous_checkpoint_sha256"])
        require(accepted == value["accepted_record_sha256"], "accepted release pointer")
        if identity is not None:
            require(
                identity["invocation_id"] != owner["systemd_invocation"],
                "same invocation",
            )
    else:
        raise ValueError("human session requires reviewed terminal recovery")
    return accepted


def prior_terminal(lease, binding, api):
    accepted = prior_owner_terminal(ROOT, lease, api)
    require(
        accepted == binding["previous_accepted_sha256"], "previous accepted checkpoint"
    )
    return True


def diagnose_once(lease, expected, request, channel_nonce, *, retired=None):
    """Root physical read-only diagnostic; never renew, refresh, render or send."""
    with lease.locked():
        require(lease.snapshot() == expected and expected["head"], "CAS diagnostic")
        head = expected["head"]
        directory = lease.root / "cnesdata" / head["operation_id"]
        record = host_json(read_private(directory / (head["record_sha256"] + ".json")))
        validate_record(record)
        require(
            read_private(directory / "original-envelope") == request.envelope_bytes
            and read_private(directory / "original-archive") == request.archive,
            "retry exact original bytes",
        )
        require(
            record["retry"] == "AVAILABLE",
            "one-shot CONSUMED; reviewed recovery required",
        )
        record["retry"] = "CONSUMED"
        record["revision"] += 1
        raw = canonical(record)
        durable(directory / (sha(raw) + ".json"), raw, immutable=True)
        current = copy.deepcopy(expected)
        current["revision"] += 1
        current["head"]["revision"] = record["revision"]
        current["head"]["record_sha256"] = sha(raw)
        lease._commit(current)
        # Consumption is durable before any response. Missing sealed receipts,
        # active executor or expired authority are diagnostic failure, not rearm.
        if retired is None:
            require(
                process_absent(expected["lease"]["owner"]["process"]),
                "original executor may still send",
            )
        else:
            require(
                record["state"] in {"RECOVERY_REQUIRED", "ROLLED_BACK"}
                and expected["lease"]["owner"]["process"] == process_identity()
                and retired()["all_absent_or_send_disabled"] is True,
                "original executor not retired",
            )
        receipt = (
            host_json(read_private(directory / "receipt.json", 65536))
            if (directory / "receipt.json").exists()
            else None
        )
        witness = (
            host_json(read_private(directory / "receipt-readback-witness.json", 65536))
            if (directory / "receipt-readback-witness.json").exists()
            else None
        )
        recovery_path = directory / "recovery-decision.json"
        decision = (
            validate_recovery_decision(host_json(read_private(recovery_path)))
            if recovery_path.exists()
            else None
        )
        require(
            receipt is not None or decision is not None,
            "original diagnostic unavailable; no new recovery allocation",
        )
        proof = {
            "version": 1,
            "channel_nonce": channel_nonce,
            "operation_nonce_sha256": record["nonce_sha256"],
            "operation_id": record["operation_id"],
            "binding_sha256": record["binding_sha256"],
            "host_key_fingerprint": record["binding"]["platform"][
                "host_key_fingerprint"
            ],
            "head_sha256": sha(canonical(current["head"])),
            "generation": record["generation"],
            "revision": record["revision"],
            "process_proof_sha256": sha(canonical(expected)),
            "result": "effect_possible"
            if record["effect_possible"]
            else "effect_confirmed"
            if record["effect_confirmed"]
            else "no_dispatch",
            "accepted": record["accepted"],
            "effect_confirmed": record["effect_confirmed"],
            "effect_possible": record["effect_possible"],
            "observed_at": utc(lease.clock.wall()),
            "retry": "CONSUMED",
        }
        # Historical E/W retain their original channel nonce and hashes. The gate
        # cannot mistake this diagnostic for accepted evidence of a fresh session.
        return canonical(
            {
                "proof": proof,
                "receipt": receipt,
                "receipt_readback_witness": witness,
                "recovery_decision": decision,
                "recovery_proof_sha256": sha(canonical(decision))
                if decision is not None
                else None,
            }
        )


def host_main():
    require(
        os.environ.get("SSH_ORIGINAL_COMMAND") in ACTIONS, "fixed forced-command action"
    )
    os.umask(0o077)
    governance = load_governance()
    channel_nonce = secrets.token_hex(32)
    sys.stdout.buffer.write((channel_nonce + "\n").encode())
    sys.stdout.buffer.flush()
    request = None
    operation = None
    window = None
    staged = None
    docker_config = None
    driver = None
    response_started = False
    try:
        signal.alarm(20)
        request = read_request(sys.stdin.buffer)
        signal.alarm(0)
        require(
            request.envelope["release_manifest"]["requested_action"]
            == os.environ["SSH_ORIGINAL_COMMAND"],
            "forced action binding",
        )
        clock = Clock()
        # Discovery uses root-retained, originally authenticated facts. Historical
        # read-only responses must not inherit live expiry/stage/OIDC admission.
        lease = HostLease(ROOT, clock)
        current = lease.snapshot()
        if current["head"]:
            directory = ROOT / "cnesdata" / current["head"]["operation_id"]
            prior_raw = read_private(
                directory / (current["head"]["record_sha256"] + ".json")
            )
            require(
                sha(prior_raw) == current["head"]["record_sha256"],
                "original record digest",
            )
            prior = host_json(prior_raw)
            validate_record(prior)
            if prior["binding"]["original_bytes"]["envelope_sha256"] == sha(
                request.envelope_bytes
            ):
                require(
                    read_private(directory / "original-governance")
                    == canonical(governance)
                    and hmac.compare_digest(
                        read_private(directory / "original-token-sha256"),
                        sha(request.token).encode(),
                    )
                    and read_private(directory / "original-archive") == request.archive,
                    "retry original governance/token/archive",
                )
                response = diagnose_once(lease, current, request, channel_nonce)
                sys.stdout.buffer.write(response)
                sys.stdout.buffer.flush()
                return 2
        api = GitHub(request.token, clock)
        b, files = authenticate_request(request, governance, api, clock.wall())
        admission = admit_physical_action(b, governance, api, clock)
        for name in ("platform", "baseline"):
            require(
                sha(read_private(ROOT / ("original-" + name + ".json")))
                == b["original_bytes"][name + "_sha256"],
                "original private handoff",
            )
        owner = {
            "class": "workflow",
            "process": process_identity(),
            "workflow": b["caller"],
            "human_session_commitment": None,
            "systemd_invocation": None,
        }
        token, snapshot = lease.acquire(
            owner,
            sha(request.envelope_bytes),
            terminal_proof=lambda prior: prior_terminal(prior, b, api),
        )
        b["lease_owner_sha256"] = sha(token)
        b["operation_nonce_sha256"] = sha(secrets.token_bytes(32))
        b["initial_generation"] = snapshot["lease"]["generation"]
        operation = Operation(
            lease,
            token,
            snapshot,
            b,
            {
                "envelope": request.envelope_bytes,
                "archive": request.archive,
                "manifest": canonical(request.envelope["release_manifest"]),
                "governance": canonical(governance),
                "token-sha256": sha(request.token).encode(),
            },
        )
        deadlines = [instant(e["expires_at"]) for e in b["expires"]]
        window = (
            admission.window(clock)
            if admission
            else Window(clock, host_started_at=clock.wall(), input_deadlines=deadlines)
        )
        if admission:
            operation.bind_closed_ready(admission)
            if window.decision is not None:
                operation.persist_recovery(window)
        watchdog = Watchdog(operation, window)
        verify_original_activation(governance, watchdog.tick)
        if b["requested_action"] != "validate":
            verify_runtime_probes(governance, watchdog.tick)
        staged = stage_archive(
            private_directory(Path("/run/personal-platform/staging")), files
        )
        driver = HostDriver(operation, watchdog, governance["host"], staged)
        if b["api_image"].startswith("ghcr.io/"):
            docker_config = Path(
                tempfile.mkdtemp(prefix="docker-", dir="/run/personal-platform")
            )
            auth = base64.b64encode(b"x-access-token:" + bytes(request.token)).decode(
                "ascii"
            )
            durable(
                docker_config / "config.json",
                canonical({"auths": {"ghcr.io": {"auth": auth}}}),
            )
            driver.env["DOCKER_CONFIG"] = str(docker_config)
        driver.run()
        response = operation.seal(channel_nonce, window, driver.processes)
        watchdog.tick()
        response_started = True
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
        # Release after sealing cannot give another operation authority without the
        # original GitHub run's authenticated terminal success and exact checkpoint.
        operation.snapshot = lease.release(
            token,
            operation.snapshot,
            operation.snapshot["head"]["record_sha256"],
            lambda: driver.processes()["all_absent_or_send_disabled"],
        )
        if b["requested_action"] != "validate":
            # The active container's read-only config mount must survive helper
            # cleanup; only tokens and unused staging are ephemeral to this call.
            staged = None
        return 0
    except BaseException:
        if operation is not None and window is not None:
            with contextlib.suppress(Exception):
                decision = operation.persist_recovery(window)
                # Known terminal effects may restore only the original physical
                # checkpoint within the ORIGINAL recovery allocation. Uncertain
                # daemon/external effects never trigger a speculative rollback.
                if (
                    driver is not None
                    and operation.record["effect_confirmed"]
                    and not operation.record["effect_possible"]
                    and (operation.directory / "previous-nginx.conf").exists()
                ):
                    window.import_recovery(decision)
                    with contextlib.suppress(Exception):
                        driver.restore_previous()
                operation.transition("RECOVERY_REQUIRED")
                if driver is not None and request is not None and not response_started:
                    driver.processes()  # Prove retirement before spending the one-shot.
                    response = diagnose_once(
                        operation.lease,
                        operation.snapshot,
                        request,
                        channel_nonce,
                        retired=driver.processes,
                    )
                    sys.stdout.buffer.write(response)
                    sys.stdout.buffer.flush()
                    return 2
        raise
    finally:
        signal.alarm(0)
        if request is not None:
            request.erase()
        if staged is not None:
            shutil.rmtree(staged)
        if docker_config is not None:
            shutil.rmtree(docker_config)


def runner_request(governance, token):
    api = GitHub(token)
    b = validate_binding(governance["binding"])
    require(
        governance["runtime_sha256"] == sha(Path(__file__).read_bytes()),
        "approved producer runtime bytes",
    )
    require(
        any(
            s["sha256"] == b["approval"]["governance_sha256"]
            for s in governance["source_files"]
        ),
        "original governance source pin",
    )
    envelope = governance["envelope"]
    raw = api.read(
        f"repos/{REPOSITORY}/actions/artifacts/{b['ci_artifact']['artifact_id']}/zip",
        raw=True,
        maximum=LIMIT,
    )
    require(
        "sha256:" + sha(raw) == b["ci_artifact"]["artifact_digest"],
        "runner artifact digest",
    )
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        require(
            len(members) == 1
            and members[0].filename == governance["archive_member"]
            and members[0].file_size <= LIMIT,
            "runner artifact member",
        )
        with archive.open(members[0]) as file:
            payload = file.read(LIMIT + 1)
    request = Request(envelope, canonical(envelope), payload, token)
    authenticate_request(request, governance, api, time.time())
    request.admission = admit_physical_action(b, governance, api, api.clock)
    inputs = {
        "PLAN_EVIDENCE_ID": b["platform"]["evidence_id"],
        "PLAN_EVIDENCE_DIGEST": b["platform"]["evidence_sha256"],
        "PLAN_RUN_ID": str(governance["plan_run_id"]),
        "ARTIFACT_ID": str(b["ci_artifact"]["artifact_id"]),
        "ARTIFACT_DIGEST": b["ci_artifact"]["artifact_digest"],
    }
    require(
        all(os.environ.get(key) == value for key, value in inputs.items()),
        "five public selectors/original handoff",
    )
    caller = b["caller"]
    require(
        os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REF") == "refs/heads/develop"
        and os.environ.get("GITHUB_SHA") == caller["source_sha"]
        and os.environ.get("GITHUB_RUN_ID") == str(caller["run_id"])
        and os.environ.get("GITHUB_RUN_ATTEMPT") == str(caller["run_attempt"]),
        "actual caller environment",
    )
    return request


def validate_recovery_decision(value: dict):
    closed(
        value,
        "version operation_id binding_sha256 generation choice_at choice_monotonic_ms clock_boot_id fixed_deadline recovery_deadline allocated_seconds convergence_budget_seconds finalization_budget_seconds uncertainty_budget_seconds checkpoint_sha256",
    )
    require(type(value["version"]) is int and value["version"] == 1, "recovery version")
    for key in ("operation_id", "binding_sha256", "checkpoint_sha256"):
        digest(value[key])
    integer(value["generation"])
    integer(value["choice_monotonic_ms"])
    for key in (
        "allocated_seconds",
        "convergence_budget_seconds",
        "finalization_budget_seconds",
        "uncertainty_budget_seconds",
    ):
        integer(value[key])
    opaque(value["clock_boot_id"])
    choice, fixed, deadline = (
        instant(value[k]) for k in ("choice_at", "fixed_deadline", "recovery_deadline")
    )
    require(
        deadline == min(fixed, choice + 420)
        and value["allocated_seconds"] == max(0, int(deadline - choice)),
        "original recovery deadline",
    )
    require(
        value["convergence_budget_seconds"] == 300
        and value["finalization_budget_seconds"]
        == value["uncertainty_budget_seconds"]
        == 60,
        "recovery allocation",
    )
    return value


@dataclasses.dataclass
class ClosedReady:
    original: dict
    artifact: dict
    close: dict
    phase: dict
    ready: dict
    binding: dict
    clock: Clock

    def window(self, clock):
        result = Window(
            clock,
            close_confirmed_at=instant(self.close["close_confirmed_at"]),
            input_deadlines=[
                instant(self.close["fixed_deadline"]),
                *(instant(e["expires_at"]) for e in self.binding["expires"]),
            ],
        )
        result.stage_deadline = instant(self.ready["stage"]["deadline"])
        result.later_seconds = self.ready["stage"]["later_seconds"]
        if self.ready["decision"] is not None:
            result.import_recovery(self.ready["decision"])
            result.stage_deadline = min(
                result.stage_deadline, instant(self.ready["stage"]["deadline"])
            )
        return result


def _closed_members(value: dict, observed, generation):
    members: list[dict] = value["members"]
    proofs: list[dict] = value["proofs"]
    require(type(members) is list and type(proofs) is list, "membership/proofs")
    ids, commitments = [], set()
    for member in members:
        if not isinstance(member, dict):
            raise ValueError("membership object")  # noqa: TRY004 -- protocol rejection has one public exception type
        closed(
            member,
            "dispatch_id request_sha256 generation initial_state execution_ref resolution proof_sha256 observed_at send_disabled_at",
        )
        ids.append(digest(member["dispatch_id"], 16))
        digest(member["request_sha256"])
        commitments.add(digest(member["proof_sha256"]))
        require(
            integer(member["generation"]) < generation, "frozen producer generation"
        )
        require(
            member["initial_state"]
            in {"NOT_SENT", "SEND_PENDING", "ACKNOWLEDGED", "OUTCOME_UNKNOWN"},
            "initial dispatch state",
        )
        require(
            member["resolution"] in {"TERMINAL", "ABSENT_PROVEN", "CANCEL_BEFORE_SEND"},
            "unresolved membership",
        )
        if member["resolution"] == "TERMINAL":
            require(
                isinstance(member["execution_ref"], str)
                and member["execution_ref"].startswith("arn:aws:"),
                "original executor reference",
            )
        else:
            require(member["execution_ref"] is None, "absent executor reference")
            if member["resolution"] == "CANCEL_BEFORE_SEND":
                require(
                    member["initial_state"] == "NOT_SENT",
                    "late dispatch cannot be cancelled before send",
                )
        require(
            instant(member["send_disabled_at"])
            <= instant(member["observed_at"])
            <= observed,
            "late sender/observation",
        )
    require(ids == sorted(set(ids)), "complete sorted membership")
    hashes = []
    for proof in proofs:
        if not isinstance(proof, dict):
            raise ValueError("proof object")  # noqa: TRY004 -- protocol rejection has one public exception type
        closed(proof, "sha256 bytes_base64")
        raw = base64.b64decode(proof["bytes_base64"], validate=True)
        require(
            0 < len(raw) <= 65536 and sha(raw) == digest(proof["sha256"]),
            "original executor proof",
        )
        hashes.append(proof["sha256"])
    require(
        len(hashes) == len(set(hashes)) and set(hashes) == commitments,
        "exact membership proofs",
    )


def validate_closed_ready(files: dict, binding: dict, now):
    close, phase, ready = (
        host_json(files[n], 1024**2)
        for n in ("close-drain.json", "phase-b.json", "closed-ready.json")
    )
    for name, obj in zip(
        ("close-drain", "phase-b", "closed-ready"), (close, phase, ready), strict=True
    ):
        require(
            canonical(obj) == files[name + ".json"]
            and type(obj["version"]) is int
            and obj["version"] == 1
            and obj["kind"] == name,
            "canonical original ClosedReady",
        )
    closed(
        close,
        "version kind common fence close_confirmed_at drain_observed_at frozen_membership_sha256 members proofs permit input_expirations fixed_deadline decision",
    )
    closed(
        phase,
        "version kind common close_drain_sha256 before after plan_sha256 audit_sha256 apply_sha256 routes observed_at",
    )
    closed(
        ready,
        "version kind common close_drain_sha256 phase_b_sha256 fence permit members proofs observed_at exclusion stage decision",
    )
    common = closed(
        close["common"],
        "repository release_id source_sha candidate_sha256 canary_id activation_sha256 promotion_id promotion_generation caller",
    )
    require(
        common == phase["common"] == ready["common"]
        and common["caller"] == binding["caller"],
        "ClosedReady binding/caller",
    )
    release = binding["release"]
    if not isinstance(release, dict):
        raise ValueError("ClosedReady requires original release")  # noqa: TRY004 -- protocol rejection has one public exception type
    require(
        release is not None
        and all(
            common[k] == release[k]
            for k in (
                "repository",
                "release_id",
                "source_sha",
                "candidate_sha256",
                "canary_id",
                "activation_sha256",
            )
        ),
        "ClosedReady release binding",
    )
    opaque(common["promotion_id"])
    generation = integer(common["promotion_generation"], 1)
    require(
        phase["close_drain_sha256"]
        == ready["close_drain_sha256"]
        == sha(files["close-drain.json"])
        and ready["phase_b_sha256"] == sha(files["phase-b.json"]),
        "original evidence links",
    )
    fence = closed(close["fence"], "environment state promotion_id version changed_at")
    require(
        fence == ready["fence"]
        and fence["environment"] == "prod"
        and fence["state"] == "CLOSED"
        and fence["promotion_id"] == common["promotion_id"],
        "same CLOSED fence",
    )
    integer(fence["version"], 1)
    t0, drain, after, observed = (
        instant(v)
        for v in (
            close["close_confirmed_at"],
            close["drain_observed_at"],
            phase["observed_at"],
            ready["observed_at"],
        )
    )
    require(
        instant(fence["changed_at"]) <= t0 <= drain <= after <= observed <= now,
        "original observation ordering",
    )
    require(
        close["permit"] is None
        and ready["permit"] is None
        and close["decision"] is None,
        "original idle permit/decision",
    )
    _closed_members(close, drain, generation)
    _closed_members(ready, observed, generation)
    require(
        close["frozen_membership_sha256"] == sha(canonical(close["members"])),
        "frozen membership commitment",
    )
    identity = lambda m: tuple(
        m[k]
        for k in (
            "dispatch_id",
            "request_sha256",
            "generation",
            "initial_state",
            "execution_ref",
            "resolution",
        )
    )
    require(
        [identity(m) for m in close["members"]]
        == [identity(m) for m in ready["members"]],
        "membership omitted/rebound",
    )
    require(
        all(instant(m["observed_at"]) >= after for m in ready["members"]),
        "membership reobserved after PhaseB",
    )
    exclusion = closed(
        ready["exclusion"], "owner generation membership_sha256 acquired_at observed_at"
    )
    require(
        exclusion["owner"] == binding["caller"]
        and exclusion["generation"] == generation
        and exclusion["membership_sha256"] == sha(canonical(ready["members"]))
        and instant(exclusion["acquired_at"]) <= t0
        and instant(exclusion["observed_at"]) == observed,
        "original continuous exclusion",
    )
    for checkpoint in (phase["before"], phase["after"]):
        closed(checkpoint, "lineage serial state_sha256 object_version")
        opaque(checkpoint["lineage"])
        opaque(checkpoint["object_version"])
        integer(checkpoint["serial"])
        digest(checkpoint["state_sha256"])
    require(
        phase["before"]["lineage"] == phase["after"]["lineage"]
        and phase["before"]["serial"] < phase["after"]["serial"]
        and phase["before"]["object_version"] != phase["after"]["object_version"],
        "real PhaseB checkpoint",
    )
    for key in ("plan_sha256", "audit_sha256", "apply_sha256"):
        digest(phase[key])
    routes = closed(
        phase["routes"],
        "mode state_machine_arn unit_revision recovery_revision audit_revision unit_environment_state_machine_arn recovery_environment_state_machine_arn",
    )
    require(
        routes["mode"] in {"initial", "established"}
        and routes["state_machine_arn"]
        == routes["unit_environment_state_machine_arn"]
        == routes["recovery_environment_state_machine_arn"]
        and routes["unit_revision"] == release["unit_revision"],
        "PhaseB routes/activation",
    )
    require(
        re.fullmatch(
            r"arn:aws:states:[a-z0-9-]+:\d{12}:stateMachine:[A-Za-z0-9_-]+",
            routes["state_machine_arn"],
        ),
        "original state machine ARN",
    )
    for key in ("unit_revision", "recovery_revision", "audit_revision"):
        require(
            isinstance(routes[key], str)
            and re.fullmatch(
                r"arn:aws:ecs:us-east-2:\d{12}:task-definition/[A-Za-z0-9_-]{1,255}:[1-9][0-9]{0,9}",
                routes[key],
            ),
            "original route ARN",
        )
    expirations: list[dict] = close["input_expirations"]
    keys = []
    require(type(expirations) is list and expirations, "original expirations")
    for expiry in expirations:
        closed(expiry, "kind object_sha256 expires_at")
        require(
            expiry["kind"]
            in {
                "envelope",
                "artifact",
                "platform",
                "cost",
                "credential",
                "activation",
                "plan",
            },
            "original expiry kind",
        )
        keys.append((expiry["kind"], digest(expiry["object_sha256"])))
        instant(expiry["expires_at"])
    require(keys == sorted(set(keys)), "unique original expirations")
    require(
        all(
            {
                "kind": e["name"],
                "object_sha256": e["source_sha256"],
                "expires_at": e["expires_at"],
            }
            in expirations
            for e in binding["expires"]
        ),
        "original expiry coverage",
    )
    fixed = min(t0 + 1800, *(instant(e["expires_at"]) for e in expirations))
    require(instant(close["fixed_deadline"]) == fixed, "original fixed deadline")
    stage = closed(ready["stage"], "name admitted_at deadline later_seconds")
    start, deadline = instant(stage["admitted_at"]), instant(stage["deadline"])
    require(start == observed and start < deadline <= fixed, "original stage deadline")
    if binding["requested_action"] == "deploy":
        require(
            ready["decision"] is None
            and stage["name"] == "api"
            and stage["later_seconds"] == 840
            and deadline <= start + 180
            and fixed - start >= 180 + 840 + 420,
            "original API admission budget",
        )
    else:
        decision = validate_recovery_decision(ready["decision"])
        require(
            binding["requested_action"] == "rollback-previous"
            and stage["name"] == "recovery"
            and stage["later_seconds"] == 120
            and instant(decision["fixed_deadline"]) <= fixed
            and instant(decision["choice_at"]) <= start
            and deadline
            <= min(
                instant(decision["recovery_deadline"]),
                instant(decision["choice_at"]) + 300,
            )
            and decision["generation"] == generation
            and decision["checkpoint_sha256"] == sha(canonical(phase["after"])),
            "original recovery stage",
        )
    return close, phase, ready


def admit_physical_action(binding, governance=None, api=None, clock=None):
    """R2a original product evidence, independently checked on runner and host."""
    if binding["requested_action"] == "validate":
        return None
    require(
        governance is not None and api is not None and clock is not None,
        "authenticated original ClosedReady required",
    )
    if governance is None or api is None or clock is None:
        raise ValueError("ClosedReady unavailable")
    validate_binding(binding)
    caller = binding["caller"]
    require(
        caller["workflow_path"] == ".github/workflows/promote-production.yml",
        "original promotion workflow",
    )
    prefix = f"repos/{REPOSITORY}/"
    source_paths = {
        caller["workflow_path"],
        "scripts/promotion/environment_gate.py",
        "scripts/promotion/phase_b.py",
        "scripts/promotion/verify_routes.py",
        "scripts/promotion/promote_api.py",
    }
    for path in source_paths:
        sources = [
            s
            for s in governance["source_files"]
            if s["repository"] == REPOSITORY
            and s["source_sha"] == caller["source_sha"]
            and s["path"] == path
        ]
        require(len(sources) == 1, "ClosedReady source closure")
        obj = api.read(prefix + "contents/" + path + "?ref=" + caller["source_sha"])
        raw = base64.b64decode(obj["content"], validate=False)
        require(
            obj["type"] == "file"
            and obj["size"] == len(raw) <= 1024**2
            and sha(raw) == digest(sources[0]["sha256"]),
            "ClosedReady actual source bytes",
        )
    run_path = (
        prefix + f"actions/runs/{caller['run_id']}/attempts/{caller['run_attempt']}"
    )
    run = api.read(run_path)
    verify_run(run, caller, caller=True)
    jobs = api.read(run_path + "/jobs?per_page=100")
    require(
        integer(jobs["total_count"]) == len(jobs["jobs"]) <= 100,
        "complete attempt jobs",
    )
    found = [j for j in jobs["jobs"] if j["name"] == "closed-ready"]
    require(len(found) == 1, "unique ClosedReady job")
    job = found[0]
    integer(job["id"], 1)
    require(
        job["run_id"] == caller["run_id"]
        and job["run_attempt"] == caller["run_attempt"]
        and job["head_sha"] == caller["source_sha"]
        and job["status"] == "completed"
        and job["conclusion"] == "success",
        "original completed ClosedReady job",
    )
    name = f"cnesdata-closed-ready-{caller['run_id']}-{caller['run_attempt']}"
    listing = api.read(
        prefix + f"actions/runs/{caller['run_id']}/artifacts?name={name}&per_page=100"
    )
    require(
        listing["total_count"] == len(listing["artifacts"]) == 1,
        "unique ClosedReady artifact",
    )
    meta = listing["artifacts"][0]
    ident = integer(meta["id"], 1)
    require(
        api.read(prefix + f"actions/artifacts/{ident}") == meta,
        "original artifact metadata",
    )
    now = clock.upper() if getattr(clock, "time_samples", None) else clock.wall()
    original = meta["workflow_run"]
    require(
        meta["name"] == name
        and meta["expired"] is False
        and instant(meta["expires_at"]) > now
        and original["id"] == caller["run_id"]
        and original["repository_id"]
        == original["head_repository_id"]
        == run["repository"]["id"]
        == run["head_repository"]["id"]
        and original["head_sha"] == caller["source_sha"]
        and original["head_branch"] == "develop"
        and instant(run["run_started_at"])
        <= instant(job["started_at"])
        < instant(meta["created_at"])
        < instant(job["completed_at"])
        <= now,
        "original artifact attempt/interval",
    )
    raw = api.read(
        prefix + f"actions/artifacts/{ident}/zip", raw=True, maximum=2 * 1024**2
    )
    require(
        len(raw) <= 2 * 1024**2 and meta["digest"] == "sha256:" + sha(raw),
        "ClosedReady ZIP digest",
    )
    files = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        require(
            len(members) == 3
            and {m.filename for m in members}
            == {"close-drain.json", "phase-b.json", "closed-ready.json"}
            and sum(m.file_size for m in members) <= 1024**2,
            "ClosedReady exact bounded members",
        )
        for member in members:
            require(
                not member.is_dir()
                and stat.S_IFMT(member.external_attr >> 16) in {0, stat.S_IFREG}
                and not member.flag_bits & 1,
                "ClosedReady regular member",
            )
            with archive.open(member) as stream:
                files[member.filename] = stream.read(1024**2 + 1)
            require(
                len(files[member.filename]) == member.file_size <= 1024**2,
                "ClosedReady member size",
            )
    now = clock.upper() if getattr(clock, "time_samples", None) else clock.wall()
    close, phase, ready = validate_closed_ready(files, binding, now)
    result = ClosedReady(
        files, meta, close, phase, ready, copy.deepcopy(binding), clock
    )
    # No lease exists yet; this admission checks F/stage with a hypothetical ample
    # lease only. The actual independent physical lease is checked before effects.
    result.window(clock).guard(lease_expires_at=now + 300)
    return result


def runner_clients(governance):
    # This dependency exists only in the hosted gate's checksum-locked closure.
    # The physical host path is standard-library-only and never imports boto3.
    import boto3
    from botocore.config import Config

    config = Config(
        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=15
    )
    endpoint = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    host = urllib.parse.urlparse(endpoint).hostname
    require(
        endpoint.startswith("https://")
        and isinstance(host, str)
        and str(host).endswith(".actions.githubusercontent.com"),
        "Actions OIDC endpoint",
    )
    request = urllib.request.Request(
        endpoint + "&audience=sts.amazonaws.com",
        headers={
            "Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        oidc = host_json(response.read(65537), 65536)["value"]
    claim = oidc.split(".")[1]
    claims = host_json(base64.urlsafe_b64decode(claim + "=" * (-len(claim) % 4)), 16384)
    pin = governance["binding"]["approval"]["reusable_sha"]
    subject = (
        "repo:VINIClUS/CnesData:ref:refs/heads/develop:job_workflow_ref:VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-host-deploy-gate.yml@"
        + pin
    )
    require(
        claims["sub"] == subject
        and claims["aud"] == "sts.amazonaws.com"
        and claims["iss"] == "https://token.actions.githubusercontent.com",
        "exact host OIDC claims",
    )
    region = governance["region"]
    sts = boto3.client(
        "sts",
        region_name=region,
        config=config,
        aws_access_key_id="",
        aws_secret_access_key="",
    )
    result = sts.assume_role_with_web_identity(
        RoleArn=governance["runner"]["role_arn"],
        RoleSessionName="cnesdata-host",
        WebIdentityToken=oidc,
        DurationSeconds=900,
    )
    credentials = result["Credentials"]
    kwargs = {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
        "region_name": region,
        "config": config,
    }
    require(
        credentials["Expiration"].timestamp() > time.time() + 156,
        "actual gate credential lifetime",
    )
    return boto3.client("s3", **kwargs), boto3.client("ssm", **kwargs)


def runner_handoff(governance, s3):
    for obj in governance["runner"]["objects"]:
        closed(obj, "bucket key version sha256 size")
        require(0 < obj["size"] <= LIMIT, "private input size")
        result = s3.get_object(
            Bucket=obj["bucket"], Key=obj["key"], VersionId=obj["version"]
        )
        try:
            raw = result["Body"].read(obj["size"] + 1)
        finally:
            result["Body"].close()
        require(
            result["VersionId"] == obj["version"]
            and result["ContentLength"] == obj["size"]
            and len(raw) == obj["size"]
            and sha(raw) == obj["sha256"],
            "original private version/readback",
        )
    platform = governance["binding"]["platform"]
    require(
        any(
            (o["bucket"], o["key"], o["version"], o["sha256"])
            == (
                platform["object_bucket"],
                platform["object_key"],
                platform["object_version"],
                platform["evidence_sha256"],
            )
            for o in governance["runner"]["objects"]
        ),
        "exact original platform carrier",
    )


def ssh_exchange(request, governance, secrets_value):
    runner = governance["runner"]
    hostname = runner["ssh_hostname"]
    require(re.fullmatch("[a-z0-9.-]+", hostname), "fixed SSH hostname")
    known = runner["known_hosts"]
    fields = known.split()
    require(
        len(fields) == 3
        and fields[0] == hostname
        and fields[1] in {"ssh-ed25519", "ecdsa-sha2-nistp256"},
        "exact SSH host key",
    )
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(base64.b64decode(fields[2])).digest()
    ).decode().rstrip("=")
    require(
        fingerprint == governance["binding"]["platform"]["host_key_fingerprint"],
        "host key drift",
    )
    with tempfile.TemporaryDirectory(prefix="cnesdata-host-", dir="/dev/shm") as temp:
        root = private_directory(Path(temp))
        durable(root / "known_hosts", (known + "\n").encode())
        durable(root / "identity", secrets_value["ssh-key"].encode())
        tool = runner["cloudflared"]
        closed(tool, "version sha256")
        require(
            re.fullmatch(r"\d{4}\.\d+\.\d+", tool["version"]),
            "immutable Cloudflare tool version",
        )
        url = (
            "https://github.com/cloudflare/cloudflared/releases/download/"
            + tool["version"]
            + "/cloudflared-linux-amd64"
        )
        with urllib.request.urlopen(url, timeout=20) as response:
            binary = response.read(64 * 1024**2 + 1)
        require(
            len(binary) <= 64 * 1024**2 and sha(binary) == digest(tool["sha256"]),
            "Cloudflare tool checksum",
        )
        durable(root / "cloudflared", binary)
        os.chmod(root / "cloudflared", 0o700)
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(root),
            "TUNNEL_SERVICE_TOKEN_ID": secrets_value["cloudflare-client-id"],
            "TUNNEL_SERVICE_TOKEN_SECRET": secrets_value["cloudflare-client-secret"],
        }
        argv = [
            "/usr/bin/ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(root / "known_hosts"),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ConnectTimeout=20",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "ProxyCommand="
            + str(root / "cloudflared")
            + " access ssh --hostname "
            + hostname,
            "-i",
            str(root / "identity"),
            "personal-cnesdata-deploy@" + hostname,
            request.envelope["release_manifest"]["requested_action"],
        ]
        with tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=errors,
                env=env,
                start_new_session=True,
            )
            try:
                if process.stdout is None or process.stdin is None:
                    raise ValueError("SSH pipe unavailable")
                require(
                    select.select([process.stdout], [], [], 20)[0], "host nonce timeout"
                )
                nonce = process.stdout.readline(66)
                require(
                    len(nonce) == 65 and nonce.endswith(b"\n"), "host nonce framing"
                )
                channel_nonce = digest(nonce[:-1].decode("ascii"))
                request.channel_nonce = channel_nonce
                wire = b"".join(
                    struct.pack(">Q", len(data)) + data
                    for data in (
                        request.envelope_bytes,
                        request.archive,
                        bytes(request.token),
                    )
                )
                fixed = min(
                    instant(e["expires_at"]) for e in governance["binding"]["expires"]
                )
                if request.admission is not None:
                    admitted = request.admission.window(request.admission.clock)
                    admitted.guard(lease_expires_at=time.time() + 300)
                    fixed = min(fixed, admitted.fixed_deadline)
                    # API effects obey their original stage on the host. Receiving
                    # its recovery diagnostic may use the remaining original F;
                    # this transport wait grants no additional effect authority.
                    timeout = fixed - time.time()
                else:
                    timeout = min(1800, fixed - time.time())
                require(timeout >= 36, "SSH original deadline")
                os.set_blocking(process.stdin.fileno(), False)
                os.set_blocking(process.stdout.fileno(), False)
                sent, received = 0, bytearray()
                end = time.monotonic() + timeout
                while True:
                    require(time.monotonic() < end, "host response deadline")
                    readable, writable, _ = select.select(
                        [process.stdout],
                        [process.stdin] if sent < len(wire) else [],
                        [],
                        1,
                    )
                    if writable:
                        sent += os.write(
                            process.stdin.fileno(), wire[sent : sent + 65536]
                        )
                        if sent == len(wire):
                            process.stdin.close()
                    if readable:
                        part = os.read(process.stdout.fileno(), 65537 - len(received))
                        require(
                            len(received) + len(part) <= 65536,
                            "host response byte bound",
                        )
                        if not part:
                            break
                        received.extend(part)
                process.wait(timeout=max(0.1, end - time.monotonic()))
                response = bytes(received)
                require(process.returncode in {0, 2}, "host response/unknown outcome")
                b = copy.deepcopy(governance["binding"])
                parsed = host_json(response, 65536)
                if process.returncode == 2:
                    accept_recovery_diagnostic(
                        response,
                        binding=b,
                        channel_nonce=channel_nonce,
                        now=time.time(),
                    )
                    request.diagnostic = True
                    return response
                # These two random commitments originate at the authenticated host.
                b["operation_nonce_sha256"] = parsed["proof"]["operation_nonce_sha256"]
                b["lease_owner_sha256"] = parsed["receipt_readback_witness"][
                    "lease_owner_sha256"
                ]
                b["initial_generation"] = integer(parsed["proof"]["generation"], 1)
                accept_response(
                    response,
                    binding=b,
                    channel_nonce=channel_nonce,
                    now=time.time(),
                    fixed_deadline=fixed,
                )
                return response
            except BaseException:
                stop_group(process)
                raise


def runner_main(mode):
    token = bytearray(sys.stdin.buffer.read(16385))
    require(
        0 < len(token) <= 16384 and all(32 < c < 127 for c in token),
        "ephemeral token pipe",
    )
    failure_status = "rejected"
    try:
        governance = host_json(os.environ["CNESDATA_HOST_GOVERNANCE"].encode())
        attempt = (
            Path(os.environ["RUNNER_TEMP"]) / "cnesdata-host-attempt.json"
            if mode == "execute"
            else None
        )
        if attempt is not None:
            require(
                not attempt.exists(),
                "original attempt already spent; use retained diagnostic or reviewed recovery",
            )
        request = runner_request(governance, token)
        if mode == "preflight":
            return 0
        # A duplicate invocation must never obtain fresh OIDC/SSM material for
        # the same physical attempt. The original return carries its diagnostic.
        if attempt is None:
            raise ValueError("execution attempt path missing")
        durable(
            attempt,
            canonical(
                {
                    "governance_sha256": sha(canonical(governance)),
                    "original_request_sha256": sha(request.envelope_bytes),
                }
            ),
            immutable=True,
        )
        # Independent repeated preflight above precedes the first OIDC request.
        s3, ssm = runner_clients(governance)
        runner_handoff(governance, s3)
        values = {}
        for name in ("ssh-key", "cloudflare-client-id", "cloudflare-client-secret"):
            arn = governance["runner"]["ssm_parameters"][name]
            require(
                re.fullmatch(
                    r"arn:aws:ssm:[a-z0-9-]+:\d{12}:parameter/cnesdata/deploy/" + name,
                    arn,
                ),
                "CnesData SSM leaf",
            )
            result = ssm.get_parameter(Name=arn, WithDecryption=True)["Parameter"]
            require(
                result["ARN"] == arn and result["Type"] == "SecureString",
                "exact private credential",
            )
            values[name] = result["Value"]
        failure_status = "recovery_required"
        response = ssh_exchange(request, governance, values)
        value = host_json(response, 65536)
        durable(
            Path(os.environ["RUNNER_TEMP"]) / "cnesdata-host-private-response.json",
            response,
            immutable=True,
        )
        if request.admission is not None:
            projected = public_handoff(
                response, request, governance["binding"], time.time()
            )
            directory = private_directory(
                Path(os.environ["RUNNER_TEMP"]) / "cnesdata-host-public"
            )
            durable(directory / "host-handoff.json", projected, immutable=True)
        outputs = {
            "status": "recovery_required" if request.diagnostic else "accepted",
            "host_evidence_version": str(value["proof"]["revision"]),
            "host_evidence_sha256": sha(response),
            "platform_evidence_version": governance["binding"]["platform"][
                "object_version"
            ],
            "platform_evidence_sha256": governance["binding"]["platform"][
                "evidence_sha256"
            ],
        }
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            for name, item in outputs.items():
                require(
                    isinstance(item, str) and "\n" not in item and "\r" not in item,
                    "scalar output",
                )
                output.write(name + "=" + item + "\n")
        return 2 if request.diagnostic else 0
    except Exception:
        if mode == "execute" and os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write("status=" + failure_status + "\n")
        raise
    finally:
        token[:] = b"\0" * len(token)


def main():
    def interrupted(signum, frame):
        raise RuntimeError("bounded helper interrupted")

    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(signum, interrupted)
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", action="store_true")
    group.add_argument("--credential-reload", action="store_true")
    group.add_argument("--runner", choices=("preflight", "execute"))
    args = parser.parse_args()
    try:
        if args.host:
            return host_main()
        if args.credential_reload:
            renew_application_credentials(load_governance())
            return 0
        return runner_main(args.runner)
    except Exception:  # noqa: BLE001 -- secret-bearing exceptions must never reach public logs
        # Secrets, HTTP bodies, commands and inventory never enter public logs.
        print(
            "host-gate: rejected or recovery_required; inspect private owner evidence",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
