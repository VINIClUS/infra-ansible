#!/usr/bin/env python3
"""Sonda da API no host: sessão Roles Anywhere nova, gravada como INI, só a expiração sai."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence

GOVERNANCE = "etc/personal-platform/host-gate.json"
HELPER = "usr/local/bin/aws_signing_helper"
CARRIER = "run/personal-platform/probes/API.credentials"
IDENTITY = "/etc/personal-platform/ra/cnesdata/"
CREDENTIAL_KEYS = {
    "application", "certificate", "private_key", "trust_anchor_arn", "profile_arn",
    "role_arn", "duration_seconds", "trust_deadline",
}
SESSION_KEYS = {"Version", "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
INSTANT = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
SESSION_SECONDS = 3600
MARGIN = 2400


def identity(root):
    value = json.loads((root / GOVERNANCE).read_bytes())["credentials"]
    valid = (
        type(value) is dict
        and set(value) == CREDENTIAL_KEYS
        and value["application"] == "cnesdata"
        and value["certificate"] == IDENTITY + "certificate.pem"
        and value["private_key"] == IDENTITY + "private-key.pem"
        and type(value["duration_seconds"]) is int
        and value["duration_seconds"] == SESSION_SECONDS
        and all(
            isinstance(value[k], str) and value[k].startswith("arn:aws:")
            for k in ("trust_anchor_arn", "profile_arn", "role_arn")
        )
    )
    if not valid:
        raise ValueError("api_probe=identity")
    return value


def mint(root, c):
    argv = [
        str(root / HELPER), "credential-process", "--certificate", c["certificate"],
        "--private-key", c["private_key"], "--trust-anchor-arn", c["trust_anchor_arn"],
        "--profile-arn", c["profile_arn"], "--role-arn", c["role_arn"],
        "--session-duration", str(SESSION_SECONDS),
    ]
    result = subprocess.run(
        argv, capture_output=True, timeout=20, check=False, env={"PATH": "/usr/bin:/bin"}
    )
    if result.returncode != 0:
        raise ValueError("api_probe=helper_failed")
    return json.loads(result.stdout)


def carrier(value, now):
    if type(value) is not dict or set(value) != SESSION_KEYS:
        raise ValueError("api_probe=session")
    fields = [value[k] for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")]
    valid = (
        type(value["Version"]) is int
        and value["Version"] == 1
        and all(isinstance(v, str) and v and not set(v) & {"\n", "\r"} for v in fields)
        and re.fullmatch(r"ASIA[0-9A-Z]{16}", value["AccessKeyId"]) is not None
        and isinstance(value["Expiration"], str)
        and re.fullmatch(INSTANT, value["Expiration"]) is not None
    )
    if not valid:
        raise ValueError("api_probe=session")
    expires = dt.datetime.strptime(value["Expiration"], "%Y-%m-%dT%H:%M:%SZ")
    if expires.replace(tzinfo=dt.UTC).timestamp() < now + MARGIN:
        raise ValueError("api_probe=short_session")
    ini = (
        "[default]\naws_access_key_id="
        + value["AccessKeyId"]
        + "\naws_secret_access_key="
        + value["SecretAccessKey"]
        + "\naws_session_token="
        + value["SessionToken"]
        + "\n"
    )
    return ini.encode(), value["Expiration"]


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("api_probe=insecure_directory")


def write_exact(path, data):
    private_directory(path.parent)
    temp = path.parent / (".write-" + secrets.token_hex(16))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    info = os.lstat(path)
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise ValueError("api_probe=carrier_readback")


def canonical(value):
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return (text + "\n").encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--root", default="/")
    args = parser.parse_args(argv)
    root = Path(args.root)
    try:
        c = identity(root)
        data, expires_at = carrier(mint(root, c), time.time())
        write_exact(root / CARRIER, data)
    except (OSError, KeyError, ValueError, subprocess.TimeoutExpired) as error:
        reason = str(error) if isinstance(error, ValueError) else ""
        print(reason if reason.startswith("api_probe=") else "api_probe=invalid", file=sys.stderr)
        return 1
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(canonical({"version": 1, "role_arn": c["role_arn"], "expires_at": expires_at}))
    os.chmod(args.output, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
