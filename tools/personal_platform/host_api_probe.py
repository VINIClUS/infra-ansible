#!/usr/bin/env python3
"""Sonda da API no host: INI temporário derivado da sessão publicada pelo renewer."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import secrets
import stat
import sys
import time
from pathlib import Path
from typing import Sequence

DOCUMENT = "run/personal-platform/credentials/cnesdata/current/aws-credentials.json"
DOCUMENT_KEYS = {"Version", "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
OUTPUT = "/run/personal-platform/probes/API.credentials"
MARGIN = 600


def session(root, now):
    value = json.loads((root / DOCUMENT).read_bytes())
    if type(value) is not dict or set(value) != DOCUMENT_KEYS:
        raise ValueError("api_probe=invalid_session")
    fields = [value[k] for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")]
    valid = (
        type(value["Version"]) is int
        and value["Version"] == 1
        and all(isinstance(v, str) and v and not set(v) & {"\n", "\r"} for v in fields)
        and re.fullmatch(r"ASIA[0-9A-Z]{16}", value["AccessKeyId"]) is not None
        and isinstance(value["Expiration"], str)
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["Expiration"]) is not None
    )
    if not valid:
        raise ValueError("api_probe=invalid_session")
    expires = dt.datetime.strptime(value["Expiration"], "%Y-%m-%dT%H:%M:%SZ")
    if expires.replace(tzinfo=dt.UTC).timestamp() < now + MARGIN:
        raise ValueError("api_probe=short_session")
    return (
        "[default]\naws_access_key_id="
        + value["AccessKeyId"]
        + "\naws_secret_access_key="
        + value["SecretAccessKey"]
        + "\naws_session_token="
        + value["SessionToken"]
        + "\n"
    ).encode()


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("api_probe=insecure_directory")


def write_exact(path, data):
    private_directory(path.parent)
    temp = path.parent / (".write-" + secrets.token_hex(16))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(temp, flags, 0o600)
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT)
    parser.add_argument("--root", default="/")
    args = parser.parse_args(argv)
    root = Path(args.root)
    if args.output != OUTPUT:
        print("api_probe=output", file=sys.stderr)
        return 2
    try:
        data = session(root, time.time())
        write_exact(root / args.output.lstrip("/"), data)
    except (OSError, ValueError) as error:
        reason = str(error) if isinstance(error, ValueError) else "api_probe=unreadable"
        print(reason if reason.startswith("api_probe=") else "api_probe=invalid", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
