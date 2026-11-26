#!/usr/bin/env python3
"""Leitura do host por execução: Caddyfile, portas dos slots ouvindo e expiração da sessão."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Sequence

PORTS = (18081, 18082)
LIMIT = 16 * 1024**2
INSTANT = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
DOCUMENT = "run/personal-platform/credentials/cnesdata/current/aws-credentials.json"
DOCUMENT_KEYS = {"Version", "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}


def read_caddyfile(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise ValueError("caddyfile=not_regular")
        data = file.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("caddyfile=too_large")
    return data


def listening(root):
    found = set()
    for name in ("tcp", "tcp6"):
        path = root / "proc" / "net" / name
        lines = path.read_text().splitlines()[1:] if path.is_file() else []
        for fields in (line.split() for line in lines):
            if len(fields) > 3 and fields[3] == "0A":
                port = int(fields[1].rsplit(":", 1)[1], 16)
                found.update({port} & set(PORTS))
    return sorted(found)


def session_expiration(root):
    try:
        value = json.loads((root / DOCUMENT).read_bytes())
    except (OSError, ValueError):
        return None
    valid = (
        type(value) is dict
        and set(value) == DOCUMENT_KEYS
        and type(value["Version"]) is int
        and value["Version"] == 1
        and isinstance(value["AccessKeyId"], str)
        and re.fullmatch(r"ASIA[0-9A-Z]{16}", value["AccessKeyId"]) is not None
        and isinstance(value["Expiration"], str)
        and re.fullmatch(INSTANT, value["Expiration"]) is not None
    )
    return value["Expiration"] if valid else None


def canonical(value):
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return (text + "\n").encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--caddyfile", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--root", default="/")
    parser.add_argument(
        "--observed-at", default=dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    args = parser.parse_args(argv)
    root = Path(args.root)
    if not re.fullmatch(INSTANT, args.observed_at) or not args.caddyfile.startswith("/"):
        print("readback=invalid_arguments", file=sys.stderr)
        return 2
    try:
        caddyfile = read_caddyfile(root / args.caddyfile.lstrip("/"))
    except (OSError, ValueError):
        print("readback=caddyfile_unreadable", file=sys.stderr)
        return 1
    value = {
        "version": 1,
        "observed_at": args.observed_at,
        "caddyfile_b64": base64.b64encode(caddyfile).decode(),
        "listening": listening(root),
        "api_session_expiration": session_expiration(root),
    }
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(canonical(value))
    os.chmod(args.output, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
