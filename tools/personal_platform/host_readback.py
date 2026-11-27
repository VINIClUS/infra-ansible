#!/usr/bin/env python3
"""Leitura do host por execução: Caddyfile e portas dos slots ouvindo."""

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
    }
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(canonical(value))
    os.chmod(args.output, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
