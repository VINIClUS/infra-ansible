#!/usr/bin/env python3
"""Readback de preflight do host: JSON canônico só com versões, hashes e booleanos."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

USER = "personal-cnesdata-deploy"
TOOLS = {
    "python3": ["python3", "--version"],
    "docker": ["docker", "--version"],
    "compose": ["docker", "compose", "version"],
    "openssl": ["openssl", "version"],
    "aws": ["aws", "--version"],
}
HASHED = {
    "host_gate_py": "usr/local/lib/personal-platform/host_gate.py",
    "contract_py": "usr/local/lib/personal-platform/contract.py",
    "sshd_dispatcher_conf": "etc/ssh/sshd_config.d/60-personal-platform-dispatcher.conf",
    "sudoers_dispatcher": "etc/sudoers.d/personal-platform-dispatcher",
}


def run(argv):
    if shutil.which(argv[0]) is None:
        return None
    result = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
    return result if result.returncode == 0 else None


def version(argv):
    result = run(argv)
    lines = (result.stdout or result.stderr).strip().splitlines() if result else []
    return lines[0].strip()[:200] if lines else None


def file_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def locked(user):
    result = run(["passwd", "-S", user])
    fields = result.stdout.split() if result else []
    return len(fields) > 1 and fields[0] == user and fields[1] == "L"


def readback(root, observed_at, tunnel_unit):
    return {
        "version": 1,
        "observed_at": observed_at,
        "tools": {name: version(argv) for name, argv in TOOLS.items()},
        "hashes": {name: file_digest(root / path) for name, path in HASHED.items()},
        "checks": {
            "dispatcher_user_locked": locked(USER),
            "tunnel_active": run(["systemctl", "is-active", "--quiet", tunnel_unit])
            is not None,
            "aws_cli_pinned": os.access(root / "usr" / "bin" / "aws", os.X_OK),
        },
    }


def canonical(value):
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return (text + "\n").encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--root", default="/")
    parser.add_argument("--tunnel-unit", default="cloudflared")
    parser.add_argument(
        "--observed-at", default=dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    args = parser.parse_args(argv)
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", args.observed_at):
        raise SystemExit("observed_at=invalid")
    data = canonical(readback(Path(args.root), args.observed_at, args.tunnel_unit))
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)
    os.chmod(args.output, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
