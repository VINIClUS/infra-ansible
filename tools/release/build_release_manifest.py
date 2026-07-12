#!/usr/bin/env python3
"""Build the immutable release manifest consumed by the deployment workflow."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Sequence


RUNNER_MINIMUM = "2.335.1"
SEMAPHORE_SHA256 = (
    "209cf89c23710ed74e4568be129690fb5f9599b66f3cdfb55ed6c1a437c94dc9"
)
SEMAPHORE_VERSION = "2.18.25"
_LOWERCASE_SHA = re.compile(r"[0-9a-f]{40}")


def build_manifest(infra_sha: str, target: str | Path) -> None:
    """Write a canonical schema-1 manifest for an exact infrastructure SHA."""
    if _LOWERCASE_SHA.fullmatch(infra_sha) is None:
        raise ValueError("infra SHA must be 40 lowercase hexadecimal characters")

    manifest = {
        "infra_sha": infra_sha,
        "runner_minimum": RUNNER_MINIMUM,
        "schema": 1,
        "semaphore_sha256": SEMAPHORE_SHA256,
        "semaphore_version": SEMAPHORE_VERSION,
    }
    destination = Path(target)
    destination.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("infra_sha", help="validated 40-character infrastructure SHA")
    parser.add_argument(
        "target",
        nargs="?",
        default="release-manifest.json",
        help="output path (default: release-manifest.json)",
    )
    args = parser.parse_args(argv)
    build_manifest(args.infra_sha, args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
