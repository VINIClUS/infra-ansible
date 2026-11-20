"""Owner CLI: governance documents under the write ceilings, cross-checks and the release guard."""
import argparse
import sys
from pathlib import Path

from tools.cnesdata_delivery import contract as c, drift_handoff
from tools.cnesdata_delivery.producers import hmac_key, release_guard

CLI_CEILING = 40960
SECRET_CEILING = 47952


def render(document, ceiling=CLI_CEILING):
    """Args: governance document, ceiling in bytes. Returns: canonical bytes. Raises: ValueError over the ceiling."""
    c.require(ceiling <= SECRET_CEILING, f"write ceiling above the secret ceiling ceiling={ceiling}")
    raw = c.canonical(document)
    c.require(len(raw) <= ceiling, f"governance above the write ceiling size={len(raw)} ceiling={ceiling}")
    return raw


def _cost_stage(document):
    cost, baseline = document.get("cost"), document.get("baseline", {})
    if cost is not None and "cost_context" in baseline:
        c.require(cost["scope"] == baseline["cost_context"]["stage"], "cost scope differs from cost context stage")


def crosscheck(document, commitments):
    """Args: governance document, public commitments. Raises: ValueError on any hash or format mismatch."""
    c.report_key(document)
    value = document["product_inputs"]["shared_outputs"]
    c.require(c.sha(c.canonical(value)) == c.digest(commitments["shared_outputs_sha256"]), "shared outputs hash")
    for pin in document.get("dependencies", []):
        c.digest(pin["content_sha256"])
        c.digest(pin["source_sha"], 40)
    if "drift_handoff" in document:
        drift_handoff.pin(document)
    _cost_stage(document)


def _release_check(args):
    release_guard.check(Path(args.repo), args.x_star, args.k)


def _render(args):
    document = c.loads(Path(args.document).read_bytes())
    commitments = c.loads(Path(args.commitments).read_bytes())
    crosscheck(document, commitments)
    sys.stdout.buffer.write(render(document))


def _key(args):
    custody = hmac_key.Custody()
    key = hmac_key.rotate(custody, custody.lookup()) if args.action == "rotate" else hmac_key.new_key()
    if args.action == "generate":
        custody.store(key)
    custody.deliver(key, args.repo, args.environment)


def parser():
    root = argparse.ArgumentParser(description="CnesData delivery owner CLI")
    commands = root.add_subparsers(dest="command", required=True)
    check = commands.add_parser("release-check")
    for name in ("--repo", "--x-star", "--k"):
        check.add_argument(name, required=True)
    check.set_defaults(run=_release_check)
    document = commands.add_parser("render")
    for name in ("--document", "--commitments"):
        document.add_argument(name, required=True)
    document.set_defaults(run=_render)
    key = commands.add_parser("key")
    key.add_argument("action", choices=("generate", "rotate"))
    key.add_argument("--repo", required=True)
    key.add_argument("--environment", required=True)
    key.set_defaults(run=_key)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        args.run(args)
    except ValueError as error:
        sys.stderr.write(f"refused reason={error}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
