#!/usr/bin/env python3
"""Builders do host path da api stage: objeto de plataforma e governança por execução."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import os
import re
import sys
import time
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.cnesdata_delivery import host_gate as g  # noqa: E402

RUNTIME = ROOT / "tools" / "cnesdata_delivery"
PROMOTION = ".github/workflows/promote-production.yml"
SECRET_LIMIT = 48000
INVENTORY_KEYS = (
    "product ssh_hostname ssh_user public_hostname proxy caddyfile_path"
    " caddy_container proxy_network caddy_ip tunnel_health_url"
)
SHARED_HOST_KEYS = (
    "public_hostname",
    "proxy",
    "caddyfile_path",
    "caddy_container",
    "proxy_network",
    "caddy_ip",
    "tunnel_health_url",
)
DEPENDENCY_KEYS = (
    "reusable_sha runtime_sha256 runtime_contract_sha256 requirements_sha256 cloudflared"
)
PREFLIGHT_KEYS = "version observed_at tools hashes checks"
PLAN_KEYS = (
    "version product inventory dependencies host_preflight inventory_sha256"
    " dependencies_sha256 host_preflight_sha256 host_key_fingerprint expires_at"
)
RUNNER_KEYS = "role_arn objects ssm_parameters ssh_hostname known_hosts cloudflared"
SSM_LEAVES = "ssh-key cloudflare-client-id cloudflare-client-secret"
STATIC_KEYS = (
    "enabled runtime_sha256 runtime_contract_sha256 binding envelope workflows images"
    " required_checks source_files archive_member cost_handoff plan_run_id region runner"
    " host credentials runtime_probes signing_spki_pem_sha256"
)


def digest_of(value):
    return g.sha(g.canonical(value))


def fingerprint(known_hosts, hostname):
    fields = known_hosts.split()
    g.require(
        len(fields) == 3
        and fields[0] == hostname
        and fields[1] in {"ssh-ed25519", "ecdsa-sha2-nistp256"},
        "exact SSH host key",
    )
    blob = hashlib.sha256(base64.b64decode(fields[2], validate=True)).digest()
    return "SHA256:" + base64.b64encode(blob).decode().rstrip("=")


def canonical_bytes(raw):
    value = g.host_json(raw)
    g.require(g.canonical(value) == raw, "canonical bytes")
    return value


def build_platform_plan(source, preflight, known_hosts, expires_at):
    """Objeto R30: canônico, com os sub-objetos que os quatro digests cobrem.

    Raises:
        ValueError: entrada fora do conjunto fechado ou bytes não canônicos.
    """
    g.closed(source, "inventory dependencies")
    inventory = g.closed(source["inventory"], INVENTORY_KEYS)
    dependencies = g.closed(source["dependencies"], DEPENDENCY_KEYS)
    g.closed(dependencies["cloudflared"], "version sha256")
    host_preflight = g.closed(canonical_bytes(preflight), PREFLIGHT_KEYS)
    g.instant(expires_at)
    value = {
        "version": 1,
        "product": "cnesdata",
        "inventory": inventory,
        "dependencies": dependencies,
        "host_preflight": host_preflight,
        "inventory_sha256": digest_of(inventory),
        "dependencies_sha256": digest_of(dependencies),
        "host_preflight_sha256": g.sha(preflight),
        "host_key_fingerprint": fingerprint(known_hosts, inventory["ssh_hostname"]),
        "expires_at": expires_at,
    }
    return g.canonical(value)


def read_plan(raw):
    value = g.closed(canonical_bytes(raw), PLAN_KEYS)
    g.require(value["version"] == 1 and value["product"] == "cnesdata", "plan identity")
    g.require(
        value["inventory_sha256"] == digest_of(value["inventory"])
        and value["dependencies_sha256"] == digest_of(value["dependencies"])
        and value["host_preflight_sha256"] == digest_of(value["host_preflight"]),
        "plan digest rules",
    )
    return value


def platform_fields(raw, version):
    """Os seis campos do platform_plan do manifest (host-archive e inputs da promoção)."""
    value = read_plan(raw)
    return {
        "evidence_id": g.opaque(version),
        "evidence_sha256": g.sha(raw),
        "inventory_sha256": value["inventory_sha256"],
        "dependencies_sha256": value["dependencies_sha256"],
        "host_preflight_sha256": value["host_preflight_sha256"],
        "host_key_fingerprint": value["host_key_fingerprint"],
    }


def carrier(runner, raw):
    found = [o for o in runner["objects"] if o["sha256"] == g.sha(raw)]
    g.require(len(found) == 1 and found[0]["size"] == len(raw), "platform carrier")
    return found[0]


def derive_binding(static, raw, run_id, run_attempt):
    b = copy.deepcopy(static["binding"])
    obj, plan = carrier(static["runner"], raw), read_plan(raw)
    b["platform"] = {
        **platform_fields(raw, obj["version"]),
        "object_bucket": obj["bucket"],
        "object_key": obj["key"],
        "object_version": obj["version"],
        "handoff_sha256": digest_of(static["runner"]),
    }
    b["original_bytes"]["platform_sha256"] = g.sha(raw)
    b["original_bytes"]["baseline_sha256"] = plan["host_preflight_sha256"]
    cost, envelope = static["cost_handoff"]["cost"], static["envelope"]
    artifact, credentials = b["ci_artifact"], static["credentials"]
    derived = {
        "platform": (plan["expires_at"], g.sha(raw)),
        "cost": (cost["expires_at"], digest_of(cost)),
        "envelope": (envelope["release_manifest"]["expires_at"], digest_of(envelope)),
        "artifact": (
            artifact["expires_at"],
            artifact["artifact_digest"].removeprefix("sha256:"),
        ),
        "credential": (credentials["trust_deadline"], digest_of(credentials)),
    }
    expires = {e["name"]: e for e in b["expires"]}
    for name, (expires_at, source) in derived.items():
        expires[name] = {"name": name, "expires_at": expires_at, "source_sha256": source}
    b["expires"] = [expires[name] for name in sorted(expires)]
    b["caller"].update(run_id=run_id, run_attempt=run_attempt)
    g.require(b["caller"]["workflow_path"] == PROMOTION, "promotion caller")
    return g.validate_binding(b)


def check_pins(doc, plan):
    deps = plan["dependencies"]
    checkout = {
        "runtime_sha256": g.sha((RUNTIME / "host_gate.py").read_bytes()),
        "runtime_contract_sha256": g.sha((RUNTIME / "contract.py").read_bytes()),
        "requirements_sha256": g.sha((RUNTIME / "runtime-requirements.txt").read_bytes()),
    }
    g.require(
        all(deps[k] == v for k, v in checkout.items())
        and doc["runtime_sha256"] == deps["runtime_sha256"]
        and doc["runtime_contract_sha256"] == deps["runtime_contract_sha256"]
        and doc["binding"]["approval"]["reusable_sha"] == deps["reusable_sha"]
        and doc["runner"]["cloudflared"] == deps["cloudflared"],
        "runtime and dependency pins",
    )


def check_runner(runner):
    g.closed(runner, RUNNER_KEYS)
    for obj in runner["objects"]:
        g.closed(obj, "bucket key version sha256 size")
    parameters = g.closed(runner["ssm_parameters"], SSM_LEAVES)
    for name, arn in parameters.items():
        g.require(
            isinstance(arn, str)
            and re.fullmatch(
                r"arn:aws:ssm:[a-z0-9-]+:\d{12}:parameter/cnesdata/deploy/" + name, arn
            ),
            "CnesData SSM leaf",
        )


def check_host(doc, plan):
    inventory, runner, host = plan["inventory"], doc["runner"], doc["host"]
    check_runner(runner)
    g.require(
        runner["ssh_hostname"] == inventory["ssh_hostname"]
        and fingerprint(runner["known_hosts"], runner["ssh_hostname"])
        == plan["host_key_fingerprint"]
        and all(host[k] == inventory[k] for k in SHARED_HOST_KEYS),
        "host inventory binding",
    )
    g.HostDriver(None, None, host, Path("/"))
    g.runtime_probe_set(doc["runtime_probes"])
    g.require(doc["enabled"] is True, "host delivery enabled")


def check_envelope(doc, now):
    b = doc["binding"]
    m = g.validate_envelope(
        doc["envelope"], workflows=set(doc["workflows"]), images=set(doc["images"]), now=now
    )
    g.require(
        all(m["platform_plan"][k] == b["platform"][k] for k in m["platform_plan"])
        and m["source_sha"] == b["caller"]["source_sha"]
        and m["requested_action"] == b["requested_action"]
        and m["images"]["api"] == b["api_image"],
        "governed release binding",
    )
    g.require(
        any(s["sha256"] == b["approval"]["governance_sha256"] for s in doc["source_files"]),
        "original governance source pin",
    )


def build_governance(static, raw, run_id, run_attempt, now):
    """Documento único: o secret CNESDATA_HOST_GOVERNANCE e o host-gate.json do host.

    Raises:
        ValueError: static incoerente com o objeto de plataforma, pins ou consumidor.
    """
    doc = copy.deepcopy(g.closed(static, STATIC_KEYS))
    plan = read_plan(raw)
    doc["binding"] = derive_binding(static, raw, run_id, run_attempt)
    check_pins(doc, plan)
    check_host(doc, plan)
    check_envelope(doc, now)
    data = g.canonical(doc)
    g.require(len(data) <= SECRET_LIMIT, "secret size")
    return data


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)
    os.chmod(path, 0o600)


def parse(argv):
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("platform-plan")
    for name in ("--source", "--preflight", "--known-hosts", "--expires-at", "--out"):
        plan.add_argument(name, required=True)
    fields = commands.add_parser("platform-fields")
    fields.add_argument("--plan", required=True)
    fields.add_argument("--version", required=True)
    governance = commands.add_parser("governance")
    for name in ("--static", "--plan", "--out"):
        governance.add_argument(name, required=True)
    governance.add_argument("--run-id", type=int, required=True)
    governance.add_argument("--run-attempt", type=int, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse(argv)
    if args.command == "platform-plan":
        known = Path(args.known_hosts).read_text().strip()
        raw = build_platform_plan(
            g.host_json(Path(args.source).read_bytes()),
            Path(args.preflight).read_bytes(),
            known,
            args.expires_at,
        )
        write_private(args.out, raw)
        print(f"sha256={g.sha(raw)}\nsize={len(raw)}")
    elif args.command == "platform-fields":
        fields = platform_fields(Path(args.plan).read_bytes(), args.version)
        sys.stdout.buffer.write(g.canonical(fields))
    else:
        raw = build_governance(
            g.host_json(Path(args.static).read_bytes()),
            Path(args.plan).read_bytes(),
            args.run_id,
            args.run_attempt,
            time.time(),
        )
        write_private(args.out, raw)
        binding = digest_of(g.host_json(raw)["binding"])
        print(f"sha256={g.sha(raw)}\nbinding_sha256={binding}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
