#!/usr/bin/env python3
"""Builders do host path da api stage: objeto de plataforma e governança por execução."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import dataclasses
import hashlib
import json
import os
import re
import sys
import tempfile
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
    " host credentials runtime_probes"
)
HOST_STATIC_KEYS = (
    "public_hostname tunnel_health_url readiness_sha256 proxy caddyfile_path"
    " caddy_container proxy_network caddy_ip"
)
READBACK_KEYS = "version observed_at caddyfile_b64 listening"
ACTIVATION_KEYS = (
    "project environment schema_version repository release_id source_sha candidate_sha256"
    " binding_sha256 canary_id derivation revisions ecr_uri phase_a_evidence_digest inputs"
)
SIGNING_KEYS = "key_arn spki_sha256 key_policy_sha256 spki_der_b64"
P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
ECR_URI = r"\d{12}\.dkr\.ecr\.us-east-2\.amazonaws\.com/[a-z0-9_./-]+@sha256:[0-9a-f]{64}"
REVISION = r"arn:aws:ecs:us-east-2:\d{12}:task-definition/[A-Za-z0-9_-]{1,255}:[1-9][0-9]{0,9}"
ROLE = r"arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_-]{1,64}"
SLOTS = {18081: "blue", 18082: "green"}
PROBE_DIRECTORY = "/run/personal-platform/probes"
API_PROBE_FLOOR = 2400
READINESS_BODY = b'{"status":"ready"}'


@dataclasses.dataclass(frozen=True)
class Inputs:
    plan: bytes
    archive: bytes
    readback: bytes
    api_probe: bytes
    signing: dict
    activation: tuple | None = None


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
    check_health_url(inventory)
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


def derive_expires(b, static, raw, plan):
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
    if b["release"] is None:
        expires.pop("activation", None)
    else:
        activation = expires["activation"]["expires_at"]
        derived["activation"] = (activation, b["release"]["activation_sha256"])
    for name, (expires_at, source) in derived.items():
        expires[name] = {"name": name, "expires_at": expires_at, "source_sha256": source}
    return [expires[name] for name in sorted(expires)]


def derive_binding(static, inputs, run_id, run_attempt):
    b, raw = copy.deepcopy(static["binding"]), inputs.plan
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
    deploy = b["requested_action"] != "validate"
    g.require(deploy == (inputs.activation is not None), "activation input")
    b["release"] = derive_release(*inputs.activation) if deploy else None
    b["expires"] = derive_expires(b, static, raw, plan)
    b["caller"].update(run_id=run_id, run_attempt=run_attempt)
    g.require(b["caller"]["workflow_path"] == PROMOTION, "promotion caller")
    return g.validate_binding(b)


def signing_pem(signing):
    """PEM determinístico do SPKI P-256 pinado no handoff privado de assinatura.

    Raises:
        ValueError: handoff fora do conjunto fechado ou SPKI fora do pin.
    """
    value = g.closed(signing, SIGNING_KEYS)
    encoded = value["spki_der_b64"]
    try:
        der = base64.b64decode(encoded, validate=True)
    except (binascii.Error, TypeError, ValueError):
        raise ValueError("signing spki encoding") from None
    g.require(
        len(encoded) == 124
        and base64.b64encode(der).decode() == encoded
        and len(der) == 91
        and der.startswith(P256_PREFIX)
        and g.sha(der) == g.digest(value["spki_sha256"]),
        "signing spki pin",
    )
    body = base64.b64encode(der)
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(lines) + b"\n-----END PUBLIC KEY-----\n"


def derive_release(raw, signature):
    """Os 13 campos de binding.release a partir dos bytes originais da ativação EXT2.

    Raises:
        ValueError: ativação fora do schema ou assinatura fora do limite do host.
    """
    g.require(len(raw) <= 65536 and 0 < len(signature) <= 128, "activation bounds")
    value = g.closed(g.host_json(raw), ACTIVATION_KEYS)
    revisions = g.closed(value["revisions"], "unit recovery audit")
    g.require(
        value["project"] == "cnesdata"
        and value["environment"] == "prod"
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["derivation"] == "cnesdata:prod:canary:v1"
        and isinstance(value["ecr_uri"], str)
        and re.fullmatch(ECR_URI, value["ecr_uri"])
        and all(isinstance(v, str) and re.fullmatch(REVISION, v) for v in revisions.values()),
        "activation schema",
    )
    keys = ("repository", "release_id", "source_sha", "candidate_sha256", "canary_id")
    return {
        **{key: value[key] for key in keys},
        "binding_sha256": value["binding_sha256"],
        "activation_sha256": g.sha(raw),
        "signature_sha256": g.sha(signature),
        "phase_a_evidence_sha256": value["phase_a_evidence_digest"],
        "ecr_image_digest": value["ecr_uri"].rsplit("@", 1)[1],
        **{name + "_revision": revisions[name] for name in ("unit", "recovery", "audit")},
    }


def check_activation(governance, raw, signature, pem):
    """Roda o verify_original_activation real sobre cópias privadas, antes da janela."""
    with tempfile.TemporaryDirectory(prefix="activation-") as temp:
        root = Path(temp)
        for name, data in (
            ("activation.json", raw),
            ("activation-signature.der", signature),
            ("activation-public-key.pem", pem),
        ):
            write_private(root / name, data)
        saved, g.ROOT = g.ROOT, root
        try:
            g.verify_original_activation(governance, lambda: None)
        finally:
            g.ROOT = saved


def read_readback(raw):
    """Documento da leitura do host: canônico, fechado e com o Caddyfile decodificado.

    Raises:
        ValueError: bytes não canônicos ou campo fora do contrato.
    """
    value = g.closed(canonical_bytes(raw), READBACK_KEYS)
    listening = value["listening"]
    g.require(
        value["version"] == 1
        and type(listening) is list
        and all(type(p) is int and p in SLOTS for p in listening)
        and listening == sorted(set(listening)),
        "readback fields",
    )
    g.instant(value["observed_at"])
    try:
        text = base64.b64decode(value["caddyfile_b64"], validate=True)
    except (binascii.Error, TypeError, ValueError):
        raise ValueError("readback caddyfile") from None
    g.require(base64.b64encode(text).decode() == value["caddyfile_b64"], "readback caddyfile")
    return {**value, "caddyfile": text}


def live_upstream(text, hostname):
    try:
        decoded = text.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("caddyfile encoding") from None
    blocks, code = g.scan_caddy(decoded)
    spans = [(opened, end) for head, opened, end in blocks if head == hostname]
    g.require(len(spans) == 1, "caddy block")
    token = re.compile(r"(?<![\w.:-])(?:" + g.CADDY_UPSTREAM.pattern + r")(?![\w.:-])")
    found = [m.group(0) for m in token.finditer(code, spans[0][0] + 1, spans[0][1])]
    g.require(len(found) == 1, "caddy upstream token")
    return found[0]


def live_slot(upstream):
    return next((s for s in SLOTS.values() if upstream == f"cnesdata-{s}-api-1:8000"), None)


def suggested_port(seen, hostname):
    live = live_slot(live_upstream(seen["caddyfile"], hostname))
    free = [p for p, s in sorted(SLOTS.items()) if s != live and p not in seen["listening"]]
    g.require(len(free) > 0, "free candidate port")
    return live or "legacy", free[0]


def check_health_url(values):
    expected = "https://" + values["public_hostname"] + "/health/ready"
    g.require(values["tunnel_health_url"] == expected, "tunnel health url")


def derive_host(static_host, seen, port):
    """Fragmento host do HostDriver: estático + slot, porta e checkpoint do Caddy lidos.

    Raises:
        ValueError: slot vivo, porta ocupada, Caddyfile ambíguo ou static fora do contrato.
    """
    host = copy.deepcopy(g.closed(static_host, HOST_STATIC_KEYS))
    g.require(host["readiness_sha256"] == g.sha(READINESS_BODY), "readiness digest")
    check_health_url(host)
    g.require(host["proxy"] == "caddy", "caddy proxy")
    g.require(port in SLOTS and port not in seen["listening"], "candidate port")
    upstream = live_upstream(seen["caddyfile"], host["public_hostname"])
    slot, live = SLOTS[port], live_slot(upstream)
    g.require(slot != live, "candidate slot live")
    ports = {name: number for number, name in SLOTS.items()}
    g.require(live is None or ports[live] in seen["listening"], "live slot port listening")
    g.render_caddy(
        seen["caddyfile"], host["public_hostname"], upstream, f"cnesdata-{slot}-api-1:8000"
    )
    other = next(s for s in SLOTS.values() if s != slot)
    host.update(
        slot=slot,
        port=port,
        previous_slot=live or other,
        previous_caddyfile_sha256=g.sha(seen["caddyfile"]),
        previous_caddy_upstream=upstream,
    )
    return host


def archive_port(archive, manifest, expected):
    """Porta publicada no compose do archive, conferida pelo validate_compose real.

    Raises:
        ValueError: archive fora do digest, compose fora do contrato ou porta fora dos slots.
    """
    files = g.inspect_archive(archive, manifest, expected)
    compose = json.loads(files["compose.yml"])
    port = compose["services"]["api"]["ports"][0]["published"]
    g.require(type(port) is int and port in SLOTS, "candidate port")
    g.validate_compose(compose, manifest["images"]["api"], port, "./config.json")
    return port


def assumed_prefix(role_arn):
    g.require(isinstance(role_arn, str) and re.fullmatch(ROLE, role_arn), "probe role")
    account, role = role_arn.split("::", 1)[1].split(":role/")
    return f"arn:aws:sts::{account}:assumed-role/{role}/"


def read_api_probe(raw):
    """Sessão da API cunhada no host: só role e expiração, canônicas e fechadas.

    Raises:
        ValueError: bytes não canônicos ou campo fora do contrato.
    """
    value = g.closed(canonical_bytes(raw), "version role_arn expires_at")
    g.require(value["version"] == 1, "API probe version")
    assumed_prefix(value["role_arn"])
    g.instant(value["expires_at"])
    return value


def derive_probes(static_probes, minted, renewer_role, now):
    """runtime_probes da API: carrier fixo, destino estático e expiração da sessão cunhada.

    Args:
        renewer_role: role_arn de credentials, a identidade da sessão da sonda API.
    Raises:
        ValueError: probe fora do conjunto fechado ou sessão sem vida suficiente.
    """
    g.runtime_probe_set(static_probes)
    g.require(static_probes["API"]["role_arn"] == renewer_role, "API probe renewer role")
    api = minted["expires_at"]
    g.require(minted["role_arn"] == renewer_role, "API probe minted role")
    g.require(g.instant(api) >= now + API_PROBE_FLOOR, "API probe session")
    result = {}
    for name in g.RUNTIME_IDENTITIES:
        probe = g.closed(static_probes[name], "role_arn bucket key")
        key = probe["key"]
        g.require(
            re.fullmatch(r"[a-z0-9-]{3,63}", str(probe["bucket"]))
            and isinstance(key, str)
            and key.startswith("cnesdata/")
            and ".." not in key.split("/"),
            "probe destination",
        )
        assumed_prefix(probe["role_arn"])
        result[name] = {
            **probe,
            "credential_path": f"{PROBE_DIRECTORY}/{name}.credentials",
            "expires_at": api,
        }
    return result


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
    return m


def build_governance(static, inputs, run_id, run_attempt, now):
    """Documento único: o secret CNESDATA_HOST_GOVERNANCE e o host-gate.json do host.

    Raises:
        ValueError: static ou entrada por execução incoerente com o consumidor real.
    """
    doc = copy.deepcopy(g.closed(static, STATIC_KEYS))
    plan = read_plan(inputs.plan)
    doc["binding"] = derive_binding(static, inputs, run_id, run_attempt)
    manifest = check_envelope(doc, now)
    original = doc["binding"]["original_bytes"]
    port = archive_port(inputs.archive, manifest, original["archive_sha256"])
    seen = read_readback(inputs.readback)
    doc["host"] = derive_host(static["host"], seen, port)
    minted = read_api_probe(inputs.api_probe)
    doc["runtime_probes"] = derive_probes(
        static["runtime_probes"], minted, static["credentials"]["role_arn"], now
    )
    pem = signing_pem(inputs.signing)
    doc["signing_spki_pem_sha256"] = g.sha(pem)
    if inputs.activation is not None:
        check_activation(doc, *inputs.activation, pem)
    check_pins(doc, plan)
    check_host(doc, plan)
    data = g.canonical(doc)
    g.require(len(data) <= SECRET_LIMIT, "secret size")
    return data


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)
    os.chmod(path, 0o600)


GOVERNANCE_INPUTS = (
    "--static", "--plan", "--archive", "--readback", "--api-probe", "--signing", "--out",
    "--handoff-dir",
)


def parse(argv):
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("platform-plan")
    for name in ("--source", "--preflight", "--known-hosts", "--expires-at", "--out"):
        plan.add_argument(name, required=True)
    fields = commands.add_parser("platform-fields")
    fields.add_argument("--plan", required=True)
    fields.add_argument("--version", required=True)
    live = commands.add_parser("live-slot")
    live.add_argument("--readback", required=True)
    live.add_argument("--hostname", required=True)
    governance = commands.add_parser("governance")
    for name in GOVERNANCE_INPUTS:
        governance.add_argument(name, required=True)
    governance.add_argument("--activation")
    governance.add_argument("--signature")
    governance.add_argument("--run-id", type=int, required=True)
    governance.add_argument("--run-attempt", type=int, required=True)
    args = parser.parse_args(argv)
    if args.command == "governance" and (args.activation is None) != (args.signature is None):
        parser.error("activation and signature go together")
    return args


def read_inputs(args):
    activation = None
    if args.activation is not None:
        activation = (Path(args.activation).read_bytes(), Path(args.signature).read_bytes())
    return Inputs(
        plan=Path(args.plan).read_bytes(),
        archive=Path(args.archive).read_bytes(),
        readback=Path(args.readback).read_bytes(),
        api_probe=Path(args.api_probe).read_bytes(),
        signing=g.host_json(Path(args.signing).read_bytes()),
        activation=activation,
    )


def originals(raw):
    baseline = g.canonical(read_plan(raw)["host_preflight"])
    return {"original-platform": raw, "original-baseline": baseline}


def write_handoffs(args, inputs):
    directory = Path(os.path.abspath(args.handoff_dir))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    files = {
        "host-gate": Path(os.path.abspath(args.out)),
        "activation-public-key": directory / "activation-public-key.pem",
    }
    write_private(files["activation-public-key"], signing_pem(inputs.signing))
    for name, data in originals(inputs.plan).items():
        files[name] = directory / (name + ".json")
        write_private(files[name], data)
    if inputs.activation is not None:
        files["activation"] = Path(os.path.abspath(args.activation))
        files["activation-signature"] = Path(os.path.abspath(args.signature))
    entries = {
        name: {"src": str(path), "sha256": g.sha(path.read_bytes())}
        for name, path in files.items()
    }
    values = {"personal_platform_dispatcher_handoffs": entries}
    write_private(directory / "handoffs.json", json.dumps(values, sort_keys=True).encode())


def run_governance(args):
    inputs, now = read_inputs(args), time.time()
    static = g.host_json(Path(args.static).read_bytes())
    raw = build_governance(static, inputs, args.run_id, args.run_attempt, now)
    write_private(args.out, raw)
    write_handoffs(args, inputs)
    value = g.host_json(raw)
    binding = digest_of(value["binding"])
    valid = min(p["expires_at"] for p in value["runtime_probes"].values())
    print(f"sha256={g.sha(raw)}\nbinding_sha256={binding}\nprobes_valid_until={valid}")


def run_platform_plan(args):
    known = Path(args.known_hosts).read_text().strip()
    raw = build_platform_plan(
        g.host_json(Path(args.source).read_bytes()),
        Path(args.preflight).read_bytes(),
        known,
        args.expires_at,
    )
    write_private(args.out, raw)
    print(f"sha256={g.sha(raw)}\nsize={len(raw)}")


def run_platform_fields(args):
    fields = platform_fields(Path(args.plan).read_bytes(), args.version)
    sys.stdout.buffer.write(g.canonical(fields))


def run_live_slot(args):
    seen = read_readback(Path(args.readback).read_bytes())
    live, port = suggested_port(seen, args.hostname)
    print(f"live={live} port={port}")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse(argv)
    {
        "platform-plan": run_platform_plan,
        "platform-fields": run_platform_fields,
        "live-slot": run_live_slot,
        "governance": run_governance,
    }[args.command](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
