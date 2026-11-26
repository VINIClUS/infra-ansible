"""Host path da api stage: chave de deploy, handoffs privados, preflight e builders.

Fixtures sintéticas; nenhuma é evidência operacional do host.
"""

import base64
import copy
import importlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ROLE = ROOT / "roles" / "personal_platform_dispatcher"
DELIVERY = ROOT / "playbooks" / "personal-platform-delivery.yml"
PREFLIGHT_PLAY = ROOT / "playbooks" / "personal-platform-preflight.yml"
PREFLIGHT = ROOT / "tools" / "personal_platform" / "host_preflight.py"
BUILDER = ROOT / "tools" / "personal_platform" / "host_governance.py"
RUNTIME = ROOT / "tools" / "cnesdata_delivery"
TAG = "personal_platform_private_handoffs"
H = "a" * 64
SHA = "b" * 40
VERSION = "v1-synthetic"
NOW = "2029-12-31T23:03:00Z"
SSH = "ssh.cnesdata.example.test"
API = "api.cnesdata.example.test"
KEY = base64.b64encode(
    b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
).decode()
KNOWN = f"{SSH} ssh-ed25519 {KEY}"
PATHS = {
    "host-gate": "/etc/personal-platform/host-gate.json",
    "original-platform": "/var/lib/personal-platform/deployments/original-platform.json",
    "original-baseline": "/var/lib/personal-platform/deployments/original-baseline.json",
}


def runtime():
    return importlib.import_module("tools.cnesdata_delivery.host_gate")


def builder():
    try:
        return importlib.import_module("tools.personal_platform.host_governance")
    except ModuleNotFoundError:
        pytest.fail("host path builder is absent")


def tasks():
    [block] = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    return block["block"]


def named(fragment):
    found = [t for t in tasks() if fragment in t["name"]]
    assert len(found) == 1, fragment
    return found[0]


def sha_of(path):
    return runtime().sha(path.read_bytes())


def inventory():
    return {
        "product": "cnesdata",
        "ssh_hostname": SSH,
        "ssh_user": "personal-cnesdata-deploy",
        "public_hostname": API,
        "proxy": "caddy",
        "caddyfile_path": "/opt/cnesdata/caddy/Caddyfile",
        "caddy_container": "caddy",
        "proxy_network": "proxy",
        "caddy_ip": "172.30.0.2",
        "tunnel_health_url": f"https://{API}/health/ready",
    }


def dependencies():
    return {
        "reusable_sha": SHA,
        "runtime_sha256": sha_of(RUNTIME / "host_gate.py"),
        "runtime_contract_sha256": sha_of(RUNTIME / "contract.py"),
        "requirements_sha256": sha_of(RUNTIME / "runtime-requirements.txt"),
        "cloudflared": {"version": "2026.11.0", "sha256": H},
    }


def preflight_bytes():
    return runtime().canonical(
        {
            "version": 1,
            "observed_at": "2029-12-31T22:00:00Z",
            "tools": {
                "python3": "Python 3.12.3",
                "docker": "Docker version 28.0.0",
                "compose": "Docker Compose version v2.30.0",
                "openssl": "OpenSSL 3.0.13",
                "aws": "aws-cli/2.22.0",
            },
            "hashes": {
                "host_gate_py": dependencies()["runtime_sha256"],
                "contract_py": dependencies()["runtime_contract_sha256"],
                "sshd_dispatcher_conf": H,
                "sudoers_dispatcher": H,
            },
            "checks": {"dispatcher_user_locked": True, "tunnel_active": True},
        }
    )


def plan():
    source = {"inventory": inventory(), "dependencies": dependencies()}
    return builder().build_platform_plan(
        source, preflight_bytes(), KNOWN, "2030-01-01T00:00:00Z"
    )


def runner(raw):
    leaf = "arn:aws:ssm:us-east-2:111122223333:parameter/cnesdata/deploy/"
    return {
        "role_arn": "arn:aws:iam::111122223333:role/cnesdata-delivery-host",
        "objects": [
            {
                "bucket": "cnesdata-evidence-synthetic",
                "key": "cnesdata/prod/platform/p1/platform-plan.json",
                "version": VERSION,
                "sha256": runtime().sha(raw),
                "size": len(raw),
            }
        ],
        "ssm_parameters": {
            name: leaf + name
            for name in ("ssh-key", "cloudflare-client-id", "cloudflare-client-secret")
        },
        "ssh_hostname": SSH,
        "known_hosts": KNOWN,
        "cloudflared": {"version": "2026.11.0", "sha256": H},
    }


def host_fragment():
    values = inventory()
    return {
        "slot": "green",
        "port": 18082,
        "previous_slot": "blue",
        "public_hostname": values["public_hostname"],
        "tunnel_health_url": values["tunnel_health_url"],
        "proxy": "caddy",
        "caddyfile_path": values["caddyfile_path"],
        "caddy_container": values["caddy_container"],
        "proxy_network": values["proxy_network"],
        "caddy_ip": values["caddy_ip"],
        "previous_caddyfile_sha256": H,
        "previous_caddy_upstream": "central-api:8000",
    }


def credentials():
    return {
        "application": "cnesdata",
        "certificate": "/etc/personal-platform/ra/cnesdata/certificate.pem",
        "private_key": "/etc/personal-platform/ra/cnesdata/private-key.pem",
        "trust_anchor_arn": "arn:aws:rolesanywhere:us-east-2:111122223333:trust-anchor/x",
        "profile_arn": "arn:aws:rolesanywhere:us-east-2:111122223333:profile/x",
        "role_arn": "arn:aws:iam::111122223333:role/cnesdata-prod-api",
        "duration_seconds": 3600,
        "trust_deadline": "2030-02-01T00:00:00Z",
    }


def probes():
    return {
        name: {
            "role_arn": f"arn:aws:iam::111122223333:role/cnesdata-prod-{name.lower()}",
            "credential_path": f"/run/personal-platform/probes/{name}.credentials",
            "expires_at": "2030-01-01T00:00:00Z",
            "bucket": "cnesdata-probe-synthetic",
            "key": f"probe/{name}",
        }
        for name in ("unit", "recovery", "API")
    }


def governed(tmp_path, monkeypatch):
    import test_personal_platform_dispatcher as dispatcher

    g, hp, raw = runtime(), builder(), plan()
    fields = hp.platform_fields(raw, VERSION)
    original = dispatcher.manifest

    def manifest(action="deploy"):
        value = original(action)
        value["platform_plan"] = dict(fields)
        return value

    monkeypatch.setattr(dispatcher, "manifest", manifest)
    request, gov, api, responses = dispatcher.authenticated_fixture(tmp_path, monkeypatch)
    promote = ".github/workflows/promote-production.yml"
    gov["binding"]["caller"]["workflow_path"] = promote
    responses["repos/VINIClUS/CnesData/actions/runs/11/attempts/1"]["path"] = promote
    static = {
        **copy.deepcopy(gov),
        "enabled": True,
        "runtime_sha256": sha_of(RUNTIME / "host_gate.py"),
        "envelope": copy.deepcopy(request.envelope),
        "plan_run_id": 12,
        "region": "us-east-2",
        "runner": runner(raw),
        "host": host_fragment(),
        "credentials": credentials(),
        "runtime_probes": probes(),
        "signing_spki_pem_sha256": H,
    }
    return g, hp, raw, static, request, api


def build(hp, static, raw, run_id=11, attempt=1):
    g = runtime()
    return hp.build_governance(static, raw, run_id, attempt, g.instant(NOW))


def test_chave_de_deploy_exclusiva_vem_do_inventario_e_recusa_placeholder():
    names = [t["name"] for t in tasks()]
    account = names.index("Create the isolated forced-command account")
    check = named("Require the deploy public key")
    install = named("Install only the deploy public key")
    assert account < names.index(check["name"]) < names.index(install["name"])
    rules = check["ansible.builtin.assert"]["that"]
    assert "personal_platform_dispatcher_authorized_key is string" in rules
    pattern = next(r for r in rules if " is match(" in r)
    regex = re.search(r"match\('(.+)'\)", pattern).group(1)
    assert re.fullmatch(regex, "ssh-ed25519 " + KEY)
    assert not re.fullmatch(regex, "ssh-rsa " + KEY)
    module = install["ansible.posix.authorized_key"]
    assert module["user"] == "{{ personal_platform_dispatcher_user }}"
    assert module["key"] == "{{ personal_platform_dispatcher_authorized_key }}"
    assert module["exclusive"] is True
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    assert defaults["personal_platform_dispatcher_authorized_key"] is None
    assert defaults["personal_platform_dispatcher_handoffs"] == {}


def test_handoffs_privados_copiam_bytes_do_controlador_para_paths_fixos():
    fixed = yaml.safe_load((ROLE / "vars" / "main.yml").read_text())
    assert fixed == {"personal_platform_dispatcher_handoff_paths": PATHS}
    own = [t for t in tasks() if TAG in t.get("tags", [])]
    names = [t["name"] for t in own]
    copy_task = named("Install the exact private handoff bytes")
    module = copy_task["ansible.builtin.copy"]
    assert "content" not in module and module["src"] == "{{ item.value.src }}"
    assert module["dest"] == "{{ personal_platform_dispatcher_handoff_paths[item.key] }}"
    assert (module["owner"], module["group"], module["mode"]) == ("root", "root", "0600")
    assert copy_task["no_log"] is True
    runtime_check = named("Require the runtime pinned by the governed handoff")
    readback = named("Read back the installed private handoff digests")
    exact = named("Require the exact private handoff bytes")
    assert names.index(runtime_check["name"]) < names.index(copy_task["name"])
    assert names.index(copy_task["name"]) < names.index(readback["name"])
    assert readback["ansible.builtin.stat"]["checksum_algorithm"] == "sha256"
    rules = " ".join(exact["ansible.builtin.assert"]["that"])
    for fragment in ("item.item.value.sha256", "uid == 0", "'0600'", "nlink == 1"):
        assert fragment in rules, fragment
    assert "runtime_sha256" in " ".join(runtime_check["ansible.builtin.assert"]["that"])


def listed(tmp_path, *selection):
    hosts = tmp_path / "hosts.yml"
    hosts.write_text(
        yaml.safe_dump(
            {"all": {"children": {"personal_platform": {"hosts": {"synthetic": {}}}}}}
        )
    )
    return subprocess.run(
        ["ansible-playbook", "-i", str(hosts), str(DELIVERY), "--list-tasks", *selection],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible-core absent")
def test_tag_dos_handoffs_roda_sozinha_depois_do_checkpoint(tmp_path):
    text = listed(tmp_path, "--tags", TAG)
    checkpoint = "Require one exact inventory host and explicit installation authorization"
    present = [
        checkpoint,
        "Require the runtime pinned by the governed handoff",
        "Install the exact private handoff bytes",
        "Require the exact private handoff bytes",
    ]
    for name in present:
        assert name in text, name
    for name in (
        "Install the self-contained runtime from this exact checkout",
        "Install the private original governed handoff",
        "Install only the deploy public key",
        "Install the fixed root-only credential renewer without starting it",
    ):
        assert name not in text, name
    positions = [text.index(name) for name in present]
    assert positions == sorted(positions)


def fake_tools(tmp_path, locked="L"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    outputs = {
        "python3": "Python 3.12.3",
        "docker": "Docker version 28.0.0, build x",
        "openssl": "OpenSSL 3.0.13 30 Jan 2024",
        "aws": "aws-cli/2.22.0 Python/3.12.6",
    }
    for name, line in outputs.items():
        script = f'#!/bin/sh\nif [ "$1" = compose ]; then echo "Docker Compose version v2"; '
        script += f'exit 0; fi\necho "{line}"\n'
        (bin_dir / name).write_text(script)
    (bin_dir / "passwd").write_text(
        f'#!/bin/sh\necho "personal-cnesdata-deploy {locked} 2026-11-15 0 99999 7 -1"\n'
    )
    (bin_dir / "systemctl").write_text('#!/bin/sh\n[ "$3" = cloudflared ]\n')
    for path in bin_dir.iterdir():
        path.chmod(0o755)
    return bin_dir


def run_preflight(tmp_path, bin_dir, *extra):
    output = tmp_path / "out" / "preflight.json"
    output.parent.mkdir()
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin"}
    subprocess.run(
        [sys.executable, "-I", str(PREFLIGHT), "--root", str(tmp_path / "root"),
         "--output", str(output), "--observed-at", "2029-12-31T22:00:00Z", *extra],
        env=env,
        check=True,
        capture_output=True,
    )
    return output


def test_preflight_emite_bytes_canonicos_so_com_versoes_hashes_e_booleanos(tmp_path):
    g = runtime()
    root = tmp_path / "root"
    installed = root / "usr/local/lib/personal-platform"
    installed.mkdir(parents=True)
    (installed / "host_gate.py").write_bytes(b"runtime")
    output = run_preflight(tmp_path, fake_tools(tmp_path))
    raw = output.read_bytes()
    value = g.host_json(raw)
    assert g.canonical(value) == raw
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert set(value) == {"version", "observed_at", "tools", "hashes", "checks"}
    assert value["version"] == 1 and value["observed_at"] == "2029-12-31T22:00:00Z"
    assert value["tools"] == {
        "python3": "Python 3.12.3",
        "docker": "Docker version 28.0.0, build x",
        "compose": "Docker Compose version v2",
        "openssl": "OpenSSL 3.0.13 30 Jan 2024",
        "aws": "aws-cli/2.22.0 Python/3.12.6",
    }
    assert value["hashes"] == {
        "host_gate_py": g.sha(b"runtime"),
        "contract_py": None,
        "sshd_dispatcher_conf": None,
        "sudoers_dispatcher": None,
    }
    assert value["checks"] == {"dispatcher_user_locked": True, "tunnel_active": True}
    assert not re.search(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", raw)


def test_preflight_reporta_conta_destravada_e_tunel_ausente(tmp_path):
    g = runtime()
    output = run_preflight(tmp_path, fake_tools(tmp_path, locked="P"), "--tunnel-unit", "x")
    value = g.host_json(output.read_bytes())
    assert value["checks"] == {"dispatcher_user_locked": False, "tunnel_active": False}


def test_playbook_de_preflight_busca_os_bytes_exatos_do_host():
    [play] = yaml.safe_load(PREFLIGHT_PLAY.read_text())
    assert play["hosts"] == "personal_platform" and play["become"] is True
    assert play["tags"] == ["personal_platform_preflight"]
    guard, produce, fetch = play["tasks"]
    rules = guard["ansible.builtin.assert"]["that"]
    assert "ansible_limit | default('') == inventory_hostname" in rules
    assert "ansible_play_hosts_all | length == 1" in rules
    script = produce["ansible.builtin.script"]
    assert "tools/personal_platform/host_preflight.py" in script["cmd"]
    assert "--output /run/personal-platform/host-preflight.json" in script["cmd"]
    module = fetch["ansible.builtin.fetch"]
    assert module["src"] == "/run/personal-platform/host-preflight.json"
    assert module["flat"] is True
    assert module["dest"] == "{{ personal_platform_preflight_dest }}"


def test_objeto_de_plataforma_aplica_as_quatro_regras_de_digest():
    g, raw = runtime(), plan()
    value = g.host_json(raw)
    assert g.canonical(value) == raw
    assert set(value) == {
        "version", "product", "inventory", "dependencies", "host_preflight",
        "inventory_sha256", "dependencies_sha256", "host_preflight_sha256",
        "host_key_fingerprint", "expires_at",
    }
    assert value["inventory"] == inventory()
    assert value["inventory_sha256"] == g.sha(g.canonical(inventory()))
    assert value["dependencies_sha256"] == g.sha(g.canonical(dependencies()))
    assert value["host_preflight_sha256"] == g.sha(preflight_bytes())
    assert g.canonical(value["host_preflight"]) == preflight_bytes()
    assert value["host_key_fingerprint"].startswith("SHA256:")
    fields = builder().platform_fields(raw, VERSION)
    assert fields == {
        "evidence_id": VERSION,
        "evidence_sha256": g.sha(raw),
        "inventory_sha256": value["inventory_sha256"],
        "dependencies_sha256": value["dependencies_sha256"],
        "host_preflight_sha256": value["host_preflight_sha256"],
        "host_key_fingerprint": value["host_key_fingerprint"],
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s, p, k: (s["inventory"].update(services={}), p, k),
        lambda s, p, k: (s["dependencies"].pop("cloudflared"), p, k),
        lambda s, p, k: (None, p.replace(b'":', b'": '), k),
        lambda s, p, k: (None, p, k.replace(SSH, "other.example.test")),
        lambda s, p, k: (None, p, k.replace("ssh-ed25519", "ssh-rsa")),
    ],
)
def test_objeto_de_plataforma_recusa_entrada_fora_do_contrato(mutate):
    source = {"inventory": inventory(), "dependencies": dependencies()}
    _, raw, known = mutate(source, preflight_bytes(), KNOWN)
    with pytest.raises(ValueError):
        builder().build_platform_plan(source, raw, known, "2030-01-01T00:00:00Z")


def test_governanca_deriva_plataforma_expiries_original_bytes_e_caller(tmp_path, monkeypatch):
    g, hp, raw, static, _, _ = governed(tmp_path, monkeypatch)
    static["binding"]["platform"] = {k: "stale" for k in static["binding"]["platform"]}
    value = g.host_json(build(hp, static, raw, run_id=4242, attempt=3))
    b = value["binding"]
    obj = g.host_json(raw)
    assert b["platform"] == {
        **hp.platform_fields(raw, VERSION),
        "object_bucket": "cnesdata-evidence-synthetic",
        "object_key": "cnesdata/prod/platform/p1/platform-plan.json",
        "object_version": VERSION,
        "handoff_sha256": g.sha(g.canonical(static["runner"])),
    }
    assert b["original_bytes"]["platform_sha256"] == g.sha(raw)
    assert b["original_bytes"]["baseline_sha256"] == obj["host_preflight_sha256"]
    expiries = {e["name"]: e for e in b["expires"]}
    assert expiries["platform"] == {
        "name": "platform", "expires_at": obj["expires_at"], "source_sha256": g.sha(raw)
    }
    cost = static["cost_handoff"]["cost"]
    assert expiries["cost"]["source_sha256"] == g.sha(g.canonical(cost))
    assert expiries["cost"]["expires_at"] == cost["expires_at"]
    envelope = static["envelope"]
    assert expiries["envelope"] == {
        "name": "envelope",
        "expires_at": envelope["release_manifest"]["expires_at"],
        "source_sha256": g.sha(g.canonical(envelope)),
    }
    artifact = b["ci_artifact"]
    assert expiries["artifact"] == {
        "name": "artifact",
        "expires_at": artifact["expires_at"],
        "source_sha256": artifact["artifact_digest"].removeprefix("sha256:"),
    }
    assert expiries["credential"] == {
        "name": "credential",
        "expires_at": credentials()["trust_deadline"],
        "source_sha256": g.sha(g.canonical(credentials())),
    }
    assert (b["caller"]["run_id"], b["caller"]["run_attempt"]) == (4242, 3)
    g.validate_binding(b)


def root_reads(g, monkeypatch):
    require, read = g.require, g.read_private
    monkeypatch.setattr(
        g, "require", lambda c, r: require(True if r == "root boundary required" else c, r)
    )
    monkeypatch.setattr(
        g,
        "read_private",
        lambda p, *a, **kw: b"pem"
        if str(p).startswith("/etc/personal-platform/ra/")
        else read(p, *a, **kw),
    )


def test_documento_unico_passa_pelo_host_e_pelo_runner_reais(tmp_path, monkeypatch):
    g, hp, raw, static, request, api = governed(tmp_path, monkeypatch)
    doc = build(hp, static, raw)
    value = g.host_json(doc)
    assert g.canonical(value) == doc and len(doc) <= 48000
    path = tmp_path / "host-gate.json"
    path.write_bytes(doc)
    path.chmod(0o600)
    root_reads(g, monkeypatch)
    host = g.load_governance(path)
    assert g.container_governance(host) == credentials()
    g.HostDriver(None, None, host["host"], Path("/staged"))
    assert g.runtime_probe_set(host["runtime_probes"]) == probes()
    now = g.instant(NOW)
    monkeypatch.setattr(g.time, "time", lambda: now)
    b_host, _ = g.authenticate_request(request, host, api, now)
    api.clock = None
    monkeypatch.setattr(g, "GitHub", lambda token, clock=None: api)
    platform = value["binding"]["platform"]
    for key, item in {
        "PLAN_EVIDENCE_ID": platform["evidence_id"],
        "PLAN_EVIDENCE_DIGEST": platform["evidence_sha256"],
        "PLAN_RUN_ID": "12",
        "ARTIFACT_ID": "20",
        "ARTIFACT_DIGEST": value["binding"]["ci_artifact"]["artifact_digest"],
        "GITHUB_REPOSITORY": "VINIClUS/CnesData",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": SHA,
        "GITHUB_RUN_ID": "11",
        "GITHUB_RUN_ATTEMPT": "1",
    }.items():
        monkeypatch.setenv(key, item)
    secret = g.host_json(doc)
    assert g.runner_request(secret, bytearray(b"fixture-token")).envelope == request.envelope
    filled = {"lease_owner_sha256": "c" * 64, "operation_nonce_sha256": "d" * 64}
    b_runner = copy.deepcopy(secret["binding"])
    for b in (b_host, b_runner):
        b.update(filled, initial_generation=5)
    assert g.sha(g.canonical(b_host)) == g.sha(g.canonical(b_runner))


def test_carrier_e_fingerprint_passam_pelo_handoff_e_ssh_reais(tmp_path, monkeypatch):
    g, hp, raw, static, request, _ = governed(tmp_path, monkeypatch)
    value = g.host_json(build(hp, static, raw))

    class Body(io.BytesIO):
        pass

    class S3:
        def get_object(self, Bucket, Key, VersionId):
            assert (Bucket, Key, VersionId) == (
                "cnesdata-evidence-synthetic",
                "cnesdata/prod/platform/p1/platform-plan.json",
                VERSION,
            )
            return {"Body": Body(raw), "VersionId": VERSION, "ContentLength": len(raw)}

    g.runner_handoff(value, S3())

    class Reached(Exception):
        pass

    def stop(*args, **kwargs):
        raise Reached

    monkeypatch.setattr(g.urllib.request, "urlopen", stop)
    secrets = {"ssh-key": "k", "cloudflare-client-id": "i", "cloudflare-client-secret": "s"}
    with pytest.raises(Reached):
        g.ssh_exchange(request, value, secrets)


def test_execucoes_diferentes_mudam_so_o_caller(tmp_path, monkeypatch):
    g, hp, raw, static, _, _ = governed(tmp_path, monkeypatch)
    first = g.host_json(build(hp, static, raw, run_id=11, attempt=1))
    second = g.host_json(build(hp, static, raw, run_id=12, attempt=2))
    for value in (first, second):
        value["binding"]["caller"].pop("run_id")
        value["binding"]["caller"].pop("run_attempt")
    assert first == second


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(runtime_sha256=H),
        lambda s: s["runner"].update(ssh_hostname="other.example.test"),
        lambda s: s["host"].update(caddy_ip="172.30.0.9"),
        lambda s: s["runner"]["objects"][0].update(sha256=H),
        lambda s: s.update(extra=True),
        lambda s: s.pop("credentials"),
        lambda s: s["host"].update(port=18083),
        lambda s: s["binding"]["approval"].update(governance_sha256=H),
        lambda s: s["envelope"]["release_manifest"]["platform_plan"].update(evidence_id="x"),
        lambda s: s["host"].update(padding="x" * 48000),
        lambda s: s["runner"]["ssm_parameters"].update({"ssh-key": "arn:aws:ssm:x"}),
        lambda s: s["runner"]["ssm_parameters"].pop("cloudflare-client-id"),
        lambda s: s["runner"]["objects"][0].update(extra=True),
        lambda s: s["runner"].update(extra=True),
    ],
)
def test_governanca_recusa_static_incoerente(tmp_path, monkeypatch, mutate):
    _, hp, raw, static, _, _ = governed(tmp_path, monkeypatch)
    mutate(static)
    with pytest.raises((ValueError, KeyError)):
        build(hp, static, raw)


def test_cli_escreve_documento_privado_e_imprime_so_digests(tmp_path, monkeypatch):
    g, hp, raw, static, _, _ = governed(tmp_path, monkeypatch)
    (tmp_path / "static.json").write_text(json.dumps(static))
    (tmp_path / "plan.json").write_bytes(raw)
    out = tmp_path / "governance.json"
    result = subprocess.run(
        [sys.executable, "-I", str(BUILDER), "governance", "--static",
         str(tmp_path / "static.json"), "--plan", str(tmp_path / "plan.json"),
         "--run-id", "11", "--run-attempt", "1", "--out", str(out)],
        capture_output=True,
        text=True,
        check=True,
        env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
    )
    doc = out.read_bytes()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    binding = g.sha(g.canonical(g.host_json(doc)["binding"]))
    assert result.stdout == f"sha256={g.sha(doc)}\nbinding_sha256={binding}\n"
    assert "arn:aws" not in result.stdout + result.stderr


def test_cli_monta_objeto_de_plataforma_e_os_seis_campos(tmp_path):
    g = runtime()
    source = {"inventory": inventory(), "dependencies": dependencies()}
    (tmp_path / "source.json").write_text(json.dumps(source))
    (tmp_path / "preflight.json").write_bytes(preflight_bytes())
    (tmp_path / "known_hosts").write_text(KNOWN + "\n")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    subprocess.run(
        [sys.executable, "-I", str(BUILDER), "platform-plan", "--source",
         str(tmp_path / "source.json"), "--preflight", str(tmp_path / "preflight.json"),
         "--known-hosts", str(tmp_path / "known_hosts"), "--expires-at",
         "2030-01-01T00:00:00Z", "--out", str(tmp_path / "plan.json")],
        check=True,
        env=env,
    )
    assert (tmp_path / "plan.json").read_bytes() == plan()
    result = subprocess.run(
        [sys.executable, "-I", str(BUILDER), "platform-fields", "--plan",
         str(tmp_path / "plan.json"), "--version", VERSION],
        capture_output=True,
        check=True,
        env=env,
    )
    assert result.stdout == g.canonical(builder().platform_fields(plan(), VERSION))
