"""Host path da api stage: entradas por execução (campos do host, ativação e sondas).

Fixtures sintéticas; nenhuma é evidência operacional do host.
"""

import base64
import dataclasses
import datetime as dt
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.error
from pathlib import Path

import pytest
import yaml

from test_personal_platform_host_path import (
    ACCESS,
    API,
    EXPIRES,
    H,
    NOW,
    ROLE,
    ROOT,
    SHA,
    TAG,
    activation_value,
    api_probe,
    builder,
    credentials,
    caddyfile,
    compose_bytes,
    derived_probes,
    governed,
    host_fragment,
    listed,
    named,
    probes,
    readback,
    runtime,
    signed,
    signing_key,
    tasks,
)

READBACK_PLAY = ROOT / "playbooks" / "personal-platform-host-readback.yml"
READBACK = ROOT / "tools" / "personal_platform" / "host_readback.py"
API_PROBE = ROOT / "tools" / "personal_platform" / "host_api_probe.py"
API_PROBE_PLAY = ROOT / "playbooks" / "personal-platform-api-probe.yml"
BUILDER = ROOT / "tools" / "personal_platform" / "host_governance.py"
CADDYFILE = "/opt/cnesdata/caddy/Caddyfile"
PROBE_OUT = "/run/personal-platform/probes/API.credentials"
INI = (
    f"[default]\naws_access_key_id={ACCESS}\naws_secret_access_key=synthetic-secret"
    "\naws_session_token=synthetic-token\n"
)


def host_of(upstream="central-api:8000", port=18082, listening=(), text=None):
    hp = builder()
    seen = hp.read_readback(readback(upstream, listening, text=text))
    return hp.derive_host(host_fragment(), seen, port)


def test_campos_do_host_derivam_da_leitura_legada_e_da_porta_do_archive():
    g = runtime()
    host = host_of()
    assert host == {
        **host_fragment(),
        "slot": "green",
        "port": 18082,
        "previous_slot": "blue",
        "previous_caddyfile_sha256": g.sha(caddyfile()),
        "previous_caddy_upstream": "central-api:8000",
    }
    assert g.HostDriver(None, None, host, Path("/staged")).project == "cnesdata-green"
    candidate = g.render_caddy(
        caddyfile(), API, host["previous_caddy_upstream"], "cnesdata-green-api-1:8000"
    )
    assert candidate == caddyfile("cnesdata-green-api-1:8000")


@pytest.mark.parametrize(
    ("upstream", "port", "listening", "slot", "previous"),
    [
        ("cnesdata-blue-api-1:8000", 18082, (18081,), "green", "blue"),
        ("cnesdata-green-api-1:8000", 18081, (18082,), "blue", "green"),
        ("central-api:8000", 18081, (), "blue", "green"),
    ],
)
def test_slot_anterior_e_o_slot_vivo_ou_o_oposto_no_legado(
    upstream, port, listening, slot, previous
):
    host = host_of(upstream, port, listening)
    assert (host["slot"], host["previous_slot"]) == (slot, previous)
    assert host["previous_caddy_upstream"] == upstream
    runtime().HostDriver(None, None, host, Path("/staged"))


TWO_BLOCKS = caddyfile() + f"{API} {{\n\treverse_proxy central-api:8000\n}}\n".encode()
NO_TOKEN = caddyfile().replace(b"central-api:8000", b"other-api:8000", 1)
TWO_TOKENS = caddyfile().replace(
    b"central-api:8000", b"central-api:8000 cnesdata-blue-api-1:8000", 1
)


@pytest.mark.parametrize(
    "case",
    [
        {"upstream": "cnesdata-green-api-1:8000", "port": 18082, "listening": (18082,)},
        {"upstream": "cnesdata-blue-api-1:8000", "port": 18082},
        {"listening": (18082,)},
        {"port": 18083},
        {"text": TWO_BLOCKS},
        {"text": NO_TOKEN},
        {"text": TWO_TOKENS},
    ],
)
def test_campos_do_host_recusam_slot_vivo_porta_ocupada_e_caddyfile_ambiguo(case):
    with pytest.raises(ValueError):
        host_of(**case)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda h: h.update(slot="green"),
        lambda h: h.pop("readiness_sha256"),
        lambda h: h.update(readiness_sha256="x"),
        lambda h: h.update(readiness_sha256="e" * 64),
        lambda h: h.update(tunnel_health_url=f"https://{API}/api/v1/system/health"),
        lambda h: h.update(tunnel_health_url="https://other.example.test/health/ready"),
        lambda h: h.update(proxy="nginx"),
    ],
)
def test_campos_do_host_recusam_static_com_campo_derivado_ou_sem_readiness(mutate):
    static = host_fragment()
    mutate(static)
    hp = builder()
    with pytest.raises((ValueError, KeyError)):
        hp.derive_host(static, hp.read_readback(readback()), 18082)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw.replace(b'":', b'": '),
        lambda raw: raw.replace(b'"listening":[]', b'"listening":[8080]'),
        lambda raw: raw.replace(b'"version":1', b'"extra":1,"version":1'),
        lambda raw: raw.replace(b'"caddyfile_b64":"', b'"caddyfile_b64":"*'),
    ],
)
def test_leitura_do_host_recusa_bytes_fora_do_contrato(mutate):
    with pytest.raises(ValueError):
        builder().read_readback(mutate(readback()))


@pytest.mark.parametrize(
    ("upstream", "listening", "expected"),
    [
        ("central-api:8000", (), "live=legacy port=18081\n"),
        ("central-api:8000", (18081,), "live=legacy port=18082\n"),
        ("cnesdata-blue-api-1:8000", (18081,), "live=blue port=18082\n"),
        ("cnesdata-green-api-1:8000", (18082,), "live=green port=18081\n"),
    ],
)
def test_cli_live_slot_indica_a_porta_do_host_archive(tmp_path, upstream, listening, expected):
    path = tmp_path / "readback.json"
    path.write_bytes(readback(upstream, listening))
    result = subprocess.run(
        [sys.executable, "-I", str(BUILDER), "live-slot", "--readback", str(path),
         "--hostname", API],
        capture_output=True, text=True, check=True,
    )
    assert result.stdout == expected


def release_archive(compose):
    import test_personal_platform_dispatcher as dispatcher

    g = runtime()
    value, config = dispatcher.manifest(), b"{}\n"
    value["compose_sha256"], value["config_sha256"] = g.sha(compose), g.sha(config)
    files = [
        ("release-manifest.json", g.canonical(value)),
        ("compose.yml", compose),
        ("config.json", config),
    ]
    return value, dispatcher.archive([(n, b, tarfile.REGTYPE) for n, b in files])


def test_porta_do_candidato_vem_do_compose_do_archive_pelo_consumidor_real():
    g = runtime()
    value, tar = release_archive(compose_bytes(18081))
    assert builder().archive_port(tar, value, g.sha(tar)) == 18081


@pytest.mark.parametrize(
    "compose",
    [
        compose_bytes(18083),
        compose_bytes().replace(b"ghcr.io/viniclus/cnesdata@", b"ghcr.io/other/x@"),
        compose_bytes().replace(b'"read_only":true,"restart"', b'"read_only":false,"restart"'),
    ],
)
def test_porta_do_candidato_recusa_compose_fora_do_contrato(compose):
    g = runtime()
    value, tar = release_archive(compose)
    with pytest.raises((ValueError, KeyError)):
        builder().archive_port(tar, value, g.sha(tar))


def test_porta_do_candidato_recusa_archive_com_digest_divergente():
    value, tar = release_archive(compose_bytes())
    with pytest.raises(ValueError):
        builder().archive_port(tar, value, H)


def test_release_deriva_da_ativacao_assinada_e_passa_pelo_verificador_real(
    tmp_path, monkeypatch
):
    g, hp = runtime(), builder()
    key, handoff = signing_key()
    raw, signature = signed(key)
    pem = hp.signing_pem(handoff)
    lines = pem.split(b"\n")
    assert lines[0] == b"-----BEGIN PUBLIC KEY-----" and lines[-2:] == [
        b"-----END PUBLIC KEY-----",
        b"",
    ]
    assert [len(line) for line in lines[1:-2]] == [64, 60]
    release = hp.derive_release(raw, signature)
    value = activation_value()
    assert release == {
        "repository": "VINIClUS/CnesData",
        "release_id": value["release_id"],
        "source_sha": SHA,
        "candidate_sha256": value["candidate_sha256"],
        "canary_id": value["canary_id"],
        "binding_sha256": value["binding_sha256"],
        "activation_sha256": g.sha(raw),
        "signature_sha256": g.sha(signature),
        "phase_a_evidence_sha256": value["phase_a_evidence_digest"],
        "ecr_image_digest": "sha256:" + "f" * 64,
        **{n + "_revision": value["revisions"][n] for n in ("unit", "recovery", "audit")},
    }
    root = tmp_path / "deployments"
    root.mkdir(mode=0o700)
    for name, data in (
        ("activation.json", raw),
        ("activation-signature.der", signature),
        ("activation-public-key.pem", pem),
    ):
        (root / name).write_bytes(data)
        (root / name).chmod(0o600)
    monkeypatch.setattr(runtime(), "ROOT", root)
    governance = {
        "binding": {"requested_action": "deploy", "release": release},
        "signing_spki_pem_sha256": g.sha(pem),
    }
    g.verify_original_activation(governance, lambda: None)
    hp.check_activation(governance, raw, signature, pem)


def test_verificacao_da_ativacao_no_build_recusa_assinatura_de_outros_bytes():
    hp = builder()
    key, handoff = signing_key()
    _, signature = signed(key)
    raw, _ = signed(key, {**activation_value(), "release_id": f"candidate-{SHA}-2-1"})
    pem = hp.signing_pem(handoff)
    governance = {
        "binding": {"requested_action": "deploy", "release": hp.derive_release(raw, signature)},
        "signing_spki_pem_sha256": runtime().sha(pem),
    }
    with pytest.raises(ValueError):
        hp.check_activation(governance, raw, signature, pem)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda v: v.update(extra=1),
        lambda v: v.update(project="limnopulse"),
        lambda v: v.update(derivation="cnesdata:prod:canary:v2"),
        lambda v: v.update(ecr_uri="111122223333.dkr.ecr.us-east-2.amazonaws.com/x:latest"),
        lambda v: v["revisions"].update(unit="arn:aws:ecs:us-east-1:111122223333:x"),
        lambda v: v.pop("inputs"),
    ],
)
def test_release_recusa_ativacao_fora_do_schema(mutate):
    key, _ = signing_key()
    value = activation_value()
    mutate(value)
    raw, signature = signed(key, value)
    with pytest.raises((ValueError, KeyError)):
        builder().derive_release(raw, signature)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(spki_sha256=H),
        lambda s: s.update(spki_der_b64=s["spki_der_b64"][:-4]),
        lambda s: s.update(extra=True),
        lambda s: s.update(
            spki_der_b64=base64.b64encode(bytes(91)).decode(),
            spki_sha256=runtime().sha(bytes(91)),
        ),
    ],
)
def test_pem_recusa_handoff_de_assinatura_fora_do_pin(mutate):
    _, handoff = signing_key()
    mutate(handoff)
    with pytest.raises(ValueError):
        builder().signing_pem(handoff)


def as_deploy(g, static, seen):
    import test_personal_platform_dispatcher as dispatcher

    manifest = static["envelope"]["release_manifest"]
    original = static["binding"]["original_bytes"]
    files = g.inspect_archive(seen.archive, manifest, original["archive_sha256"])
    manifest["requested_action"] = static["binding"]["requested_action"] = "deploy"
    tar = dispatcher.archive(
        [
            (n, g.canonical(manifest) if n == "release-manifest.json" else d, tarfile.REGTYPE)
            for n, d in files.items()
        ]
    )
    original["archive_sha256"] = g.sha(tar)
    return dataclasses.replace(seen, archive=tar)


def deploy_inputs(tmp_path, monkeypatch):
    g, hp, seen, static, _, _ = governed(tmp_path, monkeypatch)
    key, handoff = signing_key()
    raw, signature = signed(key)
    seen = as_deploy(g, static, seen)
    static["binding"]["expires"] = [
        e for e in static["binding"]["expires"] if e["name"] != "activation"
    ] + [{"name": "activation", "expires_at": EXPIRES, "source_sha256": H}]
    deploy = dataclasses.replace(seen, signing=handoff, activation=(raw, signature))
    return g, hp, static, deploy


def test_binding_de_deploy_deriva_release_e_expiry_da_ativacao(tmp_path, monkeypatch):
    g, hp, static, deploy = deploy_inputs(tmp_path, monkeypatch)
    raw, signature = deploy.activation
    b = hp.derive_binding(static, deploy, 11, 1)
    assert b["release"] == hp.derive_release(raw, signature)
    expiries = {e["name"]: e for e in b["expires"]}
    assert expiries["activation"] == {
        "name": "activation", "expires_at": EXPIRES, "source_sha256": g.sha(raw)
    }
    assert [e["name"] for e in b["expires"]] == sorted(expiries)


def test_binding_exige_ativacao_so_fora_do_validate(tmp_path, monkeypatch):
    _, hp, static, deploy = deploy_inputs(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        hp.derive_binding(static, dataclasses.replace(deploy, activation=None), 11, 1)
    static["binding"]["requested_action"] = "validate"
    with pytest.raises(ValueError):
        hp.derive_binding(static, deploy, 11, 1)


def test_carrier_cunhado_da_api_vira_ini_que_o_consumidor_real_assina(tmp_path, monkeypatch):
    g = runtime()
    root, out = mint_root(tmp_path), tmp_path / "api-probe.json"
    assert run_mint(root, out).returncode == 0
    path = root / PROBE_OUT.lstrip("/")
    assert path.read_text() == INI
    sent = []

    class Opener:
        def open(self, request, timeout):
            sent.append(request)
            body = io.BytesIO(b"<Error><Code>NoSuchKey</Code></Error>")
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", None, body)

    monkeypatch.setattr(g.urllib.request, "build_opener", lambda *a: Opener())
    probe = derived_probes()["API"]
    g.missing_object_probe(path, probe["bucket"], probe["key"], "us-east-2", lambda: None)
    [request] = sent
    assert request.full_url == (
        f"https://cnesdata-probe-synthetic.s3.us-east-2.amazonaws.com/{probe['key']}"
    )
    assert request.get_header("X-amz-security-token") == "synthetic-token"
    assert f"Credential={ACCESS}/" in request.get_header("Authorization")


def test_runtime_probes_derivam_caminho_e_expiracao_com_destino_estatico():
    g, hp = runtime(), builder()
    minted = hp.read_api_probe(api_probe(expires="2030-01-01T00:10:00Z"))
    api = probes()["API"]["role_arn"]
    value = hp.derive_probes(probes(), minted, api, g.instant(NOW))
    expected = derived_probes()
    expected["API"]["expires_at"] = "2030-01-01T00:10:00Z"
    assert value == expected
    assert g.runtime_probe_set(value) == expected


@pytest.mark.parametrize(
    "case",
    [
        {"minted": api_probe(expires="2029-12-31T23:08:00Z")},
        {"minted": api_probe(role="arn:aws:iam::111122223333:role/cnesdata-prod-other")},
        {"static": {**probes()["API"], "extra": True}},
        {"static": {**probes()["API"], "key": "other/missing-probe"}},
        {"static": {**probes()["API"], "key": "cnesdata/../x"}},
        {"static": {**probes()["API"], "bucket": "Not_A_Bucket"}},
        {"more": "unit"},
        {"more": "recovery"},
        {"api_role": "arn:aws:iam::111122223333:role/cnesdata-prod-other"},
    ],
)
def test_runtime_probes_recusam_sonda_fora_do_contrato_api_only(case):
    g, hp = runtime(), builder()
    minted = hp.read_api_probe(case.get("minted", api_probe()))
    static = {"API": case.get("static", probes()["API"])}
    if "more" in case:
        static[case["more"]] = {**probes()["API"], "key": "cnesdata/host-gate/other"}
    api = case.get("api_role", probes()["API"]["role_arn"])
    with pytest.raises((ValueError, KeyError)):
        hp.derive_probes(static, minted, api, g.instant(NOW))


@pytest.mark.parametrize(
    ("expires", "accepted"),
    [("2029-12-31T23:42:59Z", False), ("2029-12-31T23:43:00Z", True)],
)
def test_sonda_da_api_exige_2400_s_de_vida_na_escrita(expires, accepted):
    g, hp = runtime(), builder()
    minted = hp.read_api_probe(api_probe(expires=expires))
    api = probes()["API"]["role_arn"]
    if accepted:
        value = hp.derive_probes(probes(), minted, api, g.instant(NOW))
        assert value["API"]["expires_at"] == expires
    else:
        with pytest.raises(ValueError):
            hp.derive_probes(probes(), minted, api, g.instant(NOW))


@pytest.mark.parametrize(
    "raw",
    [
        api_probe().replace(b'":', b'": '),
        api_probe().replace(b'"version":1', b'"extra":1,"version":1'),
        api_probe(expires="2030-01-01"),
        api_probe(role="arn:aws:iam::111122223333:user/x"),
    ],
)
def test_sessao_da_api_cunhada_recusa_bytes_fora_do_contrato(raw):
    with pytest.raises(ValueError):
        builder().read_api_probe(raw)


def host_root(tmp_path, link=False):
    root = tmp_path / "root"
    caddy = root / CADDYFILE.lstrip("/")
    caddy.parent.mkdir(parents=True)
    if link:
        (caddy.parent / "real").write_bytes(caddyfile())
        caddy.symlink_to("real")
    else:
        caddy.write_bytes(caddyfile())
    net = root / "proc" / "net"
    net.mkdir(parents=True)
    header = "  sl  local_address rem_address   st tx_queue rx_queue\n"
    (net / "tcp").write_text(
        header
        + "   0: 0100007F:46A1 00000000:0000 0A 00000000:00000000\n"
        + "   1: 0100007F:46A2 0100007F:D431 01 00000000:00000000\n"
    )
    (net / "tcp6").write_text(header)
    return root


def run_readback(root, out):
    return subprocess.run(
        [sys.executable, "-I", str(READBACK), "--root", str(root), "--caddyfile", CADDYFILE,
         "--output", str(out), "--observed-at", "2029-12-31T23:00:00Z"],
        capture_output=True, check=False,
    )


def test_leitura_do_host_emite_so_o_caddyfile_e_as_portas_ouvindo(tmp_path):
    out = tmp_path / "readback.json"
    result = run_readback(host_root(tmp_path), out)
    assert result.returncode == 0, result.stderr
    assert out.read_bytes() == readback(listening=(18081,))
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_leitura_do_host_recusa_caddyfile_por_symlink(tmp_path):
    out = tmp_path / "readback.json"
    result = run_readback(host_root(tmp_path, link=True), out)
    assert result.returncode != 0 and not out.exists()


HELPER = """#!/bin/sh
here=$(dirname "$0")
printf '%s\\n' "$@" > "$here/argv.txt"
cat "$here/response.json"
exit "$(cat "$here/rc")"
"""


def helper_response(access=ACCESS, expiration=EXPIRES, version=1):
    return {
        "Version": version,
        "AccessKeyId": access,
        "SecretAccessKey": "synthetic-secret",
        "SessionToken": "synthetic-token",
        "Expiration": expiration,
    }


def mint_root(tmp_path, response=None, rc=0, creds=None, governance=True):
    root = tmp_path / "root"
    helper = root / "usr" / "local" / "bin" / "aws_signing_helper"
    helper.parent.mkdir(parents=True)
    helper.write_text(HELPER)
    helper.chmod(0o755)
    (helper.parent / "response.json").write_text(json.dumps(response or helper_response()))
    (helper.parent / "rc").write_text(str(rc))
    (root / "run" / "personal-platform").mkdir(parents=True, mode=0o700)
    if governance:
        path = root / "etc" / "personal-platform" / "host-gate.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(runtime().canonical({"credentials": creds or credentials(), "x": 1}))
        path.chmod(0o600)
    return root


def run_mint(root, out):
    return subprocess.run(
        [sys.executable, "-I", str(API_PROBE), "--root", str(root), "--output", str(out)],
        capture_output=True, check=False,
    )


def test_sonda_da_api_cunha_sessao_ra_nova_no_host_e_devolve_so_a_expiracao(tmp_path):
    root, out = mint_root(tmp_path), tmp_path / "api-probe.json"
    result = run_mint(root, out)
    assert result.returncode == 0, result.stderr
    path = root / PROBE_OUT.lstrip("/")
    assert path.read_text() == INI
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_nlink == 1
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert out.read_bytes() == api_probe(role=credentials()["role_arn"])
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    c = credentials()
    argv = (root / "usr" / "local" / "bin" / "argv.txt").read_text().splitlines()
    assert argv == [
        "credential-process", "--certificate", c["certificate"], "--private-key",
        c["private_key"], "--trust-anchor-arn", c["trust_anchor_arn"], "--profile-arn",
        c["profile_arn"], "--role-arn", c["role_arn"], "--session-duration", "3600",
    ]
    data = out.read_bytes() + result.stdout + result.stderr
    assert b"synthetic" not in data and ACCESS.encode() not in data


@pytest.mark.parametrize(
    "case",
    [
        {"response": helper_response(access="AKIASYNTHETICEXAMPLE")},
        {"response": helper_response(expiration="2020-01-01T00:00:00Z")},
        {"response": helper_response(version=2)},
        {"rc": 1},
        {"creds": {**credentials(), "application": "limnopulse"}},
        {"creds": {**credentials(), "private_key": "/tmp/private-key.pem"}},
        {"creds": {**credentials(), "duration_seconds": 900}},
        {"governance": False},
    ],
)
def test_sonda_da_api_recusa_sessao_ou_identidade_fora_do_contrato(tmp_path, case):
    root, out = mint_root(tmp_path, **case), tmp_path / "api-probe.json"
    result = run_mint(root, out)
    assert result.returncode != 0
    assert not (root / PROBE_OUT.lstrip("/")).exists() and not out.exists()
    assert b"synthetic" not in result.stdout + result.stderr


def in_seconds(seconds):
    instant = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=seconds)
    return instant.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.mark.parametrize(("seconds", "accepted"), [(2390, False), (2470, True)])
def test_sonda_da_api_recusa_sessao_cunhada_com_menos_de_2400_s(tmp_path, seconds, accepted):
    expiration = in_seconds(seconds)
    root = mint_root(tmp_path, response=helper_response(expiration=expiration))
    out = tmp_path / "api-probe.json"
    result = run_mint(root, out)
    carrier = root / PROBE_OUT.lstrip("/")
    if accepted:
        assert result.returncode == 0, result.stderr
        assert json.loads(out.read_bytes())["expires_at"] == expiration
    else:
        assert result.returncode == 1 and b"api_probe=short_session" in result.stderr
        assert not carrier.exists() and not out.exists()


def test_expiracao_da_governanca_e_a_da_sessao_gravada_no_carrier_da_api(tmp_path):
    g, hp = runtime(), builder()
    expiration, access = "2030-01-01T00:20:00Z", "ASIAMINTEDSESSION000"
    response = helper_response(access=access, expiration=expiration)
    root, out = mint_root(tmp_path, response=response), tmp_path / "api-probe.json"
    assert run_mint(root, out).returncode == 0
    carrier = (root / PROBE_OUT.lstrip("/")).read_text()
    assert f"aws_access_key_id={access}\n" in carrier
    minted = hp.read_api_probe(out.read_bytes())
    api = probes()["API"]["role_arn"]
    value = hp.derive_probes(probes(), minted, api, g.instant(NOW))
    assert value["API"]["expires_at"] == expiration


def test_playbook_da_sonda_da_api_cunha_le_de_volta_busca_e_remove():
    [play] = yaml.safe_load(API_PROBE_PLAY.read_text())
    assert play["hosts"] == "personal_platform" and play["become"] is True
    assert play["gather_facts"] is False
    assert play["tags"] == ["personal_platform_api_probe"]
    guard, mint, stat_task, check, fetch, remove = play["tasks"]
    rules = guard["ansible.builtin.assert"]["that"]
    assert "ansible_limit | default('') == inventory_hostname" in rules
    assert "ansible_play_hosts_all | length == 1" in rules
    script = mint["ansible.builtin.script"]
    assert "tools/personal_platform/host_api_probe.py" in script["cmd"]
    assert "--output /run/personal-platform/api-probe.json" in script["cmd"]
    assert script["executable"] == "/usr/bin/python3" and mint["no_log"] is True
    assert stat_task["ansible.builtin.stat"]["path"] == PROBE_OUT
    checks = " ".join(check["ansible.builtin.assert"]["that"])
    for fragment in ("isreg", "uid == 0", "'0600'", "nlink == 1", "size <= 16384"):
        assert fragment in checks, fragment
    module = fetch["ansible.builtin.fetch"]
    assert module["src"] == "/run/personal-platform/api-probe.json"
    assert module["dest"] == "{{ personal_platform_api_probe_dest }}"
    assert module["flat"] is True
    removal = remove["ansible.builtin.file"]
    assert (removal["path"], removal["state"]) == (PROBE_OUT, "absent")
    remove_flag = "personal_platform_api_probe_remove | default(false) | bool"
    assert remove["when"] == remove_flag
    for task in (mint, stat_task, check, fetch):
        assert task["when"] == "not (" + remove_flag + ")", task["name"]


def test_playbook_de_leitura_busca_so_o_documento_do_host_sem_fatos():
    [play] = yaml.safe_load(READBACK_PLAY.read_text())
    assert play["hosts"] == "personal_platform" and play["become"] is True
    assert play["gather_facts"] is False
    assert play["tags"] == ["personal_platform_host_readback"]
    guard, produce, fetch = play["tasks"]
    rules = guard["ansible.builtin.assert"]["that"]
    assert "ansible_limit | default('') == inventory_hostname" in rules
    assert "ansible_play_hosts_all | length == 1" in rules
    assert "personal_platform_readback_dest is abs" in rules
    assert "personal_platform_readback_caddyfile is abs" in rules
    script = produce["ansible.builtin.script"]
    assert "tools/personal_platform/host_readback.py" in script["cmd"]
    assert "--caddyfile {{ personal_platform_readback_caddyfile }}" in script["cmd"]
    assert "--output /run/personal-platform/host-readback.json" in script["cmd"]
    assert script["executable"] == "/usr/bin/python3"
    module = fetch["ansible.builtin.fetch"]
    assert module["src"] == "/run/personal-platform/host-readback.json"
    assert module["dest"] == "{{ personal_platform_readback_dest }}"
    assert module["flat"] is True


def test_handoffs_nao_instalam_carriers_de_sonda_nem_criam_o_diretorio():
    names = [t["name"] for t in tasks()]
    paths = yaml.safe_load((ROLE / "vars" / "main.yml").read_text())
    handoffs = paths["personal_platform_dispatcher_handoff_paths"]
    assert not [n for n in handoffs if n.startswith("probe-")]
    assert not [p for p in handoffs.values() if p.startswith("/run/personal-platform/probes")]
    assert "Create the private runtime probe directory" not in names
    assert not [n for n in names if "API runtime probe" in n]
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    assert "personal_platform_dispatcher_api_probe" not in defaults


def test_tmpfiles_recria_o_diretorio_das_sondas_no_boot():
    task = named("Recreate the runtime probe directory on every boot")
    module = task["ansible.builtin.copy"]
    assert module["dest"] == "/etc/tmpfiles.d/personal-platform-probes.conf"
    assert module["content"] == "d /run/personal-platform/probes 0700 root root -\n"
    assert (module["owner"], module["mode"]) == ("root", "0644")
    assert TAG not in task.get("tags", [])


@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible-core absent")
def test_tag_dos_handoffs_nao_toca_o_diretorio_das_sondas(tmp_path):
    text = listed(tmp_path, "--tags", TAG)
    assert "Install the exact private handoff bytes" in text
    assert "runtime probe directory" not in text


def test_governanca_de_deploy_verifica_a_ativacao_real_no_build(tmp_path, monkeypatch):
    g, hp, static, deploy = deploy_inputs(tmp_path, monkeypatch)
    raw, signature = deploy.activation
    value = g.host_json(hp.build_governance(static, deploy, 11, 1, g.instant(NOW)))
    assert value["binding"]["release"] == hp.derive_release(raw, signature)
    assert value["signing_spki_pem_sha256"] == g.sha(hp.signing_pem(deploy.signing))
    tampered = dataclasses.replace(deploy, activation=(raw, signature[:-1] + b"\x00"))
    with pytest.raises(ValueError):
        hp.build_governance(static, tampered, 11, 1, g.instant(NOW))


def test_cli_governance_de_deploy_entrega_so_ativacao_e_documento_nos_handoffs(
    tmp_path, monkeypatch
):
    from test_personal_platform_host_path import write_inputs

    g, hp, static, deploy = deploy_inputs(tmp_path, monkeypatch)
    out, handoff = tmp_path / "governance.json", tmp_path / "handoff"
    argv = write_inputs(tmp_path, deploy, static, activation=deploy.activation)
    subprocess.run(
        [sys.executable, "-I", str(BUILDER), "governance", *argv, "--run-id", "11",
         "--run-attempt", "1", "--out", str(out), "--handoff-dir", str(handoff)],
        capture_output=True, text=True, check=True,
        env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
    )
    values = json.loads((handoff / "handoffs.json").read_text())
    entries = values["personal_platform_dispatcher_handoffs"]
    assert set(entries) == {
        "host-gate", "activation", "activation-signature", "activation-public-key",
    }
    assert entries["activation"]["src"] == str(tmp_path / "activation")
    assert entries["activation-signature"]["src"] == str(tmp_path / "signature")
    for name, entry in entries.items():
        assert entry["sha256"] == g.sha(Path(entry["src"]).read_bytes()), name
