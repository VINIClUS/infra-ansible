"""Real store and crypto; only tool/HTTP/service transports are substituted."""
import base64
import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID
import pytest

from test_samba_ad_pki import ROOT, NOW, keys, chain, cert, pem
from test_samba_ad_pki_contract import request as contract_request


def module():
    p = ROOT / "tools/samba_ad/pki_runtime.py"
    assert p.is_file(), "S3 rotator missing"
    spec = importlib.util.spec_from_file_location("pki_runtime", p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


class Ops:
    def __init__(self, r, chain, keys):
        self.r, self.chain, self.keys = r, chain, keys
        self.auth = ec.generate_private_key(ec.SECP256R1())
        n = self.auth.public_key().public_numbers()
        r["credential"]["public_jwk"] = {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")),
                                          "y": b64(n.y.to_bytes(32, "big")), "kid": b64(hashlib.sha256(b"test-only-id").digest())}
        self.calls = []; self.bad_readback = False; self.bad_eku = False; self.claims = None

    def now(self): return NOW + 5

    def preflight(self, r): self.calls.append("preflight")

    def authorize(self, r, claims):
        self.calls.append("authorize"); self.claims = claims
        header = b64(json.dumps({"alg": "ES256", "kid": r["credential"]["public_jwk"]["kid"], "typ": "JWT"}).encode())
        body = b64(json.dumps(claims).encode())
        message = (header + "." + body).encode()
        sig = self.auth.sign(message, ec.ECDSA(hashes.SHA256()))
        a, b = decode_dss_signature(sig)
        return message.decode() + "." + b64(a.to_bytes(32, "big") + b.to_bytes(32, "big"))

    def issue(self, r, csr, jwt):
        self.calls.append("issue")
        cr = x509.load_pem_x509_csr(csr)
        assert cr.is_signature_valid
        assert self.claims["cnf"]["x5rt#S256"] == b64(hashlib.sha256(cr.public_bytes(__import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER)).digest())
        # Sign the real new public key, not a fake verification result.
        class Public:
            def public_key(_): return cr.public_key()
        eku = ExtendedKeyUsageOID.CLIENT_AUTH if self.bad_eku else ExtendedKeyUsageOID.SERVER_AUTH
        leaf = cert(Public(), r["target"]["fqdn"], self.keys[1], self.chain[1].subject,
                    eku=[eku], san=[r["target"]["fqdn"]], before=datetime.fromtimestamp(self.now(), timezone.utc))
        return pem(leaf), pem(self.chain[1])

    def reload(self, r): self.calls.append("reload")

    def observe(self, r, cert_sha256):
        self.calls.append("observe")
        return "f" * 64 if self.bad_readback else cert_sha256

    def stop(self, r): self.calls.append("stop")


def setup(tmp_path, chain, keys):
    r, manifest = contract_request()
    r["state_dir"] = str(tmp_path)
    r["credential"]["auth_key_ref"] = str(tmp_path / "dc01/auth.jwe")
    r["trust"].update(root_file=str(tmp_path / "root.pem"), issuer_file=str(tmp_path / "issuer.pem"),
                       root_sha256=chain[0].fingerprint(hashes.SHA256()).hex(),
                       issuer_sha256=chain[1].fingerprint(hashes.SHA256()).hex())
    for name, value in [("root.pem", pem(chain[0])), ("issuer.pem", pem(chain[1]))]:
        p = tmp_path / name; p.write_bytes(value); p.chmod(0o600)
    r.update(action="rotate", adapter={"kind": "samba", "port": 636})
    return r, manifest, Ops(r, chain, keys)


@pytest.mark.parametrize("check,apply", [(True, True), (False, False)])
def test_check_or_apply_false_never_creates_keys_tokens_or_files(tmp_path, chain, keys, check, apply):
    r, m, ops = setup(tmp_path, chain, keys); r["apply"] = apply
    before = set(tmp_path.rglob("*"))
    assert module().run(r, m, ops, check=check)["state"] == "planned"
    assert ops.calls == ["preflight"] and set(tmp_path.rglob("*")) == before


def test_disabled_never_calls_even_preflight():
    class NoOps:
        def __getattr__(self, _): raise AssertionError("disabled transport")
    assert module().run({"schema": "samba-ad-pki/v1", "enabled": False, "apply": False}, {}, NoOps())["state"] == "disabled"


def test_validated_generation_is_applied_as_one_pair_and_observed(tmp_path, chain, keys):
    r, m, ops = setup(tmp_path, chain, keys)
    result = module().run(r, m, ops, check=False)
    assert result["state"] == "active" and result["changed"] is True
    active = tmp_path / "dc01/active.conf"
    assert active.is_symlink()
    generation = active.resolve().parent
    assert str(generation / "fullchain.pem") in active.read_text()
    assert str(generation / "key.pem") in active.read_text()
    assert (generation / "key.pem").stat().st_mode & 0o777 == 0o600
    assert ops.calls == ["preflight", "authorize", "issue", "reload", "observe"]
    assert ops.claims["aud"] == ["https://ca.ad.example.invalid/1.0/sign"]
    assert ops.claims["sans"] == ["dc01.ad.example.invalid"] and len(ops.claims["jti"]) == 64


def test_invalid_eku_is_rejected_before_active_pointer_or_reload(tmp_path, chain, keys):
    r, m, ops = setup(tmp_path, chain, keys); ops.bad_eku = True
    with pytest.raises(ValueError, match="suppressed"): module().run(r, m, ops, check=False)
    assert not (tmp_path / "dc01/active.conf").exists() and "reload" not in ops.calls


def test_bad_readback_reverts_only_own_generation(tmp_path, chain, keys):
    r, m, ops = setup(tmp_path, chain, keys)
    module().run(r, m, ops, check=False)
    active = tmp_path / "dc01/active.conf"; prior = active.readlink()
    r["expected_active"] = hashlib.sha256(active.read_bytes()).hexdigest()
    ops.bad_readback = True
    # Explicit stage/rotate refresh override is not needed: a new issuance is due only later.
    ops.now = lambda: NOW + 362886
    # Synthetic issuer timestamps for the new leaf follow this clock.
    with pytest.raises(ValueError, match="suppressed"): module().run(r, m, ops, check=False)
    assert active.readlink() == prior
    assert ops.calls.count("reload") == 3


def test_missing_consumer_is_pending_without_key_creation(tmp_path, chain, keys):
    r, m, ops = setup(tmp_path, chain, keys); r["adapter"] = {"kind": "pending", "port": None}
    assert module().run(r, m, ops, check=False)["state"] == "integration_pending"
    assert "authorize" not in ops.calls and not (tmp_path / "dc01").exists()


def test_stage_does_not_claim_a_running_consumer(tmp_path, chain, keys):
    r, m, ops = setup(tmp_path, chain, keys)
    r.update(action="stage", adapter={"kind": "pending", "port": None})
    assert module().run(r, m, ops, check=False)["state"] == "staged"
    assert "reload" not in ops.calls and not (tmp_path / "dc01/active.conf").exists()


def test_timer_snapshots_only_managed_generation_without_reissuing(tmp_path, chain, keys):
    r, m, ops = setup(tmp_path, chain, keys)
    runtime = module(); runtime.run(r, m, ops, check=False)
    r["expected_active"] = "managed"
    ops.calls.clear()
    assert runtime.run(r, m, ops, check=False)["state"] == "current"
    assert "authorize" not in ops.calls


def test_successful_rotation_discards_only_previous_transaction_generation(tmp_path, chain, keys):
    r, m, ops = setup(tmp_path, chain, keys)
    runtime = module(); runtime.run(r, m, ops, check=False)
    active = tmp_path / "dc01/active.conf"; prior = active.resolve().parent
    r["expected_active"] = hashlib.sha256(active.read_bytes()).hexdigest()
    ops.now = lambda: NOW + 362886
    assert runtime.run(r, m, ops, check=False)["state"] == "active"
    assert not prior.exists()  # No key history/retention policy.


def test_cli_payload_stays_on_stdin_and_disables_only_flags_validation(monkeypatch):
    runtime = module(); r, _ = contract_request()
    def cli(argv, stdin=None, timeout=15):
        # v0.31.0 requires iss/aud/sub/exp flags unless --subtle even with a full stdin payload.
        assert "--subtle" in argv and "--token" not in argv
        assert "TEST-SECRET-CLAIM" not in " ".join(argv)
        assert json.loads(stdin)["jti"] == "TEST-SECRET-CLAIM"
        return b"captured.jwt.value\n"
    monkeypatch.setattr(runtime, "_command", cli)
    assert runtime.LocalOps().authorize(r, {"jti": "TEST-SECRET-CLAIM"}) == "captured.jwt.value"


def test_heartbeat_does_not_pretend_a_new_rotation_succeeded(tmp_path, chain, keys, monkeypatch):
    r, m, ops = setup(tmp_path, chain, keys); runtime = module()
    monkeypatch.setattr(runtime.time, "time", lambda: NOW + 5)
    runtime.run(r, m, ops, check=False)
    active = tmp_path / "dc01/active.conf"
    r["expected_active"] = hashlib.sha256(active.read_bytes()).hexdigest()
    monkeypatch.setattr(runtime.time, "time", lambda: NOW + 65)
    ops.now = lambda: NOW + 65
    runtime.run(r, m, ops, check=False)
    metrics = (tmp_path / "dc01/status.prom").read_text().splitlines()
    assert next(x for x in metrics if x.startswith("samba_ad_pki_last_rotation_success_seconds")).endswith(" " + str(NOW + 5))
    assert next(x for x in metrics if x.startswith("samba_ad_pki_last_check_seconds")).endswith(" " + str(NOW + 65))


@pytest.mark.parametrize("field", ["state", "root", "issuer", "credential"])
def test_real_adapter_refuses_system_paths_before_any_host_probe(monkeypatch, field):
    runtime = module(); r, _ = contract_request()
    if field == "state": r["state_dir"] = "/etc/ssl"
    if field == "root": r["trust"]["root_file"] = "/etc/ssh/ssh_host_rsa_key"
    if field == "issuer": r["trust"]["issuer_file"] = "/etc/shadow"
    if field == "credential": r["credential"]["password_ref"] = "/etc/ssh/ssh_host_ed25519_key"
    def forbidden(_): raise AssertionError("layout must fail before a host probe")
    monkeypatch.setattr(runtime, "host_snapshot", forbidden)
    with pytest.raises(ValueError, match="suppressed"):
        runtime.LocalOps().identity_tools(r)


@pytest.mark.parametrize("recreated", [False, True])
@pytest.mark.parametrize("umask", [0o022, 0o077])
def test_nginx_runtime_exists_before_first_test_and_after_runtime_removal(tmp_path, monkeypatch, recreated, umask):
    import os
    import shutil
    runtime = module(); r, _ = contract_request()
    r["adapter"] = {"kind": "nginx", "port": 443}
    r["tools"]["nginx"] = {"path": "/usr/sbin/nginx"}
    directory = tmp_path / "samba-ad-pki-nginx"
    if recreated:
        directory.mkdir(mode=0o755)
        (directory / "body").mkdir(mode=0o700)
        shutil.rmtree(directory)  # Synthetic systemd cleanup/reboot, never real /run.
    monkeypatch.setattr(runtime, "NGINX_RUNTIME", directory, raising=False)
    calls = []
    def command(argv, stdin=None, timeout=15):
        assert directory.is_dir(), "runtime ancestor must exist before nginx -t"
        assert directory.stat().st_uid == os.geteuid()
        assert directory.stat().st_mode & 0o777 == 0o755
        calls.append(argv)
        return b""
    monkeypatch.setattr(runtime, "_command", command)
    previous = os.umask(umask)
    try: runtime.LocalOps().reload(r)
    finally: os.umask(previous)
    assert calls == [["/usr/sbin/nginx", "-t", "-c", "/etc/samba-ad-pki/nginx.conf"],
                     ["systemctl", "reload-or-restart", "samba-ad-pki-nginx.service"]]


@pytest.mark.parametrize("unsafe", ["symlink", "writable"])
def test_nginx_runtime_refuses_unsafe_existing_directory_before_commands(tmp_path, monkeypatch, unsafe):
    runtime = module(); r, _ = contract_request()
    r["adapter"] = {"kind": "nginx", "port": 443}
    r["tools"]["nginx"] = {"path": "/usr/sbin/nginx"}
    directory = tmp_path / "samba-ad-pki-nginx"
    actual = tmp_path / "other"; actual.mkdir(mode=0o700)
    if unsafe == "symlink": directory.symlink_to(actual, target_is_directory=True)
    else: directory.mkdir(mode=0o777); directory.chmod(0o777)
    monkeypatch.setattr(runtime, "NGINX_RUNTIME", directory, raising=False)
    def forbidden(*args, **kwargs): raise AssertionError("unsafe runtime reached a native command")
    monkeypatch.setattr(runtime, "_command", forbidden)
    with pytest.raises(ValueError, match="suppressed"):
        runtime.LocalOps().reload(r)


def frontend_setup(tmp_path, chain, keys):
    from test_samba_ad_pki_ca_config import request as ca_request
    r, manifest, ops = setup(tmp_path, chain, keys)
    ca = manifest["resources"]["ca"]
    r.update(profile="ca", adapter={"kind": "nginx", "port": 443})
    r["target"].update(role="ca", fqdn=ca["fqdn"], kind="qemu", address=ca["address"], mac=ca["mac"])
    r["credential"]["auth_key_ref"] = str(tmp_path / "ca/auth.jwe")
    r["issuer"].update(transport="local_loopback", local_port=9443)
    configured = ca_request()
    for name in ["nginx", "njs"]: r["tools"][name] = configured["tools"][name]
    return r, manifest, ops


@pytest.mark.parametrize("with_prior", [False, True])
def test_point_fsync_failure_reconciles_actual_pointer_before_cleanup(tmp_path, chain, keys, monkeypatch, with_prior):
    r, manifest, ops = frontend_setup(tmp_path, chain, keys); runtime = module()
    monkeypatch.setattr(runtime.time, "time", lambda: ops.now())
    active = tmp_path / "ca/active.conf"
    prior = None
    if with_prior:
        runtime.run(r, manifest, ops, check=False)
        prior = active.readlink(); r["expected_active"] = "managed"
        ops.now = lambda: NOW + 362886
    ops.calls.clear()
    original_sync = runtime.sync_dir; failures = []
    def fail_once_after_replace(directory):
        if directory == active.parent and active.is_symlink() and not failures:
            failures.append(active.readlink())
            raise OSError("test-only directory fsync failure after replace")
        return original_sync(directory)
    monkeypatch.setattr(runtime, "sync_dir", fail_once_after_replace)
    with pytest.raises(ValueError, match="S3 rotation failed"):
        runtime.run(r, manifest, ops, check=False)
    assert len(failures) == 1
    assert (active.readlink() if active.is_symlink() else None) == prior
    generations = list((active.parent / "generations").iterdir())
    assert len(generations) == int(with_prior)
    assert ops.calls.count("reload") == int(with_prior)
    assert ops.calls.count("observe") == int(with_prior)
    assert ops.calls.count("stop") == int(not with_prior)
    assert "samba_ad_pki_last_attempt_success{profile=\"ca\"} 0" in (active.parent / "status.prom").read_text()
    if with_prior:
        assert json.loads((active.parent / "last_rotation.json").read_text())["at"] == NOW + 5
        assert f'samba_ad_pki_last_rotation_success_seconds{{profile="ca"}} {NOW + 5}' in (active.parent / "status.prom").read_text()
    else:
        assert not (active.parent / "last_rotation.json").exists()


@pytest.mark.parametrize("with_prior", [False, True])
def test_point_replace_failure_before_mutation_leaves_service_untouched(tmp_path, chain, keys, monkeypatch, with_prior):
    r, manifest, ops = frontend_setup(tmp_path, chain, keys); runtime = module()
    active = tmp_path / "ca/active.conf"; prior = None
    if with_prior:
        runtime.run(r, manifest, ops, check=False)
        prior = active.readlink(); r["expected_active"] = "managed"
        ops.now = lambda: NOW + 362886
    ops.calls.clear()
    original_replace = runtime.os.replace
    def fail_before_replace(source, destination):
        if destination == active: raise OSError("test-only pre-replace failure")
        return original_replace(source, destination)
    monkeypatch.setattr(runtime.os, "replace", fail_before_replace)
    with pytest.raises(ValueError, match="S3 rotation failed"):
        runtime.run(r, manifest, ops, check=False)
    assert (active.readlink() if active.is_symlink() else None) == prior
    assert all(name not in ops.calls for name in ["reload", "observe", "stop"])
    assert len(list((active.parent / "generations").iterdir())) == int(with_prior)


@pytest.mark.parametrize("rollback_failure", ["fsync", "replace", "reload", "readback"])
def test_failed_reversion_is_degraded_and_preserves_all_possibly_active_material(tmp_path, chain, keys, monkeypatch, rollback_failure):
    r, manifest, ops = frontend_setup(tmp_path, chain, keys); runtime = module()
    monkeypatch.setattr(runtime.time, "time", lambda: ops.now())
    runtime.run(r, manifest, ops, check=False)
    active = tmp_path / "ca/active.conf"; prior = active.readlink()
    r["expected_active"] = "managed"; ops.now = lambda: NOW + 362886
    ops.calls.clear(); original_sync = runtime.sync_dir; sync_failures = []
    def fail_sync(directory):
        if directory == active.parent and active.is_symlink() and (not sync_failures or rollback_failure == "fsync"):
            sync_failures.append(active.readlink())
            raise OSError("test-only fsync failure")
        return original_sync(directory)
    monkeypatch.setattr(runtime, "sync_dir", fail_sync)
    original_replace = runtime.os.replace
    def fail_rollback_replace(source, destination):
        if destination == active and sync_failures and rollback_failure == "replace":
            raise OSError("test-only rollback replace failure")
        return original_replace(source, destination)
    monkeypatch.setattr(runtime.os, "replace", fail_rollback_replace)
    if rollback_failure == "reload":
        def fail_reload(_):
            ops.calls.append("reload")
            raise OSError("test-only rollback reload failure")
        ops.reload = fail_reload
    if rollback_failure == "readback": ops.bad_readback = True
    with pytest.raises(ValueError, match="degraded"):
        runtime.run(r, manifest, ops, check=False)
    assert active.is_symlink() and active.resolve().is_file()
    assert len(list((active.parent / "generations").iterdir())) == 2
    assert (active.parent / prior).resolve().is_file()
    if rollback_failure != "replace":
        assert active.readlink() == prior
        assert ops.calls.count("reload") == 1
        assert ops.calls.count("observe") == int(rollback_failure != "reload")
    else:
        assert active.readlink() != prior
        assert "reload" not in ops.calls and "observe" not in ops.calls
    metrics = (active.parent / "status.prom").read_text()
    assert 'samba_ad_pki_last_attempt_success{profile="ca"} 0' in metrics
    assert f'samba_ad_pki_last_rotation_success_seconds{{profile="ca"}} {NOW + 5}' in metrics
    assert json.loads((active.parent / "last_rotation.json").read_text())["at"] == NOW + 5


@pytest.mark.parametrize("failed_file", ["status.prom", "last_rotation.json"])
def test_status_publication_failure_cannot_revert_a_verified_committed_activation(tmp_path, chain, keys, monkeypatch, failed_file):
    r, manifest, ops = frontend_setup(tmp_path, chain, keys); runtime = module()
    monkeypatch.setattr(runtime.time, "time", lambda: ops.now())
    runtime.run(r, manifest, ops, check=False)
    active = tmp_path / "ca/active.conf"; prior = active.readlink()
    r["expected_active"] = "managed"; ops.now = lambda: NOW + 362886; ops.calls.clear()
    original_atomic = runtime.atomic_file; failures = []
    def fail_status_once(filename, value):
        if filename.name == failed_file and not failures:
            failures.append(filename)
            raise OSError("test-only status publication failure")
        return original_atomic(filename, value)
    monkeypatch.setattr(runtime, "atomic_file", fail_status_once)
    with pytest.raises(ValueError, match="reporting degraded"):
        runtime.run(r, manifest, ops, check=False)
    assert active.readlink() != prior and active.resolve().is_file()
    assert ops.calls.count("reload") == ops.calls.count("observe") == 1
    true_stamp = ops.now() if failed_file == "status.prom" else NOW + 5
    assert json.loads((active.parent / "last_rotation.json").read_text())["at"] == true_stamp
    metrics = (active.parent / "status.prom").read_text()
    assert 'samba_ad_pki_last_attempt_success{profile="ca"} 0' in metrics
    assert f'samba_ad_pki_last_rotation_success_seconds{{profile="ca"}} {true_stamp}' in metrics


def test_initial_reversion_with_failed_unlink_fsync_stops_only_own_frontend_and_stays_degraded(tmp_path, chain, keys, monkeypatch):
    r, manifest, ops = frontend_setup(tmp_path, chain, keys); runtime = module()
    active = tmp_path / "ca/active.conf"; original_sync = runtime.sync_dir; armed = []
    def fail_directory_sync(directory):
        if directory == active.parent and (active.is_symlink() or armed):
            armed.append(True)
            raise OSError("test-only pointer directory fsync failure")
        return original_sync(directory)
    monkeypatch.setattr(runtime, "sync_dir", fail_directory_sync)
    with pytest.raises(ValueError, match="degraded"):
        runtime.run(r, manifest, ops, check=False)
    assert not active.exists() and not active.is_symlink()
    assert ops.calls.count("stop") == 1 and "reload" not in ops.calls
    assert len(list((active.parent / "generations").iterdir())) == 1
    assert not (active.parent / "last_rotation.json").exists()
    assert 'samba_ad_pki_last_attempt_success{profile="ca"} 0' in (active.parent / "status.prom").read_text()
