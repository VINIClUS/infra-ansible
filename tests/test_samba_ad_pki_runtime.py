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
                                          "y": b64(n.y.to_bytes(32, "big")), "kid": "a" * 43}
        self.calls = []; self.bad_readback = False; self.bad_eku = False; self.claims = None

    def now(self): return NOW + 5

    def preflight(self, r): self.calls.append("preflight")

    def authorize(self, r, claims):
        self.calls.append("authorize"); self.claims = claims
        header = b64(json.dumps({"alg": "ES256", "kid": "a" * 43, "typ": "JWT"}).encode())
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
