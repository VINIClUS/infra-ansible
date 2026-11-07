"""Real ephemeral cryptographic proofs; no operational keys or network."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

ROOT = Path(__file__).resolve().parents[1]
NOW = 1794052800


def module():
    path = ROOT / "tools/samba_ad/pki.py"
    assert path.is_file(), "PKI verification missing"
    spec = importlib.util.spec_from_file_location("s3_pki", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def private(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def cert(key, cn, signer, issuer, *, ca=False, days=7, eku=None, san=None, before=None, pathlen=None):
    start = datetime.fromtimestamp(NOW, timezone.utc) if before is None else before
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(start + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca, pathlen), critical=True)
         .add_extension(x509.KeyUsage(not ca, False, not ca, False, False, ca, ca, False, False), critical=True))
    if san is not None:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    if eku is not None:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return b.sign(signer, hashes.SHA256())


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    """Three temporary RSA keys, shared only to keep the authorized test light."""
    d = tmp_path_factory.mktemp("s3-crypto")
    d.chmod(0o700)
    values = [rsa.generate_private_key(public_exponent=65537, key_size=3072) for _ in range(3)]
    for i, key in enumerate(values):
        p = d / str(i)
        p.write_bytes(private(key)); p.chmod(0o600)
    return values


@pytest.fixture
def chain(keys):
    root = cert(keys[0], "TEST ROOT", keys[0], None, ca=True, days=365, pathlen=1)
    issuer = cert(keys[1], "TEST ISSUER", keys[0], root.subject, ca=True, days=90, pathlen=0)
    leaf = cert(keys[2], "dc01.ad.example.invalid", keys[1], issuer.subject,
                eku=[ExtendedKeyUsageOID.SERVER_AUTH], san=["dc01.ad.example.invalid"])
    return root, issuer, leaf


def verify(chain, keys, *, profile="dc01", now=NOW + 5, previous=None):
    root, issuer, leaf = chain
    return module().verify_leaf(pem(leaf), pem(issuer), pem(root), private(keys[2]),
                                "dc01.ad.example.invalid", profile, now,
                                root.fingerprint(hashes.SHA256()).hex(),
                                issuer.fingerprint(hashes.SHA256()).hex(), previous)


def test_valid_signature_chain_and_key_are_required(chain, keys):
    result = verify(chain, keys)
    assert result["not_after"] - result["not_before"] == 604800
    assert result["not_before"] == NOW and len(result["spki_sha256"]) == 64


@pytest.mark.parametrize("bad", ["san", "eku", "extra_eku", "ca", "expiry", "future", "duration",
                                  "signature", "key", "root_pin", "issuer_pathlen", "reused"])
def test_invalid_candidates_never_pass_even_with_well_formed_pem(chain, keys, bad):
    root, issuer, leaf = chain
    kw = {"eku": [ExtendedKeyUsageOID.SERVER_AUTH], "san": ["dc01.ad.example.invalid"]}
    signer = keys[1]
    key = keys[2]
    now = NOW + 5
    if bad == "san": kw["san"].append("dc02.ad.example.invalid")
    if bad == "eku": kw["eku"] = [ExtendedKeyUsageOID.CLIENT_AUTH]
    if bad == "extra_eku": kw["eku"].append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if bad == "ca": kw.update(ca=True, pathlen=0)
    if bad == "expiry": now = NOW + 604801
    if bad == "future": kw["before"] = datetime.fromtimestamp(NOW + 60, timezone.utc)
    if bad == "duration": kw["days"] = 8
    if bad == "signature": signer = keys[0]
    if bad == "key": key = keys[0]
    if bad == "issuer_pathlen": issuer = cert(keys[1], "TEST ISSUER", keys[0], root.subject,
                                               ca=True, days=90, pathlen=1)
    leaf = cert(key, "dc01.ad.example.invalid", signer, issuer.subject, **kw)
    previous = verify(chain, keys)["spki_sha256"] if bad == "reused" else None
    pin = "f" * 64 if bad == "root_pin" else root.fingerprint(hashes.SHA256()).hex()
    with pytest.raises(ValueError, match="suppressed"):
        module().verify_leaf(pem(leaf), pem(issuer), pem(root), private(keys[2]),
                             "dc01.ad.example.invalid", "dc01", now, pin,
                             issuer.fingerprint(hashes.SHA256()).hex(), previous)


def test_corrupted_signature_is_rejected(chain, keys):
    root, issuer, leaf = chain
    raw = bytearray(leaf.public_bytes(serialization.Encoding.DER)); raw[-1] ^= 1
    damaged = x509.load_der_x509_certificate(bytes(raw))
    with pytest.raises(ValueError, match="suppressed"):
        verify((root, issuer, damaged), keys)


def test_rotation_begins_early_and_deadline_is_conservative():
    m = module()
    assert not m.rotation_due(NOW, NOW + 604800, NOW + 362879)
    assert m.rotation_due(NOW, NOW + 604800, NOW + 362880)
    assert m.rotation_deadline(NOW, NOW + 604800) == NOW + 399168


def test_telemetry_identity_cannot_be_used_as_server(chain, keys):
    root, issuer, _ = chain
    leaf = cert(keys[2], "dc01.ad.example.invalid", keys[1], issuer.subject,
                eku=[ExtendedKeyUsageOID.CLIENT_AUTH], san=["dc01.ad.example.invalid"])
    assert verify((root, issuer, leaf), keys, profile="telemetry_dc01")["not_after"] == NOW + 604800
    with pytest.raises(ValueError): verify((root, issuer, leaf), keys, profile="dc01")
