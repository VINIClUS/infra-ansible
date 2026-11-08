"""Strict S3 PKI primitives. No network, commands, key creation or activation.

Initial signing support is RSA 3072/4096 + SHA256, not arbitrary algorithms.
Trust fingerprints come from reviewed private configuration, never a fetched CA.
"""
from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, ObjectIdentifier

PROFILES = {"dc01", "dc02", "ca", "telemetry_dc01", "telemetry_dc02", "telemetry_ca"}
LIFETIME = 604800
PROVISIONER_OID = ObjectIdentifier("1.3.6.1.4.1.37476.9000.64.1")


def require(value):
    if not value:
        raise ValueError("S3 PKI precondition failed (values suppressed)")


def spki(key) -> str:
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def rotation_due(not_before: int, not_after: int, now: int) -> bool:
    require(all(type(v) is int for v in [not_before, not_after, now]) and not_after - not_before == LIFETIME)
    return now >= not_before + LIFETIME * 3 // 5


def rotation_deadline(not_before: int, not_after: int) -> int:
    require(type(not_before) is int and type(not_after) is int and not_after - not_before == LIFETIME)
    return not_before + LIFETIME * 33 // 50


def _key(key):
    require(isinstance(key, rsa.RSAPublicKey) and key.key_size in [3072, 4096]
            and key.public_numbers().e == 65537)


def _valid_time(cert, now):
    require(cert.not_valid_before_utc.timestamp() <= now < cert.not_valid_after_utc.timestamp())


def _issuer(cert, path_length):
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    require(bc.ca and ku.key_cert_sign and ku.crl_sign)
    if path_length == 0:
        require(bc.path_length == 0)
    else:
        require(bc.path_length is None or bc.path_length >= path_length)
    require(not any(e.oid == ExtensionOID.EXTENDED_KEY_USAGE for e in cert.extensions))


def _critical(cert):
    # We do not pretend to implement critical NameConstraints or arbitrary OIDs.
    understood = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                  ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                  ExtensionOID.SUBJECT_KEY_IDENTIFIER}
    require(all(not e.critical or e.oid in understood for e in cert.extensions))


def verify_leaf(cert_pem: bytes, issuer_pem: bytes, root_pem: bytes, key_pem: bytes,
                dns: str, profile: str, now: int, root_sha256: str, issuer_sha256: str,
                previous_spki: str | None = None) -> dict:
    """Verify signatures/chain/time/identity/EKU/key and return metadata only.

    This is a deliberately narrow three-certificate hierarchy, not a general
    path builder or an assertion of online revocation status.
    """
    try:
        require(profile in PROFILES and type(now) is int)
        leafs = x509.load_pem_x509_certificates(cert_pem)
        issuers = x509.load_pem_x509_certificates(issuer_pem)
        roots = x509.load_pem_x509_certificates(root_pem)
        require(len(leafs) == len(issuers) == len(roots) == 1)
        leaf, issuer, root = leafs[0], issuers[0], roots[0]
        key = serialization.load_pem_private_key(key_pem, password=None)
        require(isinstance(key, rsa.RSAPrivateKey))
        require(root.fingerprint(hashes.SHA256()).hex() == root_sha256
                and issuer.fingerprint(hashes.SHA256()).hex() == issuer_sha256)
        for cert in [leaf, issuer, root]:
            _key(cert.public_key())
            _valid_time(cert, now)
            _critical(cert)
            require(isinstance(cert.signature_hash_algorithm, hashes.SHA256))
        root.verify_directly_issued_by(root)
        issuer.verify_directly_issued_by(root)
        leaf.verify_directly_issued_by(issuer)
        _issuer(root, 1)
        _issuer(issuer, 0)
        require(not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        require(ku.digital_signature and ku.key_encipherment and not any([
            ku.content_commitment, ku.data_encipherment, ku.key_agreement, ku.key_cert_sign, ku.crl_sign]))
        eku = list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        expected_eku = ExtendedKeyUsageOID.CLIENT_AUTH if profile.startswith("telemetry_") else ExtendedKeyUsageOID.SERVER_AUTH
        require(eku == [expected_eku])
        sans = list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
        require(len(sans) == 1 and isinstance(sans[0], x509.DNSName) and sans[0].value == dns)
        allowed_leaf = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE, ExtensionOID.EXTENDED_KEY_USAGE,
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME, ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                        ExtensionOID.SUBJECT_KEY_IDENTIFIER, PROVISIONER_OID}
        require(all(e.oid in allowed_leaf for e in leaf.extensions))
        before, after = int(leaf.not_valid_before_utc.timestamp()), int(leaf.not_valid_after_utc.timestamp())
        require(after - before == LIFETIME and issuer.not_valid_after_utc >= leaf.not_valid_after_utc)
        require(spki(leaf.public_key()) == spki(key.public_key()))
        digest = spki(key.public_key())
        require(previous_spki is None or digest != previous_spki)
        return {"not_before": before, "not_after": after, "spki_sha256": digest,
                "certificate_sha256": leaf.fingerprint(hashes.SHA256()).hex(),
                "rotation_deadline": rotation_deadline(before, after)}
    except Exception:
        raise ValueError("S3 PKI candidate rejected (values suppressed)") from None
