"""Operator-local offline root ceremony. Never installed on CA/DC by the role.

Secret comes from an inherited FD, not argv/request/log. Network isolation of
the operator workstation is an operational fact, not something a flag proves.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import socket
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tools.samba_ad.pki import require
from tools.samba_ad.pki_contract import fields, hex_value, loads
from tools.samba_ad.pki_files import exclusive_file, secure_directory, secure_file


def subject(value):
    require(isinstance(value, str) and 1 <= len(value) <= 128 and all(32 <= ord(c) <= 126 for c in value))
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def builder(name, public_key, issuer, now, days, pathlen):
    return (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.fromtimestamp(now, timezone.utc))
            .not_valid_after(datetime.fromtimestamp(now, timezone.utc) + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True))


class Local:
    def identity(self): return {"uid": os.geteuid(), "hostname": socket.gethostname()}
    def now(self): return int(time.time())


def run(r, passphrase=None, ops=None, check=True):
    try:
        return _run(r, passphrase, ops or Local(), check)
    except Exception:
        raise ValueError("S3 offline ceremony refused (values suppressed)") from None


def _run(r, passphrase, ops, check):
    require(isinstance(r, dict) and r.get("schema") == "samba-ad-root/v1"
            and type(r.get("enabled")) is bool and type(r.get("apply")) is bool)
    if not r["enabled"]: return {"state": "disabled", "changed": False}
    fields(r, "schema enabled apply action directory expected_uid expected_hostname subject key_bits validity_days "
              "csr_file root_sha256")
    require(r["action"] in ["create_root", "sign_intermediate"])
    require(type(r["expected_uid"]) is int and r["expected_uid"] > 0)
    require(ops.identity() == {"uid": r["expected_uid"], "hostname": r["expected_hostname"]})
    directory = secure_directory(r["directory"], exact=True)
    name = subject(r["subject"])
    require(type(r["key_bits"]) is int and r["key_bits"] in [3072, 4096])
    require(type(r["validity_days"]) is int and 8 <= r["validity_days"] <= 7300)
    root_file, key_file = directory / "root.pem", directory / "root.key.pem"
    if r["action"] == "create_root":
        require(r["csr_file"] is None and r["root_sha256"] is None)
        require(all(not p.exists() and not p.is_symlink() for p in [root_file, key_file]))
    else:
        hex_value(r["root_sha256"])
        root = x509.load_pem_x509_certificate(secure_file(root_file).read_bytes())
        require(root.fingerprint(hashes.SHA256()).hex() == r["root_sha256"])
        root.verify_directly_issued_by(root)
        secure_file(key_file, secret=True)
        csr = x509.load_pem_x509_csr(secure_file(r["csr_file"]).read_bytes())
        require(csr.is_signature_valid and csr.subject == name and not list(csr.extensions))
        require(isinstance(csr.public_key(), rsa.RSAPublicKey) and csr.public_key().key_size == r["key_bits"]
                and csr.public_key().public_numbers().e == 65537)
        output = directory / "intermediate.pem"
        require(not output.exists() and not output.is_symlink())
        require(root.not_valid_before_utc.timestamp() <= ops.now()
                and ops.now() + r["validity_days"] * 86400 <= root.not_valid_after_utc.timestamp())
        bc = root.extensions.get_extension_for_class(x509.BasicConstraints).value
        require(bc.ca and (bc.path_length is None or bc.path_length >= 1))
    if check or not r["apply"]:
        return {"state": "planned", "changed": False}
    require(isinstance(passphrase, bytes) and 20 <= len(passphrase) <= 4096)
    if r["action"] == "create_root":
        key = rsa.generate_private_key(public_exponent=65537, key_size=r["key_bits"])
        certificate = builder(name, key.public_key(), name, ops.now(), r["validity_days"], 1).sign(key, hashes.SHA256())
        exclusive_file(key_file, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.BestAvailableEncryption(passphrase)))
        exclusive_file(root_file, certificate.public_bytes(serialization.Encoding.PEM))
        return {"state": "root_created", "changed": True, "public_certificates": 1}
    key = serialization.load_pem_private_key(key_file.read_bytes(), password=passphrase)
    require(isinstance(key, rsa.RSAPrivateKey) and key.key_size in [3072, 4096]
            and key.public_key().public_numbers() == root.public_key().public_numbers())
    certificate = builder(name, csr.public_key(), root.subject, ops.now(), r["validity_days"], 0).sign(key, hashes.SHA256())
    exclusive_file(output, certificate.public_bytes(serialization.Encoding.PEM))
    return {"state": "intermediate_signed", "changed": True, "public_certificates": 1}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--passphrase-fd", type=int)
    args = p.parse_args(argv)
    try:
        request = loads(sys.stdin.read())
        # Validate check/identity/paths first, before reading any secret FD.
        result = run(request, check=True)
        if args.execute and request.get("apply") and request.get("enabled"):
            require(args.passphrase_fd is not None and args.passphrase_fd > 2)
            value = os.read(args.passphrase_fd, 4097).rstrip(b"\r\n")
            result = run(request, value, check=False)
        print(json.dumps(result)); return 0
    except Exception:
        print('{"state":"error","changed":false,"error":"offline ceremony refused (values suppressed)"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
