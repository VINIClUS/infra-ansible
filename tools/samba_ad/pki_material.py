"""Generate encrypted intermediate key and public CSR on the qualified CA only.

No root key, signature endpoint, downloads or service operations in this module.
"""
import argparse
import json
from pathlib import Path
import re
import sys
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tools.samba_ad.ca_substrate import validate_ca_bundle
from tools.samba_ad.pki import require
from tools.samba_ad.pki_contract import fields, hex_value, loads
from tools.samba_ad.pki_files import exclusive_file, secure_directory, secure_file


class Local:
    def layout(self, r):
        require(r["directory"] == "/etc/samba-ad-ca")

    def inspect(self, target):
        from tools.samba_ad.pki_runtime import host_snapshot
        return host_snapshot(target["interface"])


def prepare(r, passphrase=None, ops=None, check=True):
    try:
        return _prepare(r, passphrase, ops or Local(), check)
    except Exception:
        raise ValueError("S3 destination CSR refused (values suppressed)") from None


def validate(r):
    """Structural validation only: no fake host measurement or filesystem access."""
    require(isinstance(r, dict) and r.get("schema") == "samba-ad-ca-csr/v1"
            and type(r.get("enabled")) is bool and type(r.get("apply")) is bool)
    if not r["enabled"]: return None
    fields(r, "schema enabled apply guest_request target directory subject key_bits")
    guest = r["guest_request"]
    validate_ca_bundle(guest["compatibility"], guest)
    target = r["target"]
    fields(target, "fqdn address mac boot_id machine_id interface")
    require(target["fqdn"] == guest["resource"]["name"] and target["mac"] == guest["resource"]["mac"]
            and target["address"] == guest["resource"]["address"].split("/")[0])
    require(str(uuid.UUID(target["boot_id"])) == target["boot_id"])
    hex_value(target["machine_id"], 32)
    require(re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", target["interface"]))
    from tools.samba_ad.pki_contract import path
    path(r["directory"])
    require(type(r["key_bits"]) is int and r["key_bits"] in [3072, 4096])
    require(isinstance(r["subject"], str) and 1 <= len(r["subject"]) <= 128
            and all(32 <= ord(c) <= 126 for c in r["subject"]))
    return target


def _prepare(r, passphrase, ops, check):
    target = validate(r)
    if target is None: return {"state": "disabled", "changed": False}
    if isinstance(ops, Local): ops.layout(r)
    actual = ops.inspect(target)
    require(actual["uid"] == 0 and actual["virtualization"] in ["qemu", "kvm"])
    require(all(actual[k] == target[k] for k in ["fqdn", "mac", "boot_id", "machine_id"])
            and target["address"] in actual["addresses"])
    directory = Path(r["directory"])
    if directory.exists():
        secure_directory(directory)
    else:
        require(not directory.is_symlink())
        secure_directory(directory.parent)
    key_file, csr_file = directory / "intermediate.key.pem", directory / "intermediate.csr.pem"
    require(all(not p.exists() and not p.is_symlink() for p in [key_file, csr_file]))
    if check or not r["apply"]: return {"state": "planned", "changed": False}
    secure_directory(directory)
    require(isinstance(passphrase, bytes) and 20 <= len(passphrase) <= 4096)
    key = rsa.generate_private_key(public_exponent=65537, key_size=r["key_bits"])
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, r["subject"])]))
           .sign(key, hashes.SHA256()))
    exclusive_file(key_file, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.BestAvailableEncryption(passphrase)))
    exclusive_file(csr_file, csr.public_bytes(serialization.Encoding.PEM))
    return {"state": "csr_created", "changed": True, "public_csrs": 1}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--passphrase-file", required=True)
    args = p.parse_args(argv)
    try:
        request = loads(sys.stdin.read())
        result = prepare(request, check=True)
        if args.execute and request.get("enabled") and request.get("apply"):
            value = secure_file(args.passphrase_file, secret=True).read_bytes().rstrip(b"\r\n")
            result = prepare(request, value, check=False)
        print(json.dumps(result)); return 0
    except Exception:
        print('{"state":"error","changed":false,"error":"destination CSR refused (values suppressed)"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
