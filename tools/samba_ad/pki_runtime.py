"""Host-local S3 issuer client and transactional generation activation.

No package acquisition, root signing, inventory discovery or arbitrary reload
commands. Service/HTTP/tool transports are injectable; verification is real.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import uuid

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from tools.samba_ad.pki import LIFETIME, require, rotation_due, verify_leaf
from tools.samba_ad.pki_contract import loads, public_jwk, validate_request
from tools.samba_ad.pki_files import atomic_file, exclusive_file, secure_directory, secure_file, sync_dir


def consumer_conf(r, generation):
    cert, key = str(generation / "fullchain.pem"), str(generation / "key.pem")
    if r["adapter"]["kind"] == "nginx":
        return f"ssl_certificate {cert};\nssl_certificate_key {key};\n".encode()
    require(r["adapter"]["kind"] in ["samba", "pending"])
    return (f"tls certfile = {cert}\ntls keyfile = {key}\n"
            f"tls cafile = {r['trust']['root_file']}\n").encode()


class Store:
    def __init__(self, r):
        self.r = r
        root = secure_directory(r["state_dir"], exact=True)
        self.directory = root / r["profile"]
        if not self.directory.exists():
            self.directory.mkdir(mode=0o700); sync_dir(root)
        secure_directory(self.directory, exact=True)
        self.generations = self.directory / "generations"
        if not self.generations.exists():
            self.generations.mkdir(mode=0o700); sync_dir(self.directory)
        secure_directory(self.generations, exact=True)
        self.active = self.directory / "active.conf"

    @contextmanager
    def lock(self):
        p = self.directory / "rotation.lock"
        fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            secure_file(p, secret=True)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def current(self):
        if not self.active.is_symlink():
            require(not self.active.exists())
            return None
        link = self.active.readlink()
        require(re.fullmatch(r"generations/[a-f0-9]{32}/consumer\.conf", str(link)))
        generation = self.directory / link.parent
        secure_directory(generation, exact=True)
        value = secure_file(generation / "consumer.conf", secret=True).read_bytes()
        require(value == consumer_conf(self.r, generation))
        return {"link": str(link), "generation": generation, "digest": hashlib.sha256(value).hexdigest()}

    def point(self, link):
        temp = self.directory / (".active-" + uuid.uuid4().hex)
        os.symlink(link, temp)
        os.replace(temp, self.active)
        sync_dir(self.directory)

    def new(self):
        generation = self.generations / uuid.uuid4().hex
        generation.mkdir(mode=0o700); sync_dir(self.generations)
        return generation

    def discard(self, generation):
        require(generation.parent == self.generations and re.fullmatch(r"[a-f0-9]{32}", generation.name))
        current = self.current()
        require(current is None or current["generation"] != generation)
        secure_directory(generation, exact=True)
        allowed = {"key.pem", "csr.pem", "cert.pem", "fullchain.pem", "consumer.conf"}
        entries = list(generation.iterdir())
        require(all(p.name in allowed for p in entries))
        for p in entries: secure_file(p, secret=True)
        for p in entries: p.unlink()
        generation.rmdir(); sync_dir(self.generations)

    def signals(self, info=None, success=False, rotated=False):
        now = int(time.time())
        name = self.r["profile"]
        last = self.directory / "last_rotation.json"
        if rotated:
            atomic_file(last, json.dumps({"at": now}).encode())
        lines = [f'samba_ad_pki_last_check_seconds{{profile="{name}"}} {now}',
                 f'samba_ad_pki_last_attempt_success{{profile="{name}"}} {int(success)}']
        if info:
            lines += [f'samba_ad_pki_certificate_not_after_seconds{{profile="{name}"}} {info["not_after"]}',
                      f'samba_ad_pki_rotation_deadline_seconds{{profile="{name}"}} {info["rotation_deadline"]}']
            if success:
                stamp = loads(secure_file(last, secret=True).read_bytes())["at"]
                require(type(stamp) is int and stamp <= now)
                lines.append(f'samba_ad_pki_last_rotation_success_seconds{{profile="{name}"}} {stamp}')
        atomic_file(self.directory / "status.prom", ("\n".join(lines) + "\n").encode())


def _b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def claims_for(r, csr, now):
    der = x509.load_pem_x509_csr(csr).public_bytes(serialization.Encoding.DER)
    return {"iss": "s3-" + r["profile"], "sub": r["target"]["fqdn"], "sans": [r["target"]["fqdn"]],
            "aud": [r["issuer"]["url"]], "iat": now, "nbf": now, "exp": now + 300,
            "jti": secrets.token_hex(32), "cnf": {"x5rt#S256": _b64(hashlib.sha256(der).digest())}}


def verify_authorization(token, claims, jwk):
    try:
        require(isinstance(token, str) and len(token) <= 8192)
        parts = token.split("."); require(len(parts) == 3)
        decode = lambda v: base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
        header = loads(decode(parts[0]))
        require(header == {"alg": "ES256", "kid": jwk["kid"], "typ": "JWT"})
        require(loads(decode(parts[1])) == claims)
        signature = decode(parts[2]); require(len(signature) == 64)
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        public_jwk(jwk).verify(der, (parts[0] + "." + parts[1]).encode(), ec.ECDSA(hashes.SHA256()))
    except Exception:
        raise ValueError("S3 authorization rejected (values suppressed)") from None


def candidate_info(r, generation, now, previous=None):
    def read(name): return secure_file(generation / name, secret=True).read_bytes()
    trust = r["trust"]
    info = verify_leaf(read("cert.pem"), secure_file(trust["issuer_file"]).read_bytes(),
                       secure_file(trust["root_file"]).read_bytes(), read("key.pem"), r["target"]["fqdn"],
                       r["profile"], now, trust["root_sha256"], trust["issuer_sha256"], previous)
    require(read("fullchain.pem") == read("cert.pem") + secure_file(trust["issuer_file"]).read_bytes())
    return info


def run(r: dict, manifest: dict, ops=None, check: bool = True) -> dict:
    validate_request(r, manifest)
    if not r["enabled"]:
        return {"state": "disabled", "changed": False}
    ops = ops or LocalOps()
    available = ops.preflight(r)
    if check or not r["apply"] or r["action"] == "preflight":
        return {"state": "planned", "changed": False, "profiles": 1}
    if r["action"] == "rotate" and (r["adapter"]["kind"] == "pending" or available is False):
        return {"state": "integration_pending", "changed": False, "profiles": 1}
    if r["action"] == "auth_prepare":
        return ops.prepare_auth(r)
    store = Store(r)
    with store.lock():
        prior = store.current()
        if r["expected_active"] == "managed":
            require(prior is not None)  # Only canonical, validated own generation; never adopt a file.
        else:
            require((prior["digest"] if prior else None) == r["expected_active"])
        now = ops.now()
        prior_info = candidate_info(r, prior["generation"], now) if prior else None
        if prior_info and r["action"] == "rotate" and not rotation_due(prior_info["not_before"], prior_info["not_after"], now):
            require(ops.observe(r, prior_info["certificate_sha256"]) == prior_info["certificate_sha256"])
            store.signals(prior_info, success=True)
            return {"state": "current", "changed": False, "profiles": 1}
        generation = store.new()
        switched = False
        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            exclusive_file(generation / "key.pem", key.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, r["target"]["fqdn"])]))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(r["target"]["fqdn"])]), critical=False)
                .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
            exclusive_file(generation / "csr.pem", csr)
            claims = claims_for(r, csr, now)
            token = ops.authorize(r, claims)
            verify_authorization(token, claims, r["credential"]["public_jwk"])
            cert, issuer = ops.issue(r, csr, token)
            require(issuer == secure_file(r["trust"]["issuer_file"]).read_bytes())
            exclusive_file(generation / "cert.pem", cert)
            exclusive_file(generation / "fullchain.pem", cert + issuer)
            info = candidate_info(r, generation, ops.now(), prior_info["spki_sha256"] if prior_info else None)
            require(now - 60 <= info["not_before"] <= ops.now() and info["not_after"] >= now + LIFETIME - 60)
            exclusive_file(generation / "consumer.conf", consumer_conf(r, generation))
            if r["action"] == "stage":
                store.signals(info, success=False)
                return {"state": "staged", "changed": True, "profiles": 1, "integration_pending": True,
                        "generation_ref": generation.name}
            require(store.current() == prior)
            store.point("generations/" + generation.name + "/consumer.conf")
            switched = True
            ops.reload(r)
            require(ops.observe(r, info["certificate_sha256"]) == info["certificate_sha256"])
            store.signals(info, success=True, rotated=True)
            switched = False  # Commit point: cleanup failure must not roll back to a partly deleted generation.
            if prior:
                try:
                    store.discard(prior["generation"])
                except Exception:
                    store.signals(info, success=False)
                    return {"state": "active_cleanup_pending", "changed": True, "profiles": 1}
            return {"state": "active", "changed": True, "profiles": 1}
        except Exception:
            if switched:
                if prior:
                    store.point(prior["link"])
                    try:
                        candidate_info(r, prior["generation"], ops.now())
                        ops.reload(r)
                        require(ops.observe(r, prior_info["certificate_sha256"]) == prior_info["certificate_sha256"])
                    except Exception:
                        store.signals(prior_info, success=False)
                        raise ValueError("S3 activation/reversion degraded (values suppressed)") from None
                else:
                    store.active.unlink(); sync_dir(store.directory)
                    ops.stop(r)
            store.discard(generation)
            store.signals(prior_info, success=False)
            raise ValueError("S3 rotation failed (values suppressed)") from None


def _command(argv, stdin=None, timeout=15):
    result = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout, check=False)
    require(result.returncode == 0)
    return result.stdout


def host_snapshot(interface):
    data = loads(_command(["ip", "-j", "address", "show", "dev", interface], timeout=5))
    return {"uid": os.geteuid(), "fqdn": socket.gethostname(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "machine_id": Path("/etc/machine-id").read_text().strip(),
            "mac": Path("/sys/class/net", interface, "address").read_text().strip().upper(),
            "addresses": [a["local"] for row in data for a in row["addr_info"] if a["family"] == "inet"],
            "virtualization": _command(["systemd-detect-virt"], timeout=5).decode().strip()}


class LocalOps:
    def now(self): return int(time.time())

    def identity_tools(self, r):
        actual = host_snapshot(r["target"]["interface"])
        require(actual["uid"] == 0)
        for field in ["fqdn", "boot_id", "machine_id", "mac"]:
            require(actual[field] == r["target"][field])
        require(r["target"]["address"] in actual["addresses"])
        require(actual["virtualization"] in (["kvm", "qemu"] if r["target"]["kind"] == "qemu" else ["lxc"]))
        directory = Path(r["state_dir"])
        if directory.exists():
            secure_directory(directory, exact=True)
        else:
            require(not directory.is_symlink())
            secure_directory(directory.parent)
        require(cryptography.__version__ == r["tools"]["cryptography"]["version"])
        for name, artifact in r["tools"].items():
            if name == "cryptography": continue
            binary = secure_file(artifact["path"])
            require(hashlib.sha256(binary.read_bytes()).hexdigest() == artifact["sha256"])
            require(name == "njs" or binary.stat().st_mode & 0o111)

    def preflight(self, r):
        self.identity_tools(r)
        for field in ["root_file", "issuer_file"]:
            cert = x509.load_pem_x509_certificate(secure_file(r["trust"][field]).read_bytes())
            require(cert.fingerprint(hashes.SHA256()).hex() == r["trust"][field.replace("_file", "_sha256")])
        secure_file(r["credential"]["password_ref"], secret=True)
        if r["action"] != "auth_prepare": secure_file(r["credential"]["auth_key_ref"], secret=True)
        if r["adapter"]["kind"] == "samba":
            managed = Path(r["state_dir"], r["profile"], "active.conf").is_symlink()
            return managed and subprocess.run(["systemctl", "is-active", "--quiet", "samba-ad-dc.service"],
                                              capture_output=True, timeout=5, check=False).returncode == 0
        return True

    def prepare_auth(self, r):
        store = Store(r)
        with store.lock():
            key = store.directory / "auth.jwe"
            public = store.directory / "auth.public.json"
            if key.exists() or public.exists():
                secure_file(key, secret=True); secure_file(public, secret=True)
                public_jwk(loads(public.read_bytes()))
                return {"state": "auth_present", "changed": False, "public_keys": 1}
            _command([r["tools"]["step"]["path"], "crypto", "jwk", "create", str(public), str(key),
                      "--kty", "EC", "--alg", "ES256", "--use", "sig", "--password-file", r["credential"]["password_ref"]])
            secure_file(key, secret=True); secure_file(public, secret=True)
            public_jwk(loads(public.read_bytes()))
            return {"state": "auth_created", "changed": True, "public_keys": 1}

    def authorize(self, r, claims):
        # v0.31.0 validates CLI flags even when complete claims arrive on stdin.
        # --subtle disables only those CLI requirements. Payload wins over defaults;
        # run() verifies the full returned claims/signature before contacting the CA.
        return _command([r["tools"]["step"]["path"], "crypto", "jwt", "sign", "-", "--subtle", "--alg", "ES256",
                         "--key", r["credential"]["auth_key_ref"], "--password-file", r["credential"]["password_ref"]],
                        json.dumps(claims, separators=(",", ":")).encode()).decode().strip()

    def issue(self, r, csr, token):
        name = r["issuer"]["url"].split("/")[2]
        local = r["issuer"]["transport"] == "local_loopback"
        port = r["issuer"]["local_port"] if local else 443
        context = ssl.create_default_context(cafile=r["trust"]["root_file"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = http.client.HTTPSConnection(name, port=port, context=context, timeout=10)
        try:
            if local:
                conn.sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=3), server_hostname=name)
            body = json.dumps({"csr": csr.decode("ascii"), "ott": token}, separators=(",", ":"))
            conn.request("POST", "/1.0/sign", body=body, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            require(response.status == 201)
            value = response.read(32769); require(len(value) <= 32768)
            data = loads(value)
            require(isinstance(data["certChain"], list) and len(data["certChain"]) == 2
                    and data["crt"] == data["certChain"][0])
            return data["crt"].encode("ascii"), data["certChain"][1].encode("ascii")
        finally:
            conn.close()

    def reload(self, r):
        if r["adapter"]["kind"] == "nginx":
            _command([r["tools"]["nginx"]["path"], "-t", "-c", "/etc/samba-ad-pki/nginx.conf"])
            _command(["systemctl", "reload-or-restart", "samba-ad-pki-nginx.service"])
        else:
            require(r["adapter"]["kind"] == "samba")
            _command(["systemctl", "restart", "samba-ad-dc.service"])

    def observe(self, r, _expected):
        context = ssl.create_default_context(cafile=r["trust"]["root_file"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((r["target"]["address"], r["adapter"]["port"]), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=r["target"]["fqdn"]) as peer:
                return hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest()

    def stop(self, r):
        # Never stop a DC with no managed previous generation.
        require(r["adapter"]["kind"] == "nginx")
        _command(["systemctl", "stop", "samba-ad-pki-nginx.service"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--request-file")
    args = parser.parse_args(argv)
    try:
        payload = loads(secure_file(args.request_file, secret=True).read_bytes() if args.request_file else sys.stdin.read())
        require(set(payload) == {"request", "manifest"})
        result = run(payload["request"], payload["manifest"], check=not args.execute)
        print(json.dumps(result))
        return 0
    except Exception:
        print('{"state":"error","changed":false,"error":"S3 precondition or rotation failed (values suppressed)"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
