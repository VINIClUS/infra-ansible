"""Opt-in S4 protocol measurements from the exact new, owned Linux pilot.

No role/deploy integration. Input/provenance is a privately reviewed trust root;
this helper never promotes its own output into audited S4 acceptance.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import importlib.metadata
import ipaddress
import json
import logging
import multiprocessing
import os
from pathlib import Path
import re
import resource
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

from tools.samba_ad import domain

ERROR = "S4 protocol measurement unavailable (values suppressed)"
MAX_PACKET = 1024 * 1024
# Order is deliberate: each hostile variant requires a successful fresh control.
CASES = {
    "ldaps_binding_valid": ("accepted", {"authenticated"}, None),
    "ldaps_binding_missing": ("rejected", {"ldap:49"}, "ldaps_binding_valid"),
    "ldaps_binding_wrong": ("rejected", {"ldap:49"}, "ldaps_binding_valid"),
    "ldap_unsigned": ("rejected", {"ldap:8"}, "ldaps_binding_valid"),
    "tls10": ("rejected", {"tls:protocol_version"}, "ldaps_binding_valid"),
    "tls11": ("rejected", {"tls:protocol_version"}, "ldaps_binding_valid"),
    "smb_ntlmv2_signed": ("accepted", {"smb:authenticated_signed"}, None),
    "smb_unsigned": ("rejected", {"smb:signature_required"}, "smb_ntlmv2_signed"),
    "smb1": ("rejected", {"smb:no_dialect"}, "smb_ntlmv2_signed"),
    "ntlmv1": ("rejected", {"smb:logon_failure"}, "smb_ntlmv2_signed"),
    "kerberos_aes": ("accepted", {"kerberos:aes128", "kerberos:aes256"}, None),
}


def require(value):
    if not value:
        raise ValueError(ERROR)


def validate(r, manifest):
    try:
        require(r["schema"] == "samba-ad-protocol/v1")
        require(type(r["enabled"]) is bool and type(r["execute"]) is bool)
        if not r["enabled"]:
            domain.fields(r, "schema enabled execute")
            require(r["execute"] is False)
            return
        domain.fields(r, "schema enabled execute domain client server_audit_ref leaf_sha256 username timeout_seconds")
        domain.validate_request(r["domain"], manifest)
        require(r["domain"]["enabled"] is True and r["domain"]["apply"] is False)
        require(r["domain"]["target"]["sid"] is not None)
        domain.fields(r["client"], "role machine_id boot_id interface new_owned_review_ref")
        c = r["client"]
        require(c["role"] == "linux_pilot")
        require(re.fullmatch(r"[a-f0-9]{32}", c["machine_id"]))
        require(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", c["boot_id"]))
        require(re.fullmatch(r"[a-z][a-z0-9]{0,14}", c["interface"]))
        for ref in [c["new_owned_review_ref"], r["server_audit_ref"]]:
            require(re.fullmatch(r"git:[a-f0-9]{40}:[a-zA-Z0-9_./-]+", ref) and ".." not in ref)
        domain.hex_value(r["leaf_sha256"])
        require(re.fullmatch(r"s4-probe[a-z0-9-]*@" + re.escape(r["domain"]["target"]["realm"]), r["username"]))
        require(type(r["timeout_seconds"]) is int and 1 <= r["timeout_seconds"] <= 30)
    except Exception:
        raise ValueError(ERROR) from None


def run(r, manifest, adapter):
    validate(r, manifest)
    result = {"schema": "samba-ad-protocol-report/v1", "state": "not_run",
              "native_protocol_acceptance": "pending",
              "cases": {case: {"state": "not_run"} for case in CASES}}
    if not r["enabled"] or not r["execute"]:
        return result
    # Digests bind the report without publishing private addresses/identifiers.
    result["request_sha256"] = domain.sha(r)
    result["runner_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result["started_utc"] = datetime.now(timezone.utc).isoformat()
    try:
        adapter.guard(r, manifest)
        credentials = adapter.credentials(r)
        domain.fields(credentials, "username password")
        require(credentials["username"] == r["username"])
        require(isinstance(credentials["password"], str) and 14 <= len(credentials["password"]) <= 1024
                and not any(c in credentials["password"] for c in ["\0", "\r", "\n"]))
    except Exception:
        result["state"] = "operational_error"
        result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        return result
    for case, (expected, proofs, control) in CASES.items():
        if control and result["cases"][control]["state"] != "passed":
            continue
        try:
            observed = adapter.measure(case, r, manifest, credentials)
            domain.fields(observed, "outcome proof")
            require(observed["outcome"] in {"accepted", "rejected"})
            # A successful hostile variant is a measured failure. Other errors
            # cannot satisfy a negative, even when their text sounds similar.
            if observed["outcome"] != expected:
                row = {"state": "failed"}
            else:
                require(observed["proof"] in proofs)
                row = {"state": "passed", "proof": observed["proof"]}
        except Exception:
            row = {"state": "operational_error"}
        result["cases"][case] = row
    del credentials
    states = {v["state"] for v in result["cases"].values()}
    result["state"] = "measured" if states == {"passed"} else "failed" if "failed" in states else "operational_error"
    result["finished_utc"] = datetime.now(timezone.utc).isoformat()
    return result


def bounded(call, timeout):
    """Linux child holds native library state/secrets; hard deadline, no output/core."""
    context = multiprocessing.get_context("fork")
    parent, child = context.Pipe(duplex=False)
    def worker():
        parent.close()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        logging.disable(logging.CRITICAL)
        with open(os.devnull, "wb") as sink:
            os.dup2(sink.fileno(), 1); os.dup2(sink.fileno(), 2)
            try:
                child.send((True, call()))
            except BaseException:
                child.send((False, None))
        child.close()
    process = context.Process(target=worker)
    process.start(); child.close()
    try:
        require(parent.poll(timeout))
        ok, value = parent.recv()
        require(ok)
        return value
    finally:
        parent.close()
        if process.is_alive(): process.terminate()
        process.join(timeout=1)
        if process.is_alive(): process.kill(); process.join()


def exact(stream, size):
    require(0 <= size <= MAX_PACKET)
    out = bytearray()
    while len(out) < size:
        chunk = stream.recv(size - len(out))
        require(chunk)
        out.extend(chunk)
    return bytes(out)


def ber(tag, data):
    size = len(data)
    length = bytes([size]) if size < 128 else bytes([0x80 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + data


def element(stream):
    tag, length = exact(stream, 2)
    if length & 128:
        count = length & 127
        require(1 <= count <= 4)
        length = int.from_bytes(exact(stream, count), "big")
        require(length >= 128)
    return tag, exact(stream, length)


class Bytes:
    def __init__(self, value): self.value = value
    def recv(self, size):
        out, self.value = self.value[:size], self.value[size:]
        return out


def ldap_response(stream, message_id):
    tag, packet = element(stream); require(tag == 0x30)
    packet = Bytes(packet)
    tag, mid = element(packet); require(tag == 2 and int.from_bytes(mid, "big") == message_id)
    tag, operation = element(packet); require(tag == 0x61 and not packet.value)
    operation = Bytes(operation)
    tag, status = element(operation); require(tag == 10 and len(status) == 1)
    for _ in range(2):
        tag, _ = element(operation); require(tag == 4)
    token = b""
    if operation.value:
        tag, token = element(operation); require(tag == 0x87)
    require(not operation.value)
    return status[0], token


def ldap_bind(stream, context):
    """Bounded SASL GSS-SPNEGO bind; no simple/anonymous fallback or writes."""
    token = context.step()
    for mid in range(1, 6):
        require(token is not None and len(token) <= MAX_PACKET // 2)
        sasl = ber(0xa3, ber(4, b"GSS-SPNEGO") + ber(4, token))
        stream.sendall(ber(0x30, ber(2, bytes([mid])) + ber(0x60, ber(2, b"\x03") + ber(4, b"") + sasl)))
        status, incoming = ldap_response(stream, mid)
        if status == 0:
            if incoming: context.step(incoming)
            require(context.complete)
            return {"outcome": "accepted", "proof": "authenticated"}
        if status != 14:
            require(status in {8, 49})
            return {"outcome": "rejected", "proof": "ldap:" + str(status)}
        token = context.step(incoming)
    raise ValueError(ERROR)


def smb_header(command, mid, session=0, tree=0, signed=False):
    return struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 1, 0, command, 1, 8 if signed else 0,
                       0, mid, 0, tree, session, b"\0" * 16)


def smb_response(packet, command, message_id, session_id=None):
    require(len(packet) >= 64)
    h = struct.unpack("<4sHHIHHIIQIIQ16s", packet[:64])
    require(h[0] == b"\xfeSMB" and h[1] == 64 and h[4] == command and h[8] == message_id)
    require(h[6] & 1 and not h[6] & 2 and h[7] == 0)
    require(session_id is None or h[11] == session_id)
    return {"status": h[3], "flags": h[6], "tree_id": h[10], "session_id": h[11], "body": packet[64:]}


def smb_exchange(stream, packet):
    stream.sendall(len(packet).to_bytes(4, "big") + packet)
    length = exact(stream, 4)
    require(length[0] == 0)
    return exact(stream, int.from_bytes(length, "big"))


def smb_sign(packet, key):
    return packet[:48] + hmac.new(key, packet[:48] + b"\0" * 16 + packet[64:], hashlib.sha256).digest()[:16] + packet[64:]


def smb_verify(packet, key):
    require(struct.unpack_from("<I", packet, 16)[0] & 8)
    require(hmac.compare_digest(packet[48:64], smb_sign(packet, key)[48:64]))


def smb_auth(stream, context, hostname, unsigned=False):
    # SMB2.1 has a fixed HMAC-SHA256 signing algorithm, avoiding silent fallback
    # to a newer dialect requiring a different signing/key-derivation scheme.
    body = struct.pack("<HHHHI16sQH", 36, 1, 1, 0, 0, os.urandom(16), 0, 0x210)
    response = smb_response(smb_exchange(stream, smb_header(0, 0) + body), 0, 0)
    require(response["status"] == 0 and len(response["body"]) >= 64)
    require(struct.unpack_from("<H", response["body"], 4)[0] == 0x210)
    token = context.step(); session = 0
    for mid in range(1, 6):
        require(token and len(token) < 65536)
        setup = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(token), 0) + token
        response = smb_response(smb_exchange(stream, smb_header(1, mid, session) + setup), 1, mid, session or None)
        session = response["session_id"]
        if response["status"] == 0xc000006d:
            return {"outcome": "rejected", "proof": "smb:logon_failure"}
        require(response["status"] in {0, 0xc0000016})
        data = response["body"]; require(len(data) >= 8 and struct.unpack_from("<H", data)[0] == 9)
        require(struct.unpack_from("<H", data, 2)[0] & 3 == 0)  # no guest/null session
        offset, length = struct.unpack_from("<HH", data, 4)
        require(offset >= 64 and offset - 64 + length <= len(data))
        incoming = data[offset - 64:offset - 64 + length]
        if incoming: token = context.step(incoming)
        if response["status"] == 0:
            require(context.complete and len(context.session_key) >= 16)
            break
    else:
        raise ValueError(ERROR)
    path = ("\\\\" + hostname + "\\NETLOGON").encode("utf-16-le")
    packet = smb_header(3, mid + 1, session, signed=not unsigned) + struct.pack("<HHHH", 9, 0, 72, len(path)) + path
    if not unsigned: packet = smb_sign(packet, context.session_key)
    raw = smb_exchange(stream, packet)
    response = smb_response(raw, 3, mid + 1, session)
    smb_verify(raw, context.session_key)
    if unsigned and response["status"] in {0xc0000022, 0xc000a000}:
        return {"outcome": "rejected", "proof": "smb:signature_required"}
    require(response["status"] == 0)
    return {"outcome": "accepted", "proof": "smb:authenticated_signed"}


def smb1(stream):
    # A single SMB1 dialect, no downgrade fallback, no login or resource writes.
    header = b"\xffSMB\x72" + b"\0" * 4 + b"\x18" + struct.pack("<H", 0x4001) + b"\0" * 18 + b"\x01\0"
    dialect = b"\x02NT LM 0.12\0"
    packet = smb_exchange(stream, header + b"\0" + struct.pack("<H", len(dialect)) + dialect)
    require(len(packet) >= 35 and packet[:5] == b"\xffSMB\x72" and packet[9] & 0x80)
    require(packet[30:32] == b"\x01\0")
    status = struct.unpack_from("<I", packet, 5)[0]
    if status == 0xc00000bb or (status == 0 and packet[32] >= 1 and packet[33:35] == b"\xff\xff"):
        return {"outcome": "rejected", "proof": "smb:no_dialect"}
    require(status == 0)
    return {"outcome": "accepted", "proof": "smb:dialect"}


def aes_proof(lucid):
    require(lucid.protocol == 1 and lucid.cfx_kd is not None)
    # Enctype is observed from the negotiated native context, not config.
    enctype = lucid.cfx_kd.acceptor_subkey_type or lucid.cfx_kd.ctx_key_type
    require(enctype in {17, 18})
    return {"outcome": "accepted", "proof": "kerberos:aes256" if enctype == 18 else "kerberos:aes128"}


class Native:
    def __init__(self, credential_fd=None): self.credential_fd = credential_fd

    def guard(self, r, manifest):
        require(os.geteuid() == 0 and sys.platform == "linux")
        c = r["client"]; declared = manifest["resources"][c["role"]]
        require(Path("/etc/machine-id").read_text().strip() == c["machine_id"])
        require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"])
        require(socket.getfqdn() == declared["fqdn"])
        require(Path("/sys/class/net", c["interface"], "address").read_text().strip().upper() == declared["mac"])
        addresses = subprocess.run(["ip", "-j", "-4", "addr", "show", "dev", c["interface"]], capture_output=True, timeout=5, check=True)
        require(any(a["local"] == declared["address"] for row in json.loads(addresses.stdout) for a in row["addr_info"]))
        require(importlib.metadata.version("pyspnego") == "0.12.4")
        # Validate identity over a fresh trusted TLS connection before reading a password.
        bounded(lambda: self.tls_identity(r), r["timeout_seconds"])

    def credentials(self, r):
        require(type(self.credential_fd) is int and self.credential_fd > 2)
        def read():
            with os.fdopen(os.dup(self.credential_fd), "r") as stream:
                return self.read_credentials(stream)
        try:
            return bounded(read, r["timeout_seconds"])
        finally:
            os.close(self.credential_fd)

    @staticmethod
    def read_credentials(stream):
        # Same duplicate-key rejection as domain.loads, without its schema field.
        value = stream.read(8193); require(len(value) <= 8192)
        def unique(pairs):
            require(len({k for k, _ in pairs}) == len(pairs)); return dict(pairs)
        return json.loads(value, object_pairs_hook=unique)

    @staticmethod
    def connect(r, port):
        address = str(ipaddress.IPv4Interface(r["domain"]["substrate"]["resource"]["address"]).ip)
        # Numeric IPv4 only: no DNS resolution, SRV, redirects or target list.
        stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stream.settimeout(r["timeout_seconds"])
        try: stream.connect((address, port)); return stream
        except BaseException: stream.close(); raise

    def tls(self, r, version=None):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        trust = r["domain"]["pki"]["trust"]
        root_pem = domain.secure_file(trust["root_file"]).read_bytes()
        root = x509.load_pem_x509_certificate(root_pem)
        require(root.fingerprint(hashes.SHA256()).hex() == trust["root_sha256"])
        # Verify the reviewed root bytes, then consume those same bytes (no path race).
        context = ssl.create_default_context(cadata=root_pem.decode("ascii"))
        context.minimum_version = version or ssl.TLSVersion.TLSv1_2
        if version:
            context.maximum_version = version
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        raw = self.connect(r, 636)
        try:
            stream = context.wrap_socket(raw, server_hostname=r["domain"]["target"]["fqdn"])
            require(hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest() == r["leaf_sha256"])
            return stream
        except BaseException: raw.close(); raise

    def tls_identity(self, r):
        with self.tls(r): return True

    @staticmethod
    def binding(stream, mode):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        cert = x509.load_der_x509_certificate(stream.getpeercert(binary_form=True))
        algorithm = cert.signature_hash_algorithm
        name = algorithm.name if algorithm and algorithm.name not in {"md5", "sha1"} else "sha256"
        digest = hashlib.new(name, cert.public_bytes(Encoding.DER)).digest()
        if mode == "wrong": digest = bytes([digest[0] ^ 1]) + digest[1:]
        return b"tls-server-end-point:" + digest

    @staticmethod
    def ntlm(credentials, hostname, service, binding=None, version=2):
        import spnego
        from spnego.channel_bindings import GssChannelBindings
        os.environ["LM_COMPAT_LEVEL"] = "3" if version == 2 else "2"
        # Force maintained Python NTLM implementation; native SSPI/GSS providers
        # can ignore LM_COMPAT_LEVEL or use ambient machine credentials.
        return spnego.client(credentials["username"], credentials["password"], hostname=hostname, service=service,
                             protocol="negotiate", options=spnego.NegotiateOptions.use_negotiate | spnego.NegotiateOptions.use_ntlm,
                             context_req=spnego.ContextReq.no_integrity,
                             channel_bindings=GssChannelBindings(application_data=binding) if binding else None)

    def measure(self, case, r, manifest, credentials):
        return bounded(lambda: self.probe(case, r, credentials), r["timeout_seconds"])

    def probe(self, case, r, credentials):
        hostname = r["domain"]["target"]["fqdn"]
        if case.startswith("tls"):
            try:
                with self.tls(r, ssl.TLSVersion.TLSv1 if case == "tls10" else ssl.TLSVersion.TLSv1_1):
                    return {"outcome": "accepted", "proof": "tls:old"}
            except ssl.SSLError as error:
                require(error.reason == "TLSV1_ALERT_PROTOCOL_VERSION")
                return {"outcome": "rejected", "proof": "tls:protocol_version"}
        if case == "ldap_unsigned":
            with self.connect(r, 389) as stream:
                return ldap_bind(stream, self.ntlm(credentials, hostname, "ldap"))
        if case.startswith("ldaps_binding"):
            with self.tls(r) as stream:
                mode = case.removeprefix("ldaps_binding_")
                binding = None if mode == "missing" else self.binding(stream, mode)
                return ldap_bind(stream, self.ntlm(credentials, hostname, "ldap", binding))
        if case == "kerberos_aes":
            return self.kerberos(r, credentials)
        with self.connect(r, 445) as stream:
            if case == "smb1": return smb1(stream)
            return smb_auth(stream, self.ntlm(credentials, hostname, "cifs", version=1 if case == "ntlmv1" else 2), hostname,
                            unsigned=case == "smb_unsigned")

    def kerberos(self, r, credentials):
        # Private /run directory contains only a public exact-KDC config; tickets
        # and password stay in native API memory. No kinit/argv/keytab/ccache file.
        require(importlib.metadata.version("gssapi") == "1.11.1")
        import gssapi
        from gssapi.raw import acquire_cred_with_password, krb5_export_lucid_sec_context, krb5_set_allowable_enctypes
        realm = r["domain"]["target"]["realm"]
        address = str(ipaddress.IPv4Interface(r["domain"]["substrate"]["resource"]["address"]).ip)
        config = ("[libdefaults]\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n"
                  " dns_canonicalize_hostname = false\n canonicalize = false\n udp_preference_limit = 1\n"
                  " default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
                  " default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
                  " permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
                  f" default_realm = {realm}\n[realms]\n {realm} = {{\n  kdc = {address}:88\n }}\n")
        with tempfile.TemporaryDirectory(prefix="samba-ad-protocol-", dir="/run") as directory:
            path = Path(directory, "krb5.conf"); path.write_text(config); path.chmod(0o600)
            os.environ["KRB5_CONFIG"] = str(path)
            os.environ["KRB5CCNAME"] = "MEMORY:samba-ad-protocol"
            os.environ.pop("KRB5_TRACE", None)
            name = gssapi.Name(credentials["username"], name_type=gssapi.NameType.kerberos_principal)
            krb5 = gssapi.OID.from_int_seq("1.2.840.113554.1.2.2")
            raw = acquire_cred_with_password(name, credentials["password"].encode(), mechs=[krb5], usage="initiate").creds
            krb5_set_allowable_enctypes(raw, [18, 17])
            creds = gssapi.Credentials(base=raw)
            with self.tls(r) as stream:
                context = gssapi.SecurityContext(name=gssapi.Name("ldap@" + r["domain"]["target"]["fqdn"], name_type=gssapi.NameType.hostbased_service),
                    creds=creds, mech=gssapi.OID.from_int_seq("1.3.6.1.5.5.2"), usage="initiate",
                    channel_bindings=gssapi.raw.ChannelBindings(application_data=self.binding(stream, "valid")))
                measured = ldap_bind(stream, context)
                require(measured["outcome"] == "accepted")
                lucid = krb5_export_lucid_sec_context(context, 1)
                return aes_proof(lucid)


def main(argv=None):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--credential-fd", type=int)
    args = parser.parse_args(argv)
    try:
        payload = domain.loads(sys.stdin.read(MAX_PACKET + 1))
        domain.fields(payload, "schema request manifest")
        require(payload["schema"] == "samba-ad-protocol-wire/v1")
        r = payload["request"]
        validate(r, payload["manifest"])
        if not args.execute: r = dict(r, execute=False)
        result = run(r, payload["manifest"], Native(args.credential_fd))
        print(json.dumps(result, sort_keys=True))
        return 0 if result["state"] in {"not_run", "measured"} else 1
    except Exception:
        print(ERROR, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
