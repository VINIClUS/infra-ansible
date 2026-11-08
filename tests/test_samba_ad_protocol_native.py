"""Real auth tokens and wire codec over in-memory, isolated protocol peers."""
import hmac
import struct

import pytest
from cryptography.hazmat.primitives import serialization

from test_samba_ad_pki import keys, chain

from tools.samba_ad import protocol as p


@pytest.fixture
def ntlm_server(monkeypatch, tmp_path):
    # Test-only identity, never a domain, service, installed package, or socket.
    spnego = pytest.importorskip("spnego", reason="opt-in pinned native protocol dependencies unavailable")
    path = tmp_path / "ntlm-users"
    path.write_text(":s4-probe@AD.EXAMPLE.INVALID:SYNTHETIC_PASSWORD_123!\n")
    path.chmod(0o600)
    monkeypatch.setenv("NTLM_USER_FILE", str(path))
    monkeypatch.setenv("LM_COMPAT_LEVEL", "3")
    from spnego.channel_bindings import GssChannelBindings
    def server(binding=None):
        return spnego.server(protocol="negotiate", options=spnego.NegotiateOptions.use_negotiate | spnego.NegotiateOptions.use_ntlm,
                             channel_bindings=GssChannelBindings(application_data=binding) if binding else None)
    return server


CREDS = {"username": "s4-probe@AD.EXAMPLE.INVALID", "password": "SYNTHETIC_PASSWORD_123!"}


class LDAPPeer:
    def __init__(self, server, require_signing=False):
        self.server = server; self.pending = b""; self.require_signing = require_signing
        self.received = []; self.ntlm_tokens = []
    def sendall(self, packet):
        self.received.append(packet)
        tag, value = p.element(p.Bytes(packet)); assert tag == 0x30
        value = p.Bytes(value)
        _, mid = p.element(value); _, bind = p.element(value)
        bind = p.Bytes(bind)
        assert p.element(bind) == (2, b"\x03")
        assert p.element(bind) == (4, b"")
        tag, sasl = p.element(bind); assert tag == 0xa3
        sasl = p.Bytes(sasl)
        assert p.element(sasl) == (4, b"GSS-SPNEGO")
        _, token = p.element(sasl)
        self.ntlm_tokens.append(ntlm_payload(token))
        try:
            out = self.server.step(token)
            status = 0 if self.server.complete else 14
            if status == 0 and self.require_signing: status = 8
        except Exception:
            status = 49; out = None
        result = p.ber(10, bytes([status])) + p.ber(4, b"") + p.ber(4, b"")
        if out: result += p.ber(0x87, out)
        self.pending = p.ber(0x30, p.ber(2, mid) + p.ber(0x61, result))
    def recv(self, size):
        # Force partial receives; no OS networking or server is involved.
        out, self.pending = self.pending[:min(size, 7)], self.pending[min(size, 7):]
        return out


@pytest.mark.parametrize("binding,expected", [(b"tls-server-end-point:correct", "accepted"), (None, "rejected"), (b"tls-server-end-point:wrong", "rejected")])
def test_real_ntlm_cbt_valid_missing_wrong(ntlm_server, binding, expected):
    server = ntlm_server(b"tls-server-end-point:correct")
    stream = LDAPPeer(server)
    result = p.ldap_bind(stream, p.Native.ntlm(CREDS, "dc01.example.invalid", "ldap", binding))
    assert result["outcome"] == expected
    assert [struct.unpack_from("<I", token, 8)[0] for token in stream.ntlm_tokens] == [1, 3]
    from spnego._ntlm_raw.messages import Authenticate, NTClientChallengeV2, AvId
    auth = Authenticate.unpack(stream.ntlm_tokens[-1])
    av = NTClientChallengeV2.unpack(auth.nt_challenge_response[16:]).av_pairs
    assert (AvId.channel_bindings in av) == (binding is not None)


def test_plain_ldap_unsigned_result_requires_server_strong_auth_response(ntlm_server):
    stream = LDAPPeer(ntlm_server(), require_signing=True)
    assert p.ldap_bind(stream, p.Native.ntlm(CREDS, "dc01.example.invalid", "ldap")) == {"outcome": "rejected", "proof": "ldap:8"}


class SMBPeer:
    def __init__(self, server, reject_unsigned=False):
        self.server = server; self.pending = b""; self.reject_unsigned = reject_unsigned
        self.commands = []
    def sendall(self, packet):
        assert int.from_bytes(packet[:4], "big") == len(packet) - 4
        packet = packet[4:]; command = struct.unpack_from("<H", packet, 12)[0]
        mid = struct.unpack_from("<Q", packet, 24)[0]; self.commands.append(command)
        status = 0; signed = False
        if command == 0:
            assert packet[64:66] == b"\x24\x00"
            assert packet[-2:] == b"\x10\x02"
            body = struct.pack("<HHHH", 65, 3, 0x210, 0) + b"\0" * 56
            session = 0
        elif command == 1:
            offset, length = struct.unpack_from("<HH", packet, 76)
            token = self.server.step(packet[offset:offset + length])
            status = 0 if self.server.complete else 0xc0000016
            body = struct.pack("<HHHH", 9, 0, 72, len(token or b"")) + (token or b"")
            session = 55
        else:
            assert command == 3 and self.server.complete
            flags = struct.unpack_from("<I", packet, 16)[0]
            if flags & 8:
                wanted = hmac.new(self.server.session_key, packet[:48] + b"\0" * 16 + packet[64:], "sha256").digest()[:16]
                assert hmac.compare_digest(packet[48:64], wanted)
            else:
                assert packet[48:64] == b"\0" * 16
            status = 0xc0000022 if self.reject_unsigned and not flags & 8 else 0
            body = struct.pack("<HBBIII", 16, 1, 0, 0, 0, 0)
            session = 55; signed = True
        response = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 1, status, command, 1,
                               9 if signed else 1, 0, mid, 0, 3, session, b"\0" * 16) + body
        if signed:
            signature = hmac.new(self.server.session_key, response, "sha256").digest()[:16]
            response = response[:48] + signature + response[64:]
        self.pending = len(response).to_bytes(4, "big") + response
    def recv(self, size):
        out, self.pending = self.pending[:size], self.pending[size:]
        return out


@pytest.mark.parametrize("unsigned,outcome", [(False, "accepted"), (True, "rejected")])
def test_smb_control_and_unsigned_tree_connect_use_real_ntlm_keys(ntlm_server, unsigned, outcome):
    peer = SMBPeer(ntlm_server(), reject_unsigned=True)
    result = p.smb_auth(peer, p.Native.ntlm(CREDS, "dc01.example.invalid", "cifs"), "dc01.example.invalid", unsigned=unsigned)
    assert result["outcome"] == outcome
    assert peer.commands == [0, 1, 1, 3]


def test_native_ntlmv1_actually_emits_24_byte_response(ntlm_server):
    # The compatibility variant must affect the token, not merely a config flag.
    from spnego._ntlm_raw.messages import Authenticate
    client = p.Native.ntlm(CREDS, "dc01.example.invalid", "cifs", version=1)
    server = ntlm_server()
    first = client.step(); challenge = server.step(first); authenticate = client.step(challenge)
    from spnego._spnego import unpack_token
    auth = Authenticate.unpack(unpack_token(authenticate).response_token)
    assert len(auth.nt_challenge_response) == 24


def test_unsigned_ldap_tokens_negotiate_neither_sign_nor_seal(ntlm_server):
    from spnego._ntlm_raw.messages import Authenticate, NegotiateFlags
    from spnego._spnego import unpack_token
    client = p.Native.ntlm(CREDS, "dc01.example.invalid", "ldap")
    server = ntlm_server()
    challenge = server.step(client.step())
    auth = Authenticate.unpack(unpack_token(client.step(challenge)).response_token)
    assert not auth.flags & (NegotiateFlags.sign | NegotiateFlags.seal)


def test_untrusted_smb_error_signature_never_counts_as_rejection(ntlm_server):
    class Corrupt(SMBPeer):
        def sendall(self, packet):
            super().sendall(packet)
            if self.commands[-1] == 3:
                self.pending = self.pending[:52] + b"\0" * 16 + self.pending[68:]
    with pytest.raises(ValueError):
        p.smb_auth(Corrupt(ntlm_server(), True), p.Native.ntlm(CREDS, "dc01.example.invalid", "cifs"), "dc01.example.invalid", unsigned=True)


def test_tls_cbt_uses_leaf_of_current_connection_and_wrong_flips_one_byte(chain):
    import hashlib
    leaf = chain[2].public_bytes(serialization.Encoding.DER)
    class TLS:
        def getpeercert(self, binary_form=False):
            assert binary_form; return leaf
    wanted = b"tls-server-end-point:" + hashlib.sha256(leaf).digest()
    assert p.Native.binding(TLS(), "valid") == wanted
    wrong = p.Native.binding(TLS(), "wrong")
    assert wrong[:21] == wanted[:21] and wrong[22:] == wanted[22:] and wrong[21] == wanted[21] ^ 1


def test_ca_pin_drift_precedes_any_network(monkeypatch, chain):
    from test_samba_ad_protocol import request
    r, _ = request()
    class File:
        def read_bytes(self): return chain[0].public_bytes(serialization.Encoding.PEM)
    monkeypatch.setattr(p.domain, "secure_file", lambda *_args, **_kw: File())
    actual_context = p.ssl.create_default_context
    monkeypatch.setattr(p.ssl, "create_default_context", lambda **_kw: actual_context(cadata=File().read_bytes().decode()))
    monkeypatch.setattr(p.Native, "connect", lambda *_: pytest.fail("network after CA pin drift"))
    with pytest.raises(ValueError): p.Native().tls(r)


def ntlm_payload(token):
    from spnego._spnego import unpack_token
    parsed = unpack_token(token)
    return getattr(parsed, "mech_token", None) or getattr(parsed, "response_token", None)


@pytest.mark.parametrize("status", [49, 8])
def test_ldap_early_rejection_is_unmeasured_with_real_type1(ntlm_server, status):
    class Early(LDAPPeer):
        def sendall(self, packet):
            super().sendall(packet)
            self.pending = p.ber(0x30, p.ber(2, b"\x01") + p.ber(0x61,
                p.ber(10, bytes([status])) + p.ber(4, b"") + p.ber(4, b"")))
    peer = Early(ntlm_server())
    with pytest.raises(ValueError):
        p.ldap_bind(peer, p.Native.ntlm(CREDS, "dc01.example.invalid", "ldap"))
    assert [struct.unpack_from("<I", token, 8)[0] for token in peer.ntlm_tokens] == [1]


class RejectSMB(SMBPeer):
    def __init__(self, server, stage, error_body):
        super().__init__(server)
        self.stage = stage; self.error_body = error_body; self.ntlm_tokens = []

    def sendall(self, packet):
        raw = packet[4:]
        if struct.unpack_from("<H", raw, 12)[0] != 1:
            return super().sendall(packet)
        offset, length = struct.unpack_from("<HH", raw, 76)
        token = ntlm_payload(raw[offset:offset + length])
        self.ntlm_tokens.append(token)
        if struct.unpack_from("<I", token, 8)[0] != self.stage:
            return super().sendall(packet)
        mid = struct.unpack_from("<Q", raw, 24)[0]
        response = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 1, 0xc000006d,
            1, 1, 1, 0, mid, 0, 0, 55, b"\0" * 16) + self.error_body
        self.pending = len(response).to_bytes(4, "big") + response


# SMB2.1 ERROR: StructureSize=9, reserved zero, ByteCount=0, required dummy byte.
SMB_ERROR = bytes.fromhex("090000000000000000")


@pytest.mark.parametrize("stage,body", [(1, SMB_ERROR), (1, b""), (3, b""),
    (3, SMB_ERROR[:8]), (3, bytes.fromhex("0900000001000000")),
    (3, bytes.fromhex("080000000000000000")), (3, SMB_ERROR + b"extra"),
    (3, bytes.fromhex("090001000000000000")),
    (3, bytes.fromhex("0900000000000000ff"))])
def test_smb_early_or_malformed_rejection_is_unmeasured(ntlm_server, stage, body):
    client = p.Native.ntlm(CREDS, "dc01.example.invalid", "cifs", version=1)
    peer = RejectSMB(ntlm_server(), stage, body)
    with pytest.raises(ValueError):
        p.smb_auth(peer, client, "dc01.example.invalid")
    assert [struct.unpack_from("<I", token, 8)[0] for token in peer.ntlm_tokens] == ([1] if stage == 1 else [1, 3])


def test_smb_ntlmv1_negative_requires_transmitted_type3_and_valid_error(ntlm_server):
    from spnego._ntlm_raw.messages import Authenticate
    client = p.Native.ntlm(CREDS, "dc01.example.invalid", "cifs", version=1)
    peer = RejectSMB(ntlm_server(), 3, SMB_ERROR)
    assert p.smb_auth(peer, client, "dc01.example.invalid") == {"outcome": "rejected", "proof": "smb:logon_failure"}
    assert [struct.unpack_from("<I", token, 8)[0] for token in peer.ntlm_tokens] == [1, 3]
    assert len(Authenticate.unpack(peer.ntlm_tokens[-1]).nt_challenge_response) == 24


class RepeatNegotiate:
    """Keep a real pinned client, but send its actual Type1 again on round two."""
    def __init__(self, client): self.client = client; self.first = None
    def step(self, incoming=None):
        token = self.client.step(incoming)
        if self.first is None: self.first = token
        return self.first


def test_ldap_round_two_without_authenticate_is_still_unmeasured(ntlm_server):
    class LateReject(LDAPPeer):
        def sendall(self, packet):
            super().sendall(packet)
            if len(self.ntlm_tokens) == 2:
                self.pending = p.ber(0x30, p.ber(2, b"\x02") + p.ber(0x61,
                    p.ber(10, b"\x31") + p.ber(4, b"") + p.ber(4, b"")))
    peer = LateReject(ntlm_server())
    client = RepeatNegotiate(p.Native.ntlm(CREDS, "dc01.example.invalid", "ldap"))
    with pytest.raises(ValueError): p.ldap_bind(peer, client)
    assert [struct.unpack_from("<I", token, 8)[0] for token in peer.ntlm_tokens] == [1, 1]


def test_smb_round_two_without_authenticate_is_still_unmeasured(ntlm_server):
    class LateReject(RejectSMB):
        def sendall(self, packet):
            if self.ntlm_tokens: self.stage = 1
            super().sendall(packet)
    client = RepeatNegotiate(p.Native.ntlm(CREDS, "dc01.example.invalid", "cifs", version=1))
    peer = LateReject(ntlm_server(), 3, SMB_ERROR)
    with pytest.raises(ValueError): p.smb_auth(peer, client, "dc01.example.invalid")
    assert [struct.unpack_from("<I", token, 8)[0] for token in peer.ntlm_tokens] == [1, 1]
