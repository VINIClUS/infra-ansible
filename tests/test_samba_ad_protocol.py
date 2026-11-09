"""S4 source runner: no infrastructure or real credential is used here."""
import importlib.util
import json
import struct
import os
from types import SimpleNamespace

import pytest


def api():
    assert importlib.util.find_spec("tools.samba_ad.protocol"), "native protocol runner missing"
    from tools.samba_ad import protocol
    return protocol


def request():
    from test_samba_ad_domain import request as domain_request
    domain, manifest = domain_request()
    domain["target"]["sid"] = "S-1-5-21-1-2-3"
    c = manifest["resources"]["linux_pilot"]
    return {"schema": "samba-ad-protocol/v1", "enabled": True, "execute": False,
            "domain": domain, "client": {"role": "linux_pilot", "machine_id": "d" * 32,
            "boot_id": "11111111-2222-3333-4444-555555555555", "interface": "ens18",
            "new_owned_review_ref": "git:" + "a" * 40 + ":reviews/new-pilot.json"},
            "server_audit_ref": "git:" + "b" * 40 + ":reviews/installed-s4.json",
            "leaf_sha256": "e" * 64, "username": "s4-probe@" + domain["target"]["realm"],
            "timeout_seconds": 5}, manifest


def test_disabled_and_check_are_inert_before_guard_or_secret_read():
    d = api()
    class Refuse:
        def __getattr__(self, key):
            pytest.fail("inert mode touched runtime: " + key)
    assert d.run({"schema": "samba-ad-protocol/v1", "enabled": False, "execute": False}, None, Refuse())["state"] == "not_run"
    r, manifest = request()
    result = d.run(r, manifest, Refuse())
    assert result["state"] == "not_run"
    assert result["native_protocol_acceptance"] == "pending"


@pytest.mark.parametrize("change", [
    lambda r: r.update(target="192.0.2.9"),
    lambda r: r["client"].update(role="dc01"),
    lambda r: r["domain"]["target"].update(sid=None),
    lambda r: r.update(timeout_seconds=True),
    lambda r: r.update(leaf_sha256="0" * 64),
    lambda r: r["client"].update(new_owned_review_ref="approved"),
    lambda r: r.update(username="administrator@OTHER.INVALID"),
])
def test_closed_contract_refuses_foreign_targets_and_unreviewed_identity(change):
    d = api(); r, manifest = request(); change(r)
    with pytest.raises(ValueError, match="values suppressed"):
        d.run(r, manifest, object())


def test_live_identity_refusal_precedes_credentials_and_measurements():
    d = api(); r, manifest = request(); r["execute"] = True
    class Guard:
        def guard(self, *_): raise ValueError("SENTINEL secret")
        def credentials(self, *_): pytest.fail("read secret after failed guard")
    result = d.run(r, manifest, Guard())
    assert result["state"] == "operational_error"
    assert "SENTINEL" not in json.dumps(result)
    assert all(row["state"] == "not_run" for row in result["cases"].values())


def test_timeout_wrong_credentials_and_unsupported_are_never_negative_passes():
    d = api(); r, manifest = request(); r["execute"] = True
    class Transport:
        def guard(self, *_): pass
        def credentials(self, *_): return {"username": r["username"], "password": "SENTINEL_PASSWORD_123!"}
        def measure(self, case, *_):
            if case == "ldaps_binding_valid": return {"outcome": "accepted", "proof": "authenticated"}
            if case == "ldaps_binding_missing": return {"outcome": "rejected", "proof": "ldap:49"}
            raise TimeoutError("SENTINEL")
    result = d.run(r, manifest, Transport())
    assert result["cases"]["ldaps_binding_missing"]["state"] == "passed"
    assert result["cases"]["ldaps_binding_wrong"]["state"] == "operational_error"
    assert result["native_protocol_acceptance"] == "pending"
    assert "SENTINEL" not in json.dumps(result)


def test_valid_control_failure_blocks_related_negatives():
    d = api(); r, manifest = request(); r["execute"] = True
    class Transport:
        def guard(self, *_): pass
        def credentials(self, *_): return {"username": r["username"], "password": "SYNTHETIC_PASSWORD_123!"}
        def measure(self, case, *_):
            if case == "ldaps_binding_missing": pytest.fail("negative after failed control")
            return {"outcome": "rejected", "proof": "ldap:49"}
    result = d.run(r, manifest, Transport())
    assert result["cases"]["ldaps_binding_valid"]["state"] == "failed"
    assert result["cases"]["ldaps_binding_missing"]["state"] == "not_run"


def test_unknown_adapter_proofs_cannot_become_measured_passes():
    d = api(); r, manifest = request(); r["execute"] = True
    class Transport:
        def guard(self, *_): pass
        def credentials(self, *_): return {"username": r["username"], "password": "SYNTHETIC_PASSWORD_123!"}
        def measure(self, *_): return {"outcome": "accepted", "proof": "config says yes"}
    result = d.run(r, manifest, Transport())
    assert not any(row["state"] == "passed" for row in result["cases"].values())


def test_ber_parser_handles_fragmentation_and_refuses_wrong_id_or_oversize():
    d = api()
    class Stream:
        def __init__(self, data): self.data = bytearray(data)
        def recv(self, size):
            out = self.data[:1]; del self.data[:1]; return bytes(out)
    # LDAP message 1, bindResponse(success), empty matchedDN/diagnostic.
    assert d.ldap_response(Stream(bytes.fromhex("300c02010161070a010004000400")), 1) == (0, b"")
    with pytest.raises(ValueError):
        d.ldap_response(Stream(bytes.fromhex("300c02010261070a010004000400")), 1)
    with pytest.raises(ValueError):
        d.ldap_response(Stream(bytes.fromhex("308400100001")), 1)


def test_smb_response_must_match_command_id_session_and_server_direction():
    d = api()
    header = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 1, 0, 3, 1, 1, 0, 7, 0, 4, 9, b"\0" * 16)
    assert d.smb_response(header + b"\x10\x00", 3, 7, 9)["tree_id"] == 4
    for change in [dict(command=2), dict(message_id=8), dict(session_id=10)]:
        args = dict(command=3, message_id=7, session_id=9); args.update(change)
        with pytest.raises(ValueError): d.smb_response(header + b"\x10\x00", **args)


def test_bounded_worker_cannot_leak_exception_or_hang():
    d = api()
    def fail(): raise RuntimeError("SENTINEL")
    with pytest.raises(ValueError) as error: d.bounded(fail, 1)
    assert "SENTINEL" not in str(error.value)
    def hang():
        import time
        time.sleep(10)
    with pytest.raises(ValueError): d.bounded(hang, 0.05)


def test_credential_fd_is_bounded_closed_and_duplicate_fields_are_refused():
    d = api()
    read, write = os.pipe()
    os.write(write, b'{"username":"fake","password":"SENTINEL","password":"other"}')
    os.close(write)
    with pytest.raises(ValueError): d.Native(read).credentials({"timeout_seconds": 1})
    with pytest.raises(OSError): os.fstat(read)


def test_numeric_endpoint_never_uses_dns_or_supplied_alternate_port(monkeypatch):
    d = api(); r, _ = request()
    class Socket:
        def __init__(self, family, kind):
            assert family == d.socket.AF_INET and kind == d.socket.SOCK_STREAM
        def settimeout(self, timeout): assert timeout == 5
        def connect(self, target): assert target == ("198.51.100.10", 636)
    monkeypatch.setattr(d.socket, "socket", Socket)
    assert isinstance(d.Native.connect(r, 636), Socket)


def test_live_client_identity_drift_refuses_network_before_reading_password(monkeypatch):
    d = api(); r, manifest = request()
    monkeypatch.setattr(d.os, "geteuid", lambda: 0)
    monkeypatch.setattr(d.Path, "read_text", lambda _: "foreign-machine")
    monkeypatch.setattr(d.socket, "socket", lambda *_: pytest.fail("network before identity"))
    with pytest.raises(ValueError): d.Native().guard(r, manifest)


@pytest.mark.parametrize("reason,passed", [("TLSV1_ALERT_PROTOCOL_VERSION", True), ("NO_PROTOCOLS_AVAILABLE", False), ("CERTIFICATE_VERIFY_FAILED", False)])
def test_only_peer_protocol_alert_counts_as_old_tls_rejection(reason, passed):
    d = api(); r, _ = request()
    class Native(d.Native):
        def tls(self, *_):
            error = d.ssl.SSLError("SENTINEL")
            error.reason = reason
            raise error
    if passed:
        assert Native().probe("tls10", r, {}) == {"outcome": "rejected", "proof": "tls:protocol_version"}
    else:
        with pytest.raises(ValueError): Native().probe("tls10", r, {})


def test_cli_does_not_execute_or_read_fd_without_both_opt_ins(monkeypatch, capsys):
    import io
    d = api(); r, manifest = request(); r["execute"] = True
    payload = {"schema": "samba-ad-protocol-wire/v1", "request": r, "manifest": manifest}
    monkeypatch.setattr(d.sys, "stdin", io.StringIO(json.dumps(payload)))
    monkeypatch.setattr(d.Native, "guard", lambda *_: pytest.fail("implicit execution"))
    assert d.main(["--credential-fd", "3"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "not_run"


@pytest.mark.parametrize("context_type,acceptor_type,want", [(18, None, "kerberos:aes256"), (18, 17, "kerberos:aes128"), (23, None, None), (18, 23, None)])
def test_aes_control_uses_observed_native_key_enctype(context_type, acceptor_type, want):
    d = api()
    lucid = SimpleNamespace(protocol=1, cfx_kd=SimpleNamespace(ctx_key_type=context_type, acceptor_subkey_type=acceptor_type))
    if want:
        assert d.aes_proof(lucid) == {"outcome": "accepted", "proof": want}
    else:
        with pytest.raises(ValueError): d.aes_proof(lucid)


def test_smb1_no_dialect_requires_matching_server_packet():
    d = api()
    header = b"\xffSMB\x72" + b"\0" * 4 + b"\x98\x01\x40" + b"\0" * 18 + b"\x01\0"
    reply = header + b"\x01\xff\xff\x00\x00"
    class Stream:
        def __init__(self, packet): self.packet = len(packet).to_bytes(4, "big") + packet
        def sendall(self, packet):
            assert packet[4:9] == b"\xffSMB\x72" and packet[-12:] == b"\x02NT LM 0.12\0"
        def recv(self, size):
            out, self.packet = self.packet[:size], self.packet[size:]; return out
    assert d.smb1(Stream(reply)) == {"outcome": "rejected", "proof": "smb:no_dialect"}
    with pytest.raises(ValueError): d.smb1(Stream(reply[:30] + b"\x02\0" + reply[32:]))


def test_all_measurements_still_require_independent_acceptance_audit():
    d = api(); r, manifest = request(); r["execute"] = True
    class Transport:
        def guard(self, *_): pass
        def credentials(self, *_): return {"username": r["username"], "password": "SYNTHETIC_PASSWORD_123!"}
        def measure(self, case, *_):
            outcome, proofs, _ = d.CASES[case]
            return {"outcome": outcome, "proof": sorted(proofs)[0]}
    result = d.run(r, manifest, Transport())
    assert result["state"] == "measured" and result["native_protocol_acceptance"] == "pending"
    assert "runner_sha256" in result and result["started_utc"] <= result["finished_utc"]


@pytest.mark.parametrize("drift", ["hostname", "machine", "boot", "mac", "ip", "pin"])
def test_local_guard_never_resolves_before_identity_and_public_pin(monkeypatch, drift):
    d = api(); r, manifest = request()
    client = manifest["resources"]["linux_pilot"]
    monkeypatch.setattr(d.os, "geteuid", lambda: 0)
    def read(path):
        return {"/etc/machine-id": "foreign" if drift == "machine" else r["client"]["machine_id"],
            "/proc/sys/kernel/random/boot_id": "foreign" if drift == "boot" else r["client"]["boot_id"],
            "/sys/class/net/ens18/address": "foreign" if drift == "mac" else client["mac"]}[str(path)]
    monkeypatch.setattr(d.Path, "read_text", read)
    monkeypatch.setattr(d.socket, "gethostname", lambda: "foreign" if drift == "hostname" else client["fqdn"])
    def forbidden(*_a, **_kw): pytest.fail("resolver/network before identity and public trust pin")
    for name in ["gethostbyaddr", "gethostbyname", "gethostbyname_ex", "getaddrinfo", "getnameinfo", "socket"]:
        monkeypatch.setattr(d.socket, name, forbidden)
    monkeypatch.setattr(d.subprocess, "run", lambda *_a, **_kw: SimpleNamespace(stdout=json.dumps(
        [{"addr_info": [{"local": "192.0.2.1" if drift == "ip" else client["address"]}]}])))
    monkeypatch.setattr(d.importlib.metadata, "version", lambda _: "0.12.4")
    monkeypatch.setattr(d, "bounded", lambda call, _: call())
    def bad_pin(self, _):
        if drift != "pin": pytest.fail("identity drift reached TLS guard")
        raise ValueError("public pin drift")
    monkeypatch.setattr(d.Native, "tls_identity", bad_pin)
    with pytest.raises(ValueError): d.Native().guard(r, manifest)


@pytest.mark.parametrize("field,value", [("vmid", 12345), ("node", "alternate-node"),
    ("mac", "02:00:00:00:EE:FE"), ("address", "198.51.100.25"),
    ("template", {"vmid": 99998, "node": "template-node", "kind": "qemu", "storage": "other-storage"})])
def test_report_binds_manifest_identity_without_topology(field, value):
    import copy
    d = api(); r, manifest = request(); r["execute"] = True
    changed = copy.deepcopy(manifest); changed["resources"]["linux_pilot"][field] = value
    class Refuse:
        def guard(self, *_): raise ValueError()
    first = d.run(r, manifest, Refuse()); second = d.run(r, changed, Refuse())
    assert first["request_sha256"] == second["request_sha256"]
    assert first.get("manifest_sha256") != second.get("manifest_sha256")
    assert "linux-pilot" not in json.dumps(second) and "alternate-node" not in json.dumps(second)
    reordered = dict(reversed(list(manifest.items())))
    assert first["manifest_sha256"] == d.run(r, reordered, Refuse())["manifest_sha256"]
