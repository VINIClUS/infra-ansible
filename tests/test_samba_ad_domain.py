"""S4 guard boundaries: no host mutation or credential read on negative paths."""
import copy
import importlib.util
from pathlib import Path
import pytest

MODULE = "tools.samba_ad.domain"


def api():
    assert importlib.util.find_spec(MODULE) is not None, "S4 domain implementation missing"
    from tools.samba_ad import domain
    return domain


def test_rejects_duplicate_json_and_suppresses_secret_values():
    d = api()
    for payload in ['{"schema":1,"schema":2}', '{"secret":"SENTINEL_PASSWORD"}', 'NaN']:
        with pytest.raises(ValueError) as error:
            d.loads(payload)
        assert "SENTINEL" not in str(error.value)


def test_closed_request_even_when_disabled():
    d = api()
    assert d.validate_request({"schema": "samba-ad-domain/v1", "enabled": False, "apply": False}, None) == {"state": "disabled"}
    with pytest.raises(ValueError):
        d.validate_request({"schema": "samba-ad-domain/v1", "enabled": False, "apply": False, "adminpass": "SENTINEL"}, None)


def test_forest_guard_refuses_partial_or_foreign_and_reexec_drift():
    d = api()
    base = {"realm": "AD.EXAMPLE.INVALID", "netbios": "EXAMPLE", "fqdn": "dc01.ad.example.invalid", "sid": None}
    assert d.forest_action(base, None, False) == "provision"
    with pytest.raises(ValueError): d.forest_action(base, None, True)
    observed = dict(base, sid="S-1-5-21-1-2-3", domain_level=7, forest_level=7, schema_version=88)
    with pytest.raises(ValueError): d.forest_action(base, observed, True)
    expected = dict(base, sid=observed["sid"])
    assert d.forest_action(expected, observed, True) == "current"
    for field, value in [("sid", "S-1-5-21-9-8-7"), ("realm", "OTHER.INVALID"), ("schema_version", 89), ("domain_level", 6)]:
        with pytest.raises(ValueError): d.forest_action(expected, dict(observed, **{field: value}), True)
    with pytest.raises(ValueError): d.forest_action(expected, None, False)


def test_protocol_config_rejects_injection_and_sets_strong_auth():
    d = api()
    config = d.smb_conf("AD.EXAMPLE.INVALID", "EXAMPLE", "dc01", ["192.0.2.53"])
    for line in ["server min protocol = SMB2_02", "server signing = mandatory", "ntlm auth = ntlmv2-only", "ldap server require strong auth = yes", "tls priority = NORMAL:-VERS-TLS1.0:-VERS-TLS1.1", "include = /var/lib/samba-ad-pki/dc01/active.conf"]:
        assert line in config
    assert "allow_sasl" not in config
    with pytest.raises(ValueError): d.smb_conf("AD.INVALID\nfoo = bar", "EXAMPLE", "dc01", ["192.0.2.53"])


def test_password_policy_is_exact_and_reversible_is_off():
    p = api().PASSWORD_POLICY
    assert p == {"minPwdLength": 14, "pwdHistoryLength": 30, "minPwdAge": -864000000000, "maxPwdAge": 0, "pwdProperties": 1, "lockoutThreshold": 10, "lockoutDuration": -9000000000, "lockOutObservationWindow": -9000000000}


def test_check_and_reexec_do_not_read_credential_or_provision():
    d = api()
    class Fake:
        def __init__(self): self.calls = []
        def inspect(self, request): self.calls.append("inspect"); return "provision"
        def provision(self, request): self.calls.append("provision")
        def harden(self, request): self.calls.append("harden")
        def verify(self, request): self.calls.append("verify"); return {"state": "current", "changed": False}
    fake = Fake()
    assert d.execute({"apply": False}, fake) == {"state": "checked", "changed": False}
    assert fake.calls == ["inspect"]
    class Current(Fake):
        def inspect(self, request): self.calls.append("inspect"); return "current"
    current = Current()
    assert d.execute({"apply": True}, current)["state"] == "current"
    assert current.calls == ["inspect", "verify"]


def test_live_guard_failure_precedes_every_mutation():
    d = api()
    class Refuse:
        def inspect(self, request): raise ValueError("drift")
        def provision(self, request): pytest.fail("mutation after rejected guard")
    with pytest.raises(ValueError): d.execute({"apply": True}, Refuse())


def request():
    from test_samba_ad_compatibility import bundle, reseal, sha
    from test_samba_ad_pki_contract import request as pki_request
    substrate = bundle()
    substrate.update(apply=False, action="present", boot=True, expected_digest="a" * 40)
    pki, manifest = pki_request()
    for name in ["dc01", "dc02"]:
        resource = manifest["resources"][name]
        resource["kind"] = "qemu"; resource["template"]["kind"] = "qemu"
        for key in ["unprivileged", "nesting", "apparmor"]: resource.pop(key)
    c = manifest["resources"]["dc01"]
    for key in ["vmid", "node", "mac"]: substrate["resource"][key] = c[key]
    substrate["resource"]["address"] = c["address"] + "/25"
    data = substrate["compatibility"]["data"]
    data["choice"]["target_sha256"] = sha({k: substrate[k] for k in ["owner", "scope", "resource", "template", "firewall"]})
    reseal(substrate)
    pki["target"]["kind"] = "qemu"
    pki["target"]["spec_sha256"] = data["choice"]["target_sha256"]
    pki["adapter"] = {"kind": "samba", "port": 636}
    import json
    pins = {row["Package"]: row["Version"] for row in json.loads((Path(__file__).parent / "fixtures/samba_ad_vendor_runtime.json").read_text())}
    r = {"schema": "samba-ad-domain/v1", "enabled": True, "apply": False,
         "target": {"realm": manifest["domain"]["realm"], "netbios": manifest["domain"]["netbios"], "fqdn": c["fqdn"], "sid": None},
         "substrate": substrate, "pki": pki, "generation": "a" * 32,
         "identity": {"boot_id": pki["target"]["boot_id"], "machine_id": pki["target"]["machine_id"], "config_sha256": "c" * 64},
         "source": {"directory": "/var/lib/samba-ad-source", "inrelease_sha256": "a" * 64, "packages_sha256": "b" * 64,
                    "key_sha256": "95ab9a408a3e94564f5a9bfb6e82c9dc371f32e92004ee98acbf64b431c93e81", "fingerprint": "46C910D6BFCA32BC87DE5173EE5618DB12523D4B", "packages": pins, "verified_utc": "2026-11-08T12:00:00Z", "advisory_review_ref": "git:" + "a" * 40 + ":reviews/advisories.json"},
         "provenance": {"reviewed_config_revision": "a" * 40, "review_ref": "git:" + "b" * 40 + ":reviews/s4.json"}}
    return r, manifest


def test_binds_existing_two_host_qualification_and_pki_identity():
    d = api(); r, manifest = request()
    assert d.validate_request(r, manifest) == {"state": "validated"}
    for field, value in [("fqdn", "dc02.ad.example.invalid"), ("realm", "OTHER.INVALID")]:
        bad = copy.deepcopy(r); bad["target"][field] = value
        with pytest.raises(ValueError): d.validate_request(bad, manifest)
    bad = copy.deepcopy(r); bad["substrate"]["compatibility"]["data"]["report"]["qualification"] = "pending"
    with pytest.raises(ValueError): d.validate_request(bad, manifest)
    bad = copy.deepcopy(r); bad["pki"]["target"]["spec_sha256"] = "f" * 64
    with pytest.raises(ValueError): d.validate_request(bad, manifest)


def test_provision_secret_stays_in_api_memory_not_argv_or_logs(monkeypatch, capsys):
    import sys
    import types
    d = api(); calls = []
    samba = types.ModuleType("samba"); samba.version = "4.25.1"; samba.check_password_quality = lambda password: True
    monkeypatch.setitem(sys.modules, "samba", samba)
    auth = types.ModuleType("samba.auth"); auth.system_session = lambda: object()
    dsdb = types.ModuleType("samba.dsdb"); dsdb.DS_DOMAIN_FUNCTION_2016 = 7
    provision = types.ModuleType("samba.provision")
    def create(logger, session, **kwargs):
        calls.append(kwargs)
        print(kwargs["adminpass"])
        print(kwargs["adminpass"], file=sys.stderr)
    provision.provision = create
    for module in [auth, dsdb, provision]: monkeypatch.setitem(sys.modules, module.__name__, module)
    class Protected:
        def read_text(self): return "SENTINEL_PASSWORD_123!\n"
    def read_secret(path, secret=False):
        assert path == "/run/samba-ad-domain-credentials/dc01/administrator" and secret
        return Protected()
    monkeypatch.setattr(d, "secure_file", read_secret)
    monkeypatch.setattr(d, "command", lambda *args: pytest.fail("provision must not pass credential to subprocess"))
    class Native(d.Native):
        def inspect(self, request): return "provision"
        def database(self): return object()
        def prepare_config(self, request): pass
    r = {"target": {"realm": "AD.EXAMPLE.INVALID", "netbios": "EXAMPLE"}, "substrate": {"resource": {"address": "198.51.100.10/25"}}}
    Native({}).provision(r)
    assert calls[0]["adminpass"] == "SENTINEL_PASSWORD_123!"
    assert calls[0]["base_schema"] == "2019" and calls[0]["dom_for_fun_level"] == 7 and not calls[0]["useeadb"]
    assert calls[0]["skip_sysvolacl"] is False and calls[0]["plaintext_secrets"] is False
    assert "domainsid" not in calls[0]
    output = capsys.readouterr()
    assert "SENTINEL" not in output.out + output.err


def test_canonical_s1_live_preflight_only_reads_existing_qualified_guest():
    from tools.samba_ad import guest
    from test_samba_ad_guest import Fake
    r, _ = request(); substrate = r["substrate"]
    class ReadFake(Fake):
        def get(self, path, **params):
            if path in ["/nodes/node-a/status", "/nodes/node-b/status"]:
                self.calls.append(("get", path, params))
                return {"kversion": "test-kernel", "pveversion": "test-pve"}
            return super().get(path, **params)
        def mutate(self, *args, **kwargs): pytest.fail("read-only bridge mutated PVE")
        def firewall(self, node, kind, vmid, text, apply):
            assert apply is False
            return super().firewall(node, kind, vmid, text, apply)
    cluster = ReadFake(); cluster.kind = "qemu"
    c = substrate["resource"]; vmid = c["vmid"]
    cluster.guests[vmid] = dict(guest.desired_config(substrate), node=c["node"], digest=substrate["expected_digest"],
                                scsi0=c["storage"] + ":vm-" + str(vmid) + "-disk-0,size=64G", status="running")
    cluster.fw[vmid] = guest.firewall_text(substrate)
    assert api().substrate_preflight(substrate, cluster) == {"state": "verified", "changed": False}
    assert all(method in ["get", "firewall", "enforce"] for method, _, _ in cluster.calls)
    for key, value in [("digest", "f" * 40), ("description", "foreign")]:
        original = cluster.guests[vmid][key]; cluster.guests[vmid][key] = value
        with pytest.raises(ValueError): api().substrate_preflight(substrate, cluster)
        cluster.guests[vmid][key] = original
