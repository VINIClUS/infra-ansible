"""Inert defaults and host/profile/reference boundaries, synthetic identities."""
import copy
import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def module():
    path = ROOT / "tools/samba_ad/pki_contract.py"
    assert path.is_file(), "S3 request contract missing"
    spec = importlib.util.spec_from_file_location("pki_contract", path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def request():
    manifest = yaml.safe_load((ROOT / "contracts/samba_ad/example.yml").read_text())
    r = {"schema": "samba-ad-pki/v1", "enabled": True, "apply": True, "action": "auth_prepare",
         "profile": "dc01", "state_dir": "/var/lib/samba-ad-pki",
         "target": {"role": "dc01", "fqdn": "dc01.ad.example.invalid", "kind": "lxc",
                    "address": "198.51.100.10", "mac": "02:00:5E:70:00:01", "interface": "eth0",
                    "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "machine_id": "a" * 32,
                    "spec_sha256": "b" * 64},
         "trust": {"root_file": "/etc/samba-ad-pki/root.pem", "issuer_file": "/etc/samba-ad-pki/issuer.pem",
                   "root_sha256": "a" * 64, "issuer_sha256": "b" * 64},
         "credential": {"auth_key_ref": "/var/lib/samba-ad-pki/dc01/auth.jwe",
                        "password_ref": "/run/credentials/s3-dc01/passphrase", "public_jwk": None},
         "issuer": {"url": "https://ca.ad.example.invalid/1.0/sign", "transport": "public", "local_port": None},
         "tools": {"step": {"path": "/usr/bin/step", "sha256": "c" * 64, "version": "0.31.0",
                            "provenance_ref": "git:" + "a" * 40 + ":reviews/artifacts.json"},
                   "cryptography": {"version": "46.0.5", "provenance_ref": "git:" + "a" * 40 + ":reviews/artifacts.json"}},
         "adapter": {"kind": "pending", "port": None}, "expected_active": None,
         "provenance": {"private_revision": "a" * 40, "review_ref": "git:" + "a" * 40 + ":reviews/s3.json",
                        "substrate_audit_sha256": "b" * 64}}
    return r, manifest


def test_disabled_empty_contract_does_not_require_operational_fields():
    assert module().validate_request({"schema": "samba-ad-pki/v1", "enabled": False, "apply": False}, {}) == {"state": "disabled"}


def test_inert_snapshot_binds_host_and_individual_certificate_profile():
    r, manifest = request()
    p = module().validate_request(r, manifest)
    assert p["sans"] == ["dc01.ad.example.invalid"] and p["eku"] == ["serverAuth"]


def test_ca_frontend_rotation_requires_pinned_nginx_and_matching_njs_artifacts():
    from test_samba_ad_pki_ca_config import request as ca_config
    ca = ca_config()
    r, manifest = request()
    c = manifest["resources"]["ca"]
    r.update(profile="ca", action="rotate", adapter={"kind": "nginx", "port": 443})
    r["target"].update(role="ca", fqdn=c["fqdn"], kind="qemu", address=c["address"], mac=c["mac"])
    r["credential"]["auth_key_ref"] = "/var/lib/samba-ad-pki/ca/auth.jwe"
    r["credential"]["public_jwk"] = ca["registry"]["ca"]
    for key in ["nginx", "njs"]: r["tools"][key] = ca["tools"][key]
    assert module().validate_request(r, manifest)["eku"] == ["serverAuth"]
    del r["tools"]["njs"]
    with pytest.raises(ValueError): module().validate_request(r, manifest)


@pytest.mark.parametrize("case", ["missing", "boolean", "unknown", "host", "profile", "san", "eku", "wildcard",
                                    "argv_secret", "key_path", "trust", "local_bypass", "issuer", "adapter", "review"])
def test_invalid_operational_contract_is_rejected_before_runtime(case):
    r, m = request()
    if case == "missing": del r["target"]["boot_id"]
    if case == "boolean": r["apply"] = 1
    if case == "unknown": r["bypass"] = True
    if case == "host": r["target"]["fqdn"] = "dc02.ad.example.invalid"
    if case == "profile": r["profile"] = "telemetry_dc02"
    if case == "san": m["certificate_profiles"]["dc01"]["sans"].append("dc02.ad.example.invalid")
    if case == "eku": m["certificate_profiles"]["dc01"]["eku"].append("clientAuth")
    if case == "wildcard": m["resources"]["dc01"]["fqdn"] = "*.example.invalid"
    if case == "argv_secret": r["credential"]["password"] = "TEST-SENTINEL-NEVER-ECHO"
    if case == "key_path": r["credential"]["auth_key_ref"] = "/tmp/other-key"
    if case == "trust": r["trust"]["root_sha256"] = ""
    if case == "local_bypass": r["issuer"].update(transport="local_loopback", local_port=9443)
    if case == "issuer": r["issuer"]["url"] += "?token=bad"
    if case == "adapter": r["adapter"] = {"kind": "nginx", "port": 443}
    if case == "review": r["provenance"]["review_ref"] = "branch:main"
    with pytest.raises(ValueError, match="suppressed") as error:
        module().validate_request(r, m)
    assert "TEST-SENTINEL" not in str(error.value)
