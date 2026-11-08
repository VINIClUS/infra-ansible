"""Renderer is executed against public keys; native NGINX/step-ca remain pending."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from test_samba_ad_ca_substrate import ca_request, reseal
from test_samba_ad_pki import ROOT


def module():
    p = ROOT / "tools/samba_ad/pki_ca.py"
    assert p.is_file(), "CA configuration renderer missing"
    spec = importlib.util.spec_from_file_location("pki_ca", p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def request():
    g = ca_request(); c = g["resource"]
    def b64(v): return base64.urlsafe_b64encode(v).decode().rstrip("=")
    public = {}
    for name in ["dc01", "dc02", "ca", "telemetry_dc01", "telemetry_dc02", "telemetry_ca"]:
        numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        public[name] = {"kty": "EC", "crv": "P-256", "x": b64(numbers.x.to_bytes(32, "big")),
                        "y": b64(numbers.y.to_bytes(32, "big")), "kid": b64(hashlib.sha256(name.encode()).digest())}
    def artifact(path, version):
        return {"path": path, "version": version, "sha256": "a" * 64,
                "provenance_ref": "git:" + "a" * 40 + ":reviews/packages.json"}
    return {"schema": "samba-ad-ca-config/v1", "enabled": True, "apply": True, "guest_request": g,
            "target": {"fqdn": c["name"], "address": c["address"].split("/")[0], "mac": c["mac"],
                       "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "machine_id": "a" * 32,
                       "interface": "eth0"},
            "paths": {"root_cert": "/etc/samba-ad-pki/root.pem", "issuer_cert": "/etc/samba-ad-pki/issuer.pem",
                      "issuer_key": "/etc/samba-ad-ca/intermediate.key.pem",
                      "issuer_password_ref": "/run/samba-ad-pki-credentials/ca/issuer-password",
                      "ca_state": "/var/lib/samba-ad-ca", "identity_state": "/var/lib/samba-ad-pki"},
            "root_sha256": "a" * 64, "issuer_sha256": "b" * 64, "backend_port": 9443,
            "service_user": "samba-ad-ca", "frontend_user": "nginx", "registry": public,
            "tools": {"step_ca": artifact("/usr/bin/step-ca", "0.30.2"),
                      "nginx": artifact("/usr/sbin/nginx", "1.30.6-1~trixie"),
                      "njs": artifact("/usr/lib/nginx/modules/ngx_http_js_module.so", "1.30.6+1.0.2-1~trixie")},
            "expected_files": {}}


def test_renderer_binds_six_independent_provisioners_to_private_manifest():
    r = request(); files = module().render(r)
    ca = json.loads(files["/etc/samba-ad-pki/ca.json"])
    assert ca["address"] == "127.0.0.1:9443" and ca["logger"] == {"format": "common"}
    assert ca["key"] == "/etc/samba-ad-ca/intermediate.key.pem"
    assert ca["authority"]["backdate"] == "0s"
    provisioners = ca["authority"]["provisioners"]
    assert len(provisioners) == 6 and len({p["key"]["kid"] for p in provisioners}) == 6
    assert all("encryptedKey" not in p and p["claims"]["disableRenewal"] for p in provisioners)
    assert {p["claims"]["maxTLSCertDuration"] for p in provisioners} == {"168h"}
    assert "/etc/systemd/system/samba-ad-pki-ca.service" in files
    assert "/etc/systemd/system/samba-ad-pki-nginx.service" in files


def test_native_error_paths_cannot_persist_raw_request_and_access_signals_are_scalar_only():
    files = module().render(request())
    nginx = files["/etc/samba-ad-pki/nginx.conf"]
    # One main sink is inherited by all parser/body-limit/njs/upstream error paths.
    errors = re.findall(r"(?m)^\s*error_log\s+([^;]+);", nginx)
    assert len(errors) == 1 and errors[0].split()[0] == "/dev/null"
    formats = re.findall(r"(?m)^\s*log_format\s+s3\s+([^;]+);", nginx)
    assert len(formats) == 1
    variables = set(re.findall(r"\$([a-z_]+)", formats[0]))
    assert "status" in variables
    assert variables <= {"status", "body_bytes_sent", "request_time"}
    assert "access_log /dev/stdout s3;" in nginx


def test_registry_refuses_six_textual_aliases_of_one_actual_p256_key():
    r = request()
    public = copy.deepcopy(r["registry"]["dc01"])
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    def alias(value, bits):
        index = alphabet.index(value[-1])
        assert index & 3 == 0
        return value[:-1] + alphabet[index | bits]
    for index, name in enumerate(r["registry"]):
        kid = r["registry"][name]["kid"]
        r["registry"][name] = public | {"kid": kid, "x": alias(public["x"], index % 4),
                                              "y": alias(public["y"], index // 4)}
    assert len({(v["x"], v["y"]) for v in r["registry"].values()}) == 6
    decoded = {(base64.urlsafe_b64decode(v["x"] + "="), base64.urlsafe_b64decode(v["y"] + "="))
               for v in r["registry"].values()}
    assert len(decoded) == 1
    with pytest.raises(ValueError, match="suppressed"):
        module().render(r)


def test_registry_refuses_shared_canonical_material_with_distinct_kids():
    r = request()
    other_kid = r["registry"]["telemetry_dc01"]["kid"]
    r["registry"]["telemetry_dc01"] = r["registry"]["dc01"] | {"kid": other_kid}
    with pytest.raises(ValueError, match="suppressed"):
        module().render(r)


@pytest.mark.parametrize("case", ["private", "duplicate_key", "missing_profile", "shell_path", "root_online",
                                    "root_user", "wrong_target", "wrong_abi", "wide_bind", "unknown", "wildcard_manifest",
                                    "system_state", "foreign_material"])
def test_renderer_refuses_unsafe_inputs_before_any_service_or_file_write(case):
    r = request()
    if case == "private": r["registry"]["dc01"]["d"] = "PRIVATE-MUST-NOT-ENTER-CONFIG"
    if case == "duplicate_key": r["registry"]["dc02"] = copy.deepcopy(r["registry"]["dc01"])
    if case == "missing_profile": del r["registry"]["telemetry_ca"]
    if case == "shell_path": r["paths"]["issuer_key"] += "; bad"
    if case == "root_online": r["paths"]["root_key"] = "/operator/root.key.pem"
    if case == "root_user": r["service_user"] = "root"
    if case == "wrong_target": r["target"]["address"] = "198.51.100.99"
    if case == "wrong_abi": r["tools"]["njs"]["version"] = "1.28.3+1.0.2-1~trixie"
    if case == "wide_bind": r["backend_port"] = "0.0.0.0:9443"
    if case == "unknown": r["proxy_insecure"] = True
    if case == "system_state": r["paths"]["ca_state"] = "/usr/sbin"
    if case == "foreign_material": r["paths"]["issuer_key"] = "/other/project/intermediate.key.pem"
    if case == "wildcard_manifest":
        manifest = r["guest_request"]["compatibility"]["data"]["manifest"]
        manifest["resources"]["dc01"]["fqdn"] = "*.example.invalid"
        for name in ["dc01", "telemetry_dc01"]: manifest["certificate_profiles"][name]["sans"] = ["*.example.invalid"]
        reseal(r["guest_request"])
    with pytest.raises(ValueError, match="suppressed"): module().render(r)
