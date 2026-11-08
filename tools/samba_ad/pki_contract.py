"""Closed manual S3 requests. References only; values never enter errors."""
from __future__ import annotations

import base64
import ipaddress
import json
from pathlib import PurePosixPath
import re
import uuid

from cryptography.hazmat.primitives.asymmetric import ec

from tools.samba_ad.pki import PROFILES, require


def fields(data, names):
    require(isinstance(data, dict) and set(data) == set(names.split()))


def hex_value(value, length=64):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{" + str(length) + "}", value)
            and value != "0" * length)


def path(value):
    require(isinstance(value, str) and re.fullmatch(r"/[A-Za-z0-9_./-]+", value))
    p = PurePosixPath(value)
    require(str(p) == value and ".." not in p.parts and len(p.parts) >= 3)
    return value


def credential_ref(profile):
    require(profile in PROFILES)
    return "/run/samba-ad-pki-credentials/" + profile + "/passphrase"


def identity_layout(r):
    """Production paths only. Generic contract/store APIs remain transport-free."""
    require(r["state_dir"] == "/var/lib/samba-ad-pki")
    require(r["trust"]["root_file"] == "/etc/samba-ad-pki/root.pem"
            and r["trust"]["issuer_file"] == "/etc/samba-ad-pki/issuer.pem")
    require(r["credential"]["auth_key_ref"] == r["state_dir"] + "/" + r["profile"] + "/auth.jwe")
    require(r["credential"]["password_ref"] == credential_ref(r["profile"]))


def review(value):
    require(isinstance(value, str) and re.fullmatch(r"git:[a-f0-9]{40}:[A-Za-z0-9_./-]+", value)
            and ".." not in value)


def dns(value):
    require(isinstance(value, str) and len(value) <= 253 and "." in value)
    require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", v) for v in value.split(".")))


def public_jwk(value):
    require(isinstance(value, dict) and {"kty", "crv", "x", "y", "kid"} <= set(value)
            and set(value) <= {"kty", "crv", "x", "y", "kid", "alg", "use", "key_ops"})
    require(value["kty"] == "EC" and value["crv"] == "P-256" and value.get("alg", "ES256") == "ES256"
            and value.get("use", "sig") == "sig" and value.get("key_ops", ["verify"]) == ["verify"])
    decoded = {}
    for key in ["kid", "x", "y"]:
        require(isinstance(value[key], str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", value[key]))
        decoded[key] = base64.urlsafe_b64decode(value[key] + "=")
        require(len(decoded[key]) == 32 and base64.urlsafe_b64encode(decoded[key]).decode().rstrip("=") == value[key])
    # kid is an opaque canonical 256-bit identifier, not evidence of key independence.
    numbers = [int.from_bytes(decoded[k], "big") for k in ["x", "y"]]
    return ec.EllipticCurvePublicNumbers(numbers[0], numbers[1], ec.SECP256R1()).public_key()


def loads(text):
    def unique(pairs):
        require(len({k for k, _ in pairs}) == len(pairs))
        return dict(pairs)
    def constant(_):
        raise ValueError("invalid S3 JSON (values suppressed)")
    try:
        return json.loads(text, object_pairs_hook=unique, parse_constant=constant)
    except Exception:
        raise ValueError("invalid S3 JSON (values suppressed)") from None


def validate_request(request: dict, manifest: dict) -> dict:
    try:
        return _validate(request, manifest)
    except Exception:
        raise ValueError("invalid S3 request (values suppressed)") from None


def _validate(r, manifest):
    require(isinstance(r, dict) and r.get("schema") == "samba-ad-pki/v1")
    require(type(r.get("enabled")) is bool and type(r.get("apply")) is bool)
    if not r["enabled"]:
        return {"state": "disabled"}
    fields(r, "schema enabled apply action profile target state_dir trust credential issuer tools adapter "
              "expected_active provenance")
    require(r["action"] in ["preflight", "auth_prepare", "stage", "rotate"] and r["profile"] in PROFILES)
    require(manifest["schema"] == 1 and manifest["stage"] == "S0" and manifest["owner"] == "samba-ad"
            and manifest["enabled"] is False and manifest["apply"] is False)
    require(set(manifest["certificate_profiles"]) == PROFILES)
    for name, profile in manifest["certificate_profiles"].items():
        fields(profile, "sans eku validity_hours rotate_before_fraction")
        role = name.removeprefix("telemetry_")
        fqdn = manifest["resources"][role]["fqdn"]
        dns(fqdn)
        require(profile["sans"] == [fqdn] and profile["eku"] == ["clientAuth" if name.startswith("telemetry_") else "serverAuth"]
                and type(profile["validity_hours"]) is int and profile["validity_hours"] == 168
                and profile["rotate_before_fraction"] == 0.66)
    target = r["target"]
    fields(target, "role fqdn address mac kind interface boot_id machine_id spec_sha256")
    role = r["profile"].removeprefix("telemetry_")
    require(target["role"] == role)
    declared = manifest["resources"][role]
    require(declared["owner"] == "samba-ad" and declared["state"] == "candidate")
    require(all(target[k] == declared[k] for k in ["fqdn", "address", "mac", "kind"]))
    ipaddress.IPv4Address(target["address"])
    require(target["kind"] in ["qemu", "lxc"] and (role != "ca" or target["kind"] == "qemu"))
    require(str(uuid.UUID(target["boot_id"])) == target["boot_id"])
    hex_value(target["machine_id"], 32); hex_value(target["spec_sha256"])
    require(re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", target["interface"]))
    path(r["state_dir"])
    fields(r["trust"], "root_file issuer_file root_sha256 issuer_sha256")
    for key in ["root_file", "issuer_file"]: path(r["trust"][key])
    for key in ["root_sha256", "issuer_sha256"]: hex_value(r["trust"][key])
    fields(r["credential"], "auth_key_ref password_ref public_jwk")
    require(r["credential"]["auth_key_ref"] == r["state_dir"] + "/" + r["profile"] + "/auth.jwe")
    path(r["credential"]["password_ref"])
    if r["action"] != "auth_prepare" or r["credential"]["public_jwk"] is not None:
        public_jwk(r["credential"]["public_jwk"])
    fields(r["issuer"], "url transport local_port")
    require(r["issuer"]["url"] == "https://" + manifest["resources"]["ca"]["fqdn"] + "/1.0/sign")
    require(r["issuer"]["transport"] in ["public", "local_loopback"])
    if r["issuer"]["transport"] == "local_loopback":
        require(r["profile"] == "ca" and type(r["issuer"]["local_port"]) is int
                and 1024 <= r["issuer"]["local_port"] <= 65535)
    else:
        require(r["issuer"]["local_port"] is None)
    fields(r["adapter"], "kind port")
    adapter = r["adapter"]
    require(adapter == {"kind": "pending", "port": None}
            or (r["profile"] == "ca" and adapter == {"kind": "nginx", "port": 443})
            or (r["profile"] in ["dc01", "dc02"] and adapter == {"kind": "samba", "port": 636}))
    require(r["expected_active"] is None or isinstance(r["expected_active"], str))
    if r["expected_active"] == "managed":
        require(r["action"] == "rotate")
    elif r["expected_active"] is not None:
        hex_value(r["expected_active"])
    fields(r["tools"], "step cryptography nginx njs" if adapter["kind"] == "nginx" else "step cryptography")
    for name, artifact in r["tools"].items():
        if name == "cryptography": continue
        fields(artifact, "path sha256 version provenance_ref")
        path(artifact["path"]); hex_value(artifact["sha256"])
        require(isinstance(artifact["version"], str) and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,80}", artifact["version"]))
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", r["tools"]["step"]["version"]))
    if adapter["kind"] == "nginx":
        require(r["tools"]["njs"]["version"].split("+")[0] == r["tools"]["nginx"]["version"].split("-")[0])
    fields(r["tools"]["cryptography"], "version provenance_ref")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", r["tools"]["cryptography"]["version"]))
    for tool in r["tools"].values(): review(tool["provenance_ref"])
    fields(r["provenance"], "private_revision review_ref substrate_audit_sha256")
    hex_value(r["provenance"]["private_revision"], 40)
    hex_value(r["provenance"]["substrate_audit_sha256"])
    review(r["provenance"]["review_ref"])
    return manifest["certificate_profiles"][r["profile"]]
