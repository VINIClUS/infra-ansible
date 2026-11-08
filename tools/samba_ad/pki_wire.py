"""Controller-only reference validation and flow selection before SSH transport."""
import json
import sys

from tools.samba_ad.contract import validate_manifest
from tools.samba_ad.pki import require
from tools.samba_ad.pki_ca import validate as validate_ca
from tools.samba_ad.pki_contract import identity_layout, loads, validate_request
from tools.samba_ad.pki_material import Local, validate as validate_material


def references(value):
    if isinstance(value, dict):
        for key, child in value.items():
            references(key); references(child)
    elif isinstance(value, list):
        for child in value: references(child)
    elif isinstance(value, str):
        require("-----BEGIN " not in value)


def select(flow, data):
    try:
        if flow in ["identity", "trust"]:
            result = {key: data[key] for key in ["request", "manifest"]}
            references(result)
            validate_manifest(result["manifest"])
            validate_request(result["request"], result["manifest"])
            require(result["request"]["enabled"])
            identity_layout(result["request"])
        elif flow in ["ca_configure", "ca_csr"]:
            key = "ca_request" if flow == "ca_configure" else "material_request"
            result = {key: data[key]}
            references(result)
            request = result[key]
            require(request["enabled"])
            validate_manifest(request["guest_request"]["compatibility"]["data"]["manifest"])
            if flow == "ca_configure":
                validate_ca(request)
            else:
                validate_material(request)
                Local().layout(request)
                ref = data["material_password_ref"]
                require(ref == "/run/samba-ad-pki-credentials/ca/issuer-password")
                result["material_password_ref"] = ref
        else:
            raise ValueError()
        return result
    except Exception:
        raise ValueError("S3 controller payload refused (values suppressed)") from None


def main():
    try:
        print(json.dumps(select(sys.argv[1], loads(sys.stdin.read()))))
        return 0
    except Exception:
        print('{"state":"error","error":"S3 controller payload refused (values suppressed)"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
