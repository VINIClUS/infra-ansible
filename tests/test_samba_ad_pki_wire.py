"""Controller must validate/select a closed payload before any SSH transfer."""
import importlib.util
from pathlib import Path

import pytest

from test_samba_ad_pki_contract import request

ROOT = Path(__file__).resolve().parents[1]


def module():
    p = ROOT / "tools/samba_ad/pki_wire.py"
    assert p.is_file(), "controller-only PKI payload validator missing"
    spec = importlib.util.spec_from_file_location("pki_wire", p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def test_unused_ca_inputs_never_reach_an_identity_consumer():
    r, manifest = request()
    data = {"request": r, "manifest": manifest,
            "ca_request": {"unused_private_input": "TEST-SENTINEL-DO-NOT-TRANSFER"},
            "material_request": {}, "material_password_ref": "/not/used"}
    wire = module().select("identity", data)
    assert set(wire) == {"request", "manifest"}
    assert "TEST-SENTINEL" not in repr(wire)


@pytest.mark.parametrize("case", ["unknown_key", "raw_material", "bad_s0_reference"])
def test_bad_material_or_unknown_fields_are_rejected_on_controller(case):
    r, manifest = request()
    if case == "unknown_key": r["root_key"] = "TEST-SENTINEL-DO-NOT-TRANSFER"
    if case == "raw_material": manifest["software"]["os"] = "-----BEGIN " + "PRIVATE KEY-----\nTEST SENTINEL"
    if case == "bad_s0_reference": manifest["secret_refs"]["ca_provisioner"]["password"] = "TEST SENTINEL"
    with pytest.raises(ValueError, match="suppressed") as error:
        module().select("identity", {"request": r, "manifest": manifest})
    assert "SENTINEL" not in str(error.value)


def test_ca_flow_selects_only_validated_ca_configuration():
    from test_samba_ad_pki_ca_config import request as ca_request
    ca = ca_request()
    wire = module().select("ca_configure", {"ca_request": ca, "request": {"unused": True}})
    assert wire == {"ca_request": ca}


def test_material_validation_is_pure_and_limits_the_online_destination():
    from test_samba_ad_pki_ca_config import request as ca_request
    ca = ca_request()
    r = {"schema": "samba-ad-ca-csr/v1", "enabled": True, "apply": False,
         "guest_request": ca["guest_request"], "target": ca["target"],
         "directory": "/etc/samba-ad-ca", "subject": "TEST ONLY ISSUER", "key_bits": 3072}
    data = {"material_request": r,
            "material_password_ref": "/run/samba-ad-pki-credentials/ca/issuer-password"}
    assert module().select("ca_csr", data) == data
    r["directory"] = "/usr/sbin"
    with pytest.raises(ValueError, match="suppressed"):
        module().select("ca_csr", data)
