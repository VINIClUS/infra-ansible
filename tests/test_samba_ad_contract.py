"""S0 contracts must reject ambiguous identities without operating infrastructure."""
import importlib
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "contracts/samba_ad/example.yml"


def contract():
    assert EXAMPLE.exists(), "S0 inert example contract is missing"
    return yaml.safe_load(EXAMPLE.read_text())


def validator():
    assert (ROOT / "tools/samba_ad/contract.py").exists(), "S0 validator is missing"
    return importlib.import_module("tools.samba_ad.contract")


def test_example_is_valid_but_cannot_authorize_execution():
    data = contract()
    assert data["enabled"] is False and data["apply"] is False
    assert validator().validate_manifest(data) == {"resources": 6, "secret_refs": 6}


@pytest.mark.parametrize("field,value", [
    ("enabled", True), ("apply", True), ("enabled", "false"),
    ("stage", "S1"), ("schema", True),
])
def test_s0_never_accepts_activation(field, value):
    data = contract()
    data[field] = value
    with pytest.raises(ValueError):
        validator().validate_manifest(data)


@pytest.mark.parametrize("field", ["vmid", "mac", "address", "fqdn"])
def test_duplicate_guest_identity_is_rejected(field):
    data = contract()
    data["resources"]["dc02"][field] = data["resources"]["dc01"][field]
    with pytest.raises(ValueError):
        validator().validate_manifest(data)


@pytest.mark.parametrize("change", [
    {"node": "node-a"}, {"kind": "qemu"}, {"vmid": True},
    {"address": "198.51.100.200"}, {"address": "198.51.100.1"},
    {"fqdn": "dc02.other.invalid"}, {"state": "reserved"}, {"unprivileged": False},
])
def test_unsafe_dc_placement_or_identity_is_rejected(change):
    data = contract()
    data["resources"]["dc02"].update(change)
    with pytest.raises(ValueError):
        validator().validate_manifest(data)


@pytest.mark.parametrize("section,field,value", [
    ("network", "admin_sources", ["0.0.0.0/0"]),
    ("network", "existing_cidrs", ["198.51.100.0/25"]),
    ("network", "gateway", "203.0.113.1"),
    ("domain", "realm", "EXAMPLE.ORG"),
    ("domain", "sid", "S-1-5-21-1-2-3"),
    ("execution", "mode", "automatic"),
    ("execution", "digest_required", False),
    ("software", "samba_version", "4.22.11"),
])
def test_conflicting_network_domain_or_execution_contract_is_rejected(section, field, value):
    data = contract()
    data[section][field] = value
    with pytest.raises(ValueError):
        validator().validate_manifest(data)


def test_secret_values_and_unrestricted_certificate_names_are_rejected():
    data = contract()
    data["secret_refs"]["domain_admin"]["password"] = "DO-NOT-ECHO"
    with pytest.raises(ValueError) as error:
        validator().validate_manifest(data)
    assert "DO-NOT-ECHO" not in str(error.value)
    data = contract()
    data["certificate_profiles"]["dc01"]["sans"] = ["*.example.invalid"]
    with pytest.raises(ValueError):
        validator().validate_manifest(data)


@pytest.mark.parametrize("section", ["domain", "network", "software", "resources.dc01"])
def test_undeclared_secret_fields_are_rejected_at_every_boundary(section):
    data = contract()
    target = data
    for part in section.split("."):
        target = target[part]
    target["password"] = "DO-NOT-ECHO"
    with pytest.raises(ValueError):
        validator().validate_manifest(data)


def test_telemetry_certificates_are_individual_client_identities():
    data = contract()
    for role in ["dc01", "dc02", "ca", "backup"]:
        profile = data["certificate_profiles"].get("telemetry_" + role)
        assert profile, "each telemetry sender needs its own restricted profile"
        assert profile["sans"] == [data["resources"][role]["fqdn"]]
        assert profile["eku"] == ["clientAuth"]


def test_inert_defaults_match_manifest_without_becoming_inventory():
    defaults = yaml.safe_load((ROOT / "contracts/samba_ad/defaults.yml").read_text())
    assert all(contract()[key] == value for key, value in defaults.items())


@pytest.mark.parametrize("payload", [
    "enabled: false\nenabled: true\n",
    "domain: [DO-NOT-ECHO\n",
    "!!python/object/apply:os.system ['DO-NOT-ECHO']",
])
def test_cli_rejects_bad_yaml_without_echoing_payload(tmp_path, payload):
    path = tmp_path / "contract.yml"
    path.write_text(payload)
    result = subprocess.run(
        [sys.executable, "-m", "tools.samba_ad.contract", str(path)],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 2
    assert "DO-NOT-ECHO" not in result.stdout + result.stderr
    assert "invalid S0 contract" in result.stderr


def test_no_automatic_deployer_or_inventory_consumes_samba_contract():
    from tools.deploy.infra_ansible_deploy import FIXED_RUNS

    assert all("samba" not in run.playbook for run in FIXED_RUNS)
    assert not list((ROOT / "playbooks").glob("*samba*"))
    inventory = subprocess.run(
        ["ansible-inventory", "-i", "inventories/example/hosts.yml", "--list"],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert inventory.returncode == 0
    assert "samba_ad" not in inventory.stdout


def test_port_contract_has_only_scoped_origins_and_modern_ad_protocols():
    path = ROOT / "contracts/samba_ad/network-policy.yml"
    assert path.exists(), "S0 network policy is missing"
    policy = yaml.safe_load(path.read_text())
    assert policy["enforcement"] == ["router", "guest_default_drop"]
    for flow in policy["flows"]:
        assert flow["source"] in {
            "pilots", "dcs", "dc01", "administrators", "identity_guests", "backup_receiver", "monitor"
        }
        assert flow["destination"] in {
            "dcs", "dc02", "ca", "identity_guests", "dns_forwarders", "time_sources", "collector", "backup_receiver"
        }
        assert flow["protocol"] in {"tcp", "udp"}
        assert not ({"137", "138", "139", "all", "any"} & set(flow["ports"]))
    dc_tcp = set().union(*(set(f["ports"]) for f in policy["flows"]
                          if f["source"] == "dcs" and f["destination"] == "dcs" and f["protocol"] == "tcp"))
    assert {"53", "88", "135", "389", "445", "464", "636", "3268", "3269", "49152-65535"} <= dc_tcp
    assert {"source": "dc01", "destination": "dc02", "protocol": "tcp", "ports": ["22"]} in policy["flows"]
