"""Policy compiler expands exact fictional endpoints; same-L2 uses guest rules."""
import importlib
from pathlib import Path
import pytest
import yaml
ROOT = Path(__file__).resolve().parents[1]


def test_policy_expands_only_exact_peers_and_no_backup_or_self_flows():
    assert (ROOT / "tools/samba_ad/network_policy.py").exists(), "policy compiler missing"
    m = importlib.import_module("tools.samba_ad.network_policy")
    manifest = yaml.safe_load((ROOT / "contracts/samba_ad/example.yml").read_text())
    policy = yaml.safe_load((ROOT / "contracts/samba_ad/network-policy.yml").read_text())
    result = m.expand(manifest, policy, "203.0.113.19/32")
    assert set(result) == set(manifest["resources"])
    dc = result["dc01"]["flows"]
    assert {"direction": "IN", "peer": "198.51.100.11/32", "proto": "tcp", "port": "445"} in dc
    assert not any(f["peer"] == "198.51.100.10/32" for f in dc)
    assert all(f["peer"].endswith("/32") for fw in result.values() for f in fw["flows"])
    assert not any("backup" in k for k in result)
    zones = {"identity": "198.51.100.0/25", "ops": "203.0.113.0/25"}
    rules = m.router_rules(manifest, result, zones)
    assert all(rule["from"] != rule["to"] for rule in rules)
    assert any(rule["from"] == "wan" and rule["to"] == "identity" and rule["saddr"] == "192.0.2.25/32" for rule in rules)
    assert any(rule["to"] == "ops" and rule["daddr"] == "203.0.113.19/32" for rule in rules)
    with pytest.raises(ValueError): m.expand(manifest, policy, "203.0.113.0/24")
