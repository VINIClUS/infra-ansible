"""The loaded router matrix and interface jumps must match the approved artifact."""
import copy
import importlib.util
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]


def module():
    path = ROOT / "tools/samba_ad/router_guard.py"
    assert path.exists(), "router runtime proof is missing"
    spec = importlib.util.spec_from_file_location("router_guard", path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def match(left, right): return {"match": {"op": "==", "left": left, "right": right}}
def meta(key): return {"meta": {"key": key}}
def rule(chain, expr): return {"rule": {"family": "inet", "table": "filter", "chain": chain, "expr": expr}}


def contract():
    return {"interface": "eth4", "rules": [{"iif": "eth0", "oif": "eth4", "source": "192.0.2.25/32",
            "destination": "198.51.100.80/32", "proto": "tcp", "port": "22"}]}


def snapshot():
    chain = "restricted_identity"
    return {"nftables": [{"metainfo": {"version": "test"}},
        {"table": {"family": "inet", "name": "filter"}},
        {"chain": {"family": "inet", "table": "filter", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
        {"chain": {"family": "inet", "table": "filter", "name": chain}},
        rule("forward", [match({"ct": {"key": "state"}}, {"set": ["established", "related"]}), {"accept": None}]),
        rule("forward", [match(meta("iifname"), "eth4"), {"jump": {"target": chain}}]),
        rule("forward", [match(meta("oifname"), "eth4"), {"jump": {"target": chain}}]),
        rule("forward", [match(meta("iifname"), "eth2"), {"accept": None}]),
        rule(chain, [match(meta("iifname"), "eth0"), match(meta("oifname"), "eth4"),
            match({"payload": {"protocol": "ip", "field": "saddr"}}, "192.0.2.25"),
            match({"payload": {"protocol": "ip", "field": "daddr"}}, "198.51.100.80"),
            match({"payload": {"protocol": "tcp", "field": "dport"}}, 22), {"accept": None}]),
        rule(chain, [{"counter": {"packets": 10, "bytes": 100}}, {"drop": None}])]}


def test_approved_runtime_matrix_with_jumps_before_legacy_ops_is_valid():
    m = module(); d = snapshot(); m.verify(d, contract(), m.fingerprint(d), "identity")
    changed_counts = copy.deepcopy(d); changed_counts["nftables"][-1]["rule"]["expr"][0]["counter"]["packets"] = 500
    m.verify(changed_counts, contract(), m.fingerprint(d), "identity")


@pytest.mark.parametrize("attack", ["accept_before_jumps", "jumps_after_ops", "wrong_iface", "stale_port", "broad_peer", "extra_allow", "wrong_hook"])
def test_router_structural_proof_fails_even_if_bad_runtime_hash_were_approved(attack):
    m = module(); d = snapshot(); entries = d["nftables"]
    if attack == "accept_before_jumps": entries.insert(5, rule("forward", [{"accept": None}]))
    if attack == "jumps_after_ops": entries.insert(5, entries.pop(7))
    if attack == "wrong_iface": entries[5]["rule"]["expr"][0]["match"]["right"] = "eth3"
    if attack == "stale_port": entries[-2]["rule"]["expr"][-2]["match"]["right"] = 23
    if attack == "broad_peer": entries[-2]["rule"]["expr"][2]["match"]["right"] = {"prefix": {"addr": "192.0.2.0", "len": 24}}
    if attack == "extra_allow": entries.insert(-1, rule("restricted_identity", [{"accept": None}]))
    if attack == "wrong_hook": entries[2]["chain"]["hook"] = "input"
    with pytest.raises(ValueError): m.verify(d, contract(), m.fingerprint(d), "identity")


def test_old_runtime_is_refused_even_when_disk_and_some_fragments_match():
    m = module(); d = snapshot(); approved = m.fingerprint(d)
    d["nftables"][7]["rule"]["expr"][0]["match"]["right"] = "eth3"
    with pytest.raises(ValueError): m.verify(d, contract(), approved, "identity")


@pytest.mark.parametrize("proto,port_value", [("tcp", "22"), ("tcp", "49152-65535"), ("udp", "53")])
def test_rendered_router_rules_are_semantically_verified_by_nft_in_a_local_namespace(proto, port_value):
    import json, shutil, subprocess, runpy
    if not shutil.which("nft") or not shutil.which("unshare"): pytest.skip("local nft/net namespace unavailable")
    rendered = runpy.run_path(str(ROOT / "tests/test_samba_ad_router.py"))["render"]()
    rendered = rendered.replace("tcp dport 22", proto + " dport " + port_value)
    script = ('import subprocess; subprocess.run(["nft","-f","-"],input=' + repr(rendered) +
              ',text=True,capture_output=True,check=True); print(subprocess.run(["nft","-j","list","ruleset"],text=True,capture_output=True,check=True).stdout)')
    result = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "python3", "-c", script], text=True, capture_output=True)
    if "unshare: unshare failed: Operation not permitted" in result.stderr: pytest.skip("local namespace not permitted")
    assert result.returncode == 0, "local nft failed; no production access involved"
    m = module(); runtime = json.loads(result.stdout)
    expected = contract(); expected["rules"][0].update(proto=proto, port=port_value)
    m.verify(runtime, expected, m.fingerprint(runtime), "identity")
