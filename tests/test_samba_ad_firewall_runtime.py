"""Readback must prove the complete approved path, not scattered fragments."""
import copy
import json
from pathlib import Path
import runpy
import pytest
ROOT = Path(__file__).resolve().parents[1]
G = runpy.run_path(str(ROOT / "tests/test_samba_ad_guest.py"))


def snapshot():
    return json.loads((ROOT / "tests/fixtures/samba-ad/pve-runtime.json").read_text())


def test_complete_runtime_matches_approved_matrix_and_same_l2_path():
    assert G["module"]().runtime_firewall_ready(G["request"](), snapshot())


@pytest.mark.parametrize("attack", ["early_accept", "parent_accept", "root_accept", "root_missing", "missing_flow",
    "stale_port", "broader_peer", "broad_ipset", "wide_ipv6", "wrong_hook", "bridge_bypass", "bridge_nf_off", "mark_bypass"])
def test_stale_or_broader_runtime_never_opens_the_disconnected_link(attack):
    m = G["module"](); r = G["request"](); d = snapshot()
    if attack == "early_accept": d["ipv4"] = d["ipv4"].replace('-A veth800080i0-IN -j CONNMARK', '-A veth800080i0-IN -j ACCEPT\n-A veth800080i0-IN -j CONNMARK')
    if attack == "parent_accept": d["ipv4"] = d["ipv4"].replace('-A PVEFW-FWBR-IN -m physdev', '-A PVEFW-FWBR-IN -j ACCEPT\n-A PVEFW-FWBR-IN -m physdev')
    if attack == "root_accept": d["ipv4"] = d["ipv4"].replace('-A FORWARD -j', '-A FORWARD -j ACCEPT\n-A FORWARD -j')
    if attack == "root_missing": d["ipv4"] = d["ipv4"].replace('-A FORWARD -j PVEFW-FORWARD\n', '')
    if attack == "missing_flow": d["ipv4"] = d["ipv4"].replace('-A veth800080i0-IN -s 192.0.2.25/32 -p tcp -m tcp --dport 22 -j ACCEPT\n', '')
    if attack == "stale_port": d["ipv4"] = d["ipv4"].replace('--dport 22 ', '--dport 23 ')
    if attack == "broader_peer": d["ipv4"] = d["ipv4"].replace('192.0.2.25/32', '192.0.2.0/24')
    if attack == "broad_ipset": d["ipsets"] += 'add PVEFW-800080-ipfilter-net0-v4 0.0.0.0/0\n'
    if attack == "wide_ipv6": d["ipsets"] += 'add PVEFW-800080-ipfilter-net0-v6 ::/0\n'
    if attack == "wrong_hook": d["ipv6"] = d["ipv6"].replace('--physdev-out veth800080i0', '--physdev-out veth800081i0')
    if attack == "bridge_bypass": d["links"][-1]["master"] = 'vnidtest'
    if attack == "bridge_nf_off": d["bridge_filter"]["ipv4"] = 0
    if attack == "mark_bypass": d["ipv4"] = d["ipv4"].replace('-A PVEFW-SET-ACCEPT-MARK -j MARK', '-A PVEFW-SET-ACCEPT-MARK -j ACCEPT\n-A PVEFW-SET-ACCEPT-MARK -j MARK')
    assert not m.runtime_firewall_ready(r, d)


def test_ipv6_without_ndp_ra_dhcp_or_matrix_flows_cannot_accept_new_traffic():
    m = G["module"](); r = G["request"](); d = snapshot()
    d["ipv6"] = d["ipv6"].replace('-A veth800080i0-IN -j DROP', '-A veth800080i0-IN -j ACCEPT\n-A veth800080i0-IN -j DROP', 1)
    assert not m.runtime_firewall_ready(r, d)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
@pytest.mark.parametrize("direction", ["IN", "OUT"])
@pytest.mark.parametrize("ending", ["return", "fallthrough"])
def test_goto_returning_helper_cannot_escape_fwbr_binding(family, direction, ending):
    m = G["module"](); d = snapshot(); name = "S1-RETURN"
    text = d[family].replace('-A FORWARD', ':' + name + ' - [0:0]\n-A FORWARD', 1)
    parent = "PVEFW-FWBR-" + direction
    text = text.replace('-A ' + parent + ' -m physdev', '-A ' + parent + ' -g ' + name + '\n-A ' + parent + ' -m physdev', 1)
    if ending == "return": text = text.replace('COMMIT', '-A ' + name + ' -j RETURN\nCOMMIT')
    d[family] = text
    assert not m.runtime_firewall_ready(G["request"](), d)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
@pytest.mark.parametrize("direction", ["IN", "OUT"])
def test_jump_to_returning_helper_resumes_at_own_binding(family, direction):
    m = G["module"](); d = snapshot(); name = "S1-RETURN"; parent = "PVEFW-FWBR-" + direction
    text = d[family].replace('-A FORWARD', ':' + name + ' - [0:0]\n-A FORWARD', 1)
    text = text.replace('-A ' + parent + ' -m physdev', '-A ' + parent + ' -j ' + name + '\n-A ' + parent + ' -m physdev', 1)
    d[family] = text.replace('COMMIT', '-A ' + name + ' -j RETURN\nCOMMIT')
    assert m.runtime_firewall_ready(G["request"](), d)


@pytest.mark.parametrize("body", [
    '-p icmp -m icmp --icmp-type 3/4 -j ACCEPT',
    '-p udp -m multiport --dports 135,445 -j DROP',
    '-p tcp -m multiport --sports 135,139,445 -j DROP',
    '-m mark --mark 0x80000000/0x80000000 -j RETURN',
    '-m comment --comment "PVESIG:AAAAAAAAAAAAAAAAAAAAAAAAAAA"',
])
def test_native_pve_helper_grammar_and_signature_are_supported(body):
    G["module"]().ipt_rule(body)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_complete_native_helpers_and_other_host_policy_are_parsed_without_relaxing_guest(family):
    m = G["module"](); d = snapshot(); chains, policies = m.saved_filter(d[family])
    assert "PVEFW-Drop" in chains and "PVEFW-DropBroadcast" in chains
    assert any(m.transfer_of(rule)[1] == "ACCEPT" for rule in chains["PVEFW-Drop"])
    assert len(chains["S1-OTHER-HOST"]) == 3
    assert policies["INPUT"] == "DROP"
    assert m.runtime_firewall_ready(G["request"](), d)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_native_drop_helper_with_accepts_is_never_trusted_when_reachable_before_binding(family):
    m = G["module"](); d = snapshot()
    d[family] = d[family].replace('-A PVEFW-FWBR-IN -m physdev', '-A PVEFW-FWBR-IN -j PVEFW-Drop\n-A PVEFW-FWBR-IN -m physdev', 1)
    assert not m.runtime_firewall_ready(G["request"](), d)


def test_incomplete_table_with_undefined_target_is_not_runtime_evidence():
    m = G["module"]()
    with pytest.raises(ValueError, match="undeclared runtime target"):
        m.saved_filter('*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -j MISSING\nCOMMIT\n')


def test_complete_fixture_tables_are_kernel_loadable_in_isolated_namespace():
    import shutil, subprocess, sys
    if not all(shutil.which(name) for name in ["unshare", "iptables-restore", "ip6tables-restore"]):
        pytest.skip("local namespace/xtables tooling unavailable; no dependencies installed")
    result = subprocess.run([sys.executable, str(ROOT / "tests/fixtures/samba-ad/check_loadable.py")], capture_output=True, text=True)
    if "unshare failed: Operation not permitted" in result.stderr:
        pytest.skip("local unprivileged namespace unavailable")
    assert result.returncode == 0, result.stderr


def test_fixture_worker_refuses_original_namespace_before_any_netlink_write():
    import os, subprocess, sys
    descriptor = os.open("/proc/self/ns/net", os.O_RDONLY)
    try:
        result = subprocess.run([sys.executable, str(ROOT / "tests/fixtures/samba-ad/check_loadable.py"),
                                 "--inside", str(descriptor)], pass_fds=(descriptor,), text=True, capture_output=True)
    finally: os.close(descriptor)
    assert result.returncode != 0 and "different network namespace" in result.stderr
