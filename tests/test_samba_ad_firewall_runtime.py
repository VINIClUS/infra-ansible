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
