import importlib.util
import pytest


def api():
    assert importlib.util.find_spec("tools.samba_ad.domain_network"), "S4 guest firewall missing"
    from tools.samba_ad import domain_network
    return domain_network


def test_guest_firewall_has_default_drop_exact_peers_and_no_netbios():
    d = api()
    rules = {"admin_sources": ["192.0.2.1/32"], "flows": [{"direction": "IN", "peer": "192.0.2.1/32", "proto": "tcp", "port": "22"}, {"direction": "IN", "peer": "198.51.100.11/32", "proto": "tcp", "port": "49152-65535"}]}
    rendered = d.render(rules)
    assert rendered.count("policy drop") == 2
    assert "ct state established,related accept" in rendered
    assert "ip saddr 192.0.2.1/32 tcp dport 22 accept" in rendered
    assert "49152-65535" in rendered
    for field, value in [("peer", "0.0.0.0/0"), ("port", "139"), ("proto", "tcp; accept")]:
        bad = {"admin_sources": rules["admin_sources"], "flows": [dict(rules["flows"][0], **{field: value})]}
        with pytest.raises(ValueError): d.render(bad)
