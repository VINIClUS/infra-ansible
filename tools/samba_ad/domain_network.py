"""A dedicated guest table, without flushing/adopting any existing firewall."""
import ipaddress
import json
from pathlib import Path
import re

from tools.samba_ad.domain import command, fields, require, sha
from tools.samba_ad.pki_files import atomic_file, future_directory, secure_file


def render(policy):
    fields(policy, "admin_sources flows")
    require(policy["admin_sources"] and policy["flows"])
    for peer in policy["admin_sources"]: require(ipaddress.IPv4Network(peer).prefixlen == 32)
    chains = {"IN": [], "OUT": []}
    for flow in policy["flows"]:
        fields(flow, "direction peer proto port")
        direction, peer, proto, port = [flow[k] for k in ["direction", "peer", "proto", "port"]]
        require(direction in chains and proto in ["tcp", "udp"])
        require(str(ipaddress.IPv4Network(peer)) == peer and ipaddress.IPv4Network(peer).prefixlen == 32)
        require(isinstance(port, str) and re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", port))
        low, *rest = map(int, port.split("-")); high = rest[0] if rest else low
        require(1 <= low <= high <= 65535 and not any(low <= p <= high for p in [137, 138, 139, 3389]))
        chains[direction].append(f"ip {'saddr' if direction == 'IN' else 'daddr'} {peer} {proto} dport {port} accept")
    # The current SSH path must already be represented exactly, with no generic rule.
    require(all(f"ip saddr {peer} tcp dport 22 accept" in chains["IN"] for peer in policy["admin_sources"]))
    lines = ["table inet samba_ad_s4 {"]
    for direction, name, interface in [("IN", "input", "iifname"), ("OUT", "output", "oifname")]:
        lines += [f"chain {name} {{", f"type filter hook {name} priority 10; policy drop;",
                  f'{interface} "lo" accept', "ct state established,related accept"] + chains[direction] + ["}"]
    return "\n".join(lines + ["}", ""])


def state():
    data = json.loads(command(["nft", "-j", "list", "table", "inet", "samba_ad_s4"]))
    def normalize(value):
        if isinstance(value, list): return [normalize(v) for v in value if not isinstance(v, dict) or "metainfo" not in v]
        if isinstance(value, dict): return {k: normalize(v) for k, v in value.items() if k != "handle"}
        return value
    return sha(normalize(data))


def inspect(request):
    config = render(request["substrate"]["firewall"])
    tables = json.loads(command(["nft", "-j", "list", "tables"]))
    present = any(v.get("table", {}).get("name") == "samba_ad_s4" for v in tables["nftables"])
    receipt = Path("/var/lib/samba-ad-domain/network.json")
    if present:
        observed = json.loads(secure_file(receipt, secret=True).read_bytes())
        fields(observed, "spec_sha256 config_sha256 live_sha256")
        require(observed == {"spec_sha256": request["pki"]["target"]["spec_sha256"],
                             "config_sha256": sha(config), "live_sha256": state()})
    else:
        require(not receipt.exists() and not receipt.is_symlink())
        command(["nft", "--check", "--file", "-"], config.encode())
    return present


def install(request):
    require(not inspect(request))
    directory = future_directory("/var/lib/samba-ad-domain")
    if not directory.exists(): directory.mkdir(mode=0o700)
    config = render(request["substrate"]["firewall"])
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "enable", "--now", "samba-ad-firewall.service"])
    receipt = {"spec_sha256": request["pki"]["target"]["spec_sha256"],
               "config_sha256": sha(config), "live_sha256": state()}
    atomic_file(directory / "network.json", json.dumps(receipt).encode())
