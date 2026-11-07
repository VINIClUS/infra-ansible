"""Offline expansion of the reviewed Samba matrix. No DNS, SSH, secrets or mutation."""
import ipaddress
from tools.samba_ad.contract import require, validate_manifest


def exact(value):
    network = ipaddress.IPv4Network(value if "/" in value else value + "/32")
    require(network.prefixlen == 32, "exact policy endpoint")
    return str(network)


def expand(manifest, policy, collector):
    validate_manifest(manifest)
    groups = {name: [exact(manifest["resources"][r]["address"]) for r in roles]
              for name, roles in policy["resource_groups"].items()}
    groups.update(administrators=[exact(x) for x in manifest["network"]["admin_sources"]],
                  dns_forwarders=[exact(x) for x in manifest["network"]["dns_forwarders"]],
                  time_sources=[exact(x) for x in manifest["network"]["time_sources"]], collector=[exact(collector)])
    result = {role: {"admin_sources": manifest["network"]["admin_sources"], "flows": []}
              for role in manifest["resources"]}
    endpoints = {exact(r["address"]): role for role, r in manifest["resources"].items()}
    for flow in policy["flows"]:
        for source in groups[flow["source"]]:
            for destination in groups[flow["destination"]]:
                if source == destination:
                    continue
                for endpoint, peer, direction in [(source, destination, "OUT"), (destination, source, "IN")]:
                    if endpoint not in endpoints:
                        continue
                    for port in flow["ports"]:
                        rule = {"direction": direction, "peer": peer, "proto": flow["protocol"], "port": str(port)}
                        rules = result[endpoints[endpoint]]["flows"]
                        if rule not in rules:
                            rules.append(rule)
    return result


def router_rules(manifest, guest_policies, zones):
    networks = {name: ipaddress.IPv4Network(cidr) for name, cidr in zones.items()}
    def zone(address):
        matches = [name for name, net in networks.items() if ipaddress.IPv4Network(address).network_address in net]
        require(len(matches) <= 1, "non-overlapping router zones")
        return matches[0] if matches else "wan"
    result = []
    for role, fw in guest_policies.items():
        endpoint = exact(manifest["resources"][role]["address"])
        for flow in fw["flows"]:
            src, dst = (flow["peer"], endpoint) if flow["direction"] == "IN" else (endpoint, flow["peer"])
            if zone(src) == zone(dst):
                continue  # Enforced by PVE guest firewall, never inferred to traverse the router.
            rule = {"from": zone(src), "to": zone(dst), "saddr": src, "daddr": dst,
                    "proto": flow["proto"], "dport": flow["port"], "comment": "samba-ad exact flow"}
            if rule not in result:
                result.append(rule)
    return result
