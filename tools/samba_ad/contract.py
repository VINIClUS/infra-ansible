"""Validate an S0 manifest locally. Success is not authorization or readiness."""
from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import re
import sys

import yaml


class ContractError(ValueError):
    """An invalid contract, with no input values in the message."""


def require(condition, field):
    if not condition:
        raise ContractError(f"invalid S0 contract: {field}")


def mapping(value, field):
    require(isinstance(value, dict), field)
    return value


def fields(value, expected, field):
    require(set(value) == set(expected.split()), field)


def integer(value, minimum, maximum, field):
    require(type(value) is int and minimum <= value <= maximum, field)


def ipv4(value):
    require(isinstance(value, str), "IPv4 address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ContractError("invalid S0 contract: IPv4 address") from None
    require(address.version == 4 and not address.is_unspecified and not address.is_multicast, "IPv4 address")
    return address


def subnet(value):
    require(isinstance(value, str), "IPv4 subnet")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ContractError("invalid S0 contract: IPv4 subnet") from None
    require(network.version == 4 and network.prefixlen >= 24, "IPv4 subnet")
    return network


def validate_manifest(data):
    """Check declarations only; do not resolve secrets, DNS, SSH or Proxmox."""
    data = mapping(data, "root")
    require(set(data) == {
        "schema", "stage", "enabled", "apply", "owner", "execution", "domain", "network",
        "resources", "software", "secret_refs", "certificate_profiles", "split_dns",
    }, "root fields")
    require(type(data["schema"]) is int and data["schema"] == 1, "schema")
    require(data["stage"] == "S0", "stage")
    require(data["enabled"] is False and data["apply"] is False, "disabled defaults")
    require(isinstance(data["owner"], str) and re.fullmatch(r"[a-z0-9-]+", data["owner"]), "owner")
    execution = mapping(data["execution"], "execution")
    require(execution == {
        "mode": "manual", "exact_limit_required": True, "dedicated_tag_required": True,
        "identity_readback_required": True, "digest_required": True,
    } and all(type(v) is bool for k, v in execution.items() if k != "mode"), "execution")
    domain = mapping(data["domain"], "domain")
    fields(domain, "dns_domain realm netbios sid new_forest_confirmed", "domain fields")
    dns = domain.get("dns_domain")
    require(isinstance(dns, str) and len(dns) <= 253 and re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", dns
    ) and all(len(label) <= 63 for label in dns.split(".")), "domain name")
    require(domain.get("realm") == dns.upper(), "realm")
    require(isinstance(domain.get("netbios"), str) and re.fullmatch(r"[A-Z][A-Z0-9-]{0,14}", domain["netbios"]), "NetBIOS")
    require(domain.get("new_forest_confirmed") is True and domain.get("sid") is None, "new forest identity")
    network = mapping(data["network"], "network")
    fields(network, "cidr gateway vnet tag mtu existing_cidrs admin_sources dns_forwarders time_sources", "network fields")
    identity = subnet(network.get("cidr"))
    gateway = ipv4(network.get("gateway"))
    require(gateway in identity and gateway not in [identity.network_address, identity.broadcast_address], "gateway")
    require(isinstance(network.get("vnet"), str) and re.fullmatch(r"[a-z][a-z0-9]{0,7}", network["vnet"]), "VNet")
    integer(network.get("tag"), 1, 16777215, "VXLAN tag")
    integer(network.get("mtu"), 1280, 1500, "MTU")
    require(isinstance(network.get("existing_cidrs"), list) and network["existing_cidrs"], "existing networks")
    require(all(not identity.overlaps(subnet(n)) for n in network["existing_cidrs"]), "network overlap")
    require(isinstance(network.get("admin_sources"), list) and network["admin_sources"], "administrators")
    for source in network["admin_sources"]:
        require(subnet(source).prefixlen == 32, "exact administrative origins")
    for field in ["dns_forwarders", "time_sources"]:
        require(isinstance(network.get(field), list) and network[field], field)
        for address in network[field]:
            ipv4(address)
    resources = mapping(data["resources"], "resources")
    require(set(resources) == {"dc01", "dc02", "ca", "backup", "windows_pilot", "linux_pilot"}, "resource roles")
    seen = {k: set() for k in ["vmid", "mac", "address", "fqdn"]}
    for role, resource in resources.items():
        resource = mapping(resource, "resource")
        expected = "vmid node kind fqdn owner state mac address cidr bridge storage template full_clone first_boot_after_migration cores memory_mib disk_gib"
        if resource.get("kind") == "lxc":
            expected += " unprivileged nesting apparmor"
        fields(resource, expected, "resource fields")
        integer(resource.get("vmid"), 100, 999999999, "VMID")
        require(resource.get("kind") in ["lxc", "qemu"], "guest type")
        require(resource.get("owner") == data["owner"] and resource.get("state") == "candidate", "ownership/candidate")
        require(resource.get("full_clone") is True and resource.get("first_boot_after_migration") is True, "clone ordering")
        require(isinstance(resource.get("node"), str) and re.fullmatch(r"[a-z0-9-]+", resource["node"]), "placement")
        require(isinstance(resource.get("storage"), str) and resource["storage"], "target storage")
        require(resource.get("fqdn") == f"{role.replace('_', '-')}.{dns}", "FQDN")
        mac = resource.get("mac")
        require(isinstance(mac, str) and re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", mac), "MAC")
        require(int(mac[:2], 16) & 3 == 2, "local unicast MAC")
        address = ipv4(resource.get("address"))
        resource_net = subnet(resource.get("cidr"))
        require(address in resource_net and address not in [resource_net.network_address, resource_net.broadcast_address, gateway], "guest address")
        if role != "backup":
            require(resource_net == identity and resource.get("bridge") == network["vnet"], "identity network")
        else:
            require(not resource_net.overlaps(identity), "backup isolation")
        for field in seen:
            require(resource[field] not in seen[field], "duplicate resource identity")
            seen[field].add(resource[field])
        template = mapping(resource.get("template"), "template")
        fields(template, "vmid node kind storage", "template fields")
        integer(template.get("vmid"), 100, 999999999, "template VMID")
        require(template.get("kind") == resource["kind"], "template guest type")
        require(all(isinstance(template.get(k), str) and template[k] for k in ["node", "storage"]), "template placement")
        integer(resource.get("cores"), 1, 16, "CPU")
        integer(resource.get("memory_mib"), 1024, 65536, "RAM")
        integer(resource.get("disk_gib"), 16, 1024, "disk")
        if role.startswith("dc"):
            require(resource["cores"] == 2 and resource["memory_mib"] == 4096 and resource["disk_gib"] == 64, "DC sizing")
        else:
            require(resource["kind"] == "qemu", "non-DC VM isolation")
        if resource["kind"] == "lxc":
            require(resource.get("unprivileged") is True and resource.get("nesting") is False and resource.get("apparmor") == "default", "LXC isolation")
    require(resources["dc01"]["node"] != resources["dc02"]["node"], "DC physical separation")
    require(all(r["template"]["vmid"] not in seen["vmid"] for r in resources.values()), "template/resource collision")
    software = mapping(data["software"], "software")
    fields(software, "os samba_version functional_level schema_version source_candidate suite signature_status advisory_status fingerprint_ref", "software fields")
    require(software.get("samba_version") == "4.25.1" and software.get("functional_level") == "2016" and software.get("schema_version") == 88, "Samba version/levels")
    require(software.get("signature_status") == "pending" and software.get("advisory_status") == "pending", "S0 source verification status")
    refs = mapping(data["secret_refs"], "secret references")
    require(set(refs) == {"domain_admin", "dsrm", "ca_provisioner", "sysvol", "backup", "telemetry"}, "secret profiles")
    for ref in refs.values():
        ref = mapping(ref, "secret reference")
        require(set(ref) == {"vault_file", "variable"}, "secret reference fields")
        path = ref["vault_file"]
        require(isinstance(path, str) and path.startswith("inventories/prod/") and path.endswith("/vault.yml") and ".." not in path.split("/"), "vault file reference")
        require(isinstance(ref["variable"], str) and re.fullmatch(r"vault_samba_ad_[a-z0-9_]+", ref["variable"]), "vault variable reference")
    require(len({r["variable"] for r in refs.values()}) == len(refs), "distinct secret profiles")
    profiles = mapping(data["certificate_profiles"], "certificate profiles")
    require(set(profiles) == {"dc01", "dc02", "ca", "telemetry_dc01", "telemetry_dc02", "telemetry_ca", "telemetry_backup"}, "certificate roles")
    for role, profile in profiles.items():
        profile = mapping(profile, "certificate profile")
        fields(profile, "sans eku validity_hours rotate_before_fraction", "certificate fields")
        expected = resources[role.removeprefix("telemetry_")]["fqdn"]
        eku = "clientAuth" if role.startswith("telemetry_") else "serverAuth"
        require(profile.get("sans") == [expected] and profile.get("eku") == [eku], "certificate identity")
        require(profile.get("validity_hours") == 168 and profile.get("rotate_before_fraction") == 0.66, "certificate lifecycle")
    split = mapping(data["split_dns"], "split DNS")
    fields(split, "strategy municipal_cutover pilot_public_names", "split DNS fields")
    require(split.get("strategy") == "explicit_records" and split.get("municipal_cutover") is False, "split DNS scope")
    require(isinstance(split.get("pilot_public_names"), list) and split["pilot_public_names"], "pilot DNS tests")
    require(all(isinstance(n, str) and re.fullmatch(r"[a-z0-9.-]+", n) and "." in n and "*" not in n for n in split["pilot_public_names"]), "pilot DNS names")
    return {"resources": len(resources), "secret_refs": len(refs)}


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate keys so activation cannot be hidden by last-key-wins."""


def unique_mapping(loader, node, deep=False):
    pairs = loader.construct_pairs(node, deep=deep)
    require(len({key for key, _ in pairs}) == len(pairs), "duplicate YAML key")
    return dict(pairs)


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_manifest(yaml.load(args.manifest.read_text(), Loader=UniqueLoader))
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
        print("invalid S0 contract (input values suppressed)", file=sys.stderr)
        return 2
    print(f"S0 inert contract valid: resources={result['resources']} secret_refs={result['secret_refs']}; no readiness claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
