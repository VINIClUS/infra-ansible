"""Purpose-bound CA evidence. Reuses S1 lifecycle, never qualifies a DC.

The reviewed immutable private configuration is the operational trust root.
Hashes establish coherence, not authenticity of an operator or remote review.
"""
from __future__ import annotations

import ipaddress
import re

try:
    import s2_compatibility as evidence
except ImportError:
    from tools.samba_ad import compatibility as evidence

SCHEMA = "samba-ad-ca-substrate-bundle/v1"
CA_CHECKS = {"posix_acl", "systemd", "clock", "audit", "isolation", "network"}


def require(value):
    if not value:
        raise ValueError("S3 CA evidence precondition failed (values suppressed)")


def fields(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected.split()))


def review(value):
    require(isinstance(value, str) and re.fullmatch(r"git:[a-f0-9]{40}:[a-zA-Z0-9_./-]+", value)
            and ".." not in value)


def validate_ca_bundle(envelope: dict, target: dict) -> dict:
    """Accept only the manifest-bound CA QEMU target with measured substrate.

    A single CA placement is sufficient for this purpose. This neither selects
    the DC platform nor relaxes the two-node DC qualification in S2.
    """
    fields(envelope, "sha256 data")
    evidence.hex_value(envelope["sha256"], 64)
    data = envelope["data"]
    require(evidence.sha(data) == envelope["sha256"])
    fields(data, "schema purpose manifest report target_sha256 prerequisites provenance audit")
    require(data["schema"] == SCHEMA and data["purpose"] == "ca")
    require(target["scope"] == "production" and target["action"] in ["present", "start"])
    require(data["target_sha256"] == evidence.sha({k: target[k] for k in
                                                 ["owner", "scope", "resource", "template", "firewall"]}))
    manifest = data["manifest"]
    fields({k: v for k, v in manifest.items() if k != 'telemetry_collector'}, "schema stage enabled apply owner execution domain network resources software secret_refs "
                     "certificate_profiles split_dns")
    require(type(manifest["schema"]) is int and manifest["schema"] == 1 and manifest["stage"] == "S0")
    require(manifest["enabled"] is False and manifest["apply"] is False and manifest["owner"] == "samba-ad")
    require(set(manifest["resources"]) == {"dc01", "dc02", "ca", "windows_pilot", "linux_pilot"})
    ca = manifest["resources"]["ca"]
    fields(ca, "vmid node kind fqdn owner state mac address cidr bridge storage template full_clone "
               "first_boot_after_migration cores memory_mib disk_gib")
    require(ca["owner"] == target["owner"] == "samba-ad" and ca["state"] == "candidate")
    require(ca["full_clone"] is True and ca["first_boot_after_migration"] is True)
    resource = target["resource"]
    require(resource["kind"] == ca["kind"] == "qemu")
    require(tuple(resource[k] for k in ["cores", "memory_mib", "disk_gib"]) == (2, 2048, 20))
    require(all(resource[k] == ca[k] for k in ["vmid", "node", "kind", "mac", "bridge", "storage",
                                               "cores", "memory_mib", "disk_gib"]))
    require(resource["name"] == ca["fqdn"] and not ca["fqdn"].endswith(".lab.ad.test"))
    address = ipaddress.IPv4Interface(resource["address"])
    require(str(address.ip) == ca["address"] and str(address.network) == ca["cidr"] == manifest["network"]["cidr"])
    require(resource["gateway"] == manifest["network"]["gateway"] and resource["mtu"] == manifest["network"]["mtu"])
    declared_template = ca["template"]
    fields(declared_template, "vmid node kind storage")
    require(declared_template["kind"] == "qemu")
    require(all(target["template"][k] == declared_template[k] for k in ["vmid", "node", "storage"]))
    require(target["template"]["disk"] == "scsi0")

    report = evidence.validate_report(data["report"])
    fingerprint = report["platform_fingerprint"]
    template = {k: target["template"][k] for k in ["node", "vmid", "digest"]} | {"kind": "qemu"}
    require(template in fingerprint["templates"] and fingerprint["isolation"] == "qemu-no-passthrough")
    require(fingerprint["policy_sha256"] == evidence.sha(target["firewall"]))
    require(resource["node"] in evidence.qualified_nodes(report, "qemu", CA_CHECKS, template))
    subjects = [s for s in report["subjects"] if s["node"] == resource["node"] and s["template"] == template]
    require(any(all(report["observations"][s["key"]][k] for k in ["before", "after", "result"]) for s in subjects))
    require(target["template"]["node"] in fingerprint["nodes"])
    fields(data["prerequisites"], "s1_state s2_state")
    for prerequisite in data["prerequisites"].values():
        fields(prerequisite, "sha256 review_ref")
        evidence.hex_value(prerequisite["sha256"], 64)
        review(prerequisite["review_ref"])
    provenance = data["provenance"]
    fields(provenance, "reviewed_config_revision path review_ref")
    evidence.hex_value(provenance["reviewed_config_revision"], 40)
    require(provenance["path"] == "inventories/prod/contracts/samba-ad-ca-substrate.yml")
    review(provenance["review_ref"])
    audit = data["audit"]
    fields(audit, "schema scope decision review_ref public_revision private_revision manifest_sha256 "
                  "report_sha256 prerequisites_sha256 target_sha256")
    require(type(audit["schema"]) is int and audit["schema"] == 1 and audit["scope"] == "S3-ca-substrate"
            and audit["decision"] == "accept" and audit["review_ref"] == provenance["review_ref"])
    for key in ["manifest", "report", "prerequisites"]:
        require(audit[key + "_sha256"] == evidence.sha(data[key]))
    require(audit["target_sha256"] == data["target_sha256"])
    for key in ["public_revision", "private_revision"]:
        require(audit[key] == report[key])
    return fingerprint
