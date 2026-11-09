"""Purpose-bound NEW client qualification. Never substitutes DC/Linux evidence.

The immutable reviewed private inventory is the trust root, as in S2/S3.
Hashes establish consistency, not independent approval or a runtime pass.
"""
from __future__ import annotations
import ipaddress
import re
import uuid
try:
    from tools.samba_ad.compatibility import fields, hex_value, require, sha
    from tools.samba_ad.contract import validate_manifest
except ImportError:
    from s2_compatibility import fields, hex_value, require, sha
    from s0_contract import validate_manifest

SCHEMA = "samba-ad-pilot-substrate/v1"


def review(value):
    require(isinstance(value, str) and re.fullmatch(r"git:[a-f0-9]{40}:[A-Za-z0-9_./-]+", value)
            and ".." not in value)


def validate_pilot_bundle(envelope, target):
    fields(envelope, "sha256 data")
    d = envelope["data"]
    require(envelope["sha256"] == sha(d))
    fields(d, "schema purpose manifest target_sha256 report clone_uuid provenance")
    require(d["schema"] == SCHEMA and d["purpose"] in ["linux_pilot", "windows_pilot"])
    validate_manifest(d["manifest"])
    require(target["scope"] == "production" and target["action"] in ["present", "start"])
    require(d["target_sha256"] == sha({k: target[k] for k in
            ["owner", "scope", "resource", "template", "firewall"]}))
    resource = target["resource"]; declared = d["manifest"]["resources"][d["purpose"]]
    require(resource["kind"] == declared["kind"] == "qemu")
    require(all(resource[k] == declared[k] for k in ["vmid", "node", "kind", "mac", "bridge",
                "storage", "cores", "memory_mib", "disk_gib"]))
    require(resource["name"] == declared["fqdn"] and target["owner"] == declared["owner"] == "samba-ad")
    address = ipaddress.IPv4Interface(resource["address"])
    require(str(address.ip) == declared["address"] and str(address.network) == declared["cidr"])
    for key in ["gateway", "mtu"]: require(resource[key] == d["manifest"]["network"][key])
    for key in ["node", "vmid", "storage"]: require(target["template"][key] == declared["template"][key])
    require(target["template"]["disk"] == "scsi0")
    require(str(uuid.UUID(d["clone_uuid"])) == d["clone_uuid"])
    report = d["report"]
    fields(report, "schema platform_fingerprint template_observation subject artifact_sha256 review_ref" +
           (" hardware" if d["purpose"] == "windows_pilot" else ""))
    require(report["schema"] == "samba-ad-pilot-template-observation/v1")
    hex_value(report["artifact_sha256"], 64); review(report["review_ref"])
    fp = report["platform_fingerprint"]
    fields(fp, "nodes templates isolation policy_sha256")
    require(set(fp["nodes"]) == {resource["node"], target["template"]["node"]})
    for version in fp["nodes"].values():
        fields(version, "kernel pve")
        require(all(isinstance(v, str) and 0 < len(v) <= 256 for v in version.values()))
    template = {k: target["template"][k] for k in ["node", "vmid", "digest"]} | {"kind": "qemu"}
    require(fp["templates"] == [template] and fp["isolation"] == "qemu-no-passthrough")
    require(fp["policy_sha256"] == sha(target["firewall"]))
    subject = report["subject"]
    fields(subject, "node template config_digest boot_id uuid mac")
    require(subject["node"] == resource["node"] and subject["template"] == template)
    hex_value(subject["config_digest"], 40)
    require(str(uuid.UUID(subject["uuid"])) == subject["uuid"] != d["clone_uuid"])
    require(re.fullmatch(r"[a-zA-Z0-9:.-]{10,64}", subject["boot_id"]))
    require(re.fullmatch(r"02(?::[0-9A-F]{2}){5}", subject["mac"]) and subject["mac"] != resource["mac"])
    obs = report["template_observation"]
    fields(obs, "family edition build architecture machine_id local_sid image_state domain")
    require(obs["domain"] is None and obs["architecture"] == "x86_64")
    require(isinstance(obs["machine_id"], str) and re.fullmatch(r"[a-f0-9-]{32,36}", obs["machine_id"]))
    if d["purpose"] == "linux_pilot":
        require(obs["family"] == "debian" and obs["edition"] == "13" and obs["build"] == "13")
        require(obs["local_sid"] is None and obs["image_state"] == "machine-id-empty")
    else:
        validate_windows_hardware(report["hardware"], target)
        # Server 2025 only. TPM remains forbidden; the selected VBS baseline
        # requires Secure Boot, not a TPM or copied TPM secret state.
        require(obs["family"] == "windows" and obs["build"] == "26100")
        require(obs["edition"] in ["ServerStandard", "ServerDatacenter", "ServerStandardEval", "ServerDatacenterEval"])
        require(re.fullmatch(r"S-1-5-21-(?:[0-9]+-){2}[0-9]+", obs["local_sid"]))
        require(obs["image_state"] == "IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE")
    p = d["provenance"]
    fields(p, "reviewed_config_revision path review_ref")
    hex_value(p["reviewed_config_revision"], 40); review(p["review_ref"])
    require(p["path"] == "inventories/prod/contracts/samba-ad-" + d["purpose"].replace("_", "-") + ".yml")
    require(p["review_ref"] == report["review_ref"])
    return fp


def pilot_data(request):
    data = (request.get("compatibility") or {}).get("data", {})
    return data if data.get("schema") == SCHEMA else None


def validate_windows_hardware(h, target):
    """Private reviewed observations, bound by envelope/template/platform pins."""
    fields(h, "bios machine cpu efi_sha256 template_volumes clone_volumes destination_volumes nodes native")
    require(h["bios"] == "ovmf" and h["cpu"] == "host")
    require(isinstance(h["machine"], str) and re.fullmatch(r"pc-q35-[0-9]+\.[0-9]+", h["machine"]))
    hex_value(h["efi_sha256"], 64)
    t, c = target["template"], target["resource"]
    fields(h["template_volumes"], "scsi0 efidisk0")
    for volume in h["template_volumes"].values():
        require(isinstance(volume, str) and re.fullmatch(re.escape(t["storage"])+r":(?:"+str(t["vmid"])+r"/)?base-"+str(t["vmid"])+r"-disk-[0-9]+(?:\.(?:raw|qcow2))?", volume))
    require(len(set(h["template_volumes"].values())) == 2)
    for stage, storage in [("clone_volumes",t["storage"]),("destination_volumes",c["storage"])]:
        fields(h[stage], "scsi0 efidisk0")
        for volume in h[stage].values():
            require(isinstance(volume, str) and re.fullmatch(re.escape(storage)+r":(?:"+str(c["vmid"])+r"/)?vm-"+str(c["vmid"])+r"-disk-[0-9]+(?:\.(?:raw|qcow2))?", volume))
        require(len(set(h[stage].values())) == 2)
    if t["node"] == c["node"]:
        require(h["clone_volumes"] == h["destination_volumes"])

    require(set(h["nodes"]) == {t["node"], c["node"]})
    for n in h["nodes"].values():
        fields(n, "vendor model extension slat nested boot_id artifact_sha256")
        require((n["vendor"], n["extension"], n["slat"]) in [("GenuineIntel","vmx","ept"),("AuthenticAMD","svm","npt")])
        require(isinstance(n["model"], str) and 0 < len(n["model"]) <= 256 and n["nested"] is True)
        require(str(uuid.UUID(n["boot_id"])) == n["boot_id"])
        hex_value(n["artifact_sha256"], 64)
    require(len({(n["vendor"], n["model"]) for n in h["nodes"].values()}) == 1)
    fields(h["native"], "secure_boot available_security_properties uefi_lock_capable")
    require(h["native"]["secure_boot"] is True and h["native"]["uefi_lock_capable"] is True)
    require(isinstance(h["native"]["available_security_properties"], list)
            and {1, 2, 5} <= set(h["native"]["available_security_properties"]))
