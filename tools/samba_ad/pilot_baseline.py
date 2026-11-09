"""Complete, source-pinned Server 2025 v2602 member-server baseline catalog.

No caller-selected subset. Every selected backup file and policy setting is
covered. The catalog is derived from the public Microsoft artifact, not a runtime
acceptance receipt. Downloaded code is never executed.
"""
import csv
import hashlib
import io
import re
import struct
import xml.etree.ElementTree as ET
import zipfile

URL = "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%20Server%202025%20Security%20Baseline%20-%202602.zip"
SHA256 = "a66dffbe2622c3c4dd70e44a7f2080f362fb2d6f9208c50678671cbb046a286f"
ROOT = "Windows Server 2025 Security Baseline - 2602"
COMPONENTS = {
    "member": "066B7FF5-BF2B-4B1B-8A92-2A83B8619444",
    "ie-computer": "2E1948EE-56EE-45A1-9473-D5A4C2153E5F",
    "domain-security": "40CF40AD-F1B2-433F-A5C9-032DB7424608",
    "credential-guard": "5DCDD718-EB35-4D88-9E9A-2B936D7B8A4B",
    "defender": "B0CBE378-B19F-440E-A939-80B79E48C4EF",
    "ie-user": "F74D904A-2A4B-4865-8877-3E71FEFF91FF",
}
REPLACEMENTS = {
    "PasswordHistorySize": {"vendor": "24", "required": "30", "reason": "S4 password history 30"},
    "LockoutBadCount": {"vendor": "3", "required": "10", "reason": "S4 lockout threshold 10"},
}
DEFERRED = ["encrypted-LAPS", "WHfB", "AES-only", "NTLM-disabled"]


def require(value):
    if not value: raise ValueError("S6 baseline coverage failed (values suppressed)")


def pol(data):
    require(data[:8] == b"PReg\x01\0\0\0")
    pos = 8; rows = []
    def take(n):
        nonlocal pos
        require(0 <= n <= 1048576 and pos+n <= len(data))
        result = data[pos:pos+n]; pos += n; return result
    def word(): return struct.unpack("<H", take(2))[0]
    def string():
        value = []
        while (c := word()) != 0: value.append(chr(c))
        return "".join(value)
    while pos < len(data):
        require(word() == 91); key = string(); require(word() == 59)
        name = string(); require(word() == 59)
        kind = struct.unpack("<I", take(4))[0]; require(word() == 59)
        size = struct.unpack("<I", take(4))[0]; require(word() == 59)
        value = take(size); require(word() == 93)
        require(kind in [0, 1, 4])
        require((kind != 0 or (name == "" and value == b"")) and (kind != 4 or len(value) == 4))
        if kind == 1: require(value.endswith(b"\0\0") and len(value) % 2 == 0)
        require(not name.startswith("**") or name.startswith("**del."))
        rows.append({"key": key, "name": name, "type": kind, "data": value.hex()})
    require(len({(r["key"].lower(), r["name"].lower()) for r in rows}) == len(rows))
    return rows


def inf(data):
    text = data.decode("utf-16"); rows = {}; section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"): continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]; require(section not in rows); rows[section] = {}; continue
        require(section is not None and "=" in line)
        name, value = [s.strip() for s in line.split("=", 1)]
        require(name not in rows[section]); rows[section][name] = value
    require(set(rows) <= {"Unicode", "Version", "System Access", "Registry Values", "Privilege Rights"})
    require(rows["Unicode"] == {"Unicode": "yes"} and rows["Version"] == {"signature": '"$CHICAGO$"', "Revision": "1"})
    for name, value in rows.get("Privilege Rights", {}).items():
        require(re.fullmatch(r"Se[A-Za-z]+", name))
        require(all(re.fullmatch(r"\*S-[0-9-]+", x.strip()) for x in value.split(",") if x.strip()))
    for name, value in rows.get("Registry Values", {}).items():
        require(name.startswith("MACHINE\\") and re.fullmatch(r'(4,[0-9]+|1,"[^"]*")', value))
    for value in rows.get("System Access", {}).values(): require(re.fullmatch(r"[0-9]+", value))
    return rows


def audit(data):
    reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
    require(reader.fieldnames == ["Machine Name", "Policy Target", "Subcategory", "Subcategory GUID",
                                 "Inclusion Setting", "Exclusion Setting", "Setting Value"])
    rows = list(reader)
    for row in rows:
        require(row["Machine Name"] == row["Exclusion Setting"] == "" and row["Policy Target"] == "System")
        require(re.fullmatch(r"\{[0-9a-f-]{36}\}", row["Subcategory GUID"]))
        require(row["Setting Value"] in ["1", "2", "3"])
    require(len({r["Subcategory GUID"] for r in rows}) == len(rows))
    return rows


def catalog(archive):
    require(hashlib.sha256(archive).hexdigest() == SHA256)
    z = zipfile.ZipFile(io.BytesIO(archive))
    files = {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if not n.endswith("/")}
    require(len(files) == sum(not n.endswith("/") for n in z.namelist()))
    result = {"schema": "samba-ad-ms-baseline/v2", "url": URL, "sha256": SHA256,
              "root": ROOT, "files": files, "components": {}, "replacements": REPLACEMENTS,
              "deferred_absent": DEFERRED}
    for key, guid in COMPONENTS.items():
        prefix = ROOT + "/GPOs/{" + guid + "}/"
        backup = ET.fromstring(z.read(prefix + "Backup.xml"))
        names = [e.text for e in backup.iter() if e.tag.endswith("}DisplayName")]
        require(len(names) == 1)
        item = {"backup_id": guid, "name": names[0], "files": {}, "policies": [], "security": {}, "audit": [], "extensions": {}}
        for scope in ["Machine", "User"]:
            values = [e.text or "" for e in backup.iter() if e.tag.endswith("}" + scope + "ExtensionGuids")]
            require(len(values) <= 1)
            item["extensions"][scope] = re.findall(r"\[\{([A-Fa-f0-9-]{36})\}", values[0] if values else "")
        for filename in files:
            if not filename.startswith(prefix + "DomainSysvol/GPO/"): continue
            relative = filename[len(prefix + "DomainSysvol/GPO/"):]
            raw = z.read(filename)
            if relative.lower().endswith("registry.pol"):
                for row in pol(raw): item["policies"].append(row | {"scope": relative.split("/")[0]})
            elif relative.lower().endswith("gpttmpl.inf"):
                item["security"] = inf(raw)
                if key == "domain-security":
                    for setting, replacement in REPLACEMENTS.items():
                        require(item["security"]["System Access"][setting] == replacement["vendor"])
                        item["security"]["System Access"][setting] = replacement["required"]
                    for setting, replacement in REPLACEMENTS.items():
                        raw = raw.decode("utf-16").replace(setting + " = " + replacement["vendor"],
                                     setting + " = " + replacement["required"]).encode("utf-16")
            elif relative.lower().endswith("audit.csv"): item["audit"] = audit(raw)
            elif relative.lower().endswith("comment.cmtx"): ET.fromstring(raw)  # comment metadata, pinned verbatim
            else: require(False)  # every policy-bearing file needs an adapter
            item["files"][relative] = hashlib.sha256(raw).hexdigest()
        # No blind P1 exclusions: assert the pinned release has none of them.
        for row in item["policies"]:
            text = (row["key"] + "\\" + row["name"]).lower()
            require(not any(x in text for x in ["passportforwork", "\\laps\\", "supportedencryptiontypes", "blockntlm"]))
        result["components"][key] = item
    return result


def validate_request(b, ou):
    from tools.samba_ad.pilot_baseline_catalog import CATALOG
    from tools.samba_ad.pilot_substrate import review
    require(set(b) == {"title", "publisher", "url", "sha256", "archive", "gpo_name", "review_ref", "catalog_sha256"})
    require(b["title"] == "Windows Server 2025 Security Baseline v2602" and b["publisher"] == "Microsoft Corporation")
    require(b["url"] == URL and b["sha256"] == SHA256 and b["archive"] == "C:\\SambaADAssets\\baseline.zip")
    require(b["gpo_name"] == ou.split(",")[0][3:]); review(b["review_ref"])
    import json
    require(b["catalog_sha256"] == hashlib.sha256(json.dumps(CATALOG, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
