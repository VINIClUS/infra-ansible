"""Fresh host-local DC checks and DC01-only owned pilot directory creation."""
from __future__ import annotations
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
from tools.samba_ad.pilots import require, sha, membership_action


def command(argv):
    p = subprocess.run(argv, capture_output=True, timeout=120, check=False)
    require(p.returncode == 0)
    return p.stdout


def text(value):
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def database():
    from samba.auth import system_session
    from samba.param import LoadParm
    from samba.samdb import SamDB
    lp = LoadParm(); lp.load("/etc/samba/smb.conf")
    return SamDB(url="/var/lib/samba/private/sam.ldb", session_info=system_session(), lp=lp)


def check_replication(data, base, peer, now):
    required = {base, "CN=Configuration," + base, "CN=Schema,CN=Configuration," + base,
                "DC=DomainDnsZones," + base, "DC=ForestDnsZones," + base}
    rows = data.get("repsFrom")
    require(isinstance(rows, list))
    seen = set()
    for row in rows:
        require(row["is deleted"] is False and row["consecutive failures"] == 0)
        require(row["last attempt message"] == "was successful")
        require((",CN=" + peer.upper() + ",CN=Servers,").lower() in row["NTDS DN"].lower())
        last = datetime.datetime.strptime(row["last success"], "%a %b %d %H:%M:%S %Y %Z").replace(
            tzinfo=datetime.timezone.utc).timestamp()
        require(0 <= now-last <= 900)
        seen.add(row["NC dn"])
    require(seen == required)


def tree_digest(root):
    root = Path(root); require(root.is_dir() and not root.is_symlink())
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink())
        if path.is_file(): result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        else: require(path.is_dir())
    require(result and any(k.lower().endswith("gpt.ini") for k in result))
    return sha(result)


def inspect(r, manifest, role):
    import ldb
    from tools.samba_ad.domain_source import verify_installed
    require(role in ["dc01", "dc02"] and os.geteuid() == 0)
    expected = r["dcs"][role]
    require(socket.getfqdn() == expected["fqdn"])
    require(Path("/etc/machine-id").read_text().strip() == expected["machine_id"])
    require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == expected["boot_id"])
    require(command(["samba", "--version"]).decode().strip() == "Version 4.25.1")
    verify_installed(expected["source"])
    links = json.loads(command(["ip", "-j", "addr"]))
    declared = manifest["resources"][role]
    require(any(link.get("address", "").upper() == declared["mac"] and
                any(a.get("local") == expected["address"] for a in link.get("addr_info", [])) for link in links))
    cert_path = command(["testparm", "-s", "--parameter-name=tls certfile"]).decode().strip()
    cert = Path(cert_path).read_text()
    require(hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest() == expected["certificate_sha256"])
    db = database(); require(str(db.get_domain_sid()) == r["sid"])
    base = str(db.domain_dn())
    require(base.lower() == ",".join("DC=" + s for s in manifest["domain"]["dns_domain"].split(".")).lower())
    for dn, attr, value in [(base, "msDS-Behavior-Version", "7"),
            ("CN=Partitions," + str(db.get_config_basedn()), "msDS-Behavior-Version", "7"),
            (str(db.get_schema_basedn()), "objectVersion", "88")]:
        require(text(db.search(base=dn, scope=ldb.SCOPE_BASE, attrs=[attr])[0][attr][0]) == value)
    command(["systemctl", "is-active", "samba-ad-dc"])
    command(["samba-tool", "ntacl", "sysvolcheck"])
    now = int(time.time())
    check_replication(json.loads(command(["samba-tool", "drs", "showrepl", expected["fqdn"], "--json", "-P"])),
                      base, "dc02" if role == "dc01" else "dc01", now)
    if role == "dc02":
        # S5 owns its sync status; no supplied readiness flags are accepted.
        status = Path("/var/lib/samba-ad-sysvol/status.json")
        require(not status.is_symlink() and status.stat().st_uid == 0 and status.stat().st_mode & 0o077 == 0)
        require(not Path("/var/lib/samba-ad-sysvol/partial.json").exists())
        record = json.loads(status.read_text())
        require(record["sid"] == r["sid"] and record["state"] == "ok" and record["failures"] == 0
                and 0 <= now-record["last_success"] <= 600)
        command(["systemctl", "is-enabled", "samba-ad-sysvol.timer"])
        command(["systemctl", "is-active", "samba-ad-sysvol.timer"])
    return {"schema": "samba-ad-pilot-dc/v1", "role": role, "fqdn": expected["fqdn"],
            "machine_id": expected["machine_id"], "sid": r["sid"], "observed": now,
            "sysvol_sha256": tree_digest("/var/lib/samba/sysvol"), "request_sha256": sha(r)}


def directory(r, manifest, probe):
    import ldb
    from samba.ndr import ndr_unpack
    from samba.dcerpc import security
    # The controller transports this live probe from the exact target PVE host.
    require(probe["request_sha256"] == sha(r) and probe["identity"] == r["identity"])
    inspect(r, manifest, "dc01")
    db = database(); owner = "samba-ad:s6:" + r["substrate"]["compatibility"]["data"]["target_sha256"]
    short = r["substrate"]["resource"]["name"].split(".")[0].upper()
    require(len(short) <= 15)
    dn = "CN=" + short + "," + r["ou"]
    entries = db.search(base=db.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                        expression="(sAMAccountName=" + short + "$)", attrs=["description", "objectSid", "objectGUID"])
    require(len(entries) <= 1)
    found = entries[0] if entries else None
    actual_owner = text(found["description"][0]) if found is not None and "description" in found else None
    actual_sid = str(ndr_unpack(security.dom_sid, bytes(found["objectSid"][0]))).rsplit("-", 1)[0] if found else None
    action = membership_action(probe["member"], actual_owner, owner, r["sid"], actual_sid)
    if found is not None: require(str(found.dn).lower() == dn.lower())
    ous = db.search(base=db.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                    expression="(distinguishedName=" + ldb.binary_encode(r["ou"]) + ")", attrs=["description", "gPLink"])
    require(len(ous) <= 1)
    if ous:
        require("description" in ous[0] and text(ous[0]["description"][0]) == owner)
    if action == "join" and ous: require("gPLink" not in ous[0] or not bytes(ous[0]["gPLink"][0]))
    guid = bytes(found["objectGUID"][0]).hex() if found is not None else None
    if not r["apply"]:
        return {"owner": owner, "action": action, "computer_dn": dn, "computer_guid": guid, "changed": False}
    if action == "join":
        require(r["action"] == "join")
        if not ous: db.add({"dn": r["ou"], "objectClass": ["top", "organizationalUnit"], "description": owner})
        # Atomic add reserves a NEW account. Carry the measured GUID to the
        # client; a collision aborts rather than resetting a foreign account.
        db.add({"dn": dn, "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
                "sAMAccountName": short + "$", "userAccountControl": "4098", "description": owner,
                "dNSHostName": r["substrate"]["resource"]["name"]})
        created = db.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])
        require(len(created) == 1)
        guid = bytes(created[0]["objectGUID"][0]).hex()
    return {"owner": owner, "action": action, "computer_dn": dn, "computer_guid": guid, "changed": action == "join"}
