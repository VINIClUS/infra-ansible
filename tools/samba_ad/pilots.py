"""S6 manual orchestration. All private inputs arrive through stdin, never argv."""
from __future__ import annotations
import hashlib
import base64
import gzip
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import secrets
import socket
import stat
import subprocess
import sys
import time
import uuid
from tools.samba_ad.compatibility import sha
from tools.samba_ad.contract import validate_manifest
from tools.samba_ad.pilot_substrate import validate_pilot_bundle, review

ERROR = "S6 precondition failed (values suppressed)"


def require(value):
    if not value: raise ValueError(ERROR)


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()))


def hex_value(value, length=64):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{" + str(length) + "}", value)
            and value != "0" * length)


def validate(r, manifest):
    fields(r, "schema enabled apply action pilot substrate identity sid dcs trust ou provenance linux windows credential_ref")
    require(r["schema"] == "samba-ad-pilot/v1" and type(r["enabled"]) is bool and type(r["apply"]) is bool)
    require(r["enabled"] is True and r["action"] in ["prepare", "join", "verify", "policy"])
    validate_manifest(manifest)
    require(r["pilot"] in ["linux_pilot", "windows_pilot"])
    require(r["credential_ref"] == "/run/samba-ad-pilot-credentials/" + r["pilot"] + "/join.json")
    s = r["substrate"]
    from tools.samba_ad.guest import validate as validate_guest
    validate_guest(s)
    require(s["action"] == "present" and s["apply"] is False and s["boot"] is True)
    hex_value(s["expected_digest"], 40)
    validate_pilot_bundle(s["compatibility"], s)
    data = s["compatibility"]["data"]
    require(data["purpose"] == r["pilot"] and data["manifest"] == manifest)
    i = r["identity"]
    fields(i, "uuid machine_id boot_id interface local_sid")
    require(i["uuid"] == data["clone_uuid"] and str(uuid.UUID(i["uuid"])) == i["uuid"])
    require(re.fullmatch(r"[a-f0-9-]{32,36}", i["machine_id"]))
    require(i["machine_id"] != data["report"]["template_observation"]["machine_id"])
    require(re.fullmatch(r"[A-Za-z0-9:.-]{10,64}", i["boot_id"]))
    require(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_. -]{0,31}", i["interface"]))
    require(re.fullmatch(r"S-1-5-21-(?:[0-9]+-){2}[0-9]+", r["sid"]))
    fields(r["dcs"], "dc01 dc02")
    for role, dc in r["dcs"].items():
        fields(dc, "fqdn address machine_id boot_id source certificate_sha256")
        declared = manifest["resources"][role]
        require(all(dc[k] == declared[k] for k in ["fqdn", "address"]))
        require(re.fullmatch(r"[a-f0-9]{32}", dc["machine_id"]))
        require(str(uuid.UUID(dc["boot_id"])) == dc["boot_id"])
        hex_value(dc["certificate_sha256"])
        source = dc["source"]
        from tools.samba_ad.domain_source import validate_pins
        fields(source, "directory inrelease_sha256 packages_sha256 key_sha256 fingerprint packages verified_utc advisory_review_ref")
        require(source["directory"] == "/var/lib/samba-ad-source")
        for key in ["inrelease_sha256", "packages_sha256", "key_sha256"]: hex_value(source[key])
        require(source["fingerprint"] == "46C910D6BFCA32BC87DE5173EE5618DB12523D4B")
        require(source["key_sha256"] == "95ab9a408a3e94564f5a9bfb6e82c9dc371f32e92004ee98acbf64b431c93e81")
        validate_pins(source["packages"]); review(source["advisory_review_ref"])
    require(len({v["machine_id"] for v in r["dcs"].values()}) == 2)
    fields(r["trust"], "root_pem issuer_pem root_sha256 issuer_sha256")
    for key in ["root", "issuer"]:
        pem = r["trust"][key + "_pem"]
        require(isinstance(pem, str) and pem.count("-----BEGIN CERTIFICATE-----") == 1
                and "PRIVATE" not in pem and len(pem) < 16000)
        hex_value(r["trust"][key + "_sha256"])
        require(hashlib.sha256(pem.encode()).hexdigest() == r["trust"][key + "_sha256"])
    base = ",".join("DC=" + x for x in manifest["domain"]["dns_domain"].split("."))
    require(re.fullmatch(r"OU=Samba-Pilot-[a-f0-9]{16}," + re.escape(base), r["ou"]))
    fields(r["provenance"], "private_revision review_ref")
    hex_value(r["provenance"]["private_revision"], 40); review(r["provenance"]["review_ref"])
    if r["pilot"] == "linux_pilot":
        require(r["windows"] is None and i["local_sid"] is None and r["action"] != "policy")
        fields(r["linux"], "packages files assets")
        needed = {"adcli", "sssd-ad", "sssd-tools", "libnss-sss", "libpam-sss", "krb5-user",
                  "smbclient", "ldap-utils", "chrony", "ca-certificates", "python3-ldap", "libpam-modules"}
        require(needed <= set(r["linux"]["packages"]) and len(r["linux"]["packages"]) <= 256)
        for name in r["linux"]["packages"]: require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name))
        for value in r["linux"]["packages"].values(): require(re.fullmatch(r"[0-9A-Za-z.+:~_-]+", value))
        require(isinstance(r["linux"]["assets"], dict) and r["linux"]["assets"])
        for name, digest in r["linux"]["assets"].items():
            require(re.fullmatch(r"[A-Za-z0-9_+.%~:-]+\.deb", name)); hex_value(digest)
        require(set(r["linux"]["files"]) == {"/etc/sssd/sssd.conf", "/etc/krb5.conf", "/etc/nsswitch.conf",
                "/etc/pam.d/common-session", "/etc/chrony/chrony.conf", "/etc/resolv.conf"})
        for value in r["linux"]["files"].values():
            if value is not None: hex_value(value)
    else:
        require(r["linux"] is None)
        require(re.fullmatch(r"S-1-5-21-(?:[0-9]+-){2}[0-9]+", i["local_sid"]))
        require(i["local_sid"] != data["report"]["template_observation"]["local_sid"])
        fields(r["windows"], "edition build support_until support_ref baseline rsat_source rsat_files rsop")
        w = r["windows"]
        require(w["edition"] in ["ServerStandard", "ServerDatacenter"] and w["build"] == "26100")
        require(w["support_until"] == "2034-11-14")
        require(w["support_ref"] == "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2025")
        require(w["rsat_source"] == "C:\\SambaADAssets\\FoD")
        require(isinstance(w["rsat_files"], dict) and len(w["rsat_files"]) > 0)
        for path, digest in w["rsat_files"].items():
            require(re.fullmatch(r"[A-Za-z0-9_.-]+\.(cab|msu)", path)); hex_value(digest)
        from tools.samba_ad.pilot_baseline import validate_request as validate_baseline
        validate_baseline(w["baseline"], r["ou"])
        fields(w["rsop"], "profile template_artifact_sha256 samples review_ref")
        require(w["rsop"]["profile"] == "server2025-gpmc-rsop-v1")
        require(w["rsop"]["template_artifact_sha256"] == data["report"]["artifact_sha256"])
        fields(w["rsop"]["samples"], "Computer User")
        for value in w["rsop"]["samples"].values(): hex_value(value)
        review(w["rsop"]["review_ref"])
    return {"state": "validated", "changed": False}


def membership_action(member, owner, expected_owner, expected_sid, actual_sid):
    if member:
        require(owner == expected_owner and actual_sid == expected_sid)
        return "verify"
    require(owner is None and actual_sid is None)
    return "join"


def dc_evidence(r, records, now=None):
    now = time.time() if now is None else now
    require(isinstance(records, list) and len(records) == 2)
    require({d["role"] for d in records} == {"dc01", "dc02"})
    for record in records:
        fields(record, "schema role fqdn machine_id sid observed sysvol_sha256 request_sha256")
        expected = r["dcs"][record["role"]]
        require(record["schema"] == "samba-ad-pilot-dc/v1" and record["request_sha256"] == sha(r))
        require(all(record[k] == expected[k] for k in ["fqdn", "machine_id"]))
        require(record["sid"] == r["sid"] and type(record["observed"]) is int and 0 <= now-record["observed"] <= 300)
        hex_value(record["sysvol_sha256"])
    require(records[0]["sysvol_sha256"] == records[1]["sysvol_sha256"])


def needs_dc_gate(r):
    return not (r["action"] == "prepare" and r["pilot"] == "linux_pilot")


def qga(vmid, command, payload):
    require(type(vmid) is int and 100 <= vmid <= 999999999)
    body = json.dumps(payload)
    require(len(body.encode()) < 1024*1024)
    try:
        result = subprocess.run(["qm", "guest", "exec", str(vmid), "--pass-stdin", "1",
                "--synchronous", "1", "--timeout", "540", "--", *command], input=body,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=570, check=False)
        require(result.returncode == 0)
        result = json.loads(result.stdout)
        require(result.get("exited") == 1 and result.get("exitcode") == 0
                and not result.get("out-truncated") and not result.get("err-truncated"))
        data = json.loads(result["out-data"])
        require(isinstance(data, dict))
        return data
    except Exception:
        # Timeouts may leave an operation in flight. Never retry or resend.
        raise ValueError(ERROR) from None


def pve_guard(r):
    from tools.samba_ad import guest
    require(os.geteuid() == 0 and socket.gethostname().split(".")[0] == r["substrate"]["resource"]["node"])
    api = guest.Pvesh()
    class ReadOnly(guest.Pvesh):
        def mutate(self, *args, **kwargs): raise ValueError(ERROR)
    result = guest.reconcile(r["substrate"], ReadOnly(), check=True)
    require(result == {"changed": False, "state": "verified", "digest": r["substrate"]["expected_digest"]})
    s = r["substrate"]; c = s["resource"]
    cfg = api.get(f'/nodes/{c["node"]}/qemu/{c["vmid"]}/config', current=1)
    require(guest.pairs(cfg.get("smbios1", "")).get("uuid") == r["identity"]["uuid"])
    help_result = subprocess.run(["qm", "help", "guest", "exec"], capture_output=True, text=True, timeout=20)
    require(help_result.returncode == 0 and "pass-stdin" in help_result.stdout + help_result.stderr)


def run_guest(r, manifest, sources, mode, credentials=None, directory=None):
    pve_guard(r)
    nonce = secrets.token_hex(32)
    payload = {"request": r, "manifest": manifest, "mode": "probe", "nonce": nonce,
               "credentials": None, "directory": None}
    windows = r["pilot"] == "windows_pilot"
    if windows:
        from tools.samba_ad.pilot_baseline_catalog import CATALOG
        payload["baseline_catalog"] = CATALOG
    # Compress public code only to stay below the Windows CreateProcess limit.
    # Credentials and all private data remain solely in the stdin payload.
    code = base64.b64encode(gzip.compress(sources["windows"].encode(), mtime=0)).decode() if windows else ""
    public = ("$m=[IO.MemoryStream]::new([Convert]::FromBase64String('" + code + "'));"
              "$g=[IO.Compression.GZipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);"
              "$s=[IO.StreamReader]::new($g);& ([ScriptBlock]::Create($s.ReadToEnd()))")
    require(len(public) < 24000)
    command = (["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", public]
               if windows else ["/usr/bin/python3", "-B", "-c", sources["linux"]])
    probe = qga(r["substrate"]["resource"]["vmid"], command, payload)
    require(probe.get("nonce") == nonce and probe.get("identity") == r["identity"])
    require(type(probe.get("member")) is bool)
    if mode == "probe":
        return probe | {"request_sha256": sha(r)}
    require(mode == "execute")
    pve_guard(r)  # identity, digest and network rechecked immediately before credential release
    require(credentials is None)
    if r["action"] != "prepare":
        path = Path(r["credential_ref"])
        for parent in [path.parent.parent, path.parent]:
            info = parent.lstat()
            require(parent.is_dir() and not parent.is_symlink() and info.st_uid == 0 and info.st_mode & 0o077 == 0)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o777 == 0o600
                    and info.st_nlink == 1 and info.st_size <= 8192)
            credentials = json.load(stream)
        fields(credentials, "username password")
        require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", credentials["username"]))
        require(isinstance(credentials["password"], str) and 14 <= len(credentials["password"]) <= 1024
                and not any(c in credentials["password"] for c in "\r\n\x00"))
    payload.update(mode="execute", credentials=credentials, directory=directory)
    result = qga(r["substrate"]["resource"]["vmid"], command, payload)
    require(result.get("nonce") == nonce)
    return result


def main(sources):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        wire = json.load(sys.stdin)
        fields(wire, "schema request manifest credentials dc_records directory probe")
        require(wire["schema"] == "samba-ad-pilot-wire/v1")
        r = wire["request"]; manifest = wire["manifest"]
        validate(r, manifest)
        mode = sys.argv[1:]
        if mode == ["--validate"]: result = {"state": "validated", "changed": False}
        elif mode == ["--probe"]: result = run_guest(r, manifest, sources, "probe")
        elif len(mode) == 2 and mode[0] == "--dc":
            from tools.samba_ad.pilots_dc import inspect
            result = inspect(r, manifest, mode[1])
        elif mode == ["--directory"]:
            dc_evidence(r, wire["dc_records"])
            from tools.samba_ad.pilots_dc import directory
            result = directory(r, manifest, wire["probe"])
        elif mode == ["--execute"]:
            if needs_dc_gate(r): dc_evidence(r, wire["dc_records"])
            if r["action"] == "prepare":
                require(wire["credentials"] is None and wire["directory"] is None)
            else:
                require(wire["credentials"] is None)
            result = run_guest(r, manifest, sources, "execute", wire["credentials"], wire["directory"])
        else: raise ValueError(ERROR)
        print(json.dumps(result)); return 0
    except Exception:
        print(ERROR, file=sys.stderr); return 2
