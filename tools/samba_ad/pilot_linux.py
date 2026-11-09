"""Public fixed QGA program; private JSON exclusively on stdin. Debian 13."""
from __future__ import annotations
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import resource
import socket
import ssl
import subprocess
import sys
import tempfile
import time

ERROR = "S6 Linux precondition failed (values suppressed)"


def require(value):
    if not value: raise ValueError(ERROR)


def command(argv, data=None, env=None, allowed=(0,)):
    p = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env=env, timeout=90, check=False)
    require(p.returncode in allowed)
    return p.stdout


def digest(path):
    p = Path(path)
    require(not p.is_symlink())
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


def write(path, data, mode=0o600):
    p = Path(path); require(not p.is_symlink())
    require(not p.parent.is_symlink())
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if p.exists() and p.read_bytes() == data.encode() and p.stat().st_mode & 0o777 == mode: return
    fd = os.open(str(p) + ".s6-new", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.replace(str(p) + ".s6-new", p)


def inspect(r):
    i = r["identity"]; s = r["substrate"]["resource"]
    require(os.geteuid() == 0)
    require(Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower() == i["uuid"])
    require(Path("/etc/machine-id").read_text().strip() == i["machine_id"])
    require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == i["boot_id"])
    require(socket.getfqdn() == s["name"])
    require(Path("/sys/class/net", i["interface"], "address").read_text().strip().upper() == s["mac"])
    ips = json.loads(command(["ip", "-j", "addr", "show", "dev", i["interface"]]))
    require(any(a["local"] == str(ipaddress.IPv4Interface(s["address"]).ip) for n in ips for a in n["addr_info"]))
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(release["ID"].strip('"') == "debian" and release["VERSION_ID"].strip('"') == "13")
    occupied = [Path(p).exists() for p in ["/etc/krb5.keytab", "/var/lib/samba/private/secrets.tdb"]]
    state = Path("/var/lib/samba-ad-pilot/state.json")
    require(not state.is_symlink())
    previous = json.loads(state.read_text()) if state.exists() else None
    if previous:
        require(state.stat().st_uid == 0 and state.stat().st_mode & 0o077 == 0)
        require(previous["owner"] == r["substrate"]["compatibility"]["data"]["target_sha256"])
        require(previous["machine_id"] == i["machine_id"] and previous["uuid"] == i["uuid"])
    member = any(occupied)
    require(not member or (previous is not None and previous["sid"] == r["sid"] and previous["member"] is True))
    return member, previous


def configuration(r, manifest):
    domain = manifest["domain"]["dns_domain"]; realm = domain.upper()
    dcs = [r["dcs"][k]["fqdn"] for k in ["dc01", "dc02"]]
    krb = ("[libdefaults]\n default_realm = " + realm + "\n dns_lookup_kdc = false\n dns_lookup_realm = false\n"
           " rdns = false\n forwardable = false\n[realms]\n " + realm + " = {\n" +
           "".join("  kdc = " + dc + "\n" for dc in dcs) + " }\n[domain_realm]\n ." + domain + " = " + realm + "\n")
    sssd = ("[sssd]\nconfig_file_version = 2\nservices = nss, pam\ndomains = " + domain +
            "\n[domain/" + domain + "]\nid_provider = ad\nauth_provider = ad\naccess_provider = ad\n"
            "ad_domain = " + domain + "\nkrb5_realm = " + realm + "\nad_server = " + ", ".join(dcs) +
            "\nad_hostname = " + r["substrate"]["resource"]["name"] + "\nldap_id_mapping = true\n"
            "use_fully_qualified_names = true\ncache_credentials = true\nkrb5_store_password_if_offline = false\n"
            "fallback_homedir = /home/%u@%d\ndefault_shell = /bin/bash\ndyndns_update = true\n"
            "ad_gpo_access_control = enforcing\n")
    nss = Path("/etc/nsswitch.conf").read_text()
    for key in ["passwd", "group", "shadow"]:
        lines = nss.splitlines(); matches = [n for n, line in enumerate(lines) if line.startswith(key + ":")]
        require(len(matches) == 1)
        pos = matches[0]
        if "sss" not in lines[pos].split(): lines[pos] += " sss"
        nss = "\n".join(lines) + "\n"
    pam = Path("/etc/pam.d/common-session").read_text()
    if "pam_mkhomedir.so" not in pam: pam += "session optional pam_mkhomedir.so skel=/etc/skel umask=0077\n"
    return {"/etc/krb5.conf": krb, "/etc/sssd/sssd.conf": sssd, "/etc/nsswitch.conf": nss,
            "/etc/pam.d/common-session": pam,
            "/etc/resolv.conf": "search " + domain + "\n" + "".join("nameserver " + r["dcs"][k]["address"] + "\n" for k in ["dc01", "dc02"]),
            "/etc/chrony/chrony.conf": "".join("server " + address + " iburst\n" for address in manifest["network"]["time_sources"]) +
            "driftfile /var/lib/chrony/chrony.drift\nmakestep 1.0 3\nrtcsync\n"}


def prepare(r, manifest, previous):
    for path, expected in r["linux"]["files"].items():
        actual = digest(path)
        require(actual == (previous["files"].get(path) if previous else expected))
    packages = r["linux"]["packages"]
    for filename, expected in r["linux"]["assets"].items():
        path = Path("/var/cache/apt/archives") / filename
        require(digest(path) == expected)
        metadata = command(["dpkg-deb", "-f", str(path), "Package", "Version"]).decode().splitlines()
        values = dict(line.split(": ", 1) for line in metadata)
        require(packages.get(values["Package"]) == values["Version"])
    if not r["apply"]: return previous
    env = os.environ | {"DEBIAN_FRONTEND": "noninteractive"}
    command(["apt-get", "--no-download", "--no-install-recommends", "--no-remove", "-y", "install",
             *[name + "=" + version for name, version in packages.items()]], env=env)
    for name, version in packages.items():
        require(command(["dpkg-query", "-W", "-f=${Version}", name]).decode() == version)
    # Public certificates only; reject foreign files rather than overwrite them.
    for key in ["root", "issuer"]:
        path = "/usr/local/share/ca-certificates/samba-ad-" + key + ".crt"
        require(digest(path) in [None, r["trust"][key + "_sha256"]])
        write(path, r["trust"][key + "_pem"], 0o644)
    command(["update-ca-certificates"])
    for path, text in configuration(r, manifest).items(): write(path, text, 0o600 if "/sssd/" in path else 0o644)
    command(["pam-auth-update", "--package", "--enable", "sss", "--enable", "mkhomedir"])
    command(["systemctl", "enable", "--now", "chrony"])
    command(["systemctl", "restart", "chrony"])
    state = {"owner": r["substrate"]["compatibility"]["data"]["target_sha256"],
             "machine_id": r["identity"]["machine_id"], "uuid": r["identity"]["uuid"],
             "sid": r["sid"], "member": previous["member"] if previous else False,
             "files": {path: digest(path) for path in r["linux"]["files"]}}
    write("/var/lib/samba-ad-pilot/state.json", json.dumps(state))
    return state


def tls(r):
    context = ssl.create_default_context(cadata=r["trust"]["root_pem"] + r["trust"]["issuer_pem"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    for dc in r["dcs"].values():
        require({x[4][0] for x in socket.getaddrinfo(dc["fqdn"], 636, type=socket.SOCK_STREAM)} == {dc["address"]})
        with socket.create_connection((dc["address"], 636), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=dc["fqdn"]) as conn:
                require(hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest() == dc["certificate_sha256"])
    tracking = command(["chronyc", "-c", "tracking"]).decode().strip().split(",")
    require(len(tracking) >= 13 and tracking[-1] == "Normal" and 1 <= int(tracking[1]) <= 15
            and abs(float(tracking[3])) <= 1.0)


def ldap_connection(r, manifest, credentials, dc):
    import ldap
    conn = ldap.initialize("ldaps://" + dc["fqdn"] + ":636")
    conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.set_option(ldap.OPT_X_TLS_CACERTFILE, "/etc/ssl/certs/ca-certificates.crt")
    conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    conn.simple_bind_s("", "")  # finish TLS without disclosing the join credential
    require(hashlib.sha256(conn.get_option(ldap.OPT_X_TLS_PEERCERT)).hexdigest() == dc["certificate_sha256"])
    conn.simple_bind_s(credentials["username"] + "@" + manifest["domain"]["realm"], credentials["password"])
    import struct
    base = ",".join("DC=" + s for s in manifest["domain"]["dns_domain"].split("."))
    rows = conn.search_s(base, ldap.SCOPE_BASE, "(objectClass=*)", ["objectSid"])
    require(len(rows) == 1)
    raw = rows[0][1]["objectSid"][0]
    sid = "S-" + str(raw[0]) + "-" + str(int.from_bytes(raw[2:8], "big"))
    sid += "".join("-" + str(struct.unpack_from("<I", raw, 8 + n*4)[0]) for n in range(raw[1]))
    require(sid == r["sid"])
    return conn


def authentication(r, manifest, credentials):
    realm = manifest["domain"]["realm"]
    # Each kinit has exactly one KDC and a fresh isolated cache. Both authentication
    # and SYSVOL reads fail closed; no DNS-discovered KDC or NTLM fallback.
    for dc in r["dcs"].values():
        with tempfile.TemporaryDirectory(prefix="samba-ad-pilot-", dir="/run") as temp:
            os.chmod(temp, 0o700); conf = Path(temp, "krb5.conf")
            conf.write_text("[libdefaults]\n default_realm = " + realm + "\n dns_lookup_kdc = false\n rdns = false\n"
                "[realms]\n " + realm + " = {\n kdc = " + dc["address"] + "\n }\n")
            env = os.environ | {"KRB5_CONFIG": str(conf), "KRB5CCNAME": "FILE:" + temp + "/ccache"}
            try:
                command(["kinit", credentials["username"] + "@" + realm],
                        (credentials["password"] + "\n").encode(), env)
                command(["kvno", "cifs/" + dc["fqdn"]], env=env)
                command(["smbclient", "//" + dc["fqdn"] + "/SYSVOL", "--use-kerberos=required", "--no-pass",
                         "--client-protection=sign", "-c", "ls " + realm.lower() + "/Policies/*"], env=env)
            finally: command(["kdestroy"], env=env, allowed=(0, 1))
    command(["sssctl", "config-check"])
    command(["getent", "passwd", credentials["username"] + "@" + realm.lower()])
    # Exercise the PAM account stack, not just nss/getent.
    command(["sssctl", "user-checks", "-a", "acct", "-s", "sshd", credentials["username"] + "@" + realm.lower()])


def execute(w):
    r = w["request"]; manifest = w["manifest"]
    member, previous = inspect(r)
    if w["mode"] == "probe":
        if r["action"] != "prepare":
            require(previous is not None)
            for path, expected in previous["files"].items(): require(digest(path) == expected)
            tls(r)  # before PVE even opens the protected credential reference
        return {"nonce": w["nonce"], "identity": r["identity"], "member": member}
    if r["action"] == "prepare":
        require(not member and w["credentials"] is None)
        prepare(r, manifest, previous)
        return {"nonce": w["nonce"], "state": "prepared" if r["apply"] else "checked", "changed": r["apply"]}
    require(previous is not None)
    for path, expected in previous["files"].items(): require(digest(path) == expected)
    tls(r)  # public pins and bounded endpoints before bind/kinit/join credentials
    d = w["directory"]; credentials = w["credentials"]
    require(d["action"] == ("verify" if member else "join"))
    import ldap
    conn = ldap_connection(r, manifest, credentials, r["dcs"]["dc01"])
    peer = ldap_connection(r, manifest, credentials, r["dcs"]["dc02"])
    peer.unbind_s()
    try:
        accounts = conn.search_s(r["ou"], ldap.SCOPE_SUBTREE,
                    "(sAMAccountName=" + r["substrate"]["resource"]["name"].split(".")[0] + "$)", ["description", "objectGUID"])
        if not member:
            require(r["action"] == "join")
            if r["apply"]:
                require(len(accounts) == 1 and accounts[0][0].lower() == d["computer_dn"].lower()
                        and accounts[0][1].get("description") == [d["owner"].encode()]
                        and accounts[0][1]["objectGUID"][0].hex() == d["computer_guid"])
                command(["adcli", "join", "--domain=" + manifest["domain"]["dns_domain"],
                         "--domain-controller=" + r["dcs"]["dc01"]["fqdn"], "--computer-ou=" + r["ou"],
                         "--host-fqdn=" + r["substrate"]["resource"]["name"],
                         "--login-user=" + credentials["username"], "--stdin-password"],
                        (credentials["password"] + "\n").encode())
                require(Path("/etc/krb5.keytab").is_file())
                after = conn.search_s(d["computer_dn"], ldap.SCOPE_BASE, "(objectClass=computer)", ["description", "objectGUID"])
                require(len(after) == 1 and after[0][1].get("description") == [d["owner"].encode()]
                        and after[0][1]["objectGUID"][0].hex() == d["computer_guid"])
                previous["member"] = True
                previous["computer_guid"] = d["computer_guid"]
                write("/var/lib/samba-ad-pilot/state.json", json.dumps(previous))
                command(["systemctl", "enable", "--now", "sssd"])
                command(["systemctl", "restart", "sssd"])
            else: require(not accounts)
        else:
            require(len(accounts) == 1 and accounts[0][1].get("description") == [d["owner"].encode()])
            require(accounts[0][1]["objectGUID"][0].hex() == previous["computer_guid"] == d["computer_guid"])
            command(["adcli", "testjoin", "--domain-controller=" + r["dcs"]["dc01"]["fqdn"]])
            command(["adcli", "testjoin", "--domain-controller=" + r["dcs"]["dc02"]["fqdn"]])
        if r["apply"]: authentication(r, manifest, credentials)
    finally: conn.unbind_s()
    return {"nonce": w["nonce"], "state": "verified" if r["apply"] else "checked", "changed": r["apply"] and not member}


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        print(json.dumps(execute(json.load(sys.stdin)))); return 0
    except Exception:
        print(ERROR, file=sys.stderr); return 2


if __name__ == "__main__": raise SystemExit(main())
