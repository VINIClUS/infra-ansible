"""Manual DC01 guard and Samba 4.25.1 API backend. Never log input values."""
from __future__ import annotations

import hashlib
import contextlib
import io
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time

from tools.samba_ad.compatibility import validate_bundle
from tools.samba_ad.contract import validate_manifest
from tools.samba_ad.guest import spec_hash
from tools.samba_ad.pki_contract import validate_request as validate_pki
from tools.samba_ad.pki_files import secure_directory, secure_file

PASSWORD_POLICY = {
    "minPwdLength": 14, "pwdHistoryLength": 30, "minPwdAge": -864000000000,
    "maxPwdAge": 0, "pwdProperties": 1, "lockoutThreshold": 10,
    "lockoutDuration": -9000000000, "lockOutObservationWindow": -9000000000,
}
ERROR = "S4 precondition failed (values suppressed)"
CANDIDATE_PRIMARY = "46C910D6BFCA32BC87DE5173EE5618DB12523D4B"
CANDIDATE_KEY_SHA256 = "95ab9a408a3e94564f5a9bfb6e82c9dc371f32e92004ee98acbf64b431c93e81"


def require(value):
    if not value:
        raise ValueError(ERROR)


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()))


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def hex_value(value, size=64):
    require(isinstance(value, str) and re.fullmatch("[a-f0-9]{" + str(size) + "}", value)
            and value != "0" * size)


def loads(value):
    def unique(pairs):
        require(len({k for k, _ in pairs}) == len(pairs))
        return dict(pairs)
    try:
        result = json.loads(value, object_pairs_hook=unique,
                            parse_constant=lambda _: require(False))
        require(isinstance(result, dict) and "schema" in result)
        return result
    except Exception:
        raise ValueError(ERROR) from None


def validate_request(request, manifest):
    """Declarations only. Provenance is the operator-reviewed private revision."""
    try:
        r = request
        require(r["schema"] == "samba-ad-domain/v1")
        require(type(r["enabled"]) is bool and type(r["apply"]) is bool)
        if not r["enabled"]:
            fields(r, "schema enabled apply")
            require(r["apply"] is False)
            return {"state": "disabled"}
        fields(r, "schema enabled apply target substrate pki generation identity source provenance")
        validate_manifest(manifest)
        target = r["target"]
        fields(target, "realm netbios fqdn sid")
        require({k: target[k] for k in ["realm", "netbios"]} ==
                {k: manifest["domain"][k] for k in ["realm", "netbios"]})
        require(target["fqdn"] == manifest["resources"]["dc01"]["fqdn"])
        require(target["sid"] is None or bool(re.fullmatch(r"S-1-5-21-(?:[0-9]+-){2}[0-9]+", target["sid"])))
        substrate = r["substrate"]
        fields(substrate, "schema enabled apply action owner scope compatibility boot resource template expected_digest firewall")
        require(substrate["scope"] == "production" and substrate["owner"] == "samba-ad")
        require(substrate["action"] == "present" and substrate["enabled"] is True
                and substrate["apply"] is False and substrate["boot"] is True)
        hex_value(substrate["expected_digest"], 40)
        validate_bundle(substrate["compatibility"], substrate)
        declared = manifest["resources"]["dc01"]
        require(substrate["resource"]["name"] == target["fqdn"])
        for key in ["kind", "node", "vmid", "mac"]:
            require(substrate["resource"][key] == declared[key])
        address = ipaddress.IPv4Interface(substrate["resource"]["address"])
        require(str(address.ip) == declared["address"] and str(address.network) == declared["cidr"])
        validate_pki(r["pki"], manifest)
        require(r["pki"]["enabled"] is True and r["pki"]["profile"] == "dc01")
        require(r["pki"]["adapter"] == {"kind": "samba", "port": 636})
        require(r["pki"]["target"]["spec_sha256"] == spec_hash(substrate))
        require(re.fullmatch(r"[a-f0-9]{32}", r["generation"]))
        fields(r["identity"], "boot_id machine_id config_sha256")
        require(r["identity"]["boot_id"] == r["pki"]["target"]["boot_id"])
        require(r["identity"]["machine_id"] == r["pki"]["target"]["machine_id"])
        hex_value(r["identity"]["config_sha256"])
        fields(r["source"], "directory inrelease_sha256 packages_sha256 key_sha256 fingerprint packages verified_utc advisory_review_ref")
        require(r["source"]["directory"] == "/var/lib/samba-ad-source")
        for key in ["inrelease_sha256", "packages_sha256", "key_sha256"]: hex_value(r["source"][key])
        hex_value(r["source"]["fingerprint"].lower(), 40)
        require(r["source"]["fingerprint"] == CANDIDATE_PRIMARY
                and r["source"]["key_sha256"] == CANDIDATE_KEY_SHA256)
        require(re.fullmatch(r"git:[a-f0-9]{40}:[a-zA-Z0-9_./-]+", r["source"]["advisory_review_ref"])
                and ".." not in r["source"]["advisory_review_ref"])
        require(isinstance(r["source"]["packages"], dict))
        from tools.samba_ad.domain_source import validate_pins
        validate_pins(r["source"]["packages"])
        for name, version in r["source"]["packages"].items():
            require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name))
            require(isinstance(version, str) and re.fullmatch(r"[a-zA-Z0-9:+.~-]+", version))
        fields(r["provenance"], "reviewed_config_revision review_ref")
        hex_value(r["provenance"]["reviewed_config_revision"], 40)
        require(re.fullmatch(r"git:[a-f0-9]{40}:[a-zA-Z0-9_./-]+", r["provenance"]["review_ref"])
                and ".." not in r["provenance"]["review_ref"])
        return {"state": "validated"}
    except Exception:
        raise ValueError(ERROR) from None


def forest_action(expected, observed, occupied):
    if observed is None:
        require(not occupied and expected["sid"] is None)
        return "provision"
    require(occupied and expected["sid"] is not None)
    require(all(observed.get(k) == expected[k] for k in ["realm", "netbios", "fqdn", "sid"]))
    require((observed.get("domain_level"), observed.get("forest_level"), observed.get("schema_version")) == (7, 7, 88))
    return "current"


def substrate_preflight(request, api=None):
    """Reuse the canonical S1 live guard, with an adapter that cannot mutate."""
    from tools.samba_ad import guest, compatibility
    require(request["action"] == "present" and request["boot"] is True)
    require(request["enabled"] is True and request["apply"] is False)
    require(isinstance(request["expected_digest"], str) and guest.digest(request["expected_digest"]))
    class ReadOnly(guest.Pvesh):
        def mutate(self, *args, **kwargs):
            raise ValueError(ERROR)
        def firewall(self, node, kind, vmid, text, apply):
            require(apply is False)
            return super().firewall(node, kind, vmid, text, False)
    previous = sys.modules.get("s2_compatibility")
    sys.modules["s2_compatibility"] = compatibility
    try:
        result = guest.reconcile(request, api or ReadOnly(), check=True)
        require(result["state"] == "verified" and result["changed"] is False)
        return {"state": "verified", "changed": False}
    finally:
        if previous is None: sys.modules.pop("s2_compatibility", None)
        else: sys.modules["s2_compatibility"] = previous


def smb_conf(realm, netbios, hostname, forwarders):
    require(re.fullmatch(r"[A-Z0-9.-]+", realm) and re.fullmatch(r"[A-Z][A-Z0-9-]{0,14}", netbios))
    require(hostname == "dc01" and len(forwarders) > 0)
    for peer in forwarders: ipaddress.IPv4Address(peer)
    return ("[global]\n"
            f"realm = {realm}\nworkgroup = {netbios}\nnetbios name = {hostname.upper()}\n"
            "server role = active directory domain controller\n"
            "server min protocol = SMB2_02\nclient min protocol = SMB2_02\n"
            "server signing = mandatory\nclient signing = mandatory\n"
            "ntlm auth = ntlmv2-only\nlanman auth = no\n"
            "ldap server require strong auth = yes\ntls enabled = yes\n"
            "tls priority = NORMAL:-VERS-TLS1.0:-VERS-TLS1.1\n"
            "allow dns updates = secure only\n"
            "log level = 1 auth_audit:3 dsdb_audit:3\n"
            f"dns forwarder = {' '.join(forwarders)}\n"
            "include = /var/lib/samba-ad-pki/dc01/active.conf\n"
            "[sysvol]\npath = /var/lib/samba/sysvol\nread only = no\n"
            f"[netlogon]\npath = /var/lib/samba/sysvol/{realm.lower()}/scripts\nread only = no\n")


def execute(request, adapter):
    action = adapter.inspect(request)
    if not request["apply"]:
        return {"state": "checked", "changed": False}
    if action == "current":
        return adapter.verify(request)
    adapter.provision(request)
    adapter.harden(request)
    result = adapter.verify(request)
    result["changed"] = True
    return result


def command(argv, data=None, allowed=(0,)):
    """Never echo subprocess output: Samba exceptions may contain credentials."""
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode in allowed)
    return result.stdout


class Native:
    """Host-local backend. No networking, package download or shell expansion."""
    def __init__(self, manifest):
        self.manifest = manifest

    def inspect(self, r):
        from tools.samba_ad import domain_network
        require(os.geteuid() == 0)
        require(Path("/etc/machine-id").read_text().strip() == r["identity"]["machine_id"])
        require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == r["identity"]["boot_id"])
        require(socket.getfqdn() == r["target"]["fqdn"])
        interface = r["pki"]["target"]["interface"]
        require(Path("/sys/class/net", interface, "address").read_text().strip().upper() ==
                r["substrate"]["resource"]["mac"].upper())
        addresses = json.loads(command(["ip", "-j", "-4", "addr", "show", "dev", interface]))
        require(any(a["local"] == str(ipaddress.IPv4Interface(r["substrate"]["resource"]["address"]).ip)
                    for device in addresses for a in device["addr_info"]))
        config = secure_file("/etc/samba/smb.conf", secret=False).read_bytes()
        require(hashlib.sha256(config).hexdigest() == r["identity"]["config_sha256"])
        self.host_guard(r)
        self.verify_packages(r)
        self.generation(r)
        active = Path("/var/lib/samba-ad-pki/dc01/active.conf")
        if r["target"]["sid"] is None:
            require(not active.exists() and not active.is_symlink())
            require(not Path("/var/lib/samba-ad-integrity").exists()
                    and not Path("/var/lib/samba-ad-integrity").is_symlink())
        else:
            require(active.is_symlink() and str(active.readlink()) ==
                    "generations/" + r["generation"] + "/consumer.conf")
        domain_network.inspect(r)
        self.db = self.database() if Path("/var/lib/samba/private/sam.ldb").exists() else None
        from tools.samba_ad.domain_services import ServiceOps
        self.services = ServiceOps()
        self.service_snapshot = self.services.inspect(initial=self.db is None)
        occupied = any(Path(p).exists() for p in ["/var/lib/samba/private/sam.ldb", "/var/lib/samba/private/secrets.ldb"])
        if self.db is None:
            require(not Path("/etc/krb5.keytab").exists())
            for directory in ["/var/lib/samba/private", "/var/lib/samba/sysvol"]:
                p = Path(directory)
                require(not p.is_symlink() and (not p.exists() or not any(p.iterdir())))
            for server in self.manifest["network"]["dns_forwarders"]:
                response = command(["dig", "+time=3", "+tries=1", "+noall", "+comments", "+answer",
                                    "@" + server, "_ldap._tcp.dc._msdcs." + r["target"]["realm"].lower(), "SRV"]).decode()
                require("status: NOERROR" in response or "status: NXDOMAIN" in response)
                require(not any(line and not line.startswith(";") for line in response.splitlines()))
        return forest_action(r["target"], self.observed() if self.db else None, occupied)

    def host_guard(self, r):
        """S1-owned identity/egress is a private reviewed prerequisite, never widened."""
        from tools.samba_ad.pki_files import future_directory
        for path, content in self.host_files(r).items():
            p = Path(path)
            future_directory(p.parent)
            require(not p.is_symlink())
            if p.exists():
                require(secure_file(p).read_bytes() == content.encode())
        # Do not smuggle host-level capabilities into a container to make audit/time pass.
        if r["substrate"]["resource"]["kind"] == "lxc":
            status = Path("/proc/self/status").read_text()
            capabilities = int(re.search(r"^CapEff:\s+([a-f0-9]+)$", status, re.M)[1], 16)
            require(not capabilities & sum(1 << bit for bit in [25, 29, 30, 37]))
        require(command(["systemctl", "is-active", "--quiet", "systemd-journald.service"]) == b"")

    def host_files(self, r):
        from tools.samba_ad.domain_network import render
        realm = r["target"]["realm"]
        result = {
            "/etc/samba-ad-domain/nftables.conf": render(r["substrate"]["firewall"]),
            "/etc/systemd/system/samba-ad-firewall.service": "[Unit]\nDescription=Samba AD exact-peer guest firewall\nBefore=samba-ad-dc.service\n[Service]\nType=oneshot\nExecStart=/usr/sbin/nft --file /etc/samba-ad-domain/nftables.conf\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n",
            "/etc/systemd/system/samba-ad-dc.service.d/60-samba-ad-firewall.conf": "[Unit]\nRequires=samba-ad-firewall.service\nAfter=samba-ad-firewall.service\n",
            "/etc/ssh/sshd_config.d/60-samba-ad.conf": "# Managed by Samba S4\nPermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAuthenticationMethods publickey\n",
            "/etc/systemd/journald.conf.d/60-samba-ad.conf": "[Journal]\nStorage=persistent\nSeal=yes\n",
            "/etc/apt/apt.conf.d/60-samba-ad-controlled-updates": 'APT::Periodic::Enable "0";\nAPT::Periodic::Unattended-Upgrade "0";\n',
            "/etc/krb5.conf": f"[libdefaults]\n default_realm = {realm}\n dns_lookup_realm = false\n dns_lookup_kdc = true\n default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 arcfour-hmac\n default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 arcfour-hmac\n rdns = false\n",
            "/etc/systemd/system/samba-ad-integrity.service": "[Unit]\nDescription=Samba AD integrity check\n[Service]\nType=oneshot\nExecStart=/usr/bin/aide --config=/etc/samba-ad-integrity.conf --check\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\n",
            "/etc/systemd/system/samba-ad-integrity.timer": "[Unit]\nDescription=Check Samba AD integrity\n[Timer]\nOnBootSec=15min\nOnUnitActiveSec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n",
            "/etc/samba-ad-integrity.conf": "database_in=file:/var/lib/samba-ad-integrity/aide.db\ndatabase_out=file:/var/lib/samba-ad-integrity/aide.db.new\nreport_url=stdout\nS4=p+i+n+u+g+s+b+m+c+sha256\n/etc/samba S4\n/etc/ssh S4\n/usr/sbin/samba S4\n/usr/lib/x86_64-linux-gnu/samba S4\n",
        }
        if r["substrate"]["resource"]["kind"] == "qemu":
            result["/etc/audit/rules.d/60-samba-ad.rules"] = "-w /etc/samba -p wa -k samba_ad_config\n-w /var/lib/samba/private -p wa -k samba_ad_database\n"
        return result

    def verify_packages(self, r):
        from tools.samba_ad.domain_source import verify_installed
        verify_installed(r["source"])
        import samba
        require(samba.version == "4.25.1")
        require(command(["samba", "--version"]).decode().strip() == "Version 4.25.1")

    def generation(self, r):
        from tools.samba_ad.pki_runtime import candidate_info, consumer_conf
        root = secure_directory("/var/lib/samba-ad-pki/dc01", exact=True)
        generation = secure_directory(root / "generations" / r["generation"], exact=True)
        require(secure_file(generation / "consumer.conf", secret=True).read_bytes() == consumer_conf(r["pki"], generation))
        info = candidate_info(r["pki"], generation, int(time.time()))
        require(int(time.time()) < info["rotation_deadline"])
        return generation

    def database(self):
        from samba.auth import system_session
        from samba.param import LoadParm
        from samba.samdb import SamDB
        lp = LoadParm(); lp.load("/etc/samba/smb.conf")
        return SamDB(url="/var/lib/samba/private/sam.ldb", session_info=system_session(), lp=lp)

    def observed(self):
        import ldb
        db = self.db
        def attr(base, attribute):
            return str(db.search(base=base, scope=ldb.SCOPE_BASE, attrs=[attribute])[0][attribute][0])
        # Crossref and server identity are read from the database, not inferred from request.
        cross = db.search(base="CN=Partitions," + str(db.get_config_basedn()), scope=ldb.SCOPE_ONELEVEL,
                          expression="(nCName=" + str(db.domain_dn()) + ")", attrs=["dnsRoot", "nETBIOSName"])
        require(len(cross) == 1)
        return {"realm": str(cross[0]["dnsRoot"][0]).upper(), "netbios": str(cross[0]["nETBIOSName"][0]),
                "fqdn": attr(db.get_serverName(), "dNSHostName"), "sid": str(db.get_domain_sid()),
                "domain_level": int(attr(db.domain_dn(), "msDS-Behavior-Version")),
                "forest_level": int(attr("CN=Partitions," + str(db.get_config_basedn()), "msDS-Behavior-Version")),
                "schema_version": int(attr(db.get_schema_basedn(), "objectVersion"))}

    def provision(self, r):
        # Recheck immediately before creating the forest; a partial run is never adopted.
        require(self.inspect(r) == "provision")
        from samba.auth import system_session
        from samba.dsdb import DS_DOMAIN_FUNCTION_2016
        from samba.provision import provision
        import samba
        credential = secure_file("/run/samba-ad-domain-credentials/dc01/administrator", secret=True)
        password = credential.read_text().rstrip("\n")
        require(len(password) >= 14 and "\x00" not in password)
        try:
            require(samba.version == "4.25.1")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                require(samba.check_password_quality(password))
        except Exception:
            del password
            raise ValueError(ERROR) from None
        logger = logging.getLogger("samba-ad-domain-null")
        logger.handlers = [logging.NullHandler()]; logger.propagate = False
        try:
            self.prepare_config(r)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                provision(logger, system_session(), smbconf="/etc/samba/smb.conf", realm=r["target"]["realm"],
                          domain=r["target"]["netbios"], hostname="dc01", adminpass=password,
                          hostip=str(ipaddress.IPv4Interface(r["substrate"]["resource"]["address"]).ip),
                          serverrole="active directory domain controller", dns_backend="SAMBA_INTERNAL",
                          dom_for_fun_level=DS_DOMAIN_FUNCTION_2016, base_schema="2019",
                          adprep_level=DS_DOMAIN_FUNCTION_2016, useeadb=False, use_rfc2307=True,
                          skip_sysvolacl=False, plaintext_secrets=False)
        finally:
            del password
        self.db = self.database()

    def prepare_config(self, r):
        # Upstream only generates its AD configuration when smb.conf is empty or
        # absent. Replace only the exact baseline whose digest inspect approved.
        from tools.samba_ad.pki_files import atomic_file
        baseline = secure_file("/etc/samba/smb.conf").read_bytes()
        require(hashlib.sha256(baseline).hexdigest() == r["identity"]["config_sha256"])
        self.services.converge_initial(self.service_snapshot)
        atomic_file(Path("/etc/samba/smb.conf"), b"")

    def harden(self, r):
        import ldb
        from tools.samba_ad.pki_files import atomic_file
        from tools.samba_ad.pki_runtime import Store
        from tools.samba_ad.pki_files import future_directory
        from tools.samba_ad import domain_network
        require(self.db is not None)
        message = ldb.Message(); message.dn = ldb.Dn(self.db, str(self.db.domain_dn()))
        for name, value in PASSWORD_POLICY.items():
            message[name] = ldb.MessageElement(str(value), ldb.FLAG_MOD_REPLACE, name)
        self.db.modify(message)
        for path, content in self.host_files(r).items():
            p = Path(path)
            directory = future_directory(p.parent)
            if not directory.exists(): directory.mkdir(mode=0o755)
            if not p.exists(): atomic_file(p, content.encode())
        domain_network.install(r)
        command(["sshd", "-t"])
        effective = dict(line.split(" ", 1) for line in command(["sshd", "-T"]).decode().splitlines())
        require(all(effective.get(k) == v for k, v in {
            "permitrootlogin": "no", "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
            "pubkeyauthentication": "yes", "authenticationmethods": "publickey"}.items()))
        command(["systemctl", "restart", "systemd-journald.service"])
        command(["journalctl", "--flush"])
        command(["systemctl", "reload", "ssh.service"])
        if r["substrate"]["resource"]["kind"] == "qemu":
            command(["augenrules", "--load"])
            command(["systemctl", "enable", "--now", "auditd.service"])
        # Only an initial S3 generation is activated here. Rotation remains S3-owned.
        store = Store(r["pki"])
        with store.lock():
            require(store.current() is None)
            self.generation(r)
            store.point("generations/" + r["generation"] + "/consumer.conf")
        conf = smb_conf(r["target"]["realm"], r["target"]["netbios"], "dc01",
                        self.manifest["network"]["dns_forwarders"])
        atomic_file(Path("/etc/samba/smb.conf"), conf.encode())
        command(["testparm", "--suppress-prompt", "/etc/samba/smb.conf"])
        command(["systemctl", "start", "samba-ad-dc.service"])
        integrity = future_directory("/var/lib/samba-ad-integrity")
        require(not integrity.exists())
        integrity.mkdir(mode=0o700)
        command(["aide", "--config=/etc/samba-ad-integrity.conf", "--init"])
        secure_file(integrity / "aide.db.new", secret=True).rename(integrity / "aide.db")
        command(["systemctl", "daemon-reload"])
        command(["systemctl", "enable", "--now", "samba-ad-integrity.timer"])

    def verify(self, r):
        import ldb
        from tools.samba_ad import domain_network
        self.db = self.database()
        observed = self.observed()
        expected = dict(r["target"], sid=r["target"]["sid"] or observed["sid"])
        require(forest_action(expected, observed, True) == "current")
        row = self.db.search(base=self.db.domain_dn(), scope=ldb.SCOPE_BASE, attrs=list(PASSWORD_POLICY))[0]
        require(all(int(row[k][0]) == v for k, v in PASSWORD_POLICY.items()))
        require(domain_network.inspect(r))
        require(secure_file("/etc/samba/smb.conf").read_text() == smb_conf(
            r["target"]["realm"], r["target"]["netbios"], "dc01", self.manifest["network"]["dns_forwarders"]))
        command(["testparm", "--suppress-prompt", "/etc/samba/smb.conf"])
        command(["systemctl", "is-active", "--quiet", "samba-ad-dc.service"])
        from tools.samba_ad.domain_services import ServiceOps
        ServiceOps().inspect(initial=False)
        command(["samba-tool", "ntacl", "sysvolcheck"])
        # A fresh TLS connection proves the deployed leaf/chain/identity and TLS floor.
        context = ssl.create_default_context(cafile=r["pki"]["trust"]["root_file"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        address = str(ipaddress.IPv4Interface(r["substrate"]["resource"]["address"]).ip)
        with socket.create_connection((address, 636), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=r["target"]["fqdn"]) as tls:
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                cert = x509.load_pem_x509_certificate(secure_file(self.generation(r) / "cert.pem").read_bytes())
                require(tls.getpeercert(binary_form=True) == cert.public_bytes(serialization.Encoding.DER))
        command(["aide", "--config=/etc/samba-ad-integrity.conf", "--check"])
        command(["systemctl", "is-active", "--quiet", "samba-ad-integrity.timer"])
        if r["substrate"]["resource"]["kind"] == "qemu":
            command(["systemctl", "is-active", "--quiet", "auditd.service"])
        # Keep the observed SID outside Git/facts for the operator's private revision.
        from tools.samba_ad.pki_files import atomic_file
        receipt = Path("/var/lib/samba-ad-domain/identity.json")
        data = {"sid": observed["sid"], "spec_sha256": r["pki"]["target"]["spec_sha256"],
                "config_sha256": hashlib.sha256(secure_file("/etc/samba/smb.conf").read_bytes()).hexdigest()}
        if receipt.exists(): require(json.loads(secure_file(receipt, secret=True).read_bytes()) == data)
        else:
            require(r["target"]["sid"] is None and not receipt.is_symlink())
            atomic_file(receipt, json.dumps(data, sort_keys=True).encode())
        return {"state": "current", "changed": False, "sid": observed["sid"],
                "native_protocol_acceptance": "pending"}


def main():
    try:
        payload = loads(sys.stdin.read())
        fields(payload, "schema request manifest")
        require(payload["schema"] == "samba-ad-domain-wire/v1")
        state = validate_request(payload["request"], payload["manifest"])
        if state["state"] == "disabled":
            result = {"state": "disabled", "changed": False}
        else:
            request = dict(payload["request"])
            if "--execute" not in sys.argv: request["apply"] = False
            result = execute(request, Native(payload["manifest"]))
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print(ERROR, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
