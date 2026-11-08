"""Render only the qualified CA's restricted step-ca/NGINX+njs configuration.

Templates are server-side Go templates, never client templateData. This module
does not install packages, issue certificates, write files or start services.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import grp
from pathlib import Path
import pwd
import re
import sys
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from tools.samba_ad.ca_substrate import validate_ca_bundle
from tools.samba_ad.pki import PROFILES, _critical, _issuer, _key, _valid_time, require
from tools.samba_ad.pki_contract import dns, fields, hex_value, loads, path, public_jwk, review
from tools.samba_ad.pki_files import future_directory, secure_file

CONFIG = "/etc/samba-ad-pki"
LIBRARY = "/usr/libexec/samba-ad-pki"


def validate(r):
    require(isinstance(r, dict) and r.get("schema") == "samba-ad-ca-config/v1"
            and type(r.get("enabled")) is bool and type(r.get("apply")) is bool)
    if not r["enabled"]: return None
    fields(r, "schema enabled apply guest_request target paths root_sha256 issuer_sha256 backend_port "
              "service_user frontend_user registry tools expected_files")
    guest = r["guest_request"]
    validate_ca_bundle(guest["compatibility"], guest)
    manifest = guest["compatibility"]["data"]["manifest"]
    require(set(manifest["certificate_profiles"]) == PROFILES)
    for name in PROFILES:
        fqdn = manifest["resources"][name.removeprefix("telemetry_")]["fqdn"]
        dns(fqdn)
        profile = manifest["certificate_profiles"][name]
        fields(profile, "sans eku validity_hours rotate_before_fraction")
        require(profile["sans"] == [fqdn] and profile["eku"] == ["clientAuth" if name.startswith("telemetry_") else "serverAuth"]
                and profile["validity_hours"] == 168 and profile["rotate_before_fraction"] == 0.66)
    t = r["target"]
    fields(t, "fqdn address mac boot_id machine_id interface")
    c = guest["resource"]
    require(t["fqdn"] == c["name"] and t["address"] == c["address"].split("/")[0] and t["mac"] == c["mac"])
    require(str(uuid.UUID(t["boot_id"])) == t["boot_id"])
    hex_value(t["machine_id"], 32)
    require(re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", t["interface"]))
    require(type(r["backend_port"]) is int and 1024 <= r["backend_port"] <= 65535)
    for key in ["service_user", "frontend_user"]:
        require(isinstance(r[key], str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", r[key]) and r[key] != "root")
    fields(r["paths"], "root_cert issuer_cert issuer_key issuer_password_ref ca_state identity_state")
    for p in r["paths"].values(): path(p)
    require(r["paths"]["root_cert"] == CONFIG + "/root.pem" and r["paths"]["issuer_cert"] == CONFIG + "/issuer.pem")
    require(r["paths"]["issuer_key"] == "/etc/samba-ad-ca/intermediate.key.pem")
    require(r["paths"]["issuer_password_ref"] == "/run/samba-ad-pki-credentials/ca/issuer-password")
    require(r["paths"]["ca_state"] == "/var/lib/samba-ad-ca"
            and r["paths"]["identity_state"] == "/var/lib/samba-ad-pki")
    require(r["service_user"] == "samba-ad-ca" and r["frontend_user"] != r["service_user"])
    for key in ["root_sha256", "issuer_sha256"]: hex_value(r[key])
    require(isinstance(r["registry"], dict) and set(r["registry"]) == PROFILES)
    for value in r["registry"].values(): public_jwk(value)
    require(len({v["kid"] for v in r["registry"].values()}) == 6
            and len({(v["x"], v["y"]) for v in r["registry"].values()}) == 6)
    fields(r["tools"], "step_ca nginx njs")
    for artifact in r["tools"].values():
        fields(artifact, "path version sha256 provenance_ref")
        path(artifact["path"]); hex_value(artifact["sha256"]); review(artifact["provenance_ref"])
        require(isinstance(artifact["version"], str) and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,80}", artifact["version"]))
    nginx = r["tools"]["nginx"]["version"].split("-")[0]
    require(r["tools"]["njs"]["version"].split("+")[0] == nginx)
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", nginx))
    require(isinstance(r["expected_files"], dict))
    for filename, digest in r["expected_files"].items():
        path(filename)
        if digest is not None: hex_value(digest)
    return manifest


def profile_template(name, dns, audience):
    # All interpolation is JSON-escaped trusted configuration, not user data.
    prefix = r'''{{- if ne (len .Token) 9 }}{{ fail "claims denied" }}{{ end -}}
{{- if or (ne .Token.iss ISSUER) (ne .Token.sub NAME) }}{{ fail "profile denied" }}{{ end -}}
{{- if not (kindIs "slice" .Token.sans) }}{{ fail "SAN denied" }}{{ end -}}
{{- if or (ne (len .Token.sans) 1) (ne (index .Token.sans 0) NAME) }}{{ fail "SAN denied" }}{{ end -}}
{{- if not (kindIs "slice" .Token.aud) }}{{ fail "audience denied" }}{{ end -}}
{{- if or (ne (len .Token.aud) 1) (ne (index .Token.aud 0) AUDIENCE) }}{{ fail "audience denied" }}{{ end -}}
{{- if or (not .Token.iat) (not .Token.exp) (not .Token.nbf) (not .Token.jti) }}{{ fail "time/jti denied" }}{{ end -}}
{{- if or (lt (sub .Token.exp .Token.iat) 1) (gt (sub .Token.exp .Token.iat) 300) (gt .Token.nbf .Token.iat) (gt (sub .Token.iat .Token.nbf) 30) }}{{ fail "time denied" }}{{ end -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" .Token.jti) }}{{ fail "jti denied" }}{{ end -}}
{{- if not (kindIs "map" .Token.cnf) }}{{ fail "CSR binding denied" }}{{ end -}}
{{- if ne (len .Token.cnf) 1 }}{{ fail "CSR binding denied" }}{{ end -}}
{{- if not (regexMatch "^[A-Za-z0-9_-]{43}$" (index .Token.cnf "x5rt#S256")) }}{{ fail "CSR binding denied" }}{{ end -}}
{{- if not (typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey) }}{{ fail "key denied" }}{{ end -}}
{{- if or (ne .Insecure.CR.PublicKey.E 65537) (and (ne .Insecure.CR.PublicKey.N.BitLen 3072) (ne .Insecure.CR.PublicKey.N.BitLen 4096)) }}{{ fail "key denied" }}{{ end -}}
'''
    prefix = prefix.replace("ISSUER", json.dumps("s3-" + name)).replace("NAME", json.dumps(dns))
    prefix = prefix.replace("AUDIENCE", json.dumps(audience))
    leaf = {"subject": {"commonName": dns}, "dnsNames": [dns],
            "keyUsage": ["digitalSignature", "keyEncipherment"],
            "extKeyUsage": ["clientAuth" if name.startswith("telemetry_") else "serverAuth"],
            "basicConstraints": {"isCA": False}}
    return prefix + json.dumps(leaf, sort_keys=True, indent=2) + "\n"


def render(r):
    try:
        return _render(r)
    except Exception:
        raise ValueError("S3 CA configuration refused (values suppressed)") from None


def _render(r):
    manifest = validate(r)
    if manifest is None: return {}
    p = r["paths"]; files = {}
    dns = r["target"]["fqdn"]
    audience = "https://" + dns + "/1.0/sign"
    claims = {"minTLSCertDuration": "168h", "maxTLSCertDuration": "168h", "defaultTLSCertDuration": "168h",
              "disableRenewal": True, "allowRenewalAfterExpiry": False, "enableSSHCA": False,
              "disableSmallstepExtensions": False}
    provisioners = []
    for name in sorted(PROFILES):
        filename = CONFIG + "/profiles/" + name + ".tpl"
        host = manifest["certificate_profiles"][name]["sans"]
        require(host == [manifest["resources"][name.removeprefix("telemetry_")]["fqdn"]])
        files[filename] = profile_template(name, host[0], audience)
        provisioners.append({"type": "JWK", "name": "s3-" + name, "key": r["registry"][name],
                             "claims": claims, "options": {"x509": {"templateFile": filename}}})
    config = {"root": p["root_cert"], "crt": p["issuer_cert"], "key": p["issuer_key"],
              "address": "127.0.0.1:" + str(r["backend_port"]), "dnsNames": [dns],
              "logger": {"format": "common"}, "db": {"type": "badgerv2", "dataSource": p["ca_state"] + "/db"},
              "tls": {"minVersion": "1.2", "maxVersion": "1.3", "renegotiation": False},
              "authority": {"enableAdmin": False, "disableIssuedAtCheck": False, "backdate": "0s", "claims": claims,
                            "policy": {"x509": {"allow": {"dns": sorted({manifest['resources'][k]['fqdn']
                                                                        for k in ['dc01', 'dc02', 'ca']})},
                                                 "allowWildcardNames": False}}, "provisioners": provisioners}}
    files[CONFIG + "/ca.json"] = json.dumps(config, indent=2, sort_keys=True) + "\n"
    files[CONFIG + "/nginx.conf"] = f'''load_module {r['tools']['njs']['path']};
user {r['frontend_user']};
worker_processes 1;
pid /run/samba-ad-pki-nginx.pid;
error_log stderr warn;
events {{ worker_connections 128; }}
http {{
    js_engine njs;
    js_import pki from {LIBRARY}/frontend.js;
    client_max_body_size 32k;
    client_body_buffer_size 64k;
    client_body_timeout 5s;
    client_body_temp_path /run/samba-ad-pki-nginx/body;
    send_timeout 10s;
    subrequest_output_buffer_size 32k;
    limit_req_zone $binary_remote_addr zone=s3_rate:1m rate=5r/m;
    limit_conn_zone $binary_remote_addr zone=s3_conn:1m;
    log_format s3 '$status $request_method';
    access_log /dev/stdout s3;
    server {{
        listen {r['target']['address']}:443 ssl;
        server_name {dns};
        ssl_protocols TLSv1.2 TLSv1.3;
        include {p['identity_state']}/ca/active.conf;
        ssl_session_tickets off;
        ssl_session_timeout 1m;
        keepalive_timeout 5s;
        keepalive_requests 10;
        limit_conn s3_conn 2;
        location = /1.0/sign {{
            limit_req zone=s3_rate burst=2 nodelay;
            limit_req_status 429;
            js_content pki.sign;
        }}
        location = /_s3_sign {{
            internal;
            proxy_pass https://127.0.0.1:{r['backend_port']}/1.0/sign;
            proxy_method POST;
            proxy_pass_request_headers off;
            proxy_set_header Host {dns};
            proxy_set_header Content-Type application/json;
            proxy_set_header Connection "";
            proxy_ssl_server_name on;
            proxy_ssl_name {dns};
            proxy_ssl_trusted_certificate {p['root_cert']};
            proxy_ssl_verify on;
            proxy_ssl_verify_depth 2;
            proxy_ssl_protocols TLSv1.2 TLSv1.3;
            proxy_connect_timeout 3s;
            proxy_send_timeout 5s;
            proxy_read_timeout 10s;
            proxy_next_upstream off;
            proxy_redirect off;
            proxy_buffer_size 32k;
            proxy_buffers 4 32k;
            proxy_max_temp_file_size 0;
            proxy_temp_path /run/samba-ad-pki-nginx/proxy;
        }}
        location / {{ return 404; }}
    }}
}}
'''
    files["/etc/systemd/system/samba-ad-pki-ca.service"] = f'''[Unit]
Description=Samba AD intermediate CA (loopback only)
After=network.target
[Service]
Type=simple
User={r['service_user']}
Group={r['service_user']}
UMask=0077
LoadCredential=issuer-password:{p['issuer_password_ref']}
ExecStart={r['tools']['step_ca']['path']} {CONFIG}/ca.json --password-file %d/issuer-password
WorkingDirectory={p['ca_state']}
Restart=on-failure
RestartSec=10s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths={p['ca_state']}
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
'''
    files["/etc/systemd/system/samba-ad-pki-nginx.service"] = f'''[Unit]
Description=Samba AD sign-only HTTPS frontend
After=network.target samba-ad-pki-ca.service
Requires=samba-ad-pki-ca.service
[Service]
Type=simple
UMask=0077
ExecStart={r['tools']['nginx']['path']} -c {CONFIG}/nginx.conf -g "daemon off;"
ExecReload={r['tools']['nginx']['path']} -c {CONFIG}/nginx.conf -s reload
Restart=on-failure
RestartSec=10s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run
RuntimeDirectory=samba-ad-pki-nginx
RuntimeDirectoryMode=0755
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN
[Install]
WantedBy=multi-user.target
'''
    require(set(r["expected_files"]) <= set(files))
    return files


def public_chain(root_pem, issuer_pem, root_sha256, issuer_sha256, now):
    try:
        root = x509.load_pem_x509_certificate(root_pem)
        issuer = x509.load_pem_x509_certificate(issuer_pem)
        require(root.fingerprint(hashes.SHA256()).hex() == root_sha256
                and issuer.fingerprint(hashes.SHA256()).hex() == issuer_sha256)
        root.verify_directly_issued_by(root); issuer.verify_directly_issued_by(root)
        for cert in [root, issuer]:
            _key(cert.public_key()); _critical(cert); _valid_time(cert, now)
            require(isinstance(cert.signature_hash_algorithm, hashes.SHA256))
        _issuer(root, 1); _issuer(issuer, 0)
        return {"root": root.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                "issuer": issuer.public_bytes(serialization.Encoding.PEM).decode("ascii")}
    except Exception:
        raise ValueError("S3 public chain refused (values suppressed)") from None


def service_account(r):
    """Refuse shared/pre-existing accounts before Ansible user/group mutations."""
    name = r["service_user"]
    try: account = pwd.getpwnam(name)
    except KeyError: account = None
    try: group = grp.getgrnam(name)
    except KeyError: group = None
    if group is not None:
        require(group.gr_gid != 0 and set(group.gr_mem) <= {name})
    if account is not None:
        require(account.pw_uid != 0 and account.pw_dir == r["paths"]["ca_state"]
                and account.pw_shell in ["/usr/sbin/nologin", "/sbin/nologin"]
                and group is not None and account.pw_gid == group.gr_gid)
    for other in pwd.getpwall():
        if other.pw_name == name: continue
        require(account is None or other.pw_uid != account.pw_uid)
        require(group is None or other.pw_gid != group.gr_gid)
    return account


def inspect(r, ops=None):
    """Readonly host/tools/key-presence check, not a runtime acceptance report."""
    validate(r)
    if not r["enabled"]: return {"state": "disabled", "changed": False}
    if ops is None:
        account = service_account(r)
        future_directory(r["paths"]["ca_state"], account.pw_uid if account else None)
        future_directory(r["paths"]["identity_state"])
        future_directory(Path(r["paths"]["issuer_key"]).parent)
    from tools.samba_ad.pki_runtime import host_snapshot
    actual = ops.inspect(r["target"]) if ops else host_snapshot(r["target"]["interface"])
    require(actual["uid"] == 0 and actual["virtualization"] in ["kvm", "qemu"])
    require(all(actual[k] == r["target"][k] for k in ["fqdn", "boot_id", "machine_id", "mac"])
            and r["target"]["address"] in actual["addresses"])
    for name, artifact in r["tools"].items():
        binary = secure_file(artifact["path"])
        require(hashlib.sha256(binary.read_bytes()).hexdigest() == artifact["sha256"])
        require(name == "njs" or binary.stat().st_mode & 0o111)
    secure_file(r["paths"]["issuer_password_ref"], secret=True)
    # Encrypted issuer key stays on this host; never returned, copied or printed.
    key = secure_file(r["paths"]["issuer_key"])
    require(key.stat().st_mode & 0o777 in [0o600, 0o640])
    require(key.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
    import time
    public_chain(secure_file(r["paths"]["root_cert"]).read_bytes(),
                 secure_file(r["paths"]["issuer_cert"]).read_bytes(),
                 r["root_sha256"], r["issuer_sha256"], int(time.time()))
    return {"state": "planned", "changed": False, "profiles": 6}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inspect", action="store_true")
    args = p.parse_args(argv)
    try:
        request = loads(sys.stdin.read())
        print(json.dumps(inspect(request) if args.inspect else render(request)))
        return 0
    except Exception:
        print('{"state":"error","error":"S3 CA configuration refused (values suppressed)"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
