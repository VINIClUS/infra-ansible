"""Validate public Roles Anywhere CRL evidence offline; never call AWS.

Output is an input manifest, NOT proof that the JSON came from AWS. The operator
must establish live provenance/freshness and bind this manifest to the exact
audited plan. This tool neither imports a CRL nor authorizes activation.
"""
import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HISTORICAL_DEADLINE = "1970-01-01T00:00:00Z"
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def utc(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value),
            "expected canonical UTC timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def openssl_date(value):
    return datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)


def timestamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def public_pem(value):
    require(isinstance(value, bytes) and len(value) <= 32768, "public CA size invalid")
    require(re.fullmatch(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*", value),
            "expected exactly one public CA certificate; no private key or bundle")
    return value


def _read_crypto(ca_pem, crl_der, anchor_pem, now):
    binary = shutil.which("openssl")
    require(binary is not None, "openssl is required; no verification fallback")
    with tempfile.TemporaryDirectory(prefix="ra-crl-") as directory:
        base = Path(directory)
        ca, crl, anchor = base / "ca.crt", base / "crl.der", base / "anchor.crt"
        ca.write_bytes(public_pem(ca_pem))
        crl.write_bytes(crl_der)
        anchor.write_bytes(public_pem(anchor_pem))
        env = {"PATH": os.defpath, "HOME": directory, "LANG": "C", "LC_ALL": "C",
               "OPENSSL_CONF": "/dev/null"}

        def run(*args):
            result = subprocess.run([binary, *map(str, args)], env=env,
                                    capture_output=True, timeout=15, check=False)
            require(result.returncode == 0, "openssl public certificate/CRL verification failed")
            return result.stdout

        ca_der = run("x509", "-in", ca, "-outform", "DER")
        require(ca_der == run("x509", "-in", anchor, "-outform", "DER"), "anchor CA bytes mismatch")
        extensions = run("x509", "-in", ca, "-noout", "-ext", "basicConstraints,keyUsage").decode()
        require("CA:TRUE" in extensions and "Certificate Sign" in extensions and "CRL Sign" in extensions,
                "CA must have basicConstraints CA and CRL signing usage")
        run("verify", "-CAfile", ca, "-check_ss_sig", "-attime", str(int(now.timestamp())), ca)
        require(run("crl", "-inform", "DER", "-in", crl, "-outform", "DER") == crl_der,
                "CRL must be exact canonical DER without trailing data")
        run("crl", "-inform", "DER", "-in", crl, "-noout", "-verify", "-CAfile", ca)
        details = run("crl", "-inform", "DER", "-in", crl, "-noout", "-text").decode()
        require("Delta CRL Indicator" not in details and "Indirect CRL" not in details
                and "Certificate Issuer" not in details, "only full direct CRLs are supported")
        serial_values = re.findall(r"^\s*Serial Number:\s*(\S+)\s*$", details, re.MULTILINE)
        require(all(re.fullmatch(r"[0-9A-Fa-f]+", value) for value in serial_values),
                "revoked serial encoding invalid")
        serials = [int(value, 16) for value in serial_values]
        require(all(value > 0 for value in serials) and len(serials) == len(set(serials)),
                "revoked serials must be positive and unique")
        subject = run("x509", "-in", ca, "-noout", "-subject", "-nameopt", "RFC2253").decode().strip().split("=", 1)[1]
        issuer = run("crl", "-inform", "DER", "-in", crl, "-noout", "-issuer", "-nameopt", "RFC2253").decode().strip().split("=", 1)[1]
        require(subject == issuer, "CRL issuer does not match CA subject")
        dates = dict(line.split("=", 1) for line in run(
            "crl", "-inform", "DER", "-in", crl, "-noout", "-lastupdate", "-nextupdate", "-crlnumber"
        ).decode().splitlines())
        this_update, next_update = openssl_date(dates["lastUpdate"]), openssl_date(dates["nextUpdate"])
        require(re.fullmatch(r"0x[0-9A-Fa-f]+", dates["crlNumber"]), "signed CRL number required")
        number = int(dates["crlNumber"], 16)
        validity = dict(line.split("=", 1) for line in run("x509", "-in", ca, "-noout", "-dates").decode().splitlines())
        require(openssl_date(validity["notBefore"]) <= this_update < next_update <= openssl_date(validity["notAfter"]),
                "CRL interval must be within CA validity")
        require(this_update <= now < next_update, "CRL is future-dated or expired")
        return ca_der, this_update, next_update, number, sorted(serials)


def validate_handoff(ca_pem, crl_der, crl_readback, anchor_readback, expected, *, now=None):
    """Derive a public manifest from signed bytes and explicit expected identities.

    `now` is a deterministic clock for callers/tests. The CLI always uses UTC now;
    callers remain responsible for trusted clock and readback provenance.
    """
    try:
        return _validate(ca_pem, crl_der, crl_readback, anchor_readback, expected,
                         now or datetime.now(timezone.utc))
    except (KeyError, TypeError, AttributeError, OverflowError, binascii.Error,
            UnicodeError, subprocess.SubprocessError, OSError) as error:
        raise ValueError("invalid CRL handoff evidence") from error


def _validate(ca_pem, crl_der, crl_readback, anchor_readback, expected, now):
    require(now.tzinfo is not None, "verification clock must have a timezone")
    account, region = expected["account_id"], expected["region"]
    require(isinstance(account, str) and re.fullmatch(r"[0-9]{12}", account), "account invalid")
    require(region == "us-east-2", "CnesData region must be us-east-2")
    anchor_arn, crl_id = expected["trust_anchor_arn"], expected["crl_id"]
    prefix = f"arn:aws:rolesanywhere:{region}:{account}:"
    require(re.fullmatch(re.escape(prefix + "trust-anchor/") + UUID, anchor_arn), "anchor identity invalid")
    require(re.fullmatch(UUID, crl_id), "CRL identity invalid")
    require(isinstance(crl_der, bytes) and 0 < len(crl_der) <= 300000, "CRL size invalid")
    require(sha256(crl_der) == expected["crl_sha256"], "expected DER hash mismatch")
    crl, anchor = crl_readback["crl"], anchor_readback["trustAnchor"]
    require(crl["enabled"] is True and anchor["enabled"] is True, "CRL and anchor must be enabled")
    require(crl["crlId"] == crl_id and crl["crlArn"] == prefix + "crl/" + crl_id,
            "CRL readback identity mismatch")
    require(crl["trustAnchorArn"] == anchor_arn == anchor["trustAnchorArn"], "anchor readback identity mismatch")
    require(anchor["trustAnchorId"] == anchor_arn.rsplit("/", 1)[1], "anchor ID mismatch")
    require(base64.b64decode(crl["crlData"], validate=True) == crl_der, "readback DER mismatch")
    require(anchor["source"]["sourceType"] == "CERTIFICATE_BUNDLE", "only offline public CA supported")
    anchor_pem = anchor["source"]["sourceData"]["x509CertificateData"].encode("ascii")
    ca_der, this_update, next_update, number, serials = _read_crypto(ca_pem, crl_der, anchor_pem, now)
    ca_hash = sha256(ca_der)
    require(ca_hash == expected["ca_der_sha256"], "expected CA hash mismatch")
    previous = expected["previous_handoff"]
    operation = expected["operation"]
    require(operation in {"initialize", "renew"}, "explicit initialize or renew operation required")
    authorized = utc(expected["authorized_deadline"])
    require(next_update >= authorized, "new CRL deadline is shorter than authorized trust")
    if previous is None:
        require(operation == "initialize", "renewal requires previous accepted history even after closure")
        require(expected["previous_handoff_sha256"] is None, "initial import cannot discard an expected previous hash")
        require(expected["authorized_deadline"] == HISTORICAL_DEADLINE,
                "prior authorization requires the previous accepted handoff")
    else:
        require(operation == "renew", "previous history requires an explicit renewal")
        require(sha256(canonical(previous)) == expected["previous_handoff_sha256"],
                "previous accepted handoff hash mismatch")
        require(previous["handoff_version"] == 1 and previous["enabled"] is True,
                "previous accepted handoff required")
        for field, value in [("account_id", account), ("region", region), ("trust_anchor_arn", anchor_arn),
                             ("crl_id", crl_id), ("ca_der_sha256", ca_hash)]:
            require(previous[field] == value, "renewal identity changed; closed rotation required")
        require(re.fullmatch(r"0|[1-9][0-9]*", previous["crl_number"]), "previous CRL number invalid")
        require(number > int(previous["crl_number"]) and sha256(crl_der) != previous["sha256"],
                "CRL replay or number rollback")
        require(this_update >= utc(previous["this_update"]) and next_update >= utc(previous["next_update"]),
                "CRL time rollback")
        require(authorized <= utc(previous["next_update"]), "authorization exceeds previous accepted CRL")
        old_serials = previous["revoked_serials"]
        require(isinstance(old_serials, list) and all(
            isinstance(value, str) and re.fullmatch(r"[0-9]+", value) and int(value) > 0
            for value in old_serials), "previous revoked serial history required")
        require({int(value) for value in old_serials}.issubset(set(serials)),
                "previously revoked serials cannot be removed during renewal; closed rotation required")
    manifest = {
        "handoff_version": 1, "operation": operation, "account_id": account, "region": region,
        "trust_anchor_arn": anchor_arn, "crl_id": crl_id, "enabled": True,
        "ca_der_sha256": ca_hash, "ca_pem_sha256": sha256(ca_pem), "sha256": sha256(crl_der),
        "this_update": timestamp(this_update), "next_update": timestamp(next_update),
        "crl_number": str(number),
        "revoked_serials": [str(value) for value in serials],
        "readback_sha256": {"crl": sha256(canonical(crl_readback)), "trust_anchor": sha256(canonical(anchor_readback))},
        "previous_handoff_sha256": sha256(canonical(previous)) if previous else None,
    }
    return {"crl_handoff": manifest, "crl_handoff_sha256": sha256(canonical(manifest))}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ca", "crl", "get-crl", "get-trust-anchor", "expected"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        def read(path):
            require(path.stat().st_size <= 1000000, "input too large")
            return path.read_bytes()

        def document(path):
            return json.loads(read(path), object_pairs_hook=unique_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))

        result = validate_handoff(read(args.ca), read(args.crl), document(args.get_crl),
                                  document(args.get_trust_anchor), document(args.expected))
        sys.stdout.buffer.write(canonical(result) + b"\n")
        return 0
    except (ValueError, OSError) as error:
        print("CRL handoff rejected: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
