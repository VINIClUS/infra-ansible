"""Public backend and shared-outputs commitments: hashes and public facts only, no AWS."""
import os
import re
import sys
from pathlib import Path

from tools.cnesdata_delivery import contract as c

BACKEND = "identity_sha256 key workspace region encrypt use_lockfile bucket_hmac kms_key_id_sha256"
INPUTS = BACKEND + " schema_sha256 shared_outputs_sha256"
PRIVATE = "bucket identity key region encrypt use_lockfile kms_key_id schema_sha256 shared_outputs"
DIGESTS = ("identity_sha256", "bucket_hmac", "kms_key_id_sha256", "schema_sha256", "shared_outputs_sha256")
BOOLEANS = {"true": True, "false": False}
KEY = re.compile(r"[A-Za-z0-9._/-]{1,512}")
REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]")


def _flag(value, name):
    resolved = BOOLEANS.get(value, value) if type(value) is str else value
    c.require(type(resolved) is bool, f"boolean input name={name}")
    return resolved


def _hex(value, name):
    c.require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, f"digest input name={name}")
    return value


def build(inputs):
    """Args: the ten dispatch inputs. Returns: backend.json and shared-outputs.json bytes. Raises: ValueError."""
    c.closed(inputs, INPUTS)
    for name in DIGESTS:
        _hex(inputs[name], name)
    c.require(inputs["workspace"] == "default", "backend workspace")
    c.require(type(inputs["key"]) is str and KEY.fullmatch(inputs["key"]) is not None, "backend key")
    c.require(type(inputs["region"]) is str and REGION.fullmatch(inputs["region"]) is not None, "backend region")
    backend = {name: inputs[name] for name in BACKEND.split()}
    backend |= {name: _flag(inputs[name], name) for name in ("encrypt", "use_lockfile")}
    shared = {"schema_version": 2, "schema_sha256": inputs["schema_sha256"],
              "shared_outputs_sha256": inputs["shared_outputs_sha256"]}
    c.public_safe(backend)
    c.public_safe(shared)
    return {"backend.json": c.canonical(backend), "shared-outputs.json": c.canonical(shared)}


def shared_outputs(raw):
    """Args: shared-outputs.json bytes. Returns: the validated value. Raises: ValueError."""
    value = c.loads(raw, canonical=True)
    c.closed(value, "schema_version schema_sha256 shared_outputs_sha256")
    c.require(value["schema_version"] == 2 and type(value["schema_version"]) is int, "shared outputs schema version")
    _hex(value["schema_sha256"], "schema_sha256")
    _hex(value["shared_outputs_sha256"], "shared_outputs_sha256")
    return value


def dispatch_inputs(private, key_hex):
    """Args: private owner values, cycle report key (hex). Returns: the exact public dispatch inputs."""
    c.closed(private, PRIVATE)
    key = c.report_key({"report_hmac_key": key_hex})
    value = {"identity_sha256": c.sha(private["identity"].encode()), "key": private["key"],
             "workspace": "default", "region": private["region"], "encrypt": private["encrypt"],
             "use_lockfile": private["use_lockfile"],
             "bucket_hmac": c.report_hmac(key, "backend_bucket", private["bucket"].encode()),
             "kms_key_id_sha256": c.sha(private["kms_key_id"].encode()), "schema_sha256": private["schema_sha256"],
             "shared_outputs_sha256": c.sha(c.canonical(private["shared_outputs"]))}
    build(value)
    return value


def main(argv=None):
    out = Path(argv[0] if argv else os.environ["BASELINE_OUT"])
    values = {name: os.environ[name.upper()] for name in INPUTS.split()}
    files = build(values)
    out.mkdir(parents=True, exist_ok=True)
    for name, raw in files.items():
        (out / name).write_bytes(raw)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
