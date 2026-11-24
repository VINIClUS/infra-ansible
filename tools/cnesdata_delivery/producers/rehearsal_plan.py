"""Subprocess boundary of the observer: the rehearsal plan is made in the job and never leaves it."""
import os
import subprocess
import tempfile
from pathlib import Path

from tools.cnesdata_delivery import contract as c

STATE_KEY = "cnesdata/prod/opentofu.tfstate"
REGION = "us-east-2"
ROOT = "infra/opentofu/env/prod"
TIMEOUTS = {"init": 300, "plan": 600, "show": 120}


def _root():
    base = os.environ.get("PRODUCT_ROOT")
    c.require(bool(base) and (Path(base) / ROOT).is_dir(), "product tree")
    return Path(base) / ROOT


def _environment(session, home):
    frozen = session.get_credentials().get_frozen_credentials()
    return {"PATH": os.environ["PATH"], "HOME": home, "LANG": "C.UTF-8", "TF_IN_AUTOMATION": "1",
            "CHECKPOINT_DISABLE": "1", "AWS_EC2_METADATA_DISABLED": "true", "AWS_CONFIG_FILE": "/dev/null",
            "AWS_SHARED_CREDENTIALS_FILE": "/dev/null", "AWS_REGION": REGION, "AWS_DEFAULT_REGION": REGION,
            "TF_WORKSPACE": "default", "AWS_ACCESS_KEY_ID": frozen.access_key,
            "AWS_SECRET_ACCESS_KEY": frozen.secret_key, "AWS_SESSION_TOKEN": frozen.token}


def _run(name, arguments, root, env):
    failed = False
    try:
        done = subprocess.run(["tofu", name, *arguments], cwd=root, env=env, capture_output=True,
                              check=False, timeout=TIMEOUTS[name])
    except subprocess.TimeoutExpired:
        failed = True
    c.require(not failed, f"tofu {name} timeout")
    c.require(done.returncode == 0, f"tofu {name} exit={done.returncode}")
    return done.stdout


def _write(path, value):
    path.write_bytes(c.canonical(value))
    path.chmod(0o600)
    return path


def plan(config, release_inputs, session):
    """Args: private config, phase-inputs.json bytes, boto3 session of the observer role.

    Returns: plan JSON bytes, held in memory only. Raises: ValueError with the failing step.
    """
    root = _root()
    variables = {"shared_outputs": config["shared_outputs"]} | c.loads(release_inputs, canonical=True)
    with tempfile.TemporaryDirectory() as temp:
        scratch = Path(temp)
        env = _environment(session, temp)
        backend = _write(scratch / "backend.json", {"bucket": config["state_bucket"], "key": STATE_KEY,
                                                   "region": REGION})
        inputs = _write(scratch / "inputs.tfvars.json", variables)
        binary = scratch / "plan.bin"
        _run("init", ["-input=false", "-lockfile=readonly", f"-backend-config={backend}"], root, env)
        _run("plan", ["-input=false", "-refresh=false", "-lock=false", f"-var-file={inputs}",
                      f"-out={binary}"], root, env)
        return _run("show", ["-json", str(binary)], root, env)
