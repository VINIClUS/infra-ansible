"""Exact-source, mock-provider plans of the prerequisites root; no credentials or network."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "opentofu/cnesdata-delivery-prerequisites"
MOCK = '''
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
      arn        = "arn:aws:sts::111122223333:assumed-role/synthetic-operator/synthetic-session"
      user_id    = "synthetic-session"
    }
  }
}
run "contract" { command = plan }
'''


class Native:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="prereq-plan-")
        self.base = Path(self.temp.name)
        self.cache = {}
        self.prepared = None
        self.tofu, self.unshare = [shutil.which(x) for x in ("tofu", "unshare")]
        assert all((self.tofu, self.unshare)), "native tools required; no skip/fallback"
        configured = os.environ.get("CNESDATA_TEST_AWS_PROVIDER_DIR")
        assert configured, "complete cached AWS provider directory is required"
        provider = Path(configured).resolve()
        assert len(list(provider.glob("terraform-provider-aws*"))) == 1
        mirror = self.base / "mirror/registry.opentofu.org/hashicorp/aws/6.54.0"
        mirror.mkdir(parents=True)
        (mirror / "linux_amd64").symlink_to(provider)
        config = self.base / "tofu.rc"
        config.write_text('provider_installation { filesystem_mirror { path = '
                          + json.dumps(str(self.base / "mirror"))
                          + ' include = ["registry.opentofu.org/hashicorp/aws"] } }\n')
        self.env = {"PATH": os.defpath, "HOME": str(self.base), "TMPDIR": str(self.base),
                    "LANG": "C.UTF-8", "AWS_EC2_METADATA_DISABLED": "true",
                    "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
                    "TF_CLI_CONFIG_FILE": str(config), "TF_IN_AUTOMATION": "1",
                    "CHECKPOINT_DISABLE": "1"}

    def run(self, directory, *args):
        assert args[0] in {"init", "test", "validate", "fmt"}
        return subprocess.run([self.unshare, "--user", "--map-root-user", "--net",
                               self.tofu, *args], cwd=directory, env=self.env, text=True,
                              capture_output=True, timeout=180, check=False)

    def prepare(self):
        assert ROOT.is_dir() and list(ROOT.glob("*.tf")), "prerequisites root not implemented"
        self.prepared = self.base / "prepared"
        self.prepared.mkdir()
        for path in [*ROOT.glob("*.tf"), ROOT / ".terraform.lock.hcl"]:
            shutil.copy2(path, self.prepared / path.name)
        for args in [("fmt", "-check"),
                     ("init", "-backend=false", "-input=false", "-lockfile=readonly"),
                     ("validate", "-json")]:
            result = self.run(self.prepared, *args)
            assert result.returncode == 0, result.stdout + result.stderr

    def plan(self, variables, name):
        key = (name, json.dumps(variables, sort_keys=True))
        if key in self.cache:
            return self.cache[key]
        if self.prepared is None:
            self.prepare()
        directory = self.base / name
        shutil.copytree(self.prepared, directory, symlinks=True)
        (directory / "inputs.tfvars.json").write_text(json.dumps(variables))
        (directory / "contract.tftest.hcl").write_text(MOCK)
        result = self.run(directory, "test", "-json", "-verbose", "-var-file=inputs.tfvars.json")
        events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        diagnostics = [e["diagnostic"] for e in events if "diagnostic" in e]
        plans = [e["test_plan"] for e in events if "test_plan" in e]
        self.cache[key] = (result.returncode, plans, diagnostics)
        return self.cache[key]
