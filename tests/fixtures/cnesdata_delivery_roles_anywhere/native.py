"""Exact-source, mock-provider plans; no credentials, backend or network."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[3]
ROOT = REPO / "opentofu/cnesdata-delivery"


class Native:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ra-plan-")
        self.base = Path(self.temp.name)
        self.cache = {}
        self.prepared = None
        self.tofu, self.rtk, self.unshare = [shutil.which(x) for x in ("tofu", "rtk", "unshare")]
        assert all((self.tofu, self.rtk, self.unshare)), "native tools required; no skip/fallback"
        configured = os.environ.get("CNESDATA_TEST_AWS_PROVIDER_DIR")
        assert configured, "complete cached AWS provider directory is required"
        provider = Path(configured).resolve()
        assert (provider / "LICENSE").is_file() and (provider / "README.md").is_file()
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
                    "TF_CLI_CONFIG_FILE": str(config), "TF_IN_AUTOMATION": "1", "CHECKPOINT_DISABLE": "1"}

    def run(self, directory, *args):
        assert args[0] in {"init", "test", "validate", "fmt", "version"}
        result = subprocess.run([self.rtk, "proxy", self.unshare, "--user", "--map-root-user",
                                 "--net", self.tofu, *args], cwd=directory, env=self.env,
                                text=True, capture_output=True, timeout=180, check=False)
        (directory / (args[0] + ".stdout")).write_text(result.stdout)
        (directory / (args[0] + ".stderr")).write_text(result.stderr)
        return result

    def plan(self, variables, name, caller_arn=None):
        cache_key = (name, json.dumps(variables, sort_keys=True), caller_arn)
        if cache_key in self.cache:
            return self.cache[cache_key]
        assert ROOT.is_dir() and list(ROOT.glob("*.tf")), "delivery root not implemented"
        if self.prepared is None:
            self.prepared = self.base / "prepared"
            self.prepared.mkdir()
            for path in [*ROOT.glob("*.tf"), ROOT / ".terraform.lock.hcl"]:
                shutil.copy2(path, self.prepared / path.name)
            for args in [("fmt", "-check"), ("init", "-backend=false", "-input=false", "-lockfile=readonly"),
                         ("validate", "-json")]:
                result = self.run(self.prepared, *args)
                assert result.returncode == 0, result.stdout + result.stderr
        directory = self.base / (name + "-" + hashlib.sha256(repr(cache_key).encode()).hexdigest()[:8])
        shutil.copytree(self.prepared, directory, symlinks=True)
        (directory / "inputs.tfvars.json").write_text(json.dumps(variables))
        (directory / "contract.tftest.hcl").write_text('''
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
      arn = "CALLER_ARN"
      user_id = "synthetic-session"
    }
  }
  mock_resource "aws_rolesanywhere_trust_anchor" {
    defaults = {
      arn = "arn:aws:rolesanywhere:us-east-2:111122223333:trust-anchor/00000000-0000-4000-8000-000000000001"
      id = "00000000-0000-4000-8000-000000000001"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::111122223333:role/synthetic-cnesdata-api"
      id = "synthetic-cnesdata-api"
    }
  }
  mock_resource "aws_rolesanywhere_profile" {
    defaults = {
      arn = "arn:aws:rolesanywhere:us-east-2:111122223333:profile/00000000-0000-4000-8000-000000000003"
      id = "00000000-0000-4000-8000-000000000003"
    }
  }
}
run "contract" { command = plan }
'''.replace("CALLER_ARN", caller_arn or "arn:aws:sts::111122223333:assumed-role/synthetic-operator/synthetic-session"))
        result = self.run(directory, "test", "-json", "-verbose", "-var-file=inputs.tfvars.json")
        events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        diagnostics = [event["diagnostic"] for event in events if "diagnostic" in event]
        plans = [event["test_plan"] for event in events if "test_plan" in event]
        outcome = (result.returncode, plans, diagnostics)
        evidence = os.environ.get("CNESDATA_RA_EVIDENCE_DIR")
        if evidence:
            target = Path(evidence)
            target.mkdir(parents=True, exist_ok=True)
            source_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in self.prepared.glob("*.tf")}
            (target / (name + ".json")).write_text(json.dumps(
                {"source_hashes": source_hashes, "exit_code": result.returncode,
                 "plans": plans, "diagnostics": diagnostics}, indent=2
            ))
        self.cache[cache_key] = outcome
        return outcome
