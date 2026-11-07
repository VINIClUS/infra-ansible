"""Exercise disabled/guarded Ansible entrypoint without invoking any host probe."""
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("case", ["disabled", "missing_limit", "broad_limit", "extra_tag"])
def test_manual_entrypoint_cannot_reach_mutations_without_exact_guards(tmp_path, case):
    playbook = ROOT / "playbooks/samba-ad-pki.yml"
    assert playbook.is_file(), "manual S3 playbook missing"
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"samba_ad_hosts": {"hosts": {"test-ca": {"ansible_connection": "local"}}}}))
    argv = ["ansible-playbook", "-i", str(inventory), str(playbook), "--check", "--tags", "samba_ad_pki"]
    if case == "disabled": argv += ["--limit", "test-ca"]
    if case == "broad_limit": argv += ["--limit", "all"]
    if case == "extra_tag": argv += ["--limit", "test-ca", "--tags", "samba_ad_pki,all"]
    if case != "disabled": argv += ["-e", '{"samba_ad_pki_enabled":true}']
    env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_NOCOLOR="1")
    result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=25)
    assert (result.returncode == 0) == (case == "disabled"), result.stdout + result.stderr
    assert "changed=0" in result.stdout
    assert "Read the target" not in result.stdout  # Guard/end_role precede every transport.
