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


def test_invalid_controller_payload_cannot_reach_target_transport(tmp_path):
    from test_samba_ad_pki_contract import request
    r, manifest = request()
    r["root_key"] = "TEST-SENTINEL-DO-NOT-TRANSFER"
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"samba_ad_hosts": {"hosts": {"test-ca": {"ansible_connection": "local"}}}}))
    variables = tmp_path / "vars.json"
    variables.write_text(json.dumps({"samba_ad_pki_enabled": True, "samba_ad_pki_request": r,
                                     "samba_ad_pki_manifest": manifest}))
    result = subprocess.run(["ansible-playbook", "-i", str(inventory), "playbooks/samba-ad-pki.yml",
                             "--check", "--limit", "test-ca", "--tags", "samba_ad_pki", "-e", "@" + str(variables)],
                            cwd=ROOT, capture_output=True, text=True, timeout=30,
                            env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_NOCOLOR="1"))
    assert result.returncode != 0
    assert "Validate and select the reference-only payload on the controller" in result.stdout
    assert "Read the target" not in result.stdout
    assert "TEST-SENTINEL" not in result.stdout + result.stderr


def test_bootstrap_loader_executes_the_pure_ca_renderer():
    import jinja2
    from test_samba_ad_pki_ca_config import request
    template = ROOT / "roles/samba_ad_pki/templates/bootstrap.py.j2"
    env = jinja2.Environment()
    env.filters["to_json"] = json.dumps
    code = env.from_string(template.read_text()).render(
        role_path=str(template.parent.parent), samba_ad_pki_operation="ca_render",
        lookup=lambda kind, path: Path(path).read_text())
    result = subprocess.run(["python3", "-B", "-c", code, "--check"], input=json.dumps({"ca_request": request()}),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(json.loads(result.stdout)["/etc/samba-ad-pki/ca.json"])["address"] == "127.0.0.1:9443"
