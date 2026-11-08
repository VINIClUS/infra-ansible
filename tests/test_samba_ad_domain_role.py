"""Run the real disabled role and controller loader without target probes."""
import json
import os
from pathlib import Path
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize("case", ["disabled", "missing_limit", "broad_limit", "extra_tag", "root"])
def test_manual_guards_precede_transport(tmp_path, case):
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"samba_ad_hosts": {"hosts": {"test-dc": {"ansible_connection": "local", "ansible_user": "root" if case == "root" else "ansible"}}}}))
    argv = ["ansible-playbook", "-i", str(inventory), "playbooks/samba-ad-domain.yml", "--check", "--tags", "samba_ad_domain"]
    if case in ["disabled", "extra_tag", "root"]: argv += ["--limit", "test-dc"]
    if case == "broad_limit": argv += ["--limit", "all"]
    if case == "extra_tag": argv += ["--tags", "samba_ad_domain,all"]
    if case != "disabled": argv += ["-e", '{"samba_ad_domain_enabled":true}']
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30,
                            env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_NOCOLOR="1"))
    assert (result.returncode == 0) == (case == "disabled"), result.stdout + result.stderr
    assert "changed=0" in result.stdout
    assert "Read target preconditions" not in result.stdout


def test_memory_loader_rejects_secret_payload_without_echoing():
    import jinja2
    import base64, zlib
    template = ROOT / "roles/samba_ad_domain/templates/bootstrap.py.j2"
    env = jinja2.Environment(); env.filters["to_json"] = json.dumps
    env.filters["samba_ad_domain_pack_sources"] = lambda sources: base64.b64encode(zlib.compress(json.dumps(sources).encode(), 9)).decode()
    code = env.from_string(template.read_text()).render(role_path=str(template.parent.parent), lookup=lambda _, p: Path(p).read_text())
    for mode in ["--check", "--validate"]:
        result = subprocess.run(["python3", "-B", "-c", code, mode], input=json.dumps({"schema": "samba-ad-domain-wire/v1", "request": {"adminpass": "SENTINEL_PASSWORD"}, "manifest": {}}), capture_output=True, text=True, timeout=10)
        assert result.returncode != 0
        assert "SENTINEL" not in result.stdout + result.stderr
        assert "Traceback" not in result.stderr


def test_real_ansible_loader_validates_before_pve_or_dc_transport(tmp_path):
    from test_samba_ad_domain import request
    r, manifest = request(); r["adminpass"] = "SENTINEL_MUST_NOT_TRANSFER"
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"samba_ad_hosts": {"hosts": {"test-dc": {"ansible_connection": "local", "ansible_user": "ansible"}}}, "pve": {"hosts": {"node-a": {"ansible_connection": "local"}}}}))
    variables = tmp_path / "vars.json"
    variables.write_text(json.dumps({"samba_ad_domain_enabled": True, "samba_ad_domain_request": r, "samba_ad_domain_manifest": manifest}))
    result = subprocess.run(["ansible-playbook", "-i", str(inventory), "playbooks/samba-ad-domain.yml", "--check", "--limit", "test-dc", "--tags", "samba_ad_domain", "-e", "@" + str(variables)], cwd=ROOT, capture_output=True, text=True, timeout=30,
                            env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_NOCOLOR="1"))
    assert result.returncode != 0
    assert "Validate closed declarations on the controller" in result.stdout
    assert "Revalidate the canonical S1" not in result.stdout
    assert "Read target preconditions" not in result.stdout
    assert "SENTINEL" not in result.stdout + result.stderr
    assert "changed=0" in result.stdout
