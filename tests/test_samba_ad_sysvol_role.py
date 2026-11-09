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
    argv = ["ansible-playbook", "-i", str(inventory), "playbooks/samba-ad-sysvol.yml", "--check", "--tags", "samba_ad_sysvol"]
    if case in ["disabled", "extra_tag", "root"]: argv += ["--limit", "test-dc"]
    if case == "broad_limit": argv += ["--limit", "all"]
    if case == "extra_tag": argv += ["--tags", "samba_ad_sysvol,all"]
    if case != "disabled": argv += ["-e", '{"samba_ad_sysvol_enabled":true}']
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30,
                            env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_NOCOLOR="1"))
    assert (result.returncode == 0) == (case == "disabled"), result.stdout + result.stderr
    assert "changed=0" in result.stdout
    assert "Read target preconditions" not in result.stdout


def test_memory_loader_rejects_secret_payload_without_echoing():
    import jinja2
    import base64, zlib
    template = ROOT / "roles/samba_ad_sysvol/templates/bootstrap.py.j2"
    env = jinja2.Environment(); env.filters["to_json"] = json.dumps
    env.filters["samba_ad_replica_pack_sources"] = lambda sources: base64.b64encode(zlib.compress(json.dumps(sources).encode(), 9)).decode()
    code = env.from_string(template.read_text()).render(role_path=str(template.parent.parent), lookup=lambda _, p: Path(p).read_text())
    for mode in ["--check", "--validate"]:
        result = subprocess.run(["python3", "-B", "-c", code, mode], input=json.dumps({"schema": "samba-ad-sysvol-wire/v1", "request": {"adminpass": "SENTINEL_PASSWORD"}, "manifest": {}}), capture_output=True, text=True, timeout=10)
        assert result.returncode != 0
        assert "SENTINEL" not in result.stdout + result.stderr
        assert "Traceback" not in result.stderr
