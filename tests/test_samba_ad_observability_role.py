"""The manual gate must stop before any target transport or mutation."""
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('case', ['disabled', 'missing_limit', 'broad_limit', 'extra_tag'])
def test_observability_guard_precedes_transport(tmp_path, case):
    inventory = tmp_path / 'inventory.json'
    inventory.write_text(json.dumps({'samba_ad_hosts': {'hosts': {'test-ad': {'ansible_connection': 'local'}}}}))
    argv = ['ansible-playbook', '-i', str(inventory), 'playbooks/samba-ad-observability.yml',
            '--check', '--tags', 'samba_ad_observability']
    if case == 'disabled': argv += ['--limit', 'test-ad']
    if case == 'broad_limit': argv += ['--limit', 'all']
    if case == 'extra_tag': argv += ['--limit', 'test-ad', '--tags', 'samba_ad_observability,all']
    if case != 'disabled': argv += ['-e', '{"samba_ad_observability_enabled":true}']
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30,
                            env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / 'local'), ANSIBLE_NOCOLOR='1'))
    assert (result.returncode == 0) == (case == 'disabled'), result.stdout + result.stderr
    assert 'changed=0' in result.stdout
    assert 'Verify identity and owned paths before writing anything' not in result.stdout
