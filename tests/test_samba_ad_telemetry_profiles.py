"""Optional CA grants cannot widen or replace the six existing identities."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import zlib

import jinja2

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from test_samba_ad_pki_ca_config import request, reseal
from tools.samba_ad.pki_ca import render
from tools.samba_ad.pki_profiles import BASE, OPTIONAL, profile_names
from tools.samba_ad.contract import validate_manifest


def extended():
    result = request()
    manifest = result['guest_request']['compatibility']['data']['manifest']
    manifest['telemetry_collector'] = dict(fqdn='collector.example.invalid', address='192.0.2.99',
        mac='02:00:5e:00:53:99', kind='qemu', machine_id='c'*32, scope='samba-ad-observability-only')
    for profile in OPTIONAL:
        role = manifest['telemetry_collector'] if profile == 'observability_gateway' else manifest['resources'][profile.removeprefix('telemetry_')]
        manifest['certificate_profiles'][profile] = dict(sans=[role['fqdn']],
            eku=['serverAuth' if profile == 'observability_gateway' else 'clientAuth'], validity_hours=168, rotate_before_fraction=.66)
        key = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        encode = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
        result['registry'][profile] = dict(kty='EC', crv='P-256', x=encode(key.x.to_bytes(32, 'big')),
            y=encode(key.y.to_bytes(32, 'big')), kid=encode(hashlib.sha256(profile.encode()).digest()))
    reseal(result['guest_request'])
    return result, manifest


def test_optional_profiles_preserve_every_legacy_template_and_grant():
    original = request(); before = render(original)
    added, manifest = extended(); after = render(added)
    validate_manifest(manifest)
    for name in BASE:
        path = '/etc/samba-ad-pki/profiles/' + name + '.tpl'
        assert before[path] == after[path]
    backend = json.loads(after['/etc/samba-ad-pki/ca.json'])
    assert len(backend['authority']['provisioners']) == 9
    assert all(p['claims']['disableRenewal'] and not p['claims']['enableSSHCA'] for p in backend['authority']['provisioners'])
    assert 'RSA' not in after['/etc/samba-ad-pki/profiles/observability_gateway.tpl']  # Go's strict type is lowercase rsa.
    assert '*rsa.PublicKey' in after['/etc/samba-ad-pki/profiles/telemetry_windows_pilot.tpl']


@pytest.mark.parametrize('change', ['san', 'eku', 'credential_reuse', 'scope', 'unqualified_gateway'])
def test_new_identity_conflicts_are_rejected(change):
    data, manifest = extended()
    if change == 'san': manifest['certificate_profiles']['telemetry_windows_pilot']['sans'] = ['dc01.example.invalid']
    if change == 'eku': manifest['certificate_profiles']['telemetry_windows_pilot']['eku'] = ['serverAuth']
    if change == 'credential_reuse': data['registry']['telemetry_windows_pilot'] = copy.deepcopy(data['registry']['dc01'])
    if change == 'scope': manifest['telemetry_collector']['scope'] = 'shared-administration'
    if change == 'unqualified_gateway': del manifest['telemetry_collector']
    reseal(data['guest_request'])
    with pytest.raises(ValueError): render(data)


@pytest.mark.parametrize('role', ['samba_ad_replica', 'samba_ad_sysvol'])
def test_s5_memory_loader_includes_new_profile_dependency(role):
    root = Path(__file__).resolve().parents[1]
    template = root / 'roles' / role / 'templates/bootstrap.py.j2'
    env = jinja2.Environment(); env.filters['to_json'] = json.dumps
    env.filters['samba_ad_replica_pack_sources'] = lambda sources: base64.b64encode(
        zlib.compress(json.dumps(sources).encode(), 9)).decode()
    code = env.from_string(template.read_text()).render(role_path=str(template.parent.parent),
        lookup=lambda _, path: Path(path).read_text())
    payload = {'schema': 'samba-ad-replica-wire/v1', 'request': {
        'schema': 'samba-ad-replica/v1', 'enabled': False, 'apply': False}, 'manifest': {}}
    result = subprocess.run(['python3', '-B', '-c', code, '--check'], input=json.dumps(payload),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {'state': 'disabled', 'changed': False}
