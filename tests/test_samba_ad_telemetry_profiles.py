"""Optional CA grants cannot widen or replace the six existing identities."""
import base64
import copy
import hashlib
import json

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
