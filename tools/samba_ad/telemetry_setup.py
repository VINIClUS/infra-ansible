"""Manual source deployment guards. No package install or secret material transfer."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import secrets
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

VERSIONS = {'alloy': '1.18.1', 'prometheus': '3.8.0', 'promtool': '3.8.0', 'loki': '3.6.0'}
ROOTS = ['/etc/samba-ad-observability', '/opt/samba-ad-observability', '/var/lib/samba-ad-observability']


def require(value):
    if not value: raise ValueError('S7 precondition failed; input values suppressed')


def name(value):
    require(isinstance(value, str) and re.fullmatch('[a-z][a-z0-9_]{0,47}', value))


def dns(value):
    require(isinstance(value, str) and len(value) <= 253 and '.' in value)
    require(all(re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')))


def validate(payload):
    require(set(payload) == {'config', 'assets'})
    c, assets = payload['config'], payload['assets']
    require(c['schema'] == 'samba-ad-observability/v1')
    require(c['mode'] in ['agent', 'collector'])
    base = {'schema', 'mode', 'machine_id'}
    agent = {'platform', 'node', 'server_name', 'endpoint', 'telemetry_profile', 'pki_active',
             'canary_file', 'sysvol_consumer', 'drs_neighbours', 'sid', 'pki_profiles', 'log_files',
             'samba_json_enabled', 'samba_config_sha256', 'token_file'}
    collector = {'ca_file', 'pki_active', 'server_name', 'allowed_sans', 'expected_nodes',
                 'privileged_group_pattern', 'policy_dn_pattern', 'bind_address'}
    require(set(c) == base | (agent if c['mode'] == 'agent' else collector))
    require(re.fullmatch('[0-9a-f]{32}', c['machine_id']))
    for key in (['ca_file'] if c['mode'] == 'collector' else []):
        require(isinstance(c[key], str) and c[key].startswith(('/var/lib/samba-ad-pki/', '/etc/samba-ad-pki/'))
                and '..' not in Path(c[key]).parts and '\n' not in c[key])
    if c['mode'] == 'agent':
        require(c['platform'] == 'linux')
        name(c['node']); dns(c['server_name'])
        name(c['telemetry_profile'])
        require(c['telemetry_profile'].startswith('telemetry_'))
        require(c['pki_active'] == '/var/lib/samba-ad-pki/' + c['telemetry_profile'] + '/active.conf')
        require(c['token_file'] == '/var/lib/samba-ad-observability/token')
        endpoint = urlsplit(c['endpoint'])
        require(endpoint.scheme == 'https' and endpoint.hostname == c['server_name'])
        require(endpoint.port in (443, None) and endpoint.path in ('', '/')
                and not endpoint.username and not endpoint.password and not endpoint.query and not endpoint.fragment)
        require(not c['endpoint'].endswith('/'))
        require(c['canary_file'] == '/var/lib/samba-ad-observability/canary.log')
        require(type(c['sysvol_consumer']) is bool and isinstance(c['drs_neighbours'], list))
        require(re.fullmatch('S-1-5-21-[0-9]+-[0-9]+-[0-9]+', c['sid']))
        require(c['pki_profiles'] and len(c['pki_profiles']) == len(set(c['pki_profiles'])))
        for profile in c['pki_profiles']: name(profile)
        require(set(c['log_files']) >= {'audit'})
        require(type(c['samba_json_enabled']) is bool)
        if c['samba_json_enabled']:
            require(c['log_files'].get('samba_json') == '/var/log/samba/ad-audit.json')
            require(re.fullmatch('[0-9a-f]{64}', c['samba_config_sha256']))
        for source, path in c['log_files'].items():
            name(source)
            require(path.startswith('/var/log/') and not any(x in path for x in ['..', '*', '\n']))
        for row in c['drs_neighbours']:
            require(set(row) == {'nc', 'peer'} and all(isinstance(v, str) and v for v in row.values()))
        require(set(assets) == {'alloy'})
    else:
        dns(c['server_name'])
        require(c['pki_active'] == '/var/lib/samba-ad-pki/observability_gateway/active.conf')
        require(set(assets) == {'prometheus', 'promtool', 'loki'})
        require(c['allowed_sans'] and len(c['allowed_sans']) == len(set(c['allowed_sans'])))
        for san in c['allowed_sans']: dns(san)
        require(c['expected_nodes'] and len({x['name'] for x in c['expected_nodes']}) == len(c['expected_nodes']))
        for node in c['expected_nodes']:
            name(node['name']); require(node['sources'])
            for source in node['sources']: name(source)
        for field in ['privileged_group_pattern', 'policy_dn_pattern']:
            require(isinstance(c[field], str) and 1 < len(c[field]) < 4096)
            re.compile(c[field])
        import ipaddress
        address = ipaddress.ip_address(c['bind_address'])
        require(address.version == 4 and not address.is_unspecified and not address.is_multicast)
    for binary, asset in assets.items():
        require(set(asset) == {'path', 'sha256', 'version'})
        require(asset['version'] == VERSIONS[binary] and re.fullmatch('[0-9a-f]{64}', asset['sha256']))
        require(Path(asset['path']).is_absolute())
    return c


def run(argv):
    result = subprocess.run(argv, capture_output=True, timeout=45)
    require(result.returncode == 0)
    return result.stdout + result.stderr


def verify_assets(payload, remote=False):
    for binary, asset in payload['assets'].items():
        path = Path('/opt/samba-ad-observability/bin', binary) if remote else Path(asset['path'])
        require(path.is_file() and not path.is_symlink())
        with path.open('rb') as stream:
            require(hashlib.file_digest(stream, 'sha256').hexdigest() == asset['sha256'])
        if remote:
            require(VERSIONS[binary].encode() in run([str(path), '-version' if binary == 'loki' else '--version']))


def preflight(c):
    require(os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == c['machine_id'])
    marker = Path(ROOTS[0], 'owner.json')
    owned = marker.is_file() and not marker.is_symlink()
    expected = {'schema': c['schema'], 'machine_id': c['machine_id'], 'mode': c['mode']}
    if owned: require(json.loads(marker.read_text()) == expected)
    for root in ROOTS:
        path = Path(root)
        for parent in [path, *path.parents]:
            if os.path.lexists(parent):
                require(not parent.is_symlink() and parent.is_dir() and parent.stat().st_uid == 0)
                require(parent.stat().st_mode & 0o022 == 0)
        if path.exists(): require(owned)
    for path in Path('/etc/systemd/system').glob('samba-ad-observability-*'):
        require(owned and path.is_file() and not path.is_symlink() and path.stat().st_uid == 0)
    for root in ROOTS[:2]:
        if Path(root).exists():
            for path in Path(root).rglob('*'):
                require(not path.is_symlink() and path.stat().st_uid == 0 and path.stat().st_mode & 0o022 == 0)
    if not owned:
        for name in ['loki', 'prometheus']:
            require(not os.path.lexists('/var/lib/samba-ad-observability-' + name))
    for field in (['ca_file'] if c['mode'] == 'collector' else []):
        # Metadata only. Operational private keys never copied, hashed or printed.
        path = Path(c[field]); require(path.is_file())
        require(path.stat().st_uid == 0 and path.stat().st_mode & (0o077 if field == 'key_file' else 0o022) == 0)
    # Listener collision check is read-only; never reserves sockets or changes networking.
    ports = [443, 19100, 19101, 19103, 19104] if c['mode'] == 'collector' else [19102, 19105]
    if not owned:
        rows = run(['ss', '-H', '-lnt']).decode().splitlines()
        require(not any(row.split()[3].rsplit(':', 1)[-1] in {str(p) for p in ports} for row in rows))


def native(c):
    root = '/opt/samba-ad-observability/bin/'
    if c['mode'] == 'agent':
        run([root + 'alloy', 'validate', '--stability.level=experimental', '/etc/samba-ad-observability/agent.alloy'])
    else:
        run([root + 'promtool', 'check', 'config', '/etc/samba-ad-observability/prometheus.yml'])
        run([root + 'promtool', 'check', 'rules', '/etc/samba-ad-observability/prometheus-rules.yml'])
        run([root + 'loki', '-verify-config=true', '-config.file=/etc/samba-ad-observability/loki.yml'])


AUDIT_BEFORE = 'log level = 1 auth_audit:3 dsdb_audit:3'
AUDIT_AFTER = ('log level = 1 auth_audit:3 dsdb_audit:3 '
               'auth_json_audit:3@/var/log/samba/ad-audit.json '
               'dsdb_json_audit:5@/var/log/samba/ad-audit.json '
               'dsdb_group_json_audit:5@/var/log/samba/ad-audit.json '
               'dsdb_password_json_audit:5@/var/log/samba/ad-audit.json')


def audit_candidate(original, expected):
    require(hashlib.sha256(original.replace(AUDIT_AFTER.encode(), AUDIT_BEFORE.encode())).hexdigest() == expected)
    require(original.count(AUDIT_BEFORE.encode()) == 1)
    if AUDIT_AFTER.encode() in original: return original
    return original.replace(AUDIT_BEFORE.encode(), AUDIT_AFTER.encode())


def audit(c):
    require(c['mode'] == 'agent' and c['samba_json_enabled'])
    path = Path('/etc/samba/smb.conf')
    require(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0)
    require(path.stat().st_mode & 0o022 == 0)
    require(c['sid'] in run(['net', 'getdomainsid']).decode().split())
    rule = '-w /var/lib/samba/sysvol -p wa -k samba_ad_sysvol'
    rules = Path('/etc/audit/rules.d/samba-ad-observability.rules')
    require(not rules.is_symlink() and (not rules.exists() or rules.read_text() == rule + '\n'))
    active = run(['auditctl', '-l']).decode()
    require('samba_ad_sysvol' not in active or rule in active.splitlines())
    before = path.read_bytes(); after = audit_candidate(before, c['samba_config_sha256'])
    descriptor, temporary = tempfile.mkstemp(prefix='.s7-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(after); stream.flush(); os.fsync(stream.fileno())
        run(['testparm', '-s', temporary])
        require(path.read_bytes() == before)
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
        try:
            run(['smbcontrol', 'all', 'reload-config'])
        except Exception:
            path.write_bytes(before)
            run(['smbcontrol', 'all', 'reload-config'])
            raise
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    # Add one keyed rule; never flush/reload or replace another project's rules.
    if 'samba_ad_sysvol' not in active:
        run(['auditctl', '-w', '/var/lib/samba/sysvol', '-p', 'wa', '-k', 'samba_ad_sysvol'])
    require(rule in run(['auditctl', '-l']).decode().splitlines())
    if not rules.exists():
        with rules.open('x') as stream: stream.write(rule + '\n')
        rules.chmod(0o600)


def main():
    try:
        payload = json.load(sys.stdin); c = validate(payload)
        action = sys.argv[1]
        require(action in ['validate', 'preflight', 'assets', 'native', 'audit', 'token'])
        if action == 'validate': verify_assets(payload)
        if action == 'preflight': preflight(c)
        if action == 'assets': verify_assets(payload, remote=True)
        if action == 'native': native(c)
        if action == 'audit': preflight(c); audit(c)
        if action == 'token':
            require(c['mode'] == 'agent')
            token = Path(c['token_file'])
            if not token.exists():
                fd = os.open(token, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    stream.write(secrets.token_hex(32)); stream.flush(); os.fsync(stream.fileno())
            require(not token.is_symlink() and token.stat().st_uid == 0 and token.stat().st_mode & 0o077 == 0)
        print(json.dumps({'state': 'validated', 'changed': False}))
    except Exception:
        print('S7 precondition failed; values suppressed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
