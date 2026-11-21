"""Host-local, read-only AD signals. Never exports DNs, SIDs, log text or secrets."""
import datetime
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import sqlite3
import tempfile
import fcntl
import time


def require(condition):
    if not condition:
        raise ValueError('invalid telemetry input')


def number(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0)
    return value


def fresh(value, now, maximum):
    return 0 <= now - number(value) <= maximum


def sysvol(data, now, sid):
    require(isinstance(data, dict))
    require(set(('state', 'failures', 'last_success', 'last_attempt', 'sid', 'baseline', 'retention')) <= data.keys())
    require(isinstance(data['baseline'], dict) and data['baseline'])
    require(type(data['failures']) is int)
    retention = data['retention']
    require(set(retention) == {'count', 'limit', 'saturated'})
    require(type(retention['count']) is int and type(retention['limit']) is int)
    require(retention['limit'] > 0 and retention['count'] >= 0 and type(retention['saturated']) is bool)
    require(retention['saturated'] == (retention['count'] >= retention['limit']))
    healthy = (data['state'] == 'ok' and data['sid'] == sid and number(data['failures']) == 0
               and fresh(data['last_success'], now, 600) and fresh(data['last_attempt'], now, 600))
    return dict(healthy=int(healthy), last_success_seconds=data['last_success'],
                retention_saturated=int(retention['saturated']))


def pki(text, profile, now):
    require(re.fullmatch(r'[a-z0-9_]+', profile))
    parsed = {}
    for line in text.splitlines():
        match = re.fullmatch(r'samba_ad_pki_([a-z_]+)\{profile="' + profile + r'"\} ([0-9]+(?:\.[0-9]+)?)', line)
        require(match is not None and match[1] not in parsed)
        parsed[match[1]] = number(float(match[2]))
    required = {'last_check_seconds', 'last_attempt_success', 'certificate_not_after_seconds',
                'rotation_deadline_seconds'}
    require(required <= parsed.keys())
    require(parsed['last_attempt_success'] in (0, 1))
    require(parsed['rotation_deadline_seconds'] < parsed['certificate_not_after_seconds'])
    if 'last_rotation_success_seconds' in parsed:
        require(parsed['last_rotation_success_seconds'] <= now)
    return dict(healthy=int(fresh(parsed['last_check_seconds'], now, 2400)
                            and parsed['last_attempt_success'] == 1),
                expires_seconds=parsed['certificate_not_after_seconds'],
                rotate_by_seconds=parsed['rotation_deadline_seconds'],
                last_check_seconds=parsed['last_check_seconds'])


def drs(data, expected, now):
    require(isinstance(data['repsFrom'], list) and expected)
    wanted = {(item['nc'].lower(), item['peer'].lower()) for item in expected}
    seen = set()
    healthy = True
    for row in data['repsFrom']:
        key = (row['NC dn'].lower(), row['NTDS DN'].lower())
        if key not in wanted:
            continue
        require(key not in seen and type(row['is deleted']) is bool)
        seen.add(key)
        stamp = datetime.datetime.strptime(row['last success'], '%a %b %d %H:%M:%S %Y %Z')
        success = stamp.replace(tzinfo=datetime.timezone.utc).timestamp()
        healthy &= (not row['is deleted'] and number(row['consecutive failures']) == 0
                    and row['last attempt message'] == 'WERR_OK' and fresh(success, now, 900))
    return {'healthy': int(healthy and seen == wanted)}


def measure(source, collector, now):
    require(re.fullmatch(r'[a-z0-9_]+', source))
    prefix = f'samba_ad_source_up{{source="{source}"}} '
    try:
        values = collector()
        require(values and all(re.fullmatch(r'[a-z0-9_]+', name) for name in values))
        for value in values.values(): number(value)
        lines = [prefix + '1']
        lines += [f'samba_ad_{key}{{source="{source}"}} {value}' for key, value in values.items()]
    except Exception:
        lines = [prefix + '0']
    return '\n'.join(lines) + f'\nsamba_ad_source_observed_seconds{{source="{source}"}} {now}\n'


def command(argv):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, timeout=30, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(len(result.stdout) < 8 * 1024 * 1024)
    return result.stdout.decode()


def timer(unit):
    require(re.fullmatch(r'samba-ad-[a-z0-9_-]+\.timer', unit))
    active = command(['systemctl', 'is-active', unit]).strip() == 'active'
    enabled = command(['systemctl', 'is-enabled', unit]).strip() == 'enabled'
    return {'healthy': int(active and enabled)}


def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size < 8 * 1024 * 1024)
    return path.read_text()


def collect(config, now):
    lines = []
    def queue_status():
        with sqlite3.connect('file:/var/lib/samba-ad-observability/spool/queue.sqlite3?mode=ro', uri=True) as connection:
            values = dict(connection.execute('SELECT key,value FROM state'))
            oldest = connection.execute('SELECT MIN(at) FROM batches').fetchone()[0]
        return dict(healthy=int(fresh(values['heartbeat'], now, 120)), queue_bytes=number(values['bytes']),
                    queue_rejected_total=number(values['rejected']), queue_delivered_total=number(values['delivered']),
                    queue_oldest_age_seconds=now-number(oldest) if oldest is not None else 0)
    lines.append(measure('spool', queue_status, now))
    for profile in config['pki_profiles']:
        lines.append(measure('pki_' + profile, lambda: pki(
            read('/var/lib/samba-ad-pki/' + profile + '/status.prom'), profile, now), now))
        lines.append(measure('timer_' + profile, lambda: timer('samba-ad-pki-' + profile + '.timer'), now))
    if config['sysvol_consumer']:
        def inspect_sysvol():
            result = sysvol(json.loads(read('/var/lib/samba-ad-sysvol/status.json')), now, config['sid'])
            partial = any(os.path.lexists(path) for path in ['/var/lib/samba-ad-sysvol/partial.json',
                          '/var/lib/samba-ad-replica/revoked.json', '/var/lib/samba-ad-replica/watch-status.json'])
            result['healthy'] &= int(not partial)
            return result
        lines.append(measure('sysvol', inspect_sysvol, now))
        lines.append(measure('timer_sysvol', lambda: timer('samba-ad-sysvol.timer'), now))
    if config['drs_neighbours']:
        lines.append(measure('drs', lambda: drs(json.loads(command(
            ['samba-tool', 'drs', 'showrepl', '--json', '-P'])), config['drs_neighbours'], now), now))
    for source, path in config['log_files'].items():
        def inspect_file():
            require(Path(path).is_file() and not Path(path).is_symlink())
            with open(path, 'rb') as stream:
                stream.read(1)
            return {'readable': 1}
        lines.append(measure('log_' + source, inspect_file, now))
    lines.append(measure('journal', lambda: {'readable': int(bool(command(
        ['journalctl', '--no-pager', '-n', '1', '-o', 'json'])))}, now))
    lines.append(f'samba_ad_exporter_last_run_seconds {now}\n')
    return ''.join(lines)


def atomic(path, text):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def main():
    os.umask(0o077)
    try:
        config = json.loads(read('/etc/samba-ad-observability/agent.json'))
        require(Path('/etc/machine-id').read_text().strip() == config['machine_id'])
        now = int(time.time())
        atomic('/var/lib/samba-ad-observability/textfile/ad.prom', collect(config, now))
        with open('/var/lib/samba-ad-observability/canary.log', 'a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            stream.write(json.dumps({'kind': 'samba_ad_canary', 'at': now}) + '\n')
            stream.flush(); os.fsync(stream.fileno())
        return 0
    except Exception:
        print('AD telemetry collection failed; inspect protected local inputs', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
