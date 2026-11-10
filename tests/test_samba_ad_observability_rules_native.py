"""Native AD rule evaluation against synthetic inputs, no external notifications."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.parse
import urllib.request

import jinja2
import pytest
import yaml

TEMPLATES = Path(__file__).resolve().parents[1] / 'roles/samba_ad_observability/templates'


def render(name):
    environment = jinja2.Environment()
    environment.filters['to_json'] = json.dumps
    return environment.from_string((TEMPLATES / name).read_text()).render(samba_ad_observability_parameters={
        'expected_nodes': [{'name': 'dc02', 'sources': ['sysvol', 'pki_telemetry_dc02']}],
        'privileged_group_pattern': 'CN=Domain Admins,.*', 'policy_dn_pattern': '.*CN=Policies,.*'})


@pytest.mark.skipif(not os.environ.get('S7_ALLOY'), reason='Verified native Alloy required')
def test_native_full_linux_alloy_configuration(tmp_path):
    token = tmp_path / 'token'; token.write_text('a' * 64)
    environment = jinja2.Environment(); environment.filters['to_json'] = json.dumps
    config = environment.from_string((TEMPLATES / 'agent.alloy.j2').read_text()).render(samba_ad_observability_parameters={
        'platform': 'linux', 'node': 'dc02', 'token_file': str(token),
        'log_files': {'samba_json': '/var/log/samba/ad-audit.json', 'audit': '/var/log/audit/audit.log'},
        'canary_file': '/var/lib/samba-ad-observability/canary.log'})
    cfg = tmp_path / 'agent.alloy'; cfg.write_text(config)
    result = subprocess.run([os.environ['S7_ALLOY'], 'validate', '--stability.level=experimental', str(cfg)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(not os.environ.get('S7_PROMTOOL'), reason='Verified native promtool required')
def test_native_prometheus_rule_failure_absence_and_certificate_deadlines(tmp_path):
    rules = tmp_path / 'rules.yml'; rules.write_text(render('prometheus-rules.yml.j2'))
    expected = yaml.safe_load(rules.read_text())['groups'][0]['rules']
    cases = [('SambaADSourceFailed', 'samba_ad_source_up', '0x10', {'source': 'sysvol'}),
             ('SambaADStateUnhealthy', 'samba_ad_healthy', '0x10', {'source': 'drs'}),
             ('SambaADCertificateExpiry', 'samba_ad_expires_seconds', '1000x10', {'source': 'pki'}),
             ('SambaADCertificateRotationOverdue', 'samba_ad_rotate_by_seconds', '0x10', {'source': 'pki'}),
             ('SambaADQueueBacklog', 'samba_ad_queue_oldest_age_seconds', '400x10', {'source': 'spool'})]
    tests = []
    for alert, metric, values, extra in cases:
        labels = {'project': 'samba-ad', 'node': 'dc02'} | extra
        rule = next(r for r in expected if r['alert'] == alert)
        series = metric + '{' + ','.join(k + '=' + json.dumps(v) for k, v in labels.items()) + '}'
        tests.append({'interval': '1m', 'input_series': [{'series': series, 'values': values}],
            'alert_rule_test': [{'eval_time': '7m', 'alertname': alert, 'exp_alerts': [{
                'exp_labels': labels | rule['labels'], 'exp_annotations': rule['annotations']}]}]})
    rule = next(r for r in expected if r['alert'] == 'SambaADCollectorMissing_dc02')
    tests.append({'interval': '1m', 'input_series': [], 'alert_rule_test': [{
        'eval_time': '7m', 'alertname': rule['alert'], 'exp_alerts': [{
            'exp_labels': rule['labels'], 'exp_annotations': rule['annotations']}]}]})
    test = tmp_path / 'test.yml'
    test.write_text(yaml.safe_dump({'rule_files': [str(rules)], 'evaluation_interval': '1m', 'tests': tests}))
    result = subprocess.run([os.environ['S7_PROMTOOL'], 'test', 'rules', str(test)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(not os.environ.get('S7_LOKI'), reason='Verified native Loki required')
def test_native_loki_audit_rule_expressions(tmp_path):
    def port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]
    http_port, grpc_port = port(), port()
    config = yaml.safe_load(render('loki.yml.j2'))
    config['server'].update(http_listen_port=http_port, grpc_listen_port=grpc_port)
    config['common']['path_prefix'] = str(tmp_path / 'data')
    config['common']['storage']['filesystem'] = {'chunks_directory': str(tmp_path / 'chunks'),
                                                 'rules_directory': str(tmp_path / 'rules')}
    config['common']['ring']['instance_addr'] = '127.0.0.1'
    config['compactor']['working_directory'] = str(tmp_path / 'compactor')
    config['ruler']['storage']['local']['directory'] = str(tmp_path / 'rules')
    config['ruler']['rule_path'] = str(tmp_path / 'ruler-tmp')
    (tmp_path / 'rules/samba-ad').mkdir(parents=True)
    rules = render('loki-rules.yml.j2')
    (tmp_path / 'rules/samba-ad/audit.yml').write_text(rules)
    cfg = tmp_path / 'loki.yml'; cfg.write_text(yaml.safe_dump(config))
    endpoint = 'http://127.0.0.1:' + str(http_port)
    def request(path, data=None):
        req = urllib.request.Request(endpoint + path, data=data,
            headers={'X-Scope-OrgID': 'samba-ad', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=3) as response: return response.read()
    with (tmp_path / 'loki.log').open('wb') as log:
        process = subprocess.Popen([os.environ['S7_LOKI'], '-config.file=' + str(cfg)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 40
            while True:
                try: request('/ready'); break
                except Exception:
                    assert time.monotonic() < deadline and process.poll() is None, (tmp_path / 'loki.log').read_text()[-4000:]
                    time.sleep(.2)
            payloads = [('samba_json', {'type': 'groupChange', 'groupChange': {'group': 'CN=Domain Admins,DC=example,DC=test'}}),
                        ('samba_json', {'type': 'dsdbChange', 'dsdbChange': {'dn': 'CN=X,CN=Policies,DC=example,DC=test'}}),
                        ('audit', 'type=SYSCALL key="samba_ad_sysvol"'),
                        ('windows_event', {'event_id': 4728}), ('samba_json', 'malformed audit')]
            streams = []
            for index, (source, event) in enumerate(payloads):
                labels = {'project': 'samba-ad', 'node': 'dc02', 'source': source}
                if source == 'windows_event': labels['channel'] = 'Security'
                streams.append({'stream': labels, 'values': [[str(time.time_ns() - 1000000000 + index),
                    event if isinstance(event, str) else json.dumps(event)]]})
            request('/loki/api/v1/push', json.dumps({'streams': streams}).encode())
            for rule in yaml.safe_load(rules)['groups'][0]['rules']:
                if rule['alert'].startswith('SambaADLogHeartbeatMissing'): continue
                query = '/loki/api/v1/query?' + urllib.parse.urlencode({'query': rule['expr']})
                result = json.loads(request(query))
                assert result['status'] == 'success' and result['data']['result'], (rule['alert'], result)
                assert any(float(row['value'][1]) > 0 for row in result['data']['result']), rule['alert']
        finally:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
