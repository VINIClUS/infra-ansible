"""S7 adapter for the existing S3 generation transaction; Linux only."""
import http.client
import json
from pathlib import Path
import ssl
import time
from urllib.parse import urlsplit

from tools.samba_ad.pki import require
from tools.samba_ad.pki_files import secure_file


def configuration(request):
    if request['profile'] == 'observability_gateway':
        c = json.loads(secure_file('/etc/samba-ad-observability/gateway.json', secret=True).read_bytes())
        require(c['schema'] == 'samba-ad-observability/v1' and c['mode'] == 'collector')
        require(c['machine_id'] == request['target']['machine_id'] and c['server_name'] == request['target']['fqdn'])
        require(c['pki_active'] == '/var/lib/samba-ad-pki/observability_gateway/active.conf')
        return c
    c = json.loads(secure_file('/etc/samba-ad-observability/agent.json', secret=True).read_bytes())
    require(c['schema'] == 'samba-ad-observability/v1' and c['mode'] == 'agent' and c['platform'] == 'linux')
    require(c['machine_id'] == request['target']['machine_id'])
    require(c['telemetry_profile'] == request['profile'])
    require(c['pki_active'] == '/var/lib/samba-ad-pki/' + request['profile'] + '/active.conf')
    endpoint = urlsplit(c['endpoint'])
    require(endpoint.scheme == 'https' and endpoint.hostname == c['server_name'] and endpoint.port in [None, 443])
    require(not endpoint.username and not endpoint.password and not endpoint.path and not endpoint.query and not endpoint.fragment)
    return c


def observe(request, expected):
    c = configuration(request)
    active = Path(c['pki_active'])
    require(active.is_symlink())
    generation = active.resolve().parent
    require(generation.parent == Path('/var/lib/samba-ad-pki', request['profile'], 'generations'))
    references = json.loads(secure_file(active.resolve(), secret=True).read_bytes())
    require(references == {'cert_file': str(generation / 'fullchain.pem'),
                           'key_file': str(generation / 'key.pem'), 'ca_file': request['trust']['root_file']})
    context = ssl.create_default_context(cafile=request['trust']['root_file'])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(references['cert_file'], references['key_file'])
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        connection = http.client.HTTPSConnection(c['server_name'], 443, context=context, timeout=5)
        try:
            connection.request('POST', '/identity', body=b'{}', headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            if response.status == 200:
                data = json.loads(response.read(1024))
                if data == {'certificate_sha256': expected}: return expected
        except Exception:
            pass
        finally:
            connection.close()
        time.sleep(2)
    raise ValueError('S7 client certificate not observed on both telemetry write paths')
