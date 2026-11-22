"""Dedicated AD mTLS ingress. Only fixed local write APIs; never proxies reads."""
import http.client
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer, HTTPServer
import json
import os
from pathlib import Path
import ssl
import threading
import time

ROUTES = {'/loki/api/v1/push': ('loki', '/loki/api/v1/push'),
          '/api/v1/write': ('prometheus', '/api/v1/write')}
PORTS = {'loki': 19101, 'prometheus': 19100}
MAX_BODY = 8 * 1024 * 1024


def authorize(cert, allowed):
    names = cert.get('subjectAltName', ())
    return len(names) == 1 and names[0][0] == 'DNS' and names[0][1] in allowed


def route(path):
    if path not in ROUTES:
        raise ValueError('unsupported route')
    return ROUTES[path]


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass  # No identity, content, headers, DN or request strings in service logs.

    def reply(self, status, body=b''):
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'application/json')
        self.send_header('Connection', 'close')
        self.end_headers()
        if body: self.wfile.write(body)
        self.close_connection = True

    def do_POST(self):
        upstream = None
        try:
            if not authorize(self.connection.getpeercert(), self.server.allowed):
                self.reply(403); return
            identity = self.path == '/identity'
            if not identity: service, path = route(self.path)
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not lengths[0].isdigit() or self.headers.get('Transfer-Encoding'):
                self.reply(400); return
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY:
                self.reply(413); return
            body = self.rfile.read(length)
            if len(body) != length:
                self.reply(400); return
            san = self.connection.getpeercert()['subjectAltName'][0][1]
            if identity:
                if body != b'{}': self.reply(400); return
                with self.server.observed_lock:
                    fingerprints = self.server.observed.get(san, {})
                    value = fingerprints.get('loki') if (set(fingerprints) == {'loki', 'prometheus'}
                            and len(set(fingerprints.values())) == 1) else None
                self.reply(200, json.dumps({'certificate_sha256': value}).encode()); return
            content_type = self.headers.get('Content-Type', '')
            if content_type not in ('application/json', 'application/x-protobuf', 'application/x-protobuf;proto=io.prometheus.write.v2.Request'):
                self.reply(415); return
            headers = {'Content-Type': content_type, 'X-Scope-OrgID': 'samba-ad'}
            for name in ['Content-Encoding', 'X-Prometheus-Remote-Write-Version']:
                if name in self.headers:
                    headers[name] = self.headers[name]
            upstream = http.client.HTTPConnection('127.0.0.1', PORTS[service], timeout=20)
            upstream.request('POST', path, body=body, headers=headers)
            response = upstream.getresponse()
            # ACK only after backend commits. All backend rejections stay retryable.
            success = 200 <= response.status < 300
            if success:
                fingerprint = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
                with self.server.observed_lock:
                    self.server.observed.setdefault(san, {})[service] = fingerprint
            self.reply(204 if success else 503)
        except ValueError:
            self.reply(404)
        except Exception:
            self.reply(503)
        finally:
            if upstream is not None: upstream.close()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, context, allowed):
        super().__init__(address, Handler)
        self.context, self.allowed = context, allowed
        self.slots = threading.BoundedSemaphore(32)
        self.observed = {}
        self.observed_lock = threading.Lock()

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close(); return
        super().process_request(request, address)

    def process_request_thread(self, request, address):
        try:
            request.settimeout(30)
            # Handshake inside bounded worker, so stalled clients cannot block accept.
            request = self.context.wrap_socket(request, server_side=True)
            super().process_request_thread(request, address)
        except Exception:
            request.close()
        finally:
            self.slots.release()


def context(config):
    result = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=config['ca_file'])
    result.minimum_version = ssl.TLSVersion.TLSv1_2
    result.verify_mode = ssl.CERT_REQUIRED
    result.load_cert_chain(config['cert_file'], config['key_file'])
    return result


def main():
    os.umask(0o077)
    config = json.loads(Path('/etc/samba-ad-observability/gateway.json').read_text())
    if Path('/etc/machine-id').read_text().strip() != config['machine_id']:
        raise ValueError('AD collector identity mismatch')
    references = json.loads(Path(config['pki_active']).read_text())
    # The active reference is published by S3 only after chain/SAN/EKU/key validation.
    class Metrics(BaseHTTPRequestHandler):
        def log_message(self, *_args): pass

        def do_GET(self):
            if self.path != '/metrics': self.send_error(404); return
            import telemetry
            now = int(time.time())
            content = telemetry.measure('pki_observability_gateway', lambda: telemetry.pki(
                telemetry.read('/var/lib/samba-ad-pki/observability_gateway/status.prom'),
                'observability_gateway', now), now)
            content += telemetry.measure('timer_observability_gateway',
                lambda: telemetry.timer('samba-ad-pki-observability_gateway.timer'), now)
            body = content.encode()
            self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
            self.wfile.write(body)
    metrics = HTTPServer(('127.0.0.1', 19104), Metrics)
    threading.Thread(target=metrics.serve_forever, daemon=True).start()
    Server((config['bind_address'], 443), context(references), config['allowed_sans']).serve_forever()


if __name__ == '__main__':
    main()
