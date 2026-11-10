"""Isolated loopback mTLS/WAL tests. No systemd, guests, real logs or operational keys."""
import datetime
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import socket
import secrets
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tools.samba_ad import telemetry_gateway as gateway
from tools.samba_ad import telemetry_spool as spool


def certificates(root):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic S7 test CA')])
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
          .not_valid_after(now + datetime.timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
          .sign(ca_key, hashes.SHA256()))
    (root / 'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for name, san, eku in [('server', 'localhost', ExtendedKeyUsageOID.SERVER_AUTH),
                           ('client', 'dc01.example.test', ExtendedKeyUsageOID.CLIENT_AUTH),
                           ('foreign', 'foreign.example.test', ExtendedKeyUsageOID.CLIENT_AUTH)]:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san)]))
                .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), False)
                .add_extension(x509.ExtendedKeyUsage([eku]), False).sign(ca_key, hashes.SHA256()))
        (root / (name + '.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        path = root / (name + '.key')
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
        path.chmod(0o600)


class Backend(BaseHTTPRequestHandler):
    def log_message(self, *_args): pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        self.server.attempts.append((self.path, self.headers.get('X-Scope-OrgID'), body))
        if self.server.available: self.server.accepted.append(body)
        self.send_response(204 if self.server.available else 503)
        self.send_header('Content-Length', '0'); self.end_headers()


class Native(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='s7-native-test-')
        self.root = Path(self.tmp.name); certificates(self.root)
        self.backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        self.backend.available = True
        self.backend.attempts = []; self.backend.accepted = []
        threading.Thread(target=self.backend.serve_forever, daemon=True).start()
        self.port_patch = patch.dict(gateway.PORTS, {'loki': self.backend.server_port, 'prometheus': self.backend.server_port})
        self.port_patch.start()
        context = gateway.context(dict(ca_file=str(self.root / 'ca.pem'), cert_file=str(self.root / 'server.pem'),
                                       key_file=str(self.root / 'server.key')))
        self.server = gateway.Server(('127.0.0.1', 0), context, ['dc01.example.test'])
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close()
        self.backend.shutdown(); self.backend.server_close()
        self.port_patch.stop(); self.tmp.cleanup()

    def request(self, client='client', path='/loki/api/v1/push'):
        context = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        if client: context.load_cert_chain(str(self.root / (client + '.pem')), str(self.root / (client + '.key')))
        connection = http.client.HTTPSConnection('localhost', self.server.server_port, context=context, timeout=5)
        try:
            connection.request('POST', path, b'{}', {'Content-Type': 'application/json', 'X-Scope-OrgID': 'foreign'})
            response = connection.getresponse()
            return response.status, response.read()
        finally: connection.close()

    def test_native_mtls_scope_routes_outage_and_client_readback(self):
        readback = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        readback.minimum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=5) as raw:
            with readback.wrap_socket(raw, server_hostname='localhost') as peer:
                cert = x509.load_pem_x509_certificate((self.root / 'server.pem').read_bytes())
                import hashlib
                self.assertEqual(hashlib.sha256(peer.getpeercert(binary_form=True)).digest(), cert.fingerprint(hashes.SHA256()))
        with self.assertRaises((ssl.SSLError, ConnectionError, http.client.RemoteDisconnected)):
            self.request(client=None)
        self.assertEqual(self.request(client='foreign')[0], 403)
        self.assertEqual(self.request(path='/admin')[0], 404)
        self.assertEqual(self.request(path='/identity'), (200, b'{"certificate_sha256": null}'))
        self.backend.available = False
        self.assertEqual(self.request()[0], 503)
        self.assertEqual(self.backend.accepted, [])
        self.backend.available = True
        self.assertEqual(self.request()[0], 204)
        self.assertEqual(self.request(path='/identity'), (200, b'{"certificate_sha256": null}'))
        self.assertEqual(self.request(path='/api/v1/write')[0], 204)
        result = json.loads(self.request(path='/identity')[1])
        cert = x509.load_pem_x509_certificate((self.root / 'client.pem').read_bytes())
        self.assertEqual(result, {'certificate_sha256': cert.fingerprint(hashes.SHA256()).hex()})
        self.assertTrue(all(row[1] == 'samba-ad' for row in self.backend.attempts))

    @unittest.skipUnless(os.environ.get('S7_ALLOY'), 'Set S7_ALLOY to the verified official 1.18.1 binary')
    def test_native_alloy_durable_queue_survives_outage_and_restart_without_source(self):
        import jinja2
        root = self.root
        source = Path(__file__).resolve().parents[1] / 'roles/samba_ad_observability/templates/agent.alloy.j2'
        environment = jinja2.Environment(); environment.filters['to_json'] = json.dumps
        config = dict(platform='linux', pki_active=str(root / 'active.json'), node='synthetic_dc',
                      endpoint='https://localhost:' + str(self.server.server_port), server_name='localhost',
                      log_files={}, canary_file=str(root / 'events.log'), token_file=str(root / 'token'))
        token = secrets.token_hex(32); (root / 'token').write_text(token)
        queue = spool.Queue(root / 'queue')
        local = spool.Server(0, queue, token)
        threading.Thread(target=local.serve_forever, daemon=True).start()
        stop = threading.Event()
        worker = threading.Thread(target=spool.forward, args=(queue, config, stop), daemon=True); worker.start()
        references = {key: str(root / file) for key, file in [('ca_file', 'ca.pem'), ('cert_file', 'client.pem'), ('key_file', 'client.key')]}
        (root / 'active.json').write_text(json.dumps(references))
        # Production Loki writer block verbatim; fixture source only, no host journal/exporter.
        rendered = environment.from_string(source.read_text()).render(samba_ad_observability_parameters=config)
        writer = rendered.split('prometheus.remote_write "ad"')[0]
        writer = writer.replace('127.0.0.1:19105', '127.0.0.1:' + str(local.server_port))
        writer += '\nloki.source.file "fixture" {\n targets = [{__path__ = ' + json.dumps(str(root / 'events.log')) + ', source = "synthetic"}]\n forward_to = [loki.write.ad.receiver]\n}\n'
        (root / 'test.alloy').write_text(writer)
        (root / 'events.log').write_text('S7-SYNTHETIC-LOSS-RECOVERY-RECEIPT\n')
        self.backend.available = False
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0)); listen_port = reservation.getsockname()[1]
        command = [os.environ['S7_ALLOY'], 'run', '--stability.level=experimental', '--server.http.listen-addr=127.0.0.1:' + str(listen_port),
                   '--storage.path=' + str(root / 'wal'), str(root / 'test.alloy')]
        def until(predicate, seconds=45):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if predicate(): return
                if process.poll() is not None: self.fail((root / 'alloy.log').read_text()[-1800:])
                time.sleep(.2)
            self.fail('bounded native wait expired: ' + (root / 'alloy.log').read_text()[-1800:])
        with (root / 'alloy.log').open('wb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=log)
            try:
                until(lambda: bool(self.backend.attempts))
                self.assertEqual(self.backend.accepted, [])
                original = [row[2] for row in self.backend.attempts]
                # Remove the source: recovery must come from the committed queue, never rereading input.
                (root / 'events.log').unlink()
                time.sleep(2)
                process.kill(); process.wait(timeout=10)
                stop.set(); worker.join(timeout=25)
                self.assertFalse(worker.is_alive())
                # Reopen SQLite from disk, as a restarted worker does; no in-memory batch is reused.
                reopened = spool.Queue(root / 'queue')
                self.assertIsNotNone(reopened.first())
                stop = threading.Event()
                worker = threading.Thread(target=spool.forward, args=(reopened, config, stop), daemon=True); worker.start()
                process = subprocess.Popen(command, stdout=log, stderr=log)
                self.backend.available = True
                until(lambda: any(body in original for body in self.backend.accepted))
                # Exact encoded batch replayed after ungraceful restart, at-least-once semantics.
                self.assertTrue(any(body in original for body in self.backend.accepted))
            finally:
                if process.poll() is None: process.kill(); process.wait(timeout=10)
                stop.set(); worker.join(timeout=25)
                local.shutdown(); local.server_close()


if __name__ == '__main__': unittest.main()
