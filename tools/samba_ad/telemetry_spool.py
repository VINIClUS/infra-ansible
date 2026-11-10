"""Authenticated host-local durable queue; ACK after fsync, remove after remote ACK.

Runs on Linux and Windows using a qualified Python runtime. No log payloads,
credentials or private key bytes are printed. TLS material stays on this host.
"""
import hashlib
from contextlib import contextmanager
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import sqlite3
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit

MAX_BODY = 8 * 1024 * 1024
MAX_QUEUE = 512 * 1024 * 1024
PATHS = {'/loki/api/v1/push', '/api/v1/write'}


class Queue:
    def __init__(self, directory, limit=MAX_QUEUE):
        self.directory, self.limit = Path(directory), limit
        self.db = self.directory / 'queue.sqlite3'
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('CREATE TABLE IF NOT EXISTS batches (id INTEGER PRIMARY KEY, at REAL, path TEXT, headers TEXT, body BLOB)')
            connection.execute('CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value REAL)')
            for key in ['bytes', 'accepted', 'delivered', 'rejected', 'last_success', 'last_attempt', 'heartbeat']:
                connection.execute('INSERT OR IGNORE INTO state VALUES (?,0)', (key,))

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.db, timeout=5)
        connection.execute('PRAGMA synchronous=FULL')
        connection.execute('PRAGMA wal_autocheckpoint=256')
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback(); raise
        finally:
            connection.close()

    def put(self, path, headers, body):
        if path not in PATHS or not 0 < len(body) <= MAX_BODY: raise ValueError('invalid batch')
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            size = connection.execute("SELECT value FROM state WHERE key='bytes'").fetchone()[0]
            if size + len(body) > self.limit:
                connection.execute("UPDATE state SET value=value+1 WHERE key='rejected'")
                return False
            connection.execute('INSERT INTO batches(at,path,headers,body) VALUES (?,?,?,?)',
                               (time.time(), path, json.dumps(headers), body))
            connection.execute("UPDATE state SET value=value+? WHERE key='bytes'", (len(body),))
            connection.execute("UPDATE state SET value=value+1 WHERE key='accepted'")
        return True

    def first(self):
        with self.connect() as connection:
            return connection.execute('SELECT id,path,headers,body FROM batches ORDER BY id LIMIT 1').fetchone()

    def attempt(self):
        with self.connect() as connection:
            connection.execute("UPDATE state SET value=? WHERE key='last_attempt'", (time.time(),))

    def tick(self):
        with self.connect() as connection:
            connection.execute("UPDATE state SET value=? WHERE key='heartbeat'", (time.time(),))

    def ack(self, row):
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            deleted = connection.execute('DELETE FROM batches WHERE id=?', (row[0],)).rowcount
            if deleted:
                connection.execute("UPDATE state SET value=value-? WHERE key='bytes'", (len(row[3]),))
                connection.execute("UPDATE state SET value=value+1 WHERE key='delivered'")
                connection.execute("UPDATE state SET value=? WHERE key='last_success'", (time.time(),))


def send(config, row):
    if config.get('transition_file') and Path(config['transition_file']).exists():
        lease = json.loads(Path(config['transition_file']).read_text())
        if not time.time() < lease['expires'] <= time.time() + 300:
            raise ValueError('certificate activation lease expired')
    endpoint = urlsplit(config['endpoint'])
    if endpoint.scheme != 'https' or endpoint.username or endpoint.password or endpoint.hostname != config['server_name']:
        raise ValueError('invalid endpoint')
    references = json.loads(Path(config['pki_active']).read_text())
    context = ssl.create_default_context(cafile=references['ca_file'])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(references['cert_file'], references['key_file'])
    connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443, context=context, timeout=20)
    try:
        connection.request('POST', row[1], body=row[3], headers=json.loads(row[2]))
        response = connection.getresponse()
        return 200 <= response.status < 300
    finally: connection.close()


def forward(queue, config, stop, sender=send):
    delay = 1
    last_tick = 0
    while not stop.is_set():
        if time.time() - last_tick > 10:
            queue.tick(); last_tick = time.time()
        row = queue.first()
        if row is None:
            stop.wait(.5); continue
        try:
            queue.attempt()
            if not sender(config, row): raise ValueError('retryable remote failure')
            queue.ack(row); delay = 1
        except Exception:
            stop.wait(delay); delay = min(delay * 2, 30)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args): pass

    def reply(self, code):
        self.send_response(code); self.send_header('Content-Length', '0'); self.end_headers()
        self.close_connection = True

    def do_POST(self):
        try:
            self.connection.settimeout(20)
            if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + self.server.token):
                self.reply(403); return
            if self.path not in PATHS: self.reply(404); return
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not lengths[0].isdigit() or self.headers.get('Transfer-Encoding'):
                self.reply(400); return
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY: self.reply(413); return
            body = self.rfile.read(length)
            if len(body) != length: self.reply(400); return
            headers = {name: self.headers[name] for name in ['Content-Type', 'Content-Encoding',
                       'X-Prometheus-Remote-Write-Version'] if name in self.headers}
            self.reply(204 if self.server.queue.put(self.path, headers, body) else 503)
        except Exception:
            self.reply(503)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, port, queue, token):
        super().__init__(('127.0.0.1', port), Handler)
        self.queue, self.token = queue, token


def main():
    os.umask(0o077)
    if sys.argv[1] == '--metrics':
        directory = Path(sys.argv[2])
        with sqlite3.connect('file:' + str(directory / 'queue.sqlite3') + '?mode=ro', uri=True) as connection:
            values = dict(connection.execute('SELECT key,value FROM state'))
            oldest = connection.execute('SELECT MIN(at) FROM batches').fetchone()[0]
        values['oldest_age'] = time.time() - oldest if oldest is not None else 0
        print(json.dumps(values)); return
    config = json.loads(Path(sys.argv[1]).read_text())
    directory = Path('C:/ProgramData/SambaADObservability' if os.name == 'nt' else '/var/lib/samba-ad-observability')
    token = (directory / 'token').read_text().strip()
    if len(token) != 64 or any(c not in '0123456789abcdef' for c in token): raise ValueError('invalid local credential')
    queue = Queue(directory / 'spool')
    stop = threading.Event()
    thread = threading.Thread(target=forward, args=(queue, config, stop), daemon=True); thread.start()
    try: Server(19105, queue, token).serve_forever()
    finally: stop.set(); thread.join(timeout=25)


if __name__ == '__main__': main()
