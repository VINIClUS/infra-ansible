"""In-memory fake of the Cloudflare v4 endpoints the agent_context_tunnel role uses.

Runs on 127.0.0.1 with a random port. Every request is recorded so tests can
assert which methods were sent. Nothing here talks to the real Cloudflare API.
"""

import json
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ACCOUNT = "acct-fixture"
ZONE = "zone-fixture"
API_TOKEN = "fake-api-token-value"
TUNNEL_TOKEN = "fake-tunnel-token-value"
CLIENT_SECRET = "fake-client-secret-value"


class FakeCloudflare:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []
        self.tunnels = []
        self.configs = {}
        self.dns = []
        self.apps = []
        self.policies = {}
        self.service_tokens = []
        self.identity_providers = [{"id": "idp-otp", "name": "One-time PIN", "type": "onetimepin"}]
        self.secret_counter = 0
        # (method, path suffix) pairs that answer HTTP 500.
        self.fail = []
        self.last_bodies = {}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/client/v4"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def mutating(self) -> list:
        return [r for r in self.requests if r[0] != "GET"]

    def _handler(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, result=None, errors=None, list_result=False):
                body = {
                    "success": not errors,
                    "errors": errors or [],
                    "messages": [],
                    "result": result,
                }
                if list_result:
                    body["result_info"] = {
                        "page": 1,
                        "per_page": 100,
                        "count": len(result),
                        "total_count": len(result),
                        "total_pages": 1 if result else 0,
                    }
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _handle(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else {}
                url = urlparse(self.path)
                query = {k: v[0] for k, v in parse_qs(url.query).items()}
                with fake.lock:
                    fake.requests.append((method, url.path))
                    if self.headers.get("Authorization") != f"Bearer {API_TOKEN}":
                        return self._send(403, errors=[{"code": 10000, "message": "Authentication error"}])
                    handled = fake.route(method, url.path, query, body)
                if handled is None:
                    return self._send(404, errors=[{"code": 7003, "message": "No route"}])
                status, result, listing = handled
                if status >= 400:
                    return self._send(status, errors=[{"code": 9999, "message": "injected failure"}])
                return self._send(status, result, list_result=listing)

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def do_PUT(self):
                self._handle("PUT")

            def do_PATCH(self):
                self._handle("PATCH")

            def do_DELETE(self):
                self._handle("DELETE")

        return Handler

    def bad_idps(self, body):
        known = {p["id"] for p in self.identity_providers}
        return not set(body.get("allowed_idps", [])) <= known

    @staticmethod
    def missing(body, *fields):
        return [f for f in fields if f not in body or body[f] in (None, "", [])]

    def route(self, method, path, query, body):
        handled = self._route(method, path, query, body)
        return handled

    def _route(self, method, path, query, body):
        path = path.removeprefix("/client/v4")
        if any(method == m and path.endswith(suffix) for m, suffix in self.fail):
            return 500, None, False
        acct = f"/accounts/{ACCOUNT}"
        if path == f"{acct}/cfd_tunnel":
            if method == "GET":
                name = query.get("name")
                found = [t for t in self.tunnels if name in (None, t["name"])]
                if query.get("is_deleted") == "false":
                    found = [t for t in found if not t.get("deleted_at")]
                return 200, found, True
            if method == "POST":
                if self.missing(body, "name") or body.get("config_src") != "cloudflare":
                    return 400, None, False
                tunnel = {"id": str(uuid.uuid4()), "name": body["name"], "config_src": body["config_src"]}
                self.tunnels.append(tunnel)
                return 200, tunnel, False
        match = re.fullmatch(rf"{acct}/cfd_tunnel/([^/]+)/(configurations|token)", path)
        if match:
            tunnel_id, leaf = match.groups()
            if leaf == "token" and method == "GET":
                return 200, TUNNEL_TOKEN, False
            if leaf == "configurations" and method == "GET":
                config = self.configs.get(tunnel_id)
                if config is not None:
                    config = {"warp-routing": {"enabled": False}, **config}
                return 200, {"tunnel_id": tunnel_id, "source": "cloudflare", "version": 1, "config": config}, False
            if leaf == "configurations" and method == "PUT":
                ingress = body.get("config", {}).get("ingress") or []
                if not ingress or set(ingress[-1]) != {"service"} or any("service" not in r for r in ingress):
                    return 400, None, False
                self.last_bodies["PUT configurations"] = body
                self.configs[tunnel_id] = body["config"]
                return 200, {"tunnel_id": tunnel_id, "config": body["config"]}, False
        if path == f"/zones/{ZONE}/dns_records":
            if method == "GET":
                name = query.get("name")
                return 200, [r for r in self.dns if name in (None, r["name"])], True
            if method == "POST":
                if self.missing(body, "type", "name", "content") or body.get("proxied") is not True:
                    return 400, None, False
                record = {"id": str(uuid.uuid4()), **body}
                self.dns.append(record)
                return 200, record, False
        match = re.fullmatch(rf"/zones/{ZONE}/dns_records/([^/]+)", path)
        if match and method == "PATCH":
            record = next(r for r in self.dns if r["id"] == match.group(1))
            record.update(body)
            return 200, record, False
        if path == f"{acct}/access/identity_providers" and method == "GET":
            return 200, self.identity_providers, True
        if path == f"{acct}/access/apps":
            if method == "GET":
                domain = query.get("domain")
                return 200, [a for a in self.apps if domain in (None, a["domain"])], True
            if method == "POST":
                if self.missing(body, "name", "domain", "type") or self.bad_idps(body):
                    return 400, None, False
                app = {"id": str(uuid.uuid4()), **body}
                self.apps.append(app)
                self.policies[app["id"]] = []
                return 200, app, False
        match = re.fullmatch(rf"{acct}/access/apps/([^/]+)", path)
        if match and method == "PUT":
            if self.missing(body, "name", "domain", "type") or {"id", "aud"} & set(body) or self.bad_idps(body):
                return 400, None, False
            self.last_bodies["PUT apps"] = body
            app = next(a for a in self.apps if a["id"] == match.group(1))
            app.update(body)
            return 200, app, False
        match = re.fullmatch(rf"{acct}/access/apps/([^/]+)/policies(?:/([^/]+))?", path)
        if match:
            app_id, policy_id = match.groups()
            policies = self.policies.setdefault(app_id, [])
            if policy_id is None and method == "GET":
                return 200, policies, True
            if method in ("POST", "PUT") and (
                self.missing(body, "name", "decision", "include")
                or body["decision"] not in ("allow", "deny", "non_identity", "bypass")
            ):
                return 400, None, False
            if policy_id is None and method == "POST":
                policy = {"id": str(uuid.uuid4()), **body}
                policies.append(policy)
                return 200, policy, False
            if policy_id and method == "PUT":
                self.last_bodies["PUT policies"] = body
                policy = next(p for p in policies if p["id"] == policy_id)
                policy.update(body)
                return 200, policy, False
        if path == f"{acct}/access/service_tokens":
            if method == "GET":
                name = query.get("name")
                listed = [
                    {k: v for k, v in t.items() if k != "client_secret"}
                    for t in self.service_tokens
                    if name in (None, t["name"])
                ]
                return 200, listed, True
            if method == "POST":
                if self.missing(body, "name"):
                    return 400, None, False
                token = self._new_token(body["name"])
                self.service_tokens.append(token)
                return 200, token, False
        match = re.fullmatch(rf"{acct}/access/service_tokens/([^/]+)/rotate", path)
        if match and method == "POST":
            token = next(t for t in self.service_tokens if t["id"] == match.group(1))
            self.secret_counter += 1
            token["client_secret"] = f"{CLIENT_SECRET}-{self.secret_counter}"
            return 200, token, False
        return None

    def _new_token(self, name):
        self.secret_counter += 1
        return {
            "id": str(uuid.uuid4()),
            "name": name,
            "client_id": f"{uuid.uuid4().hex}.access.example.invalid",
            "client_secret": f"{CLIENT_SECRET}-{self.secret_counter}",
        }
