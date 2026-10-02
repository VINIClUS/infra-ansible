import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

from fake_cloudflare_api import ACCOUNT, API_TOKEN, CLIENT_SECRET, TUNNEL_TOKEN, ZONE, FakeCloudflare

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles/agent_context_tunnel"
PLAYBOOK = ROOT / "playbooks/agent-context-tunnel.yml"
HOSTNAME = "agent-context.example.invalid"


def role_files() -> list[Path]:
    return sorted(ROLE.rglob("*.yml"))


def all_tasks() -> list[tuple[Path, dict]]:
    tasks = []
    for path in role_files():
        if path.parent.name != "tasks":
            continue
        tasks.extend((path, task) for task in flatten(yaml.safe_load(path.read_text(encoding="utf-8"))))
    return tasks


def flatten(tasks):
    """Yield leaf tasks, descending into block/rescue/always sections."""
    for task in tasks:
        if "block" in task:
            for section in ("block", "rescue", "always"):
                yield from flatten(task.get(section, []))
        else:
            yield task


def test_disabled_by_default_and_asserted():
    defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
    assert defaults["agent_context_tunnel_enabled"] is False
    assert defaults["agent_context_tunnel_allowed_emails"] == []
    assert defaults["agent_context_tunnel_rotate_service_token"] is False
    assert defaults["agent_context_tunnel_origin_service"] == "http://ingress:8080"
    assert defaults["agent_context_tunnel_hostname"] == ""
    main = yaml.safe_load((ROLE / "tasks/main.yml").read_text(encoding="utf-8"))
    assert main[0]["ansible.builtin.assert"]["that"] == "agent_context_tunnel_enabled is boolean"
    assert main[1]["ansible.builtin.meta"] == "end_role"
    assert PLAYBOOK.read_text(encoding="utf-8").count("hosts: localhost") == 1
    assert "connection: local" in PLAYBOOK.read_text(encoding="utf-8")


def test_no_delete_and_no_no_tls_verify_anywhere():
    for path in role_files() + [PLAYBOOK]:
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\bDELETE\b", text)
        # The only removal allowed is our own empty credentials placeholder after a failed run.
        for hit in re.finditer(r"state:\s*absent", text):
            assert "Remove the empty placeholder" in text[max(0, hit.start() - 300) : hit.start()]
            assert text.count("state: absent") == 1
    assert "noTLSVerify: true" not in (ROLE / "defaults/main.yml").read_text(encoding="utf-8")


def test_every_task_touching_the_token_or_secrets_is_no_log():
    secretive = (
        r"agent_context_tunnel_api_token\b",
        "agent_context_tunnel_secret_token",
        r"agent_context_tunnel_response\b",
        r"agent_context_tunnel_read\b",
        r"agent_context_tunnel_current_config\b",
        r"agent_context_tunnel_write\b",
    )
    seen = 0
    for path, task in all_tasks():
        text = yaml.safe_dump({k: v for k, v in task.items() if k != "name"}).replace(
            "agent_context_tunnel_api_token (or", ""
        )
        uses_uri = "ansible.builtin.uri" in task
        # The api.yml asserts only print the extracted error codes and messages.
        if "ansible.builtin.assert" in task:
            continue
        if uses_uri or any(re.search(name, text) for name in secretive):
            seen += 1
            assert task.get("no_log") is True, f"{path.name}: {task['name']}"
    assert seen >= 4


def test_every_mutating_call_is_check_mode_guarded_and_gets_are_forced():
    for path, task in all_tasks():
        if "ansible.builtin.uri" in task:
            method = task["ansible.builtin.uri"]["method"]
            if method == "GET":
                assert task.get("check_mode") is False
            else:
                assert "not ansible_check_mode" in yaml.safe_dump(task["when"])
        if "ansible.builtin.include_tasks" in task and task["ansible.builtin.include_tasks"] == "api.yml":
            method = task["vars"]["agent_context_tunnel_api_method"]
            if method != "GET":
                assert "not ansible_check_mode" in task["when"], task["name"]
        if "ansible.builtin.copy" in task:
            assert "not ansible_check_mode" in task["when"]


def test_credentials_file_guards():
    main = (ROLE / "tasks/main.yml").read_text(encoding="utf-8")
    guards = (ROLE / "tasks/output_guards.yml").read_text(encoding="utf-8")
    assert 'mode: "0600"' in main and "force: false" in main
    assert "is match('^/')" in guards
    assert "rev-parse" in guards and "--is-inside-work-tree" in guards
    assert "follow: false" in guards
    assert "not agent_context_tunnel_output_file.stat.exists" in guards
    # Refuse before anything is created.
    assert main.index("output_guards.yml") < main.index("Create the missing remotely managed tunnel")
    assert main.index("Refuse to produce secrets without") < main.index("Create the missing remotely managed tunnel")


def test_playbook_is_not_deployable_by_push():
    deploy_text = (ROOT / "tools/deploy/infra_ansible_deploy.py").read_text(encoding="utf-8")
    assert "agent-context-tunnel" not in deploy_text
    assert "agent_context_tunnel" not in deploy_text
    for workflow in (ROOT / ".github").rglob("*.yml"):
        assert "agent-context-tunnel" not in workflow.read_text(encoding="utf-8")
    assert "agent_context_tunnel" not in (ROOT / "playbooks/site.yml").read_text(encoding="utf-8")
    spec = importlib.util.spec_from_file_location("deploy", ROOT / "tools/deploy/infra_ansible_deploy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert not any("agent-context-tunnel" in run.playbook for run in module.FIXED_RUNS)
    assert not any("agent-context-tunnel" in run.playbook for run in module._ALLOWED_RUNS)


# ---- Functional tests against the local fake API ----
needs_ansible = pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible-playbook missing")


def run(fake, output: Path | None, *args, extra=None, check=False, verbosity="-v", env_extra=None) -> subprocess.CompletedProcess:
    variables = {
        "agent_context_tunnel_enabled": True,
        "agent_context_tunnel_api_base_url": fake.base_url,
        "agent_context_tunnel_api_token": API_TOKEN,
        "agent_context_tunnel_account_id": ACCOUNT,
        "agent_context_tunnel_zone_id": ZONE,
        "agent_context_tunnel_hostname": HOSTNAME,
        "agent_context_tunnel_credentials_output": str(output) if output else "",
        **(extra or {}),
    }
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CLOUDFLARE_", "ANSIBLE_"))}
    for proxy in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        env.pop(proxy, None)
    env.update({"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1", "ANSIBLE_NOCOLOR": "1"})
    env.update(env_extra or {})
    # Extra vars go through a private file: high verbosity echoes -e '{json}' on the command line.
    varfile = Path(tempfile.mkdtemp(prefix="tunnel-vars-")) / "vars.json"
    varfile.touch(mode=0o600)
    varfile.write_text(json.dumps(variables), encoding="utf-8")
    command = ["ansible-playbook", "-i", "localhost,", str(PLAYBOOK), "-e", f"@{varfile}", verbosity, *args]
    if check:
        command.append("--check")
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    finally:
        shutil.rmtree(varfile.parent, ignore_errors=True)


def assert_no_secrets(result: subprocess.CompletedProcess, *extra: str):
    for secret in (API_TOKEN, TUNNEL_TOKEN, CLIENT_SECRET, *extra):
        assert secret not in result.stdout
        assert secret not in result.stderr


@needs_ansible
def test_disabled_makes_no_requests(tmp_path):
    with FakeCloudflare() as fake:
        result = run(fake, tmp_path / "creds.json", extra={"agent_context_tunnel_enabled": False})
    assert result.returncode == 0, result.stdout + result.stderr
    assert fake.requests == []


@needs_ansible
def test_first_run_creates_everything_and_second_run_is_idempotent(tmp_path):
    output = tmp_path / "creds.json"
    with FakeCloudflare() as fake:
        first = run(fake, output, extra={"agent_context_tunnel_allowed_emails": ["operator@example.invalid"]})
        assert first.returncode == 0, first.stdout + first.stderr
        assert_no_secrets(first)
        assert "DEPRECATION" not in first.stdout + first.stderr
        assert "[WARNING]" not in first.stdout + first.stderr
        assert len(fake.tunnels) == 1 and fake.tunnels[0]["config_src"] == "cloudflare"
        tunnel_id = fake.tunnels[0]["id"]
        ingress = fake.configs[tunnel_id]["ingress"]
        assert ingress == [
            {"hostname": HOSTNAME, "service": "http://ingress:8080", "originRequest": {}},
            {"service": "http_status:404"},
        ]
        assert [(r["type"], r["content"], r["proxied"]) for r in fake.dns] == [
            ("CNAME", f"{tunnel_id}.cfargotunnel.com", True)
        ]
        assert len(fake.apps) == 1 and fake.apps[0]["domain"] == HOSTNAME
        assert fake.apps[0]["type"] == "self_hosted"
        policies = fake.policies[fake.apps[0]["id"]]
        by_decision = {p["decision"]: p for p in policies}
        assert by_decision["non_identity"]["include"] == [
            {"service_token": {"token_id": fake.service_tokens[0]["id"]}}
        ]
        assert by_decision["allow"]["include"] == [{"email": {"email": "operator@example.invalid"}}]
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        credentials = json.loads(output.read_text(encoding="utf-8"))
        assert credentials["tunnel_token"] == TUNNEL_TOKEN
        assert credentials["service_token_client_secret"].startswith(CLIENT_SECRET)
        assert not any(method == "DELETE" for method, _ in fake.requests)

        before = len(fake.requests)
        second = run(
            fake,
            tmp_path / "unused.json",
            extra={"agent_context_tunnel_allowed_emails": ["operator@example.invalid"]},
        )
        assert second.returncode == 0, second.stdout + second.stderr
        assert "changed=0" in second.stdout
        assert all(method == "GET" for method, _ in fake.requests[before:])
        assert not (tmp_path / "unused.json").exists()
        assert_no_secrets(second)


@needs_ansible
def test_check_mode_only_reads_and_reports(tmp_path):
    output = tmp_path / "creds.json"
    with FakeCloudflare() as fake:
        result = run(fake, output, check=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert fake.requests and fake.mutating() == []
        assert not output.exists()
        assert "create tunnel agent-context" in result.stdout
        assert "create proxied CNAME" in result.stdout
        assert "write credentials file" in result.stdout
        assert_no_secrets(result)


@needs_ansible
def test_foreign_dns_record_is_refused_before_any_mutation(tmp_path):
    output = tmp_path / "creds.json"
    with FakeCloudflare() as fake:
        fake.dns.append({"id": "foreign", "type": "A", "name": HOSTNAME, "content": "192.0.2.10", "proxied": False})
        result = run(fake, output)
        assert result.returncode != 0
        assert "refusing to overwrite a foreign record" in result.stdout + result.stderr
        assert fake.mutating() == []
        assert not output.exists()
        assert_no_secrets(result)


@needs_ansible
def test_missing_output_path_fails_before_creating_anything():
    with FakeCloudflare() as fake:
        result = run(fake, None)
        assert result.returncode != 0
        assert "agent_context_tunnel_credentials_output" in result.stdout + result.stderr
        assert fake.mutating() == []


@needs_ansible
def test_existing_output_file_and_git_work_tree_are_refused(tmp_path):
    existing = tmp_path / "creds.json"
    existing.write_text("keep", encoding="utf-8")
    with FakeCloudflare() as fake:
        result = run(fake, existing)
        assert result.returncode != 0 and fake.mutating() == []
        assert existing.read_text(encoding="utf-8") == "keep"
        inside = Path(tempfile.mkdtemp(dir=ROOT, prefix=".tunnel-test-"))
        try:
            result = run(fake, inside / "creds.json")
            assert result.returncode != 0
            assert "git work tree" in result.stdout + result.stderr
            assert fake.mutating() == []
            assert not (inside / "creds.json").exists()
        finally:
            shutil.rmtree(inside)
        result = run(fake, tmp_path / "missing-dir" / "creds.json")
        assert result.returncode != 0 and fake.mutating() == []
        result = run(fake, Path("relative.json"))
        assert result.returncode != 0 and fake.mutating() == []


@needs_ansible
def test_existing_service_token_is_not_rotated_unless_requested(tmp_path):
    with FakeCloudflare() as fake:
        assert run(fake, tmp_path / "first.json").returncode == 0
        secret = fake.service_tokens[0]["client_secret"]
        plain = run(fake, tmp_path / "second.json")
        assert plain.returncode == 0 and not (tmp_path / "second.json").exists()
        assert fake.service_tokens[0]["client_secret"] == secret
        rotated = run(fake, tmp_path / "rotated.json", extra={"agent_context_tunnel_rotate_service_token": True})
        assert rotated.returncode == 0, rotated.stdout + rotated.stderr
        assert any(path.endswith("/rotate") for _, path in fake.requests)
        assert fake.service_tokens[0]["client_secret"] != secret
        assert json.loads((tmp_path / "rotated.json").read_text(encoding="utf-8"))["service_token_client_secret"] == (
            fake.service_tokens[0]["client_secret"]
        )
        assert stat.S_IMODE((tmp_path / "rotated.json").stat().st_mode) == 0o600
        assert_no_secrets(rotated, fake.service_tokens[0]["client_secret"])


@needs_ansible
def test_required_inputs_are_asserted(tmp_path):
    with FakeCloudflare() as fake:
        for name in (
            "agent_context_tunnel_api_token",
            "agent_context_tunnel_account_id",
            "agent_context_tunnel_zone_id",
            "agent_context_tunnel_hostname",
        ):
            result = run(fake, tmp_path / "creds.json", extra={name: ""})
            assert result.returncode != 0, name
            assert name in result.stdout + result.stderr
        assert fake.requests == []


def order_of(fake, needle_method, needle_path):
    for index, (method, path) in enumerate(fake.requests):
        if method == needle_method and path.endswith(needle_path):
            return index
    return None


@needs_ansible
def test_access_failure_publishes_no_dns_record(tmp_path):
    with FakeCloudflare() as fake:
        fake.fail.append(("POST", "/access/apps"))
        result = run(fake, tmp_path / "creds.json")
        assert result.returncode != 0
        assert "injected failure" in result.stdout + result.stderr
        assert fake.dns == []
        assert fake.configs == {}
        assert not any(path.endswith("/dns_records") and method != "GET" for method, path in fake.requests)
        assert_no_secrets(result)


@needs_ansible
def test_access_is_reconciled_before_config_and_dns(tmp_path):
    with FakeCloudflare() as fake:
        assert run(fake, tmp_path / "creds.json").returncode == 0
        app = order_of(fake, "POST", "/access/apps")
        policy = order_of(fake, "POST", "/policies")
        assert app < policy < order_of(fake, "PUT", "/configurations")
        assert policy < order_of(fake, "POST", "/dns_records")


@needs_ansible
def test_tunnel_token_failure_happens_before_the_service_token_exists(tmp_path):
    output = tmp_path / "creds.json"
    with FakeCloudflare() as fake:
        fake.fail.append(("GET", "/token"))
        result = run(fake, output)
        assert result.returncode != 0
        assert fake.service_tokens == []
        assert not output.exists()
        assert_no_secrets(result)


@needs_ansible
def test_credentials_are_written_right_after_the_service_token_secret(tmp_path):
    with FakeCloudflare() as fake:
        fake.fail.append(("POST", "/access/apps"))
        output = tmp_path / "creds.json"
        assert run(fake, output).returncode != 0
        # A later failure must not lose the one-time secret.
        assert json.loads(output.read_text(encoding="utf-8"))["service_token_client_secret"].startswith(CLIENT_SECRET)
        token_post = order_of(fake, "POST", "/service_tokens")
        assert order_of(fake, "GET", "/token") < token_post
        assert token_post + 1 == order_of(fake, "POST", "/access/apps")


@needs_ansible
def test_new_tunnel_with_existing_service_token_refuses_an_empty_secret(tmp_path):
    output = tmp_path / "creds.json"
    with FakeCloudflare() as fake:
        fake.service_tokens.append({"id": "tok", "name": "agent-context-clients", "client_id": "cid.invalid"})
        result = run(fake, output)
        assert result.returncode != 0
        assert "agent_context_tunnel_rotate_service_token=true" in result.stdout + result.stderr
        assert fake.mutating() == []
        assert not output.exists()


@needs_ansible
def test_very_verbose_run_never_prints_secrets(tmp_path):
    with FakeCloudflare() as fake:
        output = tmp_path / "creds.json"
        result = run(fake, output, verbosity="-vvv")
        assert result.returncode == 0, result.stdout[-2000:] + result.stderr
        assert output.exists() and fake.mutating(), "the run must really create and persist secrets"
        written = output.read_text()
        assert TUNNEL_TOKEN in written and CLIENT_SECRET in written
        assert_no_secrets(result)


@needs_ansible
@pytest.mark.parametrize(
    "url",
    [
        "https://api.cloudflare.com.evil.invalid/client/v4",
        "https://example.invalid/client/v4",
        "http://api.cloudflare.com/client/v4",
        "http://127.0.0.1.evil.invalid:80/client/v4",
        "http://localhost:8080@evil.invalid/client/v4",
    ],
)
def test_untrusted_api_base_url_is_refused_before_any_call(tmp_path, url):
    with FakeCloudflare() as fake:
        result = run(fake, tmp_path / "creds.json", extra={"agent_context_tunnel_api_base_url": url})
        assert result.returncode != 0
        assert "refusing to send the bearer token anywhere else" in result.stdout + result.stderr
        assert fake.requests == []
        assert_no_secrets(result)


@needs_ansible
def test_app_and_policy_updates_keep_hand_set_fields(tmp_path):
    with FakeCloudflare() as fake:
        assert run(fake, tmp_path / "creds.json").returncode == 0
        app = fake.apps[0]
        app["custom_hand_set_field"] = "keep"
        app["aud"] = "read-only-aud"
        app["session_duration"] = "24h"
        policy = fake.policies[app["id"]][0]
        policy["custom_policy_field"] = "keep"
        policy["precedence"] = 9
        again = run(fake, tmp_path / "unused.json")
        assert again.returncode == 0, again.stdout[-2000:]
        assert app["session_duration"] == "30m" and app["custom_hand_set_field"] == "keep"
        assert policy["precedence"] == 1 and policy["custom_policy_field"] == "keep"
        assert fake.last_bodies["PUT apps"].keys().isdisjoint(
            {"id", "aud", "created_at", "updated_at", "destinations", "self_hosted_domains"}
        )
        assert fake.last_bodies["PUT policies"].keys().isdisjoint({"id", "created_at", "updated_at"})


@needs_ansible
def test_deleted_tunnel_with_same_name_is_ignored_and_config_keys_survive(tmp_path):
    with FakeCloudflare() as fake:
        fake.tunnels.append({"id": "gone", "name": "agent-context", "deleted_at": "2020-01-01T00:00:00Z"})
        assert run(fake, tmp_path / "creds.json").returncode == 0
        live = [t for t in fake.tunnels if not t.get("deleted_at")]
        assert len(live) == 1 and live[0]["id"] != "gone"
        fake.configs[live[0]["id"]] = {
            "ingress": [{"service": "http_status:404"}],
            "warp-routing": {"enabled": True},
        }
        assert run(fake, tmp_path / "unused.json").returncode == 0
        assert fake.last_bodies["PUT configurations"]["config"]["warp-routing"] == {"enabled": True}


@needs_ansible
@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_unwritable_credentials_directory_fails_before_any_mutation(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        with FakeCloudflare() as fake:
            result = run(fake, locked / "creds.json")
            assert result.returncode != 0
            assert fake.mutating() == []
            assert not (locked / "creds.json").exists()
    finally:
        locked.chmod(0o700)


@needs_ansible
def test_failure_after_reservation_leaves_no_empty_placeholder(tmp_path):
    output = tmp_path / "creds.json"
    with FakeCloudflare() as fake:
        fake.fail.append(("GET", "/token"))
        result = run(fake, output)
        assert result.returncode != 0
        assert not output.exists()


def seed_app(fake, policies):
    app = {"id": "app-1", "name": "Agent Context", "domain": HOSTNAME, "type": "self_hosted",
           "session_duration": "30m"}
    fake.apps.append(app)
    fake.policies["app-1"] = policies


@needs_ansible
@pytest.mark.parametrize(
    "policy",
    [
        {"id": "p1", "name": "Open to all", "decision": "bypass", "include": [{"everyone": {}}]},
        {"id": "p2", "name": "Anyone in", "decision": "allow", "include": [{"everyone": {}}]},
        {"id": "p3", "name": "Reusable open", "decision": "bypass", "include": [{"everyone": {}}], "reusable": True},
    ],
)
def test_unmanaged_permissive_policy_blocks_publishing(tmp_path, policy):
    with FakeCloudflare() as fake:
        seed_app(fake, [] if policy.get("reusable") else [policy])
        if policy.get("reusable"):
            fake.apps[0]["policies"] = [policy]
        result = run(fake, tmp_path / "creds.json")
        assert result.returncode != 0
        assert policy["name"] in result.stdout + result.stderr
        assert fake.mutating() == []
        assert fake.dns == [] and fake.configs == {}


@needs_ansible
def test_email_access_needs_a_login_method(tmp_path):
    emails = {"agent_context_tunnel_allowed_emails": ["operator@example.invalid"]}
    with FakeCloudflare() as fake:
        fake.identity_providers.clear()
        result = run(fake, tmp_path / "creds.json", extra=emails)
        assert result.returncode != 0
        assert "needs a login method" in result.stdout + result.stderr
        assert fake.mutating() == []
    with FakeCloudflare() as fake:
        fake.identity_providers[:] = [{"id": "idp-x", "name": "Corp", "type": "github"}]
        extra = {**emails, "agent_context_tunnel_identity_provider_id": "idp-x"}
        assert run(fake, tmp_path / "creds2.json", extra=extra).returncode == 0
        assert fake.apps[0]["allowed_idps"] == ["idp-x"]


@needs_ansible
def test_configured_identity_provider_is_applied_to_an_existing_app(tmp_path):
    with FakeCloudflare() as fake:
        assert run(fake, tmp_path / "creds.json").returncode == 0
        fake.identity_providers.append({"id": "idp-x", "name": "Corp", "type": "github"})
        extra = {"agent_context_tunnel_identity_provider_id": "idp-x"}
        assert run(fake, tmp_path / "unused.json", extra=extra).returncode == 0
        assert fake.last_bodies["PUT apps"]["allowed_idps"] == ["idp-x"]


@needs_ansible
def test_reservation_validation_failure_removes_placeholder_and_allows_retry(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    liar = bindir / "id"
    liar.write_text("#!/bin/sh\necho 4242424\n")
    liar.chmod(0o755)
    output = tmp_path / "creds.json"
    with FakeCloudflare() as fake:
        failed = run(fake, output, env_extra={"PATH": f"{bindir}:{os.environ['PATH']}"})
        assert failed.returncode != 0
        assert fake.mutating() == []
        assert not output.exists()
        assert run(fake, output).returncode == 0
        assert output.exists()


@needs_ansible
def test_hand_set_allowed_idps_survive_an_app_update(tmp_path):
    with FakeCloudflare() as fake:
        assert run(fake, tmp_path / "creds.json").returncode == 0
        fake.apps[0]["name"] = "Renamed by hand"
        fake.apps[0]["allowed_idps"] = ["idp-otp"]
        assert run(fake, tmp_path / "unused.json").returncode == 0
        assert fake.last_bodies["PUT apps"]["allowed_idps"] == ["idp-otp"]
        assert fake.apps[0]["name"] != "Renamed by hand"
