import os
import stat
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from tools.deploy import infra_ansible_deploy as deploy


ROOT = Path(__file__).resolve().parents[1]
SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "f" * 40
INVENTORY_SHA = "e" * 40


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_accepts_only_clean_current_main_sha():
    deploy.validate_request(SHA, SHA, SHA, False)


@pytest.mark.parametrize(
    ("requested", "main", "checkout", "dirty"),
    [
        ("main", SHA, SHA, False),
        (SHA.upper(), SHA, SHA, False),
        (SHA, OTHER_SHA, SHA, False),
        (SHA, SHA, OTHER_SHA, False),
        (SHA, SHA, SHA, True),
    ],
)
def test_rejects_untrusted_request(requested, main, checkout, dirty):
    with pytest.raises(ValueError):
        deploy.validate_request(requested, main, checkout, dirty)


@pytest.mark.parametrize(
    "arguments",
    [
        ["main"],
        [SHA, "--inventory", "/tmp/hosts.yml"],
        [SHA, "--limit", "all"],
        [SHA, "--tags", "all"],
        [SHA, "unexpected"],
        [],
    ],
)
def test_cli_rejects_alternate_execution_inputs_and_unexpected_arguments(arguments):
    with pytest.raises(SystemExit):
        deploy.parse_args(arguments)


def test_cli_accepts_exactly_one_sha():
    assert deploy.parse_args([SHA]).requested_sha == SHA


def test_invalid_sha_is_rejected_before_lock_or_network(monkeypatch):
    def forbidden_lock(*_args, **_kwargs):
        raise AssertionError("lock must not be attempted")

    def forbidden_network(*_args, **_kwargs):
        raise AssertionError("network must not be attempted")

    monkeypatch.setattr(deploy, "deployment_lock", forbidden_lock)
    with pytest.raises(ValueError, match="40 lowercase hex"):
        deploy.deploy_requested_sha("main", open_url=forbidden_network, base_env={})


def test_public_main_response_requires_an_exact_sha():
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"object": {"sha": "not-a-sha"}}'

    with pytest.raises(ValueError):
        deploy.fetch_public_main_sha(lambda *_args, **_kwargs: Response())


def test_malformed_sha_is_rejected_before_any_git_subprocess():
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    with pytest.raises(ValueError):
        deploy.prepare_public_checkout("main", fake_run, {"PATH": "/usr/bin"})

    assert calls == []


def test_main_ref_request_ignores_inherited_proxy_ca_and_path(monkeypatch):
    inherited = {
        "PATH": "/tmp/runner-bin",
        "HTTP_PROXY": "http://runner-proxy.invalid",
        "https_proxy": "http://runner-proxy.invalid",
        "ALL_PROXY": "socks5://runner-proxy.invalid",
        "NO_PROXY": "github.com",
        "SSL_CERT_FILE": "/tmp/runner-ca.pem",
        "SSL_CERT_DIR": "/tmp/runner-certs",
        "REQUESTS_CA_BUNDLE": "/tmp/runner-requests.pem",
        "CURL_CA_BUNDLE": "/tmp/runner-curl.pem",
    }
    observed = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return ('{"object": {"sha": "' + SHA + '"}}').encode()

    def open_url(_request, **_kwargs):
        observed.update(inherited)
        return Response()

    @contextmanager
    def unlocked(*_args, **_kwargs):
        yield

    monkeypatch.setattr(deploy, "deployment_lock", unlocked)
    monkeypatch.setattr(
        deploy,
        "prepare_public_checkout",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("stop")),
    )

    with pytest.raises(RuntimeError, match="stop"):
        deploy.deploy_requested_sha(SHA, open_url=open_url, base_env=inherited)

    assert observed["PATH"] == "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
    for variable in (
        "HTTP_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    ):
        assert variable not in observed


def test_github_opener_uses_no_proxy_and_explicit_system_ca(monkeypatch):
    captured = {}
    sentinel_context = object()
    sentinel_opener = object()

    def fake_context(*, cafile):
        captured["cafile"] = cafile
        return sentinel_context

    def fake_build_opener(*handlers):
        captured["handlers"] = handlers
        return sentinel_opener

    monkeypatch.setattr(deploy.ssl, "create_default_context", fake_context)
    monkeypatch.setattr(deploy.urllib.request, "build_opener", fake_build_opener)

    assert deploy.build_github_opener() is sentinel_opener
    assert captured["cafile"] == "/etc/ssl/certs/ca-certificates.crt"
    proxy_handler, https_handler = captured["handlers"]
    assert proxy_handler.proxies == {}
    assert https_handler._context is sentinel_context


@pytest.mark.parametrize(
    ("mode", "uid", "message"),
    [
        (stat.S_IFIFO | 0o600, 0, "regular file"),
        (stat.S_IFREG | 0o600, 1234, "owned by root"),
        (stat.S_IFREG | 0o640, 0, "mode 0600"),
    ],
)
def test_lock_metadata_rejects_unsafe_type_owner_and_mode(mode, uid, message):
    metadata = SimpleNamespace(st_mode=mode, st_uid=uid)
    with pytest.raises(PermissionError, match=message):
        deploy.validate_lock_metadata(metadata)


def test_lock_rejects_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("", encoding="utf-8")
    target.chmod(0o600)
    lock = tmp_path / "deploy.lock"
    lock.symlink_to(target)

    with pytest.raises(OSError):
        with deploy.deployment_lock(str(lock), expected_uid=os.getuid()):
            pass


def test_lock_creates_missing_private_runtime_directory(tmp_path):
    runtime = tmp_path / "runtime"
    lock = runtime / "deploy.lock"

    with deploy.deployment_lock(str(lock), expected_uid=os.getuid()):
        assert runtime.is_dir()
        assert stat.S_IMODE(runtime.stat().st_mode) == 0o700
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_lock_serializes_concurrent_callers(tmp_path):
    lock = tmp_path / "deploy.lock"
    entered = threading.Event()
    finished = threading.Event()

    def contender():
        with deploy.deployment_lock(str(lock), expected_uid=os.getuid()):
            entered.set()
        finished.set()

    with deploy.deployment_lock(str(lock), expected_uid=os.getuid()):
        thread = threading.Thread(target=contender)
        thread.start()
        assert not entered.wait(0.1)

    thread.join(timeout=1)
    assert entered.is_set()
    assert finished.is_set()


def test_playbook_commands_are_fixed_and_secret_free():
    config = deploy.DeployConfig(
        infisical_domain="https://infisical.example.test",
        infisical_project_id="project-id",
        infisical_environment="prod",
        universal_auth_client_id="client-id-secret-value",
        universal_auth_client_secret="client-secret-value",
    )

    for run_spec in (*deploy.FIXED_RUNS, deploy.FIXED_ROLLBACK):
        command, child_env = deploy.build_playbook_invocation(
            run_spec,
            config,
            SHA,
            INVENTORY_SHA,
            base_env={
                "PATH": "/tmp/runner-controlled",
                "ANSIBLE_CONFIG": "/tmp/runner-ansible.cfg",
                "https_proxy": "http://runner-proxy.invalid",
                "SSL_CERT_FILE": "/tmp/runner-ca.pem",
            },
        )
        assert deploy.FIXED_INVENTORY in command
        assert run_spec.playbook in command
        assert command[command.index("--limit") + 1] == run_spec.limit
        assert command[command.index("--tags") + 1] == run_spec.tags
        assert "client-id-secret-value" not in command
        assert "client-secret-value" not in command
        assert child_env["INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"] == "client-id-secret-value"
        assert child_env["INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"] == "client-secret-value"
        assert child_env["PATH"] == "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
        assert "ANSIBLE_CONFIG" not in child_env
        assert "https_proxy" not in child_env
        assert "SSL_CERT_FILE" not in child_env


def test_external_health_secrets_are_allowlisted_and_only_enter_child_env():
    config = deploy.DeployConfig(
        infisical_domain="https://infisical.example.test",
        infisical_project_id="project-id",
        infisical_environment="prod",
        universal_auth_client_id="universal-client-id",
        universal_auth_client_secret="universal-client-secret",
    )
    calls = []
    results = iter(
        [
            subprocess.CompletedProcess([], 0, stdout="short-lived-token\n", stderr=""),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    '{"CLOUDFLARE_ACCESS_CLIENT_ID": "health-client-id", '
                    '"CLOUDFLARE_ACCESS_CLIENT_SECRET": "health-client-secret", '
                    '"UNRELATED": "must-not-be-forwarded"}'
                ),
                stderr="",
            ),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
    )

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return next(results)

    deploy.run_external_health_check(config, fake_run, {"PATH": "/usr/bin"})

    for command, _kwargs in calls:
        assert "universal-client-secret" not in command
        assert "short-lived-token" not in command
        assert "health-client-secret" not in command
    health_env = calls[-1][1]["env"]
    assert health_env["CLOUDFLARE_ACCESS_CLIENT_ID"] == "health-client-id"
    assert health_env["CLOUDFLARE_ACCESS_CLIENT_SECRET"] == "health-client-secret"
    assert "UNRELATED" not in health_env
    assert "INFISICAL_TOKEN" not in health_env


def test_inventory_is_updated_and_validated_before_it_is_recorded():
    calls = []
    outputs = iter(["", "", INVENTORY_SHA, "", "", "{}"])

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=next(outputs), stderr="")

    inventory_sha = deploy.prepare_private_inventory(fake_run, {"PATH": "/usr/bin"})

    assert inventory_sha == INVENTORY_SHA
    flattened = [call[0] for call in calls]
    assert flattened[0][:4] == ["git", "-C", deploy.INVENTORY_REPO_ROOT, "fetch"]
    assert ["git", "-C", deploy.INVENTORY_REPO_ROOT, "checkout", "--detach", "origin/main"] in flattened
    assert ["pwsh", "-NoProfile", "-File", deploy.INVENTORY_VALIDATOR] in flattened
    assert ["ansible-inventory", "-i", deploy.FIXED_INVENTORY, "--list"] in flattened
    assert flattened.index(["pwsh", "-NoProfile", "-File", deploy.INVENTORY_VALIDATOR]) < flattened.index(
        ["ansible-inventory", "-i", deploy.FIXED_INVENTORY, "--list"]
    )


def test_post_switch_failure_runs_fixed_rollback():
    calls = []

    def playbook_runner(run_spec):
        calls.append(run_spec)
        if run_spec == deploy.FIXED_RUNS[1]:
            raise subprocess.CalledProcessError(1, run_spec.playbook)

    with pytest.raises(subprocess.CalledProcessError):
        deploy.execute_fixed_sequence(playbook_runner, lambda: None)

    assert calls == [deploy.FIXED_RUNS[0], deploy.FIXED_RUNS[1], deploy.FIXED_ROLLBACK]


def test_external_health_failure_runs_fixed_rollback():
    calls = []

    with pytest.raises(RuntimeError, match="health failed"):
        deploy.execute_fixed_sequence(
            calls.append,
            lambda: (_ for _ in ()).throw(RuntimeError("health failed")),
        )

    assert calls == [*deploy.FIXED_RUNS, deploy.FIXED_ROLLBACK]


def test_initial_controller_failure_does_not_run_wrapper_rollback():
    calls = []

    def playbook_runner(run_spec):
        calls.append(run_spec)
        raise subprocess.CalledProcessError(1, run_spec.playbook)

    with pytest.raises(subprocess.CalledProcessError):
        deploy.execute_fixed_sequence(playbook_runner, lambda: None)

    assert calls == [deploy.FIXED_RUNS[0]]


def test_role_installs_only_the_narrow_root_boundary():
    defaults = yaml.safe_load(read("roles/infra_ansible_deployer/defaults/main.yml"))
    tasks = read("roles/infra_ansible_deployer/tasks/main.yml")
    env_template = read(
        "roles/infra_ansible_deployer/templates/infra-ansible-deploy.env.j2"
    )
    sudoers = read(
        "roles/infra_ansible_deployer/templates/infra-ansible-deploy.sudoers.j2"
    )

    script = read("tools/deploy/infra_ansible_deploy.py")
    readme = read("roles/infra_ansible_deployer/README.md")

    assert script.startswith("#!/usr/bin/python3 -I\n")
    assert defaults["infra_ansible_deployer_public_repo_dest"] == "/srv/infra-ansible"
    assert defaults["infra_ansible_deployer_inventory_repo_dest"] == "/srv/infra-ansible-inventory"
    assert defaults["infra_ansible_deployer_edge_ssh_key_path"] == (
        "/etc/infra-ansible-deploy/edge-ssh-key"
    )
    assert "version: \"{{ infra_ansible_deployer_public_sha }}\"" in tasks
    assert "version: \"{{ infra_ansible_deployer_inventory_sha }}\"" in tasks
    assert "dest: /usr/local/sbin/infra-ansible-deploy" in tasks
    assert 'mode: "0755"' in tasks
    assert "dest: /etc/infra-ansible-deploy.env" in tasks
    assert 'mode: "0600"' in tasks
    assert "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET=" in env_template
    assert (
        'content: "{{ '
        'infra_ansible_deployer_runtime_secrets.INFRA_INVENTORY_DEPLOY_KEY }}\\n"'
        in tasks
    )
    assert "ANSIBLE_EDGE_SSH_PRIVATE_KEY" in tasks
    assert (
        'content: "{{ '
        'infra_ansible_deployer_runtime_secrets.ANSIBLE_EDGE_SSH_PRIVATE_KEY }}\\n"'
        in tasks
    )
    assert 'dest: "{{ infra_ansible_deployer_edge_ssh_key_path }}"' in tasks
    assert "Install the dedicated edge SSH private key" in tasks
    edge_key_task = tasks.split("Install the dedicated edge SSH private key", 1)[1].split(
        "- name:", 1
    )[0]
    assert 'owner: root' in edge_key_task
    assert 'group: root' in edge_key_task
    assert 'mode: "0600"' in edge_key_task
    assert "no_log: true" in edge_key_task
    assert "ANSIBLE_EDGE_SSH_PRIVATE_KEY" not in env_template
    assert "runtime_secrets.values() |\n        select('search', '[\\r\\n]')" not in tasks
    assert "Defaults!/usr/local/sbin/infra-ansible-deploy secure_path=" in sudoers
    assert "NOPASSWD:NOSETENV:" in sudoers
    assert "/usr/local/sbin/infra-ansible-deploy ^[0-9a-f]{40}$" in sudoers
    assert "NOPASSWD: ALL" not in tasks + env_template + sudoers
    assert "path: /run/infra-ansible" in tasks
    assert 'mode: "0700"' in tasks

    assert defaults["infra_ansible_deployer_infisical_version"] == "0.43.84"
    assert defaults["infra_ansible_deployer_infisical_sha256"] == (
        "64a47155083c7b8042de64e67eee5629bf894903c102f7239f69c7ed93fdbfc5"
    )
    assert defaults["infra_ansible_deployer_powershell_version"] == "7.6.3"
    assert defaults["infra_ansible_deployer_powershell_sha256"] == (
        "856d0765d2332377f9d7a4aea76efdfde4de51446e7738dde2dfda41dba9e2a7"
    )
    assert "infisical" not in defaults["infra_ansible_deployer_packages"]
    assert "powershell" not in defaults["infra_ansible_deployer_packages"]
    assert tasks.index("Download pinned Infisical CLI archive") < tasks.index(
        "Extract verified Infisical CLI archive"
    )
    assert tasks.index("Download pinned PowerShell archive") < tasks.index(
        "Extract verified PowerShell archive"
    )
    assert "checksum: sha256:{{ infra_ansible_deployer_infisical_sha256 }}" in tasks
    assert "checksum: sha256:{{ infra_ansible_deployer_powershell_sha256 }}" in tasks
    assert "latest" not in (defaults.__repr__() + tasks).lower()
    assert "vendor apt" in readme.lower()
    assert "ANSIBLE_EDGE_SSH_PRIVATE_KEY" in readme
    assert "/etc/infra-ansible-deploy/edge-ssh-key" in readme
