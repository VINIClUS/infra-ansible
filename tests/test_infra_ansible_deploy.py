import subprocess
from pathlib import Path

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

    assert defaults["infra_ansible_deployer_public_repo_dest"] == "/srv/infra-ansible"
    assert defaults["infra_ansible_deployer_inventory_repo_dest"] == "/srv/infra-ansible-inventory"
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
    assert "runtime_secrets.values() |\n        select('search', '[\\r\\n]')" not in tasks
    assert sudoers.strip() == (
        "github-runner ALL=(root) NOPASSWD: "
        "/usr/local/sbin/infra-ansible-deploy [0-9a-f]*"
    )
    assert "NOPASSWD: ALL" not in tasks + env_template + sudoers
