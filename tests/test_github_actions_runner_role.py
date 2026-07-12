from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def role_tasks() -> list[dict]:
    return yaml.safe_load(read("roles/github_actions_runner/tasks/main.yml"))


def task_named(name: str) -> dict:
    return next(task for task in role_tasks() if task["name"] == name)


def test_runner_role_is_reusable_and_secret_safe():
    defaults = read("roles/github_actions_runner/defaults/main.yml")
    tasks = read("roles/github_actions_runner/tasks/main.yml")
    assert "github_actions_runner_version: 2.335.1" in defaults
    assert (
        "github_actions_runner_sha256_x64: "
        "4ef2f25285f0ae4477f1fe1e346db76d2f3ebf03824e2ddd1973a2819bf6c8cf"
    ) in defaults
    assert "GITHUB_ACTIONS_RUNNER_REGISTRATION_TOKEN" in tasks
    assert "no_log: true" in tasks
    assert "ansible_service_mgr == 'systemd'" in tasks
    assert "semaphore" not in tasks.lower()
    assert "NOPASSWD: ALL" not in tasks


def test_runner_role_validates_supported_platforms_and_bootstrap_token():
    platform = task_named("Validate GitHub Actions runner platform")
    assertions = platform["ansible.builtin.assert"]["that"]
    assert "ansible_os_family == 'Debian'" in assertions
    assert "ansible_distribution in ['Debian', 'Ubuntu']" in assertions
    assert "ansible_service_mgr == 'systemd'" in assertions

    token = task_named("Validate registration token for an unconfigured runner")
    assert token["when"] == "not github_actions_runner_configured.stat.exists"
    assert token["no_log"] is True


def test_runner_role_pins_archive_and_registers_only_once():
    defaults = read("roles/github_actions_runner/defaults/main.yml")
    default_values = yaml.safe_load(defaults)
    tasks = read("roles/github_actions_runner/tasks/main.yml")
    assert default_values["github_actions_runner_architecture_map"] == {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    assert default_values["github_actions_runner_labels"] == [
        "ansible-prod",
        "linux",
        "{{ github_actions_runner_architecture }}",
    ]
    assert default_values["github_actions_runner_checksum_map"] == {
        "x64": "{{ github_actions_runner_sha256_x64 }}",
        "arm64": "{{ github_actions_runner_sha256_arm64 }}",
    }
    assert "checksum: sha256:{{ github_actions_runner_archive_sha256 }}" in tasks

    registration = task_named("Register repository runner once")
    command = registration["ansible.builtin.command"]
    assert command["argv"][0] == "./config.sh"
    assert "--unattended" in command["argv"]
    assert "--replace" in command["argv"]
    assert registration["args"]["creates"] == "{{ github_actions_runner_home }}/.runner"
    assert registration["become_user"] == "{{ github_actions_runner_user }}"
    assert registration["no_log"] is True


def test_runner_role_installs_and_manages_generated_systemd_service():
    tasks = read("roles/github_actions_runner/tasks/main.yml")
    handlers = read("roles/github_actions_runner/handlers/main.yml")
    readme = read("roles/github_actions_runner/README.md")
    assert "./svc.sh" in tasks
    assert "ansible.builtin.systemd_service" in tasks
    assert "state: started" in tasks
    assert "enabled: true" in tasks
    assert "daemon_reload: true" in handlers
    assert "self-update" in readme.lower()
    assert "semaphore" not in (tasks + handlers + readme).lower()

    start = task_named("Start runner through its generated service helper")
    assert start["ansible.builtin.command"]["argv"] == ["./svc.sh", "start"]
    assert start["changed_when"] is True


def test_matrix_validates_registration_metadata_and_tracks_cleanup_before_start():
    matrix = read("tests/Validate-GitHubRunnerMatrix.ps1")
    assert "ConvertFrom-Json" in matrix
    assert '$RunnerMetadata.name -ne "matrix-runner"' in matrix
    assert '"amd64" { "x64" }' in matrix
    assert '"arm64" { "arm64" }' in matrix
    assert (
        '$ExpectedRunnerLabels = "ansible-prod,linux,$ExpectedRunnerArchitecture"'
        in matrix
    )
    assert "$RunnerMetadata.labels -ne $ExpectedRunnerLabels" in matrix
    assert '$RunnerMetadata.work -ne "/var/lib/github-actions-runner"' in matrix
    assert "Invoke-Docker exec" not in matrix
    assert '"mkdir", "-p", "/tmp/ansible/roles"' in matrix
    assert '"$($Case.Container):/tmp/ansible/roles/"' in matrix
    assert '"ansible-playbook", "-i", "localhost,"' in matrix

    cleanup_tracking = matrix.index("$Containers.Add($Case.Container)")
    container_start = matrix.index("Invoke-Docker -Arguments $RunArguments")
    assert cleanup_tracking < container_start
