import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = "roles/semaphore_controller"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_yaml(path: str):
    return yaml.safe_load(read(path))


def tasks_in(path: str) -> list[dict]:
    return load_yaml(f"{ROLE}/tasks/{path}")


def task_named(path: str, name: str) -> dict:
    return next(task for task in tasks_in(path) if task["name"] == name)


def test_native_semaphore_contract_is_exact_and_fail_closed():
    defaults_text = read(f"{ROLE}/defaults/main.yml")
    defaults = yaml.safe_load(defaults_text)
    main = read(f"{ROLE}/tasks/main.yml")

    assert defaults["semaphore_controller_enabled"] is False
    assert defaults["semaphore_controller_version"] == "2.18.25"
    assert defaults["semaphore_controller_sha256"] == (
        "209cf89c23710ed74e4568be129690fb5f9599b66f3cdfb55ed6c1a437c94dc9"
    )
    assert defaults["semaphore_controller_release_root"] == "/opt/semaphore/releases"
    assert defaults["semaphore_controller_current_path"] == "/opt/semaphore/current"
    assert defaults["semaphore_controller_config_dir"] == "/etc/semaphore"
    assert defaults["semaphore_controller_port"] == 3000
    assert defaults["semaphore_controller_required_env"] == [
        "SEMAPHORE_DB_PASSWORD",
        "SEMAPHORE_ACCESS_KEY_ENCRYPTION",
        "SEMAPHORE_ADMIN_PASSWORD",
    ]
    assert "PostgreSQL" in main
    assert "http://127.0.0.1:3000/api/ping" in main
    assert "no_log: true" in main


def test_role_requires_debian_13_amd64_one_host_limit_and_exact_tag():
    validation = task_named("main.yml", "Validate narrow Semaphore controller contract")
    assertions = validation["ansible.builtin.assert"]["that"]

    assert "ansible_facts.distribution == 'Debian'" in assertions
    assert "ansible_facts.distribution_major_version == '13'" in assertions
    assert "ansible_facts.architecture in ['x86_64', 'amd64']" in assertions
    assert "ansible_facts.service_mgr == 'systemd'" in assertions
    assert (
        "semaphore_controller_sha256 == "
        "'209cf89c23710ed74e4568be129690fb5f9599b66f3cdfb55ed6c1a437c94dc9'"
    ) in assertions
    assert (
        "semaphore_controller_download_url == "
        "'https://github.com/semaphoreui/semaphore/releases/download/"
        "v2.18.25/semaphore_2.18.25_linux_amd64.deb'"
    ) in assertions
    assert "ansible_limit is defined" in assertions
    assert "ansible_limit | trim == inventory_hostname" in assertions
    assert "ansible_play_hosts_all | length == 1" in assertions
    assert "ansible_play_hosts_all[0] == inventory_hostname" in assertions
    assert (
        "(ansible_run_tags | list | sort) == "
        "(semaphore_controller_expected_run_tags | list | sort)"
    ) in assertions


def test_install_uses_native_pinned_deb_and_immutable_release():
    defaults = load_yaml(f"{ROLE}/defaults/main.yml")
    install = read(f"{ROLE}/tasks/install.yml")
    packages = defaults["semaphore_controller_packages"]

    assert packages == [
        "postgresql",
        "postgresql-client",
        "ca-certificates",
        "curl",
        "git",
        "openssh-client",
        "rsync",
        "age",
        "python3",
        "python3-venv",
        "python3-pexpect",
        "python3-psycopg",
        "python3-boto3",
        "python3-botocore",
    ]
    assert defaults["semaphore_controller_download_url"] == (
        "https://github.com/semaphoreui/semaphore/releases/download/"
        "v{{ semaphore_controller_version }}/"
        "semaphore_{{ semaphore_controller_version }}_linux_amd64.deb"
    )

    download = task_named("install.yml", "Download exact official Semaphore package")
    assert download["ansible.builtin.get_url"]["url"] == (
        "https://github.com/semaphoreui/semaphore/releases/download/"
        "v2.18.25/semaphore_2.18.25_linux_amd64.deb"
    )
    assert download["ansible.builtin.get_url"]["checksum"] == (
        "sha256:209cf89c23710ed74e4568be129690fb5"
        "f9599b66f3cdfb55ed6c1a437c94dc9"
    )
    extraction = task_named("install.yml", "Extract immutable Semaphore release")
    assert extraction["ansible.builtin.command"]["argv"] == [
        "dpkg-deb",
        "--extract",
        "{{ semaphore_controller_download_path }}",
        "{{ semaphore_controller_release_path }}",
    ]
    assert extraction["args"]["creates"] == (
        "{{ semaphore_controller_release_path }}/usr/bin/semaphore"
    )
    assert "ansible.builtin.apt" in install
    assert "state: present" in install


def test_postgresql_and_first_run_setup_keep_secrets_out_of_argv_and_logs():
    configure = read(f"{ROLE}/tasks/configure.yml")
    database_user = task_named("configure.yml", "Create Semaphore PostgreSQL role")
    setup = task_named("configure.yml", "Run first Semaphore setup over protected stdin")

    assert "community.postgresql.postgresql_user" in configure
    assert "community.postgresql.postgresql_db" in configure
    assert database_user["no_log"] is True
    assert database_user["become_user"] == "postgres"
    assert setup["no_log"] is True
    assert setup["ansible.builtin.expect"]["echo"] is False
    assert setup["ansible.builtin.expect"]["command"] == (
        "{{ semaphore_controller_release_path }}/usr/bin/semaphore setup "
        "--config {{ semaphore_controller_config_path }}"
    )
    assert setup["when"] == "not semaphore_controller_setup_marker.stat.exists"
    assert "creates" not in setup["ansible.builtin.expect"]
    responses = setup["ansible.builtin.expect"]["responses"]
    assert any("SEMAPHORE_DB_PASSWORD" in str(value) for value in responses.values())
    assert any("SEMAPHORE_ADMIN_PASSWORD" in str(value) for value in responses.values())
    assert "SEMAPHORE_DB_PASSWORD" not in setup["ansible.builtin.expect"]["command"]
    assert "SEMAPHORE_ADMIN_PASSWORD" not in setup["ansible.builtin.expect"]["command"]

    generated = task_named("configure.yml", "Read setup-generated Semaphore configuration")
    captured = task_named("configure.yml", "Capture setup-generated cookie secrets")
    rendered = task_named("configure.yml", "Render protected Semaphore configuration")
    assert generated["no_log"] is True
    assert captured["no_log"] is True
    assert rendered["no_log"] is True
    assert rendered["ansible.builtin.template"]["mode"] == "0640"


def test_protected_transaction_accepts_only_a_native_multiline_age_identity():
    validation = task_named(
        "main.yml", "Validate protected Semaphore transaction contract"
    )
    conditions = "\n".join(validation["ansible.builtin.assert"]["that"])

    assert "age_identity is match" in conditions
    assert "AGE-SECRET-KEY-1" in conditions
    assert "age_identity is not search('\\r')" in conditions
    assert "minio_access_key is not search('[\\r\\n]')" in conditions
    assert "minio_secret_key is not search('[\\r\\n]')" in conditions
    assert "transaction_environment.values()" not in conditions

    age_condition = next(
        condition for condition in validation["ansible.builtin.assert"]["that"]
        if "age_identity is match" in condition
    )
    age_pattern = re.search(r"match\('(?P<pattern>.+)'\)$", age_condition)[
        "pattern"
    ]
    valid_identities = (
        "AGE-SECRET-KEY-1ABC123",
        "# created: 2026-07-12\n"
        "# public key: age1example\n"
        "AGE-SECRET-KEY-1ABC123",
    )
    invalid_identities = (
        "AGE-SECRET-KEY-1ABC123\r\n",
        "AGE-SECRET-KEY-1ABC123\nAGE-SECRET-KEY-1DEF456",
        "prefix\nAGE-SECRET-KEY-1ABC123",
        "AGE-SECRET-KEY-1ABC123\nsuffix",
        "AGE-SECRET-KEY-1ABC123 extra",
    )
    assert all(re.fullmatch(age_pattern, value) for value in valid_identities)
    assert not any(re.fullmatch(age_pattern, value) for value in invalid_identities)
    assert validation["ansible.builtin.assert"]["fail_msg"] == (
        "The public backup recipient, MinIO contract, native age identity, "
        "and single-line MinIO credentials are required."
    )


def test_service_activation_is_atomic_and_health_requires_200_pong():
    main = task_named("main.yml", "Require local Semaphore health")
    configure = read(f"{ROLE}/tasks/configure.yml")
    unit = read(f"{ROLE}/templates/semaphore.service.j2")
    readme = read(f"{ROLE}/README.md")

    assert main["ansible.builtin.uri"]["url"] == (
        "http://127.0.0.1:3000/api/ping"
    )
    assert main["ansible.builtin.uri"]["status_code"] == 200
    assert main["ansible.builtin.uri"]["return_content"] is True
    assert "semaphore_controller_health.content == 'pong'" in main["until"]
    assert all("trim" not in condition for condition in main["until"])
    assert "without trimming or whitespace normalization" in readme
    assert "{{ semaphore_controller_current_path }}.next" in configure
    activation = task_named("configure.yml", "Atomically activate exact Semaphore release")
    assert activation["ansible.builtin.command"]["argv"][0:2] == [
        "mv",
        "--no-target-directory",
    ]
    assert activation["changed_when"] is True
    assert (
        "{{ semaphore_controller_current_path }}/usr/bin/semaphore server "
        "--config={{ semaphore_controller_config_path }}"
    ) in unit
    assert "User={{ semaphore_controller_user }}" in unit


def test_setup_completion_state_is_root_controlled_outside_service_state():
    defaults = load_yaml(f"{ROLE}/defaults/main.yml")
    install = task_named("install.yml", "Create persistent Semaphore directories")
    configure = read(f"{ROLE}/tasks/configure.yml")
    marker = task_named("configure.yml", "Record successful first Semaphore setup")

    assert defaults["semaphore_controller_setup_state_dir"] == (
        "/var/lib/infra-ansible/semaphore"
    )
    assert defaults["semaphore_controller_setup_marker_path"] == (
        "{{ semaphore_controller_setup_state_dir }}/setup-complete"
    )
    setup_directory = next(
        item
        for item in install["loop"]
        if item["path"] == "{{ semaphore_controller_setup_state_dir }}"
    )
    assert setup_directory == {
        "path": "{{ semaphore_controller_setup_state_dir }}",
        "owner": "root",
        "group": "postgres",
        "mode": "0710",
    }
    assert "{{ semaphore_controller_setup_marker_path }}" in configure
    assert "{{ semaphore_controller_state_dir }}/.setup-complete" not in configure
    assert marker["ansible.builtin.file"]["path"] == (
        "{{ semaphore_controller_setup_marker_path }}"
    )
    assert marker["ansible.builtin.file"]["owner"] == "root"
    assert marker["ansible.builtin.file"]["group"] == "root"
    assert marker["ansible.builtin.file"]["mode"] == "0600"


def test_role_has_no_container_runtime_dependency():
    role_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / ROLE).rglob("*")
        if path.is_file()
    )
    assert "docker" not in role_text.lower()
