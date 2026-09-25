import json
import os
import subprocess
from pathlib import Path

import jinja2
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = "roles/esusdata_service"
RELEASE_SIGNERS = "release@observatorio-aps"
RELEASE_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPO8idi+sUZof5UFgdptQzEA8uWXHJmwqQh656Bapi30"
)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_yaml(path: str):
    return yaml.safe_load(read(path))


def task_names(path: str) -> list[str]:
    return [task["name"] for task in load_yaml(path)]


def task_named(tasks: list[dict], name: str) -> dict:
    return next(task for task in tasks if task["name"] == name)


def render(template: str, variables: dict) -> str:
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(ROOT / ROLE / "templates"),
        keep_trailing_newline=True,
        trim_blocks=True,
        undefined=jinja2.StrictUndefined,
    )
    environment.filters["regex_escape"] = lambda value: value.replace(".", "\\.")
    return environment.get_template(template).render(**variables)


def run_role(
    tmp_path: Path,
    variables: dict,
    *,
    limit: str | None = "esusdata-lxc",
    tags: str = "esusdata_service",
) -> subprocess.CompletedProcess:
    playbook = tmp_path / "esusdata-service.yml"
    playbook.write_text(
        """---
- name: Exercise esusdata service
  hosts: esusdata-lxc
  connection: local
  gather_facts: false
  tasks:
    - name: Import esusdata service
      ansible.builtin.import_role:
        name: esusdata_service
      tags: [esusdata_service]
""",
        encoding="utf-8",
    )
    facts = {
        "ansible_facts": {"os_family": "Debian"},
        "ansible_service_mgr": "systemd",
    }
    command = [
        "ansible-playbook",
        "-i",
        "esusdata-lxc,",
        str(playbook),
        "--tags",
        tags,
        "--extra-vars",
        json.dumps({**facts, **variables}),
    ]
    if limit is not None:
        command.extend(["--limit", limit])
    return subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, "ANSIBLE_ROLES_PATH": str(ROOT / "roles")},
        capture_output=True,
        text=True,
        check=False,
    )


TLS_ROOT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

ENABLED = {
    "esusdata_service_enabled": True,
    "esusdata_service_pec_tls_root_cert": TLS_ROOT,
    "esusdata_service_version": "0.1.2",
    "esusdata_service_pec_destinations": ["192.168.1.253:5433"],
    "esusdata_service_pec_env": "PEC_DB_PASSWORD=secret",
}


def test_defaults_are_disabled_and_pin_the_release_trust_anchor():
    defaults = load_yaml(f"{ROLE}/defaults/main.yml")

    assert defaults["esusdata_service_enabled"] is False
    assert defaults["esusdata_service_version"] == ""
    assert defaults["esusdata_service_pec_env"] == ""
    assert defaults["esusdata_service_signer_identity"] == RELEASE_SIGNERS
    assert defaults["esusdata_service_signer_public_key"] == RELEASE_PUBLIC_KEY
    assert defaults["esusdata_service_release_base_url"] == (
        "https://github.com/VINIClUS/esusdata/releases/download"
    )


def test_trust_store_matches_the_esusdata_allowed_signers_format():
    rendered = render(
        "allowed_signers.j2",
        {
            "esusdata_service_signer_identity": RELEASE_SIGNERS,
            "esusdata_service_signer_public_key": RELEASE_PUBLIC_KEY,
        },
    )

    assert rendered == f'{RELEASE_SIGNERS} namespaces="file" {RELEASE_PUBLIC_KEY}\n'


def test_disabled_role_ends_before_any_contract_or_host_change(tmp_path):
    result = run_role(tmp_path, {}, limit=None, tags="all")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Validate narrow esusdata deployment contract" not in result.stdout


@pytest.mark.parametrize(
    ("overrides", "limit", "tags"),
    [
        ({"esusdata_service_version": "v0.1.2"}, "esusdata-lxc", "esusdata_service"),
        ({"esusdata_service_version": "latest"}, "esusdata-lxc", "esusdata_service"),
        ({"esusdata_service_pec_destinations": []}, "esusdata-lxc", "esusdata_service"),
        ({"esusdata_service_signer_public_key": "ssh-rsa AAAA"}, "esusdata-lxc", "esusdata_service"),
        ({"esusdata_service_pec_tls_root_cert": ""}, "esusdata-lxc", "esusdata_service"),
        ({"esusdata_service_listen_port": 8081}, "esusdata-lxc", "esusdata_service"),
        ({"esusdata_service_pec_tls_root_cert": "not a pem"}, "esusdata-lxc", "esusdata_service"),
        ({}, None, "esusdata_service"),
        ({}, "all", "esusdata_service"),
        ({}, "esusdata-lxc", "all"),
    ],
)
def test_enabled_role_rejects_contract_deviation_before_any_change(
    tmp_path, overrides, limit, tags
):
    result = run_role(tmp_path, {**ENABLED, **overrides}, limit=limit, tags=tags)

    assert result.returncode != 0
    assert "Install esusdata host dependencies" not in result.stdout
    assert "esusdata deployment requires Debian systemd" in result.stdout


@pytest.mark.parametrize("secret", ["", "not a key value line", "A=1\nbad line"])
def test_enabled_role_rejects_malformed_secret_without_logging_it(tmp_path, secret):
    result = run_role(tmp_path, {**ENABLED, "esusdata_service_pec_env": secret})

    assert result.returncode != 0
    assert "Install esusdata host dependencies" not in result.stdout
    assert "not a key value line" not in result.stdout + result.stderr


def test_signature_and_checksum_are_verified_before_any_install():
    names = task_names(f"{ROLE}/tasks/main.yml")

    order = [
        "Install the pinned esusdata release trust store",
        "Download the signed esusdata release manifest",
        "Verify the esusdata manifest signature against the pinned signer",
        "Select the package checksum from the verified manifest",
        "Require the package in the verified manifest",
        "Download the esusdata package pinned to the verified checksum",
        "Install and verify the esusdata release",
    ]
    assert [name for name in names if name in order] == order

    tasks = load_yaml(f"{ROLE}/tasks/main.yml")
    verify = task_named(tasks, "Verify the esusdata manifest signature against the pinned signer")
    argv = verify["ansible.builtin.command"]["argv"]
    assert argv[:3] == ["ssh-keygen", "-Y", "verify"]
    assert argv[argv.index("-f") + 1] == "{{ esusdata_service_allowed_signers_path }}"
    assert argv[argv.index("-n") + 1] == "file"
    assert verify["ansible.builtin.command"]["stdin_add_newline"] is False
    package = task_named(tasks, "Download the esusdata package pinned to the verified checksum")
    assert package["ansible.builtin.get_url"]["checksum"] == (
        "sha256:{{ esusdata_service_deb_sha256 }}"
    )


def test_install_block_rolls_back_to_the_cached_preceding_release():
    install = load_yaml(f"{ROLE}/tasks/install.yml")[0]
    block = [task["name"] for task in install["block"]]
    rescue = [task["name"] for task in install["rescue"]]

    assert block[:2] == [
        "Install the verified esusdata package",
        "Require the installed esusdata version to match the release",
    ]
    version = task_named(
        install["block"], "Require the installed esusdata version to match the release"
    )
    assert "esusdata_service_version" in version["failed_when"]
    assert block[-2:] == [
        "Wait for esusdata readiness",
        "Drop the superseded PEC secret copy once the release is ready",
    ]
    assert rescue == [
        "Restore the preceding esusdata configuration",
        "Restore the preceding PEC TLS root certificate",
        "Restore the preceding PEC secret file",
        "Restore the preceding esusdata ingress rules",
        "Reload the preceding esusdata ingress rules",
        "Reinstall the preceding esusdata package",
        "Restart the preceding esusdata release",
        "Wait for the preceding esusdata release",
        "Stop the esusdata release that has no predecessor",
        "Remove the esusdata release that has no predecessor",
        "Report the failed esusdata release",
    ]
    secret = task_named(install["block"], "Install the PEC secret file for the service user only")
    assert secret["no_log"] is True
    assert secret["ansible.builtin.copy"]["owner"] == "observatorio"
    assert secret["ansible.builtin.copy"]["mode"] == "0600"
    assert secret["ansible.builtin.copy"]["backup"] is True
    restore = task_named(install["rescue"], "Restore the preceding PEC secret file")
    assert restore["no_log"] is True
    assert restore["ansible.builtin.copy"]["src"] == "{{ esusdata_service_secret.backup_file }}"
    ready = task_named(install["block"], "Wait for esusdata readiness")
    assert ready["ansible.builtin.uri"]["url"].endswith("/api/v1/ready")


def test_configuration_publishes_only_through_the_trusted_edge():
    rendered = yaml.safe_load(
        render(
            "application.yml.j2",
            {
                "esusdata_service_pec_destinations": ["192.168.1.253:5433"],
                "esusdata_service_secret_path": "/etc/observatorio-aps/pec.env",
                "esusdata_service_pec_tls_root_cert_path": "/etc/observatorio-aps/pec-ca.pem",
                "esusdata_service_public_host": "pe.esusdata.com",
                "esusdata_service_listen_port": 8080,
                "esusdata_service_trusted_proxy": "192.168.1.139",
            },
        )
    )

    assert rendered == {
        "observatorio": {
            "source": {
                "allowed-destinations": ["192.168.1.253:5433"],
                "secret-file": "/etc/observatorio-aps/pec.env",
                "tls-root-cert": "/etc/observatorio-aps/pec-ca.pem",
            },
            "web": {
                "allowed-hosts": ["pe.esusdata.com", "127.0.0.1:8080"],
                "allowed-origins": ["https://pe.esusdata.com"],
            },
        },
        "server": {
            "address": "0.0.0.0",
            "port": 8080,
            "forward-headers-strategy": "native",
            "tomcat": {"remoteip": {"internal-proxies": "192\\.168\\.1\\.139"}},
        },
    }


def test_firewall_admits_the_service_port_only_from_loopback_and_edge():
    rendered = render(
        "nftables.conf.j2",
        {
            "esusdata_service_listen_port": 8080,
            "esusdata_service_trusted_proxy": "192.168.1.139",
        },
    )

    assert (
        "tcp dport 8080 ip saddr { 127.0.0.1, 192.168.1.139 } accept" in rendered
    )
    assert "tcp dport 8080 drop" in rendered


def test_playbook_targets_only_the_esusdata_group_with_one_tag():
    play = load_yaml("playbooks/esusdata-service.yml")[0]

    assert play["hosts"] == "esusdata_service_hosts"
    assert play["become"] is True
    assert play["roles"] == [{"role": "esusdata_service", "tags": ["esusdata_service"]}]
