import json
import os
import subprocess
from pathlib import Path

import jinja2
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = "roles/protocolos_edge_route"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_yaml(path: str):
    return yaml.safe_load(read(path))


def task_named(tasks: list[dict], name: str) -> dict:
    return next(task for task in tasks if task["name"] == name)


def run_role(
    tmp_path: Path,
    variables: dict | None = None,
    *,
    host: str = "nginx",
    limit: str | None = None,
) -> subprocess.CompletedProcess:
    playbook = tmp_path / "protocolos-edge-route.yml"
    playbook.write_text(
        f"""---
- name: Exercise protocolos edge route
  hosts: {host}
  connection: local
  gather_facts: false
  tasks:
    - name: Import protocolos edge route
      ansible.builtin.import_role:
        name: protocolos_edge_route
""",
        encoding="utf-8",
    )
    command = [
            "ansible-playbook",
            "-i",
            f"{host},",
            str(playbook),
            "--extra-vars",
            json.dumps(variables or {}),
    ]
    if limit is not None:
        command.extend(["--limit", limit])
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_disabled_role_ends_without_operational_preflight(tmp_path):
    result = run_role(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Preflight Protocolos upstream" not in result.stdout
    assert "Install Protocolos Nginx route candidate" not in result.stdout


def test_playbook_applies_shared_and_dedicated_tags_to_protocolos_role():
    play = load_yaml("playbooks/edge-proxy-route.yml")[0]
    protocolos_role = next(
        role
        for role in play["roles"]
        if role["role"] == "protocolos_edge_route"
    )

    assert protocolos_role["tags"] == ["edge_proxy_route", "protocolos_edge_route"]


def test_enabled_role_requires_explicit_per_run_approval_before_any_preflight(
    tmp_path,
):
    result = run_role(
        tmp_path,
        {"protocolos_edge_route_enabled": True, **PROTOCOLS_SERVICE_CONTRACT},
        limit="nginx",
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "explicit per-run approval" in output
    assert "Preflight Protocolos upstream" not in output
    assert "Render Protocolos Nginx route candidate" not in output
    assert "Atomically install Protocolos Nginx route candidate" not in output


@pytest.mark.parametrize(
    ("host", "limit"),
    [("nginx", None), ("not-nginx", "not-nginx")],
)
def test_enabled_role_requires_exact_nginx_limit_before_any_preflight(
    tmp_path, host, limit
):
    result = run_role(
        tmp_path,
        {
            "protocolos_edge_route_enabled": True,
            "protocolos_edge_route_apply": True,
            **PROTOCOLS_SERVICE_CONTRACT,
        },
        host=host,
        limit=limit,
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "exact --limit nginx" in output
    assert "Preflight Protocolos upstream" not in output
    assert "Render Protocolos Nginx route candidate" not in output
    assert "Atomically install Protocolos Nginx route candidate" not in output


@pytest.mark.parametrize(
    "variables",
    [
        {"protocolos_edge_route_domain": "other.example"},
        {"protocolos_edge_route_upstream_address": "192.168.1.200"},
        {"protocolos_edge_route_upstream_port": 8181},
        {"protocolos_edge_route_vmid": 105},
        {"protocolos_edge_route_node": "pve-02"},
        {"protocolos_edge_route_vm_name": "OtherService"},
        {"protocolos_edge_route_vm_mac": "BC:24:11:D1:92:1C"},
        {"protocolos_edge_route_certificate_path": "/tmp/fullchain.pem"},
        {"protocolos_edge_route_private_key_path": "/tmp/privkey.pem"},
        {"protocolos_edge_route_config_path": "/etc/nginx/other.conf"},
        {"protocolos_edge_route_enabled_path": "/etc/nginx/other-enabled.conf"},
    ],
)
def test_enabled_role_rejects_contract_deviation_before_operational_preflight(
    tmp_path, variables
):
    variables = {"protocolos_edge_route_enabled": True, **variables}
    result = run_role(
        tmp_path,
        variables,
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "exact Protocolos VM 104 edge contract" in output
    assert "Preflight Protocolos upstream" not in output


def test_defaults_pin_the_disabled_vm104_route_contract():
    defaults = load_yaml(f"{ROLE}/defaults/main.yml")

    assert defaults == {
        "protocolos_edge_route_enabled": False,
        "protocolos_edge_route_apply": False,
        "protocolos_edge_route_domain": "protocolos.portosoftware.com.br",
        "protocolos_edge_route_upstream_address": "192.168.1.199",
        "protocolos_edge_route_upstream_port": 80,
        "protocolos_edge_route_upstream": "http://192.168.1.199:80",
        "protocolos_edge_route_vmid": 104,
        "protocolos_edge_route_node": "pve-01",
        "protocolos_edge_route_vm_name": "SistemaDeProtocolos",
        "protocolos_edge_route_vm_mac": "BC:24:11:D1:92:1B",
        "protocolos_edge_route_certificate_path": (
            "/etc/letsencrypt/live/protocolos.portosoftware.com.br/fullchain.pem"
        ),
        "protocolos_edge_route_private_key_path": (
            "/etc/letsencrypt/live/protocolos.portosoftware.com.br/privkey.pem"
        ),
        "protocolos_edge_route_config_path": (
            "/etc/nginx/sites-available/protocolos.portosoftware.com.br"
        ),
        "protocolos_edge_route_enabled_path": (
            "/etc/nginx/sites-enabled/protocolos.portosoftware.com.br"
        ),
        "protocolos_edge_route_candidate_path": (
            "/etc/nginx/sites-available/protocolos.portosoftware.com.br.candidate"
        ),
        "protocolos_edge_route_restore_candidate_path": (
            "/etc/nginx/sites-available/protocolos.portosoftware.com.br.restore"
        ),
        "protocolos_edge_route_probe_retries": 12,
        "protocolos_edge_route_probe_delay": 5,
        **PROTOCOLS_SERVICE_CONTRACT,
    }

    for duplicate_name in (
        "protocolos_edge_route_vmid",
        "protocolos_edge_route_node",
        "protocolos_edge_route_vm_name",
        "protocolos_edge_route_vm_mac",
    ):
        assert duplicate_name not in defaults


def test_template_enforces_exact_redirect_and_tls_proxy_behavior():
    template = jinja2.Template(read(f"{ROLE}/templates/protocolos-edge-route.conf.j2"))
    rendered = template.render(
        protocolos_edge_route_domain="protocolos.portosoftware.com.br",
        protocolos_edge_route_upstream="http://192.168.1.199:80",
        protocolos_edge_route_certificate_path=(
            "/etc/letsencrypt/live/protocolos.portosoftware.com.br/fullchain.pem"
        ),
        protocolos_edge_route_private_key_path=(
            "/etc/letsencrypt/live/protocolos.portosoftware.com.br/privkey.pem"
        ),
    )

    servers = [block for block in rendered.split("server {") if block.strip()]
    assert len(servers) == 2
    http_server, tls_server = servers
    assert "listen 80;" in http_server
    assert "return 301 https://$host$request_uri;" in http_server
    assert "listen 443 ssl;" in tls_server
    assert "client_max_body_size 20m;" in tls_server
    assert "location / {" in tls_server
    assert "proxy_pass http://192.168.1.199:80;" in tls_server
    assert "proxy_set_header Upgrade $http_upgrade;" in tls_server
    assert 'proxy_set_header Connection "upgrade";' in tls_server
    for timeout in ("proxy_connect_timeout 60s;", "proxy_send_timeout 3600s;", "proxy_read_timeout 3600s;"):
        assert timeout in tls_server
    assert "8181" not in rendered


def test_role_preflights_existing_certificate_san_timer_and_http_upstream():
    tasks = load_yaml(f"{ROLE}/tasks/main.yml")
    names = [task["name"] for task in tasks]
    contract = read(f"{ROLE}/tasks/main.yml")

    assert "\n      - certbot\n" not in contract
    assert names.index("Preflight Protocolos upstream over HTTP") < names.index(
        "Render Protocolos Nginx route candidate"
    )
    assert names.index("Validate exact Protocolos certificate SAN") < names.index(
        "Render Protocolos Nginx route candidate"
    )
    upstream = task_named(tasks, "Preflight Protocolos upstream over HTTP")
    assert upstream["ansible.builtin.uri"]["url"] == "{{ protocolos_edge_route_upstream }}"
    assert upstream["ansible.builtin.uri"]["status_code"] == 200
    timer = task_named(tasks, "Require enabled certbot renewal timer")
    assert timer["ansible.builtin.command"]["argv"] == [
        "systemctl",
        "is-enabled",
        "certbot.timer",
    ]
    san = task_named(tasks, "Read Protocolos certificate subject alternative names")
    assert san["ansible.builtin.command"]["argv"][-2:] == ["-ext", "subjectAltName"]


def test_transaction_installs_symlink_validates_reloads_and_rolls_back_both_states():
    tasks = load_yaml(f"{ROLE}/tasks/main.yml")
    transaction_tasks = load_yaml(f"{ROLE}/tasks/transaction.yml")
    transaction = task_named(
        transaction_tasks, "Install and verify Protocolos Nginx route"
    )
    block_names = [task["name"] for task in transaction["block"]]
    rescue_names = [task["name"] for task in transaction["rescue"]]
    top_level_names = [task["name"] for task in tasks]

    assert top_level_names.index("Back up preceding Protocolos Nginx route") < top_level_names.index(
        "Install and verify Protocolos Nginx route"
    )
    backup = task_named(tasks, "Back up preceding Protocolos Nginx route")
    assert backup["ansible.builtin.copy"]["dest"] == (
        "{{ protocolos_edge_route_config_path }}."
        "{{ protocolos_edge_route_backup_timestamp.stdout }}.bak"
    )
    assert block_names.index("Atomically install Protocolos Nginx route candidate") < block_names.index(
        "Ensure Protocolos Nginx route symlink"
    ) < block_names.index("Validate installed Protocolos Nginx configuration") < block_names.index(
        "Reload installed Protocolos Nginx configuration"
    )
    assert block_names[-4:] == [
        "Probe Protocolos HTTP redirect",
        "Probe Protocolos HTTPS root",
        "Probe Protocolos HTTPS CSRF endpoint",
        "Probe Protocolos HTTPS health endpoint",
    ]
    assert rescue_names.index("Restore preceding Protocolos Nginx route") < rescue_names.index(
        "Restore preceding Protocolos Nginx symlink state"
    ) < rescue_names.index("Revalidate restored Protocolos Nginx configuration") < rescue_names.index(
        "Reload restored Protocolos Nginx configuration"
    )
    assert transaction["rescue"][-1]["ansible.builtin.fail"]
    assert "state: link" in read(f"{ROLE}/tasks/main.yml")
    assert "mv" in read(f"{ROLE}/tasks/main.yml")


def test_probes_accept_the_required_public_statuses_only():
    tasks = load_yaml(f"{ROLE}/tasks/transaction.yml")
    block = task_named(tasks, "Install and verify Protocolos Nginx route")["block"]

    expected = {
        "Probe Protocolos HTTP redirect": ("http://127.0.0.1/", 301),
        "Probe Protocolos HTTPS root": ("https://127.0.0.1/", 200),
        "Probe Protocolos HTTPS CSRF endpoint": (
            "https://127.0.0.1/api/auth/csrf",
            200,
        ),
        "Probe Protocolos HTTPS health endpoint": (
            "https://127.0.0.1/api/health",
            401,
        ),
    }
    for name, (url, status) in expected.items():
        probe = task_named(block, name)["ansible.builtin.uri"]
        assert probe["url"] == url
        assert probe["status_code"] == status
        assert probe["headers"] == {"Host": "{{ protocolos_edge_route_domain }}"}
