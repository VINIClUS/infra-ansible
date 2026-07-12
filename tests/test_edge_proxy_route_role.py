import json
import re
import subprocess
from pathlib import Path

import jinja2
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = "roles/edge_proxy_route"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_yaml(path: str):
    return yaml.safe_load(read(path))


def task_named(tasks: list[dict], name: str) -> dict:
    return next(task for task in tasks if task["name"] == name)


def validate_controller_address(tmp_path: Path, address: str) -> subprocess.CompletedProcess:
    playbook = tmp_path / "validate-edge-proxy-address.yml"
    playbook.write_text(
        """---
- name: Validate edge proxy address fixture
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Import edge proxy route validation
      ansible.builtin.import_role:
        name: edge_proxy_route
""",
        encoding="utf-8",
    )
    return subprocess.run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            str(playbook),
            "--tags",
            "edge_proxy_route_validate",
            "--extra-vars",
            json.dumps({"edge_proxy_route_controller_address": address}),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_route_is_explicit_websocket_safe_and_uses_both_origin_listeners():
    template = read(f"{ROLE}/templates/nginx-route.conf.j2")

    for expected in (
        "listen 80;",
        "listen 443 ssl;",
        "server_name {{ edge_proxy_route_domain }};",
        "proxy_http_version 1.1;",
        "proxy_set_header Upgrade $http_upgrade;",
        'proxy_set_header Connection "upgrade";',
        "proxy_set_header Host $host;",
        "proxy_set_header X-Real-IP $remote_addr;",
        "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "proxy_set_header X-Forwarded-Proto $scheme;",
        "proxy_read_timeout 3600s;",
        "proxy_pass {{ edge_proxy_route_upstream }};",
    ):
        assert expected in template

    assert "default_server" not in template


def test_defaults_pin_the_public_host_and_exact_controller_upstream():
    defaults = load_yaml(f"{ROLE}/defaults/main.yml")

    assert defaults["edge_proxy_route_domain"] == "ansible.vinisantana.com"
    assert defaults["edge_proxy_route_controller_address"] == ""
    assert defaults["edge_proxy_route_upstream_port"] == 3000
    assert defaults["edge_proxy_route_upstream"] == (
        "http://{{ edge_proxy_route_controller_address }}:"
        "{{ edge_proxy_route_upstream_port }}"
    )


def test_transaction_orders_candidate_backup_install_validation_and_reload():
    tasks = load_yaml(f"{ROLE}/tasks/main.yml")
    handlers = load_yaml(f"{ROLE}/handlers/main.yml")
    transaction = task_named(tasks, "Install and verify managed Nginx route")
    block = transaction["block"]
    block_names = [task["name"] for task in block]
    handler_names = [handler["name"] for handler in handlers]
    install = task_named(block, "Atomically install Nginx route candidate")

    top_level_names = [task["name"] for task in tasks]
    assert top_level_names.index("Render Nginx route candidate") < top_level_names.index(
        "Back up preceding managed Nginx route"
    )
    assert top_level_names.index("Back up preceding managed Nginx route") < (
        top_level_names.index("Install and verify managed Nginx route")
    )
    assert block_names.index("Atomically install Nginx route candidate") < (
        block_names.index("Run pending Nginx route handlers")
    )
    assert handler_names == [
        "Validate installed Nginx configuration",
        "Reload Nginx after successful validation",
    ]
    assert install["when"] == "edge_proxy_route_changed"
    assert install["notify"] == "Validate and reload Nginx route"
    assert handlers[0]["ansible.builtin.command"]["argv"] == ["nginx", "-t"]
    assert handlers[0]["changed_when"] is True
    assert handlers[0]["listen"] == "Validate and reload Nginx route"
    assert handlers[0]["notify"] == "Reload Nginx after successful validation"
    assert handlers[1]["ansible.builtin.systemd_service"]["state"] == "reloaded"


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.0",
        "10.255.255.255",
        "172.16.0.0",
        "172.31.255.255",
        "192.168.0.0",
        "192.168.255.255",
    ],
)
def test_controller_address_accepts_rfc1918_private_ipv4(tmp_path, address):
    result = validate_controller_address(tmp_path, address)

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "address",
    [
        "",
        "0.0.0.0",
        "8.8.8.8",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.0.1",
        "172.15.255.255",
        "172.32.0.0",
        "192.169.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "010.0.0.1",
        "10.0.0.1/24",
        "10.0.0.1.evil",
        "prefix10.0.0.1",
    ],
)
def test_controller_address_rejects_non_rfc1918_or_trick_values(tmp_path, address):
    result = validate_controller_address(tmp_path, address)

    assert result.returncode != 0, result.stdout + result.stderr


def test_rescue_restores_preceding_route_or_removes_new_route_then_revalidates():
    tasks = load_yaml(f"{ROLE}/tasks/main.yml")
    transaction = task_named(tasks, "Install and verify managed Nginx route")
    rescue = transaction["rescue"]
    rescue_names = [task["name"] for task in rescue]

    assert rescue_names.index("Stage preceding Nginx route for restoration") < (
        rescue_names.index("Atomically restore preceding Nginx route")
    )
    assert rescue_names.index("Atomically restore preceding Nginx route") < (
        rescue_names.index("Revalidate restored Nginx configuration")
    )
    assert rescue_names.index("Remove newly managed Nginx route") < (
        rescue_names.index("Revalidate restored Nginx configuration")
    )
    assert rescue_names.index("Revalidate restored Nginx configuration") < (
        rescue_names.index("Reload restored Nginx configuration")
    )
    revalidate = task_named(rescue, "Revalidate restored Nginx configuration")
    assert revalidate["ansible.builtin.command"]["argv"] == ["nginx", "-t"]
    restored_reload = task_named(rescue, "Reload restored Nginx configuration")
    assert restored_reload["ansible.builtin.systemd_service"]["state"] == "reloaded"
    assert rescue[-1]["ansible.builtin.fail"]


def test_probes_require_known_host_200_pong_and_unknown_host_404():
    tasks = load_yaml(f"{ROLE}/tasks/main.yml")
    transaction = task_named(tasks, "Install and verify managed Nginx route")
    block = transaction["block"]
    known = task_named(block, "Probe managed Nginx route by public Host header")
    unknown = task_named(block, "Prove unknown Nginx Host remains explicit 404")

    known_uri = known["ansible.builtin.uri"]
    assert known_uri["url"] == "http://127.0.0.1/api/ping"
    assert known_uri["headers"]["Host"] == "{{ edge_proxy_route_domain }}"
    assert known_uri["status_code"] == 200
    assert known_uri["return_content"] is True
    assert known["until"] == [
        "edge_proxy_route_known_host_probe.status == 200",
        "edge_proxy_route_known_host_probe.content == 'pong'",
    ]

    unknown_uri = unknown["ansible.builtin.uri"]
    assert unknown_uri["url"] == "http://127.0.0.1/api/ping"
    assert unknown_uri["headers"]["Host"] == "unknown.invalid"
    assert unknown_uri["status_code"] == 404


def test_managed_route_preserves_existing_unknown_host_default_fixture():
    template = jinja2.Template(read(f"{ROLE}/templates/nginx-route.conf.j2"))
    managed = template.render(
        edge_proxy_route_domain="ansible.vinisantana.com",
        edge_proxy_route_upstream="http://10.0.0.42:3000",
    )
    existing_default = """
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;
    return 404;
}
"""
    combined = existing_default + managed

    exact_names = re.findall(r"server_name\s+([^;]+);", managed)
    assert exact_names == ["ansible.vinisantana.com"]
    assert "default_server" not in managed
    assert "listen 80 default_server;" in combined
    assert "listen 443 ssl default_server;" in combined
    assert "return 404;" in combined


def test_playbook_targets_only_edge_proxy_hosts_with_exact_role_tag():
    playbook = load_yaml("playbooks/edge-proxy-route.yml")

    assert len(playbook) == 1
    play = playbook[0]
    assert play["hosts"] == "edge_proxy_hosts"
    assert play["serial"] == 1
    assert play["roles"] == [
        {"role": "edge_proxy_route", "tags": ["edge_proxy_route"]}
    ]
