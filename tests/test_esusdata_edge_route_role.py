import json
import os
import subprocess
from pathlib import Path

import jinja2
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = "roles/esusdata_edge_route"
ESUSDATA_LXC_CONTRACT = {
    "esusdata_lxc_vmid": 170,
    "esusdata_lxc_node": "pve-01",
    "esusdata_lxc_name": "esusdata-lxc",
    "esusdata_lxc_private_address": "192.168.1.145",
    "esusdata_lxc_mac_address": "BC:24:11:7C:73:49",
    "esusdata_lxc_onboot": True,
}


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
    playbook = tmp_path / "esusdata-edge-route.yml"
    playbook.write_text(
        f"""---
- name: Exercise esusdata edge route
  hosts: {host}
  connection: local
  gather_facts: false
  tasks:
    - name: Import esusdata edge route
      ansible.builtin.import_role:
        name: esusdata_edge_route
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


def run_role_with_tags(
    tmp_path: Path, variables: dict, requested_tags: str
) -> subprocess.CompletedProcess:
    playbook = tmp_path / "esusdata-edge-route-tags.yml"
    playbook.write_text(
        """---
- name: Exercise esusdata edge route tag selection
  hosts: nginx
  connection: local
  gather_facts: false
  roles:
    - role: esusdata_edge_route
      tags: [edge_proxy_route, esusdata_edge_route]
""",
        encoding="utf-8",
    )
    return subprocess.run(
        [
            "ansible-playbook",
            "-i",
            "nginx,",
            str(playbook),
            "--limit",
            "nginx",
            "--tags",
            requested_tags,
            "--extra-vars",
            json.dumps(variables),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def run_role_task_file(
    tmp_path: Path,
    task_file: str,
    variables: dict | None = None,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    playbook = tmp_path / "esusdata-edge-route-task-file.yml"
    playbook.write_text(
        f"""---
- name: Exercise esusdata edge route task file
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Import esusdata edge route task file
      ansible.builtin.import_role:
        name: esusdata_edge_route
        tasks_from: {task_file}
""",
        encoding="utf-8",
    )
    return subprocess.run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            str(playbook),
            "--extra-vars",
            json.dumps(variables or {}),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **(environment or {})},
    )


def test_disabled_role_ends_without_operational_preflight(tmp_path):
    result = run_role(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Preflight esusdata upstream" not in result.stdout
    assert "Install esusdata Nginx route candidate" not in result.stdout


def test_playbook_applies_shared_and_dedicated_tags_to_esusdata_role():
    play = load_yaml("playbooks/edge-proxy-route.yml")[0]
    esusdata_role = next(
        role
        for role in play["roles"]
        if role["role"] == "esusdata_edge_route"
    )

    assert esusdata_role["tags"] == ["edge_proxy_route", "esusdata_edge_route"]


def test_rollout_readme_passes_the_apply_gate_as_json_boolean():
    readme = read(f"{ROLE}/README.md")

    assert "--extra-vars '{\"esusdata_edge_route_apply\": true}'" in readme
    assert "-e esusdata_edge_route_apply=true" not in readme


def test_shared_edge_tag_skips_enabled_esusdata_without_mutating(tmp_path):
    result = run_role_with_tags(
        tmp_path,
        {"esusdata_edge_route_enabled": True, **ESUSDATA_LXC_CONTRACT},
        "edge_proxy_route",
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "Preflight esusdata upstream" not in output
    assert "Require explicit approval" not in output


def test_enabled_role_requires_explicit_per_run_approval_before_any_preflight(
    tmp_path,
):
    result = run_role(
        tmp_path,
        {"esusdata_edge_route_enabled": True, **ESUSDATA_LXC_CONTRACT},
        limit="nginx",
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "explicit per-run approval" in output
    assert "Preflight esusdata upstream" not in output
    assert "Render esusdata Nginx route candidate" not in output
    assert "Atomically install esusdata Nginx route candidate" not in output


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
            "esusdata_edge_route_enabled": True,
            "esusdata_edge_route_apply": True,
            **ESUSDATA_LXC_CONTRACT,
        },
        host=host,
        limit=limit,
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "exact --limit nginx" in output
    assert "Preflight esusdata upstream" not in output
    assert "Render esusdata Nginx route candidate" not in output
    assert "Atomically install esusdata Nginx route candidate" not in output


@pytest.mark.parametrize(
    "variables",
    [
        {"esusdata_edge_route_domain": "other.example"},
        {"esusdata_edge_route_upstream_address": "192.168.1.200"},
        {"esusdata_edge_route_upstream_port": 8181},
        {"esusdata_lxc_vmid": 105},
        {"esusdata_lxc_node": "pve-02"},
        {"esusdata_lxc_name": "OtherService"},
        {"esusdata_lxc_private_address": "192.168.1.200"},
        {"esusdata_lxc_mac_address": "BC:24:11:D1:92:1C"},
        {"esusdata_lxc_onboot": False},
        {"esusdata_edge_route_certificate_path": "/tmp/fullchain.pem"},
        {"esusdata_edge_route_private_key_path": "/tmp/privkey.pem"},
        {"esusdata_edge_route_config_path": "/etc/nginx/other.conf"},
        {"esusdata_edge_route_enabled_path": "/etc/nginx/other-enabled.conf"},
    ],
)
def test_enabled_role_rejects_contract_deviation_before_operational_preflight(
    tmp_path, variables
):
    variables = {"esusdata_edge_route_enabled": True, **variables}
    result = run_role(
        tmp_path,
        variables,
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "exact esusdata LXC 170 edge contract" in output
    assert "Preflight esusdata upstream" not in output


def test_defaults_pin_the_disabled_lxc170_route_contract():
    defaults = load_yaml(f"{ROLE}/defaults/main.yml")

    assert defaults == {
        "esusdata_edge_route_enabled": False,
        "esusdata_edge_route_apply": False,
        "esusdata_edge_route_domain": "pe.esusdata.com",
        "esusdata_edge_route_upstream_address": "192.168.1.145",
        "esusdata_edge_route_upstream_port": 8080,
        "esusdata_edge_route_upstream": "http://192.168.1.145:8080",
        "esusdata_edge_route_certificate_path": (
            "/etc/letsencrypt/live/pe.esusdata.com/fullchain.pem"
        ),
        "esusdata_edge_route_private_key_path": (
            "/etc/letsencrypt/live/pe.esusdata.com/privkey.pem"
        ),
        "esusdata_edge_route_config_path": (
            "/etc/nginx/sites-available/pe.esusdata.com"
        ),
        "esusdata_edge_route_enabled_path": (
            "/etc/nginx/sites-enabled/pe.esusdata.com"
        ),
        "esusdata_edge_route_candidate_path": (
            "/etc/nginx/sites-available/pe.esusdata.com.candidate"
        ),
        "esusdata_edge_route_restore_candidate_path": (
            "/etc/nginx/sites-available/pe.esusdata.com.restore"
        ),
        "esusdata_edge_route_probe_retries": 12,
        "esusdata_edge_route_probe_delay": 5,
        **ESUSDATA_LXC_CONTRACT,
    }

    for duplicate_name in (
        "esusdata_edge_route_vmid",
        "esusdata_edge_route_node",
        "esusdata_edge_route_vm_name",
        "esusdata_edge_route_vm_mac",
    ):
        assert duplicate_name not in defaults


def test_template_enforces_exact_redirect_and_tls_proxy_behavior():
    template = jinja2.Template(read(f"{ROLE}/templates/esusdata-edge-route.conf.j2"))
    rendered = template.render(
        esusdata_edge_route_domain="pe.esusdata.com",
        esusdata_edge_route_upstream="http://192.168.1.145:8080",
        esusdata_edge_route_certificate_path=(
            "/etc/letsencrypt/live/pe.esusdata.com/fullchain.pem"
        ),
        esusdata_edge_route_private_key_path=(
            "/etc/letsencrypt/live/pe.esusdata.com/privkey.pem"
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
    assert "proxy_pass http://192.168.1.145:8080;" in tls_server
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
    assert names.index("Preflight esusdata upstream over HTTP") < names.index(
        "Render esusdata Nginx route candidate"
    )
    assert names.index("Validate exact esusdata certificate SAN") < names.index(
        "Render esusdata Nginx route candidate"
    )
    upstream = task_named(tasks, "Preflight esusdata upstream over HTTP")
    assert upstream["ansible.builtin.uri"]["url"] == "{{ esusdata_edge_route_upstream }}"
    assert upstream["ansible.builtin.uri"]["status_code"] == 200
    timer = task_named(tasks, "Require enabled certbot renewal timer")
    assert timer["ansible.builtin.command"]["argv"] == [
        "systemctl",
        "is-enabled",
        "certbot.timer",
    ]
    san = task_named(tasks, "Read esusdata certificate subject alternative names")
    assert san["ansible.builtin.command"]["argv"][-2:] == ["-ext", "subjectAltName"]


def test_transaction_installs_symlink_validates_reloads_and_rolls_back_both_states():
    tasks = load_yaml(f"{ROLE}/tasks/main.yml")
    transaction_tasks = load_yaml(f"{ROLE}/tasks/transaction.yml")
    transaction = task_named(
        transaction_tasks, "Install and verify esusdata Nginx route"
    )
    block_names = [task["name"] for task in transaction["block"]]
    rescue_names = [task["name"] for task in transaction["rescue"]]
    top_level_names = [task["name"] for task in tasks]

    assert top_level_names.index("Back up preceding esusdata Nginx route") < top_level_names.index(
        "Install and verify esusdata Nginx route"
    )
    backup = task_named(tasks, "Back up preceding esusdata Nginx route")
    assert backup["ansible.builtin.copy"]["dest"] == (
        "{{ esusdata_edge_route_config_path }}."
        "{{ esusdata_edge_route_backup_timestamp.stdout }}.bak"
    )
    assert block_names.index("Atomically install esusdata Nginx route candidate") < block_names.index(
        "Ensure esusdata Nginx route symlink"
    ) < block_names.index("Validate installed esusdata Nginx configuration") < block_names.index(
        "Reload installed esusdata Nginx configuration"
    )
    assert block_names[-3:] == [
        "Probe esusdata HTTP redirect",
        "Probe esusdata HTTPS root",
        "Probe esusdata HTTPS readiness endpoint",
    ]
    assert rescue_names.index("Restore preceding esusdata Nginx route") < rescue_names.index(
        "Restore preceding esusdata Nginx symlink state"
    ) < rescue_names.index("Revalidate restored esusdata Nginx configuration") < rescue_names.index(
        "Reload restored esusdata Nginx configuration"
    )
    assert transaction["rescue"][-1]["ansible.builtin.fail"]
    assert "transaction.yml" in read(f"{ROLE}/tasks/main.yml")
    assert "state: link" in read(f"{ROLE}/tasks/transaction.yml")
    assert "mv" in read(f"{ROLE}/tasks/transaction.yml")


def test_failed_real_transaction_restores_preceding_vhost_and_symlink(tmp_path):
    config_path = tmp_path / "sites-available" / "esusdata.conf"
    enabled_path = tmp_path / "sites-enabled" / "esusdata.conf"
    candidate_path = tmp_path / "sites-available" / "esusdata.conf.candidate"
    restore_candidate_path = (
        tmp_path / "sites-available" / "esusdata.conf.restore"
    )
    previous_target = tmp_path / "sites-available" / "previous.conf"
    config_path.parent.mkdir()
    enabled_path.parent.mkdir()
    old_vhost = "server { return 418; }\n"
    config_path.write_text(old_vhost, encoding="utf-8")
    previous_target.write_text("previous symlink target\n", encoding="utf-8")
    enabled_path.symlink_to(previous_target)
    candidate_path.write_text("server { return 200; }\n", encoding="utf-8")
    backup_path = Path(f"{config_path}.test.bak")
    backup_path.write_text(old_vhost, encoding="utf-8")

    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    nginx_calls = tmp_path / "nginx-calls"
    nginx_wrapper = bin_path / "nginx"
    nginx_wrapper.write_text(
        f"""#!/bin/sh
count=0
test ! -f '{nginx_calls}' || count=$(cat '{nginx_calls}')
count=$((count + 1))
echo "$count" >'{nginx_calls}'
test "$count" -ne 1
""",
        encoding="utf-8",
    )
    nginx_wrapper.chmod(0o755)
    systemctl_wrapper = bin_path / "systemctl"
    systemctl_wrapper.write_text(
        """#!/bin/sh
if [ "$1" = "show" ]; then
  printf 'LoadState=loaded\nActiveState=active\nSubState=running\n'
fi
exit 0
""",
        encoding="utf-8",
    )
    systemctl_wrapper.chmod(0o755)
    become_wrapper = tmp_path / "test-become-wrapper"
    become_wrapper.write_text(
        "#!/bin/sh\nwhile [ \"$1\" != \"/bin/sh\" ]; do shift; done\nexec \"$@\"\n",
        encoding="utf-8",
    )
    become_wrapper.chmod(0o755)

    result = run_role_task_file(
        tmp_path,
        "transaction.yml",
        {
            "ansible_become_exe": str(become_wrapper),
            "esusdata_edge_route_changed": True,
            "esusdata_edge_route_config_changed": True,
            "esusdata_edge_route_config_path": str(config_path),
            "esusdata_edge_route_enabled_path": str(enabled_path),
            "esusdata_edge_route_candidate_path": str(candidate_path),
            "esusdata_edge_route_restore_candidate_path": str(
                restore_candidate_path
            ),
            "esusdata_edge_route_backup_timestamp": {"stdout": "test"},
            "esusdata_edge_route_preceding_config": {"stat": {"exists": True}},
            "esusdata_edge_route_preceding_enabled": {
                "stat": {"islnk": True, "lnk_source": str(previous_target)}
            },
        },
        {"PATH": f"{bin_path}:{os.environ['PATH']}"},
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "esusdata Nginx route transaction failed" in output
    assert config_path.read_text(encoding="utf-8") == old_vhost
    assert enabled_path.is_symlink()
    assert enabled_path.readlink() == previous_target
    assert not candidate_path.exists()
    assert not restore_candidate_path.exists()


def test_probes_accept_the_required_public_statuses_only():
    tasks = load_yaml(f"{ROLE}/tasks/transaction.yml")
    block = task_named(tasks, "Install and verify esusdata Nginx route")["block"]

    expected = {
        "Probe esusdata HTTP redirect": ("http://127.0.0.1/", 301),
        "Probe esusdata HTTPS root": ("https://127.0.0.1/", 200),
        "Probe esusdata HTTPS readiness endpoint": (
            "https://127.0.0.1/api/v1/ready",
            200,
        ),
    }
    for name, (url, status) in expected.items():
        probe = task_named(block, name)["ansible.builtin.uri"]
        assert probe["url"] == url
        assert probe["status_code"] == status
        assert probe["headers"] == {"Host": "{{ esusdata_edge_route_domain }}"}
