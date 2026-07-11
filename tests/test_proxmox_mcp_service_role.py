from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_role_is_disabled_and_requires_pinned_release_contract():
    defaults = read("roles/proxmox_mcp_service/defaults/main.yml")
    assert "proxmox_mcp_service_enabled: false" in defaults
    assert 'proxmox_mcp_service_repo_ref: ""' in defaults
    assert "proxmox_mcp_service_release_root: /opt/proxmox-mcp/releases" in defaults
    assert "proxmox_mcp_service_data_volume: proxmox_mcp_data" in defaults
    assert "proxmox_mcp_service_listen_address: 127.0.0.1" in defaults
    assert "proxmox_mcp_service_resource_kind: lxc" in defaults
    assert "  - PVE_PORT" in defaults
    assert "  - PVE_TIMEOUT_MS" in defaults
    assert "  - OPENAI_API_KEY" not in defaults
    assert "  - OWNER" not in defaults
    assert "  - TTL_HOURS" not in defaults


def test_role_requires_narrow_limit_tag_and_protects_runtime_material():
    tasks = read("roles/proxmox_mcp_service/tasks/main.yml")
    assert "ansible_limit" in tasks
    assert "ansible_run_tags" in tasks
    assert "proxmox_mcp_service" in tasks
    assert "proxmox_mcp_service_repo_ref is match('^[0-9a-f]{40}$')" in tasks
    assert "no_log: true" in tasks
    assert "community.docker.docker_compose_v2" in tasks
    assert "proxmox_mcp_service_ssh_public_key_file" in tasks
    assert "state: absent" not in tasks
    assert "proxmox_mcp_service_resource_kind == 'lxc'" in tasks


def test_role_does_not_bind_the_inherited_backup_path():
    compose = read("../ProxmoxMCP/compose.mcp.yml")
    assert "/mnt/infra-backups/proxmox" not in compose


def test_playbook_and_collection_are_explicit():
    playbook = read("playbooks/proxmox-mcp-service.yml")
    requirements = read("requirements.yml")
    assert "hosts: linux_guests" in playbook
    assert "serial: 1" in playbook
    assert "role: proxmox_mcp_service" in playbook
    assert "community.docker" in requirements
