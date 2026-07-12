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
    assert "  - docker-compose\n" in defaults
    assert "docker-compose-v2" not in defaults
    assert "proxmox_mcp_service_listen_address: 127.0.0.1" in defaults
    assert "proxmox_mcp_service_resource_kind: lxc" in defaults
    assert "proxmox_mcp_service_release_source: git" in defaults
    assert 'proxmox_mcp_service_controller_repo_path: ""' in defaults
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
    assert "deploy_controller_archive.yml" in tasks


def test_controller_archive_contains_only_committed_release_files():
    tasks = read("roles/proxmox_mcp_service/tasks/deploy_controller_archive.yml")
    assert "git" in tasks
    assert "archive" in tasks
    assert "proxmox_mcp_service_repo_ref" in tasks
    assert "ansible.builtin.unarchive" in tasks
    assert "state: absent" in tasks


def test_role_does_not_bind_the_inherited_backup_path():
    forbidden_path = "/mnt/infra-backups/proxmox"
    role_root = ROOT / "roles/proxmox_mcp_service"
    role_contract = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(role_root.rglob("*"))
        if path.is_file() and path.suffix in {".j2", ".yaml", ".yml"}
    )
    assert forbidden_path not in role_contract

    # The upstream repository is available in the local multi-repository
    # workspace, but a standalone GitHub checkout must remain testable.
    upstream_compose = ROOT.parent / "ProxmoxMCP/compose.mcp.yml"
    if upstream_compose.is_file():
        assert forbidden_path not in upstream_compose.read_text(encoding="utf-8")


def test_role_keeps_secrets_out_of_compose_project_dotenv():
    runtime_env = read("roles/proxmox_mcp_service/templates/proxmox-mcp.env.j2")
    project_env = read("roles/proxmox_mcp_service/templates/compose-project.env.j2")
    tasks = read("roles/proxmox_mcp_service/tasks/main.yml")
    assert "='" in runtime_env
    assert "PVE_SSH_PUBLIC_KEY_FILE=" in project_env
    assert "PVE_TOKEN_SECRET" not in project_env
    assert ".proxmox-mcp.env" in tasks


def test_playbook_and_collection_are_explicit():
    playbook = read("playbooks/proxmox-mcp-service.yml")
    requirements = read("requirements.yml")
    assert "hosts: linux_guests" in playbook
    assert "serial: 1" in playbook
    assert "role: proxmox_mcp_service" in playbook
    assert "community.docker" in requirements
