from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_lxc_role_is_disabled_and_create_only():
    defaults = read("roles/proxmox_lxc_guest/defaults/main.yml")
    tasks = read("roles/proxmox_lxc_guest/tasks/main.yml")
    assert "proxmox_lxc_guest_enabled: false" in defaults
    assert "state: absent" not in tasks
    assert "delete" not in tasks.lower()
    assert "ansible_limit" in tasks
    assert "proxmox_lxc_guest" in tasks


def test_lxc_role_requires_approved_template_contract():
    tasks = read("roles/proxmox_lxc_guest/tasks/main.yml")
    for token in ("template", "unprivileged", "ostype", "rootfs", "vmbr0", "ip=dhcp"):
        assert token in tasks
    assert "community.proxmox.proxmox" in tasks


def test_lxc_playbook_runs_only_on_bootstrap_host():
    playbook = read("playbooks/provision-ansible-controller.yml")
    assert "hosts: ansible_controller_bootstrap" in playbook
    assert "connection: local" in playbook
    assert "role: proxmox_lxc_guest" in playbook
