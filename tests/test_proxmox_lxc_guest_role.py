import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def role_tasks() -> list[dict]:
    return yaml.safe_load(read("roles/proxmox_lxc_guest/tasks/main.yml"))


def task_named(name: str) -> dict:
    return next(task for task in role_tasks() if task["name"] == name)


def proxmox_module_calls() -> list[dict]:
    module_names = (
        "community.proxmox.proxmox_vm_info",
        "community.proxmox.proxmox",
    )
    return [
        task[module_name]
        for task in role_tasks()
        for module_name in module_names
        if module_name in task
    ]


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


def test_lxc_role_defaults_to_proxied_api_port():
    defaults = yaml.safe_load(read("roles/proxmox_lxc_guest/defaults/main.yml"))

    assert defaults.get("proxmox_lxc_guest_api_port") == 443


def test_all_proxmox_modules_use_configured_api_port():
    module_calls = proxmox_module_calls()

    assert len(module_calls) == 5
    assert all(
        call.get("api_port") == "{{ proxmox_lxc_guest_api_port }}"
        for call in module_calls
    )


def test_lxc_playbook_runs_only_on_bootstrap_host():
    playbook = read("playbooks/provision-ansible-controller.yml")
    assert "hosts: ansible_controller_bootstrap" in playbook
    assert "connection: local" in playbook
    assert "role: proxmox_lxc_guest" in playbook


def test_lxc_playbook_uses_ansible_runtime_for_local_modules():
    playbook = yaml.safe_load(read("playbooks/provision-ansible-controller.yml"))[0]

    assert playbook.get("vars", {}).get("ansible_python_interpreter") == (
        "{{ ansible_playbook_python }}"
    )


def test_lxc_role_reconciles_configuration_before_starting():
    tasks = role_tasks()
    reconcile_index = next(
        index
        for index, task in enumerate(tasks)
        if task["name"] == "Reconcile non-destructive target configuration"
    )
    reconcile = tasks[reconcile_index]["community.proxmox.proxmox"]
    start_task = tasks[reconcile_index + 1]
    start = start_task["community.proxmox.proxmox"]

    assert reconcile["update"] is True
    assert reconcile["state"] == "present"
    assert start_task["name"] == "Start reconciled target"
    assert start["state"] == "started"
    assert "update" not in start


def test_existing_target_and_postflight_require_debian():
    for name in (
        "Prove an existing target has the approved identity",
        "Prove final target configuration",
    ):
        assertions = task_named(name)["ansible.builtin.assert"]["that"]
        assert any(".config.ostype == 'debian'" in assertion for assertion in assertions)


def test_contract_checks_use_delimiter_aware_exact_matches():
    exact_checks = {
        "Prove source template safety": (
            "rootfs is match('^local-lvm:')",
            "rootfs is search('(^|,)size=32G(,|$)')",
            "net0 is search('(^|,)bridge=vmbr0(,|$)')",
            "net0 is search('(^|,)firewall=1(,|$)')",
            "net0 is search('(^|,)ip=dhcp(,|$)')",
        ),
        "Prove an existing target has the approved identity": (
            "rootfs is match('^local-lvm:')",
            "rootfs is search('(^|,)size=32G(,|$)')",
            "net0 is search('(^|,)bridge=vmbr0(,|$)')",
            "net0 is search('(^|,)firewall=1(,|$)')",
            "net0 is search('(^|,)ip=dhcp(,|$)')",
        ),
        "Prove final target configuration": (
            "rootfs is match('^local-lvm:')",
            "rootfs is search('(^|,)size=32G(,|$)')",
            "net0 is search('(^|,)bridge=vmbr0(,|$)')",
            "net0 is search('(^|,)firewall=1(,|$)')",
            "net0 is search('(^|,)ip=dhcp(,|$)')",
        ),
    }

    for task_name, checks in exact_checks.items():
        assertions = task_named(task_name)["ansible.builtin.assert"]["that"]
        for check in checks:
            assert any(check in assertion for assertion in assertions)

    assert re.match(r"^local-lvm:", "local-lvm:subvol-100-disk-0,size=32G")
    assert not re.match(r"^local-lvm:", "local-lvm-archive:subvol-100-disk-0,size=32G")
    assert re.search(r"(^|,)bridge=vmbr0(,|$)", "name=eth0,bridge=vmbr0,ip=dhcp")
    assert not re.search(r"(^|,)bridge=vmbr0(,|$)", "name=eth0,bridge=vmbr01,ip=dhcp")
    assert re.search(r"(^|,)ip=dhcp(,|$)", "name=eth0,bridge=vmbr0,ip=dhcp")
    assert not re.search(r"(^|,)ip=dhcp(,|$)", "name=eth0,bridge=vmbr0,ip=dhcp6")


def test_plan_documents_two_step_reconcile_and_start():
    plan = read("docs/superpowers/plans/2026-07-11-ansible-controller-cicd.md")
    task_two = plan.split("### Task 2:", maxsplit=1)[1].split("### Task 3:", maxsplit=1)[0]
    reconcile = task_two.index("- name: Reconcile non-destructive target configuration")
    start = task_two.index("- name: Start reconciled target")

    assert "state: present" in task_two[reconcile:start]
    assert "update: true" in task_two[reconcile:start]
    assert "state: started" in task_two[start:]
