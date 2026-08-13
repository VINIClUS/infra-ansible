from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def load_yaml(relative_path: str):
    return yaml.safe_load(read(relative_path))


def task_named(tasks: list[dict], name: str) -> dict:
    return next(task for task in tasks if task["name"] == name)


def test_container_runtime_is_disabled_until_a_technical_user_is_declared():
    """A default-enabled runtime could install Docker on real inventory hosts."""
    defaults = load_yaml("roles/container_runtime/defaults/main.yml")

    assert defaults == {
        "container_runtime_enabled": False,
        "container_runtime_technical_user": "",
        "container_runtime_packages": [
            "docker.io",
            "docker-compose",
            "docker-buildx",
            "python3-venv",
            "git",
            "curl",
            "ca-certificates",
            "rsync",
        ],
    }


def test_enabled_runtime_installs_only_the_declared_baseline_and_adds_one_user():
    """A broader group mutation would grant Docker access to unintended accounts."""
    tasks = load_yaml("roles/container_runtime/tasks/main.yml")
    install = task_named(tasks, "Install lab container runtime packages")[
        "ansible.builtin.apt"
    ]
    service = task_named(tasks, "Enable Docker service")[
        "ansible.builtin.systemd_service"
    ]
    membership = task_named(tasks, "Grant Docker access to the declared technical user")[
        "ansible.builtin.user"
    ]

    assert install == {
        "name": "{{ container_runtime_packages }}",
        "state": "present",
        "update_cache": True,
    }
    assert service == {"name": "docker.service", "enabled": True, "state": "started"}
    assert membership == {
        "name": "{{ container_runtime_technical_user }}",
        "groups": "docker",
        "append": True,
    }
    for task in (install, service, membership):
        assert task is not None

    guarded = [
        task
        for task in tasks
        if task.get("name")
        in {
            "Install lab container runtime packages",
            "Enable Docker service",
            "Grant Docker access to the declared technical user",
        }
    ]
    assert all(task["when"] == "container_runtime_enabled | bool" for task in guarded)


def test_runtime_refuses_to_create_a_technical_user_for_docker_access():
    """Creating an account implicitly would extend the host-access boundary."""
    tasks = load_yaml("roles/container_runtime/tasks/main.yml")
    lookup = task_named(tasks, "Load local passwd entries")["ansible.builtin.getent"]
    user_assertion = task_named(
        tasks, "Prove the declared technical user already exists"
    )["ansible.builtin.assert"]["that"]

    assert lookup == {"database": "passwd"}
    assert "container_runtime_technical_user in ansible_facts.getent_passwd" in (
        user_assertion
    )


def test_public_lab_playbook_reuses_the_safe_baseline_and_targets_linux_guests():
    """The lab entrypoint must not bypass SSH or firewall contract validation."""
    playbook = load_yaml("playbooks/lab-container-host.yml")

    assert playbook[0] == {
        "name": "Import safe Linux baseline contract",
        "ansible.builtin.import_playbook": "linux-baseline.yml",
    }
    assert playbook[1]["hosts"] == "linux_guests"
    assert playbook[1]["gather_facts"] is True
    assert playbook[1]["roles"] == ["container_runtime"]
