from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_playbook(path: str) -> list[dict]:
    return yaml.safe_load(read(path))


def role_contract(play: dict) -> list[tuple[str, list[str]]]:
    return [(item["role"], item["tags"]) for item in play["roles"]]


def test_bootstrap_orchestrates_controller_edge_and_access_as_separate_plays():
    plays = load_playbook("playbooks/bootstrap-ansible-controller.yml")

    assert [play["hosts"] for play in plays] == [
        "ansible_controllers",
        "edge_proxy_hosts",
        "localhost",
    ]
    assert plays[0]["serial"] == 1
    assert role_contract(plays[0]) == [
        ("common_base", ["common_base"]),
        ("ssh_hardening", ["ssh_hardening"]),
        ("github_actions_runner", ["github_actions_runner"]),
        ("infra_ansible_deployer", ["infra_ansible_deployer"]),
        ("semaphore_controller", ["semaphore_controller"]),
        ("monitoring_agent", ["monitoring_agent"]),
    ]
    assert plays[1]["serial"] == 1
    assert role_contract(plays[1]) == [
        ("edge_proxy_route", ["edge_proxy_route"]),
    ]
    assert plays[2]["connection"] == "local"
    assert role_contract(plays[2]) == [
        ("cloudflare_access_application", ["cloudflare_access_application"]),
    ]
    assert "proxmox_lxc_guest" not in read(
        "playbooks/bootstrap-ansible-controller.yml"
    )


def test_deploy_is_one_controller_play_with_only_reconciliation_roles():
    plays = load_playbook("playbooks/deploy-ansible-controller.yml")

    assert len(plays) == 1
    assert plays[0]["hosts"] == "ansible_controllers"
    assert plays[0]["serial"] == 1
    assert role_contract(plays[0]) == [
        ("semaphore_controller", ["semaphore_controller"]),
        ("monitoring_agent", ["monitoring_agent"]),
    ]
    playbook = read("playbooks/deploy-ansible-controller.yml")
    assert "proxmox_lxc_guest" not in playbook
    assert "github_actions_runner" not in playbook
    assert "edge_proxy_route" not in playbook
    assert "cloudflare_access_application" not in playbook


def test_privileged_edge_and_access_runs_remain_separate():
    edge = load_playbook("playbooks/edge-proxy-route.yml")
    access = load_playbook("playbooks/cloudflare-access.yml")

    assert len(edge) == 1
    assert edge[0]["hosts"] == "edge_proxy_hosts"
    assert edge[0]["serial"] == 1
    assert role_contract(edge[0]) == [("edge_proxy_route", ["edge_proxy_route"])]
    assert len(access) == 1
    assert access[0]["hosts"] == "localhost"
    assert access[0]["connection"] == "local"
    assert role_contract(access[0]) == [
        ("cloudflare_access_application", ["cloudflare_access_application"]),
    ]


def test_rollback_reads_the_armed_backup_id_and_runs_only_the_controller_role():
    plays = load_playbook("playbooks/rollback-ansible-controller.yml")

    assert len(plays) == 1
    play = plays[0]
    assert play["hosts"] == "ansible_controllers"
    assert play["serial"] == 1
    assert play["vars"]["semaphore_controller_rollback_mode"] is True
    assert play["pre_tasks"][0]["ansible.builtin.slurp"]["src"] == (
        "{{ semaphore_controller_rollback_marker_path }}"
    )
    assert play["pre_tasks"][0]["no_log"] is True
    assert "b64decode" in play["pre_tasks"][1]["ansible.builtin.set_fact"][
        "semaphore_controller_rollback_backup_id"
    ]
    assert role_contract(play) == [
        ("semaphore_controller", ["semaphore_controller_rollback"]),
    ]
    assert all(
        task["tags"] == ["semaphore_controller_rollback"]
        for task in play["pre_tasks"]
    )
    playbook = read("playbooks/rollback-ansible-controller.yml")
    assert "proxmox_lxc_guest" not in playbook
    assert "github_actions_runner" not in playbook
