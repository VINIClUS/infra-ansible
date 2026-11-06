from pathlib import Path

import jinja2
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles" / "proxmox_firewall"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def role_tasks() -> list[dict]:
    return yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))


def task_index(name: str) -> int:
    return next(i for i, task in enumerate(role_tasks()) if task["name"] == name)


def render(template: str, **context) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(ROLE / "templates"),
        trim_blocks=True,
        keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined,
    )
    env.filters["bool"] = lambda value: value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    base = dict(defaults, ansible_managed="Ansible managed", proxmox_firewall_render_enable=False)
    base.update(context)
    return env.get_template(template).render(base)


SAMPLE = {
    "proxmox_firewall_ipsets": {
        "pve_nodes": [{"cidr": "192.0.2.11"}, {"cidr": "192.0.2.12"}, {"cidr": "192.0.2.13"}],
        "ops": [{"cidr": "10.20.20.25", "comment": "ansible"}, {"cidr": "10.20.0.0/16", "nomatch": True}],
    },
    "proxmox_firewall_aliases": {"rtr01_wan": {"cidr": "192.0.2.5"}},
    "proxmox_firewall_security_groups": {
        "sg-base": {"rules": [{"direction": "IN", "action": "ACCEPT", "macro": "SSH", "source": "+ops"}]},
    },
    "proxmox_firewall_host_rules": {
        "pve-01": [{"direction": "IN", "action": "ACCEPT", "proto": "tcp", "dport": 9100, "source": "+ops"}],
    },
    "proxmox_firewall_guests": {
        150: {
            "options": {"enable": True, "policy_in": "DROP", "macfilter": True, "ipfilter": True},
            "rules": [
                {"group": "sg-base", "iface": "net0"},
                {"direction": "IN", "action": "DROP", "enable": False, "comment": "off"},
            ],
        },
    },
}


def test_role_is_disabled_by_default_and_never_activates_implicitly():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["proxmox_firewall_enabled"] is False
    assert defaults["proxmox_firewall_activate"] is False
    assert defaults["proxmox_firewall_nodes"] == {}


def test_contract_requires_exact_limit_single_host_and_narrow_tag():
    tasks = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "ansible_limit | trim == inventory_hostname" in tasks
    assert "ansible_play_hosts_all | length == 1" in tasks
    assert "ansible_run_tags | list | sort == ['proxmox_firewall']" in tasks
    assert "proxmox_firewall_live_nodes == proxmox_firewall_nodes" in tasks


def test_vxlan_guard_ipset_must_equal_node_addresses():
    tasks = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "proxmox_firewall_guard_entries == (proxmox_firewall_nodes.values() | list | sort)" in tasks


def test_backup_ha_guard_and_deadman_precede_any_firewall_write():
    mkdir = task_index("Ensure the datacenter firewall directory exists")
    backup = task_index("Back up firewall, SDN, node and network configuration")
    guest_guard = task_index("Refuse to enforce guest firewalls in the same run that enables the datacenter")
    ha_off = task_index("Release HA watchdogs before a live firewall change")
    arm = task_index("Arm the dead-man timer on every node before a live firewall change")
    apply_block = task_index("Apply and verify the firewall configuration")
    disarm = task_index("Disarm the dead-man timer after successful verification")
    ha_on = task_index("Restore HA after successful verification")
    assert mkdir < backup < guest_guard < ha_off < arm < apply_block < disarm < ha_on


def test_backup_only_archives_existing_paths_including_sdn():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert "etc/pve/sdn" in defaults["proxmox_firewall_backup_paths"]
    backup = role_tasks()[task_index("Back up firewall, SDN, node and network configuration")]
    assert "selectattr('stat.exists')" in backup["ansible.builtin.command"]["argv"]


def test_guest_firewalls_cannot_be_enforced_while_datacenter_is_off():
    guard = role_tasks()[task_index("Refuse to enforce guest firewalls in the same run that enables the datacenter")]
    assert "proxmox_firewall_currently_enabled" in guard["ansible.builtin.assert"]["that"][0]


def test_ha_guard_disarms_cluster_wide_or_ignores_resources_and_restores():
    ha = (ROLE / "tasks" / "ha_guard.yml").read_text(encoding="utf-8")
    assert "[ha-manager, crm-command, disarm-ha, freeze]" in ha
    assert "[ha-manager, crm-command, arm-ha]" in ha
    assert "--state, ignored]" in ha
    assert "ha-states.json" in ha
    assert "^lrm \\S+ \\(active" in ha
    wait = ha.split("- name: Wait until no LRM holds an active watchdog", 1)[1].split("- name:", 1)[0]
    assert "not ansible_check_mode" in wait


def test_apply_block_compiles_verifies_and_rescues():
    block = role_tasks()[task_index("Apply and verify the firewall configuration")]
    names = [task["name"] for task in block["block"]]
    order = [names.index(n) for n in (
        "Reset the local staging tree",
        "Stage node host firewall files",
        "Stage declared guest firewall files",
        "Stage the datacenter firewall file",
        "Validate staged candidates offline before any pmxcfs write",
        "Commit node host firewall files",
        "Commit declared guest firewall files",
        "Commit the datacenter firewall file last",
        "Compile the rendered ruleset",
    )]
    assert order == sorted(order)
    assert "Drop the persistent SSH connection so the next task opens a new one" in names
    assert "Confirm quorum and all nodes survived the change" in names
    rescue = yaml.safe_dump(block["rescue"])
    assert "proxmox_firewall_revert_command" in rescue


def test_deadman_uses_systemd_run_and_persists_the_rollback():
    deadman = (ROLE / "tasks" / "deadman.yml").read_text(encoding="utf-8")
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert "systemd-run" in deadman
    assert "proxmox_firewall_revert_command" in deadman
    assert " at " not in deadman
    revert = defaults["proxmox_firewall_revert_command"]
    assert revert.index("pvesh set /cluster/firewall/options --enable 0") < revert.index("/usr/sbin/pve-firewall stop")


def test_role_never_touches_nftables_backend_or_sdn():
    for path in (ROLE / "tasks").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "nftables" not in text
        assert "/cluster/sdn" not in text


def test_cluster_template_renders_disabled_with_vxlan_guard_first():
    output = render("cluster.fw.j2", **SAMPLE)
    lines = output.splitlines()
    assert "enable: 0" in lines
    assert "policy_in: DROP" in lines
    rules = lines.index("[RULES]")
    first_rule = next(line for line in lines[rules + 1:] if line.strip())
    assert first_rule.startswith("IN ACCEPT -source +pve_nodes -p udp -dport 4789")
    assert "[IPSET ops]" in lines
    assert "!10.20.0.0/16" in lines
    assert "rtr01_wan 192.0.2.5" in lines
    assert "[group sg-base]" in lines
    assert "IN SSH(ACCEPT) -source +ops -log nolog" in lines


def test_cluster_template_renders_enabled_when_requested():
    output = render("cluster.fw.j2", proxmox_firewall_render_enable=True, **SAMPLE)
    assert "enable: 1" in output.splitlines()


def test_host_template_renders_dport_rules_per_node():
    output = render("host.fw.j2", proxmox_firewall_item_node="pve-01", **SAMPLE)
    assert "IN ACCEPT -source +ops -p tcp -dport 9100 -log nolog" in output.splitlines()
    assert "sport" not in output
    empty = render("host.fw.j2", proxmox_firewall_item_node="pve-02", **SAMPLE)
    assert "IN " not in empty


def test_guest_template_renders_options_groups_and_disabled_rules():
    output = render("guest.fw.j2", proxmox_firewall_item_vmid=150, **SAMPLE)
    lines = output.splitlines()
    for expected in ("enable: 1", "policy_in: DROP", "macfilter: 1", "ipfilter: 1"):
        assert expected in lines
    assert "GROUP sg-base -i net0" in lines
    assert "|IN DROP -log nolog # off" in lines


def test_playbook_targets_proxmox_nodes_with_single_tag():
    playbook = yaml.safe_load(read("playbooks/proxmox-firewall.yml"))
    assert playbook[0]["hosts"] == "proxmox_nodes"
    assert playbook[0]["serial"] == 1
    assert playbook[0]["roles"][0]["tags"] == ["proxmox_firewall"]


def test_controller_reachability_check_does_not_delegate():
    block = role_tasks()[task_index("Apply and verify the firewall configuration")]
    check = next(t for t in block["block"] if t["name"] == "Prove new management connections from the controller still work")
    assert "delegate_to" not in check
    that = " ".join(check["ansible.builtin.assert"]["that"])
    assert "ssh-keyscan" in that and ":8006/" in that


def test_pmxcfs_is_never_written_by_template_or_copy():
    for path in (ROLE / "tasks").glob("*.yml"):
        for task in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            for sub in [task] + task.get("block", []) + task.get("rescue", []):
                for module in ("ansible.builtin.template", "ansible.builtin.copy"):
                    if module in sub:
                        assert not str(sub[module].get("dest", "")).startswith("/etc/pve"), sub["name"]
    stage = (ROLE / "tasks" / "stage_file.yml").read_text(encoding="utf-8")
    commit = (ROLE / "tasks" / "commit_file.yml").read_text(encoding="utf-8")
    assert "proxmox_firewall_staging_root" in stage
    render = stage.split('- name: "Render', 1)[1]
    assert "check_mode: false" in render
    assert 'cat "$1" > "$2"' in commit


def test_offline_validator_checks_rule_errors_compile_and_guards():
    script = (ROLE / "files" / "fw-candidate-check.pl").read_text(encoding="utf-8")
    assert "->{errors}" in script
    assert "testdir => $dir" in script
    assert "--dport 4789" in script
    assert "PVEFW-HOST-IN" in script
    assert "PVE::LXC::Config->load_config($vmid)" in script and "lxc => \\%lxc" in script
    assert "compiled no NIC chain" in script
    gate = role_tasks()[task_index("Apply and verify the firewall configuration")]
    check = next(t for t in gate["block"] if t["name"] == "Validate staged candidates offline before any pmxcfs write")
    assert "enable: 1" in check["ansible.builtin.command"]["argv"][2]


def test_failed_ha_disarm_restores_previous_states():
    guard = role_tasks()[task_index("Release HA watchdogs before a live firewall change")]
    assert guard["rescue"][0]["vars"]["proxmox_firewall_ha_action"] == "rearm"
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["proxmox_firewall_ha_wait_seconds"] > 600
