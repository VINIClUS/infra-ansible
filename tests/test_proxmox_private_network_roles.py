import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import jinja2
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "roles"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def defaults(role: str) -> dict:
    return yaml.safe_load((ROLES / role / "defaults" / "main.yml").read_text(encoding="utf-8"))


def render(role: str, template: str, **context) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(ROLES / role / "templates"),
        trim_blocks=True,
        lstrip_blocks=False,
        keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined,
    )
    env.filters["regex_replace"] = lambda value, pattern, repl="": re.sub(pattern, repl, str(value))
    env.filters["bool"] = lambda value: value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")
    base = dict(defaults(role), ansible_managed="Ansible managed")
    base.update(context)
    return env.get_template(template).render(base)


ROUTER = {
    "network_router_wan_interface": "eth0",
    "network_router_lan_cidr": "192.0.2.0/24",
    "network_router_admin_sources": ["192.0.2.0/24"],
    "network_router_pve_nodes": ["192.0.2.11", "192.0.2.12", "192.0.2.13"],
    "network_router_zones": {
        "svc": {"interface": "eth1", "cidr": "10.10.10.0/24", "address": "10.10.10.1/24", "internet": True,
                "dhcp": {"start": "10.10.10.200", "end": "10.10.10.219",
                         "reservations": [{"mac": "bc:24:11:00:00:01", "ip": "10.10.10.104", "name": "app"}]}},
        "ops": {"interface": "eth2", "cidr": "10.10.20.0/24", "address": "10.10.20.1/24", "internet": True,
                "full_access": True, "ssh_to_router": True},
        "ci": {"interface": "eth3", "cidr": "10.10.30.0/24", "address": "10.10.30.1/24", "internet": True},
    },
    "network_router_forward_rules": [
        {"from": "ci", "to": "svc", "saddr": "10.10.30.182", "daddr": ["10.10.10.180", "10.10.10.181"],
         "proto": "tcp", "dport": 22, "comment": "deploy"},
        {"from": "svc", "to": "wan", "saddr": "10.10.10.111", "daddr": ["192.0.2.11", "192.0.2.12"],
         "proto": "tcp", "dport": 8006, "comment": "mcp api"},
    ],
    "network_router_dns_forwarders": ["192.0.2.1", "1.1.1.1"],
    "network_router_dns_domain": "example.internal",
}


@pytest.mark.parametrize("role", ["proxmox_sdn", "proxmox_router_vm", "network_router", "proxmox_node_routes"])
def test_new_infrastructure_roles_are_disabled_by_default(role):
    assert defaults(role)[f"{role}_enabled"] is False


@pytest.mark.parametrize(
    ("role", "tag"),
    [
        ("proxmox_sdn", "proxmox_sdn"),
        ("proxmox_router_vm", "proxmox_router_vm"),
        ("network_router", "network_router"),
        ("proxmox_node_routes", "proxmox_node_routes"),
    ],
)
def test_every_role_requires_its_narrow_tag_and_an_explicit_limit(role, tag):
    tasks = read(f"roles/{role}/tasks/main.yml")
    assert f"ansible_run_tags | list | sort == ['{tag}']" in tasks
    assert "ansible_limit is defined" in tasks
    playbook = yaml.safe_load(read(f"playbooks/{role.replace('_', '-')}.yml"))
    assert playbook[0]["roles"][0] == {"role": role, "tags": [tag]}


def test_sdn_apply_is_opt_in_and_never_deletes_or_retags():
    assert defaults("proxmox_sdn")["proxmox_sdn_apply"] is False
    tasks = read("roles/proxmox_sdn/tasks/main.yml")
    assert "pvesh, delete" not in tasks and "'delete'" not in tasks
    assert "proxmox_sdn_vnet_live.tag | int == item.value.tag | int" in tasks
    assert "proxmox_sdn_live_nodes == proxmox_sdn_nodes" in tasks
    assert "'--vxlan-port'" in tasks or "--vxlan-port" in tasks
    assert "proxmox_sdn_pending | rejectattr('id', 'in', proxmox_sdn_owned)" in tasks


def test_sdn_apply_runs_under_the_shared_guard_and_verifies_every_node():
    tasks = yaml.safe_load(read("roles/proxmox_sdn/tasks/main.yml"))
    names = [task["name"] for task in tasks]
    order = [
        "Check every node before any SDN change (network file layout, drift, VXLAN guard)",
        "Release HA watchdogs before applying SDN",
        "Arm the SDN dead-man timer on every node",
        "Apply and verify the SDN configuration",
        "Disarm the SDN dead-man timer after successful verification",
        "Restore HA after successful verification",
    ]
    assert [names.index(name) for name in order] == sorted(names.index(name) for name in order)
    apply_block = tasks[names.index("Apply and verify the SDN configuration")]
    block_names = [task["name"] for task in apply_block["block"]]
    assert block_names[0] == "Apply the SDN configuration (asynchronous reload on every node)"
    assert "Wait until every node runs the declared VNets" in block_names
    assert "Confirm no node lost its address or default route" in block_names
    assert apply_block["rescue"][0]["name"] == "Revert the SDN network file on every reachable node"


def test_sdn_revert_restores_the_snapshot_without_double_quotes():
    values = defaults("proxmox_sdn")
    for key in ("proxmox_sdn_snapshot_command", "proxmox_sdn_revert_command"):
        assert '"' not in values[key]
    assert "ifreload -a" in values["proxmox_sdn_revert_command"]
    assert "sdn.prev" in values["proxmox_sdn_revert_command"]


def test_sdn_node_check_requires_the_vxlan_guard_and_checks_the_port():
    script = ROLES / "proxmox_sdn" / "files" / "sdn-node-check.sh"
    subprocess.run(["sh", "-n", str(script)], check=True)
    text = script.read_text(encoding="utf-8")
    assert "--match-set [^ ]+ src -m udp --dport $port -j RETURN" in text
    assert "dstport $port " in text
    assert "ifquery --check -a" in text
    assert "/etc/network/interfaces.new" in text


def test_change_guard_uses_per_resource_mode_only_and_refuses_direct_use():
    ha = read("roles/proxmox_change_guard/tasks/ha.yml")
    assert "crm-command" not in "\n".join(line for line in ha.splitlines() if not line.lstrip().startswith("#"))
    assert "--state, ignored" in ha
    main = yaml.safe_load(read("roles/proxmox_change_guard/tasks/main.yml"))
    assert "ansible.builtin.fail" in main[0]
    deadman = read("roles/proxmox_change_guard/tasks/deadman.yml")
    assert "systemd-run --unit=" in deadman
    assert "HostKeyAlias=" in deadman


def test_router_vm_is_create_only_with_firewall_off_and_vnet_mtu():
    tasks = read("roles/proxmox_router_vm/tasks/main.yml")
    assert "qm, destroy" not in tasks and "'destroy'" not in tasks
    assert "',firewall=0'" in tasks
    assert "',mtu=1'" in tasks
    assert "Refuse an existing VMID that is not this router" in tasks
    assert '"1"' in tasks.split("Pin the router to its replicated nodes")[1]


def test_router_policy_drops_lan_dns_clamps_mss_and_skips_nat_to_nodes():
    rules = render("network_router", "nftables.conf.j2", **ROUTER)
    assert 'iifname "eth0" udp dport { 53, 67 } drop' in rules
    assert "tcp option maxseg size set rt mtu" in rules
    assert "policy drop;" in rules
    assert 'iifname "eth2" accept comment "ops reaches every zone and the LAN"' in rules
    assert 'iifname "eth1" oifname "eth0" ip daddr != @non_internet accept' in rules
    assert ('iifname "eth3" oifname "eth1" ip saddr 10.10.30.182 ip daddr { 10.10.10.180, 10.10.10.181 } '
            'tcp dport 22 accept comment "deploy"') in rules
    assert ('oifname "eth0" ip saddr { 10.10.10.0/24, 10.10.20.0/24, 10.10.30.0/24 } '
            'ip daddr != { 192.0.2.11, 192.0.2.12, 192.0.2.13 } masquerade') in rules
    assert 'iifname "eth2" tcp dport 22 accept' in rules
    assert 'iifname "eth1" tcp dport 22 accept' not in rules


def test_router_ruleset_parses_with_nft_when_available():
    nft = shutil.which("nft") or (Path("/usr/sbin/nft") if Path("/usr/sbin/nft").exists() else None)
    unshare = shutil.which("unshare")
    if not nft or not unshare:
        pytest.skip("nft or unshare not available")
    rules = render("network_router", "nftables.conf.j2", **ROUTER)
    result = subprocess.run([unshare, "-rn", str(nft), "--check", "--file", "-"], input=rules,
                            text=True, capture_output=True)
    if result.returncode != 0 and "Operation not permitted" in result.stderr:
        pytest.skip("user namespaces unavailable")
    assert result.returncode == 0, result.stderr


def test_dnsmasq_serves_only_the_vnets_and_announces_the_mtu():
    conf = render("network_router", "dnsmasq.conf.j2", **ROUTER)
    assert [line for line in conf.splitlines() if line.startswith("interface=")] == [
        "interface=eth1", "interface=eth2", "interface=eth3"]
    assert "bind-interfaces" in conf
    assert "no-dhcp-interface=eth0" in conf
    assert "except-interface=lo" in conf
    assert "dhcp-range=set:svc,10.10.10.200,10.10.10.219,255.255.255.0,12h" in conf
    assert "dhcp-option=tag:svc,option:mtu,1450" in conf
    assert "dhcp-host=bc:24:11:00:00:01,10.10.10.104,app" in conf
    assert "dhcp-range=set:ops" not in conf


def test_router_role_blocks_service_starts_and_guards_the_ruleset():
    tasks = read("roles/network_router/tasks/main.yml")
    assert "/usr/sbin/policy-rc.d" in tasks
    assert "nft, --check, --file" in tasks
    assert "network-router-deadman" in tasks
    assert tasks.index("Disable IPv6 and enable IPv4 forwarding") < tasks.index("Install router packages")
    assert tasks.index("Install and load the new ruleset") < tasks.index("Render the dnsmasq configuration")


def test_route_hook_only_acts_for_the_route_interface(tmp_path):
    hook = tmp_path / "hook"
    hook.write_text(render(
        "proxmox_node_routes", "netiso-routes.sh.j2",
        proxmox_node_routes_list=[{"cidr": "10.10.0.0/16", "via": "192.0.2.240"}],
    ), encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IEXEC)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "calls"
    fake_ip = fake_bin / "ip"
    fake_ip.write_text(f'#!/bin/sh\necho "$@" >> {log}\nexit 1\n', encoding="utf-8")
    fake_ip.chmod(0o755)
    env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}")
    for iface, mode in (("eth9", "start"), ("vmbr0", "stop")):
        assert subprocess.run([str(hook)], env=dict(env, IFACE=iface, MODE=mode)).returncode == 0
    assert not log.exists()
    assert subprocess.run([str(hook)], env=dict(env, IFACE="vmbr0", MODE="start")).returncode == 0
    assert log.read_text(encoding="utf-8").split("\n")[0] == "route replace 10.10.0.0/16 via 192.0.2.240 dev vmbr0"


def test_node_routes_never_reload_the_network():
    tasks = read("roles/proxmox_node_routes/tasks/main.yml")
    assert "ifreload" not in tasks
    assert "addon_scripts_support" in tasks
    assert "ifquery, --check, -a" in tasks


def test_docs_describe_the_private_network_roles():
    architecture = read("docs/architecture.md")
    safety = read("docs/safety.md")
    for role in ("proxmox_sdn", "proxmox_router_vm", "network_router", "proxmox_node_routes", "proxmox_change_guard"):
        assert role in architecture
    assert "nft --check" in safety
    assert "ifquery --check -a" in safety
    assert "network_routers:" in read("inventories/example/hosts.yml")
