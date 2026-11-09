import json
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


@pytest.mark.parametrize("role", ["proxmox_sdn", "proxmox_router_vm", "network_router", "proxmox_node_routes",
                                  "proxmox_guest_network", "proxmox_guest_routes", "proxmox_guest_nic"])
def test_new_infrastructure_roles_are_disabled_by_default(role):
    assert defaults(role)[f"{role}_enabled"] is False


@pytest.mark.parametrize(
    ("role", "tag"),
    [
        ("proxmox_sdn", "proxmox_sdn"),
        ("proxmox_router_vm", "proxmox_router_vm"),
        ("network_router", "network_router"),
        ("proxmox_node_routes", "proxmox_node_routes"),
        ("proxmox_guest_network", "proxmox_guest_network"),
        ("proxmox_guest_routes", "proxmox_guest_routes"),
        ("proxmox_guest_nic", "proxmox_guest_nic"),
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


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("apply", [False, True])
@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("pending", [[], [{"id": "vnold"}]])
@pytest.mark.parametrize("mapping", [{}, {"vnold": "4096"}])
def test_sdn_policy_flag_pending_action_trace(enabled, apply, check, pending, mapping):
    tasks = yaml.safe_load(read("roles/proxmox_sdn/tasks/main.yml"))
    policy_tasks = [t for t in tasks if t.get("ansible.builtin.include_tasks") == "bridge-policy.yml"]
    assert len(policy_tasks) == 2, "separate all-node preflight and serial installation required"
    env = jinja2.Environment()
    env.filters["bool"] = bool
    context = dict(proxmox_sdn_enabled=enabled, proxmox_sdn_apply=apply,
                   ansible_check_mode=check, proxmox_sdn_pending=pending,
                   proxmox_sdn_bridge_hashmax=mapping)
    decision = next(t for t in tasks if "proxmox_sdn_live_apply" in t.get("ansible.builtin.set_fact", {}))
    context["proxmox_sdn_live_apply"] = env.from_string(
        decision["ansible.builtin.set_fact"]["proxmox_sdn_live_apply"]).render(context).strip() == "True"
    def allowed(task):
        return enabled and bool(env.compile_expression(task.get("when", "true"))(**context))
    trace = [t["vars"]["proxmox_sdn_policy_action"] for t in policy_tasks if allowed(t)]
    assert ("install" in trace) == (enabled and apply and not check and bool(mapping))
    guarded = [t for t in tasks if t.get("when", "").startswith("proxmox_sdn_live_apply")]
    assert guarded
    assert any(allowed(t) for t in guarded) == (enabled and apply and not check and bool(pending))
    if not pending and "install" in trace:
        assert not any(allowed(t) for t in guarded), "file-only path reached reload/HA/dead-man"
    names = [t["name"] for t in tasks]
    assert tasks.index(policy_tasks[0]) < names.index("Reconcile declared VXLAN zones in the pending SDN configuration")
    assert names.index("Refuse to apply pending changes the inventory does not own") < tasks.index(policy_tasks[1])
    assert tasks.index(policy_tasks[1]) < names.index("Back up SDN and node network configuration before applying")
    assert all("rescue" not in t for t in policy_tasks)


@pytest.mark.parametrize("failure", ["install", "verify"])
def test_sdn_serial_policy_include_stops_before_next_node_on_failure(failure):
    main = yaml.safe_load(read("roles/proxmox_sdn/tasks/main.yml"))
    included = yaml.safe_load(read("roles/proxmox_sdn/tasks/bridge-policy.yml"))
    install = next(t for t in main if t.get("vars", {}).get("proxmox_sdn_policy_action") == "install")
    assert install["ansible.builtin.include_tasks"] == "bridge-policy.yml"
    assert install["loop_control"]["loop_var"] == "proxmox_sdn_policy_node"
    commands = [t for t in included if "ansible.builtin.command" in t]
    assert len(commands) == 2
    assert all("loop" not in t and "with_items" not in t for t in commands)
    assert all("failed_when" in t and not t.get("ignore_errors") and not t.get("rescue") for t in commands)
    # Local action trace of the parsed sequential include boundary. Ansible's
    # failed task ends the host's task stream; no command loop can keep writing.
    trace = []
    failed = False
    for node in ["node-a", "node-b", "node-c"]:
        for action, task in zip(["install", "verify"], commands):
            trace.append((node, action))
            if node == "node-b" and action == failure:
                failed = bool(task["failed_when"])
                break
        if failed: break
    assert trace[-1] == ("node-b", failure)
    assert not any(node == "node-c" for node, _ in trace)


@pytest.mark.parametrize("action,expected", [("inspect", False), ("install", True)])
def test_sdn_policy_transport_unknown_is_failed_and_install_is_not_reported_unchanged(action, expected):
    task = yaml.safe_load(read("roles/proxmox_sdn/tasks/bridge-policy.yml"))[0]
    env = jinja2.Environment()
    env.filters.update({"bool": bool, "from_json": json.loads})
    context = {"proxmox_sdn_policy_action": action,
               "proxmox_sdn_policy_result": {"rc": 255, "stdout": ""}}
    assert env.compile_expression(task["changed_when"])(**context) is expected
    assert env.compile_expression(task["failed_when"])(**context) is True


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
    assert ("tcp flags & (syn | rst) == syn tcp option maxseg size > 1410 "
            "tcp option maxseg size set 1410") in rules
    assert "set rt mtu" not in rules
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
    assert "host-record=" not in conf


def test_dnsmasq_answers_split_horizon_records_with_the_exact_name_only():
    records = [{"name": "app.example.com", "address": "192.0.2.139"},
               {"name": "stg-app.example.com", "address": "192.0.2.139"}]
    conf = render("network_router", "dnsmasq.conf.j2", **ROUTER, network_router_dns_host_records=records)
    assert [line for line in conf.splitlines() if line.startswith("host-record=")] == [
        "host-record=app.example.com,192.0.2.139", "host-record=stg-app.example.com,192.0.2.139"]
    # address=/name/ would also answer every subdomain; host-record keeps the override to the exact names.
    assert "address=/" not in conf
    assert defaults("network_router")["network_router_dns_host_records"] == []


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


GUEST_TASKS = ROLES / "proxmox_guest_network" / "tasks"
GUEST_FILES = ROLES / "proxmox_guest_network" / "files"


def guest_tasks(name: str) -> list:
    return yaml.safe_load((GUEST_TASKS / name).read_text(encoding="utf-8"))


def test_guest_move_is_one_guest_on_its_own_node_and_refuses_unexpected_state():
    tasks = read("roles/proxmox_guest_network/tasks/main.yml")
    assert "(ansible_limit | split(',') | map('trim') | list) == [inventory_hostname]" in tasks
    assert "proxmox_guest_network_spec.node == inventory_hostname" in tasks
    assert "select('match', '^net[1-9][0-9]*$') | list | length == 0" in tasks
    assert "proxmox_guest_network_pending | length == 0" in tasks
    assert "proxmox_guest_network_ha[0].state == 'started'" in tasks
    assert "failed_when: proxmox_guest_network_busy.rc not in [1]" in tasks
    assert "- list-jobs" in tasks
    assert "proxmox_guest_network_jobs.stdout | trim | length == 0" in tasks
    assert "ip -4 neigh flush to" in tasks and "is search('lladdr')" in tasks
    assert "force: false" in read("roles/proxmox_guest_network/tasks/change.yml")


def test_guest_move_keeps_the_mac_and_changes_only_the_network_keys():
    tasks = read("roles/proxmox_guest_network/tasks/main.yml")
    assert "proxmox_guest_network_net0 | combine({'bridge': spec.to.bridge, 'ip': spec.to.ip," in tasks
    assert "'gw': spec.to.gw, 'mtu': proxmox_guest_network_mtu | string})" in tasks
    check = read("roles/proxmox_guest_network/tasks/set.yml")
    assert "got_net0 == want_net0" in check
    assert "got_net0.hwaddr == proxmox_guest_network_net0.hwaddr" in check


def test_guest_move_is_cold_snapshotted_and_restores_on_failure():
    block = guest_tasks("change.yml")[0]
    names = [task["name"] for task in block["block"]]
    order = ["Write the target MTU into the guest eth0 stanza before the stop", "Stop the guest",
             "Snapshot the stopped guest", "Apply the new network settings", "Start the guest",
             "Keep the guest MTU in step with its new net0", "Verify the guest at its new place"]
    assert [n for n in names if n in order] == order
    restore = block["rescue"][1]
    assert restore["when"] == "proxmox_guest_network_touched | default(false) | bool"
    assert [t["name"] for t in restore["block"]] == [
        "Stop the guest before putting the settings back", "Put back the settings read before this run",
        "Start the guest with its previous settings", "Keep the guest MTU in step with its previous net0",
        "Verify the guest at its previous place"]
    assert "ansible.builtin.fail" in block["rescue"][-1]


def test_guest_power_goes_through_ha_for_ha_guests():
    power = read("roles/proxmox_guest_network/tasks/power.yml")
    assert "- ha-manager" in power and "--state" in power
    assert "proxmox_guest_network_ha | length == 0" in power


def run_mtu(tmp_path, content: str, *args: str) -> tuple:
    path = tmp_path / "interfaces"
    path.write_text(content, encoding="utf-8")
    # A missing sysfs root keeps "post" off the real links of the test machine
    # (a CI runner has an eth0 and would get "ip link set" on it).
    env = dict(os.environ, NETISO_INTERFACES_FILE=str(path),
               NETISO_SYS_CLASS_NET=str(tmp_path / "no-sys-class-net"))
    result = subprocess.run(["sh", str(GUEST_FILES / "guest-mtu.sh"), *args], env=env,
                            capture_output=True, text=True)
    return result, path.read_text(encoding="utf-8")


def test_guest_mtu_script_survives_pve_rewrites_and_is_idempotent(tmp_path):
    dhcp = "auto eth0\niface eth0 inet dhcp\n\n"
    result, text = run_mtu(tmp_path, dhcp, "pre", "1450")
    assert result.returncode == 0 and result.stdout == "file=changed\n"
    assert "iface eth0 inet dhcp\n\tmtu 1450\n" in text
    pve_static = "auto eth0\niface eth0 inet static\n\taddress 10.0.0.5/24\n\tgateway 10.0.0.1\n\tmtu 1450\n\n"
    result, text = run_mtu(tmp_path, pve_static, "post", "1450")
    assert result.returncode == 0 and "file=changed" not in result.stdout and text == pve_static
    result, text = run_mtu(tmp_path, pve_static, "post", "1500")
    assert "\tmtu 1500\n" in text and "mtu 1450" not in text
    result, text = run_mtu(tmp_path, "auto eth0\niface eth0 inet dhcp\n\tmtu 1450\n\n", "post", "1500")
    assert "mtu" not in text
    result, _ = run_mtu(tmp_path, "auto lo\n", "post", "1500")
    assert result.returncode == 3


def test_guest_mtu_script_targets_only_the_named_interface(tmp_path):
    two = ("auto eth0\niface eth0 inet dhcp\n\n"
           "auto eth1\niface eth1 inet static\n\taddress 10.0.0.5/24\n\n")
    result, text = run_mtu(tmp_path, two, "post", "1450", "eth1")
    assert result.returncode == 0 and result.stdout == "file=changed\n"
    assert text == ("auto eth0\niface eth0 inet dhcp\n\n"
                    "auto eth1\niface eth1 inet static\n\tmtu 1450\n\taddress 10.0.0.5/24\n\n")
    result, again = run_mtu(tmp_path, text, "post", "1450", "eth1")
    assert result.stdout == "" and again == text
    result, _ = run_mtu(tmp_path, two, "post", "1450", "eth1; reboot")
    assert result.returncode == 2
    result, _ = run_mtu(tmp_path, "auto eth0\niface eth0 inet dhcp\n\n", "post", "1450", "eth1")
    assert result.returncode == 3


def test_guest_probe_never_prints_addresses():
    probe = (GUEST_FILES / "guest-probe.sh").read_text(encoding="utf-8")
    echoes = [line for line in probe.splitlines() if "echo" in line]
    assert all("$cidr" not in line and "$gw" not in line and "$v4" not in line for line in echoes)
    assert "result=ok" in probe and "full_size_frame" in probe and "mac_unchanged" in probe


def test_docs_describe_guest_network_moves():
    assert "proxmox_guest_network" in read("docs/architecture.md")
    assert "ha-manager set --state" in read("docs/safety.md")


def test_guest_route_hook_acts_only_for_its_interface_and_never_reloads(tmp_path):
    hook = render("proxmox_guest_routes", "netiso-routes.sh.j2", proxmox_guest_routes_spec={
        "interface": "eth0", "routes": [{"cidr": "10.10.0.0/16", "via": "192.0.2.249"}]})
    assert "ip route replace 10.10.0.0/16 via 192.0.2.249 dev eth0 || true" in hook
    script = tmp_path / "hook.sh"
    script.write_text(hook.replace("ip route replace", "echo ip route replace"), encoding="utf-8")
    other = subprocess.run(["sh", str(script)], env=dict(os.environ, IFACE="eth1", MODE="start"),
                           capture_output=True, text=True)
    assert other.returncode == 0 and other.stdout == ""
    stop = subprocess.run(["sh", str(script)], env=dict(os.environ, IFACE="eth0", MODE="stop"),
                          capture_output=True, text=True)
    assert stop.returncode == 0 and stop.stdout == ""
    tasks = read("roles/proxmox_guest_routes/tasks/main.yml")
    assert "ifreload" not in tasks and "pct reboot" not in tasks and "addon_scripts_support" in tasks


NIC_FILES = ROOT / "roles" / "proxmox_guest_nic" / "files"


def test_guest_nic_is_hot_secondary_and_never_takes_the_default_route():
    tasks = read("roles/proxmox_guest_nic/tasks/main.yml")
    assert "proxmox_guest_nic_spec.gw is not defined" in tasks
    assert "proxmox_guest_nic_spec.nic is match('^net[1-9]$')" in tasks
    assert "'firewall': '1'" in tasks
    assert "pct stop" not in tasks and "pct reboot" not in tasks and "ha-manager" not in tasks
    assert "proxmox_guest_nic_action != 'unknown'" in tasks
    assert tasks.count("guest-nic-forget.sh") == 2
    verify = read("roles/proxmox_guest_nic/tasks/verify.yml")
    assert "/../proxmox_guest_network/files/guest-mtu.sh" in verify
    assert "result=ok" in verify


def test_guest_nic_probe_never_prints_addresses():
    probe = (NIC_FILES / "guest-nic-probe.sh").read_text(encoding="utf-8")
    echoes = [line for line in probe.splitlines() if "echo" in line]
    assert all("$cidr" not in line and "$v4" not in line and "$probe" not in line for line in echoes)
    assert "default_route_elsewhere" in probe and "full_size_frame" in probe


def test_guest_nic_forget_drops_only_the_named_stanza(tmp_path):
    path = tmp_path / "interfaces"
    path.write_text("auto eth0\niface eth0 inet dhcp\n\nauto eth1\niface eth1 inet static\n"
                    "\taddress 10.0.0.5/24\n\tmtu 1450\n\nsource /etc/network/interfaces.d/*\n",
                    encoding="utf-8")
    env = dict(os.environ, NETISO_INTERFACES_FILE=str(path))
    script = str(NIC_FILES / "guest-nic-forget.sh")
    first = subprocess.run(["sh", script, "eth1"], env=env, capture_output=True, text=True)
    text = path.read_text(encoding="utf-8")
    assert first.returncode == 0 and first.stdout == "file=changed\n"
    assert "eth1" not in text and "iface eth0 inet dhcp" in text and "source " in text
    again = subprocess.run(["sh", script, "eth1"], env=env, capture_output=True, text=True)
    assert again.returncode == 0 and again.stdout == ""
    refused = subprocess.run(["sh", script, "eth0"], env=env, capture_output=True, text=True)
    assert refused.returncode == 2
