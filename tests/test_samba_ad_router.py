"""QEMU NIC and restricted-zone policy tests; all state is synthetic."""
import copy
import importlib.util
from pathlib import Path
import pytest
from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]


def module():
    path = ROOT / "tools/samba_ad/router_nic.py"
    assert path.exists(), "QEMU extension is missing"
    spec = importlib.util.spec_from_file_location("router_nic", path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def request():
    return {"node": "node-a", "vmid": 800040, "name": "router-test", "smbios1": "uuid=example",
            "expected_digest": "a" * 40, "nic": "net4", "mac": "02:00:5E:70:00:40", "bridge": "vnidtest",
            "mtu": 1450, "interface": "eth4", "address": "198.51.100.1/25",
            "existing_nics": {"net0": "virtio=02:00:5E:00:00:01,bridge=vmbr0,firewall=0",
                              "net1": "virtio=02:00:5E:00:00:02,bridge=vnold,firewall=0,mtu=1"}}


def config():
    r = request()
    return {"name": r["name"], "smbios1": r["smbios1"], "digest": r["expected_digest"],
            "scsi0": "store:vm-800040-disk-0,size=16G", "ostype": "l26", **r["existing_nics"]}


def test_extension_adds_one_exact_nic_and_never_replaces_existing_interfaces():
    m = module(); r = request(); c = config(); before = copy.deepcopy(c)
    result = m.plan(r, c, [])
    assert result["action"] == "add"
    assert result["params"] == {"digest": "a" * 40, "net4": "virtio=02:00:5E:70:00:40,bridge=vnidtest,firewall=0,mtu=1450"}
    assert c == before
    c["net4"] = result["params"]["net4"]
    assert m.plan(r, c, [])["action"] == "verify"


@pytest.mark.parametrize("change", ["digest", "name", "uuid", "nic_collision", "uplink", "pending", "extra_nic"])
def test_qemu_router_drift_is_rejected(change):
    m = module(); r = request(); c = config(); pending = []
    if change == "digest": c["digest"] = "b" * 40
    if change == "name": c["name"] = "foreign"
    if change == "uuid": c["smbios1"] = "uuid=foreign"
    if change == "nic_collision": c["net4"] = "virtio=02:00:5E:70:00:41,bridge=vnforeign"
    if change == "uplink": c["net0"] += ",link_down=1"
    if change == "pending": pending = [{"key": "memory", "pending": 2048}]
    if change == "extra_nic": c["net5"] = "virtio=02:00:5E:70:00:50,bridge=vnforeign"
    with pytest.raises(ValueError): m.plan(r, c, pending)


def test_persistent_network_matches_mac_without_default_route_or_dns():
    text = module().network_text(request())
    assert "MACAddress=02:00:5E:70:00:40" in text
    assert "Address=198.51.100.1/25" in text and "MTUBytes=1450" in text
    assert "DHCP=no" in text and "IPv6AcceptRA=no" in text and "LinkLocalAddressing=no" in text
    assert "Gateway=" not in text and "DNS=" not in text


def render():
    env = Environment(loader=FileSystemLoader(ROOT / "roles/network_router/templates"))
    env.filters["bool"] = bool
    values = {"ansible_managed": "test", "network_router_wan_interface": "eth0", "network_router_lan_cidr": "192.0.2.0/24",
              "network_router_admin_sources": ["192.0.2.25/32"], "network_router_pve_nodes": [],
              "network_router_zones": {"ops": {"interface": "eth2", "cidr": "203.0.113.0/25", "full_access": True},
                  "identity": {"interface": "eth4", "cidr": "198.51.100.0/25", "restricted": True}},
              "network_router_mtu": 1450, "network_router_lan_to_private": True,
              "network_router_forward_rules": [{"from": "wan", "to": "identity", "saddr": "192.0.2.25/32",
                    "daddr": "198.51.100.80", "proto": "tcp", "dport": 22, "comment": "approved admin"}]}
    return env.get_template("nftables.conf.j2").render(**values)


def test_restricted_zone_is_filtered_before_broad_legacy_lan_ops_access():
    text = render()
    assert 'iifname "eth4" jump restricted_identity' in text
    assert 'oifname "eth4" jump restricted_identity' in text
    assert text.index('jump restricted_identity') < text.index('ops reaches every zone and the LAN')
    assert text.index('jump restricted_identity') < text.index('trusted LAN into the VNets')
    chain = text.split('chain restricted_identity {')[1].split('}')[0]
    assert '192.0.2.25/32' in chain and '198.51.100.80' in chain and 'tcp dport 22' in chain
    assert 'counter drop' in chain
    assert 'iifname { "eth2" } udp dport { 53, 67 } accept' in text
    assert 'ops reaches every zone and the LAN' in text


def test_manual_entrypoints_have_disabled_defaults_and_one_narrow_tag():
    import yaml
    for name in ["samba_ad_guest", "samba_ad_router_nic"]:
        defaults = ROOT / "roles" / name / "defaults/main.yml"
        assert defaults.exists(), "manual guarded role missing"
        values = yaml.safe_load(defaults.read_text())
        assert values[name + "_enabled"] is False and values[name + "_apply"] is False
        play = yaml.safe_load((ROOT / "playbooks" / (name.replace("_", "-") + ".yml")).read_text())[0]
        assert play["roles"][0]["tags"] == [name]
        tasks = (ROOT / "roles" / name / "tasks/main.yml").read_text()
        assert "ansible_limit | trim == inventory_hostname" in tasks
        assert "ansible_play_hosts_all | length == 1" in tasks
        assert "ansible_run_tags | list | sort == ['" + name + "']" in tasks


def test_restricted_identity_zone_has_no_dnsmasq_listener():
    import yaml
    env = Environment(loader=FileSystemLoader(ROOT / "roles/network_router/templates"))
    import re
    env.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(pattern, replacement, value)
    values = yaml.safe_load((ROOT / "roles/network_router/defaults/main.yml").read_text())
    values["ansible_managed"] = "test"
    values["network_router_zones"] = {"ops": {"interface": "eth2"}, "identity": {"interface": "eth4", "restricted": True}}
    text = env.get_template("dnsmasq.conf.j2").render(**values)
    assert "interface=eth2" in text
    assert "interface=eth4" not in text


def test_recovery_can_remove_exact_own_pending_nic_but_refuses_foreign_pending():
    m = module(); r = request(); c = config(); c["net4"] = m.nic_text(r)
    pending = [{"key": "net4", "pending": c["net4"]}]
    assert m.plan(r, c, pending, reverting=True)["action"] == "verify"
    with pytest.raises(ValueError): m.plan(r, c, pending)
    with pytest.raises(ValueError): m.plan(r, c, pending + [{"key": "memory", "pending": 2048}], reverting=True)


@pytest.mark.parametrize("host_state,expected", [("residual", 2), ("read_error", 2), ("absent", 0)])
def test_revert_already_absent_always_proves_host_tap_absence(monkeypatch, capsys, host_state, expected):
    import io, json
    m = module(); r = request(); cfg = config(); calls = []; host_checks = []
    def api(method, path, **params):
        calls.append((method, path, params))
        assert method == "get", "absent revert must stay readonly"
        if path.endswith("/config"):
            assert params.get("current") == 1
            return cfg.copy()
        if path.endswith("/pending"): return []
        if path.endswith("/status/current"): return {"status": "running"}
        raise AssertionError(path)
    def host(r):
        host_checks.append(True)
        if host_state == "read_error": raise OSError("host read unavailable")
        return host_state == "residual"
    monkeypatch.setattr(m, "api", api); monkeypatch.setattr(m, "host_nic_present", host)
    monkeypatch.setattr(m.sys, "stdin", io.StringIO(json.dumps(r))); monkeypatch.setattr(m.sys, "argv", ["router_nic.py", "--revert"])
    assert m.main() == expected
    assert host_checks == [True]
    if expected == 0: assert json.loads(capsys.readouterr().out)["changed"] is False


def test_revert_retry_after_delete_still_refuses_a_residual_tap(monkeypatch):
    import io, json
    m = module(); r = request(); cfg = config(); cfg["net4"] = m.nic_text(r); deletes = []; checks = []
    def api(method, path, **params):
        if method == "set": deletes.append(path); cfg.pop("net4", None); return None
        if path.endswith("/config"):
            assert params.get("current") == 1
            return cfg.copy()
        if path.endswith("/pending"): return []
        if path.endswith("/status/current"): return {"status": "running"}
        raise AssertionError(path)
    def host(r): checks.append(True); return True
    monkeypatch.setattr(m, "api", api); monkeypatch.setattr(m, "host_nic_present", host)
    monkeypatch.setattr(m.sys, "argv", ["router_nic.py", "--revert"])
    for _ in range(2):
        monkeypatch.setattr(m.sys, "stdin", io.StringIO(json.dumps(r)))
        assert m.main() == 2
    assert len(deletes) == 1 and len(checks) == 2


def qga_plan(monkeypatch, *, output=None, ping_rc=0, exec_rc=0, drift=None, argv=None):
    """Exercise the real CLI preflight with only PVE/QGA boundaries replaced."""
    import io, json, types
    m = module(); r = request(); c = config(); pending = []; calls = []; gets = []
    if drift == "digest": c["digest"] = "b" * 40
    if drift == "name": c["name"] = "foreign"
    if drift == "smbios": c["smbios1"] = "uuid=foreign"
    if drift == "pending": pending = [{"key": "memory", "pending": 2048}]
    if output is None: output = {"exitcode": 0, "exited": 1, "out-data": "0\n"}
    def api(method, path, **params):
        assert method == "get", "QGA preflight must not mutate PVE"
        assert path.startswith("/nodes/node-a/qemu/800040/")
        gets.append(path)
        if path.endswith("/config"): return c.copy()
        if path.endswith("/pending"): return pending
        if path.endswith("/status/current"): return {"status": "running"}
        raise AssertionError(path)
    def run(args, **kwargs):
        calls.append(args)
        assert args[:3] in [["qm", "guest", "cmd"], ["qm", "guest", "exec"]]
        assert args[3] == str(r["vmid"])
        assert kwargs.get("timeout") and kwargs.get("capture_output")
        ping = args[2] == "cmd"
        return types.SimpleNamespace(returncode=ping_rc if ping else exec_rc,
            stdout="" if ping else json.dumps(output), stderr="suppressed failure detail")
    monkeypatch.setattr(m, "api", api); monkeypatch.setattr(m.subprocess, "run", run)
    monkeypatch.setattr(m.socket, "gethostname", lambda: "foreign" if drift == "node" else "node-a")
    monkeypatch.setattr(m.sys, "stdin", io.StringIO(json.dumps(r)))
    monkeypatch.setattr(m.sys, "argv", argv or ["router_nic.py", "--plan", "--qga-preflight"])
    return m.main(), calls, gets


def test_qga_preflight_pings_then_proves_root_on_exact_vm_without_mutation(monkeypatch):
    result, calls, gets = qga_plan(monkeypatch)
    assert result == 0
    assert calls == [["qm", "guest", "cmd", "800040", "ping"],
                     ["qm", "guest", "exec", "800040", "--timeout", "10", "--", "/usr/bin/id", "-u"]]
    assert gets


@pytest.mark.parametrize("output", [{"exitcode": 0, "exited": 1, "out-data": "1000\n"},
    {"exitcode": 1, "exited": 1, "out-data": "0\n"},
    {"exitcode": 0, "exited": 0, "out-data": "0\n"},
    {"exitcode": 0, "exited": 1, "out-data": "0\n", "out-truncated": 1},
    {"exitcode": 0, "exited": 1, "out-data": 0}, {}])
def test_qga_preflight_refuses_nonroot_incomplete_or_ambiguous_exec(monkeypatch, output):
    result, calls, _ = qga_plan(monkeypatch, output=output)
    assert result == 2 and len(calls) == 2


@pytest.mark.parametrize("phase", ["ping", "exec"])
def test_qga_preflight_does_not_enable_or_repair_unavailable_agent(monkeypatch, phase):
    result, calls, _ = qga_plan(monkeypatch, ping_rc=1 if phase == "ping" else 0,
                               exec_rc=1 if phase == "exec" else 0)
    assert result == 2 and len(calls) == (1 if phase == "ping" else 2)


@pytest.mark.parametrize("drift", ["node", "digest", "name", "smbios", "pending"])
def test_qga_preflight_cannot_bypass_router_identity_or_pending_guards(monkeypatch, drift):
    result, calls, _ = qga_plan(monkeypatch, drift=drift)
    assert result == 2 and not calls


@pytest.mark.parametrize("argv", [["router_nic.py", "--qga-preflight"],
    ["router_nic.py", "--plan", "--qga-preflight", "--revert"]])
def test_qga_preflight_cannot_be_combined_with_mutation(monkeypatch, argv):
    result, calls, _ = qga_plan(monkeypatch, argv=argv)
    assert result == 2 and not calls


def test_qga_recovery_is_separate_false_default_and_precedes_all_mutations():
    import yaml
    defaults = yaml.safe_load((ROOT / "roles/samba_ad_router_nic/defaults/main.yml").read_text())
    example = yaml.safe_load((ROOT / "contracts/samba_ad/s1-router-nic-example.yml").read_text())
    flag = "samba_ad_router_nic_qga_recovery"
    assert defaults.get(flag) is False and example.get(flag) is False
    assert defaults["samba_ad_router_nic_console_verified"] is False
    tasks = yaml.safe_load((ROOT / "roles/samba_ad_router_nic/tasks/main.yml").read_text())
    qga = next((i, t) for i, t in enumerate(tasks)
               if "--qga-preflight" in t.get("ansible.builtin.command", {}).get("argv", []))
    apply = next(i for i, t in enumerate(tasks) if t.get("ansible.builtin.include_tasks") == "apply.yml")
    assert qga[0] < apply and qga[1]["when"] == flag
    assert "StrictHostKeyChecking=yes" in qga[1]["vars"]["ansible_ssh_args"]
    assert "UpdateHostKeys=no" in qga[1]["vars"]["ansible_ssh_args"]
    assert qga[1]["no_log"] and qga[1]["changed_when"] is False
    conditions = [condition for t in tasks for condition in t.get("ansible.builtin.assert", {}).get("that", [])]
    assert "samba_ad_router_nic_console_verified or " + flag in conditions
