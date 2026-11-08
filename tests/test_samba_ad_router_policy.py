"""Exercise exact ownership and ordering of the NIC's two persistent files."""
import importlib.util
import os
from pathlib import Path
import runpy

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
R = runpy.run_path(str(ROOT / "tests/test_samba_ad_router.py"))


def module(tmp_path, monkeypatch):
    source = ROOT / "tools/samba_ad/router_policy.py"
    assert source.exists(), "Missing persistent NIC naming policy lifecycle"
    spec = importlib.util.spec_from_file_location("router_policy", source)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m, "NETWORK", tmp_path / "05-samba-ad-identity.network")
    monkeypatch.setattr(m, "LINK", tmp_path / "05-samba-ad-identity.link")
    monkeypatch.setattr(m, "SYS_CLASS_NET", tmp_path / "sys-class-net")
    # Ownership is real on production (root); the fixture also works unprivileged.
    monkeypatch.setattr(m, "OWNER", (os.getuid(), os.getgid()))
    return m


def inputs():
    r = R["request"]()
    return r, R["module"]().network_text(r)


def owned(m, subset=("NETWORK", "LINK")):
    r, network = inputs()
    for path, content in m.expected_files(r, network).items():
        if any(path == getattr(m, name) for name in subset):
            path.write_bytes(content)
            path.chmod(0o644)


def test_policy_clears_predictable_name_policy_and_matches_only_declared_virtio_mac(tmp_path, monkeypatch):
    m = module(tmp_path, monkeypatch)
    r, network = inputs()
    import configparser
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read_string(m.expected_files(r, network)[m.LINK].decode())
    assert dict(config["Match"]) == {"MACAddress": r["mac"].lower(), "Driver": "virtio_net"}
    assert dict(config["Link"]) == {"NamePolicy": "", "Name": r["interface"]}


def test_install_readbacks_both_files_before_reload_and_verify_is_readonly(tmp_path, monkeypatch):
    m = module(tmp_path, monkeypatch)
    r, network = inputs()
    calls = []
    def command(argv):
        m.verify(r, network, "verify")
        calls.append(argv)
    monkeypatch.setattr(m, "command", command)
    m.verify(r, network, "absent")
    m.install(r, network)
    assert calls == [["udevadm", "control", "--reload"]]
    stamps = {p: (p.stat().st_mtime_ns, p.stat().st_ino) for p in (m.NETWORK, m.LINK)}
    m.verify(r, network, "verify")
    m.verify(r, network, "verify")
    assert {p: (p.stat().st_mtime_ns, p.stat().st_ino) for p in stamps} == stamps
    assert len(calls) == 1


@pytest.mark.parametrize("file", ["NETWORK", "LINK"])
@pytest.mark.parametrize("kind", ["foreign", "symlink", "directory", "mode", "owner", "hardlink"])
def test_foreign_or_drifted_file_blocks_install_and_verify_before_mutation(tmp_path, monkeypatch, file, kind):
    m = module(tmp_path, monkeypatch)
    owned(m)
    path = getattr(m, file)
    if kind == "foreign": path.write_bytes(b"!" + path.read_bytes()[1:])
    elif kind == "symlink":
        path.unlink(); path.symlink_to(tmp_path / "missing-target")
    elif kind == "directory": path.unlink(); path.mkdir()
    elif kind == "mode": path.chmod(0o600)
    elif kind == "owner": monkeypatch.setattr(m, "OWNER", (os.getuid()+1, os.getgid()))
    else: os.link(path, tmp_path / "other-name")
    before = {p: p.lstat() for p in (m.NETWORK, m.LINK)}
    calls = []
    monkeypatch.setattr(m, "command", calls.append)
    r, network = inputs()
    for action in [lambda: m.verify(r, network, "absent"), lambda: m.verify(r, network, "verify"),
                   lambda: m.install(r, network), lambda: m.rollback(r, network)]:
        with pytest.raises(ValueError): action()
    assert calls == []
    assert {p: p.lstat() for p in before} == before


@pytest.mark.parametrize("subset", [(), ("NETWORK",), ("LINK",), ("NETWORK", "LINK")])
def test_rollback_handles_partial_presence_and_repeat_without_touching_old_files(tmp_path, monkeypatch, subset):
    m = module(tmp_path, monkeypatch)
    owned(m, subset)
    old = tmp_path / "10-legacy.network"
    old.write_text("legacy")
    stamp = old.stat()
    calls = []
    monkeypatch.setattr(m, "command", calls.append)
    r, network = inputs()
    m.rollback(r, network)
    assert not m.NETWORK.exists() and not m.LINK.exists()
    assert old.stat() == stamp and old.read_text() == "legacy"
    assert calls == (([["networkctl", "reload"]] if "NETWORK" in subset else []) +
                     ([["udevadm", "control", "--reload"]] if "LINK" in subset else []))
    count = len(calls)
    m.rollback(r, network)
    assert len(calls) == count


def test_rollback_checks_actual_name_mac_before_down_or_deletion(tmp_path, monkeypatch):
    m = module(tmp_path, monkeypatch)
    owned(m)
    r, network = inputs()
    iface = m.SYS_CLASS_NET / r["interface"]
    iface.mkdir(parents=True)
    (iface / "address").write_text("02:00:00:00:00:99\n")
    calls = []
    monkeypatch.setattr(m, "command", calls.append)
    with pytest.raises(ValueError): m.rollback(r, network)
    assert calls == [] and m.NETWORK.exists() and m.LINK.exists()
    (iface / "address").write_text(r["mac"].lower() + "\n")
    m.rollback(r, network)
    assert calls[0] == ["networkctl", "down", r["interface"]]


def test_missing_either_owned_file_is_not_a_verified_reexecution(tmp_path, monkeypatch):
    m = module(tmp_path, monkeypatch)
    r, network = inputs()
    for file in ("NETWORK", "LINK"):
        owned(m)
        getattr(m, file).unlink()
        with pytest.raises(ValueError): m.verify(r, network, "verify")


def test_new_kernel_renamed_interface_remains_unsafe():
    state = runpy.run_path(str(ROOT / "tests/test_samba_ad_router_state.py"))
    observed = state["observed"]()
    r = R["request"]()
    for link in observed["links"]:
        if link["ifname"] == r["interface"]: link["ifname"] = "ens22"
    with pytest.raises(ValueError):
        state["module"]().validate(r, observed, state["baseline"](), "preconfigure")


def test_task_order_guards_backup_and_both_deadmen_before_policy_before_hotplug():
    tasks = yaml.safe_load((ROOT / "roles/samba_ad_router_nic/tasks/apply.yml").read_text())
    block = next(t["block"] for t in tasks if "block" in t)
    install = next((t for t in block if t.get("vars", {}).get("samba_ad_router_nic_policy_operation") == "install"), None)
    assert install, "Both naming and network files must be installed/read back/reloaded before hotplug"
    assert block.index(install) < next(i for i,t in enumerate(block) if "Hotplug" in t["name"])
    position = next(i for i,t in enumerate(tasks) if "block" in t)
    for name in ["Preserve existing persistent network files for console recovery",
                 "Arm guest technical network recovery before adding any NIC",
                 "Arm the existing PVE change guard for exact NIC removal"]:
        assert next(i for i,t in enumerate(tasks) if t["name"] == name) < position
    main = yaml.safe_load((ROOT / "roles/samba_ad_router_nic/tasks/main.yml").read_text())
    verify = next((t for t in main if t.get("ansible.builtin.include_tasks") == "policy.yml"), None)
    assert verify, "Add and idempotent verification must validate both owned files"
    assert main.index(verify) < next(i for i,t in enumerate(main) if t.get("ansible.builtin.include_tasks") == "apply.yml")
    assert any(t.get("ansible.builtin.include_tasks") == "policy.yml" and
               t.get("vars", {}).get("samba_ad_router_nic_policy_operation") == "verify" for t in block)


def test_embedded_canonical_recovery_is_valid_shell_and_passes_exact_payload(tmp_path):
    import json
    import shlex
    import subprocess
    from jinja2 import Environment
    tasks = yaml.safe_load((ROOT / "roles/samba_ad_router_nic/tasks/apply.yml").read_text())
    content = next(t["ansible.builtin.copy"]["content"] for t in tasks
                   if t.get("ansible.builtin.copy", {}).get("dest") == "/root/samba-ad-s1-network/revert.sh")
    env = Environment()
    env.filters.update(quote=shlex.quote, to_json=json.dumps)
    r, network = inputs()
    rendered = env.from_string(content).render(
        lookup=lambda *args: (ROOT / "tools/samba_ad/router_policy.py").read_text(),
        playbook_dir=str(ROOT / "playbooks"), samba_ad_router_nic_request=r,
        samba_ad_router_nic_plan={"network": network})
    subprocess.run(["sh", "-n"], input=rendered, text=True, capture_output=True, check=True)
    # Execute with a Python shim: prove the exact embedded program and private
    # payload reach Python intact without executing commands or using host paths.
    shim = tmp_path / "python3"
    shim.write_text("#!/usr/bin/python3\nimport json,sys\n"
                    "print(json.dumps({'source': sys.argv[2], 'payload': json.load(sys.stdin)}))\n")
    shim.chmod(0o700)
    result = subprocess.run(["/bin/sh", "-c", rendered], env={"PATH": str(tmp_path)},
                            text=True, capture_output=True, check=True)
    received = json.loads(result.stdout)
    assert received == {"source": (ROOT / "tools/samba_ad/router_policy.py").read_text(),
                        "payload": {"request": r, "network": network, "operation": "rollback"}}


def test_native_link_parser_in_isolated_mount_and_network_namespaces(tmp_path, monkeypatch):
    import shutil
    import subprocess
    for tool in ["unshare", "mount", "ip", "udevadm"]:
        if not shutil.which(tool): pytest.skip("native parser dependency unavailable: " + tool)
    m = module(tmp_path, monkeypatch)
    r, network = inputs()
    source = tmp_path / "policy.link"
    source.write_bytes(m.expected_files(r, network)[m.LINK])
    script = r'''set -eu
mount --make-rprivate /
mount -t tmpfs tmpfs /etc/systemd/network
mount -t tmpfs tmpfs /run/udev
if [ -d /run/systemd/network ]; then mount -t tmpfs tmpfs /run/systemd/network; fi
mount -t sysfs sysfs /sys
cp "$1" /etc/systemd/network/05-samba-ad-identity.link
ip link add s1parse type dummy
SYSTEMD_LOG_LEVEL=debug udevadm test-builtin net_setup_link /sys/class/net/s1parse
'''
    result = subprocess.run(["unshare", "--user", "--map-root-user", "--mount", "--net",
                             "sh", "-c", script, "native-parser", str(source)], text=True,
                            capture_output=True, timeout=30)
    if "unshare failed: Operation not permitted" in result.stderr:
        pytest.skip("native namespaces unavailable")
    assert result.returncode == 0, result.stderr
    assert 'Parsed configuration file "/etc/systemd/network/05-samba-ad-identity.link"' in result.stderr
    assert "Unknown" not in result.stderr and "Failed to parse" not in result.stderr
    # Dummy is not virtio: this proves parsing only, never a production rename.
    assert "ID_NET_NAME=eth4" not in result.stdout
