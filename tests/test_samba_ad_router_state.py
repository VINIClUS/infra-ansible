"""The guest NIC is identified before reconfigure and during every verification."""
import copy
import importlib.util
from pathlib import Path
import runpy
import pytest
ROOT = Path(__file__).resolve().parents[1]
R = runpy.run_path(str(ROOT / "tests/test_samba_ad_router.py"))


def module():
    path = ROOT / "tools/samba_ad/router_state.py"
    assert path.exists(), "shared live guest readback missing"
    spec = importlib.util.spec_from_file_location("router_state", path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def baseline():
    return {"links": [{"ifname": "eth0", "ifindex": 2, "address": "02:00:5e:00:00:01", "mtu": 1500,
                       "flags": ["UP", "LOWER_UP"], "operstate": "UP", "link_type": "ether",
                       "device": "/sys/devices/pci0000:00/0000:00:01.0/virtio0", "driver": "virtio_net"}],
            "addresses": [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.0.2.40", "prefixlen": 24}]}],
            "routes4": [{"dst": "default", "gateway": "192.0.2.1", "dev": "eth0"}], "routes6": []}


def observed():
    d = baseline()
    d["links"].append({"ifname": "eth4", "ifindex": 6, "address": "02:00:5e:70:00:40", "mtu": 1450,
                       "flags": ["UP", "LOWER_UP"], "operstate": "UP", "link_type": "ether",
                       "device": "/sys/devices/pci0000:00/0000:00:05.0/virtio4", "driver": "virtio_net"})
    d["addresses"].append({"ifname": "eth4", "addr_info": [{"family": "inet", "local": "198.51.100.1", "prefixlen": 25}]})
    d["routes4"].append({"dst": "198.51.100.0/25", "dev": "eth4", "protocol": "kernel"})
    return d


def test_absence_and_new_device_then_live_verify_share_old_network_protection():
    m = module(); r = R["request"](); b = baseline()
    m.validate(r, b, b, "absent")
    d = observed(); m.validate(r, d, b, "preconfigure"); m.validate(r, d, b, "verify")


@pytest.mark.parametrize("identity", ["name", "mac", "address"])
def test_preflight_refuses_name_mac_or_address_already_owned(identity):
    m = module(); r = R["request"](); d = baseline()
    if identity == "name": d["links"][0]["ifname"] = "eth4"
    if identity == "mac": d["links"][0]["address"] = r["mac"].lower()
    if identity == "address": d["addresses"][0]["addr_info"][0]["local"] = r["address"].split("/")[0]
    with pytest.raises(ValueError): m.validate(r, d, d, "absent")


@pytest.mark.parametrize("change", ["mac", "device", "driver", "reused_index", "old_interface", "route"])
def test_reconfigure_precondition_refuses_wrong_device_or_old_network_drift(change):
    m = module(); r = R["request"](); b = baseline(); d = observed()
    if change == "mac": d["links"][-1]["address"] = "02:00:5e:00:00:ff"
    if change == "device": d["links"][-1]["device"] = None
    if change == "driver": d["links"][-1]["driver"] = "veth"
    if change == "reused_index": d["links"][-1]["ifindex"] = 2
    if change == "old_interface": d["links"][0]["mtu"] = 1450
    if change == "route": d["routes4"][0]["gateway"] = "192.0.2.254"
    with pytest.raises(ValueError): m.validate(r, d, b, "preconfigure")


@pytest.mark.parametrize("change", ["ip", "prefix", "mtu", "down", "operstate", "old_address", "old_route"])
def test_verify_never_repairs_or_accepts_live_drift(change):
    m = module(); r = R["request"](); b = baseline(); d = observed()
    if change == "ip": d["addresses"][-1]["addr_info"][0]["local"] = "198.51.100.2"
    if change == "prefix": d["addresses"][-1]["addr_info"][0]["prefixlen"] = 24
    if change == "mtu": d["links"][-1]["mtu"] = 1500
    if change == "down": d["links"][-1]["flags"] = ["BROADCAST"]
    if change == "operstate": d["links"][-1]["operstate"] = "DOWN"
    if change == "old_address": d["addresses"][0]["addr_info"] = []
    if change == "old_route": d["routes4"].pop(0)
    before = copy.deepcopy(d)
    with pytest.raises(ValueError): m.validate(r, d, b, "verify")
    assert d == before


@pytest.mark.parametrize("mode,drift", [("--reconfigure", "mac"), ("--verify-live", "ip")])
def test_cli_never_reconfigures_a_wrong_device_or_repairs_verify_drift(monkeypatch, mode, drift):
    import io, json
    m = module(); r = R["request"](); b = baseline(); d = observed(); calls = []
    if drift == "mac": d["links"][-1]["address"] = "02:00:5e:00:00:ff"
    else: d["addresses"][-1]["addr_info"][0]["local"] = "198.51.100.2"
    monkeypatch.setattr(m, "capture", lambda: d)
    monkeypatch.setattr(m, "command", lambda argv: calls.append(argv))
    monkeypatch.setattr(m.sys, "argv", ["router_state.py", mode])
    monkeypatch.setattr(m.sys, "stdin", io.StringIO(json.dumps({"request": r, "baseline": b, "phase": "verify"})))
    assert m.main() == 2 and not calls
