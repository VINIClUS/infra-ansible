"""Regression paths from independent S1 round 1; no production access."""
import copy
from pathlib import Path
import runpy
import pytest

ROOT = Path(__file__).resolve().parents[1]
G = runpy.run_path(str(ROOT / "tests/test_samba_ad_guest.py"))
R = runpy.run_path(str(ROOT / "tests/test_samba_ad_router.py"))


@pytest.mark.parametrize("identity", ["hostname", "mac", "ip", "pending_ip"])
def test_conflict_created_after_present_stopped_prevents_start(identity):
    m = G["module"](); api = G["Fake"](); r = G["request"](); r["boot"] = False
    m.reconcile(r, api); api.calls.clear()
    other = {"node": "node-b", "hostname": "foreign", "digest": "f" * 40}
    if identity == "hostname": other["hostname"] = r["resource"]["name"]
    if identity == "mac": other["net0"] = "virtio=" + r["resource"]["mac"] + ",bridge=vnold"
    if identity in ["ip", "pending_ip"]: other["ipconfig0"] = "ip=" + r["resource"]["address"]
    api.guests[800081] = other
    original = api.get
    def get(path, **params):
        data = original(path, **params)
        if path == "/cluster/resources":
            for item in data: item["maxmem"] = 1024**3
        if identity == "pending_ip" and "/800081/config" in path and params.get("current") == 1:
            data.pop("ipconfig0", None)
        return data
    api.get = get
    r.update(action="start", boot=True, expected_digest="b" * 40)
    with pytest.raises(ValueError, match="collision"): m.reconcile(r, api)
    assert not any(method != "get" and method != "firewall" for method, _, _ in api.calls)


def test_start_repeats_dad_with_own_firewall_present_and_again_before_link():
    m = G["module"](); api = G["Fake"](); r = G["request"](); r["boot"] = False
    m.reconcile(r, api); api.calls.clear()
    r.update(action="start", boot=True, expected_digest="b" * 40)
    assert m.reconcile(r, api)["state"] == "started"
    probes = [i for i, (method, _, _) in enumerate(api.calls) if method == "probe"]
    boot = next(i for i, (_, p, _) in enumerate(api.calls) if p.endswith("/status/start"))
    link = next(i for i, (_, _, args) in enumerate(api.calls) if "link_down=0" in args.get("net0", ""))
    assert len(probes) == 2 and probes[0] < boot < probes[1] < link


def test_linkup_pending_never_reports_success_using_desired_config():
    m = G["module"](); api = G["Fake"](); r = G["request"](); original = api.get
    def get(path, **params):
        data = original(path, **params)
        cfg = api.guests.get(800080, {})
        pending = "link_down=0" in cfg.get("net0", "")
        if pending and path.endswith("/pending"):
            return [{"key": "net0", "value": cfg["net0"].replace("link_down=0", "link_down=1"), "pending": cfg["net0"]}]
        if pending and path.endswith("/config") and params.get("current") == 1:
            data["net0"] = data["net0"].replace("link_down=0", "link_down=1")
        return data
    api.get = get
    with pytest.raises(ValueError): m.reconcile(r, api)
    assert any(args.get("current") == 1 for method, p, args in api.calls if p.endswith("/config"))


def test_router_revert_pending_delete_is_failure_not_removal(monkeypatch):
    import io, json
    m = R["module"](); r = R["request"](); cfg = R["config"](); cfg["net4"] = m.nic_text(r)
    deleted = False
    def api(method, path, **params):
        nonlocal deleted
        if method == "set": deleted = True; return None
        if path.endswith("/pending"):
            return [{"key": "net4", "delete": 1}] if deleted else []
        if path.endswith("/status/current"): return {"status": "running"}
        if path.endswith("/config"):
            result = copy.deepcopy(cfg)
            if deleted and params.get("current", 0) == 0: result.pop("net4")
            return result
        raise AssertionError(path)
    monkeypatch.setattr(m, "api", api)
    monkeypatch.setattr(m.sys, "stdin", io.StringIO(json.dumps(r)))
    monkeypatch.setattr(m.sys, "argv", ["router_nic.py", "--revert"])
    assert m.main() == 2


def test_collision_appearing_during_boot_keeps_link_disconnected():
    m = G["module"](); api = G["Fake"](); r = G["request"](); original = api.mutate
    def mutate(method, path, **params):
        original(method, path, **params)
        if path.endswith("/status/start"):
            api.guests[800081] = {"node": "node-b", "hostname": "foreign", "ipconfig0": "ip=" + r["resource"]["address"]}
    api.mutate = mutate
    with pytest.raises(ValueError, match="collision"): m.reconcile(r, api)
    assert "link_down=1" in api.guests[800080]["net0"]
    assert not any("link_down=0" in args.get("net0", "") for _, _, args in api.calls)


def test_dad_collision_before_start_never_boots_owned_probe():
    m = G["module"](); api = G["Fake"](); r = G["request"](); r["boot"] = False
    m.reconcile(r, api); api.calls.clear()
    def occupied(r): raise ValueError("DAD collision")
    api.probe_address = occupied; r.update(action="start", boot=True, expected_digest="b" * 40)
    with pytest.raises(ValueError, match="DAD collision"): m.reconcile(r, api)
    assert not any(p.endswith("/status/start") for _, p, _ in api.calls)


def test_host_link_readback_failure_is_not_a_successful_start():
    m = G["module"](); api = G["Fake"]()
    api.link_ready = lambda r, connected: False
    with pytest.raises(ValueError, match="host NIC"): m.reconcile(G["request"](), api)


def test_router_revert_requires_effective_host_tap_absence(monkeypatch):
    import io, json
    m = R["module"](); r = R["request"](); cfg = R["config"](); cfg["net4"] = m.nic_text(r); deleted = False
    def api(method, path, **params):
        nonlocal deleted
        if method == "set": deleted = True; return None
        if path.endswith("/pending"): return []
        if path.endswith("/status/current"): return {"status": "running"}
        if path.endswith("/config"):
            assert params.get("current") == 1
            result = copy.deepcopy(cfg)
            if deleted: result.pop("net4")
            return result
        raise AssertionError(path)
    monkeypatch.setattr(m, "api", api); monkeypatch.setattr(m, "host_nic_present", lambda r: True)
    monkeypatch.setattr(m.sys, "stdin", io.StringIO(json.dumps(r))); monkeypatch.setattr(m.sys, "argv", ["router_nic.py", "--revert"])
    assert m.main() == 2


@pytest.mark.parametrize("kind", ["valid", "parsed_error", "missing_rule", "warning"])
def test_authoritative_parser_gate_propagates_errors_even_without_compile_failure(kind):
    import subprocess
    m = G["module"]()
    # Exercise the actual embedded Perl gate. Only the installed PVE module IO
    # boundary is replaced; the gate's error/count/warning checks execute in Perl.
    rules = '[{}, {}, {}]' if kind != "missing_rule" else '[{}, {}]'
    if kind == "parsed_error": rules = '[{}, {errors=>{dport=>"invalid"}}, {}]'
    warn = 'warn "invalid rule ignored\n";' if kind == "warning" else ''
    stubs = ('BEGIN { package PVE::Firewall; sub load_clusterfw_conf { return {}; } '
             'sub load_vmfw_conf { ' + warn + ' return {rules=>' + rules + '}; } }')
    result = subprocess.run(["perl", "-e", stubs + m.PVE_VALIDATE_FW, "ct", "800080", "3"], capture_output=True, text=True)
    assert (result.returncode == 0) == (kind == "valid")
