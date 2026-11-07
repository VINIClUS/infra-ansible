"""Manual entrypoint behavior against simulated PVE and guest transport."""
import importlib.util
from pathlib import Path
import sys

import pytest

from test_samba_ad_guest import module as guest_module, request
from test_samba_ad_s2_lifecycle import LabFake
from test_samba_ad_compatibility import module as contract_module, sha
from test_samba_ad_guest_probe import expected


def module(monkeypatch):
    monkeypatch.setitem(sys.modules, "s2_guest", guest_module())
    monkeypatch.setitem(sys.modules, "s2_compatibility", contract_module())
    path = Path(__file__).resolve().parents[1] / "tools/samba_ad/probe_runner.py"
    assert path.is_file(), "manual protected-proof runner missing"
    spec = importlib.util.spec_from_file_location("probe_runner", path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def payload():
    return {"enabled": True, "apply": True, "check": False, "limit": "pve-test", "inventory_host": "pve-test",
            "node_hostname": "node-b", "hosts_count": 1, "tags": ["samba_ad_compatibility"], "request": request(),
            "provenance": {"public_revision": "a" * 40, "private_revision": "b" * 40,
                           "s1_audit_sha256": "c" * 64, "filesystem": "ext4",
                           "policy_sha256": sha(request()["firewall"])}}


class Transport:
    def __init__(self): self.executions = 0; self.snapshots = 0; self.drift = False; self.rc = 3

    def capture(self, r, source, filesystem):
        self.snapshots += 1
        value = expected()
        if self.drift and self.snapshots > 1: value["guest"]["boot_id"] = "c" * 32
        return value

    def execute(self, r, source, expectation):
        self.executions += 1
        status = "passed" if self.rc == 0 else "incompatible"
        return self.rc, {"schema": "samba-ad-s2-probe/v1", "run_id": expectation["run_id"], "status": status,
                         "checks": [{"name": "security_ntacl", "status": status,
                                     "attempts": [] if self.rc == 0 else ["EPERM", "EPERM"]}], "cleanup": "complete"}


def cluster():
    m = guest_module(); api = LabFake(); r = request(); m.reconcile(r, api)
    api.calls.clear()
    old_get = api.get

    def get(path, **params):
        result = old_get(path, **params)
        if path.endswith("/status") and "/nodes/" in path and "/storage/" not in path:
            result.update(kversion="test-kernel", pveversion="test-pve")
        return result
    api.get = get
    return api


def prepared():
    data = payload(); data["request"]["expected_digest"] = "b" * 40
    return data


def test_disabled_returns_before_request_or_api(monkeypatch):
    m = module(monkeypatch)
    assert m.run({"enabled": False, "apply": False, "check": False}, None, None, "")["state"] == "disabled"


@pytest.mark.parametrize("field,value", [("limit", "all"), ("tags", ["all"]), ("hosts_count", 2),
                                       ("node_hostname", "node-a")])
def test_manual_gate_rejects_broad_invocation_before_api(monkeypatch, field, value):
    m = module(monkeypatch); data = prepared(); data[field] = value
    with pytest.raises(ValueError): m.run(data, None, None, "")


@pytest.mark.parametrize("field", ["check", "apply"])
def test_s2_check_mode_never_executes_mutating_probe(monkeypatch, field):
    m = module(monkeypatch); api = cluster(); data = prepared(); transport = Transport()
    data[field] = field == "check"
    assert m.run(data, api, transport, "fixed source")["state"] == "preflight"
    assert transport.executions == 0 and transport.snapshots == 0
    assert all(method in ["get", "firewall", "enforce", "link"] for method, _, _ in api.calls)


def test_protected_failure_selects_qemu_without_installation_or_second_clone(monkeypatch):
    m = module(monkeypatch); api = cluster(); transport = Transport()
    result = m.run(prepared(), api, transport, "fixed source")
    assert result["report"]["selection"] == "qemu"
    assert result["report"]["qualification"] == "pending" and transport.executions == 1
    assert result["report"]["observations"]["probe"]["before"]["guest"]["namespaces"]["mnt"] == "mnt:[2]"
    assert all(method in ["get", "firewall", "enforce", "link"] for method, _, _ in api.calls)


@pytest.mark.parametrize("drift,rc", [(True, 3), (False, 99)])
def test_transport_drift_or_unknown_exit_is_operational(monkeypatch, drift, rc):
    m = module(monkeypatch); api = cluster(); transport = Transport(); transport.drift = drift; transport.rc = rc
    result = m.run(prepared(), api, transport, "fixed source")
    assert result["report"]["selection"] is None and result["status"] == "operational_error"


def test_probe_rejects_missing_guest_instead_of_treating_planned_as_verified(monkeypatch):
    m = module(monkeypatch); api = LabFake(); transport = Transport(); data = prepared()
    data["request"]["expected_digest"] = None
    with pytest.raises(ValueError): m.run(data, api, transport, "fixed source")
    assert transport.executions == 0


def test_changed_template_is_refused_before_guest_execution(monkeypatch):
    m = module(monkeypatch); api = cluster(); transport = Transport()
    api.template["digest"] = "c" * 40
    with pytest.raises(ValueError): m.run(prepared(), api, transport, "fixed source")
    assert transport.executions == 0


def test_postprobe_api_error_preserves_operational_report(monkeypatch):
    m = module(monkeypatch); api = cluster(); transport = Transport(); old_get = api.get

    def get(path, **params):
        if transport.executions and path.endswith("/config"):
            raise RuntimeError("sensitive PVE output")
        return old_get(path, **params)
    api.get = get
    result = m.run(prepared(), api, transport, "fixed source")
    assert result["status"] == "operational_error" and result["report"]["selection"] is None
    assert result["report"]["cleanup"]["probe"]["file"] == "complete"
    assert "sensitive" not in str(result)


def test_inconsistent_guest_cleanup_is_operational(monkeypatch):
    m = module(monkeypatch); api = cluster(); transport = Transport(); old_exec = transport.execute

    def execute(*args):
        rc, result = old_exec(*args); result["cleanup"] = "incomplete"
        return rc, result
    transport.execute = execute
    result = m.run(prepared(), api, transport, "fixed source")
    assert result["status"] == "operational_error" and result["report"]["selection"] is None
