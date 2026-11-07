"""Manual entrypoint behavior against simulated PVE and guest transport."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

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
            "run_id": "a" * 32,
            "provenance": {"public_revision": "a" * 40, "private_revision": "b" * 40,
                           "s1_audit_sha256": "c" * 64, "filesystem": "ext4",
                           "policy_sha256": sha(request()["firewall"])}}


class Transport:
    def __init__(self): self.executions = 0; self.snapshots = 0; self.drift = False; self.rc = 3

    def capture(self, r, source, filesystem):
        self.snapshots += 1
        value = expected()
        value.pop("run_id")  # Capture returns an identity frame; the controller supplies the run_id.
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
    data["run_id"] = None  # The controller does not prepare output for readonly execution.
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
    assert result["report"]["observations"]["probe"]["result"]["status"] == "incompatible"
    assert "sensitive" not in str(result)


def test_inconsistent_guest_cleanup_is_operational(monkeypatch):
    m = module(monkeypatch); api = cluster(); transport = Transport(); old_exec = transport.execute

    def execute(*args):
        rc, result = old_exec(*args); result["cleanup"] = "incomplete"
        return rc, result
    transport.execute = execute
    result = m.run(prepared(), api, transport, "fixed source")
    assert result["status"] == "operational_error" and result["report"]["selection"] is None


def pct_capture(monkeypatch, change=None):
    """Exercise the real transport transformation; no procfs, subprocess or guest IO."""
    m = module(monkeypatch); observed = expected()["guest"]
    files = {"/proc/4321/uid_map": "0 100000 65536", "/proc/4321/attr/current": "lxc-test (enforce)",
             "/proc/4321/cgroup": "0::/lxc/800080/ns/init.scope",
             "/proc/4321/root/proc/1/cgroup": "0::/lxc/800080/ns/init.scope",
             "/proc/4321/root/proc/sys/kernel/random/boot_id": "b" * 32,
             "/proc/4321/status": "Name:\tinit\nNSpid:\t4321\t1\n",
             "/proc/4321/stat": "4321 (init) " + " ".join(["S"] + ["0"] * 18 + ["100"])}
    links = {}
    for ns in ["user", "mnt", "pid", "cgroup"]:
        links["/proc/4321/ns/" + ns] = ns + ":[2]"
        links["/proc/self/ns/" + ns] = ns + ":[1]"
    if change == "guest_ns": observed["namespaces"]["pid"] = "pid:[3]"
    if change == "guest_cgroup_ns": observed["namespaces"]["cgroup"] = "cgroup:[3]"
    if change == "host_cgroup_ns": links["/proc/4321/ns/cgroup"] = "cgroup:[1]"
    if change == "hostname": observed["hostname"] = "foreign.lab.ad.test"
    if change == "init_pid": files["/proc/4321/status"] = "NSpid:\t4321\t2\n"

    class ProcPath:
        def __init__(self, value): self.value = str(value)
        def __truediv__(self, value): return ProcPath(self.value + "/" + str(value))
        def __str__(self): return self.value
        def read_text(self):
            value = files[self.value]
            if len(calls) > 1 and change == "starttime_reused" and self.value.endswith("/stat"):
                return value.removesuffix("100") + "101"
            if len(calls) > 1 and change == "host_membership" and self.value.endswith("/cgroup"):
                return "0::/lxc/800081/ns/init.scope"
            return value
        def stat(self):
            assert self.value == "/proc/4321/root/var/lib"
            return SimpleNamespace(st_dev=10, st_ino=20)

    calls = []
    def run(argv):
        assert argv == ["pct", "pid", "800080"]
        calls.append(argv)
        return "4322" if change == "pid_reused" and len(calls) > 1 else "4321"
    monkeypatch.setattr(m, "Path", ProcPath)
    monkeypatch.setattr(m, "os", SimpleNamespace(readlink=lambda path: links[str(path)]))
    transport = m.PctTransport(SimpleNamespace(run=run))
    monkeypatch.setattr(transport, "command", lambda *args: (0, observed))
    return m, transport


def test_real_pct_capture_separates_host_and_guest_cgroup_views(monkeypatch):
    m, transport = pct_capture(monkeypatch)
    result = transport.capture(request(), "static helper", "ext4")
    assert result["guest"]["cgroup"] == "0::/init.scope"
    assert result["host_anchor"] == {"vmid": 800080, "init_pid": 4321, "starttime": "100",
                                     "nspid": [4321, 1], "cgroup": "0::/lxc/800080/ns/init.scope"}
    assert result["guest"]["namespaces"]["cgroup"] == "cgroup:[2]"
    result["run_id"] = "a" * 32
    from test_samba_ad_guest_probe import module as probe_module
    probe_module().validate_identity(result, expected()["guest"])


@pytest.mark.parametrize("change", ["guest_ns", "guest_cgroup_ns", "host_cgroup_ns", "hostname", "init_pid",
                                   "pid_reused", "starttime_reused", "host_membership"])
def test_real_pct_capture_rejects_wrong_namespace_or_init_identity(monkeypatch, change):
    m, transport = pct_capture(monkeypatch, change)
    with pytest.raises(ValueError): transport.capture(request(), "static helper", "ext4")


@pytest.mark.parametrize("change", ["ancestor_symlink", "uid_mismatch", "existing_run"])
def test_controller_directory_preflight_stops_before_mutating_transport(monkeypatch, tmp_path, change):
    m = module(monkeypatch); controller = sys.modules["s2_compatibility"]; transport = Transport()
    directory = tmp_path; directory.chmod(0o700)
    if change == "ancestor_symlink":
        actual = tmp_path / "actual"; actual.mkdir(mode=0o700)
        (actual / "evidence").mkdir(mode=0o700)
        alias = tmp_path / "alias"; alias.symlink_to(actual, target_is_directory=True)
        directory = alias / "evidence"
    if change == "uid_mismatch":
        real_os = controller.os
        class OtherUID:
            def __getattr__(self, name): return getattr(real_os, name)
            def geteuid(self): return real_os.geteuid() + 1
        monkeypatch.setattr(controller, "os", OtherUID())
    existing = directory / ("a" * 32 + ".json")
    if change == "existing_run": existing.write_text("preserve previous evidence")
    with pytest.raises(FileExistsError if change == "existing_run" else ValueError):
        prepared_record = controller.prepare_report(str(directory), "a" * 32)
        operation = prepared(); operation["run_id"] = prepared_record["run_id"]
        m.run(operation, cluster(), transport, "static helper")
    assert transport.executions == 0 and transport.snapshots == 0
    if change == "existing_run": assert existing.read_text() == "preserve previous evidence"
    else: assert not list(directory.glob("*.json"))


def test_controller_preflight_run_id_is_used_by_probe_and_writer(monkeypatch, tmp_path):
    m = module(monkeypatch); controller = sys.modules["s2_compatibility"]; transport = Transport()
    tmp_path.chmod(0o700)
    prepared_record = controller.prepare_report(str(tmp_path), "d" * 32)
    assert list(tmp_path.iterdir()) == []  # A preflight is not a fabricated report.
    operation = prepared(); operation["run_id"] = prepared_record["run_id"]
    result = m.run(operation, cluster(), transport, "static helper")
    assert result["report"]["run_id"] == "d" * 32 and transport.executions == 1
    controller.write_report(str(tmp_path), result["report"], prepared_record)
    assert (tmp_path / ("d" * 32 + ".json")).is_file()
