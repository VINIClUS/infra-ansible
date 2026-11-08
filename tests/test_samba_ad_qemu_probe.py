"""No QGA, audit socket, xattr, fork or clock operation runs on the test host."""
import copy
import importlib.util
from pathlib import Path
import sys

import pytest

from test_samba_ad_guest_probe import module as protected_module
from test_samba_ad_compatibility import module as evidence_module, report as lxc_report
from test_samba_ad_guest import module as guest_module, request


def module(monkeypatch, name="qemu_guest_probe"):
    monkeypatch.setitem(sys.modules, "s2_protected", protected_module())
    monkeypatch.setitem(sys.modules, "s2_guest", guest_module())
    monkeypatch.setitem(sys.modules, "s2_compatibility", evidence_module())
    from test_samba_ad_probe_runner import module as lxc_module
    monkeypatch.setitem(sys.modules, "s2_probe_runner", lxc_module(monkeypatch))
    path = Path(__file__).resolve().parents[1] / "tools/samba_ad" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def expected():
    r = request()["resource"]
    r["kind"] = "qemu"
    return {"run_id": "a" * 32, "nonce": "b" * 32, "host_boot_id": "c" * 32,
            "resource": r, "guest": {"hostname": r["name"], "euid": 0, "filesystem": "ext4",
                "parent_dev": 10, "parent_ino": 20, "boot_id": "d" * 32,
                "product_uuid": "12345678-1234-1234-1234-123456789abc", "kernel": "test-kernel"}}


class Ops:
    def __init__(self):
        self.current = expected()["guest"]
        self.calls = []
        self.failure = None

    def identity(self): return self.current
    def create(self, run_id, parent): self.calls.append("create"); return "owned"
    def ntacl(self, handle): self.calls.append("security_ntacl")
    def acl(self, handle): self.calls.append("posix_acl")
    def measure(self, name, resource):
        self.calls.append(name)
        if name == self.failure: raise OSError("private output")
        return {"measured": name}
    def cleanup(self, handle):
        self.calls.append("cleanup")
        if self.failure == "cleanup": raise OSError("private output")


@pytest.mark.parametrize("change", ["host_kernel", "uuid", "uuid_type", "hostname", "filesystem", "nonroot"])
def test_identity_refusal_precedes_file_creation(monkeypatch, change):
    m = module(monkeypatch); e = expected(); ops = Ops()
    if change == "host_kernel": ops.current["boot_id"] = e["host_boot_id"]
    if change == "uuid": ops.current["product_uuid"] = "bad"
    if change == "uuid_type": ops.current["product_uuid"] = 123
    if change == "hostname": ops.current["hostname"] = "pve-host"
    if change == "filesystem": ops.current["filesystem"] = "tmpfs"
    if change == "nonroot": ops.current["euid"] = 1000
    result = m.run_probe(e, ops)
    assert result["status"] == "operational_error" and not ops.calls


def test_minimum_checks_are_measured_and_no_samba_claim(monkeypatch):
    m = module(monkeypatch); ops = Ops(); result = m.run_probe(expected(), ops)
    assert result["status"] == "passed" and result["cleanup"] == "complete"
    assert {c["name"] for c in result["checks"]} == evidence_module().MINIMUM
    assert set(result["measurements"]) == {"systemd", "clock", "audit", "isolation", "network"}
    assert ops.calls[-1] == "cleanup" and result["nonce"] == expected()["nonce"]


@pytest.mark.parametrize("failure", ["systemd", "clock", "audit", "isolation", "network", "cleanup"])
def test_failure_never_manufactures_passed_or_incompatible(monkeypatch, failure):
    m = module(monkeypatch); ops = Ops(); ops.failure = failure
    result = m.run_probe(expected(), ops)
    assert result["status"] == "operational_error" and ops.calls[-1] == "cleanup"
    if failure != "cleanup":
        assert next(c for c in result["checks"] if c["name"] == failure)["status"] == "operational_error"
    assert "private output" not in str(result)


def test_qga_rejects_partial_truncated_wrong_nonce_and_unknown_exit(monkeypatch):
    m = module(monkeypatch, "qemu_probe_runner")
    good = {"exited": 1, "exitcode": 0, "out-data": '{"nonce":"' + "b" * 32 + '"}'}
    for delta in [{"exited": 0}, {"out-truncated": True}, {"err-data": "private"},
                  {"exitcode": 99}, {"out-data": "[]"}]:
        with pytest.raises(ValueError): m.decode_qga(dict(good, **delta))
    assert m.decode_qga(good) == (0, {"nonce": "b" * 32})


def test_aggregate_preserves_lxc_and_requires_live_absence_and_two_nodes(monkeypatch):
    m = module(monkeypatch, "qemu_probe_runner")
    with pytest.raises(ValueError): m.aggregate([], [], None, {})
    # Aggregation cannot upgrade caller assertions without matching S1 requests/readback.
    original = lxc_report()
    with pytest.raises(ValueError): m.aggregate([original], [], None, {})
    assert original == lxc_report()


def test_native_audit_parser_requires_enabled_listener_and_no_loss(monkeypatch):
    m = module(monkeypatch)
    import struct
    good = [0, 1, 1, 100, 0, 8192, 0, 0]
    assert m.audit_status(struct.pack("=8I", *good))["enabled"] == 1
    for index, value in [(1, 0), (2, 0), (3, 0), (6, 1)]:
        changed = good.copy(); changed[index] = value
        with pytest.raises(ValueError): m.audit_status(struct.pack("=8I", *changed))
    with pytest.raises(ValueError): m.audit_status(b"short")


def test_network_rejects_extra_nic_wrong_address_and_route(monkeypatch):
    m = module(monkeypatch); r = expected()["resource"]
    links = [{"ifname": "lo", "flags": ["LOOPBACK"]},
             {"ifname": "ens18", "address": r["mac"].lower(), "mtu": r["mtu"],
              "flags": ["UP", "LOWER_UP"], "addr_info": [{"family": "inet", "local": "198.51.100.80", "prefixlen": 25}]}]
    routes = [{"dst": "default", "gateway": r["gateway"], "dev": "ens18"}]
    assert m.network_status(links, routes, r)["interface"] == "ens18"
    for changed_links, changed_routes in [(links + [{"ifname": "ens19"}], routes),
                                          (links, []), (links, [dict(routes[0], gateway="198.51.100.2")])]:
        with pytest.raises(ValueError): m.network_status(changed_links, changed_routes, r)


def test_preflight_does_not_enter_qga_or_create_reports(monkeypatch):
    m = module(monkeypatch, "qemu_probe_runner")
    assert m.run({"enabled": False, "apply": False, "check": False}, None, None, "") == {"state": "disabled"}
    for payload in [{"enabled": True, "apply": True, "check": True},
                    {"enabled": True, "apply": False, "check": False}]:
        # Missing invocation identity must fail before any API/transport boundary.
        with pytest.raises(ValueError): m.run(payload, None, None, "")


def qemu_request():
    r = request(); r["resource"]["kind"] = "qemu"; r["template"]["disk"] = "scsi0"
    r["expected_digest"] = "b" * 40
    return r


def operation():
    from test_samba_ad_probe_runner import payload
    p = payload(); p["request"] = qemu_request()
    return p


class Api:
    def __init__(self): self.calls = []; self.residue = False
    def get(self, path, **params):
        self.calls.append(path)
        if path.endswith("/status"):
            return {"memory": {"total": 8 * 1024**3, "used": 1024**3}, "kversion": "test-kernel", "pveversion": "test-pve"}
        return {"template": 1, "digest": "a" * 40}
    def cleanup_readback(self, r, volumes):
        self.calls.append("absence")
        if self.residue: raise ValueError("guest/volume/firewall remains")


class Transport:
    def __init__(self):
        self.calls = []; self.drift = False; self.nonce_wrong = False
        self.guest = expected()["guest"]
    def capture(self, r, source, filesystem):
        self.calls.append("capture")
        e = expected(); current = copy.deepcopy(self.guest)
        if self.drift and len(self.calls) > 1: current["boot_id"] = "e" * 32
        return {"guest": current, "host_boot_id": e["host_boot_id"],
                "qga": {"node": r["resource"]["node"], "vmid": r["resource"]["vmid"],
                        "config_digest": r["expected_digest"], "template_digest": r["template"]["digest"],
                        "spec_sha256": guest_module().spec_hash(r), "uuid": current["product_uuid"]},
                "clock": {"host_start_ns": 100, "host_end_ns": 200, "elapsed_ns": 100, "guest_ns": 150, "nonce": "b" * 32}}
    def execute(self, r, source, expectation):
        self.calls.append("execute")
        result = {"schema": "samba-ad-s2-qemu-probe/v1", "run_id": expectation["run_id"],
                  "nonce": "c" * 32 if self.nonce_wrong else expectation["nonce"], "status": "passed",
                  "checks": [{"name": name, "status": "passed", "attempts": []} for name in evidence_module().MINIMUM],
                  "cleanup": "complete", "measurements": {
                      "systemd": {"pid1": "systemd", "state": "running"},
                      "clock": {"ntp_synchronized": True, "realtime_ns": 150, "monotonic_ns": 100},
                      "audit": {"enabled": 1, "failure": 1, "listener_pid": 100, "rate_limit": 0,
                                "backlog_limit": 8192, "lost": 0, "backlog": 0},
                      "isolation": {"vm": "kvm", "container": "none", "kernel": self.guest["kernel"]},
                      "network": {"interface": "ens18", "address": r["resource"]["address"],
                                  "mac": r["resource"]["mac"], "mtu": r["resource"]["mtu"],
                                  "gateway": r["resource"]["gateway"]}}}
        result["checks"].sort(key=lambda c: ["security_ntacl", "posix_acl", "systemd", "clock", "audit", "isolation", "network"].index(c["name"]))
        return 0, result


@pytest.mark.parametrize("readonly", ["check", "apply"])
def test_verified_preflight_never_calls_transport(monkeypatch, readonly):
    m = module(monkeypatch, "qemu_probe_runner"); p = operation(); api = Api(); transport = Transport()
    p[readonly] = readonly == "check"; p["run_id"] = None
    monkeypatch.setattr(m.guest, "reconcile", lambda *a, **k: {"state": "verified"})
    assert m.run(p, api, transport, "reviewed-source") == {"state": "preflight"}
    assert transport.calls == []


@pytest.mark.parametrize("drift,wrong_nonce", [(False, False), (True, False), (False, True)])
def test_qemu_measured_report_never_qualifies_one_placement(monkeypatch, drift, wrong_nonce):
    m = module(monkeypatch, "qemu_probe_runner"); transport = Transport()
    transport.drift = drift; transport.nonce_wrong = wrong_nonce
    monkeypatch.setattr(m.guest, "reconcile", lambda *a, **k: {"state": "verified"})
    result = m.run(operation(), Api(), transport, "reviewed-source")
    report = result["report"]
    assert report["selection"] is None and report["qualification"] == "pending"
    assert report["cleanup"]["probe"]["guest"] == "pending"
    assert result["status"] == ("operational_error" if drift or wrong_nonce else "passed")
    if wrong_nonce: assert report["cleanup"]["probe"]["file"] == "incomplete"
    if drift: assert report["cleanup"]["probe"]["file"] == "complete"


def aggregate_sources(monkeypatch):
    m = module(monkeypatch, "qemu_probe_runner")
    monkeypatch.setattr(m.guest, "reconcile", lambda *a, **k: {"state": "verified"})
    from test_samba_ad_probe_runner import module as lxc_module, prepared, Transport as LxcTransport
    lm = lxc_module(monkeypatch)
    monkeypatch.setattr(lm.guest, "reconcile", lambda *a, **k: {"state": "verified"})
    lp = prepared()
    lxc = lm.run(lp, Api(), LxcTransport(), "reviewed-lxc-source")["report"]
    r = qemu_request()
    one = m.run(operation(), Api(), Transport(), "reviewed-source")["report"]
    second = operation(); second["run_id"] = "e" * 32
    second["node_hostname"] = second["request"]["resource"]["node"] = "node-a"
    transport = Transport()
    transport.guest.update(boot_id="e" * 32, product_uuid="23456789-1234-1234-1234-123456789abc")
    two = m.run(second, Api(), transport, "reviewed-source")["report"]
    return m, [lxc, one, two], [lp["request"], r, second["request"]]


def aggregate_header():
    return {"run_id": "f" * 32, "public_revision": "a" * 40, "private_revision": "b" * 40}


def test_aggregation_qualifies_only_two_nodes_and_preserves_originals(monkeypatch):
    m, sources, requests = aggregate_sources(monkeypatch)
    originals = copy.deepcopy(sources); api = Api()
    pending = m.aggregate(sources[:2], requests[:2], api, aggregate_header())
    assert pending["selection"] == "qemu" and pending["qualification"] == "pending"
    result = m.aggregate(sources, requests, api, aggregate_header())
    assert result["qualification"] == "qemu_substrate" and sources == originals
    assert result["observations"]["source0"]["before"]["source_report"] == sources[0]
    api.residue = True
    with pytest.raises(ValueError): m.aggregate(sources, requests, api, aggregate_header())
    assert sources == originals


def test_aggregation_cannot_turn_duplicate_placement_or_error_into_qualification(monkeypatch):
    m, sources, requests = aggregate_sources(monkeypatch)
    sources[2] = copy.deepcopy(sources[1]); sources[2]["created_utc"] = "2026-11-08T00:00:00Z"
    requests[2] = copy.deepcopy(requests[1])
    result = m.aggregate(sources, requests, Api(), aggregate_header())
    assert result["qualification"] == "pending"
    trace = sources[2]["observations"]["probe"]
    trace["result"].update(status="operational_error", checks=[], measurements={})
    sources[2]["checks"] = [{"name": "isolation", "subject": "probe", "status": "operational_error", "attempts": []}]
    # Empty measurement results must remain operational rather than qualify.
    result = m.aggregate(sources, requests, Api(), aggregate_header())
    assert result["selection"] is None and result["qualification"] == "pending"


def test_manual_role_selects_reviewed_qemu_source_and_retains_writer(monkeypatch):
    import yaml
    root = Path(__file__).resolve().parents[1]
    defaults = yaml.safe_load((root / "roles/samba_ad_compatibility/defaults/main.yml").read_text())
    assert defaults["samba_ad_compatibility_enabled"] is False and defaults["samba_ad_compatibility_apply"] is False
    assert defaults["samba_ad_compatibility_probe"] == "lxc_first"
    tasks = yaml.safe_load((root / "roles/samba_ad_compatibility/tasks/main.yml").read_text())
    probe = next(t for t in tasks if "samba_ad_compatibility_modules" in t.get("vars", {}))
    assert "qemu_guest_probe.py" in probe["vars"]["samba_ad_compatibility_qemu_source"]
    assert "s2_qemu_runner" in str(probe["vars"])
    assert next(i for i,t in enumerate(tasks) if "Persist the report" in t["name"]) < next(i for i,t in enumerate(tasks) if "Refuse operational" in t["name"])


@pytest.mark.parametrize("mode", ["lxc_first", "qemu_substrate"])
def test_transported_source_compiles_and_only_defines_snapshot_functions(monkeypatch, mode):
    import json
    import jinja2
    import yaml
    root = Path(__file__).resolve().parents[1]
    tasks = yaml.safe_load((root / "roles/samba_ad_compatibility/tasks/main.yml").read_text())
    probe = next(t for t in tasks if "samba_ad_compatibility_modules" in t.get("vars", {}))
    env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True)
    env.filters["to_json"] = json.dumps
    source = env.from_string(probe["vars"]["samba_ad_compatibility_probe_source"]).render(
        samba_ad_compatibility_probe=mode, playbook_dir=str(root / "playbooks"),
        samba_ad_compatibility_protected_source=(root / "tools/samba_ad/guest_probe.py").read_text(),
        samba_ad_compatibility_qemu_source=(root / "tools/samba_ad/qemu_guest_probe.py").read_text(),
        lookup=lambda plugin, path: Path(path).read_text())
    namespace = {"__name__": "snapshot"}
    monkeypatch.setitem(sys.modules, "s2_protected", protected_module())
    exec(compile(source, "transported-source", "exec"), namespace)
    assert callable(namespace["identity"])


def test_qga_commands_have_timeouts_stdin_and_no_host_execution(monkeypatch):
    from types import SimpleNamespace
    m = module(monkeypatch, "qemu_probe_runner"); calls = []
    monkeypatch.setattr(m.os, "uname", lambda: SimpleNamespace(nodename="node-b"))
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stderr="", stdout='{"exited":1,"exitcode":0,"out-data":"{}"}')
    monkeypatch.setattr(m.subprocess, "run", run)
    assert m.QgaTransport(Api()).command(qemu_request(), "reviewed-source", {"nonce": "b" * 32}) == (0, {})
    argv, kwargs = calls[0]
    assert argv[:4] == ["qm", "guest", "exec", "800080"]
    assert kwargs["timeout"] == 40 and "--pass-stdin" in argv and "--synchronous" in argv
    assert '"nonce"' in kwargs["input"] and not any("nonce" in arg for arg in argv)
    monkeypatch.setattr(m.os, "uname", lambda: SimpleNamespace(nodename="foreign"))
    with pytest.raises(ValueError): m.QgaTransport(Api()).command(qemu_request(), "source", {})
    assert len(calls) == 1


def test_aggregate_keeps_original_revisions_when_qemu_source_was_implemented_later(monkeypatch):
    m, sources, requests = aggregate_sources(monkeypatch)
    sources[0]["public_revision"] = "9" * 40
    sources[0]["private_revision"] = "8" * 40
    result = m.aggregate(sources, requests, Api(),
                         {"run_id": "f" * 32, "public_revision": "a" * 40, "private_revision": "b" * 40})
    assert result["qualification"] == "qemu_substrate"
    assert result["public_revision"] == "a" * 40 and result["private_revision"] == "b" * 40
    assert result["observations"]["source0"]["before"]["source_report"]["public_revision"] == "9" * 40


def test_aggregate_check_mode_does_not_write_and_apply_persists_once(monkeypatch, tmp_path):
    import json
    m, sources, requests = aggregate_sources(monkeypatch)
    directory = tmp_path / "evidence"; directory.mkdir(mode=0o700)
    payload = {"enabled": True, "apply": True, "check": True, "reports": sources, "requests": requests,
               "directory": str(directory), "provenance": {"public_revision": "a" * 40, "private_revision": "b" * 40}}
    assert m.aggregate_operation(payload, Api()) == {"state": "preflight"}
    assert list(directory.iterdir()) == []
    payload["check"] = False
    result = m.aggregate_operation(payload, Api())
    files = list(directory.iterdir()); assert len(files) == 1
    assert result["state"] == "aggregated" and files[0].stat().st_mode & 0o777 == 0o600
    measured = json.loads(files[0].read_text())
    assert measured["qualification"] == "qemu_substrate"
    assert measured["observations"]["source0"]["before"]["source_report"] == sources[0]


@pytest.mark.parametrize("fault", ["sequence", "kernel", "kind", "short"])
def test_audit_netlink_refuses_unbound_or_error_reply_without_opening_native_socket(monkeypatch, fault):
    import struct
    m = module(monkeypatch)
    class Channel:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def settimeout(self, value): assert value == 3
        def bind(self, address): assert address == (0, 0)
        def getsockname(self): return (123, 0)
        def sendto(self, data, address):
            self.sequence = struct.unpack("=IHHII", data)[3]
            assert address == (0, 0)
        def recvfrom(self, size):
            data = struct.pack("=IHHII8I", 48, 2 if fault == "kind" else 1000, 0,
                               self.sequence + (fault == "sequence"), 0, 0, 1, 1, 100, 0, 8192, 0, 0)
            return (data[:8] if fault == "short" else data), (1 if fault == "kernel" else 0, 0)
    monkeypatch.setattr(m.socket, "socket", lambda *a: Channel())
    with pytest.raises(ValueError): m.kernel_audit()


@pytest.mark.parametrize("observed,elapsed", [(3_000_000_000, 100), (150, 41_000_000_000), (-3_000_000_000, 100)])
def test_clock_refuses_skew_or_unbounded_qga_window(monkeypatch, observed, elapsed):
    m = module(monkeypatch, "qemu_probe_runner")
    with pytest.raises(ValueError): m.clock_window(100, 200, elapsed, observed)


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
@pytest.mark.parametrize("fault", ["relabeled_run", "nested_error", "empty_trace", "boot", "hostname",
                                   "vmid", "filesystem", "after_drift", "cleanup", "unknown_capture",
                                   "unknown_result", "check_status", "policy", "isolation"])
def test_aggregate_refuses_unbound_source_trace(monkeypatch, kind, fault):
    m, sources, requests = aggregate_sources(monkeypatch)
    source = sources[2 if kind == "qemu" else 0]
    trace = source["observations"]["probe"]
    if fault == "relabeled_run": source["run_id"] = "9" * 32
    if fault == "nested_error": trace["result"]["status"] = "operational_error"
    if fault == "empty_trace": trace.update(before={"unexpected": True}, after={}, result={})
    if fault == "boot": source["subjects"][0]["boot_id"] = "9" * 32
    if fault == "hostname": trace["before"]["guest"]["hostname"] = "foreign.lab.ad.test"
    if fault == "vmid": trace["before"]["qga" if kind == "qemu" else "host_anchor"]["vmid"] += 1
    if fault == "filesystem": source["platform_fingerprint"]["filesystem"] = "xfs"
    if fault == "after_drift": trace["after"]["guest"]["parent_ino"] += 1
    if fault == "cleanup": trace["result"]["cleanup"] = "incomplete"
    if fault == "unknown_capture": trace["after"]["unexpected"] = True
    if fault == "unknown_result": trace["result"]["unexpected"] = True
    if fault == "check_status": source["checks"] = []
    if fault == "policy":
        for item in sources: item["platform_fingerprint"]["policy_sha256"] = "9" * 64
    if fault == "isolation": source["platform_fingerprint"]["isolation"] = (
        "lxc-unprivileged-apparmor" if kind == "qemu" else "qemu-no-passthrough")
    original = copy.deepcopy(sources)
    with pytest.raises(ValueError): m.aggregate(sources, requests, Api(), aggregate_header())
    assert sources == original


def test_aggregate_refuses_copied_qga_trace_claimed_as_second_placement(monkeypatch):
    m, sources, requests = aggregate_sources(monkeypatch)
    sources[2]["observations"] = copy.deepcopy(sources[1]["observations"])
    with pytest.raises(ValueError): m.aggregate(sources, requests, Api(), aggregate_header())


@pytest.mark.parametrize("fault", ["nonce", "missing_request", "request_resource", "measurement_shape",
                                   "measurement_network", "measurement_kernel", "measurement_clock"])
def test_aggregate_refuses_unbound_qemu_expectation_or_measurements(monkeypatch, fault):
    m, sources, requests = aggregate_sources(monkeypatch)
    trace = sources[2]["observations"]["probe"]
    if fault == "nonce": trace["result"]["nonce"] = "9" * 32
    if fault == "missing_request": trace["before"].pop("probe_request", None)
    if fault == "request_resource":
        trace["before"].setdefault("probe_request", {})["resource"] = requests[1]["resource"]
    if fault == "measurement_shape": trace["result"]["measurements"]["audit"] = {"unexpected": True}
    if fault == "measurement_network": trace["result"]["measurements"]["network"]["address"] = "198.51.100.90/25"
    if fault == "measurement_kernel": trace["result"]["measurements"]["isolation"]["kernel"] = "wrong"
    if fault == "measurement_clock": trace["result"]["measurements"]["clock"]["ntp_synchronized"] = False
    with pytest.raises(ValueError): m.aggregate(sources, requests, Api(), aggregate_header())


@pytest.mark.parametrize("kind", ["lxc", "qemu"])
def test_consistent_operational_source_never_qualifies(monkeypatch, kind):
    m, sources, requests = aggregate_sources(monkeypatch)
    source = sources[0 if kind == "lxc" else 2]
    result = source["observations"]["probe"]["result"]
    result.update(status="operational_error", checks=[])
    if kind == "qemu": result["measurements"] = {}
    source.update(checks=[{"name": "security_ntacl" if kind == "lxc" else "isolation",
                          "subject": "probe", "status": "operational_error", "attempts": []}], selection=None)
    aggregated = m.aggregate(sources, requests, Api(), aggregate_header())
    assert aggregated["selection"] is None and aggregated["qualification"] == "pending"
    assert aggregated["observations"]["source0" if kind == "lxc" else "source2"]["result"] == result
