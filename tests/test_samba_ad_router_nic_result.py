"""Synthetic PUT and safe recovery evidence regressions; never run native commands."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import runpy
import subprocess
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
R = runpy.run_path(str(ROOT / "tests/test_samba_ad_router.py"))
SECRET = "private-command-output-must-not-escape"


def run_helper(monkeypatch, capsys, *, revert=False, fault=None, absent=False):
    m = R["module"]()
    request = R["request"]()
    before = R["config"]()
    if revert and not absent:
        before[request["nic"]] = m.nic_text(request)
    after = copy.deepcopy(before)
    if revert:
        after.pop(request["nic"], None)
    else:
        after[request["nic"]] = m.nic_text(request)
    after["digest"] = "b" * 40
    calls = []
    written = False

    def run(argv, **kwargs):
        nonlocal written
        calls.append(argv)
        if argv[:2] == ["pvesh", "set"]:
            written = True  # A nonzero/timeout response may follow an actual write.
            if fault == "write_rc":
                return SimpleNamespace(returncode=17, stdout=SECRET, stderr=SECRET)
            if fault == "timeout":
                raise subprocess.TimeoutExpired(argv, 60, output=SECRET, stderr=SECRET)
            return SimpleNamespace(returncode=0, stdout="update VM 800040: -net4 synthetic\n", stderr=SECRET)
        if argv[0] == "ip":
            links = [] if revert else [{"ifname": "tap800040i4"}]
            if fault == "tap_shape":
                links = [{}]
            if fault == "tap":
                links = [{"ifname": "tap800040i4"}] if revert else []
            return SimpleNamespace(returncode=0, stdout=json.dumps(links), stderr=SECRET)
        assert argv[:2] == ["pvesh", "get"]
        if argv[2].endswith("/config"):
            value = after if written else before
            if fault == "stale" and not written:
                value = dict(before, digest="c" * 40)
            if written and fault == "readback_json":
                return SimpleNamespace(returncode=0, stdout=SECRET, stderr=SECRET)
            if written and fault == "readback_shape":
                value = []
            if written and fault == "readback_empty_config":
                value = {}
        elif argv[2].endswith("/pending"):
            value = [{"key": "net4", "delete": 1}] if written and fault == "pending" else []
            if written and fault == "pending_shape":
                value = [{}]
        else:
            assert argv[2].endswith("/status/current")
            value = {"status": "running"}
        return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr=SECRET)

    monkeypatch.setattr(m.subprocess, "run", run)
    monkeypatch.setattr(m.socket, "gethostname", lambda: request["node"])
    monkeypatch.setattr(m.sys, "stdin", io.StringIO(json.dumps(request)))
    monkeypatch.setattr(m.sys, "argv", ["router_nic.py"] + (["--revert"] if revert else []))
    rc = m.main()
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err
    return rc, json.loads(output.out), calls


@pytest.mark.parametrize("revert", [False, True])
def test_put_informational_stdout_still_reaches_verified_readback(monkeypatch, capsys, revert):
    rc, result, calls = run_helper(monkeypatch, capsys, revert=revert)
    assert rc == 0
    assert result["changed"] is True
    evidence = result["diagnostic"]
    assert evidence["success"] is True
    assert evidence["mutation_attempted"] is True
    assert evidence["readback"] == "verified"
    assert evidence["state"] == ("absent" if revert else "present")
    setter = next(i for i, call in enumerate(calls) if call[:2] == ["pvesh", "set"])
    assert any(call[:2] == ["pvesh", "get"] for call in calls[setter + 1:])


@pytest.mark.parametrize("revert", [False, True])
@pytest.mark.parametrize("fault,phase,category,command_rc,attempted,readback", [
    ("write_rc", "write", "command_failed", 17, True, "not_started"),
    ("timeout", "write", "timeout", None, True, "not_started"),
    ("readback_json", "readback_config", "invalid_json", 0, True, "incomplete"),
    ("readback_shape", "readback_config", "invalid_response", 0, True, "incomplete"),
    ("pending", "readback_pending", "precondition", None, True, "incomplete"),
    ("tap", "readback_tap", "precondition", None, True, "incomplete"),
])
def test_failure_preserves_safe_phase_and_uncertainty(monkeypatch, capsys, revert, fault,
                                                     phase, category, command_rc, attempted, readback):
    rc, result, _ = run_helper(monkeypatch, capsys, revert=revert, fault=fault)
    assert rc == 2
    assert result["diagnostic"] == {
        "schema": 1, "operation": "revert" if revert else "apply", "success": False,
        "phase": phase, "category": category, "command_rc": command_rc,
        "mutation_attempted": attempted, "readback": readback, "state": "unknown",
    }
    assert result["changed"] is None


def test_prewrite_rejection_is_distinct_and_does_not_write(monkeypatch, capsys):
    rc, result, calls = run_helper(monkeypatch, capsys, fault="stale")
    assert rc == 2
    assert result["diagnostic"]["phase"] == "preconditions"
    assert result["diagnostic"]["mutation_attempted"] is False
    assert result["diagnostic"]["readback"] == "not_started"
    assert not any(call[:2] == ["pvesh", "set"] for call in calls)


@pytest.mark.parametrize("fault", ["readback_empty_config", "tap_shape", "pending_shape"])
def test_recovery_never_treats_missing_readback_fields_as_verified_absence(monkeypatch, capsys, fault):
    rc, result, _ = run_helper(monkeypatch, capsys, revert=True, fault=fault)
    assert rc == 2
    assert result["diagnostic"]["success"] is False
    assert result["diagnostic"]["state"] == "unknown"
    assert result["diagnostic"]["readback"] == "incomplete"


@pytest.mark.parametrize("stdout", ["", "update VM 800040: synthetic", "null", "[]", '"text"', '{"truncated":'])
def test_get_never_accepts_informational_empty_or_wrong_shaped_response(monkeypatch, stdout):
    m = R["module"]()
    monkeypatch.setattr(m.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=stdout, stderr=SECRET))
    with pytest.raises(ValueError):
        m.api("get", "/nodes/node-a/qemu/800040/config", current=1)


def filters():
    path = ROOT / "roles/samba_ad_router_nic/filter_plugins/router_nic_result.py"
    spec = importlib.util.spec_from_file_location("router_nic_result", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.FilterModule().filters()


def test_summary_accepts_only_bound_success_and_keeps_rescue_outcome_separate(monkeypatch, capsys):
    rc, result, _ = run_helper(monkeypatch, capsys, revert=True)
    safe = filters()["samba_ad_router_nic_result"]({"rc": rc, "stdout": json.dumps(result)}, "revert")
    assert safe["success"] is True and safe["state"] == "absent"
    assert safe["helper_rc"] == 0 and safe["attempted"] is True


def test_absent_recovery_is_verified_without_claiming_a_mutation(monkeypatch, capsys):
    rc, result, calls = run_helper(monkeypatch, capsys, revert=True, absent=True)
    safe = filters()["samba_ad_router_nic_result"]({"rc": rc, "stdout": json.dumps(result)}, "revert")
    assert safe["success"] is True and safe["state"] == "absent"
    assert safe["mutation_attempted"] is False and result["changed"] is False
    assert not any(call[:2] == ["pvesh", "set"] for call in calls)
    assert any(call[0] == "ip" for call in calls)


@pytest.mark.parametrize("fault", ["write_rc", "timeout", "readback_json", "pending", "tap"])
def test_summary_retains_valid_failed_rescue_evidence(monkeypatch, capsys, fault):
    rc, result, _ = run_helper(monkeypatch, capsys, revert=True, fault=fault)
    safe = filters()["samba_ad_router_nic_result"]({"rc": rc, "stdout": json.dumps(result)}, "revert")
    assert safe["success"] is False and safe["state"] == "unknown"
    assert safe["helper_rc"] == 2 and safe["mutation_attempted"] is True
    for field in ("phase", "category", "command_rc", "readback"):
        assert safe[field] == result["diagnostic"][field]


@pytest.mark.parametrize("raw,attempted,rc", [({}, False, None), ({"skipped": True}, False, None),
    ({"unreachable": True, "msg": SECRET}, None, None), ({"rc": 0, "stderr": SECRET}, True, 0),
    ({"rc": 19, "stdout": SECRET}, True, 19), ({"rc": True}, None, None)])
def test_guest_recovery_never_claims_readback_from_rc_alone(raw, attempted, rc):
    assert filters()["samba_ad_router_command_result"](raw) == {
        "attempted": attempted, "helper_rc": rc, "state": "unknown"}


@pytest.mark.parametrize("case", ["missing", "malformed", "truncated", "extra", "bad_enum", "bad_type",
                                  "wrong_operation", "rc_mismatch", "inconsistent", "oversized"])
def test_summary_fails_closed_and_never_repeats_untrusted_fields(monkeypatch, capsys, case):
    _, result, _ = run_helper(monkeypatch, capsys, revert=True)
    raw = {"rc": 0, "stdout": json.dumps(result), "stderr": SECRET}
    if case == "missing": raw = {}
    elif case == "malformed": raw["stdout"] = SECRET
    elif case == "truncated": raw["stdout"] = raw["stdout"][:-1]
    elif case == "rc_mismatch": raw["rc"] = 2
    elif case == "oversized": raw["stdout"] = " " * 8192 + raw["stdout"]
    else:
        if case == "extra": result["diagnostic"]["unsafe"] = SECRET
        if case == "bad_enum": result["diagnostic"]["phase"] = SECRET
        if case == "bad_type": result["diagnostic"]["command_rc"] = True
        if case == "wrong_operation": result["diagnostic"]["operation"] = "apply"
        if case == "inconsistent": result["diagnostic"]["readback"] = "incomplete"
        raw["stdout"] = json.dumps(result)
    safe = filters()["samba_ad_router_nic_result"](raw, "revert")
    assert safe["success"] is False and safe["state"] == "unknown"
    assert safe["readback"] == "unknown" and safe["mutation_attempted"] is None
    assert SECRET not in json.dumps(safe)


def test_role_validates_hotplug_before_continuing_and_reports_both_rescues():
    tasks = yaml.safe_load((ROOT / "roles/samba_ad_router_nic/tasks/apply.yml").read_text())
    transaction = next(t for t in tasks if "block" in t)
    block = transaction["block"]
    hotplug = next(t for t in block if t["name"] == "Hotplug only the declared additional QEMU NIC")
    assert hotplug["no_log"] is True and hotplug["register"] == "samba_ad_router_nic_apply_result"
    verify = next(t for t in block if "ansible.builtin.assert" in t)
    assert "samba_ad_router_nic_result" in yaml.safe_dump(verify)
    assert block.index(verify) < next(i for i, t in enumerate(block) if "ansible.builtin.include_tasks" in t)
    rescue = transaction["rescue"]
    commands = [t for t in rescue if "ansible.builtin.command" in t]
    assert len(commands) == 2
    assert all(t["register"] and t["no_log"] is True and t["failed_when"] is False for t in commands)
    message = rescue[-1]["ansible.builtin.fail"]["msg"]
    assert "samba_ad_router_nic_result" in message and "samba_ad_router_command_result" in message
    assert "stdout" not in message and "stderr" not in message
