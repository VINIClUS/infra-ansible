"""Malformed transport data must not erase a measured operational report.

Only ordinary JSON evidence files are written. No native probe or subprocess is
executed; the real decoder/capture paths run with subprocess/procfs IO replaced.
"""
import copy
import errno
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from test_samba_ad_guest import request
from test_samba_ad_guest_probe import expected
from test_samba_ad_guest_probe import Ops, module as probe_module
from test_samba_ad_probe_runner import Transport, cluster, module, pct_capture, prepared

WIRE = "WIRE_ONLY_PAYLOAD"


def operational_reply():
    return {"schema": "samba-ad-s2-probe/v1", "run_id": "a" * 32, "status": "operational_error",
            "checks": [{"name": "security_ntacl", "status": "operational_error", "attempts": []}],
            "cleanup": "incomplete"}


def bad_probe_replies():
    replies = [[], [WIRE], WIRE, "", 7, 2.5, True, False, None, {}, {"stdout": WIRE}]
    for key, value in [("schema", WIRE), ("run_id", "b" * 32), ("checks", {"stdout": WIRE}),
                       ("checks", [WIRE]), ("cleanup", [WIRE])]:
        replies.append(dict(operational_reply(), **{key: value}))
    replies.append(dict(operational_reply(), stdout=WIRE))
    replies.append(dict(operational_reply(), checks=[{"name": "security_ntacl", "status": "operational_error",
                                                    "attempts": [WIRE]}]))
    return replies


def persist_failure(controller, result, directory, ticket, *, accepted_result=False):
    assert result["state"] == "measured" and result["status"] == "operational_error"
    report = result["report"]
    assert report["selection"] is None and report["qualification"] == "pending"
    assert report["run_id"] == ticket["run_id"]
    assert report["observations"]["probe"]["before"]["host_anchor"] == expected()["host_anchor"]
    assert report["observations"]["probe"]["after"] is None
    assert report["cleanup"]["probe"]["guest"] == "pending"
    observed = report["observations"]["probe"]["result"]
    if accepted_result:
        assert observed["status"] == "incompatible" and observed["checks"][0]["attempts"] == ["EPERM", "EPERM"]
        assert report["cleanup"]["probe"]["file"] == "complete"
    else:
        assert observed is None and report["cleanup"]["probe"]["file"] == "incomplete"
    assert WIRE not in json.dumps(report)
    controller.validate_report(report)
    controller.write_report(str(directory), report, ticket)
    assert json.loads((directory / (ticket["run_id"] + ".json")).read_text()) == report


@pytest.mark.parametrize("reply", bad_probe_replies(), ids=lambda value: type(value).__name__)
def test_rejected_execute_reply_still_has_a_valid_persistible_operational_report(monkeypatch, tmp_path, reply):
    m = module(monkeypatch); controller = sys.modules["s2_compatibility"]; transport = Transport()
    tmp_path.chmod(0o700); ticket = controller.prepare_report(str(tmp_path), "a" * 32)

    def execute(*args):
        transport.executions += 1
        return 2, copy.deepcopy(reply)
    transport.execute = execute
    result = m.run(prepared(), cluster(), transport, "static helper")
    assert transport.executions == 1
    persist_failure(controller, result, tmp_path, ticket)


def bad_captures():
    frame = expected(); frame.pop("run_id")
    return [[], WIRE, 7, True, None, {}, dict(frame, guest=[]), dict(frame, host_anchor=False),
            dict(frame, stdout=WIRE)]


@pytest.mark.parametrize("reply", bad_captures(), ids=lambda value: type(value).__name__)
def test_rejected_postcapture_does_not_contaminate_report_or_erase_valid_proof(monkeypatch, tmp_path, reply):
    m = module(monkeypatch); controller = sys.modules["s2_compatibility"]; transport = Transport()
    tmp_path.chmod(0o700); ticket = controller.prepare_report(str(tmp_path), "a" * 32)
    old_capture = transport.capture

    def capture(*args):
        snapshot = old_capture(*args)
        return copy.deepcopy(reply) if transport.executions else snapshot
    transport.capture = capture
    result = m.run(prepared(), cluster(), transport, "static helper")
    assert transport.executions == 1
    persist_failure(controller, result, tmp_path, ticket, accepted_result=True)


def subprocess_reply(m, monkeypatch, stdout):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert argv[:3] == ["pct", "exec", "800080"]
        return SimpleNamespace(returncode=2, stdout=stdout, stderr=WIRE)
    monkeypatch.setattr(m, "subprocess", SimpleNamespace(run=run, SubprocessError=subprocess.SubprocessError))
    return calls


@pytest.mark.parametrize("reply", [[], WIRE, 7, 2.5, True, False, None, [{}]], ids=lambda value: type(value).__name__)
def test_real_pct_decoder_rejects_json_nonobjects_before_capture(monkeypatch, reply):
    m = module(monkeypatch); calls = subprocess_reply(m, monkeypatch, json.dumps(reply))
    with pytest.raises(ValueError) as error:
        m.PctTransport(None).command(request(), "static helper", {"run_id": "a" * 32})
    assert len(calls) == 1 and WIRE not in str(error.value)


@pytest.mark.parametrize("reply", [[], WIRE, 7, True, {}, dict(expected()["guest"], stdout=WIRE)],
                         ids=lambda value: type(value).__name__)
def test_real_pct_capture_rejects_bad_snapshot_before_constructing_expectations(monkeypatch, reply):
    m, transport = pct_capture(monkeypatch)
    monkeypatch.setattr(transport, "command", lambda *args: (0, copy.deepcopy(reply)))
    with pytest.raises(ValueError): transport.capture(request(), "static helper", "ext4")


@pytest.mark.parametrize("phase", ["execute", "postcapture"])
def test_real_decoder_failure_after_attempt_keeps_the_report(monkeypatch, tmp_path, phase):
    m = module(monkeypatch); controller = sys.modules["s2_compatibility"]; transport = Transport()
    tmp_path.chmod(0o700); ticket = controller.prepare_report(str(tmp_path), "a" * 32)
    calls = subprocess_reply(m, monkeypatch, json.dumps([WIRE]))
    decoder = m.PctTransport(None)
    if phase == "execute":
        def execute(r, source, expectation):
            transport.executions += 1
            return decoder.command(r, source, expectation)
        transport.execute = execute
    else:
        old_capture = transport.capture
        def capture(r, source, filesystem):
            if transport.executions: return decoder.command(r, source)[1]
            return old_capture(r, source, filesystem)
        transport.capture = capture
    result = m.run(prepared(), cluster(), transport, "static helper")
    assert len(calls) == 1 and transport.executions == 1
    persist_failure(controller, result, tmp_path, ticket, accepted_result=phase == "postcapture")


@pytest.mark.parametrize("operational", [False, True])
def test_valid_helper_reply_is_preserved_without_qualifying_the_platform(monkeypatch, tmp_path, operational):
    m = module(monkeypatch); controller = sys.modules["s2_compatibility"]; transport = Transport()
    tmp_path.chmod(0o700); ticket = controller.prepare_report(str(tmp_path), "a" * 32)
    ops = Ops()
    if operational: ops.errors = [errno.ENOSPC]
    helper_reply = probe_module().run_probe(expected(), ops)  # All file/xattr/fork operations are fake.

    def execute(*args):
        transport.executions += 1
        return 2 if operational else 0, helper_reply
    transport.execute = execute
    result = m.run(prepared(), cluster(), transport, "static helper")
    assert result["state"] == "measured" and result["status"] == ("operational_error" if operational else "passed")
    assert result["report"]["observations"]["probe"]["result"] == helper_reply
    assert result["report"]["selection"] is None and result["report"]["qualification"] == "pending"
    controller.validate_report(result["report"])
    controller.write_report(str(tmp_path), result["report"], ticket)
