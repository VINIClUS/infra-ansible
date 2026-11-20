import json
import os
import time
from pathlib import Path

import pytest

PHASES = ("setup", "call", "teardown")


def pytest_addoption(parser):
    parser.addoption("--ci-report-dir", action="store", default=None, dest="ci_report_dir")


def pytest_configure(config):
    report_dir = config.getoption("ci_report_dir")
    if report_dir:
        config.pluginmanager.register(CiReport(Path(report_dir)), "ci-report")


def _phase(report):
    return {"outcome": report.outcome, "duration": report.duration}


def _skip_reason(report):
    if hasattr(report, "wasxfail") or not report.skipped:
        return None
    longrepr = report.longrepr
    message = longrepr[2] if isinstance(longrepr, tuple) else str(longrepr)
    return message.removeprefix("Skipped: ")


def _classify(phases, reports):
    failed = {name for name, data in phases.items() if data["outcome"] == "failed"}
    if failed & {"setup", "teardown"}:
        return "error"
    if "call" in failed:
        return "failed"
    call = reports.get("call")
    if call is not None and hasattr(call, "wasxfail"):
        return "xfailed" if call.skipped else "xpassed"
    if any(data["outcome"] == "skipped" for data in phases.values()):
        return "skipped"
    return "passed" if phases else "not_run"


def _row(nodeid, reports):
    phases = {name: _phase(reports[name]) for name in PHASES if name in reports}
    skipped = next((r for r in reports.values() if r.skipped), None)
    return {
        "nodeid": nodeid,
        "file": nodeid.split("::", 1)[0],
        "outcome": _classify(phases, reports),
        "setup": phases.get("setup"),
        "call": phases.get("call"),
        "teardown": phases.get("teardown"),
        "skip_reason": _skip_reason(skipped) if skipped is not None else None,
        "worker": os.environ.get("PYTEST_XDIST_WORKER"),
    }


class CiReport:
    def __init__(self, report_dir):
        self.report_dir = report_dir
        self.session_started = time.time()
        self.collection_started = None
        self.collection_finished = None
        self.collect_errors = []
        self.ids = []
        self.reports = {}

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_collection(self, session):
        self.collection_started = time.time()
        yield
        self.collection_finished = time.time()

    def pytest_collectreport(self, report):
        if report.failed:
            self.collect_errors.append(report.nodeid)

    def pytest_collection_finish(self, session):
        self.ids = [item.nodeid for item in session.items]

    def pytest_runtest_logreport(self, report):
        self.reports.setdefault(report.nodeid, {})[report.when] = report

    def pytest_sessionfinish(self, session, exitstatus):
        finished = time.time()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self._write_collection()
        self._write_results()
        self._write_session(int(exitstatus), finished)

    def _write_json(self, name, payload):
        (self.report_dir / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _write_collection(self):
        started = self.collection_started or self.session_started
        finished = self.collection_finished or started
        self._write_json(
            "collection.json",
            {
                "started_at": started,
                "finished_at": finished,
                "duration": finished - started,
                "count": len(self.ids),
                "ids": self.ids,
                "errors": {"count": len(self.collect_errors), "nodeids": self.collect_errors},
                "python_hash_seed": os.environ.get("PYTHONHASHSEED"),
                "pytest_version": pytest.__version__,
            },
        )

    def _write_results(self):
        rows = (_row(nodeid, self.reports.get(nodeid, {})) for nodeid in self.ids)
        lines = "".join(json.dumps(row) + "\n" for row in rows)
        (self.report_dir / "results.jsonl").write_text(lines, encoding="utf-8")

    def _write_session(self, exitstatus, finished):
        self._write_json(
            "session.json",
            {
                "exitstatus": exitstatus,
                "started_at": self.session_started,
                "finished_at": finished,
                "duration": finished - self.session_started,
                "count": len(self.ids),
            },
        )
