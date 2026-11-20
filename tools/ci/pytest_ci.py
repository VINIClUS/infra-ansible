import json
import os
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest

from tools.ci import ci_selection as selection

SUPPORTED = {"pytest": "9.2.0", "pytest-xdist": "3.8.0"}
CANONICAL = selection.CANONICAL
DEFAULT_SPLITTABLE = Path(__file__).with_name("xdist_splittable.json")
PHASES = ("setup", "call", "teardown")


def _order_type(value):
    try:
        return selection.parse_order(value)
    except ValueError as error:
        raise pytest.UsageError(str(error)) from error


def pytest_addoption(parser):
    group = parser.getgroup("ci")
    group.addoption("--ci-report-dir", dest="ci_report_dir", default=None)
    group.addoption("--ci-order", dest="ci_order", default=None, type=_order_type)
    group.addoption(
        "--ci-quarantine", dest="ci_quarantine", default=None, choices=("exclude", "only")
    )
    group.addoption("--ci-splittable", dest="ci_splittable", default=str(DEFAULT_SPLITTABLE))


def _is_worker(config):
    return hasattr(config, "workerinput")


def _distributed(config):
    if _is_worker(config):
        return True
    if not config.pluginmanager.has_plugin("xdist"):
        return False
    return config.getoption("dist", "no") != "no" or bool(config.getoption("numprocesses", 0))


def _installed(name):
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def _guard_versions():
    found = {name: _installed(name) for name in SUPPORTED}
    if found != SUPPORTED:
        raise pytest.UsageError(f"ci_versions_unsupported found={found} supported={SUPPORTED}")


def _active(config):
    return any(config.getoption(name) for name in ("ci_report_dir", "ci_order", "ci_quarantine"))


def pytest_configure(config):
    config.addinivalue_line("markers", "quarantine(reason, issue): excluded from the blocking gate")
    if not _active(config):
        return
    if not _is_worker(config) and _distributed(config):
        _guard_versions()
    config.pluginmanager.register(CiPlugin(config), "ci-plugin")


def _canonical(item):
    return item.stash.get(CANONICAL, item.nodeid)


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
    return "passed" if phases else "missing"


def _row(nodeid, reports):
    phases = {name: _phase(reports[name]) for name in PHASES if name in reports}
    skipped = next((r for r in reports.values() if r.skipped), None)
    props = dict(next(iter(reports.values())).user_properties) if reports else {}
    return {
        "nodeid": nodeid,
        "file": selection.file_of(nodeid),
        "outcome": _classify(phases, reports),
        "setup": phases.get("setup"),
        "call": phases.get("call"),
        "teardown": phases.get("teardown"),
        "skip_reason": _skip_reason(skipped) if skipped is not None else None,
        "worker": props.get("ci_worker"),
    }


class CiPlugin:
    def __init__(self, config):
        self.config = config
        report_dir = config.getoption("ci_report_dir")
        self.report_dir = Path(report_dir) if report_dir else None
        self.session_started = time.time()
        self.times = [None, None]
        self.canonical_ids = []
        self.selected = []
        self.quarantined = []
        self.collect_errors = []
        self.reports = {}
        self.node_outputs = []

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_collection(self):
        self.times[0] = time.time()
        try:
            return (yield)
        finally:
            self.times[1] = time.time()

    def pytest_collectreport(self, report):
        if report.failed and report.nodeid not in self.collect_errors:
            self.collect_errors.append(report.nodeid)

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_collection_modifyitems(self, config, items):
        for item in items:
            item.stash[CANONICAL] = item.nodeid
        self.canonical_ids = [item.nodeid for item in items]
        self._prepare(config, items)
        result = yield
        if _distributed(config) and config.getvalue("loadgroup"):
            selection.suffix_group_ids(items)
        self.selected = [_canonical(item) for item in items]
        return result

    def _prepare(self, config, items):
        marks = selection.quarantine_marks(items)
        order = config.getoption("ci_order")
        if order:
            items[:] = selection.reorder(items, order)
        mode = config.getoption("ci_quarantine")
        if mode:
            self._quarantine(config, items, marks, mode)
        if _distributed(config):
            splittable = selection.load_splittable(config.getoption("ci_splittable"))
            self._group(config, items, splittable)

    def _group(self, config, items, splittable):
        try:
            selection.apply_groups(items, splittable, config.rootpath)
        except pytest.UsageError as error:
            sys.stderr.write(f"{error}\n")
            raise

    def _quarantine(self, config, items, marks, mode):
        kept, dropped, self.quarantined = selection.split_quarantine(items, marks, mode)
        if dropped:
            config.hook.pytest_deselected(items=dropped)
        items[:] = kept

    def pytest_collection_finish(self, session):
        if _is_worker(self.config):
            self.config.workeroutput.update(self._worker_payload())

    def _worker_payload(self):
        return {
            "ci_collection": self.canonical_ids,
            "ci_selected": self.selected,
            "ci_quarantined": self.quarantined,
            "ci_collect_errors": self.collect_errors,
            "ci_times": self.times,
        }

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_makereport(self, item, call):
        report = yield
        worker = os.environ.get("PYTEST_XDIST_WORKER")
        extra = [("ci_nodeid", _canonical(item)), ("ci_worker", worker)]
        report.user_properties = [*report.user_properties, *extra]
        return report

    def pytest_runtest_logreport(self, report):
        if _is_worker(self.config):
            return
        props = dict(report.user_properties)
        nodeid = props.get("ci_nodeid", report.nodeid)
        self.reports.setdefault(nodeid, {})[report.when] = report

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node, error):
        self.node_outputs.append(getattr(node, "workeroutput", None) or {})

    def pytest_sessionfinish(self, session, exitstatus):
        if _is_worker(self.config) or self.report_dir is None:
            return
        finished = time.time()
        merged = self._merge_nodes()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self._write_collection(merged)
        self._write_results()
        self._write_session(int(exitstatus), finished)
        if self.config.getoption("ci_quarantine"):
            self._write_json("quarantined.json", self.quarantined)

    def _merge_nodes(self):
        outputs = [out for out in self.node_outputs if "ci_collection" in out]
        if not outputs:
            return None
        first = outputs[0]
        self.canonical_ids = first["ci_collection"]
        self.selected = first["ci_selected"]
        self.quarantined = first["ci_quarantined"]
        self.collect_errors = sorted({e for out in outputs for e in out["ci_collect_errors"]})
        starts = [out["ci_times"][0] for out in outputs]
        ends = [out["ci_times"][1] for out in outputs]
        self.times = [min(starts), max(ends)]
        keys = ("ci_collection", "ci_selected")
        return all(all(out[key] == first[key] for key in keys) for out in outputs)

    def _write_json(self, name, payload):
        (self.report_dir / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _write_collection(self, identical):
        started = self.times[0] or self.session_started
        finished = self.times[1] or started
        self._write_json(
            "collection.json",
            {
                "started_at": started,
                "finished_at": finished,
                "duration": finished - started,
                "count": len(self.selected),
                "ids": self.selected,
                "canonical_ids": self.canonical_ids,
                "workers_identical": True if identical is None else identical,
                "errors": {"count": len(self.collect_errors), "nodeids": self.collect_errors},
                "python_hash_seed": os.environ.get("PYTHONHASHSEED"),
                "pytest_version": pytest.__version__,
            },
        )

    def _write_results(self):
        rows = (_row(nodeid, self.reports.get(nodeid, {})) for nodeid in self.selected)
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
                "count": len(self.selected),
            },
        )

