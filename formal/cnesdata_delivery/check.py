"""Check every CnesData delivery TLA+ and Alloy model against its expected outcome."""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MODEL_SUFFIXES = (".tla", ".cfg", ".als")
TLC_VIOLATIONS = {11: "deadlock", 12: "invariant", 13: "temporal"}
TLC_PASSED = "Model checking completed. No error has been found."
TLC_INVARIANT = re.compile(r"^Error: Invariant (\S+) is violated\.$", re.M)
ALLOY_LISTED = re.compile(r"^\d+ \. ")
ALLOY_COMMAND = re.compile(r"^(\d+) \. (Run|Check) (\S+)(?: .*)?$")


class Report:
    def __init__(self):
        self.checked = 0
        self.failures = 0

    def outcome(self, ok, tool, name, expected, observed, seconds=0.0):
        print(f"{'PASS' if ok else 'FAIL'} {tool} {name} expected={expected} observed={observed} "
              f"seconds={seconds:.1f}", flush=True)
        self.checked += tool in ("tla", "alloy")
        self.failures += not ok

    def note(self, tool, name, expected, observed, seconds=0.0):
        print(f"INFO {tool} {name} expected={expected} observed={observed} seconds={seconds:.1f}", flush=True)

    def summary(self):
        print(f"SUMMARY checked={self.checked} failures={self.failures}", flush=True)
        return 0 if self.failures == 0 and self.checked > 0 else 1


def run_tool(command, cwd, timeout):
    started = time.monotonic()
    try:
        process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                   errors="replace", start_new_session=True)
    except OSError as error:
        return f"error-{type(error).__name__}", "", time.monotonic() - started
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        return "timeout", "", time.monotonic() - started
    return process.returncode, output, time.monotonic() - started


def tlc_outcome(code, output):
    if code == 0:
        return "pass" if TLC_PASSED in output else "unconfirmed-pass"
    if code in TLC_VIOLATIONS:
        found = TLC_INVARIANT.search(output) if code == 12 else None
        return TLC_VIOLATIONS[code] + (":" + found.group(1) if found else "")
    return code if isinstance(code, str) else f"error-{code}"


def check_tla(stem, args, workspace, report):
    expected = "violation" if "Mutant" in stem else "pass"
    command = [args.java, "-XX:+UseParallelGC", "-cp", str(args.tla_jar), "tlc2.TLC", "-config", f"{stem}.cfg",
               "-workers", "auto", "-metadir", str(workspace / "states" / stem), f"{stem}.tla"]
    code, output, seconds = run_tool(command, workspace / "models", args.timeout)
    observed = tlc_outcome(code, output)
    if expected == "pass":
        ok = observed == "pass"
    else:
        ok = observed.split(":")[0] in TLC_VIOLATIONS.values()
    report.outcome(ok, "tla", stem, expected, observed, seconds)


def tla_models(models, report):
    modules = {path.stem for path in models.glob("*.tla")}
    configs = {path.stem for path in models.glob("*.cfg")}
    for stem in sorted(configs - modules):
        report.outcome(False, "tla", stem, "module", "cfg-without-module")
    for stem in sorted(modules - configs):
        if "Mutant" in stem:
            report.outcome(False, "tla", stem, "violation", "mutant-without-cfg")
        else:
            report.note("tla", stem, "library", "not-run")
    return sorted(modules & configs)


def alloy_expectation(kind, name):
    if kind == "check":
        return "counterexample" if name.startswith("mutant_") else "no-counterexample"
    return "satisfiable" if name.startswith("sat_") else "ungated"


def listing_failure(code, listed):
    if code != 0:
        return code if isinstance(code, str) else f"error-{code}"
    return "no-commands" if not listed else "unparsed-listing"


def alloy_commands(path, args, workspace, report):
    command = [args.java, "-Djava.awt.headless=true", "-jar", str(args.alloy_jar), "commands", path.name]
    code, output, seconds = run_tool(command, workspace / "models", args.timeout)
    listed = [line for line in output.splitlines() if ALLOY_LISTED.match(line)] if code == 0 else []
    found = [ALLOY_COMMAND.match(line) for line in listed]
    commands = [(match.group(2).lower(), match.group(3)) for match in found if match]
    complete = len(commands) == len(listed) and [int(match.group(1)) for match in found] == list(range(len(listed)))
    if not commands or not complete:
        observed = listing_failure(code, listed)
        report.outcome(False, "alloy", path.name, "commands", observed, seconds)
        return []
    names = [name for _, name in commands]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    for name in duplicates:
        report.outcome(False, "alloy", f"{path.name}:{name}", "unique-name", "duplicate", seconds)
    return [] if duplicates else commands


def alloy_entry(receipt, kind, name):
    entries = receipt.get("commands") if isinstance(receipt, dict) else None
    if not isinstance(entries, dict) or set(entries) != {name} or entries[name].get("type") != kind:
        return None
    return entries[name]


def check_alloy_command(path, index, kind, name, args, workspace):
    output = workspace / "alloy" / path.stem / str(index)
    command = [args.java, "-Djava.awt.headless=true", "-jar", str(args.alloy_jar), "exec", "-q", "-f",
               "-t", "json", "-o", str(output), "-c", str(index), path.name]
    code, _, seconds = run_tool(command, workspace / "models", args.timeout)
    if code != 0:
        return (code if isinstance(code, str) else f"error-{code}"), seconds
    try:
        receipt = json.loads((output / "receipt.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "no-receipt", seconds
    entry = alloy_entry(receipt, kind, name)
    if entry is None:
        return "receipt-mismatch", seconds
    if "source" not in entry:
        return "no-commands", seconds
    found = any(solution.get("instances") for solution in entry.get("solution", []))
    if kind == "check":
        return ("counterexample" if found else "no-counterexample"), seconds
    return ("satisfiable" if found else "unsatisfiable"), seconds


def check_alloy(path, args, workspace, report):
    for index, (kind, name) in enumerate(alloy_commands(path, args, workspace, report)):
        expected = alloy_expectation(kind, name)
        observed, seconds = check_alloy_command(path, index, kind, name, args, workspace)
        if observed == "no-commands":
            report.outcome(False, "alloy", path.name, "commands", observed, seconds)
        elif expected == "ungated":
            report.note("alloy", f"{path.name}:{name}", expected, observed, seconds)
        else:
            report.outcome(observed == expected, "alloy", f"{path.name}:{name}", expected, observed, seconds)


def layout(models, report):
    for path in sorted(models.rglob("*")):
        if path.suffix in MODEL_SUFFIXES and path.parent != models:
            report.outcome(False, "layout", str(path.relative_to(models)), "flat", "nested")


def arguments(argv):
    parser = argparse.ArgumentParser(description="Check the CnesData delivery formal models")
    parser.add_argument("--tla-jar", required=True, type=Path)
    parser.add_argument("--alloy-jar", required=True, type=Path)
    parser.add_argument("--models", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--java", default="java")
    parser.add_argument("--timeout", type=int, default=600)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    report = Report()
    models = args.models.resolve()
    for label, jar in (("tla-jar", args.tla_jar), ("alloy-jar", args.alloy_jar)):
        if not jar.is_file():
            report.outcome(False, "setup", label, "file", "missing")
    layout(models, report)
    if report.failures:
        return report.summary()
    with tempfile.TemporaryDirectory(prefix="formal-") as folder:
        workspace = Path(folder)
        (workspace / "models").mkdir()
        for path in sorted(models.iterdir()):
            if path.is_file() and path.suffix in MODEL_SUFFIXES:
                shutil.copy2(path, workspace / "models" / path.name)
        for stem in tla_models(models, report):
            check_tla(stem, args, workspace, report)
        for path in sorted(models.glob("*.als")):
            check_alloy(path, args, workspace, report)
    if report.checked == 0 and report.failures == 0:
        report.outcome(False, "discovery", "models", "at-least-one", "none")
    return report.summary()


if __name__ == "__main__":
    sys.exit(main())
