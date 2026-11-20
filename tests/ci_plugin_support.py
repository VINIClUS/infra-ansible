import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

INNER_SUITE = '''
import pytest


@pytest.fixture
def quebra_no_setup():
    raise RuntimeError("setup")


@pytest.fixture
def quebra_no_teardown():
    yield
    raise RuntimeError("teardown")


def test_passa():
    assert True


def test_falha():
    assert False


@pytest.mark.skip(reason="motivo do skip")
def test_pulado():
    pass


@pytest.mark.xfail(reason="esperado")
def test_xfail():
    assert False


@pytest.mark.xfail(reason="inesperado")
def test_xpass():
    assert True


def test_erro_setup(quebra_no_setup):
    pass


def test_erro_teardown(quebra_no_teardown):
    pass


@pytest.mark.parametrize("valor", [1, "a b", None])
def test_parametrizado(valor):
    assert True
'''

OUTCOMES = {
    "test_passa": "passed",
    "test_falha": "failed",
    "test_pulado": "skipped",
    "test_xfail": "xfailed",
    "test_xpass": "xpassed",
    "test_erro_setup": "error",
    "test_erro_teardown": "error",
}


def inner_env(*extra_paths):
    env = {key: value for key, value in os.environ.items() if not key.startswith("PYTEST_")}
    env["PYTHONPATH"] = os.pathsep.join([str(REPO_ROOT), *map(str, extra_paths)])
    return env


def write_suite(tmp_path, files=None):
    inner = tmp_path / "inner"
    inner.mkdir(parents=True, exist_ok=True)
    for name, content in (files or {"test_inner.py": INNER_SUITE}).items():
        (inner / name).write_text(content, encoding="utf-8")
    return inner


def pytest_run(tmp_path, *args, plugin=True, cwd=None, env=None, files=None):
    inner = write_suite(tmp_path, files)
    command = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rA"]
    command += ["--rootdir", str(inner)]
    if plugin:
        command += ["-p", "tools.ci.pytest_ci"]
    command += [*args, str(inner)]
    return subprocess.run(
        command,
        cwd=cwd or tmp_path,
        env=env or inner_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )


def run_inner(tmp_path, *extra, plugin=True):
    return pytest_run(tmp_path, *extra, plugin=plugin)


def run_with_report(tmp_path):
    report = tmp_path / "report"
    result = run_inner(tmp_path, "--ci-report-dir", str(report))
    return result, report


def read(report, name):
    return json.loads((report / name).read_text(encoding="utf-8"))


def results(report):
    lines = (report / "results.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def by_name(report):
    return {row["nodeid"].split("::", 1)[1]: row for row in results(report)}
