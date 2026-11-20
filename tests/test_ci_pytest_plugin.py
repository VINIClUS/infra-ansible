import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

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


def _inner_dir(tmp_path):
    inner = tmp_path / "inner"
    inner.mkdir()
    (inner / "test_inner.py").write_text(INNER_SUITE, encoding="utf-8")
    return inner


def _run_inner(tmp_path, *extra, plugin=True):
    inner = _inner_dir(tmp_path) if not (tmp_path / "inner").exists() else tmp_path / "inner"
    command = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rA"]
    if plugin:
        command += ["-p", "tools.ci.pytest_ci"]
    command += [*extra, str(inner)]
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    env.pop("PYTEST_ADDOPTS", None)
    return subprocess.run(
        command, cwd=tmp_path, env=env, capture_output=True, text=True, check=False
    )


def _run_with_report(tmp_path):
    report = tmp_path / "report"
    result = _run_inner(tmp_path, "--ci-report-dir", str(report))
    return result, report


def _results(report):
    lines = (report / "results.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def _by_name(report):
    return {row["nodeid"].split("::", 1)[1]: row for row in _results(report)}


def _outcome_lines(text):
    pattern = r"^(PASSED|FAILED|SKIPPED|XFAIL|XPASS|ERROR) (\S+)"
    return sorted(re.findall(pattern, text, flags=re.MULTILINE))


def _summary_line(text):
    last = [line for line in text.splitlines() if line.strip()][-1]
    return re.sub(r" in [0-9.]+s.*$", "", last)


def test_plugin_registra_nodeid_resultado_e_duracao_de_cada_teste(tmp_path):
    _, report = _run_with_report(tmp_path)

    rows = _by_name(report)
    for name, outcome in OUTCOMES.items():
        assert rows[name]["outcome"] == outcome, name
        assert "test_inner.py::" in rows[name]["nodeid"]
        assert rows[name]["file"].endswith("test_inner.py")
    passed = rows["test_passa"]
    assert passed["call"]["outcome"] == "passed"
    assert passed["call"]["duration"] >= 0
    assert passed["setup"]["outcome"] == "passed"
    assert passed["teardown"]["outcome"] == "passed"
    assert passed["skip_reason"] is None
    assert "worker" in passed
    assert (report / "session.json").exists()
    session = json.loads((report / "session.json").read_text(encoding="utf-8"))
    assert session["count"] == len(_results(report))
    assert session["exitstatus"] == 1
    assert session["finished_at"] >= session["started_at"]


def test_plugin_registra_inicio_e_fim_da_coleta(tmp_path):
    _, report = _run_with_report(tmp_path)

    collection = json.loads((report / "collection.json").read_text(encoding="utf-8"))
    assert collection["finished_at"] >= collection["started_at"] > 0
    assert collection["duration"] >= 0
    assert collection["count"] == len(collection["ids"]) == len(_results(report))
    assert collection["errors"]["count"] == 0
    assert collection["errors"]["nodeids"] == []
    assert collection["pytest_version"] == pytest.__version__
    assert "python_hash_seed" in collection
    assert [row["nodeid"] for row in _results(report)] == collection["ids"]


def test_plugin_nao_altera_resultado_nem_contagem(tmp_path):
    com = tmp_path / "com"
    sem = tmp_path / "sem"
    com.mkdir()
    sem.mkdir()
    with_plugin = _run_inner(com, "--ci-report-dir", str(com / "report"))
    without_plugin = _run_inner(sem, plugin=False)

    assert with_plugin.returncode == without_plugin.returncode == 1
    assert _outcome_lines(with_plugin.stdout) == _outcome_lines(without_plugin.stdout)
    assert _summary_line(with_plugin.stdout) == _summary_line(without_plugin.stdout)
    assert with_plugin.stderr == without_plugin.stderr


def test_plugin_registra_motivo_do_skip(tmp_path):
    _, report = _run_with_report(tmp_path)

    rows = _by_name(report)
    assert rows["test_pulado"]["skip_reason"] == "motivo do skip"
    assert rows["test_passa"]["skip_reason"] is None


def test_plugin_registra_erro_de_setup_como_error(tmp_path):
    _, report = _run_with_report(tmp_path)

    row = _by_name(report)["test_erro_setup"]
    assert row["outcome"] == "error"
    assert row["setup"]["outcome"] == "failed"
    assert row["call"] is None


def test_plugin_registra_erro_de_teardown_como_error(tmp_path):
    _, report = _run_with_report(tmp_path)

    row = _by_name(report)["test_erro_teardown"]
    assert row["outcome"] == "error"
    assert row["call"]["outcome"] == "passed"
    assert row["teardown"]["outcome"] == "failed"


def test_plugin_preserva_ids_parametrizados(tmp_path):
    _, report = _run_with_report(tmp_path)

    names = [row["nodeid"].split("::", 1)[1] for row in _results(report)]
    assert "test_parametrizado[1]" in names
    assert "test_parametrizado[a b]" in names
    assert "test_parametrizado[None]" in names
    collection = json.loads((report / "collection.json").read_text(encoding="utf-8"))
    assert collection["ids"] == [row["nodeid"] for row in _results(report)]


def test_plugin_sem_opcao_nao_escreve_nada(tmp_path):
    result = _run_inner(tmp_path)

    assert result.returncode == 1
    entries = sorted(path.name for path in tmp_path.iterdir())
    assert entries == ["inner"]
    assert sorted(path.name for path in (tmp_path / "inner").iterdir()) == ["test_inner.py"]


def test_plugin_registra_erros_de_coleta(tmp_path):
    inner = tmp_path / "inner"
    inner.mkdir()
    (inner / "test_quebrado.py").write_text("import modulo_inexistente_xyz\n", encoding="utf-8")
    (inner / "test_ok.py").write_text("def test_ok():\n    pass\n", encoding="utf-8")
    report = tmp_path / "report"
    result = _run_inner(tmp_path, "--ci-report-dir", str(report))

    collection = json.loads((report / "collection.json").read_text(encoding="utf-8"))
    assert result.returncode == 2
    assert collection["errors"]["count"] == 1
    assert collection["errors"]["nodeids"][0].endswith("test_quebrado.py")


def test_plugin_e_importavel_como_pacote_namespace():
    command = [sys.executable, "-c", "import tools.ci.pytest_ci as m; print(m.__file__)"]
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    result = subprocess.run(
        command, cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("pytest_ci.py")
    assert not (REPO_ROOT / "tools" / "__init__.py").exists()
    assert not (REPO_ROOT / "tools" / "ci" / "__init__.py").exists()
