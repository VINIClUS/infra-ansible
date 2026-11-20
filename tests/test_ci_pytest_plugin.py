import json
import os
import re
import subprocess
import sys

import pytest
from ci_plugin_support import (
    OUTCOMES,
    REPO_ROOT,
    by_name,
    inner_env,
    pytest_run,
    read,
    results,
    run_inner,
    run_with_report,
)


def _outcome_lines(text):
    pattern = r"^(PASSED|FAILED|SKIPPED|XFAIL|XPASS|ERROR) (\S+)"
    return sorted(re.findall(pattern, text, flags=re.MULTILINE))


def _summary_line(text):
    last = [line for line in text.splitlines() if line.strip()][-1]
    return re.sub(r" in [0-9.]+s.*$", "", last)


def test_plugin_registra_nodeid_resultado_e_duracao_de_cada_teste(tmp_path):
    _, report = run_with_report(tmp_path)

    rows = by_name(report)
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
    assert session["count"] == len(results(report))
    assert session["exitstatus"] == 1
    assert session["finished_at"] >= session["started_at"]


def test_plugin_registra_inicio_e_fim_da_coleta(tmp_path):
    _, report = run_with_report(tmp_path)

    collection = json.loads((report / "collection.json").read_text(encoding="utf-8"))
    assert collection["finished_at"] >= collection["started_at"] > 0
    assert collection["duration"] >= 0
    assert collection["count"] == len(collection["ids"]) == len(results(report))
    assert collection["errors"]["count"] == 0
    assert collection["errors"]["nodeids"] == []
    assert collection["pytest_version"] == pytest.__version__
    assert "python_hash_seed" in collection
    assert [row["nodeid"] for row in results(report)] == collection["ids"]


def test_plugin_nao_altera_resultado_nem_contagem(tmp_path):
    com = tmp_path / "com"
    sem = tmp_path / "sem"
    com.mkdir()
    sem.mkdir()
    with_plugin = run_inner(com, "--ci-report-dir", str(com / "report"))
    without_plugin = run_inner(sem, plugin=False)

    assert with_plugin.returncode == without_plugin.returncode == 1
    assert _outcome_lines(with_plugin.stdout) == _outcome_lines(without_plugin.stdout)
    assert _summary_line(with_plugin.stdout) == _summary_line(without_plugin.stdout)
    assert with_plugin.stderr == without_plugin.stderr


def test_plugin_registra_motivo_do_skip(tmp_path):
    _, report = run_with_report(tmp_path)

    rows = by_name(report)
    assert rows["test_pulado"]["skip_reason"] == "motivo do skip"
    assert rows["test_passa"]["skip_reason"] is None


def test_plugin_registra_erro_de_setup_como_error(tmp_path):
    _, report = run_with_report(tmp_path)

    row = by_name(report)["test_erro_setup"]
    assert row["outcome"] == "error"
    assert row["setup"]["outcome"] == "failed"
    assert row["call"] is None


def test_plugin_registra_erro_de_teardown_como_error(tmp_path):
    _, report = run_with_report(tmp_path)

    row = by_name(report)["test_erro_teardown"]
    assert row["outcome"] == "error"
    assert row["call"]["outcome"] == "passed"
    assert row["teardown"]["outcome"] == "failed"


def test_plugin_preserva_ids_parametrizados(tmp_path):
    _, report = run_with_report(tmp_path)

    names = [row["nodeid"].split("::", 1)[1] for row in results(report)]
    assert "test_parametrizado[1]" in names
    assert "test_parametrizado[a b]" in names
    assert "test_parametrizado[None]" in names
    collection = json.loads((report / "collection.json").read_text(encoding="utf-8"))
    assert collection["ids"] == [row["nodeid"] for row in results(report)]


def test_plugin_sem_opcao_nao_escreve_nada(tmp_path):
    result = run_inner(tmp_path)

    assert result.returncode == 1
    entries = sorted(path.name for path in tmp_path.iterdir())
    assert entries == ["inner"]
    assert sorted(path.name for path in (tmp_path / "inner").iterdir()) == ["test_inner.py"]


def test_plugin_registra_erros_de_coleta(tmp_path):
    files = {
        "test_quebrado.py": "import modulo_inexistente_xyz\n",
        "test_ok.py": "def test_ok():\n    pass\n",
    }
    report = tmp_path / "report"
    result = pytest_run(tmp_path, "--ci-report-dir", str(report), files=files)

    collection = read(report, "collection.json")
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
