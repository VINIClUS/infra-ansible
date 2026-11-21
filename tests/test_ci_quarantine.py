import json

import pytest
from ci_plugin_support import by_name, pytest_run, read, results

REPO_REGISTRY = "tools/ci/quarantine.json"

MARKED_FAILING = '''
import pytest


@pytest.mark.quarantine(reason="instavel", issue="#1")
def test_instavel():
    assert False


def test_estavel():
    assert True
'''
MARKED_PASSING = '''
import pytest


@pytest.mark.quarantine(reason="instavel", issue="#1")
def test_instavel():
    assert True
'''
ENTRY = {"reason": "instavel", "issue": "#1"}

PROTECTED = [
    "tests/test_cnesdata_x.py",
    "tests/test_reusable_workflow_secrets.py",
    "tests/test_github_workflow_extra.py",
    "tests/test_formal_x.py",
    "tests/production_x.py",
    "tests/production/test_p.py",
    "tests/test_ci_x.py",
]


def _registry(tmp_path, *nodeids, **entry):
    values = {**ENTRY, **entry}
    path = tmp_path / "registry.json"
    rows = [{"nodeid": nodeid, **values} for nodeid in nodeids]
    path.write_text(json.dumps(rows), encoding="utf-8")
    return str(path)


def _run(tmp_path, registry, mode, files, *extra, **kwargs):
    return pytest_run(
        tmp_path,
        "--ci-quarantine",
        mode,
        "--ci-quarantine-registry",
        registry,
        *extra,
        files=files,
        **kwargs,
    )


def test_lista_de_negacao_da_quarentena_e_fixa():
    from tools.ci.ci_selection import QUARANTINE_DENY

    assert QUARANTINE_DENY == (
        "tests/test_cnesdata_*",
        "tests/test_reusable_workflow_secrets.py",
        "tests/test_github_workflow*.py",
        "tests/test_formal_*",
        "tests/production*",
        "tests/production/*",
        "tests/test_ci_*",
    )


def test_registro_de_quarentena_comeca_vazio():
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / REPO_REGISTRY
    assert json.loads(path.read_text(encoding="utf-8")) == []


def test_quarentena_exclude_tira_do_gate_e_registra(tmp_path):
    report = tmp_path / "report"
    registry = _registry(tmp_path, "test_q.py::test_instavel")
    result = _run(
        tmp_path, registry, "exclude", {"test_q.py": MARKED_FAILING},
        "--ci-report-dir", str(report),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert [row["nodeid"] for row in results(report)] == ["test_q.py::test_estavel"]
    assert read(report, "quarantined.json") == [
        {"nodeid": "test_q.py::test_instavel", **ENTRY}
    ]


def test_quarentena_only_executa_somente_os_quarentenados(tmp_path):
    report = tmp_path / "report"
    registry = _registry(tmp_path, "test_q.py::test_instavel")
    result = _run(
        tmp_path, registry, "only", {"test_q.py": MARKED_FAILING},
        "--ci-report-dir", str(report),
    )

    rows = results(report)
    assert result.returncode == 0, result.stdout + result.stderr
    assert [row["nodeid"] for row in rows] == ["test_q.py::test_instavel"]
    assert rows[0]["outcome"] == "failed"


@pytest.mark.parametrize("path", PROTECTED)
def test_quarentena_em_arquivo_protegido_e_recusada(tmp_path, path):
    nodeid = f"{path}::test_instavel"
    registry = _registry(tmp_path, nodeid)
    result = _run(tmp_path, registry, "exclude", {path: MARKED_FAILING})

    assert result.returncode != 0
    assert f"ci_quarantine_forbidden nodeid={nodeid}" in result.stderr


def test_quarentena_em_arquivo_protegido_e_recusada_sob_xdist(tmp_path):
    path = "tests/test_reusable_workflow_secrets.py"
    nodeid = f"{path}::test_instavel"
    registry = _registry(tmp_path, nodeid)
    result = _run(
        tmp_path, registry, "exclude", {path: MARKED_FAILING},
        "-n", "2", "--dist", "loadgroup",
    )

    assert result.returncode != 0
    assert f"ci_quarantine_forbidden nodeid={nodeid}" in result.stderr


def test_quarentena_sem_registro_e_recusada(tmp_path):
    result = _run(
        tmp_path, _registry(tmp_path), "exclude", {"test_q.py": MARKED_FAILING}
    )

    assert result.returncode != 0
    assert "ci_quarantine_unregistered nodeid=test_q.py::test_instavel" in result.stderr


def test_quarentena_com_motivo_diferente_do_registro_e_recusada(tmp_path):
    registry = _registry(tmp_path, "test_q.py::test_instavel", reason="outro")
    result = _run(tmp_path, registry, "exclude", {"test_q.py": MARKED_FAILING})

    assert result.returncode != 0
    assert "ci_quarantine_unregistered nodeid=test_q.py::test_instavel" in result.stderr


@pytest.mark.parametrize(
    "stale_id",
    ["test_q.py::test_inexistente", "test_q.py::test_estavel", "test_ausente.py::test_x"],
)
def test_registro_obsoleto_e_recusado(tmp_path, stale_id):
    registry = _registry(tmp_path, "test_q.py::test_instavel", stale_id)
    result = _run(tmp_path, registry, "exclude", {"test_q.py": MARKED_FAILING})

    assert result.returncode != 0
    assert f"ci_quarantine_stale nodeid={stale_id}" in result.stderr


def test_registro_de_arquivo_nao_coletado_nao_e_obsoleto(tmp_path):
    files = {"test_q.py": MARKED_FAILING, "test_outro.py": MARKED_PASSING}
    registry = _registry(tmp_path, "test_q.py::test_instavel", "test_outro.py::test_instavel")
    target = str(tmp_path / "inner" / "test_q.py")
    result = _run(tmp_path, registry, "exclude", files, targets=[target])

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ci_quarantine_stale" not in result.stderr


def test_quarentenado_que_passa_reprova_a_execucao(tmp_path):
    registry = _registry(tmp_path, "test_q.py::test_instavel")
    result = _run(tmp_path, registry, "only", {"test_q.py": MARKED_PASSING})

    assert result.returncode == 1
    assert "ci_quarantine_now_passes nodeid=test_q.py::test_instavel" in result.stderr


def test_quarentenado_que_falha_nao_bloqueia(tmp_path):
    registry = _registry(tmp_path, "test_q.py::test_instavel")
    result = _run(tmp_path, registry, "only", {"test_q.py": MARKED_FAILING})

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ci_quarantine_now_passes" not in result.stderr
