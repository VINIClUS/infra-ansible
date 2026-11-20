import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

from ci_plugin_support import (
    REPO_ROOT,
    by_name,
    inner_env,
    pytest_run,
    read,
    results,
)

DIST = ("-n", "2", "--dist", "loadgroup")

FILE_A = "\n".join(
    f"def test_a{index}():\n    assert True\n" for index in range(6)
)
FILE_B = "\n".join(
    f"def test_b{index}():\n    assert True\n" for index in range(6)
)
FILE_PARAM = '''
import pytest


@pytest.mark.parametrize("valor", ["x@y", "z"])
def test_param(valor):
    assert True
'''
FILE_SPLIT = '''
def test_s0(tmp_path):
    assert tmp_path.exists()


def test_s1(tmp_path):
    assert tmp_path.exists()


def test_s2():
    assert True


def test_s3():
    assert True
'''
FILE_BROAD = '''
import pytest


@pytest.fixture(scope="module")
def caro():
    return 1


def test_usa_caro(caro):
    assert caro == 1
'''
FILE_QUARANTINE = '''
import pytest


@pytest.mark.quarantine(reason="instavel", issue="#1")
def test_instavel():
    assert False


def test_estavel():
    assert True
'''
FILE_ORDER = "\n".join(
    f"def test_o{index}():\n    assert True\n" for index in range(8)
)


def _splittable(tmp_path, *paths):
    target = tmp_path / "splittable.json"
    target.write_text(json.dumps(list(paths)), encoding="utf-8")
    return str(target)


def _args(tmp_path, report, *paths, extra=()):
    return (
        *DIST,
        "--ci-report-dir",
        str(report),
        "--ci-splittable",
        _splittable(tmp_path, *paths),
        *extra,
    )


def _collect_only(tmp_path, files):
    result = pytest_run(tmp_path, "--collect-only", plugin=False, files=files)
    return [line for line in result.stdout.splitlines() if "::" in line]


def test_nodeid_canonico_nao_tem_sufixo_de_grupo_xdist(tmp_path):
    files = {"test_a.py": FILE_A, "test_param.py": FILE_PARAM}
    report = tmp_path / "report"
    result = pytest_run(tmp_path, *_args(tmp_path, report), files=files)

    ids = [row["nodeid"] for row in results(report)]
    assert result.returncode == 0, result.stdout
    assert "test_param.py::test_param[x@y]" in ids
    assert not any(value.endswith("@test_a.py") for value in ids)
    assert sorted(ids) == sorted(_collect_only(tmp_path / "gt", files))
    assert all(row["outcome"] == "passed" for row in results(report))


def test_arquivo_vira_grupo_xdist_por_padrao(tmp_path):
    files = {"test_a.py": FILE_A, "test_b.py": FILE_B}
    report = tmp_path / "report"
    result = pytest_run(tmp_path, *_args(tmp_path, report), files=files)

    assert result.returncode == 0, result.stdout
    for name in ("test_a.py", "test_b.py"):
        workers = {row["worker"] for row in results(report) if row["file"] == name}
        assert len(workers) == 1 and workers <= {"gw0", "gw1"}


def test_arquivo_divisivel_nao_recebe_grupo(tmp_path):
    files = {"test_split.py": FILE_SPLIT, "test_a.py": FILE_A}
    report = tmp_path / "report"
    junit = tmp_path / "junit.xml"
    result = pytest_run(
        tmp_path,
        *_args(tmp_path, report, "test_split.py", extra=("--junitxml", str(junit))),
        files=files,
    )

    names = [case.get("name") for case in ET.parse(junit).getroot().iter("testcase")]
    assert result.returncode == 0, result.stdout
    assert any(name.startswith("test_a0") and "@" in name for name in names)
    assert all("@" not in name for name in names if name.startswith("test_s"))
    assert {row["file"] for row in results(report)} == {"test_split.py", "test_a.py"}


def test_arquivo_divisivel_com_fixture_de_modulo_e_recusado(tmp_path):
    report = tmp_path / "report"
    result = pytest_run(
        tmp_path,
        *_args(tmp_path, report, "test_broad.py"),
        files={"test_broad.py": FILE_BROAD},
    )

    assert result.returncode != 0
    assert "ci_splittable_broad_fixture nodeid=test_broad.py::test_usa_caro" in (
        result.stdout + result.stderr
    )


def test_worker_envia_colecao_canonica_ao_controlador(tmp_path):
    files = {"test_a.py": FILE_A, "test_param.py": FILE_PARAM}
    report = tmp_path / "report"
    pytest_run(tmp_path, *_args(tmp_path, report), files=files)

    collection = read(report, "collection.json")
    assert collection["workers_identical"] is True
    assert sorted(collection["ids"]) == sorted(_collect_only(tmp_path / "gt", files))
    assert collection["count"] == len(collection["ids"]) == len(results(report))
    assert read(report, "session.json")["count"] == collection["count"]


def test_plugin_carrega_nos_workers_xdist(tmp_path):
    inner = tmp_path / "inner"
    inner.mkdir()
    (inner / "test_a.py").write_text(FILE_A, encoding="utf-8")
    report = tmp_path / "report"
    env = inner_env()
    env.pop("PYTHONPATH")
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-q",
        "--rootdir",
        str(inner),
        *DIST,
        "-p",
        "tools.ci.pytest_ci",
        "--ci-report-dir",
        str(report),
        str(inner),
    ]
    result = subprocess.run(
        command, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=300
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert {row["worker"] for row in results(report)} <= {"gw0", "gw1"}
    assert read(report, "collection.json")["workers_identical"] is True


def _order(tmp_path, *order_args):
    report = tmp_path / "report"
    pytest_run(
        tmp_path,
        "--ci-report-dir",
        str(report),
        *order_args,
        files={"test_one.py": FILE_ORDER, "test_two.py": FILE_A},
    )
    return [row["nodeid"] for row in results(report)]


def test_ordem_reversa_inverte_testes_dentro_do_arquivo(tmp_path):
    normal = _order(tmp_path / "n")
    reverso = _order(tmp_path / "r", "--ci-order", "reverse")

    assert reverso[:8] == list(reversed(normal[:8]))
    assert reverso[8:] == list(reversed(normal[8:]))
    assert reverso[0].startswith("test_one.py") and reverso[-1].startswith("test_two.py")


def test_ordem_com_semente_e_deterministica(tmp_path):
    primeira = _order(tmp_path / "a", "--ci-order", "seed:20261120")
    segunda = _order(tmp_path / "b", "--ci-order", "seed:20261120")
    normal = _order(tmp_path / "c")

    assert primeira == segunda
    assert primeira != normal
    assert sorted(primeira) == sorted(normal)


def test_quarentena_exige_motivo_e_issue(tmp_path):
    suite = (
        "import pytest\n\n\n@pytest.mark.quarantine(reason='x')\n"
        "def test_sem_issue():\n    pass\n"
    )
    result = pytest_run(tmp_path, "--ci-report-dir", str(tmp_path / "r"), files={"test_q.py": suite})

    assert result.returncode == 4
    assert "ci_quarantine_invalid nodeid=test_q.py::test_sem_issue" in (
        result.stdout + result.stderr
    )


def test_quarentena_exclude_tira_do_gate_e_registra(tmp_path):
    report = tmp_path / "report"
    result = pytest_run(
        tmp_path,
        "--ci-report-dir",
        str(report),
        "--ci-quarantine",
        "exclude",
        files={"test_q.py": FILE_QUARANTINE},
    )

    assert result.returncode == 0, result.stdout
    assert [row["nodeid"] for row in results(report)] == ["test_q.py::test_estavel"]
    assert read(report, "quarantined.json") == [
        {"nodeid": "test_q.py::test_instavel", "reason": "instavel", "issue": "#1"}
    ]


def test_quarentena_only_executa_somente_os_quarentenados(tmp_path):
    report = tmp_path / "report"
    result = pytest_run(
        tmp_path,
        "--ci-report-dir",
        str(report),
        "--ci-quarantine",
        "only",
        files={"test_q.py": FILE_QUARANTINE},
    )

    rows = results(report)
    assert result.returncode == 1
    assert [row["nodeid"] for row in rows] == ["test_q.py::test_instavel"]
    assert rows[0]["outcome"] == "failed"


def test_teste_coletado_sem_resultado_e_registrado_como_missing(tmp_path):
    suite = (
        "def test_a_falha():\n    assert False\n\n\n"
        "def test_b():\n    pass\n\n\ndef test_c():\n    pass\n"
    )
    report = tmp_path / "report"
    pytest_run(tmp_path, "-x", "--ci-report-dir", str(report), files={"test_m.py": suite})
    filtered = tmp_path / "filtered"
    pytest_run(tmp_path, "-k", "test_b", "--ci-report-dir", str(filtered), files={"test_m.py": suite})

    outcomes = {row["nodeid"].split("::")[1]: row["outcome"] for row in results(report)}
    assert outcomes == {"test_a_falha": "failed", "test_b": "missing", "test_c": "missing"}
    assert by_name(report)["test_b"]["call"] is None
    assert [row["outcome"] for row in results(filtered)] == ["passed"]


def test_versao_diferente_de_pytest_ou_xdist_e_recusada_em_modo_distribuido(tmp_path):
    (tmp_path / "versoes_falsas.py").write_text(
        "import tools.ci.pytest_ci as plugin\n"
        "plugin.SUPPORTED = {'pytest': '0.0.1', 'pytest-xdist': '0.0.1'}\n",
        encoding="utf-8",
    )
    env = inner_env(tmp_path)
    report = tmp_path / "report"
    files = {"test_a.py": FILE_A}
    distribuido = pytest_run(
        tmp_path, "-p", "versoes_falsas", *_args(tmp_path, report), files=files, env=env
    )
    serial = pytest_run(
        tmp_path,
        "-p",
        "versoes_falsas",
        "--ci-report-dir",
        str(tmp_path / "serial"),
        files=files,
        env=env,
    )

    assert distribuido.returncode == 4
    assert "ci_versions_unsupported" in distribuido.stdout + distribuido.stderr
    assert serial.returncode == 0


def test_teardown_com_erro_apos_call_aprovado_e_error(tmp_path):
    suite = (
        "import pytest\n\n\n@pytest.fixture\ndef quebra():\n    yield\n"
        "    raise RuntimeError('teardown')\n\n\n"
        "def test_td(quebra):\n    assert True\n"
    )
    report = tmp_path / "report"
    result = pytest_run(
        tmp_path, *_args(tmp_path, report), files={"test_td.py": suite}
    )

    row = by_name(report)["test_td"]
    assert result.returncode == 1
    assert row["outcome"] == "error"
    assert row["call"]["outcome"] == "passed"
    assert row["teardown"]["outcome"] == "failed"


FILE_CRASH = """
import os


def test_antes():
    assert True


def test_crash():
    os._exit(1)


def test_depois():
    assert True
"""
FILE_CRASH_TEARDOWN = """
import os
import pytest


@pytest.fixture
def morre_no_fim():
    yield
    os._exit(1)


def test_crash_td(morre_no_fim):
    assert True
"""
FILE_XFAIL_SETUP = """
import pytest


@pytest.fixture
def xfail_no_setup():
    pytest.xfail("motivo")


def test_xf(xfail_no_setup):
    assert True
"""


def _crash_run(tmp_path, files, *paths):
    report = tmp_path / "report"
    pytest_run(tmp_path, *_args(tmp_path, report, *paths), files=files)
    return report


def test_crash_do_worker_apos_setup_nao_vira_passed(tmp_path):
    report = _crash_run(tmp_path, {"test_c.py": FILE_CRASH})

    outcomes = {row["nodeid"].split("::")[1]: row["outcome"] for row in results(report)}
    assert outcomes["test_crash"] == "failed"


def test_crash_em_arquivo_divisivel_nao_vira_passed(tmp_path):
    report = _crash_run(tmp_path, {"test_c.py": FILE_CRASH}, "test_c.py")

    outcomes = {row["nodeid"].split("::")[1]: row["outcome"] for row in results(report)}
    assert outcomes["test_crash"] == "failed"


def test_crash_no_teardown_nao_vira_passed(tmp_path):
    report = _crash_run(tmp_path, {"test_c.py": FILE_CRASH_TEARDOWN})

    assert by_name(report)["test_crash_td"]["outcome"] in {"failed", "missing"}


def test_xfail_imperativo_no_setup_vira_xfailed(tmp_path):
    report = tmp_path / "report"
    pytest_run(
        tmp_path, "--ci-report-dir", str(report), files={"test_x.py": FILE_XFAIL_SETUP}
    )

    assert by_name(report)["test_xf"]["outcome"] == "xfailed"


def _summary(text):
    last = [line for line in text.splitlines() if line.strip()][-1]
    return re.sub(r" in [0-9.]+s.*$", "", last)


def test_loadgroup_sem_workers_nao_altera_resultado(tmp_path):
    files = {"test_a.py": FILE_A}
    for name, extra in (
        ("sem_n", ("--dist", "loadgroup")),
        ("collect", ("-n", "2", "--collect-only")),
    ):
        com = pytest_run(
            tmp_path / name / "com",
            *extra,
            "--ci-report-dir",
            str(tmp_path / name / "r"),
            files=files,
        )
        sem = pytest_run(tmp_path / name / "sem", *extra, plugin=False, files=files)
        assert com.returncode == sem.returncode, (name, com.stdout)
        assert _summary(com.stdout) == _summary(sem.stdout), name


BROAD_CASES = {
    "setup_module": "def setup_module(module):\n    pass\n\n\ndef test_x():\n    pass\n",
    "setup_class": (
        "class TestC:\n    def setup_class(cls):\n        pass\n\n"
        "    def test_x(self):\n        pass\n"
    ),
    "fixture_de_classe": (
        "import pytest\n\n\n@pytest.fixture(scope='class')\ndef caro():\n    return 1\n\n\n"
        "def test_x(caro):\n    pass\n"
    ),
    "unittest_setupclass": (
        "import unittest\n\n\nclass T(unittest.TestCase):\n    @classmethod\n"
        "    def setUpClass(cls):\n        pass\n\n    def test_x(self):\n        pass\n"
    ),
    "override_de_funcao": (
        "import pytest\n\n\n@pytest.fixture\ndef sess(sess):\n    return sess\n\n\n"
        "def test_x(sess):\n    pass\n"
    ),
}
CONFTEST_SESSION = (
    "import pytest\n\n\n@pytest.fixture(scope='session')\ndef sess():\n    return 1\n"
)


def test_arquivo_divisivel_recusa_fixtures_amplas_de_todos_os_tipos(tmp_path):
    for name, suite in BROAD_CASES.items():
        case = tmp_path / name
        result = pytest_run(
            case,
            *_args(case, case / "report", "test_b.py"),
            files={"test_b.py": suite, "conftest.py": CONFTEST_SESSION},
        )
        assert result.returncode != 0, name
        assert "ci_splittable_broad_fixture" in result.stdout + result.stderr, name


def test_sem_saida_de_workers_marca_colecao_incompleta(tmp_path):
    report = tmp_path / "report"
    pytest_run(
        tmp_path,
        *_args(tmp_path, report, "test_broad.py"),
        files={"test_broad.py": FILE_BROAD},
    )

    collection = read(report, "collection.json")
    assert collection["workers_identical"] is False
    assert collection["count"] == 0


def test_falha_ao_gravar_relatorio_nao_altera_status(tmp_path):
    (tmp_path / "arquivo").write_text("x", encoding="utf-8")
    files = {"test_a.py": FILE_A}
    com = pytest_run(
        tmp_path / "com",
        "--ci-report-dir",
        str(tmp_path / "arquivo" / "sub"),
        files=files,
    )
    sem = pytest_run(tmp_path / "sem", plugin=False, files=files)

    assert com.returncode == sem.returncode == 0
    assert "ci_report_write_failed" in com.stderr
