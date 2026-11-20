import json
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
