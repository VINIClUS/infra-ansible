import json

from tools.ci.compare_results import main


def _report(base, name, rows):
    directory = base / name
    directory.mkdir()
    lines = [
        {"nodeid": nodeid, "outcome": outcome, "skip_reason": reason}
        for nodeid, outcome, reason in rows
    ]
    (directory / "results.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8"
    )
    (directory / "collection.json").write_text(
        json.dumps({"ids": [row[0] for row in rows], "count": len(rows)}), encoding="utf-8"
    )
    return str(directory)


BASE_ROWS = [
    ("t.py::a", "passed", None),
    ("t.py::b", "skipped", "motivo"),
    ("t.py::c", "failed", None),
]


def test_compara_relatorios_iguais_com_sucesso(tmp_path, capsys):
    first = _report(tmp_path, "um", BASE_ROWS)
    second = _report(tmp_path, "dois", list(reversed(BASE_ROWS)))
    truth = tmp_path / "truth.txt"
    truth.write_text("t.py::c\nt.py::a\nt.py::b\n", encoding="utf-8")

    code = main([first, second, "--ground-truth", str(truth)])

    assert code == 0
    assert "ids=3 dirs=2" in capsys.readouterr().out


def test_falha_com_id_ausente_em_um_relatorio(tmp_path, capsys):
    first = _report(tmp_path, "um", BASE_ROWS)
    second = _report(tmp_path, "dois", BASE_ROWS[:2])

    assert main([first, second]) == 1
    assert f"ids_ausentes dir={second} nodeid=t.py::c" in capsys.readouterr().out


def test_falha_com_resultado_diferente(tmp_path, capsys):
    changed = [BASE_ROWS[0], BASE_ROWS[1], ("t.py::c", "passed", None)]
    first = _report(tmp_path, "um", BASE_ROWS)
    second = _report(tmp_path, "dois", changed)

    assert main([first, second]) == 1
    assert "outcome_diferente nodeid=t.py::c" in capsys.readouterr().out


def test_falha_com_motivo_de_skip_diferente(tmp_path, capsys):
    changed = [BASE_ROWS[0], ("t.py::b", "skipped", "outro"), BASE_ROWS[2]]
    first = _report(tmp_path, "um", BASE_ROWS)
    second = _report(tmp_path, "dois", changed)

    assert main([first, second]) == 1
    assert "skip_reason_diferente nodeid=t.py::b" in capsys.readouterr().out


def test_falha_com_resultado_missing(tmp_path, capsys):
    missing = [BASE_ROWS[0], BASE_ROWS[1], ("t.py::c", "missing", None)]
    first = _report(tmp_path, "um", missing)
    second = _report(tmp_path, "dois", missing)

    assert main([first, second]) == 1
    assert f"missing dir={first} nodeid=t.py::c" in capsys.readouterr().out


def test_falha_quando_difere_da_verdade_de_coleta(tmp_path, capsys):
    first = _report(tmp_path, "um", BASE_ROWS)
    second = _report(tmp_path, "dois", BASE_ROWS)
    truth = tmp_path / "truth.txt"
    truth.write_text("t.py::a\nt.py::b\nt.py::z\n", encoding="utf-8")

    assert main([first, second, "--ground-truth", str(truth)]) == 1
    out = capsys.readouterr().out
    assert f"fora_da_verdade dir={first} nodeid=t.py::c" in out
    assert f"ausente_da_verdade dir={first} nodeid=t.py::z" in out


def _report_at(directory, rows):
    directory.mkdir(parents=True)
    lines = [
        {"nodeid": nodeid, "outcome": outcome, "skip_reason": reason}
        for nodeid, outcome, reason in rows
    ]
    (directory / "results.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8"
    )
    return str(directory)


def test_diretorios_com_mesmo_nome_sao_comparados_separadamente(tmp_path, capsys):
    changed = [BASE_ROWS[0], BASE_ROWS[1], ("t.py::c", "passed", None)]
    first = _report_at(tmp_path / "um" / "lane", BASE_ROWS)
    second = _report_at(tmp_path / "dois" / "lane", changed)

    assert main([first, second]) == 1
    out = capsys.readouterr().out
    assert "outcome_diferente nodeid=t.py::c" in out


def test_rotulo_dir_usa_o_caminho_informado(tmp_path, capsys):
    first = _report_at(tmp_path / "um" / "lane", BASE_ROWS)
    second = _report_at(tmp_path / "dois" / "lane", BASE_ROWS[:2])

    assert main([first, second]) == 1
    assert f"ids_ausentes dir={second} nodeid=t.py::c" in capsys.readouterr().out


def test_diretorio_repetido_e_recusado(tmp_path, capsys):
    only = _report_at(tmp_path / "um" / "lane", BASE_ROWS)

    assert main([only, only]) == 1
    assert f"diretorio_repetido dir={only}" in capsys.readouterr().out


def test_nodeid_duplicado_no_relatorio_falha(tmp_path, capsys):
    duplicated = BASE_ROWS + [("t.py::a", "passed", None)]
    first = _report_at(tmp_path / "um" / "lane", duplicated)
    second = _report_at(tmp_path / "dois" / "lane", BASE_ROWS)

    assert main([first, second]) == 1
    assert f"nodeid_duplicado dir={first} nodeid=t.py::a" in capsys.readouterr().out


def test_sucesso_conta_os_diretorios_distintos(tmp_path, capsys):
    first = _report_at(tmp_path / "um" / "lane", BASE_ROWS)
    second = _report_at(tmp_path / "dois" / "lane", BASE_ROWS)

    assert main([first, second]) == 0
    assert "ids=3 dirs=2" in capsys.readouterr().out


def test_falha_com_relatorio_vazio(tmp_path, capsys):
    first = _report_at(tmp_path / "um" / "lane", [])
    second = _report_at(tmp_path / "dois" / "lane", [])

    assert main([first, second]) == 1
    assert f"relatorio_vazio dir={first}" in capsys.readouterr().out


def test_diretorio_equivalente_por_caminho_resolvido_e_recusado(tmp_path, capsys):
    only = _report_at(tmp_path / "e1", BASE_ROWS)
    alias = f"{tmp_path}/./e1/../e1"

    assert main([only, alias]) == 1
    assert f"diretorio_repetido dir={alias}" in capsys.readouterr().out
