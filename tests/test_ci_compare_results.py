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
    assert "ids_ausentes dir=dois nodeid=t.py::c" in capsys.readouterr().out


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
    assert "missing dir=um nodeid=t.py::c" in capsys.readouterr().out


def test_falha_quando_difere_da_verdade_de_coleta(tmp_path, capsys):
    first = _report(tmp_path, "um", BASE_ROWS)
    second = _report(tmp_path, "dois", BASE_ROWS)
    truth = tmp_path / "truth.txt"
    truth.write_text("t.py::a\nt.py::b\nt.py::z\n", encoding="utf-8")

    assert main([first, second, "--ground-truth", str(truth)]) == 1
    out = capsys.readouterr().out
    assert "fora_da_verdade dir=um nodeid=t.py::c" in out
    assert "ausente_da_verdade dir=um nodeid=t.py::z" in out
