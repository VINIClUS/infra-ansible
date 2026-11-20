"""Conformidade entre o modelo TLA+ KeeperStages e a tabela de estagios do keeper (#55, F2)."""
import re
from pathlib import Path

import pytest

from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import lifecycle_contract as lc

ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "formal" / "cnesdata_delivery"
MODEL = FORMAL / "KeeperStages.tla"
EXPECT = re.compile(r"^\\\* expect (\S+)$", re.M)
MUTANTS = {
    "KeeperStagesMutantNoApiTrigger": ("NoApiTriggerRows", ["deadlock"]),
    "KeeperStagesMutantInternalHostTrigger": ("InternalHostTriggerRows", ["invariant:DeclaredTrigger"]),
}
ROW =re.compile(r'^ {4}<<"([a-z-]+)", "([a-z-]+)", "(external|internal)", "([a-z-]+)">>,?$')
TERMINAL_ROW = re.compile(r'^ {4}<<"([a-z-]+)", "([a-z-]+)">>,?$')
STAGE_ROW = re.compile(r'^ {4}"([a-z-]+)",?$')
EXPECTED_DIFFERENCE = {
    ("api", "host", "external", "static"),
    ("static", "publish-static", "internal", "unit"),
    ("unit", "unit", "internal", "phase-c-recovery"),
    ("phase-c-recovery", "phase-c-recovery", "external", "phase-c-audit"),
    ("phase-c-audit", "phase-c-audit", "external", "final"),
}
TERMINAL_EXIT = ("final", "terminal-readback", "internal", "terminal")


def _model():
    assert MODEL.is_file(), f"modelo ausente path={MODEL.relative_to(ROOT)}"
    return MODEL.read_text(encoding="utf-8")


def _block(name, pattern):
    lines = _model().splitlines()
    start = lines.index(f"{name} == <<")
    end = lines.index(">>", start)
    body = lines[start + 1:end]
    rows = [pattern.match(line) for line in body]
    assert body and all(rows), f"linha fora do formato bloco={name}"
    return [row.groups() for row in rows]


def _triggers():
    rows = _block("ModelTriggerRows", ROW)
    assert len({row[0] for row in rows}) == len(rows), "estagio com mais de um gatilho no modelo"
    return set(rows)


def _code_triggers():
    assert all(type(value) is tuple and len(value) == 2 for value in lc.STAGE_TRIGGERS.values())
    return {(stage, event, target) for stage, (event, target) in lc.STAGE_TRIGGERS.items()}


def _between_code_stages(rows):
    stages = {"application-prepare", *lc.STAGES}
    return {row for row in rows if row[0] in stages and row[3] in stages}


def _cfg(name):
    return (FORMAL / f"{name}.cfg").read_text(encoding="utf-8")


def test_cfg_do_modelo_verifica_a_tabela_conferida_aqui():
    _model()
    assert "CONSTANT TriggerRows <- ModelTriggerRows" in _cfg("KeeperStages").splitlines()
    assert EXPECT.findall(_cfg("KeeperStages")) == []


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_mutante_declara_a_violacao_esperada(name):
    assert EXPECT.findall(_cfg(name)) == MUTANTS[name][1]


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_mutante_estende_o_modelo_e_so_troca_a_tabela_de_gatilhos(name):
    module = (FORMAL / f"{name}.tla").read_text(encoding="utf-8")
    assert re.search(rf"^-+ MODULE {name} -+$", module, re.M)
    assert re.search(r"^EXTENDS KeeperStages$", module, re.M)
    base = _cfg("KeeperStages").replace("<- ModelTriggerRows", f"<- {MUTANTS[name][0]}")
    assert [line for line in _cfg(name).splitlines() if not EXPECT.match(line)] == base.splitlines()


def test_conjunto_de_mutantes_do_keeper_e_fechado():
    assert {path.stem for path in FORMAL.glob("KeeperStages*.tla")} == {"KeeperStages", *MUTANTS}


def test_ordem_dos_estagios_do_modelo_e_a_do_contrato():
    assert [row[0] for row in _block("StageOrder", STAGE_ROW)] == ["application-prepare", *lc.STAGES]


def test_cada_estagio_do_contrato_tem_exatamente_um_gatilho_no_modelo():
    assert sorted(row[0] for row in _triggers()) == sorted(["application-prepare", *lc.STAGES])


def test_gatilhos_do_codigo_estao_no_modelo_como_externos():
    model = {(row[0], row[1], row[3]): row[2] for row in _triggers()}
    assert _code_triggers() <= set(model)
    assert {model[key] for key in _code_triggers()} == {"external"}


def test_gatilhos_que_o_codigo_ainda_nao_tem_sao_exatamente_a_lista_esperada():
    code = _code_triggers()
    missing = {row for row in _between_code_stages(_triggers()) if (row[0], row[1], row[3]) not in code}
    assert missing == EXPECTED_DIFFERENCE


def test_unica_saida_para_fora_dos_estagios_do_codigo_e_o_terminal_interno_do_final():
    rows = _triggers()
    assert rows - _between_code_stages(rows) == {TERMINAL_EXIT}


def _window(stage):
    return {"stage": stage, "close": None if stage == "application-prepare" else 1,
            "decision": {"choice_at": 1} if stage == "recovery" else None}


def test_terminal_do_modelo_sai_do_estagio_que_o_codigo_exige():
    rows = _block("TerminalRows", TERMINAL_ROW)
    assert {kind for kind, _ in rows} == {"accepted-open", "failed-closed-quiescent", "failed-prepare-quiescent"}
    stages = {stage for _, stage in rows}
    for kind, stage in rows:
        assert ag._terminal_required(kind, _window(stage))
        for other in stages - {stage}:
            with pytest.raises(ValueError):
                ag._terminal_required(kind, _window(other))
