"""Conformidade entre o modelo TLA+ KeeperStages e a tabela de estagios do keeper (#55, F2)."""
import ast
import re
from pathlib import Path

import pytest

from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import lifecycle_contract as lc

ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "formal" / "cnesdata_delivery"
MODEL = FORMAL / "KeeperStages.tla"
EXPECT = re.compile(r"^\\\* expect (\S+)$", re.M)
WITNESS = "KeeperStagesMutantReachability"
MUTANTS = {
    "KeeperStagesMutantNoApiTrigger": ["deadlock"],
    "KeeperStagesMutantInternalHostTrigger": ["invariant:DeclaredTrigger"],
    "KeeperStagesMutantLeaveUnsettled": ["invariant:ExitWithOpsSettled"],
    "KeeperStagesMutantFinishUnsettled": ["invariant:ExitWithOpsSettled"],
    WITNESS: ["invariant:NoAccepted"],
}
CFG_SWAPS = {
    "KeeperStagesMutantNoApiTrigger": ("<- ModelTriggerRows", "<- NoApiTriggerRows"),
    "KeeperStagesMutantInternalHostTrigger": ("<- ModelTriggerRows", "<- InternalHostTriggerRows"),
    "KeeperStagesMutantLeaveUnsettled": ("SPECIFICATION Spec", "SPECIFICATION MutantSpec"),
    "KeeperStagesMutantFinishUnsettled": ("SPECIFICATION Spec", "SPECIFICATION MutantSpec"),
}
MUTANT_BODIES = {
    "KeeperStagesMutantLeaveUnsettled": ["MutantSpec == Init /\\ [][Next \\/ Leave]_vars /\\ Fairness"],
    "KeeperStagesMutantFinishUnsettled": [
        "MutantSpec == Init /\\ [][Next \\/ \\E kind \\in FailedKinds : Close(kind)]_vars /\\ Fairness"],
    WITNESS: ['NoAccepted == terminal /= "accepted-open"'],
}
WITNESS_CFG = ["\\* expect invariant:NoAccepted", "CONSTANT TriggerRows <- ModelTriggerRows",
               "SPECIFICATION Spec", "INVARIANT NoAccepted"]
GUARDED_EXITS = ["Advance == Leave /\\ OpsSettled(Ops(stage))",
                 "Finish(kind) == Close(kind) /\\ OpsSettled(FailureOps)"]
ROW = re.compile(r'^ {4}<<"([a-z-]+)", "([a-z-]+)", "(external|internal)", "([a-z-]+)">>,?$')
TERMINAL_ROW = re.compile(r'^ {4}<<"([a-z-]+)", "([a-z-]+)">>,?$')
STAGE_ROW = re.compile(r'^ {4}"([a-z-]+)",?$')
EXPECTED_DIFFERENCE = {
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


def _module(name):
    return (FORMAL / f"{name}.tla").read_text(encoding="utf-8").splitlines()


def test_cfg_do_modelo_verifica_a_tabela_conferida_aqui():
    _model()
    assert "CONSTANT TriggerRows <- ModelTriggerRows" in _cfg("KeeperStages").splitlines()
    assert EXPECT.findall(_cfg("KeeperStages")) == []


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_mutante_declara_a_violacao_esperada(name):
    assert EXPECT.findall(_cfg(name)) == MUTANTS[name]


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_mutante_e_um_modulo_que_estende_o_modelo(name):
    lines = _module(name)
    assert re.fullmatch(rf"-+ MODULE {name} -+", lines[0])
    assert lines[1] == "EXTENDS KeeperStages"
    assert re.fullmatch(r"=+", lines[-1])


@pytest.mark.parametrize("name", sorted(CFG_SWAPS))
def test_cfg_do_mutante_e_o_do_modelo_com_uma_unica_troca(name):
    old, new = CFG_SWAPS[name]
    base = _cfg("KeeperStages")
    assert base.count(old) == 1
    assert [line for line in _cfg(name).splitlines() if not EXPECT.match(line)] == base.replace(old, new).splitlines()


@pytest.mark.parametrize("name", sorted(MUTANT_BODIES))
def test_mutante_define_so_a_troca_declarada(name):
    assert [line for line in _module(name)[2:-1] if line.strip()] == MUTANT_BODIES[name]


def test_testemunha_do_aceite_le_a_tabela_do_modelo_e_so_nega_o_aceite():
    assert _cfg(WITNESS).splitlines() == WITNESS_CFG


def test_avanco_e_fechamento_sao_o_nucleo_mais_a_guarda_de_operacoes_liquidadas():
    lines = _model().splitlines()
    assert [line for line in GUARDED_EXITS if line in lines] == GUARDED_EXITS


def test_conjunto_de_mutantes_do_keeper_e_fechado():
    assert {path.stem for path in FORMAL.glob("KeeperStages*.tla")} == {"KeeperStages", *MUTANTS}
    assert {*CFG_SWAPS, WITNESS} == set(MUTANTS)


def test_ordem_dos_estagios_do_modelo_e_a_do_contrato():
    assert [row[0] for row in _block("StageOrder", STAGE_ROW)] == ["application-prepare", *lc.STAGES]


def test_cada_estagio_do_contrato_tem_exatamente_um_gatilho_no_modelo():
    assert sorted(row[0] for row in _triggers()) == sorted(["application-prepare", *lc.STAGES])


def test_gatilhos_do_codigo_estao_no_modelo_com_a_classificacao_do_keeper():
    """Externo sse o loop do keeper despacha o evento (KEEPER_EVENTS); interno sse o handler anterior avanca sozinho (DD-3)."""
    model = {(row[0], row[1], row[3]): row[2] for row in _triggers()}
    assert _code_triggers() <= set(model)
    assert {key: model[key] for key in _code_triggers()} == {
        key: "external" if key[1] in ag.KEEPER_EVENTS else "internal" for key in _code_triggers()}
    assert {model[key] for key in _code_triggers()} == {"external", "internal"}


def test_gatilhos_que_o_codigo_ainda_nao_tem_sao_exatamente_a_lista_esperada():
    code = _code_triggers()
    missing = {row for row in _between_code_stages(_triggers()) if (row[0], row[1], row[3]) not in code}
    assert missing == EXPECTED_DIFFERENCE


def test_unica_saida_para_fora_dos_estagios_do_codigo_e_o_terminal_interno_do_final():
    rows = _triggers()
    assert rows - _between_code_stages(rows) == {TERMINAL_EXIT}


def _is_kind(node):
    if isinstance(node, ast.Name):
        return node.id == "kind"
    if isinstance(node, ast.Subscript):
        return isinstance(node.slice, ast.Constant) and node.slice.value == "kind"
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
            and bool(node.args) and isinstance(node.args[0], ast.Constant) and node.args[0].value == "kind")


def _literals(node):
    items = node.elts if isinstance(node, (ast.Set, ast.Tuple, ast.List)) else [node]
    return {item.value for item in items if isinstance(item, ast.Constant) and isinstance(item.value, str)}


def _kinds_compared_in(module, function):
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    scope = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == function)
    found = set()
    for node in ast.walk(scope):
        sides = [node.left, *node.comparators] if isinstance(node, ast.Compare) else []
        if any(_is_kind(side) for side in sides):
            found |= set().union(*map(_literals, sides))
    return found


def test_tipos_terminais_do_modelo_sao_os_que_o_codigo_distingue():
    kinds = {kind for kind, _ in _block("TerminalRows", TERMINAL_ROW)}
    assert _kinds_compared_in(ag, "_terminal_required") == kinds
    assert _kinds_compared_in(lc, "terminal_result") == kinds


def _window(stage):
    return {"stage": stage, "close": None if stage == "application-prepare" else 1,
            "decision": {"choice_at": 1} if stage == "recovery" else None}


def test_terminal_do_modelo_sai_do_estagio_que_o_codigo_exige():
    rows = _block("TerminalRows", TERMINAL_ROW)
    stages = {stage for _, stage in rows}
    for kind, stage in rows:
        assert ag._terminal_required(kind, _window(stage))
        for other in stages - {stage}:
            with pytest.raises(ValueError):
                ag._terminal_required(kind, _window(other))
