"""LeaseTerminal.tla names and shape against the application gate code tables."""

import ast
import re
from pathlib import Path

import pytest

from tools.cnesdata_delivery import lifecycle_contract as lc

ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "formal/cnesdata_delivery"
MODEL = FORMAL / "LeaseTerminal.tla"
DELIVERY = ROOT / "tools/cnesdata_delivery"
TERMINAL_KIND = re.compile(r"(accepted|failed)(-[a-z]+)+")

# P17 owes these names to the code; it must empty this list in the same PR.
EXPECTED_MODEL_ONLY = {
    "TerminalKinds": set(),
    "FailedKinds": set(),
    "PromotionResults": set(),
    "AdmittedResults": set(),
    "LeaseStatuses": set(),
    "LeaseOutcomes": {"recovery_required", "reviewed_recovery"},
}
REQUIRED_CHECKS = {
    "INVARIANT": {"TypeOK", "MutualExclusion", "ExecuteNeedsLease", "FailedNeverAccepted",
                  "RefuseFailedUntilReview", "HolderCanMove"},
    "PROPERTY": {"AcquireEnds", "FailedStaysFailed"},
}
MUTANTS = {
    "LeaseTerminalMutantB7": {"INVARIANT": {"HolderCanMove"}, "PROPERTY": {"AcquireEnds"}},
    "LeaseTerminalMutantO22": {"INVARIANT": {"RefuseFailedUntilReview"}, "PROPERTY": set()},
    "LeaseTerminalMutantReachability": {"INVARIANT": {"NoFullStory"}, "PROPERTY": set()},
}
EXPECTED_VIOLATIONS = {
    "LeaseTerminalMutantB7": ["invariant:HolderCanMove"],
    "LeaseTerminalMutantO22": ["invariant:RefuseFailedUntilReview"],
    "LeaseTerminalMutantReachability": ["invariant:NoFullStory"],
}


def model_sets():
    found = {}
    for name, body in re.findall(r"^(\w+) == \{([^{}]*)\}[ \t]*$", MODEL.read_text(encoding="utf-8"), re.M):
        items = [item.strip() for item in body.split(",")] if body.strip() else []
        if all(re.fullmatch(r'"[^"]*"', item) for item in items):
            found[name] = {item[1:-1] for item in items}
    return found


def tree(name):
    return ast.parse((DELIVERY / name).read_text(encoding="utf-8"))


def function(module, name):
    return next(node for node in ast.walk(module) if isinstance(node, ast.FunctionDef) and node.name == name)


def strings(nodes):
    return {node.value for node in nodes if isinstance(node, ast.Constant) and isinstance(node.value, str)}


def keyed(node, key):
    if isinstance(node, ast.Subscript):
        return isinstance(node.slice, ast.Constant) and node.slice.value == key
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
            and bool(node.args) and isinstance(node.args[0], ast.Constant) and node.args[0].value == key)


def compared_with(scope, key):
    found = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.Compare) and any(keyed(side, key) for side in [node.left, *node.comparators]):
            found |= strings(side for side in [node.left, *node.comparators])
        if isinstance(node, ast.Dict):
            found |= strings(value for item, value in zip(node.keys, node.values)
                             if isinstance(item, ast.Constant) and item.value == key)
    return found


def code_terminal_kinds():
    found = set()
    for name in ("application_gate.py", "lifecycle_contract.py"):
        found |= {value for value in strings(ast.walk(tree(name))) if TERMINAL_KIND.fullmatch(value)}
    return found


def code_failed_kinds():
    result = function(tree("lifecycle_contract.py"), "terminal_result")
    sets = [side for node in ast.walk(result) if isinstance(node, ast.Compare) and keyed(node.left, "kind")
            and isinstance(node.ops[0], ast.In) for side in node.comparators if isinstance(side, ast.Set)]
    return set().union(*(strings(node.elts) for node in sets))


def code_promotion_results():
    result = function(tree("lifecycle_contract.py"), "terminal_result")
    return strings(node.value for node in ast.walk(result) if isinstance(node, ast.Return))


def code_admitted_results():
    return compared_with(function(tree("application_gate.py"), "previous_terminal"), "promotion_status")


def code_lease_statuses():
    lease = next(node for node in ast.walk(tree("coordination_lease.py"))
                 if isinstance(node, ast.ClassDef) and node.name == "Lease")
    return compared_with(lease, "status")


def code_lease_outcomes():
    return compared_with(tree("application_gate.py"), "coordination_status")


CODE_TABLES = {
    "TerminalKinds": code_terminal_kinds,
    "FailedKinds": code_failed_kinds,
    "PromotionResults": code_promotion_results,
    "AdmittedResults": code_admitted_results,
    "LeaseStatuses": code_lease_statuses,
    "LeaseOutcomes": code_lease_outcomes,
}


@pytest.mark.parametrize("name", sorted(CODE_TABLES))
def test_nome_do_modelo_iguala_a_tabela_do_codigo_salvo_a_divida_declarada_do_p17(name):
    model, code = model_sets()[name], CODE_TABLES[name]()
    assert code, name
    assert model - code == EXPECTED_MODEL_ONLY[name]
    assert code - model == set()


def test_divida_do_p17_e_exatamente_os_desfechos_de_recuperacao_revisada():
    assert {name: names for name, names in EXPECTED_MODEL_ONLY.items() if names} == {
        "LeaseOutcomes": {"recovery_required", "reviewed_recovery"}}
    assert set(EXPECTED_MODEL_ONLY) == set(CODE_TABLES)


def test_tabela_do_codigo_tem_os_nomes_atuais_do_gate():
    assert code_terminal_kinds() == {"accepted-open", "failed-closed-quiescent", "failed-prepare-quiescent"}
    assert code_lease_statuses() == {"held", "released"}
    assert code_lease_outcomes() == {"quiescent-released"}
    assert code_admitted_results() == {"accepted"}


def terminal(kind):
    value = {"kind": kind, "fence": "OPEN" if kind == "accepted-open" else "CLOSED",
             "accepted_modes": ["unit", "recovery", "audit"] if kind == "accepted-open" else [],
             "routes_match": True, "state_clean": True, "quiescent": True, "pending": [], "unknown": [],
             "observed_at": 100}
    if kind != "accepted-open":
        value["restoration"] = {"unit": True, "recovery": True, "audit": True, "api": True, "static": True,
                                "first_static_absent": False}
    return value


def test_resultado_de_cada_terminal_do_modelo_e_o_do_codigo():
    sets = model_sets()
    for kind in sets["TerminalKinds"]:
        expected = "failed" if kind in sets["FailedKinds"] else "accepted"
        assert lc.terminal_result(terminal(kind), now=110, deadline=200) == expected
    with pytest.raises(Exception):
        lc.terminal_result(terminal("accepted-open") | {"kind": "accepted-closed"}, now=110, deadline=200)


def cfg_names(path):
    found = {"INVARIANT": set(), "PROPERTY": set()}
    section = None
    text = path.read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("\\*"))
    for token in body.split():
        if token in ("INVARIANT", "INVARIANTS", "PROPERTY", "PROPERTIES"):
            section = "INVARIANT" if token.startswith("INVARIANT") else "PROPERTY"
        elif token.isupper():
            section = None
        elif section:
            found[section].add(token)
    return found


def test_cfg_do_modelo_verifica_todas_as_propriedades_exigidas():
    assert cfg_names(FORMAL / "LeaseTerminal.cfg") == REQUIRED_CHECKS


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_mutante_obrigatorio_estende_o_modelo_e_mira_so_a_sua_propriedade(name):
    module = (FORMAL / f"{name}.tla").read_text(encoding="utf-8")
    assert re.search(rf"^-+ MODULE {name} -+$", module, re.M)
    assert re.search(r"^EXTENDS LeaseTerminal$", module, re.M)
    assert cfg_names(FORMAL / f"{name}.cfg") == MUTANTS[name]


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_mutante_obrigatorio_declara_a_violacao_esperada(name):
    text = (FORMAL / f"{name}.cfg").read_text(encoding="utf-8")
    assert re.findall(r"^\\\* expect (\S+)$", text, re.M) == EXPECTED_VIOLATIONS[name]


def test_conjunto_de_mutantes_do_lease_e_fechado():
    assert {path.stem for path in FORMAL.glob("LeaseTerminal*.tla")} == {"LeaseTerminal", *MUTANTS}
