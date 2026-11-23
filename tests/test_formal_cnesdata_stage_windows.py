"""StageWindows.tla constants and bounds tables against the admission rules in the code."""

import ast
import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CODE = Path(os.environ.get("CNESDATA_F4_CODE_ROOT", ROOT)) / "tools/cnesdata_delivery"
FORMAL = ROOT / "formal/cnesdata_delivery"
MODEL = (FORMAL / "StageWindows.tla").read_text(encoding="utf-8")
CONTRACT = (CODE / "lifecycle_contract.py").read_text(encoding="utf-8")
RUNTIME = (CODE / "lifecycle_runtime.py").read_text(encoding="utf-8")
CONFIGS = {name: (FORMAL / f"{name}.cfg").read_text(encoding="utf-8")
           for name in ("StageWindows", "StageWindowsE2", "StageWindowsOverrun", "StageWindowsCodeAudit",
                        "StageWindowsCodeFinal")}
MUTANTS = {
    "StageWindowsMutantPause": ("StageWindowsE2", "ReviewPause", "60", "InBoundsAccepts"),
    "StageWindowsMutantMargin": ("StageWindowsOverrun", "AdmitMargin", "0", "EffectsInsideStage"),
    "StageWindowsMutantEarly": ("StageWindowsE2", "AllowEarly", "TRUE", "EffectsInsideStage"),
    "StageWindowsMutantLate": ("StageWindowsOverrun", "CheckCompletion", "FALSE", "AcceptBeforeDeadline"),
    "StageWindowsMutantSpan": ("StageWindowsE2", "ModeCeiling", "300", "ModeSpan"),
}
STAGE_NAMES = ["phase-b", "api", "static", "unit", "phase-c-recovery", "phase-c-audit", "final"]
MODE_PHASE = {4: "unit", 5: "recovery", 6: "audit"}


def cfg_values(text):
    return dict(re.findall(r"^\s+(\w+) = (\S+)\s*$", text, re.M))


def model_tuple(name):
    body = re.search(rf"^{name} == <<([\d, ]+)>>", MODEL, re.M).group(1)
    return [int(item) for item in body.split(",")]


def model_modes(name):
    body = re.search(rf"^{name} == <<([^>]+)>>", MODEL, re.M).group(1)
    return re.findall(r'"([\w-]+)"', body)


def model_records(name):
    block = re.search(rf"^{name} == <<\n(.*?)\n>>", MODEL, re.M | re.S).group(1)
    return [{key: int(value) for key, value in re.findall(r"(\w+) \|-> (\d+)", line)}
            for line in block.splitlines()]


def underscored(names):
    return [name.replace("-", "_") for name in names]


def code_stages():
    tree = ast.parse(CONTRACT)
    node = next(item for item in tree.body if isinstance(item, ast.Assign)
                and getattr(item.targets[0], "id", "") == "STAGES")
    return ast.literal_eval(node.value)


def function_source(text, name):
    start = text.index(f"def {name}(")
    end = text.find("\ndef ", start + 1)
    return text[start:end if end > 0 else None]


def closed_phase_branch():
    capacity = function_source(CONTRACT, "phase_capacity")
    return capacity[capacity.index("duration, later = STAGES"):]


def code_modes():
    tree = ast.parse(CONTRACT)
    node = next(item for item in tree.body if isinstance(item, ast.Assign)
                and getattr(item.targets[0], "id", "") == "MODE_SESSION_OPERATIONS")
    table = ast.literal_eval(node.value)
    found = {}
    for operation, (_, _, context, phase) in table.items():
        if context == "promotion":
            found.setdefault(phase, []).append(operation)
    return found


def timeout_of(command):
    found = set()
    for node in ast.walk(ast.parse(RUNTIME)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "run" and node.args and isinstance(node.args[0], ast.List)):
            continue
        items = node.args[0].elts
        if (len(items) > 1 and isinstance(items[0], ast.Name) and items[0].id == "tofu"
                and isinstance(items[1], ast.Constant) and items[1].value == command):
            found |= {str(word.value.value) for word in node.keywords if word.arg == "timeout"}
    return found


def watchdog_floor():
    return set(re.findall(r"operation_seconds=max\((\d+), operation_seconds\)",
                          function_source(RUNTIME.replace("    def ", "def "), "check")))


def guard_checks():
    readbacks = function_source(RUNTIME, "readbacks")
    return set(re.findall(r"guard\.check\((\d+)\)", readbacks))


def readback_post_guards():
    source = function_source(RUNTIME, "readbacks")
    start = source.index("aws.call(spec")
    segment = source[start:source.index("reports.append", start)]
    return len(re.findall(r"guard\.check\(\)", segment))


def publish_guards_per_file():
    source = function_source(RUNTIME, "publish")
    loop = source[source.index("for name, raw in"):source.index("entries.append")]
    return len(re.findall(r"guard\.check\(20\)", loop))


def trailing_guards():
    source = function_source(RUNTIME, "execute")
    return len(re.findall(r"guard\.check\(\)\n\s+publish\(", source))


def published_files():
    source = function_source(RUNTIME, "execute")
    plan = re.search(r'result_files = \{"plan\.bin".*?"checkpoint\.json": [^}]*\}', source, re.S).group(0)
    audit = re.search(r'result_files = \{"approval\.json": [^}]*\}', source).group(0)
    deploy = re.search(r'result_files = \{"checkpoint\.json": c\.canonical\(checkpoint\), '
                       r'"approval\.json": [^}]*\}', source).group(0)
    return {name: len(re.findall(r'"[\w.]+": ', body)) for name, body in
            (("plan", plan), ("audit", audit), ("deploy", deploy))}


def deploy_ops(bounds, cfg):
    tofu = {"init": int(cfg["InitTimeout"]), "show": int(cfg["ShowTimeout"]),
            "plan": int(cfg["PlanTimeout"]), "apply": int(cfg["ApplyTimeout"])}
    floor, pub = int(cfg["ReadbackFloor"]), int(cfg["PubActual"])
    act = {"init": int(cfg["InitActual"]), "show": int(cfg["ShowActual"]),
           "apply": int(cfg["ApplyActual"]), "job": int(cfg["JobActual"])}
    job, init, show = ("job", floor, act["job"]), ("init", tofu["init"], act["init"]), (
        "show", tofu["show"], act["show"])
    files = published_files()

    def publish(count):
        return [("pub", floor, pub)] * (publish_guards_per_file() * count)

    tail = [("tail", floor, 0)] * trailing_guards()
    read = lambda key: [(key, max(floor, bounds[key]), bounds[key])] + (
        [(key + "_g", floor, 0)] * readback_post_guards())
    return ([job, init, ("plan", tofu["plan"], bounds["plan"]), show] + tail + publish(files["plan"])
            + [job, init, show] + tail + publish(files["audit"])
            + [job, init] + read("aread") + [show, ("apply", tofu["apply"], act["apply"])]
            + read("pread") + tail + publish(files["deploy"]))


def stage_ops(stage, bounds, cfg):
    floor = int(cfg["AdapterFloor"])
    ops = deploy_ops(bounds, cfg) if stage in (1, 5, 6) else []
    if stage in MODE_PHASE:
        names = underscored(code_modes()[MODE_PHASE[stage]])
    else:
        names = tail_names(stage) if stage != 1 else []
    return ops + [(name, max(floor, bounds[name]), bounds[name]) for name in names]


def tail_names(stage):
    return {2: ["api_effect", "api_observe"], 3: ["static_effect", "static_observe"],
            7: ["reopen", "terminal_readback"]}[stage]


def admissible(stage, durations, bounds, cfg):
    window, margin, now = durations[stage - 1], int(cfg["AdmitMargin"]), 0
    for _, declared, actual in stage_ops(stage, bounds, cfg):
        if now + declared + margin >= window:
            return False
        now += actual
    return True


def admissible_fixed(durations, fixed, margin_reserve=420):
    return all(sum(durations[:index]) + duration + sum(durations[index + 1:]) + margin_reserve <= fixed
               for index, duration in enumerate(durations))


def table(name, cfg_name):
    cfg = cfg_values(CONFIGS[cfg_name])
    durations = model_tuple(name + "Dur")
    records = model_records(name + "Var")
    return cfg, durations, records


def test_duracoes_e_reservas_do_codigo_igualam_a_tabela_de_estagios_do_modelo():
    stages = code_stages()
    assert list(stages) == STAGE_NAMES
    durations = model_tuple("CodeDur")
    assert durations == [duration for duration, _ in stages.values()]
    assert [later for _, later in stages.values()] == [sum(durations[index + 1:])
                                                       for index in range(len(durations))]


def test_janela_fixa_e_reserva_final_do_modelo_igualam_o_codigo():
    capacity = function_source(CONTRACT, "phase_capacity")
    assert set(re.findall(r"min\(close \+ (\d+), window\[\"input_deadline\"\]\)", capacity)) == {
        cfg_values(CONFIGS["StageWindows"])["FixedWindow"]}
    branch = closed_phase_branch()
    assert re.findall(r"fixed - now >= max\(0, deadline - now\) \+ later \+ (\d+)", branch) == [
        str(re.search(r"^FinalReserve == (\d+)", MODEL, re.M).group(1))]


def test_margem_da_fase_fechada_liga_a_linha_propria_com_operador_e_termo():
    branch = closed_phase_branch()
    found = re.findall(r"now \+ operation_seconds \+ (\d+) (<=?) deadline", branch)
    assert found == [(cfg_values(CONFIGS["StageWindows"])["AdmitMargin"], "<")]
    assert "start + Declared(s, op) + AdmitMargin < Deadline(s)" in MODEL


def test_margem_do_ramo_de_recuperacao_tambem_e_ligada():
    capacity = function_source(CONTRACT, "phase_capacity")
    recovery = capacity[:capacity.index("duration, later = STAGES")]
    found = re.findall(r"now \+ operation_seconds \+ (\d+) (<=?) window\[\"deadline\"\]", recovery)
    assert found == [(cfg_values(CONFIGS["StageWindows"])["AdmitMargin"], "<")]


def test_guardas_pos_chamada_e_de_publicacao_do_codigo_estao_no_modelo():
    cfg = cfg_values(CONFIGS["StageWindows"])
    assert readback_post_guards() == int(cfg["ReadbackPostGuards"]) == 1
    assert publish_guards_per_file() == int(cfg["PublishGuardsPerFile"]) == 2
    assert trailing_guards() == int(cfg["TrailingGuards"]) == 1
    files = published_files()
    assert (files["plan"], files["audit"], files["deploy"]) == (
        int(cfg["PlanFiles"]), int(cfg["AuditFiles"]), int(cfg["DeployFiles"]))


def test_piso_do_watchdog_e_reserva_das_leituras_do_codigo_estao_no_modelo():
    cfg = cfg_values(CONFIGS["StageWindows"])
    assert watchdog_floor() == {cfg["ReadbackFloor"]}
    assert guard_checks() == {cfg["ReadbackFloor"]}


@pytest.mark.parametrize("command,key", [("init", "InitTimeout"), ("show", "ShowTimeout"),
                                         ("plan", "PlanTimeout"), ("apply", "ApplyTimeout")])
def test_timeout_de_cada_comando_tofu_do_modelo_iguala_o_runtime(command, key):
    cfg = cfg_values(CONFIGS["StageWindows"])
    assert timeout_of(command) == {cfg[key]}, command


def test_operacoes_de_modo_do_modelo_igualam_a_tabela_do_contrato():
    found = code_modes()
    assert model_modes("UnitModeOps") == underscored(found["unit"])
    assert model_modes("RecoveryModeOps") == underscored(found["recovery"])
    assert model_modes("AuditModeOps") == underscored(found["audit"])


@pytest.mark.parametrize("name,cfg_name", [("Code", "StageWindows"), ("E2", "StageWindowsE2")])
def test_limites_do_modelo_sao_admissiveis_e_maximais_pelas_reservas_do_codigo(name, cfg_name):
    cfg, durations, records = table(name, cfg_name)
    assert len(records) == 7
    assert admissible_fixed(durations, int(cfg["FixedWindow"]))
    infeasible = {int(item) for item in re.findall(r"\d+", cfg["InfeasibleStages"])}
    for stage, bounds in enumerate(records, start=1):
        if stage in infeasible:
            assert set(bounds.values()) == {1}, (name, stage)
            assert not admissible(stage, durations, bounds, cfg), (name, stage)
            continue
        assert admissible(stage, durations, bounds, cfg), (name, stage)
        for key in bounds:
            raised = dict(bounds) | {key: bounds[key] + 1}
            assert not admissible(stage, durations, raised, cfg), (name, stage, key)
    assert infeasible == ({5, 6} if name == "Code" else set())


def test_estouro_difere_do_e2_so_no_excesso_de_duracao():
    e2, overrun = cfg_values(CONFIGS["StageWindowsE2"]), cfg_values(CONFIGS["StageWindowsOverrun"])
    assert {key for key in e2 if e2[key] != overrun[key]} == {"Over"}


def test_configuracoes_de_cauda_do_codigo_comecam_em_c_audit_e_no_final():
    audit, final = cfg_values(CONFIGS["StageWindowsCodeAudit"]), cfg_values(CONFIGS["StageWindowsCodeFinal"])
    main = cfg_values(CONFIGS["StageWindows"])
    for tail, first, infeasible in ((audit, "6", "{6}"), (final, "7", "{}")):
        assert {key for key in main if main[key] != tail[key]} == {"FirstStage", "InfeasibleStages"}
        assert (tail["FirstStage"], tail["InfeasibleStages"]) == (first, infeasible)


def test_configuracao_e2_usa_as_janelas_governadas_e_prazo_fixo_da_soma_mais_reserva():
    cfg = cfg_values(CONFIGS["StageWindowsE2"])
    durations = model_tuple("E2Dur")
    assert durations == [360, 180, 180, 180, 330, 330, 90]
    assert int(cfg["FixedWindow"]) == sum(durations) + 420


def test_configuracao_principal_usa_o_codigo_atual_e_sem_pausa_antecipacao_ou_estouro():
    values = cfg_values(CONFIGS["StageWindows"])
    assert (values["Over"], values["ReviewPause"], values["AllowEarly"], values["CheckCompletion"]) == (
        "0", "0", "FALSE", "TRUE")
    assert (values["FirstStage"], values["AdapterFloor"]) == ("1", "0")
    assert "AcceptBeforeDeadline" in CONFIGS["StageWindows"]
    assert "AcceptBeforeDeadline" in CONFIGS["StageWindowsE2"]
    assert "AcceptBeforeDeadline" in CONFIGS["StageWindowsOverrun"]
    assert "ModeSpan" in CONFIGS["StageWindows"]
    assert re.search(r"^InfeasibleStages$|InfeasibleStages = \{5,6\}", CONFIGS["StageWindows"], re.M)


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_mutante_difere_em_uma_constante_e_espera_a_violacao_nomeada(name):
    base, constant, value, invariant = MUTANTS[name]
    text = (FORMAL / f"{name}.cfg").read_text(encoding="utf-8")
    main, mutant = cfg_values(CONFIGS[base]), cfg_values(text)
    differing = {key for key in main if main[key] != mutant.get(key)}
    assert differing == {constant}
    assert mutant[constant] == value
    assert f"\\* expect invariant:{invariant}" in text
    assert re.search(rf"^INVARIANT {invariant}$", text, re.M)
