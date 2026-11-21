"""StageWindows.tla constants against the stage table and admission rule in the code."""

import re
from pathlib import Path

import pytest

from tools.cnesdata_delivery import lifecycle_contract as lc

ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "formal/cnesdata_delivery"
DELIVERY = ROOT / "tools/cnesdata_delivery"
MODEL = (FORMAL / "StageWindows.tla").read_text(encoding="utf-8")
MAIN_CFG = (FORMAL / "StageWindows.cfg").read_text(encoding="utf-8")
CONSTANTS = ("AdmitMargin", "ApplyTimeout", "Over", "ReviewPause", "AllowEarly")
MUTANTS = {
    "StageWindowsMutantPause": ("ReviewPause", "60", "InBoundsAccepts"),
    "StageWindowsMutantMargin": ("AdmitMargin", "0", "EffectsInsideStage"),
    "StageWindowsMutantEarly": ("AllowEarly", "TRUE", "EffectsInsideStage"),
}
MODEL_STAGE_ORDER = ["phase-b", "api", "static", "unit", "phase-c-recovery", "phase-c-audit", "final"]
DEPLOY_STAGES = {1, 5, 6}


def source(name, function):
    text = (DELIVERY / name).read_text(encoding="utf-8")
    start = text.index(f"def {function}(")
    end = text.find("\ndef ", start + 1)
    return text[start:end if end > 0 else None]


def cfg_values(text):
    return dict(re.findall(r"^\s+(\w+) = (\S+)\s*$", text, re.M))


def model_number(name):
    return int(re.search(rf"^{name} == (\d+)\s*$", MODEL, re.M).group(1))


def model_stage_durations():
    body = re.search(r"^StageDur == <<([\d, ]+)>>", MODEL, re.M).group(1)
    return [int(item) for item in body.split(",")]


def model_bounds():
    pairs = re.findall(r"^\s+(?:CASE|\[\]) (.+?) -> (\d+)\s*$", MODEL, re.M)
    return {guard: int(value) for guard, value in pairs}


def stage_bounds(stage):
    guards = model_bounds()
    values = {}
    for guard, value in guards.items():
        member = re.match(r"s \\in \{([\d, ]+)\} /\\ op = \"(\w+)\"", guard)
        single = re.match(r"s = (\d+) /\\ op = \"(\w+)\"", guard)
        if member and stage in {int(item) for item in member.group(1).split(",")}:
            values[member.group(2)] = value
        elif single and int(single.group(1)) == stage:
            values[single.group(2)] = value
        elif guard == 'op = "observe"':
            values["observe"] = value
    return values


def test_duracoes_dos_estagios_do_modelo_igualam_a_tabela_do_codigo():
    assert list(lc.STAGES) == MODEL_STAGE_ORDER
    assert model_stage_durations() == [duration for duration, _ in lc.STAGES.values()]


def test_reserva_posterior_do_codigo_e_a_soma_dos_estagios_seguintes():
    durations = model_stage_durations()
    assert [later for _, later in lc.STAGES.values()] == [
        sum(durations[index + 1:]) for index in range(len(durations))]


def test_margem_de_admissao_do_modelo_iguala_a_regra_do_codigo():
    margins = set(re.findall(r"now \+ operation_seconds \+ (\d+) < (?:window\[\"deadline\"\]|deadline)",
                             source("lifecycle_contract.py", "phase_capacity")))
    assert margins == {cfg_values(MAIN_CFG)["AdmitMargin"]}
    assert "last.start + last.secs + 37 < last.dl" in MODEL


def test_timeout_do_apply_do_modelo_iguala_o_tofu_apply_do_runtime():
    runtime = (DELIVERY / "lifecycle_runtime.py").read_text(encoding="utf-8")
    timeouts = re.findall(r'"apply", "-input=false".*?timeout=(\d+)\)', runtime, re.S)
    assert set(timeouts) == {cfg_values(MAIN_CFG)["ApplyTimeout"]}


def test_janela_fixa_e_reserva_final_do_modelo_igualam_o_codigo():
    capacity = source("lifecycle_contract.py", "phase_capacity")
    assert set(re.findall(r"min\(close \+ (\d+), window\[\"input_deadline\"\]\)", capacity)) == {
        str(model_number("Fixed"))}
    assert set(re.findall(r"\+ later \+ (\d+)", capacity)) == {str(model_number("FinalReserve"))}
    contract = (DELIVERY / "lifecycle_contract.py").read_text(encoding="utf-8")
    assert set(re.findall(r"maximum = (\d+) if manifest\[\"context_kind\"\] == \"promotion\"",
                          contract)) == {str(model_number("ModeWindow"))}


@pytest.mark.parametrize("stage", range(1, 8))
def test_limites_de_duracao_do_modelo_sao_os_maiores_que_mantem_cada_operacao_admissivel(stage):
    margin = int(cfg_values(MAIN_CFG)["AdmitMargin"])
    apply = int(cfg_values(MAIN_CFG)["ApplyTimeout"])
    window = list(lc.STAGES.values())[stage - 1][0]
    bounds = stage_bounds(stage)
    if stage in DEPLOY_STAGES:
        assert set(bounds) == {"plan", "audit", "observe"}
        assert sum(bounds.values()) == window - margin - apply - 1
    else:
        assert set(bounds) == {"effect", "observe"}
        assert sum(bounds.values()) == window - margin - 1


def test_modelo_principal_nao_tem_pausa_nem_largada_antecipada_nem_estouro():
    values = cfg_values(MAIN_CFG)
    assert (values["Over"], values["ReviewPause"], values["AllowEarly"]) == ("0", "0", "FALSE")


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_mutante_difere_do_modelo_principal_em_uma_constante_e_espera_a_violacao(name):
    constant, value, invariant = MUTANTS[name]
    text = (FORMAL / f"{name}.cfg").read_text(encoding="utf-8")
    main, mutant = cfg_values(MAIN_CFG), cfg_values(text)
    assert {key for key in CONSTANTS if main[key] != mutant[key]} - {"Over"} == {constant}
    assert mutant[constant] == value
    assert f"\\* expect invariant:{invariant}" in text
    assert re.search(rf"^INVARIANT {invariant}$", text, re.M)
