"""Runner and CI contract of the CnesData delivery formal models."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "formal/cnesdata_delivery/check.py"
PIPELINE = ROOT / ".github/workflows/pipeline.yml"
FORMAL_STEP = "Check the CnesData delivery formal models"
PYTEST_STEP = "Run Python tests (public context; external targets reported)"
TLA_URL = "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar"
TLA_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
ALLOY_URL = "https://github.com/AlloyTools/org.alloytools.alloy/releases/download/v6.2.0/org.alloytools.alloy.dist.jar"
ALLOY_SHA256 = "6b8c1cb5bc93bedfc7c61435c4e1ab6e688a242dc702a394628d9a9801edb78d"

COUNTER = """---- MODULE {name} ----
EXTENDS Naturals
VARIABLE x
Init == x = 0
Inc == x < 3 /\\ x' = x + 1
Done == x = 3 /\\ UNCHANGED x
Spec == Init /\\ [][Inc \\/ Done]_x /\\ WF_x(Inc)
Bounded == x \\in 0..3
Small == x < 3
Reach == <>(x = 3)
====
"""
PASSING_CFG = "SPECIFICATION Spec\nINVARIANT Bounded\nPROPERTY Reach\n"
VIOLATING_CFG = "SPECIFICATION Spec\nINVARIANT Small\n"
ALLOY = """sig Node {{ succ: lone Node }}
assert acyclic_or_linked {{ all n: Node | n not in n.^succ or some n.succ }}
assert cycle_free {{ no n: Node | n in n.^succ }}
{commands}
"""


def tools():
    tla, alloy = os.environ.get("FORMAL_TLA_JAR"), os.environ.get("FORMAL_ALLOY_JAR")
    if tla and alloy:
        return tla, alloy
    if os.environ.get("GITHUB_ACTIONS") == "true":
        pytest.fail("FORMAL_TLA_JAR/FORMAL_ALLOY_JAR ausentes no CI")
    pytest.skip("FORMAL_TLA_JAR/FORMAL_ALLOY_JAR ausentes")


def run_check(models, *extra, java=None):
    tla, alloy = tools()
    command = [sys.executable, str(CHECK), "--tla-jar", tla, "--alloy-jar", alloy, "--models", str(models)]
    command += ["--java", java] if java else []
    return subprocess.run(command + list(extra), capture_output=True, text=True, timeout=300, check=False)


def lines(result):
    found = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] in ("PASS", "FAIL"):
            found[parts[2]] = (parts[0], line)
    return found


def write(directory, files):
    directory.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (directory / name).write_text(text, encoding="utf-8")
    return directory


def tla(name, cfg):
    return {f"{name}.tla": COUNTER.format(name=name), f"{name}.cfg": cfg}


def alloy(commands):
    return {"toy.als": ALLOY.format(commands=commands)}


def snapshot(directory):
    return {path.relative_to(directory): path.read_bytes() for path in sorted(directory.rglob("*"))}


def test_modelo_tla_que_passa_aprova_a_execucao(tmp_path):
    models = write(tmp_path / "m", tla("Counter", PASSING_CFG))
    result = run_check(models)
    assert result.returncode == 0, result.stdout + result.stderr
    assert lines(result)["Counter"][0] == "PASS"


def test_modelo_tla_com_violacao_reprova_a_execucao(tmp_path):
    models = write(tmp_path / "m", tla("Counter", VIOLATING_CFG))
    result = run_check(models)
    assert result.returncode == 1
    assert lines(result)["Counter"][0] == "FAIL"


def test_mutante_tla_que_passa_reprova_a_execucao(tmp_path):
    models = write(tmp_path / "m", tla("Counter", PASSING_CFG) | tla("CounterMutantWeak", PASSING_CFG))
    result = run_check(models)
    assert result.returncode == 1
    assert lines(result)["Counter"][0] == "PASS"
    assert lines(result)["CounterMutantWeak"][0] == "FAIL"


@pytest.mark.parametrize("cfg, observed", [
    (VIOLATING_CFG, "observed=invariant"),
    ("SPECIFICATION Spec\nPROPERTY Never\n", "observed=temporal"),
])
def test_mutante_tla_com_violacao_aprova_a_execucao(tmp_path, cfg, observed):
    files = tla("CounterMutantCut", cfg)
    files["CounterMutantCut.tla"] = files["CounterMutantCut.tla"].replace("====", "Never == [](x < 3)\n====")
    models = write(tmp_path / "m", files)
    result = run_check(models)
    assert result.returncode == 0, result.stdout + result.stderr
    status, line = lines(result)["CounterMutantCut"]
    assert status == "PASS" and observed in line


def test_mutante_tla_com_deadlock_aprova_a_execucao(tmp_path):
    files = tla("CounterMutantStop", "SPECIFICATION Spec\nINVARIANT Bounded\n")
    files["CounterMutantStop.tla"] = files["CounterMutantStop.tla"].replace("[Inc \\/ Done]_x", "[Inc]_x")
    result = run_check(write(tmp_path / "m", files))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "observed=deadlock" in lines(result)["CounterMutantStop"][1]


def test_mutante_tla_com_erro_de_sintaxe_reprova_a_execucao(tmp_path):
    files = tla("CounterMutantTypo", VIOLATING_CFG)
    files["CounterMutantTypo.tla"] = files["CounterMutantTypo.tla"].replace("x < 3 /\\", "y < 3 /\\")
    result = run_check(write(tmp_path / "m", files))
    assert result.returncode == 1
    assert lines(result)["CounterMutantTypo"][0] == "FAIL"


def test_mutante_tla_com_cfg_invalido_reprova_a_execucao(tmp_path):
    models = write(tmp_path / "m", tla("CounterMutantCfg", "SPECIFICATION Spec\nINVARIANT Missing\n"))
    result = run_check(models)
    assert result.returncode == 1
    assert lines(result)["CounterMutantCfg"][0] == "FAIL"


def test_cfg_sem_modulo_reprova_a_execucao(tmp_path):
    models = write(tmp_path / "m", tla("Counter", PASSING_CFG) | {"Orphan.cfg": PASSING_CFG})
    result = run_check(models)
    assert result.returncode == 1
    assert lines(result)["Orphan"][0] == "FAIL"


def test_mutante_sem_cfg_reprova_a_execucao(tmp_path):
    files = tla("Counter", PASSING_CFG) | {"CounterMutantLost.tla": COUNTER.format(name="CounterMutantLost")}
    result = run_check(write(tmp_path / "m", files))
    assert result.returncode == 1
    assert lines(result)["CounterMutantLost"][0] == "FAIL"


def test_modulo_sem_cfg_e_biblioteca_usavel_por_extends(tmp_path):
    files = {"Base.tla": COUNTER.format(name="Base"),
             "Derived.tla": "---- MODULE Derived ----\nEXTENDS Base\n====\n",
             "Derived.cfg": PASSING_CFG}
    result = run_check(write(tmp_path / "m", files))
    assert result.returncode == 0, result.stdout + result.stderr
    assert lines(result)["Derived"][0] == "PASS"
    assert "Base" not in lines(result)


def test_check_alloy_sem_contraexemplo_aprova_e_run_sat_satisfativel_aprova(tmp_path):
    models = write(tmp_path / "m", alloy("check acyclic_or_linked for 3\nrun sat_edge { some succ } for 3"))
    result = run_check(models)
    assert result.returncode == 0, result.stdout + result.stderr
    assert lines(result)["toy.als:acyclic_or_linked"][0] == "PASS"
    assert lines(result)["toy.als:sat_edge"][0] == "PASS"


def test_check_mutant_sem_contraexemplo_reprova_a_execucao(tmp_path):
    models = write(tmp_path / "m", alloy("check mutant_linked { all n: Node | n not in n.^succ or some n.succ } for 3"))
    result = run_check(models)
    assert result.returncode == 1
    assert lines(result)["toy.als:mutant_linked"][0] == "FAIL"


def test_check_mutant_com_contraexemplo_aprova_a_execucao(tmp_path):
    models = write(tmp_path / "m", alloy("check mutant_cycle_free { no n: Node | n in n.^succ } for 3"))
    result = run_check(models)
    assert result.returncode == 0, result.stdout + result.stderr
    assert lines(result)["toy.als:mutant_cycle_free"][0] == "PASS"


def test_check_comum_com_contraexemplo_reprova_a_execucao(tmp_path):
    result = run_check(write(tmp_path / "m", alloy("check cycle_free for 3")))
    assert result.returncode == 1
    assert lines(result)["toy.als:cycle_free"][0] == "FAIL"


def test_run_sat_insatisfativel_reprova_a_execucao(tmp_path):
    result = run_check(write(tmp_path / "m", alloy("run sat_empty { some Node and no Node } for 3")))
    assert result.returncode == 1
    assert lines(result)["toy.als:sat_empty"][0] == "FAIL"


def test_run_sem_prefixo_sat_nao_decide_a_execucao(tmp_path):
    models = write(tmp_path / "m", alloy("check acyclic_or_linked for 3\nrun empty { some Node and no Node } for 3"))
    result = run_check(models)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ungated" in result.stdout and "toy.als:empty" not in lines(result)


def test_nomes_de_comando_alloy_duplicados_reprovam_a_execucao(tmp_path):
    models = write(tmp_path / "m", alloy("run sat_x { some Node } for 3\nrun sat_x { no Node } for 3"))
    result = run_check(models)
    assert result.returncode == 1
    assert lines(result)["toy.als:sat_x"][0] == "FAIL"


def test_alloy_sem_comando_reprova_a_execucao(tmp_path):
    result = run_check(write(tmp_path / "m", alloy("")))
    assert result.returncode == 1
    assert lines(result)["toy.als"][0] == "FAIL"


def test_alloy_com_erro_de_tipo_reprova_a_execucao(tmp_path):
    models = write(tmp_path / "m", alloy("check mutant_typo { no n: Node | n in n.^next } for 3"))
    result = run_check(models)
    assert result.returncode == 1
    assert lines(result)["toy.als"][0] == "FAIL"


def test_diretorio_sem_modelos_reprova_a_execucao(tmp_path):
    result = run_check(write(tmp_path / "m", {"README.txt": "nada"}))
    assert result.returncode == 1
    assert "SUMMARY checked=0" in result.stdout


def test_arquivo_de_modelo_em_subdiretorio_reprova_a_execucao(tmp_path):
    models = write(tmp_path / "m", tla("Counter", PASSING_CFG))
    write(models / "nested", tla("Hidden", PASSING_CFG))
    result = run_check(models)
    assert result.returncode == 1
    assert "FAIL layout" in result.stdout


def test_execucao_nao_escreve_no_diretorio_dos_modelos(tmp_path):
    files = tla("Counter", PASSING_CFG) | tla("CounterMutantCut", VIOLATING_CFG)
    files |= alloy("check mutant_cycle_free { no n: Node | n in n.^succ } for 3")
    models = write(tmp_path / "m", files)
    before = snapshot(models)
    result = run_check(models)
    assert result.returncode == 0, result.stdout + result.stderr
    assert snapshot(models) == before


def test_processo_que_estoura_o_tempo_e_morto_e_reprova(tmp_path):
    fake = tmp_path / "slow-java"
    fake.write_text("#!/bin/sh\nexec sleep 60\n", encoding="utf-8")
    fake.chmod(0o755)
    models = write(tmp_path / "m", tla("Counter", PASSING_CFG))
    result = run_check(models, "--timeout", "2", java=str(fake))
    assert result.returncode == 1
    assert "observed=timeout" in lines(result)["Counter"][1]


def test_jar_inexistente_reprova_a_execucao(tmp_path):
    tools()
    models = write(tmp_path / "m", tla("Counter", PASSING_CFG))
    command = [sys.executable, str(CHECK), "--tla-jar", str(tmp_path / "absent.jar"),
               "--alloy-jar", str(tmp_path / "absent.jar"), "--models", str(models)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 1
    assert "FAIL setup tla-jar expected=file observed=missing" in result.stdout
    assert "FAIL setup alloy-jar expected=file observed=missing" in result.stdout


def validate_job():
    return yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))["jobs"]["validate"]


def test_pipeline_verifica_sha256_dos_jars_antes_de_rodar_os_modelos():
    validate = validate_job()
    names = [step.get("name") for step in validate["steps"]]
    step = validate["steps"][names.index(FORMAL_STEP)]
    assert validate["runs-on"] == "ubuntu-latest"
    assert names.index(FORMAL_STEP) < names.index(PYTEST_STEP)
    assert step["shell"] == "bash" and step["run"].startswith("set -euo pipefail\n")
    assert step["timeout-minutes"] == 30
    assert step["env"] == {"TLA_TOOLS_URL": TLA_URL, "TLA_TOOLS_SHA256": TLA_SHA256,
                           "ALLOY_URL": ALLOY_URL, "ALLOY_SHA256": ALLOY_SHA256}
    run = step["run"]
    order = ["${TLA_TOOLS_URL}", "${ALLOY_URL}", "sha256sum --check --strict", "java -version",
             "python3 formal/cnesdata_delivery/check.py", "GITHUB_ENV"]
    positions = [run.index(fragment) for fragment in order]
    assert positions == sorted(positions)
    assert run.count("curl ") == 2 and run.count("--proto '=https'") == 2
    assert "uses" not in step


def test_pipeline_exporta_os_jars_verificados_para_os_testes_do_harness():
    run = next(step for step in validate_job()["steps"] if step.get("name") == FORMAL_STEP)["run"]
    export = [line.strip() for line in run.splitlines() if "GITHUB_ENV" in line]
    assert export == ["printf 'FORMAL_TLA_JAR=%s\\n' \"${tools}/tla2tools.jar\" >> \"${GITHUB_ENV}\"",
                      "printf 'FORMAL_ALLOY_JAR=%s\\n' \"${tools}/alloy.jar\" >> \"${GITHUB_ENV}\""]
    assert run.index("sha256sum --check --strict") < run.index(export[0])
