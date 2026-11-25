"""P16b ruling 6 item 3: the phase-c child runtime, the product uv.lock cp313 entries at the pinned commit."""
import re
import tomllib
from pathlib import Path

import pytest
import yaml

from test_cnesdata_mode_frames import PRODUCT_FRAMES_ORIGIN
from test_github_workflow import ACTION_PINS

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "tools/cnesdata_delivery/phase-c-child-requirements.txt"
LOCK = ROOT / "tests/fixtures/cnesdata_phase_c_child_lock.toml"
LOCK_ORIGIN = {"commit": "47b122f5957ccd8ab1e1ca30015ef44f7429e4f0",
               "uv_lock_sha256": "aaca6116865ec03bb47df96e876755cdf76a1c97df5bf9b60dc19e69ad80aac1"}
CLOSURE = {"annotated-types", "botocore", "jmespath", "pydantic", "pydantic-core", "python-dateutil", "six",
           "typing-extensions", "typing-inspection", "urllib3"}
LINE = re.compile(r"([a-z0-9-]+)==([0-9a-z.]+) --hash=sha256:([0-9a-f]{64})")
WHEEL = re.compile(r"[A-Za-z0-9_.-]+-(?:py3|py2\.py3)-none-any\.whl"
                   r"|[A-Za-z0-9_.-]+-cp313-cp313-manylinux_2_17_x86_64\.manylinux2014_x86_64\.whl")
APPLICATION = ".github/workflows/reusable-cnesdata-application-gate.yml"
PIPELINE = ".github/workflows/pipeline.yml"
SETUP = "Set up the pinned phase-c child Python"
INSTALL = "Install the hash-pinned phase-c child runtime"


def _pins():
    lines = REQUIREMENTS.read_text().splitlines()
    matches = [LINE.fullmatch(line) for line in lines]
    assert all(matches), lines
    return {match[1]: (match[2], match[3]) for match in matches}, len(lines)


def _packages():
    return tomllib.loads(LOCK.read_text())["package"]


def test_cada_pin_do_filho_e_a_entrada_do_lock_do_produto_com_o_hash_da_roda_cp313():
    pins, count = _pins()
    packages = _packages()
    assert count == len(pins) == len(packages) == len(CLOSURE)
    assert set(pins) == {package["name"] for package in packages} == CLOSURE
    for package in packages:
        version, digest = pins[package["name"]]
        wheels = [wheel for wheel in package["wheels"] if WHEEL.fullmatch(wheel["url"].rsplit("/", 1)[1])]
        assert package["version"] == version and package["source"] == {"registry": "https://pypi.org/simple"}
        assert [wheel["hash"] for wheel in wheels] == ["sha256:" + digest], package["name"]


def test_lock_do_filho_vem_do_commit_pinado_dos_frames_do_produto():
    assert LOCK_ORIGIN["commit"] == PRODUCT_FRAMES_ORIGIN["commit"]


def test_fecho_do_filho_cobre_todas_as_dependencias_do_lock():
    assert {dependency["name"] for package in _packages() for dependency in package.get("dependencies", [])} <= CLOSURE


def test_runtime_dos_gates_continua_com_o_botocore_proprio_e_sem_pydantic():
    runtime = (ROOT / "tools/cnesdata_delivery/runtime-requirements.txt").read_text()
    assert "\nbotocore==1.40.71 --hash=" in runtime and "pydantic" not in runtime
    assert _pins()[0]["botocore"][0] == "1.43.82"


def _steps(path, job):
    return yaml.safe_load((ROOT / path).read_text())["jobs"][job]["steps"]


@pytest.mark.parametrize("path, job, before", [
    (APPLICATION, "execute", "Repeat source gate then request exact OIDC role"),
    (PIPELINE, "validate", "Run Python tests (public context; external targets reported)")], ids=["gate", "validacao"])
def test_job_provisiona_o_python_3_13_pinado_e_o_alvo_do_filho_antes_de_usar(path, job, before):
    steps = _steps(path, job)
    names = [step.get("name") for step in steps]
    assert names.count(SETUP) == names.count(INSTALL) == 1
    assert names.index(SETUP) + 1 == names.index(INSTALL) < names.index(before)
    assert steps[names.index(SETUP)] == {"name": SETUP, "id": "phase-c-python",
                                         "uses": "actions/setup-python@" + ACTION_PINS["actions/setup-python"],
                                         "with": {"python-version": "3.13", "update-environment": False}}
    install = steps[names.index(INSTALL)]
    assert install["shell"] == "bash" and install["env"] == {"PHASE_C_PYTHON": "${{ steps.phase-c-python.outputs.python-path }}"}
    for fragment in ("set -euo pipefail\n", '"${PHASE_C_PYTHON}" -I -m pip install', "--require-hashes", "--only-binary=:all:",
                     '--target "${target}"', "-r tools/cnesdata_delivery/phase-c-child-requirements.txt",
                     "phase_c_child_install seconds=", "CNESDATA_PHASE_C_PYTHON=", "CNESDATA_PHASE_C_TARGET="):
        assert fragment in install["run"]
    assert "--no-deps" not in install["run"] and "runtime-requirements" not in install["run"]


def test_instalacao_do_filho_e_a_mesma_no_gate_e_na_validacao():
    gate, validation = ([step for step in _steps(path, job) if step.get("name") == INSTALL]
                        for path, job in ((APPLICATION, "execute"), (PIPELINE, "validate")))
    assert len(gate) == 1 and gate == validation


def test_no_gate_o_filho_e_provisionado_no_inicio_antes_das_credenciais_e_do_lease():
    names = [step.get("name") for step in _steps(APPLICATION, "execute")]
    assert (names.index("Install checksum-locked protected runtime") < names.index(SETUP) < names.index(INSTALL)
            < names.index("Repeat source gate then request exact OIDC role")
            < names.index("Execute under CAS watchdog and verify final publication"))
