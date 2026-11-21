import re
from pathlib import Path

from tools.ci.pytest_ci import SUPPORTED

CI_DIR = Path(__file__).resolve().parents[1] / "tools" / "ci"
LOCK = CI_DIR / "requirements-ci.txt"
SOURCE = CI_DIR / "requirements-ci.in"


def _entries(text):
    blocks = re.split(r"\n(?=\S)", text.strip())
    return [block for block in blocks if re.match(r"[A-Za-z0-9_.-]+==", block)]


def _pins():
    return {
        block.split("==", 1)[0].lower(): block.split("==", 1)[1].split()[0]
        for block in _entries(LOCK.read_text(encoding="utf-8"))
    }


def test_requirements_ci_fixa_versao_exata_com_hash():
    entries = _entries(LOCK.read_text(encoding="utf-8"))

    assert len(entries) >= 30
    for block in entries:
        assert re.match(r"[A-Za-z0-9_.-]+==[0-9][^\s;]*", block), block
        assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", block)) >= 1, block
    assert not re.search(r"^\s*(-e|git\+|https?://)", LOCK.read_text(encoding="utf-8"), re.M)
    assert SOURCE.read_text(encoding="utf-8").split() == [
        "pytest==9.2.0",
        "pytest-xdist==3.8.0",
        "ansible-core==2.21.6",
        "ansible-lint==26.11.0",
        "yamllint==1.38.0",
    ]


def test_pins_de_pytest_e_xdist_conferem_com_o_plugin():
    pins = _pins()

    assert pins["pytest"] == SUPPORTED["pytest"]
    assert pins["pytest-xdist"] == SUPPORTED["pytest-xdist"]
    assert pins["execnet"] == "2.1.2"


def test_requirements_ci_nao_tem_plugin_de_retentativa():
    names = set(_pins())

    assert not {name for name in names if "rerun" in name or "flaky" in name or "retry" in name}
    assert "pytest-rerunfailures" not in names
