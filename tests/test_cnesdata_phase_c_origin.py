"""P16b ruling 6 item 2: the recovery and audit observes take phase-c from the keeper's own accepted elements."""
import json
from types import SimpleNamespace

import pytest

from test_cnesdata_mode_stages import _mode_case
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import mode_broker


def _element(kind):
    value = {"version": 1, "kind": kind, "common": {"release_id": "liberação-fixture", "source_sha": "b" * 40},
             "routes": {"unit": "unit:9", "recovery": "recovery:9", "audit": None if kind.endswith("recovery") else "audit:9"}}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


RECOVERY, AUDIT = _element("phase-c-recovery"), _element("phase-c-audit")


def _source(operation, elements, names=("phase-c",)):
    window = _mode_case(operation)[2]
    keeper = SimpleNamespace(_contexts=[], phase_c_elements=dict(elements))
    return ag.mode_input_source(keeper=keeper, owner={}, window=window, operation=operation, names=list(names))


def _product_canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def test_recovery_observe_recebe_a_lista_com_o_elemento_do_recovery():
    assert _source("recovery-observe", {"phase-c-recovery": RECOVERY}) == {
        "phase-c": _product_canonical([json.loads(RECOVERY)])}


def test_audit_observe_recebe_recovery_e_audit_na_ordem_dos_modos():
    raw = _source("audit-observe", {"phase-c-audit": AUDIT, "phase-c-recovery": RECOVERY})["phase-c"]
    assert raw == _product_canonical([json.loads(RECOVERY), json.loads(AUDIT)])
    assert [item["kind"] for item in json.loads(raw)] == ["phase-c-recovery", "phase-c-audit"]


def test_lista_phase_c_e_canonica_pela_regra_do_produto_e_nao_escapa_o_texto():
    raw = _source("audit-observe", {"phase-c-audit": AUDIT, "phase-c-recovery": RECOVERY})["phase-c"]
    assert raw == _product_canonical(json.loads(raw)) == c.canonical(json.loads(raw))
    assert "liberação-fixture".encode() in raw and b"\\u00e7" not in raw and b"\\u00e7" in RECOVERY


@pytest.mark.parametrize("operation, elements", [
    ("recovery-observe", {}),
    ("recovery-observe", {"phase-c-recovery": RECOVERY, "phase-c-audit": AUDIT}),
    ("audit-observe", {"phase-c-audit": AUDIT}),
    ("audit-observe", {"phase-c-recovery": RECOVERY}),
], ids=["recovery-sem-elemento", "recovery-com-o-audit", "audit-so-com-o-proprio", "audit-sem-o-proprio"])
def test_elementos_fora_do_conjunto_do_modo_recusam(operation, elements):
    with pytest.raises(ValueError, match="^phase-c original$"):
        _source(operation, elements)


@pytest.mark.parametrize("operation", ["unit-observe", "unit-start", "recovery-record", "recovery-start", "audit-record",
                                       "audit-start"])
def test_origem_phase_c_so_abre_para_os_observes_de_recovery_e_audit(monkeypatch, operation):
    monkeypatch.setattr(mode_broker, "MODE_UNIT_START_OPEN", True)
    with pytest.raises(ValueError, match="^mode_inputs=source_unconnected$"):
        _source(operation, {"phase-c-recovery": RECOVERY, "phase-c-audit": AUDIT})


def test_origem_phase_c_esta_ligada_so_aos_dois_observes():
    assert mode_broker.MODE_KEEPER_ORIGINS["phase-c"] == ("recovery-observe", "audit-observe")
