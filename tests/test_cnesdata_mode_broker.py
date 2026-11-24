"""P16b: mode SDK broker, fence-read broker, mode readbacks and their keeper seam."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

REUSABLE_LISTS = {"application-gate": 1, "infra-audit-gate": 1, "infra-deploy-gate": 1, "infra-plan-gate": 1, "observer": 2}
UNKNOWN = {"kind": "sdk-call", "reference_sha256": "a" * 64}


def _mode_broker_module():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _broker(kind, journal, *, uncertainty=()):
    cls = getattr(_mode_broker_module(), kind)
    broker = cls.__new__(cls)
    broker.journal, broker.calls = journal, []
    broker.evidence = [SimpleNamespace(uncertainty=list(uncertainty), _aws="ledger-client")]
    broker.call = lambda **kwargs: broker.calls.append(kwargs) or {"kind": "sdk-result", "value": {"ok": True}}
    journal._broker = broker
    return broker


def test_brokers_admitidos_sao_os_dois_do_p15_mais_os_dois_de_modo_na_ordem_exata():
    mb = _mode_broker_module()
    assert ag._brokers() == (ag.ClosedReadyBroker, ag.StaticBroker, mb.ModeBroker, mb.FenceReadBroker)
    assert ag.BROKERS == (ag.ClosedReadyBroker, ag.StaticBroker)


def test_mode_broker_entra_no_pyboot_e_nas_cinco_listas_dos_reusables():
    assert "mode_broker.py" in lc.APPLICATION_PYBOOT
    assert "tools/cnesdata_delivery/mode_broker.py" in lc.APPLICATION_CLOSURE_PATHS
    root = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    for name, count in REUSABLE_LISTS.items():
        assert (root / f"reusable-cnesdata-{name}.yml").read_text().count('"mode_broker.py"') == count, name


@pytest.mark.parametrize("kind", ["ModeBroker", "FenceReadBroker"])
def test_frame_call_vai_para_o_broker_de_modo_admitido_no_journal(kind):
    journal = SimpleNamespace()
    broker = _broker(kind, journal)
    frame = c.canonical({"kind": "call", "role": "r", "service": "s", "operation": "o", "parameters": {"k": 1}})
    assert ag._adapter_message(frame, journal) == ({"kind": "sdk-result", "value": {"ok": True}}, None)
    assert broker.calls == [{"role": "r", "service": "s", "operation": "o", "parameters": {"k": 1}}]


def test_frame_call_recusa_broker_que_so_imita_o_broker_de_modo():
    journal = SimpleNamespace(_broker=SimpleNamespace(call=lambda **kwargs: {"kind": "sdk-result", "value": {}}))
    frame = c.canonical({"kind": "call", "role": "r", "service": "s", "operation": "o", "parameters": {}})
    with pytest.raises(ValueError, match="^adapter protected SDK admission absent$"):
        ag._adapter_message(frame, journal)


@pytest.mark.parametrize("kind", ["ModeBroker", "FenceReadBroker"])
def test_keeper_anexa_o_broker_de_modo_e_a_incerteza_do_ledger_segura_o_lease(kind):
    from test_cnesdata_mode_stages import _keeper, _mode_journal
    journal, _, _ = _mode_journal("unit")
    keeper = _keeper(journal)
    broker = _broker(kind, journal, uncertainty=[UNKNOWN])
    keeper.attach(broker)
    assert ag._journal_of(broker) is journal
    assert UNKNOWN in keeper.uncertainty()
    assert ag._mode_journal(keeper, "unit") is journal


OWNER, OTHER, CANARY = "1" * 64, "2" * 64, "c" * 32
TENANT = "TENANT#" + ("prod-canary-" + CANARY).encode().hex()
RUNS = tuple(f"{name}-{OWNER[:16]}" for name in ("unit", "recovery-a", "recovery-b"))
DISPATCH = "dispatch-0001"


def _run_pk(run):
    return TENANT + "#RUN#" + run.encode().hex()


def _keys(owner=OWNER, run=RUNS[0], dispatch=DISPATCH, tenant=TENANT):
    return {"record-unit": (tenant, f"PROD_CANARY#{owner}#unit"),
            "record-recovery": (tenant, f"PROD_CANARY#{owner}#recovery"),
            "record-audit": (tenant, f"PROD_CANARY#{owner}#audit"),
            "control": (tenant, f"PROD_CANARY_CONTROL#{owner}"),
            "ticket": (tenant, f"PROD_CANARY_EFFECT#{owner}#{'e' * 64}"),
            "binding": (_run_pk(run), f"PROD_CANARY#{dispatch}"),
            "seed-raw": (tenant, "RAW_MANIFEST#" + f"cnes-local-v1-unit-{owner[:16]}".encode().hex()),
            "seed-run": (tenant, "RUN#" + run.encode().hex()),
            "seed-unit": (_run_pk(run), "UNIT#" + ("a" * 32).encode().hex())}


SEED = {(family, action) for family in ("seed-raw", "seed-run", "seed-unit") for action in ("put", "get")}
ADMITTED = {
    "unit-seed": SEED | {("record-unit", "put"), ("record-unit", "get"), ("control", "put"), ("control", "get")},
    "recovery-seed": SEED | {("record-recovery", "put"), ("record-recovery", "get"), ("control", "get")},
    "dispatch-unit": {("binding", "put"), ("ticket", "put"), ("ticket", "get"), ("control", "put"), ("control", "get")},
    "ledger-admit": {("ticket", "put"), ("ticket", "get"), ("control", "put"), ("control", "get")},
    "ledger-unknown": {("ticket", "put"), ("ticket", "get")},
    "ledger-settle": {("ticket", "put"), ("ticket", "get")},
}


def _binding(frame):
    return {"canary_id": CANARY, "owner_sha256": OWNER, "run_ids": list(RUNS),
            "dispatch_id": DISPATCH if frame == "dispatch-unit" else None}


def _admit(frame, action, key):
    return _mode_broker_module().admit_mode_key(frame, action, key, binding=_binding(frame))


def test_conjunto_de_chaves_admitidas_por_frame_e_fechado():
    assert _mode_broker_module().MODE_KEY_FRAMES == ADMITTED
    assert set(ADMITTED) == {"unit-seed", "recovery-seed", "dispatch-unit", "ledger-admit", "ledger-unknown",
                             "ledger-settle"}


@pytest.mark.parametrize("frame, family, action", sorted((frame, family, action) for frame, pairs in ADMITTED.items()
                                                         for family, action in pairs))
def test_frame_admite_so_as_chaves_do_proprio_owner_e_fase(frame, family, action):
    for run in RUNS:
        assert _admit(frame, action, _keys(run=run)[family]) == family


@pytest.mark.parametrize("frame, family, action", sorted(
    (frame, family, action) for frame in ADMITTED for family in _keys() for action in ("put", "get")
    if (family, action) not in ADMITTED[frame]))
def test_frame_recusa_chave_fora_do_proprio_conjunto_antes_de_qualquer_chamada(frame, family, action):
    with pytest.raises(ValueError, match="^mode key outside frame$"):
        _admit(frame, action, _keys()[family])


@pytest.mark.parametrize("frame, action, family", [
    ("dispatch-unit", "put", "record-unit"), ("recovery-seed", "put", "control"), ("unit-seed", "put", "ticket"),
    ("recovery-seed", "put", "ticket"), ("unit-seed", "put", "record-recovery")])
def test_mutantes_do_c1_sao_recusados(frame, action, family):
    with pytest.raises(ValueError, match="^mode key outside frame$"):
        _admit(frame, action, _keys()[family])


@pytest.mark.parametrize("frame", sorted(ADMITTED))
@pytest.mark.parametrize("change", ["owner", "run", "dispatch", "tenant"])
def test_frame_recusa_qualquer_chave_de_outro_owner_run_dispatch_ou_tenant(frame, change):
    other_tenant = "TENANT#" + ("prod-canary-" + "d" * 32).encode().hex()
    keys = {"owner": _keys(owner=OTHER, run=f"unit-{OTHER[:16]}"), "run": _keys(run=f"unit-{OTHER[:16]}"),
            "dispatch": _keys(dispatch="dispatch-0002"), "tenant": _keys(tenant=other_tenant)}[change]
    moved = {family: key for family, key in keys.items() if key != _keys()[family]}
    assert moved
    for family, key in moved.items():
        for action in ("put", "get"):
            with pytest.raises(ValueError, match="^mode key outside frame$"):
                _admit(frame, action, key)


@pytest.mark.parametrize("key", [("TENANT#" + "x" * 3, "RUN#00"), (TENANT, "RUN#zz"), (TENANT, "RAW_MANIFEST#"),
                                 (TENANT, "RAW_MANIFEST#" + f"x-{OWNER[:16]}y".encode().hex()),
                                 (TENANT, "UNIT#" + ("a" * 32).encode().hex()), (_run_pk(RUNS[0]), "UNIT#" + "a" * 64),
                                 (_run_pk(RUNS[0]), "UNIT#" + ("A" * 32).encode().hex()),
                                 (TENANT, f"PROD_CANARY_EFFECT#{OWNER}#{'e' * 63}"), (TENANT, f"PROD_CANARY#{OWNER}#final"),
                                 [TENANT, f"PROD_CANARY_CONTROL#{OWNER}"]])
def test_frame_recusa_chave_malformada(key):
    for frame in ADMITTED:
        for action in ("put", "get"):
            with pytest.raises(ValueError, match="^mode key outside frame$"):
                _admit(frame, action, key)


@pytest.mark.parametrize("binding, message", [
    ({"canary_id": "C" * 32}, "^mode key binding$"), ({"owner_sha256": "1" * 63}, "^mode key binding$"),
    ({"run_ids": []}, "^mode key binding$"), ({"run_ids": ["x", "x"]}, "^mode key binding$"),
    ({"dispatch_id": None}, "^mode key binding$"), ({"dispatch_id": "a#b"}, "^mode key binding$"),
    ({"run_ids": [f"unit-{OTHER[:16]}"]}, "^mode key binding$"), ({"extra": 1}, "^closed object fields$")])
def test_vinculo_das_chaves_e_fechado(binding, message):
    with pytest.raises(ValueError, match=message):
        _mode_broker_module().admit_mode_key("dispatch-unit", "put", _keys()["binding"],
                                             binding=_binding("dispatch-unit") | binding)


def test_seed_nao_carrega_dispatch_no_vinculo():
    with pytest.raises(ValueError, match="^mode key binding$"):
        _mode_broker_module().admit_mode_key("unit-seed", "put", _keys()["seed-run"],
                                             binding=_binding("unit-seed") | {"dispatch_id": DISPATCH})


def test_acao_e_frame_fora_da_tabela_sao_recusados():
    with pytest.raises(ValueError, match="^mode key outside frame$"):
        _admit("unit-seed", "delete", _keys()["seed-run"])
    with pytest.raises(ValueError, match="^mode key outside frame$"):
        _mode_broker_module().admit_mode_key("unit-start", "get", _keys()["seed-run"], binding=_binding("unit-start"))
