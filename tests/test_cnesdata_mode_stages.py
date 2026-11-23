"""P16: mode adapter operations, DD-4 unit/recovery/audit validators and the post-static stage triggers."""
import inspect
import json

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

PRODUCT_MODE_ORIGIN = {
    "commit": "c7b1ece1b030073570a63f8327b7c9bb13142acb",
    "scripts/promotion/_adapter_abi.py": "c485be2e93de45b2093fa74fbe6a60397b6a14067bfa917343a4a4a272748cee",
    "scripts/promotion/promote_mode.py": "991d30a3f8e3589f64c906a3c2c796d98da76d40d75d2c066d2b0707815b2370"}
VENDORED_MODE_SHA256 = "67b826fdb5e7ee4be25dedfc0421f0a3f32cfab68426226bc5648a6249513e90"
MODES = ("unit", "recovery", "audit")
MODE_STAGE = {"unit": "unit", "recovery": "phase-c-recovery", "audit": "phase-c-audit"}
MODE_WINDOWS = {"unit": (1720, 1900), "phase-c-recovery": (1900, 2230), "phase-c-audit": (2230, 2560)}


def _product_mode_abi():
    """Vendored from CnesData c7b1ece1: _adapter_abi MODE_OPERATIONS, MODE_INPUTS, MODE_OBSERVATIONS,
    MODE_OBSERVATION_FIELDS, and promote_mode._observation (canonical of _api_static_records)."""
    operations = {
        "unit-seed": ("unit", "unit"), "unit-start": ("unit", "unit"), "unit-observe": ("unit", "unit"),
        "recovery-seed": ("recovery", "phase-c-recovery"), "recovery-start": ("recovery", "phase-c-recovery"),
        "recovery-observe": ("recovery", "phase-c-recovery"),
        "audit-start": ("audit", "phase-c-audit"), "audit-observe": ("audit", "phase-c-audit")}
    scheduled = frozenset({"activation", "network", "close-drain", "phase-b", "phase-c", "mode-result", "readbacks"})
    seed = frozenset({"record", "mode-start", "fixture-manifest", "fixture-cnes-local", "fixture-cnes-nacional"})
    start = frozenset({"record", "readbacks", "previous", "mode-seed", "mode-start"})
    inputs = {"unit-seed": seed, "recovery-seed": seed, "unit-start": start, "recovery-start": start,
              "audit-start": start | {"audit-event-ids"},
              "unit-observe": frozenset({"activation", "close-drain", "record", "mode-result", "readbacks", "observed"}),
              "recovery-observe": scheduled, "audit-observe": scheduled | {"recovery-result", "recovery-readbacks"}}
    observations = {name: "mode-seed" if name.endswith("-seed") else "mode-result" if name.endswith("-start")
                    else "mode" for name in operations}
    fields = frozenset({"version", "kind", "accepted", "checks", "commitments"})

    def canonical(value):
        return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")

    def observation(kind, checks, request, originals):
        commitments = {"owner": request["owner"]["owner_sha256"]}
        commitments |= {name: c.sha(raw) for name, raw in originals.items()}
        return canonical({"version": 1, "kind": kind, "accepted": not checks, "checks": sorted(checks),
                          "commitments": commitments})
    return {"operations": operations, "inputs": inputs, "observations": observations, "fields": fields,
            "observation": observation}


PRODUCT = _product_mode_abi()


def test_copia_vendorizada_do_abi_de_modo_so_muda_junto_com_a_origem_registrada():
    """infra-ansible CI cannot import CnesData: a refresh of the vendored tables updates its origin and this digest."""
    assert set(PRODUCT_MODE_ORIGIN) == {"commit", "scripts/promotion/_adapter_abi.py", "scripts/promotion/promote_mode.py"}
    assert c.sha(inspect.getsource(_product_mode_abi).encode()) == VENDORED_MODE_SHA256


@pytest.mark.parametrize("operation", sorted(PRODUCT["operations"]))
def test_tabelas_de_adapter_do_keeper_batem_com_o_abi_de_modo_do_produto(operation):
    assert set(lc.ADAPTER_INPUTS[operation].split()) == PRODUCT["inputs"][operation]
    assert lc.ADAPTER_STAGES[operation] == {PRODUCT["operations"][operation][1]}
    assert lc.ADAPTER_OBSERVATIONS[operation] == PRODUCT["observations"][operation]


def test_oito_sessoes_de_promotion_sao_as_operacoes_de_modo_do_produto():
    from fixtures.cnesdata_delivery_lifecycle import MODE_SESSION_VECTORS
    promotion = {name: phase for name, (_, _, context, phase) in lc.MODE_SESSION_OPERATIONS.items() if context == "promotion"}
    assert promotion == {name: mode for name, (mode, _) in PRODUCT["operations"].items()}
    vectors = {vector["operation"]: vector for vector in MODE_SESSION_VECTORS if vector["operation"] in promotion}
    assert set(vectors) == set(promotion)
    for name, vector in vectors.items():
        assert lc.mode_session(vector["binding"], "promotion")["session_name"] == vector["session_name"]
        assert vector["binding"]["phase"] == promotion[name]


def _mode_case(operation, *, stage=None):
    from test_cnesdata_application_gate import _adapter_case
    request, owner, window, _ = _adapter_case("closed-ready")
    start, deadline = MODE_WINDOWS[stage or PRODUCT["operations"][operation][1]]
    window.update(stage=stage or PRODUCT["operations"][operation][1], admitted_at=start, deadline=deadline)
    inputs = {name: c.canonical({"fixture_only": name}) for name in sorted(PRODUCT["inputs"][operation])}
    request |= {"operation": operation,
                "stage": {key: value for key, value in window.items() if key not in lc.application_identity(owner)},
                "inputs": {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in inputs.items()}}
    return request, owner, window, inputs


def _validate_request(request, owner, window, inputs):
    return lc.validate_adapter_request(c.canonical(request), operation=request["operation"], owner=owner, window=window,
                                       inputs=inputs, activation_sha256=request["activation_sha256"])


@pytest.mark.parametrize("operation", sorted(PRODUCT["operations"]))
def test_request_de_modo_e_aceito_so_no_estagio_do_proprio_modo(operation):
    request, owner, window, inputs = _mode_case(operation)
    assert _validate_request(request, owner, window, inputs) == request
    other = next(stage for stage in MODE_WINDOWS if stage != window["stage"])
    request, owner, window, inputs = _mode_case(operation, stage=other)
    with pytest.raises(ValueError, match="^adapter original stage$"):
        _validate_request(request, owner, window, inputs)


def _mode_journal(mode, *, checks=(), change=None):
    from tools.cnesdata_delivery.application_gate import AdapterJournal
    request, owner, window, inputs = _mode_case(mode + "-observe")

    class Guard:
        def check(self, seconds=0):
            return None
    journal = AdapterJournal(c.canonical(request), operation=request["operation"], owner=owner, window=window,
                             inputs=inputs, activation_sha256=request["activation_sha256"], guard=Guard())
    raw = PRODUCT["observation"](mode, list(checks), request, inputs)
    if change is not None:
        value = json.loads(raw)
        change(value)
        raw = c.canonical(value)
    journal.observe("mode", raw)
    return journal, owner, raw


def _keeper(*journals):
    from test_cnesdata_application_gate import _accepted_terminal_case
    keeper, _ = _accepted_terminal_case()
    for journal in journals:
        keeper.attach(journal)
    return keeper


def _mode_validator(keeper, mode):
    from tools.cnesdata_delivery import application_gate as ag
    return ag.TERMINAL_VALIDATORS[mode][1](keeper)


@pytest.mark.parametrize("mode", MODES)
def test_validador_de_modo_aceita_so_a_observacao_original_do_journal_do_observe(mode):
    journal, owner, raw = _mode_journal(mode)
    source = {"mode": c.sha(raw)}
    result = _mode_validator(_keeper(journal), mode)(source, owner=owner, window={"stage": "final"}, observations={})
    assert result == {"sha256": c.sha(c.canonical(source)), "facts": {"accepted": True}}


@pytest.mark.parametrize("mode", MODES)
def test_validador_de_modo_reporta_a_recusa_do_produto_sem_inventar_aceite(mode):
    journal, owner, raw = _mode_journal(mode, checks=["canary=schema"])
    result = _mode_validator(_keeper(journal), mode)({"mode": c.sha(raw)}, owner=owner, window={}, observations={})
    assert result["facts"] == {"accepted": False}


def test_cada_modo_le_o_proprio_journal_embora_os_tres_observes_tenham_o_mesmo_kind():
    found = {mode: _mode_journal(mode) for mode in MODES}
    keeper = _keeper(*(journal for journal, _, _ in found.values()))
    latest = keeper._latest_observation_bytes()
    assert [c.sha(raw) for _, _, raw in found.values() if c.sha(raw) in latest] == [c.sha(found["audit"][2])]
    for mode, (_, owner, raw) in found.items():
        facts = _mode_validator(keeper, mode)({"mode": c.sha(raw)}, owner=owner, window={}, observations=latest)["facts"]
        assert facts == {"accepted": True}


def _drop_input(value):
    value["commitments"].pop("readbacks")


MUTATIONS = {
    "extra-field": (lambda v: v.update(freeze=True), "^closed object fields$"),
    "missing-field": (lambda v: v.pop("checks"), "^closed object fields$"),
    "version-bool": (lambda v: v.update(version=True), "^terminal source kind=unit$"),
    "version-2": (lambda v: v.update(version=2), "^terminal source kind=unit$"),
    "other-mode": (lambda v: v.update(kind="recovery"), "^terminal source kind=unit$"),
    "accepted-with-checks": (lambda v: v.update(checks=["canary=schema"]), "^terminal mode verdict$"),
    "refused-without-checks": (lambda v: v.update(accepted=False), "^terminal mode verdict$"),
    "accepted-type": (lambda v: v.update(accepted="true", checks=[]), "^terminal mode verdict$"),
    "checks-unsorted": (lambda v: v.update(accepted=False, checks=["b", "a"]), "^terminal mode verdict$"),
    "checks-type": (lambda v: v.update(accepted=False, checks=[1]), "^terminal mode verdict$"),
    "commitment-input": (lambda v: v["commitments"].update(readbacks="0" * 64), "^terminal mode commitments$"),
    "commitment-missing": (_drop_input, "^terminal mode commitments$"),
    "commitment-extra": (lambda v: v["commitments"].update(foreign="0" * 64), "^terminal mode commitments$"),
    "commitment-owner": (lambda v: v["commitments"].update(owner="0" * 64), "^terminal mode commitments$"),
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_validador_de_modo_recusa_observacao_fora_da_forma_ou_dos_compromissos(mutation):
    change, message = MUTATIONS[mutation]
    journal, owner, raw = _mode_journal("unit", change=change)
    with pytest.raises(ValueError, match=message):
        _mode_validator(_keeper(journal), "unit")({"mode": c.sha(raw)}, owner=owner, window={}, observations={})


@pytest.mark.parametrize("case", ["no-journal", "two-journals", "other-bytes", "source-fields", "owner"])
def test_validador_de_modo_recusa_fonte_que_nao_e_o_original_unico_do_journal(case):
    journal, owner, raw = _mode_journal("unit")
    journals, source = [journal], {"mode": c.sha(raw)}
    if case == "no-journal":
        journals = [_mode_journal("recovery")[0]]
    if case == "two-journals":
        journals.append(_mode_journal("unit", checks=["canary=schema"])[0])
    if case == "other-bytes":
        source = {"mode": c.sha(raw + b" ")}
    if case == "source-fields":
        source |= {"extra": c.sha(raw)}
    if case == "owner":
        owner = owner | {"owner_sha256": "0" * 64}
    message = {"no-journal": "^terminal mode journal mode=unit$", "two-journals": "^terminal mode journal mode=unit$",
               "other-bytes": "^terminal mode source$", "source-fields": "^closed object fields$",
               "owner": "^terminal mode owner$"}[case]
    with pytest.raises(ValueError, match=message):
        _mode_validator(_keeper(*journals), "unit")(source, owner=owner, window={}, observations={})


def test_registro_de_producao_tem_os_validadores_de_modo_com_rotulo_do_produto():
    from tools.cnesdata_delivery import application_gate as ag
    assert {kind: ag.TERMINAL_VALIDATORS[kind][0] for kind in MODES} == {kind: "product-mode-" + kind for kind in MODES}
    assert {kind: ag.TERMINAL_SOURCE_ROLES[kind] for kind in MODES} == dict.fromkeys(MODES, "mode")
