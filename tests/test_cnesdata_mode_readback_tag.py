"""P16b ruling 5a item 1: readback intents carry tag 3 only in a -readbacks namespace; closed-ready keeps tag 2."""
import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_runtime as lr

GOVERNANCE = {"evidence_bucket": "synthetic-evidence", "evidence_prefix": "cnesdata/prod/evidence/",
              "account_id": "111122223333", "role": "application"}
OWNER = {"repository": c.REPOSITORY, "source_sha": "a" * 40, "run_id": 4242, "run_attempt": 1, "release_sha256": "b" * 64,
         "generation": 3, "session_sha256": "c" * 64, "owner_sha256": "d" * 64}
CALLER = {"application_purpose": "promotion", "context_kind": "promotion", "caller_binding_sha256": "e" * 64}
CALL = {"role": "mode_observe", "service": "scheduler", "operation": "get_schedule", "parameters": {"Name": "x"}}
READBACKS = ("unit-readbacks", "recovery-readbacks", "audit-readbacks")


def _readback(operation="unit-readbacks", **changes):
    value = {"schema_version": 3, "operation": operation, "owner": OWNER, "caller": CALLER, "checkpoint_sha256": "f" * 64,
             "sequence": 0, "previous": None, "role_session_sha256": "1" * 64, "call": CALL}
    return value | changes


def _adapter(operation="closed-ready", **changes):
    value = {"schema_version": 2, "operation": operation, "owner": OWNER, "sequence": 0, "previous_receipt_sha256": None,
             "caller": CALLER, "adapter_request_sha256": "2" * 64, "checkpoint_sha256": "f" * 64,
             "activation_sha256": "3" * 64, "prepared_sha256": "4" * 64, "role_session_sha256": "1" * 64, "call": CALL}
    return value | changes


def _without(value, key):
    return {name: item for name, item in value.items() if name != key}


@pytest.mark.parametrize("operation", READBACKS)
def test_intent_de_readback_com_tag_3_e_admitido_nos_tres_namespaces(operation):
    value = _readback(operation)
    assert lr.evidence_intent(c.canonical(value), operation=operation) == value


@pytest.mark.parametrize("operation", ["closed-ready", "inventory", "publish-static", "recovery-start"])
def test_intent_do_adapter_com_tag_2_continua_admitido_no_namespace_da_operacao(operation):
    value = _adapter(operation)
    assert lr.evidence_intent(c.canonical(value), operation=operation) == value


REFUSALS = {
    "forma-do-adapter-em-readbacks": ("unit-readbacks", _adapter("unit-readbacks")),
    "forma-de-readback-em-operacao": ("closed-ready", _readback("closed-ready")),
    "tag-2-com-a-forma-de-readback": ("unit-readbacks", _readback(schema_version=2)),
    "tag-3-com-a-forma-do-adapter": ("closed-ready", _adapter(schema_version=3)),
    "subconjunto-em-readbacks": ("unit-readbacks", _without(_readback(), "previous")),
    "subconjunto-em-operacao": ("closed-ready", _without(_adapter(), "prepared_sha256")),
    "intent-de-outro-namespace": ("unit-readbacks", _readback("audit-readbacks")),
}


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_intent_fora_da_forma_do_proprio_namespace_recusa(case):
    operation, value = REFUSALS[case]
    with pytest.raises(ValueError):
        lr.evidence_intent(c.canonical(value), operation=operation)


@pytest.mark.parametrize("operation", ["drill-readbacks", "unit-readback", "readbacks"])
def test_namespace_fora_dos_tres_recusa(operation):
    with pytest.raises(ValueError, match="^fence evidence operation$"):
        lr.evidence_intent(c.canonical(_readback(operation)), operation=operation)
    with pytest.raises(ValueError, match="^fence evidence operation$"):
        lr.closed_ready_evidence_keys(GOVERNANCE, owner=OWNER, caller=CALLER, checkpoint_sha256="f" * 64, sequence=0,
                                      operation=operation)


@pytest.mark.parametrize("operation, tag", [*[(name, 3) for name in READBACKS], ("closed-ready", 2), ("recovery-start", 2),
                                            ("inventory", 2)])
def test_chaves_dos_readbacks_hasheiam_com_3_e_as_do_closed_ready_nao_mudam(operation, tag):
    digest = c.sha(c.canonical({"schema_version": tag, "operation": operation, "owner": OWNER, "caller": CALLER,
                                "checkpoint_sha256": "f" * 64, "sequence": 7}))
    keys = lr.closed_ready_evidence_keys(GOVERNANCE, owner=OWNER, caller=CALLER, checkpoint_sha256="f" * 64, sequence=7,
                                         operation=operation)
    assert all(keys[name].endswith("sdk-" + digest[:40] + "-" + name + ".json") for name in ("intent", "response", "receipt"))
