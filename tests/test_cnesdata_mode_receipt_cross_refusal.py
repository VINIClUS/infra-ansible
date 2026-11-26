"""P16b c-1125-p16b-pc: the readback receipt and the closed-ready receipt, both schema 2, refuse each other's objects."""
import pytest

from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401

from test_cnesdata_application_gate import _durable_closed_ready_case
from test_cnesdata_mode_readback_context import _keys, _readback
from tools.cnesdata_delivery import contract as c

DATE = "Thu, 09 Oct 2025 08:53:20 GMT"


def _closed_ready_receipt(intent, response):
    return {"schema_version": 2, "intent_sha256": c.sha(intent), "response_sha256": c.sha(response),
            "call_receipt": {"sequence": 0, "request_sha256": "1" * 64, "role_session_sha256": "2" * 64,
                             "guard_before_sha256": "3" * 64, "started_monotonic_ns": 0, "response_sha256": c.sha(response),
                             "request_id": "aws-id", "server_date": DATE, "ended_monotonic_ns": 1,
                             "guard_after_sha256": "3" * 64}}


def _closed_ready_intent(intent, response):
    value = c.loads(intent, canonical=True)
    value.pop("previous")
    return value | {"schema_version": 2, "previous_receipt_sha256": None, "adapter_request_sha256": "1" * 64,
                    "activation_sha256": "2" * 64, "prepared_sha256": "3" * 64}


def _readback_side(monkeypatch, forge):
    readback, _, store, _, request = _readback(monkeypatch)
    readback.read()
    last = _keys(request, _last(store, request))
    forged = c.canonical(forge(store.objects[last["intent"]], store.objects[last["response"]]))
    store.objects[last["receipt"]] = forged
    readback.head = c.sha(forged)
    with pytest.raises(ValueError, match="^mode readback chain$"):
        readback.original()


def _last(store, request):
    sequence = 0
    while _keys(request, sequence + 1)["receipt"] in store.objects:
        sequence += 1
    return sequence


def _closed_ready_side(monkeypatch):
    create, store, native = _durable_closed_ready_case(monkeypatch)
    ledger, journal = create()
    ledger.reserve()
    ticket = journal.begin_sdk_call(c.canonical(native), role_session_sha256="2" * 64)
    response = b'{"Item":{"state":{"S":"CLOSED"}}}\n'
    ledger.complete(response, journal.complete_sdk_call(ticket, response, request_id="aws-id", server_date=DATE))
    receipt = next(key for key in store.objects if key.endswith("-receipt.json"))
    store.objects[receipt] = c.canonical({"schema_version": 2, "intent_sha256": ledger.intent_sha256,
                                          "response_sha256": c.sha(response), "request_id": "aws-id", "server_date": DATE})
    restarted, _ = create()
    with pytest.raises(ValueError, match="^closed object fields$"):
        restarted.reserve()


CASES = {
    "recibo-do-closed-ready-em-readbacks": lambda monkeypatch: _readback_side(monkeypatch, _closed_ready_receipt),
    "intent-do-closed-ready-como-recibo-de-readback": lambda monkeypatch: _readback_side(monkeypatch, _closed_ready_intent),
    "recibo-de-readback-no-closed-ready": _closed_ready_side,
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_recibos_de_schema_2_recusam_o_objeto_do_outro_verificador(monkeypatch, case):
    CASES[case](monkeypatch)
