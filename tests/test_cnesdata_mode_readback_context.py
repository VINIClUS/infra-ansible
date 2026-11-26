"""P16b c-1124-p16b-next item 2 (ruling 5): ModeReadback with durable <mode>-readbacks receipts and a verified handoff."""
import json
import time
from email.utils import formatdate

import pytest

from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401

from test_cnesdata_mode_readback import RESOURCES, _responses
from test_cnesdata_mode_stages import _lease_journal, _mode_world
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery import lifecycle_runtime as lr

GOVERNANCE = {"evidence_bucket": "synthetic-evidence", "evidence_prefix": "cnesdata/prod/evidence/",
              "account_id": "111122223333", "role": "application"}
SOURCE = ag.mode_input_source
INTENT_FIELDS = {"schema_version", "operation", "owner", "caller", "checkpoint_sha256", "sequence", "previous",
                 "role_session_sha256", "call"}


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


class _Exists(Exception):
    def __init__(self):
        super().__init__("exists")
        self.response = {"Error": {"Code": "PreconditionFailed"}}


class _Store:
    def __init__(self, broken=None):
        self.objects, self.broken = {}, broken

    def get(self, bucket, key, *, maximum, absent=False):
        assert bucket == GOVERNANCE["evidence_bucket"]
        return self.objects.get(key), "etag"

    def put(self, bucket, key, raw):
        if self.broken is not None and key.endswith(self.broken):
            raise TimeoutError("evidence write lost")
        if key in self.objects:
            raise _Exists()
        self.objects[key] = raw


def _metadata():
    return {"RequestId": "native-id", "HTTPStatusCode": 200, "HTTPHeaders": {"date": formatdate(time.time(), usegmt=True)}}


class _Client:
    KEYS = {"describe_state_machine": "state_machine", "get_schedule": "schedules",
            "describe_task_definition": "task_definitions", "describe_alarms": "alarms"}

    def __init__(self, mode, fail=None, during=None):
        self.mode, self.fail, self.during, self.calls = mode, fail, during, []

    def call(self, service, operation, **parameters):
        self.calls.append((service, operation, parameters))
        if self.during is not None:
            self.during(len(self.calls))
        if self.fail == len(self.calls):
            raise TimeoutError("native response lost")
        family = self.KEYS[operation]
        key = family if family == "state_machine" else f"{family}.{self.mode}"
        return json.loads(json.dumps(_responses(self.mode)[key])) | {"ResponseMetadata": _metadata()}


def _world(monkeypatch):
    world = _mode_world(monkeypatch)
    record = world.keeper.lease.check()
    return world, lc.owner_binding(record), record["lifecycle"]


def _readback(monkeypatch, mode="unit", code=None, binding=None, **client):
    world, owner, window = _world(monkeypatch)
    request = _mb().mode_readback_request(owner, window, mode)
    store, native = _Store(), _Client(mode, **client)
    session = _mb()._ModeSession(native, "c" * 64, {"resources": RESOURCES}, world.clock.value + 600,
                                 binding or c.sha(c.canonical(request)), None,
                                 code=code or lc.MODE_SESSION_OPERATIONS[mode + "-observe"][0], alias="mode_observe")
    readback = _mb().ModeReadback(store, GOVERNANCE, session, guard=ag.KeeperGuard(world.keeper), mode=mode,
                                  clock=lambda: world.clock.value)
    return readback, world, store, native, request


def _keys(request, sequence):
    return lr.closed_ready_evidence_keys(GOVERNANCE, owner=request["owner"], caller=request["caller"],
                                         checkpoint_sha256=request["checkpoint_sha256"], sequence=sequence,
                                         operation=request["operation"])


def test_readback_le_o_conjunto_fechado_com_recibo_duravel_por_chamada(monkeypatch):
    readback, world, store, native, request = _readback(monkeypatch)
    raw = readback.read()
    assert raw == _mb().mode_readback_bytes("unit", RESOURCES, _responses("unit"))
    assert [(call["service"], call["operation"], call["parameters"]) for call in _mb().mode_readback_calls("unit", RESOURCES)] \
        == native.calls
    assert len(store.objects) == 3 * len(native.calls) and request["operation"] == "unit-readbacks"
    assert any(item is readback for item in world.keeper._contexts) and world.keeper.uncertainty() == []
    assert readback._observations == [{"kind": "readbacks", "sha256": c.sha(raw), "size": len(raw)}]


def test_cadeia_comeca_em_zero_encadeia_o_recibo_anterior_e_fecha_o_intent(monkeypatch):
    readback, world, store, native, request = _readback(monkeypatch)
    readback.read()
    previous = None
    for sequence, call in enumerate(_mb().mode_readback_calls("unit", RESOURCES)):
        keys = _keys(request, sequence)
        intent = c.loads(store.objects[keys["intent"]], canonical=True)
        assert set(intent) == INTENT_FIELDS and intent["schema_version"] == 3
        assert intent["operation"] == "unit-readbacks" and intent["sequence"] == sequence
        assert intent["previous"] == previous and intent["checkpoint_sha256"] == world.keeper.lease.check()["lifecycle"][
            "checkpoint_sha256"]
        assert intent["role_session_sha256"] == "c" * 64 and intent["call"] == {
            "role": "mode_observe", "service": call["service"], "operation": call["operation"], "parameters": call["parameters"]}
        previous = c.sha(store.objects[keys["receipt"]])
    assert readback.head == previous


def test_entrega_rele_a_cadeia_e_devolve_os_bytes_da_observacao(monkeypatch):
    readback, _, _, _, _ = _readback(monkeypatch, "recovery")
    raw = readback.read()
    assert readback.original() == raw == _mb().mode_readback_bytes("recovery", RESOURCES, _responses("recovery"))


def _adapter_intent(store, keys):
    intent = c.loads(store.objects[keys["intent"]], canonical=True)
    intent.pop("previous")
    intent |= {"previous_receipt_sha256": None, "adapter_request_sha256": "1" * 64, "activation_sha256": "2" * 64,
               "prepared_sha256": "3" * 64}
    return c.canonical(intent)


def _tamper(case, store, request, readback):
    first, second = _keys(request, 0), _keys(request, 1)
    if case == "recibo-removido":
        del store.objects[second["receipt"]]
    if case == "recibos-trocados":
        for name in ("intent", "response", "receipt"):
            store.objects[first[name]], store.objects[second[name]] = store.objects[second[name]], store.objects[first[name]]
    if case == "corpo-adulterado":
        body = c.loads(store.objects[first["response"]], canonical=True)
        body["definition"] = json.dumps({"StartAt": "other"})
        store.objects[first["response"]] = c.canonical(body)
    if case == "cabeca-velha":
        readback.head = c.sha(store.objects[first["receipt"]])
    if case == "intent-do-adapter":
        store.objects[first["intent"]] = _adapter_intent(store, first)
    if case == "intent-com-campo-extra":
        intent = c.loads(store.objects[first["intent"]], canonical=True) | {"extra": 1}
        store.objects[first["intent"]] = c.canonical(intent)
    if case == "intent-de-outra-operacao":
        intent = c.loads(store.objects[first["intent"]], canonical=True) | {"operation": "unit-start"}
        store.objects[first["intent"]] = c.canonical(intent)
    if case == "outra-sessao":
        intent = c.loads(store.objects[first["intent"]], canonical=True) | {"role_session_sha256": "d" * 64}
        store.objects[first["intent"]] = c.canonical(intent)


@pytest.mark.parametrize("case", ["recibo-removido", "recibos-trocados", "corpo-adulterado", "cabeca-velha",
                                  "intent-do-adapter", "intent-com-campo-extra", "intent-de-outra-operacao", "outra-sessao"])
def test_entrega_recusa_cadeia_quebrada(monkeypatch, case):
    readback, _, store, _, request = _readback(monkeypatch)
    readback.read()
    _tamper(case, store, request, readback)
    with pytest.raises(ValueError, match="^mode readback chain$"):
        readback.original()


@pytest.mark.parametrize("operation", ["unit-readbacks", "recovery-readbacks", "audit-readbacks"])
def test_namespace_de_readbacks_e_fechado_nos_tres_modos(operation):
    from test_cnesdata_mode_session_sts import _journal
    owner = _journal("unit-seed")[1] | {"owner_sha256": "a" * 64}
    identity = lc.application_identity(owner, required=True)
    owner = {key: owner[key] for key in [*lc.OWNER_FIELDS, "owner_sha256"]}
    keys = lr.closed_ready_evidence_keys(GOVERNANCE, owner=owner, caller=identity, checkpoint_sha256="e" * 64, sequence=0,
                                         operation=operation)
    assert all("/" + operation + "/" in key for key in keys.values())
    with pytest.raises(ValueError, match="^fence evidence operation$"):
        lr.closed_ready_evidence_keys(GOVERNANCE, owner=owner, caller=identity, checkpoint_sha256="e" * 64, sequence=0,
                                      operation="drill-readbacks")


@pytest.mark.parametrize("change", ["codigo", "binding", "modo"])
def test_sessao_de_outro_codigo_binding_ou_modo_recusa_antes_do_io(monkeypatch, change):
    kwargs = {"codigo": {"code": "ux"}, "binding": {"binding": "9" * 64}, "modo": {}}[change]
    if change == "modo":
        world, owner, window = _world(monkeypatch)
        session = _mb()._ModeSession(_Client("unit"), "c" * 64, {"resources": RESOURCES}, world.clock.value + 600,
                                     "9" * 64, None, code="do", alias="mode_observe")
        with pytest.raises(ValueError, match="^mode readback original context$"):
            _mb().ModeReadback(_Store(), GOVERNANCE, session, guard=ag.KeeperGuard(world.keeper), mode="readiness")
        return
    with pytest.raises(ValueError, match="^mode readback original context$"):
        _readback(monkeypatch, **kwargs)


def test_falha_entre_chamada_e_recibo_deixa_incerteza_e_segura_o_lease(monkeypatch):
    readback, world, store, native, request = _readback(monkeypatch, fail=2)
    with pytest.raises(ValueError, match="^mode readback outcome unknown$"):
        readback.read()
    intent = c.sha(store.objects[_keys(request, 1)["intent"]])
    assert readback._failed and {"kind": "sdk-call", "reference_sha256": intent} in readback.unknown
    assert {"kind": "context-failed"} in world.keeper.uncertainty() and readback._observations == []
    with pytest.raises(ValueError):
        readback.original()


def test_recibo_nao_gravado_deixa_incerteza(monkeypatch):
    world, owner, window = _world(monkeypatch)
    request = _mb().mode_readback_request(owner, window, "unit")
    session = _mb()._ModeSession(_Client("unit"), "c" * 64, {"resources": RESOURCES}, world.clock.value + 600,
                                 c.sha(c.canonical(request)), None, code="uo", alias="mode_observe")
    store = _Store(broken="-receipt.json")
    readback = _mb().ModeReadback(store, GOVERNANCE, session, guard=ag.KeeperGuard(world.keeper), mode="unit",
                                  clock=lambda: world.clock.value)
    with pytest.raises(ValueError, match="^mode readback outcome unknown$"):
        readback.read()
    assert readback.unknown and world.keeper.uncertainty()


def test_checkpoint_trocado_entre_reserva_e_recibo_recusa(monkeypatch):
    world, owner, window = _world(monkeypatch)
    request = _mb().mode_readback_request(owner, window, "unit")
    original = world.keeper.lease.check

    def moved(count):
        record = original()
        stale = json.loads(json.dumps(record))
        stale["lifecycle"]["checkpoint_sha256"] = "f" * 64
        monkeypatch.setattr(world.keeper.lease, "check", lambda: stale)
    session = _mb()._ModeSession(_Client("unit", during=moved), "c" * 64, {"resources": RESOURCES},
                                 world.clock.value + 600, c.sha(c.canonical(request)), None, code="uo", alias="mode_observe")
    readback = _mb().ModeReadback(_Store(), GOVERNANCE, session, guard=ag.KeeperGuard(world.keeper), mode="unit",
                                  clock=lambda: world.clock.value)
    with pytest.raises(ValueError, match="^mode readback original checkpoint$"):
        readback.read()
    assert readback._failed and readback.unknown


def test_intent_ja_existente_nao_e_reexecutado(monkeypatch):
    readback, world, store, native, request = _readback(monkeypatch)
    store.objects[_keys(request, 0)["intent"]] = b"{}\n"
    with pytest.raises(ValueError, match="^mode readback replay$"):
        readback.read()
    assert native.calls == [] and readback._failed and world.keeper.uncertainty()


def test_readback_fora_da_janela_da_sessao_recusa_antes_do_io(monkeypatch):
    readback, world, store, native, request = _readback(monkeypatch)
    world.clock.value = readback.session.deadline - 20
    with pytest.raises(ValueError, match="^mode readback window$"):
        readback.read()
    assert native.calls == [] and store.objects == {}


def test_readback_le_uma_vez(monkeypatch):
    readback, _, _, native, _ = _readback(monkeypatch)
    readback.read()
    with pytest.raises(ValueError, match="^mode readback once$"):
        readback.read()
    assert len(native.calls) == 2


def test_keeper_com_readback_anexado_ainda_serve_o_journal_do_observe_e_as_origens_s(monkeypatch):
    readback, world, _, _, _ = _readback(monkeypatch)
    raw = readback.read()
    observe = _lease_journal("unit-observe", observations=[("mode", c.canonical({"fixture": "mode"}))])
    start = _lease_journal("recovery-start", inputs={"readbacks": raw})
    world.keeper.attach(observe)
    world.keeper.attach(start)
    assert ag._mode_journal(world.keeper, "unit") is observe
    assert world.keeper._latest_observation_bytes()[c.sha(raw)] == raw
    found = SOURCE(keeper=world.keeper, owner={}, window={}, operation="audit-observe", names=["recovery-readbacks"])
    assert found == {"recovery-readbacks": raw}


def test_attach_admite_o_readback_e_nao_outro_objeto(monkeypatch):
    world, _, _ = _world(monkeypatch)
    with pytest.raises(ValueError, match="^original adapter context$"):
        world.keeper.attach(object())


def _reseal(store, request, readback, sequence, intent=None, response=None, receipt=None):
    calls = _mb().mode_readback_calls(readback.mode, RESOURCES)
    previous = None if sequence == 0 else c.sha(store.objects[_keys(request, sequence - 1)["receipt"]])
    for index in range(sequence, len(calls)):
        keys = _keys(request, index)
        value = c.loads(store.objects[keys["intent"]], canonical=True) | {"previous": previous}
        body = store.objects[keys["response"]]
        if index == sequence:
            value = intent(value) if intent else value
            body = response(body) if response else body
        store.objects[keys["intent"]], store.objects[keys["response"]] = c.canonical(value), body
        seal = c.loads(store.objects[keys["receipt"]], canonical=True) | {
            "intent_sha256": c.sha(store.objects[keys["intent"]]), "response_sha256": c.sha(body)}
        store.objects[keys["receipt"]] = c.canonical(receipt(seal) if receipt and index == sequence else seal)
        previous = c.sha(store.objects[keys["receipt"]])
    readback.head = previous


def _adapter_shape(value):
    value = dict(value)
    value["previous_receipt_sha256"] = value.pop("previous")
    return value | {"adapter_request_sha256": "1" * 64, "activation_sha256": "2" * 64, "prepared_sha256": "3" * 64}


def _body(raw):
    value = c.loads(raw, canonical=True)
    value["definition"] = json.dumps({"StartAt": "other"})
    return c.canonical(value)


RESEALED = {
    "intent-do-adapter": {"intent": _adapter_shape},
    "intent-com-campo-extra": {"intent": lambda value: value | {"extra": 1}},
    "intent-de-outra-operacao": {"intent": lambda value: value | {"operation": "unit-start"}},
    "intent-de-outro-schema": {"intent": lambda value: value | {"schema_version": 1}},
    "intent-com-a-tag-do-closed-ready": {"intent": lambda value: value | {"schema_version": 2}},
    "outra-sessao": {"intent": lambda value: value | {"role_session_sha256": "d" * 64}},
    "outro-checkpoint": {"intent": lambda value: value | {"checkpoint_sha256": "e" * 64}},
    "outro-caller": {"intent": lambda value: value | {"caller": value["caller"] | {"caller_binding_sha256": "0" * 64}}},
    "outra-chamada": {"intent": lambda value: value | {"call": value["call"] | {"role": "mode_seed"}}},
    "outra-sequencia": {"intent": lambda value: value | {"sequence": 5}},
    "previous-falso": {"intent": lambda value: value | {"previous": "0" * 64}},
    "corpo-resselado": {"response": _body},
    "recibo-de-outro-intent": {"receipt": lambda seal: seal | {"intent_sha256": "0" * 64}},
    "recibo-de-outra-resposta": {"receipt": lambda seal: seal | {"response_sha256": "0" * 64}},
    "recibo-com-campo-extra": {"receipt": lambda seal: seal | {"extra": 1}},
    "recibo-de-outro-schema": {"receipt": lambda seal: seal | {"schema_version": 1}},
}


@pytest.mark.parametrize("sequence", [0, 1])
def test_cadeia_ressalada_sem_mudanca_e_aceita(monkeypatch, sequence):
    readback, _, store, _, request = _readback(monkeypatch)
    raw = readback.read()
    _reseal(store, request, readback, sequence)
    assert readback.original() == raw


@pytest.mark.parametrize("case", sorted(RESEALED))
def test_cadeia_ressalada_com_elo_fora_da_forma_recusa(monkeypatch, case):
    readback, _, store, _, request = _readback(monkeypatch)
    readback.read()
    _reseal(store, request, readback, 0, **RESEALED[case])
    with pytest.raises(ValueError, match="^mode readback chain$"):
        readback.original()


def test_checkpoint_trocado_antes_da_leitura_recusa_sem_io(monkeypatch):
    readback, world, store, native, _ = _readback(monkeypatch)
    stale = json.loads(json.dumps(world.keeper.lease.check()))
    stale["lifecycle"]["checkpoint_sha256"] = "f" * 64
    monkeypatch.setattr(world.keeper.lease, "check", lambda: stale)
    with pytest.raises(ValueError, match="^mode readback original checkpoint$"):
        readback.read()
    assert native.calls == [] and store.objects == {}


def test_sessao_de_outro_alias_recusa(monkeypatch):
    world, owner, window = _world(monkeypatch)
    request = _mb().mode_readback_request(owner, window, "unit")
    session = _mb()._ModeSession(_Client("unit"), "c" * 64, {"resources": RESOURCES}, world.clock.value + 600,
                                 c.sha(c.canonical(request)), None, code="uo", alias="mode_seed")
    with pytest.raises(ValueError, match="^mode readback original context$"):
        _mb().ModeReadback(_Store(), GOVERNANCE, session, guard=ag.KeeperGuard(world.keeper), mode="unit")


@pytest.mark.parametrize(("change", "message"), [({"HTTPStatusCode": 500}, "mode readback native metadata"),
                                                 ({"RequestId": ""}, "mode readback native metadata"),
                                                 ({"HTTPHeaders": {"date": formatdate(time.time() - 60, usegmt=True)}},
                                                  "mode readback native clock")])
def test_resposta_nativa_fora_da_metadata_envenena(monkeypatch, change, message):
    readback, world, store, native, _ = _readback(monkeypatch)
    original = native.call

    def call(service, operation, **parameters):
        response = original(service, operation, **parameters)
        response["ResponseMetadata"] |= change
        return response
    monkeypatch.setattr(native, "call", call)
    with pytest.raises(ValueError, match=f"^{message}$"):
        readback.read()
    assert readback._failed and readback.unknown


def test_evidencia_relida_diferente_envenena(monkeypatch):
    readback, world, store, native, _ = _readback(monkeypatch)
    monkeypatch.setattr(store, "get", lambda bucket, key, *, maximum, absent=False: (b"{}\n", "etag"))
    with pytest.raises(ValueError, match="^mode readback evidence readback$"):
        readback.read()
    assert readback._failed and readback.unknown and native.calls == []


def test_guard_perdido_depois_das_leituras_nao_registra_a_observacao(monkeypatch):
    readback, world, store, native, _ = _readback(monkeypatch)
    count = {"checks": 0}
    original = readback._guard.check

    def check(seconds=0):
        count["checks"] += 1
        if count["checks"] > 3 * len(_mb().mode_readback_calls("unit", RESOURCES)):
            raise ValueError("lease lost")
        return original(seconds)
    monkeypatch.setattr(readback._guard, "check", check)
    with pytest.raises(ValueError, match="^lease lost$"):
        readback.read()
    assert readback._observations == [] and readback._failed and len(native.calls) == 2


def test_entrega_recusa_depois_de_falha_do_contexto(monkeypatch):
    readback, _, _, _, _ = _readback(monkeypatch)
    readback.read()

    def lost(seconds=0):
        raise ValueError("lease lost")
    monkeypatch.setattr(readback._guard, "check", lost)
    with pytest.raises(ValueError, match="^lease lost$"):
        readback.guard()
    with pytest.raises(ValueError, match="^mode readback original observation$"):
        readback.original()


def test_intent_liga_o_compromisso_da_sessao_que_serviu(monkeypatch):
    world, owner, window = _world(monkeypatch)
    request = _mb().mode_readback_request(owner, window, "unit")
    store = _Store()
    session = _mb()._ModeSession(_Client("unit"), "b" * 64, {"resources": RESOURCES}, world.clock.value + 600,
                                 c.sha(c.canonical(request)), None, code="uo", alias="mode_observe")
    readback = _mb().ModeReadback(store, GOVERNANCE, session, guard=ag.KeeperGuard(world.keeper), mode="unit",
                                  clock=lambda: world.clock.value)
    raw = readback.read()
    intent = c.loads(store.objects[_keys(request, 0)["intent"]], canonical=True)
    assert intent["role_session_sha256"] == "b" * 64 and readback.original() == raw
