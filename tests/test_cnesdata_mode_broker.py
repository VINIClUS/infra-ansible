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


OBSERVES = ("unit-observe", "recovery-observe", "audit-observe")
FENCE_READS = (("ENV#prod#FENCE", "FENCE"), ("ENV#prod#SEMAPHORE", "UNIT"))


def _scope():
    from test_cnesdata_application_gate import CLOSE_SCOPE
    return dict(CLOSE_SCOPE)


def _observe_request(operation, stage=None):
    from test_cnesdata_mode_stages import _mode_case
    return _mode_case(operation, stage=stage)[0]


def _fence_read(pk, sk, **parameters):
    table = _scope()["control_table_arn"].rsplit("/", 1)[1]
    return {"role": "fence_operator", "service": "dynamodb", "operation": "get_item",
            "parameters": {"TableName": table, "Key": {"pk": {"S": pk}, "sk": {"S": sk}}, "ConsistentRead": True} | parameters}


@pytest.mark.parametrize("operation", OBSERVES)
@pytest.mark.parametrize("pk, sk", FENCE_READS)
def test_observe_admite_so_a_leitura_forte_de_fence_e_semaphore_no_proprio_estagio(operation, pk, sk):
    call = _fence_read(pk, sk)
    request = _observe_request(operation)
    assert lc.validate_fence_call(request=request, history=[], **call, **_scope()) == call["parameters"]
    assert lc.validate_mode_observe_call(request=request, **call, **_scope()) == call["parameters"]
    assert lc.FENCE_SDK_OPERATIONS[operation] == {("dynamodb", "get_item")}


def _observe_refusal(case):
    call, scope, request = _fence_read(*FENCE_READS[0]), _scope(), _observe_request("unit-observe")
    if case == "describe":
        call |= {"service": "stepfunctions", "operation": "describe_execution",
                 "parameters": {"executionArn": scope["machine_arn"].replace(":stateMachine:", ":execution:") + ":" + "0" * 16,
                                "includedData": "METADATA_ONLY"}}
    elif case == "update":
        call["operation"] = "update_item"
    elif case == "role":
        call["role"] = "mode_observe"
    elif case == "eventual":
        call["parameters"]["ConsistentRead"] = False
    elif case == "attempts":
        call = _fence_read("ENV#prod#ATTEMPTS", "UNIT")
    elif case == "crossed":
        call = _fence_read("ENV#prod#FENCE", "UNIT")
    elif case == "table":
        call["parameters"]["TableName"] = "cnesdata-prod-other"
    elif case == "extra":
        call["parameters"]["ProjectionExpression"] = "pk"
    elif case == "scope-table":
        scope["control_table_arn"] = scope["control_table_arn"].replace("cnesdata-prod-", "other-")
    elif case == "scope-machine":
        scope["machine_arn"] += "-x"
    elif case == "stage":
        request = _observe_request("unit-observe", stage="phase-c-recovery")
    return call, scope, request


OBSERVE_REFUSALS = {"describe": "^mode observe finite SDK operation$", "update": "^mode observe finite SDK operation$",
                    "role": "^mode observe finite SDK operation$", "stage": "^mode observe finite SDK operation$",
                    "eventual": "^mode observe strong fence read$", "attempts": "^mode observe strong fence read$",
                    "crossed": "^mode observe strong fence read$", "table": "^mode observe strong fence read$",
                    "extra": "^closed object fields$", "scope-table": "^mode observe protected resource scope$",
                    "scope-machine": "^mode observe protected resource scope$"}


@pytest.mark.parametrize("case", sorted(OBSERVE_REFUSALS))
def test_observe_recusa_qualquer_chamada_fora_da_leitura_forte_do_fence(case):
    call, scope, request = _observe_refusal(case)
    with pytest.raises(ValueError, match=OBSERVE_REFUSALS[case]):
        lc.validate_fence_call(request=request, history=[], **call, **scope)


def test_politica_da_sessao_do_observe_e_so_o_getitem_da_sessao_do_fence():
    from tools.cnesdata_delivery import session_policy as sp
    table, machine = _scope()["control_table_arn"], _scope()["machine_arn"]
    full = sp.fence_session_policy(control_table_arn=table, execution_prefix=machine.replace(":stateMachine:", ":execution:") + ":",
                                   deadline=1900)
    observe = sp.fence_observe_session_policy(control_table_arn=table, deadline=1900)
    assert observe == {"Version": "2012-10-17", "Statement": [full["Statement"][0]]}
    assert c.canonical(observe) == c.canonical({"Version": "2012-10-17", "Statement": [full["Statement"][0]]})


@pytest.mark.parametrize("change, message", [({"control_table_arn": "arn:aws:dynamodb:us-east-2:111122223333:table/other"},
                                               "^fence session table$"),
                                              ({"deadline": 1900.5}, "integer")])
def test_politica_da_sessao_do_observe_recusa_escopo_inexato(change, message):
    from tools.cnesdata_delivery import session_policy as sp
    with pytest.raises(ValueError, match=message):
        sp.fence_observe_session_policy(**{"control_table_arn": _scope()["control_table_arn"], "deadline": 1900} | change)


def _observe_session_case(monkeypatch, *, operation="unit-observe", mutation=None):
    from test_cnesdata_application_gate import _fence_sdk_boundary_case
    from test_cnesdata_mode_stages import _mode_case
    _, args, calls, native = _fence_sdk_boundary_case(monkeypatch)
    request, owner, window, inputs = _mode_case(operation)
    window.update(admitted_at=1500, deadline=min(window["fixed_deadline"], 1500 + window["windows"]["stages"][window["stage"]]))
    request["stage"] = {key: value for key, value in window.items() if key not in lc.application_identity(owner)}
    now = window["admitted_at"] + 30 - (mutation == "future-admission") * 31
    now = window["deadline"] - 40 if mutation == "late" else now
    monkeypatch.setattr(ag.time, "time", lambda: now)

    class Guard:
        def check(self, seconds=0):
            return None
    journal = ag.AdapterJournal(c.canonical(request), operation=operation, owner=owner, window=window, inputs=inputs,
                                activation_sha256=request["activation_sha256"], guard=Guard())
    stage = journal._request["stage"]
    if mutation == "deadline":
        stage["deadline"] -= 1
    if mutation == "other-stage":
        stage["stage"] = "phase-c-recovery" if operation == "unit-observe" else "unit"
    if mutation == "open":
        stage["close"] = None
    if mutation == "decision":
        stage["decision"] = {"choice_at": now}
    scope = {key: args["scope"][key] for key in ("account", "control_table_arn", "machine_arn")}
    if mutation == "members":
        scope["members"] = []
    if mutation == "no-get-grant":
        args["role"]["policy"]["Statement"].pop(0)
    args.update(journal=journal, scope=scope, clock=lambda: now, credential_limit=now + 899 if mutation == "credential" else 3000)
    return args, calls, native, stage


OBSERVE_SESSION_REFUSALS = {
    "late": "^fence original mode stage/credential window$", "deadline": "^fence original mode stage/credential window$",
    "future-admission": "^fence original mode stage/credential window$",
    "credential": "^fence original mode stage/credential window$",
    "other-stage": "^fence original mode stage/credential window$", "open": "^fence original mode stage/credential window$",
    "decision": "^fence original mode stage/credential window$", "members": "^closed object fields$",
    "no-get-grant": "^fence original effective strong-read grant$"}


@pytest.mark.parametrize("operation", OBSERVES)
def test_sessao_do_fence_do_observe_e_so_leitura_ate_o_prazo_do_estagio_do_modo(monkeypatch, operation):
    from tools.cnesdata_delivery import session_policy as sp
    args, calls, native, stage = _observe_session_case(monkeypatch, operation=operation)
    session = ag._assume_fence_session(**args)
    assert session.scope == args["scope"] and session.deadline == stage["deadline"] and len(calls) == len(native) == 1
    expected = sp.fence_observe_session_policy(control_table_arn=args["scope"]["control_table_arn"], deadline=stage["deadline"])
    assert calls[0][2] == {"RoleArn": args["role"]["role_arn"], "RoleSessionName": args["role"]["session_name"],
                           "DurationSeconds": 900, "Policy": c.canonical(expected).decode().strip()}
    assert args["operation_session"].calls == [(operation, args["role"]["session_name"], stage)]


@pytest.mark.parametrize("mutation", sorted(OBSERVE_SESSION_REFUSALS))
def test_sessao_do_fence_do_observe_recusa_fora_da_janela_ou_do_escopo_sem_sts(monkeypatch, mutation):
    args, calls, native, _ = _observe_session_case(monkeypatch, mutation=mutation)
    with pytest.raises(ValueError, match=OBSERVE_SESSION_REFUSALS[mutation]):
        ag._assume_fence_session(**args)
    assert calls == native == [] and args["operation_session"].calls == []


class _Evidence:
    def __init__(self):
        self.objects, self.events = {}, []

    def get(self, bucket, key, *, maximum, absent=False):
        return self.objects.get(key), "etag"

    def put(self, bucket, key, raw):
        assert key not in self.objects
        self.events.append(key.rsplit("-", 1)[1])
        self.objects[key] = raw


def _fence_read_broker(monkeypatch):
    import time
    from email.utils import formatdate
    args, _, _, stage = _observe_session_case(monkeypatch)
    session = ag._assume_fence_session(**args)
    evidence, native = _Evidence(), []
    metadata = {"RequestId": "native-id", "HTTPStatusCode": 200, "HTTPHeaders": {"date": formatdate(time.time(), usegmt=True)}}

    def sdk(service, operation, **parameters):
        native.append((service, operation, parameters))
        return {"Item": {"pk": {"S": parameters["Key"]["pk"]["S"]}, "state": {"S": "CLOSED"}}, "ResponseMetadata": metadata}
    session.client.call = sdk
    broker = _mode_broker_module().FenceReadBroker(evidence, args["governance"], args["journal"], session,
                                                   prepared_sha256="3" * 64, clock=args["clock"])
    return broker, args["journal"], evidence, native


@pytest.mark.parametrize("pk, sk", FENCE_READS)
def test_broker_do_observe_faz_a_leitura_forte_com_evidencia_duravel(monkeypatch, pk, sk):
    broker, journal, evidence, native = _fence_read_broker(monkeypatch)
    frame = _fence_read(pk, sk) | {"kind": "call"}
    frame["parameters"]["TableName"] = "cnesdata-prod-control"
    reply, result = ag._adapter_message(c.canonical(frame), journal)
    assert result is None and reply == {"kind": "sdk-result", "value": {"Item": {"pk": {"S": pk}, "state": {"S": "CLOSED"}}}}
    assert evidence.events == ["intent.json", "response.json", "receipt.json"] and len(native) == 1
    assert len(journal.call_receipts) == 1 and broker.uncertainty == [] and journal.unknown == []
    assert type(broker) in ag._brokers() and type(broker) is not ag.ClosedReadyBroker


@pytest.mark.parametrize("change", ["describe", "eventual", "update"])
def test_broker_do_observe_recusa_chamada_fora_da_leitura_forte_antes_de_qualquer_io(monkeypatch, change):
    broker, journal, evidence, native = _fence_read_broker(monkeypatch)
    frame = _fence_read(*FENCE_READS[0]) | {"kind": "call"}
    frame["parameters"]["TableName"] = "cnesdata-prod-control"
    if change == "describe":
        frame |= {"service": "stepfunctions", "operation": "describe_execution",
                  "parameters": {"executionArn": "arn:aws:states:us-east-2:111122223333:execution:cnesdata-prod:" + "a" * 16,
                                 "includedData": "METADATA_ONLY"}}
    if change == "eventual":
        frame["parameters"]["ConsistentRead"] = False
    if change == "update":
        frame["operation"] = "update_item"
    with pytest.raises(ValueError, match="^mode observe (finite SDK operation|strong fence read)$"):
        ag._adapter_message(c.canonical(frame), journal)
    assert native == [] and evidence.objects == {} and journal.call_receipts == []


def test_clientes_do_broker_do_observe_sao_descartados(monkeypatch):
    broker, _, _, _ = _fence_read_broker(monkeypatch)
    ag._drop_operation_clients(broker)
    assert (broker.aws, broker.session.client, broker.session.evidence) == (None, None, None)
