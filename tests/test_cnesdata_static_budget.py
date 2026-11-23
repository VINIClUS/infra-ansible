"""Prazo do child no broker, folga do bloco das raizes e tetos de bytes do publish-static (#55, P15b)."""
import base64
import hashlib
import io

import pytest

from tools.cnesdata_delivery import contract as c

from test_cnesdata_static_stage import (ACTIVATION, BUCKET, BODIES, EVIDENCE_GOVERNANCE, INVALIDATION, PAIR, _Evidence,
                                        _Native, _dist, _frame, _journal, _put, _session)

LIST = ("observer", "s3", "ListObjectVersions", {"Bucket": BUCKET})


class _Clock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


def _broker(*, child=None, now=1505, dashboard=None):
    from tools.cnesdata_delivery import application_gate as ag
    journal, owner, window, inputs = _journal(rollback=PAIR, dashboard=dashboard)
    evidence, clock = _Evidence(), _Clock(now)
    clients = {"observer": _Native("observer", versions=PAIR), "normal": _Native("normal")}
    broker = ag.StaticBroker(evidence, EVIDENCE_GOVERNANCE, journal, _session(journal, clients, evidence), clock=clock)
    if child is not None:
        broker.admit_child(child)
    return ag, broker, journal, clients, evidence, clock


@pytest.mark.parametrize("offset, admitted", [(21, True), (20, False)])
def test_broker_admite_chamada_so_com_vinte_segundos_antes_do_prazo_do_child(offset, admitted):
    ag, broker, journal, clients, evidence, clock = _broker(child=1600)
    clock.value = 1600 - offset
    if admitted:
        ag._adapter_message(_frame(*LIST), journal)
        assert len(clients["observer"].calls) == 1
        return
    with pytest.raises(ValueError, match="^original finite SDK request/window$"):
        ag._adapter_message(_frame(*LIST), journal)
    assert clients["observer"].calls == [] and evidence.writes == []


def test_prazo_do_child_e_fixado_uma_vez_e_nunca_alarga_o_prazo_do_estagio():
    ag, broker, journal, clients, evidence, clock = _broker(child=1680 + 300)
    with pytest.raises(ValueError, match="^static child deadline$"):
        broker.admit_child(1600)
    clock.value = 1680 - 20
    with pytest.raises(ValueError, match="^original finite SDK request/window$"):
        ag._adapter_message(_frame(*LIST), journal)
    assert clients["observer"].calls == []


@pytest.mark.parametrize("remaining, admitted", [(101, True), (100, False)])
def test_primeiro_put_de_raiz_so_entra_com_folga_para_os_dois_pares_e_a_invalidacao(remaining, admitted):
    ag, broker, journal, clients, evidence, clock = _broker(child=1505 + remaining)
    assert ag.STATIC_ROOT_BLOCK_SECONDS == 5 * 20
    if admitted:
        ag._adapter_message(_frame(*_put("index.html")), journal)
        assert [call[1] for call in clients["normal"].calls] == ["put_object"]
        return
    with pytest.raises(ValueError, match=f"^static_roots=window_short remaining={remaining} required=100$"):
        ag._adapter_message(_frame(*_put("index.html")), journal)
    assert clients["normal"].calls == [] and evidence.writes == [] and journal.call_receipts == []


def test_depois_do_primeiro_put_de_raiz_o_bloco_segue_a_admissao_por_chamada():
    ag, broker, journal, clients, evidence, clock = _broker(child=1505 + 101)
    ag._adapter_message(_frame(*_put("index.html")), journal)
    clock.value = 1606 - 21
    for call in (("normal", "s3", "GetObject", {"Bucket": BUCKET, "Key": "index.html"}), _put("theme-init.js"),
                 ("normal", "s3", "GetObject", {"Bucket": BUCKET, "Key": "theme-init.js"}), INVALIDATION):
        ag._adapter_message(_frame(*call), journal)
    assert [call[1] for call in clients["normal"].calls] == ["put_object", "get_object", "put_object", "get_object",
                                                             "create_invalidation"]


def test_put_de_asset_nao_exige_a_folga_das_raizes():
    ag, broker, journal, clients, evidence, clock = _broker(child=1505 + 30)
    ag._adapter_message(_frame(*_put("assets/app.js")), journal)
    assert [call[1] for call in clients["normal"].calls] == ["put_object"]


def _run(monkeypatch, operation, *, seconds=77, dashboard=None):
    from test_cnesdata_application_gate import _prepare_stage_keeper
    from test_cnesdata_static_inputs import _inventory_journal
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store = _prepare_stage_keeper()
    if operation == "publish-static":
        journal, owner, window, inputs = _journal(dashboard=dashboard)
        aliases, activation = ("observer", "normal"), ACTIVATION
    else:
        journal, owner, window = _inventory_journal()
        inputs, aliases, activation = journal._inputs, ("observer",), b"release"
    request_raw = ag._operation_request(operation, owner=owner, window=window, inputs=inputs, activation=activation)
    seen = []

    def capability(*, journal, keeper):
        evidence = _Evidence()
        clients = {alias: _Native(alias) for alias in aliases}
        session = _session(journal, clients, evidence) if operation == "publish-static" else ag._StaticSession(
            clients, "9" * 64, {"account": EVIDENCE_GOVERNANCE["account_id"], "bucket": BUCKET, "plan": None},
            window["preparation_deadline"], c.sha(c.canonical(journal._request)), evidence)
        broker = ag.StaticBroker(evidence, EVIDENCE_GOVERNANCE, journal, session, clock=lambda: 1505)
        keeper.attach(broker)
        return broker

    def invoke(**kwargs):
        seen.append((kwargs["timeout"], kwargs["journal"]._broker.child_deadline))
    monkeypatch.setattr(ag, "invoke_adapter", invoke)
    runner = ag.run_publish_static if operation == "publish-static" else ag.run_inventory

    def call():
        return runner(keeper=keeper, request_raw=request_raw, owner=owner, window=window, inputs=inputs,
                      activation_sha256=c.sha(activation), capability=capability, product="product",
                      source=owner["source_sha"], manifest={}, manifest_sha256="0" * 64, seconds=lambda: seconds)
    return call, seen


@pytest.mark.parametrize("operation", ["publish-static", "inventory"])
def test_run_entrega_ao_broker_o_prazo_do_child_antes_do_adapter(monkeypatch, operation):
    call, seen = _run(monkeypatch, operation)
    call()
    assert seen == [(77, 1505 + 77)]


def test_corte_do_child_no_bloco_das_raizes_vira_recusa_antes_do_primeiro_put_de_raiz(monkeypatch):
    from test_cnesdata_stage_events import HOST_REFERENCE
    from test_cnesdata_static_stage import _lifecycle, _static_world
    world = _static_world(monkeypatch, static={"capability": "real", "latency": 10})
    with pytest.raises(ValueError, match="^static_roots=window_short remaining=90 required=100$"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    puts = [call[3]["Key"] for call in world.clients["normal"].calls if call[1] == "put_object"]
    assert puts == ["assets/app.js"]
    assert _lifecycle(world)["stage"] == "static" and world.store.get()[0]["status"] == "held"


def test_teto_por_arquivo_e_1_mib_no_put_e_no_get():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert lc.STATIC_MEMBER_LIMIT == 1024**2
    for size, accepted in ((1024**2, True), (1024**2 + 1, False)):
        digest = hashlib.sha256(b"x" * size).digest()
        body = {"member": "assets/app.js", "size": size, "sha256": digest.hex()}
        parameters = {"Key": "assets/app.js", "Body": body, "ChecksumSHA256": base64.b64encode(digest).decode("ascii")}
        if accepted:
            assert lc.s3_put_body(parameters) == body
            assert lc.s3_body_value(io.BytesIO(b"x" * size), maximum=lc.STATIC_MEMBER_LIMIT)["size"] == size
            continue
        with pytest.raises(ValueError):
            lc.s3_put_body(parameters)
        with pytest.raises(ValueError, match="^S3 Body bound$"):
            lc.s3_body_value(io.BytesIO(b"x" * size), maximum=lc.STATIC_MEMBER_LIMIT)


def _dashboard(app_size):
    files = dict(BODIES) | {"assets/app.js": b"a" * app_size}
    return _dist(files), files


@pytest.mark.parametrize("extra, refused", [(0, False), (1, True)])
def test_publish_static_recusa_soma_dos_corpos_acima_do_piso_de_upload_vezes_o_timeout_do_child(monkeypatch, extra, refused):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert lc.STATIC_UPLOAD_FLOOR == 512 * 1024
    roots = len(BODIES["index.html"]) + len(BODIES["theme-init.js"])
    dist, files = _dashboard(2 * lc.STATIC_UPLOAD_FLOOR - roots + extra)
    call, seen = _run(monkeypatch, "publish-static", seconds=2, dashboard=dist)
    total = sum(len(raw) for raw in files.values())
    if not refused:
        call()
        assert seen == [(2, 1507)]
        return
    with pytest.raises(ValueError, match=f"^static_total=over_window total={total} limit={2 * lc.STATIC_UPLOAD_FLOOR} seconds=2$"):
        call()
    assert seen == []


def test_publish_static_recusa_membro_acima_do_teto_ou_ausente_antes_do_child(monkeypatch):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    dist, _ = _dashboard(lc.STATIC_MEMBER_LIMIT + 1)
    call, seen = _run(monkeypatch, "publish-static", seconds=600, dashboard=dist)
    with pytest.raises(ValueError, match=f"^static_body=member_size key=assets/app.js size={lc.STATIC_MEMBER_LIMIT + 1} "
                                         f"limit={lc.STATIC_MEMBER_LIMIT}$"):
        call()
    assert seen == []
    dist = _dist({key: raw for key, raw in BODIES.items() if key != "theme-init.js"})
    call, seen = _run(monkeypatch, "publish-static", seconds=600, dashboard=dist)
    with pytest.raises(ValueError, match="^static_body=member_absent key=theme-init.js$"):
        call()
    assert seen == []
