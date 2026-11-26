"""Guardas do broker, do STS e do handler estaticos e a publicacao contra os recibos do journal (#55, P15 rodada 1)."""
import re
from datetime import datetime, timezone

import pytest

from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401

from tools.cnesdata_delivery import contract as c

from test_cnesdata_static_stage import (ACCOUNT, BUCKET, DISTRIBUTION, EVIDENCE_GOVERNANCE, INVALIDATION, PAIR, ROLES,
                                        _Evidence, _Native, _broker_case, _frame, _journal, _lifecycle, _metadata,
                                        _publish_journal, _put, _session, _static_world)

from test_cnesdata_static_roles import ROLE_FACTS, role_files

LIST = ("observer", "s3", "ListObjectVersions", {"Bucket": BUCKET})


def _clock(*values):
    seen = list(values)
    return lambda: seen.pop(0) if len(seen) > 1 else seen[0]


class _Patched(_Native):
    """Native client whose responses carry a chosen HTTP status or replaced top-level fields."""
    def __init__(self, alias, *, status=None, fields=None, versions=()):
        super().__init__(alias, versions=versions)
        self.status, self.fields = status, fields or {}

    def call(self, service, operation, **kwargs):
        response = super().call(service, operation, **kwargs)
        if self.status is not None:
            response["ResponseMetadata"] = _metadata(self.status)
        return response | self.fields.get(operation, {})


def _broker_with(clients, *, governance=EVIDENCE_GOVERNANCE, evidence=None, clock=None):
    from tools.cnesdata_delivery import application_gate as ag
    journal, _, window, _ = _journal(rollback=PAIR)
    evidence = evidence or _Evidence()
    broker = ag.StaticBroker(evidence, governance, journal, _session(journal, clients, evidence),
                             clock=clock or (lambda: window["admitted_at"] + 5))
    return ag, broker, journal, evidence


_RECEIPT_CONTRADICTIONS = {
    "nothing-uploaded-no-invalidation": ({"uploaded": [], "invalidation_id": None},
                                         "publication=uploaded_mismatch index=0 observed=0 receipts=3"),
    "version-never-returned": ({"uploaded": [["assets/app.js", "Forged.9"], ["index.html", "New.2"], ["theme-init.js", "New.3"]]},
                               "publication=uploaded_mismatch index=0 observed=3 receipts=3"),
    "uploaded-out-of-order": ({"uploaded": [["index.html", "New.2"], ["assets/app.js", "New.1"], ["theme-init.js", "New.3"]]},
                              "publication=uploaded_mismatch index=0 observed=3 receipts=3"),
    "invalidation-never-created": ({"invalidation_id": "IFORGED"}, "publication=invalidation_mismatch"),
    "already-published-foreign-key": ({"already_published": ["assets/foreign.js"]}, "publication=already_published_invalid"),
    "already-published-and-uploaded": ({"already_published": ["index.html"]}, "publication=already_published_invalid"),
    "uploaded-prefix-of-receipts": ({"uploaded": [["assets/app.js", "New.1"], ["index.html", "New.2"]]},
                                    "publication=uploaded_mismatch index=2 observed=2 receipts=3"),
}


@pytest.mark.parametrize("name", sorted(_RECEIPT_CONTRADICTIONS))
def test_publicacao_que_contradiz_os_recibos_do_journal_e_recusada_com_o_lease_retido(monkeypatch, name):
    from test_cnesdata_stage_events import HOST_REFERENCE
    observation, message = _RECEIPT_CONTRADICTIONS[name]
    world = _static_world(monkeypatch, static={"capability": "real", "observation": observation})
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert len(_publish_journal(world).call_receipts) == 9
    assert _lifecycle(world)["stage"] == "static" and world.store.get()[0]["status"] == "held"


class _Settled:
    def __init__(self, calls):
        self.calls = calls

    def _settled_calls(self):
        return self.calls


def _put_receipt(key, version):
    return {"call": {"operation": "PutObject", "parameters": {"Key": key}}, "response": {"VersionId": version}}


def _invalidation_receipt(identifier):
    return {"call": {"operation": "CreateInvalidation", "parameters": {}}, "response": {"Invalidation": {"Id": identifier}}}


def test_recibo_de_put_com_version_id_null_e_recusado():
    from tools.cnesdata_delivery import application_gate as ag
    with pytest.raises(ValueError, match="^static version id$"):
        ag._publication_receipts(_Settled([_put_receipt("index.html", "null")]))


def test_dois_recibos_de_create_invalidation_sao_recusados():
    from tools.cnesdata_delivery import application_gate as ag
    calls = [_put_receipt("index.html", "New.1"), _invalidation_receipt("I1"), _invalidation_receipt("I2")]
    with pytest.raises(ValueError, match="^publication=invalidation_calls count=2$"):
        ag._publication_receipts(_Settled(calls))


def test_publicacao_sem_chamada_de_invalidacao_so_aceita_invalidation_id_nulo(monkeypatch):
    from test_cnesdata_stage_events import HOST_REFERENCE
    world = _static_world(monkeypatch, static={"observation": {"invalidation_id": "I2SYNTH"}})
    with pytest.raises(ValueError, match="^publication=invalidation_mismatch$"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert _lifecycle(world)["stage"] == "static" and world.store.get()[0]["status"] == "held"


def test_publicacao_igual_aos_recibos_avanca_para_unit(monkeypatch):
    from test_cnesdata_stage_events import HOST_REFERENCE
    world = _static_world(monkeypatch, static={"capability": "real", "observation": {"already_published": []}})
    world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert _lifecycle(world)["stage"] == "unit"


@pytest.mark.parametrize("observation", [{"already_published": "index.html"}, {"already_published": [7]},
                                         {"invalidation_id": 7}])
def test_publicacao_com_tipo_de_campo_errado_recusa_pela_forma(monkeypatch, observation):
    from test_cnesdata_stage_events import HOST_REFERENCE
    world = _static_world(monkeypatch, static={"observation": observation})
    with pytest.raises(ValueError, match="^publish-static single publication observation bound"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert _lifecycle(world)["stage"] == "static"


@pytest.mark.parametrize("length", [96528, 96529, 97243, 98064, 125138, 310126])
def test_put_object_dos_tamanhos_que_o_p15_recusava_passa_pelo_digest_com_pedido_abaixo_do_limite(length):
    from test_cnesdata_static_inputs import _digest_broker, _digest_put
    body = (bytes(range(256)) * 1212)[:length]
    ag, broker, journal, clients, evidence = _digest_broker({"assets/app.js": body, "index.html": b"<html></html>\n",
                                                             "theme-init.js": b"theme()\n"})
    role, service, operation, parameters = _digest_put("assets/app.js", body)
    size = len(c.canonical({"role": role, "service": service, "operation": operation, "parameters": parameters}))
    ag._adapter_message(_frame(role, service, operation, parameters), journal)
    (call,) = clients["normal"].calls
    assert size < 1024 < ag.STATIC_REQUEST_LIMIT and call[3]["Body"] == body and evidence.writes


@pytest.mark.parametrize("slack, admitted", [(0, True), (-1, False)])
def test_pedido_com_exatamente_o_limite_de_bytes_e_aceito_e_um_byte_acima_e_recusado(monkeypatch, slack, admitted):
    from test_cnesdata_static_inputs import _digest_broker, _digest_put
    body = b"<html></html>\n"
    ag, broker, journal, clients, evidence = _digest_broker({"assets/app.js": b"app()\n", "index.html": body,
                                                             "theme-init.js": b"theme()\n"})
    assert ag.STATIC_REQUEST_LIMIT == 128 * 1024 - 2048
    role, service, operation, parameters = _digest_put("index.html", body)
    size = len(c.canonical({"role": role, "service": service, "operation": operation, "parameters": parameters}))
    monkeypatch.setattr(ag, "STATIC_REQUEST_LIMIT", size + slack)
    if admitted:
        ag._adapter_message(_frame(role, service, operation, parameters), journal)
        assert len(clients["normal"].calls) == 1
        return
    with pytest.raises(ValueError, match=f"^static request size={size} limit={size - 1}$"):
        ag._adapter_message(_frame(role, service, operation, parameters), journal)
    assert clients["normal"].calls == [] and evidence.writes == []


def test_politica_estatica_e_exatamente_o_documento_esperado_por_alias():
    from tools.cnesdata_delivery import session_policy
    bucket = "arn:aws:s3:::" + BUCKET
    condition = {"DateLessThan": {"aws:CurrentTime": c.utc(2000)}}

    def allow(actions, resource):
        return {"Effect": "Allow", "Action": actions, "Resource": resource, "Condition": condition}
    expected = {"observer": [allow(["s3:ListBucketVersions", "s3:ListBucketMultipartUploads"], bucket),
                             allow(["s3:GetObjectVersion", "s3:ListMultipartUploadParts"], bucket + "/*")],
                "normal": [allow(["s3:PutObject", "s3:GetObject"], [bucket + "/assets/app.js", bucket + "/index.html"]),
                           allow(["cloudfront:CreateInvalidation"], DISTRIBUTION)]}
    keys = {"observer": None, "normal": ["assets/app.js", "index.html"]}
    for alias, statements in expected.items():
        policy = session_policy.static_session_policy(alias, bucket_arn=bucket, distribution_arn=DISTRIBUTION, deadline=2000,
                                                      keys=keys[alias])
        assert policy == {"Version": "2012-10-17", "Statement": statements}


@pytest.mark.parametrize("bucket", ["arn:aws:s3:::other-static-web", "arn:aws:s3:::cnesdata-prod-"])
def test_politica_estatica_recusa_bucket_fora_do_prefixo_de_producao(bucket):
    from tools.cnesdata_delivery import session_policy
    with pytest.raises(ValueError, match="^static session bucket$"):
        session_policy.static_session_policy("observer", bucket_arn=bucket, distribution_arn=DISTRIBUTION, deadline=2000)


def test_intencao_duravel_sem_recibo_recusa_a_repeticao_sem_chamada_nativa():
    failing = {"observer": _Native("observer", error=TimeoutError("late S3 response")), "normal": _Native("normal")}
    ag, _, journal, evidence = _broker_with(failing)
    with pytest.raises(TimeoutError):
        ag._adapter_message(_frame(*LIST), journal)
    healthy = {"observer": _Native("observer", versions=PAIR), "normal": _Native("normal")}
    ag, _, retry, _ = _broker_with(healthy, evidence=evidence)
    with pytest.raises(ValueError, match="^existing durable call is historical/unknown; no fresh SDK replay$"):
        ag._adapter_message(_frame(*LIST), retry)
    assert healthy["observer"].calls == [] and retry._failed


def test_reserva_que_consome_a_janela_recusa_antes_da_chamada_nativa():
    deadline = _journal()[2]["deadline"]
    ag, broker, journal, clients, evidence = _broker_case(clock=_clock(deadline - 21, deadline - 20))
    with pytest.raises(ValueError, match="^SDK reservation consumed original budget$"):
        ag._adapter_message(_frame(*LIST), journal)
    assert clients["observer"].calls == [] and journal._failed


def test_reserva_com_vinte_e_um_segundos_chama_o_nativo():
    deadline = _journal()[2]["deadline"]
    ag, broker, journal, clients, evidence = _broker_case(clock=_clock(deadline - 21))
    reply, _ = ag._adapter_message(_frame(*LIST), journal)
    assert reply["kind"] == "sdk-result" and len(clients["observer"].calls) == 1


def test_resposta_nativa_no_prazo_do_estagio_fica_desconhecida():
    deadline = _journal()[2]["deadline"]
    ag, broker, journal, clients, evidence = _broker_case(clock=_clock(deadline - 21, deadline - 21, deadline))
    with pytest.raises(ValueError, match="^native response exceeded original static window$"):
        ag._adapter_message(_frame(*LIST), journal)
    assert len(clients["observer"].calls) == 1 and journal.unknown and broker.uncertainty and journal._failed


def test_evidencia_estatica_recusa_conta_fora_da_governanca_antes_do_io():
    natives = {"observer": _Native("observer"), "normal": _Native("normal")}
    governance = EVIDENCE_GOVERNANCE | {"account_id": "governance-of-another-account"}
    ag, _, journal, evidence = _broker_with(natives, governance=governance)
    with pytest.raises(ValueError, match="^original static journal scope$"):
        ag._adapter_message(_frame(*LIST), journal)
    assert natives["observer"].calls == [] and evidence.writes == []


def test_evidencia_estatica_recusa_bucket_fora_do_estatico_de_producao():
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    journal, _, _, _ = _journal(rollback=PAIR)
    plan = lc.static_plan(journal._inputs["static-plan"], bucket=BUCKET)
    raw = c.canonical({"role": "observer", "service": "s3", "operation": "ListObjectVersions",
                       "parameters": {"Bucket": "other-static-web"}})
    with pytest.raises(ValueError, match="^original static journal scope$"):
        ag.StaticEvidence(_Evidence(), EVIDENCE_GOVERNANCE, journal, raw, prepared_sha256="9" * 64,
                          role_session_sha256="9" * 64, scope={"account": ACCOUNT, "bucket": "other-static-web", "plan": plan})


def test_broker_estatico_recusa_sessao_ligada_a_outro_pedido():
    from tools.cnesdata_delivery import application_gate as ag
    journal, _, _, _ = _journal(rollback=PAIR)
    evidence = _Evidence()
    session = _session(journal, {"observer": _Native("observer"), "normal": _Native("normal")}, evidence)
    session.request_binding = "0" * 64
    with pytest.raises(ValueError, match="^one original admitted static broker$"):
        ag.StaticBroker(evidence, EVIDENCE_GOVERNANCE, journal, session, clock=lambda: 1505)
    assert getattr(journal, "_broker", None) is None


@pytest.mark.parametrize("call, status", [(_put("assets/app.js"), 201), (INVALIDATION, 200)])
def test_broker_estatico_exige_o_status_nativo_exato_de_cada_operacao(call, status):
    clients = {"observer": _Native("observer"), "normal": _Patched("normal", status=status)}
    ag, broker, journal, evidence = _broker_with(clients)
    with pytest.raises(ValueError, match="^native SDK authenticated status$"):
        ag._adapter_message(_frame(*call), journal)
    assert len(clients["normal"].calls) == 1 and journal.unknown


@pytest.mark.parametrize("size, accepted", [(64 * 1024, True), (1024**2, True), (1024**2 + 1, False)])
def test_get_object_acima_do_limite_do_corpo_e_recusado(size, accepted):
    ag, broker, journal, clients, evidence = _broker_case()
    ag._adapter_message(_frame(*_put("index.html")), journal)
    clients["normal"].stored["index.html"] = (b"x" * size, "New.1", "text/html", "no-cache")
    frame = _frame("normal", "s3", "GetObject", {"Bucket": BUCKET, "Key": "index.html"})
    if accepted:
        reply, _ = ag._adapter_message(frame, journal)
        assert reply["value"]["Body"] == {"sha256": c.sha(b"x" * size), "size": size}
        return
    with pytest.raises(ValueError, match="^S3 Body bound$"):
        ag._adapter_message(frame, journal)
    assert journal.unknown


@pytest.mark.parametrize("fields, message", [
    ({"list_object_versions": {"Versions": ["not-a-dict"]}}, "static response list"),
    ({"list_object_versions": {"Versions": [{"Key": "index.html"}] * 1001}}, "static response list"),
    ({"list_object_versions": {"IsTruncated": "false"}}, "static response field"),
    ({"list_object_versions": {"NextKeyMarker": 7}}, "static response field")])
def test_broker_estatico_recusa_resposta_com_lista_ou_campo_de_tipo_errado(fields, message):
    clients = {"observer": _Patched("observer", fields=fields), "normal": _Native("normal")}
    ag, broker, journal, evidence = _broker_with(clients)
    with pytest.raises(ValueError, match=f"^{message}$"):
        ag._adapter_message(_frame(*LIST), journal)
    assert journal.unknown


def _sts(monkeypatch, *, now, credential_limit, expiry=900, governance=EVIDENCE_GOVERNANCE):
    from tools.cnesdata_delivery import application_gate as ag, aws_boundary, lifecycle_contract as lc
    journal, _, window, _ = _journal()
    binding = ag._static_binding(EVIDENCE_GOVERNANCE, journal)
    names, minted = lc.static_sessions(binding, "publish-static"), []

    def assumed(alias):
        return ROLES[alias].replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + names[alias]

    def user(alias):
        return "AROA" + alias.upper().ljust(17, "X") + ":" + names[alias]

    class Operation:
        def call(self, service, operation, **parameters):
            alias = next(name for name, role in ROLES.items() if role == parameters["RoleArn"])
            return {"PackedPolicySize": 10, "AssumedRoleUser": {"Arn": assumed(alias), "AssumedRoleId": user(alias)},
                    "Credentials": {"AccessKeyId": alias, "SecretAccessKey": "synthetic-secret", "SessionToken": "synthetic-token",
                                    "Expiration": datetime.fromtimestamp(now + expiry, timezone.utc)}}

    class Delegated:
        def __init__(self, governance, *, credentials):
            alias = credentials["AccessKeyId"]
            self.identity = {"Account": ACCOUNT, "Arn": assumed(alias), "UserId": user(alias)}
    monkeypatch.setattr(aws_boundary, "AWS", Delegated)

    def factory(name, role, stage):
        minted.append(name)
        return Operation()

    def assume():
        return ag._assume_static_session(governance=governance, journal=journal, binding=binding, roles=ROLE_FACTS,
                                         credential_limit=credential_limit, operation_session=factory, clock=lambda: now)
    return assume, window, minted


@pytest.mark.parametrize("offset, accepted", [(40, False), (41, True)])
def test_sts_estatico_so_com_mais_de_quarenta_segundos_ate_o_prazo(monkeypatch, offset, accepted):
    deadline = _journal()[2]["deadline"]
    assume, window, minted = _sts(monkeypatch, now=deadline - offset, credential_limit=deadline + 5000)
    if accepted:
        assert set(assume().clients) == {"observer", "normal"}
        return
    with pytest.raises(ValueError, match="^static original stage/credential window$"):
        assume()
    assert minted == []


@pytest.mark.parametrize("margin, accepted", [(899, False), (900, True)])
def test_sts_estatico_so_com_novecentos_segundos_de_credencial(monkeypatch, margin, accepted):
    assume, window, minted = _sts(monkeypatch, now=1505, credential_limit=1505 + margin)
    if accepted:
        assert set(assume().clients) == {"observer", "normal"}
        return
    with pytest.raises(ValueError, match="^static original stage/credential window$"):
        assume()
    assert minted == []


@pytest.mark.parametrize("expiry, accepted", [(140, False), (141, True), (900, True), (901, False)])
def test_sts_estatico_recusa_expiracao_fora_de_141_a_900_segundos(monkeypatch, expiry, accepted):
    assume, window, minted = _sts(monkeypatch, now=1505, credential_limit=9000, expiry=expiry)
    if accepted:
        assert set(assume().clients) == {"observer", "normal"}
        return
    with pytest.raises(ValueError, match="^static original STS expiration$"):
        assume()


def test_sts_estatico_recusa_role_da_governanca_fora_do_nome_protegido(monkeypatch):
    swapped = EVIDENCE_GOVERNANCE | {"application_delegations": {"observer": ROLES["normal"], "normal": ROLES["observer"]}}
    assume, window, minted = _sts(monkeypatch, now=1505, credential_limit=9000, governance=swapped)
    with pytest.raises(ValueError, match="^static exact protected roles$"):
        assume()
    assert minted == []


def test_sts_estatico_recusa_politica_acima_de_2048_caracteres(monkeypatch):
    from tools.cnesdata_delivery import session_policy
    real = session_policy.static_session_policy

    def oversized(alias, **kwargs):
        policy = real(alias, **kwargs)
        policy["Statement"][0]["Action"] = policy["Statement"][0]["Action"] + [f"s3:Synthetic{index:04d}" for index in range(120)]
        return policy
    monkeypatch.setattr(session_policy, "static_session_policy", oversized)
    assume, window, minted = _sts(monkeypatch, now=1505, credential_limit=9000)
    with pytest.raises(ValueError, match="^static STS policy limit$"):
        assume()
    assert minted == []


def test_capability_recusa_recibo_do_host_sem_o_closed_ready_do_keeper_antes_do_sts():
    from test_cnesdata_application_gate import _prepare_stage_keeper
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store = _prepare_stage_keeper()
    receipt = c.canonical({field: None for field in ag.HOST_HANDOFF_FIELDS.split()}
                          | {"version": 1, "kind": "host-handoff", "status": "accepted", "closed_ready_sha256": "0" * 64})
    journal, _, _, _ = _journal(receipt=receipt)
    minted = []
    with pytest.raises(ValueError, match="^publish-static host-receipt closed-ready binding$"):
        ag.static_capability(governance=EVIDENCE_GOVERNANCE, journal=journal, keeper=keeper, credential_limit=6000,
                             operation_session=lambda *args: minted.append(args), clock=lambda: 1505,
                             carrier=ag._static_binding(EVIDENCE_GOVERNANCE, journal), prepared=role_files())
    assert minted == [] and journal._failed and store.get()[0]["status"] == "held"


def test_handler_reconfere_o_closed_ready_depois_do_child_e_retem_o_lease(monkeypatch):
    from test_cnesdata_stage_events import HOST_REFERENCE
    from tools.cnesdata_delivery import application_gate as ag
    world = _static_world(monkeypatch)
    rechecked = []

    def refused(journal, keeper):
        rechecked.append(journal)
        raise ValueError("publish-static host-receipt closed-ready binding")
    monkeypatch.setattr(ag, "publish_static_closed_ready", refused)
    with pytest.raises(ValueError, match="^publish-static host-receipt closed-ready binding$"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert rechecked == [_publish_journal(world)] and world.invoke
    assert _lifecycle(world)["stage"] == "static" and world.store.get()[0]["status"] == "held"


@pytest.mark.parametrize("now, advanced", [(1379, True), (1380, False)])
def test_handler_so_abre_o_unit_antes_do_prazo_do_static(monkeypatch, now, advanced):
    from test_cnesdata_stage_events import HOST_REFERENCE
    from tools.cnesdata_delivery import application_gate as ag
    world = _static_world(monkeypatch)
    real = ag.publish_static_closed_ready

    def late(journal, keeper):
        ready = real(journal, keeper)
        while world.clock.value < now:
            world.clock.value = min(now, world.clock.value + 30)
            keeper.tick()
        return ready
    monkeypatch.setattr(ag, "publish_static_closed_ready", late)
    if advanced:
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
        assert _lifecycle(world)["stage"] == "unit" and _lifecycle(world)["admitted_at"] == now
        return
    with pytest.raises(ValueError, match="^static stage deadline elapsed$"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert _lifecycle(world)["stage"] == "static" and world.store.get()[0]["status"] == "held"
