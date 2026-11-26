"""P17b: brokers reais do terminal (reopen, terminal-readback, rollback-api-static) e o routing do final pela phase-c-audit."""
import urllib.parse
from types import SimpleNamespace

import pytest

from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

ACCOUNT = "111122223333"
TABLE = "cnesdata-prod-control-plane"
SCOPE = {"account": ACCOUNT, "control_table_arn": f"arn:aws:dynamodb:us-east-2:{ACCOUNT}:table/{TABLE}",
         "machine_arn": f"arn:aws:states:us-east-2:{ACCOUNT}:stateMachine:cnesdata-prod"}
EXECUTION = SCOPE["machine_arn"].replace(":stateMachine:", ":execution:") + ":"
OWNER = "d" * 64
FENCE = {"pk": {"S": "ENV#prod#FENCE"}, "sk": {"S": "FENCE"}}
SEMAPHORE = {"pk": {"S": "ENV#prod#SEMAPHORE"}, "sk": {"S": "UNIT"}}
REOPEN_SDK_VECTOR_SHA256 = "1b99b76fc1ec46570fc81ed1b382d0f99bda8426b1f5ca4fbb573464d4e57636"


def _read(key):
    return {"role": "fence_operator", "service": "dynamodb", "operation": "get_item",
            "parameters": {"ConsistentRead": True, "Key": key, "TableName": TABLE}}


def _update(promotion):
    return {"role": "fence_operator", "service": "dynamodb", "operation": "update_item", "parameters": {
        "ConditionExpression": "#version = :expected",
        "ExpressionAttributeNames": {"#changed": "changed_at", "#entity": "entity", "#promotion": "promotion_id",
                                     "#state": "state", "#version": "version"},
        "ExpressionAttributeValues": {":changed": {"S": "2026-11-09T12:20:00.000000+00:00"},
                                      ":entity": {"S": "PROMOTIONFENCE"}, ":expected": {"N": "1"},
                                      ":promotion": {"S": promotion}, ":state": {"S": "OPEN"}, ":version": {"N": "2"}},
        "Key": FENCE, "TableName": TABLE,
        "UpdateExpression": "SET #entity = :entity, #state = :state, #promotion = :promotion, #version = :version, "
                            "#changed = :changed"}}


def _product_reopen(promotion):
    """Vendored from CnesData 182dc74c tests/production/delivery/reopen_sdk_vector.json, section reopen (P17c)."""
    return {"final": [_read(FENCE), _read(SEMAPHORE), _read(FENCE), _update(promotion), _read(FENCE), _read(SEMAPHORE)],
            "recovery": [_read(FENCE), _read(SEMAPHORE)]}


def _request(operation, stage):
    return {"operation": operation, "stage": {"stage": stage, "close": None if stage == "application-prepare" else 1000},
            "owner": {"owner_sha256": OWNER}}


def _response(call, version="1"):
    if call["operation"] != "get_item":
        return {}
    if call["parameters"]["Key"] == FENCE:
        return {"Item": FENCE | {"state": {"S": "CLOSED"}, "promotion_id": {"S": OWNER}, "version": {"N": version}}}
    return {"Item": SEMAPHORE}


def _replay(operation, stage, calls, **scope):
    history = []
    for call in calls:
        lc.validate_fence_call(request=_request(operation, stage), history=history, **call, **SCOPE, **scope)
        history.append({"call": call, "response": _response(call)})
    return history


def test_vetor_do_reopen_vendorizado_e_a_secao_reopen_do_vetor_do_produto():
    assert c.sha(c.canonical(_product_reopen("<owner_sha256>"))) == REOPEN_SDK_VECTOR_SHA256


def test_reopen_em_final_admite_a_sequencia_do_produto_com_um_cas_depois_da_leitura_do_fence():
    history = _replay("reopen", "final", _product_reopen(OWNER)["final"])
    assert [entry["call"]["operation"] for entry in history].count("update_item") == 1


def test_reopen_em_recovery_admite_so_as_leituras_e_recusa_o_cas():
    history = _replay("reopen", "recovery", _product_reopen(OWNER)["recovery"])
    with pytest.raises(ValueError, match="^reopen finite SDK operation$"):
        lc.validate_fence_call(request=_request("reopen", "recovery"), history=history, **_update(OWNER), **SCOPE)


def _values(**changes):
    def change(call):
        call["parameters"]["ExpressionAttributeValues"].update(changes)
    return change


REOPEN_UPDATE_REFUSALS = {
    "sem-condicao-cas": lambda call: call["parameters"].pop("ConditionExpression"),
    "condicao-trocada": lambda call: call["parameters"].update(ConditionExpression="attribute_exists(pk)"),
    "outro-dono": _values(**{":promotion": {"S": "e" * 64}}),
    "estado-fechado": _values(**{":state": {"S": "CLOSED"}}),
    "versao-saltada": _values(**{":version": {"N": "3"}}),
    "esperada-fora-da-leitura": _values(**{":expected": {"N": "7"}, ":version": {"N": "8"}}),
    "outra-entidade": _values(**{":entity": {"S": "OTHER"}}),
    "outra-tabela": lambda call: call["parameters"].update(TableName="cnesdata-prod-other"),
    "chave-do-semaforo": lambda call: call["parameters"].update(Key=SEMAPHORE),
}


@pytest.mark.parametrize("mutation", sorted(REOPEN_UPDATE_REFUSALS))
def test_reopen_em_final_recusa_cas_fora_do_vetor_ou_do_dono_da_leitura(mutation):
    calls = _product_reopen(OWNER)["final"]
    history = _replay("reopen", "final", calls[:3])
    update = _update(OWNER)
    REOPEN_UPDATE_REFUSALS[mutation](update)
    with pytest.raises(ValueError, match="^reopen "):
        lc.validate_fence_call(request=_request("reopen", "final"), history=history, **update, **SCOPE)


def test_reopen_em_final_recusa_cas_sem_leitura_previa_do_fence_ou_repetido():
    with pytest.raises(ValueError, match="^reopen update once after a strong FENCE read$"):
        lc.validate_fence_call(request=_request("reopen", "final"), history=[], **_update(OWNER), **SCOPE)
    history = _replay("reopen", "final", _product_reopen(OWNER)["final"])
    with pytest.raises(ValueError, match="^reopen update once after a strong FENCE read$"):
        lc.validate_fence_call(request=_request("reopen", "final"), history=history, **_update(OWNER), **SCOPE)


@pytest.mark.parametrize("call", [
    _read(FENCE) | {"parameters": _read(FENCE)["parameters"] | {"ConsistentRead": False}},
    {"role": "fence_operator", "service": "stepfunctions", "operation": "describe_execution",
     "parameters": {"executionArn": EXECUTION + "0123456789abcdef", "includedData": "METADATA_ONLY"}},
    _read(FENCE) | {"role": "normal"}])
def test_reopen_recusa_leitura_fraca_probe_ou_outro_papel(call):
    with pytest.raises(ValueError, match="^reopen "):
        lc.validate_fence_call(request=_request("reopen", "final"), history=[], **call, **SCOPE)


def _member(dispatch, resolution):
    return {"dispatch_id": dispatch, "request_sha256": "1" * 64, "generation": 1, "initial_state": "ACKNOWLEDGED",
            "execution_ref": EXECUTION + dispatch if resolution == "TERMINAL" else None, "resolution": resolution,
            "proof_sha256": "2" * 64, "observed_at": c.utc(990), "send_disabled_at": c.utc(980)}


MEMBERS = [_member("0123456789abcdef", "TERMINAL"), _member("fedcba9876543210", "CANCEL_BEFORE_SEND")]


def _probe(dispatch, **parameters):
    return {"role": "fence_operator", "service": "stepfunctions", "operation": "describe_execution",
            "parameters": {"executionArn": EXECUTION + dispatch, "includedData": "METADATA_ONLY"} | parameters}


@pytest.mark.parametrize("stage", ["application-prepare", "final", "recovery"])
def test_terminal_readback_admite_as_leituras_fortes_e_o_probe_so_dos_membros_terminais(stage):
    members = [] if stage == "application-prepare" else MEMBERS
    calls = [_read(FENCE), _read(SEMAPHORE)] + ([_probe("0123456789abcdef")] if members else [])
    _replay("terminal-readback", stage, calls, members=members)


@pytest.mark.parametrize("call", [
    _probe("fedcba9876543210"), _probe("00000000000000aa"), _probe("0123456789abcdef", includedData="ALL_DATA"),
    _update(OWNER), _read(FENCE) | {"parameters": _read(FENCE)["parameters"] | {"ConsistentRead": False}}],
    ids=["membro-cancelado", "fora-da-membership", "payload", "update", "leitura-fraca"])
def test_terminal_readback_recusa_probe_fora_dos_membros_terminais_e_qualquer_escrita(call):
    with pytest.raises(ValueError, match="^terminal-readback "):
        lc.validate_fence_call(request=_request("terminal-readback", "final"), history=[], **call, **SCOPE, members=MEMBERS)


def test_reopen_e_terminal_readback_tem_namespace_de_evidencia_do_fence():
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    assert lr._evidence_tag("reopen") == lr._evidence_tag("terminal-readback") == 2
    assert lc.FENCE_SDK_OPERATIONS["reopen"] == {("dynamodb", "get_item"), ("dynamodb", "update_item")}
    assert lc.FENCE_SDK_OPERATIONS["terminal-readback"] == {("dynamodb", "get_item"), ("stepfunctions", "describe_execution")}


def test_politica_da_sessao_do_reopen_concede_leitura_forte_e_update_so_no_fence_ate_o_prazo():
    from tools.cnesdata_delivery import session_policy as sp
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    table = SCOPE["control_table_arn"]
    policy = sp.fence_reopen_session_policy(control_table_arn=table, deadline=2000)
    role = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}

    def allowed(action, key, now=1999, resource=table):
        return effective_iam(role, [policy], action, resource,
                             {"aws:CurrentTime": c.utc(now), "dynamodb:LeadingKeys": [key]})
    assert allowed("dynamodb:GetItem", "ENV#prod#FENCE") and allowed("dynamodb:GetItem", "ENV#prod#SEMAPHORE")
    assert allowed("dynamodb:UpdateItem", "ENV#prod#FENCE")
    assert not allowed("dynamodb:UpdateItem", "ENV#prod#SEMAPHORE") and not allowed("dynamodb:GetItem", "ENV#prod#FENCE", 2000)
    assert not allowed("dynamodb:ConditionCheckItem", "ENV#prod#SEMAPHORE")
    assert not allowed("states:DescribeExecution", "ENV#prod#FENCE", resource=EXECUTION + "0" * 16)


def _close_raw(members):
    close = dict.fromkeys(lc.CLOSE_DRAIN_FIELDS.split()) | {"members": members,
                                                             "frozen_membership_sha256": c.sha(c.canonical(members))}
    return c.canonical(close)


def _fence_capability_case(monkeypatch, operation, stage, *, prepared=True):
    """The close-drain capability world (real prepared package, fake STS and IAM) with a terminal journal at stage."""
    from test_cnesdata_application_gate import _close_drain_capability_case
    from test_cnesdata_mode_stages import _mode_case
    from tools.cnesdata_delivery import application_gate as ag, terminal_gate as tg
    _, args, sts_calls, keeper, close_journal, events = _close_drain_capability_case(monkeypatch)
    _, base_owner, window, _ = _mode_case("unit-observe")
    owner = close_journal._request["owner"] | close_journal._identity
    identity = lc.application_identity(owner)
    window = {key: value for key, value in window.items() if key not in lc.application_identity(base_owner)} | identity
    window.update(stage=stage, admitted_at=1280)
    if stage == "final":
        window["deadline"] = min(window["fixed_deadline"], 1280 + window["windows"]["stages"]["final"])
    else:
        window.update(decision={"choice_at": 1270, "deadline": 1690, "checkpoint_sha256": "7" * 64}, deadline=1570)
    activation = close_journal._inputs["activation"]
    close = _close_raw([MEMBERS[0] | {"execution_ref": SCOPE["machine_arn"].replace(":stateMachine:", ":execution:")
                                      .replace(ACCOUNT, args["governance"]["account_id"]) + ":0123456789abcdef"}])
    membership = ag._frozen_membership(close)
    if operation == "reopen":
        inputs = {"activation": activation, "routing": c.canonical({"unit": "u", "recovery": "r", "audit": "a"}),
                  "canaries": b"null", "membership": membership}
    else:
        inputs = {"routing": b"{}", "membership": membership, "host-receipt": b"{}", "static-receipt": b"{}",
                  "decision": b"null"}

    class Guard:
        def check(self, seconds=0):
            return None
    journal = ag.AdapterJournal(ag._operation_request(operation, owner=owner, window=window, inputs=inputs,
                                                      activation=activation),
                                operation=operation, owner=owner, window=window, inputs=inputs,
                                activation_sha256=c.sha(activation), guard=Guard())
    state = {"close-drain": close} | ({"prepared": args["prepared"]} if prepared else {})
    context = tg.TerminalContext(governance=args["governance"], authority=args["authority"], state=state,
                                 credential_limit=args["credential_limit"], operation_session=args["operation_session"],
                                 clock=args["clock"])
    return tg, context, sts_calls, keeper, journal, events


@pytest.mark.parametrize(("operation", "stage", "policy"), [
    ("terminal-readback", "final", "fence_session_policy"), ("terminal-readback", "recovery", "fence_session_policy"),
    ("reopen", "final", "fence_reopen_session_policy"), ("reopen", "recovery", "fence_observe_session_policy")])
def test_capability_terminal_roda_na_sessao_do_fence_preparado_com_a_politica_da_operacao(monkeypatch, operation, stage,
                                                                                          policy):
    from tools.cnesdata_delivery import application_gate as ag, mode_broker as mb, session_policy as sp
    tg, context, sts_calls, keeper, journal, events = _fence_capability_case(monkeypatch, operation, stage)
    broker = tg.terminal_capability(journal=journal, keeper=keeper, guard=journal._guard, context=context)
    expected = mb.FenceReadBroker if operation == "terminal-readback" else ag.ClosedReadyBroker
    assert type(broker) is expected and keeper._contexts == [broker] and journal._broker is broker
    scope = broker.session.scope
    members = c.loads(journal._inputs["membership"], canonical=True)["members"]
    assert scope.get("members") == (members if operation == "terminal-readback" else None)
    deadline, table = journal._request["stage"]["deadline"], scope["control_table_arn"]
    prefix = scope["machine_arn"].replace(":stateMachine:", ":execution:") + ":"
    builder = getattr(sp, policy)
    document = (builder(control_table_arn=table, deadline=deadline) if policy != "fence_session_policy"
                else builder(control_table_arn=table, execution_prefix=prefix, deadline=deadline))
    (_, _, sent), = [call for call in sts_calls if call[1] == "assume_role"]
    assert sent["Policy"] == c.canonical(document).decode().strip()
    assert context.operation_session.calls == [(operation, "promotion-fence-r1", journal._request["stage"])]
    assert ("sts", "assume_role") in events


@pytest.mark.parametrize("operation", ["terminal-readback", "reopen"])
def test_capability_terminal_sem_pacote_do_fence_recusa_antes_do_sts_e_envenena_o_journal(monkeypatch, operation):
    tg, context, sts_calls, keeper, journal, events = _fence_capability_case(monkeypatch, operation, "final", prepared=False)
    with pytest.raises(ValueError, match="^terminal_broker=prepared_absent$"):
        tg.terminal_capability(journal=journal, keeper=keeper, guard=journal._guard, context=context)
    assert journal._failed is True and [call for call in sts_calls if call[1] == "assume_role"] == []


def test_capability_do_terminal_readback_recusa_membership_que_nao_e_a_do_close_drain(monkeypatch):
    tg, context, sts_calls, keeper, journal, events = _fence_capability_case(monkeypatch, "terminal-readback", "final")
    context.state["close-drain"] = _close_raw([])
    with pytest.raises(ValueError, match="^terminal-readback membership is the close-drain frozen set$"):
        tg.terminal_capability(journal=journal, keeper=keeper, guard=journal._guard, context=context)
    assert journal._failed is True and [call for call in sts_calls if call[1] == "assume_role"] == []


def test_capability_terminal_recusa_contexto_ausente_e_envenena_o_journal():
    from tools.cnesdata_delivery import terminal_gate as tg
    journal = SimpleNamespace(_failed=False, _request={"operation": "reopen"})
    with pytest.raises(ValueError, match="^terminal_broker=unconnected$"):
        tg.terminal_capability(journal=journal, keeper=None, guard=None, context=None)
    assert journal._failed is True


def _rollback_parameters(key, version, **changes):
    from test_cnesdata_static_stage import BUCKET
    return {"Bucket": BUCKET, "Key": key, "CopySource": {"Bucket": BUCKET, "Key": key, "VersionId": version},
            "ChecksumAlgorithm": "SHA256", "MetadataDirective": "COPY"} | changes


def _rollback_plan():
    from test_cnesdata_static_stage import BUCKET, PAIR, _static_inputs
    return lc.static_plan(_static_inputs("a" * 40, rollback=PAIR)["static-plan"], bucket=BUCKET)


def test_rollback_admite_o_copy_object_da_versao_planejada_e_a_invalidacao_sob_o_alias_recovery():
    from test_cnesdata_static_stage import BUCKET, INVALIDATION, PAIR
    plan, request = _rollback_plan(), {"operation": "rollback-api-static"}
    for key, version in PAIR:
        assert lc.validate_static_call(request=request, role="recovery", service="s3", operation="CopyObject",
                                       parameters=_rollback_parameters(key, version), bucket=BUCKET,
                                       plan=plan) == "copy_object"
    _, service, operation, parameters = INVALIDATION
    assert lc.validate_static_call(request=request, role="recovery", service=service, operation=operation,
                                   parameters=parameters, bucket=BUCKET, plan=plan) == "create_invalidation"


@pytest.mark.parametrize(("role", "operation", "parameters"), [
    ("recovery", "CopyObject", _rollback_parameters("index.html", "Other.Version")),
    ("recovery", "CopyObject", _rollback_parameters("index.html", "Prev+Theme=2")),
    ("recovery", "CopyObject", _rollback_parameters("index.html", "Prev.Index_1", MetadataDirective="REPLACE")),
    ("recovery", "CopyObject", _rollback_parameters("index.html", "Prev.Index_1", ChecksumAlgorithm="CRC32")),
    ("recovery", "CopyObject", _rollback_parameters("index.html", "Prev.Index_1", Bucket="other-bucket")),
    ("recovery", "CopyObject", _rollback_parameters("index.html", "Prev.Index_1", ACL="public-read")),
    ("normal", "CopyObject", _rollback_parameters("index.html", "Prev.Index_1")),
    ("recovery", "PutObject", {"Bucket": "cnesdata-prod-static-web", "Key": "index.html"})],
    ids=["versao-fora-do-plano", "versao-de-outra-chave", "diretiva", "checksum", "bucket", "campo-extra", "papel-normal",
         "put-object"])
def test_rollback_recusa_copia_fora_do_par_planejado_ou_fora_do_catalogo(role, operation, parameters):
    from test_cnesdata_static_stage import BUCKET
    with pytest.raises(ValueError):
        lc.validate_static_call(request={"operation": "rollback-api-static"}, role=role, service="s3", operation=operation,
                                parameters=parameters, bucket=BUCKET, plan=_rollback_plan())


def test_sessao_do_rollback_e_a_sp_rollback_do_498_sob_o_alias_recovery():
    binding = {"release_id": "r" + "0" * 31, "run_id": 4242, "run_attempt": 1, "generation": 2,
               "product_source_sha": "a" * 40, "shared_source_sha": "c" * 40, "static_plan_sha256": "9" * 64}
    names = lc.static_sessions(binding, "rollback-api-static")
    expected = "sp-rollback-" + c.sha(c.canonical(binding | {"operation": "rollback"}))[:40]
    assert names == {"recovery": expected}


def test_resposta_do_copy_object_guarda_so_a_versao_e_o_checksum_que_o_produto_le():
    from tools.cnesdata_delivery import application_gate as ag
    response = {"VersionId": "New.1", "CopyObjectResult": {"ChecksumSHA256": "q" * 44, "ETag": '"1f"', "LastModified": 1},
                "ServerSideEncryption": "AES256", "ResponseMetadata": {}}
    assert ag._static_response("CopyObject", response) == {"VersionId": "New.1",
                                                          "CopyObjectResult": {"ChecksumSHA256": "q" * 44}}


def test_iam_efetivo_avalia_a_condicao_bool():
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    role = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*",
                                                    "Condition": {"Bool": {"s3:ObjectCreationOperation": "true"}}}]}
    star = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    assert effective_iam(role, [star], "s3:PutObject", "x", {"s3:ObjectCreationOperation": "true"})
    assert not effective_iam(role, [star], "s3:PutObject", "x", {"s3:ObjectCreationOperation": "false"})
    assert not effective_iam(role, [star], "s3:PutObject", "x", {})


def _recovery_role_policy(plan):
    from test_cnesdata_static_stage import BUCKET, DISTRIBUTION
    expiry = {"DateLessThan": {"aws:CurrentTime": "2027-02-12T00:00:00Z"}}
    statements = [{"Effect": "Allow", "Action": ["cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"],
                   "Resource": DISTRIBUTION, "Condition": expiry}]
    for ref in plan["rollback_versions"]:
        statements += [
            {"Effect": "Allow", "Action": "s3:GetObjectVersion", "Resource": f"arn:aws:s3:::{BUCKET}/{ref['key']}",
             "Condition": expiry | {"StringEquals": {"s3:VersionId": ref["version_id"]}}},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{BUCKET}/{ref['key']}",
             "Condition": expiry | {"StringEquals": {"s3:x-amz-copy-source": f"{BUCKET}/{ref['key']}?versionId="
                                                     + urllib.parse.quote(ref["version_id"], safe="")},
                                    "Bool": {"s3:ObjectCreationOperation": "true"}}}]
    return {"Version": "2012-10-17", "Statement": statements}


def _rollback_sts_case(monkeypatch, *, role_policy=None):
    from datetime import datetime, timezone
    from test_cnesdata_application_gate import _adapter_case
    from test_cnesdata_static_stage import ACCOUNT as STATIC_ACCOUNT, EVIDENCE_GOVERNANCE, PAIR, _static_inputs
    from tools.cnesdata_delivery import application_gate as ag, aws_boundary
    _, owner, window, _ = _adapter_case("closed-ready")
    window.update(stage="recovery", admitted_at=1500, deadline=1700,
                  decision={"choice_at": 1490, "deadline": 1910, "checkpoint_sha256": "7" * 64})
    static = _static_inputs(owner["source_sha"], rollback=PAIR)
    inputs = {"static-plan": static["static-plan"], "inventory": static["inventory"], "publication": b"null",
              "host-recovery-receipt": c.canonical({"fixture": "host"}), "recovery-decision": c.canonical({"f": 1})}
    activation = b"p" * 40
    journal = ag.AdapterJournal(ag._operation_request("rollback-api-static", owner=owner, window=window, inputs=inputs,
                                                      activation=activation),
                                operation="rollback-api-static", owner=owner, window=window, inputs=inputs,
                                activation_sha256=c.sha(activation), guard=SimpleNamespace(check=lambda seconds=0: None))
    governance = EVIDENCE_GOVERNANCE | {"application_delegations": EVIDENCE_GOVERNANCE["application_delegations"] | {
        "recovery": f"arn:aws:iam::{STATIC_ACCOUNT}:role/cnesdata-prod-static-recovery"}}
    binding = ag._static_binding(governance, journal, candidate=static["candidate"])
    names = lc.static_sessions(binding, "rollback-api-static")
    role_arn = governance["application_delegations"]["recovery"]
    plan = lc.static_plan(inputs["static-plan"], bucket="cnesdata-prod-static-web")
    roles = {"recovery": {"role_arn": role_arn, "role_name": "cnesdata-prod-static-recovery", "role_id": "AROARECOVERYXXXXXXXXX",
                          "policy_name": "cnesdata-prod-static-recovery-runtime",
                          "policy": role_policy or _recovery_role_policy(plan)}}
    assumed = role_arn.replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + names["recovery"]
    calls, factory = [], []

    class Operation:
        def call(self, service, operation, **parameters):
            calls.append((service, operation, parameters))
            return {"PackedPolicySize": 10,
                    "AssumedRoleUser": {"Arn": assumed, "AssumedRoleId": "AROARECOVERYXXXXXXXXX:" + names["recovery"]},
                    "Credentials": {"AccessKeyId": "recovery", "SecretAccessKey": "s", "SessionToken": "t",
                                    "Expiration": datetime.fromtimestamp(1505 + 900, timezone.utc)}}

    class Delegated:
        def __init__(self, governance, *, credentials):
            self.identity = {"Account": STATIC_ACCOUNT, "Arn": assumed,
                             "UserId": "AROARECOVERYXXXXXXXXX:" + names["recovery"]}
    monkeypatch.setattr(aws_boundary, "AWS", Delegated)
    args = dict(governance=governance, journal=journal, binding=binding, roles=roles, credential_limit=1505 + 900,
                operation_session=lambda *item: factory.append(item) or Operation(), clock=lambda: 1505)
    return ag, args, names, calls, factory, plan


def test_sessao_estatica_do_rollback_assume_o_recovery_com_a_politica_do_par_planejado(monkeypatch):
    from test_cnesdata_static_stage import BUCKET, DISTRIBUTION
    from tools.cnesdata_delivery import session_policy as sp
    ag, args, names, calls, factory, plan = _rollback_sts_case(monkeypatch)
    session = ag._assume_static_session(**args)
    stage = args["journal"]._request["stage"]
    assert factory == [("rollback-api-static", {"recovery": names["recovery"]}, stage)]
    policy = sp.static_session_policy("recovery", bucket_arn="arn:aws:s3:::" + BUCKET, distribution_arn=DISTRIBUTION,
                                      deadline=stage["deadline"], keys=["index.html", "theme-init.js"])
    (_, operation, parameters), = calls
    assert operation == "assume_role" and parameters == {
        "RoleArn": args["roles"]["recovery"]["role_arn"], "RoleSessionName": names["recovery"], "DurationSeconds": 900,
        "Policy": c.canonical(policy).decode().strip()}
    assert set(session.clients) == {"recovery"} and session.deadline == stage["deadline"] and session.scope["plan"] == plan
    broker = ag.StaticBroker(session.evidence, args["governance"], args["journal"], session, clock=args["clock"])
    assert broker.prepared_sha256 == c.sha(args["journal"]._inputs["static-plan"])


def test_sessao_estatica_do_rollback_recusa_papel_sem_a_copia_do_par_planejado_antes_do_sts(monkeypatch):
    from test_cnesdata_static_stage import DISTRIBUTION
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "cloudfront:CreateInvalidation",
                                                      "Resource": DISTRIBUTION}]}
    ag, args, names, calls, factory, plan = _rollback_sts_case(monkeypatch, role_policy=policy)
    with pytest.raises(ValueError, match="^static_role=effective_iam alias=recovery action=s3:GetObjectVersion$"):
        ag._assume_static_session(**args)
    assert calls == [] and factory == []


def test_politica_da_sessao_recovery_concede_so_a_copia_das_chaves_e_a_invalidacao_ate_o_prazo():
    from test_cnesdata_static_stage import BUCKET, DISTRIBUTION
    from tools.cnesdata_delivery import session_policy as sp
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    bucket = "arn:aws:s3:::" + BUCKET
    role = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    policy = sp.static_session_policy("recovery", bucket_arn=bucket, distribution_arn=DISTRIBUTION, deadline=2000,
                                      keys=["index.html", "theme-init.js"])
    for action, resource in (("s3:GetObjectVersion", bucket + "/index.html"), ("s3:PutObject", bucket + "/theme-init.js"),
                             ("cloudfront:CreateInvalidation", DISTRIBUTION)):
        assert effective_iam(role, [policy], action, resource, {"aws:CurrentTime": c.utc(1999)})
        assert not effective_iam(role, [policy], action, resource, {"aws:CurrentTime": c.utc(2000)})
    for action, resource in (("s3:PutObject", bucket + "/assets/a.js"), ("s3:DeleteObjectVersion", bucket + "/index.html"),
                             ("s3:GetObject", bucket + "/index.html")):
        assert not effective_iam(role, [policy], action, resource, {"aws:CurrentTime": c.utc(1999)})
    empty = sp.static_session_policy("recovery", bucket_arn=bucket, distribution_arn=DISTRIBUTION, deadline=2000, keys=[])
    assert [statement["Action"] for statement in empty["Statement"]] == [["cloudfront:CreateInvalidation"]]


def test_capability_do_rollback_autentica_plano_binding_e_papel_e_anexa_o_static_broker(monkeypatch):
    from test_cnesdata_static_stage import PAIR, _static_inputs
    from tools.cnesdata_delivery import application_gate as ag, static_inputs, terminal_gate as tg
    ag_mod, args, names, calls, factory, plan = _rollback_sts_case(monkeypatch)
    journal = args["journal"]
    candidate = _static_inputs(journal._request["owner"]["source_sha"], rollback=PAIR)["candidate"]
    seen = []
    monkeypatch.setattr(static_inputs, "carrier_binding", lambda terraform: seen.append(("carrier", terraform)) or "carrier")
    monkeypatch.setattr(ag, "_compare_carrier", lambda binding, carrier: seen.append(("compare", binding, carrier)))
    monkeypatch.setattr(static_inputs, "static_role_facts",
                        lambda checkpoint, approval, *, governance, aliases: seen.append(("roles", aliases)) or args["roles"])
    keeper = SimpleNamespace(_contexts=[], static_inputs={"candidate": candidate},
                             lease=SimpleNamespace(check=lambda: {"held": True}))
    keeper.attach = keeper._contexts.append
    state = {"static-plan": journal._inputs["static-plan"], "terraform": "carrier-terraform",
             "prepared": {"checkpoint.json": b"cp", "approval.json": b"ap"}}
    context = tg.TerminalContext(governance=args["governance"], authority=None, state=state,
                                 credential_limit=args["credential_limit"], operation_session=args["operation_session"],
                                 clock=args["clock"])
    broker = tg.terminal_capability(journal=journal, keeper=keeper, guard=journal._guard, context=context)
    assert type(broker) is ag.StaticBroker and keeper._contexts == [broker] and journal._broker is broker
    assert seen == [("carrier", "carrier-terraform"), ("compare", args["binding"], "carrier"), ("roles", ("recovery",))]
    assert set(broker.session.clients) == {"recovery"} and [call[1] for call in calls] == ["assume_role"]


def test_capability_do_rollback_recusa_plano_que_nao_e_o_do_estado_antes_do_sts(monkeypatch):
    from tools.cnesdata_delivery import terminal_gate as tg
    ag_mod, args, names, calls, factory, plan = _rollback_sts_case(monkeypatch)
    journal = args["journal"]
    keeper = SimpleNamespace(_contexts=[], static_inputs={}, lease=SimpleNamespace(check=lambda: {"held": True}))
    context = tg.TerminalContext(governance=args["governance"], authority=None, state={"static-plan": b"other"},
                                 credential_limit=args["credential_limit"], operation_session=args["operation_session"],
                                 clock=args["clock"])
    with pytest.raises(ValueError, match="^terminal rollback static plan$"):
        tg.terminal_capability(journal=journal, keeper=keeper, guard=journal._guard, context=context)
    assert journal._failed is True and calls == [] and factory == []


def _element(routes):
    return (__import__("json").dumps({"kind": "phase-c-audit", "routes": routes, "version": 1}, sort_keys=True,
                                     separators=(",", ":")) + "\n").encode()


def test_routing_do_final_e_a_projecao_das_rotas_da_evidencia_phase_c_audit_e_nao_dos_alvos_renderizados(monkeypatch):
    from test_cnesdata_terminal_gate import _accepted_world, _loop
    from tools.cnesdata_delivery import terminal_gate as tg
    real = tg.terminal_input_source
    world, state = _accepted_world(monkeypatch)
    monkeypatch.setattr(tg, "terminal_input_source", real)
    routes = {"unit": "arn:unit:9", "recovery": "arn:recovery:9", "audit": "arn:audit:9"}
    assert all(routes[mode] != state["revisions"][mode] for mode in routes)
    world.keeper.phase_c_elements["phase-c-audit"] = _element(routes)
    world.next_event = lambda window: pytest.fail("no event at final")
    outcome = _loop(world)
    assert outcome["kind"] == "accepted-open"
    reopen = next(call[3] for call in world.terminal.calls if call[0] == "reopen")
    assert reopen["routing"] == c.canonical(routes)


@pytest.mark.parametrize("element", [
    None, b"{}", _element({"unit": "u", "recovery": "r"}), _element({"unit": "u", "recovery": "r", "audit": None}),
    _element({"unit": "u", "recovery": "r", "audit": "a", "extra": "x"}),
    _element({"unit": "u", "recovery": "r", "audit": "a"}).replace(b"phase-c-audit", b"phase-c-recovery")],
    ids=["ausente", "sem-rotas", "modo-faltando", "modo-nulo", "modo-extra", "outro-elemento"])
def test_routing_do_final_recusa_elemento_phase_c_audit_sem_as_tres_rotas(element):
    from tools.cnesdata_delivery import terminal_gate as tg
    keeper = SimpleNamespace(phase_c_elements={} if element is None else {"phase-c-audit": element})
    with pytest.raises(ValueError, match="^terminal final routing$"):
        tg.terminal_input_source(keeper=keeper, owner={}, window={"stage": "final"}, operation="reopen", names=["routing"])


@pytest.mark.parametrize(("operation", "stage", "names"), [
    ("reopen", "recovery", ["routing"]), ("terminal-readback", "final", ["routing"]), ("reopen", "final", ["canaries"])])
def test_fonte_de_insumos_terminal_so_serve_o_routing_do_reopen_no_final(operation, stage, names):
    from tools.cnesdata_delivery import terminal_gate as tg
    keeper = SimpleNamespace(phase_c_elements={"phase-c-audit": _element({"unit": "u", "recovery": "r", "audit": "a"})})
    with pytest.raises(ValueError, match="^terminal_inputs=source_unconnected$"):
        tg.terminal_input_source(keeper=keeper, owner={}, window={"stage": stage}, operation=operation, names=names)


@pytest.mark.parametrize(("operation", "role", "sessions"), [
    ("reopen", {"session_name": "promotion-fence-r1"}, {"fence_operator": "promotion-fence-r1"}),
    ("terminal-readback", {"session_name": "promotion-fence-r1"}, {"fence_operator": "promotion-fence-r1"}),
    ("rollback-api-static", {"recovery": "sp-rollback-" + "0" * 40}, {"recovery": "sp-rollback-" + "0" * 40})])
def test_fabrica_de_sessao_de_operacao_serve_as_tres_operacoes_terminais(monkeypatch, operation, role, sessions):
    from test_cnesdata_application_gate import _operation_factory_case
    factory, admitted, world, stage, seen, client, credentials = _operation_factory_case(monkeypatch)
    assert factory(operation, role, stage) is client
    assert seen[0][2] == {"application_purpose": "promotion", "delegations": tuple(sessions), "sessions": sessions}
