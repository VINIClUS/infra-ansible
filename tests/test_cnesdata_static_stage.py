"""Estagio static do keeper: broker s3/cloudfront, STS estatico, publish-static e avanco static -> unit (#55, P15)."""
import base64
import hashlib
import io
from datetime import datetime, timezone
from email.utils import formatdate
from types import SimpleNamespace

import pytest

from tools.cnesdata_delivery import contract as c

ACCOUNT = "111122223333"
BUCKET = "cnesdata-prod-static-web"
DISTRIBUTION = "arn:aws:cloudfront::111122223333:distribution/E2SYNTHETIC0"
ROLES = {"observer": "arn:aws:iam::111122223333:role/cnesdata-prod-static-observer",
         "normal": "arn:aws:iam::111122223333:role/cnesdata-prod-static-normal"}
GATE_SHA = "c" * 40
ACTIVATION = b"p" * 40
PAIR = (("index.html", "Prev.Index_1"), ("theme-init.js", "Prev+Theme=2"))
KEYS = ("assets/app.js", "index.html", "theme-init.js")
BODIES = {"assets/app.js": b"console.log(1)\n", "index.html": b"<!doctype html><script src=\"/assets/app.js\"></script>\n",
          "theme-init.js": b"document.documentElement.dataset.theme='light'\n"}
TYPES = {"assets/app.js": ("text/javascript", "public, max-age=31536000, immutable"),
         "index.html": ("text/html", "no-cache"), "theme-init.js": ("text/javascript", "no-cache")}
EVIDENCE_GOVERNANCE = {"role": "application", "account_id": ACCOUNT, "evidence_bucket": "synthetic-evidence",
                       "evidence_prefix": "cnesdata/prod/evidence/", "gate_shas": {"application": GATE_SHA},
                       "application_delegations": dict(ROLES)}


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _metadata(status=200):
    return {"RequestId": "native-request", "HTTPStatusCode": status, "HTTPHeaders": {"date": formatdate(usegmt=True)}}


def _static_inputs(source, *, rollback=(), retire=0, plan=None):
    dashboard = b"synthetic-dist-tar"
    inventory = c.canonical({"fixture": "inventory"})
    candidate = c.canonical({"repository": c.REPOSITORY, "source_sha": source, "release_id": f"candidate-{source}-4242-1",
                             "dashboard_sha256": c.sha(dashboard)})
    value = {"schema": "cnesdata.static-plan/v1", "bucket": BUCKET, "distribution_arn": DISTRIBUTION,
             "inventory_sha256": c.sha(inventory), "candidate_keys": sorted(KEYS),
             "rollback_versions": [{"key": key, "version_id": version} for key, version in rollback],
             "retire_versions": [{"key": "assets/old.js", "version_id": f"Old-{index}"} for index in range(retire)],
             "multipart_keys": []} | (plan or {})
    return {"candidate": candidate, "dashboard-artifact": dashboard, "static-plan": c.canonical(value), "inventory": inventory}


class _Guard:
    def __init__(self):
        self.checks = []

    def check(self, seconds=0):
        self.checks.append(seconds)


def _journal(*, rollback=(), retire=0, plan=None, receipt=None, guard=None):
    from test_cnesdata_application_gate import _adapter_case
    from tools.cnesdata_delivery import application_gate as ag
    _, owner, window, _ = _adapter_case("publish-static")
    inputs = _static_inputs(owner["source_sha"], rollback=rollback, retire=retire, plan=plan)
    inputs["host-receipt"] = receipt or c.canonical({"fixture": "host-receipt"})
    request = ag._operation_request("publish-static", owner=owner, window=window, inputs=inputs, activation=ACTIVATION)
    journal = ag.AdapterJournal(request, operation="publish-static", owner=owner, window=window, inputs=inputs,
                                activation_sha256=c.sha(ACTIVATION), guard=guard or _Guard())
    return journal, owner, window, inputs


class _Evidence:
    def __init__(self):
        self.objects, self.writes = {}, []

    def get(self, bucket, key, *, maximum, absent=False):
        return self.objects.get(key), None

    def put(self, bucket, key, raw):
        assert key not in self.objects
        self.writes.append(key)
        self.objects[key] = raw


class _Native:
    """Boundary boto3-shaped client: real-shaped S3/CloudFront responses with the fields the broker must drop."""
    def __init__(self, alias, *, world=None, versions=(), latency=0, error=None):
        self.alias, self.world, self.versions, self.latency, self.error = alias, world, list(versions), latency, error
        self.calls, self.stored, self.counter = [], {}, 0

    def call(self, service, operation, *, region="us-east-2", **kwargs):
        if self.world is not None:
            self.world.native_starts.append(self.world.clock.value)
            self.world.clock.value += self.latency
        self.calls.append((service, operation, region, kwargs))
        if self.error is not None:
            raise self.error
        when = datetime(2026, 11, 1, tzinfo=timezone.utc)
        owner = {"DisplayName": "synthetic-owner", "ID": "f" * 64}
        if operation == "list_object_versions":
            return {"IsTruncated": False, "KeyMarker": "", "VersionIdMarker": "", "Name": BUCKET, "Prefix": "", "MaxKeys": 1000,
                    "Versions": [{"ETag": '"0f"', "ChecksumAlgorithm": ["SHA256"], "Size": 12, "StorageClass": "STANDARD",
                                  "Key": key, "VersionId": version, "IsLatest": True, "LastModified": when, "Owner": owner}
                                 for key, version in self.versions],
                    "DeleteMarkers": [], "ResponseMetadata": _metadata()}
        if operation == "head_object":
            return {"VersionId": kwargs["VersionId"], "ChecksumSHA256": _b64(b"\0" * 32), "ContentLength": 12, "ETag": '"0f"',
                    "LastModified": when, "ResponseMetadata": _metadata()}
        if operation == "list_multipart_uploads":
            return {"Bucket": BUCKET, "IsTruncated": False, "Uploads": [], "ResponseMetadata": _metadata()}
        if operation == "put_object":
            self.counter += 1
            version = f"New.{self.counter}"
            self.stored[kwargs["Key"]] = (kwargs["Body"], version, kwargs["ContentType"], kwargs["CacheControl"])
            return {"ETag": '"1f"', "ChecksumSHA256": kwargs["ChecksumSHA256"], "ServerSideEncryption": "AES256",
                    "VersionId": version, "ResponseMetadata": _metadata()}
        if operation == "get_object":
            body, version, content_type, cache = self.stored[kwargs["Key"]]
            return {"Body": io.BytesIO(body), "ContentType": content_type, "CacheControl": cache, "VersionId": version,
                    "ETag": '"1f"', "ContentLength": len(body), "LastModified": when, "AcceptRanges": "bytes", "Metadata": {},
                    "ResponseMetadata": _metadata()}
        assert operation == "create_invalidation"
        return {"Location": "https://cloudfront.amazonaws.com/2020-05-31/distribution/E2SYNTHETIC0/invalidation/I2SYNTH",
                "Invalidation": {"Id": "I2SYNTH", "Status": "InProgress", "CreateTime": when,
                                 "InvalidationBatch": kwargs["InvalidationBatch"]}, "ResponseMetadata": _metadata(201)}


def _session(journal, clients, evidence):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    plan = lc.static_plan(journal._inputs["static-plan"], bucket=BUCKET)
    return ag._StaticSession(clients, "9" * 64, {"account": ACCOUNT, "bucket": BUCKET, "plan": plan},
                             journal._request["stage"]["deadline"], c.sha(c.canonical(journal._request)), evidence)


def _broker_case(*, versions=PAIR, error=None, clock=None):
    from tools.cnesdata_delivery import application_gate as ag
    journal, owner, window, inputs = _journal(rollback=PAIR)
    evidence = _Evidence()
    clients = {"observer": _Native("observer", versions=versions), "normal": _Native("normal", error=error)}
    broker = ag.StaticBroker(evidence, EVIDENCE_GOVERNANCE, journal, _session(journal, clients, evidence),
                             clock=clock or (lambda: window["admitted_at"] + 5))
    return ag, broker, journal, clients, evidence


def _frame(role, service, operation, parameters):
    return c.canonical({"kind": "call", "role": role, "service": service, "operation": operation, "parameters": parameters})


def _put(key):
    content_type, cache = TYPES[key]
    parameters = {"Bucket": BUCKET, "Key": key, "Body": {"base64": _b64(BODIES[key])}, "ContentType": content_type,
                  "CacheControl": cache, "ChecksumSHA256": _b64(hashlib.sha256(BODIES[key]).digest())}
    return ("normal", "s3", "PutObject", parameters | ({} if key in ("index.html", "theme-init.js") else {"IfNoneMatch": "*"}))


INVALIDATION = ("normal", "cloudfront", "CreateInvalidation", {"DistributionId": "E2SYNTHETIC0", "InvalidationBatch": {
    "Paths": {"Quantity": 2, "Items": ["/index.html", "/theme-init.js"]}, "CallerReference": "0f" * 16}})


def _product_calls(versions):
    """CnesData publish_dashboard.py wire order: list, head per version, multipart, assets, readbacks, roots, invalidation."""
    calls = [("observer", "s3", "ListObjectVersions", {"Bucket": BUCKET})]
    calls += [("observer", "s3", "HeadObject", {"Bucket": BUCKET, "Key": key, "VersionId": version, "ChecksumMode": "ENABLED"})
              for key, version in versions]
    calls += [("observer", "s3", "ListMultipartUploads", {"Bucket": BUCKET}), _put("assets/app.js"),
              ("normal", "s3", "GetObject", {"Bucket": BUCKET, "Key": "assets/app.js"})]
    for key in ("index.html", "theme-init.js"):
        calls += [_put(key), ("normal", "s3", "GetObject", {"Bucket": BUCKET, "Key": key})]
    return calls + [INVALIDATION]


def test_broker_estatico_despacha_list_object_versions_real_e_devolve_so_os_campos_que_o_produto_le():
    ag, broker, journal, clients, evidence = _broker_case(versions=PAIR + (("assets/old.js", "Old-1"),))
    reply, result = ag._adapter_message(_frame("observer", "s3", "ListObjectVersions", {"Bucket": BUCKET}), journal)
    assert result is None and reply["kind"] == "sdk-result"
    assert clients["observer"].calls == [("s3", "list_object_versions", "us-east-2", {"Bucket": BUCKET})]
    assert reply["value"] == {"IsTruncated": False, "DeleteMarkers": [], "Versions": [
        {"Key": key, "VersionId": version, "IsLatest": True, "LastModified": "2026-11-01T00:00:00Z", "Size": 12}
        for key, version in PAIR + (("assets/old.js", "Old-1"),)]}
    assert len(journal.call_receipts) == 1 and journal.pending == journal.unknown == [] and broker.uncertainty == []
    assert len(evidence.writes) == 3 and all("/publish-static/" in key for key in evidence.writes)
    assert all(b"synthetic-owner" not in raw and b"STANDARD" not in raw for raw in [*evidence.objects.values(),
                                                                                   *journal.call_bytes.values()])


def test_broker_estatico_envia_o_put_object_com_os_bytes_decodificados_e_o_checksum_do_produto():
    ag, broker, journal, clients, evidence = _broker_case()
    role, service, operation, parameters = _put("assets/app.js")
    reply, _ = ag._adapter_message(_frame(role, service, operation, parameters), journal)
    (call,) = clients["normal"].calls
    assert call[:3] == ("s3", "put_object", "us-east-2")
    assert call[3] == parameters | {"Body": BODIES["assets/app.js"]} and type(call[3]["Body"]) is bytes
    assert reply == {"kind": "sdk-result", "value": {"VersionId": "New.1", "ChecksumSHA256": parameters["ChecksumSHA256"]}}
    assert broker.uncertainty == [] and journal.unknown == [] and len(journal.call_receipts) == 1


def test_broker_estatico_le_o_get_object_como_base64_e_cria_a_invalidacao_no_endpoint_global():
    ag, broker, journal, clients, evidence = _broker_case()
    ag._adapter_message(_frame(*_put("index.html")), journal)
    reply, _ = ag._adapter_message(_frame("normal", "s3", "GetObject", {"Bucket": BUCKET, "Key": "index.html"}), journal)
    assert reply["value"] == {"Body": {"base64": _b64(BODIES["index.html"])}, "VersionId": "New.1",
                              "ContentType": "text/html", "CacheControl": "no-cache"}
    reply, _ = ag._adapter_message(_frame(*INVALIDATION), journal)
    assert reply["value"] == {"Invalidation": {"Id": "I2SYNTH"}}
    assert clients["normal"].calls[-1][:3] == ("cloudfront", "create_invalidation", "us-east-1")
    assert clients["normal"].calls[-1][3] == INVALIDATION[3]
    assert len(journal.call_receipts) == 3 and broker.uncertainty == [] and len(evidence.writes) == 9


@pytest.mark.parametrize("call", [
    ("normal", "s3", "DeleteObject", {"Bucket": BUCKET, "Key": "assets/old.js", "VersionId": "Old-1"}),
    ("observer", "s3", "PutObject", _put("assets/app.js")[3]),
    ("observer", "s3", "ListObjectVersions", {"Bucket": "other-static-web"}),
    ("normal", "s3", "PutObject", _put("assets/app.js")[3] | {"Key": "assets/foreign.js"}),
    ("normal", "s3", "PutObject", _put("assets/app.js")[3] | {"ChecksumSHA256": _b64(b"\1" * 32)})])
def test_broker_estatico_recusa_chamada_fora_do_catalogo_antes_de_evidencia_ou_io(call):
    ag, broker, journal, clients, evidence = _broker_case()
    with pytest.raises(ValueError):
        ag._adapter_message(_frame(*call), journal)
    assert clients["observer"].calls == clients["normal"].calls == [] and evidence.objects == {}


def test_broker_estatico_torna_desconhecida_a_falha_nativa_e_nao_repete():
    ag, broker, journal, clients, evidence = _broker_case(error=TimeoutError("late S3 response"))
    with pytest.raises(TimeoutError):
        ag._adapter_message(_frame(*_put("assets/app.js")), journal)
    assert len(clients["normal"].calls) == 1 and broker.uncertainty and journal.unknown and journal._failed
    with pytest.raises(ValueError):
        ag._adapter_message(_frame(*_put("assets/app.js")), journal)
    assert len(clients["normal"].calls) == 1


def test_broker_estatico_recusa_chamada_sem_vinte_segundos_antes_do_prazo_do_estagio():
    journal_deadline = _journal()[2]["deadline"]
    ag, broker, journal, clients, evidence = _broker_case(clock=lambda: journal_deadline - 20)
    with pytest.raises(ValueError, match="original finite SDK request/window"):
        ag._adapter_message(_frame("observer", "s3", "ListObjectVersions", {"Bucket": BUCKET}), journal)
    assert clients["observer"].calls == [] and evidence.objects == {}


def test_keeper_trata_o_broker_estatico_como_contexto_original():
    from test_cnesdata_application_gate import _prepare_stage_keeper
    ag, broker, journal, clients, evidence = _broker_case(error=TimeoutError("late S3 response"))
    keeper, _ = _prepare_stage_keeper()
    keeper.attach(broker)
    assert keeper.uncertainty() == []
    with pytest.raises(TimeoutError):
        ag._adapter_message(_frame(*_put("assets/app.js")), journal)
    assert {"kind": "context-failed"} in keeper.uncertainty() and broker.uncertainty[0] in keeper.uncertainty()


def test_binding_estatico_e_o_do_498_derivado_do_dono_do_candidato_e_do_plano():
    from tools.cnesdata_delivery import application_gate as ag
    journal, owner, _, inputs = _journal()
    release = f"candidate-{owner['source_sha']}-4242-1"
    assert ag._static_binding(EVIDENCE_GOVERNANCE, journal) == {
        "release_id": "r" + hashlib.sha256(release.encode()).hexdigest()[:31], "run_id": owner["run_id"],
        "run_attempt": owner["run_attempt"], "generation": owner["generation"], "product_source_sha": owner["source_sha"],
        "shared_source_sha": GATE_SHA, "static_plan_sha256": c.sha(inputs["static-plan"])}


@pytest.mark.parametrize("change", [{"source_sha": "e" * 40}, {"release_id": "candidate-" + "e" * 40 + "-4242-1"},
                                    {"release_id": "candidate-x"}, {"release_id": 7}])
def test_binding_estatico_recusa_candidato_de_outra_fonte(change):
    from tools.cnesdata_delivery import application_gate as ag
    journal, owner, _, inputs = _journal()
    journal._inputs["candidate"] = c.canonical(c.loads(inputs["candidate"]) | change)
    with pytest.raises(ValueError, match="^static binding candidate$"):
        ag._static_binding(EVIDENCE_GOVERNANCE, journal)


def _sts_case(monkeypatch, mutation=None):
    from tools.cnesdata_delivery import application_gate as ag, aws_boundary, lifecycle_contract as lc
    journal, owner, window, inputs = _journal()
    binding = ag._static_binding(EVIDENCE_GOVERNANCE, journal)
    names = lc.static_sessions(binding, "publish-static")
    calls, factory_calls, built = [], [], []

    def assumed(alias):
        role = ROLES[alias]
        return role.replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + names[alias]

    class Operation:
        def call(self, service, operation, **parameters):
            calls.append((service, operation, parameters))
            alias = next(name for name, role in ROLES.items() if role == parameters["RoleArn"])
            user = "AROA" + alias.upper().ljust(17, "X") + ":" + parameters["RoleSessionName"]
            if mutation == "foreign-session" and alias == "normal":
                user = user.rsplit(":", 1)[0] + ":sp-publish-" + "0" * 40
            return {"PackedPolicySize": 10, "AssumedRoleUser": {"Arn": assumed(alias), "AssumedRoleId": user}, "Credentials": {
                "AccessKeyId": alias, "SecretAccessKey": "synthetic-secret", "SessionToken": "synthetic-token",
                "Expiration": datetime.fromtimestamp(1505 + 900 + (1 if mutation == "expiration" else 0), timezone.utc)}}
    operation = Operation()

    def factory(name, role, stage):
        factory_calls.append((name, dict(role), dict(stage)))
        return operation

    class Delegated:
        def __init__(self, governance, *, credentials):
            alias = credentials["AccessKeyId"]
            built.append((governance["role"], governance["roles"]))
            arn = assumed(alias) + ("-foreign" if mutation == "arn" and alias == "observer" else "")
            self.identity = {"Account": ACCOUNT, "Arn": arn,
                             "UserId": "AROA" + alias.upper().ljust(17, "X") + ":" + names[alias]}
    monkeypatch.setattr(aws_boundary, "AWS", Delegated)
    clock = (lambda: window["deadline"] - 40) if mutation == "late" else (lambda: 1505)
    args = dict(governance=EVIDENCE_GOVERNANCE, journal=journal, binding=binding, credential_limit=1505 + 900,
                operation_session=factory, clock=clock)
    return ag, args, names, calls, factory_calls, built, operation


def test_sessao_estatica_assume_observer_e_normal_com_os_nomes_do_498_e_a_politica_de_prazo_do_estagio(monkeypatch):
    from tools.cnesdata_delivery import session_policy
    ag, args, names, calls, factory_calls, built, operation = _sts_case(monkeypatch)
    session = ag._assume_static_session(**args)
    stage = args["journal"]._request["stage"]
    assert factory_calls == [("publish-static", {"observer": names["observer"], "normal": names["normal"]}, stage)]
    assert [(item[0], item[1]) for item in calls] == [("sts", "assume_role"), ("sts", "assume_role")]
    for (_, _, parameters), alias in zip(calls, ("observer", "normal")):
        policy = session_policy.static_session_policy(alias, bucket_arn="arn:aws:s3:::" + BUCKET,
                                                      distribution_arn=DISTRIBUTION, deadline=stage["deadline"])
        assert parameters == {"RoleArn": ROLES[alias], "RoleSessionName": names[alias], "DurationSeconds": 900,
                              "Policy": c.canonical(policy).decode().strip()}
        assert len(parameters["Policy"]) <= 2048
    assert built == [(alias, {alias: ROLES[alias]}) for alias in ("observer", "normal")]
    assert set(session.clients) == {"observer", "normal"} and session.evidence is operation
    assert session.deadline == stage["deadline"] and session.scope["bucket"] == BUCKET and session.scope["account"] == ACCOUNT
    assert session.request_binding == c.sha(c.canonical(args["journal"]._request))
    c.digest(session.commitment)


@pytest.mark.parametrize("mutation", ["arn", "foreign-session", "expiration", "late"])
def test_sessao_estatica_recusa_identidade_nativa_validade_ou_janela_fora_do_contrato(monkeypatch, mutation):
    ag, args, names, calls, factory_calls, built, operation = _sts_case(monkeypatch, mutation)
    with pytest.raises(ValueError):
        ag._assume_static_session(**args)
    assert (factory_calls, calls) == ([], []) if mutation == "late" else len(factory_calls) == 1


def test_politica_de_sessao_estatica_concede_so_as_acoes_das_chamadas_do_produto_ate_o_prazo():
    from tools.cnesdata_delivery import session_policy
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    bucket = "arn:aws:s3:::" + BUCKET
    allowed = {"observer": [("s3:ListBucketVersions", bucket), ("s3:ListBucketMultipartUploads", bucket),
                            ("s3:GetObjectVersion", bucket + "/index.html"), ("s3:ListMultipartUploadParts", bucket + "/assets/a.js")],
               "normal": [("s3:PutObject", bucket + "/assets/a.js"), ("s3:GetObject", bucket + "/index.html"),
                          ("cloudfront:CreateInvalidation", DISTRIBUTION)]}
    denied = [("s3:DeleteObjectVersion", bucket + "/assets/a.js"), ("s3:PutObject", "arn:aws:s3:::other/index.html"),
              ("cloudfront:CreateInvalidation", DISTRIBUTION + "X"), ("s3:AbortMultipartUpload", bucket + "/assets/a.js")]
    role = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    for alias, grants in allowed.items():
        policy = session_policy.static_session_policy(alias, bucket_arn=bucket, distribution_arn=DISTRIBUTION, deadline=2000)
        others = [grant for name, items in allowed.items() if name != alias for grant in items]
        for action, resource in grants:
            assert effective_iam(role, [policy], action, resource, {"aws:CurrentTime": c.utc(1999)}), (alias, action)
            assert not effective_iam(role, [policy], action, resource, {"aws:CurrentTime": c.utc(2000)}), (alias, action)
        for action, resource in denied + others:
            assert not effective_iam(role, [policy], action, resource, {"aws:CurrentTime": c.utc(1999)}), (alias, action)


def test_capability_recusa_o_plano_de_43_retire_versions_antes_do_sts():
    """R16 fica fora de P15 (D-C1): o maior plano que o #498 admite recusa fail-closed, sem credencial nem child."""
    from test_cnesdata_application_gate import _prepare_stage_keeper, _retire_static_plan_bound
    from tools.cnesdata_delivery import application_gate as ag
    count = _retire_static_plan_bound()
    assert count == 43
    keeper, store = _prepare_stage_keeper()
    journal, _, _, _ = _journal(retire=count)
    keeper.attach(journal)
    minted = []
    with pytest.raises(ValueError, match="^static_plan=retire_versions_unsupported count=43$"):
        ag.static_capability(governance=EVIDENCE_GOVERNANCE, journal=journal, keeper=keeper, credential_limit=6000,
                             operation_session=lambda *a: minted.append(a), clock=lambda: 1505)
    assert minted == [] and journal._failed and {"kind": "context-failed"} in keeper.uncertainty()
    assert getattr(journal, "_broker", None) is None and store.get()[0]["status"] == "held"


@pytest.mark.parametrize("plan, message", [({"inventory_sha256": "e" * 64}, "static plan inventory binding"),
                                           ({"bucket": "other-static-web"}, "static plan bucket"),
                                           ({"account": "governance-of-another-account"}, "static plan distribution account")])
def test_capability_recusa_plano_fora_do_inventario_do_bucket_ou_da_conta_antes_do_sts(plan, message):
    from test_cnesdata_application_gate import _prepare_stage_keeper
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store = _prepare_stage_keeper()
    account = plan.pop("account", ACCOUNT)
    journal, _, _, _ = _journal(plan=plan)
    minted = []
    with pytest.raises(ValueError, match=message):
        ag.static_capability(governance=EVIDENCE_GOVERNANCE | {"account_id": account}, journal=journal, keeper=keeper,
                             credential_limit=6000,
                             operation_session=lambda *a: minted.append(a), clock=lambda: 1505)
    assert minted == [] and journal._failed and journal in keeper._contexts


@pytest.mark.parametrize("now, credential_limit, expected", [
    (1205, 6000, 1380 - 1205 - 38 - 7), (1205, 1205 + 121 + 7 + 30, 30), (1322, 6000, 13), (1205, 1205 + 121 + 7 + 20, 20)])
def test_static_seconds_e_o_maior_child_que_a_regra_real_de_admissao_do_static_admite(now, credential_limit, expected):
    """180 s do static (STAGES): phase_capacity admite o child com piso max(20, op) e deixa a saida de 7 s do adapter."""
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    window = _static_window()
    seconds = ag._static_seconds(window, credential_limit, now)
    assert seconds == expected and ag.STATIC_RESERVE_SECONDS == ag.ADAPTER_EXIT_SECONDS == 7
    lc.phase_capacity(window, now=now, credential_deadline=credential_limit, operation_seconds=max(20, seconds))
    assert now + seconds + ag.STATIC_RESERVE_SECONDS + 37 < window["deadline"]


@pytest.mark.parametrize("now, credential_limit", [(1323, 6000), (1336, 6000), (1205, 1205 + 121 + 7), (1400, 6000)])
def test_static_seconds_recusa_sem_capacidade_no_estagio_static(now, credential_limit):
    from tools.cnesdata_delivery import application_gate as ag
    with pytest.raises(ValueError):
        ag._static_seconds(_static_window(), credential_limit, now)


def _static_window(windows=None):
    from test_cnesdata_application_gate import MINIMUM_WINDOWS
    from tools.cnesdata_delivery import lifecycle_contract as lc
    api = {"sequence": 2, "stage": "api", "close": 1050, "fixed_deadline": 2850, "input_deadline": 5000, "decision": None,
           "admitted_at": 1130, "deadline": 1310, "preparation_deadline": 2000, "checkpoint_sha256": "e" * 64,
           "windows": MINIMUM_WINDOWS if windows is None else windows}
    return lc.static_window(api, now=1200)


@pytest.mark.parametrize("vector, deadline", [("MINIMUM_WINDOWS", 1300 + 120), ("WINDOWS", 1300 + 180)])
def test_unit_window_segue_o_estagio_static_com_a_janela_governada_do_unit(vector, deadline):
    import test_cnesdata_application_gate as gate
    from tools.cnesdata_delivery import lifecycle_contract as lc
    windows = lc.governed_windows(getattr(gate, vector))
    window = _static_window(windows)
    assert window["deadline"] == 1200 + windows["stages"]["static"]
    assert lc.unit_window(window, now=1300) == window | {"sequence": 4, "stage": "unit", "admitted_at": 1300,
                                                        "deadline": deadline}
    assert lc.unit_window(window | {"fixed_deadline": 1400}, now=1300)["deadline"] == 1400


@pytest.mark.parametrize("change", [{"stage": "api"}, {"close": None}, {"decision": {"choice_at": 1}}, {"admitted_at": 1301}])
def test_unit_window_so_segue_o_estagio_static_fechado(change):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    with pytest.raises(ValueError, match="unit follows the closed static stage"):
        lc.unit_window(_static_window() | change, now=1300)


def test_gatilho_static_e_interno_e_o_event_source_nunca_o_consulta():
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    assert lc.STAGE_TRIGGERS["static"] == ("publish-static", "unit")
    assert "publish-static" not in ag.KEEPER_EVENTS and ag.KEEPER_EVENTS == ("prepared", "phase-b", "host")
    assert ag.BROKERS == (ag.ClosedReadyBroker, ag.StaticBroker)


def test_fabrica_de_sessao_de_operacao_serve_o_publish_static_com_observer_e_normal(monkeypatch):
    from test_cnesdata_application_gate import _operation_factory_case
    factory, admitted, world, stage, seen, client, credentials = _operation_factory_case(monkeypatch)
    sessions = {"observer": "sp-i-" + "1" * 40, "normal": "sp-publish-" + "2" * 40}
    assert factory("publish-static", dict(sessions), stage) is client
    assert seen[0][1:] == ((admitted[0], "b" * 40, 4242, 1, "publish-static"),
                           {"application_purpose": "promotion", "delegations": ("observer", "normal"), "sessions": sessions})
    with pytest.raises(ValueError, match="closed object fields"):
        factory("publish-static", {"observer": sessions["observer"]}, stage)


def _static_world(monkeypatch, *, static=None, **flags):
    from test_cnesdata_stage_events import _api_world
    return _install_static(monkeypatch, _api_world(monkeypatch, **flags), static)


def _install_static(monkeypatch, world, static=None):
    """Static-stage boundaries on a _stage_world: input source, capability (or STS only), child and native S3/CloudFront."""
    from tools.cnesdata_delivery import application_gate as ag
    static = {"capability": "fake", "capability_error": None, "capability_seconds": 5, "observation": {}, "observations": 1,
              "pending": False, "child_seconds": 10, "rollback": (), "versions": (), "latency": 0, "inputs": None} | (static or {})
    world.governance.update({key: value for key, value in EVIDENCE_GOVERNANCE.items() if key not in world.governance})
    world.static = static
    world.static_values = _static_inputs(world.owner["source_sha"], rollback=static["rollback"])
    world.static_requests, world.static_capability, world.native_starts = [], [], []

    def source(**kwargs):
        world.events.append("static_inputs")
        world.static_requests.append(kwargs)
        return dict(static["inputs"] if static["inputs"] is not None else world.static_values)
    monkeypatch.setattr(ag, "static_input_source", source)
    if static["capability"] == "fake":
        def capability(**kwargs):
            world.events.append("static_capability")
            world.static_capability.append(kwargs)
            world.clock.value += static["capability_seconds"]
            journal = kwargs["journal"]
            if static["capability_error"] is not None:
                journal._failed = True
                kwargs["keeper"].attach(journal)
                raise ValueError(static["capability_error"])
            broker = ag.StaticBroker.__new__(ag.StaticBroker)
            broker.aws, broker.evidence, broker.journal = "operation-client", [], journal
            broker.session = SimpleNamespace(clients={"observer": "observer-client", "normal": "normal-client"},
                                             evidence="operation-client")
            journal._broker = broker
            kwargs["keeper"].attach(broker)
            return broker
        monkeypatch.setattr(ag, "static_capability", capability)
    else:
        def assume(**kwargs):
            world.events.append("assume_static_session")
            world.clock.value += static["capability_seconds"]
            journal = kwargs["journal"]
            world.static_evidence = _Evidence()
            world.clients = {"observer": _Native("observer", world=world, versions=static["versions"], latency=static["latency"]),
                             "normal": _Native("normal", world=world, latency=static["latency"])}
            return _session(journal, world.clients, world.static_evidence)
        monkeypatch.setattr(ag, "_assume_static_session", assume)
    inner = ag.invoke_adapter

    def invoke(**kwargs):
        if kwargs["journal"]._request["operation"] != "publish-static":
            return inner(**kwargs)
        world.events.append("invoke_adapter")
        world.invoke.append(kwargs)
        return _publish_static_child(world, kwargs["journal"], kwargs["timeout"])
    monkeypatch.setattr(ag, "invoke_adapter", invoke)
    return world


def _publication(world, journal):
    """With the real capability the product publishes three keys and invalidates; the fake child brokers nothing."""
    real = world.static["capability"] == "real"
    uploaded = [[key, f"New.{index}"] for index, key in enumerate(("assets/app.js", "index.html", "theme-init.js"), start=1)]
    return {"schema": "cnesdata.static-publication/v1", "plan_sha256": c.sha(journal._inputs["static-plan"]),
            "closed_ready_sha256": c.sha(world.ready_raw), "uploaded": uploaded if real else [],
            "already_published": [], "invalidation_id": "I2SYNTH" if real else None} | world.static["observation"]


def _publish_static_child(world, journal, timeout):
    from tools.cnesdata_delivery import application_gate as ag
    static, started = world.static, world.clock.value
    if static["capability"] == "real":
        for call in _product_calls(static["versions"]):
            reply, result = ag._adapter_message(_frame(*call), journal)
            assert result is None and reply["kind"] == "sdk-result"
    raw = c.canonical(_publication(world, journal))
    if static["capability"] == "real":
        frame = c.canonical({"kind": "observe", "observation_kind": "publication", "bytes": _b64(raw)})
        assert ag._adapter_message(frame, journal)[0] == {"sha256": c.sha(raw)}
    else:
        for _ in range(static["observations"]):
            journal._observations.append({"kind": "publication", "sha256": c.sha(raw), "size": len(raw)})
        journal._observation_bytes[c.sha(raw)] = raw
        journal._pending = [{"kind": "sdk-call", "reference_sha256": "f" * 64}] if static["pending"] else []
        world.clock.value += static["child_seconds"]
    world.static_raw = raw
    assert world.clock.value - started <= timeout
    world.clock.value += ag.STATIC_RESERVE_SECONDS


def _publish_journal(world):
    from tools.cnesdata_delivery import application_gate as ag
    found = [item for item in world.keeper._contexts if type(item) is ag.AdapterJournal
             and item._request["operation"] == "publish-static"]
    assert len(found) == 1
    return found[0]


def _lifecycle(world):
    return world.store.get()[0]["lifecycle"]


def test_host_handler_roda_o_publish_static_e_avanca_de_static_para_unit(monkeypatch):
    """P15 RED: api -> static (handoff aceito) -> unit, depois de uma observacao publication liquidada sem incerteza."""
    from test_cnesdata_stage_events import HOST_REFERENCE
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    world = _static_world(monkeypatch)
    before = _lifecycle(world)
    world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert world.events[-4:] == ["authenticate_host_handoff", "static_inputs", "static_capability", "invoke_adapter"]
    journal = _publish_journal(world)
    static = before | {"sequence": 3, "stage": "static", "admitted_at": 1200, "deadline": 1380}
    request, inputs = journal._request, journal._inputs
    assert set(request["inputs"]) == set(inputs) == set(lc.ADAPTER_INPUTS["publish-static"].split())
    assert request["stage"] == {key: static[key] for key in lc.ADAPTER_STAGE_FIELDS.split()}
    assert request["activation_sha256"] == c.sha(world.activation) and request["checkpoint_sha256"] == static["checkpoint_sha256"]
    handoff = c.loads(inputs["host-receipt"], canonical=True)
    assert handoff["status"] == "accepted" and handoff["closed_ready_sha256"] == c.sha(world.ready_raw)
    assert {name: inputs[name] for name in world.static_values} == world.static_values
    (requested,) = world.static_requests
    assert requested == {"keeper": world.keeper, "owner": world.owner, "window": static}
    (capability,) = world.static_capability
    assert {key: capability[key] for key in capability if key not in {"journal", "keeper"}} == {
        "governance": world.governance, "credential_limit": 6000, "operation_session": world.operation_session,
        "clock": world.clock}
    assert capability["journal"] is journal and capability["keeper"] is world.keeper
    (invoked,) = world.invoke[-1:]
    assert invoked["journal"] is journal and invoked["timeout"] == 1380 - 1205 - 38 - 7
    assert _lifecycle(world) == static | {"sequence": 4, "stage": "unit", "admitted_at": 1222, "deadline": 1342}
    assert world.keeper.uncertainty() == [] and world.store.get()[0]["status"] == "held"


def test_host_handler_sem_fonte_dos_insumos_estaticos_recusa_fail_closed_no_estagio_static(monkeypatch):
    """Producao hoje: candidate, dashboard, plano e inventario nao tem fonte autenticada no keeper; o lease fica retido."""
    from test_cnesdata_stage_events import HOST_REFERENCE, _api_world
    world = _api_world(monkeypatch)
    with pytest.raises(ValueError, match="^static_inputs=source_unconnected$"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert _lifecycle(world)["stage"] == "static" and world.store.get()[0]["status"] == "held"
    assert [item for item in world.invoke if item["journal"]._request["operation"] == "publish-static"] == []


_PUBLICATION_REFUSALS = {
    "other-ready": {"observation": {"closed_ready_sha256": "0" * 64}},
    "other-plan": {"observation": {"plan_sha256": "0" * 64}},
    "foreign-key": {"observation": {"uploaded": [["assets/foreign.js", "New.1"]]}},
    "schema": {"observation": {"schema": "cnesdata.static-publication/v2"}},
    "extra": {"observation": {"extra": 1}},
    "two": {"observations": 2},
    "pending": {"pending": True},
}


@pytest.mark.parametrize("mutation", sorted(_PUBLICATION_REFUSALS))
def test_host_handler_so_avanca_com_uma_publicacao_amarrada_ao_plano_e_ao_closed_ready_sem_incerteza(monkeypatch, mutation):
    from test_cnesdata_stage_events import HOST_REFERENCE
    world = _static_world(monkeypatch, static=_PUBLICATION_REFUSALS[mutation])
    with pytest.raises(ValueError, match="publish-static single publication"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert _lifecycle(world)["stage"] == "static" and world.store.get()[0]["status"] == "held"


def test_host_handler_nunca_roda_o_child_quando_a_capability_estatica_recusa(monkeypatch):
    from test_cnesdata_stage_events import HOST_REFERENCE
    world = _static_world(monkeypatch, static={"capability_error": "static capability refused"})
    with pytest.raises(ValueError, match="static capability refused"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert [item for item in world.invoke if item["journal"]._request["operation"] == "publish-static"] == []
    assert _lifecycle(world)["stage"] == "static" and {"kind": "context-failed"} in world.keeper.uncertainty()


def test_host_handler_solta_os_clientes_estaticos_quando_o_publish_static_termina(monkeypatch):
    from test_cnesdata_stage_events import HOST_REFERENCE
    world = _static_world(monkeypatch)
    world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    broker = _publish_journal(world)._broker
    assert broker in world.keeper._contexts
    assert (broker.aws, broker.session.clients, broker.session.evidence) == (None, None, None)


def test_host_handler_recusa_sem_capacidade_depois_da_capability_e_nunca_roda_o_child(monkeypatch):
    from test_cnesdata_stage_events import HOST_REFERENCE
    world = _static_world(monkeypatch, static={"capability_seconds": 1380 - 1200 - 57})
    with pytest.raises(ValueError):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert [item for item in world.invoke if item["journal"]._request["operation"] == "publish-static"] == []
    assert _lifecycle(world)["stage"] == "static" and world.store.get()[0]["status"] == "held"


@pytest.mark.parametrize("rollback, versions", [((), ()), (PAIR, PAIR + (("assets/old.js", "Old-1"),))],
                         ids=["primeira-publicacao", "par-presente"])
def test_publicacao_de_um_candidato_cabe_nos_180_s_do_static_pela_regra_real_de_admissao(monkeypatch, rollback, versions):
    """Broker, evidencia duravel e capability reais; so STS, S3/CloudFront nativos e o child sao fakes (10 s por chamada)."""
    from test_cnesdata_stage_events import HOST_REFERENCE
    world = _static_world(monkeypatch, static={"capability": "real", "rollback": rollback, "versions": versions, "latency": 10})
    world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    journal = _publish_journal(world)
    calls = _product_calls(versions)
    assert len(journal.call_receipts) == len(calls) and len(world.static_evidence.writes) == 3 * len(calls)
    assert journal.pending == journal.unknown == [] and journal._broker.uncertainty == [] and world.keeper.uncertainty() == []
    assert all(start + 20 < 1380 for start in world.native_starts) and len(world.native_starts) == len(calls)
    assert [call[1] for client in world.clients.values() for call in client.calls].count("put_object") == 3
    window = _lifecycle(world)
    assert window["stage"] == "unit" and window["admitted_at"] == 1205 + 10 * len(calls) + 7 < 1380 - 37
    assert world.store.get()[0]["status"] == "held"
    assert (journal._broker.aws, journal._broker.session.clients) == (None, None)
