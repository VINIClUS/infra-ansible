"""Keeper-published plan inputs: the publisher writes, the plan gate reads with the DD-2 consumer interval."""
import copy
import io
import zipfile
from types import SimpleNamespace

import pytest

from tools.cnesdata_delivery import contract as c

SOURCE, RUN, ATTEMPT = "b" * 40, 44, 2
STEP = "phase-b-plan"
GOVERNANCE = {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "evidence", "context_kind": "promotion"}
OWNER = {"source_sha": SOURCE, "run_id": RUN, "run_attempt": ATTEMPT, "owner_sha256": "a" * 64, "generation": 3,
         "application_purpose": "promotion", "context_kind": "promotion", "caller_binding_sha256": "e" * 64}
PHASE = {"image_digest": "sha256:" + "8" * 64, "processor_active_unit_task_definition_arn": "arn:a",
         "processor_retained_unit_task_definition_arns": [], "canary_storage_enabled": True,
         "canary_release_id": "r1", "canary_trusted_principal_arn": "arn:aws:iam::111122223333:role/app"}
INPUTS = c.canonical(PHASE | {"static_promotion": None, "mode_canary": None})
NAME = f"cnesdata-plan-inputs-{STEP}-{RUN}-{ATTEMPT}"


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put(self, bucket, key, raw):
        self.objects[key] = raw

    def get(self, bucket, key, maximum=None):
        return self.objects[key], {}


class FakeApi:
    def __init__(self):
        self.jobs = [{"name": "plan", "status": "in_progress", "conclusion": None, "id": 9, "started_at": "2026-11-25T10:00:00Z"}]
        self.artifacts, self.zips = [], {}
        self.metadata = {}

    def add(self, name, files, *, created="2026-11-25T10:05:00Z", artifact_id=70):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for member, raw in files.items():
                archive.writestr(member, raw)
        raw = buffer.getvalue()
        digest = "sha256:" + c.sha(raw)
        self.artifacts.append({"id": artifact_id, "name": name, "created_at": created, "digest": digest})
        self.metadata[artifact_id] = {"id": artifact_id, "name": name, "digest": digest, "expired": False,
                                      "expires_at": "2026-12-25T10:00:00Z", "created_at": created,
                                      "workflow_run": {"id": RUN, "head_sha": SOURCE}}
        self.zips[artifact_id] = raw

    def read(self, path, raw=False):
        if path.endswith("/zip"):
            return self.zips[int(path.rsplit("/", 2)[1])]
        if "/jobs?" in path:
            return {"total_count": len(self.jobs), "jobs": self.jobs}
        if "/artifacts?" in path:
            return {"total_count": len(self.artifacts), "artifacts": self.artifacts}
        return self.metadata[int(path.rsplit("/", 1)[1])]


def _published(s3, api, *, raw=INPUTS, owner=OWNER, step=STEP, extra=None):
    from tools.cnesdata_delivery import plan_inputs
    files = {"inputs.json": raw} | (extra or {})
    prefix = f"cnesdata/prod/evidence/lifecycle/{SOURCE}/{RUN}/{ATTEMPT}/{plan_inputs.step_name(step)}/"
    for name, data in files.items():
        s3.put("evidence", prefix + name, data)
    index = plan_inputs.index_bytes(owner, step=step, files=files, source_sha=SOURCE, run=RUN, attempt=ATTEMPT)
    api.add(NAME, {"index.json": index})


def _read(s3, api, owner=OWNER):
    from tools.cnesdata_delivery import plan_inputs
    return plan_inputs.read_plan_inputs(api=api, aws=s3, governance=GOVERNANCE, request={"source_sha": SOURCE, "step": STEP},
                                        run={"id": RUN, "run_attempt": ATTEMPT}, step={"job_name": "plan"}, owner=owner,
                                        guard=SimpleNamespace(check=lambda *a: None), now=c.instant("2026-11-25T11:00:00Z"))


def test_le_as_entradas_publicadas_pelo_keeper_durante_o_job_do_plano():
    s3, api = FakeS3(), FakeApi()
    _published(s3, api)
    assert _read(s3, api) == INPUTS


def test_recusa_job_do_plano_fora_de_andamento():
    s3, api = FakeS3(), FakeApi()
    _published(s3, api)
    api.jobs[0] |= {"status": "completed", "conclusion": "success"}
    with pytest.raises(ValueError, match="plan_inputs=consumer_not_in_progress"):
        _read(s3, api)


def test_recusa_artefato_criado_antes_do_inicio_do_job():
    s3, api = FakeS3(), FakeApi()
    _published(s3, api)
    api.artifacts[0]["created_at"] = "2026-11-25T09:59:59Z"
    with pytest.raises(ValueError, match="plan_inputs=publication_interval"):
        _read(s3, api)


def test_recusa_dois_artefatos_com_o_mesmo_nome():
    s3, api = FakeS3(), FakeApi()
    _published(s3, api)
    api.add(NAME, {"index.json": b"{}"}, artifact_id=71)
    with pytest.raises(ValueError, match="plan_inputs=publication_unique"):
        _read(s3, api)


def test_recusa_artefato_ausente():
    with pytest.raises(ValueError, match="plan_inputs=publication_unique"):
        _read(FakeS3(), FakeApi())


def test_recusa_artefato_criado_exatamente_no_inicio_do_job():
    s3, api = FakeS3(), FakeApi()
    _published(s3, api)
    api.artifacts[0]["created_at"] = "2026-11-25T10:00:00Z"
    with pytest.raises(ValueError, match="plan_inputs=publication_interval"):
        _read(s3, api)


def test_recusa_artefato_criado_depois_do_relogio_atual():
    s3, api = FakeS3(), FakeApi()
    _published(s3, api)
    api.artifacts[0]["created_at"] = "2026-11-25T11:00:01Z"
    with pytest.raises(ValueError, match="plan_inputs=publication_interval"):
        _read(s3, api)


def test_static_promotion_recusa_inventario_diferente_do_registrado_no_plano():
    from tools.cnesdata_delivery import plan_inputs
    vector = _vector()
    with pytest.raises(ValueError, match="plan_inputs=static_plan_inventory"):
        plan_inputs.static_promotion_input(
            binding=vector["binding"], application_promotion=vector["application_promotion"], enabled_until=vector["enabled_until"],
            plan=bytes.fromhex(vector["plan_hex"]), inventory=bytes.fromhex(vector["inventory_hex"]) + b" ")


@pytest.mark.parametrize("change", [{"owner_sha256": "f" * 64}, {"generation": 4}])
def test_recusa_dono_ou_geracao_diferentes_do_lease(change):
    s3, api = FakeS3(), FakeApi()
    _published(s3, api, owner=OWNER | change)
    with pytest.raises(ValueError, match="plan_inputs=owner"):
        _read(s3, api)


def test_recusa_arquivo_extra_no_indice():
    s3, api = FakeS3(), FakeApi()
    _published(s3, api, extra={"checkpoint.json": b"{}"})
    with pytest.raises(ValueError, match="plan_inputs=files"):
        _read(s3, api)


def test_recusa_bytes_privados_diferentes_do_indice():
    s3, api = FakeS3(), FakeApi()
    _published(s3, api)
    key = f"cnesdata/prod/evidence/lifecycle/{SOURCE}/{RUN}/{ATTEMPT}/plan-inputs-{STEP}/inputs.json"
    s3.objects[key] = INPUTS + b" "
    with pytest.raises(ValueError):
        _read(s3, api)


def test_recusa_passo_do_indice_diferente_do_plano():
    s3, api = FakeS3(), FakeApi()
    _published(s3, api, step="phase-c-audit-plan")
    api.artifacts[0]["name"] = NAME
    with pytest.raises(ValueError):
        _read(s3, api)


def test_attach_so_age_no_papel_plan_e_registra_a_origem(monkeypatch):
    from tools.cnesdata_delivery import plan_inputs
    monkeypatch.setattr(plan_inputs, "read_plan_inputs", lambda **context: INPUTS)
    for role in ("audit", "deploy"):
        payload, origins = {}, {}
        plan_inputs.attach(role, payload, origins, request={"step": STEP})
        assert payload == {} and origins == {}
    payload, origins = {}, {}
    plan_inputs.attach("plan", payload, origins, request={"step": STEP})
    assert payload == {"inputs.json": INPUTS} and origins == {"inputs.json": "plan-inputs-" + STEP}


def test_attach_recusa_inputs_de_outra_fonte_no_plano(monkeypatch):
    from tools.cnesdata_delivery import plan_inputs
    monkeypatch.setattr(plan_inputs, "read_plan_inputs", lambda **context: INPUTS)
    with pytest.raises(ValueError, match="ambiguous private payload"):
        plan_inputs.attach("plan", {"inputs.json": b"{}"}, {}, request={"step": STEP})


def _vector():
    import json
    from pathlib import Path
    return json.loads((Path(__file__).parent / "fixtures" / "cnesdata_plan_inputs_p25_vector.json").read_text())


def test_static_promotion_e_inputs_reproduzem_o_vetor_gerado_pelo_produto():
    from tools.cnesdata_delivery import plan_inputs
    vector = _vector()
    promotion = plan_inputs.static_promotion_input(
        binding=vector["binding"], application_promotion=vector["application_promotion"], enabled_until=vector["enabled_until"],
        plan=bytes.fromhex(vector["plan_hex"]), inventory=bytes.fromhex(vector["inventory_hex"]))
    assert promotion == vector["static_promotion"]
    assert plan_inputs.inputs_bytes(vector["base"], promotion, None) == bytes.fromhex(vector["inputs_hex"])


def test_vetor_fixa_a_fonte_do_gerador_do_produto_no_merge_do_p35c():
    assert _vector()["generator"] == {
        "repository": "VINIClUS/CnesData", "commit": "182dc74c",
        "path": "scripts/promotion/lifecycle_inputs.py",
        "sha256": "d40a5ec96d14d3ddac2fbf8afea715c352ec4e3cb0ef51234b348dbe92ff28a9"}


def test_bootstrap_reproduz_o_vetor_do_produto_sem_plano_nem_inventory():
    from tools.cnesdata_delivery import plan_inputs
    vector = _vector()
    promotion = plan_inputs.static_bootstrap_input(
        binding=vector["binding"], application_promotion=vector["application_promotion"], enabled_until=vector["enabled_until"])
    assert promotion == vector["bootstrap_static_promotion"]
    assert promotion["binding"]["static_plan_sha256"] is None and promotion["inventory_sha256"] is None
    assert plan_inputs.inputs_bytes(vector["base"], promotion, None) == bytes.fromhex(vector["bootstrap_inputs_hex"])


@pytest.mark.parametrize("change", [{"enabled_until": "tomorrow"}, {"binding": {"release_id": "R"}}], ids=["janela", "binding"])
def test_bootstrap_recusa_entrada_fora_do_contrato(change):
    from tools.cnesdata_delivery import plan_inputs
    vector = _vector()
    arguments = {"binding": vector["binding"], "application_promotion": vector["application_promotion"],
                 "enabled_until": vector["enabled_until"]} | change
    with pytest.raises(ValueError):
        plan_inputs.static_bootstrap_input(**arguments)


def _static_binding(plan_sha):
    return _vector()["binding"] | {"static_plan_sha256": plan_sha}


@pytest.mark.parametrize("operation", ["publish", "retire"])
def test_sessao_estatica_so_admite_plano_nulo_na_inventory(operation):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert lc.static_session(_static_binding(None), "inventory").startswith("sp-i-")
    with pytest.raises(ValueError):
        lc.static_session(_static_binding(None), operation)


def test_binding_do_bootstrap_com_plano_nulo_so_casa_com_a_recomputacao_nula():
    from tools.cnesdata_delivery import static_inputs as si
    carrier = si.carrier_binding(c.canonical({"static_promotion": {"mode": "observer-bootstrap", "binding": _static_binding(None)}}))
    si.compare_binding(_static_binding(None), carrier)
    with pytest.raises(ValueError, match="static_binding=carrier_mismatch field=static_plan_sha256"):
        si.compare_binding(_static_binding("a" * 64), carrier)
    operational = si.carrier_binding(c.canonical({"static_promotion": {"mode": "operational", "binding": _static_binding("a" * 64)}}))
    with pytest.raises(ValueError, match="static_binding=carrier_mismatch field=static_plan_sha256"):
        si.compare_binding(_static_binding(None), operational)


@pytest.mark.parametrize("change", [{"plan": b"{}"}, {"enabled_until": "tomorrow"},
                                    {"binding": {"release_id": "R"}}], ids=["plano", "janela", "binding"])
def test_static_promotion_recusa_entrada_fora_do_contrato(change):
    from tools.cnesdata_delivery import plan_inputs
    vector = _vector()
    arguments = {"binding": vector["binding"], "application_promotion": vector["application_promotion"],
                 "enabled_until": vector["enabled_until"], "plan": bytes.fromhex(vector["plan_hex"]),
                 "inventory": bytes.fromhex(vector["inventory_hex"])} | change
    with pytest.raises(ValueError):
        plan_inputs.static_promotion_input(**arguments)


def test_inputs_recusa_chave_reservada_na_base_e_arquivo_acima_do_limite():
    from tools.cnesdata_delivery import plan_inputs
    with pytest.raises(ValueError, match="inputs=reserved_key"):
        plan_inputs.inputs_bytes({"mode_canary": None}, None, None)
    with pytest.raises(ValueError):
        plan_inputs.inputs_bytes({"filler": "x" * 131072}, None, None)


def _publish(monkeypatch, api, s3, *, raw=INPUTS):
    from tools.cnesdata_delivery import application_gate as gate, plan_inputs
    uploads = []
    monkeypatch.setattr(gate, "KeeperGuard", lambda keeper: SimpleNamespace(check=lambda *a: None))
    monkeypatch.setattr(gate, "_upload_keeper_artifact", lambda keeper, api_, run, **kwargs: uploads.append(kwargs) or {"id": 70})
    keeper = SimpleNamespace(governance=GOVERNANCE, evidence_aws=s3)
    plan_inputs.publish_plan_inputs(keeper=keeper, api=api, run={"id": RUN, "run_attempt": ATTEMPT}, owner=OWNER,
                                    plan_step=STEP, step={"job_name": "plan"}, raw=raw, phase_a_inputs=PHASE, credential_limit=0)
    return uploads


def test_publisher_escreve_o_objeto_privado_e_o_indice_que_o_plano_le(monkeypatch):
    s3, api = FakeS3(), FakeApi()
    uploads = _publish(monkeypatch, api, s3)
    assert [upload["name"] for upload in uploads] == [NAME] and set(uploads[0]["files"]) == {"index.json"}
    api.add(NAME, uploads[0]["files"])
    assert _read(s3, api) == INPUTS


def test_publisher_recusa_job_do_plano_ainda_nao_em_andamento(monkeypatch):
    s3, api = FakeS3(), FakeApi()
    api.jobs[0]["status"] = "queued"
    with pytest.raises(ValueError, match="plan_inputs=consumer_not_in_progress"):
        _publish(monkeypatch, api, s3)
    assert s3.objects == {}


def test_publisher_recusa_bytes_vazios_ou_acima_do_limite(monkeypatch):
    for raw in (b"", b"x" * 131073):
        with pytest.raises(ValueError, match="plan_inputs=files"):
            _publish(monkeypatch, FakeApi(), FakeS3(), raw=raw)


def test_base_carrega_as_seis_chaves_originais_da_fase_a_sobre_o_product_inputs():
    from tools.cnesdata_delivery import plan_inputs
    phase = {"image_digest": "sha256:" + "8" * 64, "processor_active_unit_task_definition_arn": "arn:a",
             "processor_retained_unit_task_definition_arns": [], "canary_storage_enabled": True,
             "canary_release_id": "r1", "canary_trusted_principal_arn": "arn:aws:iam::111122223333:role/app"}
    governance = {"product_inputs": {"shared_outputs": {"account_id": "111122223333"}}}
    assert plan_inputs.base_inputs(governance, {"envelope": {"plan": {"phase_a_inputs": phase}}}) == governance["product_inputs"] | phase


def test_base_recusa_chave_do_product_inputs_que_colide_com_a_fase_a_ou_reservada():
    from tools.cnesdata_delivery import plan_inputs
    phase = {"image_digest": "x", "processor_active_unit_task_definition_arn": "x", "processor_retained_unit_task_definition_arns": [],
             "canary_storage_enabled": True, "canary_release_id": "r", "canary_trusted_principal_arn": "x"}
    original = {"envelope": {"plan": {"phase_a_inputs": phase}}}
    for key in ("canary_release_id", "static_promotion"):
        with pytest.raises(ValueError, match="plan_inputs=base_collision"):
            plan_inputs.base_inputs({"product_inputs": {key: 1}}, original)


MODE = {"schema_version": 2, "context_kind": "promotion", "enabled_until": "2026-11-26T00:00:00Z"}


def test_relay_do_mode_canary_autentica_so_o_artefato_do_job_de_inventario(monkeypatch):
    from tools.cnesdata_delivery import application_gate as gate, plan_inputs
    calls = []
    monkeypatch.setattr(gate, "_caller_artifact", lambda api, run, owner, **kwargs: calls.append(kwargs) or {"mode-canary.json": c.canonical(MODE)})
    value = plan_inputs.mode_canary_source(api=None, run={"id": RUN}, owner=OWNER, guard=None, now=0)
    assert value == MODE
    assert calls == [{"job_name": "static-inventory", "name": f"cnesdata-lifecycle-inputs-{RUN}-{ATTEMPT}",
                      "members": {"mode-canary.json"}, "guard": None, "now": 0}]


def test_relay_recusa_membro_nao_objeto_e_acima_do_limite(monkeypatch):
    from tools.cnesdata_delivery import application_gate as gate, plan_inputs
    for raw in (b"[]\n", b'{"a":"' + b"x" * 131072 + b'"}\n'):
        monkeypatch.setattr(gate, "_caller_artifact", lambda *a, **k: {"mode-canary.json": raw})
        with pytest.raises(ValueError, match="plan_inputs=mode_canary"):
            plan_inputs.mode_canary_source(api=None, run={"id": RUN}, owner=OWNER, guard=None, now=0)


@pytest.mark.parametrize("key", sorted(PHASE))
def test_publisher_recusa_entradas_sem_uma_das_seis_chaves_originais(monkeypatch, key):
    value = dict(PHASE | {"static_promotion": None, "mode_canary": None})
    del value[key]
    with pytest.raises(ValueError, match="plan_inputs=custody"):
        _publish(monkeypatch, FakeApi(), FakeS3(), raw=c.canonical(value))


@pytest.mark.parametrize("key", sorted(PHASE))
def test_publisher_recusa_valor_diferente_da_custodia(monkeypatch, key):
    value = dict(PHASE | {"static_promotion": None, "mode_canary": None})
    value[key] = "outro" if key != "canary_storage_enabled" else False
    s3 = FakeS3()
    with pytest.raises(ValueError, match="plan_inputs=custody"):
        _publish(monkeypatch, FakeApi(), s3, raw=c.canonical(value))
    assert s3.objects == {}


def test_binding_release_id_reproduz_o_vetor_do_produto():
    from tools.cnesdata_delivery import static_inputs
    values = _vector()["binding_release_id"]["values"]
    assert len(values) >= 2
    for candidate, expected in values.items():
        assert static_inputs.binding_release_id(candidate) == expected


def test_binding_release_id_usa_31_hex_e_recusa_id_fora_do_formato():
    import hashlib
    from tools.cnesdata_delivery import static_inputs
    candidate = next(iter(_vector()["binding_release_id"]["values"]))
    result = static_inputs.binding_release_id(candidate)
    assert len(result) == 32 and result != "r" + hashlib.sha256(candidate.encode()).hexdigest()[:32]
    for bad in ("candidate-" + "a" * 39 + "-1-1", "candidate-" + "A" * 40 + "-1-1", "candidate-" + "a" * 40 + "-0-1", "x", 7):
        with pytest.raises(ValueError, match="static binding candidate"):
            static_inputs.binding_release_id(bad)
