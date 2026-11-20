"""Observador de leitura (job observe): CI e local com o mesmo codigo (P18, N3a)."""
import copy
import json

import pytest

from fixtures.cnesdata_phase_a_replay import ReplayChain
from fixtures.cnesdata_producers import (EVIDENCE, KEY_HEX, SOURCE, config, namespace_prefix, public_objects,
                                         request, world)
from tools.cnesdata_delivery import contract as c, drift_catalog, session_owner
from tools.cnesdata_delivery.producers import aws_reader, observer

KEY = bytes.fromhex(KEY_HEX)


@pytest.fixture
def chain(monkeypatch, tmp_path):
    return ReplayChain(monkeypatch, tmp_path)


def run(chain, *, mutate=None, **changes):
    settings = config()
    reader, names, _ = world(chain, settings)
    if mutate:
        mutate(reader, settings, names)
    asked = request(public_objects=public_objects(names), **changes)
    return reader, observer.observe(reader, settings, asked, KEY_HEX), asked


def observations(result):
    return c.loads(result.files["observations.json"], canonical=True)


def test_observador_registra_o_sha256_do_plano_de_ensaio_lido_de_phase_inputs(chain):
    reader, result, _ = run(chain)
    settings = config()
    plan_key = EVIDENCE + "phase-inputs/rehearsal/plan.json"
    assert (settings["evidence_bucket"], plan_key) in reader.reads
    measured = observations(result)["drift-baseline"]
    assert measured["rehearsal_plan_sha256"] == c.sha(c.canonical(chain.replay.plan))
    assert measured["handoff_sha256"] == c.sha(result.files["drift-handoff.json"])
    assert measured["catalog_sha256"] == drift_catalog.CATALOG_SHA256 and measured["matrix_version"] == 2
    assert measured["state_identity"] == c.state_identity(c.canonical(chain.prior))


def test_observador_conta_linhas_e_especificacoes_do_handoff(chain):
    _, result, _ = run(chain)
    measured = observations(result)["drift-baseline"]
    document = c.loads(result.files["drift-handoff.json"], canonical=True)
    assert measured["rows_before"] == len(document["matrix"]["before"])
    assert measured["rows_after"] == len(document["matrix"]["after"])
    assert measured["readbacks_before"] == len(document["readbacks"]["before"]) and measured["absent_rows"] == 0


def test_observador_sem_plano_de_ensaio_recusa(chain):
    def remove(reader, settings, names):
        del reader.objects[settings["evidence_bucket"], EVIDENCE + "phase-inputs/rehearsal/plan.json"]

    with pytest.raises(ValueError, match="rehearsal plan"):
        run(chain, mutate=remove)


def test_observador_so_chama_operacoes_de_leitura_e_nao_escreve(chain):
    reader, _, _ = run(chain)
    allowed = {(service, op) for service, ops in aws_reader.READS.items() for op in ops}
    assert reader.calls and set(reader.calls) <= allowed
    assert not hasattr(reader, "put") and not hasattr(reader, "write")


def test_leitor_real_recusa_operacao_de_escrita_e_de_assume_role():
    for service, operation in (("s3", "put_object"), ("sts", "assume_role"), ("iam", "create_role"),
                               ("dynamodb", "put_item"), ("ecr", "put_image")):
        with pytest.raises(ValueError, match="read-only"):
            aws_reader.require_read(service, operation)
    aws_reader.require_read("iam", "get_role")


def test_leitor_real_usa_a_sessao_e_o_cliente_de_leitura_so_depois_de_validar(monkeypatch):
    calls = []

    class Client:
        def get_role(self, **kwargs):
            calls.append(kwargs)
            return {"Role": {}, "ResponseMetadata": {"HTTPHeaders": {}}}

    session = type("S", (), {"client": lambda self, service, **kw: Client()})()
    reader = aws_reader.Reader(session)
    assert reader.call("iam", "get_role", RoleName="r")["Role"] == {}
    with pytest.raises(ValueError):
        reader.call("iam", "delete_role", RoleName="r")
    assert calls == [{"RoleName": "r"}]


def test_leitor_normaliza_datas_do_sdk_para_utc(monkeypatch):
    from datetime import datetime, timezone

    class Client:
        def get_role(self, **kwargs):
            return {"Role": {"CreateDate": datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)}, "ResponseMetadata": {}}

    session = type("S", (), {"client": lambda self, service, **kw: Client()})()
    assert aws_reader.Reader(session).call("iam", "get_role")["Role"]["CreateDate"] == "2026-01-02T03:04:05Z"


def test_namespace_exige_exatamente_tres_objetos_com_hash_igual_ao_publico(chain):
    _, result, _ = run(chain)
    namespace = observations(result)["phase_input_namespace"]
    prefix = namespace_prefix(config())
    from fixtures.cnesdata_producers import PAYLOAD_REFERENCE
    assert namespace == {"purpose": "phase-inputs", "dedicated": True,
                         "payload_reference_sha256": c.sha(c.canonical(PAYLOAD_REFERENCE)),
                         "prefix_sha256": c.sha(prefix.encode())}


def test_namespace_recusa_quarto_objeto(chain):
    def extra(reader, settings, names):
        reader.objects[settings["evidence_bucket"], namespace_prefix(settings) + "extra.json"] = b"{}\n"

    with pytest.raises(ValueError, match="namespace"):
        run(chain, mutate=extra)


def test_namespace_recusa_objeto_faltando(chain):
    def drop(reader, settings, names):
        del reader.objects[settings["evidence_bucket"], namespace_prefix(settings) + "candidate.json"]

    with pytest.raises(ValueError, match="namespace"):
        run(chain, mutate=drop)


def test_namespace_recusa_hash_diferente_do_publico(chain):
    def corrupt(reader, settings, names):
        reader.objects[settings["evidence_bucket"], namespace_prefix(settings) + "promotion.json"] += b" "

    with pytest.raises(ValueError, match="namespace"):
        run(chain, mutate=corrupt)


def test_plano_de_ensaio_fora_do_namespace_nao_muda_a_contagem(chain):
    reader, _, _ = run(chain)
    prefix = namespace_prefix(config())
    assert len(reader.list(config()["evidence_bucket"], prefix)) == 3
    assert len(reader.list(config()["evidence_bucket"], EVIDENCE + "phase-inputs/")) == 4


def test_fatos_da_sessao_sao_hmac_e_iguais_aos_do_session_owner(chain):
    _, result, asked = run(chain, mode="local")
    pins = result.pins
    assert set(pins) == {"plan", "deploy"}
    for role, pin in pins.items():
        assert observations(result)["session_facts"][role] == session_owner._facts(pin, KEY)
        assert pin["owner_producer"] == asked["owner_producer"] and pin["root_source_sha"] == "d" * 40
        assert c.sha(c.canonical(pin["document"])) == pin["document_sha256"]


def test_modo_ci_nao_devolve_os_pins_privados(chain):
    _, result, _ = run(chain, mode="ci")
    assert result.pins is None


def test_prazos_do_pin_seguem_a_cadeia_de_expiracao(chain):
    _, result, _ = run(chain, mode="local")
    pin = result.pins["plan"]
    assert pin["observed_at"] == "2026-11-20T12:00:00Z" and pin["frozen_until"] == "2026-11-20T16:00:00Z"
    assert pin["expires_at"] == "2026-11-20T15:00:00Z"


def test_arquivos_publicos_nao_carregam_arn_conta_bucket_nem_chave(chain):
    _, result, _ = run(chain, mode="local")
    for raw in result.files.values():
        text = raw.decode()
        assert KEY_HEX not in text and "arn:aws" not in text and "111122223333" not in text
        assert config()["state_bucket"] not in text and config()["evidence_bucket"] not in text
        c.public_safe(c.loads(raw, canonical=True), config())


def test_observador_recusa_leitura_ao_vivo_divergente_do_plano(chain):
    def drift(reader, settings, names):
        for (operation, _), document in reader.responses.items():
            if operation == "get_role":
                document["Role"]["Arn"] += "x"
                return

    with pytest.raises(ValueError):
        run(chain, mutate=drift)


def test_observador_usa_so_a_leitura_before_do_estagio_ao_vivo(chain):
    reader, result, _ = run(chain)
    document = c.loads(result.files["drift-handoff.json"], canonical=True)
    reads = [(s, o) for s, o in reader.calls if s != "iam" or o in {"get_role", "get_role_policy"}]
    assert len(reads) >= len(document["readbacks"]["before"])


def test_binding_r2_recalculado_sobre_o_candidate_do_namespace(chain):
    _, result, asked = run(chain)
    measured = observations(result)["r2-candidate-a2-binding"]
    raw = c.canonical({"repository": c.REPOSITORY, "source_sha": SOURCE, "release_id": "fixture"})
    binding = c.canary_binding(c.loads(raw), c.sha(raw))
    assert measured == {"candidate_sha256": c.sha(raw), "release_id": "fixture", "canary_id": binding["canary_id"],
                        "binding_sha256": binding["binding_sha256"], "creator_workflow_sha": asked["creator_workflow_sha"]}


def test_oci_mede_manifesto_blobs_e_plataforma_com_hmac_do_repositorio(chain):
    _, result, _ = run(chain)
    measured = observations(result)["oci-promotion-byte-integrity"]
    promotion = c.loads(world(chain)[1]["promotion.json"])
    assert measured["image_digest"] == promotion["image_digest"] and measured["platform"] == "linux/amd64"
    assert measured["manifest_sha256"] == promotion["manifest_sha256"] and measured["config_digest"] == promotion["config_digest"]
    assert measured["blob_digests_sha256"] == c.sha(c.canonical(promotion["blob_digests"]))
    assert len(measured["repository_hmac"]) == 64 and "repository_sha256" not in measured


def test_oci_recusa_blob_com_bytes_diferentes(chain):
    def corrupt(reader, settings, names):
        digest = next(iter(reader.blobs))
        reader.blobs[digest] = reader.blobs[digest] + b"x"

    with pytest.raises(ValueError, match="OCI"):
        run(chain, mutate=corrupt)


def test_observador_recusa_proposito_sem_envelope_de_drift(chain):
    settings = config()
    reader, names, _ = world(chain, settings)
    with pytest.raises(ValueError, match="purpose"):
        observer.observe(reader, settings, request(purpose="bootstrap", public_objects=[]), KEY_HEX)


def test_observador_nao_muta_a_configuracao_nem_o_pedido(chain):
    settings, asked = config(), request()
    snapshot = copy.deepcopy((settings, asked))
    reader, names, _ = world(chain, settings)
    observer.observe(reader, settings, asked | {"public_objects": public_objects(names)}, KEY_HEX)
    assert (settings, asked) == snapshot and json.dumps(settings)
