"""Observador de leitura (job observe): CI e local com o mesmo codigo (P18, N3a)."""
import copy
import json

import pytest

from fixtures.cnesdata_phase_a_replay import ACCOUNT, ReplayChain
from fixtures.cnesdata_producers import (ATTEMPT, EVIDENCE, KEY_HEX, RUN, SOURCE, config, namespace_prefix,
                                         public_objects, rehearsal_key, request, world)
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
    plan_key = rehearsal_key(settings)
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
        del reader.objects[settings["evidence_bucket"], rehearsal_key(settings)]

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
    assert set(pins) == {"plan", "deploy", "audit"}
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


ARN_LEAK = f"AccessDenied: arn:aws:sts::{ACCOUNT}:assumed-role/cnesdata-infra-plan/s on bucket cnesdata-state-4f6e21"


class ClientError(Exception):
    pass


@pytest.fixture
def cli(monkeypatch, tmp_path):
    asked = tmp_path / "request.json"
    asked.write_text(json.dumps(request(mode="local")))
    monkeypatch.setenv("OBSERVER_CONFIG", json.dumps(config()))
    monkeypatch.setenv("REPORT_HMAC_KEY", KEY_HEX)
    monkeypatch.setattr(observer, "_session", lambda asked_: object())
    return ["--request", str(asked), "--out", str(tmp_path / "out")]


def test_main_nao_deixa_arn_conta_nem_bucket_de_um_erro_do_sdk_chegar_a_saida(cli, monkeypatch, capsys):
    class Failing:
        def __init__(self, *args):
            pass

        def read(self, *args, **kwargs):
            raise ClientError(ARN_LEAK)

        call = list = blob = read

    monkeypatch.setattr(aws_reader, "Reader", Failing)
    assert observer.main(cli) != 0
    seen = capsys.readouterr()
    for text in (seen.out, seen.err):
        assert ACCOUNT not in text and "arn:" not in text and "cnesdata-state" not in text
    assert "refused reason=ClientError" in seen.err


def test_main_recusa_recusas_do_contrato_so_com_a_classe(cli, monkeypatch, capsys):
    monkeypatch.setattr(observer, "observe", lambda *args: (_ for _ in ()).throw(ValueError("bucket cnesdata-evid-4f6e21")))
    assert observer.main(cli) != 0
    seen = capsys.readouterr()
    assert "cnesdata-evid" not in seen.err + seen.out and "refused reason=ValueError" in seen.err


@pytest.mark.parametrize("change", [lambda v: v | {"extra": "x"}, lambda v: {k: x for k, x in v.items() if k != "ecr_repository"}])
def test_main_recusa_configuracao_com_chaves_diferentes_das_seis(cli, monkeypatch, capsys, change):
    monkeypatch.setenv("OBSERVER_CONFIG", json.dumps(change(config())))
    assert observer.main(cli) != 0
    assert "refused reason=ValueError" in capsys.readouterr().err


@pytest.mark.parametrize("field", ["ecr_repository", "evidence_prefix", "state_bucket", "evidence_bucket"])
def test_varredura_de_vazamento_cobre_os_seis_valores_da_configuracao(field):
    settings = config() | {"ecr_repository": "cnesdata-ecr-9b2d71"}
    leaked = {"drift-handoff.json": c.canonical({"note": "x " + settings[field] + " y"}), "observations.json": c.canonical({})}
    with pytest.raises(ValueError):
        observer._sanitize(leaked, settings, KEY_HEX, {})


@pytest.mark.parametrize("other", [
    {"source": "b" * 40}, {"run": RUN + 1}, {"attempt": ATTEMPT + 1},
], ids=["outra-fonte", "outro-run", "outra-tentativa"])
def test_observador_recusa_plano_de_ensaio_de_outra_fonte_run_ou_tentativa(chain, other):
    def move(reader, settings, names):
        raw = reader.objects.pop((settings["evidence_bucket"], rehearsal_key(settings)))
        reader.objects[settings["evidence_bucket"], rehearsal_key(settings, **other)] = raw

    with pytest.raises(ValueError, match="rehearsal plan absent"):
        run(chain, mutate=move)


def test_observador_le_a_chave_de_ensaio_do_proprio_run(chain):
    reader, _, _ = run(chain)
    assert (config()["evidence_bucket"], rehearsal_key(config())) in reader.reads
    assert observer.rehearsal_key(config(), request()) == rehearsal_key(config())


def test_observador_mede_o_pin_do_audit_alem_de_plan_e_deploy(chain):
    _, result, _ = run(chain)
    assert observer.ROLES == ("plan", "deploy", "audit")
    assert set(observations(result)["session_facts"]) == {"plan", "deploy", "audit"}


def test_observador_fecha_roles_da_configuracao_com_o_audit(monkeypatch):
    settings = config()
    monkeypatch.setenv("OBSERVER_CONFIG", c.canonical(settings).decode())
    assert set(observer._config()["roles"]) == {"plan", "deploy", "audit"}
    without = settings | {"roles": {key: value for key, value in settings["roles"].items() if key != "audit"}}
    monkeypatch.setenv("OBSERVER_CONFIG", c.canonical(without).decode())
    with pytest.raises(ValueError):
        observer._config()


def test_observador_le_o_plano_de_ensaio_da_tentativa_pedida_e_nao_o_da_primeira(chain):
    second = ATTEMPT + 1
    other = copy.deepcopy(chain.replay.plan)
    other["format_version"] = "outro"

    def stage(reader, settings, names):
        raw = reader.objects.pop((settings["evidence_bucket"], rehearsal_key(settings)))
        reader.objects[settings["evidence_bucket"], rehearsal_key(settings, attempt=second)] = raw
        reader.objects[settings["evidence_bucket"], rehearsal_key(settings)] = c.canonical(other)
        old, new = namespace_prefix(settings), namespace_prefix(settings).replace(f"/{ATTEMPT}/", f"/{second}/")
        for (bucket, key), value in list(reader.objects.items()):
            if key.startswith(old):
                reader.objects[bucket, new + key[len(old):]] = value

    reference = request()["payload_reference"] | {"run_attempt": second}
    _, result, _ = run(chain, mutate=stage, payload_reference=reference)
    measured = observations(result)["drift-baseline"]["rehearsal_plan_sha256"]
    assert measured == c.sha(c.canonical(chain.replay.plan)) != c.sha(c.canonical(other))
