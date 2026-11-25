"""Observador de leitura (job observe): CI e local com o mesmo codigo (P18, N3a)."""
import copy
import json

import pytest

from fixtures.cnesdata_phase_a_replay import ACCOUNT, ReplayChain
from fixtures.cnesdata_producers import (KEY_HEX, SOURCE, config, namespace_prefix, public_objects, request,
                                         stub_plan, world)
from tools.cnesdata_delivery import contract as c, drift_catalog, session_owner
from tools.cnesdata_delivery.producers import aws_reader, observer, rehearsal_plan

KEY = bytes.fromhex(KEY_HEX)


@pytest.fixture
def chain(monkeypatch, tmp_path):
    built = ReplayChain(monkeypatch, tmp_path)
    stub_plan(monkeypatch, built)
    return built


def run(chain, *, mutate=None, **changes):
    settings = config()
    reader, names, _ = world(chain, settings)
    if mutate:
        mutate(reader, settings, names)
    asked = request(public_objects=public_objects(names), **changes)
    return reader, observer.observe(reader, settings, asked, KEY_HEX), asked


def observations(result):
    return c.loads(result.files["observations.json"], canonical=True)


def test_observador_registra_o_sha256_do_plano_gerado_no_job(chain, monkeypatch):
    seen = []
    stub_plan(monkeypatch, chain, seen)
    reader, result, _ = run(chain)
    measured = observations(result)["drift-baseline"]
    assert measured["rehearsal_plan_sha256"] == c.sha(c.canonical(chain.replay.plan))
    assert measured["handoff_sha256"] == c.sha(result.files["drift-handoff.json"])
    assert measured["catalog_sha256"] == drift_catalog.CATALOG_SHA256 and measured["matrix_version"] == 2
    assert measured["state_identity"] == c.state_identity(c.canonical(chain.prior))
    (settings, release_inputs, session), = seen
    assert settings == config() and session is reader.session
    assert release_inputs == c.canonical(chain.gov["phase_a_inputs"])


def test_plano_nunca_chega_ao_leitor_nem_aos_arquivos_publicos(chain, monkeypatch):
    marker = "plano-que-fica-no-job"
    monkeypatch.setattr(rehearsal_plan, "plan", lambda *args: c.canonical(chain.replay.plan | {"format_version": marker}))
    reader, result, _ = run(chain)
    assert set(result.files) == {"drift-handoff.json", "observations.json"}
    assert all(marker.encode() not in raw for raw in result.files.values())
    assert not hasattr(reader, "writes") and all(marker not in key for _, key in reader.reads)
    assert observations(result)["drift-baseline"]["rehearsal_plan_sha256"] == c.sha(
        c.canonical(chain.replay.plan | {"format_version": marker}))


def test_main_nao_grava_o_plano_na_saida_nem_no_arquivo_privado(cli, chain, monkeypatch, tmp_path):
    marker = "plano-que-fica-no-job"
    reader, names, _ = world(chain, config())
    monkeypatch.setattr(rehearsal_plan, "plan", lambda *args: c.canonical(chain.replay.plan | {"format_version": marker}))
    monkeypatch.setattr(aws_reader, "Reader", lambda *args: reader)
    asked = tmp_path / "request.json"
    asked.write_text(json.dumps(request(mode="local", public_objects=public_objects(names))))
    assert observer.main(["--request", str(asked), "--out", str(tmp_path / "out"),
                          "--private-out", str(tmp_path / "private.json")]) == 0
    written = [path for path in tmp_path.rglob("*") if path.is_file() and path != asked]
    assert written and all(marker.encode() not in path.read_bytes() for path in written)


def test_falha_do_plano_para_antes_de_qualquer_medicao(chain, monkeypatch):
    def refuse(*args):
        raise ValueError("tofu plan exit=1")

    monkeypatch.setattr(rehearsal_plan, "plan", refuse)
    settings = config()
    reader, names, _ = world(chain, settings)
    with pytest.raises(ValueError, match="tofu plan exit=1"):
        observer.observe(reader, settings, request(public_objects=public_objects(names)), KEY_HEX)
    assert reader.calls == [] and (settings["state_bucket"], observer.STATE_KEY) not in reader.reads


def test_observador_recusa_insumos_de_release_ausentes_antes_do_plano(chain, monkeypatch):
    called = []
    monkeypatch.setattr(rehearsal_plan, "plan", lambda *args: called.append(args))
    with pytest.raises(ValueError, match="phase input namespace objects"):
        run(chain, mutate=lambda reader, settings, names: reader.objects.pop(
            (settings["evidence_bucket"], namespace_prefix(settings) + "promotion.json")))
    assert called == []


def test_observador_conta_linhas_e_especificacoes_do_handoff(chain):
    _, result, _ = run(chain)
    measured = observations(result)["drift-baseline"]
    document = c.loads(result.files["drift-handoff.json"], canonical=True)
    assert measured["rows_before"] == len(document["matrix"]["before"])
    assert measured["rows_after"] == len(document["matrix"]["after"])
    assert measured["readbacks_before"] == len(document["readbacks"]["before"]) and measured["absent_rows"] == 0


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


@pytest.mark.parametrize("change", [lambda v: v | {"extra": "x"}, lambda v: {k: x for k, x in v.items() if k != "ecr_repository"},
                                    lambda v: {k: x for k, x in v.items() if k != "shared_outputs"}],
                         ids=["chave-extra", "sem-ecr", "sem-shared-outputs"])
def test_main_recusa_configuracao_com_chaves_diferentes_das_do_observador(cli, monkeypatch, capsys, change):
    monkeypatch.setenv("OBSERVER_CONFIG", json.dumps(change(config())))
    assert observer.main(cli) != 0
    assert "refused reason=ValueError" in capsys.readouterr().err


@pytest.mark.parametrize("field", ["ecr_repository", "evidence_prefix", "state_bucket", "evidence_bucket", "shared_outputs"])
def test_varredura_de_vazamento_cobre_os_valores_da_configuracao(field):
    settings = config() | {"ecr_repository": "cnesdata-ecr-9b2d71"}
    value = settings[field] if field != "shared_outputs" else settings[field]["kms_key_arn"]
    leaked = {"drift-handoff.json": c.canonical({"note": "x " + value + " y"}), "observations.json": c.canonical({})}
    with pytest.raises(ValueError):
        observer._sanitize(leaked, settings, KEY_HEX, {})


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


@pytest.mark.parametrize("name", observer.CONFIG_KEYS.split())
def test_observador_recusa_configuracao_sem_chave_nomeando_a_chave(monkeypatch, name):
    monkeypatch.setenv("OBSERVER_CONFIG", c.canonical({k: v for k, v in config().items() if k != name}).decode())
    with pytest.raises(ValueError, match=f"^observer config missing key={name}$"):
        observer._config()


def test_observador_recusa_configuracao_com_chave_extra_nomeando_a_chave(monkeypatch):
    monkeypatch.setenv("OBSERVER_CONFIG", c.canonical(config() | {"surprise": 1}).decode())
    with pytest.raises(ValueError, match="^observer config extra key=surprise$"):
        observer._config()


@pytest.mark.parametrize("change", [
    {"toolchain": "x"}, {"toolchain": {"lock_sha256": "0" * 64}},
    {"toolchain": {"lock_sha256": "zz", "providers": ["registry.opentofu.org/hashicorp/aws"]}},
    {"toolchain": {"lock_sha256": "0" * 64, "providers": []}},
    {"toolchain": {"lock_sha256": "0" * 64, "providers": [3]}}],
    ids=["texto", "sem-providers", "sha-invalido", "providers-vazio", "provider-nao-texto"])
def test_observador_recusa_toolchain_malformado_na_configuracao(monkeypatch, change):
    monkeypatch.setenv("OBSERVER_CONFIG", c.canonical(config() | change).decode())
    with pytest.raises(ValueError, match="observer toolchain|closed object fields|digest"):
        observer._config()


TEXT = "Zq7 shared output plain text"


@pytest.mark.parametrize("value", [{"name": TEXT}, {"names": [TEXT]}, {"deep": {"inner": [{"leaf": TEXT}]}}],
                         ids=["texto", "lista", "aninhado"])
def test_varredura_de_vazamento_pega_texto_do_shared_outputs_que_nao_e_arn(value):
    settings = config()
    settings["shared_outputs"] = settings["shared_outputs"] | value
    leaked = {"drift-handoff.json": c.canonical({"note": "x " + TEXT + " y"}), "observations.json": c.canonical({})}
    with pytest.raises(ValueError, match="configuration value in a public file"):
        observer._sanitize(leaked, settings, KEY_HEX, {})


def test_varredura_ignora_texto_curto_do_shared_outputs():
    settings = config()
    settings["shared_outputs"] = settings["shared_outputs"] | {"short": "abc"}
    clean = {"drift-handoff.json": c.canonical({"note": "abc"}), "observations.json": c.canonical({})}
    observer._sanitize(clean, settings, KEY_HEX, {})


@pytest.mark.parametrize("value", [{}, "texto", ["a"]], ids=["vazio", "texto", "lista"])
def test_observador_recusa_shared_outputs_vazio_ou_que_nao_e_objeto(monkeypatch, value):
    monkeypatch.setenv("OBSERVER_CONFIG", c.canonical(config() | {"shared_outputs": value}).decode())
    with pytest.raises(ValueError, match="observer shared_outputs"):
        observer._config()


def test_sha_do_plano_de_ensaio_e_o_dos_bytes_crus_do_show_e_nao_o_da_forma_canonica(chain, monkeypatch):
    raw = json.dumps(chain.replay.plan, indent=2).encode()
    assert raw != c.canonical(chain.replay.plan)
    monkeypatch.setattr(rehearsal_plan, "plan", lambda *args: raw)
    _, result, _ = run(chain)
    assert observations(result)["drift-baseline"]["rehearsal_plan_sha256"] == c.sha(raw)
