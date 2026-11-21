"""Compromissos publicos do backend e das saidas compartilhadas: validador, workflow e leitura do montador (P18)."""
import json
import re
from pathlib import Path

import pytest
import yaml

from fixtures.cnesdata_phase_a_replay import ACCOUNT
from fixtures.cnesdata_producers import KEY_HEX
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.producers import baseline_commitments

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/cnesdata-baseline-commitments.yml"
STATE_BUCKET = "cnesdata-state-4f6e21"
INPUTS = ("identity_sha256 key workspace region encrypt use_lockfile bucket_hmac kms_key_id_sha256 "
          "schema_sha256 shared_outputs_sha256").split()


def inputs(**changes):
    return {"identity_sha256": "a" * 64, "key": "cnesdata/prod/opentofu.tfstate", "workspace": "default",
            "region": "us-east-2", "encrypt": True, "use_lockfile": True, "bucket_hmac": "b" * 64,
            "kms_key_id_sha256": "c" * 64, "schema_sha256": "d" * 64, "shared_outputs_sha256": "e" * 64} | changes


def test_validador_emite_os_dois_membros_com_os_nomes_exatos():
    files = baseline_commitments.build(inputs())
    assert set(files) == {"backend.json", "shared-outputs.json"}
    backend = c.loads(files["backend.json"], canonical=True)
    assert backend == {name: inputs()[name] for name in
                       "identity_sha256 key workspace region encrypt use_lockfile bucket_hmac kms_key_id_sha256".split()}
    assert c.loads(files["shared-outputs.json"], canonical=True) == {
        "schema_version": 2, "schema_sha256": "d" * 64, "shared_outputs_sha256": "e" * 64}


def test_validador_aceita_booleanos_em_texto_do_ambiente_do_workflow():
    files = baseline_commitments.build(inputs(encrypt="true", use_lockfile="false"))
    backend = c.loads(files["backend.json"], canonical=True)
    assert backend["encrypt"] is True and backend["use_lockfile"] is False


@pytest.mark.parametrize("change", [
    {"extra": "x"}, {"workspace": "prod"}, {"identity_sha256": "xyz"}, {"bucket_hmac": "A" * 64},
    {"kms_key_id_sha256": "c" * 63}, {"schema_sha256": ""}, {"shared_outputs_sha256": None},
    {"encrypt": "yes"}, {"use_lockfile": 1}, {"region": "US_EAST"}, {"key": f"arn:aws:s3:::{STATE_BUCKET}"},
    {"key": f"bucket {ACCOUNT}"},
])
def test_validador_recusa_entradas_fora_do_contrato(change):
    with pytest.raises(ValueError):
        baseline_commitments.build(inputs(**change))


@pytest.mark.parametrize("missing", INPUTS)
def test_validador_recusa_entrada_ausente(missing):
    value = inputs()
    value.pop(missing)
    with pytest.raises(ValueError):
        baseline_commitments.build(value)


def private():
    return {"bucket": STATE_BUCKET, "identity": "backend-config-identity", "key": "cnesdata/prod/opentofu.tfstate",
            "region": "us-east-2", "encrypt": True, "use_lockfile": True,
            "kms_key_id": f"arn:aws:kms:us-east-2:{ACCOUNT}:key/0d8f", "schema_sha256": "d" * 64,
            "shared_outputs": {"k": "v"}}


def test_entradas_do_dispatch_trazem_so_hashes_e_o_hmac_do_bucket_com_a_chave_do_ciclo():
    dispatch = baseline_commitments.dispatch_inputs(private(), KEY_HEX)
    assert set(dispatch) == set(INPUTS)
    assert dispatch["bucket_hmac"] == c.report_hmac(bytes.fromhex(KEY_HEX), "backend_bucket", b"cnesdata-state-4f6e21")
    assert dispatch["shared_outputs_sha256"] == c.sha(c.canonical({"k": "v"}))
    assert dispatch["identity_sha256"] == c.sha(b"backend-config-identity")
    text = json.dumps(dispatch)
    assert STATE_BUCKET not in text and ACCOUNT not in text and KEY_HEX not in text
    baseline_commitments.build(dispatch)


@pytest.fixture(scope="module")
def document():
    return yaml.safe_load(WORKFLOW.read_text())


@pytest.fixture(scope="module")
def text():
    return WORKFLOW.read_text()


def test_workflow_so_roda_por_dispatch_manual_com_as_dez_entradas_publicas(document):
    triggers = document.get("on", document.get(True))
    assert set(triggers) == {"workflow_dispatch"}
    declared = triggers["workflow_dispatch"]["inputs"]
    assert set(declared) == set(INPUTS)
    assert declared["encrypt"]["type"] == "boolean" and declared["use_lockfile"]["type"] == "boolean"
    assert all(item["required"] is True for item in declared.values())


def test_workflow_nao_tem_aws_segredo_id_token_nem_environment(document, text):
    assert document["permissions"] == {}
    job = next(iter(document["jobs"].values()))
    assert len(document["jobs"]) == 1 and job["runs-on"] == "ubuntu-latest" and "environment" not in job
    assert job["permissions"] == {"contents": "read"}
    assert "secrets." not in text and "id-token" not in text and "AWS_" not in text and "aws-actions" not in text


def test_workflow_so_roda_no_main_do_infra_ansible(text):
    assert 'github.repository == \'VINIClUS/infra-ansible\'' in text and "refs/heads/main" in text


def test_acoes_fixadas_pelos_mesmos_shas_dos_reusables_do_gate(text):
    used = re.findall(r"uses: (\S+)", text)
    assert used and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", item) for item in used)
    gate = " ".join(path.read_text() for path in (ROOT / ".github/workflows").glob("reusable-cnesdata-*gate.yml"))
    assert all(item in gate for item in used)


def test_entradas_nunca_sao_interpoladas_dentro_de_scripts(document):
    for step in next(iter(document["jobs"].values()))["steps"]:
        assert "inputs." not in step.get("run", "")
    assert "inputs." not in "".join(step.get("run", "") for step in next(iter(document["jobs"].values()))["steps"])


def test_workflow_publica_os_dois_artefatos_com_nome_estavel_e_retencao_de_30_dias(document):
    steps = next(iter(document["jobs"].values()))["steps"]
    uploads = [step["with"] for step in steps if step.get("uses", "").startswith("actions/upload-artifact")]
    assert {item["name"] for item in uploads} == {"delivery-baseline-backend", "delivery-baseline-shared-outputs"}
    assert all(item["retention-days"] == 30 and item["if-no-files-found"] == "error" for item in uploads)
    assert {Path(item["path"]).name for item in uploads} == {"backend.json", "shared-outputs.json"}


def test_workflow_roda_o_produtor_como_modulo_sobre_o_checkout_sem_credencial(document):
    steps = next(iter(document["jobs"].values()))["steps"]
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["persist-credentials"] is False
    assert any("-m tools.cnesdata_delivery.producers.baseline_commitments" in step.get("run", "") for step in steps)
