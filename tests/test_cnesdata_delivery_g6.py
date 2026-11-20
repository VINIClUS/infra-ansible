"""G6: nada derivado de conta, ARN ou documento e publico; custo ligado a fonte (N10)."""

import hmac
import json

import pytest

from fixtures.cnesdata_cost import SOURCE_MANIFEST_SHA256, fixture
from test_cnesdata_session_owner import original_owner
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import session_owner

NOW = 1794053700


def _validate(cost, stage, evidence, manifest, source=SOURCE_MANIFEST_SHA256):
    c.validate_cost(cost, purpose="phase-a", stage=stage, evidence=evidence,
                    manifest=manifest, now=NOW, source_manifest_sha256=source)


def _reissue_evidence(cost, evidence):
    cost["evidence_sha256"] = c.sha(c.canonical(evidence))


def test_custo_com_fonte_autenticada_igual_e_aceito():
    cost, stage, evidence, manifest = fixture(True)
    _validate(cost, stage, evidence, manifest)


def test_custo_sem_source_manifest_sha256_e_recusado():
    cost, stage, evidence, manifest = fixture(True)
    evidence["measurement"].pop("source_manifest_sha256")
    _reissue_evidence(cost, evidence)
    with pytest.raises(ValueError):
        _validate(cost, stage, evidence, manifest)


def test_custo_com_source_manifest_sha256_diferente_da_fonte_e_recusado():
    cost, stage, evidence, manifest = fixture(True)
    evidence["measurement"]["source_manifest_sha256"] = "f" * 64
    _reissue_evidence(cost, evidence)
    with pytest.raises(ValueError):
        _validate(cost, stage, evidence, manifest)


def test_custo_recusa_quando_a_fonte_autenticada_e_outra():
    cost, stage, evidence, manifest = fixture(True)
    with pytest.raises(ValueError):
        _validate(cost, stage, evidence, manifest, source="f" * 64)


def _key(governance):
    return bytes.fromhex(governance["report_hmac_key"])


def _expected(governance, label, value):
    return hmac.new(_key(governance), label + b"\0" + value, "sha256").hexdigest()


def test_fatos_da_sessao_usam_hmac_e_nao_publicam_a_conta():
    gov, _, _, _, _, _ = original_owner()
    pin = gov["session_policy_pins"]["plan"]
    facts = session_owner._facts(pin, _key(gov))
    assert "account_id" not in facts
    assert not {"role_arn_sha256", "policy_arn_sha256", "document_sha256"} & set(facts)
    assert facts["role_arn_hmac"] == _expected(gov, b"role_arn", pin["role_arn"].encode())
    assert facts["policy_arn_hmac"] == _expected(gov, b"policy_arn", pin["policy_arn"].encode())
    assert facts["document_hmac"] == _expected(gov, b"document", pin["document_sha256"].encode())
    assert gov["account_id"] not in json.dumps(facts)


def test_relatorio_policy_evaluation_nao_publica_conta():
    gov, _, _, files, _, _ = original_owner()
    raw = files["policy-evaluation.json"].decode()
    assert gov["account_id"] not in raw
    assert gov["report_hmac_key"] not in raw


def _with_measurement(args, extra):
    gov, descriptor, proof, files, api, now = args
    report = next(x for x in proof["reports"] if x["check_id"] == "policy-evaluation")
    check = next(x for x in proof["checks"] if x["check_id"] == "policy-evaluation")
    body = c.loads(files[report["name"]], canonical=True)
    body["measurement"].update(extra)
    files[report["name"]] = c.canonical(body)
    report.update(size=len(files[report["name"]]), sha256=c.sha(files[report["name"]]))
    digest = c.sha(c.canonical(body["measurement"]))
    check.update(expected_sha256=digest, observed_sha256=digest)
    api.freeze_owner(gov, proof, files)
    return gov, descriptor, proof, files, api, now


def _leaks(gov):
    pin = gov["session_policy_pins"]["plan"]
    return {
        "conta-em-claro": lambda: {"account": gov["account_id"]},
        "arn-bruto": lambda: {"role": pin["role_arn"]},
        "arn-em-uri": lambda: {"role": "x/" + pin["policy_arn"] + "/y"},
        "sha256-simples-do-role-arn": lambda: {"role": c.sha(pin["role_arn"].encode())},
        "sha256-simples-do-policy-arn": lambda: {"policy": c.sha(pin["policy_arn"].encode())},
        "sha256-simples-do-documento": lambda: {"document": pin["document_sha256"]},
        "chave-do-hmac": lambda: {"key": gov["report_hmac_key"]},
    }


@pytest.mark.parametrize(
    "leak",
    ["conta-em-claro", "arn-bruto", "arn-em-uri", "sha256-simples-do-role-arn",
     "sha256-simples-do-policy-arn", "sha256-simples-do-documento", "chave-do-hmac"],
)
def test_validate_proof_recusa_relatorio_publico_com_valor_derivado_de_conta(leak):
    args = original_owner()
    gov, descriptor, proof, files, api, now = _with_measurement(args, _leaks(args[0])[leak]())
    with pytest.raises(ValueError):
        session_owner.authenticate(gov, descriptor, proof, files, api, now, "plan", "bootstrap")


def test_hmac_com_chave_errada_nao_verifica_os_fatos():
    gov, descriptor, proof, files, api, now = original_owner()
    gov["report_hmac_key"] = "ab" * 32
    with pytest.raises(ValueError):
        session_owner.authenticate(gov, descriptor, proof, files, api, now, "plan", "bootstrap")


@pytest.mark.parametrize("key", [None, "", "zz" * 32, "ab" * 16])
def test_gate_recusa_chave_hmac_ausente_ou_malformada(key):
    gov, descriptor, proof, files, api, now = original_owner()
    if key is None:
        gov.pop("report_hmac_key")
    else:
        gov["report_hmac_key"] = key
    with pytest.raises(ValueError):
        session_owner.authenticate(gov, descriptor, proof, files, api, now, "plan", "bootstrap")


def test_bytes_da_chave_nao_aparecem_em_nenhuma_saida_do_gate(capsys, caplog):
    gov, descriptor, proof, files, api, now = original_owner()
    key = gov["report_hmac_key"]
    authority = session_owner.authenticate(gov, descriptor, proof, files, api, now, "plan", "bootstrap")
    outputs = [repr(authority), json.dumps(authority.pin), capsys.readouterr().out,
               capsys.readouterr().err, caplog.text]
    outputs += [raw.decode() for raw in files.values()]
    assert all(key not in text for text in outputs)


def test_erro_de_verificacao_nao_ecoa_a_chave():
    gov, descriptor, proof, files, api, now = original_owner()
    gov["report_hmac_key"] = "ab" * 32
    with pytest.raises(ValueError) as caught:
        session_owner.authenticate(gov, descriptor, proof, files, api, now, "plan", "bootstrap")
    assert "ab" * 32 not in str(caught.value)
