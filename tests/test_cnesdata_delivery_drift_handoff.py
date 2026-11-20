"""G3: matriz e readbacks entram por membro autenticado do baseline drift; public_safe (P07)."""
import re
from pathlib import Path

import pytest

from fixtures.cnesdata_session_chain import OwnerChain as Chain
from tools.cnesdata_delivery import contract as c, runtime

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
ROW = {"address": "aws_acm_certificate.static_web", "attribute": "status", "readback": 0,
       "path": ["Certificate", "Status"], "encoding": "identity"}
SPEC = {"service": "acm", "operation": "describe_certificate", "address": "aws_acm_certificate.static_web"}


@pytest.fixture
def chain(monkeypatch, tmp_path):
    value = Chain(monkeypatch, tmp_path)
    value.gov["readbacks"] = {"before": [], "after": [dict(SPEC)]}
    value.gov["drift_matrix"]["after"] = [dict(ROW)]
    return value


def refused(chain, match, role="plan"):
    chain.configure(role, 1)
    with pytest.raises(ValueError, match=match):
        runtime.admission(role)


def test_governanca_com_matriz_inline_e_recusada(chain):
    chain.governance_edit = lambda value: value | {"drift_matrix": chain.gov["drift_matrix"]}
    refused(chain, "inline drift matrix")
    chain.governance_edit = lambda value: value | {"readbacks": chain.gov["readbacks"]}
    refused(chain, "inline drift matrix")


def test_governanca_sem_drift_handoff_e_recusada(chain):
    chain.governance_edit = lambda value: {k: v for k, v in value.items() if k != "drift_handoff"}
    refused(chain, "drift handoff governance")


@pytest.mark.parametrize("edit", [{"member": "outro.json"}, {"extra": 1}])
def test_drift_handoff_da_governanca_e_fechado_e_aponta_o_membro_fixo(chain, edit):
    def governance(value):
        value["drift_handoff"] = ({"member": "drift-handoff.json", "sha256": chain.handoff_sha256} | edit)
        return value
    chain.governance_edit = governance
    refused(chain, "drift handoff governance|closed object fields")


def test_hidrata_matriz_do_artefato_drift_e_passa_plan_gate(chain):
    chain.configure("plan", 1)
    governance = runtime.admission("plan")[0]
    assert governance["drift_matrix"] == chain.gov["drift_matrix"]
    assert governance["readbacks"] == chain.gov["readbacks"]
    runtime.execute("plan")


def test_hidrata_a_matriz_tambem_no_deploy(chain):
    chain.configure("plan", 1)
    runtime.execute("plan")
    planned = chain.planned()
    chain.configure("deploy", 2, planned)
    governance = runtime.admission("deploy")[0]
    assert governance["drift_matrix"] == chain.gov["drift_matrix"]


def test_recusa_hash_do_membro_diferente_da_governanca(chain):
    chain.governance_edit = lambda value: value | {"drift_handoff": {"member": "drift-handoff.json",
                                                                      "sha256": "0" * 64}}
    refused(chain, "drift handoff hash")


def test_recusa_artefato_drift_sem_o_membro():
    from tools.cnesdata_delivery import drift_handoff
    governance = {"drift_handoff": {"member": "drift-handoff.json", "sha256": "0" * 64}}
    with pytest.raises(ValueError, match="drift handoff member"):
        drift_handoff.load({"facts.json": b"{}"}, governance, {"reports": []}, {}, source="a" * 40, purpose="phase-a")


def test_recusa_hash_diferente_da_medicao_drift_baseline(chain):
    chain.report_edit = lambda measurement: measurement | {"handoff_sha256": "1" * 64}
    refused(chain, "drift handoff measurement")


def test_recusa_relatorio_drift_baseline_sem_o_plan_sha256_do_ensaio(chain):
    chain.report_edit = lambda measurement: {k: v for k, v in measurement.items() if k != "rehearsal_plan_sha256"}
    refused(chain, "drift handoff measurement")


def test_recusa_relatorio_drift_baseline_com_plan_sha256_do_ensaio_malformado(chain):
    chain.report_edit = lambda measurement: measurement | {"rehearsal_plan_sha256": "nao-e-hash"}
    refused(chain, "digest")


@pytest.mark.parametrize("field,value", [
    ("source_sha", "b" * 40), ("purpose", "bootstrap"), ("handoff_version", 2), ("catalog_sha256", "2" * 64)])
def test_recusa_handoff_de_outro_source_ou_purpose(chain, field, value):
    chain.handoff_edit = lambda document: document | {field: value}
    refused(chain, "drift handoff identity")


def test_recusa_handoff_com_matriz_de_outra_identidade(chain):
    chain.handoff_edit = lambda document: document | {"matrix": document["matrix"] | {"source_sha": "b" * 40}}
    refused(chain, "drift handoff identity")


def test_recusa_handoff_nao_canonico(chain):
    chain.handoff_bytes_edit = lambda raw: raw.replace(b",", b", ", 1)
    refused(chain, "noncanonical JSON bytes")


def test_recusa_handoff_com_chave_extra(chain):
    chain.handoff_edit = lambda document: document | {"cost_manifest": {}}
    refused(chain, "closed object fields")


@pytest.mark.parametrize("value", [
    "arn:aws:iam::111122223333:role/x", "conta 111122223333", "https://exemplo", "synthetic-state"])
def test_recusa_handoff_com_arn_ou_conta(chain, value):
    def edit(document):
        document["readbacks"]["after"][0]["address"] = value
        return document
    chain.handoff_edit = edit
    refused(chain, "private material in public transport")


def test_recusa_handoff_com_a_conta_de_governanca(chain):
    def edit(document):
        document["matrix"]["after"][0]["path"] = ["111122223333"]
        return document
    chain.handoff_edit = edit
    refused(chain, "private material in public transport")


@pytest.mark.parametrize("mutation", ["parameters", "bucket"])
def test_recusa_handoff_com_parameters_ou_bucket(chain, mutation):
    def edit(document):
        spec = document["readbacks"]["after"][0]
        if mutation == "parameters":
            spec["parameters"] = {"CertificateArn": "x"}
        else:
            spec["address"] = f"{chain.gov['state_bucket']}/aws_acm_certificate.static_web"
        return document
    chain.handoff_edit = edit
    refused(chain, "closed object fields|private material in public transport")


def test_recusa_endereco_de_tipo_fora_do_catalogo(chain):
    def edit(document):
        document["readbacks"]["after"][0]["address"] = "aws_kms_key.segredo"
        document["matrix"]["after"][0]["address"] = "aws_kms_key.segredo"
        return document
    chain.handoff_edit = edit
    refused(chain, "drift handoff address")


def test_falha_de_handoff_ocorre_antes_do_acquire_do_lease(chain, monkeypatch):
    from tools.cnesdata_delivery import coordination_lease
    acquired = []
    monkeypatch.setattr(coordination_lease.Lease, "acquire", lambda self: acquired.append(1))
    chain.governance_edit = lambda value: value | {"drift_handoff": {"member": "drift-handoff.json",
                                                                      "sha256": "0" * 64}}
    chain.configure("plan", 1)
    with pytest.raises(ValueError, match="drift handoff hash"):
        runtime.execute("plan")
    assert not acquired and not hasattr(chain, "sts_request")


def reusable_lists():
    result = {}
    for path in sorted(WORKFLOWS.glob("reusable-cnesdata-*.yml")):
        found = re.findall(r"files = (\[[^\]]*\])", path.read_text())
        if found:
            result[path.name] = [eval(value, {}) for value in found]
    return result


def test_listas_dos_reusables_cobrem_os_modulos_do_pyboot():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert "drift_handoff.py" in lc.APPLICATION_PYBOOT
    lists = reusable_lists()
    assert {len(values) for values in lists.values()} <= {1, 2} and len(lists) == 3
    for name, values in lists.items():
        for files in values:
            assert "drift_handoff.py" in files and len(files) == len(set(files)), name


def test_runtime_importa_o_modulo_novo_e_ele_nao_importa_aws():
    source = (ROOT / "tools/cnesdata_delivery/drift_handoff.py").read_text()
    assert "boto3" not in source and "urllib" not in source
    assert "drift_handoff" in (ROOT / "tools/cnesdata_delivery/runtime.py").read_text()


def test_public_safe_recusa_sequencia_de_12_digitos_delimitada():
    for value in ("111122223333.dkr.ecr", "conta 111122223333", "role_111122223333", "x:111122223333/y"):
        with pytest.raises(ValueError, match="private material in public transport"):
            c.public_safe({"campo": [value]})


def test_public_safe_nao_confunde_hash_nem_numero_maior_com_conta():
    digest = "ab" + "111122223333" + "cd" + "0" * 50
    c.public_safe({"sha256": digest, "sha": "1" * 12 + "a" * 28, "inteiro": 111122223333})
    c.public_safe(["1111222233333", "123456789", "v2026-11-20T10:11:12Z"])


def test_public_safe_recusa_nome_de_bucket_de_governanca_so_com_a_governanca():
    governance = {"state_bucket": "synthetic-state", "evidence_bucket": "evi"}
    c.public_safe({"campo": "synthetic-state"})
    for value in ("synthetic-state", "synthetic-state/chave", "x evi y", "evi/chave"):
        with pytest.raises(ValueError, match="private material in public transport"):
            c.public_safe({"campo": value}, governance)
    c.public_safe({"campo": "evidence previous synthetic-state-2 evi-x"}, governance)


def test_public_safe_com_governanca_exige_chaves_de_bucket():
    c.public_safe({"campo": "ok"}, {})



def test_fora_da_phase_a_drift_coverage_segue_sem_envelope_e_com_matriz_v1(chain, monkeypatch):
    log = []
    original = c.drift_coverage
    monkeypatch.setattr(c, "drift_coverage", lambda *args, **kwargs: log.append((args, kwargs)) or original(*args, **kwargs))
    runtime.execute("plan")
    assert log and all(kwargs.get("envelope") is None and args[2]["matrix_version"] == 1 for args, kwargs in log)
