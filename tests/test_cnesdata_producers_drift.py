"""Gerador da matriz e dos readbacks, derivador do phase_a_graph e recusa de plano fora do COVERED (P18)."""
import copy
import json

import pytest

from fixtures.cnesdata_phase_a_replay import ACCOUNT, ReplayChain
from tools.cnesdata_delivery import contract as c, drift_catalog, drift_handoff as gate, iam_boundary
from tools.cnesdata_delivery.producers import drift_handoff, phase_a_graph

SOURCE = "a" * 40


@pytest.fixture
def chain(monkeypatch, tmp_path):
    return ReplayChain(monkeypatch, tmp_path)


def generated(chain):
    return drift_handoff.generate(chain.replay.plan, chain.prior, SOURCE, "phase-a")


def derive_graph(chain):
    inputs = chain.gov["phase_a_inputs"]
    return phase_a_graph.derive(chain.replay.plan, dict(chain.replay.sources), inputs, ACCOUNT)


def test_gerador_produz_a_matriz_e_os_readbacks_do_replay(chain):
    document = generated(chain)
    assert document["matrix"] == chain.gov["drift_matrix"]
    assert document["readbacks"] == chain.gov["readbacks"]
    assert document["catalog_sha256"] == drift_catalog.CATALOG_SHA256
    assert {k: document[k] for k in ("handoff_version", "source_sha", "purpose")} == {
        "handoff_version": 1, "source_sha": SOURCE, "purpose": "phase-a"}


def test_gerador_nao_emite_parameters_nem_aliases_de_bucket(chain):
    raw = drift_handoff.serialize(generated(chain))
    text = raw.decode()
    assert '"parameters"' not in text and "synthetic-" not in text and ACCOUNT not in text
    assert raw == c.canonical(c.loads(raw, canonical=True))


def test_saida_do_gerador_passa_o_load_do_gate(chain):
    raw = drift_handoff.serialize(generated(chain))
    governance = {k: v for k, v in chain.gov.items() if k not in {"drift_matrix", "readbacks"}} | {
        "drift_handoff": {"member": "drift-handoff.json", "sha256": c.sha(raw)}}
    measurement = {"handoff_sha256": c.sha(raw), "rehearsal_plan_sha256": "e" * 64}
    proof = {"reports": [{"check_id": "drift-baseline", "name": "drift.json"}]}
    files = {"drift.json": c.canonical({"check_id": "drift-baseline", "source_sha": SOURCE, "measurement": measurement})}
    hydrated = gate.load({"drift-handoff.json": raw}, governance, proof, files, source=SOURCE, purpose="phase-a")
    assert hydrated["drift_matrix"] == chain.gov["drift_matrix"]


def test_auto_conferencia_admit_stages_aceita_a_saida(chain):
    document = generated(chain)
    drift_catalog.admit_stages(chain.replay.plan, document["readbacks"], document["matrix"], set())


def test_gerador_usa_instancias_do_state_e_recusa_state_divergente_do_plano(chain):
    state = copy.deepcopy(chain.prior)
    role = next(r for r in state["resources"] if r["type"] == "aws_iam_role")
    role["instances"].append({"schema_version": 0, "index_key": "ghost", "attributes": dict(role["instances"][0]["attributes"])})
    with pytest.raises(ValueError, match="state"):
        drift_handoff.generate(chain.replay.plan, state, SOURCE, "phase-a")


def test_gerador_recusa_endereco_com_arn_no_index_key(chain):
    plan = copy.deepcopy(chain.replay.plan)
    item = next(x for x in plan["resource_changes"] if x["type"] == "aws_iam_role")
    item["address"] = f'module.runtime_iam.aws_iam_role.x["arn:aws:iam::{ACCOUNT}:role/r"]'
    with pytest.raises(ValueError):
        drift_handoff.generate(plan, chain.prior, SOURCE, "phase-a")


def test_gerador_recusa_delete_sem_create_na_phase_a(chain):
    plan = copy.deepcopy(chain.replay.plan)
    target = next(x for x in plan["resource_changes"] if x["type"] == "aws_iam_role")
    target["change"] = {"actions": ["delete"], "before": target["change"]["before"], "after": None,
                        "after_unknown": {}}
    with pytest.raises(ValueError, match="delete"):
        drift_handoff.generate(plan, chain.prior, SOURCE, "phase-a")


def test_gerador_recusa_tipo_alterado_fora_do_envelope(chain):
    plan = copy.deepcopy(chain.replay.plan)
    plan["resource_changes"].append({"address": "module.m.aws_sqs_queue.q", "mode": "managed", "type": "aws_sqs_queue",
                                     "change": {"actions": ["create"], "before": None, "after": {"name": "q"},
                                                "after_unknown": {}}})
    with pytest.raises(ValueError):
        drift_handoff.generate(plan, chain.prior, SOURCE, "phase-a")


def test_gerador_recusa_proposito_sem_envelope(chain):
    with pytest.raises(ValueError, match="purpose"):
        drift_handoff.generate(chain.replay.plan, chain.prior, SOURCE, "bootstrap")


def test_plano_real_igual_ao_de_ensaio_e_aceito(chain):
    drift_handoff.refuse_uncovered(chain.replay.plan, generated(chain))


def test_plano_real_com_endereco_fora_do_covered_e_recusado(chain):
    real = copy.deepcopy(chain.replay.plan)
    real["resource_changes"].append({"address": "module.m.aws_s3_bucket.extra", "mode": "managed", "type": "aws_s3_bucket",
                                     "change": {"actions": ["create"], "before": None, "after": {"bucket": "b"},
                                                "after_unknown": {}}})
    with pytest.raises(ValueError, match="COVERED"):
        drift_handoff.refuse_uncovered(real, generated(chain))


def test_plano_real_com_no_op_fora_do_covered_e_aceito(chain):
    real = copy.deepcopy(chain.replay.plan)
    real["resource_changes"].append({"address": "module.m.aws_s3_bucket.extra", "mode": "managed", "type": "aws_s3_bucket",
                                     "change": {"actions": ["no-op"], "before": {"bucket": "b"}, "after": {"bucket": "b"},
                                                "after_unknown": {}}})
    drift_handoff.refuse_uncovered(real, generated(chain))


def test_derivador_fecha_com_validate_graph_na_forma_do_p2(chain):
    graph = derive_graph(chain)
    resolver = iam_boundary.prepare(chain.replay.plan, chain.gov["phase_a_inputs"], ACCOUNT, "phase-a", dict(chain.replay.sources))
    assert c.validate_graph(chain.replay.plan, graph, dict(chain.replay.sources), resolver)["governance_sha256"]
    assert 0 < len(graph["source_files"]) <= 32
    assert [item["path"] for item in graph["source_files"]] == sorted(item["path"] for item in graph["source_files"])


def test_derivador_so_inclui_arquivos_que_o_resolver_leu(chain):
    graph = derive_graph(chain)
    assert {item["path"] for item in graph["source_files"]} < set(chain.replay.sources)
    expected = {w["address"] for w in chain.graph()["unknown_policies"]}
    assert {item["address"] for item in graph["unknown_policies"]} == expected
    assert graph["known_policies"] == chain.graph()["known_policies"]
    assert graph["configuration_sha256"] == chain.graph()["configuration_sha256"]


def test_derivador_recusa_mais_de_32_arquivos_lidos(chain, monkeypatch):
    monkeypatch.setattr(phase_a_graph, "MAX_SOURCE_FILES", 1)
    with pytest.raises(ValueError, match="source"):
        derive_graph(chain)


@pytest.mark.parametrize("mutation", ["source", "configuration", "producer", "before"])
def test_graph_derivado_falha_ao_mutar_fonte_configuracao_ou_produtor(chain, mutation):
    graph = derive_graph(chain)
    plan, sources = copy.deepcopy(chain.replay.plan), dict(chain.replay.sources)
    if mutation == "source":
        sources[graph["source_files"][0]["path"]] += b"\n# tamper\n"
    elif mutation == "configuration":
        plan["configuration"]["root_module"]["variables"] = {"x": {"default": 1}}
    elif mutation == "producer":
        graph["unknown_policies"][0]["producers"] = graph["unknown_policies"][0]["producers"][:-1] or ["x"]
    else:
        graph["unknown_policies"][0]["before_policy_sha256"] = "f" * 64
    resolver = iam_boundary.prepare(chain.replay.plan, chain.gov["phase_a_inputs"], ACCOUNT, "phase-a", dict(chain.replay.sources))
    with pytest.raises(ValueError):
        c.validate_graph(plan, graph, sources, resolver)


def test_derivador_nao_muta_o_plano_nem_as_fontes(chain):
    plan, sources = copy.deepcopy(chain.replay.plan), dict(chain.replay.sources)
    derive_graph(chain)
    assert chain.replay.plan == plan and dict(chain.replay.sources) == sources
    assert json.dumps(plan, sort_keys=True)
