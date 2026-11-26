"""P16b follow-up item 1: the vendored unit_observe builders reproduce the product vector section (amendment 3)."""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SECTION = json.loads((ROOT / "tests" / "fixtures" / "cnesdata_mode_canary_frames_vector.json").read_bytes())["unit_observe"]
CASES = {case["name"]: case for case in SECTION["cases"]}
DISPATCH = SECTION["dispatch"]
SERVICE = SECTION["cluster_arn"].replace(":cluster/", ":service/")


def _observe():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker.product_unit_observe()


def test_secao_do_vetor_tem_os_sete_casos_do_produto():
    assert set(CASES) == {"aceito-pascal", "aceito-camel", "sem-arn", "task-alheia", "task-missing", "exit-nao-zero",
                          "execucao-nao-succeeded"}
    assert all(case["execution"]["synthetic"] is True for case in CASES.values())


def test_construtores_vendorizados_reproduzem_o_request_da_execucao_e_as_leituras_dos_outputs():
    observe = _observe()
    assert observe.unit_execution_request(SECTION["machine_arn"], DISPATCH["dispatch_id"]) == SECTION["execution_request"]
    assert list(observe.unit_output_reads(SECTION["table"], DISPATCH["tenant_id"], DISPATCH["run_id"],
                                          DISPATCH["unit_ids"])) == SECTION["output_reads"]


def test_projecao_vendorizada_dos_outputs_e_a_do_vetor():
    assert _observe().unit_outputs(DISPATCH["tenant_id"], DISPATCH["run_id"], DISPATCH["unit_ids"],
                                   SECTION["unit_items"]) == SECTION["outputs"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_tasks_e_describe_de_cada_caso_vem_dos_construtores_vendorizados(name):
    observe, case = _observe(), CASES[name]
    arns = observe.unit_task_arns(case["execution"]["response"], SECTION["cluster_arn"])
    assert list(arns) == case["task_arns"]
    assert (observe.describe_tasks_request(SECTION["cluster_arn"], arns) if arns else None) == case["describe_request"]


def test_cluster_da_definicao_do_vetor_e_o_do_alvo_e_o_do_readback():
    assert _observe().unit_cluster(SECTION["definition"]) == SECTION["cluster_arn"]
    assert SECTION["readbacks"]["state_machine"]["definition"] == SECTION["definition"]


@pytest.mark.parametrize("cluster", [SERVICE, "cnesdata-prod", None], ids=["servico-com-conta", "sem-arn", "nulo"])
def test_cluster_fora_da_forma_de_cluster_e_none(cluster):
    assert _observe().unit_cluster(SECTION["definition"].replace(json.dumps(SECTION["cluster_arn"]),
                                                                 json.dumps(cluster))) is None
