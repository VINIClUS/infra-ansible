"""P16b design 2 origin (a): the `network` input of recovery-observe and audit-observe, from the mode-input resources."""
import json

import pytest

from test_cnesdata_mode_readback import RESOURCES as READBACK_RESOURCES
from tools.cnesdata_delivery import contract as c

PRODUCT_NETWORK_FIELDS = {"cluster", "subnets", "security_group", "public_ip", "platform"}
RESOURCES = READBACK_RESOURCES | {"network": {"public_subnet_ids": ["subnet-0bbb2222", "subnet-0aaa1111"],
                                              "security_group_id": "sg-0ccc3333"}}


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def test_campos_do_network_sao_os_do_produto():
    """Labelled literals of CnesData scripts/promotion/promote_mode.py:48 NETWORK_FIELDS and run_canary.py:70-71
    (public_ip ENABLED, platform 1.4.0)."""
    raw = _mb().mode_network_input(RESOURCES)
    assert set(json.loads(raw)) == PRODUCT_NETWORK_FIELDS


def test_network_e_o_documento_canonico_do_mode_input_com_as_subnets_ordenadas():
    assert _mb().mode_network_input(RESOURCES) == c.canonical({
        "cluster": RESOURCES["cluster_arn"], "subnets": ["subnet-0aaa1111", "subnet-0bbb2222"],
        "security_group": "sg-0ccc3333", "public_ip": "ENABLED", "platform": "1.4.0"})


def test_ordem_das_subnets_no_mode_input_nao_muda_os_bytes():
    swapped = RESOURCES | {"network": {"public_subnet_ids": ["subnet-0aaa1111", "subnet-0bbb2222"],
                                       "security_group_id": "sg-0ccc3333"}}
    assert _mb().mode_network_input(swapped) == _mb().mode_network_input(RESOURCES)


def test_network_confere_com_a_rede_do_schedule_pela_regra_do_observe_do_produto():
    """Product _phase_c_core._route_role_deadline: vpc == {Subnets: sorted, SecurityGroups: [sg], AssignPublicIp}."""
    network = json.loads(_mb().mode_network_input(RESOURCES))
    vpc = {"Subnets": ["subnet-0aaa1111", "subnet-0bbb2222"], "SecurityGroups": ["sg-0ccc3333"], "AssignPublicIp": "ENABLED"}
    assert vpc == {"Subnets": sorted(network["subnets"]), "SecurityGroups": [network["security_group"]],
                   "AssignPublicIp": network["public_ip"]}


@pytest.mark.parametrize("change", [
    {"network": None}, {"network": {"public_subnet_ids": ["subnet-0aaa1111"]}},
    {"network": {"public_subnet_ids": ["subnet-0aaa1111"], "security_group_id": "sg-0ccc3333", "extra": 1}},
    {"network": {"public_subnet_ids": [], "security_group_id": "sg-0ccc3333"}},
    {"network": {"public_subnet_ids": [f"subnet-0{index:07x}" for index in range(17)], "security_group_id": "sg-0ccc3333"}},
    {"network": {"public_subnet_ids": ["subnet-0aaa1111", "subnet-0aaa1111"], "security_group_id": "sg-0ccc3333"}},
    {"network": {"public_subnet_ids": ["subnet-0aaa1111", 7], "security_group_id": "sg-0ccc3333"}},
    {"network": {"public_subnet_ids": ["vpc-0aaa1111"], "security_group_id": "sg-0ccc3333"}},
    {"network": {"public_subnet_ids": "subnet-0aaa1111", "security_group_id": "sg-0ccc3333"}},
    {"network": {"public_subnet_ids": ["subnet-0aaa1111"], "security_group_id": ""}},
    {"network": {"public_subnet_ids": ["subnet-0aaa1111"], "security_group_id": "subnet-0ccc3333"}},
    {"cluster_arn": None}, {"cluster_arn": "arn:aws:ecs:us-east-2:111122223333:service/x"}],
    ids=["sem-network", "sem-grupo", "campo-extra", "sem-subnet", "dezessete", "duplicada", "nao-texto", "nao-subnet",
         "lista-ausente", "grupo-vazio", "grupo-invalido", "sem-cluster", "cluster-invalido"])
def test_network_fora_da_forma_do_mode_input_recusa(change):
    with pytest.raises(ValueError, match="^mode network input$"):
        _mb().mode_network_input(RESOURCES | change)
