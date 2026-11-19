"""Phase A allowlist conformance to A3 section 6 (promotion fence role and policy)."""
import pytest

from tools.cnesdata_delivery import contract as c

FENCE = ("module.runtime_iam.aws_iam_role.promotion_fence_operator[0]",
         "module.runtime_iam.aws_iam_role_policy.promotion_fence_operator[0]")
CANARY = ("module.runtime_iam.aws_iam_role.canary_task[0]",
          "module.runtime_iam.aws_iam_role_policy.canary_verifier[0]")


def change(address, actions):
    return {"address": address, "mode": "managed", "type": address.split(".")[-2],
            "change": {"actions": actions, "before": {}, "after": {}}}


@pytest.mark.parametrize("address", FENCE + CANARY)
@pytest.mark.parametrize("actions", [["create"], ["update"]])
def test_fase_a_admite_fence_e_canary_em_criacao_e_atualizacao(address, actions):
    c.validate_delta({"resource_changes": [change(address, actions)]}, "phase-a")


@pytest.mark.parametrize("address", FENCE)
@pytest.mark.parametrize("actions", [["delete"], ["delete", "create"]])
def test_fase_a_recusa_remocao_e_substituicao_do_fence(address, actions):
    with pytest.raises(ValueError, match="delete/replacement"):
        c.validate_delta({"resource_changes": [change(address, actions)]}, "phase-a")


@pytest.mark.parametrize("address", [
    "module.runtime_iam.aws_iam_role.promotion_fence_operator[1]",
    "module.runtime_iam.aws_iam_role.promotion_fence_operator",
    "module.runtime_iam.aws_iam_role_policy.promotion_fence_operator_extra[0]",
    "module.runtime_iam.aws_iam_role.promotion_other[0]",
    "module.runtime_iam.aws_iam_role_attachment.promotion_fence_operator[0]",
])
def test_fase_a_nao_alarga_alem_do_fence_exato(address):
    with pytest.raises(ValueError, match="Phase A invariant address|exact Phase A address"):
        c.validate_delta({"resource_changes": [change(address, ["update"])]}, "phase-a")


def test_fence_continua_fora_do_proposito_acm_certificate():
    with pytest.raises(ValueError, match="ACM initial create-only scope"):
        c.validate_delta({"resource_changes": [change(FENCE[0], ["update"])]}, "acm-certificate")
