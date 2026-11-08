"""Pure capacity regressions; synthetic names are not owner or AWS evidence."""

import json

import pytest

from tools.cnesdata_delivery import session_policy


def governance():
    account = "111122223333"
    return {
        "account_id": account,
        "role": "plan",
        "roles": {
            role: f"arn:aws:iam::{account}:role/cnesdata-infra-{role}"
            for role in ("plan", "deploy")
        },
        "state_bucket": "cnesdata-state-4f6e21",
        "evidence_bucket": "cnesdata-evid-4f6e21",
        "state_kms_key_arn": f"arn:aws:kms:us-east-2:{account}:key/00000000-0000-4000-8000-000000000001",
        "evidence_kms_key_arn": f"arn:aws:kms:us-east-2:{account}:key/00000000-0000-4000-8000-000000000002",
        "evidence_prefix": "cnesdata/prod/evidence/",
    }


@pytest.mark.parametrize("role", ["plan", "deploy"])
def test_inline_dinamico_nao_preserva_poderes_estaticos_por_catch_all(role):
    encoded = session_policy.build(governance(), "a" * 40, 42448571873, 1, role, [])
    policy = json.loads(encoded)
    assert not any(statement.get("Action") == "*" for statement in policy["Statement"])
    assert not any("NotResource" in statement for statement in policy["Statement"])
    assert all(
        "cnesdata-state-4f6e21" not in json.dumps(statement)
        for statement in policy["Statement"]
    )


def test_capacidade_representativa_com_history_inclui_arn_real():
    gov = governance()
    historical = gov["evidence_prefix"] + "b" * 40 + "/42448920421/1/applied/*"
    encoded = session_policy.build(
        gov, "a" * 40, 42448571873, 1, "deploy", [historical]
    )
    arn = f"arn:aws:iam::{gov['account_id']}:policy/cnesdata-infra-deploy-session"
    assert len(encoded) + len(arn) <= 2048
    assert json.loads(encoded)["Statement"]


def test_keys_exatas_que_nao_cabem_continuam_fechadas():
    gov = governance()
    prefix = gov["evidence_prefix"] + "phase-inputs/" + "a" * 40 + "/42448920421/1/"
    keys = [
        prefix + name
        for name in ("phase-inputs.json", "candidate.json", "promotion.json")
    ]
    keys += [gov["evidence_prefix"] + "b" * 40 + "/42448920421/1/applied/*"]
    with pytest.raises(ValueError, match="2048"):
        session_policy.build(gov, "a" * 40, 42448571873, 1, "plan", keys)


def test_prefixo_grouping_recebido_como_texto_json_nao_tem_autoridade():
    gov = governance()
    prefix = gov["evidence_prefix"] + "phase-inputs/" + "a" * 40 + "/42448920421/1/*"
    with pytest.raises(ValueError, match="authenticated run scope"):
        session_policy.build(gov, "a" * 40, 42448571873, 1, "plan", [prefix])
