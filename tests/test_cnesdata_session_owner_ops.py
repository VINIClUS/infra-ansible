"""The ops managed policy pin is its own original-owner pin and joins the application authority."""
import dataclasses

import pytest

from tools.cnesdata_delivery import contract as c

ACCOUNT = "111122223333"
OWNER = {"repository": "VINIClUS/infra-ansible", "workflow_path": ".github/workflows/owner.yml", "workflow_sha": "a" * 40}
APPLICATION = f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-application"
DOCUMENT = {"Version": "2012-10-17", "Statement": []}


def governance(**changes):
    pin = {"account_id": ACCOUNT, "role_arn": APPLICATION,
           "policy_arn": f"arn:aws:iam::{ACCOUNT}:policy/cnesdata-prod-application-ops-session", "root_source_sha": "d" * 40,
           "default_version_id": "v1", "document": DOCUMENT, "document_sha256": c.sha(c.canonical(DOCUMENT)),
           "observed_at": "2026-11-26T00:00:00Z", "expires_at": "2026-11-27T00:00:00Z", "frozen_until": "2026-11-27T00:00:00Z",
           "owner_producer": OWNER}
    return {"account_id": ACCOUNT, "roles": {"application": APPLICATION}, "proof_producers": [OWNER],
            "session_policy_pins": {"application_ops": pin | changes}}


def test_pin_ops_e_aceito_com_o_role_da_application_e_o_arn_ops():
    from tools.cnesdata_delivery import session_owner
    assert session_owner._pin(governance(), "application_ops")["policy_arn"].endswith("application-ops-session")


@pytest.mark.parametrize("changes", [
    {"policy_arn": f"arn:aws:iam::{ACCOUNT}:policy/cnesdata-prod-application-session"},
    {"role_arn": f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-plan"},
    {"owner_producer": {**OWNER, "workflow_sha": "b" * 40}}])
def test_pin_ops_recusa_arn_do_keeper_role_alheio_e_produtor_nao_provado(changes):
    from tools.cnesdata_delivery import session_owner
    with pytest.raises(ValueError):
        session_owner._pin(governance(**changes), "application_ops")


def test_autoridade_de_operacao_troca_o_pin_pelo_ops_e_mantem_prazo_e_fragmento():
    from tools.cnesdata_delivery import session_owner
    keeper, ops = {"policy_arn": "keeper"}, {"policy_arn": "ops"}
    authority = session_owner.Authority(keeper, 99.0, None, {"enabled_until": "x"}, "f" * 64, ops)
    chosen = session_owner.operation_authority(authority)
    assert chosen.pin is ops and chosen.expires_at == 99.0 and chosen.application_fragment == {"enabled_until": "x"}
    assert authority.pin is keeper
    with pytest.raises(ValueError, match="ops session pin"):
        session_owner.operation_authority(dataclasses.replace(authority, ops_pin=None))
