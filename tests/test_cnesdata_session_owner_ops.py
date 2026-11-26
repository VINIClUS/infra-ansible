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


def _owned(monkeypatch, *, ops_fact=True, ops_changes=None):
    import copy
    from tools.cnesdata_delivery import session_owner
    from tools.cnesdata_delivery.session_policy import managed_arn
    from test_cnesdata_session_owner import original_owner
    gov, descriptor, proof, files, api, now = original_owner("plan", "application-prepare")
    fragment = {"application_role_arn": gov["roles"]["plan"].replace("-plan", "-application"), "enabled_until": c.utc(now + 10000)}
    monkeypatch.setattr(session_owner, "application_fragment", lambda governance, when: copy.deepcopy(fragment))
    gov["roles"]["application"] = fragment["application_role_arn"]
    pin = gov["session_policy_pins"].pop("plan")
    pin.update(role_arn=fragment["application_role_arn"], policy_arn=managed_arn(gov, "application"))
    gov["session_policy_pins"]["application"] = pin
    ops = copy.deepcopy(pin) | {"policy_arn": managed_arn(gov, "application_ops")} | (ops_changes or {})
    gov["session_policy_pins"]["application_ops"] = ops
    key = c.report_key(gov)
    measured = {"managed_session_policy": session_owner._facts(pin, key), "application_fragment_sha256": c.sha(c.canonical(fragment))}
    if ops_fact:
        measured["ops_session_policy"] = session_owner._facts(ops, key)
    name = "policy-evaluation.json"
    files[name] = c.canonical({"check_id": "policy-evaluation", "source_sha": descriptor["source_sha"], "measurement": measured})
    next(x for x in proof["reports"] if x["check_id"] == "policy-evaluation").update(size=len(files[name]), sha256=c.sha(files[name]))
    digest = c.sha(c.canonical(measured))
    next(x for x in proof["checks"] if x["check_id"] == "policy-evaluation").update(expected_sha256=digest, observed_sha256=digest)
    api.freeze_owner(gov, proof, files)
    gov["session_owner_references"] = {"application": api.owner_reference}
    return session_owner, gov, api, descriptor, now, pin, ops


def test_autenticacao_da_application_carrega_o_pin_ops_comprometido_na_prova(monkeypatch):
    session_owner, gov, api, descriptor, now, pin, ops = _owned(monkeypatch)
    authority = session_owner.authenticate_lifecycle(gov, api, descriptor["source_sha"], "application", "application-prepare", now)
    assert authority.pin == pin and authority.ops_pin == ops and session_owner.operation_authority(authority).pin == ops


@pytest.mark.parametrize("ops_fact,changes", [
    (False, None), (True, {"observed_at": "2026-01-01T00:00:00Z"}), (True, {"frozen_until": "2026-01-01T00:00:00Z"})])
def test_autenticacao_da_application_recusa_prova_sem_ou_com_janela_diferente_do_pin_ops(monkeypatch, ops_fact, changes):
    session_owner, gov, api, descriptor, now, _, _ = _owned(monkeypatch, ops_fact=ops_fact, ops_changes=changes)
    with pytest.raises(ValueError):
        session_owner.authenticate_lifecycle(gov, api, descriptor["source_sha"], "application", "application-prepare", now)
