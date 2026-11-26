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
    {"owner_producer": {**OWNER, "workflow_sha": "b" * 40}},
    {"extra_field": "x"}])
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


def test_autenticacao_recusa_pin_ops_de_outro_produtor_provado_que_o_da_application(monkeypatch):
    other = {**OWNER, "workflow_sha": "b" * 40}
    session_owner, gov, api, descriptor, now, pin, ops = _owned(monkeypatch, ops_changes={"owner_producer": other})
    gov["proof_producers"] = [*gov["proof_producers"], other]
    assert session_owner._pin(gov, "application_ops")["owner_producer"] == other
    with pytest.raises(ValueError, match="ops session policy commitment"):
        session_owner.authenticate_lifecycle(gov, api, descriptor["source_sha"], "application", "application-prepare", now)


def _owned_plan(monkeypatch, *, activation_read=True, fact=True, pin=True, changes=None):
    import copy
    from tools.cnesdata_delivery import session_owner
    from tools.cnesdata_delivery.session_policy import managed_arn
    from test_cnesdata_session_owner import original_owner
    gov, descriptor, proof, files, api, now = original_owner("plan", "application-prepare")
    plan_pin = gov["session_policy_pins"]["plan"]
    activation = copy.deepcopy(plan_pin) | {"policy_arn": managed_arn(gov, "plan_activation")} | (changes or {})
    if pin:
        gov["session_policy_pins"]["plan_activation"] = activation
    if activation_read:
        gov["activation_read"] = {"ceiling": {}}
    key = c.report_key(gov)
    measured = {"managed_session_policy": session_owner._facts(plan_pin, key)}
    if fact:
        measured["activation_session_policy"] = session_owner._facts(activation, key)
    name = "policy-evaluation.json"
    files[name] = c.canonical({"check_id": "policy-evaluation", "source_sha": descriptor["source_sha"], "measurement": measured})
    next(x for x in proof["reports"] if x["check_id"] == "policy-evaluation").update(size=len(files[name]), sha256=c.sha(files[name]))
    digest = c.sha(c.canonical(measured))
    next(x for x in proof["checks"] if x["check_id"] == "policy-evaluation").update(expected_sha256=digest, observed_sha256=digest)
    api.freeze_owner(gov, proof, files)
    gov["session_owner_references"] = {"plan": api.owner_reference}
    return session_owner, gov, api, descriptor, now, plan_pin, activation


def test_autenticacao_do_plan_com_ativacao_carrega_o_pin_de_ativacao_comprometido_na_prova(monkeypatch):
    session_owner, gov, api, descriptor, now, plan_pin, activation = _owned_plan(monkeypatch)
    authority = session_owner.authenticate_lifecycle(gov, api, descriptor["source_sha"], "plan", "application-prepare", now)
    assert authority.pin == plan_pin and authority.activation_pin == activation and authority.ops_pin is None
    assert session_owner.activation_authority(authority).pin == activation


def test_autenticacao_do_plan_sem_ativacao_nao_exige_o_pin_de_ativacao(monkeypatch):
    session_owner, gov, api, descriptor, now, plan_pin, _ = _owned_plan(monkeypatch, activation_read=False, fact=False, pin=False)
    authority = session_owner.authenticate_lifecycle(gov, api, descriptor["source_sha"], "plan", "application-prepare", now)
    assert authority.activation_pin is None
    with pytest.raises(ValueError, match="activation session pin absent"):
        session_owner.activation_authority(authority)


@pytest.mark.parametrize("kwargs,message", [
    ({"fact": False}, "plan_activation session policy commitment"),
    ({"pin": False}, "original owner session pin absent"),
    ({"changes": {"observed_at": "2026-01-01T00:00:00Z"}}, "plan_activation session policy commitment"),
    ({"changes": {"frozen_until": "2026-01-01T00:00:00Z"}}, "plan_activation session policy commitment")])
def test_autenticacao_do_plan_com_ativacao_recusa_prova_ou_pin_ausente_ou_com_janela_diferente(monkeypatch, kwargs, message):
    session_owner, gov, api, descriptor, now, _, _ = _owned_plan(monkeypatch, **kwargs)
    with pytest.raises(ValueError, match=message):
        session_owner.authenticate_lifecycle(gov, api, descriptor["source_sha"], "plan", "application-prepare", now)


def test_pin_de_ativacao_recusa_arn_do_plan_role_alheio_e_campo_extra():
    from tools.cnesdata_delivery import session_owner
    base = governance()
    pin = base["session_policy_pins"].pop("application_ops")
    plan = f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-plan"
    good = pin | {"role_arn": plan, "policy_arn": f"arn:aws:iam::{ACCOUNT}:policy/cnesdata-prod-plan-activation-session"}
    base["roles"]["plan"] = plan
    base["session_policy_pins"]["plan_activation"] = good
    assert session_owner._pin(base, "plan_activation")["policy_arn"].endswith("plan-activation-session")
    for changes in ({"policy_arn": good["policy_arn"].replace("activation-", "")}, {"role_arn": APPLICATION}, {"extra_field": "x"}):
        base["session_policy_pins"]["plan_activation"] = good | changes
        with pytest.raises(ValueError):
            session_owner._pin(base, "plan_activation")
