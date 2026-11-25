"""Every session policy document stays inside the 2048-character STS limit at the governed maxima."""
import json

import pytest

SOURCE, RUN, ATTEMPT = "b" * 40, 2**53 - 1, 123
BUCKET = "evidence-" + "b" * 54
PREFIX = "cnesdata/prod/" + "p" * 17 + "/"
LONG = "s" * 52
PLANS = tuple(("plan-%d-" % index) + "x" * 44 for index in range(5))
ACCOUNT = "111122223333"


def _governance(prefix=PREFIX):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    steps = {name: {"role": "plan", "job_name": name} for name in PLANS}
    steps |= {"audit-" + "x" * 46: {"role": "audit", "job_name": "a"}, "deploy-" + "x" * 45: {"role": "deploy", "job_name": "d"}}
    roles = {name: f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-{suffix}" for name, suffix in lc.APPLICATION_DELEGATIONS.items()}
    return {"account_id": ACCOUNT, "state_bucket": BUCKET, "evidence_bucket": BUCKET, "evidence_prefix": prefix,
            "evidence_kms_key_arn": "arn:aws:kms:us-east-2:" + ACCOUNT + ":key/00000000-0000-4000-8000-000000000002",
            "roles": {name: f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-{name}" for name in ("plan", "audit", "deploy", "application")},
            "application_delegations": roles, "lifecycle_steps": steps}


def _size(request):
    return len(request["Policy"]) + len(request["PolicyArns"][0]["arn"])


def _lifecycle_documents(governance):
    from tools.cnesdata_delivery.session_policy import lifecycle_request
    deletes = [f"arn:aws:states:us-east-2:{ACCOUNT}:stateMachine:cnesdata-prod-" + "m" * 40 + str(index) for index in range(8)]
    for role, direction, resources in (("plan", "advance", ()), ("audit", "advance", ()), ("deploy", "advance", ()),
                                       ("deploy", "converge", deletes)):
        yield f"lifecycle {role} {direction}", lifecycle_request(governance, SOURCE, RUN, ATTEMPT, role, LONG, direction=direction,
                                                                   delete_resources=resources)


def _application_documents(governance):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.session_policy import application_request
    names = {"observer": "sp-i-" + "a" * 40, "normal": "sp-publish-" + "a" * 40, "recovery": "sp-rollback-" + "a" * 40,
             "seeder": "canary-seeder-" + "a" * 32, "verifier": "canary-verifier-" + "a" * 32,
             "fence_operator": "promotion-fence-" + "a" * 32}
    for purpose in lc.APPLICATION_CONTEXTS:
        yield f"application keeper {purpose}", application_request(governance, SOURCE, RUN, ATTEMPT, "keeper", application_purpose=purpose)
    for aliases in (("normal", "observer"), ("recovery", "observer"), ("seeder",), ("verifier",), ("fence_operator",)):
        yield "application " + "+".join(aliases), application_request(
            governance, SOURCE, RUN, ATTEMPT, LONG, application_purpose="promotion", delegations=list(aliases),
            sessions={alias: names[alias] for alias in aliases})
    for operation, (code, role, context, _) in lc.MODE_SESSION_OPERATIONS.items():
        purpose = "mode-readiness-drill" if context == "readiness" else "promotion"
        yield "application mode " + operation, application_request(
            governance, SOURCE, RUN, ATTEMPT, LONG, application_purpose=purpose, delegations=[role],
            sessions={role: "mc-" + code + "-" + "a" * 40})
    yield "application closed-ready", application_request(governance, SOURCE, RUN, ATTEMPT, "closed-ready", application_purpose="promotion")


def test_toda_sessao_cabe_em_2048_caracteres_nos_maximos_governados(capsys):
    governance = _governance()
    rows = [(name, _size(request)) for name, request in (*_lifecycle_documents(governance), *_application_documents(governance))]
    with capsys.disabled():
        for name, size in rows:
            print(f"capacity {name}: {size}")
    assert rows and all(size <= 2048 for _, size in rows)


def test_keeper_cresce_so_com_o_balde_e_o_prefixo_nao_com_o_numero_de_planos():
    from tools.cnesdata_delivery.session_policy import application_request
    one = _governance() | {"lifecycle_steps": {PLANS[0]: {"role": "plan", "job_name": "p"}}}
    five = _governance()
    sizes = [_size(application_request(governance, SOURCE, RUN, ATTEMPT, "keeper", application_purpose="promotion"))
             for governance in (one, five)]
    assert sizes[0] == sizes[1]


def test_prefixo_de_evidencia_aceita_32_e_recusa_33_caracteres():
    from tools.cnesdata_delivery.session_policy import application_request
    accepted = "cnesdata/prod/" + "p" * 18
    refused = "cnesdata/prod/" + "p" * 19
    assert len(accepted) == 32 and len(refused) == 33
    application_request(_governance(accepted), SOURCE, RUN, ATTEMPT, "keeper", application_purpose="promotion")
    with pytest.raises(ValueError, match="session evidence namespace"):
        application_request(_governance(refused), SOURCE, RUN, ATTEMPT, "keeper", application_purpose="promotion")


def test_documento_do_keeper_e_json_valido_com_um_unico_recurso_de_plan_inputs():
    from tools.cnesdata_delivery.session_policy import application_request
    request = application_request(_governance(), SOURCE, RUN, ATTEMPT, "keeper", application_purpose="promotion")
    puts = [s["Resource"] for s in json.loads(request["Policy"])["Statement"] if s["Action"] == "s3:PutObject" and s["Effect"] == "Allow"]
    assert len(puts) == 1 and sum("plan-inputs-" in resource for resource in puts[0]) == 1
