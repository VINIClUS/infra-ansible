"""Every session policy document stays at 1998 characters or less at three governed points."""
import pytest

SOURCE = "b" * 40
ACCOUNT = "111122223333"
LIMIT = 1998
POINTS = {"p1-balde63-prefixo32": (63, 32, 2**53 - 1, 123), "p2-balde40-prefixo32": (40, 32, 2**53 - 1, 123),
          "p3-balde35-prefixo23": (35, 23, 10**10, 1)}
NAMES = {"observer": "sp-i-" + "a" * 40, "normal": "sp-publish-" + "a" * 40, "recovery": "sp-rollback-" + "a" * 40,
         "seeder": "canary-seeder-" + "a" * 32, "verifier": "canary-verifier-" + "a" * 32,
         "fence_operator": "promotion-fence-" + "a" * 32}
ALIASES = (("normal", "observer"), ("recovery", "observer"), ("normal",), ("recovery",), ("observer",), ("seeder",),
           ("verifier",), ("fence_operator",))
STEP = "s" * 64


def governance(bucket, prefix):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    name = "evidence-" + "b" * (bucket - 9)
    roles = {role: f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-{role}" for role in ("plan", "audit", "deploy", "application")}
    delegations = {alias: f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-{suffix}" for alias, suffix in lc.APPLICATION_DELEGATIONS.items()}
    return {"account_id": ACCOUNT, "state_bucket": name, "evidence_bucket": name,
            "evidence_prefix": "cnesdata/prod/" + "p" * (prefix - 15) + "/",
            "evidence_kms_key_arn": f"arn:aws:kms:us-east-2:{ACCOUNT}:key/00000000-0000-4000-8000-000000000002",
            "roles": roles, "application_delegations": delegations}


def delete_arns(count, length):
    head = f"arn:aws:cloudwatch:us-east-2:{ACCOUNT}:alarm:cnesdata-prod-"
    return [(head + "a" * length)[: length - 1] + str(index) for index in range(count)]


def size(request):
    return len(request["Policy"]) + sum(len(item["arn"]) for item in request["PolicyArns"])


def documents(point):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery import session_policy as sp
    bucket, prefix, run, attempt = point
    gov = governance(bucket, prefix)
    count = max(len(lc.scheduler_closure(kind)) for kind in ("recovery", "audit"))
    found = {}
    for role in ("plan", "audit", "deploy"):
        found[f"lifecycle {role} advance"] = lambda r=role: sp.lifecycle_request(gov, SOURCE, run, attempt, r, STEP, direction="advance")
    found["lifecycle deploy converge"] = lambda: sp.lifecycle_request(
        gov, SOURCE, run, attempt, "deploy", STEP, direction="converge", delete_resources=delete_arns(count, sp.DELETE_ARN_MAX))
    for purpose in lc.APPLICATION_CONTEXTS:
        found[f"keeper {purpose}"] = lambda p=purpose: sp.application_request(gov, SOURCE, run, attempt, "keeper", application_purpose=p)
    found["closed-ready"] = lambda: sp.application_request(gov, SOURCE, run, attempt, "closed-ready", application_purpose="promotion")
    for aliases in ALIASES:
        found["application " + "+".join(aliases)] = lambda a=aliases: sp.application_request(
            gov, SOURCE, run, attempt, "publish-static", application_purpose="promotion", delegations=list(a),
            sessions={alias: NAMES[alias] for alias in a})
    for operation, (code, role, context, _) in lc.MODE_SESSION_OPERATIONS.items():
        found["mode " + operation] = lambda o=operation, k=code, r=role, x=context: sp.application_request(
            gov, SOURCE, run, attempt, o, application_purpose="mode-readiness-drill" if x == "readiness" else "promotion",
            delegations=[r], sessions={r: "mc-" + k + "-" + "a" * 40})
    return found


@pytest.mark.parametrize("label", sorted(POINTS))
def test_toda_sessao_cabe_em_1998_caracteres_nos_tres_pontos(label, capsys):
    rows = {}
    for name, build in documents(POINTS[label]).items():
        try:
            rows[name] = size(build())
        except ValueError as error:
            rows[name] = str(error)
    with capsys.disabled():
        for name, value in rows.items():
            print(f"capacity {label} {name}: {value}")
    assert {name: value for name, value in rows.items() if type(value) is not int or value > LIMIT} == {}


def test_limite_de_exclusoes_deriva_dos_fechamentos_e_nao_de_um_literal(monkeypatch):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery import session_policy as sp
    gov = governance(35, 23)
    closure = max(len(lc.scheduler_closure(kind)) for kind in ("recovery", "audit"))
    sp.lifecycle_request(gov, SOURCE, 1, 1, "deploy", "step", direction="converge", delete_resources=delete_arns(closure, 90))
    with pytest.raises(ValueError, match="inverse exact resource inventory"):
        sp.lifecycle_request(gov, SOURCE, 1, 1, "deploy", "step", direction="converge", delete_resources=delete_arns(closure + 1, 90))
    monkeypatch.setattr(lc, "scheduler_closure", lambda kind: {f"module.schedulers.x{i}" for i in range(closure + 2)})
    sp.lifecycle_request(gov, SOURCE, 1, 1, "deploy", "step", direction="converge", delete_resources=delete_arns(closure + 2, 90))


def test_arn_de_exclusao_acima_do_maximo_medido_e_recusado():
    from tools.cnesdata_delivery import session_policy as sp
    gov = governance(35, 23)
    assert sp.DELETE_ARN_MAX == 104
    sp.lifecycle_request(gov, SOURCE, 1, 1, "deploy", "step", direction="converge", delete_resources=delete_arns(1, 104))
    with pytest.raises(ValueError, match="inverse exact same-product ARN"):
        sp.lifecycle_request(gov, SOURCE, 1, 1, "deploy", "step", direction="converge", delete_resources=delete_arns(1, 105))


def test_nenhum_nome_real_do_produto_passa_de_104_caracteres():
    longest = f"arn:aws:cloudwatch:us-east-2:{ACCOUNT}:alarm:cnesdata-prod-scheduler-recovery-repeated-failure"
    from tools.cnesdata_delivery import session_policy as sp
    assert len(longest) == 97 <= sp.DELETE_ARN_MAX == 104
