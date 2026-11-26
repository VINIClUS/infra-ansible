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


def activated(gov, bucket, key_length):
    from tools.cnesdata_delivery import session_policy as sp
    base = gov["evidence_prefix"] + "ext2/"
    keys = {slot: base + slot[0] * (key_length - len(base)) for slot in sp.ACTIVATION_SLOTS}
    return dict(gov, activation_read={
        "ceiling": {"bucket_arn": "arn:aws:s3:::" + gov["evidence_bucket"], "cipher_kms_key_arn": gov["evidence_kms_key_arn"], "keys": keys},
        "ordinary_bucket_denies": list(sp.ACTIVATION_BUCKET_READS), "plan_role_arn": gov["roles"]["plan"],
        "identity_sha256": "b" * 64, "session_sha256": "c" * 64})


HISTORICAL = {
    "legacy-infra": {"protocol": "legacy-infra", "source_sha": "e" * 40, "run_id": 1, "run_attempt": 1,
                     "status": "applied", "purpose": "phase-a"},
    "lifecycle-terminal": {"protocol": "lifecycle", "source_sha": "e" * 40, "run_id": 1, "run_attempt": 1,
                           "status": "terminal", "purpose": "application"}}
VERSIONS = {"payload": "P" * 32, "signature": "S" * 32, "receipt": "R" * 32}
DEADLINE = "2030-01-01T00:15:00Z"


def activation_sizes(gov):
    from tools.cnesdata_delivery import session_policy as sp
    return {name: size(sp.activation_request(gov, selected, deadline=DEADLINE))
            for name, selected in (("receipt-only", {"receipt": VERSIONS["receipt"]}), ("three-versions", VERSIONS))}


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
    found["plan operational with activation"] = lambda: sp.lifecycle_request(
        activated(gov, bucket, sp.ACTIVATION_KEY_LIMIT), SOURCE, run, attempt, "plan", STEP, direction="advance")
    for protocol, selector in HISTORICAL.items():
        found["plan historical " + protocol] = lambda x=selector: sp.lifecycle_request(
            activated(gov, bucket, sp.ACTIVATION_KEY_LIMIT), SOURCE, run, attempt, "plan", STEP, direction="advance",
            predecessor=dict(x, run_id=run - 1, run_attempt=attempt))
    for scope, selected in (("receipt-only", {"receipt": VERSIONS["receipt"]}), ("three-versions", VERSIONS)):
        found["activation " + scope] = lambda s=selected: sp.activation_request(
            activated(gov, bucket, sp.ACTIVATION_KEY_LIMIT), s, deadline=DEADLINE)
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


def test_limite_de_chave_de_ativacao_e_justo_no_ponto_p1(monkeypatch):
    from tools.cnesdata_delivery import session_policy as sp
    gov = governance(63, 32)
    limit = sp.ACTIVATION_KEY_LIMIT
    assert limit == 273
    assert max(activation_sizes(activated(gov, 63, limit)).values()) <= LIMIT
    monkeypatch.setattr(sp, "ACTIVATION_KEY_LIMIT", limit + 1)
    assert max(activation_sizes(activated(gov, 63, limit + 1)).values()) > LIMIT


def test_chave_de_ativacao_acima_do_limite_e_recusada():
    from tools.cnesdata_delivery import session_policy as sp
    gov = governance(63, 32)
    sp.activation_request(activated(gov, 63, sp.ACTIVATION_KEY_LIMIT), VERSIONS, deadline=DEADLINE)
    with pytest.raises(ValueError, match="activation exact distinct keys"):
        sp.activation_request(activated(gov, 63, sp.ACTIVATION_KEY_LIMIT + 1), VERSIONS, deadline=DEADLINE)


def test_versao_longa_demais_para_o_limite_total_e_recusada_antes_do_sts():
    from tools.cnesdata_delivery import session_policy as sp
    gov = activated(governance(63, 32), 63, sp.ACTIVATION_KEY_LIMIT)
    with pytest.raises(ValueError, match="exceeds 2048"):
        sp.activation_request(gov, VERSIONS | {"receipt": "R" * 1024}, deadline=DEADLINE)


def test_limite_de_2048_conta_o_arn_exato_anexado_a_sessao_de_ativacao():
    from tools.cnesdata_delivery import session_policy as sp
    gov = activated(governance(63, 32), 63, sp.ACTIVATION_KEY_LIMIT)

    def total(length):
        try:
            return size(sp.activation_request(gov, VERSIONS | {"receipt": "R" * length}, deadline=DEADLINE))
        except ValueError:
            return None
    fits = max(length for length in range(1, 1025) if total(length) is not None)
    assert total(fits) == 2048 and total(fits + 1) is None
