"""Rendered native role/trust/effective policy checks, not Terraform text assertions."""
import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures/cnesdata_delivery_roles_anywhere"


def activation_governance():
    from test_cnesdata_session_capacity import governance
    gov = governance()
    prefix = gov["evidence_prefix"] + "ext2/" + "a" * 40 + "/42448000000/1/"
    gov["activation_read"] = {
        "ceiling": {"bucket_arn": "arn:aws:s3:::" + gov["evidence_bucket"],
            "cipher_kms_key_arn": gov["evidence_kms_key_arn"],
            "keys": dict(zip(("payload", "signature", "receipt"),
                (prefix + name for name in ("activation.json", "signature.der", "receipt.json"))))},
        "ordinary_bucket_denies": ["s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetBucketObjectLockConfiguration"],
        "plan_role_arn": gov["roles"]["plan"], "identity_sha256": "b" * 64, "session_sha256": "c" * 64,
    }
    return gov


def test_activation_restrictions_exact_capacity_and_original_deadline():
    import copy
    from tools.cnesdata_delivery import session_policy as sp
    gov = activation_governance()
    versions = dict(zip(("payload", "signature", "receipt"), ("P" * 32, "S" * 32, "R" * 32)))
    for selected, expected in (({"receipt": versions["receipt"]}, 1571), (versions, 2041)):
        request = sp.activation_request(gov, selected, deadline="2030-01-01T00:15:00Z")
        assert len(request["Policy"]) + len(request["PolicyArns"][0]["arn"]) == expected
        statements = json.loads(request["Policy"])["Statement"]
        assert statements[1]["Condition"] == {"DateGreaterThanEquals": {"aws:CurrentTime": "2030-01-01T00:15:00Z"}}
        assert not any(action.startswith("iam:") for action in statements[0]["NotAction"])
    versions["receipt"] += "R" * 8
    with pytest.raises(ValueError, match="2048"):
        sp.activation_request(gov, versions, deadline="2030-01-01T00:15:00Z")
    for selected in ({}, {"payload": "P"}, {"receipt": None}, {"receipt": "null"}, {"receipt": True}):
        with pytest.raises(ValueError):
            sp.activation_request(gov, selected, deadline="2030-01-01T00:15:00Z")
    bad = copy.deepcopy(gov)
    bad["activation_read"]["ceiling"]["keys"]["receipt"] += "*"
    with pytest.raises(ValueError):
        sp.activation_request(bad, {"receipt": "R"}, deadline="2030-01-01T00:15:00Z")


def test_activation_deadline_evaluator_denies_equality_and_requires_timezone():
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    identity = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObjectVersion", "Resource": "*"}]}
    session = {"Version": "2012-10-17", "Statement": identity["Statement"] + [
        {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {
            "DateGreaterThanEquals": {"aws:CurrentTime": "2030-01-01T00:15:00Z"}}}]}
    for now, allowed in (("2030-01-01T00:14:59Z", True), ("2030-01-01T00:15:00Z", False), ("2030-01-01T00:15:01Z", False)):
        assert effective_iam(identity, [session], "s3:GetObjectVersion", "arn:aws:s3:::bucket/object", {"aws:CurrentTime": now}) is allowed
    with pytest.raises(ValueError, match="timezone"):
        effective_iam(identity, [session], "s3:GetObjectVersion", "arn:aws:s3:::bucket/object", {"aws:CurrentTime": "2030-01-01T00:14:59"})


@pytest.fixture(scope="module")
def native():
    from fixtures.cnesdata_delivery_oidc_native import Native
    instance = Native()
    yield instance
    instance.temp.cleanup()


def variables():
    return {"account_id": "111122223333", "region": "us-east-2", "ca_certificate_pem": (FIXTURE / "ca.crt").read_text(),
            "identity": {"trust_anchor_name": "synthetic-anchor", "role_name": "synthetic-cnesdata-api", "profile_name": "synthetic-profile",
                         "common_name": "synthetic-cnesdata-api", "san_uri": "spiffe://synthetic.invalid/cnesdata/api", "duration_seconds": 900},
            "github_delivery": {"provider_arn": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
                "provider_client_ids": ["sts.amazonaws.com"], "provider_thumbprints": ["0" * 40], "read_resource_arns": [],
                "plan_role_name": "cnesdata-test-plan", "deploy_role_name": "cnesdata-test-deploy", "plan_workflow_sha": "a" * 40,
                "deploy_workflow_sha": "b" * 40, "enabled_until": "2030-01-01T00:00:00Z", "state_bucket_arn": "arn:aws:s3:::synthetic-state",
                "state_kms_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000001",
                "evidence_bucket_arn": "arn:aws:s3:::synthetic-evidence",
                "evidence_kms_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000002",
                "evidence_prefix": "cnesdata/prod/evidence/", "product_permissions": [], "pass_roles": []}}


def render(native, values, name):
    code, plans, errors = native.plan(values, name)
    assert code == 0, json.dumps(errors, indent=2)
    values = plans[0]["planned_values"]
    return {r["address"]: r["values"] for r in values["root_module"]["resources"] if r["mode"] == "managed"}, values["outputs"]


def application_values():
    values = variables()
    roles = {"observer": "static-observer", "normal": "static-normal", "recovery": "static-recovery",
             "seeder": "canary-seeder", "verifier": "canary-verifier", "fence_operator": "promotion-fence-operator",
             "mode_seed": "mode-seed", "mode_dispatch": "mode-dispatch",
             "mode_audit_launch": "mode-audit-launch", "mode_observe": "mode-observe"}
    values["application_promotion"] = {"role_name": "cnesdata-prod-application", "workflow_sha": "c" * 40,
        "source_closure_sha256": "d" * 64, "enabled_until": "2030-01-01T00:00:00Z",
        "delegations": {k: "arn:aws:iam::111122223333:role/cnesdata-prod-" + v for k, v in roles.items()}}
    return values


def test_application_is_absent_by_default(native):
    resources, outputs = render(native, variables(), "application-disabled")
    assert not any(k.startswith("aws_iam_role.application") for k in resources)
    assert outputs.get("application_promotion", {}).get("value") is None


def test_application_owns_coordination_and_only_exact_product_delegation(native):
    resources, outputs = render(native, application_values(), "application-enabled")
    assert "aws_iam_role.application[0]" in resources
    policy = json.loads(resources["aws_iam_role_policy.application[0]"]["policy"])
    role = resources["aws_iam_role.application[0]"]
    trust = json.loads(role["assume_role_policy"])["Statement"]
    assert len(trust) == 1
    assert trust[0]["Principal"] == {"Federated": variables()["github_delivery"]["provider_arn"]}
    assert trust[0]["Condition"]["StringEquals"] == {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:VINIClUS/CnesData:environment:production:job_workflow_ref:VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-application-gate.yml@" + "c" * 40}
    fragment = outputs["application_promotion"]
    assert fragment["sensitive"] is True
    assert fragment["value"]["application_role_arn"] == "arn:aws:iam::111122223333:role/cnesdata-prod-application"
    assert fragment["value"]["application_role_name"] == "cnesdata-prod-application"
    assert fragment["value"]["producer"]["workflow_sha"] == "c" * 40
    assert fragment["value"]["fragment_version"] == 4
    assert "caller" not in fragment["value"] and "predecessor_reads" not in fragment["value"]
    assert fragment["value"]["caller_by_purpose"] == {
        purpose: {"repository": "VINIClUS/CnesData", "workflow_path": path,
                  "ref": "refs/heads/develop", "environment": "production"}
        for purpose, path in (("promotion", ".github/workflows/promote-production.yml"),
                              ("mode-readiness-drill", ".github/workflows/readiness-production.yml"))}
    from fixtures.cnesdata_iam_evaluation import allowed
    roles = application_values()["application_promotion"]["delegations"]
    assert allowed(policy, "sts:AssumeRole", roles["observer"], {"sts:RoleSessionName": "sp-i-" + "a" * 40})
    assert not allowed(policy, "sts:AssumeRole", "arn:aws:iam::111122223333:role/limnopulse-observer", {"sts:RoleSessionName": "sp-i-" + "a" * 40})
    assert not allowed(policy, "sts:AssumeRole", roles["observer"], {"sts:RoleSessionName": "arbitrary"})
    modes = {"mode_seed": ("us", "rs", "ds"), "mode_dispatch": ("ux", "rx", "dx", "dr", "h1", "h2"),
             "mode_audit_launch": ("ax",), "mode_observe": ("uo", "ro", "ao", "do")}
    for alias, codes in modes.items():
        for code in {code for group in modes.values() for code in group}:
            assert allowed(policy, "sts:AssumeRole", roles[alias],
                           {"sts:RoleSessionName": "mc-" + code + "-" + "a" * 40}) is (code in codes)
        for bad in ("mc-zz-" + "a" * 40, "mc-" + codes[0] + "-" + "a" * 39,
                    "mc-" + codes[0] + "-" + "a" * 41):
            assert not allowed(policy, "sts:AssumeRole", roles[alias], {"sts:RoleSessionName": bad})
    for action, resource in [("s3:PutObject", "arn:aws:s3:::cnesdata-prod-static-web/index.html"),
                             ("s3:GetObject", "arn:aws:s3:::synthetic-state/cnesdata/prod/opentofu.tfstate"),
                             ("cloudfront:CreateInvalidation", "arn:aws:cloudfront::111122223333:distribution/EXAMPLE")]:
        assert not allowed(policy, action, resource)
    assert set(outputs["github"]["value"]) == {"infrastructure_plan_role_arn", "infrastructure_deploy_role_arn"}


@pytest.mark.parametrize("status,purpose,names", [
    ("planned", "phase-a", {"envelope.json", "lease.json", "checkpoint.json"}),
    ("applied", "phase-a", {"envelope.json", "lease.json", "checkpoint.json", "drift.json", "ecr-before.json"}),
    ("applied", "bootstrap", {"envelope.json", "lease.json", "checkpoint.json", "drift.json"}),
    ("terminal", "application", {"terminal.json", "lease.json", "checkpoint.json"}),
])
def test_native_application_history_exact_objects_and_decrypt_only(native, status, purpose, names):
    from fixtures.cnesdata_iam_evaluation import allowed
    from tools.cnesdata_delivery import contract as c
    data = application_values()
    history = {"protocol": "lifecycle" if status == "terminal" else "legacy-infra", "source_sha": "e" * 40,
               "run_id": 42, "run_attempt": 2, "status": status, "purpose": purpose}
    data["application_promotion"]["predecessor_read"] = history
    resources, outputs = render(native, data, "history-" + status + "-" + purpose)
    fragment = outputs["application_promotion"]["value"]
    assert fragment["fragment_version"] == 4
    assert {k: fragment["predecessor_reads"][k] for k in history} == history
    private = fragment["predecessor_reads"]
    root = "arn:aws:s3:::synthetic-evidence/cnesdata/prod/evidence/"
    prefix = root + ("lifecycle/" if status == "terminal" else "") + "e" * 40 + "/42/2/" + status + "/"
    assert set(private["object_arns"]) == {prefix + name for name in names}
    history_policy = json.loads(resources["aws_iam_role_policy.application_history[0]"]["policy"])
    assert private["policy_sha256"] == c.sha(resources["aws_iam_role_policy.application_history[0]"]["policy"].encode())
    key = data["github_delivery"]["evidence_kms_arn"]
    for name in names:
        obj = prefix + name
        context = {"kms:ViaService": "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": obj}
        assert allowed(history_policy, "s3:GetObject", obj)
        assert allowed(history_policy, "kms:Decrypt", key, context)
        for action in ("s3:PutObject", "s3:DeleteObject", "s3:GetObjectVersion"):
            assert not allowed(history_policy, action, obj)
        assert not allowed(history_policy, "kms:Encrypt", key, context)
        assert not allowed(history_policy, "kms:GenerateDataKey", key, context)
        assert not allowed(history_policy, "kms:Decrypt", key, context | {"kms:ViaService": "s3.us-east-1.amazonaws.com"})
    for obj in (prefix + "unknown.json", prefix.replace("/42/2/", "/43/2/") + "checkpoint.json",
                "arn:aws:s3:::synthetic-state/cnesdata/prod/opentofu.tfstate"):
        assert not allowed(history_policy, "s3:GetObject", obj)
        assert not allowed(history_policy, "kms:Decrypt", key, {"kms:ViaService": "s3.us-east-2.amazonaws.com",
                                                               "kms:EncryptionContext:aws:s3:arn": obj})


def test_rendered_oidc_roles_are_separate_and_exact(native):
    resources, outputs = render(native, variables(), "oidc")
    for role, char in (("plan", "a"), ("deploy", "b")):
        rendered = resources[f'aws_iam_role.delivery["{role}"]']
        trust = json.loads(rendered["assume_role_policy"])
        assert len(trust["Statement"]) == 1
        statement = trust["Statement"][0]
        assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
        assert statement["Principal"] == {"Federated": variables()["github_delivery"]["provider_arn"]}
        exact = statement["Condition"]["StringEquals"]
        assert exact == {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub":
            f"repo:VINIClUS/CnesData:environment:production:job_workflow_ref:VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-{role}-gate.yml@{char * 40}"}
        assert statement["Condition"]["DateLessThan"] == {"aws:CurrentTime": "2030-01-01T00:00:00Z"}
        policy = json.loads(resources[f'aws_iam_role_policy.delivery["{role}"]']["policy"])
        assert any(s["Effect"] == "Deny" and "sts:AssumeRole" in s["Action"] for s in policy["Statement"])
        state = "arn:aws:s3:::synthetic-state/cnesdata/prod/opentofu.tfstate"
        writers = [s for s in policy["Statement"] if s["Effect"] == "Allow" and s["Resource"] == state and "s3:PutObject" in s["Action"]]
        assert bool(writers) is (role == "deploy")
        assert not any(s["Effect"] == "Allow" and any(a.endswith(":*") for a in s["Action"]) for s in policy["Statement"])
        from tools.cnesdata_delivery.session_policy import request
        from fixtures.cnesdata_iam_evaluation import effective as permits
        settings = variables()["github_delivery"]
        governance = {"account_id": variables()["account_id"], "state_bucket": "synthetic-state",
            "evidence_bucket": "synthetic-evidence", "state_kms_key_arn": settings["state_kms_arn"],
            "evidence_kms_key_arn": settings["evidence_kms_arn"], "evidence_prefix": settings["evidence_prefix"],
            "roles": {kind: f"arn:aws:iam::111122223333:role/cnesdata-test-{kind}" for kind in ("plan", "deploy")}}
        historical = "cnesdata/prod/evidence/" + "c" * 40 + "/9/1/planned/*"
        session_request = request(governance, "d" * 40, 10, 1, role, [historical])
        session = json.loads(session_request["Policy"])
        managed = json.loads(resources[f'aws_iam_policy.delivery_session["{role}"]']["policy"])
        assert len(session_request["Policy"]) + sum(len(item["arn"]) for item in session_request["PolicyArns"]) <= 2048
        def effective(action, resource, context=None):
            return permits(policy, managed, session, action, resource, context)
        status = "planned" if role == "plan" else "applied"
        own_prefix = "cnesdata/prod/evidence/" + "d" * 40 + "/10/1/" + status + "/"
        own = "arn:aws:s3:::synthetic-evidence/" + own_prefix + "envelope.json"
        old = "arn:aws:s3:::synthetic-evidence/" + historical[:-1] + "plan.bin"
        assert effective("s3:PutObject", own) and effective("s3:GetObject", own)
        assert effective("s3:GetObject", old) and not effective("s3:PutObject", old)
        assert not effective("s3:DeleteObject", own) and not effective("s3:DeleteObject", old)
        assert not effective("s3:GetObjectVersion", old, {"s3:VersionId": "unapproved"})
        assert not effective("s3:ListBucketVersions", settings["evidence_bucket_arn"])
        assert not effective("s3:ListBucket", settings["evidence_bucket_arn"], {"s3:prefix": own_prefix})
        assert not effective("s3:ListBucket", settings["evidence_bucket_arn"], {"s3:prefix": "cnesdata/prod/evidence/"})
        assert effective("s3:PutObject", state) is (role == "deploy")
        assert effective("s3:DeleteObject", state + ".tflock")
        assert not effective("s3:DeleteObject", state)
        context = {"kms:ViaService": "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": own}
        assert effective("kms:GenerateDataKey", settings["evidence_kms_arn"], context)
        assert not effective("kms:GenerateDataKey", settings["evidence_kms_arn"], context | {"kms:EncryptionContext:aws:s3:arn": old})
        assert effective("kms:Decrypt", settings["evidence_kms_arn"], context | {"kms:EncryptionContext:aws:s3:arn": old})
        assert not effective("kms:Decrypt", settings["evidence_kms_arn"], context | {"kms:ViaService": "ec2.us-east-2.amazonaws.com"})
        assert not effective("sts:AssumeRole", "*")
    assert set(outputs["github"]["value"]) == {"infrastructure_plan_role_arn", "infrastructure_deploy_role_arn"}
    assert not any(key.startswith("aws_iam_openid_connect_provider.") for key in resources)


@pytest.mark.parametrize("field,value", [("plan_workflow_sha", "main"), ("provider_arn", "arn:aws:iam::999988887777:oidc-provider/token.actions.githubusercontent.com")])
def test_native_rejects_unreviewed_provider_or_mutable_trust(native, field, value):
    data = variables()
    data["github_delivery"][field] = value
    code, _, diagnostics = native.plan(data, "invalid-" + field)
    assert code != 0 and diagnostics


def test_native_identity_managed_and_inline_bound_exact_inverse(native):
    from fixtures.cnesdata_iam_evaluation import effective
    from tools.cnesdata_delivery.session_policy import lifecycle_request
    data = application_values()
    owned = "arn:aws:scheduler:us-east-2:111122223333:schedule/cnesdata-prod/cnesdata-prod-audit"
    preexisting = owned + "-prior"
    foreign = owned.replace("cnesdata-prod-audit", "other-product-audit")
    data["github_delivery"]["product_permissions"] = [{"actions": ["scheduler:DeleteSchedule"], "resources": [owned, preexisting]}]
    resources, _ = render(native, data, "inverse-native-boundary")
    identity = json.loads(resources['aws_iam_role_policy.delivery["deploy"]']["policy"])
    managed = json.loads(resources['aws_iam_policy.delivery_session["deploy"]']["policy"])
    settings = data["github_delivery"]
    governance = {"account_id": data["account_id"], "state_bucket": "synthetic-state", "evidence_bucket": "synthetic-evidence",
                  "evidence_prefix": settings["evidence_prefix"], "evidence_kms_key_arn": settings["evidence_kms_arn"],
                  "roles": {"deploy": "arn:aws:iam::111122223333:role/cnesdata-test-deploy"}}
    advance = json.loads(lifecycle_request(governance, "a" * 40, 123, 1, "deploy", "phase-c-audit",
                                          direction="advance")["Policy"])
    inverse = json.loads(lifecycle_request(governance, "a" * 40, 123, 1, "deploy", "phase-c-audit-converge",
                                          direction="converge", delete_resources=[owned])["Policy"])
    assert not effective(identity, managed, advance, "scheduler:DeleteSchedule", owned)
    assert effective(identity, managed, inverse, "scheduler:DeleteSchedule", owned)
    assert not effective(identity, managed, inverse, "scheduler:DeleteSchedule", preexisting)
    assert not effective(identity, managed, inverse, "scheduler:DeleteSchedule", foreign)
    lease = "arn:aws:s3:::synthetic-state/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"
    assert effective(identity, managed, inverse, "s3:GetObject", lease)
    assert not effective(identity, managed, inverse, "s3:PutObject", lease)
    assert not effective(identity, managed, inverse, "s3:DeleteObject", lease)


def test_native_application_sessions_separate_keeper_history_and_operation(native):
    from fixtures.cnesdata_iam_evaluation import effective
    from tools.cnesdata_delivery.session_policy import application_request
    data = application_values()
    data["application_promotion"]["predecessor_read"] = {
        "protocol": "legacy-infra", "source_sha": "e" * 40, "run_id": 42, "run_attempt": 2,
        "status": "applied", "purpose": "phase-a"}
    resources, outputs = render(native, data, "application-session-union")
    identity = json.loads(resources["aws_iam_role_policy.application[0]"]["policy"])
    identity["Statement"] += json.loads(resources["aws_iam_role_policy.application_history[0]"]["policy"])["Statement"]
    managed = json.loads(resources["aws_iam_policy.application_session[0]"]["policy"])
    settings = data["github_delivery"]
    roles = data["application_promotion"]["delegations"]
    governance = {"account_id": data["account_id"], "state_bucket": "synthetic-state", "evidence_bucket": "synthetic-evidence",
                  "evidence_prefix": settings["evidence_prefix"], "evidence_kms_key_arn": settings["evidence_kms_arn"],
                  "roles": {"application": "arn:aws:iam::111122223333:role/cnesdata-prod-application"},
                  "application_delegations": roles}
    requests = [application_request(governance, "b" * 40, 44, 1, "keeper", application_purpose="promotion"),
                application_request(governance, "b" * 40, 44, 1, "publish-static", application_purpose="promotion",
                            delegations=["normal", "observer"], sessions={"normal": "sp-publish-" + "a" * 40, "observer": "sp-i-" + "a" * 40})]
    for request in requests:
        assert len(request["Policy"]) + len(request["PolicyArns"][0]["arn"]) <= 2048
    keeper, operation = (json.loads(x["Policy"]) for x in requests)
    lease = "arn:aws:s3:::synthetic-state/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"
    assert effective(identity, managed, keeper, "s3:PutObject", lease)
    assert not effective(identity, managed, operation, "s3:PutObject", lease)
    assert effective(identity, managed, operation, "s3:GetObject", lease)
    history = outputs["application_promotion"]["value"]["predecessor_reads"]["object_arns"]
    for arn in history:
        assert effective(identity, managed, keeper, "s3:GetObject", arn)
        assert not effective(identity, managed, operation, "s3:GetObject", arn)
        assert not effective(identity, managed, keeper, "s3:PutObject", arn)
        context = {"kms:ViaService": "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": arn}
        assert effective(identity, managed, keeper, "kms:Decrypt", settings["evidence_kms_arn"], context)
        assert not effective(identity, managed, keeper, "kms:Encrypt", settings["evidence_kms_arn"], context)
    own = "arn:aws:s3:::synthetic-evidence/cnesdata/prod/evidence/lifecycle/" + "b" * 40 + "/44/1/"
    for policy, step in ((keeper, "terminal"), (operation, "publish-static")):
        assert effective(identity, managed, policy, "s3:PutObject", own + step + "/receipt.json")
        assert not effective(identity, managed, policy, "s3:PutObject", own + "other-step/receipt.json")
        assert not effective(identity, managed, policy, "s3:GetObject", own.replace("/44/1/", "/45/1/") + "receipt.json")
        assert not effective(identity, managed, policy, "s3:GetObject", "arn:aws:s3:::synthetic-state/cnesdata/prod/opentofu.tfstate")
    for role, pattern in (("normal", "sp-publish-" + "a" * 40), ("observer", "sp-i-" + "a" * 40)):
        assert effective(identity, managed, operation, "sts:AssumeRole", roles[role], {"sts:RoleSessionName": pattern})
        assert not effective(identity, managed, keeper, "sts:AssumeRole", roles[role], {"sts:RoleSessionName": pattern})
        assert not effective(identity, managed, operation, "sts:AssumeRole", roles[role], {"sts:RoleSessionName": pattern[:-1] + "b"})
    assert not effective(identity, managed, operation, "sts:AssumeRole", roles["recovery"], {"sts:RoleSessionName": "sp-rollback-" + "a" * 40})


@pytest.mark.parametrize("with_history", [False, True])
def test_native_application_fragment_requires_original_owner_and_exact_iam_readback(native, with_history, monkeypatch, tmp_path):
    import copy
    from urllib.parse import quote
    from tools.cnesdata_delivery import contract as c, session_owner
    from tools.cnesdata_delivery.session_policy import managed_arn
    from test_cnesdata_session_owner import original_owner
    gov, descriptor, proof, files, api, now = original_owner("plan", "application-prepare")
    data = application_values()
    data["application_promotion"]["enabled_until"] = c.utc(now + 10000)
    if with_history:
        data["application_promotion"]["predecessor_read"] = {
            "protocol": "legacy-infra", "source_sha": "e" * 40, "run_id": 42, "run_attempt": 2,
            "status": "applied", "purpose": "phase-a"}
    resources, outputs = render(native, data, "application-fragment-readback-" + str(with_history))
    fragment = outputs["application_promotion"]["value"]
    settings = data["github_delivery"]
    gov.update(state_bucket="synthetic-state", evidence_bucket="synthetic-evidence", evidence_prefix=settings["evidence_prefix"],
               state_kms_key_arn=settings["state_kms_arn"], evidence_kms_key_arn=settings["evidence_kms_arn"],
               application_fragment=fragment, application_configuration=data["application_promotion"],
               application_delegations=data["application_promotion"]["delegations"],
               application_source_closure_sha256=data["application_promotion"]["source_closure_sha256"],
               gate_shas={"application": "c" * 40})
    if with_history:
        from tools.cnesdata_delivery.session_policy import predecessor_keys
        gov["predecessor_read"] = data["application_promotion"]["predecessor_read"]
        # Native IAM fixture: structural historical metadata only. Real original
        # receipt/private-byte authentication is exercised by application tests.
        entries = [{"name": key.rsplit("/", 1)[1], "sha256": c.sha(key.encode()), "size": 10}
                   for key in predecessor_keys(gov, gov["predecessor_read"])]
        gov["lifecycle_predecessor"] = {"predecessor_version": 1, "protocol": "legacy-infra", "repository": c.REPOSITORY,
            "source_sha": "e" * 40, "run_id": 42, "run_attempt": 2, "owner_sha256": "a" * 64, "generation": None,
            "session_sha256": "b" * 64, "checkpoint_sha256": next(x["sha256"] for x in entries if x["name"] == "checkpoint.json"),
            "artifact_id": 42, "artifact_digest": "sha256:" + "c" * 64, "producer_job_id": 91,
            "producer_name": "apply / execute", "objects": entries}
    gov["roles"]["application"] = fragment["application_role_arn"]
    pin = gov["session_policy_pins"].pop("plan")
    pin.update(role_arn=fragment["application_role_arn"], policy_arn=managed_arn(gov, "application"),
               document=json.loads(resources["aws_iam_policy.application_session[0]"]["policy"]))
    pin["document_sha256"] = c.sha(c.canonical(pin["document"]))
    gov["session_policy_pins"]["application"] = pin
    measured = {"managed_session_policy": session_owner._facts(pin), "application_fragment_sha256": c.sha(c.canonical(fragment))}
    name = "policy-evaluation.json"
    files[name] = c.canonical({"check_id": "policy-evaluation", "source_sha": descriptor["source_sha"], "measurement": measured})
    next(x for x in proof["reports"] if x["check_id"] == "policy-evaluation").update(size=len(files[name]), sha256=c.sha(files[name]))
    digest = c.sha(c.canonical(measured))
    next(x for x in proof["checks"] if x["check_id"] == "policy-evaluation").update(expected_sha256=digest, observed_sha256=digest)
    api.freeze_owner(gov, proof, files)
    gov["session_owner_references"] = {"application": api.owner_reference}
    authority = session_owner.authenticate_lifecycle(gov, api, descriptor["source_sha"], "application", "application-prepare", now)
    assert authority.application_fragment == fragment
    assert authority.application_fragment is not fragment
    # Infra lifecycle credentials must authenticate the application fragment too,
    # before reaching their own plan/deploy token exchange.
    from tools.cnesdata_delivery import lifecycle_runtime
    old_fragment = copy.deepcopy(gov)
    old_fragment["application_fragment"]["fragment_version"] = 3
    exchanges = []
    monkeypatch.setattr(lifecycle_runtime.time, "time", lambda: now)
    monkeypatch.setattr(lifecycle_runtime, "admission", lambda role: (old_fragment,
        {"source_sha": descriptor["source_sha"], "step": "prepare-plan"},
        {"purpose": "application-prepare", "direction": "advance"}, api, {"id": 44, "run_attempt": 1}, {}))
    monkeypatch.setattr(lifecycle_runtime, "oidc_credentials", lambda *args: exchanges.append(args))
    with pytest.raises(ValueError, match="private fragment version"):
        lifecycle_runtime.credentials("plan")
    assert exchanges == []
    for field, value in (("trust_sha256", "f" * 64),):
        changed = copy.deepcopy(gov)
        changed["application_fragment"][field] = value
        with pytest.raises(ValueError, match="original owner private fragment commitment"):
            session_owner.authenticate_lifecycle(changed, api, descriptor["source_sha"], "application", "application-prepare", now)
    for version in (1, 2, 3):
        bad = copy.deepcopy(gov)
        bad["application_fragment"]["fragment_version"] = version
        with pytest.raises(ValueError): session_owner.application_fragment(bad, now)
    for purpose in ("promotion", "mode-readiness-drill"):
        bad = copy.deepcopy(gov)
        bad["application_fragment"]["caller_by_purpose"][purpose]["workflow_path"] = ".github/workflows/other.yml"
        with pytest.raises(ValueError): session_owner.application_fragment(bad, now)
    bad = copy.deepcopy(gov)
    bad["application_configuration"]["caller"] = "unreviewed"
    with pytest.raises(ValueError): session_owner.application_fragment(bad, now)
    bad = copy.deepcopy(gov)
    bad["application_fragment"]["extra"] = True
    with pytest.raises(ValueError): session_owner.application_fragment(bad, now)
    bad = copy.deepcopy(gov)
    bad["application_fragment"]["delegations"]["normal"] = "arn:aws:iam::111122223333:role/cnesdata-prod-foreign"
    with pytest.raises(ValueError): session_owner.application_fragment(bad, now)
    if with_history:
        bad = copy.deepcopy(gov)
        bad["application_fragment"]["predecessor_reads"]["object_arns"][0] += "*"
        with pytest.raises(ValueError): session_owner.application_fragment(bad, now)
        for mutation in ("hash", "missing", "null", "current-purpose", "selector-null", "reference-missing", "reference-extra", "reference-run", "output-float"):
            bad = copy.deepcopy(gov)
            if mutation == "hash": bad["application_fragment"]["predecessor_reads"]["policy_sha256"] = "0" * 64
            if mutation == "missing": bad["application_fragment"].pop("predecessor_reads")
            if mutation == "null": bad["application_fragment"]["predecessor_reads"] = None
            if mutation == "current-purpose": bad["application_fragment"]["predecessor_reads"]["purpose"] = "promotion"
            if mutation == "selector-null": bad["predecessor_read"] = None
            if mutation == "reference-missing": bad.pop("lifecycle_predecessor")
            if mutation == "reference-extra": bad["lifecycle_predecessor"]["objects"][0]["bucket"] = "foreign"
            if mutation == "reference-run": bad["lifecycle_predecessor"]["run_id"] = 43
            if mutation == "output-float": bad["application_fragment"]["predecessor_reads"]["run_id"] = 42.0
            with pytest.raises(ValueError): session_owner.application_fragment(bad, now)
    else:
        bad = copy.deepcopy(gov)
        bad["lifecycle_predecessor"] = {"protocol": "legacy-infra"}
        with pytest.raises(ValueError): session_owner.application_fragment(bad, now)
        for value in (None, {}):
            bad = copy.deepcopy(gov)
            bad["application_fragment"]["predecessor_reads"] = value
            with pytest.raises(ValueError): session_owner.application_fragment(bad, now)


    class Guard:
        def __init__(self): self.admissions = []
        def check(self, seconds=1): self.admissions.append(seconds)
    class IAM:
        def __init__(self, mutation=None):
            self.mutation, self.roles_read, self.policies_read = mutation, 0, 0
        def call(self, service, operation, **parameters):
            assert service == "iam"
            if operation == "get_policy":
                return {"Policy": {"Arn": pin["policy_arn"], "PolicyName": pin["policy_arn"].rsplit("/", 1)[1],
                    "DefaultVersionId": "v9" if self.mutation == "managed-default" else pin["default_version_id"],
                    "AttachmentCount": 0, "PermissionsBoundaryUsageCount": 0}}
            if operation == "get_policy_version":
                return {"PolicyVersion": {"VersionId": pin["default_version_id"], "IsDefaultVersion": True, "Document": pin["document"]}}
            if operation == "get_role":
                self.roles_read += 1
                value = {"RoleName": fragment["application_role_name"], "Arn": fragment["application_role_arn"],
                         "RoleId": "AROAoriginal", "MaxSessionDuration": 3600,
                         "AssumeRolePolicyDocument": resources["aws_iam_role.application[0]"]["assume_role_policy"]}
                if self.mutation == "boundary": value["PermissionsBoundary"] = {"PermissionsBoundaryArn": "other"}
                if self.mutation == "trust": value["AssumeRolePolicyDocument"] = {"Statement": []}
                if self.mutation == "duration": value["MaxSessionDuration"] = 7200
                if self.mutation == "role-replaced" and self.roles_read == 2: value["RoleId"] = "AROAreplaced"
                return {"Role": value}
            if operation == "list_role_policies":
                names = ["cnesdata-application-coordination"] + (["cnesdata-application-predecessor-read"] if with_history else [])
                if self.mutation == "extra-policy": names.append("other-policy")
                return {"IsTruncated": self.mutation == "truncated", "PolicyNames": names}
            if operation == "list_attached_role_policies":
                return {"IsTruncated": False, "AttachedPolicies": [{"PolicyArn": "other"}] if self.mutation == "attached" else []}
            assert operation == "get_role_policy"
            self.policies_read += 1
            key = "application_history" if parameters["PolicyName"].endswith("predecessor-read") else "application"
            document = resources[f"aws_iam_role_policy.{key}[0]"]["policy"]
            if self.mutation == "policy-changed" and self.roles_read == 2: document = '{"Statement":[]}'
            return {"RoleName": fragment["application_role_name"], "PolicyName": parameters["PolicyName"],
                    "PolicyDocument": quote(document)}
    guard = Guard()
    report = session_owner.verify_application(IAM(), authority, now + 3600, guard, clock=lambda: now)
    assert report["fragment_sha256"] == measured["application_fragment_sha256"]
    original_documents = session_owner.verify_application(IAM(), authority, now + 3600, Guard(), clock=lambda: now, include_documents=True)
    assert original_documents["role_id"] == "AROAoriginal"
    assert original_documents["documents"]["application_managed"] == pin["document"]
    expected_policies = [json.loads(resources["aws_iam_role_policy.application[0]"]["policy"])]
    if with_history:
        expected_policies.append(json.loads(resources["aws_iam_role_policy.application_history[0]"]["policy"]))
    assert original_documents["documents"]["application_identity"] == {"Version": "2012-10-17",
        "Statement": [statement for document in expected_policies for statement in document["Statement"]]}
    assert 20 in guard.admissions and set(guard.admissions) == {1, 20}
    for mutation in ("managed-default", "boundary", "trust", "duration", "role-replaced", "extra-policy", "truncated", "attached", "policy-changed"):
        with pytest.raises(ValueError):
            session_owner.verify_application(IAM(mutation), authority, now + 3600, Guard(), clock=lambda: now)

    # Own-role bootstrap uses the real source and authority/readback validators.
    # The OIDC exchange and IAM network boundary are synthetic; no AWS is used.
    import subprocess
    from datetime import datetime, timezone
    from tools.cnesdata_delivery import application_gate as ag
    product = tmp_path / "product"
    script = product / "scripts/promotion/promote_api.py"
    script.parent.mkdir(parents=True)
    script.write_text("def execute_shared_operation(operation, request, context):\n    raise RuntimeError('fixture not an operational adapter')\n")
    def git(*args):
        return subprocess.run(["git", *args], cwd=product, check=True, capture_output=True).stdout.decode().strip()
    git("init", "-q")
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "bootstrap source fixture")
    source = git("rev-parse", "HEAD")
    proof["source"]["source_sha"] = source
    for row in proof["reports"]:
        report_value = c.loads(files[row["name"]], canonical=True)
        report_value["source_sha"] = source
        files[row["name"]] = c.canonical(report_value)
        row.update(size=len(files[row["name"]]), sha256=c.sha(files[row["name"]]))
    api.freeze_owner(gov, proof, files)
    gov["session_owner_references"]["application"] = api.owner_reference
    manifest = {"version": 1, "source_sha": source, "files": {"scripts/promotion/promote_api.py": c.sha(script.read_bytes())}}
    gov.update(role="application", application_product_source_manifest=manifest,
               application_product_source_closure_sha256=c.sha(c.canonical(manifest)))
    request = {"source_sha": source, "step": "closed-ready", "application_purpose": "promotion"}
    run = {"id": 44, "run_attempt": 1}
    exported = tmp_path / "github-env"
    monkeypatch.setenv("GITHUB_ENV", str(exported))
    native_credentials = {"AccessKeyId": "synthetic-key", "SecretAccessKey": "synthetic-secret", "SessionToken": "synthetic-token",
                          "Expiration": datetime.fromtimestamp(now + 3600, timezone.utc)}
    bootstrap_exchanges = []
    def oidc(governance, role, restriction, current_run):
        assert role == "application" and current_run == run
        statements = json.loads(restriction["Policy"])["Statement"]
        assert {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"} in statements
        bootstrap_exchanges.append(restriction)
        return native_credentials
    identity_change = {}
    class BootstrapIAM(IAM):
        def __init__(self, governance, *, credentials):
            super().__init__()
            assert credentials == native_credentials
            self.identity = {"Account": gov["account_id"], "Arn": fragment["application_role_arn"].replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/cnesdata-44-1",
                             "UserId": "AROAoriginal:cnesdata-44-1"} | identity_change
    monkeypatch.setattr(lifecycle_runtime, "oidc_credentials", oidc)
    monkeypatch.setattr(lifecycle_runtime, "AWS", BootstrapIAM)
    admitted = (gov, request, {"purpose": "application-prepare"}, api, run, {})
    ag.credentials(admitted, product=product)
    original_export = exported.read_bytes()
    assert b"AWS_CREDENTIAL_EXPIRATION=" in original_export and len(bootstrap_exchanges) == 1
    for field, value in (("UserId", "AROAother:cnesdata-44-1"), ("Account", "999900001111"), ("Arn", "arn:aws:sts::111122223333:assumed-role/foreign/cnesdata-44-1")):
        identity_change.clear()
        identity_change[field] = value
        with pytest.raises(ValueError, match="original bootstrap GetCallerIdentity"):
            ag.credentials(admitted, product=product)
        assert exported.read_bytes() == original_export
    before = len(bootstrap_exchanges)
    script.write_text(script.read_text() + "# dirty source\n")
    with pytest.raises(ValueError, match="dirty or shadowed"):
        ag.credentials(admitted, product=product)
    assert len(bootstrap_exchanges) == before


def test_native_schema_confirms_readonly_computed_delta_fields(native):
    from tools.cnesdata_delivery.lifecycle_contract import COMPUTED_OUTPUTS
    schemas = native.schema()
    for name, expected in COMPUTED_OUTPUTS.items():
        observed = {key for key, value in schemas[name]["block"]["attributes"].items()
                    if value.get("computed") and not value.get("optional") and not value.get("required")}
        assert observed == expected, name


@pytest.mark.parametrize("mutation", [None, "extra", "extra-history", "string-run", "bool-run", "float-run", "old-six", "foreign-role"])
def test_private_application_raw_configuration_is_closed_before_terraform_coercion(mutation):
    from tools.cnesdata_delivery import session_owner
    assert callable(getattr(session_owner, "application_configuration", None)), "raw application configuration validator required"
    value = application_values()["application_promotion"]
    value["predecessor_read"] = {"protocol": "legacy-infra", "source_sha": "e" * 40,
        "run_id": 42, "run_attempt": 2, "status": "applied", "purpose": "phase-a"}
    if mutation == "extra": value["caller"] = {}
    if mutation == "extra-history": value["predecessor_read"]["bucket"] = "foreign"
    if mutation == "string-run": value["predecessor_read"]["run_id"] = "42"
    if mutation == "bool-run": value["predecessor_read"]["run_id"] = True
    if mutation == "float-run": value["predecessor_read"]["run_id"] = 42.0
    if mutation == "old-six": value["delegations"] = {k: v for k, v in value["delegations"].items() if not k.startswith("mode_")}
    if mutation == "foreign-role": value["delegations"]["mode_seed"] += "-foreign"
    if mutation is None:
        assert session_owner.application_configuration(value, "111122223333") == value
    else:
        with pytest.raises(ValueError): session_owner.application_configuration(value, "111122223333")


@pytest.mark.parametrize("mutation", ["extra", "extra-history", "string-run", "bool-run"])
def test_native_application_raw_extra_fields_never_disappear_by_coercion(native, mutation):
    data = application_values()
    value = data["application_promotion"]
    value["predecessor_read"] = {"protocol": "legacy-infra", "source_sha": "e" * 40,
        "run_id": 42, "run_attempt": 2, "status": "applied", "purpose": "phase-a"}
    if mutation == "extra": value["caller"] = {}
    if mutation == "extra-history": value["predecessor_read"]["bucket"] = "foreign"
    if mutation == "string-run": value["predecessor_read"]["run_id"] = "42"
    if mutation == "bool-run": value["predecessor_read"]["run_id"] = True
    code, _, errors = native.plan(data, "raw-" + mutation)
    assert code != 0 and any(x["severity"] == "error" for x in errors)



def test_native_mode_sessions_intersect_exact_role_session_and_purpose(native):
    from fixtures.cnesdata_iam_evaluation import effective
    from fixtures.cnesdata_delivery_lifecycle import MODE_SESSION_VECTORS
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.session_policy import application_request
    data = application_values()
    resources, _ = render(native, data, "mode-session-exact")
    identity = json.loads(resources["aws_iam_role_policy.application[0]"]["policy"])
    managed = json.loads(resources["aws_iam_policy.application_session[0]"]["policy"])
    settings = data["github_delivery"]
    roles = data["application_promotion"]["delegations"]
    gov = {"account_id": data["account_id"], "state_bucket": "synthetic-state", "evidence_bucket": "synthetic-evidence",
           "evidence_prefix": settings["evidence_prefix"], "evidence_kms_key_arn": settings["evidence_kms_arn"],
           "roles": {"application": "arn:aws:iam::111122223333:role/cnesdata-prod-application"}, "application_delegations": roles}
    for vector in MODE_SESSION_VECTORS:
        binding = vector["binding"]
        purpose = "promotion" if binding["context_kind"] == "promotion" else "mode-readiness-drill"
        session = lc.mode_session(binding, purpose)
        alias, name = session["alias"], session["session_name"]
        request = application_request(gov, binding["product_source_sha"], binding["run_id"], binding["run_attempt"],
            binding["operation"], application_purpose=purpose, delegations=[alias], sessions={alias: name})
        assert len(request["Policy"]) + len(request["PolicyArns"][0]["arn"]) <= 2048
        policy = json.loads(request["Policy"])
        for other in MODE_SESSION_VECTORS:
            assert effective(identity, managed, policy, "sts:AssumeRole", roles[other["alias"]],
                             {"sts:RoleSessionName": other["session_name"]}) is (other["operation"] == vector["operation"])
        assert not effective(identity, managed, policy, "sts:AssumeRole", roles[alias],
                             {"sts:RoleSessionName": name[:-1] + ("0" if name[-1] != "0" else "1")})
    for alias, name in (("mode_audit_launch", "mc-ax-" + "a" * 40), ("normal", "sp-publish-" + "a" * 40),
                        ("mode_dispatch", "mc-ux-" + "a" * 40), ("fence_operator", "promotion-fence-r1")):
        with pytest.raises(ValueError):
            application_request(gov, "b" * 40, 44, 1, "readiness", application_purpose="mode-readiness-drill",
                                delegations=[alias], sessions={alias: name})
    with pytest.raises(ValueError):
        application_request(gov, "b" * 40, 44, 1, "unit-start", application_purpose="promotion", delegations=["mode_dispatch"])


def test_native_closed_ready_composition_is_readonly_and_frozen(native):
    """Native shared policies; synthetic fence policy is not product provenance."""
    from fixtures.cnesdata_iam_evaluation import effective, allowed
    from tools.cnesdata_delivery.session_policy import application_request
    data = application_values()
    resources, _ = render(native, data, "application-closed-ready")
    identity = json.loads(resources["aws_iam_role_policy.application[0]"]["policy"])
    managed = json.loads(resources["aws_iam_policy.application_session[0]"]["policy"])
    settings = data["github_delivery"]
    roles = data["application_promotion"]["delegations"]
    gov = {"account_id": data["account_id"], "state_bucket": "synthetic-state", "evidence_bucket": "synthetic-evidence",
           "evidence_prefix": settings["evidence_prefix"], "evidence_kms_key_arn": settings["evidence_kms_arn"],
           "roles": {"application": "arn:aws:iam::111122223333:role/cnesdata-prod-application"}, "application_delegations": roles}
    session = json.loads(application_request(gov, "b" * 40, 44, 1, "closed-ready", application_purpose="promotion",
                         delegations=["fence_operator"], sessions={"fence_operator": "promotion-fence-r1"})["Policy"])
    def app(action, arn, context=None): return effective(identity, managed, session, action, arn, context)
    assert app("sts:AssumeRole", roles["fence_operator"], {"sts:RoleSessionName": "promotion-fence-r1"})
    assert not app("sts:AssumeRole", roles["fence_operator"], {"sts:RoleSessionName": "promotion-fence-r2"})
    assert not app("sts:AssumeRole", roles["normal"], {"sts:RoleSessionName": "promotion-fence-r1"})
    own = "arn:aws:s3:::synthetic-evidence/cnesdata/prod/evidence/lifecycle/" + "b" * 40 + "/44/1/"
    assert app("s3:PutObject", own + "closed-ready/sdk-original-intent.json")
    for arn in (own + "other/receipt.json", "arn:aws:s3:::synthetic-state/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"):
        assert not app("s3:PutObject", arn)
    for arn in (own.replace("/44/1/", "/43/1/") + "closed-ready/receipt.json", "arn:aws:s3:::synthetic-state/cnesdata/prod/opentofu.tfstate"):
        assert not app("s3:GetObject", arn)
    for action in ("iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies"):
        assert app(action, roles["fence_operator"])
        assert not app(action, roles["fence_operator"] + "-foreign")
    table = "arn:aws:dynamodb:us-east-2:111122223333:table/cnesdata-prod-control"
    execution = "arn:aws:states:us-east-2:111122223333:execution:cnesdata-prod-probe:original"
    assert not app("dynamodb:GetItem", table)
    assert not app("states:DescribeExecution", execution)
    # Synthetic policy fixture only. Product #500 source includes this grant,
    # but source integration is not evidence that its IAM has been applied.
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": table,
         "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["ENV#prod#FENCE", "ENV#prod#SEMAPHORE"]}, "Null": {"dynamodb:LeadingKeys": "false"}}},
        {"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": execution}]}
    frozen = {"Version": "2012-10-17", "Statement": [
        {**item, "Condition": {**item.get("Condition", {}), "DateLessThan": {"aws:CurrentTime": "2030-01-01T00:00:00Z"}}} for item in policy["Statement"]]}
    context = {"aws:CurrentTime": "2029-12-31T23:59:59Z", "dynamodb:LeadingKeys": ["ENV#prod#FENCE"]}
    empty = {"Version": "2012-10-17", "Statement": []}
    assert effective(policy, empty, frozen, "dynamodb:GetItem", table, context)
    assert effective(policy, empty, frozen, "dynamodb:GetItem", table, context | {"dynamodb:LeadingKeys": ["ENV#prod#SEMAPHORE"]})
    for changed in ({"dynamodb:LeadingKeys": ["TENANT"]}, {"dynamodb:LeadingKeys": []}, {"aws:CurrentTime": "2030-01-01T00:00:00Z"}):
        assert not effective(policy, empty, frozen, "dynamodb:GetItem", table, context | changed)
    assert not effective(policy, empty, frozen, "dynamodb:UpdateItem", table, context)
    assert effective(policy, empty, frozen, "states:DescribeExecution", execution, context)
    assert not effective(policy, empty, frozen, "states:DescribeExecution", execution + "-foreign", context)
    legacy = {**policy, "Statement": policy["Statement"][:1]}
    assert not effective(legacy, empty, frozen, "states:DescribeExecution", execution, context)
    assert not effective(policy, empty, frozen, "states:DescribeExecution", execution, context | {"aws:CurrentTime": "2030-01-01T00:00:00Z"})
    # The native OIDC trust's source freeze also rejects new sessions at expiry.
    trust = json.loads(resources["aws_iam_role.application[0]"]["assume_role_policy"])
    claim = trust["Statement"][0]["Condition"]["StringEquals"]
    assert allowed(trust, "sts:AssumeRoleWithWebIdentity", "*", claim | {"aws:CurrentTime": "2029-12-31T23:59:59Z"})
    assert not allowed(trust, "sts:AssumeRoleWithWebIdentity", "*", claim | {"aws:CurrentTime": "2030-01-01T00:00:00Z"})
    from tools.cnesdata_delivery import iam_boundary, lifecycle_contract as lc
    scope = {"role_arn": roles["fence_operator"], "session_name": "promotion-fence-r1", "control_table_arn": table,
        "execution_arn": execution, "foreign_execution_arn": execution + "-foreign",
        "evidence_arn": own + "closed-ready/sdk-original-intent.json",
        "lease_arn": "arn:aws:s3:::synthetic-state/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"}
    documents = {"application_identity": identity, "application_managed": managed, "application_session": session,
        "fence_identity": policy, "fence_session": frozen, "freeze": {"frozen_until": "2030-01-01T00:00:00Z",
        "application_fragment_sha256": "a" * 64, "owner_policy_sha256": "b" * 64}}
    report = iam_boundary.fence_effective_evaluation(documents, scope, evaluator_source_sha="c" * 40, observed_at="2029-12-31T23:59:59Z")
    assert {item["case_id"] for item in report["cases"]} == set(lc.FENCE_EVALUATION_CASES)
    assert all(item["observed"] is item["expected"] for item in report["cases"])
    with pytest.raises(ValueError, match="effective IAM case"):
        iam_boundary.fence_effective_evaluation(documents | {"fence_identity": legacy}, scope,
            evaluator_source_sha="c" * 40, observed_at="2029-12-31T23:59:59Z")


@pytest.mark.parametrize("value,exists", [(None, False), (None, True), ([], True), (["FENCE"], True), (["FOREIGN"], True)])
def test_finite_iam_allvalues_and_null_are_independent(value, exists):
    from fixtures.cnesdata_iam_evaluation import allowed
    condition = {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["FENCE"]}}
    statement = {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "*", "Condition": condition}
    context = {"dynamodb:LeadingKeys": value} if exists else {}
    assert allowed({"Statement": [statement]}, "dynamodb:GetItem", "*", context) is (value != ["FOREIGN"])
    condition["Null"] = {"dynamodb:LeadingKeys": "false"}
    assert allowed({"Statement": [statement]}, "dynamodb:GetItem", "*", context) is (exists and value == ["FENCE"])


@pytest.mark.parametrize("now,expected", [("2029-12-31T21:00:00-03:00", False), ("2029-12-31T20:59:59.999999-03:00", True),
    ("2030-01-01T00:00:00.000001Z", False), ("2030-01-01T01:00:00+01:00", False), (None, False)])
def test_finite_iam_date_less_than_has_no_other_deny_condition(now, expected):
    from fixtures.cnesdata_iam_evaluation import allowed
    policy = {"Statement": [{"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": "*",
               "Condition": {"DateLessThan": {"aws:CurrentTime": "2030-01-01T00:00:00Z"}}}]}
    assert allowed(policy, "states:DescribeExecution", "*", {} if now is None else {"aws:CurrentTime": now}) is expected
