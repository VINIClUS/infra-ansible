"""Public synthetic CRL handoff and native, network-isolated delivery plans."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys

import pytest

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests/fixtures/cnesdata_delivery_roles_anywhere"
HELPER = REPO / "tools/cnesdata_delivery/crl_handoff.py"
ACCOUNT = "111122223333"
ANCHOR = f"arn:aws:rolesanywhere:us-east-2:{ACCOUNT}:trust-anchor/00000000-0000-4000-8000-000000000001"
CRL_ID = "00000000-0000-4000-8000-000000000002"
NOW = datetime(2027, 1, 1, tzinfo=timezone.utc)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def inputs(label="current"):
    ca = (FIXTURES / "ca.crt").read_bytes()
    crl = base64.b64decode(json.loads((FIXTURES / "crls.json").read_text())[label])
    return {
        "ca_pem": ca,
        "crl_der": crl,
        "crl_readback": {"crl": {
            "crlId": CRL_ID,
            "crlArn": f"arn:aws:rolesanywhere:us-east-2:{ACCOUNT}:crl/{CRL_ID}",
            "trustAnchorArn": ANCHOR, "enabled": True,
            "crlData": base64.b64encode(crl).decode(),
        }},
        "anchor_readback": {"trustAnchor": {
            "trustAnchorId": ANCHOR.rsplit("/", 1)[1], "trustAnchorArn": ANCHOR,
            "enabled": True, "source": {"sourceType": "CERTIFICATE_BUNDLE",
                "sourceData": {"x509CertificateData": ca.decode()}},
        }},
        "expected": {
            "operation": "initialize",
            "account_id": ACCOUNT, "region": "us-east-2",
            "trust_anchor_arn": ANCHOR, "crl_id": CRL_ID,
            "ca_der_sha256": digest(ssl.PEM_cert_to_DER_cert(ca.decode())),
            "crl_sha256": digest(crl), "previous_handoff": None,
            "previous_handoff_sha256": None,
            "authorized_deadline": "1970-01-01T00:00:00Z",
        },
    }


@pytest.fixture(scope="module")
def helper():
    assert HELPER.is_file(), "offline CRL handoff validator is not implemented"
    spec = importlib.util.spec_from_file_location("ra_crl_handoff", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_signed_der_drives_canonical_handoff_without_claiming_activation(helper):
    case = inputs()
    result = helper.validate_handoff(**case, now=NOW)
    manifest = result["crl_handoff"]
    assert manifest["next_update"] == "2030-01-01T00:00:00Z"
    assert manifest["this_update"] == "2026-01-01T00:00:00Z"
    assert manifest["crl_number"] == "10"
    assert manifest["revoked_serials"] == ["1234"]  # DER hexadecimal 04D2, normalized.
    assert manifest["sha256"] == digest(case["crl_der"])
    assert manifest["ca_pem_sha256"] == digest(case["ca_pem"])
    assert manifest["trust_anchor_arn"] == ANCHOR
    assert manifest["enabled"] is True
    assert set(result) == {"crl_handoff", "crl_handoff_sha256"}
    assert result["crl_handoff_sha256"] == digest(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    )


@pytest.mark.parametrize("field,value", [
    ("enabled", False), ("enabled", "true"), ("enabled", None),
    ("crlId", "00000000-0000-4000-8000-000000000099"),
    ("trustAnchorArn", ANCHOR.replace(ACCOUNT, "999988887777")),
    ("crlArn", f"arn:aws:rolesanywhere:us-west-2:{ACCOUNT}:crl/{CRL_ID}"),
    ("crlData", "not-base64"), ("crlData", base64.b64encode(b"wrong bytes").decode()),
])
def test_crl_readback_must_bind_enabled_identity_and_exact_bytes(helper, field, value):
    case = inputs()
    case["crl_readback"]["crl"][field] = value
    with pytest.raises(ValueError):
        helper.validate_handoff(**case, now=NOW)


@pytest.mark.parametrize("mutation", ["disabled", "anchor", "source", "ca", "missing"])
def test_anchor_readback_must_bind_exact_public_ca(helper, mutation):
    case = inputs()
    anchor = case["anchor_readback"]["trustAnchor"]
    if mutation == "disabled":
        anchor["enabled"] = False
    elif mutation == "anchor":
        anchor["trustAnchorArn"] = ANCHOR.replace(ACCOUNT, "999988887777")
    elif mutation == "source":
        anchor["source"]["sourceType"] = "AWS_ACM_PCA"
    elif mutation == "ca":
        anchor["source"]["sourceData"]["x509CertificateData"] = (FIXTURES / "other-ca.crt").read_text()
    else:
        del anchor["source"]
    with pytest.raises(ValueError):
        helper.validate_handoff(**case, now=NOW)


@pytest.mark.parametrize("mutation", ["account", "region", "ca-hash", "crl-hash", "private", "trailing", "signature"])
def test_operator_expectations_and_signed_bytes_cannot_be_substituted(helper, mutation):
    case = inputs("bad-signature" if mutation == "signature" else "current")
    if mutation in {"account", "region"}:
        case["expected"]["account_id" if mutation == "account" else "region"] = "999988887777" if mutation == "account" else "us-west-2"
    elif mutation in {"ca-hash", "crl-hash"}:
        case["expected"]["ca_der_sha256" if mutation == "ca-hash" else "crl_sha256"] = "0" * 64
    elif mutation == "private":
        case["ca_pem"] += b"-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n"
    elif mutation == "trailing":
        case["crl_der"] += b"trailing bytes"
        case["expected"]["crl_sha256"] = digest(case["crl_der"])
        case["crl_readback"]["crl"]["crlData"] = base64.b64encode(case["crl_der"]).decode()
    with pytest.raises(ValueError):
        helper.validate_handoff(**case, now=NOW)


@pytest.mark.parametrize("now", [
    datetime(2025, 12, 31, tzinfo=timezone.utc),
    datetime(2030, 1, 1, tzinfo=timezone.utc),
    datetime(2030, 1, 2, tzinfo=timezone.utc),
])
def test_future_this_update_and_expiry_including_equality_are_rejected(helper, now):
    with pytest.raises(ValueError):
        helper.validate_handoff(**inputs(), now=now)


def test_renewal_requires_monotonic_number_dates_and_authorized_deadline(helper):
    previous = helper.validate_handoff(**inputs("previous"), now=NOW)["crl_handoff"]
    case = inputs()
    case["expected"].update(operation="renew", previous_handoff=previous, authorized_deadline=previous["next_update"])
    case["expected"]["previous_handoff_sha256"] = digest(json.dumps(previous, sort_keys=True, separators=(",", ":")).encode())
    assert helper.validate_handoff(**case, now=NOW)["crl_handoff"]["crl_number"] == "10"
    for changed in ("replay", "deadline", "previous-anchor", "previous-ca", "shorter"):
        bad = copy.deepcopy(case)
        if changed == "replay":
            bad["expected"]["previous_handoff"] = helper.validate_handoff(**inputs(), now=NOW)["crl_handoff"]
        elif changed == "deadline":
            bad["expected"]["authorized_deadline"] = "2031-01-01T00:00:00Z"
        elif changed == "previous-anchor":
            bad["expected"]["previous_handoff"]["trust_anchor_arn"] = ANCHOR.replace(ACCOUNT, "999988887777")
        elif changed == "previous-ca":
            bad["expected"]["previous_handoff"]["ca_der_sha256"] = "0" * 64
        else:
            bad = inputs("shorter")
            bad["expected"].update(operation="renew", previous_handoff=previous, authorized_deadline=previous["next_update"])
        with pytest.raises(ValueError):
            helper.validate_handoff(**bad, now=NOW)


def test_unexplained_prior_authorization_is_not_bootstrap(helper):
    case = inputs()
    case["expected"]["authorized_deadline"] = "2029-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        helper.validate_handoff(**case, now=NOW)


def test_missing_openssl_is_failure_not_skip(helper, monkeypatch):
    monkeypatch.setattr(helper.shutil, "which", lambda _: None)
    with pytest.raises(ValueError, match="openssl"):
        helper.validate_handoff(**inputs(), now=NOW)


def test_cli_emits_only_public_manifest_and_fails_closed_on_invalid_json(tmp_path):
    case = inputs()
    names = {"ca_pem": "ca", "crl_der": "crl", "crl_readback": "get-crl",
             "anchor_readback": "get-trust-anchor", "expected": "expected"}
    command = [sys.executable, str(HELPER)]
    for key, name in names.items():
        path = tmp_path / name
        value = case[key]
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        command.extend(["--" + name, str(path)])
    env = {"PATH": os.defpath, "HOME": str(tmp_path), "LANG": "C.UTF-8"}
    result = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert set(json.loads(result.stdout)) == {"crl_handoff", "crl_handoff_sha256"}
    (tmp_path / "get-crl").write_text('{"crl":{},"crl":{}}')
    result = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.fixture(scope="module")
def native():
    from fixtures.cnesdata_delivery_roles_anywhere.native import Native
    harness = Native()
    yield harness
    harness.temp.cleanup()


def root_inputs(helper, active):
    result = {
        "account_id": ACCOUNT, "region": "us-east-2",
        "ca_certificate_pem": (FIXTURES / "ca.crt").read_text(),
        "identity": {"trust_anchor_name": "synthetic-cnesdata-ca", "role_name": "synthetic-cnesdata-api",
                     "profile_name": "synthetic-cnesdata-api", "common_name": "synthetic-cnesdata-api",
                     "san_uri": "spiffe://synthetic.invalid/cnesdata/api", "duration_seconds": 900},
        "activation_enabled": active,
    }
    if active:
        result.update(helper.validate_handoff(**inputs(), now=NOW))
    return result


def planned(native, values, name):
    code, plans, errors = native.plan(values, name)
    assert code == 0, errors
    assert len(plans) == 1
    return plans[0]["planned_values"]


def resources(plan):
    return {r["address"]: r["values"] for r in plan["root_module"]["resources"] if r["mode"] == "managed"}


def trust_contract(policy, deadline):
    assert policy == {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "rolesanywhere.amazonaws.com"},
        "Action": ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"],
        "Condition": {
            "ArnEquals": {"aws:SourceArn": ANCHOR},
            "StringEquals": {"aws:SourceAccount": ACCOUNT,
                             "aws:PrincipalTag/x509Subject/CN": "synthetic-cnesdata-api",
                             "aws:PrincipalTag/x509SAN/URI": "spiffe://synthetic.invalid/cnesdata/api"},
            "DateLessThan": {"aws:CurrentTime": deadline},
        },
    }]}


def trust_allows(policy, context):
    """Independent oracle for the deliberately narrow rendered IAM contract."""
    for statement in policy["Statement"]:
        if statement["Effect"] != "Allow":
            continue
        conditions = statement["Condition"]
        assert set(conditions) <= {"StringEquals", "ArnEquals", "DateLessThan"}
        matched = True
        for operator, entries in conditions.items():
            for key, expected in entries.items():
                actual = context.get(key)
                matched &= actual is not None and (actual < expected if operator == "DateLessThan" else actual == expected)
        if matched:
            return True
    return False


def test_bootstrap_profile_is_disabled_trust_expired_and_fragment_null(native, helper):
    plan = planned(native, root_inputs(helper, False), "bootstrap")
    values = resources(plan)
    assert set(values) == {"aws_iam_role.api", "aws_rolesanywhere_trust_anchor.ca", "aws_rolesanywhere_profile.api"}
    assert values["aws_rolesanywhere_profile.api"]["enabled"] is False
    trust_contract(json.loads(values["aws_iam_role.api"]["assume_role_policy"]), "1970-01-01T00:00:00Z")
    assert plan["outputs"]["roles_anywhere"]["value"] is None


def test_active_native_plan_has_exact_trust_singleton_profile_and_v2_fragment(native, helper):
    plan = planned(native, root_inputs(helper, True), "active")
    values = resources(plan)
    assert set(values) == {"aws_iam_role.api", "aws_rolesanywhere_trust_anchor.ca", "aws_rolesanywhere_profile.api"}
    role = values["aws_iam_role.api"]
    trust_contract(json.loads(role["assume_role_policy"]), "2030-01-01T00:00:00Z")
    assert role["max_session_duration"] == 3600
    profile = values["aws_rolesanywhere_profile.api"]
    assert profile["enabled"] is True
    assert profile["role_arns"] == [f"arn:aws:iam::{ACCOUNT}:role/synthetic-cnesdata-api"]
    assert profile["duration_seconds"] == 900
    assert profile["accept_role_session_name"] is False
    assert not profile.get("managed_policy_arns") and not profile.get("session_policy")
    anchor = values["aws_rolesanywhere_trust_anchor.ca"]
    assert anchor["source"][0]["source_type"] == "CERTIFICATE_BUNDLE"
    assert anchor["source"][0]["source_data"][0]["x509_certificate_data"] == (FIXTURES / "ca.crt").read_text()
    fragment = plan["outputs"]["roles_anywhere"]["value"]
    assert fragment == {
        "api_role_arn": f"arn:aws:iam::{ACCOUNT}:role/synthetic-cnesdata-api",
        "profile_arn": f"arn:aws:rolesanywhere:us-east-2:{ACCOUNT}:profile/00000000-0000-4000-8000-000000000003",
        "trust_anchor_arn": ANCHOR,
        "crl": {"crl_id": CRL_ID, "enabled": True, "next_update": "2030-01-01T00:00:00Z",
                "sha256": digest(inputs()["crl_der"])},
    }


@pytest.mark.parametrize("key,value", [
    ("aws:CurrentTime", "2030-01-01T00:00:00Z"),
    ("aws:CurrentTime", "2030-01-01T00:00:01Z"),
    ("aws:CurrentTime", None),
    ("aws:SourceAccount", "999988887777"), ("aws:SourceArn", ANCHOR + "foreign"),
    ("aws:PrincipalTag/x509Subject/CN", "other-application"),
    ("aws:PrincipalTag/x509SAN/URI", "spiffe://synthetic.invalid/other/api"),
    ("aws:PrincipalTag/x509Subject/CN", None), ("aws:PrincipalTag/x509SAN/URI", None),
])
def test_rendered_trust_rejects_foreign_identity_and_expired_or_missing_clock(native, helper, key, value):
    policy = json.loads(resources(planned(native, root_inputs(helper, True), "active"))["aws_iam_role.api"]["assume_role_policy"])
    context = {"aws:CurrentTime": "2029-12-31T23:59:59Z", "aws:SourceAccount": ACCOUNT,
               "aws:SourceArn": ANCHOR, "aws:PrincipalTag/x509Subject/CN": "synthetic-cnesdata-api",
               "aws:PrincipalTag/x509SAN/URI": "spiffe://synthetic.invalid/cnesdata/api"}
    assert trust_allows(policy, context)
    context[key] = value
    assert not trust_allows(policy, context)


@pytest.mark.parametrize("mutation", ["deadline-removed", "ifexists", "extra-allow", "extended", "source-removed"])
def test_trust_oracle_detects_security_mutations(native, helper, mutation):
    policy = json.loads(resources(planned(native, root_inputs(helper, True), "active"))["aws_iam_role.api"]["assume_role_policy"])
    condition = policy["Statement"][0]["Condition"]
    if mutation == "deadline-removed":
        del condition["DateLessThan"]
    elif mutation == "ifexists":
        condition["DateLessThanIfExists"] = condition.pop("DateLessThan")
    elif mutation == "extra-allow":
        policy["Statement"].append({"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"})
    elif mutation == "extended":
        condition["DateLessThan"]["aws:CurrentTime"] = "2031-01-01T00:00:00Z"
    else:
        del condition["ArnEquals"]
    with pytest.raises(AssertionError):
        trust_contract(policy, "2030-01-01T00:00:00Z")


@pytest.mark.parametrize("mutation", ["missing", "disabled", "expired", "future", "anchor", "ca", "hash", "duration", "wildcard"])
def test_native_activation_rejects_unbound_handoff_and_unbounded_identity(native, helper, mutation):
    values = root_inputs(helper, True)
    if mutation == "missing":
        values.pop("crl_handoff")
        values.pop("crl_handoff_sha256")
    elif mutation == "duration":
        values["identity"]["duration_seconds"] = 43200
    elif mutation == "wildcard":
        values["identity"]["common_name"] = "*"
    else:
        if mutation == "disabled":
            values["crl_handoff"]["enabled"] = False
        elif mutation == "expired":
            values["crl_handoff"]["next_update"] = "2020-01-01T00:00:00Z"
        elif mutation == "future":
            values["crl_handoff"]["this_update"] = "2099-01-01T00:00:00Z"
        elif mutation == "anchor":
            values["crl_handoff"]["trust_anchor_arn"] = ANCHOR.replace(ACCOUNT, "999988887777")
        elif mutation == "ca":
            values["crl_handoff"]["ca_pem_sha256"] = "0" * 64
        if mutation != "hash":
            values["crl_handoff_sha256"] = digest(json.dumps(values["crl_handoff"], sort_keys=True, separators=(",", ":")).encode())
        else:
            values["crl_handoff_sha256"] = "0" * 64
    code, _, diagnostics = native.plan(values, "invalid-" + mutation)
    assert code != 0
    assert any(d["summary"] in {"Invalid value for variable", "Resource precondition failed"} for d in diagnostics), diagnostics


def test_profile_rejects_role_substitution_for_another_application(native, helper):
    profile = resources(planned(native, root_inputs(helper, True), "active"))["aws_rolesanywhere_profile.api"]
    other_role = f"arn:aws:iam::{ACCOUNT}:role/synthetic-other-api"
    api_role = f"arn:aws:iam::{ACCOUNT}:role/synthetic-cnesdata-api"
    assert api_role in profile["role_arns"]
    assert other_role not in profile["role_arns"]


@pytest.mark.parametrize("caller", [f"arn:aws:iam::{ACCOUNT}:root", f"arn:aws:iam::{ACCOUNT}:user/synthetic-user"])
def test_native_rejects_root_and_non_session_callers(native, helper, caller):
    code, _, diagnostics = native.plan(root_inputs(helper, False), "caller-" + caller.rsplit(":", 1)[1].replace("/", "-"), caller_arn=caller)
    assert code != 0
    assert any(d["summary"] == "Resource precondition failed" for d in diagnostics), diagnostics


def test_renewal_cannot_drop_revocations_even_with_higher_crl_number(helper):
    previous = helper.validate_handoff(**inputs(), now=NOW)["crl_handoff"]
    case = inputs("unrevoked")
    case["expected"].update(operation="renew", previous_handoff=previous, authorized_deadline=previous["next_update"])
    case["expected"]["previous_handoff_sha256"] = digest(json.dumps(previous, sort_keys=True, separators=(",", ":")).encode())
    with pytest.raises(ValueError, match="revoked"):
        helper.validate_handoff(**case, now=NOW)


def test_renewal_requires_history_even_after_closed_trust(helper):
    case = inputs()
    case["expected"]["operation"] = "renew"
    with pytest.raises(ValueError, match="previous"):
        helper.validate_handoff(**case, now=NOW)
    previous = helper.validate_handoff(**inputs("previous"), now=NOW)["crl_handoff"]
    del previous["revoked_serials"]
    case["expected"]["previous_handoff"] = previous
    with pytest.raises(ValueError):
        helper.validate_handoff(**case, now=NOW)


def test_renewal_cannot_replace_accepted_history_with_modified_manifest(helper):
    accepted = helper.validate_handoff(**inputs(), now=NOW)
    case = inputs("unrevoked")
    case["expected"].update(operation="renew", previous_handoff=accepted["crl_handoff"],
                            previous_handoff_sha256=accepted["crl_handoff_sha256"],
                            authorized_deadline="2030-01-01T00:00:00Z")
    case["expected"]["previous_handoff"]["revoked_serials"] = []
    with pytest.raises(ValueError, match="previous.*hash"):
        helper.validate_handoff(**case, now=NOW)


@pytest.mark.parametrize("label", ["no-number", "delta", "wrong-issuer"])
def test_only_full_numbered_direct_crls_are_accepted(helper, label):
    with pytest.raises(ValueError):
        helper.validate_handoff(**inputs(label), now=NOW)
