"""P16b Falta 6 (ruling 1 item 1, ruling 3 item 3): the stage re-validates the prepared mode files into the ModeAuthority,
with validate_mode_canary_input against the same originals and the mode-evaluation recomputed byte for byte."""
import copy

import pytest

from test_cnesdata_mode_package import mode_input
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _world(monkeypatch):
    from test_cnesdata_application_gate import _fence_prepare_package_case
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    kwargs, calls, _ = _fence_prepare_package_case(monkeypatch)
    files = lr.fence_prepare_package(**kwargs)
    calls.clear()
    arguments = {"governance": copy.deepcopy(kwargs["governance"]), "application": copy.deepcopy(kwargs["authority"]),
                 "owner": dict(kwargs["owner"]), "activation_sha256": kwargs["activation_sha256"],
                 "window": copy.deepcopy(kwargs["guard"].window)}
    return lr.PreparedFence(files), arguments, kwargs, calls


def test_autoridade_do_estagio_e_o_pacote_preparado_revalidado(monkeypatch):
    from tools.cnesdata_delivery.iam_boundary import _mode_codes, _mode_document_names, mode_stage_evaluation
    prepared, arguments, _, calls = _world(monkeypatch)
    authority = _mb().mode_prepared_authority(prepared, **arguments)
    mode = c.loads(prepared["mode-input.json"], canonical=True)["mode_canary"]
    assert type(authority) is _mb().ModeAuthority and calls == []
    assert c.canonical(authority.evaluation) == prepared["mode-evaluation.json"]
    assert authority.scope["resources"] == mode["resources"] and authority.scope["owner_sha256"] == arguments["owner"]["owner_sha256"]
    window = arguments["window"]
    assert authority.scope["deadline"] == min(int(c.instant(mode["enabled_until"])), window["preparation_deadline"]
                                              + lc.governed_windows(window["windows"])["fixed_deadline_seconds"])
    assert sorted(authority.scope["session_names"].values()) == sorted(
        name for names in mode["delegation_sessions"].values() for name in names)
    assert set(authority.roles) == set(lc.MODE_ALIASES) and all(entry["role"]["Role"]["RoleId"] for entry in authority.roles.values())
    assert set(authority.documents) == lc.MODE_EVALUATION_DOCUMENTS
    for code in _mode_codes():
        names = _mode_document_names((code,))
        mode_stage_evaluation(authority.evaluation, {name: authority.documents[name] for name in names}, authority.scope,
                              code=code)


def _rewrite(prepared, name, change):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    value = c.loads(prepared[name], canonical=True)
    change(value)
    return lr.PreparedFence(dict(prepared) | {name: c.canonical(value)})


def _policy(value):
    for item in value["readbacks"]:
        item["observations"][1]["observed"]["PolicyDocument"]["Statement"][0]["Sid"] = "Other"


def _role_id(value):
    for item in value["readbacks"]:
        item["observations"][0]["observed"]["Role"]["RoleId"] = ""


def _case_resource(value):
    value["cases"][0]["resource"] += "-other"


def _evaluator(value):
    value["evaluator_source_sha"] = "d" * 40


@pytest.mark.parametrize("mutation, message", [
    ("release", "^mode context original producer commitments$"),
    ("closure", "^mode context original producer commitments$"),
    ("fixture-manifest", "^mode context original producer commitments$"),
    ("principal", "^mode application principal$"),
    ("activation", "^mode prepared authority binding$"),
    ("owner", "^mode prepared authority binding$"),
    ("preparation-deadline", "^mode prepared authority binding$"),
    ("role-policy", "^mode prepared evaluation recompute$"),
    ("role-id", "^fence mode roles readback identity$"),
    ("case-resource", "^mode prepared evaluation recompute$"),
    ("evaluator", "^mode prepared evaluation recompute$"),
    ("pin", "^mode prepared evaluation recompute$"),
    ("missing-file", "^mode prepared authority package$"),
    ("plain-dict", "^mode prepared authority package$"),
])
def test_autoridade_do_estagio_recusa_um_byte_trocado_em_cada_arquivo_ou_original(monkeypatch, mutation, message):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    prepared, arguments, kwargs, calls = _world(monkeypatch)
    if mutation == "release":
        prepared = lr.PreparedFence(dict(prepared) | {"mode-input.json": c.canonical(
            mode_input(kwargs["owner"], release_id="other-release", activation_sha256=kwargs["activation_sha256"]))})
    if mutation == "closure":
        arguments["governance"]["application_product_source_closure_sha256"] = "9" * 64
    if mutation == "fixture-manifest":
        arguments["governance"]["application_product_source_manifest"]["files"][lc.MODE_FIXTURE_MANIFEST] = "6" * 63 + "7"
    if mutation == "principal":
        arguments["application"].application_fragment["application_role_arn"] += "-other"
    if mutation == "activation":
        arguments["activation_sha256"] = "9" * 64
    if mutation == "owner":
        arguments["owner"]["owner_sha256"] = "9" * 64
    if mutation == "preparation-deadline":
        arguments["window"]["preparation_deadline"] += 1
    if mutation == "role-policy":
        prepared = _rewrite(prepared, "mode-roles.json", _policy)
    if mutation == "role-id":
        prepared = _rewrite(prepared, "mode-roles.json", _role_id)
    if mutation == "case-resource":
        prepared = _rewrite(prepared, "mode-evaluation.json", _case_resource)
    if mutation == "evaluator":
        prepared = _rewrite(prepared, "mode-evaluation.json", _evaluator)
    if mutation == "pin":
        arguments["application"].ops_pin["document"]["Statement"].append(
            {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"})
    if mutation == "missing-file":
        prepared = lr.PreparedFence({name: raw for name, raw in prepared.items() if name != "mode-roles.json"})
    if mutation == "plain-dict":
        prepared = dict(prepared)
    with pytest.raises(ValueError, match=message):
        _mb().mode_prepared_authority(prepared, **arguments)
    assert calls == []
