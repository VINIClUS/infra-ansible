"""P16b Falta 6 (ruling 1 item 1, ruling 4 items 2 and 8): mode-input.json, mode-roles.json and mode-evaluation.json in
the prepared fence package, closed in the contract."""
import copy
import json
import pathlib
from types import SimpleNamespace

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

ROLES = json.loads((pathlib.Path(__file__).resolve().parent / "fixtures" / "cnesdata_mode_roles.json").read_text())
ACCOUNT = "111122223333"
PRINCIPAL = f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-application"
ROLE_ARNS = {alias: ROLES["roles"][alias]["role"]["Role"]["Arn"] for alias in lc.MODE_ALIASES}
IDENTITY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                    "Resource": sorted(ROLE_ARNS.values())}]}
GATE = {"product_source_closure_sha256": "1" * 64, "shared_source_sha": "2" * 40,
        "shared_source_closure_sha256": "3" * 64, "fixture_manifest_sha256": "6" * 64}
TIMES = ("2026-11-23T12:00:00Z", "2026-11-23T12:20:00Z", ROLES["fields"]["enabled_until"])
MODE_FILES = frozenset({"mode-input.json", "mode-roles.json", "mode-evaluation.json"})


def governance(owner):
    from tools.cnesdata_delivery.session_owner import _terraform_document_digest
    manifest = {"version": 1, "source_sha": owner["source_sha"],
                "files": {"scripts/promotion/promote_api.py": "5" * 64, lc.MODE_FIXTURE_MANIFEST: GATE["fixture_manifest_sha256"]}}
    fragment = {"policy_sha256": _terraform_document_digest(IDENTITY), "application_role_arn": PRINCIPAL}
    return {"role": "application", "account_id": ACCOUNT, "state_bucket": "synthetic-state",
            "evidence_bucket": "synthetic-evidence", "evidence_prefix": "cnesdata/prod/evidence/",
            "evidence_kms_key_arn": f"arn:aws:kms:us-east-2:{ACCOUNT}:key/00000000-0000-0000-0000-000000000000",
            "roles": {"application": PRINCIPAL}, "application_delegations": dict(ROLE_ARNS),
            "application_coordination_policy": c.canonical(IDENTITY).decode().strip(),
            "application_product_source_closure_sha256": GATE["product_source_closure_sha256"],
            "gate_shas": {"application": GATE["shared_source_sha"]},
            "application_source_closure_sha256": GATE["shared_source_closure_sha256"],
            "application_product_source_manifest": manifest, "application_fragment": fragment}


def application(governance):
    return SimpleNamespace(application_fragment=copy.deepcopy(governance["application_fragment"]),
                           pin={"document": copy.deepcopy(IDENTITY)})


def world(owner):
    prefix = owner["owner_sha256"][:16]
    text = json.dumps(ROLES).replace("61" * 16, prefix.encode().hex()).replace("a" * 16, prefix)
    return json.loads(text)


def _sessions(manifest, digest):
    sessions = {alias: [] for alias in lc.MODE_ALIASES}
    for operation, (_, alias, context, phase) in lc.MODE_SESSION_OPERATIONS.items():
        if context != "promotion":
            continue
        binding = {key: manifest[key] for key in ("schema_version", "context_kind", "product_source_sha",
                   "product_source_closure_sha256", "shared_source_sha", "shared_source_closure_sha256",
                   "release_id", "activation_sha256")}
        binding.update(manifest["owner"], operation=operation, phase=phase, context_manifest_sha256=digest)
        sessions[alias].append(lc.mode_session(binding, "promotion")["session_name"])
    return {alias: sorted(names) for alias, names in sessions.items()}


def mode_input(owner, *, release_id, activation_sha256):
    resources = world(owner)["fields"]["resources"]
    manifest = {"schema_version": 2, "context_kind": "promotion",
                "owner": {key: owner[key] for key in ("repository", "run_id", "run_attempt", "generation", "owner_sha256")},
                "product_source_sha": owner["source_sha"], **GATE, "release_id": release_id,
                "activation_sha256": activation_sha256, "resources_sha256": c.sha(c.canonical(resources)),
                "scenario_plan_sha256": "7" * 64, "predecessor_terminal_sha256": None,
                "admitted_at": TIMES[0], "deadline": TIMES[1]}
    raw = c.canonical(manifest)
    return {"mode_canary": {"schema_version": 2, "context_kind": "promotion", "application_principal_arn": PRINCIPAL,
                            "owner": copy.deepcopy(manifest["owner"]),
                            "context_manifest": {"canonical_utf8": raw.decode(), "sha256": c.sha(raw)},
                            "delegation_sessions": _sessions(manifest, c.sha(raw)), "resources": resources,
                            "enabled_until": TIMES[2]}}


def session_names(mode):
    return {name.split("-")[1]: name for names in mode["mode_canary"]["delegation_sessions"].values() for name in names}


def mode_roles(owner, mode, preparation, role_ids=None):
    roles = world(owner)["roles"]
    admitted = {"application_principal_arn": PRINCIPAL, "enabled_until": TIMES[2],
                "delegation_sessions": mode["mode_canary"]["delegation_sessions"]}
    observations = []
    for alias in sorted(lc.MODE_ALIASES):
        native = copy.deepcopy(roles[alias]["role"]["Role"])
        native |= {"RoleId": (role_ids or {}).get(alias, "AROA" + alias.upper().replace("_", "")),
                   "AssumeRolePolicyDocument": lc._mode_trust(admitted, alias, False)}
        observations += [{"service": "iam", "operation": "get_role", "observed": {"Role": native}},
                         {"service": "iam", "operation": "get_role_policy",
                          "observed": copy.deepcopy(roles[alias]["policy"])}]
    start = preparation["admitted_at"]
    return {"proof_kind": "iam-readback-and-evaluation",
            "readbacks": [{"observed_at": start + offset, "observations": copy.deepcopy(observations)} for offset in (0, 10)]}


def mode_scope(owner, mode):
    return {"resources": mode["mode_canary"]["resources"], "owner_sha256": owner["owner_sha256"], "role_arns": dict(ROLE_ARNS),
            "session_names": session_names(mode), "deadline": int(c.instant(mode["mode_canary"]["enabled_until"]))}


def mode_documents(owner, mode, gov):
    from tools.cnesdata_delivery import session_policy
    scope, names, roles = mode_scope(owner, mode), session_names(mode), world(owner)["roles"]
    documents = {"application_identity": IDENTITY, "application_managed": IDENTITY}
    for operation, (code, alias, context, _) in lc.MODE_SESSION_OPERATIONS.items():
        if context != "promotion":
            continue
        request = session_policy.application_request(gov, owner["source_sha"], owner["run_id"], owner["run_attempt"],
                                                     operation, application_purpose="promotion", delegations=[alias],
                                                     sessions={alias: names[code]})
        documents["application_session." + code] = json.loads(request["Policy"])
        documents["session." + code] = session_policy.mode_session_policy(
            operation, resources=scope["resources"], owner_sha256=owner["owner_sha256"], deadline=scope["deadline"])
        documents["role." + alias] = roles[alias]["policy"]["PolicyDocument"]
    documents["session.uw"] = session_policy.mode_unit_wait_policy(resources=scope["resources"], deadline=scope["deadline"])
    return documents


def mode_payloads(owner, *, release_id, activation_sha256, preparation, workflow_sha):
    """The three mode files of one coherent world, as decoded documents keyed by file name."""
    from tools.cnesdata_delivery.iam_boundary import mode_effective_evaluation
    mode = mode_input(owner, release_id=release_id, activation_sha256=activation_sha256)
    evaluation = mode_effective_evaluation(mode_documents(owner, mode, governance(owner)), mode_scope(owner, mode),
                                           evaluator_source_sha=workflow_sha,
                                           observed_at=c.utc(preparation["observed_at"]))
    return {"mode-input.json": mode, "mode-roles.json": mode_roles(owner, mode, preparation), "mode-evaluation.json": evaluation}


def test_inventario_do_pacote_preparado_tem_os_tres_arquivos_de_modo_fechados():
    assert MODE_FILES <= lc.FENCE_PREPARE_FILES and len(lc.FENCE_PREPARE_FILES) == 11
    assert {name: lc.FENCE_SCHEMAS[name] for name in MODE_FILES} == {
        "mode-input.json": "mode_canary", "mode-roles.json": "proof_kind readbacks",
        "mode-evaluation.json": "schema_version evaluator_source_sha documents cases"}


def _case():
    from test_cnesdata_application_gate import _fence_contract_case
    return _fence_contract_case()


def test_contrato_do_pacote_aceita_os_tres_arquivos_de_modo_coerentes():
    payloads, _, kwargs, encode = _case()
    files, originals = encode()
    assert MODE_FILES <= set(files) and len(files) == 11
    assert lc.validate_fence_prepared_package(files, originals=originals, **kwargs)["outcome"] == "observed"


def _roles_alias(payloads, alias, operation):
    rounds = payloads["mode-roles.json"]["readbacks"]
    index = sorted(lc.MODE_ALIASES).index(alias) * 2 + (operation == "get_role_policy")
    return [item["observations"][index]["observed"] for item in rounds]


@pytest.mark.parametrize("mutation, message", [
    ("input-extra-key", None),
    ("input-context-digest", "^mode context inner bytes digest$"),
    ("roles-one-round", "^fence mode roles readback rounds$"),
    ("roles-rounds-differ", "^fence mode roles readback rounds$"),
    ("roles-before-preparation", "^fence mode roles readback rounds$"),
    ("roles-without-role-id", "^fence mode roles readback identity$"),
    ("roles-foreign-account", "^fence mode roles readback identity$"),
    ("roles-other-policy-name", "^fence mode roles readback identity$"),
    ("roles-missing-alias", "^fence mode roles readback inventory$"),
    ("evaluation-other-evaluator", "^fence mode evaluation original$"),
    ("evaluation-role-digest", "^fence mode evaluation original$"),
    ("evaluation-observed-flipped", "^mode evaluation$"),
    ("missing-mode-file", "^fence exact private inventory$"),
])
def test_contrato_do_pacote_recusa_arquivo_de_modo_fora_da_forma_fechada(mutation, message):
    payloads, _, kwargs, encode = _case()
    mode = payloads["mode-input.json"]["mode_canary"]
    rounds = payloads["mode-roles.json"]["readbacks"]
    evaluation = payloads["mode-evaluation.json"]
    if mutation == "input-extra-key":
        payloads["mode-input.json"]["other"] = 1
    if mutation == "input-context-digest":
        mode["context_manifest"]["sha256"] = "0" * 64
    if mutation == "roles-one-round":
        del rounds[1]
    if mutation == "roles-rounds-differ":
        rounds[1]["observations"][0]["observed"]["Role"]["MaxSessionDuration"] = 7200
    if mutation == "roles-before-preparation":
        rounds[0]["observed_at"] = kwargs["preparation"]["admitted_at"] - 1
    for item in _roles_alias(payloads, "mode_seed", "get_role"):
        if mutation == "roles-without-role-id":
            item["Role"]["RoleId"] = ""
        if mutation == "roles-foreign-account":
            item["Role"]["Arn"] = item["Role"]["Arn"].replace(ACCOUNT, "999999999999")
    for item in _roles_alias(payloads, "mode_seed", "get_role_policy"):
        if mutation == "roles-other-policy-name":
            item["PolicyName"] = item["RoleName"] + "-other"
    if mutation == "roles-missing-alias":
        for item in rounds:
            del item["observations"][-2:]
    if mutation == "evaluation-other-evaluator":
        evaluation["evaluator_source_sha"] = "d" * 40
    if mutation == "evaluation-role-digest":
        evaluation["documents"]["role.mode_seed"] = "0" * 64
    if mutation == "evaluation-observed-flipped":
        evaluation["cases"][0]["observed"] = not evaluation["cases"][0]["observed"]
    files, originals = encode()
    if mutation == "missing-mode-file":
        del files["mode-roles.json"], originals["mode-roles.json"]
    with pytest.raises(ValueError, match=message):
        lc.validate_fence_prepared_package(files, originals=originals, **kwargs)


def _producer(monkeypatch):
    from test_cnesdata_application_gate import _fence_prepare_package_case
    return _fence_prepare_package_case(monkeypatch)


def test_produtor_grava_os_tres_arquivos_de_modo_que_o_contrato_aceita(monkeypatch):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    kwargs, _, fragment = _producer(monkeypatch)
    files = lr.fence_prepare_package(**kwargs)
    manifest = c.loads(files["fence-prepared.json"], canonical=True)
    evaluation = c.loads(files["mode-evaluation.json"], canonical=True)
    assert set(files) == lc.FENCE_PREPARE_FILES
    assert files["mode-input.json"] == kwargs["mode_input_raw"]
    assert files["mode-roles.json"] == c.canonical(kwargs["mode_readbacks"])
    assert evaluation["evaluator_source_sha"] == manifest["producer"]["workflow_sha"]
    assert len(evaluation["cases"]) == len(lc.MODE_EVALUATION_CASES) == 95
    assume = next(case for case in evaluation["cases"] if case["case_id"] == "assume-us")
    assert assume["context"]["aws:CurrentTime"] == c.utc(manifest["preparation"]["observed_at"]) and assume["observed"] is True
    lc.validate_fence_prepared_package(files, owner=kwargs["owner"], fragment=fragment, activation_sha256="1" * 64,
        producer=manifest["producer"], preparation=manifest["preparation"],
        originals={name: raw for name, raw in files.items() if name != "fence-prepared.json"},
        predecessor_raw=kwargs["previous_raw"], predecessor_reference=kwargs["predecessor"])


@pytest.mark.parametrize("mutation, message", [
    ("activation", "^mode context original producer commitments$"),
    ("release", "^mode context original producer commitments$"),
    ("fixture-manifest", "^mode context original producer commitments$"),
    ("principal", "^mode application principal$"),
    ("roles-window", "^fence mode roles readback rounds$"),
])
def test_produtor_recusa_entrada_ou_papeis_de_modo_antes_de_qualquer_github_ou_iam(monkeypatch, mutation, message):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    kwargs, calls, fragment = _producer(monkeypatch)
    if mutation == "activation":
        kwargs["activation_sha256"] = "9" * 64
    if mutation == "release":
        mode = c.loads(kwargs["mode_input_raw"])
        manifest = json.loads(mode["mode_canary"]["context_manifest"]["canonical_utf8"])
        owner = dict(kwargs["owner"])
        kwargs["mode_input_raw"] = c.canonical(mode_input(owner, release_id="other-release", activation_sha256="1" * 64))
        assert manifest["release_id"] != "other-release"
    if mutation == "fixture-manifest":
        kwargs["governance"]["application_product_source_manifest"]["files"][lc.MODE_FIXTURE_MANIFEST] = "6" * 63 + "7"
    if mutation == "principal":
        fragment["application_role_arn"] = fragment["application_role_arn"] + "-other"
    if mutation == "roles-window":
        kwargs["mode_readbacks"]["readbacks"][0]["observed_at"] = 999
    with pytest.raises(ValueError, match=message):
        lr.fence_prepare_package(**kwargs)
    assert calls == []
