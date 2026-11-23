import copy
import json

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

ACCOUNT = "111122223333"
PRINCIPAL = f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-application"
ALIASES = ("mode_seed", "mode_dispatch", "mode_audit_launch", "mode_observe")
GATE = {"product_source_closure_sha256": "1" * 64, "shared_source_sha": "2" * 40,
        "shared_source_closure_sha256": "3" * 64, "release_id": "fixture-release"}
ACTIVATION = "4" * 64
RESOURCES = {"table_arn": f"arn:aws:dynamodb:us-east-2:{ACCOUNT}:table/cnesdata-prod-control-plane",
             "cluster_arn": f"arn:aws:ecs:us-east-2:{ACCOUNT}:cluster/cnesdata-prod"}
TIMES = {"promotion": ("2026-11-23T12:00:00Z", "2026-11-23T12:20:00Z", "2026-11-23T12:30:00Z"),
         "readiness": ("2026-11-23T12:00:00Z", "2026-11-23T16:00:00Z", "2026-11-23T15:00:00Z")}
STATIC = [f"module.runtime_iam.{kind}.static_{name}[0]" for name in ("normal", "recovery")
          for kind in ("aws_iam_role", "aws_iam_role_policy")]


def _owner(context):
    purpose = "promotion" if context == "promotion" else "mode-readiness-drill"
    return {"repository": c.REPOSITORY, "source_sha": "a" * 40, "run_id": 41, "run_attempt": 1,
            "release_sha256": "b" * 64, "generation": 2, "session_sha256": "c" * 64, "owner_sha256": "d" * 64,
            "application_purpose": purpose, "context_kind": context, "caller_binding_sha256": "e" * 64}


def _sessions(manifest, digest):
    sessions = {alias: [] for alias in ALIASES}
    for operation, (_, alias, context, phase) in lc.MODE_SESSION_OPERATIONS.items():
        if context != manifest["context_kind"]:
            continue
        binding = {key: manifest[key] for key in ("schema_version", "context_kind", "product_source_sha",
                   "product_source_closure_sha256", "shared_source_sha", "shared_source_closure_sha256",
                   "release_id", "activation_sha256")}
        binding.update(manifest["owner"], operation=operation, phase=phase, context_manifest_sha256=digest)
        sessions[alias].append(lc.mode_session(binding, "promotion" if context == "promotion"
                                               else "mode-readiness-drill")["session_name"])
    return {alias: sorted(names) for alias, names in sessions.items()}


def _mode_input(context="promotion", *, manifest_change=None, input_change=None, sessions_from=None):
    owner = _owner(context)
    admitted, deadline, enabled = TIMES[context]
    manifest = {"schema_version": 2, "context_kind": context,
                "owner": {key: owner[key] for key in ("repository", "run_id", "run_attempt", "generation", "owner_sha256")},
                "product_source_sha": owner["source_sha"], **GATE, "activation_sha256": ACTIVATION,
                "resources_sha256": c.sha(c.canonical(RESOURCES)), "fixture_manifest_sha256": "6" * 64,
                "scenario_plan_sha256": "7" * 64,
                "predecessor_terminal_sha256": None if context == "promotion" else "8" * 64,
                "admitted_at": admitted, "deadline": deadline}
    manifest.update(manifest_change or {})
    raw = c.canonical(manifest)
    digest = c.sha(raw)
    source = sessions_from(manifest) if sessions_from else manifest
    mode = {"schema_version": 2, "context_kind": context, "application_principal_arn": PRINCIPAL,
            "owner": copy.deepcopy(manifest["owner"]), "context_manifest": {"canonical_utf8": raw.decode(), "sha256": digest},
            "delegation_sessions": _sessions(source, c.sha(c.canonical(source)) if sessions_from else digest),
            "resources": copy.deepcopy(RESOURCES), "enabled_until": enabled}
    mode.update(input_change or {})
    return {"mode_canary": mode}, owner


def _admit(inputs, owner, **change):
    arguments = {"owner": owner, "application_purpose": owner["application_purpose"], "principal_arn": PRINCIPAL,
                 "originals": dict(GATE),
                 "activation_sha256": ACTIVATION if owner["context_kind"] == "promotion" else None} | change
    return lc.validate_mode_canary_input(c.canonical(inputs), **arguments)


@pytest.mark.parametrize("context,count", [("promotion", 8), ("readiness", 6)])
def test_entrada_de_modo_admite_so_as_sessoes_derivadas_do_manifesto_e_dos_originais_do_gate(context, count):
    inputs, owner = _mode_input(context)
    admitted = _admit(inputs, owner)
    assert admitted["delegation_sessions"] == inputs["mode_canary"]["delegation_sessions"]
    assert sum(map(len, admitted["delegation_sessions"].values())) == count
    assert admitted["enabled_until"] == TIMES[context][2]


@pytest.mark.parametrize("field,value", [("product_source_closure_sha256", "9" * 64), ("shared_source_sha", "9" * 40),
                                         ("shared_source_closure_sha256", "9" * 64), ("release_id", "other-release"),
                                         ("activation_sha256", "9" * 64)])
def test_entrada_de_modo_recusa_campo_de_sessao_trocado_mesmo_com_wrapper_e_sessoes_coerentes(field, value):
    inputs, owner = _mode_input(manifest_change={field: value})
    with pytest.raises(ValueError, match="mode context original producer commitments|mode promotion activation original"):
        _admit(inputs, owner)


def test_entrada_de_modo_recusa_dono_de_outra_tentativa_mesmo_coerente():
    inputs, owner = _mode_input()
    shifted = dict(owner, run_attempt=2)
    with pytest.raises(ValueError, match="mode context original owner"):
        _admit(inputs, shifted)


def _other_attempt(manifest):
    return manifest | {"owner": dict(manifest["owner"], run_attempt=2)}


@pytest.mark.parametrize("mutation", ["attempt", "swap", "readiness", "dropped", "extra"])
def test_entrada_de_modo_recusa_nomes_de_sessao_deslocados(mutation):
    inputs, owner = _mode_input(sessions_from=_other_attempt if mutation == "attempt" else None)
    sessions = inputs["mode_canary"]["delegation_sessions"]
    if mutation == "swap":
        sessions["mode_seed"], sessions["mode_observe"] = sessions["mode_observe"], sessions["mode_seed"]
    if mutation == "readiness":
        other, _ = _mode_input("readiness")
        inputs["mode_canary"]["delegation_sessions"] = other["mode_canary"]["delegation_sessions"]
    if mutation == "dropped":
        sessions["mode_dispatch"] = sessions["mode_dispatch"][1:]
    if mutation == "extra":
        sessions["mode_dispatch"] = sorted(sessions["mode_dispatch"] + ["mc-ux-" + "0" * 40])
    with pytest.raises(ValueError, match="mode delegation sessions"):
        _admit(inputs, owner)


@pytest.mark.parametrize("mutation,message", [
    ("principal", "mode application principal"),
    ("owner", "mode input owner"),
    ("context", "mode input context"),
    ("schema", "mode input schema"),
    ("resources", "mode context original producer commitments"),
    ("extra", "closed object fields"),
    ("purpose", "mode context original purpose"),
    ("activation-absent", "mode promotion activation original"),
    ("activation-readiness", "mode readiness activation original"),
    ("gate-extra", "closed object fields"),
])
def test_entrada_de_modo_recusa_campos_fora_do_contrato(mutation, message):
    context = "readiness" if mutation == "activation-readiness" else "promotion"
    inputs, owner = _mode_input(context)
    mode, change = inputs["mode_canary"], {}
    if mutation == "principal":
        change["principal_arn"] = f"arn:aws:iam::{ACCOUNT}:role/other"
    if mutation == "owner":
        mode["owner"]["generation"] = 3
    if mutation == "context":
        mode["context_kind"] = "readiness"
    if mutation == "schema":
        mode["schema_version"] = 1
    if mutation == "resources":
        mode["resources"]["cluster_arn"] += "-other"
    if mutation == "extra":
        mode["note"] = "x"
    if mutation == "purpose":
        change["application_purpose"] = "mode-readiness-drill"
    if mutation == "activation-absent":
        change["activation_sha256"] = None
    if mutation == "activation-readiness":
        change["activation_sha256"] = ACTIVATION
    if mutation == "gate-extra":
        change["originals"] = dict(GATE, activation_sha256=ACTIVATION)
    with pytest.raises(ValueError, match=message):
        _admit(inputs, owner, **change)


@pytest.mark.parametrize("context,field,value,message", [
    ("promotion", "admitted_at", 1000, "mode context admitted_at instant"),
    ("promotion", "admitted_at", "2026-11-23 12:00:00Z", "mode context admitted_at instant"),
    ("promotion", "deadline", "2026-11-23T12:20:00+00:00", "mode context deadline instant"),
    ("promotion", "deadline", "2026-11-23T12:20:01Z", "mode context original bounded deadline"),
    ("promotion", "deadline", "2026-02-30T12:20:00Z", "mode context deadline instant"),
    ("readiness", "deadline", "2026-11-23T16:00:01Z", "mode context original bounded deadline"),
])
def test_manifesto_de_modo_aceita_so_o_instante_utc_do_produto_e_o_teto_do_contexto(context, field, value, message):
    inputs, owner = _mode_input(context, manifest_change={field: value})
    with pytest.raises(ValueError, match=message):
        _admit(inputs, owner)


@pytest.mark.parametrize("context,value,message", [
    ("promotion", 1800, "mode enabled_until instant"),
    ("promotion", "2026-11-23T12:00:00Z", "mode enabled_until after admission"),
    ("readiness", "2026-11-23T16:00:01Z", "mode readiness enabled_until deadline"),
])
def test_entrada_de_modo_recusa_enabled_until_fora_das_regras_do_produto(context, value, message):
    inputs, owner = _mode_input(context, input_change={"enabled_until": value})
    with pytest.raises(ValueError, match=message):
        _admit(inputs, owner)


def test_promotion_pode_ter_enabled_until_depois_do_deadline_como_no_produto():
    inputs, owner = _mode_input(input_change={"enabled_until": "2026-11-23T13:00:00Z"})
    assert _admit(inputs, owner)["enabled_until"] == "2026-11-23T13:00:00Z"


def _trust(admitted, alias):
    closed = alias == "mode_audit_launch" and admitted["manifest"]["context_kind"] == "readiness"
    statement = {"Effect": "Deny" if closed else "Allow", "Principal": {"AWS": PRINCIPAL}, "Action": "sts:AssumeRole"}
    if not closed:
        statement["Condition"] = {"DateLessThan": {"aws:CurrentTime": admitted["enabled_until"]},
                                  "StringEquals": {"sts:RoleSessionName": admitted["delegation_sessions"][alias]}}
    return {"Version": "2012-10-17", "Statement": [statement]}


def _row(address, kind, before, after, actions):
    return {"address": address, "mode": "managed", "type": kind,
            "change": {"actions": actions, "before": before, "after": after, "after_unknown": {}}}


def _mode_rows(admitted, stage="initial"):
    rows, before = [], {}
    for alias in ALIASES:
        name = "cnesdata-prod-" + alias.replace("_", "-")
        closed = alias == "mode_audit_launch" and admitted["manifest"]["context_kind"] == "readiness"
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}] if closed
                  else [{"Sid": "Fixture", "Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": RESOURCES["table_arn"]}]}
        role = {"name": name, "max_session_duration": 3600, "assume_role_policy": json.dumps(_trust(admitted, alias))}
        inline = {"name": name + "-runtime", "role": name, "policy": json.dumps(policy)}
        for kind, after in (("aws_iam_role", role), ("aws_iam_role_policy", inline)):
            address = f"module.runtime_iam.{kind}.{alias}[0]"
            old = None if stage == "initial" else dict(after, **({"policy": "{}"} if kind == "aws_iam_role_policy"
                                                                  else {"assume_role_policy": "{}"}))
            rows.append(_row(address, kind, old, after, ["create"] if stage == "initial" else ["update"]))
            if old is not None:
                before[address] = old
    return rows, before


def _static_rows():
    return [_row(address, address.split(".")[1], None,
                 {"name": address} | ({"assume_role_policy": "{}"} if ".aws_iam_role." in address else {"policy": "{}"}),
                 ["create"]) for address in STATIC]


def _delta(plan, mode, before):
    changes = [row for row in plan["resource_changes"] if row["mode"] == "managed"
               and row["change"]["actions"] not in (["no-op"], ["read"])]
    return {"purpose": "application-prepare", "direction": "advance", "mode": mode, "before": before,
            "original": {}, "created": {}, "expected_changes_sha256": c.sha(c.canonical(changes))}


def _view(inputs):
    mode = inputs["mode_canary"]
    return {"manifest": json.loads(mode["context_manifest"]["canonical_utf8"]),
            "delegation_sessions": mode["delegation_sessions"], "enabled_until": mode["enabled_until"]}


def _promotion_plan(stage="initial"):
    inputs, _ = _mode_input()
    rows, before = _mode_rows(_view(inputs), stage)
    return {"resource_changes": _static_rows() + rows}, before


def test_estagio_do_modo_vem_do_baseline_auditado_e_recusa_inventario_parcial():
    from tools.cnesdata_delivery.iam_source import MODE_POLICIES
    assert lc.MODE_ADDRESSES == set(MODE_POLICIES) | set(MODE_POLICIES.values())
    _, before = _promotion_plan("established")
    assert lc.mode_canary_stage({}) == "initial"
    assert lc.mode_canary_stage(before) == "established"
    assert lc.mode_canary_stage(before | {"module.other.aws_s3_bucket.x": {}}) == "established"
    partial = dict(before)
    partial.pop(sorted(partial)[0])
    with pytest.raises(ValueError, match="mode partial baseline"):
        lc.mode_canary_stage(partial)


@pytest.mark.parametrize("stage", ["initial", "established"])
def test_operational_coaplica_os_oito_enderecos_de_modo(stage):
    plan, before = _promotion_plan(stage)
    changes = lc.validate_delta(plan, _delta(plan, "operational", before))
    assert {row["address"] for row in changes} >= lc.MODE_ADDRESSES


def test_operational_estabelecido_aceita_inventario_de_modo_sem_mudanca():
    plan, before = _promotion_plan("established")
    for row in plan["resource_changes"]:
        if row["address"] in lc.MODE_ADDRESSES:
            row["change"].update(actions=["no-op"], before=before[row["address"]], after=before[row["address"]])
    assert {row["address"] for row in lc.validate_delta(plan, _delta(plan, "operational", before))} == set(STATIC)


@pytest.mark.parametrize("mutation,message", [
    ("absent", "mode exact eight-address inventory"),
    ("one-absent", "mode exact eight-address inventory"),
    ("ninth", "unapproved phase resource"),
    ("import", "mode no import"),
    ("unknown", "mode unknown authority"),
    ("delete", "mode initial create only"),
    ("replace", "mode initial create only"),
    ("established-create", "mode established update only"),
    ("kind", "mode exact resource kind"),
    ("data", "mode managed inventory"),
])
def test_operational_recusa_delta_de_modo_fora_do_oraculo(mutation, message):
    plan, before = _promotion_plan("established" if mutation == "established-create" else "initial")
    rows = plan["resource_changes"]
    mode = next(row for row in rows if row["address"] == "module.runtime_iam.aws_iam_role_policy.mode_seed[0]")
    if mutation == "absent":
        plan["resource_changes"] = [row for row in rows if row["address"] not in lc.MODE_ADDRESSES]
    if mutation == "one-absent":
        rows.remove(mode)
    if mutation == "ninth":
        rows.append(_row("module.runtime_iam.aws_iam_role.mode_extra[0]", "aws_iam_role", None, {"name": "x"}, ["create"]))
    if mutation == "import":
        mode["change"]["importing"] = {"id": "x"}
    if mutation == "unknown":
        mode["change"]["after_unknown"]["policy"] = True
    if mutation == "delete":
        mode["change"].update(actions=["delete"], after=None)
    if mutation == "replace":
        mode["change"]["actions"] = ["delete", "create"]
    if mutation == "established-create":
        mode["change"]["actions"] = ["create"]
    if mutation == "kind":
        mode["type"] = "aws_iam_policy"
    if mutation == "data":
        mode["mode"] = "data"
        mode["change"]["actions"] = ["read"]
    with pytest.raises(ValueError, match=message):
        lc.validate_delta(plan, _delta(plan, "operational", before))


def test_passo_mode_canary_isolado_admite_so_os_oito_enderecos():
    inputs, _ = _mode_input("readiness")
    rows, _ = _mode_rows(_view(inputs))
    plan = {"resource_changes": rows}
    assert {row["address"] for row in lc.validate_delta(plan, _delta(plan, "mode-canary", {}))} == lc.MODE_ADDRESSES
    plan["resource_changes"] += _static_rows()
    with pytest.raises(ValueError, match="mode all other resources noop"):
        lc.validate_delta(plan, _delta(plan, "mode-canary", {}))


@pytest.mark.parametrize("context", ["promotion", "readiness"])
def test_trust_do_plano_bate_com_principal_expiracao_e_sessoes_derivadas(context):
    inputs, owner = _mode_input(context)
    admitted = _admit(inputs, owner)
    rows, _ = _mode_rows(admitted)
    assert lc.validate_mode_canary_trust({"resource_changes": rows}, admitted) == sorted(
        f"module.runtime_iam.aws_iam_role.{alias}[0]" for alias in ALIASES)


@pytest.mark.parametrize("mutation", ["shifted", "principal", "expiry", "allow-closed", "missing", "policy-closed"])
def test_trust_do_plano_recusa_sessoes_deslocadas_e_documento_trocado(mutation):
    context = "readiness" if mutation in {"allow-closed", "policy-closed"} else "promotion"
    inputs, owner = _mode_input(context)
    admitted = _admit(inputs, owner)
    rows, _ = _mode_rows(admitted)
    role = next(row for row in rows if row["address"] == "module.runtime_iam.aws_iam_role.mode_dispatch[0]")
    trust = json.loads(role["change"]["after"]["assume_role_policy"])
    statement = trust["Statement"][0]
    if mutation == "shifted":
        shifted, _ = _mode_input(sessions_from=_other_attempt)
        statement["Condition"]["StringEquals"]["sts:RoleSessionName"] = shifted["mode_canary"]["delegation_sessions"]["mode_dispatch"]
    if mutation == "principal":
        statement["Principal"]["AWS"] = f"arn:aws:iam::{ACCOUNT}:root"
    if mutation == "expiry":
        statement["Condition"]["DateLessThan"]["aws:CurrentTime"] = "2027-01-01T00:00:00Z"
    if mutation == "allow-closed":
        role = next(row for row in rows if row["address"] == "module.runtime_iam.aws_iam_role.mode_audit_launch[0]")
        trust = json.loads(role["change"]["after"]["assume_role_policy"])
        trust["Statement"][0]["Effect"] = "Allow"
    if mutation == "missing":
        rows.remove(role)
    if mutation == "policy-closed":
        policy = next(row for row in rows if row["address"] == "module.runtime_iam.aws_iam_role_policy.mode_audit_launch[0]")
        policy["change"]["after"]["policy"] = json.dumps({"Version": "2012-10-17", "Statement": []})
    else:
        role["change"]["after"]["assume_role_policy"] = json.dumps(trust)
    with pytest.raises(ValueError, match="mode trust document|mode closed policy|mode exact eight-address inventory"):
        lc.validate_mode_canary_trust({"resource_changes": rows}, admitted)


def test_leitura_de_saida_espera_role_e_policy_do_estado_aplicado():
    inputs, _ = _mode_input()
    admitted = _view(inputs)
    rows, _ = _mode_rows(admitted)
    resources = {}
    for row in rows:
        after = dict(row["change"]["after"])
        if row["type"] == "aws_iam_role":
            after["arn"] = f"arn:aws:iam::{ACCOUNT}:role/" + after["name"]
        resources[row["address"]] = after
    expected = lc.mode_readback_expected(resources, ACCOUNT)
    assert set(expected) == set(ALIASES)
    dispatch = expected["mode_dispatch"]
    assert dispatch["role"] == {"Role": {"RoleName": "cnesdata-prod-mode-dispatch",
                                         "Arn": f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-mode-dispatch",
                                         "AssumeRolePolicyDocument": _trust(admitted, "mode_dispatch"),
                                         "MaxSessionDuration": 3600}}
    assert dispatch["policy"]["PolicyName"] == "cnesdata-prod-mode-dispatch-runtime"
    assert dispatch["policy"]["PolicyDocument"] == json.loads(resources[
        "module.runtime_iam.aws_iam_role_policy.mode_dispatch[0]"]["policy"])
    resources.pop("module.runtime_iam.aws_iam_role.mode_seed[0]")
    with pytest.raises(ValueError, match="mode output applied inventory"):
        lc.mode_readback_expected(resources, ACCOUNT)


def test_prepare_operational_resolve_politicas_estaticas_e_de_modo_no_mesmo_plano():
    from fixtures.cnesdata_delivery_lifecycle import mode_source_case
    from tools.cnesdata_delivery.iam_boundary import prepare
    from tools.cnesdata_delivery.iam_source import MODE_POLICIES
    plan, sources, inputs = mode_source_case()
    configured = plan["configuration"]["root_module"]["module_calls"]["runtime_iam"]["module"]["resources"]
    plan["resource_changes"] += json.loads(json.dumps(
        [row for row in plan["resource_changes"] if ".mode_seed[0]" in row["address"]]).replace("mode_seed", "static_normal"))
    configured += json.loads(json.dumps([row for row in configured if row["address"].endswith(".mode_seed")]).replace(
        "mode_seed", "static_normal"))
    path = "infra/opentofu/modules/runtime-iam/"
    sources[path + "static-promotion.tf"] = sources[path + "mode-canary.tf"].split(b"\n}\n")[0].replace(
        b"mode_seed", b"static_normal") + b"\n}\n" + sources[path + "mode-canary.tf"].split(b"\n}\n")[1].replace(
        b"mode_seed", b"static_normal") + b"\n}"
    resolver = prepare(plan, inputs, ACCOUNT, "application-prepare", sources, mode="operational")
    assert set(resolver.traces) == set(MODE_POLICIES) | {"module.runtime_iam.aws_iam_role_policy.static_normal[0]"}
    with pytest.raises(ValueError, match="iam=mode_exact_generated_input"):
        prepare(plan, {**inputs, "mode_canary": {"fixture_only": False}}, ACCOUNT, "application-prepare", sources,
                mode="operational")


def _runtime_case(context="promotion"):
    inputs, owner = _mode_input(context)
    admitted = _admit(inputs, owner)
    rows, _ = _mode_rows(admitted)
    governance = {"application_product_source_closure_sha256": GATE["product_source_closure_sha256"],
                  "gate_shas": {"application": GATE["shared_source_sha"]},
                  "application_source_closure_sha256": GATE["shared_source_closure_sha256"]}
    historical = {"envelope": {"plan": {"release": {"release_id": GATE["release_id"]}}}}
    arguments = {"plan": {"resource_changes": rows}, "step_mode": "operational" if context == "promotion" else "mode-canary",
                 "inputs_raw": c.canonical(inputs), "owner": owner, "governance": governance, "historical": historical,
                 "activation_sha256": ACTIVATION if context == "promotion" else None, "principal_arn": PRINCIPAL}
    return arguments, admitted, rows


@pytest.mark.parametrize("context", ["promotion", "readiness"])
def test_admissao_de_modo_do_runtime_liga_os_originais_do_gate_e_o_contexto_do_passo(context):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    arguments, admitted, _ = _runtime_case(context)
    assert lr.mode_canary_admission(**arguments)["delegation_sessions"] == admitted["delegation_sessions"]
    other = "mode-canary" if context == "promotion" else "operational"
    with pytest.raises(ValueError, match="mode step context"):
        lr.mode_canary_admission(**arguments | {"step_mode": other})


@pytest.mark.parametrize("mutation", ["closure", "shared", "shared-closure", "release", "trust"])
def test_admissao_de_modo_do_runtime_recusa_original_do_gate_trocado_e_trust_deslocado(mutation):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    arguments, _, rows = _runtime_case()
    governance = copy.deepcopy(arguments["governance"])
    if mutation == "closure":
        governance["application_product_source_closure_sha256"] = "9" * 64
    if mutation == "shared":
        governance["gate_shas"]["application"] = "9" * 40
    if mutation == "shared-closure":
        governance["application_source_closure_sha256"] = "9" * 64
    if mutation == "release":
        arguments["historical"] = {"envelope": {"plan": {"release": {"release_id": "other-release"}}}}
    if mutation == "trust":
        shifted, _ = _mode_input(sessions_from=_other_attempt)
        role = next(row for row in rows if row["address"] == "module.runtime_iam.aws_iam_role.mode_seed[0]")
        trust = json.loads(role["change"]["after"]["assume_role_policy"])
        trust["Statement"][0]["Condition"]["StringEquals"]["sts:RoleSessionName"] = (
            shifted["mode_canary"]["delegation_sessions"]["mode_seed"])
        role["change"]["after"]["assume_role_policy"] = json.dumps(trust)
    with pytest.raises(ValueError, match="mode context original producer commitments|mode trust document"):
        lr.mode_canary_admission(**arguments | {"governance": governance})


def _applied(rows):
    resources, state = {}, {"resources": []}
    for row in rows:
        attributes = dict(row["change"]["after"])
        if row["type"] == "aws_iam_role":
            attributes.update(arn=f"arn:aws:iam::{ACCOUNT}:role/" + attributes["name"], path="/",
                              unique_id="AROA" + attributes["name"].upper().replace("-", "")[:16])
        resources[row["address"]] = attributes
        name = row["address"].split(".")[-1].removesuffix("[0]")
        state["resources"].append({"module": "module.runtime_iam", "mode": "managed", "type": row["type"], "name": name,
                                   "instances": [{"index_key": 0, "attributes": attributes}]})
    return resources, state


class _Iam:
    def __init__(self, resources, change=None):
        self.resources, self.change, self.calls = resources, change or {}, []

    def call(self, service, operation, **parameters):
        import datetime
        self.calls.append((service, operation, parameters["RoleName"]))
        role = next(item for address, item in self.resources.items()
                    if ".aws_iam_role." in address and item["name"] == parameters["RoleName"])
        if operation == "get_role":
            body = {"Path": role["path"], "RoleName": role["name"], "RoleId": role["unique_id"], "Arn": role["arn"],
                    "CreateDate": datetime.datetime(2026, 11, 23, 12, 0, tzinfo=datetime.timezone.utc),
                    "AssumeRolePolicyDocument": json.loads(role["assume_role_policy"]),
                    "MaxSessionDuration": role["max_session_duration"], "RoleLastUsed": {}}
            return {"Role": body | self.change, "ResponseMetadata": {"RequestId": "fixture"}}
        policy = next(item for address, item in self.resources.items()
                      if ".aws_iam_role_policy." in address and item["role"] == parameters["RoleName"])
        return {"RoleName": policy["role"], "PolicyName": parameters["PolicyName"],
                "PolicyDocument": json.loads(policy["policy"]), "ResponseMetadata": {"RequestId": "fixture"}}


class _Window:
    window = {"admitted_at": 1000, "preparation_deadline": 1900}

    def check(self, *args):
        pass


def test_saida_de_modo_do_runtime_aceita_a_resposta_real_do_iam_com_os_campos_extras_do_role():
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    _, _, rows = _runtime_case()
    resources, state = _applied(rows)
    aws, now = _Iam(resources), [1100.0]
    proof = lr.mode_canary_output(aws, state=state, account=ACCOUNT, guard=_Window(), clock=lambda: now[0],
                                  sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
    assert proof["proof_kind"] == "iam-readback-and-evaluation" and len(proof["readbacks"]) == 2
    role = proof["readbacks"][0]["observations"][0]["observed"]["Role"]
    assert role["RoleId"].startswith("AROA") and role["CreateDate"] == "2026-11-23T12:00:00Z" and role["RoleLastUsed"] == {}
    assert len(aws.calls) == 4 + 16 and {call[1] for call in aws.calls[:4]} == {"get_role"}


@pytest.mark.parametrize("change", [{"RoleId": "AROAOTHER"}, {"Path": "/other/"}, {"MaxSessionDuration": 7200},
                                    {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}])
def test_saida_de_modo_do_runtime_recusa_role_observado_diferente_do_estado_aplicado(change):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    _, _, rows = _runtime_case()
    resources, state = _applied(rows)
    with pytest.raises(ValueError, match="mode output role identity"):
        lr.mode_canary_output(_Iam(resources, change), state=state, account=ACCOUNT, guard=_Window(),
                              clock=lambda: 1100.0, sleep=lambda seconds: None)
