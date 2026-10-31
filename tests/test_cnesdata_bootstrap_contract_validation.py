"""Contrato fechado, catálogo completo e reserva bruta no kernel puro B1b/C1."""

from copy import deepcopy
import json
import logging
from pathlib import Path
from typing import Any, cast

import pytest

from fixtures.cnesdata_bootstrap_foundation_case import canonical, digest, field, load_case, plain
from test_cnesdata_bootstrap_foundation_plan import _bloquear_fronteiras, _provar_imutabilidade
from test_cnesdata_bootstrap_validation_privacy import _executar_duas_vezes
from tools.aws_bootstrap.contract import BootstrapPlan, BootstrapSpec, Readback


CANARY = "canario_privado_sintetico_c1"
ADDRESS = "aws_kms_key.foundation"
ROOTS = ("foundation", "budget-backend", "identity-handoff", "budget-identities")


def _valor(documento: Any, caminho: tuple[Any, ...]) -> Any:
    for chave in caminho:
        documento = documento[chave]
    return documento


def _records() -> list[tuple[tuple[Any, ...], str]]:
    caso = cast(dict[str, Any], load_case("enabled"))
    entrada = caso["input"]
    paths: list[tuple[tuple[Any, ...], str]] = [
        (("spec",), "spec"), (("spec", "run"), "run"), (("spec", "step"), "step"),
        (("facts",), "facts"), (("facts", "authorizations"), "authorizations"),
        (("facts", "authorizations", "initial"), "initial"),
        (("facts", "authorizations", "stage"), "stage"),
        (("facts", "financial"), "financial"), (("plan",), "plan"),
        (("plan", "estimated_cost"), "estimated_cost")]
    for origem in (("spec", "run"), ("facts", "authorizations", "initial")):
        for root in ROOTS:
            path = (*origem, "roots", root)
            paths.append((path, "root"))
            paths.extend(((*path, name), name) for name in ("backend", "logging"))
            paths.extend(((*path, "resources", address), "resource")
                         for address in _valor(entrada, path)["resources"])
    paths.extend((("spec", "run", "identities", name), "identity")
                 for name in entrada["spec"]["run"]["identities"])
    paths.extend((("facts", "financial", "lines", name), "financial_line")
                 for name in entrada["facts"]["financial"]["lines"])
    paths.extend((("facts", "resources", "foundation", address), "observation")
                 for address in entrada["facts"]["resources"]["foundation"])
    for chave in entrada["facts"]["evidence"]:
        paths.extend(((("facts", "evidence", chave), "evidence_observation"),
                      (("facts", "evidence", chave, "observation"), "snapshot")))
    for indice in range(22):
        paths.extend(((("plan", "operations", indice), "operation_resource"),
                      (("plan", "operations", indice, "target"), "target")))
    return paths


RECORDS = _records()
REQUIRED = json.loads((Path(__file__).parent / "fixtures" /
                       "cnesdata_bootstrap_contract_required_fields.json").read_text())
CAMPOS = [(path, key) for path, schema in RECORDS for key in REQUIRED[schema]]
PARAMETROS = [(path, None) for path, _ in RECORDS] + CAMPOS


@pytest.fixture(autouse=True)
def _canais_sem_canario(capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.DEBUG)
    yield
    captura = capsys.readouterr()
    registros = [*caplog.get_records("setup"), *caplog.get_records("call"),
                 *caplog.get_records("teardown")]
    mensagens = [r.getMessage() + (logging.Formatter().formatException(r.exc_info)
                 if r.exc_info else "") + (r.exc_text or "") + (r.stack_info or "")
                 for r in registros]
    assert CANARY not in captura.out + captura.err + "".join(mensagens)


def _rejeitar(mapping: dict[str, Any], classe: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    anterior = deepcopy(mapping)
    eventos: list[str] = []
    try:
        with pytest.raises(ValueError) as erro:
            with monkeypatch.context() as patch:
                _bloquear_fronteiras(patch, eventos)
                classe.from_mapping(mapping)
        assert str(erro.value) == "invalid_bootstrap_input"
        assert CANARY not in repr(erro.value)
    finally:
        assert eventos == []
        assert mapping == anterior


@pytest.mark.parametrize("path,campo", PARAMETROS, ids=[
    "/".join(map(str, path)) + "/" + (campo or "desconhecido") for path, campo in PARAMETROS])
def test_record_nested_rejeita_campo_desconhecido_ou_obrigatorio_ausente(
    path: tuple[Any, ...], campo: str | None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    caso = cast(dict[str, Any], load_case("enabled"))
    entrada = {**caso["input"], "plan": caso["expected"]}
    record = _valor(entrada, path)
    if campo is None:
        record["mutation_probe"] = True
    else:
        del record[campo]
    classes = {"spec": BootstrapSpec, "facts": Readback, "plan": BootstrapPlan}
    _rejeitar(entrada[path[0]], classes[path[0]], monkeypatch)


TIPOS: tuple[tuple[tuple[Any, ...], Any], ...] = (
    (("spec", "contract_version"), True), (("plan", "contract_version"), True),
    (("spec", "step", "enabled"), "true"), (("spec", "run", "roots"), []),
    (("spec", "step", "expected_principal_arn"), 123),
    (("spec", "step", "stage"), CANARY), (("spec", "step", "execution_mode"), CANARY),
    (("spec", "step", "execution_surface"), CANARY),
    (("spec", "run", "roots", "foundation", "resources", ADDRESS, "identity_kind"), CANARY),
    (("facts", "mfa_verified"), 1), (("facts", "session_kind"), CANARY),
    (("facts", "resources", "foundation", ADDRESS, "observation_status"), CANARY),
    (("facts", "financial", "lines", "cmk", "quantity"), True),
    (("facts", "financial", "lines", "cmk", "max"), True),
    (("facts", "financial", "lines", "cmk", "min"), float("nan")),
    (("facts", "financial", "lines", "cmk", "base"), float("inf")),
    (("spec", "run", "tags", "Project"), []),
    (("spec", "run", "tags"), {1: "valor"}),
    (("spec", "run", "policy_template_digests"), {CANARY: 1}),
    (("facts", "verified_authorization_sha256"), [123]),
    (("facts", "evidence"), {CANARY: {}}),
    (("facts", "authorizations", "initial", "allowed_state_actions", "foundation"), [CANARY]),
    (("facts", "authorizations", "initial", "allowed_resource_actions", "foundation", ADDRESS),
     [CANARY]),
    (("plan", "status"), CANARY), (("plan", "operations", 0, "kind"), CANARY),
    (("plan", "operations", 0, "action"), CANARY),
    (("plan", "operations", 0, "target", "identity_kind"), CANARY),
    (("plan", "operations", 0, "target", "exact_id"), 123),
    (("plan", "estimated_cost", "currency"), {}), (("plan", "estimated_cost", "basis"), {}),
) + tuple((("plan", "estimated_cost", campo), valor) for campo in (
    "project_forecast_gross", "aggregate_forecast_gross", "project_limit", "aggregate_limit",
    "rotation_max") for valor in (True, "1.0"))


@pytest.mark.parametrize("path,valor", TIPOS, ids=["/".join(map(str, p)) for p, _ in TIPOS])
def test_record_nested_rejeita_tipo_ou_enum_invalido(
    path: tuple[Any, ...], valor: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    caso = cast(dict[str, Any], load_case("enabled"))
    entrada = {**caso["input"], "plan": caso["expected"]}
    _valor(entrada, path[:-1])[path[-1]] = deepcopy(valor)
    classes = {"spec": BootstrapSpec, "facts": Readback, "plan": BootstrapPlan}
    _rejeitar(entrada[path[0]], classes[path[0]], monkeypatch)


def _reatar(entrada: dict[str, Any]) -> None:
    spec, facts = entrada["spec"], entrada["facts"]
    spec["run"]["cost_manifest_sha256"] = digest(facts["financial"])
    run_hash = digest(spec["run"])
    initial, stage = facts["authorizations"]["initial"], facts["authorizations"]["stage"]
    initial["roots"] = deepcopy(spec["run"]["roots"])
    initial["run_sha256"] = stage["run_sha256"] = run_hash
    evidence = {}
    for observation in facts["resources"]["foundation"].values():
        source = facts["evidence"][observation["source_evidence_sha256"]]
        source["run_sha256"] = run_hash
        observation["source_evidence_sha256"] = digest(source)
        evidence[digest(source)] = source
    facts["evidence"] = evidence
    stage["authority_sha256"] = digest(initial)
    stage["step_sha256"] = digest(spec["step"])
    stage["before_manifest_sha256"] = digest({
        "run_sha256": run_hash, "root_id": "foundation", "observed_at": facts["observed_at"],
        "resources": facts["resources"]["foundation"],
    })
    facts["verified_authorization_sha256"] = [digest(initial), digest(stage)]


def _integridade(entrada: dict[str, Any]) -> None:
    spec, facts = entrada["spec"], entrada["facts"]
    initial, stage = facts["authorizations"]["initial"], facts["authorizations"]["stage"]
    assert spec["run"]["cost_manifest_sha256"] == digest(facts["financial"])
    assert initial["roots"] == spec["run"]["roots"]
    assert initial["run_sha256"] == stage["run_sha256"] == digest(spec["run"])
    assert stage["authority_sha256"] == digest(initial)
    assert stage["step_sha256"] == digest(spec["step"])
    assert facts["verified_authorization_sha256"] == [digest(initial), digest(stage)]
    assert stage["before_manifest_sha256"] == digest({
        "run_sha256": digest(spec["run"]), "root_id": "foundation",
        "observed_at": facts["observed_at"], "resources": facts["resources"]["foundation"],
    })
    for observation in facts["resources"]["foundation"].values():
        chave = observation["source_evidence_sha256"]
        assert digest(facts["evidence"][chave]) == chave
        assert facts["evidence"][chave]["run_sha256"] == digest(spec["run"])


def _bloqueado(plano: BootstrapPlan, motivo: str) -> None:
    assert (field(plano, "status"), plain(field(plano, "operations")),
            plain(field(plano, "proposals")), plain(field(plano, "blocked_reasons"))) == (
                "blocked", [], [], [motivo])
    assert CANARY not in canonical(plain(plano.as_mapping())).decode()


GRANTS: tuple[tuple[str, str], ...] = (
    ("initial-null", "invalid_bootstrap_input"), ("stage-null", "invalid_bootstrap_input"),
    ("foreign-run", "authorization_run_mismatch"),
    ("foreign-authority", "authorization_authority_mismatch"),
    ("unverified", "authorization_not_verified"),
    ("initial-expired", "authorization_window_invalid"),
    ("stage-expired", "authorization_window_invalid"),
    ("future", "authorization_window_invalid"), ("account", "account_mismatch"),
    ("region", "region_mismatch"), ("principal", "caller_mismatch"),
    ("mfa", "caller_unverified"), ("session", "session_expired"),
    ("ci", "unsupported_bootstrap_surface"), ("head", "unsupported_checkpoint"),
    ("no-create", "create_not_authorized"),
)


def _grant(entrada: dict[str, Any], caso: str) -> None:
    spec, facts = entrada["spec"], entrada["facts"]
    auth = facts["authorizations"]
    edits: dict[str, tuple[dict[str, Any], str, Any]] = {
        "initial-null": (auth, "initial", None), "stage-null": (auth, "stage", None),
        "foreign-run": (auth["stage"], "run_sha256", "0" * 64),
        "foreign-authority": (auth["stage"], "authority_sha256", "0" * 64),
        "unverified": (facts, "verified_authorization_sha256", []),
        "initial-expired": (auth["initial"], "expires_at", "2026-10-26T11:59:00Z"),
        "stage-expired": (auth["stage"], "expires_at", "2026-10-26T11:59:00Z"),
        "future": (auth["initial"], "not_before", "2026-10-26T12:01:00Z"),
        "account": (facts, "caller_account", "210987654321"),
        "region": (auth["initial"], "region", "us-west-2"),
        "principal": (facts, "caller_arn", "arn:aws:iam::123456789012:user/foreign"),
        "mfa": (facts, "mfa_verified", False),
        "session": (facts, "session_expiration", "2026-10-26T11:59:00Z"),
        "ci": (spec["step"], "execution_surface", "ci"),
        "head": (facts, "known_checkpoint_head", {
            "generation": 1, "checkpoint_sha256": "0" * 64, "receipt_sha256": []}),
        "no-create": (auth["initial"]["allowed_resource_actions"]["foundation"], ADDRESS, []),
    }
    target, key, value = edits[caso]
    target[key] = value
    if caso in ("initial-expired", "stage-expired", "future", "region", "ci", "no-create"):
        auth["stage"]["authority_sha256"] = digest(auth["initial"])
        auth["stage"]["step_sha256"] = digest(spec["step"])
        facts["verified_authorization_sha256"] = [digest(auth["initial"]), digest(auth["stage"])]


@pytest.mark.parametrize("caso,motivo", GRANTS, ids=[c for c, _ in GRANTS])
def test_grants_caller_janelas_e_head_genesis_preservam_motivo_atual(
    caso: str, motivo: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case("enabled")["input"])
    _grant(entrada, caso)
    _bloqueado(_executar_duas_vezes(entrada, monkeypatch), motivo)


SCOPE: tuple[tuple[tuple[str, ...], str], ...] = (
    (("foundation", "root_path"), "outro/foundation"),
    (("budget-backend", "root_path"), "outro/budget"),
    (("identity-handoff", "root_path"), "outro/identity"),
    (("budget-identities", "root_path"), "outro/budget-identities"),
    (("foundation", "owner"), "LimnoPulse"),
    (("budget-backend", "owner"), "infra-ansible:cnesdata"),
    (("identity-handoff", "owner"), "personal-infra-live:cnesdata"),
    (("budget-identities", "owner"), "infra-ansible:cnesdata"),
    (("foundation", "backend", "key"), "bootstrap/../foundation.tfstate"),
    (("identity-handoff", "backend", "key"), "bootstrap/foundation.tfstate"),
    (("budget-identities", "backend", "key"), "bootstrap/backend.tfstate"),
    (("foundation", "logging", "prefix"), "foreign/"),
)


@pytest.mark.parametrize("path,valor", SCOPE, ids=["/".join(p) for p, _ in SCOPE])
def test_catalogo_completo_e_destinos_nao_sao_legitimados_por_rehash(
    path: tuple[str, ...], valor: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case("enabled")["input"])
    _valor(entrada["spec"]["run"]["roots"], path[:-1])[path[-1]] = valor
    _reatar(entrada)
    _integridade(entrada)
    _bloqueado(_executar_duas_vezes(entrada, monkeypatch), "run_scope_invalid")


def _colidir(roots: dict[str, Any], caso: str) -> None:
    slot = "backend" if caso == "bucket" else "logging"
    roots["budget-backend"][slot]["bucket"] = roots["foundation"][slot]["bucket"]
    roots["budget-identities"][slot]["bucket"] = roots["foundation"][slot]["bucket"]
    roots["budget-backend"]["resources"][
        "aws_s3_bucket.state" if caso == "bucket" else "aws_s3_bucket.logging"][
            "configured_name"] = roots["foundation"][slot]["bucket"]
    if caso == "bucket":
        for root_id in ("budget-backend", "budget-identities"):
            roots[root_id]["logging"]["prefix"] = "access/syn-cnesdata-state-123456789012/"


@pytest.mark.parametrize("caso", ("remove-future", "budget", "sns", "produto", "bucket", "sink"))
def test_catalogo_finito_rejeita_enderecos_estrangeiros_e_colisoes(
    caso: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case("enabled")["input"])
    roots = entrada["spec"]["run"]["roots"]
    if caso == "remove-future":
        del roots["identity-handoff"]["resources"]["aws_iam_role.budget_operator"]
        del entrada["facts"]["authorizations"]["initial"]["allowed_resource_actions"][
            "identity-handoff"]["aws_iam_role.budget_operator"]
    elif caso in ("budget", "sns", "produto"):
        address = {"budget": "aws_budgets_budget.foreign", "sns": "aws_sns_topic.foreign",
                   "produto": "aws_ecs_cluster.foreign"}[caso]
        roots["budget-backend"]["resources"][address] = {
            "configured_name": "foreign", "identity_kind": "configured"}
        entrada["facts"]["authorizations"]["initial"]["allowed_resource_actions"][
            "budget-backend"][address] = ["create"]
    else:
        _colidir(roots, caso)
    _reatar(entrada)
    _integridade(entrada)
    _bloqueado(_executar_duas_vezes(entrada, monkeypatch), "run_scope_invalid")


LEDGER: tuple[tuple[tuple[str, ...], Any], ...] = (
    (("currency",), "BRL"), (("lines", "cmk", "min"), 1.1),
    (("lines", "cmk", "base"), 1.1), (("lines", "cmk", "quantity"), 2),
    (("lines", "backends", "quantity"), 1), (("lines", "logging_sinks", "quantity"), 1),
    (("lines", "independent_recovery_media", "quantity"), 0),
    (("lines", "iam", "quantity"), -1), (("lines", "kms_requests", "max"), -0.01),
    (("rotation_max",), 1.8), (("project_forecast_gross",), 1.8),
    (("aggregate_forecast_gross",), 1.8),
)


@pytest.mark.parametrize("path,valor", LEDGER, ids=["/".join(p) for p, _ in LEDGER])
def test_ledger_bruto_invalido_nao_e_aprovado_por_net_zero(
    path: tuple[str, ...], valor: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case("enabled")["input"])
    financeiro = entrada["facts"]["financial"]
    _valor(financeiro, path[:-1])[path[-1]] = valor
    assert financeiro["net_actual"] == financeiro["net_forecast"] == 0
    _reatar(entrada)
    _integridade(entrada)
    _bloqueado(_executar_duas_vezes(entrada, monkeypatch), "financial_manifest_invalid")


@pytest.mark.parametrize("campo,valor,motivo", (
    ("project_forecast_gross", 8.01, "project_cost_limit_exceeded"),
    ("aggregate_forecast_gross", 15.01, "aggregate_cost_limit_exceeded"),
))
def test_limites_brutos_preservam_codigos_existentes(
    campo: str, valor: float, motivo: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case("enabled")["input"])
    entrada["facts"]["financial"][campo] = valor
    _reatar(entrada)
    _integridade(entrada)
    _bloqueado(_executar_duas_vezes(entrada, monkeypatch), motivo)


def test_controle_intacto_preserva_oraculo_literal_imutabilidade_e_reserva(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caso = cast(dict[str, Any], load_case("enabled"))
    _integridade(caso["input"])
    plano = _executar_duas_vezes(caso["input"], monkeypatch)
    atual = cast(dict[str, Any], plain(plano.as_mapping()))
    assert {k: v for k, v in atual.items() if k != "operations"} == {
        k: v for k, v in caso["expected"].items() if k != "operations"}
    assert {op["address"]: op for op in atual["operations"]} == {
        op["address"]: op for op in caso["expected"]["operations"]}
    assert field(plano, "status") == "ready" and len(field(plano, "operations")) == 22
    financeiro = caso["input"]["facts"]["financial"]
    assert sum(v["quantity"] * v["max"] for v in financeiro["lines"].values()) == pytest.approx(1.8)
    assert financeiro["rotation_max"] == 3.8
    eventos: list[str] = []
    with monkeypatch.context() as patch:
        _bloquear_fronteiras(patch, eventos)
        for classe, mapping in ((BootstrapSpec, caso["input"]["spec"]),
                                (Readback, caso["input"]["facts"]),
                                (BootstrapPlan, caso["expected"])):
            anterior = deepcopy(mapping)
            valor = classe.from_mapping(mapping)
            _provar_imutabilidade(valor)
            if mapping != anterior:
                raise AssertionError("from_mapping_input_mutated")
    assert eventos == []


def test_linha_financeira_faltante_bloqueia_com_digest_coerente(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case("enabled")["input"])
    del entrada["facts"]["financial"]["lines"]["restore_egress"]
    _reatar(entrada)
    _integridade(entrada)
    _bloqueado(_executar_duas_vezes(entrada, monkeypatch), "financial_manifest_invalid")


def test_timestamp_lexical_invalido_permanece_representavel_e_privado(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case("enabled")["input"])
    entrada["spec"]["step"]["expires_at"] = CANARY + "Z"
    entrada["facts"]["authorizations"]["stage"]["expires_at"] = CANARY + "Z"
    _reatar(entrada)
    plano = _executar_duas_vezes(entrada, monkeypatch)
    _bloqueado(plano, "invalid_timestamp")
    assert field(plano, "expires_at") is None


TARGETS_ALTERNATIVOS: dict[str, tuple[str | None, str | None]] = {
    "aws_iam_policy.executor_boundary": ("boundary-alternativo",
        "arn:aws:iam::123456789012:policy/cnesdata/boundary-alternativo"),
    "aws_iam_role.bootstrap_executor": ("executor-alternativo", "executor-alternativo"),
    "aws_iam_role.bootstrap_readback": ("readback-alternativo", "readback-alternativo"),
    "aws_iam_role_policy.bootstrap_executor": (
        "executor-inline", "executor-alternativo:executor-inline"),
    "aws_iam_role_policy.bootstrap_readback": (
        "readback-inline", "readback-alternativo:readback-inline"),
    "aws_iam_user.bootstrap_operator": ("operador-alternativo", "operador-alternativo"),
    "aws_iam_user_policy.local_assume": ("assume-inline", "operador-alternativo:assume-inline"),
    "aws_iam_user_policy_attachment.local_login": (None, None),
    "aws_kms_key.foundation": (None, None),
    "aws_s3_bucket.state": (
        "syn-estado-alternativo-123456789012", "syn-estado-alternativo-123456789012"),
    "aws_s3_bucket.logging": (
        "syn-logs-alternativo-123456789012", "syn-logs-alternativo-123456789012"),
    "aws_s3_bucket_lifecycle_configuration.logging": (None, "syn-logs-alternativo-123456789012"),
    "aws_s3_bucket_logging.state": (None, "syn-estado-alternativo-123456789012"),
    "aws_s3_bucket_ownership_controls.logging": (None, "syn-logs-alternativo-123456789012"),
    "aws_s3_bucket_ownership_controls.state": (None, "syn-estado-alternativo-123456789012"),
    "aws_s3_bucket_policy.logging": (None, "syn-logs-alternativo-123456789012"),
    "aws_s3_bucket_policy.state": (None, "syn-estado-alternativo-123456789012"),
    "aws_s3_bucket_public_access_block.logging": (None, "syn-logs-alternativo-123456789012"),
    "aws_s3_bucket_public_access_block.state": (None, "syn-estado-alternativo-123456789012"),
    "aws_s3_bucket_server_side_encryption_configuration.logging": (
        None, "syn-logs-alternativo-123456789012"),
    "aws_s3_bucket_server_side_encryption_configuration.state": (
        None, "syn-estado-alternativo-123456789012"),
    "aws_s3_bucket_versioning.state": (None, "syn-estado-alternativo-123456789012"),
}


def test_nomes_alternativos_preservam_vinte_e_dois_targets_literais(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrada = cast(dict[str, Any], load_case("enabled")["input"])
    run = entrada["spec"]["run"]
    for root_id in ("foundation", "identity-handoff"):
        root = run["roots"][root_id]
        root["backend"]["bucket"] = "syn-estado-alternativo-123456789012"
        root["logging"]["bucket"] = "syn-logs-alternativo-123456789012"
        root["logging"]["prefix"] = "access/syn-estado-alternativo-123456789012/"
    for name, novo in (("boundary", "boundary-alternativo"), ("executor", "executor-alternativo"),
                       ("readback", "readback-alternativo"), ("operator", "operador-alternativo")):
        run["identities"][name]["name"] = novo
    for address, (nome, _) in TARGETS_ALTERNATIVOS.items():
        run["roots"]["foundation"]["resources"][address]["configured_name"] = nome
    _reatar(entrada)
    _integridade(entrada)
    plano = _executar_duas_vezes(entrada, monkeypatch)
    assert field(plano, "status") == "ready"
    assert plain(field(plano, "blocked_reasons")) == []
    operacoes = cast(list[dict[str, Any]], plain(field(plano, "operations")))
    assert len(operacoes) == len({op["address"] for op in operacoes}) == 22
    assert {op["address"]: (op["target"]["configured_name"], op["target"]["exact_id"])
            for op in operacoes} == TARGETS_ALTERNATIVOS
    assert all(op["action"] == "create" for op in operacoes)
    assert {op["address"] for op in operacoes
            if op["target"]["identity_kind"] == "provider_assigned"} == {
                "aws_kms_key.foundation", "aws_iam_user_policy_attachment.local_login"}


def test_precos_unitarios_alternativos_validos_nao_sao_constantes_de_producao(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caso = cast(dict[str, Any], load_case("enabled"))
    entrada = caso["input"]
    financeiro = entrada["facts"]["financial"]
    financeiro["lines"]["cmk"] = {"quantity": 1, "min": 0.5, "base": 0.5, "max": 0.5}
    financeiro["lines"]["iam"]["quantity"] = 0
    for campo in ("rotation_max", "project_forecast_gross", "aggregate_forecast_gross"):
        financeiro[campo] = 2.3
    _reatar(entrada)
    _integridade(entrada)
    plano = _executar_duas_vezes(entrada, monkeypatch)
    assert field(plano, "status") == "ready" and len(field(plano, "operations")) == 22
    assert plain(field(plano, "estimated_cost")) == {
        "currency": "USD", "basis": "synthetic-gross-monthly-reservation",
        "project_forecast_gross": 2.3, "aggregate_forecast_gross": 2.3,
        "project_limit": 8, "aggregate_limit": 15, "rotation_max": 2.3}
    operacoes = cast(list[dict[str, Any]], plain(field(plano, "operations")))
    assert {op["address"]: op["target"] for op in operacoes} == {
        op["address"]: op["target"] for op in caso["expected"]["operations"]}
