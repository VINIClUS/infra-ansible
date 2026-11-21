"""Montador do proof (job assemble, sem AWS) e medicoes por check_id (P18)."""
import ast
import copy
from pathlib import Path

import pytest

from fixtures.cnesdata_phase_a_replay import ACCOUNT
from test_cnesdata_session_owner import original_owner
from tools.cnesdata_delivery import contract as c, session_owner
from tools.cnesdata_delivery.provenance import BASE_CHECKS
from tools.cnesdata_delivery.producers import assembler, cost_context, cost_ledger, measurements

PRODUCERS = Path(__file__).resolve().parents[1] / "tools/cnesdata_delivery/producers"
T = "2026-11-20T12:00:00Z"
SOURCE = "f" * 40
CALLER_K = {"repository": "VINIClUS/infra-ansible", "workflow_path": ".github/workflows/cnesdata-producers.yml",
            "workflow_sha": "9" * 40, "run_id": 100, "run_attempt": 1}


def at(hours):
    return c.utc(c.instant(T) + hours * 3600)


def test_cadeia_de_expiracao_deriva_dos_prazos_de_T():
    chain = assembler.expiry_chain(T)
    assert chain == {"observed_at": T, "proof_expires_at": at(3), "check_expires_at": at(3),
                     "pin_observed_at": T, "pin_expires_at": at(3), "frozen_until": at(4)}


def good(**changes):
    return {"proof": at(3), "cost": at(3), "cloudfront": at(3), "pin": at(3), "frozen": at(4), "artifacts": [at(3)],
            "plan": at(2)} | changes


@pytest.mark.parametrize("changes", [
    {"cost": at(1)}, {"cloudfront": at(2)}, {"pin": at(2)}, {"frozen": at(3)}, {"artifacts": [at(2)]}])
def test_cadeia_recusa_prazo_que_vence_antes_do_exigido(changes):
    with pytest.raises(ValueError, match="expiry"):
        assembler.validate_chain(assembler.expiry_chain(T), good(**changes))


def test_cadeia_aceita_prazos_iguais_ou_maiores():
    assembler.validate_chain(assembler.expiry_chain(T), good(cost=at(5), cloudfront=at(6), artifacts=[at(30)]))


def test_nomes_dos_artefatos_seguem_a_convencao_do_plano():
    names = assembler.artifact_names("ab12cd34" + "0" * 32, "plan", 55, 2)
    assert names == {"drift": "delivery-drift-ab12cd34-55-2", "admission": "delivery-admission-plan-55-2"}


def owner_inputs(role="plan", mutate=None):
    gov, descriptor, proof, files, api, now = original_owner(role)
    key = bytes.fromhex(gov["report_hmac_key"])
    chain = assembler.expiry_chain(c.utc(now - 10))
    pin = gov["session_policy_pins"][role]
    pin.update(observed_at=chain["pin_observed_at"], expires_at=chain["pin_expires_at"], frozen_until=chain["frozen_until"])
    facts = session_owner._facts(pin, key)
    required = sorted(c.loads(files[r["name"]], canonical=True)["check_id"] for r in proof["reports"])
    measured = {check: {"fact": check} for check in required} | {"policy-evaluation": {"managed_session_policy": facts}}
    api.expiries = {key: now + 30 * 86400 for key in api.expiries}
    members = copy.deepcopy(api.members)
    entries = [{"purpose": p["purpose"], "reference": p["reference"], "members": members, "expires_at": chain["pin_expires_at"]}
               for p in proof["artifacts"]]
    inputs = {"purpose": "bootstrap", "role": role, "source_sha": descriptor["source_sha"], "observed_at": chain["observed_at"],
              "producer": proof["producer"], "measurements": measured, "artifacts": entries,
              "candidate_sha256": None, "promotion_evidence_sha256": None,
              "plan_binding_sha256": proof["plan_binding_sha256"]}
    if mutate:
        mutate(inputs)
    return gov, descriptor, api, now, inputs, key


@pytest.mark.parametrize("role", ["plan", "deploy"])
def test_proof_montado_e_autenticado_pelo_gate_real(role):
    gov, descriptor, api, now, inputs, _ = owner_inputs(role)
    built = assembler.assemble(inputs)
    proof = c.loads(built.files["proof.json"], canonical=True)
    assert proof == built.proof
    api.freeze_owner(gov, proof, {k: v for k, v in built.files.items() if k != "proof.json"})
    binding = inputs["plan_binding_sha256"]
    authority = session_owner.authenticate(gov, descriptor, proof, built.files | {"proof.json": c.canonical(proof)}, api, now,
                                           role, "bootstrap", plan_binding_sha256=binding)
    assert authority.pin["observed_at"] == inputs["observed_at"]


def test_proof_tem_o_caller_k_como_producer_e_checks_ordenados():
    _, _, _, _, inputs, _ = owner_inputs()
    proof = assembler.assemble(inputs).proof
    assert proof["producer"] == inputs["producer"]
    assert [x["check_id"] for x in proof["checks"]] == sorted(BASE_CHECKS) == [x["check_id"] for x in proof["reports"]]


def test_cada_check_expira_com_o_proof_e_observed_sha256_e_o_hash_da_medicao():
    _, _, _, _, inputs, _ = owner_inputs()
    proof = assembler.assemble(inputs).proof
    expected = assembler.expiry_chain(inputs["observed_at"])["proof_expires_at"]
    assert {x["expires_at"] for x in proof["checks"]} == {proof["expires_at"]} == {expected}
    for check in proof["checks"]:
        measured = inputs["measurements"][check["check_id"]]
        assert check["observed_sha256"] == check["expected_sha256"] == c.sha(c.canonical(measured))


def test_relatorio_e_check_id_source_sha_e_medicao_canonicos():
    _, _, _, _, inputs, _ = owner_inputs()
    built = assembler.assemble(inputs)
    report = next(r for r in built.proof["reports"] if r["check_id"] == "dependency-pins")
    raw = built.files[report["name"]]
    assert c.loads(raw, canonical=True) == {"check_id": "dependency-pins", "source_sha": inputs["source_sha"],
                                            "measurement": {"fact": "dependency-pins"}}
    assert report["size"] == len(raw) and report["sha256"] == c.sha(raw)


@pytest.mark.parametrize("mode", ["falta", "sobra"])
def test_conjunto_de_checks_e_exato_por_proposito_e_papel(mode):
    def mutate(inputs):
        if mode == "falta":
            inputs["measurements"].pop("dependency-pins")
        else:
            inputs["measurements"]["promotion469-origin"] = {"x": 1}

    _, _, _, _, inputs, _ = owner_inputs(mutate=mutate)
    with pytest.raises(ValueError, match="checks"):
        assembler.assemble(inputs)


def test_deploy_exige_os_dois_checks_do_deploy_e_o_binding():
    _, _, _, _, inputs, _ = owner_inputs("deploy")
    inputs["plan_binding_sha256"] = None
    with pytest.raises(ValueError):
        assembler.assemble(inputs)


def test_deploy_com_os_dois_checks_adicionais_e_aceito():
    def add(inputs):
        inputs["measurements"] |= {"exact-saved-plan-package": {"fact": 1}, "planned-source-input-binding": {"fact": 2}}

    _, _, _, _, inputs, _ = owner_inputs("deploy", add)
    assert {x["check_id"] for x in assembler.assemble(inputs).proof["checks"]} == BASE_CHECKS | {
        "exact-saved-plan-package", "planned-source-input-binding"}


def test_medicao_com_arn_ou_conta_e_recusada_antes_de_montar():
    for value in (f"arn:aws:iam::{ACCOUNT}:role/r", ACCOUNT, "https://x.example.invalid/y"):
        def poison(inputs, value=value):
            inputs["measurements"]["dependency-pins"] = {"leak": value}

        _, _, _, _, inputs, _ = owner_inputs(mutate=poison)
        with pytest.raises(ValueError):
            assembler.assemble(inputs)


def test_artefatos_levam_content_sha256_pela_lista_de_membros_e_prazo_do_proof():
    _, _, _, _, inputs, _ = owner_inputs()
    proof = assembler.assemble(inputs).proof
    members = inputs["artifacts"][0]["members"]
    inventory = [{"name": n, "size": len(r), "sha256": c.sha(r)} for n, r in sorted(members.items())]
    assert all(a["content_sha256"] == c.sha(c.canonical(inventory)) for a in proof["artifacts"])
    assert [a["purpose"] for a in proof["artifacts"]] == sorted(a["purpose"] for a in proof["artifacts"])


def test_artefato_que_vence_antes_do_proof_e_recusado():
    def shorten(inputs):
        inputs["artifacts"][0]["expires_at"] = c.utc(c.instant(inputs["observed_at"]) + 3600)

    _, _, _, _, inputs, _ = owner_inputs(mutate=shorten)
    with pytest.raises(ValueError, match="expiry"):
        assembler.assemble(inputs)


def test_drift_baseline_sem_plan_sha256_do_ensaio_e_recusado():
    observation = {"handoff_sha256": "a" * 64, "catalog_sha256": "b" * 64, "matrix_version": 2, "source_sha": SOURCE,
                   "purpose": "phase-a", "state_identity": {}, "rows_before": 1, "rows_after": 1, "absent_rows": 0,
                   "readbacks_before": 1, "readbacks_after": 1}
    with pytest.raises(ValueError, match="rehearsal plan sha256"):
        measurements.drift_baseline(observation)
    assert measurements.drift_baseline(observation | {"rehearsal_plan_sha256": "c" * 64})["rehearsal_plan_sha256"] == "c" * 64
    with pytest.raises(ValueError, match="rehearsal plan sha256"):
        measurements.drift_baseline(observation | {"rehearsal_plan_sha256": "xyz"})


def test_montagem_recusa_drift_baseline_sem_plan_sha256():
    def strip(inputs):
        inputs["purpose"] = "phase-a"
        inputs["measurements"]["drift-baseline"] = {"handoff_sha256": "a" * 64}

    _, _, _, _, inputs, _ = owner_inputs(mutate=strip)
    with pytest.raises(ValueError, match="rehearsal plan sha256"):
        assembler.assemble(inputs)


def phase_a_inputs():
    from test_cnesdata_producers_cost import NOW, active_stage, derive
    derived = derive()
    stage = active_stage()
    return derived, stage, NOW


def test_cost_baseline_da_phase_a_leva_o_bloco_o6_so_no_estagio_active():
    derived, stage, _ = phase_a_inputs()
    baseline = assembler.cost_baseline("phase-a", derived, stage)
    assert baseline["cost_context"]["stage"] == "active" and baseline["cost_context"]["cloudfront"] == stage["cloudfront"]
    assert set(baseline) == {"cost_context", "cost_evidence", "cost_manifest", "source_manifest_sha256", "cost"}
    pre = cost_context.stage("bootstrap", SOURCE, {"source_sha": SOURCE, "checkpoint_sha256": "d" * 64, "target_sha256": "e" * 64}, None)
    assert pre["cloudfront"] is None
    with pytest.raises(ValueError, match="pre-activation"):
        assembler.cost_baseline("bootstrap", derived, pre)


def test_cost_baseline_passa_validate_cost_e_o_relatorio_e_o_cost_evidence():
    derived, stage, now = phase_a_inputs()
    baseline = assembler.cost_baseline("phase-a", derived, stage)
    c.validate_cost(baseline["cost"], purpose="phase-a", stage=baseline["cost_context"],
                    evidence=baseline["cost_evidence"], manifest=baseline["cost_manifest"], now=now,
                    source_manifest_sha256=baseline["source_manifest_sha256"])
    report = measurements.cost_ledger(baseline["cost_evidence"])
    assert report == baseline["cost_evidence"]["measurement"]


def test_estagio_active_exige_proposito_diferente_de_pre_ativacao():
    derived, stage, _ = phase_a_inputs()
    with pytest.raises(ValueError):
        assembler.cost_baseline("acm-certificate", derived, stage)


def test_dependency_pins_recalcula_a_closure_e_recusa_pin_diferente():
    pins = [{"repository": "VINIClUS/infra-ansible", "source_sha": "b" * 40, "content_sha256": "c" * 64}]
    assert measurements.dependency_pins(pins, "c" * 64, "b" * 40) == {"pins": pins, "closure_recomputed_sha256": "c" * 64}
    with pytest.raises(ValueError, match="closure"):
        measurements.dependency_pins(pins, "d" * 64, "b" * 40)


@pytest.mark.parametrize("change", [{"source_sha": "0" * 40}, {"repository": "VINIClUS/other"}])
def test_dependency_pins_exige_source_sha_igual_a_x_star_e_o_repositorio_da_entrega(change):
    pins = [{"repository": "VINIClUS/infra-ansible", "source_sha": "b" * 40, "content_sha256": "c" * 64} | change]
    with pytest.raises(ValueError, match="dependency pin"):
        measurements.dependency_pins(pins, "c" * 64, "b" * 40)


def test_toolchain_exige_lock_providers_iguais_aos_da_medicao():
    toolchain = {"opentofu": {"version": "1.13.2", "binary_sha256": "d" * 64}, "lock_sha256": "e" * 64,
                 "providers": [{"source": "registry.opentofu.org/hashicorp/aws", "version": "6.54.0", "package_sha256": "f" * 64}]}
    assert measurements.toolchain(toolchain, toolchain["providers"]) == toolchain | {"lock_providers_equal": True}
    with pytest.raises(ValueError, match="providers"):
        measurements.toolchain(toolchain, [])


def test_backend_replica_a_configuracao_do_artefato_do_dono():
    backend = {"identity_sha256": "a" * 64, "key": "cnesdata/prod/opentofu.tfstate", "workspace": "default", "region": "us-east-2",
               "encrypt": True, "use_lockfile": True, "bucket_hmac": "b" * 64, "kms_key_id_sha256": "c" * 64}
    assert measurements.backend(backend) == backend
    with pytest.raises(ValueError):
        measurements.backend(backend | {"workspace": "other"})
    with pytest.raises(ValueError):
        measurements.backend({k: v for k, v in backend.items() if k != "bucket_hmac"})


def test_policy_evaluation_junta_fatos_namespace_e_hashes_do_p_b():
    facts = {"role_arn_hmac": "a" * 64}
    namespace = {"purpose": "phase-inputs", "dedicated": True, "payload_reference_sha256": "b" * 64, "prefix_sha256": "c" * 64}
    value = measurements.policy_evaluation(facts, namespace, {"policy_sha256": "d" * 64, "conftest_sha256": "e" * 64})
    assert value == {"managed_session_policy": facts, "phase_input_namespace": namespace, "policy_sha256": "d" * 64,
                     "conftest_sha256": "e" * 64}
    assert "phase_input_namespace" not in measurements.policy_evaluation(facts, None, {"policy_sha256": "d" * 64, "conftest_sha256": "e" * 64})


PR_HEAD = "a" * 40
MERGED = "2026-11-19T18:41:36Z"
APP = 15368


def head_check(name, conclusion="success", **extra):
    return {"id": 10, "name": name, "head_sha": PR_HEAD, "status": "completed", "conclusion": conclusion,
            "started_at": "2026-11-19T17:35:56Z", "completed_at": "2026-11-19T17:50:49Z", "app": {"id": APP}} | extra


def merged_pull(**extra):
    return {"number": 7, "merged_at": MERGED, "merge_commit_sha": SOURCE, "head": {"sha": PR_HEAD},
            "base": {"ref": "main", "repo": {"full_name": c.REPOSITORY}}} | extra


class FakeAPI:
    def __init__(self, checks, status="ahead", contexts=("ci",), head=None, pulls=None):
        self.checks, self.status, self.paths = checks, status, []
        self.contexts = contexts if type(contexts) is dict else dict.fromkeys(contexts)
        self.head = [head_check(name, id=index) for index, name in enumerate(self.contexts)] if head is None else head
        self.pulls = [merged_pull()] if pulls is None else pulls

    def read(self, path):
        self.paths.append(path)
        if "/compare/" in path:
            return {"status": self.status}
        if "/rules/branches/" in path:
            return [{"type": "pull_request", "parameters": {}},
                    {"type": "required_status_checks", "parameters": {"required_status_checks": [
                        {"context": name, "integration_id": app} for name, app in self.contexts.items()]}}]
        if f"/commits/{SOURCE}/pulls?" in path:
            return self.pulls
        if "/pulls/" in path:
            return next(item for item in self.pulls if item["number"] == int(path.rsplit("/", 1)[1]))
        if f"/commits/{PR_HEAD}/check-runs?filter=all" in path:
            return {"check_runs": self.head}
        assert f"/commits/{SOURCE}/check-runs?" in path
        return {"check_runs": self.checks}


def check(name, conclusion="success", head=SOURCE):
    return {"name": name, "conclusion": conclusion, "head_sha": head}


def test_source_develop_checks_espelha_a_api_e_recusa_check_ausente_ou_vermelho():
    checks = [{"name": "ci", "conclusion": "success", "head_sha": SOURCE}, {"name": "lint", "conclusion": "success", "head_sha": SOURCE}]
    value = measurements.source_checks(FakeAPI(checks), SOURCE, ["lint", "ci", "ci"])
    assert value == {"branch": "main", "compare_status": "ahead", "required": [
        {"name": "ci", "conclusion": "success", "head_sha": SOURCE}, {"name": "lint", "conclusion": "success", "head_sha": SOURCE}],
        "pull": {"number": 7, "head_sha": PR_HEAD, "merged_at": MERGED,
                 "checks": {"ci": {"id": 0, "completed_at": "2026-11-19T17:50:49Z"}}}}
    with pytest.raises(ValueError):
        measurements.source_checks(FakeAPI(checks[:1]), SOURCE, ["ci", "lint"])
    with pytest.raises(ValueError):
        measurements.source_checks(FakeAPI([dict(checks[0], conclusion="failure")]), SOURCE, ["ci"])
    with pytest.raises(ValueError):
        measurements.source_checks(FakeAPI(checks, "diverged"), SOURCE, ["ci"])


def test_source_develop_checks_cobre_os_contextos_do_ruleset_no_head_do_pr_mergeado():
    contexts = {"lint-test-coverage": None, "sonar": None, "opentofu-native": APP}
    api = FakeAPI([check("ci")], contexts=contexts)
    value = measurements.source_checks(api, SOURCE, ["ci"])
    assert [item["name"] for item in value["required"]] == ["ci"]
    assert sorted(value["pull"]["checks"]) == ["lint-test-coverage", "opentofu-native", "sonar"]
    assert f"repos/{c.REPOSITORY}/rules/branches/main?per_page=100" in api.paths
    assert f"repos/{c.REPOSITORY}/pulls/7" in api.paths


def without(name):
    return lambda head: [item for item in head if item["name"] != name]


def replaced(name, **extra):
    return lambda head: [item | extra if item["name"] == name else item for item in head]


@pytest.mark.parametrize("mutate", [
    without("sonar"),
    replaced("sonar", conclusion="failure"),
    replaced("sonar", conclusion="cancelled"),
    replaced("sonar", conclusion=None),
    replaced("sonar", status="in_progress"),
    replaced("sonar", completed_at="2026-11-19T18:41:37Z"),
    replaced("sonar", completed_at=None),
    replaced("sonar", started_at="2026-11-19T18:41:37Z"),
    replaced("sonar", head_sha=SOURCE),
    replaced("opentofu-native", app={"id": 1}),
    lambda head: head + [head_check("sonar", "failure", id=99)],
], ids=["ausente", "failure", "cancelled", "sem-conclusao", "em-andamento", "concluido-apos-o-merge",
        "sem-conclusao-datada", "iniciado-apos-o-merge", "outro-sha", "outro-app", "o-mais-recente-vermelho"])
def test_source_develop_checks_recusa_contexto_do_ruleset_sem_verde_no_head_do_pr(mutate):
    contexts = {"sonar": None, "opentofu-native": APP}
    head = mutate([head_check("sonar", id=1), head_check("opentofu-native", id=2)])
    api = FakeAPI([check("ci"), check("sonar")], contexts=contexts, head=head)
    with pytest.raises(ValueError, match="required pull check name="):
        measurements.source_checks(api, SOURCE, ["ci"])


def test_source_develop_checks_check_so_no_source_nao_satisfaz_contexto_do_ruleset():
    api = FakeAPI([check("ci"), check("sonar")], contexts=("sonar",), head=[])
    with pytest.raises(ValueError, match="required pull check name=sonar"):
        measurements.source_checks(api, SOURCE, ["ci"])


@pytest.mark.parametrize("pulls", [
    [],
    [merged_pull(), merged_pull(number=8)],
    [merged_pull(merged_at=None)],
    [merged_pull(merge_commit_sha="0" * 40)],
    [merged_pull(base={"ref": "develop", "repo": {"full_name": c.REPOSITORY}})],
    [merged_pull(base={"ref": "main", "repo": {"full_name": "other/CnesData"}})],
], ids=["nenhum", "dois", "nao-mergeado", "outro-merge", "outra-base", "outro-repositorio"])
def test_source_develop_checks_exige_exatamente_um_pr_mergeado_no_main_com_o_source(pulls):
    with pytest.raises(ValueError, match="source merged pull"):
        measurements.source_checks(FakeAPI([check("ci")], pulls=pulls), SOURCE, ["ci"])


def test_source_develop_checks_nunca_aceita_ausencia_de_nome_pedido_mesmo_listado_no_ruleset():
    api = FakeAPI([check("ci")], contexts=("ci", "sonar"))
    with pytest.raises(ValueError, match="required source check name=sonar"):
        measurements.source_checks(api, SOURCE, ["ci", "sonar"])


def test_source_develop_checks_ignora_check_de_outro_sha_no_source():
    api = FakeAPI([check("ci"), check("lint", head="0" * 40)])
    with pytest.raises(ValueError, match="required source check name=lint"):
        measurements.source_checks(api, SOURCE, ["ci", "lint"])


@pytest.mark.parametrize("contexts", [(), ("",)])
def test_source_develop_checks_recusa_ruleset_sem_contexto_obrigatorio(contexts):
    with pytest.raises(ValueError, match="product ruleset contexts"):
        measurements.source_checks(FakeAPI([check("ci")], contexts=contexts), SOURCE, ["ci"])


def test_source_develop_checks_recusa_pagina_cheia_de_check_runs_do_head():
    head = [head_check("ci", id=index) for index in range(100)]
    with pytest.raises(ValueError, match="pull check runs page"):
        measurements.source_checks(FakeAPI([check("ci")], head=head), SOURCE, ["ci"])


class OriginAPI:
    def __init__(self, created):
        self.created = created

    def read(self, path):
        if "/artifacts/" in path:
            return {"id": 9, "created_at": self.created, "expires_at": at(30)}
        return {"run_started_at": at(-1), "updated_at": at(1)}


def test_artifact_origin_mede_o_intervalo_interior_do_run():
    ref = {"repository": c.REPOSITORY, "run_id": 5, "run_attempt": 1, "artifact_id": 9, "artifact_digest": "sha256:" + "a" * 64}
    value = measurements.artifact_origin(OriginAPI(T), [{"purpose": "drift", "reference": ref}])
    assert value[0]["interior"] is True and value[0]["reference_sha256"] == c.sha(c.canonical(ref))
    assert value[0]["artifact_digest"] == ref["artifact_digest"] and value[0]["expires_at"] == at(30)
    with pytest.raises(ValueError, match="interior"):
        measurements.artifact_origin(OriginAPI(at(2)), [{"purpose": "drift", "reference": ref}])


def test_montador_nao_importa_boto3_nem_usa_chave_nem_id_token():
    for name in ("assembler.py", "measurements.py", "cost_context.py", "cost_ledger.py"):
        text = (PRODUCERS / name).read_text()
        tree = ast.parse(text)
        imports = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imports |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        assert "boto3" not in imports and "botocore" not in imports, name
        assert "report_hmac_key" not in text and "id-token" not in text, name


def test_medicoes_do_deploy_e_da_origem_da_promocao_tem_forma_fechada():
    digests = {"plan_binding_sha256": "a" * 64, "envelope_sha256": "b" * 64, "package_aggregate_sha256": "c" * 64}
    index = dict.fromkeys(measurements.TRANSPORT_INDEX.split(), "x") | digests
    assert measurements.exact_plan_package(index, "sha256:" + "d" * 64) == digests | {"index_artifact_digest": "sha256:" + "d" * 64}
    for wrong in (digests, index | {"extra": 1}, index | {"envelope_sha256": "q"}):
        with pytest.raises(ValueError):
            measurements.exact_plan_package(wrong, "sha256:" + "d" * 64)
    bound = measurements.planned_binding(SOURCE, "phase-a", {"phase_inputs": "1" * 64, "planned": "2" * 64}, "3" * 64)
    assert bound == {"source_sha": SOURCE, "purpose": "phase-a", "phase_inputs_reference_sha256": "1" * 64,
                     "planned_reference_sha256": "2" * 64, "release_candidate_sha256": "3" * 64}
    producer = {"repository": c.REPOSITORY, "workflow_path": ".github/workflows/phase-a-prepare.yml",
                "workflow_sha": "8" * 40, "run_id": 1, "run_attempt": 1}
    origin = measurements.promotion_origin("4" * 64, producer, "sha256:" + "5" * 64)
    assert origin == {"promotion_sha256": "4" * 64, "producer": producer, "artifact_digest": "sha256:" + "5" * 64}
    with pytest.raises(ValueError):
        measurements.promotion_origin("zz", producer, "sha256:" + "5" * 64)


def test_diretorio_de_observacao_ausente_no_deploy_vira_mapa_vazio(tmp_path):
    assert assembler.read_observed(tmp_path / "absent") == {}
    (tmp_path / "observations.json").write_bytes(b"{}\n")
    assert assembler.read_observed(tmp_path) == {"observations.json": b"{}\n"}
