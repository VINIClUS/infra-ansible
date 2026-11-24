"""Entradas do montador a partir dos artefatos autenticados, das observacoes e do pedido publico (P18)."""
import base64
import copy
import json
import socket
import sys
from pathlib import Path

import pytest
import yaml

from fixtures.cnesdata_phase_a_replay import ReplayChain
from fixtures.cnesdata_producers import KEY_HEX, PAYLOAD_REFERENCE, SOURCE, config, public_objects, request, world
from test_cnesdata_producers_cost import NOW, owner_block
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.producers import assembler, baseline_commitments, inputs, observer, pins

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/reusable-cnesdata-observer.yml"
T = "2026-11-20T12:00:00Z"
PRODUCER = {"repository": "VINIClUS/infra-ansible", "workflow_path": ".github/workflows/cnesdata-producers.yml",
            "workflow_sha": "9" * 40, "run_id": 7001, "run_attempt": 1}
X_STAR = "b" * 40
PR_HEAD = "c" * 40


def merged_pull_route(path):
    pull = {"number": 7, "merged_at": at(-60), "merge_commit_sha": SOURCE, "head": {"sha": PR_HEAD},
            "base": {"ref": "main", "repo": {"full_name": c.REPOSITORY}}}
    if f"/commits/{SOURCE}/pulls?" in path:
        return [pull]
    if path.endswith("/pulls/7"):
        return pull
    if f"/commits/{PR_HEAD}/check-runs?" in path:
        return {"check_runs": [{"id": 1, "name": "ci", "head_sha": PR_HEAD, "status": "completed",
                                "conclusion": "success", "completed_at": at(-120)}]}
    return None


def at(seconds):
    return c.utc(c.instant(T) + seconds)


def reference(index):
    return {"repository": c.REPOSITORY, "run_id": 100 + index, "run_attempt": 1, "artifact_id": index,
            "artifact_digest": "sha256:" + f"{index:x}" * 64, "workflow_path": f".github/workflows/p{index}.yml",
            "workflow_sha": SOURCE, "source_sha": SOURCE}


class API:
    def __init__(self, members):
        self.members = members
        self.kwargs = {}

    def read(self, path):
        if "/contents/" in path:
            item = ROOT / path.split("/contents/")[1].split("?")[0]
            return {"type": "file", "encoding": "base64", "content": base64.b64encode(item.read_bytes()).decode()}
        if "/compare/" in path:
            return {"status": "identical"}
        if merged_pull_route(path) is not None:
            return merged_pull_route(path)
        if "/check-runs" in path:
            return {"check_runs": [{"name": "ci", "conclusion": "success", "head_sha": SOURCE}]}
        if "/rules/branches/main" in path:
            return [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "ci"}]}}]
        if "/artifacts/" in path:
            return {"created_at": at(0), "expires_at": at(86400)}
        return {"run_started_at": at(-60), "updated_at": at(60)}

    def artifact(self, reference_, now, **kwargs):
        self.kwargs[reference_["artifact_id"]] = kwargs
        return self.members[reference_["artifact_id"]]


@pytest.fixture
def setup(monkeypatch, tmp_path):
    chain = ReplayChain(monkeypatch, tmp_path)
    settings = config()
    reader, names, _ = world(chain, settings)
    asked = request(public_objects=public_objects(names), observed_at=T)
    observed = observer.observe(reader, settings, asked, KEY_HEX).files
    source = Path(__file__).parent / "fixtures/cnesdata_cost_source_manifest.json"
    toolchain = {"opentofu": {"version": "1.13.2", "binary_sha256": "d" * 64}, "lock_sha256": "e" * 64,
                 "providers": [{"source": "registry.opentofu.org/hashicorp/aws", "version": "6.54.0", "package_sha256": "f" * 64}]}
    committed = baseline_commitments.build({
        "identity_sha256": "a" * 64, "key": "cnesdata/prod/opentofu.tfstate", "workspace": "default",
        "region": "us-east-2", "encrypt": True, "use_lockfile": True, "bucket_hmac": "b" * 64,
        "kms_key_id_sha256": "c" * 64, "schema_sha256": "d" * 64, "shared_outputs_sha256": "e" * 64})
    context = {"source_sha": SOURCE, "checkpoint_sha256": c.sha(source.read_bytes()), "target_sha256": "e" * 64}
    names_ = ("backend", "cost", "policy", "shared-outputs", "toolchain", "phase-inputs")
    references = {name: reference(index) for index, name in enumerate(names_, 1)}
    members = {
        2: {"cost-manifest-source.json": source.read_bytes(), "cost-context.json": json.dumps(context).encode()},
        1: {"backend.json": committed["backend.json"]}, 3: {"policy.json": json.dumps(
            {"policy_sha256": "1" * 64, "conftest_sha256": "2" * 64}).encode()},
        4: {"shared-outputs.json": committed["shared-outputs.json"]}, 5: {"toolchain.json": json.dumps(toolchain).encode()},
        6: {"inputs.json": b"{}\n"}}
    pin = pins.producer_pins(pins.api_reader(API({})), X_STAR)
    value = {"purpose": "phase-a", "role": "plan", "source_sha": SOURCE, "x_star": X_STAR, "producer": PRODUCER,
             "references": references | {"drift": reference(9)}, "now": float(NOW), "required_checks": ["ci"],
             "dependencies": pin, "public_objects": public_objects(names), "payload_reference": PAYLOAD_REFERENCE,
             "promotion_producer": PRODUCER, "cloudfront": owner_block(observed_at=at(-30), expires_at=at(7 * 3600)),
             "cost_expires_at": at(5 * 3600), "plan_expires_at": at(4 * 3600), "artifact_expires_at": at(30 * 86400),
             "candidate_sha256": "3" * 64, "promotion_evidence_sha256": "4" * 64, "plan_binding_sha256": None}
    return API(members), value, observed


def test_entradas_montam_o_proof_da_phase_a_com_os_treze_checks_do_plan(setup):
    api, value, observed = setup
    values, extra = inputs.build(api, value, observed)
    built = assembler.assemble(values)
    assert [item["check_id"] for item in built.proof["checks"]] == assembler.required_checks("phase-a", "plan")
    assert set(extra) == {"cost-baseline.json", "cost-sources.json"}
    assert c.loads(extra["cost-baseline.json"], canonical=True)["cost_context"]["stage"] == "active"


def test_proof_da_phase_a_leva_o_plan_sha256_do_ensaio_no_drift_baseline(setup):
    api, value, observed = setup
    built = assembler.assemble(inputs.build(api, value, observed)[0])
    report = next(item for item in built.proof["reports"] if item["check_id"] == "drift-baseline")
    measured = c.loads(built.files[report["name"]], canonical=True)["measurement"]
    assert len(measured["rehearsal_plan_sha256"]) == 64


@pytest.mark.parametrize("missing", ["backend", "cost", "policy", "toolchain"])
def test_entradas_recusam_referencia_de_baseline_ausente(setup, missing):
    api, value, observed = setup
    value = copy.deepcopy(value)
    value["references"].pop(missing)
    with pytest.raises(ValueError, match="baseline"):
        inputs.build(api, value, observed)


def test_entradas_recusam_cloudfront_ausente_no_estagio_active(setup):
    api, value, observed = setup
    with pytest.raises(ValueError, match="cloudfront"):
        inputs.build(api, value | {"cloudfront": None}, observed)


def test_entradas_recusam_custo_que_vence_antes_do_plano(setup):
    api, value, observed = setup
    with pytest.raises(ValueError, match="expiry"):
        inputs.build(api, value | {"cost_expires_at": at(3600)}, observed)


def test_entradas_recusam_pin_de_dependencia_diferente_da_closure(setup):
    api, value, observed = setup
    wrong = [value["dependencies"][0] | {"content_sha256": "0" * 64}]
    with pytest.raises(ValueError, match="closure"):
        inputs.build(api, value | {"dependencies": wrong}, observed)


def test_producer_extrai_o_caller_do_ref_do_workflow():
    env = {"GITHUB_WORKFLOW_REF": "VINIClUS/infra-ansible/.github/workflows/cnesdata-producers.yml@refs/heads/main",
           "GITHUB_SHA": "9" * 40, "GITHUB_RUN_ID": "7001", "GITHUB_RUN_ATTEMPT": "1"}
    assert inputs.producer(env) == PRODUCER
    with pytest.raises(ValueError):
        inputs.producer(env | {"GITHUB_WORKFLOW_REF": "x"})


@pytest.mark.parametrize("role", ["plan", "audit"])
def test_request_from_acrescenta_a_referencia_do_drift_do_proprio_run(role):
    env = {"GITHUB_WORKFLOW_REF": "VINIClUS/infra-ansible/.github/workflows/cnesdata-producers.yml@refs/heads/main",
           "GITHUB_SHA": "9" * 40, "GITHUB_RUN_ID": "7001", "GITHUB_RUN_ATTEMPT": "2", "PURPOSE": "phase-a",
           "ROLE": role, "SOURCE_SHA": SOURCE, "X_STAR": X_STAR, "DRIFT_ARTIFACT_ID": "55",
           "DRIFT_ARTIFACT_DIGEST": "a" * 64, "REQUEST": json.dumps({"references": {"cost": {"artifact_id": 2}}})}
    merged = inputs.request_from(env)
    drift = merged["references"]["drift"]
    assert drift["artifact_id"] == 55 and drift["run_attempt"] == 2 and drift["source_sha"] == "9" * 40
    assert drift["workflow_path"] == ".github/workflows/cnesdata-producers.yml" and merged["x_star"] == X_STAR
    assert drift["artifact_digest"] == "sha256:" + "a" * 64


@pytest.mark.parametrize("digest", ["sha256:" + "a" * 64, "A" * 64, "a" * 63, ""])
def test_request_from_recusa_digest_do_drift_ja_prefixado_ou_malformado(digest):
    env = {"GITHUB_WORKFLOW_REF": "VINIClUS/infra-ansible/.github/workflows/cnesdata-producers.yml@refs/heads/main",
           "GITHUB_SHA": "9" * 40, "GITHUB_RUN_ID": "7001", "GITHUB_RUN_ATTEMPT": "1", "PURPOSE": "phase-a",
           "ROLE": "plan", "SOURCE_SHA": SOURCE, "X_STAR": X_STAR, "DRIFT_ARTIFACT_ID": "55",
           "DRIFT_ARTIFACT_DIGEST": digest, "REQUEST": json.dumps({"references": {}})}
    with pytest.raises(ValueError, match="digest"):
        inputs.request_from(env)


def uploads(job):
    found = {}
    for step in job["steps"]:
        if step.get("uses", "").startswith("actions/upload-artifact"):
            paths = [line.strip() for line in step["with"]["path"].splitlines() if line.strip()]
            found[step["with"]["name"]] = {Path(item).name for item in paths}
    return found


def assemble_receives():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    sent = uploads(jobs["observe"])
    downloads = [step["with"] for step in jobs["assemble"]["steps"]
                 if step.get("uses", "").startswith("actions/download-artifact")]
    run = next(step["run"] for step in jobs["assemble"]["steps"] if "producers.assembler" in step.get("run", ""))
    assert downloads and all(item["path"] == "${{ runner.temp }}/observed" for item in downloads)
    assert '--observed "${RUNNER_TEMP}/observed"' in run
    return set().union(*(sent[item["name"]] for item in downloads))


def drift_upload():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    return next(names for name, names in uploads(jobs["observe"]).items() if name.startswith("delivery-drift-"))


def test_montagem_do_plan_recebe_do_workflow_exatamente_os_arquivos_que_inputs_le(setup):
    api, value, observed = setup
    received = assemble_receives()
    built = assembler.assemble(inputs.build(api, value, {name: observed[name] for name in received})[0])
    assert [item["check_id"] for item in built.proof["checks"]] == assembler.required_checks("phase-a", "plan")
    assert received <= set(observed)


def with_r2(api, value):
    value = copy.deepcopy(value)
    value["references"]["r2-candidate"] = reference(7)
    api.members[7] = {"candidate.json": b"{}\n"}
    return value


def test_entradas_autenticam_o_r2_candidate_com_a_excecao_do_criador_e_so_ele(setup):
    api, value, observed = setup
    inputs.build(api, with_r2(api, value), observed)
    assert api.kwargs[7] == {"r2": True}
    assert all(api.kwargs[index] == {"r2": False} for index in (1, 2, 3, 4, 5, 6))


def test_entradas_recusam_dependencia_com_source_sha_ou_repositorio_fora_de_x_star(setup):
    api, value, observed = setup
    for change in ({"source_sha": "0" * 40}, {"repository": "VINIClUS/other"}):
        wrong = [value["dependencies"][0] | change]
        with pytest.raises(ValueError, match="pin"):
            inputs.build(api, value | {"dependencies": wrong}, observed)


def test_entradas_recusam_contexto_de_custo_com_source_sha_ou_checkpoint_fora_da_fonte(setup):
    api, value, observed = setup
    context = json.loads(api.members[2]["cost-context.json"])
    for change in ({"source_sha": "0" * 40}, {"checkpoint_sha256": "0" * 64}):
        api.members[2]["cost-context.json"] = json.dumps(context | change).encode()
        with pytest.raises(ValueError, match="cost context"):
            inputs.build(api, value, observed)


def plan_index(**changes):
    return {"index_version": 1, "kind": "cnesdata-private-plan-transport", "status": "planned",
            "repository": c.REPOSITORY, "source_sha": SOURCE,
            "producer": {"workflow_path": ".github/workflows/p12.yml", "workflow_sha": SOURCE, "run_id": 112,
                         "run_attempt": 1},
            "purpose": "phase-a", "created_at": at(600), "expires_at": at(7200), "plan_binding_sha256": "a" * 64,
            "envelope_sha256": "b" * 64, "package_aggregate_sha256": "c" * 64,
            "private_locator": {"scope": "cnesdata-prod", "source_sha": SOURCE, "run_id": 112, "run_attempt": 1,
                                "status": "planned"},
            "policy": {"verdict": "pass", "evidence_sha256": "1" * 64}, "cost": {}, "drift": {"verdict": "pass",
            "evidence_sha256": "2" * 64}, "admission_proof": {}} | changes


def plan_run(artifact_id):
    return reference(9) | {"artifact_id": artifact_id, "artifact_digest": "sha256:" + f"{artifact_id:x}" * 32}


@pytest.fixture
def deploy(setup):
    api, value, observed = setup
    sent = uploads(yaml.safe_load(WORKFLOW.read_text())["jobs"]["observe"])
    names = {prefix: next(files for name, files in sent.items() if name.startswith(prefix))
             for prefix in ("delivery-drift-", "delivery-observed-")}
    api.members[9] = {name: observed[name] for name in names["delivery-drift-"]}
    api.members[10] = {name: observed[name] for name in names["delivery-observed-"]}
    api.members[12] = {"index.json": c.canonical(plan_index()), "redacted-plan.json": b"{}\n"}
    references = value["references"] | {"planned": reference(12)}
    value = value | {"role": "deploy", "references": references, "plan_binding_sha256": None,
                     "observed_reference": plan_run(10)}
    return api, value


def test_deploy_monta_so_com_os_artefatos_do_ciclo_do_plan_sem_observacao_local(deploy):
    api, value = deploy
    values, extra = inputs.build(api, value, {})
    built = assembler.assemble(values)
    assert [item["check_id"] for item in built.proof["checks"]] == assembler.required_checks("phase-a", "deploy")
    assert built.proof["plan_binding_sha256"] == plan_index()["plan_binding_sha256"]
    assert [item["purpose"] for item in built.proof["artifacts"]] == sorted(value["references"])
    assert set(extra) == {"cost-baseline.json", "cost-sources.json"}


def test_deploy_le_o_indice_publico_do_artefato_planned_e_leva_o_digest_dele(deploy):
    api, value = deploy
    built = assembler.assemble(inputs.build(api, value, {})[0])
    texts = {item["check_id"]: c.loads(built.files[item["name"]], canonical=True)["measurement"]
             for item in built.proof["reports"]}
    package = texts["exact-saved-plan-package"]
    index = plan_index()
    assert package == {"plan_binding_sha256": index["plan_binding_sha256"], "envelope_sha256": index["envelope_sha256"],
                       "package_aggregate_sha256": index["package_aggregate_sha256"],
                       "index_artifact_digest": value["references"]["planned"]["artifact_digest"]}
    binding = texts["planned-source-input-binding"]
    assert binding["source_sha"] == SOURCE and binding["purpose"] == "phase-a"
    assert binding["planned_reference_sha256"] == c.sha(c.canonical(value["references"]["planned"]))
    assert binding["phase_inputs_reference_sha256"] == c.sha(c.canonical(value["references"]["phase-inputs"]))
    assert binding["release_candidate_sha256"] == value["candidate_sha256"]


@pytest.mark.parametrize("changes", [{"status": "applied"}, {"source_sha": "0" * 40}, {"purpose": "bootstrap"},
                                     {"extra": 1}, {"plan_binding_sha256": "xyz"}])
def test_deploy_recusa_indice_do_planned_fora_do_status_da_fonte_do_proposito_ou_da_forma(deploy, changes):
    api, value = deploy
    api.members[12] = {"index.json": c.canonical(plan_index(**changes))}
    with pytest.raises(ValueError):
        inputs.build(api, value, {})


def test_deploy_recusa_observacao_de_um_run_diferente_do_drift_do_plan(deploy):
    api, value = deploy
    for change in ({"run_id": 999}, {"run_attempt": 2}, {"workflow_sha": "7" * 40}):
        with pytest.raises(ValueError, match="plan cycle"):
            inputs.build(api, value | {"observed_reference": plan_run(10) | change}, {})


def test_deploy_nao_faz_nenhuma_chamada_aws(deploy, monkeypatch):
    api, value = deploy

    def blocked(*args, **kwargs):
        raise AssertionError("network")

    for name in ("boto3", "botocore", "botocore.config", "botocore.exceptions"):
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    built = assembler.assemble(inputs.build(api, value, {})[0])
    assert [item["check_id"] for item in built.proof["checks"]] == assembler.required_checks("phase-a", "deploy")


def test_deploy_recusa_pedido_sem_planned_ou_sem_observacao_do_ciclo(deploy):
    api, value = deploy
    with pytest.raises(ValueError, match="plan cycle observation reference"):
        inputs.build(api, {k: v for k, v in value.items() if k != "observed_reference"}, {})
    references = {k: v for k, v in value["references"].items() if k != "planned"}
    with pytest.raises(ValueError, match="planned"):
        inputs.build(api, value | {"references": references}, {})


def test_request_from_do_deploy_nao_inventa_a_referencia_do_drift_do_proprio_run():
    env = {"GITHUB_WORKFLOW_REF": "VINIClUS/infra-ansible/.github/workflows/cnesdata-producers.yml@refs/heads/main",
           "GITHUB_SHA": "9" * 40, "GITHUB_RUN_ID": "7001", "GITHUB_RUN_ATTEMPT": "1", "PURPOSE": "phase-a",
           "ROLE": "deploy", "SOURCE_SHA": SOURCE, "X_STAR": X_STAR,
           "REQUEST": json.dumps({"references": {"drift": {"artifact_id": 55}}})}
    assert inputs.request_from(env)["references"]["drift"] == {"artifact_id": 55}


def test_entradas_recusam_membro_de_saidas_compartilhadas_fora_do_contrato(setup):
    api, value, observed = setup
    api.members[4] = {"shared-outputs.json": b"{}\n"}
    with pytest.raises(ValueError):
        inputs.build(api, value, observed)


def test_entradas_recusam_backend_com_workspace_que_nao_e_default(setup):
    api, value, observed = setup
    backend = json.loads(api.members[1]["backend.json"]) | {"workspace": "prod"}
    api.members[1] = {"backend.json": json.dumps(backend).encode()}
    with pytest.raises(ValueError, match="workspace"):
        inputs.build(api, value, observed)


def test_membros_extras_publicos_passam_pela_varredura_public_safe(setup):
    api, value, observed = setup
    raw = api.members[2]["cost-manifest-source.json"].replace(b'"https://', b'"https://111122223333.example.invalid/', 1)
    context = json.loads(api.members[2]["cost-context.json"]) | {"checkpoint_sha256": c.sha(raw)}
    api.members[2] = {"cost-manifest-source.json": raw, "cost-context.json": json.dumps(context).encode()}
    with pytest.raises(ValueError, match="private material"):
        inputs.build(api, value, observed)
