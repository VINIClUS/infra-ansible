"""Entradas do montador a partir dos artefatos autenticados, das observacoes e do pedido publico (P18)."""
import base64
import copy
import json
from pathlib import Path

import pytest

from fixtures.cnesdata_phase_a_replay import ReplayChain
from fixtures.cnesdata_producers import KEY_HEX, PAYLOAD_REFERENCE, SOURCE, config, public_objects, request, world
from test_cnesdata_producers_cost import NOW, owner_block
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.producers import assembler, inputs, observer, pins

ROOT = Path(__file__).resolve().parents[1]
T = "2026-11-20T12:00:00Z"
CONTEXT = {"checkpoint_sha256": "d" * 64, "target_sha256": "e" * 64}
PRODUCER = {"repository": "VINIClUS/infra-ansible", "workflow_path": ".github/workflows/cnesdata-producers.yml",
            "workflow_sha": "9" * 40, "run_id": 7001, "run_attempt": 1}
X_STAR = "b" * 40


def at(seconds):
    return c.utc(c.instant(T) + seconds)


def reference(index):
    return {"repository": c.REPOSITORY, "run_id": 100 + index, "run_attempt": 1, "artifact_id": index,
            "artifact_digest": "sha256:" + f"{index:x}" * 64, "workflow_path": f".github/workflows/p{index}.yml",
            "workflow_sha": SOURCE, "source_sha": SOURCE}


class API:
    def __init__(self, members):
        self.members = members

    def read(self, path):
        if "/contents/" in path:
            item = ROOT / path.split("/contents/")[1].split("?")[0]
            return {"type": "file", "encoding": "base64", "content": base64.b64encode(item.read_bytes()).decode()}
        if "/compare/" in path:
            return {"status": "identical"}
        if "/check-runs" in path:
            return {"check_runs": [{"name": "ci", "conclusion": "success", "head_sha": SOURCE}]}
        if "/artifacts/" in path:
            return {"created_at": at(0), "expires_at": at(86400)}
        return {"run_started_at": at(-60), "updated_at": at(60)}

    def artifact(self, reference_, now, **kwargs):
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
    backend = {"identity_sha256": "a" * 64, "key": "cnesdata/prod/opentofu.tfstate", "workspace": "default",
               "region": "us-east-2", "encrypt": True, "use_lockfile": True, "bucket_hmac": "b" * 64,
               "kms_key_id_sha256": "c" * 64}
    names_ = ("backend", "cost", "policy", "shared-outputs", "toolchain", "phase-inputs")
    references = {name: reference(index) for index, name in enumerate(names_, 1)}
    members = {
        2: {"cost-manifest-source.json": source.read_bytes(), "cost-context.json": json.dumps(CONTEXT).encode()},
        1: {"backend.json": json.dumps(backend).encode()}, 3: {"policy.json": json.dumps(
            {"policy_sha256": "1" * 64, "conftest_sha256": "2" * 64}).encode()},
        4: {"shared-outputs.json": b"{}\n"}, 5: {"toolchain.json": json.dumps(toolchain).encode()},
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


def test_request_from_acrescenta_a_referencia_do_drift_do_proprio_run():
    env = {"GITHUB_WORKFLOW_REF": "VINIClUS/infra-ansible/.github/workflows/cnesdata-producers.yml@refs/heads/main",
           "GITHUB_SHA": "9" * 40, "GITHUB_RUN_ID": "7001", "GITHUB_RUN_ATTEMPT": "2", "PURPOSE": "phase-a",
           "ROLE": "plan", "SOURCE_SHA": SOURCE, "X_STAR": X_STAR, "DRIFT_ARTIFACT_ID": "55",
           "DRIFT_ARTIFACT_DIGEST": "sha256:" + "a" * 64, "REQUEST": json.dumps({"references": {"cost": {"artifact_id": 2}}})}
    merged = inputs.request_from(env)
    drift = merged["references"]["drift"]
    assert drift["artifact_id"] == 55 and drift["run_attempt"] == 2 and drift["source_sha"] == "9" * 40
    assert drift["workflow_path"] == ".github/workflows/cnesdata-producers.yml" and merged["x_star"] == X_STAR
