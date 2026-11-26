"""Junta real do proof do dono: observador, montador e authenticate_lifecycle em cada role do lifecycle (P42)."""
import copy
import json
from pathlib import Path

import pytest
import yaml

from fixtures.cnesdata_phase_a_replay import ReplayChain
from fixtures.cnesdata_producers import KEY_HEX, PAYLOAD_REFERENCE, SOURCE, config, policy_responses, public_objects
from fixtures.cnesdata_producers import request as observer_request
from fixtures.cnesdata_producers import world
from test_cnesdata_producers_cost import owner_block
from test_cnesdata_producers_e2e import REST
from test_cnesdata_producers_inputs import PRODUCER, ROOT, T, WORKFLOW, X_STAR, at, reference
from tools.cnesdata_delivery import contract as c, provenance, session_owner
from tools.cnesdata_delivery.producers import (assembler, baseline_commitments, governance_assembly, observer, pins,
                                               rehearsal_plan)

NOW = c.instant(T) + 60
DRIFT_ID = 9001
OWN = ("repository", "workflow_path", "workflow_sha")
FRAGMENT = {"fragment_version": 4, "enabled_until": "2027-02-12T00:00:00Z"}
ADMISSION_IDS = {"application": 9101, "plan": 9102, "deploy": 9103, "audit": 9104}
CASES = [("plan", False), ("plan", True), ("deploy", False), ("audit", False), ("application", False),
         ("application", True)]


def observed_world(monkeypatch, tmp_path, activation):
    chain = ReplayChain(monkeypatch, tmp_path)
    settings = config()
    settings["roles"]["application"] = settings["roles"]["plan"].replace("-plan", "-application")
    reader, names, document = world(chain, settings)
    for role in ("application", "application-ops", "plan-activation"):
        reader.responses |= policy_responses(settings, role, document)
    plan = copy.deepcopy(chain.replay.plan)
    plan["resource_changes"] = [item for item in plan["resource_changes"]
                                if item["type"] in ("aws_iam_role", "aws_iam_role_policy")]
    monkeypatch.setattr(rehearsal_plan, "plan", lambda *args: c.canonical(plan))
    asked = observer_request(purpose="lifecycle", role="application", mode="local", activation=activation,
                             public_objects=public_objects(names))
    return settings, names, observer.observe(reader, settings, asked, KEY_HEX)


def baseline_members():
    source = ROOT / "tests/fixtures/cnesdata_cost_source_manifest.json"
    toolchain = {"opentofu": {"version": "1.13.2", "binary_sha256": "d" * 64}, "lock_sha256": "e" * 64,
                 "providers": [{"source": "registry.opentofu.org/hashicorp/aws", "version": "6.54.0",
                                "package_sha256": "f" * 64}]}
    committed = baseline_commitments.build({
        "identity_sha256": "a" * 64, "key": "cnesdata/prod/opentofu.tfstate", "workspace": "default",
        "region": "us-east-2", "encrypt": True, "use_lockfile": True, "bucket_hmac": "b" * 64,
        "kms_key_id_sha256": "c" * 64, "schema_sha256": "d" * 64, "shared_outputs_sha256": "e" * 64})
    context = {"source_sha": SOURCE, "checkpoint_sha256": c.sha(source.read_bytes()), "target_sha256": "e" * 64}
    return {2: {"cost-manifest-source.json": source.read_bytes(), "cost-context.json": json.dumps(context).encode()},
            1: {"backend.json": committed["backend.json"]},
            3: {"policy.json": json.dumps({"policy_sha256": "1" * 64, "conftest_sha256": "2" * 64}).encode()},
            4: {"shared-outputs.json": committed["shared-outputs.json"]},
            5: {"toolchain.json": json.dumps(toolchain).encode()}, 6: {"inputs.json": b"{}\n"}}


def run_environment(rest, names, observed, activation):
    members = baseline_members()
    references = {name: reference(index) for index, name in
                  enumerate(("backend", "cost", "policy", "shared-outputs", "toolchain", "phase-inputs"), 1)}
    for item in references.values():
        item["artifact_digest"] = rest.publish(item, members[item["artifact_id"]])
    own = {key: PRODUCER[key] for key in ("repository", "run_id", "run_attempt", "workflow_path", "workflow_sha")}
    own |= {"artifact_id": DRIFT_ID, "source_sha": PRODUCER["workflow_sha"]}
    digest = rest.publish(own, {"drift-handoff.json": observed["drift-handoff.json"]})
    public = {"references": references, "required_checks": ["ci"],
              "dependencies": pins.producer_pins(pins.api_reader(provenance.GitHub(token="x")), X_STAR),
              "public_objects": public_objects(names), "payload_reference": PAYLOAD_REFERENCE,
              "promotion_producer": PRODUCER, "cloudfront": owner_block(observed_at=at(-30), expires_at=at(7 * 3600)),
              "cost_expires_at": at(5 * 3600), "plan_expires_at": at(4 * 3600), "artifact_expires_at": at(30 * 86400),
              "candidate_sha256": "3" * 64, "promotion_evidence_sha256": "4" * 64, "activation": activation,
              "application_fragment_sha256": c.sha(c.canonical(FRAGMENT))}
    return {"GITHUB_WORKFLOW_REF": f"{PRODUCER['repository']}/{PRODUCER['workflow_path']}@refs/heads/main",
            "GITHUB_SHA": PRODUCER["workflow_sha"], "GITHUB_RUN_ID": str(PRODUCER["run_id"]),
            "GITHUB_RUN_ATTEMPT": str(PRODUCER["run_attempt"]), "PURPOSE": "lifecycle", "ROLE": "application",
            "SOURCE_SHA": SOURCE, "X_STAR": X_STAR, "DRIFT_ARTIFACT_ID": str(DRIFT_ID),
            "DRIFT_ARTIFACT_DIGEST": digest.removeprefix("sha256:"), "REQUEST": json.dumps(public),
            "GITHUB_TOKEN": "x"}


def assembled(monkeypatch, tmp_path, rest, environment, observed):
    directory = tmp_path / "observed"
    directory.mkdir()
    for name in ("observations.json", "drift-handoff.json"):
        (directory / name).write_bytes(observed[name])
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("time.time", lambda: NOW)
    out = tmp_path / "admission"
    assert assembler.main(["--observed", str(directory), "--out", str(out)]) == 0
    directories = {"application": out} | {role: Path(f"{out}-{role}") for role in ("plan", "deploy", "audit")}
    references = {}
    for role, path in directories.items():
        files = {item.name: item.read_bytes() for item in path.iterdir()}
        item = {key: PRODUCER[key] for key in ("repository", "run_id", "run_attempt", "workflow_path", "workflow_sha")}
        item |= {"artifact_id": ADMISSION_IDS[role], "source_sha": PRODUCER["workflow_sha"]}
        item["artifact_digest"] = rest.publish(item, files)
        references[role] = item
    return references


def lifecycle_governance(settings, environment, private_pins, references, activation):
    public = json.loads(environment["REQUEST"])
    drift = {key: PRODUCER[key] for key in ("repository", "run_id", "run_attempt", "workflow_path", "workflow_sha")}
    drift |= {"artifact_id": DRIFT_ID, "source_sha": PRODUCER["workflow_sha"],
              "artifact_digest": "sha256:" + environment["DRIFT_ARTIFACT_DIGEST"]}
    artifacts = copy.deepcopy(public["references"]) | {"drift": drift}
    value = {"account_id": settings["account_id"], "roles": settings["roles"],
             "proof_producers": [{key: PRODUCER[key] for key in OWN}], "report_hmac_key": KEY_HEX,
             "session_policy_pins": copy.deepcopy(private_pins), "session_owner_references": references,
             "artifact_purposes": sorted(artifacts), "artifact_references": artifacts,
             "state_bucket": settings["state_bucket"], "evidence_bucket": settings["evidence_bucket"]}
    if activation:
        value["activation_read"] = {"bucket": "activation"}
    return value


@pytest.fixture
def lifecycle_world(monkeypatch, tmp_path, request):
    activation = request.param
    settings, names, result = observed_world(monkeypatch, tmp_path, activation)
    rest = REST()
    monkeypatch.setattr(provenance.GitHub, "_read", rest)
    environment = run_environment(rest, names, result.files, activation)
    references = assembled(monkeypatch, tmp_path, rest, environment, result.files)
    monkeypatch.setattr(session_owner, "application_fragment", lambda governance, now: copy.deepcopy(FRAGMENT))
    return lifecycle_governance(settings, environment, result.pins, references, activation)


@pytest.mark.parametrize("role,lifecycle_world", CASES, indirect=["lifecycle_world"])
def test_proof_do_ciclo_do_application_autentica_no_authenticate_lifecycle_real(role, lifecycle_world):
    governance = lifecycle_world
    purpose = "application-prepare" if role == "application" else "phase-b"
    authority = session_owner.authenticate_lifecycle(governance, provenance.GitHub(token="x"), SOURCE, role, purpose,
                                                     NOW)
    pins_ = governance["session_policy_pins"]
    assert authority.pin == pins_[role]
    assert authority.ops_pin == (pins_["application_ops"] if role == "application" else None)
    expected = pins_["plan_activation"] if role == "plan" and "activation_read" in governance else None
    assert authority.activation_pin == expected


@pytest.mark.parametrize("activation", [False, True])
def test_observador_do_application_fixa_todos_os_pins_do_lifecycle_no_mesmo_instante(monkeypatch, tmp_path,
                                                                                    activation):
    _, _, result = observed_world(monkeypatch, tmp_path, activation)
    expected = {"plan", "deploy", "audit", "application", "application_ops"} | ({"plan_activation"} if activation
                                                                                  else set())
    assert set(result.pins) == expected
    assert {pin["observed_at"] for pin in result.pins.values()} == {T}
    facts = c.loads(result.files["observations.json"], canonical=True)["session_facts"]
    assert set(facts) == expected


def test_observador_do_application_recusa_configuracao_sem_o_role_do_application(monkeypatch, tmp_path):
    chain = ReplayChain(monkeypatch, tmp_path)
    settings = config()
    reader, names, _ = world(chain, settings)
    asked = observer_request(purpose="lifecycle", role="application", public_objects=public_objects(names))
    with pytest.raises(ValueError, match="observer application role"):
        observer.observe(reader, settings, asked, KEY_HEX)


def doc_pin(**changes):
    value = {"observed_at": "2026-11-21T09:00:00Z", "expires_at": "2026-11-21T12:00:00Z",
             "frozen_until": "2026-11-21T13:00:00Z"}
    return value | changes


def document(**changes):
    return {"product_inputs": {"shared_outputs": {"a": 1}}, "report_hmac_key": "5a" * 32} | changes


COMMITMENTS = {"shared_outputs_sha256": c.sha(c.canonical({"a": 1}))}


def test_escrita_3_com_todos_os_pins_de_um_run_e_aceita():
    pins_ = {role: doc_pin() for role in ("plan", "deploy", "audit", "application", "application_ops",
                                          "plan_activation")}
    governance_assembly.crosscheck(document(session_policy_pins=pins_, activation_read={"x": 1}), COMMITMENTS)


def test_escrita_recusa_pins_de_runs_diferentes():
    pins_ = {"plan": doc_pin(), "deploy": doc_pin(), "application": doc_pin(observed_at="2026-11-21T09:00:01Z",
                                                                             expires_at="2026-11-21T12:00:01Z",
                                                                             frozen_until="2026-11-21T13:00:01Z")}
    pins_["application_ops"] = pins_["application"]
    with pytest.raises(ValueError, match="session pins from one observe run"):
        governance_assembly.crosscheck(document(session_policy_pins=pins_), COMMITMENTS)


def test_escrita_recusa_pins_de_produtores_diferentes():
    pins_ = {"plan": doc_pin(owner_producer={"workflow_sha": "a" * 40}),
             "deploy": doc_pin(owner_producer={"workflow_sha": "b" * 40})}
    with pytest.raises(ValueError, match="session pins from one observe run"):
        governance_assembly.crosscheck(document(session_policy_pins=pins_), COMMITMENTS)


def test_escrita_com_pin_do_application_exige_o_pin_ops():
    pins_ = {"application": doc_pin()}
    with pytest.raises(ValueError, match="session pin companion role=application_ops"):
        governance_assembly.crosscheck(document(session_policy_pins=pins_), COMMITMENTS)


def test_escrita_com_activation_read_e_pin_do_plan_exige_o_pin_de_activation():
    pins_ = {"plan": doc_pin(), "deploy": doc_pin()}
    with pytest.raises(ValueError, match="session pin companion role=plan_activation"):
        governance_assembly.crosscheck(document(session_policy_pins=pins_, activation_read={"x": 1}), COMMITMENTS)


@pytest.fixture
def reusable():
    return yaml.safe_load(WORKFLOW.read_text())


def test_observe_roda_tambem_para_o_role_application(reusable):
    condition = reusable["jobs"]["observe"]["if"]
    assert "'application'" in condition and "deploy" not in condition
    assert "application" in reusable["on"]["workflow_call"]["inputs"]["role"]["description"]


def test_assemble_do_application_baixa_a_propria_observacao_e_publica_os_proofs_do_lifecycle(reusable):
    steps = reusable["jobs"]["assemble"]["steps"]
    download = next(step for step in steps if step["name"].startswith("Download the observations"))
    assert "'application'" in download["if"]
    uploads = {step["with"]["path"]: step for step in steps if step.get("uses", "").startswith("actions/upload-artifact")}
    for role in ("plan", "deploy", "audit"):
        step = uploads["${{ runner.temp }}/admission-" + role]
        assert step["if"] == "${{ inputs.role == 'application' }}"
        assert step["with"]["name"] == ("delivery-admission-${{ inputs.role }}-lifecycle-" + role
                                        + "-${{ github.run_id }}-${{ github.run_attempt }}")
        assert step["with"]["retention-days"] == 30
