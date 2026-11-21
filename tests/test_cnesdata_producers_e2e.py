"""Ponta a ponta do role plan: observador, arquivos entregues pelo workflow, montagem e conferencia do gate (P18)."""
import ast
import base64
import copy
import io
import json
import zipfile

import pytest
import yaml

from fixtures.cnesdata_producers import KEY_HEX, SOURCE, config
from test_cnesdata_producers_inputs import (PRODUCER, ROOT, T, WORKFLOW, X_STAR, assemble_receives, at, drift_upload,
                                            setup)
from tools.cnesdata_delivery import contract as c, drift_handoff, provenance
from tools.cnesdata_delivery.producers import assembler, inputs

NOW = c.instant(T) + 60
DRIFT_ID = 9001
OWN = ("repository", "workflow_path", "workflow_sha")
PRODUCERS = ROOT / "tools/cnesdata_delivery/producers"
READERS = ("observer.py", "phase_inputs.py", "inputs.py", "measurements.py", "assembler.py")
REQUEST_FIELDS = {"artifact_expires_at", "candidate_sha256", "cloudfront", "cost_expires_at", "creator_workflow_sha",
                  "dependencies", "observed_reference", "owner_producer", "payload_reference", "plan_expires_at",
                  "promotion_evidence_sha256", "promotion_producer", "public_objects", "references", "required_checks",
                  "root_source_sha"}
COMPOSED = ("purpose", "role", "source_sha", "mode", "observed_at")


def archive(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as handle:
        for name in sorted(members):
            handle.writestr(name, members[name])
    return buffer.getvalue()


class REST:
    """Fronteira HTTP do GitHub (runs, metadados, zips, conteudo); a autenticacao e a real de provenance."""

    def __init__(self):
        self.runs, self.artifacts = {}, {}

    def publish(self, reference, members):
        raw = archive(members)
        self.runs[reference["repository"], reference["run_id"], reference["run_attempt"]] = {
            "id": reference["run_id"], "run_attempt": reference["run_attempt"],
            "repository": {"full_name": reference["repository"]}, "head_sha": reference["workflow_sha"],
            "path": reference["workflow_path"] + "@refs/heads/main", "status": "completed", "conclusion": "success",
            "run_started_at": at(-120), "updated_at": at(120)}
        meta = {"id": reference["artifact_id"], "digest": "sha256:" + c.sha(raw), "expired": False,
                "expires_at": at(31 * 86400), "created_at": at(0),
                "workflow_run": {"id": reference["run_id"], "head_sha": reference["source_sha"]}}
        self.artifacts[reference["repository"], reference["artifact_id"]] = {"meta": meta, "zip": raw}
        return meta["digest"]

    def __call__(self, path, *, raw, maximum):
        if "/contents/" in path:
            item = ROOT / path.split("/contents/")[1].split("?")[0]
            return {"type": "file", "encoding": "base64", "content": base64.b64encode(item.read_bytes()).decode()}
        if "/compare/" in path:
            return {"status": "identical"}
        if "/check-runs" in path:
            return {"check_runs": [{"name": "ci", "conclusion": "success", "head_sha": SOURCE}]}
        if "/rules/branches/main" in path:
            return [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "ci"}]}}]
        parts = path.split("/")
        repository = parts[1] + "/" + parts[2]
        assert raw == path.endswith("/zip")
        if parts[4] == "runs":
            return copy.deepcopy(self.runs[repository, int(parts[5]), int(parts[7])])
        record = self.artifacts[repository, int(parts[5])]
        return record["zip"] if raw else copy.deepcopy(record["meta"])


def plan_request(value, digest_hex):
    public = {key: item for key, item in value.items()
              if key not in ("purpose", "role", "source_sha", "x_star", "producer", "now")}
    public["references"] = {key: item for key, item in value["references"].items() if key != "drift"}
    env = {"GITHUB_WORKFLOW_REF": f"{PRODUCER['repository']}/{PRODUCER['workflow_path']}@refs/heads/main",
           "GITHUB_SHA": PRODUCER["workflow_sha"], "GITHUB_RUN_ID": str(PRODUCER["run_id"]),
           "GITHUB_RUN_ATTEMPT": str(PRODUCER["run_attempt"]), "PURPOSE": "phase-a", "ROLE": "plan",
           "SOURCE_SHA": SOURCE, "X_STAR": X_STAR, "DRIFT_ARTIFACT_ID": str(DRIFT_ID),
           "DRIFT_ARTIFACT_DIGEST": digest_hex, "REQUEST": json.dumps(public)}
    return inputs.request_from(env) | {"now": NOW}


@pytest.fixture
def world(setup, monkeypatch):
    fake, value, observed = setup
    rest = REST()
    monkeypatch.setattr(provenance.GitHub, "_read", rest)
    value = copy.deepcopy(value)
    for name, reference in value["references"].items():
        if name != "drift":
            reference["artifact_digest"] = rest.publish(reference, fake.members[reference["artifact_id"]])
    sent = {name: observed[name] for name in drift_upload()}
    own = {key: PRODUCER[key] for key in ("repository", "run_id", "run_attempt", "workflow_path", "workflow_sha")}
    own |= {"artifact_id": DRIFT_ID, "source_sha": PRODUCER["workflow_sha"]}
    request = plan_request(value, rest.publish(own, sent).removeprefix("sha256:"))
    received = {name: observed[name] for name in assemble_receives()}
    return rest, request, received, sent


def listed_drift(rest):
    meta = rest.artifacts[PRODUCER["repository"], DRIFT_ID]["meta"]
    return {"repository": PRODUCER["repository"], "run_id": meta["workflow_run"]["id"],
            "run_attempt": PRODUCER["run_attempt"], "artifact_id": meta["id"], "artifact_digest": meta["digest"],
            "workflow_path": PRODUCER["workflow_path"], "workflow_sha": PRODUCER["workflow_sha"],
            "source_sha": meta["workflow_run"]["head_sha"]}


def test_referencia_do_drift_montada_por_inputs_autentica_no_github_e_e_a_que_o_dono_copia(world):
    rest, request, _, sent = world
    reference = request["references"]["drift"]
    assert provenance.GitHub(token="x").artifact(reference, NOW) == sent
    assert reference == listed_drift(rest)


def test_plan_ponta_a_ponta_do_observador_ao_proof_conferido_pelo_gate(world):
    rest, request, received, sent = world
    values, _ = inputs.build(provenance.GitHub(token="x"), request, received)
    built = assembler.assemble(values)
    proof = c.loads(built.files["proof.json"], canonical=True)
    settings = config()
    governance = {"proof_producers": [{key: PRODUCER[key] for key in OWN}],
                  "artifact_purposes": sorted(request["references"]),
                  "artifact_references": copy.deepcopy(request["references"]) | {"drift": listed_drift(rest)},
                  "report_hmac_key": KEY_HEX,
                  "account_id": settings["account_id"], "roles": settings["roles"],
                  "state_bucket": settings["state_bucket"], "evidence_bucket": settings["evidence_bucket"],
                  "drift_handoff": {"member": "drift-handoff.json", "sha256": c.sha(sent["drift-handoff.json"])}}
    gate = provenance.GitHub(token="x")
    provenance.validate_proof(proof, built.files, governance, gate, NOW, SOURCE, "phase-a", "plan")
    drift = gate.artifact(governance["artifact_references"]["drift"], NOW)
    loaded = drift_handoff.load(drift, governance, proof, built.files, source=SOURCE, purpose="phase-a")
    assert loaded["drift_matrix"]["matrix_version"] == 2 and proof["plan_binding_sha256"] is None


def read_keys(name):
    found = set()
    for node in ast.walk(ast.parse((PRODUCERS / name).read_text())):
        owner, key = None, None
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            owner, key = node.value, node.slice.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" \
                and node.args and isinstance(node.args[0], ast.Constant):
            owner, key = node.func.value, node.args[0].value
        elif isinstance(node, ast.Compare) and isinstance(node.left, ast.Constant) \
                and any(isinstance(op, ast.In) for op in node.ops):
            owner, key = node.comparators[0], node.left.value
        if isinstance(owner, ast.Name) and owner.id in {"asked", "request"}:
            found.add(key)
    return found


def test_campos_do_pedido_publico_sao_os_que_o_observe_e_o_assemble_leem():
    observe = read_keys("observer.py") | read_keys("phase_inputs.py")
    assemble = set().union(*(read_keys(name) for name in READERS[2:]))
    env = {"GITHUB_WORKFLOW_REF": f"{PRODUCER['repository']}/{PRODUCER['workflow_path']}@refs/heads/main",
           "GITHUB_SHA": PRODUCER["workflow_sha"], "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
           "PURPOSE": "phase-a", "ROLE": "deploy", "SOURCE_SHA": SOURCE, "X_STAR": X_STAR,
           "REQUEST": json.dumps({"references": {}})}
    injected = set(inputs.request_from(env)) - {"references"}
    compose = next(step["run"] for step in yaml.safe_load(WORKFLOW.read_text())["jobs"]["observe"]["steps"]
                   if step.get("name") == "Compose the observation request")
    assert all(f'"{key}"' in compose for key in COMPOSED)
    assert (observe - set(COMPOSED)) | (assemble - injected) == REQUEST_FIELDS
