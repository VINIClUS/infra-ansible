"""Original owner reports are authenticated by the real proof validator before STS."""

import pytest
from typing import Any

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.provenance import BASE_CHECKS
from tools.cnesdata_delivery import session_owner
from tools.cnesdata_delivery.session_policy import managed_arn
from test_cnesdata_session_capacity import governance


class OwnerAPI:
    """HTTP/artifact boundary fixture; validation code remains real."""

    def __init__(self, producer, references, expires):
        self.producer = producer
        self.references = references
        self.owner_reference = None
        self.owner_files = {}
        self.members = {"owner.txt": b"synthetic original measurement source\n"}
        self.expiries = {
            (ref["repository"], ref["artifact_id"]): expires
            for ref in references.values()
        }

    def read(self, path):
        producer = self.producer
        assert (
            path
            == f"repos/{producer['repository']}/actions/runs/{producer['run_id']}/attempts/{producer['run_attempt']}"
        )
        return {
            "conclusion": "success",
            "status": "completed",
            "path": producer["workflow_path"],
            "head_sha": producer["workflow_sha"],
            "run_attempt": producer["run_attempt"],
        }

    def artifact(self, reference, now, **kwargs):
        if reference == self.owner_reference:
            return self.owner_files
        assert reference in self.references.values()
        return self.members

    def freeze_owner(self, governance, proof, files):
        self.owner_files = dict(files, **{"proof.json": c.canonical(proof)})
        self.owner_reference = proof["producer"] | {
            "artifact_id": 999,
            "source_sha": proof["producer"]["workflow_sha"],
            "artifact_digest": "sha256:"
            + c.sha(
                c.canonical(
                    [
                        {"name": name, "sha256": c.sha(raw)}
                        for name, raw in sorted(self.owner_files.items())
                    ]
                )
            ),
        }
        governance["admission_reference"] = self.owner_reference


def original_owner(role="plan", purpose="bootstrap"):
    gov, source, now = governance(), "f" * 40, 2000000000
    observed, expires = c.utc(now - 10), c.utc(now + 7200)
    owner = {
        "repository": "VINIClUS/infra-ansible",
        "workflow_path": ".github/workflows/owner-root-proof.yml",
        "workflow_sha": "e" * 40,
    }
    pin = {
        "account_id": gov["account_id"],
        "role_arn": gov["roles"][role],
        "policy_arn": managed_arn(gov, role),
        "root_source_sha": "d" * 40,
        "default_version_id": "v3",
        "document": {"Version": "2012-10-17", "Statement": []},
        "observed_at": observed,
        "expires_at": expires,
        "frozen_until": expires,
        "owner_producer": owner,
    }
    pin["document_sha256"] = c.sha(c.canonical(pin["document"]))
    fact = {
        "account_id": pin["account_id"],
        "role_arn_sha256": c.sha(pin["role_arn"].encode()),
        "policy_arn_sha256": c.sha(pin["policy_arn"].encode()),
        "root_source_sha": pin["root_source_sha"],
        "default_version_id": pin["default_version_id"],
        "document_sha256": pin["document_sha256"],
        "observed_at": observed,
        "expires_at": expires,
        "frozen_until": expires,
        "attachment_count": 0,
        "permissions_boundary_usage_count": 0,
    }
    purposes = ["backend", "policy", "cost", "drift", "shared-outputs", "toolchain"]
    refs = {
        name: {"repository": c.REPOSITORY, "artifact_id": index}
        for index, name in enumerate(purposes, 1)
    }
    gov.update(
        session_policy_pins={role: pin},
        proof_producers=[owner],
        artifact_purposes=purposes,
        artifact_references=refs,
    )
    producer = owner | {"run_id": 100, "run_attempt": 1}
    api = OwnerAPI(producer, refs, now + 7200)
    files, checks, reports = {}, [], []
    required = BASE_CHECKS | (
        {"exact-saved-plan-package", "planned-source-input-binding"}
        if role == "deploy"
        else set()
    )
    if purpose == "phase-a":
        required |= {
            "promotion469-origin",
            "r2-candidate-a2-binding",
            "oci-promotion-byte-integrity",
        }
    for check_id in sorted(required):
        measurement = (
            {"managed_session_policy": fact}
            if check_id == "policy-evaluation"
            else {"fact": check_id}
        )
        raw = c.canonical(
            {"check_id": check_id, "source_sha": source, "measurement": measurement}
        )
        name, digest = check_id + ".json", c.sha(c.canonical(measurement))
        files[name] = raw
        checks.append(
            {
                "check_id": check_id,
                "subject_sha256": "a" * 64,
                "expected_sha256": digest,
                "observed_sha256": digest,
                "result": "pass",
                "observed_at": observed,
                "expires_at": expires,
            }
        )
        reports.append(
            {"check_id": check_id, "name": name, "size": len(raw), "sha256": c.sha(raw)}
        )
    content = [
        {"name": name, "size": len(raw), "sha256": c.sha(raw)}
        for name, raw in sorted(api.members.items())
    ]
    proof = {
        "proof_version": 1,
        "source": {
            "repository": c.REPOSITORY,
            "ref": "refs/heads/develop",
            "source_sha": source,
        },
        "producer": producer,
        "checks": checks,
        "reports": reports,
        "observed_at": observed,
        "expires_at": expires,
        "candidate_sha256": None,
        "promotion_evidence_sha256": None,
        "plan_binding_sha256": "d" * 64 if role == "deploy" else None,
        "artifacts": [
            {
                "purpose": name,
                "reference": refs[name],
                "content_sha256": c.sha(c.canonical(content)),
                "expires_at": expires,
            }
            for name in sorted(purposes)
        ],
    }
    api.freeze_owner(gov, proof, files)
    descriptor: dict[str, Any] = {"source_sha": source}
    return gov, descriptor, proof, files, api, now


@pytest.mark.parametrize("role", ["plan", "deploy"])
def test_pin_precisa_da_medicao_original_fresca_do_owner(role):
    args = original_owner(role)
    binding = "d" * 64 if role == "deploy" else None
    authority = session_owner.authenticate(
        *args, role, "bootstrap", plan_binding_sha256=binding
    )
    assert authority.pin == args[0]["session_policy_pins"][role]
    assert authority.expires_at == args[-1] + 7200
    assert (
        c.loads(args[4].owner_files["proof.json"], canonical=True)[
            "plan_binding_sha256"
        ]
        == binding
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "absent",
        "document",
        "document-and-digest",
        "version",
        "root",
        "expired",
        "expiry-extension",
        "consumer",
        "consumer-and-pin",
        "report-bytes",
        "freeze",
        "carrier",
        "source-mixed",
    ],
)
def test_pin_autoafirmado_ou_prova_invalida_nao_autorizam_sessao(mutation):
    gov, descriptor, proof, files, api, now = original_owner()
    pin = gov["session_policy_pins"]["plan"]
    if mutation == "absent":
        gov.pop("session_policy_pins")
    elif mutation.startswith("document"):
        pin["document"]["Statement"] = [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ]
        if mutation == "document-and-digest":
            pin["document_sha256"] = c.sha(c.canonical(pin["document"]))
    elif mutation == "version":
        pin["default_version_id"] = "v4"
    elif mutation == "root":
        pin["root_source_sha"] = "a" * 40
    elif mutation == "expired":
        now += 7201
    elif mutation == "expiry-extension":
        pin["expires_at"] = c.utc(now + 9999)
    elif mutation.startswith("consumer"):
        consumer = {
            "repository": "VINIClUS/infra-ansible",
            "workflow_path": ".github/workflows/reusable-cnesdata-infra-plan-gate.yml",
            "workflow_sha": "b" * 40,
        }
        proof["producer"] = consumer | {"run_id": 101, "run_attempt": 1}
        gov["proof_producers"].append(consumer)
        api.producer = proof["producer"]
        if mutation == "consumer-and-pin":
            pin["owner_producer"] = consumer
    elif mutation == "report-bytes":
        files["policy-evaluation.json"] += b" "
    elif mutation == "carrier":
        gov["admission_reference"] = dict(
            gov["admission_reference"],
            workflow_path=".github/workflows/consumer-proof.yml",
        )
    elif mutation == "source-mixed":
        descriptor["source_sha"] = "b" * 40
    else:
        pin["frozen_until"] = c.utc(now + 100)
    with pytest.raises((ValueError, KeyError)):
        session_owner.authenticate(
            gov, descriptor, proof, files, api, now, "plan", "bootstrap"
        )


def test_grouping_consume_namespace_da_mesma_prova_owner_original_validada():
    from tools.cnesdata_delivery.session_grouping import phase_input_reads

    gov, descriptor, proof, files, api, now = original_owner(purpose="phase-a")
    reference = {
        "source_sha": descriptor["source_sha"],
        "run_id": 42448920421,
        "run_attempt": 1,
        "repository": c.REPOSITORY,
        "workflow_path": ".github/workflows/inputs.yml",
        "workflow_sha": "e" * 40,
        "artifact_id": 123,
    }
    prefix = (
        gov["evidence_prefix"]
        + "phase-inputs/"
        + descriptor["source_sha"]
        + "/42448920421/1/"
    )
    descriptor["payload_artifact"] = reference
    gov["phase_input_objects"] = {
        name: {"key": prefix + name, "sha256": "c" * 64}
        for name in ("phase-inputs.json", "candidate.json", "promotion.json")
    }
    gov["artifact_purposes"] = sorted([*gov["artifact_purposes"], "phase-inputs"])
    gov["artifact_references"]["phase-inputs"] = reference
    api.expiries[reference["repository"], reference["artifact_id"]] = now + 7200
    proof["artifacts"].append(
        dict(proof["artifacts"][0], purpose="phase-inputs", reference=reference)
    )
    proof["artifacts"].sort(key=lambda item: item["purpose"])
    report = next(
        item for item in proof["reports"] if item["check_id"] == "policy-evaluation"
    )
    measured = c.loads(files[report["name"]], canonical=True)
    measured["measurement"]["phase_input_namespace"] = {
        "purpose": "phase-inputs",
        "dedicated": True,
        "payload_reference_sha256": c.sha(c.canonical(reference)),
        "prefix_sha256": c.sha(prefix.encode()),
    }
    files[report["name"]] = c.canonical(measured)
    report.update(size=len(files[report["name"]]), sha256=c.sha(files[report["name"]]))
    check = next(
        item for item in proof["checks"] if item["check_id"] == "policy-evaluation"
    )
    digest = c.sha(c.canonical(measured["measurement"]))
    check.update(expected_sha256=digest, observed_sha256=digest)
    api.freeze_owner(gov, proof, files)
    authority = session_owner.authenticate(
        gov, descriptor, proof, files, api, now, "plan", "phase-a"
    )
    assert phase_input_reads(gov, descriptor, authority) == [prefix + "*"]


@pytest.mark.parametrize("binding", [None, "b" * 64])
def test_prova_original_deploy_nao_substitui_binding_do_indice_admitido(binding):
    args = original_owner("deploy")
    with pytest.raises(ValueError):
        session_owner.authenticate(
            *args, "deploy", "bootstrap", plan_binding_sha256=binding
        )
