"""Synthetic complete A3 packet for field/binding tests; no live receipt claim."""
import copy
import hashlib

from fixtures.cnesdata_cost import encoded, fixture


def hashed(data):
    return hashlib.sha256(data).hexdigest()


def packet():
    cost, stage, evidence, manifest = fixture(False)
    files = {"plan.bin": b"saved-original-binary", "plan.json": encoded({"resource_changes": [
        {"address": "aws_acm_certificate.static_web", "type": "aws_acm_certificate", "mode": "managed",
         "change": {"actions": ["create"], "before": None, "after": {"domain_name": "cnesdata.com.br"}}}]}),
             "inputs.tfvars.json": b"{}\n", "policy-evaluation.json": b"[]\n"}
    files["policy-proof.json"] = encoded({"evaluation_sha256": hashed(files["policy-evaluation.json"]), "graph_proof": None})
    files["redacted-plan.json"] = encoded({"view_version": 1, "repository": "VINIClUS/CnesData", "source_sha": "a" * 40,
        "purpose": "acm-certificate", "plan_json_sha256": hashed(files["plan.json"]), "changes": [{"address_shape": "aws_acm_certificate.static_web",
            "address_sha256": hashed(b"aws_acm_certificate.static_web"), "type": "aws_acm_certificate", "actions": ["create"]}]})
    configuration = {"type": "s3", "bucket": "synthetic-state", "key": "cnesdata/prod/opentofu.tfstate", "workspace": "default",
                     "region": "us-east-2", "encrypt": True, "use_lockfile": True,
                     "kms_key_id": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000001"}
    entries = [{"name": name, "size": len(data), "sha256": hashed(data)} for name, data in sorted(files.items())]
    plan = {"repository": "VINIClUS/CnesData", "source_sha": "a" * 40,
            "producer": {"workflow_path": ".github/workflows/infra-plan.yml", "workflow_sha": "a" * 40, "run_id": 1, "run_attempt": 1},
            "package": {"files": entries, "aggregate_sha256": hashed(encoded(entries))}, "purpose": "acm-certificate",
            "created_at": "2026-11-07T12:00:00Z", "expires_at": "2026-11-07T13:00:00Z",
            "binary_sha256": hashed(files["plan.bin"]), "json_sha256": hashed(files["plan.json"]),
            "inputs_sha256": hashed(files["inputs.tfvars.json"]),
            "dependencies": [{"repository": "VINIClUS/infra-ansible", "source_sha": "b" * 40, "content_sha256": "c" * 64}],
            "toolchain": {"opentofu": {"version": "1.13.2", "binary_sha256": "d" * 64}, "lock_sha256": "e" * 64,
                          "providers": [{"source": "registry.opentofu.org/hashicorp/aws", "version": "6.54.0", "package_sha256": "f" * 64}]},
            "backend": {"identity_sha256": hashed(encoded(configuration)), "configuration": configuration},
            "state_before": {"lineage": None, "serial": None, "state_sha256": None},
            "policy": {"verdict": "pass", "evidence_sha256": hashed(files["policy-proof.json"]), "policy_sha256": "a" * 64,
                       "evaluator_sha256": "b" * 64, "plan_json_sha256": hashed(files["plan.json"])}, "cost": cost,
            "drift": {"verdict": "pass", "evidence_sha256": "c" * 64, "state_sha256": None,
                      "observed_at": "2026-11-07T12:00:00Z", "expires_at": "2026-11-07T13:00:00Z"},
            "release": None, "phase_a_inputs": None}
    baseline = {k: copy.deepcopy(plan[k]) for k in ("dependencies", "toolchain", "backend")}
    baseline |= {"cost_context": stage, "cost_evidence": evidence, "cost_manifest": manifest,
                 "deploy_role_arn": "arn:aws:iam::111122223333:role/cnesdata-test-deploy"}
    envelope = {"schema_version": 1, "status": "planned", "plan": plan, "apply": None, "plan_binding_sha256": hashed(encoded(plan))}
    return envelope, files, baseline
