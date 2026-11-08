"""Synthetic original owner HTTP/artifact/SDK facts over the unchanged executable Chain."""

import time
from email.utils import formatdate

from fixtures.cnesdata_delivery_chain import Chain
from fixtures.cnesdata_session_cases import expected_documents
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.session_policy import managed_arn


class OwnerChain(Chain):
    sts_failure: Exception | None = None
    packed_size: int = 10

    def __init__(
        self,
        monkeypatch,
        root,
        mutation=None,
        *,
        purpose="acm-certificate",
        compact_names=False,
    ):
        self.owner_mode = False
        super().__init__(
            monkeypatch, root, purpose=purpose, compact_names=compact_names
        )
        self.expires = c.utc(self.now + 7200)
        for _, metadata, _, _ in self.artifacts.values():
            metadata["expires_at"] = self.expires
        self.gov["roles"] = {
            role: f"arn:aws:iam::111122223333:role/cnesdata-infra-{role}"
            for role in ("plan", "deploy")
        }
        self.gov["evidence_kms_key_arn"] = (
            "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000002"
        )
        owner = {
            "repository": "VINIClUS/infra-ansible",
            "workflow_path": ".github/workflows/owner-root-proof.yml",
            "workflow_sha": "e" * 40,
        }
        self.gov["proof_producers"] = [owner]
        self.gov["session_policy_pins"] = {}
        for role in ("plan", "deploy"):
            document = expected_documents(self.gov, role)[1]
            self.gov["session_policy_pins"][role] = {
                "account_id": self.gov["account_id"],
                "role_arn": self.gov["roles"][role],
                "policy_arn": managed_arn(self.gov, role),
                "root_source_sha": "d" * 40,
                "default_version_id": "v3",
                "document": document,
                "document_sha256": c.sha(c.canonical(document)),
                "observed_at": c.utc(self.now),
                "expires_at": self.expires,
                "frozen_until": self.expires,
                "owner_producer": owner,
            }
        self.run(
            owner["repository"],
            100,
            owner["workflow_path"],
            source=owner["workflow_sha"],
        )
        self.owner_mode, self.owner_calls, self.owner_mutation = True, [], mutation
        self.configure("plan", 1)

    def configure(self, role, run_id, planned=None):
        if hasattr(self, "owner_boundary"):
            del self.owner_boundary
        return super().configure(role, run_id, planned)

    def proof(self, role, binding=None):
        reference = super().proof(role, binding)
        if not self.owner_mode:
            return reference
        pin = self.gov["session_policy_pins"][role]
        fact = {
            "account_id": pin["account_id"],
            "role_arn_sha256": c.sha(pin["role_arn"].encode()),
            "policy_arn_sha256": c.sha(pin["policy_arn"].encode()),
            "root_source_sha": pin["root_source_sha"],
            "default_version_id": pin["default_version_id"],
            "document_sha256": pin["document_sha256"],
            "observed_at": pin["observed_at"],
            "expires_at": pin["expires_at"],
            "frozen_until": pin["frozen_until"],
            "attachment_count": 0,
            "permissions_boundary_usage_count": 0,
        }
        members = dict(
            self.artifacts[reference["repository"], reference["artifact_id"]][2]
        )
        proof = c.loads(members["proof.json"], canonical=True)
        report = next(
            item for item in proof["reports"] if item["check_id"] == "policy-evaluation"
        )
        measurement = {"managed_session_policy": fact}
        raw = c.canonical(
            {
                "check_id": "policy-evaluation",
                "source_sha": "a" * 40,
                "measurement": measurement,
            }
        )
        members[report["name"]] = raw
        report.update(size=len(raw), sha256=c.sha(raw))
        check = next(
            item for item in proof["checks"] if item["check_id"] == "policy-evaluation"
        )
        check.update(
            expected_sha256=c.sha(c.canonical(measurement)),
            observed_sha256=c.sha(c.canonical(measurement)),
        )
        members["proof.json"] = c.canonical(proof)
        return self.add_artifact(
            reference["run_id"],
            members,
            reference["workflow_path"],
            repository=reference["repository"],
            source=reference["workflow_sha"],
        )

    def sdk(self, service, operation, parameters):
        if service == "sts" and operation == "get_caller_identity":
            role = self.gov["roles"][self.role].rsplit("/", 1)[1]
            if self.owner_mutation == "wrong-principal":
                role = "other-role"
            return {
                "Account": self.gov["account_id"],
                "Arn": f"arn:aws:sts::{self.gov['account_id']}:assumed-role/{role}/fixture",
                "ResponseMetadata": {
                    "RequestId": "synthetic-session-identity",
                    "HTTPHeaders": {"date": formatdate(time.time(), usegmt=True)},
                },
            }
        if service != "iam" or operation not in {"get_policy", "get_policy_version"}:
            return super().sdk(service, operation, parameters)
        from test_cnesdata_session_readback import IAMBoundary

        if not hasattr(self, "owner_boundary"):
            self.owner_boundary = IAMBoundary(
                self.gov["session_policy_pins"][self.role], self.owner_mutation
            )
        self.owner_calls.append(operation)
        result = self.owner_boundary.call(service, operation, **parameters)
        result["ResponseMetadata"] = {
            "RequestId": "synthetic-owner-read",
            "HTTPHeaders": {"date": formatdate(time.time(), usegmt=True)},
        }
        return result
