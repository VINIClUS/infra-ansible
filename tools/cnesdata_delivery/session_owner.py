"""Fresh original-owner facts bind the managed session default before and after STS."""

import re
import time
from dataclasses import dataclass
from urllib.parse import unquote

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.provenance import validate_proof
from tools.cnesdata_delivery.session_policy import managed_arn

CONSUMER_WORKFLOWS = {
    ".github/workflows/infra-plan.yml",
    ".github/workflows/infra-apply.yml",
    ".github/workflows/reusable-cnesdata-infra-plan-gate.yml",
    ".github/workflows/reusable-cnesdata-infra-deploy-gate.yml",
}


@dataclass(frozen=True)
class Authority:
    pin: dict
    expires_at: float
    namespace: dict | None


def _pin(governance, role):
    c.require(
        type(governance.get("session_policy_pins")) is dict
        and role in governance["session_policy_pins"],
        "original owner session pin absent",
    )
    pin = governance["session_policy_pins"][role]
    c.closed(
        pin,
        "account_id role_arn policy_arn root_source_sha default_version_id document "
        "document_sha256 observed_at expires_at frozen_until owner_producer",
    )
    c.require(
        pin["account_id"] == governance["account_id"]
        and pin["role_arn"] == governance["roles"][role]
        and pin["policy_arn"] == managed_arn(governance, role),
        "own deterministic session policy",
    )
    c.digest(pin["root_source_sha"], 40)
    c.digest(pin["document_sha256"])
    c.require(
        type(pin["document"]) is dict
        and c.sha(c.canonical(pin["document"], limit=65536)) == pin["document_sha256"],
        "complete expected private session document",
    )
    c.require(
        type(pin["default_version_id"]) is str
        and re.fullmatch(r"v[1-9][0-9]*(?:\.[A-Za-z0-9]+)?", pin["default_version_id"]),
        "expected default version",
    )
    owner = c.closed(pin["owner_producer"], "repository workflow_path workflow_sha")
    c.digest(owner["workflow_sha"], 40)
    c.require(
        owner in governance["proof_producers"]
        and owner["workflow_path"] not in CONSUMER_WORKFLOWS,
        "independent original owner producer; consumer self-measurement forbidden",
    )
    return pin


def _facts(pin):
    return {
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


def authenticate(
    governance,
    descriptor,
    proof,
    files,
    api,
    now,
    role,
    purpose,
    *,
    plan_binding_sha256=None,
):
    pin = _pin(governance, role)
    reference = governance.get("admission_reference")
    c.require(type(reference) is dict, "original owner artifact reference absent")
    c.require(
        {key: reference[key] for key in ("repository", "workflow_path", "workflow_sha")}
        == pin["owner_producer"],
        "original owner artifact producer, not consumer carrier",
    )
    c.require(
        {
            key: reference[key]
            for key in (
                "repository",
                "workflow_path",
                "workflow_sha",
                "run_id",
                "run_attempt",
            )
        }
        == proof["producer"],
        "original owner artifact/proof run binding",
    )
    original = api.artifact(reference, now)
    c.require(
        original.get("proof.json") == c.canonical(proof),
        "original authenticated owner proof bytes",
    )
    for report in proof["reports"]:
        c.require(
            original.get(report["name"]) == files.get(report["name"]),
            "original authenticated owner report bytes",
        )
    files = original
    if role == "deploy":
        c.digest(plan_binding_sha256)
    else:
        c.require(
            plan_binding_sha256 is None,
            "plan admission has no future saved-plan binding",
        )
    c.require(
        proof["plan_binding_sha256"] == plan_binding_sha256,
        "original owner saved-plan binding",
    )
    validate_proof(
        proof, files, governance, api, now, descriptor["source_sha"], purpose, role
    )
    producer = {
        key: proof["producer"][key]
        for key in ("repository", "workflow_path", "workflow_sha")
    }
    c.require(
        producer == pin["owner_producer"],
        "original owner provenance, not consumer report",
    )
    report = next(
        item for item in proof["reports"] if item["check_id"] == "policy-evaluation"
    )
    check = next(
        item for item in proof["checks"] if item["check_id"] == "policy-evaluation"
    )
    measured = c.loads(files[report["name"]], canonical=True, limit=262144)[
        "measurement"
    ]
    c.require(
        type(measured) is dict
        and c.canonical(measured.get("managed_session_policy"))
        == c.canonical(_facts(pin)),
        "original owner managed-session facts absent or mixed",
    )
    c.require(
        check["observed_at"] == pin["observed_at"]
        and check["expires_at"] == pin["expires_at"],
        "original dated owner check cannot be extended",
    )
    observed, expires = c.instant(pin["observed_at"]), c.instant(pin["expires_at"])
    frozen_until = c.instant(pin["frozen_until"])
    proof_expiry = c.instant(proof["expires_at"])
    c.require(
        observed <= now
        and now + 3600 <= proof_expiry <= expires
        and now + 3600 <= frozen_until,
        "fresh proof and serialized owner freeze for full session",
    )
    document = c.loads(c.canonical(pin), canonical=True, limit=262144)
    return Authority(document, proof_expiry, measured.get("phase_input_namespace"))


def _metadata(value, pin):
    c.require(
        value["Arn"] == pin["policy_arn"]
        and value["PolicyName"] == pin["policy_arn"].rsplit("/", 1)[1]
        and value["DefaultVersionId"] == pin["default_version_id"],
        "managed policy identity/default",
    )
    c.require(
        type(value["AttachmentCount"]) is int
        and value["AttachmentCount"] == 0
        and type(value["PermissionsBoundaryUsageCount"]) is int
        and value["PermissionsBoundaryUsageCount"] == 0,
        "session-only zero identity/boundary use",
    )


def verify_managed(aws, authority, session_expires, clock=time.time):
    pin = authority.pin
    c.require(
        clock() < session_expires <= authority.expires_at
        and session_expires <= c.instant(pin["frozen_until"]),
        "session proof/freeze expiry",
    )
    first = aws.call("iam", "get_policy", PolicyArn=pin["policy_arn"])["Policy"]
    _metadata(first, pin)
    version = aws.call(
        "iam",
        "get_policy_version",
        PolicyArn=pin["policy_arn"],
        VersionId=pin["default_version_id"],
    )["PolicyVersion"]
    c.require(
        version["VersionId"] == pin["default_version_id"]
        and version["IsDefaultVersion"] is True,
        "current default version readback",
    )
    document = version["Document"]
    if type(document) is str:
        document = c.loads(unquote(document).encode(), limit=65536)
    c.require(
        type(document) is dict
        and c.canonical(document, limit=65536)
        == c.canonical(pin["document"], limit=65536)
        and c.sha(c.canonical(document, limit=65536)) == pin["document_sha256"],
        "exact default session document readback",
    )
    second = aws.call("iam", "get_policy", PolicyArn=pin["policy_arn"])["Policy"]
    _metadata(second, pin)
    c.require(
        first["Arn"] == second["Arn"]
        and first["DefaultVersionId"] == second["DefaultVersionId"],
        "managed default changed around document read",
    )
    c.require(
        clock() < session_expires <= authority.expires_at
        and session_expires <= c.instant(pin["frozen_until"]),
        "session proof expired during readback",
    )
