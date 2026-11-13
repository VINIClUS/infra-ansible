"""Fresh original-owner facts bind the managed session default before and after STS."""

import re
import time
from dataclasses import dataclass, field
from urllib.parse import unquote

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.provenance import validate_proof
from tools.cnesdata_delivery.session_policy import managed_arn

CONSUMER_WORKFLOWS = {
    ".github/workflows/infra-plan.yml",
    ".github/workflows/infra-apply.yml",
    ".github/workflows/reusable-cnesdata-infra-plan-gate.yml",
    ".github/workflows/reusable-cnesdata-infra-deploy-gate.yml",
    ".github/workflows/reusable-cnesdata-application-gate.yml",
    ".github/workflows/promote-production.yml",
    ".github/workflows/readiness-production.yml",
}


@dataclass(frozen=True)
class Authority:
    pin: dict
    expires_at: float
    namespace: dict | None
    application_fragment: dict | None = field(default=None, repr=False)


def authenticate_lifecycle(governance, api, source, role, purpose, now):
    """Original owner policy proof is independent of the later same-run plan.

    Deploy still requires its separate exact-plan audit in lifecycle_runtime; this
    proof authenticates only the managed session document and serialized freeze.
    """
    from tools.cnesdata_delivery.lifecycle_contract import PURPOSES
    c.require(purpose in PURPOSES, "lifecycle owner purpose")
    pin = _pin(governance, role)
    reference = governance["session_owner_references"][role]
    files = api.artifact(reference, now)
    proof = c.loads(files["proof.json"], canonical=True)
    validate_proof(proof, files, governance, api, now, source, purpose, "plan")
    c.require(proof["plan_binding_sha256"] is None, "owner proof cannot authorize future plan")
    c.require({k: proof["producer"][k] for k in ("repository", "workflow_path", "workflow_sha")} == pin["owner_producer"],
              "original owner source, not lifecycle consumer")
    report = next(x for x in proof["reports"] if x["check_id"] == "policy-evaluation")
    check = next(x for x in proof["checks"] if x["check_id"] == "policy-evaluation")
    measured = c.loads(files[report["name"]], canonical=True)["measurement"]
    c.require(measured.get("managed_session_policy") == _facts(pin)
              and check["observed_at"] == pin["observed_at"] and check["expires_at"] == pin["expires_at"], "original policy facts")
    expiry = c.instant(proof["expires_at"])
    c.require(c.instant(pin["observed_at"]) <= now and now + 3600 <= expiry <= c.instant(pin["expires_at"])
              and now + 3600 <= c.instant(pin["frozen_until"]), "full original session freeze")
    fragment = None
    if role == "application":
        fragment = application_fragment(governance, now)
        c.require(measured.get("application_fragment_sha256") == c.sha(c.canonical(fragment)),
                  "original owner private fragment commitment")
    return Authority(pin, expiry, None, fragment)


def application_configuration(value, account):
    """Validate protected raw input before Terraform can coerce/drop fields."""
    from tools.cnesdata_delivery import lifecycle_contract as lc, session_policy
    if value is None:
        return None
    c.closed(value, "role_name workflow_sha source_closure_sha256 enabled_until delegations"
             + (" predecessor_read" if "predecessor_read" in value else ""))
    c.require(type(account) is str and re.fullmatch(r"[0-9]{12}", account), "application account")
    c.require(type(value["role_name"]) is str and re.fullmatch(r"cnesdata-[a-z0-9-]+-application", value["role_name"]),
              "application role name")
    c.digest(value["workflow_sha"], 40)
    c.digest(value["source_closure_sha256"])
    c.instant(value["enabled_until"])
    expected = {name: "arn:aws:iam::" + account + ":role/cnesdata-prod-" + suffix
                for name, suffix in lc.APPLICATION_DELEGATIONS.items()}
    c.require(value["delegations"] == expected, "private original ten delegations")
    if value.get("predecessor_read") is not None:
        session_policy.predecessor_keys({"evidence_prefix": "cnesdata/prod/validation/"}, value["predecessor_read"])
    return c.loads(c.canonical(value), canonical=True)


def application_fragment(governance, now):
    """Private catalog bytes, committed by the original public owner proof.

    The fragment itself never travels in a public GitHub artifact. This parser
    grants nothing; authenticate_lifecycle checks its original owner commitment
    before STS and verify_application checks the actual IAM documents afterward.
    """
    from tools.cnesdata_delivery import session_policy, lifecycle_contract as lc
    from tools.cnesdata_delivery.coordination_lease import KEY
    value = c.loads(c.canonical(governance["application_fragment"], limit=65536), canonical=True, limit=65536)
    config = application_configuration(governance["application_configuration"], governance["account_id"])
    c.require(config is not None, "application configuration disabled")
    history = governance.get("predecessor_read")
    c.require(config.get("predecessor_read") == history, "protected predecessor selector/configuration")
    reference = governance.get("lifecycle_predecessor")
    c.require((history is None) == (reference is None), "protected predecessor selector/reference composition")
    if history is not None:
        from tools.cnesdata_delivery.lifecycle_runtime import validate_predecessor_reference
        validate_predecessor_reference(governance)
    fields = "fragment_version account_id region application_role_arn application_role_name producer caller_by_purpose provider_arn lease evidence delegations trust_sha256 policy_sha256 enabled_until"
    c.closed(value, fields + (" predecessor_reads" if history is not None else ""))
    c.require(type(value["fragment_version"]) is int and value["fragment_version"] == 4
              and value["account_id"] == governance["account_id"] and value["region"] == "us-east-2", "private fragment version/account/region")
    session_policy.managed_arn(governance, "application")
    c.require(value["application_role_arn"] == governance["roles"]["application"]
              and value["application_role_name"] == value["application_role_arn"].rsplit("/", 1)[1], "private application role identity")
    c.require(value["provider_arn"] == "arn:aws:iam::" + governance["account_id"] + ":oidc-provider/token.actions.githubusercontent.com", "private original provider")
    c.closed(value["producer"], "repository workflow_path workflow_sha source_closure_sha256")
    c.require(value["producer"] == {"repository": "VINIClUS/infra-ansible", "workflow_path": ".github/workflows/reusable-cnesdata-application-gate.yml",
        "workflow_sha": c.digest(governance["gate_shas"]["application"], 40),
        "source_closure_sha256": c.digest(governance["application_source_closure_sha256"])}, "private immutable producer closure")
    c.require(value["caller_by_purpose"] == lc.APPLICATION_CALLERS, "private exact purpose callers")
    c.require(value["lease"] == {"bucket_arn": "arn:aws:s3:::" + governance["state_bucket"], "key": KEY,
                                "kms_key_arn": governance["state_kms_key_arn"]}, "private original coordination locus")
    c.require(value["evidence"] == {"bucket_arn": "arn:aws:s3:::" + governance["evidence_bucket"],
                                   "prefix": session_policy._prefix(governance) + "lifecycle/",
                                   "kms_key_arn": governance["evidence_kms_key_arn"]}, "private original evidence locus")
    c.require(value["delegations"] == config["delegations"] == governance["application_delegations"], "private original ten delegations")
    c.require(value["application_role_name"] == config["role_name"]
              and value["producer"]["workflow_sha"] == config["workflow_sha"]
              and value["producer"]["source_closure_sha256"] == config["source_closure_sha256"]
              and value["enabled_until"] == config["enabled_until"], "private original raw configuration")
    for key in ("trust_sha256", "policy_sha256"):
        c.digest(value[key])
    c.require(now + 3600 <= c.instant(value["enabled_until"]), "private application expiry for full session")
    if history is not None:
        selected = value["predecessor_reads"]
        c.closed(selected, "protocol source_sha run_id run_attempt status purpose object_arns policy_sha256")
        session_policy.predecessor_keys(governance, {key: selected[key] for key in history})
        keys = session_policy.predecessor_keys(governance, history)
        arns = ["arn:aws:s3:::" + governance["evidence_bucket"] + "/" + key for key in keys]
        c.require({k: selected[k] for k in history} == history and selected["object_arns"] == arns, "private exact predecessor inventory")
        c.require(selected["policy_sha256"] == _terraform_document_digest(session_policy.predecessor_policy(governance, history)),
                  "private independently derived predecessor policy")
    return value


def _iam_document(value):
    if type(value) is str:
        value = c.loads(unquote(value).encode(), limit=65536)
    c.require(type(value) is dict, "IAM original document")
    return value


def _terraform_document_digest(value):
    # Terraform jsonencode has no final LF and escapes these HTML/JS codepoints.
    raw = c.canonical(_iam_document(value), limit=65536)[:-1].decode()
    for char, escaped in (("<", r"\u003c"), (">", r"\u003e"), ("&", r"\u0026"), ("\u2028", r"\u2028"), ("\u2029", r"\u2029")):
        raw = raw.replace(char, escaped)
    return c.sha(raw.encode())


def verify_application(aws, authority, session_expires, guard, *, clock=time.time, include_documents=False):
    """Read back exact original identity and unattached managed policy, guarded."""
    fragment = authority.application_fragment
    c.require(type(fragment) is dict, "original application fragment authority absent")
    c.require(authority.pin["role_arn"] == fragment["application_role_arn"], "application owner pin/fragment identity")
    class Guarded:
        def call(self, service, operation, **kwargs):
            c.require(clock() < session_expires <= min(authority.expires_at, c.instant(fragment["enabled_until"])), "application readback expiry")
            guard.check(20)
            result = aws.call(service, operation, **kwargs)
            guard.check()
            return result
    client = Guarded()
    verify_managed(client, authority, session_expires, clock=clock)
    name = fragment["application_role_name"]
    policies = {"cnesdata-application-coordination": fragment["policy_sha256"]}
    if "predecessor_reads" in fragment:
        policies["cnesdata-application-predecessor-read"] = fragment["predecessor_reads"]["policy_sha256"]
    observed, original_documents = [], {}
    for _ in range(2):
        role = client.call("iam", "get_role", RoleName=name)["Role"]
        c.require(role["RoleName"] == name and role["Arn"] == fragment["application_role_arn"]
                  and role["MaxSessionDuration"] == 3600 and role.get("PermissionsBoundary") is None
                  and type(role["RoleId"]) is str and bool(role["RoleId"]), "original application role metadata")
        c.require(_terraform_document_digest(role["AssumeRolePolicyDocument"]) == fragment["trust_sha256"], "original application trust readback")
        inline = client.call("iam", "list_role_policies", RoleName=name, MaxItems=100)
        attached = client.call("iam", "list_attached_role_policies", RoleName=name, MaxItems=100)
        c.require(inline.get("IsTruncated") is False and len(inline["PolicyNames"]) == len(policies)
                  and set(inline["PolicyNames"]) == set(policies), "exact application inline policy inventory")
        c.require(attached.get("IsTruncated") is False and attached["AttachedPolicies"] == [], "application has no attached policies")
        for policy, digest in policies.items():
            response = client.call("iam", "get_role_policy", RoleName=name, PolicyName=policy)
            c.require(response["RoleName"] == name and response["PolicyName"] == policy
                      and _terraform_document_digest(response["PolicyDocument"]) == digest, "original application inline policy readback")
            original_documents[policy] = _iam_document(response["PolicyDocument"])
        observed.append(role["RoleId"])
    c.require(observed[0] == observed[1], "application identity replaced during readback")
    verify_managed(client, authority, session_expires, clock=clock)
    report = {"fragment_sha256": c.sha(c.canonical(fragment)), "trust_sha256": fragment["trust_sha256"],
              "policy_sha256": fragment["policy_sha256"], "managed_policy_sha256": authority.pin["document_sha256"]}
    if include_documents:
        statements = []
        for policy in policies:
            document = original_documents[policy]
            c.closed(document, "Version Statement" + (" Id" if "Id" in document else ""))
            c.require(document["Version"] == "2012-10-17" and type(document["Statement"]) is list, "native application policy statements")
            statements.extend(document["Statement"])
        report |= {"role_id": observed[-1], "documents": {"application_identity": {"Version": "2012-10-17", "Statement": statements},
                                                        "application_managed": authority.pin["document"]}}
    return c.loads(c.canonical(report), canonical=True)


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
