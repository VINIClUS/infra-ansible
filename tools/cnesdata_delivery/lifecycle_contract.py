"""Closed lifecycle oracles; authority is authenticated by lifecycle_runtime.

The legacy plan/apply envelopes and 1980-second initial admission remain separate.
No credentials, network, caller commands or lifecycle side effects in this module.
"""
import time
import re

from tools.cnesdata_delivery import contract as c

APPLICATION_CONTEXTS = {"promotion": "promotion", "mode-readiness-drill": "readiness"}
APPLICATION_CALLERS = {
    purpose: {"repository": c.REPOSITORY, "workflow_path": ".github/workflows/" + workflow,
              "ref": "refs/heads/develop", "environment": "production"}
    for purpose, workflow in (("promotion", "promote-production.yml"),
                              ("mode-readiness-drill", "readiness-production.yml"))
}
APPLICATION_DELEGATIONS = {
    "observer": "static-observer", "normal": "static-normal", "recovery": "static-recovery",
    "seeder": "canary-seeder", "verifier": "canary-verifier", "fence_operator": "promotion-fence-operator",
    "mode_seed": "mode-seed", "mode_dispatch": "mode-dispatch",
    "mode_audit_launch": "mode-audit-launch", "mode_observe": "mode-observe",
}


MODE_SESSION_OPERATIONS = {
    "unit-seed": ("us", "mode_seed", "promotion", "unit"),
    "unit-start": ("ux", "mode_dispatch", "promotion", "unit"),
    "unit-observe": ("uo", "mode_observe", "promotion", "unit"),
    "recovery-seed": ("rs", "mode_seed", "promotion", "recovery"),
    "recovery-start": ("rx", "mode_dispatch", "promotion", "recovery"),
    "recovery-observe": ("ro", "mode_observe", "promotion", "recovery"),
    "audit-start": ("ax", "mode_audit_launch", "promotion", "audit"),
    "audit-observe": ("ao", "mode_observe", "promotion", "audit"),
    "drill-seed": ("ds", "mode_seed", "readiness", "readiness"),
    "drill-unit-start": ("dx", "mode_dispatch", "readiness", "readiness"),
    "drill-recovery-start": ("dr", "mode_dispatch", "readiness", "readiness"),
    "drill-hang-first": ("h1", "mode_dispatch", "readiness", "readiness"),
    "drill-hang-second": ("h2", "mode_dispatch", "readiness", "readiness"),
    "drill-observe": ("do", "mode_observe", "readiness", "readiness"),
}
CALLER_BINDING_FIELDS = ("application_purpose context_kind repository workflow_path ref environment source_sha "
                         "run_id run_attempt producer_workflow_sha producer_source_closure_sha256")
ADAPTER_INPUTS = {
    "inventory": "candidate dashboard-artifact archive static-baseline",
    "close-drain": "activation canary membership",
    "closed-ready": "activation close-drain phase-b membership",
    "publish-static": "candidate dashboard-artifact static-plan inventory host-receipt",
    "rollback-api-static": "static-plan inventory publication host-recovery-receipt recovery-decision",
    "reopen": "activation routing canaries membership",
    "terminal-readback": "routing membership host-receipt static-receipt decision",
}
ADAPTER_STAGES = {
    "inventory": {"application-prepare"}, "close-drain": {"application-prepare"}, "closed-ready": {"api"},
    "publish-static": {"static"}, "rollback-api-static": {"recovery"}, "reopen": {"final", "recovery"},
    "terminal-readback": {"application-prepare", "final", "recovery"},
}
ADAPTER_OBSERVATIONS = {
    "inventory": "inventory", "close-drain": "close-drain", "closed-ready": "closed-ready",
    "publish-static": "publication", "rollback-api-static": "rollback", "reopen": "routing", "terminal-readback": "terminal",
}
ADAPTER_STAGE_FIELDS = "close fixed_deadline input_deadline stage admitted_at deadline decision preparation_deadline sequence checkpoint_sha256"
FENCE_PREPARE_PRODUCER = {
    "workflow_path": ".github/workflows/reusable-cnesdata-infra-deploy-gate.yml", "job": "execute", "step_id": "gate",
    "step_name": "Execute under CAS watchdog and verify final publication", "step": "application-prepare-operational",
    "job_name": "application-prepare-operational / execute", "purpose": "application-prepare", "mode": "operational", "direction": "advance",
}
FENCE_PREPARE_FILES = frozenset({"checkpoint.json", "approval.json", "fence-prepared.json", "fence-role.json",
                               "fence-readbacks.json", "fence-origins.json", "fence-chain.json", "fence-evaluation.json"})
FENCE_ORIGIN_FIELDS = "repository source_sha run_id run_attempt job_id artifact_id artifact_digest producer_name step name sha256 size"
FENCE_PHASE_A_FILES = frozenset({"envelope.json", "checkpoint.json", "drift.json"})
FENCE_HISTORY_GAPS = frozenset({"plan.json", "inputs.tfvars.json"})
FENCE_EVALUATION_CASES = {
    "assume-exact": "sts:AssumeRole", "assume-other-session": "sts:AssumeRole", "app-direct-get": "dynamodb:GetItem",
    "get-fence": "dynamodb:GetItem", "get-tenant": "dynamodb:GetItem", "update-fence": "dynamodb:UpdateItem",
    "probe-own": "states:DescribeExecution", "probe-foreign": "states:DescribeExecution", "write-own-evidence": "s3:PutObject",
    "put-lease": "s3:PutObject", "freeze-expired": "dynamodb:GetItem",
}
FENCE_SCHEMAS = {
    "fence-prepared.json": "schema_version proof_kind operation application_purpose context_kind owner caller_binding_sha256 activation_sha256 application_fragment_sha256 producer preparation files outcome",
    "fence-role.json": "schema_version role_arn role_name role_id policy_name release_id session_name trust policy max_session_duration tags original_projection_sha256 current_projection_sha256",
    "fence-origins.json": "schema_version phase_a current_source_sha current_source_closure_sha256 current_plan projection_source_files",
    "fence-chain.json": "schema_version owner_sha256 generation anchor_sha256 head_sha256 entries",
    "fence-evaluation.json": "schema_version evaluator_source_sha documents cases",
    "fence-readbacks.json": "proof_kind readbacks",
}


def _fence_origin(value):
    c.closed(value, FENCE_ORIGIN_FIELDS)
    c.require(value["repository"] == c.REPOSITORY, "fence original repository")
    for key in ("run_id", "run_attempt", "job_id", "artifact_id"):
        c.integer(value[key])
    c.integer(value["size"], 1, 128 * 1024**2)
    c.digest(value["source_sha"], 40)
    c.digest(value["sha256"])
    c.require(value["artifact_digest"] == "sha256:" + c.digest(value["artifact_digest"].removeprefix("sha256:")), "fence artifact digest")
    c.require(type(value["producer_name"]) is str and 1 <= len(value["producer_name"]) <= 128
              and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value["step"])
              and re.fullmatch(r"[a-z][a-z0-9.-]{0,63}\.(?:json|bin)", value["name"]), "fence original finite file/producer")


def _fence_state(value):
    c.closed(value, "lineage serial state_sha256")
    c.require(type(value["lineage"]) is str and 1 <= len(value["lineage"]) <= 128, "fence state lineage")
    c.integer(value["serial"], 0)
    c.digest(value["state_sha256"])


def _fence_readback_document(value, role, preparation):
    from email.utils import parsedate_to_datetime
    c.require(value["proof_kind"] == "iam-readback-and-evaluation" and type(value["readbacks"]) is list
              and len(value["readbacks"]) == 2, "fence two original readbacks")
    operations = ("get_role", "list_role_policies", "list_attached_role_policies", "get_role_policy")
    previous, bodies, request_ids = None, None, set()
    for row in value["readbacks"]:
        c.closed(row, "observed_at observations")
        c.integer(row["observed_at"])
        c.require(preparation["admitted_at"] <= row["observed_at"] < preparation["deadline"]
                  and (previous is None or row["observed_at"] >= previous + 10), "fence original spaced observation")
        c.require(type(row["observations"]) is list and len(row["observations"]) == 4, "fence eight exact IAM reads")
        current = []
        for operation, report in zip(operations, row["observations"]):
            c.closed(report, "service operation parameters response")
            parameters = {"RoleName": role["role_name"]}
            if operation.startswith("list_"):
                parameters["MaxItems"] = 100
            if operation == "get_role_policy":
                parameters["PolicyName"] = role["policy_name"]
            c.require(report["service"] == "iam" and report["operation"] == operation
                      and report["parameters"] == parameters, "fence exact readback request")
            response = report["response"]
            c.require(type(response) is dict and "ResponseMetadata" in response, "fence native response")
            metadata = response["ResponseMetadata"]
            c.closed(metadata, "RequestId HTTPStatusCode HTTPHeaders" + (" RetryAttempts" if "RetryAttempts" in metadata else ""))
            c.require(type(metadata["RequestId"]) is str and 1 <= len(metadata["RequestId"]) <= 256
                      and metadata["RequestId"] not in request_ids and type(metadata["HTTPStatusCode"]) is int
                      and metadata["HTTPStatusCode"] == 200 and type(metadata["HTTPHeaders"]) is dict, "fence original request metadata")
            request_ids.add(metadata["RequestId"])
            c.require(all(type(k) is str and type(v) is str and len(k) <= 128 and len(v) <= 4096 for k, v in metadata["HTTPHeaders"].items()), "fence bounded SDK headers")
            date = parsedate_to_datetime(metadata["HTTPHeaders"]["date"])
            c.require(date.tzinfo is not None and abs(date.timestamp() - row["observed_at"]) <= 30, "fence original SDK clock")
            body = {key: item for key, item in response.items() if key != "ResponseMetadata"}
            if operation == "get_role":
                c.closed(body, "Role")
                item = body["Role"]
                expected = {"RoleName": role["role_name"], "Arn": role["role_arn"], "RoleId": role["role_id"], "MaxSessionDuration": 3600,
                            "AssumeRolePolicyDocument": role["trust"], "Tags": [{"Key": "ReleaseId", "Value": role["release_id"]}]}
                c.require(set(expected) <= set(item) <= set(expected) | {"Path", "CreateDate", "Description", "RoleLastUsed"}
                          and all(c.canonical(item[key]) == c.canonical(expected[key]) for key in expected), "fence original role projection")
            elif operation == "get_role_policy":
                c.require(body == {"RoleName": role["role_name"], "PolicyName": role["policy_name"], "PolicyDocument": role["policy"]}, "fence original policy readback")
            else:
                expected = {"PolicyNames": [role["policy_name"]], "IsTruncated": False} if operation == "list_role_policies" else {"AttachedPolicies": [], "IsTruncated": False}
                c.require(c.canonical(body) == c.canonical(expected), "fence exact inline/attached inventory")
            current.append(body)
        c.require(bodies is None or c.canonical(bodies) == c.canonical(current), "fence identity/documents changed between reads")
        previous, bodies = row["observed_at"], current
    c.require(previous == preparation["observed_at"], "fence original completed observation")


def validate_fence_checkpoint_chain(chain, checkpoint_raw, owner, *, anchor_sha256, original_state):
    """Validate a chain whose original bytes/producer are independently protected."""
    c.closed(chain, FENCE_SCHEMAS["fence-chain.json"])
    c.require(type(chain["schema_version"]) is int and chain["schema_version"] == 1, "fence chain schema")
    c.require(chain["owner_sha256"] == owner["owner_sha256"] and type(chain["generation"]) is int and chain["generation"] == owner["generation"]
              and type(chain["entries"]) is list and 1 <= len(chain["entries"]) <= 256, "fence current keeper ancestry")
    previous, serial = c.digest(chain["anchor_sha256"]), original_state["serial"]
    c.require(previous == anchor_sha256, "fence original historical anchor")
    for sequence, entry in enumerate(chain["entries"]):
        c.closed(entry, "sequence checkpoint_sha256 previous_checkpoint_sha256 state state_object origin")
        c.require(type(entry["sequence"]) is int and entry["sequence"] == sequence and entry["previous_checkpoint_sha256"] == previous, "fence ordered checkpoint ancestry")
        _fence_state(entry["state"])
        c.closed(entry["state_object"], "status version_id etag_sha256")
        c.require(entry["state_object"]["status"] == "present" and type(entry["state_object"]["version_id"]) is str
                  and bool(entry["state_object"]["version_id"]) and entry["state_object"]["version_id"] != "null", "fence current state object")
        c.digest(entry["state_object"]["etag_sha256"])
        _fence_origin(entry["origin"])
        c.require(entry["state"]["lineage"] == original_state["lineage"] and entry["state"]["serial"] >= serial
                  and all(entry["origin"][key] == owner[key] for key in ("source_sha", "run_id", "run_attempt"))
                  and entry["origin"]["sha256"] == entry["checkpoint_sha256"], "fence current lineage/original checkpoint")
        previous, serial = c.digest(entry["checkpoint_sha256"]), entry["state"]["serial"]
    checkpoint = c.loads(checkpoint_raw, canonical=True)
    c.closed(checkpoint, "state state_object owner purpose plan_sha256 readbacks")
    _fence_state(checkpoint["state"])
    c.require(chain["head_sha256"] == previous == c.sha(checkpoint_raw)
              and c.canonical(checkpoint["owner"]) == c.canonical(owner)
              and c.canonical(checkpoint["state"]) == c.canonical(chain["entries"][-1]["state"])
              and c.canonical(checkpoint["state_object"]) == c.canonical(chain["entries"][-1]["state_object"]), "fence original current checkpoint")
    return checkpoint


def validate_fence_prepared_package(files, *, owner, fragment, activation_sha256, producer, preparation, originals):
    """Closed codec against protected originals; never a provenance/capability API.

    The protected producer must authenticate the arguments and derive original
    role/source/evaluation/chain documents before calling. The current transport
    cannot yet supply all historical Phase A inputs; privileged wiring is closed.
    """
    c.require(type(files) is dict and set(files) == FENCE_PREPARE_FILES, "fence exact private inventory")
    c.require(type(originals) is dict and set(originals) == FENCE_PREPARE_FILES - {"fence-prepared.json"}, "fence complete protected original documents")
    c.closed(fragment, "fragment_version account_id region application_role_arn application_role_name producer caller_by_purpose provider_arn lease evidence delegations trust_sha256 policy_sha256 enabled_until"
             + (" predecessor_reads" if "predecessor_reads" in fragment else ""))
    c.require(type(fragment.get("fragment_version")) is int and fragment["fragment_version"] == 4
              and fragment["caller_by_purpose"] == APPLICATION_CALLERS, "fence current schema4 authority")
    c.require(application_identity(owner, required=True)["application_purpose"] == "promotion", "fence only current promotion owner")
    c.closed(owner, " ".join(OWNER_FIELDS + ["owner_sha256", *APPLICATION_OWNER_FIELDS]))
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(owner[key])
    c.require(owner["repository"] == c.REPOSITORY, "fence current owner repository")
    c.digest(owner["source_sha"], 40)
    for key in ("owner_sha256", "release_sha256", "session_sha256"):
        c.digest(owner[key])
    c.require(fragment["delegations"] == {alias: "arn:aws:iam::" + fragment["account_id"] + ":role/cnesdata-prod-" + suffix
                                         for alias, suffix in APPLICATION_DELEGATIONS.items()}, "fence current ten aliases")
    values = {}
    for name, raw in files.items():
        c.require(type(raw) is bytes and 0 < len(raw) <= 1024**2, "fence private file bound")
        values[name] = c.loads(raw, canonical=True, limit=1024**2)
        if name in FENCE_SCHEMAS:
            c.closed(values[name], FENCE_SCHEMAS[name])
        if name != "fence-prepared.json":
            c.require(raw == originals[name], "fence original producer bytes")
        if "schema_version" in values[name]:
            c.require(type(values[name]["schema_version"]) is int and values[name]["schema_version"] == 1, "fence document schema")
    manifest = values["fence-prepared.json"]
    c.require(manifest["proof_kind"] == "iam-readback-and-evaluation" and manifest["operation"] == "closed-ready"
              and manifest["application_purpose"] == manifest["context_kind"] == "promotion"
              and manifest["outcome"] == "observed", "fence observation only, not adapter acceptance")
    c.require(c.canonical(manifest["owner"]) == c.canonical(owner)
              and manifest["caller_binding_sha256"] == owner["caller_binding_sha256"]
              and manifest["activation_sha256"] == c.digest(activation_sha256)
              and manifest["application_fragment_sha256"] == c.sha(c.canonical(fragment)), "fence original current binding")
    c.closed(manifest["producer"], "repository source_sha workflow_sha run_id run_attempt job_id " + " ".join(FENCE_PREPARE_PRODUCER))
    c.require(c.canonical(manifest["producer"]) == c.canonical(producer) and all(producer[key] == value for key, value in FENCE_PREPARE_PRODUCER.items())
              and all(producer[key] == owner[key] for key in ("repository", "source_sha", "run_id", "run_attempt")), "fence protected deploy producer")
    c.digest(producer["workflow_sha"], 40)
    for key in ("run_id", "run_attempt", "job_id"):
        c.integer(producer[key])
    c.closed(manifest["preparation"], "admitted_at deadline observed_at")
    c.require(c.canonical(manifest["preparation"]) == c.canonical(preparation), "fence original preparation window")
    for value in preparation.values():
        c.integer(value)
    c.require(preparation["admitted_at"] <= preparation["observed_at"] < preparation["deadline"] <= preparation["admitted_at"] + 900,
              "fence preparation is not future F")
    expected = [{"name": name, "sha256": c.sha(files[name]), "size": len(files[name])} for name in sorted(FENCE_PREPARE_FILES - {"fence-prepared.json"})]
    c.require(c.canonical(manifest["files"]) == c.canonical(expected), "fence complete private commitments without self hash")
    origins, role, chain = (values[name] for name in ("fence-origins.json", "fence-role.json", "fence-chain.json"))
    old = origins["phase_a"]
    c.closed(old, "source_sha source_closure_sha256 release_id canary_id candidate_sha256 plan_binary_sha256 plan_json_sha256 inputs_sha256 plan_receipt state files")
    c.require(origins["current_source_sha"] == owner["source_sha"], "fence current and historical sources distinguished")
    c.digest(origins["current_source_closure_sha256"])
    current_plan = origins["current_plan"]
    c.closed(current_plan, "source_sha run_id run_attempt step index_sha256 plan_binary_sha256 plan_json_sha256 inputs_sha256")
    c.require(all(c.canonical(current_plan[key]) == c.canonical(owner[key]) for key in ("source_sha", "run_id", "run_attempt"))
              and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", current_plan["step"]), "fence distinct original current plan")
    for key in ("index_sha256", "plan_binary_sha256", "plan_json_sha256", "inputs_sha256"):
        c.digest(current_plan[key])
    source_files = origins["projection_source_files"]
    c.require(type(source_files) is list and 1 <= len(source_files) <= 64, "fence finite projection closure")
    paths = []
    for item in source_files:
        c.closed(item, "path sha256")
        c.require(re.fullmatch(r"infra/opentofu/(?:env/prod|modules/[a-z0-9-]+)/[a-z0-9_.-]+\.tf", item["path"]), "fence original source path")
        c.digest(item["sha256"])
        paths.append(item["path"])
    c.require(paths == sorted(set(paths)), "fence exact projection source inventory")
    c.digest(old["source_sha"], 40)
    for key in ("source_closure_sha256", "candidate_sha256", "plan_binary_sha256", "plan_json_sha256", "inputs_sha256"):
        c.digest(old[key])
    for key in ("release_id", "canary_id"):
        c.require(type(old[key]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", old[key]), "fence original release identity")
    c.require(type(old["files"]) is dict and set(old["files"]) == FENCE_PHASE_A_FILES, "fence Phase A original inventory")
    for name, reference in old["files"].items():
        _fence_origin(reference)
        c.require(reference["name"] == name and reference["source_sha"] == old["source_sha"], "fence original Phase A source/file")
    c.closed(old["plan_receipt"], "plan_binding_sha256 consumed_plan_artifact")
    c.digest(old["plan_receipt"]["plan_binding_sha256"])
    consumed = old["plan_receipt"]["consumed_plan_artifact"]
    c.closed(consumed, "artifact_id artifact_sha256 run_id run_attempt")
    for key in ("artifact_id", "run_id", "run_attempt"):
        c.integer(consumed[key])
    c.digest(consumed["artifact_sha256"])
    # These commitments come from the authenticated applied envelope. Requiring
    # raw binary/candidate bytes would add no input to the finite role resolver.
    _fence_state(old["state"])
    c.require(role["role_name"] == "cnesdata-prod-promotion-fence-operator"
              and role["role_arn"] == fragment["delegations"]["fence_operator"]
              and role["policy_name"] == role["role_name"] + "-gate"
              and role["release_id"] == old["canary_id"] and role["session_name"] == "promotion-fence-" + old["canary_id"], "fence original release/session")
    c.require(type(role["role_id"]) is str and bool(role["role_id"]) and type(role["max_session_duration"]) is int
              and role["max_session_duration"] == 3600 and role["tags"] == {"ReleaseId": old["canary_id"]}, "fence original role identity/tags")
    expected_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": fragment["application_role_arn"]},
        "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:RoleSessionName": role["session_name"]}}}]}
    c.require(role["trust"] == expected_trust, "fence original trust compatible with current schema4 principal")
    projection = {key: role[key] for key in ("role_arn", "role_name", "role_id", "policy_name", "trust", "policy", "max_session_duration", "tags")}
    c.require(role["original_projection_sha256"] == role["current_projection_sha256"] == c.sha(c.canonical(projection)), "fence role projection, not entire historical state")
    checkpoint = validate_fence_checkpoint_chain(chain, files["checkpoint.json"], owner,
        anchor_sha256=old["files"]["checkpoint.json"]["sha256"], original_state=old["state"])
    c.require(current_plan["plan_binary_sha256"] == checkpoint["plan_sha256"], "fence current applied saved plan")
    approval = values["approval.json"]
    c.require(current_plan["inputs_sha256"] == approval["inputs_sha256"], "fence current original inputs")
    c.closed(approval, "version owner purpose direction plan_sha256 inputs_sha256 checkpoint_sha256 delta drift_matrix readbacks")
    c.closed(approval["delta"], "purpose direction mode before original created expected_changes_sha256")
    c.require(type(approval["version"]) is int and approval["version"] == 1 and c.canonical(approval["owner"]) == c.canonical(owner)
              and approval["purpose"] == checkpoint["purpose"] == "application-prepare" and approval["direction"] == "advance"
              and approval["plan_sha256"] == checkpoint["plan_sha256"]
              and all(approval["delta"][key] == FENCE_PREPARE_PRODUCER[key] for key in ("purpose", "direction", "mode")), "fence original applied deploy branch")
    _fence_readback_document(values["fence-readbacks.json"], role, preparation)
    evaluation = values["fence-evaluation.json"]
    c.require(evaluation["evaluator_source_sha"] == producer["workflow_sha"], "fence original evaluator source")
    c.closed(evaluation["documents"], "application_identity application_managed application_session fence_identity fence_session freeze")
    for digest in evaluation["documents"].values():
        c.digest(digest)
    c.require(type(evaluation["cases"]) is list and len(evaluation["cases"]) == len(FENCE_EVALUATION_CASES), "fence complete effective IAM cases")
    seen = set()
    for case in evaluation["cases"]:
        c.closed(case, "case_id action resource context expected observed")
        c.require(case["case_id"] in FENCE_EVALUATION_CASES and case["case_id"] not in seen
                  and case["action"] == FENCE_EVALUATION_CASES[case["case_id"]]
                  and type(case["resource"]) is str and 1 <= len(case["resource"]) <= 2048 and type(case["context"]) is dict
                  and type(case["expected"]) is bool and type(case["observed"]) is bool and case["expected"] == case["observed"], "fence original IAM evaluation result")
        c.require(set(case["context"]) <= {"sts:RoleSessionName", "dynamodb:LeadingKeys", "aws:CurrentTime"}, "fence finite IAM context keys")
        for key, value in case["context"].items():
            if key == "dynamodb:LeadingKeys":
                c.require(type(value) is list and len(value) <= 2 and all(type(x) is str and len(x) <= 128 for x in value), "fence finite IAM leading keys")
            else:
                c.require(type(value) is str and 1 <= len(value) <= 128, "fence finite IAM context value")
        seen.add(case["case_id"])
    return manifest


def validate_adapter_request(raw, *, operation, owner, window, inputs, activation_sha256):
    """ABI2 byte binding only; provenance and domain validators remain mandatory.

    The old generic canary adapter route is deliberately unavailable: #499 uses
    different identities and producers that must be integrated before dispatch.
    """
    request = c.loads(raw, canonical=True, limit=128 * 1024)
    c.closed(request, "abi_version operation repository source_sha owner checkpoint_sha256 activation_sha256 stage inputs")
    c.require(type(request["abi_version"]) is int and request["abi_version"] == 2
              and operation in ADAPTER_INPUTS and request["operation"] == operation, "closed adapter ABI/operation")
    identity = application_identity(owner, required=True)
    c.require(identity["application_purpose"] == "promotion" and application_identity(window, required=True) == identity,
              "original adapter purpose/caller")
    c.require(request["repository"] == owner["repository"] == c.REPOSITORY
              and request["source_sha"] == c.digest(owner["source_sha"], 40), "adapter original source")
    c.closed(request["owner"], " ".join(OWNER_FIELDS) + " owner_sha256")
    c.require(request["owner"] == {key: owner[key] for key in [*OWNER_FIELDS, "owner_sha256"]}, "adapter original owner")
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(request["owner"][key])
    for key in ("release_sha256", "session_sha256", "owner_sha256"):
        c.digest(request["owner"][key])
    c.closed(request["stage"], ADAPTER_STAGE_FIELDS)
    c.require(request["stage"] == {key: window[key] for key in ADAPTER_STAGE_FIELDS.split()}
              and window["stage"] in ADAPTER_STAGES[operation], "adapter original stage")
    c.require(request["checkpoint_sha256"] == c.digest(window["checkpoint_sha256"])
              and request["activation_sha256"] == c.digest(activation_sha256), "adapter original checkpoint/activation")
    c.closed(request["inputs"], ADAPTER_INPUTS[operation])
    c.require(type(inputs) is dict and set(inputs) == set(request["inputs"]), "adapter complete original input inventory")
    for name, reference in request["inputs"].items():
        c.closed(reference, "sha256 size")
        c.integer(reference["size"], 1, 128 * 1024**2)
        c.require(type(inputs[name]) is bytes and len(inputs[name]) == reference["size"]
                  and c.sha(inputs[name]) == c.digest(reference["sha256"]), "adapter original input bytes")
    return request


def validate_adapter_result(raw, *, request, observations, call_receipts, pending, unknown):
    """Compare with the shared broker journal, never an adapter success flag."""
    result = c.loads(raw, canonical=True, limit=128 * 1024)
    c.closed(result, "abi_version operation owner_sha256 generation checkpoint_sha256 observations call_receipts_sha256 pending unknown")
    c.integer(result["generation"])
    c.require(type(result["abi_version"]) is int and result["abi_version"] == 2
              and result["operation"] == request["operation"] in ADAPTER_INPUTS
              and result["owner_sha256"] == request["owner"]["owner_sha256"]
              and result["generation"] == request["owner"]["generation"]
              and result["checkpoint_sha256"] == request["checkpoint_sha256"], "adapter result original binding")
    c.require(type(result["observations"]) is list and result["observations"] == observations, "adapter registered observations")
    for item in result["observations"]:
        c.closed(item, "kind sha256 size")
        c.require(item["kind"] == ADAPTER_OBSERVATIONS[result["operation"]], "adapter operation observation")
        c.digest(item["sha256"])
        c.integer(item["size"], 1, 1024**2)
    c.require(type(call_receipts) is list and result["call_receipts_sha256"] == c.sha(c.canonical(call_receipts)),
              "adapter original call receipts")
    for key, original in (("pending", pending), ("unknown", unknown)):
        c.require(type(result[key]) is list and result[key] == original, "adapter uncertainty must be preserved")
        for item in result[key]:
            c.closed(item, "kind reference_sha256")
            c.require(type(item["kind"]) is str and 1 <= len(item["kind"]) <= 64, "adapter uncertainty kind")
            c.digest(item["reference_sha256"])
    return result


def _product_context_bytes(value):
    """Product A3 UTF-8 codec; deliberately distinct from ASCII session names."""
    import json
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    c.require(len(raw) <= 131072, "mode context full request bound")
    return raw


def decode_mode_context(inputs_raw):
    """Decode the adopted wrapper inside the entire bounded generated request.

    This codec accepts no alternate representation or silent normalization. Its
    return is not admission: all fifteen manifest fields require semantic and
    original-evidence validation separately.
    """
    inputs = c.loads(inputs_raw, limit=131072)
    c.require(_product_context_bytes(inputs) == inputs_raw and type(inputs) is dict
              and type(inputs.get("mode_canary")) is dict, "mode context original request bytes")
    wrapper = inputs["mode_canary"].get("context_manifest")
    c.closed(wrapper, "canonical_utf8 sha256")
    c.require(type(wrapper["canonical_utf8"]) is str, "mode context UTF-8 text")
    raw = wrapper["canonical_utf8"].encode("utf-8")
    c.require(c.sha(raw) == c.digest(wrapper["sha256"]), "mode context inner bytes digest")
    manifest = c.loads(raw, limit=131072)
    c.require(type(manifest) is dict and _product_context_bytes(manifest) == raw, "mode context canonical inner bytes")
    return manifest, raw


def validate_mode_context(inputs_raw, *, owner, application_purpose, originals):
    """Bind the adopted manifest to protected originals and derive finite sessions.

    The caller must authenticate owner and every original producer before using
    this pure check. This neither admits STS nor proves the mode policy oracle.
    """
    manifest, raw = decode_mode_context(inputs_raw)
    original_fields = ("product_source_sha product_source_closure_sha256 shared_source_sha shared_source_closure_sha256 "
                       "release_id activation_sha256 resources_sha256 fixture_manifest_sha256 scenario_plan_sha256 "
                       "predecessor_terminal_sha256 admitted_at deadline")
    owner_fields = "repository run_id run_attempt generation owner_sha256"
    c.closed(manifest, "schema_version context_kind owner " + original_fields)
    c.closed(originals, original_fields)
    c.closed(manifest["owner"], owner_fields)
    identity = application_identity(owner, required=True)
    c.require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 2
              and application_purpose == identity["application_purpose"]
              and manifest["context_kind"] == identity["context_kind"], "mode context original purpose/schema")
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(manifest["owner"][key])
        c.integer(owner[key])
    c.require(manifest["owner"]["repository"] == c.REPOSITORY
              and manifest["owner"] == {key: owner[key] for key in owner_fields.split()}, "mode context original owner")
    c.digest(manifest["owner"]["owner_sha256"])
    c.require(c.canonical({key: manifest[key] for key in original_fields.split()}) == c.canonical(originals),
              "mode context original producer commitments")
    for key in ("product_source_sha", "shared_source_sha"):
        c.digest(manifest[key], 40)
    c.require(manifest["product_source_sha"] == c.digest(owner["source_sha"], 40), "mode context current source")
    for key in ("product_source_closure_sha256", "shared_source_closure_sha256", "activation_sha256", "resources_sha256",
                "fixture_manifest_sha256", "scenario_plan_sha256"):
        c.digest(manifest[key])
    c.require(type(manifest["release_id"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", manifest["release_id"]),
              "mode context release id")
    predecessor = manifest["predecessor_terminal_sha256"]
    if predecessor is not None:
        c.digest(predecessor)
    c.require(manifest["context_kind"] != "readiness" or predecessor is not None, "readiness original predecessor")
    for key in ("admitted_at", "deadline"):
        c.integer(manifest[key])
    maximum = 900 if manifest["context_kind"] == "promotion" else 14400
    c.require(0 < manifest["deadline"] - manifest["admitted_at"] <= maximum, "mode context original bounded deadline")
    digest = c.sha(raw)
    sessions = {alias: [] for alias in ("mode_seed", "mode_dispatch", "mode_audit_launch", "mode_observe")}
    for operation, (_, alias, context, phase) in MODE_SESSION_OPERATIONS.items():
        if context != manifest["context_kind"]:
            continue
        binding = {key: manifest[key] for key in ("schema_version", "context_kind", "product_source_sha", "product_source_closure_sha256",
                   "shared_source_sha", "shared_source_closure_sha256", "release_id", "activation_sha256")}
        binding.update(manifest["owner"], operation=operation, phase=phase, context_manifest_sha256=digest)
        sessions[alias].append(mode_session(binding, application_purpose)["session_name"])
    return {"manifest": manifest, "context_manifest_sha256": digest,
            "delegation_sessions": {alias: sorted(set(names)) for alias, names in sessions.items()}}


def validate_closed_ready_call(*, request, role, service, operation, parameters, account, control_table_arn, machine_arn, members):
    """F2 request scope from protected resources and original frozen membership.

    This does not authenticate artifacts or replace the domain producer. The
    broker must validate those originals before providing these arguments.
    """
    c.require(request["operation"] == "closed-ready" and request["stage"]["stage"] == "api"
              and role == "fence_operator" and (service, operation) in {("dynamodb", "get_item"), ("stepfunctions", "describe_execution")},
              "closed-ready finite SDK operation")
    c.require(type(account) is str and re.fullmatch(r"[0-9]{12}", account), "closed-ready account")
    table = re.fullmatch(r"arn:aws:dynamodb:us-east-2:" + account + r":table/(cnesdata-prod-[A-Za-z0-9_.-]+)", control_table_arn)
    c.require(table and re.fullmatch(r"arn:aws:states:us-east-2:" + account + r":stateMachine:cnesdata-prod-[A-Za-z0-9_-]+", machine_arn),
              "closed-ready protected resource scope")
    if service == "dynamodb":
        c.closed(parameters, "TableName Key ConsistentRead")
        allowed = [{"TableName": table[1], "Key": {"pk": {"S": pk}, "sk": {"S": sk}}, "ConsistentRead": True}
                   for pk, sk in (("ENV#prod#FENCE", "FENCE"), ("ENV#prod#SEMAPHORE", "UNIT"))]
        c.require(any(c.canonical(parameters) == c.canonical(value) for value in allowed), "closed-ready strong original gate read")
        return parameters
    c.require(type(members) is list and len(members) <= 4096, "closed-ready frozen membership bound")
    executions, dispatches = set(), set()
    for member in members:
        c.closed(member, "dispatch_id request_sha256 generation initial_state execution_ref resolution proof_sha256 observed_at send_disabled_at")
        dispatch = c.digest(member["dispatch_id"], 16)
        c.require(dispatch not in dispatches, "closed-ready duplicate member")
        dispatches.add(dispatch)
        c.integer(member["generation"], 0)
        c.digest(member["request_sha256"])
        c.digest(member["proof_sha256"])
        execution = machine_arn.replace(":stateMachine:", ":execution:") + ":" + dispatch
        c.require((member["resolution"] == "TERMINAL" and member["execution_ref"] == execution)
                  or (member["resolution"] == "CANCEL_BEFORE_SEND" and member["execution_ref"] is None),
                  "closed-ready original member execution")
        executions.add(execution)
    c.closed(parameters, "executionArn includedData")
    c.require(parameters["executionArn"] in executions and parameters["includedData"] == "METADATA_ONLY",
              "closed-ready exact fresh metadata probe")
    return parameters


def closed_ready_probe_response(response, *, execution_arn, machine_arn):
    """Discard execution payloads before any receipt, artifact or adapter IPC."""
    c.require(type(response) is dict and response.get("input") in (None, "") and response.get("output") in (None, ""),
              "unexpected private execution payload")
    c.require(response.get("executionArn") == execution_arn and response.get("stateMachineArn") == machine_arn
              and response.get("name") == execution_arn.rsplit(":", 1)[1]
              and response.get("status") in {"RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"}
              and "startDate" in response, "closed-ready original execution response")
    return {key: response[key] for key in ("executionArn", "stateMachineArn", "name", "status", "startDate", "stopDate") if key in response}


def application_caller_binding(evidence, producer):
    """Exact codec for separately authenticated source/run/claim observations."""
    c.closed(evidence, CALLER_BINDING_FIELDS + " event fragment_version")
    purpose = evidence["application_purpose"]
    c.require(purpose in APPLICATION_CONTEXTS and evidence["context_kind"] == APPLICATION_CONTEXTS[purpose],
              "application purpose/context")
    c.require(type(evidence["fragment_version"]) is int and evidence["fragment_version"] == 4
              and evidence["event"] == "workflow_dispatch", "application original manual schema4 caller")
    c.require(all(evidence[k] == value for k, value in APPLICATION_CALLERS[purpose].items()), "application exact purpose caller")
    c.require(evidence["producer_workflow_sha"] == c.digest(producer["workflow_sha"], 40)
              and evidence["producer_source_closure_sha256"] == c.digest(producer["source_closure_sha256"]),
              "application original producer closure")
    c.digest(evidence["source_sha"], 40)
    for name in ("run_id", "run_attempt"):
        c.integer(evidence[name])
    return {key: evidence[key] for key in CALLER_BINDING_FIELDS.split()}


def mode_session(binding, application_purpose):
    """Fourteen nominal algorithms only; a codec is not a preparation receipt."""
    c.closed(binding, "schema_version context_kind operation phase repository product_source_sha product_source_closure_sha256 "
             "shared_source_sha shared_source_closure_sha256 release_id activation_sha256 run_id run_attempt generation owner_sha256 context_manifest_sha256")
    c.require(type(binding["schema_version"]) is int and binding["schema_version"] == 2
              and binding["repository"] == c.REPOSITORY and binding["operation"] in MODE_SESSION_OPERATIONS,
              "mode session nominal operation")
    code, alias, context, phase = MODE_SESSION_OPERATIONS[binding["operation"]]
    c.require(application_purpose in APPLICATION_CONTEXTS and APPLICATION_CONTEXTS[application_purpose] == context
              and binding["context_kind"] == context and binding["phase"] == phase, "mode session original purpose/phase")
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(binding[key])
    for key, value in binding.items():
        if key not in {"schema_version", "run_id", "run_attempt", "generation"}:
            c.require(type(value) is str and value.isascii(), "mode session ASCII strings")
    for key in ("product_source_sha", "shared_source_sha"):
        c.digest(binding[key], 40)
    for key in ("product_source_closure_sha256", "shared_source_closure_sha256", "activation_sha256", "owner_sha256", "context_manifest_sha256"):
        c.digest(binding[key])
    c.require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", binding["release_id"]), "mode session release id")
    digest = c.sha(c.canonical(binding))
    return {"alias": alias, "session_name": "mc-" + code + "-" + digest[:40], "binding_sha256": digest}


PURPOSES = frozenset({"application-prepare", "phase-b", "phase-c-recovery", "phase-c-audit", "static-maintenance"})
STAGES = {"phase-b": (360, 1020), "api": (180, 840), "static": (180, 660),
          "unit": (120, 540), "phase-c-recovery": (240, 300), "phase-c-audit": (240, 60),
          "final": (60, 0)}
OWNER_FIELDS = "repository source_sha run_id run_attempt release_sha256 generation session_sha256".split()
STATE_MACHINE = "module.processing.aws_sfn_state_machine.processor[0]"
API_POLICY = "module.runtime_iam.aws_iam_role_policy.api[0]"

# Pinned AWS6.54.0 native schema: computed=true, optional/required absent.
# Proof sha256 9a477dedf8b09ed69f33033917c72b7187bc1b415f90b1daaba972411255c123.
COMPUTED_OUTPUTS = {
    "aws_sfn_state_machine": {"arn", "creation_date", "description", "revision_id", "state_machine_version_arn", "status", "version_description"},
    "aws_scheduler_schedule": {"arn"},
    "aws_scheduler_schedule_group": {"arn", "creation_date", "last_modification_date", "state"},
    "aws_iam_role": {"arn", "create_date", "unique_id"},
    "aws_iam_role_policy": set(),
    "aws_cloudwatch_event_rule": {"arn"},
    "aws_cloudwatch_metric_alarm": {"arn"},
}


def scheduler_closure(mode):
    c.require(mode in {"recovery", "audit"}, "scheduler mode")
    fields = [f'aws_scheduler_schedule.mode["{mode}"]', f'aws_scheduler_schedule_group.mode["{mode}"]',
              f'aws_cloudwatch_event_rule.task_outcome["{mode}_failed"]',
              f'aws_cloudwatch_metric_alarm.repeated_failure["{mode}"]',
              f'aws_cloudwatch_metric_alarm.lost_invocation["{mode}"]']
    if mode == "audit":
        fields += ['aws_cloudwatch_event_rule.task_outcome["audit_succeeded"]',
                   'aws_cloudwatch_metric_alarm.outbox_backlog[0]']
    return {"module.schedulers." + name for name in fields}


def state_resources(state):
    """Actual raw state address map; reject deposed/multiple identities."""
    result = {}
    for row in state.get("resources", []):
        if row.get("mode") != "managed":
            continue
        prefix = (row.get("module", "") + ".").lstrip(".") + row["type"] + "." + row["name"]
        for instance in row.get("instances", []):
            c.require(not instance.get("deposed"), "deposed state is uncertain")
            suffix = "[" + c.canonical(instance["index_key"]).decode().strip() + "]" if "index_key" in instance else ""
            address = prefix + suffix
            c.require(address not in result, "duplicate state identity")
            result[address] = instance["attributes"]
    return result



def has_unknown(value):
    """Terraform masks are recursive booleans; an empty/false block is known."""
    if type(value) is bool:
        return value
    c.require(type(value) in {dict, list}, "malformed unknown mask")
    values = value.values() if type(value) is dict else value
    return any([has_unknown(item) for item in values])

def validate_mode_canary_delta(plan, before, *, stage):
    """Structural gate only; source/input/trust/output audit is also mandatory.

    Stage comes from the authenticated baseline, never a new caller wire field.
    This does not admit a prepare or replace the complete independent oracle.
    """
    from tools.cnesdata_delivery.iam_source import MODE_POLICIES
    c.require(stage in {"initial", "established"} and type(before) is dict, "mode prepare baseline")
    c._secrets(plan)
    expected = set(MODE_POLICIES) | set(MODE_POLICIES.values())
    rows = {row["address"]: row for row in plan["resource_changes"]}
    c.require(len(rows) == len(plan["resource_changes"]) and expected <= set(rows)
              and set(before) <= set(rows), "mode exact eight-address inventory")
    for address, row in rows.items():
        change = row["change"]
        c.require(not row.get("importing") and not change.get("importing"), "mode no import")
        if row["mode"] != "managed":
            c.require(row["mode"] == "data" and change["actions"] in (["read"], ["no-op"]), "mode data read only")
            continue
        c.require(change["before"] == before.get(address), "mode actual baseline")
        if address in expected:
            kind = "aws_iam_role_policy" if address in MODE_POLICIES else "aws_iam_role"
            c.require(row["type"] == kind and type(change["after"]) is dict, "mode exact resource kind")
        if address not in expected or change["actions"] == ["no-op"]:
            c.require(change["actions"] == ["no-op"] and change["before"] == change["after"]
                      and not has_unknown(change.get("after_unknown", {})), "mode all other resources noop")
            continue
        if stage == "initial":
            c.require(change["actions"] == ["create"] and change["before"] is None, "mode initial create only")
        else:
            c.require(change["actions"] == ["update"] and type(change["before"]) is dict, "mode established update only")
        computed = COMPUTED_OUTPUTS[kind] | {"id"}
        c.require(not has_unknown({key: value for key, value in change.get("after_unknown", {}).items()
                                   if key not in computed}), "mode unknown authority")
    c.require(all(rows[address]["mode"] == "managed" for address in expected), "mode managed inventory")
    return expected


def validate_delta(plan, approval):
    """Source-bound independent audit plus closed structural phase oracle.

    approval is authenticated evidence, not workflow input. Its complete change
    digest includes exact values/unknown masks/output-relevant references; runtime
    additionally verifies actual checkpoint, source closure and binary digest.
    """
    c.closed(approval, "purpose direction mode before original created expected_changes_sha256")
    purpose, direction, mode = (approval[k] for k in ("purpose", "direction", "mode"))
    c.require(purpose in PURPOSES and direction in {"advance", "converge"}, "lifecycle purpose/direction")
    c._secrets(plan)
    changes = [r for r in plan.get("resource_changes", []) if r.get("mode") == "managed"
               and r["change"]["actions"] not in (["no-op"], ["read"])]
    c.require(c.sha(c.canonical(changes)) == c.digest(approval["expected_changes_sha256"]), "independent exact delta audit")
    c.require(len(changes) == len({r["address"] for r in changes}), "duplicate change")
    creates, updates = set(), {}
    if purpose == "application-prepare":
        c.require(direction == "advance" and mode in {"observer-bootstrap", "operational"}, "prepare mode")
        roles = ("observer",) if mode == "observer-bootstrap" else ("normal", "recovery")
        for name in roles:
            for kind in ("aws_iam_role", "aws_iam_role_policy"):
                address = f"module.runtime_iam.{kind}.static_{name}[0]"
                creates.add(address)
                updates[address] = {"assume_role_policy"} if kind == "aws_iam_role" else {"policy"}
    elif purpose == "phase-b":
        c.require(mode in {"initial", "established"}, "B checkpoint mode")
        updates[STATE_MACHINE] = {"definition"}
        if mode == "initial":
            creates.add(STATE_MACHINE)
            updates[API_POLICY] = {"policy"}
    elif purpose.startswith("phase-c-"):
        c.require(mode in {"initial", "established"}, "C checkpoint mode")
        target = purpose.removeprefix("phase-c-")
        creates = scheduler_closure(target) if mode == "initial" else set()
        updates[f'module.schedulers.aws_scheduler_schedule.mode["{target}"]'] = {"target"}
        updates[f'module.schedulers.aws_iam_role_policy.run["{target}"]'] = {"policy"}
    else:
        c.require(direction == "advance" and mode == "post-open", "maintenance after OPEN")
        updates = {"module.static_web.aws_s3_bucket_lifecycle_configuration.this": {"rule"},
                   "module.static_web.aws_cloudfront_response_headers_policy.this": {"security_headers_config", "custom_headers_config"}}
    for row in changes:
        address, change = row["address"], row["change"]
        before, after, actions = change["before"], change["after"], change["actions"]
        computed = COMPUTED_OUTPUTS.get(row["type"], set())
        c.require(address in creates | set(updates), "unapproved phase resource")
        c.require(before == approval["before"].get(address), "actual checkpoint resource")
        c.require(not row.get("importing") and actions in (["create"], ["update"], ["delete"]), "no imports/replacement")
        if actions == ["delete"]:
            c.require(direction == "converge" and address in creates and purpose != "application-prepare"
                      and address not in approval["original"] and approval["created"].get(address) == before,
                      "delete requires original absence and own exact create")
            c.require(after is None, "inverse delete after")
        elif actions == ["create"]:
            c.require(direction == "advance" and address in creates and before is None, "closed initial create")
        else:
            c.require(address in updates and type(before) is dict and type(after) is dict, "closed phase update")
            mutable = updates[address]
            if direction == "converge":
                original = approval["original"].get(address)
                c.require(type(original) is dict
                          and {key: after.get(key) for key in mutable} == {key: original.get(key) for key in mutable},
                          "original resource restoration required")
            c.require({k: v for k, v in before.items() if k not in mutable | computed}
                      == {k: v for k, v in after.items() if k not in mutable | computed}, "phase update invariant")
            if "aws_scheduler_schedule.mode" in address:
                def without_revision(value):
                    import copy
                    item = copy.deepcopy(value)
                    for target in item.get("target", []):
                        for ecs in target.get("ecs_parameters", []):
                            ecs.pop("task_definition_arn", None)
                    return item
                c.require(without_revision({k: v for k, v in before.items() if k not in computed})
                          == without_revision({k: v for k, v in after.items() if k not in computed}), "scheduler target invariant")
        unknown = change.get("after_unknown", {})
        if actions == ["update"]:
            c.require(not has_unknown({k: v for k, v in unknown.items() if k not in computed}), "updated authority cannot be unknown")
        elif actions == ["create"]:
            c.require(set(k for k, v in unknown.items() if has_unknown(v)) <= computed | {"id", "tags_all"},
                      "unknown initial authority")
    return changes


APPLICATION_OWNER_FIELDS = ("application_purpose", "context_kind", "caller_binding_sha256")


def application_identity(value, *, required=False):
    """Atomic current caller fields; historical records keep their original form."""
    present = set(value) & set(APPLICATION_OWNER_FIELDS)
    if not present and not required:
        return {}
    c.require(present == set(APPLICATION_OWNER_FIELDS), "complete current application identity")
    purpose = value["application_purpose"]
    c.require(purpose in APPLICATION_CONTEXTS and value["context_kind"] == APPLICATION_CONTEXTS[purpose], "original application purpose/context")
    c.digest(value["caller_binding_sha256"])
    return {key: value[key] for key in APPLICATION_OWNER_FIELDS}


def owner_binding(record):
    c.require(record.get("lifecycle_version") == 1, "lifecycle owner protocol")
    c.require(record["repository"] == c.REPOSITORY, "owner repository")
    for key in ("run_id", "run_attempt", "generation"):
        c.integer(record[key])
    c.digest(record["source_sha"], 40)
    for key in ("release_sha256", "session_sha256"):
        c.digest(record[key])
    return {key: record[key] for key in OWNER_FIELDS} | {"owner_sha256": c.sha(record["owner"].encode())} | application_identity(record)


class DelegatedLeaseView:
    """Read-only capability; renewal ETags may change, original owner may not."""
    def __init__(self, store, binding, *, clock=time.time, monotonic=None):
        c.closed(binding, " ".join(OWNER_FIELDS) + " owner_sha256 " + " ".join(application_identity(binding)))
        self.store, self.binding = store, dict(binding)
        self.clock, self.monotonic = clock, monotonic or clock
        self.failed = False

    def check(self):
        try:
            c.require(not self.failed, "delegated owner previously uncertain")
            value, etag = self.store.get()
            c.require(value is not None and etag is not None and value.get("status") == "held"
                      and owner_binding(value) == self.binding, "delegated owner changed/released")
            c.require(type(value.get("expires_at")) is int and value["expires_at"] > self.clock() + 157,
                      "delegated owner expiry")
            self.acquired_at = value["acquired_at"]
            if hasattr(self.store, "deadline"):
                c.require(self.monotonic() + 157 < self.store.deadline(value["expires_at"]),
                          "delegated owner clock uncertainty")
            return value
        except Exception:
            self.failed = True
            raise


def checkpoint_transition(previous, current):
    c.closed(current, "sequence preparation_deadline close fixed_deadline input_deadline stage admitted_at deadline decision checkpoint_sha256"
             + (" predecessor_sha256" if "predecessor_sha256" in current else "")
             + " " + " ".join(application_identity(current)))
    if "predecessor_sha256" in current:
        c.digest(current["predecessor_sha256"])
    c.integer(current["sequence"], 0)
    c.digest(current["checkpoint_sha256"])
    c.require(current["preparation_deadline"] > 0, "preparation deadline")
    if previous is None:
        c.require(current["sequence"] == 0 and current["close"] is None
                  and current["fixed_deadline"] is None and current["decision"] is None,
                  "initial lifecycle is before fence")
    else:
        c.require(application_identity(current) == application_identity(previous), "original current caller cannot change")
        c.require(current.get("predecessor_sha256") == previous.get("predecessor_sha256"), "original historical reference cannot change")
        c.require(current["sequence"] == previous["sequence"] + 1
                  and current["preparation_deadline"] == previous["preparation_deadline"],
                  "checkpoint sequence/preparation rearm")
        if previous["close"] is not None:
            c.require(all(current[k] == previous[k] for k in ("close", "fixed_deadline", "input_deadline")),
                      "original fence cannot rearm")
        if previous["decision"] is not None:
            c.require(current["decision"] == previous["decision"], "original recovery cannot rearm")
        if current["stage"] == previous["stage"]:
            c.require(current["admitted_at"] == previous["admitted_at"] and current["deadline"] == previous["deadline"],
                      "same stage cannot rearm")
        elif current["decision"] is None:
            stages = ["application-prepare", *STAGES]
            c.require(previous["stage"] in stages and current["stage"] in stages
                      and stages.index(current["stage"]) == stages.index(previous["stage"]) + 1,
                      "normal phases cannot skip or retreat")
            c.require(current["admitted_at"] >= previous["admitted_at"], "stage admission precedes predecessor")
        else:
            c.require(current["stage"] == "recovery" and previous["stage"] != "recovery",
                      "recovery stage cannot restart")
    if current["close"] is not None:
        c.require(current["fixed_deadline"] == min(current["close"] + 1800, current["input_deadline"]),
                  "original fixed deadline")


def phase_capacity(window, *, now, credential_deadline, operation_seconds):
    """Wall-clock samples are conservative; each admission spends existing time."""
    c.require(type(operation_seconds) in (int, float) and 0 < operation_seconds <= 1800,
              "bounded operation")
    c.require(now + operation_seconds + 120 < credential_deadline, "credential finalization margin")
    close, fixed = window["close"], window["fixed_deadline"]
    if close is None:
        c.require(fixed is None and window["stage"] == "application-prepare" and window["decision"] is None
                  and now + operation_seconds + 157 < window["preparation_deadline"], "pre-fence prepare deadline")
        return
    c.require(fixed == min(close + 1800, window["input_deadline"]) and close <= window["admitted_at"] <= now,
              "original F deadline")
    decision = window["decision"]
    if decision is not None:
        c.closed(decision, "choice_at deadline checkpoint_sha256")
        c.digest(decision["checkpoint_sha256"])
        c.require(close <= decision["choice_at"] <= now and decision["deadline"] == min(fixed, decision["choice_at"] + 420),
                  "original recovery deadline")
        c.require(window["stage"] == "recovery" and window["deadline"] <= min(decision["deadline"], decision["choice_at"] + 300)
                  and now + operation_seconds + 37 < window["deadline"]
                  and window["deadline"] + 120 <= decision["deadline"], "recovery convergence/finalization")
    else:
        c.require(window["stage"] in STAGES, "closed phase")
        duration, later = STAGES[window["stage"]]
        deadline = window["deadline"]
        c.require(deadline <= min(fixed, window["admitted_at"] + duration)
                  and now + operation_seconds + 37 < deadline
                  and fixed - now >= max(0, deadline - now) + later + 420, "phase remaining capacity")



def terminal_deadline(window):
    if window["close"] is None:
        return window["preparation_deadline"]
    if window["decision"] is not None:
        decision = window["decision"]
        c.require(decision["deadline"] == min(window["fixed_deadline"], decision["choice_at"] + 420),
                  "original terminal recovery deadline")
        return decision["deadline"]
    return min(window["fixed_deadline"], window["deadline"])

def terminal_result(value, *, now, deadline):
    common = "kind fence accepted_modes routes_match state_clean quiescent pending unknown observed_at"
    failure = value.get("kind") in {"failed-closed-quiescent", "failed-prepare-quiescent"}
    c.closed(value, common + (" restoration" if failure else ""))
    c.require(value["state_clean"] is True and value["quiescent"] is True
              and value["pending"] == [] and value["unknown"] == []
              and value["routes_match"] is True and value["observed_at"] <= now < deadline
              and now - value["observed_at"] <= 30, "terminal uncertainty/drift/expiry")
    if value["kind"] == "accepted-open":
        c.require(value["fence"] == "OPEN" and set(value["accepted_modes"]) == {"unit", "recovery", "audit"}
                  and len(value["accepted_modes"]) == 3, "all routes accepted and OPEN required")
        return "accepted"
    c.require(failure and value["accepted_modes"] == [], "closed terminal kind")
    restored = value["restoration"]
    c.closed(restored, "unit recovery audit api static first_static_absent")
    c.require(all(restored[k] is True for k in ("unit", "recovery", "audit", "api"))
              and (restored["static"] is True or restored["first_static_absent"] is True), "original recovery incomplete")
    c.require(value["fence"] == "CLOSED" or value["kind"] == "failed-prepare-quiescent", "failed promotion must remain CLOSED")
    return "failed"
