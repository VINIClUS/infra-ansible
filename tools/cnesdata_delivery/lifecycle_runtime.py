"""Manual same-run lifecycle plan/apply, delegated to the original CAS owner.

Public artifacts authenticate job/attempt and private bytes. A plan is never an
apply approval: deploy additionally consumes an independent, source-pinned audit.
No AWS client is constructed before public admission. Default configuration closes.
"""
import base64
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.aws_boundary import AWS, S3LeaseStore
from tools.cnesdata_delivery.coordination_lease import Watchdog
from tools.cnesdata_delivery.provenance import GitHub, lifecycle_artifact


def source_admission(governance, api, role, source, run_id, attempt):
    c.digest(source, 40)
    c.integer(run_id)
    c.integer(attempt)
    c.require(role in {"plan", "deploy", "application"} and source == governance["source_sha"], "governed source/role")
    c.require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and os.environ.get("GITHUB_REF") == "refs/heads/develop"
              and os.environ.get("GITHUB_REPOSITORY") == c.REPOSITORY, "manual production caller")
    purpose = governance["application_purpose"]
    c.require(purpose in lc.APPLICATION_CONTEXTS and governance["context_kind"] == lc.APPLICATION_CONTEXTS[purpose],
              "application purpose/context")
    caller = lc.APPLICATION_CALLERS[purpose]
    run = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}")
    c.require(run["id"] == run_id and run["run_attempt"] == attempt and run["head_sha"] == source
              and run["repository"]["full_name"] == c.REPOSITORY and run["event"] == "workflow_dispatch"
              and run["path"].split("@")[0] == caller["workflow_path"] and run["head_branch"] == "develop"
              and run["status"] == "in_progress", "original live manual attempt")
    path = ("VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-application-gate.yml" if role == "application"
            else f"VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-{role}-gate.yml")
    pin = c.digest(governance["gate_shas"][role], 40)
    refs = [x for x in run.get("referenced_workflows", []) if x["path"].startswith(path + "@")]
    c.require(len(refs) == 1 and refs[0]["path"] == path + "@" + pin and refs[0]["sha"] == pin, "immutable reusable")
    comparison = api.read(f"repos/{c.REPOSITORY}/compare/{source}...develop")
    c.require(comparison["status"] in {"ahead", "identical"}, "source ancestry")
    checks = api.read(f"repos/{c.REPOSITORY}/commits/{source}/check-runs?per_page=100")["check_runs"]
    c.require(bool(governance["required_checks"]) and all(any(x["name"] == name and x["head_sha"] == source
              and x["conclusion"] == "success" for x in checks) for name in governance["required_checks"]), "source mandatory checks")
    return run


def authenticate_application_predecessor(api, governance, current):
    """Public half of H4 before STS; private originals still precede acquire."""
    c.require(type(governance.get("lifecycle_predecessor")) is dict
              and type(governance.get("predecessor_read")) is dict, "protected application predecessor required")
    purpose = governance["application_purpose"]
    c.require(purpose in lc.APPLICATION_CONTEXTS, "closed application purpose")
    reference = authenticate_predecessor(api, governance)
    c.require((reference["run_id"], reference["run_attempt"]) != (current["id"], current["run_attempt"]), "distinct original predecessor execution")
    if purpose == "mode-readiness-drill":
        c.require(reference["protocol"] == "lifecycle", "readiness requires original lifecycle predecessor")
    return reference


def admission(role):
    raw = os.environ.get("CNESDATA_DELIVERY_GOVERNANCE", "").encode()
    c.require(raw, "protected governance absent; lifecycle disabled")
    governance = c.loads(raw, canonical=True, limit=262144)
    c.require(governance.get("activation_enabled") is True and governance.get("lifecycle_enabled") is True
              and governance.get("lifecycle_authority") == "infra-ansible#55/6755178450", "lifecycle disabled/authority")
    request_raw = os.environ["REQUEST_DESCRIPTOR"].encode()
    c.require(c.sha(request_raw) == c.digest(os.environ["REQUEST_DESCRIPTOR_SHA256"]), "request bytes")
    request = c.loads(request_raw, canonical=True, limit=65536)
    c.closed(request, "schema_version repository source_sha step payloads application_purpose caller_binding_sha256")
    c.require(type(request["schema_version"]) is int and request["schema_version"] == 1 and request["repository"] == c.REPOSITORY
              and request["source_sha"] == os.environ["EXPECTED_SOURCE_SHA"], "lifecycle request")
    step = governance["lifecycle_steps"].get(request["step"])
    c.require(type(step) is dict and step["role"] == role and step["purpose"] == os.environ["PURPOSE"], "governed step")
    c.require(step["purpose"] in lc.PURPOSES or role == "application", "closed purpose")
    c.require(set(request["payloads"]) == set(step["input_jobs"]), "complete payload inventory")
    api = GitHub()
    run = source_admission(governance, api, role, request["source_sha"], int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"]))
    from tools.cnesdata_delivery.provenance import application_caller
    caller, original_job = application_caller(api, governance, run, role, step, include_job=True)
    c.require(request["application_purpose"] == caller["application_purpose"]
              and request["caller_binding_sha256"] == c.sha(c.canonical(caller)), "original requested application caller")
    governance = governance | {"authenticated_application_caller": caller, "authenticated_application_job": original_job}
    if caller["application_purpose"] == "mode-readiness-drill" and role in {"plan", "deploy"}:
        c.require(step["purpose"] == "application-prepare" and step["mode"] == "mode-canary"
                  and step["direction"] == "advance", "readiness infra only mode-canary prepare")
    if role == "application":
        authenticate_application_predecessor(api, governance, run)
    if step.get("historical_entry") is True:
        c.require(role in {"plan", "deploy"} and step["purpose"] == "application-prepare"
                  and step["direction"] == "advance", "closed historical entry step")
        predecessor = authenticate_predecessor(api, governance)
        c.require((run["id"], run["run_attempt"]) != (predecessor["run_id"], predecessor["run_attempt"]), "historical run cannot be current keeper")
    contract = governance["lifecycle_contract"]
    c.closed(contract, "repository source_sha path sha256")
    for field, env in (("repository", "CONTRACT_REPOSITORY"), ("source_sha", "CONTRACT_SOURCE_SHA"),
                       ("path", "CONTRACT_PATH"), ("sha256", "CONTRACT_SHA256")):
        c.require(contract[field] == os.environ[env], "independent lifecycle authority")
    c.digest(contract["source_sha"], 40)
    c.require(contract["repository"] == "VINIClUS/infra-ansible" and contract["path"] == "docs/cnesdata-delivery-application-lifecycle.md", "authority locus")
    document = api.read(f"repos/{contract['repository']}/contents/{contract['path']}?ref={contract['source_sha']}")
    c.require(c.sha(base64.b64decode(document["content"])) == c.digest(contract["sha256"]), "authority original bytes")
    payloads = {}
    for name, reference in request["payloads"].items():
        producer = step["input_jobs"][name]
        c.closed(producer, "name step")
        c.require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", producer["step"]), "original producer step")
        payloads[name] = lifecycle_artifact(api, reference, time.time(), source=request["source_sha"],
            run_id=run["id"], attempt=run["run_attempt"], producer_name=producer["name"],
            artifact_name="lifecycle-" + producer["step"], application_purpose=governance["application_purpose"])
    return governance | {"role": role}, request, step, api, run, payloads


def namespace(governance, request, run, step=None):
    prefix = governance["evidence_prefix"]
    c.require(re.fullmatch(r"cnesdata/prod/[A-Za-z0-9_/-]+/", prefix) is not None, "private lifecycle prefix")
    name = request["step"] if step is None else step
    c.require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) is not None, "step namespace")
    return f"{prefix}lifecycle/{request['source_sha']}/{run['id']}/{run['run_attempt']}/{name}/"


def keeper_transport(*, aws, governance, owner, predecessor, guard):
    """Read the original keeper's same-run carrier after public predecessor admission."""
    prefix = namespace(governance, {"source_sha": owner["source_sha"], "step": "keeper"},
                       {"id": owner["run_id"], "run_attempt": owner["run_attempt"]})
    guard.check(20)
    raw, _ = aws.get(governance["evidence_bucket"], prefix + "checkpoint.json", maximum=262144)
    guard.check()
    wrapper = c.loads(raw, canonical=True, limit=262144)
    c.closed(wrapper, "version owner predecessor_sha256 phase_a_originals")
    c.require(type(wrapper["version"]) is int and wrapper["version"] == 2
              and c.canonical(wrapper["owner"]) == c.canonical(owner)
              and wrapper["predecessor_sha256"] == c.sha(c.canonical(predecessor)), "original keeper transport owner/predecessor")
    lc.phase_a_originals(wrapper["phase_a_originals"])
    guard.check()
    return wrapper


def private_payload(aws, governance, request, run, public, *, guard=None, names=None):
    c.require(set(public) == {"index.json"}, "sanitized lifecycle index only")
    index = c.loads(public["index.json"], canonical=True)
    c.closed(index, "version source_sha run_id run_attempt step owner_sha256 generation files " + " ".join(lc.application_identity(index)))
    c.require(type(index["version"]) is int and index["version"] == 1 and index["source_sha"] == request["source_sha"]
              and index["run_id"] == run["id"] and index["run_attempt"] == run["run_attempt"], "private index producer")
    if "application_purpose" in request:
        c.require(lc.application_identity(index) == {"application_purpose": request["application_purpose"],
            "context_kind": governance["context_kind"], "caller_binding_sha256": request["caller_binding_sha256"]},
            "original current payload caller")
    c.digest(index["owner_sha256"])
    c.integer(index["generation"])
    c.require(type(index["files"]) is list and 0 < len(index["files"]) <= 32, "private file inventory")
    prefix = namespace(governance, request, run, index["step"])
    result = {}
    seen = set()
    c.require(names is None or type(names) is set and names, "private protected selection")
    for item in index["files"]:
        c.closed(item, "name sha256 size")
        name = item["name"]
        c.require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}\.(?:json|bin)", name) and name not in seen, "private basename")
        seen.add(name)
        c.integer(item["size"], 1, c.LIMIT)
        c.digest(item["sha256"])
        if names is not None and name not in names:
            continue
        if guard is not None:
            guard.check(20)
        raw, _ = aws.get(governance["evidence_bucket"], prefix + name, maximum=item["size"])
        if guard is not None:
            guard.check()
        c.require(len(raw) == item["size"] and c.sha(raw) == c.digest(item["sha256"]), "private original bytes")
        result[name] = raw
    c.require(names is None or set(result) == names, "complete protected private selection")
    return index, result


def current_checkpoint_chain(api, aws, governance, request, run, *, owner, predecessor, current_raw,
                             approval_raw, previous_raw, producer, guard, now):
    """Authenticate each earlier checkpoint from completed same-run publications.

    The first historical plan republishes the actual acquisition predecessor.
    Deploy reads that copy under its existing same-run scope; it never acquires a
    historical S3 grant or treats embedded Phase A as the established anchor.
    """
    original_api = api
    class GuardedAPI:
        def read(self, *args, **kwargs):
            guard.check(20)
            result = original_api.read(*args, **kwargs)
            guard.check()
            return result
    api = GuardedAPI()
    def inventory(path, key):
        result, total = [], None
        for page in range(1, 21):
            value = api.read(path + f"?per_page=100&page={page}")
            c.integer(value["total_count"], 0, 2000)
            if total is None:
                total = value["total_count"]
            c.require(value["total_count"] == total and type(value[key]) is list, "stable current publication inventory")
            result.extend(value[key])
            if len(result) >= total:
                break
        c.require(len(result) == total and len({row["id"] for row in result}) == total, "complete unique publication inventory")
        return result

    def checked(files, step):
        checkpoint = c.loads(files["checkpoint.json"], canonical=True)
        c.closed(checkpoint, "state state_object owner purpose plan_sha256 readbacks phase_a_originals")
        approval = c.loads(files["approval.json"], canonical=True)
        c.closed(approval, "version owner purpose direction plan_sha256 inputs_sha256 checkpoint_sha256 delta drift_matrix readbacks")
        c.require(type(approval["version"]) is int and approval["version"] == 1
                  and c.canonical(checkpoint["owner"]) == c.canonical(approval["owner"]) == c.canonical(owner)
                  and checkpoint["purpose"] == approval["purpose"] == step["purpose"]
                  and approval["direction"] == step["direction"]
                  and all(approval["delta"][field] == step[field] for field in ("purpose", "direction", "mode"))
                  and checkpoint["plan_sha256"] == approval["plan_sha256"], "original current deploy checkpoint/approval")
        return checkpoint, c.digest(approval["checkpoint_sha256"])

    current, parent = checked({"checkpoint.json": current_raw, "approval.json": approval_raw}, lc.FENCE_PREPARE_PRODUCER)
    c.require(parent == c.sha(previous_raw), "current deploy immediate predecessor bytes")
    anchor = predecessor["checkpoint_sha256"]
    baseline = previous_raw if c.sha(previous_raw) == anchor else None
    prior = {}
    if parent != anchor:
        catalog = governance["lifecycle_steps"]
        c.require(type(catalog) is dict and 1 <= len(catalog) <= 256, "finite protected lifecycle catalog")
        root = f"repos/{c.REPOSITORY}/actions/runs/{run['id']}"
        jobs = inventory(root + f"/attempts/{run['run_attempt']}/jobs", "jobs")
        artifacts = inventory(root + "/artifacts", "artifacts")
        for step_name, step in catalog.items():
            if step_name == request["step"] or step["role"] not in {"plan", "deploy"}:
                continue
            if step["role"] == "plan" and step.get("historical_entry") is not True:
                continue
            matches = [job for job in jobs if job["name"] == step["job_name"] and job["status"] == "completed" and job["conclusion"] == "success"]
            c.require(len(matches) <= 1, "unique completed current producer")
            if not matches:
                continue
            job = matches[0]
            candidates = [item for item in artifacts if item["name"] == "lifecycle-" + step_name
                          and c.instant(job["started_at"]) < c.instant(item["created_at"]) < c.instant(job["completed_at"])]
            c.require(len(candidates) == 1, "unique current publication in original job interval")
            artifact = candidates[0]
            reference = {"job_id": job["id"], "artifact_id": artifact["id"], "artifact_digest": artifact["digest"]}
            public = lifecycle_artifact(api, reference, now, source=owner["source_sha"], run_id=owner["run_id"],
                attempt=owner["run_attempt"], producer_name=step["job_name"], artifact_name="lifecycle-" + step_name)
            names = {"checkpoint.json"} | ({"approval.json"} if step["role"] == "deploy" else set())
            index, files = private_payload(aws, governance, request, run, public, guard=guard, names=names)
            c.require(index["step"] == step_name and index["owner_sha256"] == owner["owner_sha256"]
                      and type(index["generation"]) is int and index["generation"] == owner["generation"], "current chain original owner")
            raw = files["checkpoint.json"]
            digest = c.sha(raw)
            if step["role"] == "plan":
                c.require(digest == anchor and (baseline is None or baseline == raw), "historical plan preserves acquisition predecessor")
                baseline = raw
                continue
            checkpoint, previous = checked(files, step)
            c.require(digest not in prior, "ambiguous current checkpoint")
            origin = {"repository": c.REPOSITORY, "source_sha": owner["source_sha"], "run_id": owner["run_id"],
                      "run_attempt": owner["run_attempt"], "job_id": job["id"], "producer_name": job["name"],
                      "artifact_id": artifact["id"], "artifact_digest": artifact["digest"], "step": step_name,
                      "name": "checkpoint.json", "sha256": digest, "size": len(raw)}
            prior[digest] = (checkpoint, previous, origin)
    c.require(type(baseline) is bytes, "authenticated current copy of acquisition predecessor required")
    lc.fence_predecessor_baseline(baseline, predecessor, current["phase_a_originals"])
    rows = [(current, parent, lc.fence_current_origin(producer, current_raw))]
    visited = {c.sha(current_raw)}
    while parent != anchor:
        c.require(parent in prior and parent not in visited and len(rows) < 256, "complete acyclic current checkpoint ancestry")
        visited.add(parent)
        checkpoint, parent, origin = prior[parent]
        c.require(c.canonical(checkpoint["phase_a_originals"]) == c.canonical(current["phase_a_originals"]), "current chain original Phase A carrier")
        rows.append((checkpoint, parent, origin))
    entries = [{"sequence": sequence, "checkpoint_sha256": origin["sha256"], "previous_checkpoint_sha256": previous,
                "state": checkpoint["state"], "state_object": checkpoint["state_object"], "origin": origin}
               for sequence, (checkpoint, previous, origin) in enumerate(reversed(rows))]
    chain = {"schema_version": 3, "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
             "anchor_sha256": anchor, "head_sha256": c.sha(current_raw), "entries": entries}
    lc.validate_fence_checkpoint_chain(chain, current_raw, owner, predecessor_raw=baseline, predecessor_reference=predecessor, producer=producer)
    return chain, baseline




HISTORICAL_SOURCE_PATH = r"infra/opentofu/(?:env/prod|modules/[a-z0-9-]+)/[a-z0-9_.-]+\.tf"


def historical_sources(api, carrier, *, current_source, paths, guard=None):
    """Pinned read of original Phase A source blobs (amendment 2026-11-13 item 4).

    The commit is the authenticated Phase A source_sha only; ancestry uses the
    admission compare. Absence is decided from the complete tree, never from a
    failed read. Limits equal authenticate_sources: 64 paths, 256 KiB, 2 MiB.
    """
    import hashlib
    history = lc.phase_a_originals(carrier)
    plan = history["envelope"]["plan"]
    source = history["predecessor_reference"]["source_sha"]
    c.require(source == plan["source_sha"] == plan["release"]["source_sha"], "historical Phase A source pin")
    c.digest(source, 40)
    c.digest(current_source, 40)
    c.require(type(paths) is list and 1 <= len(paths) <= 64 and paths == sorted(set(paths))
              and all(type(path) is str and re.fullmatch(HISTORICAL_SOURCE_PATH, path) for path in paths), "historical source path inventory")

    def read(path):
        if guard is not None:
            guard.check(20)
        value = api.read(path)
        if guard is not None:
            guard.check()
        return value

    comparison = read(f"repos/{c.REPOSITORY}/compare/{source}...{current_source}")
    c.require(comparison["status"] in {"ahead", "identical"} and comparison["merge_base_commit"]["sha"] == source,
              "historical source ancestry")
    tree = read(f"repos/{c.REPOSITORY}/git/trees/{source}?recursive=1")
    c.require(tree["truncated"] is False and type(tree["tree"]) is list, "historical complete source tree")
    blobs = {}
    for entry in tree["tree"]:
        if entry.get("path") in paths:
            c.require(entry["path"] not in blobs and entry["type"] == "blob" and entry["mode"] in {"100644", "100755"},
                      "historical source tree entry")
            blobs[entry["path"]] = c.digest(entry["sha"], 40)
    result, total = {}, 0
    for path in paths:
        if path not in blobs:
            continue
        item = read(f"repos/{c.REPOSITORY}/contents/{path}?ref={source}")
        c.require(item["type"] == "file" and item["path"] == path and item["encoding"] == "base64"
                  and type(item["size"]) is int and 0 <= item["size"] <= 256 * 1024, "historical source file")
        raw = base64.b64decode(item["content"], validate=False)
        blob = hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()
        c.require(len(raw) == item["size"] and blob == item["sha"] == blobs[path], "historical source blob sha1")
        total += len(raw)
        c.require(total <= 2 * 1024**2, "historical source total")
        result[path] = raw
    return result


def fence_current_role_projection(*, plan_raw, inputs_raw, state_raw, sources, original_sources, source_sha,
                                  activation_source_sha, current_index, checkpoint, chain, historical, owner, fragment, producer,
                                  predecessor_raw, predecessor_reference, terraform_raw=None):
    """Derive one existing role from current plan/source and authenticated history.

    Infra producer only: supplied index/history/source closures and schema4 owner
    must already be independently authenticated. This measurement performs no
    S3/state read, SDK/STS, plan apply or capability/IPC activation.
    """
    from tools.cnesdata_delivery.iam_source import SourceResolver
    from tools.cnesdata_delivery.iam_boundary import bind_state
    c.require(source_sha == activation_source_sha == owner["source_sha"], "fence current activation source")
    c.digest(source_sha, 40)
    c.require(type(fragment.get("fragment_version")) is int and fragment["fragment_version"] == 4
              and fragment["caller_by_purpose"] == lc.APPLICATION_CALLERS
              and lc.application_identity(owner, required=True)["application_purpose"] == "promotion", "fence current schema4 promotion")
    c.closed(current_index, "version source_sha run_id run_attempt step owner_sha256 generation files " + " ".join(lc.APPLICATION_OWNER_FIELDS))
    c.require(type(current_index["version"]) is int and current_index["version"] == 1
              and all(c.canonical(current_index[key]) == c.canonical(owner[key]) for key in ("source_sha", "run_id", "run_attempt", "owner_sha256", "generation"))
              and lc.application_identity(current_index, required=True) == lc.application_identity(owner, required=True), "fence current plan owner/caller")
    entries = current_index["files"]
    c.require(type(entries) is list and 3 <= len(entries) <= 32, "fence current plan inventory")
    indexed = {}
    for item in entries:
        c.closed(item, "name size sha256")
        c.require(item["name"] not in indexed, "fence duplicate current file")
        indexed[item["name"]] = item
    c.require("plan.bin" in indexed and indexed["plan.bin"]["sha256"] == checkpoint["plan_sha256"], "fence applied current saved-plan commitment")
    c.digest(indexed["plan.bin"]["sha256"])
    c.integer(indexed["plan.bin"]["size"])
    for name, raw in (("plan.json", plan_raw), ("inputs.json", inputs_raw)):
        c.require(name in indexed and indexed[name]["sha256"] == c.sha(raw) and indexed[name]["size"] == len(raw), "fence original current plan/input bytes")
    # The operational plan publishes the version2 carrier as inputs.json; its hash is the
    # current commitment while the unwrapped Terraform bytes feed the resolver.
    inputs = c.loads(inputs_raw if terraform_raw is None else terraform_raw, canonical=True)
    plan, state = c.loads(plan_raw, state=True), c.loads(state_raw, state=True)
    c.require(c.canonical(checkpoint["owner"]) == c.canonical(owner) and checkpoint["purpose"] == "application-prepare"
              and c.canonical(checkpoint["state"]) == c.canonical(c.state_identity(state_raw)), "fence full current state checkpoint")
    envelope, old_checkpoint, reference = historical["envelope"], historical["checkpoint"], historical["predecessor_reference"]
    c.require(reference["protocol"] == "legacy-infra" and envelope["status"] == "applied"
              and envelope["plan"]["purpose"] == "phase-a" and envelope["apply"]["result"] == "success"
              and envelope["plan"]["source_sha"] == reference["source_sha"], "fence original applied Phase A")
    old_refs = {item["name"]: item for item in reference["objects"]}
    for name, value in (("envelope.json", envelope), ("checkpoint.json", old_checkpoint)):
        raw = c.canonical(value)
        c.require(name in old_refs and old_refs[name]["sha256"] == c.sha(raw) and old_refs[name]["size"] == len(raw), "fence original historical bytes")
    old_state = old_checkpoint["state_after"]
    lc.validate_fence_checkpoint_chain(chain, c.canonical(checkpoint), owner,
        predecessor_raw=predecessor_raw, predecessor_reference=predecessor_reference, producer=producer)
    phase, release = envelope["plan"]["phase_a_inputs"], envelope["plan"]["release"]
    c.require(phase["canary_storage_enabled"] is True and phase["canary_release_id"] == release["canary_id"]
              and phase["canary_trusted_principal_arn"] == fragment["application_role_arn"]
              and all(inputs.get(key) == phase[key] for key in ("canary_release_id", "canary_trusted_principal_arn", "canary_storage_enabled")), "fence original release/principal inputs")
    role_address = "module.runtime_iam.aws_iam_role.promotion_fence_operator[0]"
    policy_address = "module.runtime_iam.aws_iam_role_policy.promotion_fence_operator[0]"
    changes = {row["address"]: row for row in plan["resource_changes"]}
    c.require(len(changes) == len(plan["resource_changes"]), "fence duplicate current resource")
    for address in (role_address, policy_address):
        c.require(address in changes, "fence current no-op resource missing")
        change = changes[address]["change"]
        c.require(change["actions"] == ["no-op"] and not change.get("after_unknown")
                  and c.canonical(change["before"]) == c.canonical(change["after"]), "fence projection requires existing no-op role/policy")
    resolver = SourceResolver(plan, sources, {"generated_inputs": inputs, "account_id": fragment["account_id"],
        "region": "us-east-2", "purpose": "application-prepare", "mode": "operational"}, projection="fence-noop")
    resolver.precheck(policy_address)
    resources = bind_state(resolver, state)
    role, policy = resources[role_address], resources[policy_address]
    c.require(c.canonical(role) == c.canonical(changes[role_address]["change"]["after"])
              and c.canonical(policy) == c.canonical(changes[policy_address]["change"]["after"]), "fence current no-op state projection")
    scope = resolver.instance_scope(role_address)
    derived = {field: resolver.evaluate("runtime_iam", resolver.attribute("runtime_iam", ("resource", "aws_iam_role.promotion_fence_operator", field)), scope)
               for field in ("name", "assume_role_policy", "max_session_duration", "tags")}
    for field, value in derived.items():
        actual = role[field]
        if field == "assume_role_policy":
            value, actual = c.loads(value.encode()), c.loads(actual.encode())
        c.require(c.canonical(value) == c.canonical(actual), "fence current role source field")
    # Compare every source file actually traversed, not the whole old/current
    # repository or state. Unrelated current changes may legitimately differ.
    c.require(all(path in original_sources and original_sources[path] == sources[path] for path in resolver.blocks), "fence original/current role source closure")
    role_name = "cnesdata-prod-promotion-fence-operator"
    c.require(role["name"] == role_name and role["arn"] == fragment["delegations"]["fence_operator"]
              and policy["name"] == role_name + "-gate" and not role.get("permissions_boundary")
              and not role.get("managed_policy_arns"), "fence exact current role inventory")
    observed = {}
    for row in old_checkpoint["readbacks"]:
        if row["service"] != "iam" or row["operation"] not in {"get_role", "get_role_policy"}:
            continue
        value = row["observed"]
        name = value.get("Role", {}).get("RoleName") if row["operation"] == "get_role" else value.get("RoleName")
        if name != role_name or row["operation"] == "get_role_policy" and value.get("PolicyName") != policy["name"]:
            continue
        c.require(row["operation"] not in observed and row["sha256"] == c.sha(c.canonical(value)), "fence unique original IAM readback")
        observed[row["operation"]] = value
    c.require(set(observed) == {"get_role", "get_role_policy"}, "fence historical role/policy readbacks required")
    old_role = observed["get_role"]["Role"]
    c.require(not old_role.get("PermissionsBoundary") and old_role["Arn"] == role["arn"]
              and old_role["RoleId"] == role["unique_id"] and old_role["MaxSessionDuration"] == role["max_session_duration"] == 3600
              and c.canonical(old_role["AssumeRolePolicyDocument"]) == c.canonical(c.loads(role["assume_role_policy"].encode()))
              and old_role["Tags"] == [{"Key": "ReleaseId", "Value": release["canary_id"]}]
              and role["tags"] == {"ReleaseId": release["canary_id"]}
              and c.canonical(observed["get_role_policy"]["PolicyDocument"]) == c.canonical(resolver.policy(policy_address)), "fence original/current applied role projection")
    projected = {"role_arn": role["arn"], "role_name": role_name, "role_id": role["unique_id"], "policy_name": policy["name"],
        "trust": c.loads(role["assume_role_policy"].encode()), "policy": resolver.policy(policy_address), "max_session_duration": 3600, "tags": role["tags"]}
    projection_sha = c.sha(c.canonical(projected))
    return {"role": projected | {"schema_version": 1, "release_id": release["canary_id"], "session_name": "promotion-fence-" + release["canary_id"],
            "original_projection_sha256": projection_sha, "current_projection_sha256": projection_sha},
        "current_plan": {"source_sha": source_sha, "run_id": owner["run_id"], "run_attempt": owner["run_attempt"], "step": current_index["step"],
            "index_sha256": c.sha(c.canonical(current_index)), "plan_binary_sha256": indexed["plan.bin"]["sha256"],
            "plan_json_sha256": c.sha(plan_raw), "inputs_sha256": c.sha(inputs_raw)},
        "current_state": checkpoint["state"], "historical_checkpoint_sha256": c.sha(c.canonical(old_checkpoint)),
        "source_files": [{"path": path, "sha256": c.sha(sources[path])} for path in sorted(resolver.blocks)]}

def closed_ready_evidence_keys(governance, *, owner, caller, checkpoint_sha256, sequence):
    """Single derivation of own-run closed-ready intent/response/receipt keys.

    Used by ClosedReadyEvidence and by the prepared evaluation scope (item 2).
    """
    c.closed(owner, " ".join(lc.OWNER_FIELDS) + " owner_sha256")
    c.integer(sequence, 0, 8191)
    operation = c.sha(c.canonical({"schema_version": 2, "operation": "closed-ready", "owner": owner, "caller": caller,
                                   "checkpoint_sha256": c.digest(checkpoint_sha256), "sequence": sequence}))
    prefix = namespace(governance, {"source_sha": owner["source_sha"], "step": "closed-ready"},
                       {"id": owner["run_id"], "run_attempt": owner["run_attempt"]})
    return {name: prefix + "sdk-" + operation[:40] + "-" + name + ".json" for name in ("intent", "response", "receipt")}


def _allowed_resources(policy, action):
    found = []
    for statement in policy["Statement"]:
        actions = statement.get("Action", [])
        actions = [actions] if type(actions) is str else actions
        if statement.get("Effect") == "Allow" and action in actions:
            c.require("Resource" in statement, "fence policy exact resource")
            resource = statement["Resource"]
            found.extend([resource] if type(resource) is str else resource)
    c.require(len(found) == 1 and type(found[0]) is str, "fence policy single resource for " + action)
    return found[0]


def fence_policy_scope(governance, policy):
    """The single derivation of the effective fence scope from the projected role policy (item 2).

    Shared by the prepared evaluation and the closed-ready capability. The table is
    the single GetItem Resource; executions come from the single trailing wildcard
    of DescribeExecution; both are bound to the protected account. State is never
    consulted.
    """
    account = re.escape(governance["account_id"])
    table = _allowed_resources(policy, "dynamodb:GetItem")
    c.require(re.fullmatch(r"arn:aws:dynamodb:us-east-2:" + account + r":table/cnesdata-prod-[A-Za-z0-9_.-]+", table),
              "fence policy protected table")
    match = re.fullmatch(r"(arn:aws:states:us-east-2:" + account + r":execution:(cnesdata-prod-[A-Za-z0-9_-]+):)\*",
                         _allowed_resources(policy, "states:DescribeExecution"))
    c.require(match is not None, "fence execution prefix single final wildcard")
    return {"control_table_arn": table, "execution_prefix": match[1],
            "machine_arn": match[1].replace(":execution:", ":stateMachine:")[:-1]}


def fence_evaluation_scope(*, governance, role, control_table_arn, owner, checkpoint_sha256):
    """Effective fence scope from the authenticated projected role policy (item 2).

    The table derived by fence_policy_scope must equal the authenticated
    Terraform shared_outputs value. Evidence is the own-run closed-ready intent
    for (owner, caller, checkpoint, sequence 0).
    """
    from tools.cnesdata_delivery.coordination_lease import KEY
    derived = fence_policy_scope(governance, role["policy"])
    table, prefix = derived["control_table_arn"], derived["execution_prefix"]
    c.require(table == control_table_arn, "fence table equals authenticated shared output")
    machine = derived["machine_arn"].rsplit(":", 1)[1]
    identity = lc.application_identity(owner, required=True)
    request_owner = {key: owner[key] for key in [*lc.OWNER_FIELDS, "owner_sha256"]}
    keys = closed_ready_evidence_keys(governance, owner=request_owner, caller=identity, checkpoint_sha256=checkpoint_sha256, sequence=0)
    scope = {"role_arn": role["role_arn"], "session_name": role["session_name"], "control_table_arn": table,
             "execution_arn": prefix + "0" * 16,
             "foreign_execution_arn": prefix.replace(":" + machine + ":", ":" + machine + "-foreign:") + "0" * 16,
             "evidence_arn": "arn:aws:s3:::" + governance["evidence_bucket"] + "/" + keys["intent"],
             "lease_arn": "arn:aws:s3:::" + governance["state_bucket"] + "/" + KEY}
    return scope, prefix


def fence_evaluation_documents(*, governance, pin, fragment, owner, role, control_table_arn, execution_prefix, observed_at):
    """Six evaluation documents from protected sources (amendment 2026-11-13 item 3)."""
    from tools.cnesdata_delivery import session_owner, session_policy
    c.integer(observed_at)
    frozen = min(c.instant(pin["frozen_until"]), c.instant(fragment["enabled_until"]))
    c.require(type(frozen) in (int, float) and observed_at < frozen, "fence evaluation before freeze")
    session = session_policy.application_request(governance, owner["source_sha"], owner["run_id"], owner["run_attempt"],
        "closed-ready", application_purpose="promotion", delegations=("fence_operator",),
        sessions={"fence_operator": role["session_name"]})
    return {
        "application_identity": session_owner.application_identity_document(governance, fragment),
        "application_managed": c.loads(c.canonical(pin["document"]), canonical=True),
        "application_session": c.loads(session["Policy"].encode()),
        "fence_identity": role["policy"],
        "fence_session": session_policy.fence_session_policy(control_table_arn=control_table_arn,
            execution_prefix=execution_prefix, deadline=int(min(observed_at + 180, frozen))),
        "freeze": {"frozen_until": c.utc(frozen), "application_fragment_sha256": c.sha(c.canonical(fragment)),
                   "owner_policy_sha256": c.digest(pin["document_sha256"])},
    }


def fence_prepared_files(*, originals, owner, fragment, activation_sha256, producer, preparation, predecessor_raw, predecessor_reference):
    """Build before upload; enclosing artifact provenance remains external."""
    c.require(type(originals) is dict and set(originals) == lc.FENCE_PREPARE_FILES - {"fence-prepared.json"},
              "fence exact original documents")
    manifest = {"schema_version": 1, "proof_kind": "iam-readback-and-evaluation", "operation": "closed-ready",
        "application_purpose": "promotion", "context_kind": "promotion", "owner": owner,
        "caller_binding_sha256": owner["caller_binding_sha256"], "activation_sha256": activation_sha256,
        "application_fragment_sha256": c.sha(c.canonical(fragment)), "producer": producer, "preparation": preparation,
        "files": [{"name": name, "sha256": c.sha(raw), "size": len(raw)} for name, raw in sorted(originals.items())],
        "outcome": "observed"}
    files = dict(originals, **{"fence-prepared.json": c.canonical(manifest)})
    lc.validate_fence_prepared_package(files, originals=originals, owner=owner, fragment=fragment,
        activation_sha256=activation_sha256, producer=producer, preparation=preparation,
        predecessor_raw=predecessor_raw, predecessor_reference=predecessor_reference)
    return files


def fence_producer_job(api, run, source):
    """Identify the running producer job before publication (amendment 2026-11-13 item 5).

    Exactly one current-attempt job with the fixed name, in progress on this
    runner, at the source, with the gate step running after eight completed-success
    steps in order. Anything else refuses before any private publication.
    """
    runner = os.environ.get("RUNNER_NAME")
    c.require(type(runner) is str and 0 < len(runner) <= 256, "producer RUNNER_NAME")
    c.digest(source, 40)
    root = f"repos/{c.REPOSITORY}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs"
    jobs, total = [], None
    for page in range(1, 21):
        value = api.read(root + f"?per_page=100&page={page}")
        c.integer(value["total_count"], 0, 2000)
        total = value["total_count"] if total is None else total
        c.require(value["total_count"] == total and type(value["jobs"]) is list, "stable producer job inventory")
        jobs.extend(value["jobs"])
        if len(jobs) >= total or not value["jobs"]:
            break
    c.require(len(jobs) == total and len({job["id"] for job in jobs}) == total, "complete producer job inventory")
    named = [job for job in jobs if job["name"] == lc.FENCE_PREPARE_PRODUCER["job_name"]]
    c.require(len(named) == 1, "unique fixed producer job")
    job = named[0]
    c.integer(job["id"])
    c.require(job["status"] == "in_progress" and job["head_sha"] == source and job["runner_name"] == runner,
              "running producer job on this runner")
    steps = job.get("steps")
    c.require(type(steps) is list, "producer job steps")
    numbers = []
    for index, name in enumerate(lc.FENCE_PREPARE_STEPS):
        found = [item for item in steps if item.get("name") == name]
        last = index == len(lc.FENCE_PREPARE_STEPS) - 1
        c.require(len(found) == 1 and (found[0]["status"] == "in_progress" if last else
                  found[0]["status"] == "completed" and found[0]["conclusion"] == "success"), "producer step state")
        numbers.append(c.integer(found[0]["number"]))
    c.require(numbers == sorted(set(numbers)), "producer step order")
    return job


def fence_phase_a_origin(history, projection_source_files):
    """fence-origins.json phase_a from the authenticated original carrier only."""
    plan, applied, reference = history["envelope"]["plan"], history["envelope"]["apply"], history["predecessor_reference"]
    indexed = {entry["name"]: entry for entry in reference["objects"]}
    files = {name: {key: reference[key] for key in ("repository", "source_sha", "run_id", "run_attempt", "artifact_id", "artifact_digest")}
             | {"job_id": reference["producer_job_id"], "producer_name": reference["producer_name"], "step": "applied", **indexed[name]}
             for name in sorted(lc.FENCE_PHASE_A_FILES)}
    return {"source_sha": plan["source_sha"], "source_closure_sha256": lc.fence_source_closure(projection_source_files),
            "release_id": plan["release"]["release_id"], "canary_id": plan["release"]["canary_id"],
            "candidate_sha256": plan["release"]["candidate_sha256"], "plan_binary_sha256": plan["binary_sha256"],
            "plan_json_sha256": plan["json_sha256"], "inputs_sha256": plan["inputs_sha256"],
            "plan_receipt": {"plan_binding_sha256": applied["plan_binding_sha256"], "consumed_plan_artifact": applied["consumed_plan_artifact"]},
            "state": history["checkpoint"]["state_after"], "files": files}


def fence_prepare_package(*, api, aws, governance, request, run, owner, guard, authority, predecessor, carrier, plan_index,
                          plan_raw, inputs_raw, terraform_raw, approval_raw, previous_raw, checkpoint_raw, state_raw,
                          sources, activation_sha256, clock=time.time, sleep=time.sleep):
    """Eight-file prepared observation inside the running gate (amendment 2026-11-13 items 2, 3, 5, 6).

    Only protected inputs already authenticated by execute: owner/lease, schema4
    authority, H4 predecessor and carrier, the plan index read by private_payload,
    the audited approval, the applied checkpoint/state and product sources.
    Returns bytes to publish; it never grants a capability.
    """
    from tools.cnesdata_delivery.iam_boundary import fence_effective_evaluation
    producer_step = lc.FENCE_PREPARE_PRODUCER
    c.require(request["step"] == producer_step["step"], "fence producer step")
    fragment = authority.application_fragment
    c.require(type(fragment) is dict, "fence schema4 application authority")
    job = fence_producer_job(api, run, request["source_sha"])
    producer = producer_step | {"repository": c.REPOSITORY, "source_sha": request["source_sha"],
        "workflow_sha": c.digest(governance["gate_shas"]["deploy"], 40), "run_id": run["id"],
        "run_attempt": run["run_attempt"], "job_id": job["id"]}
    chain, baseline = current_checkpoint_chain(api, aws, governance, request, run, owner=owner, predecessor=predecessor,
        current_raw=checkpoint_raw, approval_raw=approval_raw, previous_raw=previous_raw, producer=producer, guard=guard, now=clock())
    history = lc.phase_a_originals(carrier)
    original_sources = historical_sources(api, carrier, current_source=request["source_sha"], paths=sorted(sources), guard=guard)
    checkpoint = c.loads(checkpoint_raw, canonical=True)
    projection = fence_current_role_projection(plan_raw=plan_raw, inputs_raw=inputs_raw, terraform_raw=terraform_raw,
        state_raw=state_raw, sources=sources, original_sources=original_sources, source_sha=request["source_sha"],
        activation_source_sha=request["source_sha"], current_index=plan_index, checkpoint=checkpoint, chain=chain,
        historical=history, owner=owner, fragment=fragment, producer=producer, predecessor_raw=baseline,
        predecessor_reference=predecessor)
    role = projection["role"]
    observed = {row["operation"]: row["observed"] for row in history["checkpoint"]["readbacks"]
                if row["service"] == "iam" and row["operation"] in {"get_role", "get_role_policy"}
                and (row["observed"].get("Role", {}).get("RoleName") == role["role_name"] or row["observed"].get("RoleName") == role["role_name"])}
    expected = {"role": {"Role": observed["get_role"]["Role"]},
                "policy": {"RoleName": role["role_name"], "PolicyName": role["policy_name"], "PolicyDocument": role["policy"]}}
    window = guard.window
    readbacks = fence_role_readbacks(aws, account=governance["account_id"], expected=expected,
        preparation_admitted_at=window["admitted_at"], preparation_deadline=window["preparation_deadline"],
        guard=guard, clock=clock, sleep=sleep)
    preparation = {"admitted_at": window["admitted_at"], "deadline": window["preparation_deadline"],
                   "observed_at": readbacks["readbacks"][-1]["observed_at"]}
    terraform = c.loads(terraform_raw, canonical=True)
    scope, execution_prefix = fence_evaluation_scope(governance=governance, role=role,
        control_table_arn=terraform["shared_outputs"]["control_table_arn"], owner=owner, checkpoint_sha256=c.sha(checkpoint_raw))
    documents = fence_evaluation_documents(governance=governance, pin=authority.pin, fragment=fragment, owner=owner, role=role,
        control_table_arn=scope["control_table_arn"], execution_prefix=execution_prefix, observed_at=preparation["observed_at"])
    evaluation = fence_effective_evaluation(documents, scope, evaluator_source_sha=producer["workflow_sha"],
                                            observed_at=c.utc(preparation["observed_at"]))
    origins = {"schema_version": 1, "phase_a": fence_phase_a_origin(history, projection["source_files"]),
               "current_source_sha": request["source_sha"],
               "current_source_closure_sha256": c.sha(c.canonical(governance["source_closure"])),
               "current_plan": projection["current_plan"], "projection_source_files": projection["source_files"]}
    originals = {"checkpoint.json": checkpoint_raw, "approval.json": approval_raw, "fence-role.json": c.canonical(role),
                 "fence-readbacks.json": c.canonical(readbacks), "fence-origins.json": c.canonical(origins),
                 "fence-chain.json": c.canonical(chain), "fence-evaluation.json": c.canonical(evaluation)}
    guard.check()
    return fence_prepared_files(originals=originals, owner=owner, fragment=fragment, activation_sha256=activation_sha256,
        producer=producer, preparation=preparation, predecessor_raw=baseline, predecessor_reference=predecessor)


class PreparedFence(dict):
    """Private bytes obtained from the completed, authenticated deploy producer."""


def fence_prepared_payload(api, aws, governance, request, run, reference, *, owner, now,
                           predecessor_raw, predecessor_reference, guard=None):
    """Read a completed deploy observation; no capability, credentials or SDK dispatch.

    Owner/request/governance must already have independent schema4 admission. This
    extra consumer is inactive until original Phase A and chain transport exist.
    Publication is inside the running gate; acceptance is after completed-success.
    """
    producer = lc.FENCE_PREPARE_PRODUCER
    identity = lc.application_identity(owner, required=True)
    c.require(identity["application_purpose"] == "promotion" and identity["context_kind"] == "promotion"
              and request["application_purpose"] == identity["application_purpose"]
              and request["caller_binding_sha256"] == identity["caller_binding_sha256"]
              and governance["context_kind"] == identity["context_kind"], "fence protected promotion caller")
    c.require(request["source_sha"] == owner["source_sha"] == run["head_sha"]
              and run["id"] == owner["run_id"] and run["run_attempt"] == owner["run_attempt"], "fence current owner source/run")
    pin = c.digest(governance["gate_shas"]["deploy"], 40)
    actual = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run['id']}/attempts/{run['run_attempt']}")
    path = "VINIClUS/infra-ansible/" + producer["workflow_path"]
    refs = [item for item in actual.get("referenced_workflows", []) if item["path"].startswith(path + "@")]
    c.require(actual["head_branch"] == "develop" and len(refs) == 1
              and refs[0]["path"] == path + "@" + pin and refs[0]["sha"] == pin, "fence exact deploy reusable pin")
    c.closed(reference, "artifact_id artifact_digest job_id")
    c.integer(reference["job_id"])
    job = api.read(f"repos/{c.REPOSITORY}/actions/jobs/{reference['job_id']}")
    names = lc.FENCE_PREPARE_STEPS
    steps = job.get("steps")
    c.require(type(steps) is list, "fence original producer steps")
    selected = []
    for name in names:
        found = [item for item in steps if item.get("name") == name]
        c.require(len(found) == 1 and found[0]["status"] == "completed" and found[0]["conclusion"] == "success",
                  "fence completed-success named producer step")
        selected.append(c.integer(found[0]["number"]))
    c.require(selected == sorted(set(selected)), "fence original producer step order")
    public = lifecycle_artifact(api, reference, now, source=request["source_sha"], run_id=run["id"], attempt=run["run_attempt"],
                                producer_name=producer["job_name"], artifact_name="lifecycle-" + producer["step"])
    c.require(set(public) == {"index.json"}, "fence sanitized public inventory")
    index = c.loads(public["index.json"], canonical=True)
    c.closed(index, "version source_sha run_id run_attempt step owner_sha256 generation files " + " ".join(identity))
    c.require(type(index["version"]) is int and index["version"] == 1
              and index["source_sha"] == request["source_sha"] and type(index["run_id"]) is int and index["run_id"] == run["id"]
              and type(index["run_attempt"]) is int and index["run_attempt"] == run["run_attempt"]
              and index["step"] == producer["step"] and index["owner_sha256"] == owner["owner_sha256"]
              and type(index["generation"]) is int and index["generation"] == owner["generation"]
              and lc.application_identity(index, required=True) == identity, "fence exact current public binding")
    entries = index["files"]
    c.require(type(entries) is list and len(entries) == len(lc.FENCE_PREPARE_FILES)
              and {item["name"] for item in entries} == lc.FENCE_PREPARE_FILES, "fence complete public file inventory")
    for item in entries:
        c.closed(item, "name size sha256")
        c.integer(item["size"], 1, 1024**2)
        c.digest(item["sha256"])
    files = private_payload(aws, governance, request, run, public, guard=guard)[1]
    manifest = c.loads(files["fence-prepared.json"], canonical=True, limit=1024**2)
    expected = producer | {"repository": c.REPOSITORY, "source_sha": request["source_sha"], "workflow_sha": pin,
                           "run_id": run["id"], "run_attempt": run["run_attempt"], "job_id": reference["job_id"]}
    c.require(c.canonical(manifest["producer"]) == c.canonical(expected), "fence private producer matches authenticated job")
    chain = c.loads(files["fence-chain.json"], canonical=True)
    historical = c.loads(files["fence-origins.json"], canonical=True)["phase_a"]
    lc._fence_state(historical["state"])
    lc.validate_fence_checkpoint_chain(chain, files["checkpoint.json"], owner,
        predecessor_raw=predecessor_raw, predecessor_reference=predecessor_reference, producer=expected)
    lc.validate_fence_prepared_package(files, owner=owner, fragment=governance["application_fragment"],
        activation_sha256=manifest["activation_sha256"], producer=expected, preparation=manifest["preparation"],
        originals={name: raw for name, raw in files.items() if name != "fence-prepared.json"},
        predecessor_raw=predecessor_raw, predecessor_reference=predecessor_reference)
    return PreparedFence(files)

def first_checkpoint(predecessor, record, expected_owner, actual_state, actual_object):
    """Plan-only historical entry oracle; predecessor is separately authenticated.

    Does not relabel historical bytes as same-run. The application principal
    never receives state bytes or a state-reading capability.
    """
    c.require(type(predecessor) is dict, "original predecessor missing")
    c.require(lc.owner_binding(record) == expected_owner, "original current owner")
    historical = predecessor["checkpoint"]
    c.require(record["lifecycle"]["sequence"] == 0
              and record["lifecycle"]["checkpoint_sha256"] == c.sha(predecessor["raw"]),
              "historical checkpoint only at original entry")
    c.require(c.canonical(historical) == predecessor["raw"]
              and predecessor["lease"]["checkpoint_sha256"] == c.sha(predecessor["raw"]), "original predecessor bytes")
    identity_field = "state" if predecessor["lease"].get("lifecycle_version") == 1 else "state_after"
    c.require(historical[identity_field] == c.state_identity(actual_state)
              and historical["state_object"] == actual_object, "historical actual state drift")
    return historical


def validate_predecessor_reference(governance):
    """One closed historical descriptor validator for parser and public admission."""
    from tools.cnesdata_delivery import session_policy
    reference, selector = governance["lifecycle_predecessor"], governance["predecessor_read"]
    c.closed(reference, "predecessor_version protocol repository source_sha run_id run_attempt owner_sha256 generation session_sha256 checkpoint_sha256 artifact_id artifact_digest producer_job_id producer_name objects")
    c.require(reference["predecessor_version"] == 1 and reference["repository"] == c.REPOSITORY
              and all(reference[k] == selector[k] for k in ("protocol", "source_sha", "run_id", "run_attempt")), "original predecessor selection")
    keys = session_policy.predecessor_keys(governance, selector)
    for key in ("owner_sha256", "session_sha256", "checkpoint_sha256"):
        c.digest(reference[key])
    if reference["protocol"] == "lifecycle" or reference["generation"] is not None:
        c.integer(reference["generation"])
    c.integer(reference["artifact_id"])
    c.integer(reference["producer_job_id"])
    c.require(reference["artifact_digest"] == "sha256:" + c.digest(reference["artifact_digest"].removeprefix("sha256:")), "original predecessor artifact digest")
    entries = reference["objects"]
    c.require(type(entries) is list and len(entries) == len(keys)
              and {x["name"] for x in entries} == {k.rsplit("/", 1)[1] for k in keys}, "complete original historical objects")
    for item in entries:
        c.closed(item, "name sha256 size")
        c.digest(item["sha256"])
        c.integer(item["size"], 1, 262144)
    c.require(next(x["sha256"] for x in entries if x["name"] == "checkpoint.json") == reference["checkpoint_sha256"], "original historical checkpoint commitment")
    return reference


def authenticate_predecessor(api, governance):
    """Original public receipt/job; no state access or credentials at admission."""
    from tools.cnesdata_delivery import runtime
    reference = validate_predecessor_reference(governance)
    selector = governance["predecessor_read"]
    run_id, attempt, source = (reference[k] for k in ("run_id", "run_attempt", "source_sha"))
    if reference["protocol"] == "legacy-infra":
        run, status, receipt, index = runtime._published_receipt(api, governance, run_id, attempt)
        c.require(status == selector["status"] and index["purpose"] == selector["purpose"] and run["head_sha"] == source
                  and receipt["index_artifact_id"] == reference["artifact_id"]
                  and receipt["index_artifact_digest"] == reference["artifact_digest"]
                  and receipt["checkpoint_sha256"] == reference["checkpoint_sha256"], "original legacy predecessor receipt")
        expected_name = f"cnesdata-{status}-{run_id}-{attempt}"
    else:
        c.integer(reference["generation"])
        run = api.read(f"repos/{c.REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}")
        c.require(run["status"] == "completed" and run["conclusion"] == "success" and run["head_branch"] == "develop",
                  "previous lifecycle not successful; reviewed recovery required")
        pin = c.digest(governance["gate_shas"]["application"], 40)
        path = "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-application-gate.yml@"
        refs = [x for x in run.get("referenced_workflows", []) if x["path"].startswith(path)]
        c.require(len(refs) == 1 and refs[0]["path"] == path + pin and refs[0]["sha"] == pin, "original history reusable")
        c.require(reference["producer_name"] == governance["lifecycle_terminal_job"], "original terminal job")
        public = lifecycle_artifact(api, {"artifact_id": reference["artifact_id"], "artifact_digest": reference["artifact_digest"],
            "job_id": reference["producer_job_id"]}, time.time(), source=source, run_id=run_id, attempt=attempt,
            producer_name=reference["producer_name"], artifact_name="lifecycle-terminal")
        c.require(set(public) == {"index.json"}, "original terminal public package")
        index = c.loads(public["index.json"], canonical=True)
        c.closed(index, "version source_sha run_id run_attempt step owner_sha256 generation files " + " ".join(lc.application_identity(index)))
        c.require(index["version"] == 1 and index["step"] == "terminal"
                  and all(index[k] == reference[k] for k in ("source_sha", "run_id", "run_attempt", "owner_sha256", "generation"))
                  and sorted(index["files"], key=lambda x: x["name"]) == sorted(reference["objects"], key=lambda x: x["name"]), "original terminal history index")
        expected_name = "lifecycle-terminal"
    job = api.read(f"repos/{c.REPOSITORY}/actions/jobs/{reference['producer_job_id']}")
    c.require(job["run_id"] == run_id and job["run_attempt"] == attempt and job["head_sha"] == source
              and job["name"] == reference["producer_name"] and job["status"] == "completed" and job["conclusion"] == "success", "original historical producer job")
    metadata = api.read(f"repos/{c.REPOSITORY}/actions/artifacts/{reference['artifact_id']}")
    c.require(metadata["id"] == reference["artifact_id"] and metadata["digest"] == reference["artifact_digest"]
              and metadata["name"] == expected_name and metadata["workflow_run"]["id"] == run_id
              and metadata["workflow_run"]["head_sha"] == source and metadata["expired"] is False
              and c.instant(job["started_at"]) < c.instant(metadata["created_at"]) < c.instant(job["completed_at"]),
              "original history artifact/job interval")
    return reference


def historical_checkpoint(aws, governance, reference, record, *, raw=None):
    """One plan-only exact read, then original bytes travel in the saved plan."""
    from tools.cnesdata_delivery.session_policy import predecessor_keys
    window = record["lifecycle"]
    c.require(window["sequence"] == 0 and window["stage"] == "application-prepare"
              and window.get("predecessor_sha256") == c.sha(c.canonical(reference))
              and window["checkpoint_sha256"] == reference["checkpoint_sha256"]
              and (record["run_id"], record["run_attempt"]) != (reference["run_id"], reference["run_attempt"]), "original initial predecessor binding")
    entry = next(x for x in reference["objects"] if x["name"] == "checkpoint.json")
    if raw is None:
        key = next(k for k in predecessor_keys(governance, governance["predecessor_read"]) if k.endswith("/checkpoint.json"))
        raw, _ = aws.get(governance["evidence_bucket"], key, maximum=entry["size"])
    c.require(len(raw) == entry["size"] and c.sha(raw) == entry["sha256"], "original historical checkpoint bytes")
    checkpoint = c.loads(raw, canonical=True)
    if reference["protocol"] == "lifecycle":
        c.require(all(checkpoint["owner"][k] == reference[k] for k in ("repository", "source_sha", "run_id", "run_attempt", "owner_sha256", "generation", "session_sha256")),
                  "original historical checkpoint owner")
    return raw


class LifecycleWatchdog(Watchdog):
    """Existing process-group termination with read-only delegated lease/time."""
    def __init__(self, lease, window, credential_deadline, *, clock=time.time, monotonic=time.monotonic):
        super().__init__(lease, fixed_deadline=0, credential_deadline=credential_deadline, monotonic=monotonic)
        self.window, self.clock = dict(window), clock

    def check(self, operation_seconds=1):
        lc.phase_capacity(self.window, now=self.clock(), credential_deadline=self.credential_deadline, operation_seconds=max(20, operation_seconds))
        c.require(not self.cancelled, "lifecycle cancelled")
        record = self.lease.check()
        c.require(record["lifecycle"] == self.window, "phase checkpoint superseded")
        lc.phase_capacity(self.window, now=self.clock(), credential_deadline=self.credential_deadline, operation_seconds=operation_seconds)

    def admit(self):
        self.check()

    def run(self, command, *, cwd, env, output, timeout=1800, mutating=True):
        self.check()
        lc.phase_capacity(self.window, now=self.clock(), credential_deadline=self.credential_deadline,
                          operation_seconds=timeout)
        return super().run(command, cwd=cwd, env=env, output=output, timeout=timeout, mutating=mutating)


def readbacks(aws, specifications, guard):
    allowed = {"iam": {"get_role", "get_role_policy"}, "stepfunctions": {"describe_state_machine"},
               "scheduler": {"get_schedule", "get_schedule_group", "list_schedules"},
               "events": {"describe_rule"}, "cloudwatch": {"describe_alarms"},
               "cloudfront": {"get_response_headers_policy"}, "s3": {"get_bucket_lifecycle_configuration"}}
    reports = []
    for spec in specifications:
        grouped = spec.get("service") == "scheduler" and spec.get("operation") == "list_schedules"
        c.closed(spec, "service operation parameters absent" + (" members" if grouped else ""))
        c.require(spec["operation"] in allowed.get(spec["service"], set()), "lifecycle readback API")
        c.require(type(spec["parameters"]) is dict and type(spec["absent"]) is bool, "readback parameters")
        if grouped:
            value = schedule_inventory(aws, spec, guard)
            reports.append({"service": spec["service"], "operation": spec["operation"], "observed": _dates(value)})
            continue
        guard.check(20)
        try:
            value = aws.call(spec["service"], spec["operation"], **spec["parameters"])
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code")
            c.require(spec["absent"] is True and code in {"ResourceNotFoundException", "StateMachineDoesNotExist", "ResourceNotFound"}, "readback unknown")
            value = {"absent": True}
        else:
            c.require(spec["absent"] is False, "resource still exists/DELETING")
            value.pop("ResponseMetadata", None)
            if spec["operation"] in {"get_schedule_group", "describe_state_machine"}:
                c.require(value.get("State", value.get("status")) == "ACTIVE", "resource DELETING/unknown")
        guard.check()
        reports.append({"service": spec["service"], "operation": spec["operation"], "observed": _dates(value)})
    return reports



def mode_canary_readbacks(aws, *, account, expected, preparation_admitted_at, preparation_deadline,
                         guard, clock=time.time, sleep=time.sleep):
    """Finite original IAM observations; never a claim of real propagation.

    Expected normalized documents must come from the independently audited plan
    and actual applied state. This function does not authenticate those inputs
    or admit an application operation by itself.
    """
    aliases = sorted(name for name in lc.APPLICATION_DELEGATIONS if name.startswith("mode_"))
    c.require(re.fullmatch(r"[0-9]{12}", account) and type(expected) is dict and set(expected) == set(aliases),
              "mode readback exact inventory/account")
    c.integer(preparation_admitted_at)
    c.integer(preparation_deadline)
    c.require(preparation_admitted_at < preparation_deadline <= preparation_admitted_at + 900, "mode original prepare deadline")
    specifications, originals = [], []
    for alias in aliases:
        c.closed(expected[alias], "role policy")
        role, policy = expected[alias]["role"], expected[alias]["policy"]
        c.closed(role, "Role")
        c.closed(policy, "RoleName PolicyName PolicyDocument")
        name = "cnesdata-prod-" + lc.APPLICATION_DELEGATIONS[alias]
        c.require(role["Role"]["RoleName"] == policy["RoleName"] == name
                  and role["Role"]["Arn"] == "arn:aws:iam::" + account + ":role/" + name
                  and role["Role"]["MaxSessionDuration"] == 3600 and policy["PolicyName"] == name + "-runtime",
                  "mode readback exact role/policy")
        for operation, parameters, document in (("get_role", {"RoleName": name}, role),
                ("get_role_policy", {"RoleName": name, "PolicyName": name + "-runtime"}, policy)):
            specifications.append({"service": "iam", "operation": operation, "parameters": parameters, "absent": False})
            originals.append({"service": "iam", "operation": operation, "observed": _dates(document)})
    original_raw = c.canonical(originals, limit=1024**2)
    observations, first_completed = [], None
    for index in range(2):
        if index:
            guard.check(30)
            c.require(clock() + 30 < preparation_deadline, "mode readback spacing budget")
            sleep(10)
            guard.check()
            c.require(clock() >= first_completed + 10, "mode readback minimum spacing")
        reports = []
        for specification in specifications:
            c.require(preparation_admitted_at <= clock() and clock() + 20 < preparation_deadline, "mode readback original deadline")
            reports.extend(readbacks(aws, [specification], guard))
            c.require(clock() < preparation_deadline, "mode readback completed before deadline")
        c.require(c.canonical(reports, limit=1024**2) == original_raw, "mode readback original document equality")
        completed = clock()
        observations.append({"observed_at": int(completed), "observations": reports})
        if not index:
            first_completed = completed
    return {"proof_kind": "iam-readback-and-evaluation", "readbacks": observations}


def fence_role_readbacks(aws, *, account, expected, preparation_admitted_at, preparation_deadline,
                         guard, clock=time.time, sleep=time.sleep):
    """Finite reader for a future protected current-owner preparation producer.

    Expected documents must be derived from authenticated Phase A sources and
    actual state. This helper authenticates neither those producers nor the
    current owner/activation and returns no STS capability. The executable
    application broker remains closed until that composition exists.
    """
    from email.utils import parsedate_to_datetime
    c.require(type(account) is str and re.fullmatch(r"[0-9]{12}", account), "fence readback account")
    c.closed(expected, "role policy")
    c.closed(expected["role"], "Role")
    c.closed(expected["policy"], "RoleName PolicyName PolicyDocument")
    name = "cnesdata-prod-promotion-fence-operator"
    role, policy = expected["role"]["Role"], expected["policy"]
    c.require(role["RoleName"] == policy["RoleName"] == name
              and role["Arn"] == "arn:aws:iam::" + account + ":role/" + name
              and type(role["RoleId"]) is str and bool(role["RoleId"])
              and type(role["MaxSessionDuration"]) is int and role["MaxSessionDuration"] == 3600
              and role.get("PermissionsBoundary") is None and policy["PolicyName"] == name + "-gate",
              "fence original role/policy identity")
    c.integer(preparation_admitted_at)
    c.integer(preparation_deadline)
    c.require(preparation_admitted_at < preparation_deadline <= preparation_admitted_at + 900, "fence original prepare deadline")
    specifications = [
        ("get_role", {"RoleName": name}, expected["role"]),
        ("list_role_policies", {"RoleName": name, "MaxItems": 100}, {"PolicyNames": [name + "-gate"], "IsTruncated": False}),
        ("list_attached_role_policies", {"RoleName": name, "MaxItems": 100}, {"AttachedPolicies": [], "IsTruncated": False}),
        ("get_role_policy", {"RoleName": name, "PolicyName": name + "-gate"}, policy),
    ]
    specifications = [(operation, parameters, c.canonical(_exact_sdk_dates(document)))
                      for operation, parameters, document in specifications]
    observations, first_completed = [], None
    for index in range(2):
        if index:
            guard.check(30)
            c.require(clock() + 30 < preparation_deadline, "fence readback spacing budget")
            sleep(10)
            guard.check()
            c.require(clock() >= first_completed + 10, "fence readback minimum spacing")
        reports = []
        for operation, parameters, original in specifications:
            c.require(preparation_admitted_at <= clock() and clock() + 20 < preparation_deadline, "fence readback original deadline")
            guard.check(20)
            response = aws.call("iam", operation, **parameters)
            guard.check()
            c.require(clock() < preparation_deadline, "fence readback completed before deadline")
            metadata = response.get("ResponseMetadata", {})
            c.require(type(metadata.get("RequestId")) is str and bool(metadata["RequestId"])
                      and metadata.get("HTTPStatusCode") == 200
                      and type(metadata.get("HTTPHeaders", {}).get("date")) is str, "fence original SDK metadata")
            server_date = parsedate_to_datetime(metadata["HTTPHeaders"]["date"])
            c.require(server_date.tzinfo is not None and abs(clock() - server_date.timestamp()) <= 30, "fence SDK clock uncertainty")
            value = {key: item for key, item in response.items() if key != "ResponseMetadata"}
            c.require(c.canonical(_exact_sdk_dates(value)) == original, "fence original source/state document equality")
            reports.append({"service": "iam", "operation": operation, "parameters": parameters, "response": _exact_sdk_dates(response)})
        completed = clock()
        observations.append({"observed_at": int(completed), "observations": reports})
        if not index:
            first_completed = completed
    return {"proof_kind": "iam-readback-and-evaluation", "readbacks": observations}


def _exact_sdk_dates(value):
    from datetime import datetime, timezone
    if type(value) is datetime:
        c.require(value.tzinfo is not None and value.utcoffset() is not None, "SDK timestamp timezone")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if type(value) is dict:
        return {key: _exact_sdk_dates(item) for key, item in value.items()}
    if type(value) is list:
        return [_exact_sdk_dates(item) for item in value]
    return value


def schedule_inventory(aws, spec, guard):
    """Exhaust the exact group; unknown members block inverse group deletion."""
    c.closed(spec["parameters"], "GroupName")
    group = spec["parameters"]["GroupName"]
    c.require(type(group) is str and re.fullmatch(r"cnesdata-prod[a-z0-9-]{0,48}", group), "exact product group")
    members = spec["members"]
    c.require(spec["absent"] is False and type(members) is list and len(members) <= 32
              and all(type(name) is str for name in members)
              and len(set(members)) == len(members), "exact group member inventory")
    observed, seen_tokens, token = {}, set(), None
    for _ in range(100):
        guard.check()
        parameters = {"GroupName": group, "MaxResults": 100}
        if token is not None:
            parameters["NextToken"] = token
        page = aws.call("scheduler", "list_schedules", **parameters)
        guard.check()
        c.require(type(page) is dict and type(page.get("Schedules")) is list, "schedule page unknown")
        for schedule in page["Schedules"]:
            c.require(type(schedule) is dict and schedule.get("Name") in members
                      and schedule.get("GroupName") == group, "unknown schedule/group membership")
            name = schedule["Name"]
            c.require(name not in observed, "duplicate schedule page")
            observed[name] = schedule
        token = page.get("NextToken")
        if token is None:
            c.require(set(observed) == set(members), "missing schedule membership")
            return {"Schedules": [observed[name] for name in sorted(observed)]}
        c.require(type(token) is str and 0 < len(token) <= 2048 and token not in seen_tokens, "pagination token cycle")
        seen_tokens.add(token)
    raise ValueError("schedule pagination exceeds bounded inventory")

def _dates(value):
    from datetime import datetime
    if type(value) is datetime:
        return c.utc(value.timestamp())
    if type(value) is dict:
        return {k: _dates(v) for k, v in value.items()}
    if type(value) is list:
        return [_dates(v) for v in value]
    return value



def authenticate_infrastructure_closure(product, source, expected):
    """Authenticate the whole tracked OpenTofu tree, including ASL/templates.

    IAM's .tf-only resolver inventory is insufficient for the evaluated plan.
    Equality to every tracked infra blob prevents a manifest from omitting an
    indirect file/templatefile dependency while keeping the checkout clean.
    """
    c.digest(source, 40)
    c.require(type(expected) is dict and 0 < len(expected) <= 4096, "infrastructure closure inventory")
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all", "--", "infra/opentofu"],
                            cwd=product, capture_output=True, check=True, timeout=5)
    c.require(not status.stdout, "dirty infrastructure closure")
    tree = subprocess.run(["git", "ls-tree", "-r", "-z", source, "--", "infra/opentofu"],
                          cwd=product, capture_output=True, check=True, timeout=5).stdout
    c.require(tree.endswith(b"\0"), "infrastructure source tree")
    result = {}
    for entry in tree[:-1].split(b"\0"):
        metadata, encoded_name = entry.split(b"\t", 1)
        mode, kind, _ = metadata.split(b" ")
        name = encoded_name.decode("utf-8")
        c.require(mode in {b"100644", b"100755"} and kind == b"blob"
                  and re.fullmatch(r"infra/opentofu/[A-Za-z0-9_./-]+", name)
                  and name in expected and ".." not in name.split("/"), "source file mode/path/inventory")
        path = product / name
        c.require(path.is_file() and not path.is_symlink() and product.resolve() in path.resolve().parents,
                  "source real checkout file")
        original = subprocess.run(["git", "show", source + ":" + name], cwd=product,
                                  capture_output=True, check=True, timeout=5).stdout
        c.require(len(original) <= 1024 * 1024 and path.read_bytes() == original
                  and c.sha(original) == c.digest(expected[name]), "infrastructure original blob")
        result[name] = original
    c.require(set(result) == set(expected) and sum(map(len, result.values())) <= 16 * 1024**2,
              "complete infrastructure closure")
    return result

def _activation_profile(governance, reference):
    """The single ext2.history profile whose reference equals the selection; ceiling-bound."""
    from tools.cnesdata_delivery import evidence as e, session_policy, signing_gate
    profile = signing_gate._selection(governance["ext2"], {"mode": "historical", "ext2_post_upload_receipt_v1": dict(reference)})
    storage, ceiling = e.storage_config(profile), session_policy.activation_ceiling(governance)
    c.require(storage["bucket_arn"] == ceiling["bucket_arn"] and storage["cipher_kms_key_arn"] == ceiling["cipher_kms_key_arn"]
              and list(storage["current_keys"]) == [ceiling["keys"][slot] for slot in session_policy.ACTIVATION_SLOTS],
              "activation profile equals protected read ceiling")
    return profile, storage


def operational_inputs(raw, *, governance, owner, window):
    """Unwrap the operational preparation carrier against the protected read ceiling; no fallback.

    Item 9: the deploy revalidates SPKI, profile hash and signature locally; it reads no EXT2 object.
    """
    from tools.cnesdata_delivery import session_policy
    ceiling = session_policy.activation_ceiling(governance)
    decoded = lc.inputs_envelope(raw, owner=owner, window=window)
    for slot, reference in decoded["objects"].items():
        c.require(reference["bucket_arn"] == ceiling["bucket_arn"] and reference["cipher_kms_key_arn"] == ceiling["cipher_kms_key_arn"]
                  and reference["key"] == ceiling["keys"][slot], "envelope object within protected activation ceiling")
    revalidate_activation(governance, c.loads(raw, canonical=True, limit=lc.ENVELOPE_LIMIT)["activation"], decoded["activation"])
    return decoded


def revalidate_activation(governance, activation, decoded):
    """Local deploy-side EXT2 revalidation: governed profile hash, SPKI and signature; no EXT2 read."""
    from tools.cnesdata_delivery import signing_gate
    profile, _ = _activation_profile(governance, activation["ext2_reference"])
    c.require(activation["ext2_governance_sha256"] == c.sha(c.canonical(profile)), "envelope original EXT2 profile hash")
    spki = decoded["signing_spki"]
    c.require(spki == signing_gate._governed_signing_spki(profile), "envelope original EXT2 SPKI")
    signing_gate.verify_signature(decoded["payload"], decoded["signature"], spki, governance=profile)


ACTIVATION_POLICY_LIMIT = 2048


def activation_session_factory(governance, run):
    """Production read sessions: one OIDC exchange per activation_request scope, size-checked first."""
    from tools.cnesdata_delivery import session_policy, signing_gate
    def open_session(versions, deadline):
        restriction = session_policy.activation_request(governance, versions, deadline=deadline)
        c.require(len(restriction["Policy"].encode()) <= ACTIVATION_POLICY_LIMIT, "activation session policy size")
        credentials = oidc_credentials(governance, "plan", restriction, run)
        return signing_gate._sdk_clients(credentials)["s3"]
    return open_session


def plan_activation_carrier(*, governance, step, owner, window, terraform_raw, github, session_factory, now):
    """Original EXT2 authentication inside the operational plan (amendment 2026-11-13 item 9).

    Public reference, receipt-only session, receipt read, three-pair session,
    complete historical verify_ext2_reference, then render_ext2 from the real
    VerifiedActivation. The EXT2 gate configuration/invocation is never called.
    """
    import base64
    from datetime import datetime, timezone
    from tools.cnesdata_delivery import evidence as e, ext2_transport as t, signing_gate
    selection = step.get("activation_selection")
    c.closed(selection, "selection_version ext2_post_upload_receipt_v1")
    c.require(type(selection["selection_version"]) is int and selection["selection_version"] == 1, "activation selection version")
    reference = dict(selection["ext2_post_upload_receipt_v1"])
    t.validate_reference(reference)
    profile, storage = _activation_profile(governance, reference)
    moment = datetime.fromtimestamp(now, timezone.utc)
    authenticated = t.authenticate_reference(reference, github=github, governance=profile, current_invocation=None, now=moment)
    member = authenticated.receipt_reference
    deadline = c.utc(window["preparation_deadline"])
    receipt_s3 = session_factory({"receipt": member["receipt_version_id"]}, deadline)
    receipt_object = e.read_version({"bucket_arn": storage["bucket_arn"], "key": storage["current_keys"][2],
        "version_id": member["receipt_version_id"], "content_sha256": member["receipt_sha256"],
        "content_length": member["receipt_size"], "server_side_encryption": "aws:kms",
        "cipher_kms_key_arn": storage["cipher_kms_key_arn"], "bucket_key_enabled": False}, s3=receipt_s3, governance=profile)
    receipt = t.loads(receipt_object.body, 65536)
    versions = {"payload": receipt["object"]["version_id"], "signature": receipt["signature_object"]["version_id"],
                "receipt": member["receipt_version_id"]}
    verified = signing_gate.verify_ext2_reference(reference, github=github, s3=session_factory(versions, deadline),
                                                  governance=profile, now=moment, historical=True)
    request = {"request_version": 1, "mode": "historical", "inputs": None,
               "source_sha": t.hex_digest(profile["invocation"]["source_sha"], 40), "ext2_post_upload_receipt_v1": dict(reference)}
    rendered = signing_gate._load_consumer(profile, request, github).render(verified, profile)
    def blob(raw):
        return {"sha256": c.sha(raw), "size": len(raw), "bytes_base64": base64.b64encode(raw).decode()}
    objects = {slot: dict(item.reference()) | {"content_length": len(item.body)} for slot, item in
               (("payload", verified.payload_object), ("signature", verified.signature_object), ("receipt", verified.receipt_object))}
    carrier = {"lifecycle_inputs_version": 2, "owner": owner,
        "preparation": {"admitted_at": window["admitted_at"], "deadline": window["deadline"], "observed_at": int(now)},
        "terraform": blob(terraform_raw),
        "activation": {"carrier_version": 1, "ext2_reference": reference, "ext2_governance_sha256": c.sha(c.canonical(profile)),
            "payload": blob(verified.payload_bytes), "signature": blob(verified.signature_der), "receipt": blob(verified.receipt_bytes),
            "signing_spki": blob(verified.signing_spki_der), "objects": objects, "rendered_targets": rendered}}
    raw = c.canonical(carrier, limit=lc.ENVELOPE_LIMIT)
    lc.inputs_envelope(raw, owner=owner, window=window)
    return raw


def execute(role):
    from tools.cnesdata_delivery import runtime
    from tools.cnesdata_delivery.iam_boundary import authenticate_sources, prepare
    governance, request, step, api, run, public = admission(role)
    c.require(not (role == "plan" and step["mode"] == "operational") or type(step.get("activation_selection")) is dict,
              "operational plan requires activation transport")
    aws = AWS(governance)
    from tools.cnesdata_delivery import session_owner
    application_authority = session_owner.authenticate_lifecycle(governance, api, request["source_sha"], "application", "application-prepare", time.time())
    authority = session_owner.authenticate_lifecycle(governance, api, request["source_sha"], role, step["purpose"], time.time())
    session_owner.verify_managed(aws, authority, c.instant(os.environ["AWS_CREDENTIAL_EXPIRATION"]))
    record, _ = S3LeaseStore(aws).get()
    owner = lc.owner_binding(record)
    c.require(owner["source_sha"] == request["source_sha"] and owner["run_id"] == run["id"]
              and owner["run_attempt"] == run["run_attempt"]
              and lc.application_identity(owner, required=True) == {"application_purpose": request["application_purpose"],
                  "context_kind": governance["context_kind"], "caller_binding_sha256": request["caller_binding_sha256"]},
              "original owner run/caller")
    lease = lc.DelegatedLeaseView(S3LeaseStore(aws), owner, monotonic=time.monotonic)
    guard = LifecycleWatchdog(lease, record["lifecycle"], c.instant(os.environ["AWS_CREDENTIAL_EXPIRATION"]))
    guard.check()
    predecessor = authenticate_predecessor(api, governance)
    c.require(record["lifecycle"]["predecessor_sha256"] == c.sha(c.canonical(predecessor)), "original keeper predecessor commitment")
    transport = keeper_transport(aws=aws, governance=governance, owner=owner, predecessor=predecessor, guard=guard)
    carrier = transport["phase_a_originals"]
    historical = lc.phase_a_originals(carrier)
    c.require(historical["envelope"]["plan"]["phase_a_inputs"]["canary_trusted_principal_arn"] ==
              application_authority.application_fragment["application_role_arn"], "original Phase A/current application principal")
    payload, plan_indexes = {}, []
    for input_name, public_files in public.items():
        index, files = private_payload(aws, governance, request, run, public_files, guard=guard)
        c.require(index["step"] == step["input_jobs"][input_name]["step"], "private original producer step")
        c.require(index["owner_sha256"] == owner["owner_sha256"] and index["generation"] == owner["generation"], "payload original owner")
        c.require(not set(files) & set(payload), "ambiguous private payload")
        payload.update(files)
        if "plan.json" in files:
            plan_indexes.append(index)
    product = Path.cwd() / "product"
    source = subprocess.run(["git", "rev-parse", "HEAD"], cwd=product, capture_output=True, text=True, check=True, timeout=5).stdout.strip()
    c.require(source == request["source_sha"], "immutable product checkout")
    authenticate_infrastructure_closure(product, source, governance["source_closure"])
    sources = authenticate_sources(product, source)
    root = product / "infra/opentofu/env/prod"
    baseline = governance["baseline"]
    tofu = shutil.which("tofu")
    c.require(tofu and c.sha(Path(tofu).read_bytes()) == baseline["toolchain"]["opentofu"]["binary_sha256"]
              and c.sha((root / ".terraform.lock.hcl").read_bytes()) == baseline["toolchain"]["lock_sha256"], "pinned actual toolchain")
    guard.check(20)
    before_raw, before_object = aws.get_state()
    guard.check()
    before = c.state_identity(before_raw)
    if step.get("historical_entry") is True:
        c.require(role == "plan" or "checkpoint.json" in payload, "deploy must consume saved historical checkpoint")
        guard.check(20)
        payload["checkpoint.json"] = historical_checkpoint(aws, governance, governance["lifecycle_predecessor"], record,
                                                          raw=payload.get("checkpoint.json"))
        guard.check()
    checkpoint = c.loads(payload["checkpoint.json"], canonical=True)
    if step.get("historical_entry") is True and predecessor["protocol"] == "legacy-infra":
        c.require(payload["checkpoint.json"] == historical["raw"]["checkpoint.json"], "first checkpoint is original Phase A bytes")
    else:
        c.require(c.canonical(checkpoint["phase_a_originals"]) == c.canonical(carrier), "checkpoint preserves original Phase A custody")
    if step.get("historical_entry") is True and governance["predecessor_read"]["protocol"] == "legacy-infra":
        checkpoint_state = checkpoint["state_after"]
    else:
        checkpoint_state = checkpoint["state"]
        if step.get("historical_entry") is not True:
            c.require(c.canonical(checkpoint["owner"]) == c.canonical(owner), "same-owner checkpoint")
    c.require(checkpoint_state == before and checkpoint["state_object"] == before_object
              and c.sha(payload["checkpoint.json"]) == guard.window["checkpoint_sha256"], "real predecessor checkpoint")
    terraform_raw, activation_sha256 = payload["inputs.json"], None
    if role == "deploy" and step["purpose"] == "application-prepare" and step["mode"] == "operational":
        unwrapped = operational_inputs(terraform_raw, governance=governance, owner=owner, window=guard.window)
        terraform_raw, activation_sha256 = unwrapped["terraform"], unwrapped["activation_sha256"]
    inputs = c.loads(terraform_raw, canonical=True)
    original_phase = historical["envelope"]["plan"]["phase_a_inputs"]
    c.require(all(c.canonical(inputs.get(key)) == c.canonical(original_phase[key]) for key in
                  ("canary_storage_enabled", "canary_release_id", "canary_trusted_principal_arn")), "original Phase A release/principal inputs")
    c.validate_cost(governance["cost"], purpose=step["purpose"], stage=baseline["cost_context"],
                    evidence=baseline["cost_evidence"], manifest=baseline["cost_manifest"], now=time.time())
    with tempfile.TemporaryDirectory(prefix="cnesdata-lifecycle-") as directory:
        temp = Path(directory)
        temp.chmod(0o700)
        (temp / "inputs.json").write_bytes(terraform_raw)
        backend = dict(baseline["backend"]["configuration"])
        c.require(backend.pop("workspace") == "default" and backend.pop("type") == "s3", "backend kind/workspace")
        (temp / "backend.json").write_bytes(c.canonical(backend))
        env = runtime._environment()
        guard.run([tofu, "init", "-input=false", "-lockfile=readonly", "-backend-config=" + str(temp / "backend.json")],
                  cwd=root, env=env, output=temp / "init.log", timeout=45, mutating=False)
        c.effective_backend(c.loads((root / ".terraform/terraform.tfstate").read_bytes(), state=True), "default", baseline["backend"]["configuration"])
        published_inputs = payload["inputs.json"]
        if role == "plan" and step["purpose"] == "application-prepare" and step["mode"] == "operational":
            published_inputs = plan_activation_carrier(governance=governance, step=step, owner=owner, window=guard.window,
                terraform_raw=terraform_raw, github=api, session_factory=activation_session_factory(governance, run), now=time.time())
            guard.check()
        if role == "plan":
            guard.run([tofu, "plan", "-input=false", "-lock-timeout=20s", "-var-file=" + str(temp / "inputs.json"), "-out=" + str(temp / "plan.bin")],
                      cwd=root, env=env, output=temp / "plan.log", timeout=120)
            guard.run([tofu, "show", "-json", str(temp / "plan.bin")], cwd=root, env=env, output=temp / "plan.json", timeout=20, mutating=False)
            result_files = {"plan.bin": (temp / "plan.bin").read_bytes(), "plan.json": (temp / "plan.json").read_bytes(),
                            "inputs.json": published_inputs, "checkpoint.json": payload["checkpoint.json"]}
            # A saved plan is published unapproved; only the independent audit job
            # can authorize its digest for a subsequent deploy invocation.
            c._secrets(c.loads(result_files["plan.json"], state=True))
            status = "planned"
        else:
            approval = c.loads(payload["approval.json"], canonical=True)
            c.closed(approval, "version owner purpose direction plan_sha256 inputs_sha256 checkpoint_sha256 delta drift_matrix readbacks")
            c.require(approval["version"] == 1 and approval["owner"] == owner and approval["purpose"] == step["purpose"]
                      and approval["direction"] == step["direction"] and approval["plan_sha256"] == c.sha(payload["plan.bin"])
                      and approval["inputs_sha256"] == c.sha(payload["inputs.json"])
                      and approval["checkpoint_sha256"] == c.sha(payload["checkpoint.json"]), "independent exact plan audit")
            c.require(type(approval["delta"]) is dict
                      and all(approval["delta"].get(key) == step[key] for key in ("purpose", "direction", "mode")),
                      "independent protected step discriminants")
            c.require(step["mode"] != "mode-canary", "mode-canary executable oracle unavailable")
            plan = c.loads(payload["plan.json"], state=True)
            c.require(approval["delta"]["before"] == lc.state_resources(c.loads(before_raw, state=True)), "audit actual full state")
            lc.validate_delta(plan, approval["delta"])
            resolver = prepare(plan, inputs, governance["account_id"], step["purpose"], sources, mode=step["mode"])
            before_reports = readbacks(aws, approval["readbacks"]["before"], guard)
            c.drift_coverage(plan, before_reports, approval["drift_matrix"], source, step["purpose"], "before")
            (temp / "plan.bin").write_bytes(payload["plan.bin"])
            guard.run([tofu, "show", "-json", str(temp / "plan.bin")], cwd=root, env=env, output=temp / "saved.json", timeout=20, mutating=False)
            c.require(c.loads((temp / "saved.json").read_bytes(), state=True) == plan, "binary/json exact plan")
            current_raw, current_object = aws.get_state()
            c.require(current_object == before_object and c.state_identity(current_raw) == before, "checkpoint changed before apply")
            session_owner.verify_managed(aws, authority, c.instant(os.environ["AWS_CREDENTIAL_EXPIRATION"]))
            guard.run([tofu, "apply", "-input=false", "-lock-timeout=20s", str(temp / "plan.bin")],
                      cwd=root, env=env, output=temp / "apply.log", timeout=120)
            after_raw, after_object = aws.get_state()
            state = c.loads(after_raw, state=True)
            c.applied_state(plan, state)
            if resolver:
                from tools.cnesdata_delivery.iam_boundary import bind_state
                bind_state(resolver, state)
            reports = readbacks(aws, approval["readbacks"]["after"], guard)
            c.drift_coverage(plan, reports, approval["drift_matrix"], source, step["purpose"], "after", state=state)
            checkpoint = {"state": c.state_identity(after_raw), "state_object": after_object, "owner": owner,
                          "purpose": step["purpose"], "plan_sha256": c.sha(payload["plan.bin"]), "readbacks": reports,
                          "phase_a_originals": carrier}
            result_files = {"checkpoint.json": c.canonical(checkpoint), "approval.json": payload["approval.json"]}
            if step["purpose"] == "application-prepare" and step["mode"] == "operational":
                # Amendment 2026-11-13 item 6: the eight-file observation is produced inside this running gate.
                c.require(len(plan_indexes) == 1, "fence single authenticated current plan index")
                result_files = fence_prepare_package(api=api, aws=aws, governance=governance, request=request, run=run,
                    owner=owner, guard=guard, authority=application_authority, predecessor=predecessor, carrier=carrier,
                    plan_index=plan_indexes[0], plan_raw=payload["plan.json"], inputs_raw=payload["inputs.json"],
                    terraform_raw=terraform_raw, approval_raw=payload["approval.json"], previous_raw=payload["checkpoint.json"],
                    checkpoint_raw=result_files["checkpoint.json"], state_raw=after_raw, sources=sources,
                    activation_sha256=activation_sha256)
            status = "applied"
        guard.check()
        publish(aws, governance, request, run, owner, result_files, api, guard, temp, status)


def publish(aws, governance, request, run, owner, files, api, guard, temp, status):
    from tools.cnesdata_delivery import runtime
    prefix = namespace(governance, request, run)
    entries = []
    for name, raw in sorted(files.items()):
        guard.check(20)
        aws.put(governance["evidence_bucket"], prefix + name, raw)
        guard.check(20)
        observed, _ = aws.get(governance["evidence_bucket"], prefix + name)
        c.require(observed == raw, "private publication readback")
        entries.append({"name": name, "size": len(raw), "sha256": c.sha(raw)})
    index = {"version": 1, "source_sha": request["source_sha"], "run_id": run["id"], "run_attempt": run["run_attempt"],
             "step": request["step"], "owner_sha256": owner["owner_sha256"], "generation": owner["generation"], "files": entries,
             **lc.application_identity(owner)}
    directory = temp / "public"
    directory.mkdir()
    (directory / "index.json").write_bytes(c.canonical(index))
    receipt = runtime._upload(directory, "lifecycle-" + request["step"], guard, temp)
    runtime._verify_current_artifact(api, receipt, {"index.json": c.canonical(index)}, run["id"])
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for key, value in {"evidence_run_id": run["id"], "evidence_artifact_id": receipt["id"],
                           "evidence_artifact_digest": receipt["digest"], "evidence_status": status}.items():
            output.write(f"{key}={value}\n")


def credentials(role):
    from tools.cnesdata_delivery import session_owner, session_policy
    governance, request, step, api, run, _ = admission(role)
    session_owner.authenticate_lifecycle(governance, api, request["source_sha"], "application", "application-prepare", time.time())
    authority = session_owner.authenticate_lifecycle(governance, api, request["source_sha"], role, step["purpose"], time.time())
    restriction = session_policy.lifecycle_request(governance, request["source_sha"], run["id"], run["run_attempt"],
        role, request["step"], direction=step["direction"], delete_resources=step.get("delete_resources", []),
        predecessor=governance["predecessor_read"] if role == "plan" and step.get("historical_entry") is True else None)
    value = oidc_credentials(governance, role, restriction, run)
    session_owner.verify_managed(AWS(governance, credentials=value), authority, value["Expiration"].timestamp())
    export_credentials(value)


def oidc_credentials(governance, role, restriction, run):
    import urllib.request
    from urllib.parse import urlparse
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    from tools.cnesdata_delivery.aws_boundary import bounded
    from tools.cnesdata_delivery.session_policy import validate_response
    path = ("VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-application-gate.yml" if role == "application"
            else f"VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-{role}-gate.yml")
    workflow = path + "@" + governance["gate_shas"][role]
    caller = governance["authenticated_application_caller"]
    c.closed(caller, lc.CALLER_BINDING_FIELDS)
    lc.application_caller_binding(caller | {"event": "workflow_dispatch", "fragment_version": 4},
        {"workflow_sha": governance["gate_shas"]["application"], "source_closure_sha256": governance["application_source_closure_sha256"]})
    c.require(caller["application_purpose"] == governance["application_purpose"] and caller["source_sha"] == run["head_sha"]
              and caller["run_id"] == run["id"] and caller["run_attempt"] == run["run_attempt"], "original admitted caller before OIDC")
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    parsed = urlparse(url)
    c.require(parsed.scheme == "https" and parsed.hostname and parsed.hostname.endswith(".actions.githubusercontent.com"), "OIDC request host")
    req = urllib.request.Request(url + "&audience=sts.amazonaws.com", headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with urllib.request.urlopen(req, timeout=20) as response:
        token = c.loads(response.read(65536))["value"]
    parts = token.split(".")
    c.require(len(parts) == 3, "OIDC token")
    claims = c.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    c.require(claims["iss"] == "https://token.actions.githubusercontent.com" and claims["aud"] == "sts.amazonaws.com"
              and claims["sub"] == f"repo:{c.REPOSITORY}:environment:production:job_workflow_ref:{workflow}"
              and claims["job_workflow_ref"] == workflow and claims["repository"] == c.REPOSITORY
              and claims["ref"] == "refs/heads/develop" and int(claims["run_id"]) == run["id"]
              and int(claims["run_attempt"]) == run["run_attempt"], "OIDC original run/attempt/producer")
    c.require(claims["workflow_ref"] == caller["repository"] + "/" + caller["workflow_path"] + "@" + caller["ref"]
              and claims["workflow_sha"] == caller["source_sha"] and claims["sha"] == caller["source_sha"]
              and claims["event_name"] == "workflow_dispatch" and claims["environment"] == caller["environment"]
              and claims["run_id"] == str(caller["run_id"]) and claims["run_attempt"] == str(caller["run_attempt"]),
              "OIDC original purpose caller claims")
    client = boto3.client("sts", region_name="us-east-2", config=Config(signature_version=UNSIGNED,
        connect_timeout=5, read_timeout=10, retries={"total_max_attempts": 1}, ignore_configured_endpoint_urls=True))
    result = bounded(lambda: client.assume_role_with_web_identity(RoleArn=governance["roles"][role],
        RoleSessionName=f"cnesdata-{run['id']}-{run['run_attempt']}", WebIdentityToken=token, DurationSeconds=3600, **restriction))
    return validate_response(result)


def export_credentials(value):
    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
        secret = value[field]
        c.require(type(secret) is str and secret and "\n" not in secret and "\r" not in secret, "credential control channel")
        print("::add-mask::" + secret.replace("%", "%25"), flush=True)
    with open(os.environ["GITHUB_ENV"], "a") as output:
        for name, field in (("AWS_ACCESS_KEY_ID", "AccessKeyId"), ("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"), ("AWS_SESSION_TOKEN", "SessionToken")):
            output.write(name + "=" + value[field] + "\n")
        output.write("AWS_CREDENTIAL_EXPIRATION=" + c.utc(value["Expiration"].timestamp()) + "\n")


def main(role, operation):
    c.require(role in {"plan", "deploy"} and operation in {"preflight", "credentials", "execute"}, "closed lifecycle command")
    if operation == "preflight":
        admission(role)
    elif operation == "credentials":
        credentials(role)
    else:
        execute(role)
