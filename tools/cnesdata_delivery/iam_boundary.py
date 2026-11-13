"""Authenticate producer source bytes and retain one bounded IAM authorization operation."""
from pathlib import Path
import re
import subprocess

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.iam_source import MODE_POLICIES, SourceResolver

DIRECTORIES = {"env/prod", *("modules/" + name for name in (
    "runtime-iam", "processing", "processor-registry", "control-plane", "schedulers", "athena", "data-buckets", "static-web"))}


def effective_iam(identity, sessions, action, resource, context):
    """Finite identity ∩ session-union evaluation; unknown semantics refuse.

    This evaluates authenticated native documents, never an authority supplied
    by an adapter. Trust/readbacks, SDK scope and original clocks remain gates.
    """
    from datetime import datetime
    c.require(type(sessions) is list and 1 <= len(sessions) <= 10 and type(context) is dict, "finite IAM inputs")
    c.require(type(action) is str and type(resource) is str, "finite IAM action/resource")

    def values(value):
        result = [value] if type(value) is str else value
        c.require(type(result) is list and 1 <= len(result) <= 256
                  and all(type(item) is str and 1 <= len(item) <= 2048 for item in result), "finite IAM patterns")
        c.require(all("${" not in item for item in result), "unresolved IAM policy variable")
        return result

    def match(actual, patterns, *, wildcard=False, folded=False):
        if type(actual) is not str:
            return False
        if folded:
            actual, patterns = actual.lower(), [item.lower() for item in patterns]
        return any(re.fullmatch(re.escape(item).replace(r"\*", ".*").replace(r"\?", "."), actual) is not None
                   if wildcard else actual == item for item in patterns)

    def condition(operator, key, raw):
        patterns = values(raw)
        actual = context.get(key)
        if operator == "Null":
            c.require(len(patterns) == 1 and patterns[0] in {"true", "false"}, "finite IAM Null")
            return (actual is None or actual == []) == (patterns[0] == "true")
        if operator == "ForAllValues:StringEquals":
            found = [] if actual is None else [actual] if type(actual) is str else actual
            c.require(type(found) is list and all(type(item) is str for item in found), "finite IAM multivalue")
            return all(item in patterns for item in found)
        if operator in {"DateLessThan", "DateGreaterThanEquals"}:
            if actual is None:
                return False
            c.require(type(actual) is str and len(actual) <= 128 and len(patterns) == 1, "finite IAM Date")
            now, deadline = (datetime.fromisoformat(item.replace("Z", "+00:00")) for item in (actual, patterns[0]))
            c.require(now.tzinfo is not None and deadline.tzinfo is not None, "finite IAM timezone")
            return now < deadline if operator == "DateLessThan" else now >= deadline
        c.require(operator in {"StringEquals", "StringLike", "ArnEquals", "ArnLike", "StringNotEquals", "StringNotLike", "ArnNotLike"},
                  "unsupported IAM condition")
        found = match(actual, patterns, wildcard=operator.endswith("Like"))
        return not found if "Not" in operator else found

    def decide(policy):
        c.canonical(policy, limit=65536)
        c.closed(policy, "Version Statement" + (" Id" if "Id" in policy else ""))
        c.require(policy["Version"] == "2012-10-17" and type(policy["Statement"]) is list
                  and len(policy["Statement"]) <= 256, "finite IAM document")
        accepted = False
        for statement in policy["Statement"]:
            c.require(type(statement) is dict and set(statement) <= {"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition"}
                      and statement.get("Effect") in {"Allow", "Deny"}
                      and ("Action" in statement) != ("NotAction" in statement)
                      and ("Resource" in statement) != ("NotResource" in statement), "finite IAM statement")
            action_key = "Action" if "Action" in statement else "NotAction"
            resource_key = "Resource" if "Resource" in statement else "NotResource"
            action_match = match(action, values(statement[action_key]), wildcard=True, folded=True)
            resource_match = match(resource, values(statement[resource_key]), wildcard=True)
            if action_match == (action_key == "NotAction") or resource_match == (resource_key == "NotResource"):
                continue
            conditions = statement.get("Condition", {})
            c.require(type(conditions) is dict and len(conditions) <= 16, "finite IAM conditions")
            passed = True
            for operator, entries in conditions.items():
                c.require(type(operator) is str and type(entries) is dict and 1 <= len(entries) <= 32, "finite IAM condition entries")
                for key, raw in entries.items():
                    c.require(type(key) is str and 1 <= len(key) <= 256, "finite IAM condition key")
                    passed = condition(operator, key, raw) and passed
            if passed and statement["Effect"] == "Deny":
                return "Deny"
            accepted = accepted or passed
        return "Allow" if accepted else None

    decisions = [decide(policy) for policy in [identity, *sessions]]
    return "Deny" not in decisions and decisions[0] == "Allow" and "Allow" in decisions[1:]


def fence_effective_evaluation(documents, scope, *, evaluator_source_sha, observed_at):
    """Measure the finite contract against independently authenticated documents."""
    from tools.cnesdata_delivery.lifecycle_contract import FENCE_EVALUATION_CASES
    c.closed(documents, "application_identity application_managed application_session fence_identity fence_session freeze")
    c.closed(scope, "role_arn session_name control_table_arn execution_arn foreign_execution_arn evidence_arn lease_arn")
    freeze = c.closed(documents["freeze"], "frozen_until application_fragment_sha256 owner_policy_sha256")
    c.require(c.instant(observed_at) < c.instant(freeze["frozen_until"]), "original finite IAM freeze")
    c.digest(freeze["application_fragment_sha256"])
    c.digest(freeze["owner_policy_sha256"])
    c.digest(evaluator_source_sha, 40)
    for value in scope.values():
        c.require(type(value) is str and 1 <= len(value) <= 2048 and "*" not in value and "?" not in value,
                  "exact finite IAM evaluation scope")
    c.require(scope["execution_arn"] != scope["foreign_execution_arn"], "distinct foreign execution control")
    now = {"aws:CurrentTime": observed_at}
    cases = {
        "assume-exact": ("application", scope["role_arn"], now | {"sts:RoleSessionName": scope["session_name"]}, True),
        "assume-other-session": ("application", scope["role_arn"], now | {"sts:RoleSessionName": scope["session_name"] + "-foreign"}, False),
        "app-direct-get": ("application", scope["control_table_arn"], now | {"dynamodb:LeadingKeys": ["ENV#prod#FENCE"]}, False),
        "get-fence": ("fence", scope["control_table_arn"], now | {"dynamodb:LeadingKeys": ["ENV#prod#FENCE"]}, True),
        "get-tenant": ("fence", scope["control_table_arn"], now | {"dynamodb:LeadingKeys": ["TENANT#foreign"]}, False),
        "update-fence": ("fence", scope["control_table_arn"], now | {"dynamodb:LeadingKeys": ["ENV#prod#FENCE"]}, False),
        "probe-own": ("fence", scope["execution_arn"], now, True),
        "probe-foreign": ("fence", scope["foreign_execution_arn"], now, False),
        "write-own-evidence": ("application", scope["evidence_arn"], now, True),
        "put-lease": ("application", scope["lease_arn"], now, False),
        "freeze-expired": ("fence", scope["control_table_arn"], {"aws:CurrentTime": freeze["frozen_until"], "dynamodb:LeadingKeys": ["ENV#prod#FENCE"]}, False),
    }
    reports = []
    for case_id, action in FENCE_EVALUATION_CASES.items():
        principal, resource, context, expected = cases[case_id]
        sessions = ([documents["application_managed"], documents["application_session"]] if principal == "application"
                    else [documents["fence_session"]])
        observed = effective_iam(documents[principal + "_identity"], sessions, action, resource, context)
        c.require(observed is expected, "effective IAM case " + case_id)
        reports.append({"case_id": case_id, "action": action, "resource": resource, "context": context,
                        "expected": expected, "observed": observed})
    return {"schema_version": 1, "evaluator_source_sha": evaluator_source_sha,
            "documents": {name: c.sha(c.canonical(value)) for name, value in documents.items()}, "cases": reports}


def authenticate_sources(product: Path, source: str) -> dict[str, bytes]:
    """Read only tracked immutable blobs and require equal checkout bytes."""
    c.digest(source, 40)
    clean = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all", "--", "infra/opentofu"],
                           cwd=product, capture_output=True, check=True, timeout=5)
    c.require(not clean.stdout, "iam=dirty_or_untracked_source")
    result = subprocess.run(["git", "ls-tree", "-r", "-z", "--name-only", source, "--", "infra/opentofu"],
                            cwd=product, capture_output=True, check=True, timeout=5)
    c.require(result.stdout.endswith(b"\0"), "iam=source_tree_shape")
    names = result.stdout.decode("utf-8").split("\0")[:-1]
    selected = [name for name in names if name.endswith(".tf") and name.removeprefix("infra/opentofu/").rsplit("/", 1)[0] in DIRECTORIES]
    c.require(0 < len(selected) <= 64 and len(set(selected)) == len(selected), "iam=source_inventory")
    sources = {}
    for name in selected:
        c.require(re.fullmatch(r"infra/opentofu/(?:env/prod|modules/[a-z0-9-]+)/[a-z0-9_.-]+\.tf", name), "iam=source_path")
        path = product / name
        c.require(path.is_file() and not path.is_symlink() and product.resolve() in path.resolve().parents, "iam=source_checkout_path")
        raw = subprocess.run(["git", "show", source + ":" + name], cwd=product,
                             capture_output=True, check=True, timeout=5).stdout
        c.require(len(raw) <= 256 * 1024 and path.read_bytes() == raw, "iam=immutable_source_bytes")
        sources[name] = raw
    c.require(sum(map(len, sources.values())) <= 2 * 1024**2, "iam=source_total")
    return sources


def prepare(plan, inputs, account, purpose, sources, *, mode=None):
    addresses = sorted(item["address"] for item in plan["resource_changes"]
                       if item["type"] == "aws_iam_role_policy" and item["change"]["actions"] != ["no-op"])
    if mode == "mode-canary":
        c.require(purpose == "application-prepare", "iam=mode_prepare_purpose")
        c.require(inputs.get("mode_canary") is not None
                  and plan.get("variables", {}).get("mode_canary", {}).get("value") == inputs["mode_canary"],
                  "iam=mode_exact_generated_input")
        present = {item["address"] for item in plan["resource_changes"] if item["type"] == "aws_iam_role_policy"}
        c.require(set(MODE_POLICIES) <= present and set(addresses) <= set(MODE_POLICIES), "iam=mode_policy_inventory")
        addresses = sorted(MODE_POLICIES)
    if not addresses:
        return None
    resolver = SourceResolver(plan, sources, {"generated_inputs": inputs, "account_id": account,
                                             "region": "us-east-2", "purpose": purpose, "mode": mode})
    for address in addresses:
        resolver.precheck(address)
    return resolver


def bind_state(resolver, state):
    c.require(resolver is not None, "iam=source_resolver_required")
    resources = {}
    for row in state["resources"]:
        if row.get("mode") != "managed":
            continue
        prefix = (row.get("module", "") + ".") if row.get("module") else ""
        base = prefix + row["type"] + "." + row["name"]
        for instance in row["instances"]:
            key = instance.get("index_key")
            address = base if key is None else base + "[" + c.canonical(key, 4096).decode().strip() + "]"
            c.require(address not in resources, "iam=state_duplicate")
            resources[address] = instance["attributes"]
    resolver.bind(resources)
    resolver.verify_state(state)
    return resources


def verify_api(resolver, resources, parameters, observed):
    addresses = [address for address in resolver.traces if resources[address]["name"] == parameters["PolicyName"]
                 and resources[address]["role"] == parameters["RoleName"]]
    if not addresses:
        return None
    c.require(len(addresses) == 1, "iam=source_policy_api_binding")
    address = addresses[0]
    module, local = address.removeprefix("module.").split(".", 1)
    name = resolver.evaluate(module, resolver.attribute(module, ("resource", local.split("[", 1)[0], "name")), resolver.instance_scope(address))
    expected = {"RoleName": resolver.role_values[address], "PolicyName": name, "PolicyDocument": resolver.policy(address)}
    c.require(observed == expected, "iam=source_policy_api_document")
    return address
