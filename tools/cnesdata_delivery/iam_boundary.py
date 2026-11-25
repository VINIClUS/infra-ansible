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


def mode_effective_evaluation(documents, scope, *, evaluator_source_sha, observed_at):
    """Prepared mode-evaluation (P16b ruling 4 item 2): every promotion mode session case against its read-back role.

    Args: documents (application identity/managed, per-code application and mode sessions, per-alias role policies),
    scope {resources owner_sha256 role_arns session_names deadline}, evaluator source sha, observed_at.
    Returns: the fence-evaluation-shaped document. Raises: ValueError.
    """
    from tools.cnesdata_delivery import lifecycle_contract as lc
    c.digest(evaluator_source_sha, 40)
    reports = _mode_reports(documents, scope, observed_at, tuple(_mode_codes()))
    evaluation = {"schema_version": 1, "evaluator_source_sha": evaluator_source_sha,
                  "documents": {name: c.sha(c.canonical(value)) for name, value in documents.items()}, "cases": reports}
    lc.validate_mode_evaluation(evaluation)
    return evaluation


def mode_stage_evaluation(evaluation, documents, scope, *, code):
    """Stage recompute (closed-ready pattern): this session's cases from its own documents equal the prepared ones.

    Returns: the prepared rows of code. Raises: ValueError before any STS call.
    """
    from tools.cnesdata_delivery import lifecycle_contract as lc
    c.require(type(code) is str and code in _mode_codes(), "mode stage evaluation code")
    lc.validate_mode_evaluation(evaluation)
    names = _mode_document_names((code,))
    c.require(type(documents) is dict and set(documents) == names
              and all(evaluation["documents"][name] == c.sha(c.canonical(documents[name])) for name in names),
              "mode stage evaluation documents")
    prepared = [case for case in evaluation["cases"] if lc.MODE_EVALUATION_CASES[case["case_id"]][0] == code]
    observed_at = next(case["context"]["aws:CurrentTime"] for case in prepared if case["case_id"] == "assume-" + code)
    c.require(c.canonical(_mode_reports(documents, scope, observed_at, (code,))) == c.canonical(prepared),
              "mode stage evaluation cases")
    return prepared


def _mode_codes():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    codes = {code: (operation, alias) for operation, (code, alias, context, _) in lc.MODE_SESSION_OPERATIONS.items()
             if context == "promotion"}
    return codes | {part: codes[session] for part, session in lc.MODE_SESSION_PARTS.items()}


def _mode_session_code(code):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    return lc.MODE_SESSION_PARTS.get(code, code)


def _mode_document_names(codes):
    operations = _mode_codes()
    return {"application_identity", "application_managed", *(f"application_session.{_mode_session_code(code)}" for code in codes),
            *(f"session.{code}" for code in codes), *(f"role.{operations[code][1]}" for code in codes)}


def _mode_scope(scope, operations):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    c.closed(scope, "resources owner_sha256 role_arns session_names deadline")
    c.integer(scope["deadline"])
    c.closed(scope["role_arns"], " ".join(lc.MODE_ALIASES))
    c.closed(scope["session_names"], " ".join(code for code in operations if code not in lc.MODE_SESSION_PARTS))
    c.require(all(type(arn) is str and re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/cnesdata-prod-" + alias.replace("_", "-"), arn)
                  for alias, arn in scope["role_arns"].items())
              and all(type(name) is str and re.fullmatch(f"mc-{code}-[0-9a-f]{{40}}", name)
                      for code, name in scope["session_names"].items()), "mode evaluation scope")


def _mode_reports(documents, scope, observed_at, codes):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    operations = _mode_codes()
    c.require(type(documents) is dict and set(documents) == _mode_document_names(codes), "mode evaluation documents")
    _mode_scope(scope, operations)
    c.require(type(observed_at) is str and c.instant(observed_at) < scope["deadline"], "mode evaluation before session deadline")
    for code in codes:
        expected = mode_session_document(code, operations[code][0], scope)
        c.require(c.canonical(documents["session." + code]) == c.canonical(expected), "mode evaluation session document")
    specs = _mode_case_specs(scope, operations)
    reports = []
    for case_id, (code, action) in lc.MODE_EVALUATION_CASES.items():
        if code not in codes:
            continue
        resource, context, expected, expired = specs[case_id]
        context = {"aws:CurrentTime": c.utc(scope["deadline"]) if expired else observed_at} | context
        if case_id.startswith("assume-"):
            observed = effective_iam(documents["application_identity"], [documents["application_managed"],
                                     documents["application_session." + _mode_session_code(code)]], action, resource, context)
        else:
            observed = effective_iam(documents["role." + operations[code][1]], [documents["session." + code]], action,
                                     resource, context)
        c.require(observed is expected, "effective IAM case " + case_id)
        reports.append({"case_id": case_id, "action": action, "resource": resource, "context": context,
                        "expected": expected, "observed": observed})
    return reports


def mode_session_document(code, operation, scope):
    """The session policy of one mode session code (a part included) on the evaluation scope, as the stage mints it.

    Returns: the policy document. Raises: ValueError before any STS call.
    """
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.session_policy import mode_session_policy, mode_unit_wait_policy
    if code in lc.MODE_SESSION_PARTS:
        return mode_unit_wait_policy(resources=scope["resources"], deadline=scope["deadline"])
    return mode_session_policy(operation, resources=scope["resources"], owner_sha256=scope["owner_sha256"],
                               deadline=scope["deadline"])


def _mode_case_specs(scope, operations):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    targets = _mode_targets(scope)
    families = {"us": _mode_seed_specs(targets, "unit", "recovery"), "rs": _mode_seed_specs(targets, "recovery", "unit"),
                **_mode_start_specs(targets),
                **{code: _mode_observe_specs(targets, mode) for code, mode in (("uo", "unit"), ("ro", "recovery"), ("ao", "audit"))}}
    specs = {}
    for code, cases in families.items():
        role, name = scope["role_arns"][operations[code][1]], scope["session_names"][_mode_session_code(code)]
        specs[f"assume-{code}"] = (role, {"sts:RoleSessionName": name}, True, False)
        specs[f"assume-{code}-other-session"] = (role, {"sts:RoleSessionName": name + "-other"}, False, False)
        specs |= {f"{code}-{key}": value + (False,) for key, value in cases.items()}
        first = next(case for case, (owner, _) in lc.MODE_EVALUATION_CASES.items() if owner == code and not case.startswith("assume-"))
        specs[f"{code}-expired"] = specs[first][:2] + (False, True)
    c.require(set(specs) == set(lc.MODE_EVALUATION_CASES), "mode evaluation cases")
    return specs


def _mode_leading(key):
    return {"dynamodb:LeadingKeys": [key]}


def _mode_targets(scope):
    from tools.cnesdata_delivery.session_policy import MODE_SEED_RUN_PREFIXES
    resources, owner = scope["resources"], scope["owner_sha256"]
    tenant = "TENANT#" + resources["scope"]["tenant_id"].encode().hex()
    runs = {}
    for mode, prefixes in MODE_SEED_RUN_PREFIXES.items():
        found = [run for run in resources["scope"]["run_ids"] if run in {f"{prefix}-{owner[:16]}" for prefix in prefixes}]
        c.require(bool(found), "mode evaluation runs")
        runs[mode] = tenant + "#RUN#" + found[0].encode().hex()
    data, tasks = resources["data_bucket_arn"], resources["cluster_arn"].replace(":cluster/", ":task/")
    return {"resources": resources, "tenant": tenant, "runs": runs,
            "raw": data + "/" + resources["scope"]["raw_object_keys"][0],
            "output": data + "/" + resources["scope"]["output_object_keys"][0],
            "audit": resources["audit_bucket_arn"] + "/" + (resources["scope"]["audit_object_keys"] or ["probe"])[0],
            "task": tasks + "/" + "0" * 32, "foreign_task": tasks + "-foreign/" + "0" * 32,
            "execution": resources["machine_arn"].replace(":stateMachine:", ":execution:") + ":probe"}


def _mode_seed_specs(targets, own, other):
    table, tenant = targets["resources"]["table_arn"], targets["tenant"]
    return {"put-tenant": (table, _mode_leading(tenant), True), "put-own-run": (table, _mode_leading(targets["runs"][own]), True),
            "put-raw": (targets["raw"], {}, True),
            "put-foreign-tenant": (table, _mode_leading("TENANT#" + "prod-canary-foreign".encode().hex()), False),
            "put-other-mode-run": (table, _mode_leading(targets["runs"][other]), False),
            "get-fence": (table, _mode_leading("ENV#prod#FENCE"), False), "put-output": (targets["output"], {}, False)}


def _mode_start_specs(targets):
    resources, tenant = targets["resources"], _mode_leading(targets["tenant"])
    table, revisions, roles = resources["table_arn"], resources["revisions"], resources["task_role_arns"]
    cluster, foreign = {"ecs:cluster": resources["cluster_arn"]}, {"ecs:cluster": resources["cluster_arn"] + "-foreign"}
    passed = {"iam:PassedToService": "ecs-tasks.amazonaws.com"}
    return {
        "ux": {"put-ticket": (table, tenant, True), "put-binding": (table, _mode_leading(targets["runs"]["unit"]), True),
               "start-execution": (resources["machine_arn"], {}, True),
               "update-control": (table, tenant, False), "run-task": (revisions["recovery"], cluster, False),
               "stop-execution": (targets["execution"], {}, False),
               "put-recovery-run": (table, _mode_leading(targets["runs"]["recovery"]), False),
               "check-fence": (table, _mode_leading("ENV#prod#FENCE"), True),
               "update-semaphore": (table, _mode_leading("ENV#prod#SEMAPHORE"), True),
               "consume-attempt": (table, _mode_leading("ENV#prod#ATTEMPTS"), True),
               "check-unit-run": (table, _mode_leading(targets["runs"]["unit"]), True),
               "check-semaphore": (table, _mode_leading("ENV#prod#SEMAPHORE"), False),
               "query-unit-run": (table, _mode_leading(targets["runs"]["unit"]), False),
               "update-unit-run": (table, _mode_leading(targets["runs"]["unit"]), False),
               "describe-own-execution": (targets["execution"], {}, False)},
        "uw": {"describe-own-execution": (targets["execution"], {}, True), "describe-own-task": (targets["task"], cluster, True),
               "describe-foreign-cluster-task": (targets["foreign_task"], foreign, False),
               "start-execution": (resources["machine_arn"], {}, False)},
        "rx": {"run-recovery": (revisions["recovery"], cluster, True), "pass-recovery-role": (roles["recovery"], passed, True),
               "put-ticket": (table, tenant, True), "run-audit-revision": (revisions["audit"], cluster, False),
               "run-other-cluster": (revisions["recovery"], foreign, False), "pass-unit-role": (roles["unit"], passed, False),
               "put-run-partition": (table, _mode_leading(targets["runs"]["recovery"]), False),
               "start-execution": (resources["machine_arn"], {}, False)},
        "ax": {"run-audit": (revisions["audit"], cluster, True), "pass-audit-role": (roles["audit"], passed, True),
               "run-recovery-revision": (revisions["recovery"], cluster, False),
               "pass-other-role": (roles["recovery"], passed, False), "get-tenant": (table, tenant, False)}}


def _mode_observe_specs(targets, mode):
    resources = targets["resources"]
    specs = {"describe-machine": (resources["machine_arn"], {}, True),
             "describe-task-definition": (resources["revisions"][mode], {}, True),
             "get-tenant": (resources["table_arn"], _mode_leading(targets["tenant"]), False),
             "get-audit-object": (targets["audit"], {}, False)}
    if mode == "unit":
        return specs | {"get-output": (targets["output"], {}, True)}
    other = "audit" if mode == "recovery" else "recovery"
    return specs | {"get-own-schedule": (resources["schedule_arns"][mode], {}, True),
                    "describe-own-alarm": (resources["alarm_arns"][mode + "_repeated_failure"], {}, True),
                    f"get-{other}-schedule": (resources["schedule_arns"][other], {}, False),
                    "get-output": (targets["output"], {}, False)}


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
    present = {item["address"] for item in plan["resource_changes"] if item["type"] == "aws_iam_role_policy"}
    if mode == "mode-canary" or (mode == "operational" and present & set(MODE_POLICIES)):
        c.require(purpose == "application-prepare", "iam=mode_prepare_purpose")
        c.require(inputs.get("mode_canary") is not None
                  and plan.get("variables", {}).get("mode_canary", {}).get("value") == inputs["mode_canary"],
                  "iam=mode_exact_generated_input")
        c.require(set(MODE_POLICIES) <= present and (mode == "operational" or set(addresses) <= set(MODE_POLICIES)),
                  "iam=mode_policy_inventory")
        addresses = sorted(set(MODE_POLICIES) | (set(addresses) if mode == "operational" else set()))
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
