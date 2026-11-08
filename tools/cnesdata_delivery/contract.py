"""Closed A3 field validation against #28/6715994616; not a competing schema.

No network/credentials here. The consumer-owned JSON schema remains #468's work.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import PurePosixPath

LIMIT = 128 * 1024**2
REPOSITORY = "VINIClUS/CnesData"
CONTRACT_SHA = "7ebc0e3dc024617b33903577c87dac3ca6fba529"
CONTRACT_PATH = "docs/superpowers/specs/2026-11-07-phase-a-contract-amendment.md"
PURPOSES = {"acm-certificate", "bootstrap", "phase-a"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def scheduler_preflight(plan, state):
    """Compare resolved saved-plan inputs to the *previous* applied revisions."""
    variables = plan.get("variables")
    require(type(variables) is dict, "scheduler resolved variables absent")
    inputs = {}
    for mode in ("recovery", "audit"):
        value = variables.get(f"scheduler_{mode}_task_definition_arn")
        require(type(value) is dict and set(value) == {"value"}, "scheduler unresolved input")
        inputs[mode] = value["value"]
    outputs = state.get("outputs", {}) if state is not None else {}
    require(type(outputs) is dict, "scheduler prior outputs malformed")
    output = outputs.get("processor_task_definition_arns")
    require("processor_task_definition_arns" not in outputs or type(output) is dict and "value" in output,
            "scheduler prior output malformed")
    revisions = output["value"] if output is not None else None
    if revisions is None or revisions == {}:
        # Initial bootstrap (including the first Phase A after bootstrap) has
        # neither applied revisions nor Schedulers. Missing output alone is no proof.
        resources = state.get("resources", []) if state is not None else []
        require(not any(resource.get("mode") == "managed"
                        and resource.get("type") in {"aws_ecs_task_definition", "aws_scheduler_schedule"}
                        and resource.get("instances") for resource in resources)
                and all(value is None for value in inputs.values()),
                "scheduler output absent outside initial bootstrap")
        return
    require(type(revisions) is dict and set(revisions) == {"unit", "recovery", "audit"},
            "scheduler complete prior revision map required")
    for value in revisions.values():
        require(type(value) is str and re.fullmatch(
            r"arn:aws:ecs:us-east-2:[0-9]{12}:task-definition/[A-Za-z0-9_-]+:[1-9][0-9]*", value),
            "scheduler invalid prior revision")
    require(all(inputs[mode] == revisions[mode] for mode in inputs),
            "scheduler input differs from prior applied revision")


def applied_state(plan, state):
    """Resolve only saved-plan unknowns; no refreshed or replacement plan."""
    def match(expected, actual, unknown=False):
        if unknown is True:
            return
        if type(expected) is dict:
            require(type(actual) is dict and type(unknown) in (dict, bool), "saved-plan object")
            mask = unknown if type(unknown) is dict else {}
            require(set(actual) == set(expected) | set(mask), "saved-plan attribute set")
            for key in actual:
                match(expected.get(key), actual[key], mask.get(key, False))
        elif type(expected) is list:
            require(type(actual) is list and len(actual) == len(expected), "saved-plan list")
            require(type(unknown) in (list, bool), "saved-plan list mask")
            masks = unknown if type(unknown) is list else [False] * len(expected)
            require(len(masks) == len(expected), "saved-plan mask length")
            for value, observed, mask in zip(expected, actual, masks):
                match(value, observed, mask)
        else:
            require(type(expected) is type(actual) and expected == actual, "saved-plan known value changed")

    observed = {}
    for resource in state.get("resources", []):
        if resource.get("mode") != "managed":
            continue
        prefix = (resource.get("module", "") + ".").lstrip(".") + resource["type"] + "." + resource["name"]
        for instance in resource.get("instances", []):
            require(not instance.get("deposed"), "ambiguous deposed state; recovery_required")
            suffix = "[" + canonical(instance["index_key"])[:-1].decode() + "]" if "index_key" in instance else ""
            address = prefix + suffix
            require(address not in observed, "state address duplicate")
            observed[address] = instance["attributes"]
    changes = [item for item in plan.get("resource_changes", []) if item.get("mode") == "managed"
               and item["change"]["after"] is not None]
    require(len(changes) == len({item["address"] for item in changes})
            and set(observed) == {item["address"] for item in changes}, "saved-plan state resource set")
    for item in changes:
        change = item["change"]
        match(change["after"], observed[item["address"]], change.get("after_unknown", False))
    for name, change in plan.get("output_changes", {}).items():
        if change["after"] is None and not change.get("after_unknown"):
            require(name not in state.get("outputs", {}), "saved-plan removed output")
        else:
            require(name in state.get("outputs", {}), "saved-plan output missing")
            match(change["after"], state["outputs"][name]["value"], change.get("after_unknown", False))


def drift_coverage(plan, reports, matrix, source_sha, purpose, stage, state=None):
    """Every managed attribute must have a source-bound live projection.

    This deliberately refuses unsupported/unobservable fields. A production
    matrix and concrete provider/API projections remain an owner handoff;
    a nonempty collection of chosen API hashes cannot stand in for coverage.
    """
    closed(matrix, "matrix_version source_sha purpose before after")
    require(type(matrix["matrix_version"]) is int and matrix["matrix_version"] == 1
            and matrix["source_sha"] == source_sha and matrix["purpose"] == purpose
            and stage in {"before", "after"}, "governed drift matrix identity")
    changes = {item["address"]: item["change"] for item in plan.get("resource_changes", [])
               if item.get("mode") == "managed"}
    expected = {address: change[stage] for address, change in changes.items() if change[stage] is not None}
    if stage == "after":
        require(state is not None, "post drift state missing")
        applied_state(plan, state)
        expected = {}
        for resource in state.get("resources", []):
            if resource.get("mode") != "managed":
                continue
            prefix = (resource.get("module", "") + ".").lstrip(".") + resource["type"] + "." + resource["name"]
            for instance in resource.get("instances", []):
                suffix = "[" + canonical(instance["index_key"])[:-1].decode() + "]" if "index_key" in instance else ""
                expected[prefix + suffix] = instance["attributes"]
    required = {(address, name) for address, values in expected.items() for name in values}
    rows = matrix[stage]
    require(type(rows) is list and len(rows) <= 4096, "bounded drift coverage")
    seen = set()
    for row in rows:
        closed(row, "address attribute readback path encoding")
        key = (row["address"], row["attribute"])
        require(key in required and key not in seen, "unknown/duplicate drift coverage")
        seen.add(key)
        index = row["readback"]
        require(type(index) is int and 0 <= index < len(reports), "drift readback reference")
        require(type(row["path"]) is list and len(row["path"]) <= 32, "drift response path")
        observed = reports[index]["observed"]
        for component in row["path"]:
            if type(observed) is dict:
                require(type(component) is str and component in observed, "drift response field")
            else:
                require(type(observed) is list and type(component) is int and 0 <= component < len(observed), "drift response index")
            observed = observed[component]
        value = expected[row["address"]][row["attribute"]]
        require(row["encoding"] in {"identity", "json"}, "unknown drift projection encoding")
        if row["encoding"] == "json":
            value = loads(value.encode()) if type(value) is str else value
            observed = loads(observed.encode()) if type(observed) is str else observed
        require(canonical(value) == canonical(observed), "saved-plan live functional drift")
    require(seen == required, "incomplete governed drift coverage; Production blocked")


def closed(value, fields):
    require(type(value) is dict and set(value) == set(fields.split()), "closed object fields")
    return value


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(value, length=64):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value), "digest")
    return value


def integer(value, minimum=1, maximum=2**53 - 1):
    require(type(value) is int and minimum <= value <= maximum, "integer range")
    return value


def instant(value):
    require(type(value) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value), "UTC timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _number(token):
    require(len(token) <= 1024, "numeric token limit")
    coefficient, _, exponent = token.lower().partition("e")
    require(len(exponent.lstrip("+-")) <= 4, "exponent length")
    require(not exponent or abs(int(exponent)) <= 4096, "exponent limit")
    require(len(coefficient.replace("-", "").replace(".", "")) <= 1024, "coefficient limit")
    value = Decimal(token)
    parts = value.as_tuple()
    require(len(parts.digits) + abs(parts.exponent) + 3 <= 4096, "expanded number limit")
    return value


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def loads(data, *, state=False, canonical=False, limit=LIMIT):
    require(type(data) is bytes and len(data) <= limit and not data.startswith(b"\xef\xbb\xbf"), "JSON size/BOM")
    def number(token):
        require(state, "protocol numbers must be integer")
        return _number(token)
    def invalid(_):
        raise ValueError("nonfinite JSON")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_int=lambda t: _number(t) if state else int(t),
                           parse_float=number, parse_constant=invalid)
        encoded = globals()["canonical"](value)
    except (UnicodeError, OverflowError, RecursionError) as error:
        raise ValueError("invalid/bounded JSON") from error
    if canonical:
        require(encoded == data, "noncanonical JSON bytes")
    return value


def canonical(value, limit=LIMIT):
    chunks = []
    used = 0
    def emit(text):
        nonlocal used
        data = text.encode("utf-8")
        used += len(data)
        require(used <= limit, "canonical output budget")
        chunks.append(data)
    def visit(item):
        if item is None or type(item) is bool:
            emit(json.dumps(item))
        elif type(item) is str:
            emit(json.dumps(item, ensure_ascii=False))
        elif type(item) is int:
            emit(str(item))
        elif type(item) is Decimal:
            parts = item.as_tuple()
            require(item.is_finite() and len(parts.digits) + abs(parts.exponent) + 3 <= 4096, "decimal expansion")
            text = "0" if item == 0 else format(item, "f")
            if "." in text:
                text = text.rstrip("0").rstrip(".")
            emit(text)
        elif type(item) is list:
            emit("[")
            for index, child in enumerate(item):
                if index:
                    emit(",")
                visit(child)
            emit("]")
        elif type(item) is dict:
            require(all(type(k) is str for k in item), "JSON object key")
            emit("{")
            for index, key in enumerate(sorted(item)):
                if index:
                    emit(",")
                visit(key)
                emit(":")
                visit(item[key])
            emit("}")
        else:
            raise ValueError("unsupported JSON value")
    try:
        visit(value)
        emit("\n")
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid Unicode/JSON depth") from error
    return b"".join(chunks)


def canary_binding(candidate, candidate_sha256):
    value = {key: candidate[key] for key in ("repository", "release_id", "source_sha")}
    value["candidate_sha256"] = digest(candidate_sha256)
    require(all(type(v) is str and v for v in value.values()), "A2 strings")
    binding = sha(b"cnesdata:prod:canary:v1\0" + canonical(value)[:-1])
    return value | {"binding_sha256": binding, "canary_id": binding[:32]}


def r2_candidate(raw):
    """Preserve R2's sorted compact json.dumps + LF, including number spelling."""
    loads(raw, state=True, limit=262144)  # strict duplicate/Unicode/bounded-number admission
    value = json.loads(raw)
    require((json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode() == raw,
            "R2 canonical candidate bytes")
    return value


def money(value):
    require(type(value) is str and re.fullmatch(r"(0|[1-9][0-9]*)\.[0-9]{2}", value), "money type")
    return Decimal(value)


def budget(product, aggregate, paid_actions):
    require(money(product) <= 8 and money(aggregate) < 15 and paid_actions == "0.00", "budget freeze/paid fallback")


def validate_cost(value, *, purpose, stage, evidence, manifest, now):
    common = "verdict evidence_sha256 manifest_sha256 product_monthly_usd aggregate_monthly_usd paid_actions_limit_usd calculated_at expires_at scope cloudfront"
    pre = value.get("scope") == "pre-activation"
    closed(value, common + (" activation dns workloads unbound_monthly_usd" if pre else ""))
    require(value["verdict"] == "pass", "cost verdict")
    budget(value["product_monthly_usd"], value["aggregate_monthly_usd"], value["paid_actions_limit_usd"])
    require(instant(value["calculated_at"]) <= now < instant(value["expires_at"]), "dated cost validity")
    require(type(stage) is dict and stage.get("stage") == value["scope"], "authenticated monotonic stage missing/regressive")
    digest(stage["checkpoint_sha256"])
    digest(stage["target_sha256"])
    closed(evidence, "check_id source_sha measurement")
    require(evidence["check_id"] == "cost-ledger-purpose-scope" and evidence["source_sha"] == stage["source_sha"], "cost source/report")
    require(sha(canonical(evidence)) == digest(value["evidence_sha256"])
            and evidence["measurement"]["cost"] == {k: v for k, v in value.items() if k != "evidence_sha256"}
            and evidence["measurement"]["checkpoint"] == stage, "measured cost/checkpoint; no selfhash")
    require(sha(canonical(manifest)) == digest(value["manifest_sha256"])
            == evidence["measurement"]["manifest_sha256"], "separate financial manifest")
    require(manifest["source_sha"] == stage["source_sha"] and manifest["gross"] is True
            and manifest["credits_usd"] == "0.00" and manifest["calculated_at"] == value["calculated_at"]
            and manifest["expires_at"] == value["expires_at"], "gross source-bound ledger without credits")
    components = manifest["components"]
    require(type(components) is list and bool(components) and len(components) <= 64, "complete cost ledger")
    product = aggregate = unbound = Decimal(0)
    categories = set()
    for item in components:
        closed(item, "category scope monthly_usd unbound")
        require(type(item["unbound"]) is bool and item["scope"] in {"product", "aggregate-only"}, "ledger scope")
        amount = money(item["monthly_usd"])
        aggregate += amount
        if item["scope"] == "product":
            product += amount
            if item["unbound"]:
                unbound += amount
        categories.add(item["category"])
    require({"kms-encryption", "kms-signing", "s3-requests-versions-logs", "cloudfront-waf"} <= categories,
            "CMK/S3/logs/WAF components missing")
    require(product == money(value["product_monthly_usd"]) and aggregate == money(value["aggregate_monthly_usd"]), "gross sums")
    if pre:
        require(purpose in {"acm-certificate", "bootstrap"} and value["cloudfront"] == {"plan": None, "status": None}
                and all(value[k] == "blocked" for k in ("activation", "dns", "workloads")), "PRE guardrails/purpose")
        require(money(value["unbound_monthly_usd"]) == unbound and
                (not stage["unbound_required"] or unbound > 0), "unbound exposure omitted/credited")
    else:
        require(value["scope"] == "active", "cost stage enum")
        cf = closed(value["cloudfront"], "plan status subscription_sha256 distribution_sha256 waf_binding_sha256 observed_at expires_at")
        require(cf == stage["cloudfront"] and cf["plan"] == "FREE" and cf["status"] == "ACTIVE"
                and instant(cf["observed_at"]) <= now < instant(cf["expires_at"])
                and instant(value["expires_at"]) <= instant(cf["expires_at"]), "actual exact CloudFront binding/expiry")
        for field in ("subscription_sha256", "distribution_sha256", "waf_binding_sha256"):
            digest(cf[field])


def verify_package(package, files):
    closed(package, "files aggregate_sha256")
    entries = package["files"]
    require(type(entries) is list and 3 <= len(entries) <= 32, "package count")
    names = [entry["name"] for entry in entries]
    require(names == sorted(set(names)) and set(names) == set(files), "package extras/order")
    require({"plan.bin", "plan.json", "inputs.tfvars.json"} <= set(names), "required package files")
    total = 0
    for entry in entries:
        closed(entry, "name size sha256")
        name = entry["name"]
        require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) and PurePosixPath(name).name == name and name not in {".", ".."}, "package path")
        maximum = 32 * 1024**2 if name == "plan.bin" else LIMIT
        size = integer(entry["size"], 0, maximum)
        require(type(files[name]) is bytes and len(files[name]) == size and sha(files[name]) == digest(entry["sha256"]), "package tamper")
        total += size
    require(total <= 192 * 1024**2 and sha(canonical(entries)) == digest(package["aggregate_sha256"]), "package aggregate")


def _secrets(value):
    if isinstance(value, dict):
        for key, child in value.items():
            require(key.lower() not in {"password", "private_key", "secret_access_key", "access_token"}
                    or child in (None, ""), "secret material")
            _secrets(child)
    elif isinstance(value, list):
        for child in value:
            _secrets(child)


def public_safe(value):
    """Defense in depth on the already authenticated sanitized producer reports."""
    if type(value) is dict:
        for key, child in value.items():
            require(key.lower() not in {"password", "secret", "token", "access_key_id", "secret_access_key", "state_json", "terraform_state"}, "private field in public transport")
            public_safe(child)
    elif type(value) is list:
        for child in value:
            public_safe(child)
    elif type(value) is str:
        require(len(value) <= 4096 and not re.search(r"arn:aws(?:-[a-z]+)?:|://|BEGIN (?:RSA |EC )?PRIVATE KEY|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:vpc|subnet|sg|eni|i)-[0-9a-f]{8,17}\b", value), "private material in public transport")


def redacted_plan(raw, source_sha, purpose):
    plan = loads(raw, state=True)
    changes = []
    for item in plan.get("resource_changes", []):
        if item["change"]["actions"] in (["no-op"], ["read"]):
            continue
        address = item["address"]
        # Instance keys can be private topology. Shape + commitment preserve review
        # utility without publishing any physical key, value, ARN or runtime ID.
        shape = re.sub(r'\[(?:"(?:\\.|[^"\\])*"|[0-9]+)\]', "[redacted]", address)
        require(re.fullmatch(r"[A-Za-z0-9_.-]+(?:\[redacted\][A-Za-z0-9_.-]*)*", shape),
                "unsafe/unparsed address shape")
        changes.append({"address_shape": shape,
                        "address_sha256": sha(address.encode()), "type": item["type"],
                        "actions": item["change"]["actions"]})
    changes.sort(key=lambda item: (item["address_shape"], item["address_sha256"]))
    result = {"view_version": 1, "repository": REPOSITORY, "source_sha": digest(source_sha, 40),
              "purpose": purpose, "plan_json_sha256": sha(raw), "changes": changes}
    public_safe(result)
    return canonical(result)


def validate_delta(plan, purpose):
    require(purpose in PURPOSES, "purpose")
    _secrets(plan)
    bootstrap = ("module.athena.", "module.cognito.", "module.control_plane.", "module.data_buckets.",
                 "module.network.", "module.observability.", "module.processing.", "module.processor_registry.",
                 "module.runtime_iam.", "module.schedulers.", "module.static_web.", "aws_cloudwatch_log_group.processor")
    phase = ("module.processing.aws_ecs_task_definition.processor[", "module.processing.aws_iam_role_policy.step_functions_ecs[",
             "module.processing.aws_iam_role_policy.canary_verifier_run_task[", "module.processing.aws_dynamodb_table.canary[",
             "module.processing.aws_s3_bucket", "module.runtime_iam.aws_iam_role.canary_", "module.runtime_iam.aws_iam_role_policy.canary_")
    changed = []
    for resource in plan.get("resource_changes", []):
        actions = resource["change"]["actions"]
        if actions in (["no-op"], ["read"]):
            continue
        address = resource["address"]
        changed.append(address)
        retained_replace = purpose == "phase-a" and address.startswith("module.processing.aws_ecs_task_definition.processor[") and set(actions) == {"delete", "create"}
        require("delete" not in actions or retained_replace, "delete/replacement requires separate reviewed recovery")
        require(set(actions) <= ({"create", "delete"} if retained_replace else {"create", "update"}), "change actions")
        if purpose == "acm-certificate":
            require(address == "aws_acm_certificate.static_web" and actions == ["create"], "ACM initial create-only scope")
        elif purpose == "bootstrap":
            require(address == "aws_acm_certificate.static_web" or address.startswith(bootstrap), "bootstrap scope")
        else:
            require(address.startswith(phase), "Phase A invariant address")
            require(re.fullmatch(r'module\.processing\.(aws_ecs_task_definition\.processor\["(?:unit|recovery|audit)"\]|aws_iam_role_policy\.(?:step_functions_ecs|canary_verifier_run_task)\[0\]|aws_dynamodb_table\.canary\[0\]|aws_s3_bucket(?:_public_access_block|_ownership_controls|_versioning|_server_side_encryption_configuration|_object_lock_configuration|_lifecycle_configuration|_policy)?\.canary\[0\])|module\.runtime_iam\.aws_iam_role(?:_policy)?\.canary_(?:task|execution|seeder|verifier)\[0\]', address), "exact Phase A address")
            if "aws_ecs_task_definition" in address:
                after = resource["change"].get("after", {})
                require(after.get("skip_destroy") is True and after.get("track_latest") is False, "retained task revisions")
                before = resource["change"].get("before")
                if before:
                    for field in ("family", "cpu", "memory", "network_mode", "requires_compatibilities", "execution_role_arn", "task_role_arn"):
                        require(before.get(field) == after.get(field), "Phase A functional ECS invariant")
                    old = loads(before["container_definitions"].encode(), state=True)
                    new = loads(after["container_definitions"].encode(), state=True)
                    require([{k: v for k, v in item.items() if k != "image"} for item in old] ==
                            [{k: v for k, v in item.items() if k != "image"} for item in new], "Phase A container invariant")
    if purpose == "acm-certificate":
        require(changed == ["aws_acm_certificate.static_web"], "one initial certificate create, no reset/no-op retry plan")


def state_identity(data):
    if data is None:
        return {"lineage": None, "serial": None, "state_sha256": None}
    value = loads(data, state=True)
    serial = value["serial"]
    require(serial == int(serial) and serial >= 0 and type(value["lineage"]) is str, "state identity")
    return {"lineage": value["lineage"], "serial": int(serial), "state_sha256": sha(canonical(value))}


def effective_backend(metadata, workspace, expected):
    backend = metadata.get("backend", {})
    require(backend.get("type") == "s3" and workspace == expected["workspace"] == "default", "effective remote backend/workspace")
    actual = backend.get("config", {})
    for key, value in expected.items():
        if key not in {"type", "workspace"}:
            require(actual.get(key) == value and (type(actual.get(key)) is bool if type(value) is bool else True), "effective backend field " + key)
    def empty(value):
        if type(value) is dict:
            return all(empty(child) for child in value.values())
        if type(value) is list:
            return all(empty(child) for child in value)
        return value is None or value is False or value == ""
    forbidden = {"access_key", "secret_key", "token", "profile", "assume_role", "assume_role_with_web_identity",
                 "role_arn", "endpoint", "endpoints", "iam_endpoint", "sts_endpoint", "custom_ca_bundle", "insecure",
                 "shared_credentials_file", "shared_credentials_files", "skip_credentials_validation", "skip_region_validation",
                 "skip_requesting_account_id", "use_path_style", "force_path_style"}
    require(all(empty(actual.get(key)) for key in forbidden), "unreviewed backend credential/endpoint/validation override")
    require(actual.get("workspace_key_prefix") in {None, "", "env:"}, "workspace prefix override")


def validate_graph(plan, approved, source_files, resolver=None):
    """Unknown policy is safe only under an independently approved source/proof graph."""
    closed(approved, "source_files configuration_sha256 unknown_policies known_policies")
    require(type(approved["source_files"]) is list and 0 < len(approved["source_files"]) <= 32, "source proof capacity")
    require(sha(canonical(plan["configuration"])) == approved["configuration_sha256"], "independent configuration graph")
    require(approved["source_files"] == sorted(approved["source_files"], key=lambda item: item["path"]), "source file order")
    for entry in approved["source_files"]:
        closed(entry, "path sha256")
        require(entry["path"] in source_files and sha(source_files[entry["path"]]) == digest(entry["sha256"]), "actual approved source bytes")
    configuration = {}
    def walk(module, prefix=""):
        for resource in module.get("resources", []):
            configuration[prefix + resource["address"]] = resource
        for name, call in module.get("module_calls", {}).items():
            walk(call["module"], prefix + "module." + name + ".")
    walk(plan["configuration"]["root_module"])
    changes = {item["address"]: item for item in plan.get("resource_changes", []) if item["change"]["actions"] != ["no-op"]}
    witnesses = {item["address"]: item for item in approved["unknown_policies"]}
    require([item["address"] for item in approved["unknown_policies"]] == sorted(witnesses) and len(witnesses) <= 32, "unknown witness order/duplicates")
    seen = set()
    for address, item in changes.items():
        if item["type"] != "aws_iam_role_policy":
            continue
        change = item["change"]
        unknown = change.get("after_unknown", {})
        require(not any(value for key, value in unknown.items() if key not in {"id", "policy", "role", "name", "name_prefix"}), "unexpected policy unknown field")
        if unknown.get("policy") is True or unknown.get("role") is True:
            require(address in witnesses, "unproven unknown IAM policy/role")
            if unknown.get("policy") is True:
                require(change["after"].get("policy") is None, "unknown policy value")
            else:
                require(address in approved["known_policies"] and sha(canonical(loads(change["after"]["policy"].encode()))) == approved["known_policies"][address], "known policy plus unknown role exact grants")
            witness = closed(witnesses[address], "address references producers before_policy_sha256")
            local = re.sub(r"\[[^]]+\]", "", address)
            references = configuration[local]["expressions"]["policy"]["references"]
            require(sorted(set(references)) == witness["references"] and bool(witness["producers"]), "IAM expression references")
            for producer in witness["producers"]:
                require(producer in changes and "create" in changes[producer]["change"]["actions"], "unknown ARN producer edge")
            if resolver is not None:
                require(set(witness["producers"]) == resolver.precheck(address), "source-derived exact producer graph")
                if unknown.get("role") is True:
                    require(resolver.role_producer(address) in witness["producers"], "source-derived canonical role producer")
            elif unknown.get("role") is True:
                # The whole expression graph has already matched independent governance.
                # Unknown role.id additionally needs a concrete new role with a KNOWN
                # name, referenced by the exact role expression, not a generic bypass.
                role_refs = configuration[local]["expressions"]["role"]["references"]
                module = address.split(".aws_iam_role_policy.")[0]
                candidates = {module + "." + match.group(1) for reference in role_refs
                              if (match := re.fullmatch(r"(aws_iam_role\.[a-zA-Z0-9_]+\[0\])(?:\.[a-zA-Z0-9_]+)?", reference))}
                require(len(candidates) == 1, "unknown role exact expression")
                producer = candidates.pop()
                require(producer in witness["producers"] and producer in changes and changes[producer]["type"] == "aws_iam_role", "unknown role producer")
                role_change = changes[producer]["change"]
                name = role_change["after"].get("name")
                require(type(name) is str and name.startswith("cnesdata-") and not role_change.get("after_unknown", {}).get("name"), "unknown role name not proven")
            if address == "module.processing.aws_iam_role_policy.step_functions_ecs[0]":
                require('module.processing.aws_ecs_task_definition.processor["unit"]' in witness["producers"], "SFN unit producer")
            if address == "module.processing.aws_iam_role_policy.canary_verifier_run_task[0]":
                require('module.processing.aws_ecs_task_definition.processor["audit"]' in witness["producers"], "verifier audit producer")
            before = change.get("before")
            previous = sha(canonical(loads(before["policy"].encode()))) if before else None
            require(previous == witness["before_policy_sha256"], "previous exact IAM grants")
            seen.add(address)
        else:
            require(address in approved["known_policies"] and
                    sha(canonical(loads(change["after"]["policy"].encode()))) == approved["known_policies"][address], "known exact IAM grants")
    require(seen == set(witnesses), "extra/missing unknown policy witness")
    return approved | {"governance_sha256": sha(canonical(approved))}


def validate_envelope(envelope, files, baseline, now, expected_source, status="planned"):
    closed(envelope, "schema_version status plan apply plan_binding_sha256")
    require(envelope["schema_version"] == 1 and type(envelope["schema_version"]) is int and envelope["status"] == status, "envelope version/status")
    plan = closed(envelope["plan"], "repository source_sha producer package purpose created_at expires_at binary_sha256 json_sha256 inputs_sha256 dependencies toolchain backend state_before policy cost drift release phase_a_inputs")
    require(plan["repository"] == REPOSITORY and plan["source_sha"] == digest(expected_source, 40), "plan source")
    producer = closed(plan["producer"], "workflow_path workflow_sha run_id run_attempt")
    digest(producer["workflow_sha"], 40)
    integer(producer["run_id"])
    integer(producer["run_attempt"])
    require(producer["workflow_path"] == ".github/workflows/infra-plan.yml", "plan caller workflow")
    require(plan["purpose"] in PURPOSES and 0 < instant(plan["expires_at"]) - instant(plan["created_at"]) <= 3600
            and instant(plan["created_at"]) <= now < instant(plan["expires_at"]), "plan validity")
    require(sha(canonical(plan)) == digest(envelope["plan_binding_sha256"]), "plan binding")
    verify_package(plan["package"], files)
    require("redacted-plan.json" in files and files["redacted-plan.json"] == redacted_plan(files["plan.json"], expected_source, plan["purpose"]), "redacted view exact source binding")
    for field, name in (("binary_sha256", "plan.bin"), ("json_sha256", "plan.json"), ("inputs_sha256", "inputs.tfvars.json")):
        require(digest(plan[field]) == sha(files[name]), "plan content binding")
    for field in ("dependencies", "toolchain", "backend"):
        require(plan[field] == baseline[field], "governed " + field)
    backend = closed(plan["backend"], "identity_sha256 configuration")
    config = closed(backend["configuration"], "type bucket key workspace region encrypt use_lockfile kms_key_id")
    require(config["type"] == "s3" and config["key"] == "cnesdata/prod/opentofu.tfstate" and config["workspace"] == "default"
            and config["region"] == "us-east-2" and config["encrypt"] is True and config["use_lockfile"] is True
            and backend["identity_sha256"] == sha(canonical(config)), "backend identity/workspace")
    toolchain = closed(plan["toolchain"], "opentofu providers lock_sha256")
    closed(toolchain["opentofu"], "version binary_sha256")
    require(toolchain["opentofu"]["version"] == "1.13.2", "tofu version")
    digest(toolchain["opentofu"]["binary_sha256"])
    digest(toolchain["lock_sha256"])
    require(type(toolchain["providers"]) is list and len(toolchain["providers"]) >= 1, "provider selections")
    for provider in toolchain["providers"]:
        closed(provider, "source version package_sha256")
        digest(provider["package_sha256"])
        if provider["source"] == "registry.opentofu.org/hashicorp/aws":
            require(provider["version"] == "6.54.0", "AWS version")
    before = closed(plan["state_before"], "lineage serial state_sha256")
    require(all(v is None for v in before.values()) or all(v is not None for v in before.values()), "bootstrap state identity")
    if before["serial"] is not None:
        integer(before["serial"], 0)
        digest(before["state_sha256"])
    policy = closed(plan["policy"], "verdict evidence_sha256 policy_sha256 evaluator_sha256 plan_json_sha256")
    require(policy["verdict"] == "pass" and policy["plan_json_sha256"] == plan["json_sha256"], "policy plan binding")
    for key in set(policy) - {"verdict"}:
        digest(policy[key])
    validate_cost(plan["cost"], purpose=plan["purpose"], stage=baseline["cost_context"],
                  evidence=baseline["cost_evidence"], manifest=baseline["cost_manifest"], now=now)
    if plan["cost"]["scope"] == "pre-activation":
        creating_unbound = any(item["type"] in {"aws_cloudfront_distribution", "aws_wafv2_web_acl"}
                               and "create" in item["change"]["actions"] for item in loads(files["plan.json"], state=True).get("resource_changes", []))
        require(not creating_unbound or (baseline["cost_context"]["unbound_required"] is True
                                        and money(plan["cost"]["unbound_monthly_usd"]) > 0), "real plan unbound exposure required")
    drift = closed(plan["drift"], "verdict evidence_sha256 state_sha256 observed_at expires_at")
    require(drift["verdict"] == "pass" and drift["state_sha256"] == before["state_sha256"] and
            instant(drift["observed_at"]) <= now < instant(drift["expires_at"]) and
            instant(plan["expires_at"]) <= min(instant(drift["expires_at"]), instant(plan["cost"]["expires_at"])), "drift expiry/binding")
    digest(drift["evidence_sha256"])
    if plan["purpose"] != "phase-a":
        require(plan["release"] is None and plan["phase_a_inputs"] is None, "bootstrap release inputs")
    else:
        release = closed(plan["release"], "release_id source_sha candidate_sha256 canary_id binding_sha256 image_digest")
        phase = closed(plan["phase_a_inputs"], "image_digest processor_active_unit_task_definition_arn processor_retained_unit_task_definition_arns canary_storage_enabled canary_release_id canary_trusted_principal_arn")
        expected = canary_binding({"repository": REPOSITORY, "release_id": release["release_id"], "source_sha": expected_source}, release["candidate_sha256"])
        require(all(release[k] == expected[k] for k in ("source_sha", "candidate_sha256", "binding_sha256", "canary_id")), "A2 binding")
        require(phase["canary_release_id"] == release["canary_id"] and phase["image_digest"] == release["image_digest"]
                and phase["canary_storage_enabled"] is True, "Phase A input binding")
        retained = phase["processor_retained_unit_task_definition_arns"]
        require(type(retained) is list and retained == sorted(set(retained)) and len(retained) <= 128, "retained revisions")
    validate_delta(loads(files["plan.json"], state=True), plan["purpose"])
    require("policy-proof.json" in files and sha(files["policy-proof.json"]) == policy["evidence_sha256"], "actual policy report bytes")
    report = loads(files["policy-proof.json"], canonical=True)
    closed(report, "evaluation_sha256 graph_proof")
    require("policy-evaluation.json" in files and sha(files["policy-evaluation.json"]) == report["evaluation_sha256"], "actual evaluator report")
    if plan["purpose"] == "phase-a":
        graph = validate_graph(loads(files["plan.json"], state=True), baseline["phase_a_graph"], baseline["actual_source_files"], baseline.get("iam_resolver"))
        require(report["graph_proof"] == graph, "approved private graph proof")
    else:
        require(report["graph_proof"] is None, "unexpected graph proof")
    if status == "planned":
        require(envelope["apply"] is None, "planned apply is null")
    else:
        validate_apply(envelope, baseline)
    return plan


def validate_apply(envelope, baseline):
    plan = envelope["plan"]
    apply = closed(envelope["apply"], "producer consumed_plan_artifact plan_binding_sha256 started_at completed_at result lease principal state_after drift outputs")
    require(apply["result"] == "success" and apply["plan_binding_sha256"] == envelope["plan_binding_sha256"], "applied binding/result")
    producer = closed(apply["producer"], "workflow_path workflow_sha run_id run_attempt")
    require(producer["workflow_path"] == ".github/workflows/infra-apply.yml", "apply caller workflow")
    digest(producer["workflow_sha"], 40)
    for field in ("run_id", "run_attempt"):
        integer(producer[field])
    consumed = closed(apply["consumed_plan_artifact"], "artifact_id artifact_sha256 run_id run_attempt")
    for field in ("artifact_id", "run_id", "run_attempt"):
        integer(consumed[field])
    digest(consumed["artifact_sha256"])
    require(consumed["run_id"] == plan["producer"]["run_id"] and consumed["run_attempt"] == plan["producer"]["run_attempt"], "consumed attempt")
    start, end = instant(apply["started_at"]), instant(apply["completed_at"])
    require(instant(plan["created_at"]) <= start < end < instant(plan["expires_at"]) - 120, "apply time margin")
    lease = closed(apply["lease"], "protocol owner_sha256 repository run_id run_attempt session_sha256 acquired_at released_at ttl_seconds renew_interval_seconds safety_margin_seconds acquire_etag_sha256 release_etag_sha256 renewal_count checkpoint_sha256 evidence_sha256 terminal_status")
    require(lease["protocol"] == "s3-cas-v1" and lease["repository"] == REPOSITORY and lease["terminal_status"] == "released"
            and lease["ttl_seconds"] == 300 and lease["renew_interval_seconds"] == 60 and lease["safety_margin_seconds"] == 120,
            "lease contract")
    for field in ("run_id", "run_attempt"):
        require(type(lease[field]) is int and lease[field] == producer[field], "lease owner run/attempt")
    for field in ("owner_sha256", "session_sha256", "acquire_etag_sha256", "release_etag_sha256", "checkpoint_sha256", "evidence_sha256"):
        digest(lease[field])
    integer(lease["renewal_count"], 0)
    require(instant(lease["acquired_at"]) <= start <= end <= instant(lease["released_at"]), "lease execution interval")
    principal = closed(apply["principal"], "kind account_id region gate role_arn session_sha256 credential_expires_at evidence_sha256")
    require(principal["kind"] == "assumed-role" and principal["region"] == "us-east-2" and principal["gate"] == "deploy"
            and principal["role_arn"] == baseline["deploy_role_arn"] and principal["account_id"] == principal["role_arn"].split(":")[4]
            and principal["session_sha256"] == lease["session_sha256"] and instant(principal["credential_expires_at"]) > end + 120,
            "temporary approved principal")
    digest(principal["evidence_sha256"])
    after = closed(apply["state_after"], "lineage serial state_sha256 outputs_sha256")
    integer(after["serial"], 0)
    digest(after["state_sha256"])
    require(after["outputs_sha256"] == sha(canonical(apply["outputs"])), "output digest")
    if plan["state_before"]["lineage"] is not None:
        require(after["lineage"] == plan["state_before"]["lineage"] and after["serial"] >= plan["state_before"]["serial"], "state continuity")
    drift = closed(apply["drift"], "verdict evidence_sha256 readback_sha256 observed_at")
    require(drift["verdict"] == "clean" and start <= instant(drift["observed_at"]) <= instant(lease["released_at"]) + 1, "post-apply clean drift")
    digest(drift["evidence_sha256"])
    digest(drift["readback_sha256"])
    if plan["purpose"] == "phase-a":
        outputs = closed(apply["outputs"], "processor_task_definition_arns image_digest active_before retained_before retained_after canary_id binding_sha256 resource_fingerprints grant_fingerprints route_fingerprints")
        closed(outputs["processor_task_definition_arns"], "unit recovery audit")
        phase = plan["phase_a_inputs"]
        require(outputs["image_digest"] == plan["release"]["image_digest"] and outputs["canary_id"] == plan["release"]["canary_id"]
                and outputs["binding_sha256"] == plan["release"]["binding_sha256"] and outputs["active_before"] == phase["processor_active_unit_task_definition_arn"]
                and outputs["retained_before"] == phase["processor_retained_unit_task_definition_arns"], "applied Phase A exact bindings")
        require(outputs["retained_after"] == sorted(set(outputs["retained_before"] + [outputs["processor_task_definition_arns"]["unit"]]))
                and len(outputs["retained_after"]) <= 128, "retained revisions union")
        for field in ("resource_fingerprints", "grant_fingerprints", "route_fingerprints"):
            values = outputs[field]
            require(type(values) is list and len(values) <= 64 and [x["address"] for x in values] == sorted(set(x["address"] for x in values)), "fingerprint order/capacity")
            for value in values:
                closed(value, "address fingerprint_sha256")
                digest(value["fingerprint_sha256"])
    else:
        from tools.cnesdata_delivery.outputs import validate
        validate(apply["outputs"], plan["purpose"], principal["account_id"])
