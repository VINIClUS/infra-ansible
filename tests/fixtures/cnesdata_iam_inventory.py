"""Complete producer source inventories; identity leaves alone are synthetic."""
import copy
import json
from pathlib import Path

from tools.cnesdata_delivery.iam_expression import Budget, Evaluator, attributes, parse, reference_sets, source_blocks
from tools.cnesdata_delivery.iam_source import BOOTSTRAP_POLICIES, POLICIES, TYPES
from fixtures.cnesdata_iam_sources import ACCOUNT, REGION


def source_expression(raw):
    node = parse(raw, Budget())
    required, allowed = reference_sets(node)
    return {"references": sorted(allowed)} if required else {"constant_value": Evaluator(lambda *_: None, Budget()).value(node)}


def inventory(purpose):
    base = Path(__file__).parent / "cnesdata_delivery_sources"
    sources = {str(path.relative_to(base)): path.read_bytes() for path in base.rglob("*.tf")}
    root = {"resources": [], "module_calls": {}}
    for kind, name, body in source_blocks(sources["infra/opentofu/env/prod/main.tf"]):
        if kind != "module":
            continue
        fields = attributes(body)
        source = json.loads(fields["source"])
        directory = "infra/opentofu/" + source.removeprefix("../../")
        if not any(path.startswith(directory + "/") for path in sources):
            continue
        root["module_calls"][name] = {"source": source, "expressions": {}, "module": {"resources": [], "outputs": {}}}
        for field, raw in fields.items():
            if field in {"source", "providers", "depends_on"}:
                continue
            try:
                root["module_calls"][name]["expressions"][field] = source_expression(raw)
            except ValueError:
                pass
    variables = {}
    for kind, name, body in source_blocks(sources["infra/opentofu/env/prod/variables.tf"]):
        fields = attributes(body)
        if kind == "variable" and "default" in fields:
            variables[name] = {"value": Evaluator(lambda *_: None, Budget()).value(parse(fields["default"], Budget()))}
    inputs = {"canary_release_id": "c" * 32 if purpose == "phase-a" else None,
              "canary_storage_enabled": purpose == "phase-a",
              "image_digest": "sha256:" + "a" * 64 if purpose == "phase-a" else None,
              "canary_trusted_principal_arn": f"arn:aws:iam::{ACCOUNT}:role/promotion" if purpose == "phase-a" else None,
              "processor_active_unit_task_definition_arn": None,
              "processor_retained_unit_task_definition_arns": [],
              "shared_outputs": {"account_id": ACCOUNT, "roles_anywhere": {"api_role_arn": f"arn:aws:iam::{ACCOUNT}:role/api"}}}
    variables.update({key: {"value": value} for key, value in inputs.items()})
    resources = []
    for module, call in [("", {"module": root, "source": "../../env/prod"}), *root["module_calls"].items()]:
        directory = "infra/opentofu/" + call["source"].removeprefix("../../")
        for path, data in sources.items():
            if not path.startswith(directory + "/"):
                continue
            for kind, name, body in source_blocks(data):
                fields = attributes(body)
                if kind == "output":
                    try:
                        call["module"]["outputs"][name] = {"expression": source_expression(fields["value"])}
                    except ValueError:
                        pass
                if kind != "resource" or name.split(".", 1)[0] not in TYPES | {"aws_iam_role_policy": "policy"}:
                    continue
                row = {"address": name, "expressions": {}}
                for field in {"name", "family", "bucket", "policy", "role", "count", "for_each"} & fields.keys():
                    try:
                        expression = source_expression(fields[field])
                    except ValueError:
                        continue
                    if field in {"count", "for_each"}:
                        row[field + "_expression"] = expression
                    else:
                        row["expressions"][field] = expression
                call["module"]["resources"].append(row)
    prefix = "cnesdata-prod"
    values = {
        "aws_cloudwatch_log_group.processor": {"name": f"/ecs/{prefix}-processor"},
        "module.processor_registry.aws_ecr_repository.this": {"name": prefix + "-processor"},
        "module.control_plane.aws_dynamodb_table.control_plane": {"name": prefix + "-control-plane"},
        "module.data_buckets.aws_s3_bucket.data": {"bucket": prefix + "-data"},
        "module.data_buckets.aws_s3_bucket.audit": {"bucket": prefix + "-audit"},
        "module.processing.aws_ecs_cluster.processor": {"name": prefix + "-processor"},
        "module.runtime_iam.aws_iam_role.execution": {"name": prefix + "-processor-execution"},
        "module.runtime_iam.aws_iam_role.step_functions[0]": {"name": prefix + "-step-functions"},
        "module.athena.aws_iam_role.cutoff": {"name": prefix + "-athena-cutoff"},
    }
    for mode in ("unit", "recovery", "audit"):
        values[f'module.runtime_iam.aws_iam_role.task["{mode}"]'] = {"name": prefix + "-processor-" + mode}
        if purpose == "phase-a":
            values[f'module.processing.aws_ecs_task_definition.processor["{mode}"]'] = {"family": prefix + "-processor-" + mode}
    for mode in ("recovery", "audit"):
        values[f'module.schedulers.aws_iam_role.scheduler["{mode}"]'] = {"name": prefix + "-scheduler-" + mode}
    if purpose == "phase-a":
        for name in ("canary_task", "canary_execution", "canary_seeder", "canary_verifier", "promotion_fence_operator"):
            values[f"module.runtime_iam.aws_iam_role.{name}[0]"] = {"name": prefix + "-" + name.replace("_", "-")}
        values["module.processing.aws_dynamodb_table.canary[0]"] = {"name": prefix + "-canary"}
        values["module.processing.aws_s3_bucket.canary[0]"] = {"bucket": prefix + "-canary"}
    policies = POLICIES if purpose == "phase-a" else BOOTSTRAP_POLICIES
    values.update({address: {"policy": None, "role": None} for address in policies})
    changes = []
    for address, fields in values.items():
        kind = address.split(".")[-2]
        changes.append({"address": address, "type": kind, "mode": "managed", "change": {
            "actions": ["create"], "before": None, "after": copy.deepcopy(fields),
            "after_unknown": {"policy": True, "role": True} if kind == "aws_iam_role_policy" else {"arn": True, "id": True}}})
    plan = {"configuration": {"root_module": root}, "variables": variables, "resource_changes": changes}
    return plan, sources, inputs, values, policies


def identities(values):
    result = copy.deepcopy(values)
    for address, fields in result.items():
        kind = address.split(".")[-2]
        if kind == "aws_iam_role_policy":
            continue
        name = fields[TYPES[kind]]
        prefixes = {"aws_iam_role": f"arn:aws:iam::{ACCOUNT}:role/",
                    "aws_ecs_task_definition": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/",
                    "aws_ecs_cluster": f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/",
                    "aws_dynamodb_table": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/",
                    "aws_s3_bucket": "arn:aws:s3:::",
                    "aws_ecr_repository": f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/",
                    "aws_cloudwatch_log_group": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:"}
        fields.update(id=name, arn=prefixes[kind] + name + (":2" if kind == "aws_ecs_task_definition" else ""))
    return result
