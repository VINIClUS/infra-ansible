"""Identity map of live drift readbacks: resource type to identity attribute to call parameter."""
import re

from tools.cnesdata_delivery import contract as c

IDENTITY = {
    "aws_iam_role": (("name", "RoleName"),),
    "aws_iam_role_policy": (("role", "RoleName"), ("name", "PolicyName")),
    "aws_ecs_task_definition": (("family", "taskDefinition"),),
    "aws_ecs_cluster": (("name", "clusters"),),
    "aws_dynamodb_table": (("name", "TableName"),),
    "aws_s3_bucket": (("bucket", "Bucket"),),
    "aws_s3_bucket_policy": (("bucket", "Bucket"),),
    "aws_s3_bucket_versioning": (("bucket", "Bucket"),),
    "aws_s3_bucket_object_lock_configuration": (("bucket", "Bucket"),),
    "aws_scheduler_schedule": (("name", "Name"), ("group_name", "GroupName")),
    "aws_acm_certificate": (("arn", "CertificateArn"),),
}
FENCE_READS = {"module.runtime_iam.aws_iam_role.promotion_fence_operator[0]": "get_role",
               "module.runtime_iam.aws_iam_role_policy.promotion_fence_operator[0]": "get_role_policy"}
READ_ONLY = {"iam": {"get_role", "get_role_policy", "get_policy", "get_policy_version"},
             "ecs": {"describe_task_definition", "describe_clusters"}, "scheduler": {"get_schedule"},
             "s3": {"get_bucket_policy", "get_bucket_versioning", "get_object_lock_configuration"},
             "dynamodb": {"describe_table"}, "acm": {"describe_certificate"}}
LIST_PARAMETERS = {"clusters"}
CREATE_DELETE = {"create", "delete"}


def resource_type(address):
    parts = re.sub(r"\[[^\]]*\]", "", address).split(".")
    return parts[-2] if len(parts) > 1 else ""


def require_read_only(service, operation):
    c.require(operation in READ_ONLY.get(service, set()), "read-only API boundary")


def _identity(tipo):
    c.require(tipo in IDENTITY, "readback identity type")
    return IDENTITY[tipo]


def parameters(tipo, atributos):
    """Args: tipo, atributos. Returns: call parameters. Raises: ValueError."""
    result = {}
    for attribute, name in _identity(tipo):
        value = atributos.get(attribute) if type(atributos) is dict else None
        c.require(type(value) is str and bool(value), "readback identity value")
        result[name] = [value] if name in LIST_PARAMETERS else value
    return result


def _changes(plan):
    return {item["address"]: item["change"] for item in plan.get("resource_changes", [])
            if item.get("mode") == "managed"}


def _masked(change, attribute):
    unknown = change.get("after_unknown")
    return unknown is True or (type(unknown) is dict and unknown.get(attribute) not in (None, False))


def _usable(attributes, attribute):
    c.require(attribute in attributes, "readback identity unknown")
    value = attributes[attribute]
    c.require(type(value) is str and bool(value), "readback identity value")


def _known(change, tipo):
    after = change.get("after")
    if after is None:
        return
    for attribute, _ in _identity(tipo):
        c.require(not _masked(change, attribute), "readback identity unknown")
        _usable(after, attribute)


def _declared(change, tipo):
    after = change.get("after") or {}
    for attribute, _ in _identity(tipo):
        if not _masked(change, attribute):
            _usable(after, attribute)


def _planned(change, tipo):
    before = change.get("before") or {}
    for attribute, _ in _identity(tipo):
        _usable(before, attribute)


def _stable(change, tipo):
    before, after = change.get("before"), change.get("after")
    if before is None or after is None or CREATE_DELETE & set(change["actions"]):
        return
    for attribute, _ in _identity(tipo):
        c.require(before.get(attribute) == after.get(attribute), "readback identity changed")


def check_spec(spec, changes, stage):
    """Args: spec, plan changes by address, stage. Returns: resource type. Raises: ValueError."""
    c.closed(spec, "service operation address")
    require_read_only(spec["service"], spec["operation"])
    c.require(spec["address"] in changes, "readback address")
    tipo = resource_type(spec["address"])
    _identity(tipo)
    change = changes[spec["address"]]
    c.require(stage != "before" or change["before"] is not None, "readback absent before")
    c.require(stage != "after" or change["after"] is not None, "readback absent after")
    if stage == "before":
        _planned(change, tipo)
    if "create" in change["actions"]:
        _declared(change, tipo)
    else:
        _known(change, tipo)
        _stable(change, tipo)
    return tipo


def _call(spec, changes, expected, stage):
    tipo = check_spec(spec, changes, stage)
    c.require(spec["address"] in expected, "readback absent before")
    return spec | {"parameters": parameters(tipo, expected[spec["address"]])}


def readback_calls(plan, specs, stage, state=None):
    """Args: plan, specs, stage, state. Returns: specs plus parameters. Raises: ValueError."""
    c.require(type(specs) is list and len(specs) <= 4096 and stage in {"before", "after"}, "readback specs")
    changes = _changes(plan)
    expected = c.stage_expectation(plan, stage, state)
    return [_call(spec, changes, expected, stage) for spec in specs]


def bind_rows(calls, rows):
    """Args: calls, rows. Raises: ValueError on a foreign-address row or an orphan readback."""
    c.require(type(rows) is list, "bounded drift coverage")
    used = set()
    for row in rows:
        index = row.get("readback") if type(row) is dict else None
        c.require(type(index) is int and 0 <= index < len(calls), "drift readback reference")
        c.require(calls[index]["address"] == row.get("address"), "readback address binding")
        used.add(index)
    c.require(used == set(range(len(calls))), "orphan readback")


def absence(plan, address, observed):
    """Args: plan, address, observed parameters. Returns: parameters equal to the plan before."""
    change = _changes(plan).get(address)
    c.require(change is not None and change.get("before") is not None, "absence identity")
    derived = parameters(resource_type(address), change["before"])
    c.require(observed == derived, "absence identity")
    return derived


def _count(specs, address, operation):
    return sum(spec["address"] == address and spec["operation"] == operation for spec in specs)


def admit_stages(plan, readbacks, matrix, tracked):
    """Args: plan, readbacks, matrix, tracked policy addresses. Raises: ValueError before acquire."""
    c.closed(readbacks, "before after")
    changes = _changes(plan)
    for stage in ("before", "after"):
        c.require(type(readbacks[stage]) is list and type(matrix.get(stage)) is list, "readback specs")
        for spec in readbacks[stage]:
            check_spec(spec, changes, stage)
        bind_rows(readbacks[stage], matrix[stage])
    after = readbacks["after"]
    for address in sorted(tracked):
        c.require(_count(after, address, "get_role_policy") == 1, "tracked policy readback")
    present = _changes(plan)
    for address, operation in FENCE_READS.items():
        c.require(address not in present or _count(after, address, operation) == 1
                  and _count(after, address, operation) == sum(s["address"] == address for s in after),
                  "fence readback")
