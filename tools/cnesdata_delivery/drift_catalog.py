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


def _read(service, operation, rows):
    return {name: (service, operation, tuple(path.split(".")), encoding) for name, (path, encoding) in rows.items()}


CATALOG = {
    "aws_iam_role": _read("iam", "get_role", {
        "arn": ("Role.Arn", "identity"), "assume_role_policy": ("Role.AssumeRolePolicyDocument", "json"),
        "create_date": ("Role.CreateDate", "identity"), "description": ("Role.Description", "identity"),
        "id": ("Role.RoleName", "identity"), "max_session_duration": ("Role.MaxSessionDuration", "identity"),
        "name": ("Role.RoleName", "identity"), "path": ("Role.Path", "identity"),
        "permissions_boundary": ("Role.PermissionsBoundary.PermissionsBoundaryArn", "identity"),
        "tags_all": ("Role.Tags", "tags-kv"), "unique_id": ("Role.RoleId", "identity")}),
    "aws_iam_role_policy": _read("iam", "get_role_policy", {
        "name": ("PolicyName", "identity"), "policy": ("PolicyDocument", "json"), "role": ("RoleName", "identity")}),
    "aws_ecs_task_definition": _read("ecs", "describe_task_definition", {
        "arn": ("taskDefinition.taskDefinitionArn", "identity"),
        "container_definitions": ("taskDefinition.containerDefinitions", "ecs-container-definitions"),
        "cpu": ("taskDefinition.cpu", "identity"),
        "enable_fault_injection": ("taskDefinition.enableFaultInjection", "identity"),
        "execution_role_arn": ("taskDefinition.executionRoleArn", "identity"),
        "family": ("taskDefinition.family", "identity"), "id": ("taskDefinition.family", "identity"),
        "ipc_mode": ("taskDefinition.ipcMode", "identity"), "memory": ("taskDefinition.memory", "identity"),
        "network_mode": ("taskDefinition.networkMode", "identity"), "pid_mode": ("taskDefinition.pidMode", "identity"),
        "requires_compatibilities": ("taskDefinition.requiresCompatibilities", "json-set"),
        "revision": ("taskDefinition.revision", "identity"),
        "task_role_arn": ("taskDefinition.taskRoleArn", "identity")}),
    "aws_dynamodb_table": _read("dynamodb", "describe_table", {
        "arn": ("Table.TableArn", "identity"), "billing_mode": ("Table.BillingModeSummary.BillingMode", "identity"),
        "deletion_protection_enabled": ("Table.DeletionProtectionEnabled", "identity"),
        "id": ("Table.TableName", "identity"), "name": ("Table.TableName", "identity"),
        "read_capacity": ("Table.ProvisionedThroughput.ReadCapacityUnits", "identity"),
        "stream_arn": ("Table.LatestStreamArn", "identity"),
        "stream_enabled": ("Table.StreamSpecification.StreamEnabled", "identity"),
        "stream_label": ("Table.LatestStreamLabel", "identity"),
        "stream_view_type": ("Table.StreamSpecification.StreamViewType", "identity"),
        "table_class": ("Table.TableClassSummary.TableClass", "identity"),
        "write_capacity": ("Table.ProvisionedThroughput.WriteCapacityUnits", "identity")}),
    "aws_s3_bucket_policy": _read("s3", "get_bucket_policy", {"policy": ("Policy", "json")}),
    "aws_s3_bucket_object_lock_configuration": _read("s3", "get_object_lock_configuration", {
        "object_lock_enabled": ("ObjectLockConfiguration.ObjectLockEnabled", "identity")}),
}
NOT_OBSERVABLE = {
    "aws_iam_role": {"force_detach_policies": "state-only", "inline_policy": "other-api",
                     "managed_policy_arns": "other-api", "name_prefix": "state-only", "tags": "state-only"},
    "aws_iam_role_policy": {"id": "state-only", "name_prefix": "state-only"},
    "aws_ecs_task_definition": {
        "arn_without_revision": "other-encoding", "ephemeral_storage": "other-encoding",
        "placement_constraints": "other-encoding", "proxy_configuration": "other-encoding", "region": "state-only",
        "runtime_platform": "other-encoding", "skip_destroy": "state-only", "tags": "other-api",
        "tags_all": "other-api", "track_latest": "state-only", "volume": "other-encoding"},
    "aws_dynamodb_table": {
        "attribute": "other-encoding", "global_secondary_index": "other-encoding",
        "global_table_witness": "other-encoding", "hash_key": "other-encoding", "import_table": "state-only",
        "local_secondary_index": "other-encoding", "on_demand_throughput": "other-encoding",
        "point_in_time_recovery": "other-api", "range_key": "other-encoding", "region": "state-only",
        "replica": "other-encoding", "restore_backup_arn": "state-only", "restore_date_time": "state-only",
        "restore_source_name": "state-only", "restore_source_table_arn": "state-only",
        "restore_to_latest_time": "state-only", "server_side_encryption": "other-encoding", "tags": "other-api",
        "tags_all": "other-api", "timeouts": "state-only", "ttl": "other-api", "warm_throughput": "other-encoding"},
    "aws_s3_bucket_policy": {"bucket": "request-parameter", "id": "request-parameter", "region": "state-only"},
    "aws_s3_bucket_object_lock_configuration": {
        "bucket": "request-parameter", "expected_bucket_owner": "state-only", "id": "request-parameter",
        "region": "state-only", "rule": "other-encoding", "token": "state-only"},
}
OMITTED = {
    "aws_iam_role": {"description": ("", None), "permissions_boundary": ("", None), "tags_all": ({}, None)},
    "aws_dynamodb_table": {
        "billing_mode": ("PROVISIONED",), "table_class": ("STANDARD",), "stream_enabled": (False, None),
        "stream_view_type": ("", None), "stream_arn": ("", None), "stream_label": ("", None)},
}
NO_CHANGE = (["no-op"], ["read"])


def _operation(tipo):
    return {entry[:2] for entry in CATALOG[tipo].values()}.pop()


class Envelope:
    """COVERED and SUPPORTED resource types of one purpose; entries come from CATALOG."""

    def __init__(self, covered, supported):
        self.covered, self.supported = frozenset(covered), frozenset(supported)
        c.require(self.covered <= self.supported and all(CATALOG.get(tipo) for tipo in self.supported),
                  "envelope catalog")

    def required(self, plan, expected):
        """Args: plan, expected attributes by address. Returns: required (address, attribute) pairs."""
        changed = {address for address, change in _changes(plan).items() if change["actions"] not in NO_CHANGE}
        for address in sorted(changed):
            c.require(resource_type(address) in self.supported, "unsupported changed type")
        required = set()
        for address, values in expected.items():
            tipo = resource_type(address)
            if tipo not in self.covered and address not in changed:
                continue
            for name in values:
                if name not in NOT_OBSERVABLE[tipo]:
                    c.require(name in CATALOG[tipo], "unclassified attribute")
                    required.add((address, name))
        return required

    @staticmethod
    def observable(row):
        c.require(row["attribute"] not in NOT_OBSERVABLE.get(resource_type(row["address"]), {}),
                  "not observable drift row")

    @staticmethod
    def omitted(row):
        return OMITTED.get(resource_type(row["address"]), {}).get(row["attribute"])

    @staticmethod
    def bind(spec, row):
        service, operation, path, encoding = CATALOG[resource_type(row["address"])][row["attribute"]]
        c.require((spec["service"], spec["operation"]) == (service, operation) and row["path"] == list(path)
                  and row["encoding"] == encoding, "catalog drift row")

    def absent(self, plan, rows, binding, stage):
        """Args: plan, absent rows, (specs, reports, used indexes), stage. Raises: ValueError."""
        specs, reports, used = binding
        c.require(type(rows) is list and len(rows) <= 4096, "bounded drift coverage")
        for row in rows:
            c.closed(row, "address readback")
            c.require(type(row["readback"]) is int, "drift readback reference")
        if stage != "after":
            return
        required = {address for address, change in _changes(plan).items() if change["actions"] == ["delete"]}
        seen = set()
        for row in rows:
            index, address = row["readback"], row["address"]
            c.require(0 <= index < len(specs), "drift readback reference")
            c.require(specs[index]["address"] == address, "readback address binding")
            c.require(address in required and address not in seen, "absent drift coverage")
            seen.add(address)
            c.require(specs[index].get("absent") is True and reports[index]["observed"] == {"absent": True},
                      "absent drift proof")
            c.require((specs[index]["service"], specs[index]["operation"]) == _operation(resource_type(address)),
                      "catalog drift row")
            absence(plan, address, specs[index].get("parameters"))
            used.add(index)
        c.require(seen == required, "absent drift coverage")


PHASE_A_ENVELOPE = Envelope(
    covered={"aws_iam_role", "aws_iam_role_policy", "aws_ecs_task_definition"},
    supported={"aws_iam_role", "aws_iam_role_policy", "aws_ecs_task_definition", "aws_dynamodb_table",
               "aws_s3_bucket_policy", "aws_s3_bucket_object_lock_configuration"})
ENVELOPES = {"phase-a": PHASE_A_ENVELOPE}


def catalog_document():
    """Returns: the canonical catalogue document hashed into CATALOG_SHA256."""
    return {"catalog": {tipo: {name: [service, operation, list(path), encoding]
                               for name, (service, operation, path, encoding) in entries.items()}
                        for tipo, entries in CATALOG.items()},
            "envelopes": {name: {"covered": sorted(envelope.covered), "supported": sorted(envelope.supported)}
                          for name, envelope in ENVELOPES.items()},
            "identity": {tipo: [list(pair) for pair in pairs] for tipo, pairs in IDENTITY.items()},
            "not_observable": NOT_OBSERVABLE,
            "omitted": {tipo: {name: list(values) for name, values in entries.items()} for tipo, entries in OMITTED.items()},
            "container_defaults": c.CONTAINER_DEFAULTS}


CATALOG_SHA256 = c.sha(c.canonical(catalog_document()))
