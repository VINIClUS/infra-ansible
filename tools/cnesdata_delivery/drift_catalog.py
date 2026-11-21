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
LIFECYCLE_IDENTITY = {
    "aws_sfn_state_machine": (("arn", "stateMachineArn"),),
    "aws_scheduler_schedule_group": (("name", "Name"),),
    "aws_cloudwatch_event_rule": (("name", "Name"),),
    "aws_cloudwatch_metric_alarm": (("alarm_name", "AlarmNames"),),
    "aws_s3_bucket_lifecycle_configuration": (("bucket", "Bucket"),),
    "aws_cloudfront_response_headers_policy": (("id", "Id"),),
}
LIFECYCLE_ONLY = IDENTITY | LIFECYCLE_IDENTITY
FENCE_READS = {"module.runtime_iam.aws_iam_role.promotion_fence_operator[0]": "get_role",
               "module.runtime_iam.aws_iam_role_policy.promotion_fence_operator[0]": "get_role_policy"}
READ_ONLY = {"iam": {"get_role", "get_role_policy", "get_policy", "get_policy_version"},
             "ecs": {"describe_task_definition", "describe_clusters"}, "scheduler": {"get_schedule"},
             "s3": {"get_bucket_policy", "get_bucket_versioning", "get_object_lock_configuration"},
             "dynamodb": {"describe_table"}, "acm": {"describe_certificate"}}
LIFECYCLE_READ_ONLY = {"stepfunctions": {"describe_state_machine"}, "scheduler": {"get_schedule_group"},
                       "events": {"describe_rule"}, "cloudwatch": {"describe_alarms"},
                       "cloudfront": {"get_response_headers_policy"},
                       "s3": {"get_bucket_lifecycle_configuration"}}
LIST_PARAMETERS = {"clusters", "AlarmNames"}
CREATE_DELETE = {"create", "delete"}


def resource_type(address):
    parts = re.sub(r"\[[^\]]*\]", "", address).split(".")
    return parts[-2] if len(parts) > 1 else ""


def require_read_only(service, operation):
    c.require(operation in READ_ONLY.get(service, set()), "read-only API boundary")


def _identity(tipo, table=IDENTITY):
    c.require(tipo in table, "readback identity type")
    return table[tipo]


def parameters(tipo, atributos, table=IDENTITY):
    """Args: tipo, atributos, identity table. Returns: call parameters. Raises: ValueError."""
    result = {}
    for attribute, name in _identity(tipo, table):
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


def _stable(change, tipo, table=IDENTITY):
    before, after = change.get("before"), change.get("after")
    if before is None or after is None or CREATE_DELETE & set(change["actions"]):
        return
    for attribute, _ in _identity(tipo, table):
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
    inventories = {index for index, call in enumerate(calls) if "members" in call}
    c.require(used | inventories == set(range(len(calls))), "orphan readback")


def absence(plan, address, observed, table=IDENTITY):
    """Args: plan, address, observed parameters, identity table. Returns: parameters equal to the plan before."""
    change = _changes(plan).get(address)
    c.require(change is not None and change.get("before") is not None, "absence identity")
    derived = parameters(resource_type(address), change["before"], table)
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
    "aws_sfn_state_machine": _read("stepfunctions", "describe_state_machine", {
        "arn": ("stateMachineArn", "identity"), "definition": ("definition", "json"),
        "description": ("description", "identity"), "id": ("stateMachineArn", "identity"),
        "name": ("name", "identity"), "role_arn": ("roleArn", "identity"),
        "status": ("status", "identity"), "type": ("type", "identity")}),
    "aws_scheduler_schedule": _read("scheduler", "get_schedule", {
        "action_after_completion": ("ActionAfterCompletion", "identity"), "arn": ("Arn", "identity"),
        "description": ("Description", "identity"), "group_name": ("GroupName", "identity"),
        "kms_key_arn": ("KmsKeyArn", "identity"), "name": ("Name", "identity"),
        "schedule_expression": ("ScheduleExpression", "identity"),
        "schedule_expression_timezone": ("ScheduleExpressionTimezone", "identity"),
        "state": ("State", "identity"), "target": ("Target", "scheduler-target")}),
    "aws_scheduler_schedule_group": _read("scheduler", "get_schedule_group", {
        "arn": ("Arn", "identity"), "id": ("Name", "identity"), "name": ("Name", "identity"),
        "state": ("State", "identity")}),
    "aws_cloudwatch_event_rule": _read("events", "describe_rule", {
        "arn": ("Arn", "identity"), "description": ("Description", "identity"),
        "event_bus_name": ("EventBusName", "identity"), "event_pattern": ("EventPattern", "json"),
        "id": ("Name", "identity"), "name": ("Name", "identity"), "role_arn": ("RoleArn", "identity"),
        "schedule_expression": ("ScheduleExpression", "identity"), "state": ("State", "identity")}),
    "aws_cloudwatch_metric_alarm": {
        name: ("cloudwatch", "describe_alarms", ("MetricAlarms", 0, field), "identity")
        for name, field in {
            "actions_enabled": "ActionsEnabled", "alarm_description": "AlarmDescription", "alarm_name": "AlarmName",
            "arn": "AlarmArn", "comparison_operator": "ComparisonOperator",
            "datapoints_to_alarm": "DatapointsToAlarm", "evaluation_periods": "EvaluationPeriods",
            "extended_statistic": "ExtendedStatistic", "id": "AlarmName", "metric_name": "MetricName",
            "namespace": "Namespace", "period": "Period", "statistic": "Statistic", "threshold": "Threshold",
            "threshold_metric_id": "ThresholdMetricId", "treat_missing_data": "TreatMissingData",
            "unit": "Unit"}.items()},
    "aws_s3_bucket_lifecycle_configuration": _read("s3", "get_bucket_lifecycle_configuration", {
        "transition_default_minimum_object_size": ("TransitionDefaultMinimumObjectSize", "identity")}),
    "aws_cloudfront_response_headers_policy": _read("cloudfront", "get_response_headers_policy", {
        "comment": ("ResponseHeadersPolicy.ResponseHeadersPolicyConfig.Comment", "identity"),
        "etag": ("ETag", "identity"), "id": ("ResponseHeadersPolicy.Id", "identity"),
        "name": ("ResponseHeadersPolicy.ResponseHeadersPolicyConfig.Name", "identity")}),
}
CATALOG["aws_cloudwatch_metric_alarm"].update({
    name: ("cloudwatch", "describe_alarms", ("MetricAlarms", 0, field), "json-set")
    for name, field in {"alarm_actions": "AlarmActions", "insufficient_data_actions": "InsufficientDataActions",
                        "ok_actions": "OkActions"}.items()})
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
    "aws_sfn_state_machine": {
        "creation_date": "other-encoding", "encryption_configuration": "other-encoding",
        "logging_configuration": "other-encoding", "name_prefix": "state-only", "publish": "state-only",
        "region": "state-only", "revision_id": "other-encoding", "state_machine_version_arn": "state-only",
        "tags": "other-api", "tags_all": "other-api", "timeouts": "state-only",
        "tracing_configuration": "other-encoding", "version_description": "state-only"},
    "aws_scheduler_schedule": {
        "end_date": "other-encoding", "flexible_time_window": "other-encoding", "id": "other-encoding",
        "name_prefix": "state-only", "region": "state-only", "start_date": "other-encoding"},
    "aws_scheduler_schedule_group": {
        "creation_date": "other-encoding", "last_modification_date": "other-encoding", "name_prefix": "state-only",
        "region": "state-only", "tags": "other-api", "tags_all": "other-api", "timeouts": "state-only"},
    "aws_cloudwatch_event_rule": {
        "force_destroy": "state-only", "is_enabled": "state-only", "name_prefix": "state-only",
        "region": "state-only", "tags": "other-api", "tags_all": "other-api"},
    "aws_cloudwatch_metric_alarm": {
        "dimensions": "other-encoding",
        "evaluate_low_sample_count_percentiles": "other-encoding", "evaluation_criteria": "other-encoding",
        "evaluation_interval": "other-encoding", "metric_query": "other-encoding", "region": "state-only",
        "tags": "other-api", "tags_all": "other-api"},
    "aws_s3_bucket_lifecycle_configuration": {
        "bucket": "request-parameter", "expected_bucket_owner": "state-only", "id": "request-parameter",
        "region": "state-only", "rule": "other-encoding", "timeouts": "state-only"},
    "aws_cloudfront_response_headers_policy": {
        "arn": "state-only", "cors_config": "other-encoding",
        "custom_headers_config": "other-encoding", "remove_headers_config": "other-encoding",
        "security_headers_config": "other-encoding", "server_timing_headers_config": "other-encoding"},
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

    def __init__(self, covered, supported, identity=IDENTITY):
        self.covered, self.supported, self.identity = frozenset(covered), frozenset(supported), identity
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
            absence(plan, address, specs[index].get("parameters"), self.identity)
            used.add(index)
        c.require(seen == required, "absent drift coverage")


PHASE_A_ENVELOPE = Envelope(
    covered={"aws_iam_role", "aws_iam_role_policy", "aws_ecs_task_definition"},
    supported={"aws_iam_role", "aws_iam_role_policy", "aws_ecs_task_definition", "aws_dynamodb_table",
               "aws_s3_bucket_policy", "aws_s3_bucket_object_lock_configuration"})
LIFECYCLE_ENVELOPE = Envelope(
    covered={"aws_iam_role", "aws_iam_role_policy"},
    supported={"aws_iam_role", "aws_iam_role_policy", "aws_sfn_state_machine", "aws_scheduler_schedule",
               "aws_scheduler_schedule_group", "aws_cloudwatch_event_rule", "aws_cloudwatch_metric_alarm",
               "aws_s3_bucket_lifecycle_configuration", "aws_cloudfront_response_headers_policy"},
    identity=LIFECYCLE_ONLY)
ENVELOPES = {"phase-a": PHASE_A_ENVELOPE, "lifecycle": LIFECYCLE_ENVELOPE}
ABSENT_CODES = {
    ("stepfunctions", "describe_state_machine"): frozenset({"StateMachineDoesNotExist"}),
    ("scheduler", "get_schedule"): frozenset({"ResourceNotFoundException"}),
    ("scheduler", "get_schedule_group"): frozenset({"ResourceNotFoundException"}),
    ("events", "describe_rule"): frozenset({"ResourceNotFoundException"}),
}
DELETING_FIELD = {("stepfunctions", "describe_state_machine"): "status", ("scheduler", "get_schedule_group"): "State"}
LIFECYCLE_SPEC_FIELDS = {"service", "operation", "address", "absent", "members"}


def absent_by_error(service, operation, code):
    """Args: service, operation, AWS error code. Returns: absent observation. Raises: ValueError."""
    c.require(code in ABSENT_CODES.get((service, operation), frozenset()), "readback unknown")
    return {"absent": True}


def _alarms(spec, value):
    alarms, composites = value.get("MetricAlarms"), value.get("CompositeAlarms", [])
    c.require(type(alarms) is list and type(composites) is list, "readback unknown")
    if spec["absent"]:
        c.require(not alarms and not composites, "resource still exists")
        return {"absent": True}
    c.require(len(alarms) == 1 and not composites, "readback absent")
    return value


def observe_response(spec, value):
    """Args: spec, successful response. Returns: observed value, or the absent projection. Raises: ValueError."""
    key = (spec["service"], spec["operation"])
    if key == ("cloudwatch", "describe_alarms"):
        return _alarms(spec, value)
    field = DELETING_FIELD.get(key)
    state = value.get(field) if field else None
    if spec["absent"]:
        c.require(state == "DELETING", "resource still exists")
        return {"absent": True}
    c.require(field is None or state == "ACTIVE", "resource DELETING/unknown")
    return value


def _lifecycle_call(spec, changes, expected):
    c.require(type(spec) is dict and {"service", "operation", "address", "absent"} <= set(spec)
              <= LIFECYCLE_SPEC_FIELDS and type(spec["absent"]) is bool, "readback spec fields")
    grouped = "members" in spec
    c.require(not grouped or (spec["service"], spec["operation"]) == ("scheduler", "list_schedules"),
              "readback spec fields")
    change = changes.get(spec["address"])
    c.require(change is not None, "readback address")
    tipo = resource_type(spec["address"])
    if spec["absent"]:
        c.require(change["actions"] == ["delete"] and change["before"] is not None, "absence identity")
        derived = parameters(tipo, change["before"], LIFECYCLE_ONLY)
    else:
        c.require(spec["address"] in expected, "readback absent before")
        _stable(change, tipo, LIFECYCLE_ONLY)
        derived = parameters(tipo, expected[spec["address"]], LIFECYCLE_ONLY)
    if grouped:
        c.require(tipo == "aws_scheduler_schedule_group", "readback spec fields")
        derived = {"GroupName": derived["Name"]}
    return spec | {"parameters": derived}


def lifecycle_calls(plan, specs, stage, state=None):
    """Args: plan, specs, stage, state. Returns: specs plus identity-derived parameters. Raises: ValueError."""
    c.require(type(specs) is list and len(specs) <= 4096 and stage in {"before", "after"}, "readback specs")
    changes = _changes(plan)
    live = any(type(spec) is not dict or spec.get("absent") is not True for spec in specs)
    expected = c.stage_expectation(plan, stage, state) if live else {}
    return [_lifecycle_call(spec, changes, expected) for spec in specs]


def catalog_document():
    """Returns: the canonical catalogue document hashed into CATALOG_SHA256."""
    return {"catalog": {tipo: {name: [service, operation, list(path), encoding]
                               for name, (service, operation, path, encoding) in entries.items()}
                        for tipo, entries in CATALOG.items()},
            "envelopes": {name: {"covered": sorted(envelope.covered), "supported": sorted(envelope.supported)}
                          for name, envelope in ENVELOPES.items()},
            "identity": {tipo: [list(pair) for pair in pairs] for tipo, pairs in LIFECYCLE_ONLY.items()},
            "not_observable": NOT_OBSERVABLE,
            "omitted": {tipo: {name: list(values) for name, values in entries.items()}
                        for tipo, entries in OMITTED.items()},
            "container_defaults": c.CONTAINER_DEFAULTS}


CATALOG_SHA256 = c.sha(c.canonical(catalog_document()))
