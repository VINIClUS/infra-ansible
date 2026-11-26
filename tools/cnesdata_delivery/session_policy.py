"""Dynamic evidence scope; static powers exist only in the own managed session policy."""

import re
from typing import Any

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.coordination_lease import KEY

STATE_KEYS = (
    "cnesdata/prod/opentofu.tfstate",
    "cnesdata/prod/opentofu.tfstate.tflock",
    KEY,
)
LIFECYCLE_DELETES = ["states:DeleteStateMachine", "scheduler:DeleteSchedule", "scheduler:DeleteScheduleGroup",
                     "events:DeleteRule", "cloudwatch:DeleteAlarms"]

OPS_ROLE = "application_ops"
ACTIVATION_ROLE = "plan_activation"
ACTIVATION_KEY_LIMIT = 273
DELETE_ARN_MAX = 104

ACTIVATION_BUCKET_READS = ["s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetBucketObjectLockConfiguration"]
ACTIVATION_SLOTS = ("payload", "signature", "receipt")


def activation_ceiling(governance):
    """Closed root-owned ceiling; its original owner commitment is checked separately."""
    value = governance.get("activation_read")
    c.closed(value, "ceiling ordinary_bucket_denies plan_role_arn identity_sha256 session_sha256")
    ceiling = c.closed(value["ceiling"], "bucket_arn cipher_kms_key_arn keys")
    c.require(type(ceiling["bucket_arn"]) is str and re.fullmatch(r"arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", ceiling["bucket_arn"]), "activation bucket")
    c.require(type(ceiling["cipher_kms_key_arn"]) is str and re.fullmatch(
        "arn:aws:kms:us-east-2:" + re.escape(governance["account_id"]) + r":key/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", ceiling["cipher_kms_key_arn"]), "activation cipher")
    c.closed(ceiling["keys"], "payload signature receipt")
    from tools.cnesdata_delivery.evidence import key_valid
    keys = list(ceiling["keys"].values())
    c.require(all(type(key) is str and key_valid(key) and len(key.encode()) <= ACTIVATION_KEY_LIMIT for key in keys)
              and len(set(keys)) == 3, "activation exact distinct keys")
    for key in keys:
        c.require(not key.startswith(_prefix(governance) + "lifecycle/")
                  and key not in STATE_KEYS, "activation/lifecycle/state disjoint")
    denies = value["ordinary_bucket_denies"]
    c.require(type(denies) is list and len(set(denies)) == len(denies)
              and all(action in ACTIVATION_BUCKET_READS for action in denies), "activation original bucket denial")
    c.require(value["plan_role_arn"] == governance["roles"]["plan"], "activation plan role")
    c.digest(value["identity_sha256"])
    c.digest(value["session_sha256"])
    return ceiling


def activation_ordinary_denies(governance, role):
    if role != "plan" or governance.get("activation_read") is None:
        return []
    ceiling = activation_ceiling(governance)
    if not governance["activation_read"]["ordinary_bucket_denies"]:
        return []
    return [{"Effect": "Deny", "Action": governance["activation_read"]["ordinary_bucket_denies"], "Resource": ceiling["bucket_arn"]}]


def activation_request(governance, versions, *, deadline):
    """Two internal read scopes; exact encoded bytes must fit before either STS call."""
    ceiling = activation_ceiling(governance)
    c.require(type(versions) is dict and set(versions) in ({"receipt"}, set(ACTIVATION_SLOTS)), "activation version slots")
    for version in versions.values():
        c.require(type(version) is str and 0 < len(version) <= 1024 and version != "null"
                  and all(ord(ch) >= 32 and ord(ch) != 127 for ch in version), "activation version identity")
    c.require(type(deadline) is str and re.fullmatch(r"20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ", deadline), "activation original deadline")
    c.instant(deadline)
    objects = {slot: ceiling["bucket_arn"] + "/" + ceiling["keys"][slot] for slot in ACTIVATION_SLOTS}
    receipt_only = set(versions) == {"receipt"}
    statements = [{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"DateGreaterThanEquals": {"aws:CurrentTime": deadline}}}]
    statements += [{"Effect": "Deny", "Action": "s3:GetObjectVersion", "Resource": objects[slot],
        "Condition": {"StringNotEquals": {"s3:VersionId": versions[slot]}}} for slot in ACTIVATION_SLOTS if slot in versions]
    if receipt_only:
        statements += [
            {"Effect": "Deny", "Action": ["s3:GetObjectVersion", "s3:GetObjectRetention"], "Resource": [objects["payload"], objects["signature"]]},
            {"Effect": "Deny", "Action": "kms:*", "Resource": "*",
             "Condition": {"StringNotEquals": {"kms:EncryptionContext:aws:s3:arn": objects["receipt"]}}},
        ]
    return {"Policy": _encode(governance, ACTIVATION_ROLE, statements), "PolicyArns": [{"arn": managed_arn(governance, ACTIVATION_ROLE)}]}


def fence_session_policy(*, control_table_arn, execution_prefix, deadline):
    """Single pure closed-ready fence session (amendment 2026-11-13 item 3).

    Shared by the prepared evaluation and the real STS call; only the
    DateLessThan value differs between preparation and the API stage.
    """
    condition = _fence_session_condition(control_table_arn, execution_prefix, deadline)
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": control_table_arn, "Condition": condition | {
            "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["ENV#prod#FENCE", "ENV#prod#SEMAPHORE"]},
            "Null": {"dynamodb:LeadingKeys": "false"}}},
        {"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": execution_prefix + "*", "Condition": condition}]}


def fence_close_session_policy(*, control_table_arn, execution_prefix, deadline):
    """Finite close-drain fence session (amendment 6886977054 decision 4).

    TransactWriteItems has no IAM action of its own: each item is authorized by its
    per-item action, Update by UpdateItem on FENCE and ConditionCheck by ConditionCheckItem on SEMAPHORE.
    """
    condition = _fence_session_condition(control_table_arn, execution_prefix, deadline)
    def keys(*values):
        return condition | {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": list(values)},
                            "Null": {"dynamodb:LeadingKeys": "false"}}
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": control_table_arn,
         "Condition": keys("ENV#prod#FENCE", "ENV#prod#SEMAPHORE")},
        {"Effect": "Allow", "Action": "dynamodb:UpdateItem", "Resource": control_table_arn, "Condition": keys("ENV#prod#FENCE")},
        {"Effect": "Allow", "Action": "dynamodb:ConditionCheckItem", "Resource": control_table_arn,
         "Condition": keys("ENV#prod#SEMAPHORE")},
        {"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": execution_prefix + "*", "Condition": condition}]}


STATIC_SESSION_ACTIONS = {
    "observer": (("s3:ListBucketVersions", "s3:ListBucketMultipartUploads"), ("s3:GetObjectVersion", "s3:ListMultipartUploadParts"),
                 ()),
    "normal": ((), ("s3:PutObject", "s3:GetObject"), ("cloudfront:CreateInvalidation",)),
}


def static_session_policy(alias, *, bucket_arn, distribution_arn, deadline, keys=None):
    """Static session of one #498 static role: the IAM actions of its product calls, until the stage deadline.

    Bucket, object and distribution actions in that order. The normal object statement names exactly the
    authenticated candidate keys; the observer keeps bucket/* (its role narrows keys and versions).
    The observer has no distribution action, so inventory (no plan yet) passes distribution_arn None.
    """
    c.require(alias in STATIC_SESSION_ACTIONS, "static session alias")
    c.require(type(bucket_arn) is str and re.fullmatch(r"arn:aws:s3:::cnesdata-prod-[a-z0-9-]+", bucket_arn), "static session bucket")
    c.require((alias == "observer" and distribution_arn is None)
              or (type(distribution_arn) is str and re.fullmatch(r"arn:aws:cloudfront::[0-9]{12}:distribution/[A-Z0-9]+",
                                                                 distribution_arn) is not None), "static session distribution")
    c.require((alias == "observer" and keys is None)
              or (alias == "normal" and type(keys) is list and 0 < len(keys) == len(set(keys))
                  and all(type(key) is str and re.fullmatch(r"[A-Za-z0-9._/-]+", key) for key in keys)), "static session keys")
    c.integer(deadline)
    condition = {"DateLessThan": {"aws:CurrentTime": c.utc(deadline)}}
    objects = bucket_arn + "/*" if keys is None else [bucket_arn + "/" + key for key in keys]
    resources = (bucket_arn, objects, distribution_arn)
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": list(actions), "Resource": resource, "Condition": condition}
        for actions, resource in zip(STATIC_SESSION_ACTIONS[alias], resources) if actions]}


def fence_observe_session_policy(*, control_table_arn, deadline):
    """Observe fence session (P16b): only the strong FENCE/SEMAPHORE GetItem statement of fence_session_policy."""
    _fence_session_table(control_table_arn)
    c.integer(deadline)
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": control_table_arn, "Condition": {
            "DateLessThan": {"aws:CurrentTime": c.utc(deadline)},
            "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["ENV#prod#FENCE", "ENV#prod#SEMAPHORE"]},
            "Null": {"dynamodb:LeadingKeys": "false"}}}]}


MODE_SEED_RUN_PREFIXES = {"unit": ("unit",), "recovery": ("recovery-a", "recovery-b")}
MODE_SESSION_FRAMES = {"unit-seed": ("unit-seed",), "recovery-seed": ("recovery-seed",), "unit-start": ("dispatch-unit",),
                       "recovery-start": ("ledger-admit", "ledger-unknown", "ledger-settle")}
MODE_RESOURCE_SHAPES = {"revisions": "audit recovery unit", "task_role_arns": "audit recovery unit",
                        "network": "public_subnet_ids security_group_id", "schedule_arns": "audit recovery",
                        "alarm_arns": "audit_outbox_backlog audit_repeated_failure recovery_repeated_failure",
                        "scope": "audit_object_keys output_object_keys raw_object_keys run_ids tenant_id"}
_MODE_RESOURCE_FIELDS = frozenset({"table_arn", "index_arn", "data_bucket_arn", "audit_bucket_arn", "cluster_arn", "machine_arn",
                                   "execution_role_arn", "log_group_arn", *MODE_RESOURCE_SHAPES})
_MODE_ARNS = {"table_arn": r"arn:aws:dynamodb:us-east-2:[0-9]{12}:table/cnesdata-prod-[A-Za-z0-9_.-]+",
              "data_bucket_arn": r"arn:aws:s3:::cnesdata-prod-[a-z0-9-]+",
              "cluster_arn": r"arn:aws:ecs:us-east-2:[0-9]{12}:cluster/[A-Za-z0-9_-]+",
              "machine_arn": r"arn:aws:states:us-east-2:[0-9]{12}:stateMachine:[A-Za-z0-9_-]+",
              "execution_role_arn": r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]+"}
_MODE_MAPS = {"revisions": r"arn:aws:ecs:us-east-2:[0-9]{12}:task-definition/[A-Za-z0-9_-]+:[0-9]+",
              "task_role_arns": r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]+"}
_MODE_OBJECT_KEY = re.compile(r"[A-Za-z0-9._/=-]{1,1024}")
_MODE_RUN_FAMILIES = frozenset({"seed-unit", "binding"})
_MODE_DYNAMODB = {"get": "dynamodb:GetItem", "put": "dynamodb:PutItem"}
_MODE_READS = {"describe_state_machine": "states:DescribeStateMachine", "get_schedule": "scheduler:GetSchedule",
               "describe_task_definition": "ecs:DescribeTaskDefinition", "describe_alarms": "cloudwatch:DescribeAlarms"}


def mode_session_policy(operation, *, resources, owner_sha256, deadline):
    """Mode stage session (P16b ruling 4 item 1): the native calls of one promotion operation, until the deadline.

    DynamoDB actions and keys come from the operation's C1 key frames, pinned against the vendored vector; observe
    reads come from mode_readback_calls. Each session is a strict subset of its mode role grant.
    Raises: ValueError before any STS call.
    """
    from tools.cnesdata_delivery import lifecycle_contract as lc
    entry = lc.MODE_SESSION_OPERATIONS.get(operation) if type(operation) is str else None
    c.require(entry is not None and entry[2] == "promotion", "mode session operation")
    _mode_session_resources(resources)
    c.require(type(owner_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", owner_sha256) is not None, "mode session owner")
    c.integer(deadline)
    phase, step = entry[3], operation.removeprefix(entry[3] + "-")
    statements = (_mode_unit_start(resources, owner_sha256) if operation == "unit-start"
                  else _mode_dynamodb(operation, resources, owner_sha256))
    if step == "seed":
        statements.append(_mode_allow(["s3:PutObject", "s3:GetObject"], _mode_objects(resources, "raw_object_keys")))
    elif step == "start":
        statements += _mode_start(phase, resources)
    else:
        statements += _mode_observe(phase, resources)
    return _mode_expiring(statements, deadline)


def mode_unit_wait_policy(*, resources, deadline):
    """ux wait part (P16b ruling 5 item 3 (2)): the unit-execution and unit-task reads after StartExecution, assumed on
    the ux role and session name, until the deadline.

    Raises: ValueError before any STS call.
    """
    _mode_session_resources(resources)
    c.integer(deadline)
    execution = resources["machine_arn"].replace(":stateMachine:", ":execution:") + ":*"
    return _mode_expiring([_mode_allow(["states:DescribeExecution"], execution), _mode_tasks(resources)], deadline)


def _mode_expiring(statements, deadline):
    expiry = {"DateLessThan": {"aws:CurrentTime": c.utc(deadline)}}
    return {"Version": "2012-10-17", "Statement": [statement | {"Condition": expiry | statement.get("Condition", {})}
                                                   for statement in statements]}


def _mode_session_resources(resources):
    c.require(type(resources) is dict and set(resources) == _MODE_RESOURCE_FIELDS
              and all(type(resources[key]) is dict and set(resources[key]) == set(shape.split())
                      for key, shape in MODE_RESOURCE_SHAPES.items())
              and all(type(resources[key]) is str and re.fullmatch(pattern, resources[key]) is not None
                      for key, pattern in _MODE_ARNS.items())
              and all(type(value) is str and re.fullmatch(pattern, value) is not None
                      for key, pattern in _MODE_MAPS.items() for value in resources[key].values()), "mode session resources")
    scope = resources["scope"]
    runs = scope["run_ids"]
    c.require(type(runs) is list and len(set(runs)) == len(runs)
              and all(type(name) is str and re.fullmatch(r"[0-9a-z-]{1,64}", name) is not None for name in [scope["tenant_id"], *runs])
              and all(_mode_keys(scope[field], 1) for field in ("raw_object_keys", "output_object_keys"))
              and _mode_keys(scope["audit_object_keys"], 0), "mode session resources")


def _mode_keys(value, minimum):
    return (type(value) is list and minimum <= len(value) <= 64 and len(set(value)) == len(value)
            and all(type(key) is str and _MODE_OBJECT_KEY.fullmatch(key) is not None for key in value))


def _mode_allow(actions, resource, condition=None):
    return {"Effect": "Allow", "Action": actions, "Resource": resource} | ({"Condition": condition} if condition else {})


def _mode_objects(resources, field):
    return [resources["data_bucket_arn"] + "/" + key for key in resources["scope"][field]]


def _mode_runs(operation, resources, owner):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    names = {f"{prefix}-{owner[:16]}" for prefix in MODE_SEED_RUN_PREFIXES[lc.MODE_SESSION_OPERATIONS[operation][3]]}
    runs = [run for run in resources["scope"]["run_ids"] if run in names]
    c.require(bool(runs), "mode session runs")
    return runs


def _mode_dynamodb(operation, resources, owner):
    from tools.cnesdata_delivery.mode_broker import MODE_KEY_FRAMES
    tenant = "TENANT#" + resources["scope"]["tenant_id"].encode().hex()
    families = set().union(*(MODE_KEY_FRAMES[frame] for frame in MODE_SESSION_FRAMES.get(operation, ())))
    runs = ([tenant + "#RUN#" + run.encode().hex() for run in _mode_runs(operation, resources, owner)]
            if any(family in _MODE_RUN_FAMILIES for family, _ in families) else [])
    keys = {}
    for family, action in families:
        keys.setdefault(_MODE_DYNAMODB[action], set()).update(runs if family in _MODE_RUN_FAMILIES else [tenant])
    grouped = {}
    for action in sorted(keys):
        grouped.setdefault(tuple(sorted(keys[action])), []).append(action)
    return [_mode_allow(actions, resources["table_arn"], {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": list(found)},
                                                        "Null": {"dynamodb:LeadingKeys": "false"}})
            for found, actions in grouped.items()]


def _mode_table(actions, resources, keys):
    return _mode_allow(actions, resources["table_arn"], {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": sorted(keys)},
                                                         "Null": {"dynamodb:LeadingKeys": "false"}})


def _mode_unit_start(resources, owner):
    from tools.cnesdata_delivery.mode_broker import unit_start_grants
    actions, rectangles = {}, {}
    for action, keys in unit_start_grants(resources, owner).items():
        for key in keys:
            actions.setdefault(key, set()).add(action)
    for key, found in actions.items():
        rectangles.setdefault(tuple(sorted(found)), set()).add(key)
    return [_mode_table(list(found), resources, keys) for found, keys in sorted(rectangles.items())]


def _mode_tasks(resources):
    return _mode_allow(["ecs:DescribeTasks"], resources["cluster_arn"].replace(":cluster/", ":task/") + "/*",
                       {"ArnEquals": {"ecs:cluster": resources["cluster_arn"]}})


def _mode_start(phase, resources):
    if phase == "unit":
        return [_mode_allow(["states:StartExecution"], resources["machine_arn"])]
    return [_mode_allow(["ecs:RunTask"], resources["revisions"][phase], {"ArnEquals": {"ecs:cluster": resources["cluster_arn"]}}),
            _mode_allow(["iam:PassRole"], [resources["task_role_arns"][phase], resources["execution_role_arn"]],
                        {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}), _mode_tasks(resources)]


def _mode_observe(phase, resources):
    from tools.cnesdata_delivery.mode_broker import mode_readback_calls
    targets = {"describe_state_machine": resources["machine_arn"], "describe_task_definition": "*",
               "get_schedule": resources["schedule_arns"].get(phase),
               "describe_alarms": resources["alarm_arns"].get(phase + "_repeated_failure")}
    statements = [_mode_allow([_MODE_READS[call["operation"]]], targets[call["operation"]])
                  for call in mode_readback_calls(phase, resources)]
    if phase == "unit":
        statements.append(_mode_allow(["s3:GetObject"], _mode_objects(resources, "output_object_keys")))
    return statements


def _fence_session_table(control_table_arn):
    c.require(type(control_table_arn) is str and re.fullmatch(
        r"arn:aws:dynamodb:us-east-2:[0-9]{12}:table/cnesdata-prod-[A-Za-z0-9_.-]+", control_table_arn), "fence session table")


def _fence_session_condition(control_table_arn, execution_prefix, deadline):
    _fence_session_table(control_table_arn)
    c.require(type(execution_prefix) is str and re.fullmatch(
        r"arn:aws:states:us-east-2:[0-9]{12}:execution:cnesdata-prod:", execution_prefix), "fence session execution prefix")
    c.integer(deadline)
    return {"DateLessThan": {"aws:CurrentTime": c.utc(deadline)}}


def predecessor_keys(governance, selector):
    """The reviewed historical union derives keys; a caller never supplies paths."""
    c.closed(selector, "protocol source_sha run_id run_attempt status purpose")
    c.digest(selector["source_sha"], 40)
    c.integer(selector["run_id"])
    c.integer(selector["run_attempt"])
    protocol, status, purpose = (selector[k] for k in ("protocol", "status", "purpose"))
    if protocol == "legacy-infra":
        c.require(status in {"planned", "applied"} and purpose in c.PURPOSES, "original legacy history selector")
        names = ["envelope.json", "lease.json", "checkpoint.json"]
        if status == "applied":
            names += ["drift.json"] + (["ecr-before.json"] if purpose == "phase-a" else [])
    else:
        c.require(protocol == "lifecycle" and status == "terminal" and purpose == "application", "original lifecycle history selector")
        names = ["terminal.json", "lease.json", "checkpoint.json"]
    prefix = _prefix(governance) + ("lifecycle/" if protocol == "lifecycle" else "")
    prefix += f"{selector['source_sha']}/{selector['run_id']}/{selector['run_attempt']}/{status}/"
    return [prefix + name for name in names]


def predecessor_policy(governance, selector):
    """Original H4 policy derived independently of the private output digest."""
    arns = ["arn:aws:s3:::" + governance["evidence_bucket"] + "/" + key
            for key in predecessor_keys(governance, selector)]
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": arns},
        {"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": governance["evidence_kms_key_arn"],
         "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-2.amazonaws.com",
                                        "kms:EncryptionContext:aws:s3:arn": arns}}},
    ]}


def lifecycle_request(governance, source, run_id, attempt, role, step, *, direction, delete_resources=(), predecessor=None):
    """Same-run evidence, read-only original lease, exact inverse resources.

    The existing managed policy supplies state/provider permissions; explicit
    inline Denies apply to their union, including when product policy allows it.
    Never silently compress an over-quota list into wildcard authorization.
    """
    c.digest(source, 40)
    c.integer(run_id)
    c.integer(attempt)
    c.require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", step) and direction in {"advance", "converge"}, "lifecycle session step")
    base = "arn:aws:s3:::" + governance["evidence_bucket"] + "/" + _prefix(governance)
    run = base + f"lifecycle/{source}/{run_id}/{attempt}/"
    own = run + step + "/*"
    key = governance["evidence_kms_key_arn"]
    statements = [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": run + "*"},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": own},
        # KMS has the same run boundary; S3 PutObject still limits writes to own step.
        {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], "Resource": key,
         "Condition": {"StringLike": {"kms:EncryptionContext:aws:s3:arn": run + "*"}}},
    ]
    if predecessor is not None:
        c.require(role == "plan" and direction == "advance"
                  and (predecessor["run_id"], predecessor["run_attempt"]) != (run_id, attempt), "first plan distinct historical owner")
        keys = predecessor_keys(governance, predecessor)
        checkpoint = next(k for k in keys if k.endswith("/checkpoint.json"))
        arn = "arn:aws:s3:::" + governance["evidence_bucket"] + "/" + checkpoint
        statements += [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": arn},
            {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key,
             "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": arn}}},
        ]
    if direction == "advance" or role in {"plan", "audit"}:
        c.require(not delete_resources, "advance/read session cannot delete")
        if role == "deploy":
            statements.append({"Effect": "Deny", "Action": LIFECYCLE_DELETES, "Resource": "*"})
    else:
        c.require(type(delete_resources) in (list, tuple) and 0 < len(delete_resources) <= _delete_bound()
                  and len(set(delete_resources)) == len(delete_resources), "inverse exact resource inventory")
        for arn in delete_resources:
            c.require(re.fullmatch(r"arn:aws:(?:states|scheduler|events|cloudwatch):us-east-2:"
                                  + re.escape(governance["account_id"]) + r":[A-Za-z0-9_./:-]+", arn)
                      and "cnesdata-prod" in arn and len(arn) <= DELETE_ARN_MAX, "inverse exact same-product ARN")
        statements.append({"Effect": "Deny", "Action": LIFECYCLE_DELETES, "NotResource": list(delete_resources)})
    return {"Policy": _encode(governance, role, statements + activation_ordinary_denies(governance, role)), "PolicyArns": [{"arn": managed_arn(governance, role)}]}


def _delete_bound():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    return max(len(lc.scheduler_closure(kind)) for kind in ("recovery", "audit"))


def application_request(governance, source, run_id, attempt, step, *, application_purpose, delegations=(), sessions=None):
    """Keeper can coordinate/read history; operation sessions cannot write lease.

    The separately authenticated own managed policy holds only static permissions
    and the one exact predecessor inventory. It never grants lifecycle evidence
    access; the inline policy supplies only this run and its own output step.
    Session names are protected dispatcher outputs after context/prepare checks,
    never product API arguments. This scope alone is not a prepare receipt.
    """
    c.digest(source, 40)
    c.integer(run_id)
    c.integer(attempt)
    c.require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", step), "application session step")
    from tools.cnesdata_delivery import lifecycle_contract as lc
    c.require(application_purpose in lc.APPLICATION_CONTEXTS, "closed application purpose")
    keeper = step == "keeper"
    c.require(type(delegations) in (list, tuple) and len(set(delegations)) == len(delegations)
              and set(delegations) <= set(lc.APPLICATION_DELEGATIONS),
              "closed application delegation")
    c.require(not keeper or not delegations, "keeper cannot assume product roles")
    c.require(type(sessions) is dict and set(sessions) == set(delegations) if delegations else sessions in (None, {}),
              "exact protected delegation sessions required")
    if application_purpose == "mode-readiness-drill":
        c.require(set(delegations) <= {"mode_seed", "mode_dispatch", "mode_observe"}, "readiness has no static/fence/audit-launch authority")
    for alias in delegations:
        name = sessions[alias]
        c.require(type(name) is str, "protected delegation session name")
        if alias.startswith("mode_"):
            codes = [code for code, role, context, _ in lc.MODE_SESSION_OPERATIONS.values()
                     if role == alias and context == lc.APPLICATION_CONTEXTS[application_purpose]]
            c.require(any(re.fullmatch("mc-" + code + r"-[0-9a-f]{40}", name) for code in codes), "nominal exact mode session")
        else:
            patterns = {"observer": r"sp-i-[0-9a-f]{40}", "normal": r"sp-(?:publish|retire)-[0-9a-f]{40}",
                        "recovery": r"sp-(?:rollback|readback|abort)-[0-9a-f]{40}",
                        "seeder": r"canary-seeder-[A-Za-z0-9][A-Za-z0-9_.-]{0,31}",
                        "verifier": r"canary-verifier-[A-Za-z0-9][A-Za-z0-9_.-]{0,31}",
                        "fence_operator": r"promotion-fence-[A-Za-z0-9][A-Za-z0-9_.-]{0,31}"}
            c.require(re.fullmatch(patterns[alias], name), "nominal exact original session")
    run = "arn:aws:s3:::" + governance["evidence_bucket"] + "/" + _prefix(governance) + f"lifecycle/{source}/{run_id}/{attempt}/"
    own = [run + name + "/*" for name in (("keeper", "terminal") if keeper else (step,))]
    statements = [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": run + "*"},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": own},
        {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
         "Resource": governance["evidence_kms_key_arn"], "Condition": {"StringLike": {"kms:EncryptionContext:aws:s3:arn": run + "*"},
                                                                     "StringEquals": {"kms:ViaService": "s3.us-east-2.amazonaws.com"}}},
    ]
    if delegations:
        roles = governance["application_delegations"]
        c.require(all(roles[name] == "arn:aws:iam::" + governance["account_id"] + ":role/cnesdata-prod-" + lc.APPLICATION_DELEGATIONS[name]
                      for name in delegations), "exact governed product roles")
        statements += [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": roles[alias],
                        "Condition": {"StringEquals": {"sts:RoleSessionName": sessions[alias]}}} for alias in delegations]
    if keeper:
        statements.append({"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"})
    managed = "application" if keeper else OPS_ROLE
    return {"Policy": _encode(governance, managed, statements), "PolicyArns": [{"arn": managed_arn(governance, managed)}]}


class PhaseInputScope(str):
    """Internal output of the original-owner grouping validator, never a JSON input."""


def managed_arn(governance, role):
    c.require(role in {"plan", "deploy", "application", "audit", OPS_ROLE, ACTIVATION_ROLE}, "session role")
    base = {OPS_ROLE: "application", ACTIVATION_ROLE: "plan"}.get(role, role)
    account = governance["account_id"]
    c.require(
        type(account) is str and re.fullmatch(r"[0-9]{12}", account), "session account"
    )
    role_arn = governance["roles"][base]
    c.require(
        re.fullmatch(
            rf"arn:aws:iam::{account}:role/cnesdata-[a-z0-9-]+-{base}", role_arn
        ),
        "deterministic governed session role",
    )
    kind = {OPS_ROLE: "-ops-session", ACTIVATION_ROLE: "-activation-session"}.get(role, "-session")
    return f"arn:aws:iam::{account}:policy/{role_arn.rsplit('/', 1)[1]}{kind}"


def _prefix(governance):
    prefix = governance["evidence_prefix"]
    c.require(
        type(prefix) is str
        and prefix.startswith("cnesdata/prod/")
        and ".." not in prefix
        and re.fullmatch(r"[A-Za-z0-9_./-]+", prefix),
        "session evidence namespace",
    )
    return prefix.rstrip("/") + "/"


def _reads(prefix: str, read_keys: list[str]) -> list[str]:
    c.require(
        type(read_keys) is list and len(read_keys) <= 64,
        "bounded exact historical reads",
    )
    for key in read_keys:
        exact = isinstance(key, str) and key.startswith(prefix) and ".." not in key
        wildcard = (
            re.escape(prefix)
            + r"[0-9a-f]{40}/[1-9][0-9]*/[1-9][0-9]*/(?:planned|applied)/\*"
        )
        grouped = type(key) is PhaseInputScope and re.fullmatch(
            re.escape(prefix) + r"phase-inputs/[0-9a-f]{40}/[1-9][0-9]*/[1-9][0-9]*/\*",
            key,
        )
        c.require(
            exact
            and (
                re.fullmatch(r"[A-Za-z0-9_./-]+", key)
                or re.fullmatch(wildcard, key)
                or grouped
            ),
            "exact read or authenticated run scope",
        )
    return sorted(set(read_keys))


def _encode(governance, role, statements):
    encoded = c.canonical({"Version": "2012-10-17", "Statement": statements})[
        :-1
    ].decode()
    arns = [{"arn": managed_arn(governance, role)}]
    c.require(
        len(arns) <= 10
        and encoded.isascii()
        and len(encoded) + sum(len(item["arn"]) for item in arns) <= 2048,
        "STS inline plus managed session policy exceeds 2048 characters; reviewed recovery required",
    )
    return encoded


def build(governance, source, run_id, attempt, role, read_keys):
    c.digest(source, 40)
    c.integer(run_id)
    c.integer(attempt)
    managed_arn(governance, role)
    prefix = _prefix(governance)
    bucket = governance["evidence_bucket"]
    c.require(
        type(bucket) is str
        and re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket),
        "session bucket name",
    )
    bucket_arn = "arn:aws:s3:::" + bucket
    own = (
        bucket_arn
        + "/"
        + prefix
        + f"{source}/{run_id}/{attempt}/{'planned' if role == 'plan' else 'applied'}/*"
    )
    historical = [bucket_arn + "/" + key for key in _reads(prefix, read_keys)]
    c.require(
        not any(
            item.startswith(own[:-1]) or own.startswith(item.removesuffix("*"))
            for item in historical
        ),
        "historical/current scope overlap",
    )
    key_arn = governance["evidence_kms_key_arn"]
    c.require(
        re.fullmatch(
            rf"arn:aws:kms:us-east-2:{governance['account_id']}:key/"
            r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",
            key_arn,
        ),
        "session evidence CMK",
    )
    read = [own, *historical]
    statements = [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": read},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": own},
        {
            "Effect": "Allow",
            "Action": "kms:Decrypt",
            "Resource": key_arn,
            "Condition": {"StringLike": {"kms:EncryptionContext:aws:s3:arn": read}},
        },
        {
            "Effect": "Allow",
            "Action": ["kms:Encrypt", "kms:GenerateDataKey"],
            "Resource": key_arn,
            "Condition": {"StringLike": {"kms:EncryptionContext:aws:s3:arn": own}},
        },
    ]
    if historical:
        statements.append(
            {"Effect": "Deny", "Action": "s3:PutObject", "Resource": historical}
        )
    return _encode(governance, role, statements + activation_ordinary_denies(governance, role))


def request(governance, source, run_id, attempt, role, read_keys):
    return {
        "Policy": build(governance, source, run_id, attempt, role, read_keys),
        "PolicyArns": [{"arn": managed_arn(governance, role)}],
    }


def validate_response(response: dict[str, Any]) -> dict[str, Any]:
    c.require(
        type(response) is dict
        and type(response.get("PackedPolicySize")) is int
        and 0 <= response["PackedPolicySize"] <= 100,
        "STS packed policy utilization",
    )
    if "SessionTokenUtilization" in response:
        c.require(
            type(response["SessionTokenUtilization"]) is int
            and 0 <= response["SessionTokenUtilization"] <= 100,
            "STS token utilization",
        )
    return response["Credentials"]
