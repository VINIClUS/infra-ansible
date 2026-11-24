"""Mode SDK broker, fence-read broker and mode readbacks of the promotion mode stages (P16b)."""
import importlib.util
import pathlib
import re
import sys
import time

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.application_gate import (AdapterJournal, ClosedReadyBroker, Keeper, _assume_fence_session,
                                                      _fence_operation_iam, _operation_journals)

MODE_PHASES = ("unit", "recovery", "audit")
MODE_SEED_KEYS = frozenset((family, action) for family in ("seed-raw", "seed-run", "seed-unit") for action in ("put", "get"))
MODE_KEY_FRAMES = {
    "unit-seed": MODE_SEED_KEYS | {("record-unit", "put"), ("record-unit", "get"), ("control", "put"), ("control", "get")},
    "recovery-seed": MODE_SEED_KEYS | {("record-recovery", "put"), ("record-recovery", "get"), ("control", "get")},
    "dispatch-unit": frozenset({("binding", "put"), ("ticket", "put"), ("ticket", "get"), ("control", "put"),
                                ("control", "get")}),
    "ledger-admit": frozenset({("ticket", "put"), ("ticket", "get"), ("control", "put"), ("control", "get")}),
    "ledger-unknown": frozenset({("ticket", "put"), ("ticket", "get")}),
    "ledger-settle": frozenset({("ticket", "put"), ("ticket", "get")}),
}
PRODUCT_FRAMES = (
    ("cnes_infra.control_plane.dynamodb_keys", "product_dynamodb_keys.py",
     "5810031c6ed6fae18f7a70e578c5255b9297ce63f0745b237eca191688ca19eb"),
    ("cnes_domain.orchestration.mode_canary", "product_mode_canary.py",
     "255431e9f02f0f26554c42370ee0b0c55b1ab9287a79422c24be377df45571d2"),
    ("cnes_infra.aws.mode_canary_frames", "product_mode_canary_frames.py",
     "3b95d77a70c9c121c6dc77cea9b71d0cac5fab359fd4b6d655269f3a61a315a6"))
_PRODUCT = {}
_RUN = re.compile(r"[a-z0-9-]{1,64}")
_DISPATCH = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_MANIFEST = re.compile(r"[A-Za-z0-9._-]{1,128}")


def _load_product_frames(folder):
    c.require(sys.version_info >= (3, 12), "mode_frames=python_version")
    verified = []
    for name, file, digest in PRODUCT_FRAMES:
        raw = (folder / file).read_bytes()
        c.require(c.sha(raw) == digest, f"mode product frames sha256 file={file}")
        verified.append((name, str(folder / file), raw))
    saved = {name: sys.modules.get(name) for name, _, _ in verified}
    try:
        for name, origin, raw in verified:
            module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None, origin=origin))
            sys.modules[name] = module
            exec(compile(raw, origin, "exec"), module.__dict__)
        return sys.modules[PRODUCT_FRAMES[-1][0]]
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


def product_frames():
    """C2 vendored product ledger builders (ruling 3): the pinned product bytes, run under their product module names.

    Returns: the cnes_infra.aws.mode_canary_frames module. Raises: ValueError on any byte drift, before executing.
    """
    if "frames" not in _PRODUCT:
        _PRODUCT["frames"] = _load_product_frames(pathlib.Path(__file__).resolve().parent)
    return _PRODUCT["frames"]


def _hex(value):
    return value.encode().hex()


def _decoded(raw, pattern):
    try:
        value = bytes.fromhex(raw).decode("ascii")
    except ValueError:
        return None
    return value if pattern.fullmatch(value) is not None and _hex(value) == raw else None


def _mode_key_binding(frame, binding):
    c.closed(binding, "canary_id owner_sha256 run_ids dispatch_id")
    owner, runs, dispatch = binding["owner_sha256"], binding["run_ids"], binding["dispatch_id"]
    c.require(type(binding["canary_id"]) is str and re.fullmatch(r"[0-9a-f]{32}", binding["canary_id"]) is not None
              and type(owner) is str and re.fullmatch(r"[0-9a-f]{64}", owner) is not None
              and type(runs) is list and 1 <= len(runs) <= 8 and len(set(runs)) == len(runs)
              and all(type(run) is str and _RUN.fullmatch(run) is not None and run.endswith("-" + owner[:16]) for run in runs)
              and (dispatch is None) == (frame != "dispatch-unit")
              and (dispatch is None or type(dispatch) is str and _DISPATCH.fullmatch(dispatch) is not None),
              "mode key binding")


def _tenant_family(sk, binding):
    owner = binding["owner_sha256"]
    named = {f"PROD_CANARY_CONTROL#{owner}": "control",
             **{f"PROD_CANARY#{owner}#{phase}": "record-" + phase for phase in MODE_PHASES},
             **{"RUN#" + _hex(run): "seed-run" for run in binding["run_ids"]}}
    if sk in named:
        return named[sk]
    if re.fullmatch(f"PROD_CANARY_EFFECT#{owner}#[0-9a-f]{{64}}", sk) is not None:
        return "ticket"
    raw = sk.removeprefix("RAW_MANIFEST#") if sk.startswith("RAW_MANIFEST#") else None
    manifest = _decoded(raw, _MANIFEST) if raw else None
    return "seed-raw" if manifest is not None and manifest.endswith("-" + owner[:16]) else None


def _mode_key_family(key, binding):
    pk, sk = key
    tenant = "TENANT#" + _hex("prod-canary-" + binding["canary_id"])
    if pk == tenant:
        return _tenant_family(sk, binding)
    if pk not in {tenant + "#RUN#" + _hex(run) for run in binding["run_ids"]}:
        return None
    if sk.startswith("UNIT#") and _decoded(sk.removeprefix("UNIT#"), re.compile(r"[0-9a-f]{32}")) is not None:
        return "seed-unit"
    return "binding" if binding["dispatch_id"] is not None and sk == "PROD_CANARY#" + binding["dispatch_id"] else None


def admit_mode_key(frame, action, key, *, binding):
    """C1 sort-key fence (LeadingKeys fences only the partition key): the closed key family set of the frame.

    Args: frame, action put/get, (pk, sk), binding {canary_id, owner_sha256, run_ids, dispatch_id}.
    Returns: the item family. Raises: ValueError before any SDK call.
    """
    c.require(frame in MODE_KEY_FRAMES and action in ("put", "get"), "mode key outside frame")
    _mode_key_binding(frame, binding)
    c.require(type(key) is tuple and len(key) == 2 and all(type(part) is str for part in key), "mode key outside frame")
    family = _mode_key_family(key, binding)
    c.require((family, action) in MODE_KEY_FRAMES[frame], "mode key outside frame")
    return family


LEDGER_REBUILD_CODES = frozenset({"None", "ConditionalCheckFailed", "TransactionConflict"})
LEDGER_CANCELS = {"transact_write_items": "TransactionCanceledException", "put_item": "ConditionalCheckFailedException"}
_LEDGER_ITEM = frozenset({"pk", "sk", "entity", "payload"})


def _cancel_reasons(operation, response):
    if operation == "put_item":
        return [{"Code": "ConditionalCheckFailed"}]
    reasons = response.get("CancellationReasons")
    if type(reasons) is not list or not reasons or not all(type(item) is dict and type(item.get("Code")) is str
                                                           for item in reasons):
        return None
    return [{"Code": item["Code"]} for item in reasons]


def ledger_cancel_response(operation, error):
    """R12 split of a ledger write error (ruling 3 item 2): a cancel applied nothing, anything else is unknown.

    Returns: the definite cancel as the receipted response, or None when the outcome is unknown (poison, no retry).
    """
    response = getattr(error, "response", None)
    if operation not in LEDGER_CANCELS or type(response) is not dict:
        return None
    metadata, failure = response.get("ResponseMetadata"), response.get("Error")
    if (type(metadata) is not dict or metadata.get("HTTPStatusCode") != 400 or type(failure) is not dict
            or failure.get("Code") != LEDGER_CANCELS[operation]):
        return None
    reasons = _cancel_reasons(operation, response)
    return None if reasons is None else {"Error": {"Code": LEDGER_CANCELS[operation]}, "CancellationReasons": reasons}


def ledger_cancel_codes(response):
    """Returns: None for the applied write ({}), else the cancellation codes. Raises: ValueError mode ledger response."""
    if response == {}:
        return None
    reasons = response.get("CancellationReasons") if type(response) is dict else None
    c.require(type(response) is dict and set(response) == {"Error", "CancellationReasons"}
              and response["Error"] in [{"Code": code} for code in LEDGER_CANCELS.values()]
              and type(reasons) is list and len(reasons) >= 1
              and all(type(item) is dict and set(item) == {"Code"} and type(item["Code"]) is str for item in reasons),
              "mode ledger response")
    return tuple(item["Code"] for item in reasons)


def _ledger_put(table, put):
    frames = product_frames()
    item = put.get("Item") if type(put) is dict else None
    c.require(type(item) is dict and set(item) == _LEDGER_ITEM
              and all(type(item[name]) is dict and set(item[name]) == {"S"} and type(item[name]["S"]) is str
                      for name in _LEDGER_ITEM)
              and put.get("TableName") == table
              and (put.get("ConditionExpression"), set(put)) in [
                  (frames.INSERT_ONLY, {"TableName", "Item", "ConditionExpression"}),
                  (frames.SWAP, {"TableName", "Item", "ConditionExpression", "ExpressionAttributeValues"})],
              "mode ledger request shape")
    return item["pk"]["S"], item["sk"]["S"]


def _ledger_keys(table, operation, request):
    c.require(operation in LEDGER_CANCELS and type(request) is dict, "mode ledger request shape")
    if operation == "put_item":
        return [_ledger_put(table, request)]
    items = request.get("TransactItems")
    c.require(set(request) == {"TransactItems"} and type(items) is list and 1 <= len(items) <= 3
              and all(type(item) is dict and set(item) == {"Put"} for item in items), "mode ledger request shape")
    return [_ledger_put(table, item["Put"]) for item in items]


def ledger_write(frame, *, table, binding, reads, read, build, execute):
    """Ruling 3 item 2: a ledger write built by the vendored product builder, rebuilt only after a definite cancel.

    Args: C1 frame and binding, control table, strong-read keys, read(keys) -> {key: text}, build(texts) ->
    (operation, request) or None once applied, execute(operation, request) -> receipted response (raises if unknown).
    Returns: native writes made. Raises: ValueError (C1, shape, ledger_cancel reason=, ledger_contended attempts=).
    """
    c.require(frame in MODE_KEY_FRAMES, "mode key outside frame")
    attempts = product_frames().ATTEMPTS
    for key in reads:
        admit_mode_key(frame, "get", key, binding=binding)
    for attempt in range(attempts):
        planned = build(read(reads))
        if planned is None:
            return attempt
        operation, request = planned
        for key in _ledger_keys(table, operation, request):
            admit_mode_key(frame, "put", key, binding=binding)
        codes = ledger_cancel_codes(execute(operation, request))
        if codes is None:
            return attempt + 1
        refused = [code for code in codes if code not in LEDGER_REBUILD_CODES]
        c.require(not refused, f"ledger_cancel reason={refused[0] if refused else ''}")
    raise ValueError(f"ledger_contended attempts={attempts}")


MODE_RECORD_FIELDS = "version kind record audit_event_ids"


def mode_record_inputs(raw, *, mode, owner_sha256, activation_sha256):
    """Seed/start inputs from the journaled mode-record of the pure product <mode>-record operation (ruling 2 item 1).

    Args: observation bytes, mode, current owner_sha256, request activation_sha256.
    Returns: {"record": exact record text bytes} plus {"audit-event-ids": canonical ids} for audit. Raises: ValueError.
    """
    value = c.loads(raw, canonical=True, limit=64 * 1024)
    c.closed(value, MODE_RECORD_FIELDS)
    text, ids = value["record"], value["audit_event_ids"]
    c.require(type(value["version"]) is int and value["version"] == 1 and value["kind"] == "mode-record"
              and type(text) is str and (ids is None) == (mode != "audit")
              and (ids is None or type(ids) is list and 1 <= len(ids) <= 8
                   and all(type(item) is str and 1 <= len(item) <= 256 for item in ids)),
              "mode record observation")
    record = c.loads(text.encode(), canonical=True, limit=32 * 1024)
    c.require(type(record) is dict and record.get("mode") == record.get("phase") == mode
              and record.get("owner_sha256") == owner_sha256 and record.get("activation_sha256") == activation_sha256,
              "mode record binding")
    return {"record": text.encode()} | ({} if ids is None else {"audit-event-ids": c.canonical(ids)})


MODE_READBACK_KEYS = {"unit": ("state_machine", "task_definitions.unit"),
                      **{mode: ("state_machine", f"schedules.{mode}", f"task_definitions.{mode}", f"alarms.{mode}")
                         for mode in ("recovery", "audit")}}
_MACHINE = re.compile(r"arn:aws:states:[a-z0-9-]+:[0-9]{12}:stateMachine:[A-Za-z0-9_-]{1,80}")
_REVISION = re.compile(r"arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:task-definition/[A-Za-z0-9_-]{1,255}:[1-9][0-9]{0,9}")
_SCHEDULE = re.compile(r"arn:aws:scheduler:[a-z0-9-]+:[0-9]{12}:schedule/([0-9A-Za-z_.-]{1,64})/([0-9A-Za-z_.-]{1,64})")
_ALARM = re.compile(r"arn:aws:cloudwatch:[a-z0-9-]+:[0-9]{12}:alarm:([A-Za-z0-9_.-]{1,255})")


def _target(pattern, resources, field, key=None):
    value = resources.get(field) if type(resources) is dict else None
    if key is not None:
        value = value.get(key) if type(value) is dict else None
    match = pattern.fullmatch(value) if type(value) is str else None
    c.require(match is not None, "mode readback target")
    return match


def mode_readback_calls(mode, resources):
    """The closed reads of the mode key set (design 4.4), with targets from the admitted mode-input resources.

    Returns: [{key, service, operation, parameters}] in key-set order. Raises: ValueError before any read.
    """
    c.require(mode in MODE_READBACK_KEYS, "mode readback target")
    calls = [{"key": "state_machine", "service": "stepfunctions", "operation": "describe_state_machine",
              "parameters": {"stateMachineArn": _target(_MACHINE, resources, "machine_arn").group(0)}}]
    if mode != "unit":
        group, name = _target(_SCHEDULE, resources, "schedule_arns", mode).groups()
        calls.append({"key": f"schedules.{mode}", "service": "scheduler", "operation": "get_schedule",
                      "parameters": {"Name": name, "GroupName": group}})
    calls.append({"key": f"task_definitions.{mode}", "service": "ecs", "operation": "describe_task_definition",
                  "parameters": {"taskDefinition": _target(_REVISION, resources, "revisions", mode).group(0)}})
    if mode != "unit":
        alarm = _target(_ALARM, resources, "alarm_arns", f"{mode}_repeated_failure").group(1)
        calls.append({"key": f"alarms.{mode}", "service": "cloudwatch", "operation": "describe_alarms",
                      "parameters": {"AlarmNames": [alarm]}})
    return calls


def _pick(node, fields, required=()):
    c.require(type(node) is dict and all(key in node for key in required), "mode readback shape")
    return {key: node[key] for key in fields if key in node}


def _project_machine(response, _):
    machine = _pick(response, ("stateMachineArn", "definition"), ("stateMachineArn", "definition"))
    c.require(all(type(value) is str for value in machine.values()), "mode readback shape")
    return machine


def _project_schedule(response, _):
    target = _pick(response, ("Target",), ("Target",))["Target"]
    projected = _pick(target, ("Arn", "RetryPolicy", "EcsParameters"), ("Arn", "RetryPolicy", "EcsParameters"))
    ecs = projected["EcsParameters"]
    parameters = _pick(ecs, ("TaskDefinitionArn", "TaskCount", "LaunchType", "PlatformVersion"), ("TaskDefinitionArn",))
    network = _pick(ecs, ("NetworkConfiguration",), ("NetworkConfiguration",))["NetworkConfiguration"]
    vpc = _pick(network, ("awsvpcConfiguration",), ("awsvpcConfiguration",))["awsvpcConfiguration"]
    parameters["NetworkConfiguration"] = {"awsvpcConfiguration": _pick(vpc, ("Subnets", "SecurityGroups", "AssignPublicIp"))}
    retry = _pick(projected["RetryPolicy"], ("MaximumRetryAttempts", "MaximumEventAgeInSeconds"))
    return {"Target": {"Arn": projected["Arn"], "RetryPolicy": retry, "EcsParameters": parameters}}


def _project_task_definition(response, _):
    definition = _pick(response, ("taskDefinition",), ("taskDefinition",))["taskDefinition"]
    projected = _pick(definition, ("taskDefinitionArn", "taskRoleArn", "containerDefinitions"),
                      ("taskDefinitionArn", "containerDefinitions"))
    containers = projected["containerDefinitions"]
    c.require(type(containers) is list and 1 <= len(containers) <= 16, "mode readback shape")
    projected["containerDefinitions"] = [_pick(item, ("name", "command"), ("name",)) for item in containers]
    return {"taskDefinition": projected}


def _project_alarm(response, parameters):
    alarms = _pick(response, ("MetricAlarms",), ("MetricAlarms",))["MetricAlarms"]
    c.require(type(alarms) is list and len(alarms) == 1 and type(alarms[0]) is dict
              and [alarms[0].get("AlarmName")] == parameters["AlarmNames"], "mode readback shape")
    alarm = _pick(alarms[0], ("AlarmName", "Dimensions", "EvaluationPeriods", "DatapointsToAlarm", "ActionsEnabled",
                              "AlarmActions"))
    if "Dimensions" in alarm:
        c.require(type(alarm["Dimensions"]) is list and len(alarm["Dimensions"]) <= 30, "mode readback shape")
        alarm["Dimensions"] = [_pick(item, ("Name", "Value")) for item in alarm["Dimensions"]]
    return alarm


_PROJECTIONS = {"state_machine": _project_machine, "schedules": _project_schedule,
                "task_definitions": _project_task_definition, "alarms": _project_alarm}


def _integral(value):
    if type(value) is float:
        raise ValueError("mode readback non-integer")
    for item in value.values() if type(value) is dict else value if type(value) is list else ():
        _integral(item)


def mode_readback_bytes(mode, resources, responses):
    """ModeReadback document (design 4.4): only the fields the product reads, present keys only, volatile fields out.

    Args: mode, admitted mode-input resources, raw SDK response by key. Returns: canonical bytes. Raises: ValueError.
    """
    calls = mode_readback_calls(mode, resources)
    c.require(type(responses) is dict and set(responses) == set(MODE_READBACK_KEYS[mode]), "mode readback key set")
    document = {}
    for call in calls:
        family, _, member = call["key"].partition(".")
        projected = _PROJECTIONS[family](responses[call["key"]], call["parameters"])
        _integral(projected)
        if member:
            document.setdefault(family, {})[member] = projected
        else:
            document[family] = projected
    return c.canonical(document)


_SUBNET = re.compile(r"subnet-[0-9a-f]{8,17}")
_SECURITY_GROUP = re.compile(r"sg-[0-9a-f]{8,17}")
_CLUSTER = re.compile(r"arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:cluster/[A-Za-z0-9_-]{1,255}")


def mode_network_input(resources):
    """Design 2 origin (a): the `network` input of recovery-observe and audit-observe from the mode-input resources.

    Returns: canonical {cluster, sorted subnets, security_group, public_ip, platform}. Raises: ValueError.
    """
    network, cluster = resources.get("network"), resources.get("cluster_arn")
    subnets = network.get("public_subnet_ids") if type(network) is dict else None
    group = network.get("security_group_id") if type(network) is dict else None
    c.require(type(network) is dict and set(network) == {"public_subnet_ids", "security_group_id"}
              and type(subnets) is list and 1 <= len(subnets) <= 16 and len(set(map(str, subnets))) == len(subnets)
              and all(type(item) is str and _SUBNET.fullmatch(item) is not None for item in subnets)
              and type(group) is str and _SECURITY_GROUP.fullmatch(group) is not None
              and type(cluster) is str and _CLUSTER.fullmatch(cluster) is not None, "mode network input")
    return c.canonical({"cluster": cluster, "subnets": sorted(subnets), "security_group": group, "public_ip": "ENABLED",
                        "platform": "1.4.0"})


MODE_WAIT_RESERVE = 30
MODE_WAIT_INTERVAL = 5


def mode_wait(poll, *, terminal, child_deadline, clock, sleep):
    """Design 4.1 bounded native wait (ruling 2 item 4): every 5 s until terminal or wait_end = kill - R, R = 30 s.

    Args: poll() -> receipted response, terminal(response), the child kill instant, clock, sleep.
    Returns: (final response only, C4 timing). Raises: ValueError mode wait elapsed, before any poll.
    """
    end = child_deadline - MODE_WAIT_RESERVE
    started = clock()
    c.require(started < end, "mode wait elapsed")
    polls = 0
    while True:
        response = poll()
        polls, now = polls + 1, clock()
        done = bool(terminal(response))
        if done or now + MODE_WAIT_INTERVAL > end:
            return response, {"kind": "wait", "started_at": started, "ended_at": now, "wait_end": end, "polls": polls,
                              "terminal": done}
        sleep(MODE_WAIT_INTERVAL)


MODE_RUN_TASK_ROUTES = {"recovery": {"locator": "PROD_CANARY_BINDING", "command": ["recover-once"]},
                        "audit": {"locator": "PROD_CANARY_AUDIT_OBSERVE", "command": ["dispatch-outbox-once"]}}
_TOKEN = re.compile(r"mc-[0-9a-f]{60}")
_LOCATOR_LIMIT = 4096


def _route_network(ecs):
    vpc = ecs["NetworkConfiguration"]["awsvpcConfiguration"]
    return {"awsvpcConfiguration": {"subnets": vpc["Subnets"], "securityGroups": vpc["SecurityGroups"],
                                    "assignPublicIp": vpc["AssignPublicIp"]}}


def _mode_route(mode, readbacks, record, resources):
    c.require(mode in MODE_RUN_TASK_ROUTES, "mode run_task readbacks")
    target = readbacks["schedules"][mode]["Target"]
    ecs, definition = target["EcsParameters"], readbacks["task_definitions"][mode]["taskDefinition"]
    revision, containers = record["revisions"][mode], definition["containerDefinitions"]
    c.require(revision == resources["revisions"][mode] == ecs["TaskDefinitionArn"] == definition["taskDefinitionArn"]
              and ecs.get("TaskCount", 1) == 1 and target["RetryPolicy"]["MaximumRetryAttempts"] == 0
              and target["Arn"] == resources["cluster_arn"] and type(containers) is list and len(containers) == 1
              and containers[0].get("command") == MODE_RUN_TASK_ROUTES[mode]["command"], "mode run_task readbacks")
    launch = {name: ecs[key] for key, name in (("LaunchType", "launchType"), ("PlatformVersion", "platformVersion"))
              if key in ecs}
    route = {"cluster": target["Arn"], "taskDefinition": revision, "count": 1, "enableExecuteCommand": False,
             "networkConfiguration": _route_network(ecs)} | launch
    return route, containers[0]["name"]


def _run_task_locator(parameters):
    try:
        (override,) = parameters["overrides"]["containerOverrides"]
        (entry,) = override["environment"]
        value = entry["value"]
    except (KeyError, TypeError, ValueError):
        return None
    return value if type(value) is str and 1 <= len(value.encode()) <= _LOCATOR_LIMIT else None


def validate_mode_run_task(mode, parameters, *, readbacks, record, resources):
    """Design 4.1: the RunTask is the product run_task_request over the route re-derived from the projected readbacks.

    Args: mode, RunTask parameters, projected readbacks document, record mapping, mode-input resources.
    Raises: ValueError mode run_task readbacks (route outside the product target) or mode run_task route.
    """
    try:
        route, container = _mode_route(mode, readbacks, record, resources)
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise ValueError("mode run_task readbacks") from error
    locator, token = _run_task_locator(parameters), parameters.get("clientToken") if type(parameters) is dict else None
    environment = [{"name": MODE_RUN_TASK_ROUTES[mode]["locator"], "value": locator}]
    expected = route | {"overrides": {"containerOverrides": [{"name": container, "environment": environment}]},
                        "clientToken": token}
    c.require(locator is not None and type(token) is str and _TOKEN.fullmatch(token) is not None
              and c.canonical(parameters) == c.canonical(expected), "mode run_task route")


def validate_mode_describe_tasks(parameters, *, cluster_arn, launched):
    """Design 4.1: DescribeTasks only for the task this operation's RunTask returned. Raises: ValueError."""
    tasks = parameters.get("tasks") if type(parameters) is dict else None
    c.require(type(parameters) is dict and set(parameters) == {"cluster", "tasks"} and parameters["cluster"] == cluster_arn
              and type(tasks) is list and len(tasks) == 1 and type(tasks[0]) is str and tasks[0] in launched,
              "mode describe_tasks own task")


MODE_KEEPER_ORIGINS = {"mode-start": None, "previous": None, "mode-seed": "audit", "recovery-readbacks": "audit-observe"}


def _lease_original(keeper, operation, kind, label):
    journals = _operation_journals(keeper, operation)
    c.require(len(journals) == 1, label)
    if kind is None:
        return journals[0]._inputs["readbacks"]
    found = [entry for entry in journals[0]._observations if entry["kind"] == kind]
    c.require(len(found) == 1, label)
    return journals[0]._observation_bytes[found[0]["sha256"]]


def mode_input_source(*, keeper, owner, window, operation, names):
    """Mode originals the keeper derives itself (design 2): (k) mode-start and previous null; (s) the audit mode-seed
    and recovery-readbacks from this lease's recovery journals. Any other origin is not connected and refuses first.

    Returns: {name: bytes}. Raises: ValueError.
    """
    mode = operation.partition("-")[0]
    c.require(all(name in MODE_KEEPER_ORIGINS and MODE_KEEPER_ORIGINS[name] in (None, mode, operation) for name in names),
              "mode_inputs=source_unconnected")
    inputs = {}
    for name in names:
        if name == "mode-start":
            inputs[name] = c.canonical({"version": 1, "kind": "mode-start", "frozen": mode == "audit",
                                        "started_at": c.utc(window["admitted_at"])})
        elif name == "previous":
            c.require(not _operation_journals(keeper, operation), "mode reentry unavailable")
            inputs[name] = c.canonical(None)
        elif name == "mode-seed":
            inputs[name] = _lease_original(keeper, "recovery-seed", "mode-seed", "mode-seed original")
        else:
            inputs[name] = _lease_original(keeper, "recovery-start", None, "recovery-readbacks original")
    return inputs


class ModeBroker:
    """Finite private SDK dispatcher of one mode seed/start operation, on its own derived mc-* session.

    The read session serves mode_readbacks and the unit outputs; any unknown native outcome poisons, never retries.
    """

    @property
    def uncertainty(self):
        return [item for ledger in self.evidence for item in ledger.uncertainty]


class FenceReadBroker(ClosedReadyBroker):
    """Finite private dispatcher of the observe operations: strong FENCE/SEMAPHORE GetItem on the observe fence session.

    The ClosedReadyBroker reservation, durable evidence and poison rules; lc.validate_fence_call admits only those reads.
    """


def fence_observe_capability(*, governance, authority, journal, keeper, prepared, credential_limit, operation_session,
                             clock=time.time):
    """Observe capability (design 3.2): the authenticated PreparedFence role and recomputed scope, the local
    operation-session effective IAM, the observe fence STS and a FenceReadBroker attached to the keeper.

    Every check precedes STS; a refusal poisons the journal, keeps the lease held and mints no credential.
    Returns: FenceReadBroker. Raises: ValueError.
    """
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    c.require(type(journal) is AdapterJournal and type(keeper) is Keeper and type(prepared) is lr.PreparedFence,
              "mode observe original journal/keeper/prepared authority")
    c.require(journal._request["operation"] in lc.MODE_OBSERVES and getattr(journal, "_broker", None) is None,
              "mode observe capability only")
    try:
        keeper.lease.check()
        owner = journal._request["owner"] | journal._identity
        manifest = c.loads(prepared["fence-prepared.json"], canonical=True)
        role = c.loads(prepared["fence-role.json"], canonical=True)
        evaluation = c.loads(prepared["fence-evaluation.json"], canonical=True)
        c.require(manifest["activation_sha256"] == journal._request["activation_sha256"] == c.sha(journal._inputs["activation"]),
                  "prepared/request/input activation_sha256")
        c.require(role["role_arn"] == governance["application_delegations"]["fence_operator"], "fence_operator delegation")
        c.require(c.canonical(manifest["owner"]) == c.canonical(owner), "prepared current owner")
        cases = {case["case_id"]: case for case in evaluation["cases"]}
        derived = lr.fence_policy_scope(governance, role["policy"])
        c.require(cases["get-fence"]["resource"] == derived["control_table_arn"]
                  and cases["probe-own"]["resource"] == derived["execution_prefix"] + "0" * 16,
                  "capability scope recomputed from prepared policy")
        scope = {"account": governance["account_id"], "control_table_arn": derived["control_table_arn"],
                 "machine_arn": derived["machine_arn"]}
        _fence_operation_iam(governance, authority, journal, role, clock)
        journal.guard()
        prepared_sha256 = c.sha(prepared["fence-prepared.json"])
        session = _assume_fence_session(governance=governance, role=role, scope=scope, journal=journal,
                                        prepared_sha256=prepared_sha256, credential_limit=credential_limit,
                                        operation_session=operation_session, clock=clock)
        broker = FenceReadBroker(session.evidence, governance, journal, session, prepared_sha256=prepared_sha256, clock=clock)
        keeper.attach(broker)
        return broker
    except BaseException:
        journal._failed = True
        keeper.attach(journal)
        raise
