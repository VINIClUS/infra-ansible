"""Mode SDK broker, fence-read broker and mode readbacks of the promotion mode stages (P16b)."""
import base64
import binascii
import datetime
import importlib.util
import json
import pathlib
import re
import sys
import time
from collections import namedtuple

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.application_gate import (AdapterJournal, ClosedReadyBroker, ClosedReadyEvidence, Keeper,
                                                      _assume_fence_session, _fence_operation_iam, _operation_journals,
                                                      _poison_call)

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
     "35cd96e6362a53c835369f0683e8eaec8b3eb9d3ea134f02e1689437df08cf33"),
    ("cnes_infra.aws.mode_canary_dispatch", "product_mode_canary_dispatch.py",
     "5952a2c4afd66872d82efcdf15efb3937e5227df9ad8d05734698dd64c63793c"))
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
    modules = {}
    try:
        for name, origin, raw in verified:
            module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None, origin=origin))
            sys.modules[name] = modules[name] = module
            exec(compile(raw, origin, "exec"), module.__dict__)
        return modules
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


def _product_module(name):
    if "modules" not in _PRODUCT:
        _PRODUCT["modules"] = _load_product_frames(pathlib.Path(__file__).resolve().parent)
    return _PRODUCT["modules"][name]


def product_frames():
    """C2 vendored product ledger builders (ruling 3): the pinned product bytes, run under their product module names.

    Returns: the cnes_infra.aws.mode_canary_frames module. Raises: ValueError on any byte drift, before executing.
    """
    return _product_module("cnes_infra.aws.mode_canary_frames")


def product_dispatch():
    """Vendored product unit-start builders (P16c addendum 3), loaded with the frames from the same verified bytes.

    Returns: the cnes_infra.aws.mode_canary_dispatch module. Raises: ValueError on any byte drift, before executing.
    """
    return _product_module("cnes_infra.aws.mode_canary_dispatch")


UNIT_LEASE_SECONDS = 3600
UnitLocator = namedtuple("UnitLocator", "tenant_id run_ids owner_sha256 record_sha256 phase context_kind")
UnitHolder = namedtuple("UnitHolder", "dispatch_id run_id tenant_id")
_PRODUCT_KEYS = "cnes_infra.control_plane.dynamodb_keys"


def _unit_requests(start):
    dispatch, keys = product_dispatch(), _product_module(_PRODUCT_KEYS)
    unit, permit, reference = start.dispatch, dispatch.StartPermit(1, 0), "execution"
    pk, sk = keys.run_entity_key(unit.tenant_id, unit.run_id)
    run_item = {"pk": {"S": pk}, "sk": {"S": sk}, "payload": {"S": '{"state":"PROCESSING"}'}}
    unit_items = [{"pk": {"S": key[0]}, "sk": {"S": key[1]}, "payload": {"S": "{}"}}
                  for key in (keys.unit_key(unit.tenant_id, unit.run_id, unit_id) for unit_id in unit.unit_ids)]

    def reads(step):
        return [("get_item", request) for request in dispatch.step_reads(start, step)]
    return (reads("reserve") + [("transact_write_items", dispatch.reserve_request(start, run_item, unit_items)),
                                ("transact_write_items", dispatch.acquire_request(start))]
            + reads("gate") + [("update_item", dispatch.attempt_request(start))] + reads("gate") + reads("claim")
            + [("transact_write_items", dispatch.claim_request(start, permit))] + reads("bind")
            + [("transact_write_items", dispatch.bind_request(start, permit, reference, run_item))]
            + [("update_item", request) for request in dispatch.confirm_requests(start, permit, reference)])


def unit_start_targets(locator, units, *, table, now):
    """Q1 (B2): the product unit-start of the stage over the keeper-written seed units at the stage clock, with its
    (IAM action, table, pk, sk) targets: request_targets of every keeper request, the dispatch-unit frame writes and the
    record, control and ticket reads. Keys never depend on read values.

    Returns: (UnitStart, effect_id, frozenset of targets). Raises: ValueError (product refusals included).
    """
    frames, dispatch = product_frames(), product_dispatch()
    c.require(type(locator) is UnitLocator and locator.phase == "unit", "mode unit locator")
    unit = dispatch.unit_dispatch(locator, units, now)
    start = dispatch.UnitStart(unit, table, now, UNIT_LEASE_SECONDS, locator.owner_sha256)
    holder = UnitHolder(unit.dispatch_id, unit.run_id, unit.tenant_id)
    effect = frames.effect_id(locator.record_sha256, "start-execution", frames.start_request(holder, unit.unit_ids))
    owner, tenant = locator.owner_sha256, frames.tenant_partition(unit.tenant_id)
    run = _product_module(_PRODUCT_KEYS).dispatch_key(unit.tenant_id, unit.run_id)[0]
    frame = {("GetItem", tenant, frames.record_key(owner, "unit")), ("GetItem", tenant, frames.control_key(owner)),
             ("GetItem", tenant, frames.ticket_key(owner, effect)), ("PutItem", tenant, frames.control_key(owner)),
             ("PutItem", tenant, frames.ticket_key(owner, effect)), ("PutItem", run, "PROD_CANARY#" + unit.dispatch_id)}
    targets = frozenset(dispatch.request_targets(_unit_requests(start)))
    return start, effect, targets | {(action, table, pk, sk) for action, pk, sk in frame}


def unit_start_grants(resources, owner_sha256):
    """Q1 ux LeadingKeys: the pk projection of unit_start_targets on the scope's unit run, independent of the unit ids,
    so the prepare and the stage derive the same session.

    Returns: {IAM action: frozenset of pks}. Raises: ValueError.
    """
    scope, run = resources["scope"], "unit-" + owner_sha256[:16]
    c.require(run in scope["run_ids"], "mode session runs")
    locator = UnitLocator(scope["tenant_id"], (run,), owner_sha256, "0" * 64, "unit", "promotion")
    probe = [{"tenant_id": scope["tenant_id"], "run_id": run, "unit_id": "0" * 32, "state": "PENDING", "lease_until": None,
              "depends_on_unit_ids": []}]
    epoch = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)
    grants = {}
    for action, _, pk, _ in unit_start_targets(locator, probe, table=resources["table_arn"].rsplit("/", 1)[1], now=epoch)[2]:
        grants.setdefault("dynamodb:" + action, set()).add(pk)
    return {action: frozenset(keys) for action, keys in grants.items()}


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
    return _readback_document(calls, {call["key"]: _readback_piece(call, responses[call["key"]]) for call in calls})


def _readback_piece(call, response):
    projected = _PROJECTIONS[call["key"].partition(".")[0]](response, call["parameters"])
    _integral(projected)
    return projected


def _readback_document(calls, pieces):
    document = {}
    for call in calls:
        family, _, member = call["key"].partition(".")
        if member:
            document.setdefault(family, {})[member] = pieces[call["key"]]
        else:
            document[family] = pieces[call["key"]]
    return c.canonical(document)


def mode_readback_request(owner, window, mode):
    """Ruling 5: the binding of one ModeReadback run, its <mode>-readbacks namespace, owner, caller and held checkpoint.

    Returns: the request mapping the session and every intent bind. Raises: ValueError outside the three modes.
    """
    c.require(mode in lc.MODE_READBACK_OPERATIONS, "mode readback original context")
    return {"operation": lc.MODE_READBACK_OPERATIONS[mode],
            "owner": {key: owner[key] for key in [*lc.OWNER_FIELDS, "owner_sha256"]},
            "caller": lc.application_identity(owner, required=True), "checkpoint_sha256": c.digest(window["checkpoint_sha256"]),
            "stage": {key: window[key] for key in lc.ADAPTER_STAGE_FIELDS.split()}}


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


MODE_KEEPER_ORIGINS = {"mode-start": None, "previous": None, "mode-seed": "audit", "recovery-readbacks": "audit-observe",
                       "phase-c": ("recovery-observe", "audit-observe"),
                       "readbacks": ("unit-start", "unit-observe", "recovery-start", "recovery-observe", "audit-start",
                                     "audit-observe")}


def _lease_original(keeper, operation, kind, label):
    journals = _operation_journals(keeper, operation)
    c.require(len(journals) == 1, label)
    if kind is None:
        return journals[0]._inputs["readbacks"]
    found = [entry for entry in journals[0]._observations if entry["kind"] == kind]
    c.require(len(found) == 1, label)
    return journals[0]._observation_bytes[found[0]["sha256"]]


def _origin_open(name, mode, operation):
    origin = MODE_KEEPER_ORIGINS.get(name, False)
    return operation in origin if type(origin) is tuple else origin in (None, mode, operation)


def _phase_c_original(keeper, mode):
    purposes = lc.PHASE_C_PURPOSES[:lc.PHASE_C_PURPOSES.index("phase-c-" + mode) + 1]
    elements = keeper.phase_c_elements
    c.require(type(elements) is dict and set(elements) == set(purposes), "phase-c original")
    return c.canonical([c.loads(elements[purpose]) for purpose in purposes])


def _readbacks_original(keeper, mode):
    found = [item for item in keeper._contexts if type(item) is ModeReadback and item.mode == mode]
    c.require(len(found) == 1, "readbacks original")
    return found[0].original()


def mode_input_source(*, keeper, owner, window, operation, names):
    """Mode originals the keeper derives itself (design 2): (k) mode-start and previous null; (s) the audit mode-seed
    and recovery-readbacks from this lease's recovery journals; phase-c, the list of this keeper's accepted phase-c
    elements in mode order (P17 ruling 6); readbacks, the handoff of this keeper's single ModeReadback of the mode
    (ruling 5). Any other origin is not connected and refuses first.

    Returns: {name: bytes}. Raises: ValueError.
    """
    mode = operation.partition("-")[0]
    c.require(all(_origin_open(name, mode, operation) for name in names), "mode_inputs=source_unconnected")
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
        elif name == "phase-c":
            inputs[name] = _phase_c_original(keeper, mode)
        elif name == "readbacks":
            inputs[name] = _readbacks_original(keeper, mode)
        else:
            inputs[name] = _lease_original(keeper, "recovery-start", None, "recovery-readbacks original")
    return inputs


ModeAuthority = namedtuple("ModeAuthority", "evaluation documents scope roles")
MODE_EFFECTS = ("unit-seed", "recovery-seed", "unit-start", "recovery-start", "audit-start")


class _ModeSession:
    """Shared-only result of the mc-* STS boundary of one mode effect operation; never exposed over IPC."""
    def __init__(self, client, commitment, scope, deadline, request_binding, evidence, *, code, alias):
        self.client, self.commitment = client, c.digest(commitment)
        self.scope = c.loads(c.canonical(scope), canonical=True)
        self.deadline, self.request_binding, self.evidence = deadline, request_binding, evidence
        self.code, self.alias = code, alias


_ModeTarget = namedtuple("_ModeTarget", "operation owner stage reserve guard")


def _journal_target(journal):
    request = journal._request
    return _ModeTarget(request["operation"], request["owner"], request["stage"], journal._guard.check, journal.guard)


def _mode_window(target, credential_limit, clock):
    stage = target.stage
    seconds = lc.governed_windows(stage["windows"])["stages"].get(stage["stage"])
    c.require({stage["stage"]} == lc.ADAPTER_STAGES[target.operation] and stage["close"] is not None
              and stage["decision"] is None and seconds is not None
              and stage["deadline"] == min(stage["fixed_deadline"], stage["admitted_at"] + seconds)
              and stage["admitted_at"] <= clock() and clock() + 40 < stage["deadline"]
              and clock() + 900 <= credential_limit, "mode session original stage/credential window")
    return stage


def _mode_role(governance, authority, code, alias):
    scope, entry = authority.scope, authority.roles.get(alias) if type(authority.roles) is dict else None
    role = entry["role"]["Role"] if type(entry) is dict else {}
    name = scope["session_names"][code]
    trust = role.get("AssumeRolePolicyDocument", {}).get("Statement", [{}])
    names = [item.get("Condition", {}).get("StringEquals", {}).get("sts:RoleSessionName") for item in trust]
    c.require(role.get("Arn") == scope["role_arns"][alias] == governance["application_delegations"].get(alias)
              and role.get("RoleName") == "cnesdata-prod-" + alias.replace("_", "-")
              and type(role.get("RoleId")) is str and bool(role["RoleId"])
              and c.canonical(entry["policy"]["PolicyDocument"]) == c.canonical(authority.documents["role." + alias])
              and len(names) == 1 and type(names[0]) is list and name in names[0], "mode session role readback")
    return {"role_arn": role["Arn"], "role_id": role["RoleId"], "session_name": name}


def _mode_application(governance, application, documents, target, role, clock):
    from tools.cnesdata_delivery import session_policy
    from tools.cnesdata_delivery.iam_boundary import effective_iam
    from tools.cnesdata_delivery.session_owner import application_identity_document
    owner, (code, alias) = target.owner, lc.MODE_SESSION_OPERATIONS[target.operation][:2]
    inline = c.loads(session_policy.application_request(governance, owner["source_sha"], owner["run_id"], owner["run_attempt"],
        target.operation, application_purpose="promotion", delegations=[alias],
        sessions={alias: role["session_name"]})["Policy"].encode())
    identity = application_identity_document(governance, application.application_fragment)
    c.require(all(c.canonical(value) == c.canonical(documents[name]) for name, value in (
        ("application_identity", identity), ("application_managed", application.pin["document"]),
        ("application_session." + code, inline))), "mode session application documents")
    now = {"aws:CurrentTime": c.utc(clock())}
    managed = [documents["application_managed"], documents["application_session." + code]]
    c.require(all(effective_iam(identity, managed, "sts:AssumeRole", role["role_arn"], now | {"sts:RoleSessionName": name})
                  is expected for name, expected in ((role["session_name"], True), (role["session_name"] + "-foreign", False))),
              "mode session operation effective IAM")


def _mode_sts(governance, target, role, policy, *, deadline, credential_limit, operation_session, clock):
    from tools.cnesdata_delivery.aws_boundary import AWS
    from tools.cnesdata_delivery.session_policy import validate_response
    alias = lc.MODE_SESSION_OPERATIONS[target.operation][1]
    target.reserve(40)
    target.guard()
    operation = operation_session(target.operation, role, target.stage)
    c.require(clock() + 40 < deadline and clock() + 900 <= credential_limit, "mode original window after operation session")
    response = operation.call("sts", "assume_role", RoleArn=role["role_arn"], RoleSessionName=role["session_name"],
                              DurationSeconds=900, Policy=policy)
    credentials = validate_response(response)
    expiry = credentials["Expiration"]
    c.require(getattr(expiry, "tzinfo", None) is not None and clock() + 140 < expiry.timestamp()
              <= min(credential_limit, clock() + 900), "mode STS expiration")
    c.require(all(type(credentials[field]) is str and credentials[field] and "\n" not in credentials[field]
                  and "\r" not in credentials[field] for field in ("AccessKeyId", "SecretAccessKey", "SessionToken")),
              "mode temporary credential shape")
    target.guard()
    client = AWS(governance | {"role": alias, "roles": {alias: role["role_arn"]}}, credentials=credentials)
    expected_arn = (role["role_arn"].replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/"
                    + role["session_name"])
    expected_id = role["role_id"] + ":" + role["session_name"]
    c.require(client.identity["Account"] == governance["account_id"] and client.identity["Arn"] == expected_arn
              and client.identity["UserId"] == expected_id
              and response["AssumedRoleUser"] == {"Arn": expected_arn, "AssumedRoleId": expected_id},
              "mode exact native role ID/session/account")
    target.guard()
    c.require(clock() + 20 < deadline, "mode STS completed in original window")
    return client, operation, expiry, expected_arn, expected_id


def assume_mode_session(*, governance, application, authority, journal, credential_limit, operation_session, clock=time.time):
    """The mc-* session of one mode effect operation on prepared authority (design 4.5): stage recompute of the
    mode-evaluation, role readback, application documents and local effective IAM, all before STS.

    Args: application is the authenticated application authority; authority the ModeAuthority of the stage.
    Returns: _ModeSession. Raises: ValueError, minting no credential on any refusal before STS.
    """
    c.require(type(journal) is AdapterJournal and journal._request["operation"] in MODE_EFFECTS
              and journal._identity["application_purpose"] == "promotion" and type(authority) is ModeAuthority,
              "mode session original operation")
    return _mode_assume(governance, application, authority, (_journal_target(journal), c.sha(c.canonical(journal._request))),
                        credential_limit=credential_limit, operation_session=operation_session, clock=clock)


def assume_readback_session(*, governance, application, authority, guard, mode, credential_limit, operation_session,
                            clock=time.time):
    """Ruling 5: the mode_observe session of one mode on the same prepared authority as assume_mode_session, bound to
    the <mode>-readbacks request of the held keeper window, that ModeReadback and the mode-readbacks frame admit.

    Args: guard is the KeeperGuard of the held lease; mode one of unit, recovery, audit.
    Returns: _ModeSession. Raises: ValueError, minting no credential on any refusal before STS.
    """
    from tools.cnesdata_delivery.application_gate import KeeperGuard
    keeper = guard.keeper if type(guard) is KeeperGuard else None
    record = keeper.lease.check() if type(keeper) is Keeper else None
    c.require(record is not None and type(authority) is ModeAuthority, "mode readback original context")
    request = mode_readback_request(lc.owner_binding(record), record["lifecycle"], mode)
    c.require(request["caller"]["application_purpose"] == "promotion", "mode readback original context")
    target = _ModeTarget(mode + "-observe", request["owner"], request["stage"], guard.check, guard.check)
    return _mode_assume(governance, application, authority, (target, c.sha(c.canonical(request))),
                        credential_limit=credential_limit, operation_session=operation_session, clock=clock)


def assume_unit_start_sessions(*, governance, application, authority, journal, credential_limit, operation_session,
                               clock=time.time):
    """Ruling 7 item 1: the ux session of unit-start and its wait part uw, on the same role and session name, with every
    pre-STS check of both parts before the first STS and both minted before any dispatch write.

    Returns: (ux _ModeSession, uw _ModeSession). Raises: ValueError, minting no credential on any refusal before STS.
    """
    c.require(type(journal) is AdapterJournal and journal._request["operation"] == "unit-start"
              and journal._identity["application_purpose"] == "promotion" and type(authority) is ModeAuthority,
              "mode unit sessions original operation")
    bound = (_journal_target(journal), c.sha(c.canonical(journal._request)))
    plans = [_mode_plan(governance, application, authority, bound, part, credential_limit=credential_limit, clock=clock)
             for part in (None, "uw")]
    return tuple(_mode_mint(governance, plan, credential_limit=credential_limit, operation_session=operation_session,
                            clock=clock) for plan in plans)


def _mode_assume(governance, application, authority, bound, *, credential_limit, operation_session, clock):
    plan = _mode_plan(governance, application, authority, bound, None, credential_limit=credential_limit, clock=clock)
    return _mode_mint(governance, plan, credential_limit=credential_limit, operation_session=operation_session, clock=clock)


_ModePlan = namedtuple("_ModePlan", "target binding code alias role policy deadline evaluation scope")


def _mode_plan(governance, application, authority, bound, part, *, credential_limit, clock):
    from tools.cnesdata_delivery.iam_boundary import mode_session_document, mode_stage_evaluation
    target, binding = bound
    session_code, alias = lc.MODE_SESSION_OPERATIONS[target.operation][:2]
    code = part or session_code
    c.require(part is None or lc.MODE_SESSION_PARTS.get(part) == session_code, "mode session part")
    stage = _mode_window(target, credential_limit, clock)
    scope = authority.scope
    c.require(type(scope) is dict and scope.get("owner_sha256") == target.owner["owner_sha256"], "mode session original owner")
    names = {"application_identity", "application_managed", "application_session." + session_code, "session." + code,
             "role." + alias}
    documents = {name: authority.documents[name] for name in names if name in authority.documents}
    mode_stage_evaluation(authority.evaluation, documents, scope, code=code)
    role = _mode_role(governance, authority, session_code, alias)
    _mode_application(governance, application, documents, target, role, clock)
    policy = mode_session_document(code, target.operation, scope)
    c.require(len(c.canonical(policy).decode().strip()) <= 2048, "mode STS policy limit")
    deadline = min(stage["deadline"], scope["deadline"])
    c.require(clock() + 40 < deadline, "mode session original stage/credential window")
    return _ModePlan(target, binding, code, alias, role, policy, deadline, authority.evaluation, scope)


def _mode_mint(governance, plan, *, credential_limit, operation_session, clock):
    role, policy, deadline = plan.role, plan.policy, plan.deadline
    c.require(clock() + 40 < deadline, "mode session original stage/credential window")
    client, operation, expiry, arn, user_id = _mode_sts(governance, plan.target, role, c.canonical(policy).decode().strip(),
        deadline=deadline, credential_limit=credential_limit, operation_session=operation_session, clock=clock)
    commitment = c.sha(c.canonical({"evaluation_sha256": c.sha(c.canonical(plan.evaluation)), "request_sha256": plan.binding,
        "role_arn": role["role_arn"], "role_id": role["role_id"], "session_name": role["session_name"],
        "policy_sha256": c.sha(c.canonical(policy)), "expires_at": c.utc(expiry.timestamp()),
        "account": governance["account_id"], "arn": arn, "user_id": user_id}))
    return _ModeSession(client, commitment, plan.scope, deadline, plan.binding, operation, code=plan.code, alias=plan.alias)


_MODE_BODY_LIMIT = 256 * 1024


def _mode_call_scope(governance, journal, session):
    from tools.cnesdata_delivery.session_policy import MODE_SEED_RUN_PREFIXES
    resources, operation = session.scope["resources"], journal._request["operation"]
    owner, phase = journal._request["owner"]["owner_sha256"], lc.MODE_SESSION_OPERATIONS[operation][3]
    names = {f"{prefix}-{owner[:16]}" for prefix in MODE_SEED_RUN_PREFIXES.get(phase, ())}
    binding = {"canary_id": resources["scope"]["tenant_id"].removeprefix("prod-canary-"), "owner_sha256": owner,
               "run_ids": [run for run in resources["scope"]["run_ids"] if run in names], "dispatch_id": None}
    started = operation in ("recovery-start", "audit-start")
    return {"account": governance["account_id"], "table": resources["table_arn"].rsplit("/", 1)[1],
            "bucket": resources["data_bucket_arn"].removeprefix("arn:aws:s3:::"),
            "raw_keys": list(resources["scope"]["raw_object_keys"]), "resources": resources,
            "binding": binding if operation.endswith("-seed") else None,
            "readbacks": c.loads(journal._inputs["readbacks"], canonical=True) if started else None,
            "record": json.loads(journal._inputs["record"]) if started else None, "launches": 0, "launched": []}


def _mode_dynamodb_call(operation, name, parameters, scope):
    put = name == "put_item"
    fields = {"TableName", "Item", "ConditionExpression"} if put else {"TableName", "Key", "ConsistentRead"}
    c.require(type(parameters) is dict and set(parameters) == fields and parameters["TableName"] == scope["table"]
              and (parameters["ConditionExpression"] == "attribute_not_exists(pk)" if put else parameters["ConsistentRead"] is True),
              "mode dynamodb call")
    item = parameters["Item"] if put else parameters["Key"]
    c.require(type(item) is dict and (put or set(item) == {"pk", "sk"})
              and all(type(item.get(part)) is dict and set(item[part]) == {"S"} and type(item[part]["S"]) is str
                      for part in ("pk", "sk")), "mode dynamodb call")
    admit_mode_key(operation, "put" if put else "get", (item["pk"]["S"], item["sk"]["S"]), binding=scope["binding"])
    return parameters


def _mode_s3_call(name, parameters, scope):
    put = name == "put_object"
    body = parameters.get("Body") if type(parameters) is dict else None
    c.require(type(parameters) is dict and set(parameters) == ({"Bucket", "Key", "Body", "IfNoneMatch"} if put else {"Bucket", "Key"})
              and parameters["Bucket"] == scope["bucket"] and type(parameters["Key"]) is str and parameters["Key"] in scope["raw_keys"]
              and (not put or parameters["IfNoneMatch"] == "*" and type(body) is dict and set(body) == {"bytes"}
                   and type(body["bytes"]) is str), "mode s3 call")
    if not put:
        return parameters
    try:
        raw = base64.b64decode(body["bytes"], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("mode s3 call") from error
    c.require(len(raw) <= _MODE_BODY_LIMIT, "mode s3 call")
    return parameters | {"Body": raw}


def validate_mode_call(operation, native, scope):
    """Design 4.1 closed table: alias, MODE_EFFECT_CALLS[operation], then the per-service validator.

    Returns: the native SDK parameters (wire bytes decoded). Raises: ValueError before any SDK call.
    """
    c.closed(native, "role service operation parameters")
    role, service, name, parameters = (native[key] for key in ("role", "service", "operation", "parameters"))
    c.require(role == lc.MODE_SESSION_OPERATIONS[operation][1], "mode call alias")
    c.require((role, service, name) in lc.MODE_EFFECT_CALLS[operation], "mode call outside table")
    if service == "dynamodb":
        return _mode_dynamodb_call(operation, name, parameters, scope)
    if service == "s3":
        return _mode_s3_call(name, parameters, scope)
    return _mode_ecs_call(operation, name, parameters, scope)


def _mode_ecs_call(operation, name, parameters, scope):
    if name == "run_task":
        c.require(scope["launches"] == 0, "mode run_task once")
        validate_mode_run_task(lc.MODE_SESSION_OPERATIONS[operation][3], parameters, readbacks=scope["readbacks"],
                               record=scope["record"], resources=scope["resources"])
    else:
        validate_mode_describe_tasks(parameters, cluster_arn=scope["resources"]["cluster_arn"], launched=scope["launched"])
    return parameters


def validate_mode_frame_call(operation, frame, native, scope):
    """Design 4.2: a native call of the active keeper ledger frame, its keys inside the C1 set of that frame.

    Returns: the native SDK parameters. Raises: ValueError before any SDK call.
    """
    c.closed(native, "role service operation parameters")
    role, service, name, parameters = (native[key] for key in ("role", "service", "operation", "parameters"))
    c.require(frame is not None and (role, service, name) in lc.MODE_FRAME_CALLS.get(operation, ()), "mode frame call outside table")
    if name != "get_item":
        for key in _ledger_keys(scope["table"], name, parameters):
            admit_mode_key(frame["name"], "put", key, binding=frame["binding"])
        return parameters
    key = parameters.get("Key") if type(parameters) is dict else None
    c.require(type(parameters) is dict and set(parameters) == {"TableName", "Key", "ConsistentRead"}
              and parameters["TableName"] == scope["table"] and parameters["ConsistentRead"] is True
              and type(key) is dict and set(key) == {"pk", "sk"}
              and all(type(key[part]) is dict and set(key[part]) == {"S"} and type(key[part]["S"]) is str for part in key),
              "mode dynamodb call")
    admit_mode_key(frame["name"], "get", (key["pk"]["S"], key["sk"]["S"]), binding=frame["binding"])
    return parameters


def validate_mode_read_call(operation, native, resources):
    """Design 4.2 mode-readbacks: one read of the ModeReadback key set of the start operation, on the observe alias.

    Returns: the native SDK parameters. Raises: ValueError before any SDK call.
    """
    c.closed(native, "role service operation parameters")
    calls = (mode_readback_calls(lc.MODE_SESSION_OPERATIONS[operation][3], resources)
             if operation in lc.MODE_READBACK_FRAME_CALLS else [])
    c.require(native["role"] == "mode_observe"
              and any(c.canonical([call["service"], call["operation"], call["parameters"]])
                      == c.canonical([native["service"], native["operation"], native["parameters"]]) for call in calls),
              "mode read call outside table")
    return native["parameters"]


class ModeEvidence(ClosedReadyEvidence):
    """ClosedReadyEvidence over one mode effect call, re-validated against the ModeBroker call scope."""
    @staticmethod
    def _native(journal, native_raw, scope, governance):
        c.require(scope["account"] == governance["account_id"], "original mode journal account")
        native = c.loads(native_raw, canonical=True, limit=128 * 1024)
        if scope.get("frame") is not None:
            validate_mode_frame_call(journal._request["operation"], scope["frame"], native, scope)
        elif scope.get("reads") is not None:
            validate_mode_read_call(journal._request["operation"], native, scope["reads"])
        else:
            validate_mode_call(journal._request["operation"], native, scope)
        return native


_LEDGER_FRAME_FIELDS = {"ledger-admit": "kind effect_kind request_sha256 target_sha256 admitted_at",
                        "ledger-unknown": "kind effect_id", "ledger-settle": "kind effect_id receipt_sha256"}
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _ledger_frame(value, clock):
    fields = set(_LEDGER_FRAME_FIELDS[value["kind"]].split())
    digests = [value[name] for name in ("request_sha256", "target_sha256", "effect_id", "receipt_sha256") if name in value]
    admitted = value.get("admitted_at")
    c.require(set(value) == fields and all(type(item) is str and _HEX64.fullmatch(item) is not None for item in digests)
              and (value["kind"] != "ledger-admit" or type(value["effect_kind"]) is str and type(admitted) is str
                   and _STAMP.fullmatch(admitted) is not None and abs(c.instant(admitted) - clock()) <= 5),
              "mode ledger frame")
    return admitted


def _mode_reply(value):
    if "Error" in value:
        return {"kind": "sdk-error", "code": value["Error"]["Code"]}
    return {"kind": "sdk-result", "value": value}


def _mode_body(stream):
    chunks, size = [], 0
    while size <= _MODE_BODY_LIMIT:
        chunk = stream.read(_MODE_BODY_LIMIT + 1 - size)
        c.require(type(chunk) is bytes, "mode S3 Body stream bytes")
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    c.require(size <= _MODE_BODY_LIMIT, "mode S3 Body bound")
    return base64.b64encode(b"".join(chunks)).decode()


_MODE_TASK_FIELDS = ("taskArn", "taskDefinitionArn", "lastStatus", "stopCode")
_MODE_CONTAINER_FIELDS = ("name", "exitCode", "lastStatus")
_MODE_FAILURE_FIELDS = ("arn", "reason", "detail")


def _mode_ecs_response(response):
    tasks, failures = response.get("tasks", []), response.get("failures", [])
    c.require(set(response) <= {"tasks", "failures", "ResponseMetadata"} and type(tasks) is list and len(tasks) <= 1
              and type(failures) is list and len(failures) <= 8
              and all(type(item) is dict for item in tasks + failures)
              and all(type(task.get("containers", [])) is list and len(task.get("containers", [])) <= 10
                      and all(type(item) is dict for item in task.get("containers", [])) for task in tasks),
              "finite native ECS response")
    projected = []
    for task in tasks:
        item = {key: task[key] for key in _MODE_TASK_FIELDS if key in task}
        if "containers" in task:
            item["containers"] = [{key: entry[key] for key in _MODE_CONTAINER_FIELDS if key in entry}
                                  for entry in task["containers"]]
        projected.append(item)
    return {"tasks": projected, "failures": [{key: item[key] for key in _MODE_FAILURE_FIELDS if key in item}
                                             for item in failures]}


def _mode_task_terminal(reply):
    tasks = reply["value"]["tasks"]
    return not (len(tasks) == 1 and tasks[0].get("lastStatus") != "STOPPED")


_MODE_READ_FAMILIES = {"describe_state_machine": "state_machine", "get_schedule": "schedules",
                       "describe_task_definition": "task_definitions", "describe_alarms": "alarms"}


def _mode_response(service, operation, response, sdk):
    if operation in _MODE_READ_FAMILIES:
        native = {key: value for key, value in response.items() if key != "ResponseMetadata"}
        return _readback_piece({"key": _MODE_READ_FAMILIES[operation], "parameters": sdk}, native)
    if service == "ecs":
        return _mode_ecs_response(response)
    if (service, operation) == ("dynamodb", "get_item"):
        c.require(set(response) <= {"Item", "ResponseMetadata"}, "finite native DynamoDB response")
        return {key: response[key] for key in ("Item",) if key in response}
    if (service, operation) == ("s3", "get_object"):
        return {"Body": {"bytes": _mode_body(response["Body"])}}
    return {}


class ModeBroker:
    """Finite private SDK dispatcher of one mode seed/start operation, on its own derived mc-* session.

    A durable reservation precedes native IO; only lc.MODE_DEFINITE_ERRORS are definite, any other outcome poisons.
    """
    def __init__(self, aws, governance, journal, session, *, prepared_sha256, credential_limit, clock=None, sleep=None,
                 reads=None, wait=None):
        c.require(type(journal) is AdapterJournal and type(session) is _ModeSession
                  and session.request_binding == c.sha(c.canonical(journal._request))
                  and getattr(journal, "_broker", None) is None, "one original admitted mode broker")
        if reads is not None:
            phase = lc.MODE_SESSION_OPERATIONS[journal._request["operation"]][3]
            request = mode_readback_request(journal._request["owner"] | journal._identity, journal._request["stage"], phase)
            c.require(type(reads) is _ModeSession and reads.code == lc.MODE_SESSION_OPERATIONS[phase + "-observe"][0]
                      and reads.alias == "mode_observe" and reads.request_binding == c.sha(c.canonical(request)),
                      "mode readback original context")
        c.require(wait is None or (type(wait) is _ModeSession and journal._request["operation"] == "unit-start"
                                   and wait.code == "uw" and wait.alias == session.alias
                                   and wait.request_binding == session.request_binding), "mode wait original context")
        self.aws, self.governance, self.journal, self.session, self.reads = aws, governance, journal, session, reads
        self.wait = wait
        self.prepared_sha256, self.credential_limit = c.digest(prepared_sha256), credential_limit
        self.clock, self.sleep = clock or time.time, sleep or time.sleep
        self.scope = _mode_call_scope(governance, journal, session)
        self.evidence, self._frame, self._reading, self.described = [], None, False, None
        journal._broker = self

    @property
    def uncertainty(self):
        return [item for ledger in self.evidence for item in ledger.uncertainty]

    def call(self, *, role, service, operation, parameters):
        journal, session = self.journal, self.session
        journal.guard()
        c.require(session.request_binding == c.sha(c.canonical(journal._request)) and self.clock() + 20 < session.deadline,
                  "mode finite SDK request/window")
        native = {"role": role, "service": service, "operation": operation, "parameters": parameters}
        sdk = validate_mode_call(journal._request["operation"], native, self._call_scope())
        raw = c.canonical(native, limit=128 * 1024)
        if (service, operation) != ("ecs", "describe_tasks"):
            return _mode_reply(self._native_call(raw, service, operation, sdk))
        stage = journal._request["stage"]
        reply, timing = mode_wait(lambda: _mode_reply(self._native_call(raw, service, operation, sdk)), terminal=_mode_task_terminal,
                                  child_deadline=min(stage["deadline"] - 38, session.deadline),
                                  clock=self.clock, sleep=self.sleep)
        journal.__dict__.setdefault("_timings", []).append(timing)
        tasks = reply["value"]["tasks"]
        self.described = tasks[0] if tasks else None
        return reply

    def _call_scope(self):
        launches = [entry["response"] for entry in self.journal._settled_calls() if entry["call"]["operation"] == "run_task"]
        return self.scope | {"launches": len(launches), "frame": self._frame,
                             "reads": self.reads.scope["resources"] if self._reading else None,
                             "launched": [task["taskArn"] for response in launches for task in response.get("tasks", [])]}

    def readbacks(self):
        """Design 4.2 mode-readbacks frame: the ModeReadback key set and projection on the stage observe session, each
        read receipted in this journal.

        Returns: the readbacks document mapping. Raises: ValueError; an unknown read poisons.
        """
        journal, operation = self.journal, self.journal._request["operation"]
        c.require("mode_readbacks" in lc.MODE_EFFECT_METHODS[operation] and self.reads is not None, "mode method outside table")
        journal.guard()
        c.require(self.clock() + 20 < min(self.session.deadline, self.reads.deadline), "mode finite SDK request/window")
        calls = mode_readback_calls(lc.MODE_SESSION_OPERATIONS[operation][3], self.reads.scope["resources"])
        pieces = {}
        for call in calls:
            native = {"role": self.reads.alias, "service": call["service"], "operation": call["operation"],
                      "parameters": call["parameters"]}
            self._reading = True
            try:
                pieces[call["key"]] = self._native_call(c.canonical(native), call["service"], call["operation"],
                                                        call["parameters"], session=self.reads)
            finally:
                self._reading = False
        return c.loads(_readback_document(calls, pieces), canonical=True)

    def frame(self, value):
        """Design 4.2 keeper ledger frame of a recovery-start child method, on the vendored product builders.

        Returns: {"effect_id"} for ledger-admit, {} for the transitions. Raises: ValueError (product refusals included).
        """
        journal, session, operation = self.journal, self.session, self.journal._request["operation"]
        kind = value.get("kind") if type(value) is dict else None
        c.require(lc.MODE_LEDGER_FRAMES.get(kind) in lc.MODE_EFFECT_METHODS[operation], "mode method outside table")
        journal.guard()
        c.require(session.request_binding == c.sha(c.canonical(journal._request)) and self.clock() + 20 < session.deadline,
                  "mode finite SDK request/window")
        admitted = _ledger_frame(value, self.clock)
        frames, record, binding, keys = self._ledger_context()
        pk, owner = frames.tenant_partition(binding.tenant_id), record.owner_sha256
        if kind == "ledger-admit":
            return self._ledger_admit(value, admitted, (frames, record, binding, keys), pk)
        ticket = (pk, frames.ticket_key(owner, value["effect_id"]))
        change = ("UNKNOWN", None) if kind == "ledger-unknown" else ("SETTLED", value["receipt_sha256"])
        if kind == "ledger-settle":
            c.require(any(entry["kind"] in lc.ADAPTER_STEPS[operation] and entry["sha256"] == change[1]
                          for entry in journal._observations), "mode ledger settle receipt")

        def build(texts):
            item = frames.transition(self.scope["table"], binding, (value["effect_id"], texts[ticket]), change)
            return None if item is None else ("put_item", item)
        self._ledger_write(kind, [ticket], build, keys)
        return {}

    def _ledger_admit(self, value, admitted, context, pk):
        import datetime
        frames, record, binding, keys = context
        now = datetime.datetime.fromtimestamp(c.instant(admitted), datetime.timezone.utc)
        effect = frames.ledger_effect(value["effect_kind"], value["request_sha256"], value["target_sha256"])
        identifier = frames.effect_id(binding.record_sha256, effect.kind, effect.request_sha256)
        control, ticket = (pk, frames.control_key(record.owner_sha256)), (pk, frames.ticket_key(record.owner_sha256, identifier))

        def build(texts):
            plan = frames.admission(self.scope["table"], frames.LedgerState(binding, record, texts[control], texts[ticket]),
                                    effect, now)
            return None if plan.items is None else ("transact_write_items", {"TransactItems": plan.items})
        self._ledger_write("ledger-admit", [control, ticket], build, keys)
        return {"effect_id": identifier}

    def _ledger_context(self):
        frames, raw, operation = product_frames(), self.journal._inputs["record"], self.journal._request["operation"]
        try:
            record = frames.ModeCanaryRecord.from_mapping(json.loads(raw))
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            raise ValueError("mode ledger record") from error
        c.require(record.owner_sha256 == self.journal._request["owner"]["owner_sha256"]
                  and "prod-canary-" + record.canary_id == self.session.scope["resources"]["scope"]["tenant_id"]
                  and record.phase == lc.MODE_SESSION_OPERATIONS[operation][3], "mode ledger record")
        binding = frames.ModeCanaryBinding("prod-canary-" + record.canary_id, record.run_ids, record.owner_sha256, c.sha(raw),
                                           record.phase, record.context_kind)
        keys = {"canary_id": record.canary_id, "owner_sha256": record.owner_sha256, "run_ids": list(record.run_ids),
                "dispatch_id": None}
        return frames, record, binding, keys

    def _ledger_write(self, frame, reads, build, keys):
        self._frame = {"name": frame, "binding": keys}
        try:
            ledger_write(frame, table=self.scope["table"], binding=keys, reads=reads, read=self._ledger_read, build=build,
                         execute=self._frame_call)
        finally:
            self._frame = None

    def _ledger_read(self, keys):
        texts = {}
        for pk, sk in keys:
            value = self._frame_call("get_item", {"TableName": self.scope["table"], "Key": {"pk": {"S": pk}, "sk": {"S": sk}},
                                                  "ConsistentRead": True})
            item = value.get("Item")
            payload = item.get("payload") if type(item) is dict else None
            c.require(item is None or (item.get("pk") == {"S": pk} and item.get("sk") == {"S": sk} and type(payload) is dict
                                       and set(payload) == {"S"} and type(payload["S"]) is str), "mode ledger read")
            texts[(pk, sk)] = None if item is None else payload["S"]
        return texts

    def _frame_call(self, name, parameters):
        native = {"role": self.session.alias, "service": "dynamodb", "operation": name, "parameters": parameters}
        validate_mode_frame_call(self.journal._request["operation"], self._frame, native, self.scope)
        return self._native_call(c.canonical(native, limit=128 * 1024), "dynamodb", name, parameters)

    def _native_call(self, raw, service, operation, sdk, session=None):
        from tools.cnesdata_delivery.lifecycle_runtime import _exact_sdk_dates
        journal, session = self.journal, session or self.session
        ledger = ModeEvidence(self.aws, self.governance, journal, raw, prepared_sha256=self.prepared_sha256,
                              role_session_sha256=session.commitment, scope=self._call_scope())
        self.evidence.append(ledger)
        ticket, created = None, False
        try:
            c.require(ledger.reserve() == "created", "existing durable call is historical/unknown; no fresh SDK replay")
            created = True
            ticket = journal.begin_sdk_call(raw, role_session_sha256=session.commitment)
            c.require(self.clock() + 20 < session.deadline, "SDK reservation consumed original budget")
            journal._guard.check(20)
            response, failure, status = self._sdk(session, service, operation, sdk)
            metadata = response.get("ResponseMetadata", {})
            c.require(type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == status,
                      "mode native SDK authenticated status")
            value = failure if failure is not None else _mode_response(service, operation, response, sdk)
            response_raw = c.canonical(_exact_sdk_dates(value), limit=1024**2)
            c.require(self.clock() < session.deadline, "native response exceeded original mode window")
            receipt = journal.complete_sdk_call(ticket, response_raw, request_id=metadata["RequestId"],
                                                server_date=metadata["HTTPHeaders"]["date"])
            ledger.complete(response_raw, receipt)
            journal.guard()
            c.require(self.clock() < session.deadline, "durable receipt exceeded original mode window")
            return c.loads(response_raw, canonical=True)
        except BaseException:
            _poison_call(journal, ledger, ticket, created)
            raise

    def _sdk(self, session, service, operation, sdk):
        try:
            return session.client.call(service, operation, **sdk), None, 200
        except Exception as error:
            response = getattr(error, "response", None)
            if self._frame is not None:
                cancel = ledger_cancel_response(operation, error)
                c.require(cancel is not None, "mode native SDK outcome unknown")
                return response, cancel, 400
            code = response.get("Error", {}).get("Code") if type(response) is dict else None
            definite = lc.MODE_DEFINITE_ERRORS.get((service, operation))
            c.require(definite is not None and code == definite[0], "mode native SDK outcome unknown")
            return response, {"Error": {"Code": code}}, definite[1]


_READBACK_RECEIPT = "schema_version intent_sha256 response_sha256 request_id server_date"


class ModeReadback:
    """Design 4.4 and ruling 5: the closed reads of one mode on the stage observe session, each behind a durable
    <mode>-readbacks intent, response and receipt, and one observation whose handoff re-verifies the whole chain.

    Attached to the keeper before any IO; a failure or an unreceipted call keeps the lease held.
    """
    def __init__(self, aws, governance, session, *, guard, mode, clock=None):
        from tools.cnesdata_delivery.application_gate import KeeperGuard
        keeper = guard.keeper if type(guard) is KeeperGuard else None
        record = keeper.lease.check() if type(keeper) is Keeper else None
        c.require(record is not None and type(session) is _ModeSession and mode in lc.MODE_READBACK_OPERATIONS
                  and session.code == lc.MODE_SESSION_OPERATIONS[mode + "-observe"][0] and session.alias == "mode_observe",
                  "mode readback original context")
        self._request = mode_readback_request(lc.owner_binding(record), record["lifecycle"], mode)
        c.require(session.request_binding == c.sha(c.canonical(self._request)), "mode readback original context")
        self.aws, self.governance, self.keeper, self.session, self.mode = aws, governance, keeper, session, mode
        self.resources, self.clock, self._guard = session.scope["resources"], clock or time.time, guard
        self._failed, self._inflight, self._pending, self._unknown = False, None, [], []
        self._observations, self._observation_bytes, self.head = [], {}, None
        keeper.attach(self)

    @property
    def pending(self):
        return c.loads(c.canonical(self._pending), canonical=True)

    @property
    def unknown(self):
        return c.loads(c.canonical(self._unknown), canonical=True)

    def guard(self):
        c.require(not self._failed, "mode readback failed; original recovery required")
        try:
            self._guard.check()
        except BaseException:
            self._failed = True
            raise

    def read(self):
        """Returns: the readbacks observation bytes. Raises: ValueError; a call without its receipt poisons."""
        c.require(not self._observations and self.head is None, "mode readback once")
        calls = mode_readback_calls(self.mode, self.resources)
        pieces = {call["key"]: self._call(sequence, call) for sequence, call in enumerate(calls)}
        raw = _readback_document(calls, pieces)
        self.guard()
        self._observation_bytes[c.sha(raw)] = raw
        self._observations.append({"kind": "readbacks", "sha256": c.sha(raw), "size": len(raw)})
        return raw

    def original(self):
        """Ruling 5 handoff: the chain re-read from sequence 0, each intent rebuilt byte for byte, each receipt over its
        intent and response, the head equal and the document recomputed equal to the observation.

        Returns: the readbacks bytes. Raises: ValueError mode readback chain.
        """
        c.require(len(self._observations) == 1 and not self._failed and self._inflight is None
                  and not self._pending and not self._unknown, "mode readback original observation")
        calls = mode_readback_calls(self.mode, self.resources)
        pieces, previous = {}, None
        try:
            for sequence, call in enumerate(calls):
                pieces[call["key"]], previous = self._link(sequence, call, previous)
        except (ValueError, TypeError, KeyError) as error:
            raise ValueError("mode readback chain") from error
        raw = self._observation_bytes[self._observations[0]["sha256"]]
        c.require(previous == self.head and _readback_document(calls, pieces) == raw, "mode readback chain")
        return raw

    def _intent(self, sequence, call, previous):
        native = {"role": self.session.alias, "service": call["service"], "operation": call["operation"],
                  "parameters": call["parameters"]}
        request = self._request
        return c.canonical({"schema_version": 3, "operation": request["operation"], "owner": request["owner"],
                            "caller": request["caller"], "checkpoint_sha256": request["checkpoint_sha256"],
                            "sequence": sequence, "previous": previous, "role_session_sha256": self.session.commitment,
                            "call": native})

    def _keys(self, sequence):
        from tools.cnesdata_delivery.lifecycle_runtime import closed_ready_evidence_keys
        request = self._request
        return closed_ready_evidence_keys(self.governance, owner=request["owner"], caller=request["caller"],
                                          checkpoint_sha256=request["checkpoint_sha256"], sequence=sequence,
                                          operation=request["operation"])

    def _link(self, sequence, call, previous):
        from tools.cnesdata_delivery.lifecycle_runtime import evidence_intent
        keys, bucket = self._keys(sequence), self.governance["evidence_bucket"]
        intent, response, receipt = (self.aws.get(bucket, keys[name], maximum=1024**2, absent=True)[0]
                                     for name in ("intent", "response", "receipt"))
        evidence_intent(intent, operation=self._request["operation"])
        c.require(intent == self._intent(sequence, call, previous), "mode readback chain")
        seal = c.loads(receipt, canonical=True)
        c.closed(seal, _READBACK_RECEIPT)
        c.require(seal["schema_version"] == 2 and seal["intent_sha256"] == c.sha(intent)
                  and seal["response_sha256"] == c.sha(response), "mode readback chain")
        return c.loads(response, canonical=True), c.sha(receipt)

    def _checkpoint(self):
        held = self.keeper.lease.check()["lifecycle"]["checkpoint_sha256"]
        c.require(held == self._request["checkpoint_sha256"], "mode readback original checkpoint")

    def _call(self, sequence, call):
        c.require(self.clock() + 20 < self.session.deadline, "mode readback window")
        self._checkpoint()
        intent, keys = self._intent(sequence, call, self.head), self._keys(sequence)
        reference = {"kind": "sdk-call", "reference_sha256": c.sha(intent)}
        self._pending.append(reference)
        self._inflight = reference
        try:
            self._create(keys["intent"], intent, replay=True)
            piece, metadata = _readback_response(call, self.session.client.call(call["service"], call["operation"],
                                                                                  **call["parameters"]))
            self._checkpoint()
            body = c.canonical(piece)
            receipt = c.canonical({"schema_version": 2, "intent_sha256": c.sha(intent), "response_sha256": c.sha(body)}
                                  | metadata)
            self._create(keys["response"], body)
            self._create(keys["receipt"], receipt)
        except BaseException as error:
            self._failed, self._inflight = True, None
            self._unknown.append(reference)
            if isinstance(error, ValueError):
                raise
            raise ValueError("mode readback outcome unknown") from error
        self._pending.remove(reference)
        self._inflight, self.head = None, c.sha(receipt)
        return piece

    def _create(self, key, raw, *, replay=False):
        self.guard()
        try:
            self.aws.put(self.governance["evidence_bucket"], key, raw)
        except Exception as error:
            response = getattr(error, "response", None)
            code = response.get("Error", {}).get("Code") if type(response) is dict else None
            c.require(not (replay and code == "PreconditionFailed"), "mode readback replay")
            raise
        stored, _ = self.aws.get(self.governance["evidence_bucket"], key, maximum=1024**2, absent=True)
        c.require(stored == raw, "mode readback evidence readback")


def _readback_response(call, response):
    from email.utils import parsedate_to_datetime
    metadata = response.get("ResponseMetadata") if type(response) is dict else None
    headers = metadata.get("HTTPHeaders") if type(metadata) is dict else None
    c.require(type(metadata) is dict and metadata.get("HTTPStatusCode") == 200 and type(metadata.get("RequestId")) is str
              and 1 <= len(metadata["RequestId"]) <= 256 and type(headers) is dict and type(headers.get("date")) is str,
              "mode readback native metadata")
    server = parsedate_to_datetime(headers["date"])
    c.require(server.tzinfo is not None and abs(time.time() - server.timestamp()) <= 30, "mode readback native clock")
    piece = _readback_piece(call, {key: value for key, value in response.items() if key != "ResponseMetadata"})
    return piece, {"request_id": metadata["RequestId"], "server_date": headers["date"]}


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
