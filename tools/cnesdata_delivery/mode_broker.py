"""Mode SDK broker, fence-read broker and mode readbacks of the promotion mode stages (P16b)."""
import importlib.util
import pathlib
import re
import sys
import time

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.application_gate import (AdapterJournal, ClosedReadyBroker, Keeper, _assume_fence_session,
                                                      _fence_operation_iam)

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
     "250343666e0b199ae1ddbd29fb030de144d92d8fa18f576a27fa55b3d314d881"))
_PRODUCT = {}
_RUN = re.compile(r"[a-z0-9-]{1,64}")
_DISPATCH = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_MANIFEST = re.compile(r"[A-Za-z0-9._-]{1,128}")


def _load_product_frames(folder):
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
