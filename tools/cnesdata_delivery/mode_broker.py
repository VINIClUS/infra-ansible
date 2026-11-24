"""Mode SDK broker, fence-read broker and mode readbacks of the promotion mode stages (P16b)."""
import re

from tools.cnesdata_delivery import contract as c

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
_RUN = re.compile(r"[a-z0-9-]{1,64}")
_DISPATCH = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_MANIFEST = re.compile(r"[A-Za-z0-9._-]{1,128}")


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


class ModeBroker:
    """Finite private SDK dispatcher of one mode seed/start operation, on its own derived mc-* session.

    The read session serves mode_readbacks and the unit outputs; any unknown native outcome poisons, never retries.
    """

    @property
    def uncertainty(self):
        return [item for ledger in self.evidence for item in ledger.uncertainty]


class FenceReadBroker:
    """Finite private dispatcher of the observe operations: strong FENCE/SEMAPHORE GetItem on the fence session only."""

    @property
    def uncertainty(self):
        return [item for ledger in self.evidence for item in ledger.uncertainty]
