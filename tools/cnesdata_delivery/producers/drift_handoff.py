"""Generator of the drift handoff: catalogue-expanded matrix and readback specs, self-checked."""
from tools.cnesdata_delivery import contract as c, drift_catalog, drift_handoff as gate


def _changes(plan):
    return {item["address"]: item["change"] for item in plan["resource_changes"] if item.get("mode") == "managed"}


def _state_addresses(state):
    found = set()
    for row in state.get("resources", []):
        if row.get("mode") != "managed":
            continue
        base = (row.get("module", "") + ".").lstrip(".") + row["type"] + "." + row["name"]
        for instance in row.get("instances", []):
            key = instance.get("index_key")
            found.add(base if key is None else base + "[" + c.canonical(key)[:-1].decode() + "]")
    return found


def _covered(envelope, changes, state):
    planned = {a for a, ch in changes.items() if drift_catalog.resource_type(a) in envelope.covered
               and ch["before"] is not None}
    observed = {a for a in _state_addresses(state) if drift_catalog.resource_type(a) in envelope.covered}
    c.require(planned == observed, "state covered instances differ from the plan")


def _predicted(change):
    unknown = change.get("after_unknown")
    c.require(type(unknown) is dict, "after_unknown shape")
    return {name: None for name in unknown} | change["after"]


def _stage(envelope, plan, expected):
    required = envelope.required(plan, expected)
    specs, rows = [], []
    for address in sorted({address for address, _ in required}):
        tipo = drift_catalog.resource_type(address)
        names = sorted(name for owner, name in required if owner == address)
        service, operation = drift_catalog.CATALOG[tipo][names[0]][:2]
        for name in names:
            _, _, path, encoding = drift_catalog.CATALOG[tipo][name]
            rows.append({"address": address, "attribute": name, "readback": len(specs), "path": list(path),
                         "encoding": encoding})
        specs.append({"service": service, "operation": operation, "address": address})
    return specs, rows


def _document(source_sha, purpose, stages):
    (specs_before, rows_before), (specs_after, rows_after) = stages
    matrix = {"matrix_version": 2, "source_sha": source_sha, "purpose": purpose, "before": rows_before,
              "after": rows_after, "absent": []}
    return {"handoff_version": 1, "source_sha": source_sha, "purpose": purpose,
            "catalog_sha256": drift_catalog.CATALOG_SHA256, "matrix": matrix,
            "readbacks": {"before": specs_before, "after": specs_after}}


def check(document, plan):
    """Args: handoff document, plan.json. Raises: ValueError when the gate would refuse the document."""
    source, purpose = document["source_sha"], document["purpose"]
    gate._shape(document, source, purpose)
    gate._addresses(document, purpose)
    drift_catalog.admit_stages(plan, document["readbacks"], document["matrix"], set())
    c.public_safe(document)


def generate(plan, state, source_sha, purpose):
    """Args: rehearsal plan.json, observed state, source sha, purpose. Returns: the handoff document."""
    c.require(purpose in drift_catalog.ENVELOPES, "purpose without envelope")
    c.digest(source_sha, 40)
    envelope = drift_catalog.ENVELOPES[purpose]
    changes = _changes(plan)
    c.require(all(change["actions"] != ["delete"] for change in changes.values()), "delete without create refused")
    c.require(all(gate.ADDRESS.fullmatch(address) for address in changes), "handoff address shape")
    _covered(envelope, changes, state)
    before = {a: ch["before"] for a, ch in changes.items() if ch["before"] is not None}
    after = {a: _predicted(ch) for a, ch in changes.items() if ch["after"] is not None}
    document = _document(source_sha, purpose, [_stage(envelope, plan, before), _stage(envelope, plan, after)])
    check(document, plan)
    return document


def serialize(document):
    """Args: handoff document. Returns: canonical bytes within the gate limit."""
    return c.canonical(document, limit=gate.LIMIT)


def refuse_uncovered(real_plan, document):
    """Args: real plan.json, handoff document. Raises: ValueError when a changed address is outside COVERED."""
    covered = {row["address"] for row in document["matrix"]["before"]}
    changed = {a for a, ch in _changes(real_plan).items() if ch["actions"] not in drift_catalog.NO_CHANGE}
    c.require(changed <= covered, "real plan address outside COVERED")
