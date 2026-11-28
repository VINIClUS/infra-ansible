"""G3 drift handoff: the catalogue projection of a plan, carried by the drift baseline or derived by the audit."""
import re

from tools.cnesdata_delivery import contract as c, drift_catalog

MEMBER = "drift-handoff.json"
LIMIT = 2 * 1024**2
FIELDS = "handoff_version source_sha purpose catalog_sha256 matrix readbacks"
ADDRESS = re.compile(r'[A-Za-z0-9_.\-]+(?:\[(?:"[A-Za-z0-9_.\-]+"|[0-9]+)\])?(?:\.[A-Za-z0-9_\-]+(?:\[(?:"[A-Za-z0-9_.\-]+"|[0-9]+)\])?)*')


def pin(governance):
    """Args: governance. Returns: the closed drift_handoff pin. Raises: ValueError."""
    c.require("drift_matrix" not in governance and "readbacks" not in governance, "inline drift matrix refused")
    value = governance.get("drift_handoff")
    c.require(type(value) is dict, "drift handoff governance")
    c.closed(value, "member sha256")
    c.require(value["member"] == MEMBER, "drift handoff governance")
    c.digest(value["sha256"])
    return value


def _address(value, allowed):
    c.require(type(value) is str and ADDRESS.fullmatch(value) is not None
              and drift_catalog.resource_type(value) in allowed, "drift handoff address")


def _addresses(document, purpose):
    allowed = drift_catalog.ENVELOPES[purpose].supported if purpose in drift_catalog.ENVELOPES \
        else set(drift_catalog.IDENTITY)
    matrix = document["matrix"]
    rows = matrix["before"] + matrix["after"] + matrix.get("absent", [])
    specs = document["readbacks"]["before"] + document["readbacks"]["after"]
    for item in rows + specs:
        c.require(type(item) is dict, "drift handoff address")
        _address(item.get("address"), allowed)


def _shape(document, source, purpose):
    c.closed(document, FIELDS)
    version = 2 if purpose in drift_catalog.ENVELOPES else 1
    matrix = document["matrix"]
    c.require(document["handoff_version"] == 1 and type(document["handoff_version"]) is int
              and document["source_sha"] == source and document["purpose"] == purpose
              and document["catalog_sha256"] == drift_catalog.CATALOG_SHA256
              and type(matrix) is dict and matrix.get("matrix_version") == version
              and matrix.get("source_sha") == source and matrix.get("purpose") == purpose, "drift handoff identity")
    c.closed(matrix, "matrix_version source_sha purpose before after" + (" absent" if version == 2 else ""))
    c.closed(document["readbacks"], "before after")
    c.require(type(matrix.get("absent", [])) is list, "drift handoff shape")
    for stage in ("before", "after"):
        c.require(type(matrix[stage]) is list and type(document["readbacks"][stage]) is list, "drift handoff shape")
        for spec in document["readbacks"][stage]:
            c.require(type(spec) is dict, "drift handoff shape")
            c.closed(spec, "service operation address" + (" absent" if "absent" in spec else ""))


def _measurement(proof, proof_files, digest):
    reports = [item for item in proof["reports"] if item["check_id"] == "drift-baseline"]
    c.require(len(reports) == 1, "drift handoff measurement")
    measured = c.loads(proof_files[reports[0]["name"]], canonical=True, limit=262144)["measurement"]
    c.require(type(measured) is dict and measured.get("handoff_sha256") == digest
              and "rehearsal_plan_sha256" in measured, "drift handoff measurement")
    c.digest(measured["rehearsal_plan_sha256"])
    return measured


def load(files, governance, proof, proof_files, *, source, purpose):
    """Args: drift artifact members, governance, proof, proof members, source, purpose.

    Returns: governance with the hydrated drift_matrix and readbacks. Raises: ValueError before credentials.
    """
    fixed = pin(governance)
    c.require(MEMBER in files, "drift handoff member")
    raw = files[MEMBER]
    c.require(c.sha(raw) == fixed["sha256"], "drift handoff hash")
    _measurement(proof, proof_files, fixed["sha256"])
    document = c.loads(raw, canonical=True, limit=LIMIT)
    c.public_safe(document, governance)
    c.refuse_account_derived(raw, governance)
    _shape(document, source, purpose)
    _addresses(document, purpose)
    return governance | {"drift_matrix": document["matrix"], "readbacks": document["readbacks"]}


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


def envelope_for(purpose):
    """Args: purpose. Returns: the Phase A envelope, or the lifecycle one for a step purpose. Raises: ValueError."""
    from tools.cnesdata_delivery.lifecycle_contract import PURPOSES
    if purpose == "phase-a":
        return drift_catalog.PHASE_A_ENVELOPE
    c.require(purpose in PURPOSES, "lifecycle step purpose")
    return drift_catalog.LIFECYCLE_ENVELOPE


def derive(plan, state, source_sha, purpose, *, envelope):
    """Args: plan.json, observed state, source sha, purpose, envelope. Returns: the handoff document. Raises: ValueError."""
    c.digest(source_sha, 40)
    changes = _changes(plan)
    c.require(all(change["actions"] != ["delete"] for change in changes.values()), "delete without create refused")
    c.require(all(ADDRESS.fullmatch(address) for address in changes), "handoff address shape")
    _covered(envelope, changes, state)
    before = {a: ch["before"] for a, ch in changes.items() if ch["before"] is not None}
    after = {a: _predicted(ch) for a, ch in changes.items() if ch["after"] is not None}
    return _document(source_sha, purpose, [_stage(envelope, plan, before), _stage(envelope, plan, after)])


def lifecycle(plan, state, source_sha, purpose):
    """Args: saved plan.json, before state, source sha, lifecycle step purpose.

    Returns: (matrix, readbacks) of exactly that purpose from the pinned catalog. Raises: ValueError.
    """
    envelope = envelope_for(purpose)
    c.require(envelope is drift_catalog.LIFECYCLE_ENVELOPE, "lifecycle step purpose")
    document = derive(plan, state, source_sha, purpose, envelope=envelope)
    readbacks = {stage: [spec | {"absent": False} for spec in specs] for stage, specs in document["readbacks"].items()}
    return document["matrix"], readbacks
