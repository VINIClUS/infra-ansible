"""Generator of the drift handoff: the gate's catalogue projection of the rehearsal plan, self-checked."""
from tools.cnesdata_delivery import contract as c, drift_catalog, drift_handoff as gate


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
    document = gate.derive(plan, state, source_sha, purpose, envelope=drift_catalog.ENVELOPES[purpose])
    check(document, plan)
    return document


def serialize(document):
    """Args: handoff document. Returns: canonical bytes within the gate limit."""
    return c.canonical(document, limit=gate.LIMIT)


def refuse_uncovered(real_plan, document):
    """Args: real plan.json, handoff document. Raises: ValueError when a changed address is outside COVERED."""
    covered = {row["address"] for row in document["matrix"]["before"]}
    changed = {a for a, ch in gate._changes(real_plan).items() if ch["actions"] not in drift_catalog.NO_CHANGE}
    c.require(changed <= covered, "real plan address outside COVERED")
