"""G3 drift handoff: matrix and readbacks carried by a member of the authenticated drift baseline."""
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
    _shape(document, source, purpose)
    _addresses(document, purpose)
    return governance | {"drift_matrix": document["matrix"], "readbacks": document["readbacks"]}
