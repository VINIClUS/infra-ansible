"""Only original owner facts authorize the dedicated full phase-inputs run namespace."""

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.session_policy import PhaseInputScope, _prefix


def phase_input_reads(governance, descriptor, authority):
    objects = governance["phase_input_objects"]
    exact = sorted(spec["key"] for spec in objects.values())
    try:
        names = {"phase-inputs.json", "candidate.json", "promotion.json"}
        c.require(
            set(objects) == names and len(set(exact)) == 3, "exact three logical inputs"
        )
        reference = descriptor["payload_artifact"]
        c.require(
            reference == governance["artifact_references"]["phase-inputs"]
            and "phase-inputs" in governance["artifact_purposes"],
            "authenticated purpose payload",
        )
        source = c.digest(reference["source_sha"], 40)
        c.require(
            source == descriptor["source_sha"], "payload/current authenticated source"
        )
        run, attempt = (
            c.integer(reference["run_id"]),
            c.integer(reference["run_attempt"]),
        )
        prefix = _prefix(governance) + f"phase-inputs/{source}/{run}/{attempt}/"
        for name, spec in objects.items():
            c.closed(spec, "key sha256")
            c.digest(spec["sha256"])
            c.require(spec["key"] == prefix + name, "literal purpose/run object key")
        c.require(
            c.canonical(authority.namespace)
            == c.canonical(
                {
                    "purpose": "phase-inputs",
                    "dedicated": True,
                    "payload_reference_sha256": c.sha(c.canonical(reference)),
                    "prefix_sha256": c.sha(prefix.encode()),
                }
            ),
            "original owner dedicated purpose/run namespace",
        )
        return [PhaseInputScope(prefix + "*")]
    except (KeyError, TypeError, ValueError, AttributeError):
        return exact
