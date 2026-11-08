"""Grouping requires original authenticated owner purpose facts, never common prefixes."""

import copy

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.session_owner import Authority
from tools.cnesdata_delivery.session_grouping import phase_input_reads


def case():
    reference = {
        "source_sha": "a" * 40,
        "run_id": 42448920421,
        "run_attempt": 1,
        "repository": "VINIClUS/CnesData",
        "workflow_path": ".github/workflows/inputs.yml",
        "workflow_sha": "b" * 40,
        "artifact_id": 123,
    }
    prefix = "cnesdata/prod/evidence/phase-inputs/" + "a" * 40 + "/42448920421/1/"
    objects = {
        name: {"key": prefix + name, "sha256": "c" * 64}
        for name in ("phase-inputs.json", "candidate.json", "promotion.json")
    }
    gov = {
        "evidence_prefix": "cnesdata/prod/evidence/",
        "artifact_purposes": ["phase-inputs"],
        "artifact_references": {"phase-inputs": reference},
        "phase_input_objects": objects,
    }
    fact = {
        "purpose": "phase-inputs",
        "dedicated": True,
        "payload_reference_sha256": c.sha(c.canonical(reference)),
        "prefix_sha256": c.sha(prefix.encode()),
    }
    authority = Authority({}, 9999999999, fact)
    return (
        gov,
        {"payload_artifact": reference, "source_sha": reference["source_sha"]},
        authority,
        prefix,
    )


def test_agrupa_somente_os_tres_nomes_do_payload_e_purpose_autenticados():
    gov, descriptor, authority, prefix = case()
    assert phase_input_reads(gov, descriptor, authority) == [prefix + "*"]
    assert set(gov["phase_input_objects"]) == {
        "phase-inputs.json",
        "candidate.json",
        "promotion.json",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "owner",
        "purpose",
        "payload",
        "source",
        "run",
        "attempt",
        "ancestor",
        "duplicate",
        "name",
        "dedicated",
    ],
)
def test_falha_de_grouping_preserva_apenas_as_keys_exatas(mutation):
    gov, descriptor, authority, prefix = case()
    if mutation == "owner":
        authority = Authority({}, 9999999999, None)
    elif mutation == "purpose":
        assert authority.namespace is not None
        authority.namespace["purpose"] = "planned"
    elif mutation == "payload":
        descriptor = {
            "payload_artifact": dict(descriptor["payload_artifact"], artifact_id=124)
        }
    elif mutation in {"source", "run", "attempt"}:
        field = {"source": "source_sha", "run": "run_id", "attempt": "run_attempt"}[
            mutation
        ]
        reference = copy.deepcopy(descriptor["payload_artifact"])
        reference[field] = "d" * 40 if mutation == "source" else 2
        descriptor = {"payload_artifact": reference}
    elif mutation == "ancestor":
        gov["phase_input_objects"]["candidate.json"]["key"] = (
            prefix.rsplit("/", 3)[0] + "/candidate.json"
        )
    elif mutation == "duplicate":
        gov["phase_input_objects"]["candidate.json"]["key"] = (
            prefix + "phase-inputs.json"
        )
    elif mutation == "name":
        gov["phase_input_objects"]["other.json"] = gov["phase_input_objects"].pop(
            "candidate.json"
        )
    else:
        assert authority.namespace is not None
        authority.namespace["dedicated"] = False
    exact = sorted(spec["key"] for spec in gov["phase_input_objects"].values())
    assert phase_input_reads(gov, descriptor, authority) == exact
