"""At the activation key limit every governed document fits at prod-length names; write 3 binds."""
import copy

import pytest
from test_cnesdata_delivery_oidc import PROD_EVIDENCE_BUCKET, native, prod_documents, prod_values, quota_margins  # noqa: F401
from test_cnesdata_producers_application import (PREDECESSOR_JOB, closure_reference, entry, full_catalog,  # noqa: F401
                                                 originals, produced_release, producer)
from test_cnesdata_producers_release import RECEIPT
from test_cnesdata_session_policy_capacity import LIMIT, activated, activation_sizes, governance
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import session_policy as sp
from tools.cnesdata_delivery.producers import governance_assembly as ga

ACCOUNT = "111122223333"
PIN_POLICIES = {"plan": 'aws_iam_policy.delivery_session["plan"]', "deploy": 'aws_iam_policy.delivery_session["deploy"]',
                "audit": 'aws_iam_policy.delivery_session["audit"]', "application": "aws_iam_policy.application_session[0]",
                "application_ops": "aws_iam_policy.application_ops_session[0]",
                "plan_activation": "aws_iam_policy.plan_activation_session[0]"}
PROD_NAMES = {"synthetic-state": "s" * 48, "synthetic-evidence": "e" * 45, "cnesdata-test-": "cnesdata-prod-"}


def pin(role, document):
    base = {"application_ops": "application", "plan_activation": "plan"}.get(role, role)
    kind = {"application_ops": "-ops-session", "plan_activation": "-activation-session"}.get(role, "-session")
    return {"account_id": ACCOUNT, "role_arn": f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-{base}",
            "policy_arn": f"arn:aws:iam::{ACCOUNT}:policy/cnesdata-prod-{base}{kind}", "root_source_sha": "e" * 40,
            "default_version_id": "v12", "document": document, "document_sha256": c.sha(c.canonical(document)),
            "observed_at": "2026-11-27T09:00:00Z", "expires_at": "2026-11-27T12:00:00Z", "frozen_until": "2026-11-27T13:00:00Z",
            "owner_producer": {"repository": "VINIClUS/infra-ansible",
                               "workflow_path": ".github/workflows/cnesdata-producers.yml", "workflow_sha": "f" * 40}}


def reference(index):
    return {"repository": "VINIClUS/infra-ansible", "run_id": 19876543210 + index, "run_attempt": 1,
            "artifact_id": 4876543210 + index, "artifact_digest": "sha256:" + f"{index:x}" * 64,
            "workflow_path": ".github/workflows/cnesdata-producers.yml", "workflow_sha": "f" * 40, "source_sha": "f" * 40}


def write_three(entry, resources, ceiling):
    previous, _ = entry.store.get()
    selector = entry.gov.pop("predecessor_read")
    for key in ("lifecycle_predecessor", "lifecycle_steps_sha256", "source_closure_sha256"):
        entry.gov.pop(key)
    predecessor = producer().predecessor(entry.api, entry.gov, selector, lease=previous, job=PREDECESSOR_JOB,
                                         objects=originals(entry.store.aws, entry.gov, selector))
    catalog_raw, catalog_reference = producer().catalog_member(full_catalog())
    pieces = predecessor | entry.section | catalog_reference | closure_reference() | {"release": produced_release()}
    document = copy.deepcopy(producer().document(entry.gov, pieces, catalog_raw))
    document["session_policy_pins"] = {role: pin(role, c.loads(resources[address]["policy"].encode()))
                                       for role, address in PIN_POLICIES.items()}
    document["roles"] = {role: f"arn:aws:iam::{ACCOUNT}:role/cnesdata-prod-{role}" for role in ("plan", "deploy", "audit", "application")}
    document.setdefault("gate_shas", {})["audit"] = "9" * 40
    document["session_owner_references"] = {role: reference(index) for index, role in enumerate(document["roles"], 1)}
    document["activation_read"] = {"ceiling": dict(ceiling, bucket_arn=PROD_EVIDENCE_BUCKET),
        "ordinary_bucket_denies": list(sp.ACTIVATION_BUCKET_READS), "plan_role_arn": document["roles"]["plan"],
        "identity_sha256": "1" * 64, "session_sha256": "2" * 64}
    document.update(activation_receipts={"operational-plan": RECEIPT}, activation_enabled=True)
    raw = ga.render(document, ceiling=ga.SECRET_CEILING).decode()
    for old, new in PROD_NAMES.items():
        raw = raw.replace(old, new)
    return len(raw.encode())


@pytest.fixture(scope="module")
def prod_resources(native):
    return prod_documents(native, sp.ACTIVATION_KEY_LIMIT)


def test_no_limite_de_chave_todo_documento_cabe_com_nomes_de_producao_e_a_escrita_3_e_a_mais_justa(prod_resources, entry):
    assert sp.ACTIVATION_KEY_LIMIT == 128
    values, resources = prod_values(sp.ACTIVATION_KEY_LIMIT), prod_resources
    margins = quota_margins(resources)
    for scope, size in activation_sizes(activated(governance(45, 23), 45, sp.ACTIVATION_KEY_LIMIT)).items():
        margins["activation " + scope] = LIMIT - size
    margins["write 3"] = ga.CLI_CEILING - write_three(entry, resources, values["github_delivery"]["activation_read"])
    assert {name: margin for name, margin in margins.items() if margin <= 0} == {}
    assert min(margins, key=margins.__getitem__) == "write 3"
