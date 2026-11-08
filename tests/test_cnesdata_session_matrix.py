"""Pure finite fixtures complement the separate hosted actual native-rendered matrix."""

import json

import pytest

from fixtures.cnesdata_session_cases import assert_matrix, expected_documents, inline
from test_cnesdata_session_capacity import governance


@pytest.mark.parametrize("role", ["plan", "deploy"])
@pytest.mark.parametrize(
    "same_bucket,same_key", [(False, False), (False, True), (True, False), (True, True)]
)
def test_preserva_poderes_uteis_e_nega_outros_contextos_nas_quatro_combinacoes(
    role, same_bucket, same_key
):
    gov = governance()
    if same_bucket:
        gov["state_bucket"] = gov["evidence_bucket"]
    if same_key:
        gov["state_kms_key_arn"] = gov["evidence_kms_key_arn"]
    identity, managed = expected_documents(gov, role)
    request = inline(gov, role)
    assert (
        len(request["Policy"]) + sum(len(item["arn"]) for item in request["PolicyArns"])
        <= 2048
    )
    assert_matrix(identity, managed, json.loads(request["Policy"]), gov, role)
