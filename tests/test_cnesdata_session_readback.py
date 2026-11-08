"""Real verification code, with only the SDK network boundary replaced."""

import copy
from urllib.parse import quote

import pytest

from tools.cnesdata_delivery import contract as c, session_owner
from test_cnesdata_session_owner import original_owner


class IAMBoundary:
    def __init__(self, pin, mutation=None):
        self.pin, self.mutation, self.calls = pin, mutation, []

    def call(self, service, operation, **arguments):
        assert service == "iam" and arguments["PolicyArn"] == self.pin["policy_arn"]
        self.calls.append(operation)
        if self.mutation == "denied" or (
            self.mutation == "deleted" and operation == "get_policy_version"
        ):
            raise ValueError("SDK read denied/missing version")
        if operation == "get_policy_version":
            assert arguments["VersionId"] == self.pin["default_version_id"]
            document = copy.deepcopy(self.pin["document"])
            if self.mutation == "document":
                document["Statement"] = [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ]
            if self.mutation == "encoded":
                document = quote(c.canonical(document).decode())
            return {
                "PolicyVersion": {
                    "Document": document,
                    "VersionId": "v4"
                    if self.mutation == "version"
                    else self.pin["default_version_id"],
                    "IsDefaultVersion": self.mutation != "not-default",
                }
            }
        result = {
            "Arn": self.pin["policy_arn"],
            "PolicyName": self.pin["policy_arn"].rsplit("/", 1)[1],
            "DefaultVersionId": self.pin["default_version_id"],
            "AttachmentCount": 0,
            "PermissionsBoundaryUsageCount": 0,
        }
        second = len(self.calls) == 3
        for field, mutation in (
            ("AttachmentCount", "attached"),
            ("PermissionsBoundaryUsageCount", "boundary"),
        ):
            if self.mutation == mutation or (
                second and self.mutation == mutation + "-second"
            ):
                result[field] = 1
        if self.mutation == "arn":
            result["Arn"] += "-other"
        if self.mutation == "name":
            result["PolicyName"] += "-other"
        if self.mutation == "default" or (second and self.mutation == "default-second"):
            result["DefaultVersionId"] = "v4"
        return {"Policy": result}


@pytest.mark.parametrize("mutation", [None, "encoded"])
def test_confere_default_documento_e_default_novamente_antes_de_exportar(mutation):
    args = original_owner()
    authority = session_owner.authenticate(*args, "plan", "bootstrap")
    boundary = IAMBoundary(authority.pin, mutation)
    session_owner.verify_managed(boundary, authority, args[-1] + 3600, lambda: args[-1])
    assert boundary.calls == ["get_policy", "get_policy_version", "get_policy"]


@pytest.mark.parametrize(
    "mutation",
    [
        "attached",
        "attached-second",
        "boundary",
        "boundary-second",
        "arn",
        "name",
        "default",
        "default-second",
        "document",
        "version",
        "not-default",
        "denied",
        "deleted",
    ],
)
def test_divergencia_ou_readback_ausente_impede_export_e_mutacao(mutation):
    args = original_owner()
    authority = session_owner.authenticate(*args, "plan", "bootstrap")
    with pytest.raises((ValueError, KeyError)):
        session_owner.verify_managed(
            IAMBoundary(authority.pin, mutation),
            authority,
            args[-1] + 3600,
            lambda: args[-1],
        )


def test_prova_expira_durante_readbacks_e_nao_ganha_validade_por_governanca():
    args = original_owner()
    authority = session_owner.authenticate(*args, "plan", "bootstrap")
    clock = iter([args[-1], args[-1] + 7201])
    with pytest.raises(ValueError, match="expired"):
        session_owner.verify_managed(
            IAMBoundary(authority.pin), authority, args[-1] + 3600, lambda: next(clock)
        )
