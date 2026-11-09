"""Independent synthetic delivery-root inventory/oracles, never cloud evidence."""

import copy
from fnmatch import fnmatchcase
import json
import shutil
import subprocess
from pathlib import Path

from . import ACCOUNT, KEY, KEYS, PIN, SIGNING_KEY, UNTIL
from fixtures.cnesdata_delivery_roles_anywhere.native import Native

ROOT = Path(__file__).resolve().parents[3]
ROLE = f"arn:aws:iam::{ACCOUNT}:role/cnesdata-delivery-ext2-gate"
ALIAS = "alias/cnesdata-delivery-ext2-signing"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
FOUR = {
    "aws_iam_role.ext2_gate[0]",
    "aws_iam_role_policy.ext2_gate[0]",
    "aws_kms_key.ext2_signing[0]",
    "aws_kms_alias.ext2_signing[0]",
}
ADMIN = [
    "kms:DescribeKey",
    "kms:GetKeyPolicy",
    "kms:PutKeyPolicy",
    "kms:GetPublicKey",
    "kms:EnableKey",
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion",
    "kms:TagResource",
    "kms:UntagResource",
]


def variables(enabled=True):
    bucket = "arn:aws:s3:::synthetic-ext2-evidence"
    return {
        "account_id": ACCOUNT,
        "region": "us-east-2",
        "activation_enabled": False,
        "ca_certificate_pem": (
            ROOT / "tests/fixtures/cnesdata_delivery_roles_anywhere/ca.crt"
        ).read_text(),
        "identity": {
            "trust_anchor_name": "synthetic-cnesdata-ca",
            "role_name": "synthetic-cnesdata-api",
            "profile_name": "synthetic-cnesdata-api",
            "common_name": "synthetic-cnesdata-api",
            "san_uri": "spiffe://synthetic.invalid/cnesdata/api",
            "duration_seconds": 900,
        },
        "github_delivery": {
            "provider_arn": PROVIDER,
            "provider_client_ids": ["sts.amazonaws.com"],
            "provider_thumbprints": ["c" * 40],
            "plan_role_name": "cnesdata-synthetic-plan",
            "deploy_role_name": "cnesdata-synthetic-deploy",
            "plan_workflow_sha": "d" * 40,
            "deploy_workflow_sha": "e" * 40,
            "enabled_until": UNTIL,
            "state_bucket_arn": "arn:aws:s3:::synthetic-state",
            "state_kms_arn": KEY,
            "evidence_bucket_arn": bucket,
            "evidence_kms_arn": KEY,
            "evidence_prefix": "cnesdata/prod/ext1/",
            "read_resource_arns": [],
            "product_permissions": [],
            "pass_roles": [],
        },
        "ext2_enabled": enabled,
        "ext2": {
            "workflow_sha": PIN,
            "enabled_until": UNTIL,
            "retain_until": UNTIL,
            "admin_arns": [f"arn:aws:iam::{ACCOUNT}:role/synthetic-delivery-operator"],
            "bucket_arn": bucket,
            "cipher_kms_key_arn": KEY,
            "current_object_arns": [bucket + "/" + key for key in KEYS],
            "history_object_arns": [
                bucket + "/cnesdata/prod/ext2/history/original.json"
            ],
        },
    }


def trust(v):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": PROVIDER},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:sub": "repo:VINIClUS/CnesData:environment:production:job_workflow_ref:VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-signing-gate.yml@"
                        + v["ext2"]["workflow_sha"],
                    }
                },
            }
        ],
    }


def key_policy(v):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "OwnerAdministration",
                "Effect": "Allow",
                "Principal": {"AWS": v["ext2"]["admin_arns"]},
                "Action": ADMIN,
                "Resource": "*",
            },
            {
                "Sid": "GateRead",
                "Effect": "Allow",
                "Principal": {"AWS": ROLE},
                "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:GetKeyPolicy"],
                "Resource": "*",
            },
            {
                "Sid": "GateSign",
                "Effect": "Allow",
                "Principal": {"AWS": ROLE},
                "Action": "kms:Sign",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "kms:SigningAlgorithm": "ECDSA_SHA_256",
                        "kms:MessageType": "DIGEST",
                    },
                    "DateLessThan": {"aws:CurrentTime": v["ext2"]["enabled_until"]},
                },
            },
        ],
    }


def policy(v):
    x = v["ext2"]
    current, objects = (
        x["current_object_arns"],
        x["current_object_arns"] + x["history_object_arns"],
    )
    time = {"aws:CurrentTime": x["enabled_until"]}
    retention = {
        "StringEquals": {"s3:object-lock-mode": "COMPLIANCE"},
        "DateEquals": {"s3:object-lock-retain-until-date": x["retain_until"]},
        "DateLessThan": time,
    }
    put = copy.deepcopy(retention)
    put["StringEquals"].update(
        {
            "s3:x-amz-server-side-encryption": "aws:kms",
            "s3:x-amz-server-side-encryption-aws-kms-key-id": x["cipher_kms_key_arn"],
        }
    )
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
                "Resource": objects,
            },
            {
                "Effect": "Deny",
                "Action": "s3:ListBucketMultipartUploads",
                "Resource": x["bucket_arn"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObjectVersion", "s3:GetObjectRetention"],
                "Resource": objects,
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetEncryptionConfiguration",
                    "s3:GetBucketVersioning",
                    "s3:GetBucketObjectLockConfiguration",
                ],
                "Resource": x["bucket_arn"],
            },
            {
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": current,
                "Condition": put,
            },
            {
                "Effect": "Allow",
                "Action": "s3:PutObjectRetention",
                "Resource": current,
                "Condition": retention,
            },
            {
                "Effect": "Allow",
                "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:GetKeyPolicy"],
                "Resource": SIGNING_KEY,
            },
            {
                "Effect": "Allow",
                "Action": "kms:Sign",
                "Resource": SIGNING_KEY,
                "Condition": {
                    "StringEquals": {
                        "kms:SigningAlgorithm": "ECDSA_SHA_256",
                        "kms:MessageType": "DIGEST",
                    },
                    "DateLessThan": time,
                },
            },
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": x["cipher_kms_key_arn"],
                "Condition": {
                    "StringEquals": {
                        "kms:ViaService": "s3.us-east-2.amazonaws.com",
                        "kms:EncryptionContext:aws:s3:arn": objects,
                    }
                },
            },
            {
                "Effect": "Allow",
                "Action": "kms:GenerateDataKey",
                "Resource": x["cipher_kms_key_arn"],
                "Condition": {
                    "StringEquals": {
                        "kms:ViaService": "s3.us-east-2.amazonaws.com",
                        "kms:EncryptionContext:aws:s3:arn": current,
                    },
                    "DateLessThan": time,
                },
            },
        ],
    }


class Ext2Native(Native):
    def run(self, directory, *args):
        if args[0] == "test":
            path = directory / "contract.tftest.hcl"
            text = path.read_text()
            text += """
override_resource {
  target = aws_iam_role.ext2_gate[0]
  values = { id = "cnesdata-delivery-ext2-gate", arn = "ROLE" }
}
override_resource {
  target = aws_kms_key.ext2_signing[0]
  values = { id = "00000000-0000-4000-8000-000000000002", key_id = "00000000-0000-4000-8000-000000000002", arn = "KEY" }
}
""".replace("ROLE", ROLE).replace("KEY", SIGNING_KEY)
            text = text.replace(
                'mock_provider "aws" {',
                """mock_provider "aws" {
  mock_resource "aws_kms_key" { defaults = { region = "us-east-2" } }
  mock_resource "aws_kms_alias" { defaults = { region = "us-east-2", target_key_arn = "SIGNING", arn = "arn:aws:kms:us-east-2:111122223333:alias/cnesdata-delivery-ext2-signing", id = "alias/cnesdata-delivery-ext2-signing" } }
  mock_data "aws_iam_openid_connect_provider" {
    defaults = { url = "token.actions.githubusercontent.com", client_id_list = ["sts.amazonaws.com"], thumbprint_list = ["THUMB"] }
  }""".replace("PROVIDER", PROVIDER)
                .replace("THUMB", "c" * 40)
                .replace("SIGNING", SIGNING_KEY),
            )
            for name in ("plan", "deploy"):
                role_name = "cnesdata-synthetic-" + name
                text += (
                    '\noverride_resource {\n target = aws_iam_role.delivery["'
                    + name
                    + '"]\n values = { id = "'
                    + role_name
                    + '", arn = "arn:aws:iam::'
                    + ACCOUNT
                    + ":role/"
                    + role_name
                    + '" }\n}\n'
                )
                text += (
                    '\noverride_resource {\n target = aws_iam_policy.delivery_session["'
                    + name
                    + '"]\n values = { arn = "arn:aws:iam::'
                    + ACCOUNT
                    + ":policy/"
                    + role_name
                    + '-session" }\n}\n'
                )
            path.write_text(text)
        return super().run(directory, *args)


def values(plan):
    return {
        r["address"]: r["values"]
        for r in plan["planned_values"]["root_module"]["resources"]
        if r["mode"] == "managed"
    }


def raw_state(resources, serial):
    rows = []
    for address, attrs in resources.items():
        base, _, index = address.partition("[")
        kind, name = base.split(".")
        instance = {"schema_version": 0, "attributes": copy.deepcopy(attrs)}
        if index:
            instance["index_key"] = json.loads(index[:-1])
        rows.append(
            {
                "mode": "managed",
                "type": kind,
                "name": name,
                "provider": 'provider["registry.opentofu.org/hashicorp/aws"]',
                "instances": [instance],
            }
        )
    return {
        "version": 4,
        "terraform_version": "1.13.2",
        "serial": serial,
        "lineage": "00000000-0000-4000-8000-000000000029",
        "outputs": {},
        "resources": rows,
    }


def inventory_case(native, enabled=True):
    from . import canonical, sha
    from tools.cnesdata_delivery.ext2_inventory import _SavedPlan

    v = variables(enabled)
    code, plans, errors = native.plan(
        v, "ext2-four" if enabled else "ext2-disabled-inventory"
    )
    assert code == 0, errors
    plan = copy.deepcopy(plans[0])
    resources = values(plan)
    prior = {a: r for a, r in resources.items() if a not in FOUR}
    for row in plan["resource_changes"]:
        if row["mode"] == "managed" and row["address"] in prior:
            row["change"]["actions"] = ["no-op"]
            row["change"]["before"] = copy.deepcopy(row["change"]["after"])
    before, after = raw_state(prior, 1), raw_state(resources, 2 if enabled else 1)
    if enabled:
        after["outputs"]["ext2"] = copy.deepcopy(
            plan["planned_values"]["outputs"]["ext2"]
        )
    paths = [
        p
        for p in (ROOT / "opentofu/cnesdata-delivery").iterdir()
        if p.suffix == ".tf" or p.name == ".terraform.lock.hcl"
    ]
    head = {str(p.relative_to(ROOT)): p.read_bytes() for p in paths}
    base = {}
    for path in head:
        if path.endswith(("signing.tf", "evidence.tf")):
            continue
        base[path] = subprocess.run(
            [
                "rtk",
                "proxy",
                "git",
                "show",
                "99fc0e4805b96fbca7df06440d5ea3ad42e53369:" + path,
            ],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout
    binary = b"explicitly synthetic saved plan; never an apply artifact"
    gov = {
        "root": "opentofu/cnesdata-delivery",
        "state_key": "shared/cnesdata-delivery/prod/opentofu.tfstate",
        "base_sha": "99fc0e4805b96fbca7df06440d5ea3ad42e53369",
        "source_sha": PIN,
        "base_sources": {p: sha(b) for p, b in base.items()},
        "sources": {p: sha(b) for p, b in head.items()},
        "plan_sha256": sha(binary),
        "plan_json_sha256": sha(canonical(plan)),
        "inputs_sha256": sha(canonical(v)),
        "before_sha256": sha(canonical(before)),
        "after_sha256": sha(canonical(after)),
        "spki_sha256": sha(b"synthetic-SPKI"),
        "tofu_sha256": sha(Path(shutil.which("tofu")).read_bytes()),
    }
    return {
        "source_blobs": {"base": base, "head": head},
        # Explicit offline decoder double, never a real apply artifact.
        "saved_plan": _SavedPlan(binary, plan, gov["tofu_sha256"]),
        "generated_inputs": v,
        "state_before": before,
        "state_after": after,
        "governance": gov,
    }


def rebind(case):
    """Re-authenticate mutated operator inputs; semantics must still reject them."""
    from . import canonical, sha

    g = case["governance"]
    g["plan_json_sha256"] = sha(canonical(case["saved_plan"]["json"]))
    g["before_sha256"] = sha(canonical(case["state_before"]))
    g["after_sha256"] = sha(canonical(case["state_after"]))
    from tools.cnesdata_delivery.ext2_inventory import _SavedPlan

    # Models a new operator decode for semantic tests, never a caller bypass.
    case["saved_plan"] = _SavedPlan(
        case["saved_plan"]["binary"], case["saved_plan"]["json"], g["tofu_sha256"]
    )


class InventoryAPI:
    """SDK-shaped read-only double; response mutations do not change source oracles."""

    def __init__(self, case):
        self.resources = {}
        self.calls, self.covered, self.mutation = [], set(), None
        for row in case["state_after"]["resources"]:
            for item in row["instances"]:
                address = row["type"] + "." + row["name"]
                if "index_key" in item:
                    address += "[" + json.dumps(item["index_key"]) + "]"
                self.resources[address] = copy.deepcopy(item["attributes"])

    def find(self, kind, field, value):
        found = [
            (a, r)
            for a, r in self.resources.items()
            if a.startswith(kind + ".") and r[field] == value
        ]
        assert len(found) == 1, (kind, field, value, found)
        self.covered.add(found[0][0])
        return found[0][1]

    def get_role(self, **kw):
        self.calls.append(("get_role", kw))
        r = self.find("aws_iam_role", "name", kw["RoleName"])
        trust = json.loads(r["assume_role_policy"])
        if self.mutation == "prior-readback" and r["name"] == "synthetic-cnesdata-api":
            trust["Statement"] = []
        return {
            "Role": {
                "RoleName": r["name"],
                "Arn": r["arn"],
                "Path": r.get("path") or "/",
                "MaxSessionDuration": r["max_session_duration"],
                "AssumeRolePolicyDocument": trust,
            }
        }

    def list_role_policies(self, **kw):
        self.calls.append(("list_role_policies", kw))
        names = [
            r["name"]
            for a, r in self.resources.items()
            if a.startswith("aws_iam_role_policy.") and r["role"] == kw["RoleName"]
        ]
        if self.mutation == "extra-inline":
            names.append("untracked-policy")
        return {"IsTruncated": False, "PolicyNames": names}

    def list_attached_role_policies(self, **kw):
        self.calls.append(("list_attached_role_policies", kw))
        return {
            "IsTruncated": False,
            "AttachedPolicies": [{"PolicyArn": "foreign"}]
            if self.mutation == "extra-attached"
            else [],
        }

    def get_role_policy(self, **kw):
        self.calls.append(("get_role_policy", kw))
        found = [
            (a, r)
            for a, r in self.resources.items()
            if a.startswith("aws_iam_role_policy.")
            and r["role"] == kw["RoleName"]
            and r["name"] == kw["PolicyName"]
        ]
        assert len(found) == 1
        self.covered.add(found[0][0])
        return kw | {"PolicyDocument": json.loads(found[0][1]["policy"])}

    def get_policy(self, **kw):
        self.calls.append(("get_policy", kw))
        r = self.find("aws_iam_policy", "arn", kw["PolicyArn"])
        return {
            "Policy": {
                "Arn": r["arn"],
                "PolicyName": r["name"],
                "DefaultVersionId": "v1",
                "AttachmentCount": 0,
                "PermissionsBoundaryUsageCount": 0,
            }
        }

    def get_policy_version(self, **kw):
        self.calls.append(("get_policy_version", kw))
        r = self.find("aws_iam_policy", "arn", kw["PolicyArn"])
        return {
            "PolicyVersion": {
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "Document": json.loads(r["policy"]),
            }
        }

    def get_trust_anchor(self, **kw):
        self.calls.append(("get_trust_anchor", kw))
        r = self.find("aws_rolesanywhere_trust_anchor", "id", kw["trustAnchorId"])
        return {
            "trustAnchor": {
                "trustAnchorId": r["id"],
                "trustAnchorArn": r["arn"],
                "name": r["name"],
                "enabled": r["enabled"],
                "source": {
                    "sourceType": r["source"][0]["source_type"],
                    "sourceData": {
                        "x509CertificateData": r["source"][0]["source_data"][0][
                            "x509_certificate_data"
                        ]
                    },
                },
            }
        }

    def get_profile(self, **kw):
        self.calls.append(("get_profile", kw))
        r = self.find("aws_rolesanywhere_profile", "id", kw["profileId"])
        return {
            "profile": {
                "profileId": r["id"],
                "profileArn": r["arn"],
                "name": r["name"],
                "enabled": r["enabled"],
                "durationSeconds": r["duration_seconds"],
                "roleArns": r["role_arns"],
                "acceptRoleSessionName": r["accept_role_session_name"],
                "managedPolicyArns": [],
                "requireInstanceProperties": False,
            }
        }

    def describe_key(self, **kw):
        self.calls.append(("describe_key", kw))
        if kw["KeyId"].startswith("alias/"):
            r = self.find("aws_kms_alias", "name", kw["KeyId"])
            target = r["target_key_id"]
            key = next(
                r for a, r in self.resources.items() if a.startswith("aws_kms_key.")
            )
            return {"KeyMetadata": {"KeyId": target, "Arn": key["arn"]}}
        r = self.find("aws_kms_key", "arn", kw["KeyId"])
        return {
            "KeyMetadata": {
                "KeyId": r["key_id"],
                "Arn": r["arn"],
                "AWSAccountId": ACCOUNT,
                "KeyUsage": "SIGN_VERIFY",
                "KeySpec": "ECC_NIST_P256",
                "Origin": "AWS_KMS",
                "Enabled": True,
                "KeyState": "Disabled" if self.mutation == "key-state" else "Enabled",
                "MultiRegion": False,
                "SigningAlgorithms": ["ECDSA_SHA_256"],
            }
        }

    def get_key_policy(self, **kw):
        self.calls.append(("get_key_policy", kw))
        return {"Policy": self.find("aws_kms_key", "arn", kw["KeyId"])["policy"]}

    def get_public_key(self, **kw):
        self.calls.append(("get_public_key", kw))
        return {
            "KeyId": kw["KeyId"],
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "ECC_NIST_P256",
            "SigningAlgorithms": ["ECDSA_SHA_256"],
            "PublicKey": b"foreign-SPKI"
            if self.mutation == "spki"
            else b"synthetic-SPKI",
        }


def decision(policy, action, resource, context, principal=None):
    """Small independent policy oracle; unsupported syntax is an assertion failure."""
    result = "implicit"
    for s in policy["Statement"]:
        assert set(s) <= {
            "Sid",
            "Effect",
            "Action",
            "Resource",
            "Condition",
            "Principal",
        }
        actions = [s["Action"]] if isinstance(s["Action"], str) else s["Action"]
        resources = [s["Resource"]] if isinstance(s["Resource"], str) else s["Resource"]
        if not any(fnmatchcase(action.lower(), a.lower()) for a in actions) or not any(
            fnmatchcase(resource, r) for r in resources
        ):
            continue
        if "Principal" in s:
            principals = s["Principal"]["AWS"]
            if principal not in (
                [principals] if isinstance(principals, str) else principals
            ):
                continue
        matched = True
        for op, entries in s.get("Condition", {}).items():
            assert op in {"StringEquals", "StringLike", "DateEquals", "DateLessThan"}
            for key, expected in entries.items():
                actual = context.get(key)
                choices = [expected] if isinstance(expected, str) else expected
                matched &= actual is not None and any(
                    actual < value
                    if op == "DateLessThan"
                    else fnmatchcase(actual, value)
                    if op == "StringLike"
                    else actual == value
                    for value in choices
                )
        if matched:
            if s["Effect"] == "Deny":
                return "deny"
            result = "allow"
    return result
