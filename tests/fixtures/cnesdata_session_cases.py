"""Independent useful permission oracles shared by pure and actual native-rendered tests."""

import copy

from fixtures.cnesdata_iam_evaluation import allowed, decision, effective
from tools.cnesdata_delivery.session_policy import (
    STATE_KEYS,
    PhaseInputScope,
    managed_arn,
    request,
)


def scopes(gov, role):
    prefix = gov["evidence_prefix"]
    bucket = "arn:aws:s3:::" + gov["evidence_bucket"]
    status = "planned" if role == "plan" else "applied"
    current = prefix + "a" * 40 + "/42448571873/1/" + status + "/"
    history = prefix + "b" * 40 + "/42448920421/1/applied/"
    inputs = prefix + "phase-inputs/" + "c" * 40 + "/42448920421/1/"
    return bucket, current, history, inputs


def inline(gov, role):
    _, _, history, inputs = scopes(gov, role)
    return request(
        gov,
        "a" * 40,
        42448571873,
        1,
        role,
        [PhaseInputScope(inputs + "*"), history + "*"],
    )


def expected_documents(gov, role):
    """Synthetic finite fixtures; actual ToFu documents are checked separately in hosted CI."""
    state_bucket = "arn:aws:s3:::" + gov["state_bucket"]
    evidence_bucket = "arn:aws:s3:::" + gov["evidence_bucket"]
    state = [state_bucket + "/" + key for key in STATE_KEYS]
    product = "arn:aws:s3:::cnesdata-product-aaaaaa"
    state_get = {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": state[0]}
    lock = {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        "Resource": state[1],
    }
    lease = {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject"],
        "Resource": state[2],
    }
    listing = {
        "Effect": "Allow",
        "Action": ["s3:ListBucket"],
        "Resource": state_bucket,
        "Condition": {"StringEquals": {"s3:prefix": list(STATE_KEYS)}},
    }
    crypto = {
        "Effect": "Allow",
        "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
        "Resource": gov["state_kms_key_arn"],
        "Condition": {
            "StringEquals": {
                "kms:ViaService": "s3.us-east-2.amazonaws.com",
                "kms:EncryptionContext:aws:s3:arn": state,
            }
        },
    }
    policy_reads = {
        "Effect": "Allow",
        "Action": ["iam:GetPolicy", "iam:GetPolicyVersion"],
        "Resource": managed_arn(gov, role),
    }
    common = [state_get, lock, lease, listing, crypto, policy_reads]
    if role == "deploy":
        common += [
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": state[0]}
        ]
    identity = copy.deepcopy(common) + [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": evidence_bucket + "/" + gov["evidence_prefix"] + "*",
        },
        {
            "Effect": "Allow",
            "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
            "Resource": gov["evidence_kms_key_arn"],
            "Condition": {
                "StringEquals": {"kms:ViaService": "s3.us-east-2.amazonaws.com"},
                "StringLike": {
                    "kms:EncryptionContext:aws:s3:arn": evidence_bucket
                    + "/"
                    + gov["evidence_prefix"]
                    + "*"
                },
            },
        },
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": evidence_bucket,
            "Condition": {"StringLike": {"s3:prefix": gov["evidence_prefix"] + "*"}},
        },
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:GetBucketObjectLockConfiguration"],
            "Resource": product,
        },
        {
            "Effect": "Deny",
            "Action": [
                "sts:AssumeRole",
                "sts:AssumeRoleWithWebIdentity",
                "sts:AssumeRoleWithSAML",
            ],
            "Resource": "*",
        },
    ]
    if role == "deploy":
        identity += [
            {
                "Effect": "Allow",
                "Action": ["s3:PutBucketObjectLockConfiguration"],
                "Resource": product,
            }
        ]
    managed = copy.deepcopy(common) + [
        {
            "Effect": "Allow",
            "NotAction": ["s3:*Object*", "s3:ListBucket*", "s3:*Multipart*", "kms:*"],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "NotResource": evidence_bucket,
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketObjectLockConfiguration",
                "s3:PutBucketObjectLockConfiguration",
            ],
            "Resource": product,
        },
        {"Effect": "Deny", "Action": ["s3:DeleteObject"], "NotResource": state[1]},
        {
            "Effect": "Deny",
            "Action": [
                "s3:*ObjectVersion*",
                "s3:*ObjectAcl",
                "s3:*ObjectTagging",
                "s3:*ObjectRetention",
                "s3:*ObjectLegalHold",
                "s3:RestoreObject",
                "s3:GetObjectAttributes",
                "s3:*Multipart*",
            ],
            "Resource": evidence_bucket + "/" + gov["evidence_prefix"] + "*",
        },
        {
            "Effect": "Deny",
            "Action": ["s3:ListBucketVersions", "s3:ListBucketMultipartUploads"],
            "Resource": evidence_bucket,
        },
        {
            "Effect": "Deny",
            "Action": ["kms:*"],
            "Resource": list(
                set([gov["state_kms_key_arn"], gov["evidence_kms_key_arn"]])
            ),
            "Condition": {
                "StringNotEquals": {"kms:ViaService": "s3.us-east-2.amazonaws.com"}
            },
        },
        {
            "Effect": "Deny",
            "Action": [
                "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion",
                "iam:DeletePolicyVersion",
                "iam:DeletePolicy",
                "iam:Attach*Policy",
                "iam:Put*PermissionsBoundary",
            ],
            "Resource": "*",
        },
    ]
    return {"Statement": identity}, {"Statement": managed}


def assert_matrix(identity, managed, policy, gov, role):
    def check(action, resource, context=None):
        return effective(identity, managed, policy, action, resource, context)

    bucket, current, history, inputs = scopes(gov, role)
    own, old, phase = [
        bucket + "/" + prefix + "envelope.json" for prefix in (current, history, inputs)
    ]
    states = ["arn:aws:s3:::" + gov["state_bucket"] + "/" + key for key in STATE_KEYS]
    assert allowed(identity, "s3:GetObject", states[0]) and allowed(
        managed, "s3:GetObject", states[0]
    )
    assert not allowed(policy, "s3:GetObject", states[0]) and check(
        "s3:GetObject", states[0]
    )
    assert not allowed(managed, "s3:GetObject", own) and allowed(
        policy, "s3:GetObject", own
    )
    assert check("s3:PutObject", states[0]) is (role == "deploy")
    for state in states:
        assert check("s3:GetObject", state)
    for state in states[1:]:
        assert check("s3:PutObject", state)
    assert check("s3:DeleteObject", states[1])
    assert not check("s3:DeleteObject", states[0]) and not check(
        "s3:DeleteObject", states[2]
    )
    for resource in (own, old, phase):
        assert check("s3:GetObject", resource)
        assert check("s3:PutObject", resource) is (resource == own)
        for action in (
            "s3:DeleteObject",
            "s3:GetObjectVersion",
            "s3:DeleteObjectVersion",
            "s3:PutObjectAcl",
            "s3:PutObjectTagging",
            "s3:GetObjectAttributes",
            "s3:ListMultipartUploadParts",
            "s3:AbortMultipartUpload",
            "s3:RestoreObject",
        ):
            assert not check(action, resource, {"s3:VersionId": "unapproved"}), (
                role,
                action,
                resource,
            )
            if action in {"s3:ListMultipartUploadParts", "s3:AbortMultipartUpload"}:
                assert decision(managed, action, resource) == "Deny"
        context = {
            "kms:ViaService": "s3.us-east-2.amazonaws.com",
            "kms:EncryptionContext:aws:s3:arn": resource,
        }
        assert check("kms:Decrypt", gov["evidence_kms_key_arn"], context)
        for action in ("kms:Encrypt", "kms:GenerateDataKey"):
            assert check(action, gov["evidence_kms_key_arn"], context) is (
                resource == own
            )
    for part in (
        current.replace("a" * 40, "d" * 40),
        current.replace("42448571873", "42448571874"),
        current.replace("/1/", "/2/"),
        current.replace("/planned/", "/other/").replace("/applied/", "/other/"),
    ):
        resource = bucket + "/" + part + "envelope.json"
        assert not check("s3:GetObject", resource) and not check(
            "s3:PutObject", resource
        )
    for state in states:
        context = {
            "kms:ViaService": "s3.us-east-2.amazonaws.com",
            "kms:EncryptionContext:aws:s3:arn": state,
        }
        for action in ("kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"):
            assert check(action, gov["state_kms_key_arn"], context)
    for key in set([gov["state_kms_key_arn"], gov["evidence_kms_key_arn"]]):
        for context in (
            {},
            {"kms:ViaService": "s3.us-east-2.amazonaws.com"},
            {
                "kms:ViaService": "s3.us-east-2.amazonaws.com",
                "kms:EncryptionContext:aws:s3:arn": bucket,
            },
            {
                "kms:ViaService": "s3.us-east-1.amazonaws.com",
                "kms:EncryptionContext:aws:s3:arn": own,
            },
        ):
            assert not check("kms:Decrypt", key, context)
    for key in STATE_KEYS:
        assert check(
            "s3:ListBucket", "arn:aws:s3:::" + gov["state_bucket"], {"s3:prefix": key}
        )
    assert not check("s3:ListBucket", bucket, {"s3:prefix": current})
    assert not check("s3:ListBucketVersions", bucket)
    assert not check("s3:ListBucketMultipartUploads", bucket)
    assert decision(managed, "s3:ListBucketMultipartUploads", bucket) == "Deny"
    product = "arn:aws:s3:::cnesdata-product-aaaaaa"
    assert check("s3:ListBucket", product, {"s3:prefix": "product/"})
    assert check("s3:GetBucketObjectLockConfiguration", product)
    assert check("s3:PutBucketObjectLockConfiguration", product) is (role == "deploy")
    assert check("iam:GetPolicy", managed_arn(gov, role)) and check(
        "iam:GetPolicyVersion", managed_arn(gov, role)
    )
    for action in (
        "sts:AssumeRole",
        "sts:AssumeRoleWithWebIdentity",
        "sts:AssumeRoleWithSAML",
    ):
        assert not check(action, "*")
    deny = copy.deepcopy(managed)
    deny["Statement"].append(
        {"Effect": "Deny", "Action": "s3:GetObject", "Resource": own}
    )
    assert not effective(identity, deny, policy, "s3:GetObject", own)
    widened = copy.deepcopy(managed)
    widened["Statement"].append(
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": old}
    )
    assert not effective(identity, widened, policy, "s3:PutObject", old)
