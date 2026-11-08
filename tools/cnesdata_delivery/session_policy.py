"""Dynamic evidence scope; static powers exist only in the own managed session policy."""

import re
from typing import Any

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.coordination_lease import KEY

STATE_KEYS = (
    "cnesdata/prod/opentofu.tfstate",
    "cnesdata/prod/opentofu.tfstate.tflock",
    KEY,
)


class PhaseInputScope(str):
    """Internal output of the original-owner grouping validator, never a JSON input."""


def managed_arn(governance, role):
    c.require(role in {"plan", "deploy"}, "session role")
    account = governance["account_id"]
    c.require(
        type(account) is str and re.fullmatch(r"[0-9]{12}", account), "session account"
    )
    role_arn = governance["roles"][role]
    c.require(
        re.fullmatch(
            rf"arn:aws:iam::{account}:role/cnesdata-[a-z0-9-]+-{role}", role_arn
        ),
        "deterministic governed session role",
    )
    return f"arn:aws:iam::{account}:policy/{role_arn.rsplit('/', 1)[1]}-session"


def _prefix(governance):
    prefix = governance["evidence_prefix"]
    c.require(
        type(prefix) is str
        and prefix.startswith("cnesdata/prod/")
        and ".." not in prefix
        and re.fullmatch(r"[A-Za-z0-9_./-]+", prefix),
        "session evidence namespace",
    )
    return prefix.rstrip("/") + "/"


def _reads(prefix: str, read_keys: list[str]) -> list[str]:
    c.require(
        type(read_keys) is list and len(read_keys) <= 64,
        "bounded exact historical reads",
    )
    for key in read_keys:
        exact = isinstance(key, str) and key.startswith(prefix) and ".." not in key
        wildcard = (
            re.escape(prefix)
            + r"[0-9a-f]{40}/[1-9][0-9]*/[1-9][0-9]*/(?:planned|applied)/\*"
        )
        grouped = type(key) is PhaseInputScope and re.fullmatch(
            re.escape(prefix) + r"phase-inputs/[0-9a-f]{40}/[1-9][0-9]*/[1-9][0-9]*/\*",
            key,
        )
        c.require(
            exact
            and (
                re.fullmatch(r"[A-Za-z0-9_./-]+", key)
                or re.fullmatch(wildcard, key)
                or grouped
            ),
            "exact read or authenticated run scope",
        )
    return sorted(set(read_keys))


def _encode(governance, role, statements):
    encoded = c.canonical({"Version": "2012-10-17", "Statement": statements})[
        :-1
    ].decode()
    arns = [{"arn": managed_arn(governance, role)}]
    c.require(
        len(arns) <= 10
        and encoded.isascii()
        and len(encoded) + sum(len(item["arn"]) for item in arns) <= 2048,
        "STS inline plus managed session policy exceeds 2048 characters; reviewed recovery required",
    )
    return encoded


def build(governance, source, run_id, attempt, role, read_keys):
    c.digest(source, 40)
    c.integer(run_id)
    c.integer(attempt)
    managed_arn(governance, role)
    prefix = _prefix(governance)
    bucket = governance["evidence_bucket"]
    c.require(
        type(bucket) is str
        and re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket),
        "session bucket name",
    )
    bucket_arn = "arn:aws:s3:::" + bucket
    own = (
        bucket_arn
        + "/"
        + prefix
        + f"{source}/{run_id}/{attempt}/{'planned' if role == 'plan' else 'applied'}/*"
    )
    historical = [bucket_arn + "/" + key for key in _reads(prefix, read_keys)]
    c.require(
        not any(
            item.startswith(own[:-1]) or own.startswith(item.removesuffix("*"))
            for item in historical
        ),
        "historical/current scope overlap",
    )
    key_arn = governance["evidence_kms_key_arn"]
    c.require(
        re.fullmatch(
            rf"arn:aws:kms:us-east-2:{governance['account_id']}:key/"
            r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",
            key_arn,
        ),
        "session evidence CMK",
    )
    read = [own, *historical]
    statements = [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": read},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": own},
        {
            "Effect": "Allow",
            "Action": "kms:Decrypt",
            "Resource": key_arn,
            "Condition": {"StringLike": {"kms:EncryptionContext:aws:s3:arn": read}},
        },
        {
            "Effect": "Allow",
            "Action": ["kms:Encrypt", "kms:GenerateDataKey"],
            "Resource": key_arn,
            "Condition": {"StringLike": {"kms:EncryptionContext:aws:s3:arn": own}},
        },
    ]
    if historical:
        statements.append(
            {"Effect": "Deny", "Action": "s3:PutObject", "Resource": historical}
        )
    return _encode(governance, role, statements)


def request(governance, source, run_id, attempt, role, read_keys):
    return {
        "Policy": build(governance, source, run_id, attempt, role, read_keys),
        "PolicyArns": [{"arn": managed_arn(governance, role)}],
    }


def validate_response(response: dict[str, Any]) -> dict[str, Any]:
    c.require(
        type(response) is dict
        and type(response.get("PackedPolicySize")) is int
        and 0 <= response["PackedPolicySize"] <= 100,
        "STS packed policy utilization",
    )
    if "SessionTokenUtilization" in response:
        c.require(
            type(response["SessionTokenUtilization"]) is int
            and 0 <= response["SessionTokenUtilization"] <= 100,
            "STS token utilization",
        )
    return response["Credentials"]
