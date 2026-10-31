"""Gramática fechada dos documentos e referências estáticas v2."""

from collections.abc import Callable, Mapping
import re
from typing import Any

from tools.aws_bootstrap.catalog import CATALOG

Validator = Callable[[Any], bool]


def text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def enum(*values: str) -> Validator:
    return lambda value: text(value) and value in values


def pattern(expression: str) -> Validator:
    return lambda value: text(value) and re.fullmatch(expression, value) is not None


def nullable(validator: Validator) -> Validator:
    return lambda value: value is None or validator(value)


def ordered_sequence(validator: Validator) -> Validator:
    return lambda value: isinstance(value, (list, tuple)) and all(map(validator, value))


def sequence(validator: Validator) -> Validator:
    return lambda value: (
        isinstance(value, (list, tuple))
        and all(
            validator(child) and child not in value[:index] for index, child in enumerate(value)
        )
    )


def nonempty_sequence(validator: Validator) -> Validator:
    return lambda value: bool(value) and sequence(validator)(value)


def mapping(key: Validator, child: Validator) -> Validator:
    return lambda value: (
        isinstance(value, Mapping)
        and all(key(name) and child(item) for name, item in value.items())
    )


def record(
    fields: Mapping[str, Validator],
    optional: Mapping[str, Validator] | None = None,
) -> Validator:
    options = {} if optional is None else optional

    def validate(value: Any) -> bool:
        return (
            isinstance(value, Mapping)
            and set(fields) <= set(value) <= (set(fields) | set(options))
            and all(validator(value[name]) for name, validator in fields.items())
            and all(options[name](value[name]) for name in set(value) - set(fields))
        )

    return validate


DIGEST = pattern(r"[0-9a-f]{64}")
SOURCE = pattern(r"[0-9a-f]{40}")
ROOT = enum(*CATALOG)
IAM_ADDRESSES = {
    root: frozenset(
        address
        for address in addresses
        if address.split(".")[0]
        in (
            "aws_iam_role",
            "aws_iam_policy",
        )
    )
    for root, addresses in CATALOG.items()
}
DOCUMENT_TYPES = frozenset(
    (
        "aws_iam_role",
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_kms_key",
        "aws_s3_bucket_policy",
    )
)
POLICY_ADDRESSES = {
    root: frozenset(
        address
        for address in addresses
        if address.split(".")[0] in (DOCUMENT_TYPES | {"aws_iam_user_policy_attachment"})
    )
    for root, addresses in CATALOG.items()
}
CONFIGURED = record(
    {
        "kind": enum("configured"),
        "root_id": ROOT,
        "address": text,
        "attribute": enum("arn"),
    }
)
EXTERNAL = record(
    {
        "kind": enum("external"),
        "source_id": text,
        "exact_arn": text,
        "observation_sha256": DIGEST,
    }
)
PROVIDER_SLOT = record(
    {
        "kind": enum("provider_slot"),
        "root_id": enum("foundation"),
        "address": enum("aws_kms_key.foundation"),
        "attribute": enum("arn"),
    }
)


def configured(value: Any) -> bool:
    return CONFIGURED(value) and value["address"] in IAM_ADDRESSES[value["root_id"]]


def arn_term(value: Any) -> bool:
    return text(value) or configured(value) or EXTERNAL(value) or PROVIDER_SLOT(value)


def literals(value: Any) -> bool:
    return text(value) or nonempty_sequence(text)(value)


def resources(value: Any) -> bool:
    return arn_term(value) or nonempty_sequence(arn_term)(value)


def principal(value: Any) -> bool:
    return (
        value == "*"
        or bool(value)
        and mapping(enum("AWS", "Service", "Federated"), literals)(value)
    )


CONDITIONS = mapping(
    enum(
        "StringEquals",
        "StringLike",
        "ArnEquals",
        "ArnLike",
        "Bool",
        "Null",
        "ForAllValues:StringEquals",
    ),
    mapping(text, literals),
)
STATEMENT = record(
    {"Effect": enum("Allow", "Deny"), "Action": literals},
    {"Sid": text, "Condition": CONDITIONS, "Resource": resources, "Principal": principal},
)


def statement(value: Any) -> bool:
    return STATEMENT(value) and bool({"Resource", "Principal"} & set(value))


DOCUMENT = record({"Version": enum("2012-10-17"), "Statement": sequence(statement)})
POLICY_TEMPLATES = record(
    {
        root: record(
            {
                address: sequence(DOCUMENT)
                if address.startswith("aws_iam_user_policy_attachment.")
                else nonempty_sequence(DOCUMENT)
                for address in addresses
            }
        )
        for root, addresses in POLICY_ADDRESSES.items()
    }
)


def policy_templates(value: Any) -> bool:
    return (
        POLICY_TEMPLATES(value)
        and not (value["foundation"]["aws_iam_user_policy_attachment.local_login"])
    )


def iam_path(address: str) -> Validator:
    expression = r"/(?:[A-Za-z0-9_+=,.@-]+/)*"
    if address.startswith("aws_iam_role."):
        expression = r"/(?:[\x21-\x7e]+/)?"
    validate = pattern(expression)
    return lambda value: (
        validate(value) and all(part not in (".", "..") for part in value.split("/"))
    )


CONFIGURED_PATHS = record(
    {
        root: record({address: iam_path(address) for address in addresses})
        for root, addresses in IAM_ADDRESSES.items()
    }
)
POLICY_DIGESTS = record(
    {root: record(dict.fromkeys(addresses, DIGEST)) for root, addresses in POLICY_ADDRESSES.items()}
)
