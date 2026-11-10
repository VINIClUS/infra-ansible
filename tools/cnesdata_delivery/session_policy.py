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
LIFECYCLE_DELETES = ["states:DeleteStateMachine", "scheduler:DeleteSchedule", "scheduler:DeleteScheduleGroup",
                     "events:DeleteRule", "cloudwatch:DeleteAlarms"]


def predecessor_keys(governance, selector):
    """The reviewed historical union derives keys; a caller never supplies paths."""
    c.closed(selector, "protocol source_sha run_id run_attempt status purpose")
    c.digest(selector["source_sha"], 40)
    c.integer(selector["run_id"])
    c.integer(selector["run_attempt"])
    protocol, status, purpose = (selector[k] for k in ("protocol", "status", "purpose"))
    if protocol == "legacy-infra":
        c.require(status in {"planned", "applied"} and purpose in c.PURPOSES, "original legacy history selector")
        names = ["envelope.json", "lease.json", "checkpoint.json"]
        if status == "applied":
            names += ["drift.json"] + (["ecr-before.json"] if purpose == "phase-a" else [])
    else:
        c.require(protocol == "lifecycle" and status == "terminal" and purpose == "application", "original lifecycle history selector")
        names = ["terminal.json", "lease.json", "checkpoint.json"]
    prefix = _prefix(governance) + ("lifecycle/" if protocol == "lifecycle" else "")
    prefix += f"{selector['source_sha']}/{selector['run_id']}/{selector['run_attempt']}/{status}/"
    return [prefix + name for name in names]


def predecessor_policy(governance, selector):
    """Original H4 policy derived independently of the private output digest."""
    arns = ["arn:aws:s3:::" + governance["evidence_bucket"] + "/" + key
            for key in predecessor_keys(governance, selector)]
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": arns},
        {"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": governance["evidence_kms_key_arn"],
         "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-2.amazonaws.com",
                                        "kms:EncryptionContext:aws:s3:arn": arns}}},
    ]}


def lifecycle_request(governance, source, run_id, attempt, role, step, *, direction, delete_resources=(), predecessor=None):
    """Same-run evidence, read-only original lease, exact inverse resources.

    The existing managed policy supplies state/provider permissions; explicit
    inline Denies apply to their union, including when product policy allows it.
    Never silently compress an over-quota list into wildcard authorization.
    """
    c.digest(source, 40)
    c.integer(run_id)
    c.integer(attempt)
    c.require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", step) and direction in {"advance", "converge"}, "lifecycle session step")
    base = "arn:aws:s3:::" + governance["evidence_bucket"] + "/" + _prefix(governance)
    run = base + f"lifecycle/{source}/{run_id}/{attempt}/"
    own = run + step + "/*"
    key = governance["evidence_kms_key_arn"]
    statements = [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": run + "*"},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": own},
        # KMS has the same run boundary; S3 PutObject still limits writes to own step.
        {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], "Resource": key,
         "Condition": {"StringLike": {"kms:EncryptionContext:aws:s3:arn": run + "*"}}},
        {"Effect": "Deny", "Action": ["s3:PutObject", "s3:DeleteObject"],
         "Resource": "arn:aws:s3:::" + governance["state_bucket"] + "/" + KEY},
    ]
    if predecessor is not None:
        c.require(role == "plan" and direction == "advance"
                  and (predecessor["run_id"], predecessor["run_attempt"]) != (run_id, attempt), "first plan distinct historical owner")
        keys = predecessor_keys(governance, predecessor)
        checkpoint = next(k for k in keys if k.endswith("/checkpoint.json"))
        arn = "arn:aws:s3:::" + governance["evidence_bucket"] + "/" + checkpoint
        statements += [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": arn},
            {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key,
             "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": arn}}},
        ]
    if direction == "advance" or role == "plan":
        c.require(not delete_resources, "advance/read session cannot delete")
        statements.append({"Effect": "Deny", "Action": LIFECYCLE_DELETES, "Resource": "*"})
    else:
        c.require(type(delete_resources) in (list, tuple) and 0 < len(delete_resources) <= 8
                  and len(set(delete_resources)) == len(delete_resources), "inverse exact resource inventory")
        for arn in delete_resources:
            c.require(re.fullmatch(r"arn:aws:(?:states|scheduler|events|cloudwatch):us-east-2:"
                                  + re.escape(governance["account_id"]) + r":[A-Za-z0-9_./:-]+", arn)
                      and "cnesdata-prod" in arn, "inverse exact same-product ARN")
        statements.append({"Effect": "Deny", "Action": LIFECYCLE_DELETES, "NotResource": list(delete_resources)})
    return {"Policy": _encode(governance, role, statements), "PolicyArns": [{"arn": managed_arn(governance, role)}]}


def application_request(governance, source, run_id, attempt, step, *, application_purpose, delegations=(), sessions=None):
    """Keeper can coordinate/read history; operation sessions cannot write lease.

    The separately authenticated own managed policy holds only static permissions
    and the one exact predecessor inventory. It never grants lifecycle evidence
    access; the inline policy supplies only this run and its own output step.
    Session names are protected dispatcher outputs after context/prepare checks,
    never product API arguments. This scope alone is not a prepare receipt.
    """
    c.digest(source, 40)
    c.integer(run_id)
    c.integer(attempt)
    c.require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", step), "application session step")
    from tools.cnesdata_delivery import lifecycle_contract as lc
    c.require(application_purpose in lc.APPLICATION_CONTEXTS, "closed application purpose")
    keeper = step == "keeper"
    c.require(type(delegations) in (list, tuple) and len(set(delegations)) == len(delegations)
              and set(delegations) <= set(lc.APPLICATION_DELEGATIONS),
              "closed application delegation")
    c.require(not keeper or not delegations, "keeper cannot assume product roles")
    c.require(type(sessions) is dict and set(sessions) == set(delegations) if delegations else sessions in (None, {}),
              "exact protected delegation sessions required")
    if application_purpose == "mode-readiness-drill":
        c.require(set(delegations) <= {"mode_seed", "mode_dispatch", "mode_observe"}, "readiness has no static/fence/audit-launch authority")
    for alias in delegations:
        name = sessions[alias]
        c.require(type(name) is str, "protected delegation session name")
        if alias.startswith("mode_"):
            codes = [code for code, role, context, _ in lc.MODE_SESSION_OPERATIONS.values()
                     if role == alias and context == lc.APPLICATION_CONTEXTS[application_purpose]]
            c.require(any(re.fullmatch("mc-" + code + r"-[0-9a-f]{40}", name) for code in codes), "nominal exact mode session")
        else:
            patterns = {"observer": r"sp-i-[0-9a-f]{40}", "normal": r"sp-(?:publish|retire)-[0-9a-f]{40}",
                        "recovery": r"sp-(?:rollback|readback|abort)-[0-9a-f]{40}",
                        "seeder": r"canary-seeder-[A-Za-z0-9][A-Za-z0-9_.-]{0,31}",
                        "verifier": r"canary-verifier-[A-Za-z0-9][A-Za-z0-9_.-]{0,31}",
                        "fence_operator": r"promotion-fence-[A-Za-z0-9][A-Za-z0-9_.-]{0,31}"}
            c.require(re.fullmatch(patterns[alias], name), "nominal exact original session")
    run = "arn:aws:s3:::" + governance["evidence_bucket"] + "/" + _prefix(governance) + f"lifecycle/{source}/{run_id}/{attempt}/"
    lease = "arn:aws:s3:::" + governance["state_bucket"] + "/" + KEY
    own = [run + name + "/*" for name in (("keeper", "terminal") if keeper else (step,))]
    statements = [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": run + "*"},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": own},
        {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
         "Resource": governance["evidence_kms_key_arn"], "Condition": {"StringLike": {"kms:EncryptionContext:aws:s3:arn": run + "*"},
                                                                     "StringEquals": {"kms:ViaService": "s3.us-east-2.amazonaws.com"}}},
    ]
    if delegations:
        roles = governance["application_delegations"]
        selected = [roles[name] for name in delegations]
        c.require(all(roles[name] == "arn:aws:iam::" + governance["account_id"] + ":role/cnesdata-prod-" + lc.APPLICATION_DELEGATIONS[name]
                      for name in delegations), "exact governed product roles")
        statements.append({"Effect": "Deny", "Action": "sts:AssumeRole", "NotResource": selected})
        for alias in delegations:
            statements.append({"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": roles[alias],
                               "Condition": {"StringNotEquals": {"sts:RoleSessionName": sessions[alias]}}})
    else:
        statements.append({"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"})
    if not keeper:
        statements += [
            {"Effect": "Deny", "Action": ["s3:PutObject", "s3:DeleteObject"], "Resource": lease},
            {"Effect": "Deny", "Action": "s3:GetObject", "NotResource": [lease, run + "*"]},
        ]
    return {"Policy": _encode(governance, "application", statements),
            "PolicyArns": [{"arn": managed_arn(governance, "application")}]}


class PhaseInputScope(str):
    """Internal output of the original-owner grouping validator, never a JSON input."""


def managed_arn(governance, role):
    c.require(role in {"plan", "deploy", "application"}, "session role")
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
