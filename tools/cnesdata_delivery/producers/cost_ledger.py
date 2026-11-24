"""Gate cost manifest derived from the authenticated source manifest, never from a free-form value."""
import json
from datetime import date
import re
from decimal import ROUND_CEILING, Decimal

from tools.cnesdata_delivery import contract as c

CREDIT_REASON = "credit not applied"
SPEND_LINE = "other_projects_spend"
UNPRICED_CREDITS = frozenset({"cognito_allowance"})
CATEGORIES = {
    "fargate_vcpu_hours": "fargate-vcpu", "fargate_memory_gb_hours": "fargate-memory",
    "public_ipv4_hours": "public-ipv4", "cloudwatch_alarm_metrics": "cloudwatch-alarms",
    "cloudwatch_custom_metrics": "cloudwatch-custom-metrics", "cloudwatch_logs_ingestion": "cloudwatch-logs-ingestion",
    "cloudwatch_logs_storage": "cloudwatch-logs-storage", "lambda_requests": "lambda-requests",
    "lambda_compute": "lambda-compute", "sns_requests": "sns-requests", "ecr_storage": "ecr-storage",
    "step_functions_transitions": "step-functions", "dynamodb_read_units": "dynamodb-reads",
    "dynamodb_write_units": "dynamodb-writes", "dynamodb_pitr_storage": "dynamodb-pitr",
    "dynamodb_storage": "dynamodb-storage", "s3_web_storage": "s3-web-storage", "s3_data_storage": "s3-data-storage",
    "s3_audit_storage": "s3-audit-storage", "s3_athena_results_storage": "s3-athena-storage",
    "s3_requests": "s3-requests-versions-logs", "athena_scanned": "athena-scanned",
    "cognito_essentials_mau": "cognito-mau", "cloudfront_free_plan": "cloudfront-waf", "waf_dedicated": "cloudfront-waf",
    "data_transfer_out": "data-transfer-out", "secrets_manager": "secrets-manager", "github_actions": "github-actions",
    "kms_envelope": "kms-encryption", "kms_signing": "kms-signing", "state_backend": "state-backend",
    "budget_actions": "budget-actions", SPEND_LINE: "other-projects-spend",
}
SCOPES = {"product": "product", "shared": "aggregate-only"}
CENT = Decimal("0.01")
MONTH = re.compile(r"\d{4}-(?:0[1-9]|1[0-2])")
DAY = re.compile(r"\d{4}-\d\d-\d\d")


def _source(raw):
    document = json.loads(raw, parse_float=Decimal, parse_int=Decimal)
    c.require(type(document) is dict and document.get("schema_version") == 1 and document.get("region") == "us-east-2"
              and document.get("currency") == "USD" and type(document.get("lines")) is list, "source manifest shape")
    return document


def _credit(line):
    price = line["unit_price_usd"]
    if line["id"] == SPEND_LINE:
        return False
    if price is None:
        c.require(line["id"] in UNPRICED_CREDITS, f"unpriced line id={line['id']}")
        return True
    return price < 0


def _maximum(line):
    quantity, allowance = line["quantity"]["max"], line["free_allowance"]["max"]
    c.require(quantity is not None and allowance is not None, f"line quantity id={line['id']}")
    return max(Decimal(0), quantity - allowance) * line["unit_price_usd"]


def _real_day(value):
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _spend(line):
    price = line["unit_price_usd"]
    c.require(price is not None and price >= 0, f"other projects spend price id={line['id']}")
    measurement = line.get("measurement")
    c.require(type(measurement) is dict and {"month", "measured_on", "total_usd", "method"} <= set(measurement),
              "other projects spend measurement")
    month, measured_on = measurement["month"], measurement["measured_on"]
    c.require(type(month) is str and MONTH.fullmatch(month) is not None, "other projects spend measurement")
    c.require(type(measured_on) is str and DAY.fullmatch(measured_on) is not None and _real_day(measured_on),
              "other projects spend measurement")


def _component(line):
    if line["id"] == SPEND_LINE:
        _spend(line)
    category = CATEGORIES.get(line["id"])
    c.require(category is not None and line["scope"] in SCOPES, f"line category id={line['id']}")
    amount = _maximum(line).quantize(CENT, ROUND_CEILING)
    return {"category": category, "scope": SCOPES[line["scope"]], "monthly_usd": f"{amount:.2f}", "unbound": False}


def _sum(components, scope=None):
    return sum((Decimal(item["monthly_usd"]) for item in components if scope in (None, item["scope"])), Decimal(0))


def derive(raw, *, source_sha, calculated_at, expires_at):
    """Args: source manifest bytes, keyword source_sha, calculated_at, expires_at.

    Returns: manifest, excluded, sources and totals. Raises: ValueError.
    """
    document = _source(raw)
    lines = document["lines"]
    spend = [line for line in lines if line["id"] == SPEND_LINE]
    c.require(len(spend) == 1, f"other projects spend count={len(spend)}")
    components = [_component(line) for line in lines if not _credit(line)]
    c.require(0 < len(components) <= 64, "complete cost ledger")
    product, total = _sum(components, "product"), _sum(components)
    c.budget(f"{product:.2f}", f"{total:.2f}", "0.00")
    manifest = {"source_sha": source_sha, "calculated_at": calculated_at, "expires_at": expires_at,
                "credits_usd": "0.00", "gross": True, "components": components}
    return {"manifest": manifest, "manifest_sha256": c.sha(c.canonical(manifest)),
            "excluded": [{"id": line["id"], "reason": CREDIT_REASON} for line in lines if _credit(line)],
            "sources": [{"id": line["id"], "url": line["source"]["url"], "retrieved_on": document["as_of"]}
                        for line in lines],
            "source_manifest_sha256": c.sha(raw), "product_monthly_usd": f"{product:.2f}",
            "aggregate_monthly_usd": f"{total:.2f}"}
