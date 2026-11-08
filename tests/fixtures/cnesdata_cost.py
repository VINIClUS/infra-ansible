"""Explicit synthetic measured cost transport, never a real subscription/readback."""
import hashlib
import json


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def fixture(active=True):
    cloudfront = {"plan": "FREE", "status": "ACTIVE", "subscription_sha256": "a" * 64,
                  "distribution_sha256": "b" * 64, "waf_binding_sha256": "c" * 64,
                  "observed_at": "2026-11-07T12:00:00Z", "expires_at": "2026-11-07T13:00:00Z"}
    manifest = {"source_sha": "a" * 40, "calculated_at": "2026-11-07T12:00:00Z", "expires_at": "2026-11-07T13:00:00Z",
                "credits_usd": "0.00", "gross": True,
                "components": [{"category": "kms-encryption", "scope": "product", "monthly_usd": "1.00", "unbound": False},
                               {"category": "kms-signing", "scope": "product", "monthly_usd": "1.00", "unbound": False},
                               {"category": "s3-requests-versions-logs", "scope": "product", "monthly_usd": "1.00", "unbound": False},
                               {"category": "cloudfront-waf", "scope": "product", "monthly_usd": "1.00", "unbound": not active}]}
    cost = {"verdict": "pass", "manifest_sha256": hashlib.sha256(encoded(manifest)).hexdigest(),
            "product_monthly_usd": "4.00", "aggregate_monthly_usd": "4.00", "paid_actions_limit_usd": "0.00",
            "calculated_at": "2026-11-07T12:00:00Z", "expires_at": "2026-11-07T13:00:00Z",
            "scope": "active" if active else "pre-activation", "cloudfront": cloudfront if active else {"plan": None, "status": None}}
    if not active:
        cost |= {"activation": "blocked", "dns": "blocked", "workloads": "blocked", "unbound_monthly_usd": "1.00"}
    stage = {"stage": cost["scope"], "source_sha": "a" * 40, "checkpoint_sha256": "d" * 64,
             "target_sha256": "e" * 64, "cloudfront": cloudfront if active else None, "unbound_required": not active}
    evidence = {"check_id": "cost-ledger-purpose-scope", "source_sha": "a" * 40,
                "measurement": {"cost": cost.copy(), "checkpoint": stage.copy(), "manifest_sha256": cost["manifest_sha256"]}}
    cost["evidence_sha256"] = hashlib.sha256(encoded(evidence)).hexdigest()
    return cost, stage, evidence, manifest
