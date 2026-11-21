"""Authenticated cost stage per purpose and the cost objects the gate validates."""
import copy

from tools.cnesdata_delivery import contract as c

PRE_ACTIVATION = {"acm-certificate", "bootstrap"}
CLOUDFRONT = "plan status subscription_sha256 distribution_sha256 waf_binding_sha256 observed_at expires_at"


def stage_name(purpose):
    return "pre-activation" if purpose in PRE_ACTIVATION else "active"


def _block(value):
    c.closed(value, CLOUDFRONT)
    c.require(value["plan"] == "FREE" and value["status"] == "ACTIVE", "cloudfront plan or status")
    for field in ("subscription_sha256", "distribution_sha256", "waf_binding_sha256"):
        c.digest(value[field])
    c.require(c.instant(value["observed_at"]) <= c.instant(value["expires_at"]), "cloudfront window")
    return copy.deepcopy(value)


def stage(purpose, source_sha, context, cloudfront):
    """Args: purpose, source sha, P-B cost context, owner CloudFront block. Returns: the cost_context stage."""
    c.digest(source_sha, 40)
    c.require(type(context) is dict, "cost context")
    c.require(context.get("source_sha") == source_sha, "cost context source_sha")
    digests = {name: c.digest(context.get(name)) for name in ("checkpoint_sha256", "target_sha256")}
    pre = stage_name(purpose) == "pre-activation"
    c.require(not pre or cloudfront is None, "cloudfront block in pre-activation")
    c.require(pre or type(cloudfront) is dict, "cloudfront owner block required")
    return {"stage": stage_name(purpose), "source_sha": source_sha, **digests,
            "cloudfront": None if pre else _block(cloudfront), "unbound_required": pre}


def cost_objects(derived, checkpoint):
    """Args: derived ledger, active stage. Returns: (cost, evidence) bound to the derived manifest."""
    c.require(checkpoint["stage"] == "active", f"pre-activation cost not derived stage={checkpoint['stage']}")
    c.require(checkpoint["checkpoint_sha256"] == derived["source_manifest_sha256"], "cost context checkpoint")
    manifest = derived["manifest"]
    block = checkpoint["cloudfront"]
    c.require(c.instant(manifest["expires_at"]) <= c.instant(block["expires_at"]),
              "cloudfront expiry before cost expiry")
    cost = {"verdict": "pass", "manifest_sha256": derived["manifest_sha256"],
            "product_monthly_usd": derived["product_monthly_usd"],
            "aggregate_monthly_usd": derived["aggregate_monthly_usd"], "paid_actions_limit_usd": "0.00",
            "calculated_at": manifest["calculated_at"], "expires_at": manifest["expires_at"], "scope": "active",
            "cloudfront": copy.deepcopy(block)}
    evidence = {"check_id": "cost-ledger-purpose-scope", "source_sha": checkpoint["source_sha"],
                "measurement": {"cost": copy.deepcopy(cost), "checkpoint": copy.deepcopy(checkpoint),
                                "manifest_sha256": derived["manifest_sha256"],
                                "source_manifest_sha256": derived["source_manifest_sha256"],
                                "excluded": copy.deepcopy(derived["excluded"])}}
    return cost | {"evidence_sha256": c.sha(c.canonical(evidence))}, evidence
