"""Expiry chain of one cycle, derived from the plan observation instant T."""
from tools.cnesdata_delivery import contract as c

PROOF_SECONDS = 3 * 3600
FREEZE_SECONDS = 4 * 3600


def expiry_chain(observed_at):
    """Args: T as a UTC timestamp. Returns: proof, check, pin and freeze instants."""
    start = c.instant(observed_at)
    proof = c.utc(start + PROOF_SECONDS)
    return {"observed_at": observed_at, "proof_expires_at": proof, "check_expires_at": proof,
            "pin_observed_at": observed_at, "pin_expires_at": proof, "frozen_until": c.utc(start + FREEZE_SECONDS)}


def validate_chain(chain, limits):
    """Args: chain, instants for proof, cost, cloudfront, pin, frozen, artifacts and plan. Raises: ValueError."""
    proof = c.instant(chain["proof_expires_at"])
    ok = (c.instant(limits["cost"]) >= c.instant(limits["plan"])
          and c.instant(limits["cloudfront"]) >= c.instant(limits["cost"])
          and c.instant(limits["pin"]) >= proof
          and c.instant(limits["frozen"]) >= c.instant(chain["frozen_until"])
          and all(c.instant(value) >= proof for value in limits["artifacts"]))
    c.require(ok, "expiry chain violated")
