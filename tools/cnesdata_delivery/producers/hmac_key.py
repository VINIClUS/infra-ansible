"""Per-cycle report_hmac_key: generation, local custody and delivery by stdin only."""
import secrets
import subprocess

from tools.cnesdata_delivery import contract as c

LOCAL = ["secret-tool", "store", "--label=cnesdata report_hmac_key", "service", "cnesdata-delivery",
         "kind", "report_hmac_key"]
LOOKUP = ["secret-tool", "lookup", "service", "cnesdata-delivery", "kind", "report_hmac_key"]


def new_key(token_bytes=secrets.token_bytes):
    return token_bytes(32).hex()


class Custody:
    def __init__(self, run=subprocess.run):
        self.run = run

    def _send(self, argv, key):
        failed = False
        try:
            self.run(argv, input=key, text=True, check=True, capture_output=True)
        except (subprocess.CalledProcessError, OSError):
            failed = True
        c.require(not failed, f"custody command failed tool={argv[0]}")

    def store(self, key):
        self._send(LOCAL, key)

    def deliver(self, key, repository, environment):
        self._send(["gh", "secret", "set", "REPORT_HMAC_KEY", "--repo", repository, "--env", environment], key)

    def lookup(self):
        done = self.run(LOOKUP, text=True, capture_output=True, check=False)
        return done.stdout.strip() or None if done.returncode == 0 else None


def rotate(custody, previous, token_bytes=secrets.token_bytes):
    """Args: custody, previous key, entropy source. Returns: a fresh key stored locally. Raises: ValueError."""
    fresh = new_key(token_bytes)
    c.require(fresh != previous, "report hmac key reuse")
    custody.store(fresh)
    return fresh
