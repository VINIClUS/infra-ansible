"""Owner CLI guard: X* strict ancestor of K, caller pinned to X*, no pinned surface drift in X*..K."""
import re
import subprocess

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.producers.pins import PINNED_SURFACE, on_surface

CALLER = ".github/workflows/cnesdata-producers.yml"
OBSERVER = "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-observer.yml"
USES = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)


def _ancestor(repo, x_star, k):
    c.require(x_star != k, "X* is not a strict ancestor of K")
    code = _git(repo, "merge-base", "--is-ancestor", x_star, k).returncode
    c.require(code == 0, "X* is not an ancestor of K")


def _surface(repo, x_star, k):
    done = _git(repo, "diff", "--name-only", "--no-renames", "-z", f"{x_star}..{k}")
    c.require(done.returncode == 0, "diff X*..K unavailable")
    touched = [name for name in done.stdout.decode().split("\0") if name and on_surface(name)]
    c.require(not touched, f"diff touches the pinned surface count={len(touched)} globs={len(PINNED_SURFACE)}")


def _uses(repo, x_star, k):
    done = _git(repo, "cat-file", "blob", f"{k}:{CALLER}")
    c.require(done.returncode == 0, "caller absent at K")
    values = [value for value in USES.findall(done.stdout.decode()) if "reusable-cnesdata-observer.yml" in value]
    c.require(bool(values) and all(value == f"{OBSERVER}@{x_star}" for value in values),
              "caller uses pin differs from X*")


def check(repo, x_star, k):
    """Args: repository path, X* sha, K sha. Raises: ValueError when any release rule fails."""
    c.digest(x_star, 40)
    c.digest(k, 40)
    _ancestor(repo, x_star, k)
    _uses(repo, x_star, k)
    _surface(repo, x_star, k)
