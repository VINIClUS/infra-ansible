"""Pinned surface of X* and the producer pin derived from the application closure."""
import base64
import subprocess
from fnmatch import fnmatchcase

from tools.cnesdata_delivery import contract as c, lifecycle_contract as lc

PINNED_SURFACE = ("tools/cnesdata_delivery/**", ".github/workflows/reusable-cnesdata-*.yml")
REPOSITORY = "VINIClUS/infra-ansible"


def on_surface(path):
    """Args: repository path. Returns: whether the path is inside the pinned surface."""
    tree, workflow = PINNED_SURFACE
    directory, _, name = path.rpartition("/")
    base, _, pattern = workflow.rpartition("/")
    return path.startswith(tree.removesuffix("**")) or (directory == base and fnmatchcase(name, pattern))


def git_reader(repo):
    def read(pin, path):
        c.digest(pin, 40)
        done = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", f"{pin}:{path}"],
                              capture_output=True, check=True)
        return done.stdout
    return read


def producer_pins(reader, x_star):
    """Args: reader(pin, path), X*. Returns: the dependencies list for the descriptor and governance."""
    c.digest(x_star, 40)
    closure = lc.application_source_closure(lambda path: reader(x_star, path))
    return [{"repository": REPOSITORY, "source_sha": x_star, "content_sha256": closure}]


def api_reader(api):
    def read(pin, path):
        c.digest(pin, 40)
        item = api.read(f"repos/{REPOSITORY}/contents/{path}?ref={pin}")
        c.require(item.get("type") == "file" and item.get("encoding") == "base64", "closure file")
        return base64.b64decode(item["content"])
    return read
