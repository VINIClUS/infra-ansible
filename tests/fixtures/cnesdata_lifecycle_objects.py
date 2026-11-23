"""P37: lifecycle catalog and source closure carried by the authenticated product source manifest."""
import base64
import subprocess

from tools.cnesdata_delivery import contract as c

CATALOG_PATH = ".github/delivery/lifecycle-steps.json"
CLOSURE = {"infra/opentofu/env/prod/main.tf": "1" * 64, "infra/opentofu/modules/processing/ecs.tf": "2" * 64}


def install(governance, manifest, steps, closure=None):
    closure = dict(CLOSURE if closure is None else closure)
    raw = c.canonical(steps)
    manifest["files"].update(closure)
    manifest["files"][CATALOG_PATH] = c.sha(raw)
    governance.pop("lifecycle_steps", None)
    governance.pop("source_closure", None)
    governance["lifecycle_steps_sha256"] = c.sha(raw)
    governance["source_closure_sha256"] = c.sha(c.canonical(closure))
    return raw


def catalog_url(source):
    return f"repos/{c.REPOSITORY}/contents/{CATALOG_PATH}?ref={source}"


def contents(raw):
    return {"type": "file", "path": CATALOG_PATH, "encoding": "base64", "content": base64.b64encode(raw).decode()}


def _git(checkout, *args, stdin=None):
    return subprocess.run(["git", *args], cwd=checkout, input=stdin, capture_output=True, check=True,
                          timeout=120).stdout


def _blobs(checkout, entries):
    output = _git(checkout, "cat-file", "--batch", stdin="".join(oid + "\n" for _, oid in entries).encode())
    found, offset = {}, 0
    for name, _ in entries:
        end = output.index(b"\n", offset)
        size = int(output[offset:end].split(b" ")[2])
        found[name] = output[end + 1:end + 1 + size]
        offset = end + 2 + size
    return found


def _entries(checkout, source, *paths, strict=True):
    tree = _git(checkout, "ls-tree", "-r", "-z", source, "--", *paths)
    entries = []
    for record in tree[:-1].split(b"\0") if tree else []:
        metadata, name = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split(" ")
        if strict and (mode not in {"100644", "100755"} or kind != "blob"):
            raise ValueError(f"product_source=entry path={name.decode()} mode={mode}")
        if kind == "blob" and mode in {"100644", "100755"}:
            entries.append((name.decode(), oid))
    return entries


def product_manifest(checkout, source, *, strict=True):
    """Mirror of the CnesData P09 producer: every tracked blob of S, sha256 of its bytes."""
    blobs = _blobs(checkout, _entries(checkout, source, strict=strict))
    return {"version": 1, "source_sha": source, "files": {name: c.sha(raw) for name, raw in blobs.items()}}


def inline_closure(checkout, source):
    """The inline governance value before P37: every infra/opentofu blob of S, sha256 of its bytes."""
    blobs = _blobs(checkout, _entries(checkout, source, "infra/opentofu", strict=False))
    return {name: c.sha(raw) for name, raw in blobs.items()}
