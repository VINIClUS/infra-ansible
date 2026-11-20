import fnmatch
import json
import random
from pathlib import Path

import pytest

BROAD_SCOPES = {"class", "module", "package", "session"}
QUARANTINE_DENY = (
    "tests/test_cnesdata_*",
    "tests/test_reusable_workflow_secrets.py",
    "tests/test_github_workflow*.py",
    "tests/test_formal_*",
    "tests/production*",
    "tests/production/*",
    "tests/test_ci_*",
)
WRAPPER_PREFIXES = ("_xunit_setup_", "_unittest_setUpClass_fixture_")
CANONICAL = pytest.StashKey[str]()


def file_of(nodeid):
    return nodeid.split("::", 1)[0]


def parse_order(value):
    if value == "reverse":
        return value
    prefix, _, seed = value.partition(":")
    if prefix == "seed" and seed.lstrip("-").isdigit():
        return value
    raise ValueError(f"ci_order_invalid value={value}")


def reorder(items, order):
    by_file = {}
    for item in items:
        by_file.setdefault(file_of(item.nodeid), []).append(item)
    rng = random.Random(int(order.split(":", 1)[1])) if order.startswith("seed:") else None
    ordered = []
    for group in by_file.values():
        rng.shuffle(group) if rng else group.reverse()
        ordered.extend(group)
    return ordered


def quarantine_marks(items):
    marks = {}
    for item in items:
        mark = item.get_closest_marker("quarantine")
        if mark is not None:
            marks[item.nodeid] = _validated(item.nodeid, mark)
    return marks


def _validated(nodeid, mark):
    names = ("reason", "issue")
    values = {**dict(zip(names, mark.args)), **mark.kwargs}
    if not all(str(values.get(name) or "").strip() for name in names):
        raise pytest.UsageError(f"ci_quarantine_invalid nodeid={nodeid}")
    return {"reason": str(values["reason"]), "issue": str(values["issue"])}


def split_quarantine(items, marks, mode):
    quarantined = [item for item in items if item.nodeid in marks]
    wanted = set(map(id, quarantined)) if mode == "only" else None
    if wanted is None:
        dropped = quarantined
    else:
        dropped = [item for item in items if id(item) not in wanted]
    dropped_ids = set(map(id, dropped))
    kept = [item for item in items if id(item) not in dropped_ids]
    entries = [{"nodeid": item.nodeid, **marks[item.nodeid]} for item in quarantined]
    return kept, dropped, entries


def load_registry(path):
    entries = json.loads(Path(path).read_text(encoding="utf-8"))
    return [{**entry, "issue": str(entry["issue"])} for entry in entries]


def _denied(nodeid):
    return any(fnmatch.fnmatchcase(file_of(nodeid), pattern) for pattern in QUARANTINE_DENY)


def _stale(entry, marks, collected, rootpath):
    name = file_of(entry["nodeid"])
    if not (rootpath / name).exists():
        return True
    return name in collected and entry["nodeid"] not in marks


def quarantine_violations(marks, registry, collected, rootpath):
    registered = {(e["nodeid"], e["reason"], e["issue"]) for e in registry}
    found = []
    for nodeid, mark in marks.items():
        if _denied(nodeid):
            found.append(f"ci_quarantine_forbidden nodeid={nodeid}")
        elif (nodeid, mark["reason"], mark["issue"]) not in registered:
            found.append(f"ci_quarantine_unregistered nodeid={nodeid}")
    for entry in registry:
        nodeid = entry["nodeid"]
        if _denied(nodeid):
            found.append(f"ci_quarantine_forbidden nodeid={nodeid}")
        elif _stale(entry, marks, collected, rootpath):
            found.append(f"ci_quarantine_stale nodeid={nodeid}")
    return list(dict.fromkeys(found))


def load_splittable(path):
    return set(json.loads(Path(path).read_text(encoding="utf-8")))


def apply_groups(items, splittable, rootpath):
    for item in items:
        name = file_of(item.nodeid)
        if name in splittable:
            _refuse_broad_fixtures(item, rootpath)
        else:
            item.add_marker(pytest.mark.xdist_group(name=name))


def _is_project_fixture(fixturedef, rootpath):
    if fixturedef.argname.startswith(WRAPPER_PREFIXES):
        return True
    code = getattr(fixturedef.func, "__code__", None)
    if code is None:
        return True
    path = Path(code.co_filename)
    return path.is_relative_to(rootpath) and "site-packages" not in path.parts


def _refuse_broad_fixtures(item, rootpath):
    info = getattr(item, "_fixtureinfo", None)
    for definitions in (info.name2fixturedefs.values() if info else ()):
        for definition in definitions:
            if definition.scope in BROAD_SCOPES and _is_project_fixture(definition, rootpath):
                raise pytest.UsageError(
                    f"ci_splittable_broad_fixture nodeid={item.nodeid} "
                    f"fixture={definition.argname}"
                )


def strip_group_suffix(nodeid):
    if nodeid.rfind("@") > nodeid.rfind("]"):
        return nodeid.rsplit("@", 1)[0]
    return nodeid


def _group_names(item):
    names = set()
    for mark in item.iter_markers("xdist_group"):
        names.add(str(mark.args[0] if mark.args else mark.kwargs.get("name", "default")))
    return names


def suffix_group_ids(items):
    from _pytest.nodeid import NodeId

    for item in items:
        names = _group_names(item)
        if names and item.nodeid == item.stash.get(CANONICAL, item.nodeid):
            item._id = NodeId.parse(f"{item.nodeid}@{'_'.join(sorted(names))}")
