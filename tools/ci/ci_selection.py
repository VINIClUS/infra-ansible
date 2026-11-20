import json
import random
from pathlib import Path

import pytest

BROAD_SCOPES = {"module", "package", "session"}
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
    code = getattr(fixturedef.func, "__code__", None)
    if code is None:
        return False
    path = Path(code.co_filename)
    return path.is_relative_to(rootpath) and "site-packages" not in path.parts


def _refuse_broad_fixtures(item, rootpath):
    info = getattr(item, "_fixtureinfo", None)
    for definitions in (info.name2fixturedefs.values() if info else ()):
        last = definitions[-1]
        if last.scope in BROAD_SCOPES and _is_project_fixture(last, rootpath):
            raise pytest.UsageError(
                f"ci_splittable_broad_fixture nodeid={item.nodeid} fixture={last.argname}"
            )


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
