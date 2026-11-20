"""Derivation of baseline.phase_a_graph: the inverse of contract.validate_graph over a real plan."""
import re

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.iam_source import SourceResolver

MAX_SOURCE_FILES = 32
NO_CHANGE = ["no-op"]


class _Reads(dict):
    def __init__(self, sources):
        super().__init__(sources)
        self.read = set()

    def __getitem__(self, key):
        self.read.add(key)
        return super().__getitem__(key)


def _configuration(module, prefix=""):
    found = {prefix + resource["address"]: resource for resource in module.get("resources", [])}
    for name, call in module.get("module_calls", {}).items():
        found |= _configuration(call["module"], prefix + "module." + name + ".")
    return found


def _policy_hash(text):
    return c.sha(c.canonical(c.loads(text.encode())))


def _changed_policies(plan):
    return sorted((item for item in plan["resource_changes"] if item["type"] == "aws_iam_role_policy"
                   and item["change"]["actions"] != NO_CHANGE), key=lambda item: item["address"])


def _witness(item, producers, expressions):
    change = item["change"]
    local = re.sub(r"\[[^]]+\]", "", item["address"])
    references = expressions[local]["expressions"]["policy"]["references"]
    before = change.get("before")
    return {"address": item["address"], "references": sorted(set(references)), "producers": sorted(producers),
            "before_policy_sha256": _policy_hash(before["policy"]) if before else None}


def _policies(plan, resolver):
    expressions = _configuration(plan["configuration"]["root_module"])
    witnesses, known = [], {}
    for item in _changed_policies(plan):
        unknown = item["change"].get("after_unknown") or {}
        producers = resolver.precheck(item["address"])
        if unknown.get("policy") is True or unknown.get("role") is True:
            witnesses.append(_witness(item, producers, expressions))
        if unknown.get("policy") is not True:
            known[item["address"]] = _policy_hash(item["change"]["after"]["policy"])
    return witnesses, known


def derive(plan, sources, inputs, account):
    """Args: plan.json, source bytes by path, generated inputs, account. Returns: the approved graph."""
    reads = _Reads(sources)
    bindings = {"generated_inputs": inputs, "account_id": account, "region": "us-east-2",
                "purpose": "phase-a", "mode": None}
    resolver = SourceResolver(plan, reads, bindings)
    witnesses, known = _policies(plan, resolver)
    c.require(0 < len(reads.read) <= MAX_SOURCE_FILES, "source proof capacity")
    return {"source_files": [{"path": path, "sha256": c.sha(sources[path])} for path in sorted(reads.read)],
            "configuration_sha256": c.sha(c.canonical(plan["configuration"])),
            "unknown_policies": witnesses, "known_policies": known}
