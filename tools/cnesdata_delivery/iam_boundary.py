"""Authenticate producer source bytes and retain one bounded IAM authorization operation."""
from pathlib import Path
import re
import subprocess

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.iam_source import MODE_POLICIES, SourceResolver

DIRECTORIES = {"env/prod", *("modules/" + name for name in (
    "runtime-iam", "processing", "processor-registry", "control-plane", "schedulers", "athena", "data-buckets", "static-web"))}


def authenticate_sources(product: Path, source: str) -> dict[str, bytes]:
    """Read only tracked immutable blobs and require equal checkout bytes."""
    c.digest(source, 40)
    clean = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all", "--", "infra/opentofu"],
                           cwd=product, capture_output=True, check=True, timeout=5)
    c.require(not clean.stdout, "iam=dirty_or_untracked_source")
    result = subprocess.run(["git", "ls-tree", "-r", "-z", "--name-only", source, "--", "infra/opentofu"],
                            cwd=product, capture_output=True, check=True, timeout=5)
    c.require(result.stdout.endswith(b"\0"), "iam=source_tree_shape")
    names = result.stdout.decode("utf-8").split("\0")[:-1]
    selected = [name for name in names if name.endswith(".tf") and name.removeprefix("infra/opentofu/").rsplit("/", 1)[0] in DIRECTORIES]
    c.require(0 < len(selected) <= 64 and len(set(selected)) == len(selected), "iam=source_inventory")
    sources = {}
    for name in selected:
        c.require(re.fullmatch(r"infra/opentofu/(?:env/prod|modules/[a-z0-9-]+)/[a-z0-9_.-]+\.tf", name), "iam=source_path")
        path = product / name
        c.require(path.is_file() and not path.is_symlink() and product.resolve() in path.resolve().parents, "iam=source_checkout_path")
        raw = subprocess.run(["git", "show", source + ":" + name], cwd=product,
                             capture_output=True, check=True, timeout=5).stdout
        c.require(len(raw) <= 256 * 1024 and path.read_bytes() == raw, "iam=immutable_source_bytes")
        sources[name] = raw
    c.require(sum(map(len, sources.values())) <= 2 * 1024**2, "iam=source_total")
    return sources


def prepare(plan, inputs, account, purpose, sources, *, mode=None):
    addresses = sorted(item["address"] for item in plan["resource_changes"]
                       if item["type"] == "aws_iam_role_policy" and item["change"]["actions"] != ["no-op"])
    if mode == "mode-canary":
        c.require(purpose == "application-prepare", "iam=mode_prepare_purpose")
        c.require(inputs.get("mode_canary") is not None
                  and plan.get("variables", {}).get("mode_canary", {}).get("value") == inputs["mode_canary"],
                  "iam=mode_exact_generated_input")
        present = {item["address"] for item in plan["resource_changes"] if item["type"] == "aws_iam_role_policy"}
        c.require(set(MODE_POLICIES) <= present and set(addresses) <= set(MODE_POLICIES), "iam=mode_policy_inventory")
        addresses = sorted(MODE_POLICIES)
    if not addresses:
        return None
    resolver = SourceResolver(plan, sources, {"generated_inputs": inputs, "account_id": account,
                                             "region": "us-east-2", "purpose": purpose, "mode": mode})
    for address in addresses:
        resolver.precheck(address)
    return resolver


def bind_state(resolver, state):
    c.require(resolver is not None, "iam=source_resolver_required")
    resources = {}
    for row in state["resources"]:
        if row.get("mode") != "managed":
            continue
        prefix = (row.get("module", "") + ".") if row.get("module") else ""
        base = prefix + row["type"] + "." + row["name"]
        for instance in row["instances"]:
            key = instance.get("index_key")
            address = base if key is None else base + "[" + c.canonical(key, 4096).decode().strip() + "]"
            c.require(address not in resources, "iam=state_duplicate")
            resources[address] = instance["attributes"]
    resolver.bind(resources)
    resolver.verify_state(state)
    return resources


def verify_api(resolver, resources, parameters, observed):
    addresses = [address for address in resolver.traces if resources[address]["name"] == parameters["PolicyName"]
                 and resources[address]["role"] == parameters["RoleName"]]
    if not addresses:
        return None
    c.require(len(addresses) == 1, "iam=source_policy_api_binding")
    address = addresses[0]
    module, local = address.removeprefix("module.").split(".", 1)
    name = resolver.evaluate(module, resolver.attribute(module, ("resource", local.split("[", 1)[0], "name")), resolver.instance_scope(address))
    expected = {"RoleName": resolver.role_values[address], "PolicyName": name, "PolicyDocument": resolver.policy(address)}
    c.require(observed == expected, "iam=source_policy_api_document")
    return address
