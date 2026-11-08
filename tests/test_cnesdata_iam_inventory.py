"""Exercise the complete ratified source inventories in one global budget."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import pytest

from fixtures.cnesdata_iam_inventory import inventory, identities
from fixtures.cnesdata_iam_sources import ACCOUNT, REGION, symbolic_state
from tools.cnesdata_delivery import contract, runtime
from tools.cnesdata_delivery.iam_source import SourceResolver

ORACLES = json.loads((Path(__file__).parent / "fixtures/cnesdata_iam_policy_oracles.json").read_text())


def test_policy_source_fixtures_are_the_recorded_immutable_producer_bytes():
    root = Path(__file__).parent / "fixtures/cnesdata_delivery_sources"
    manifest = json.loads((root / "source-manifest.json").read_text())
    assert manifest["source_sha"] == "00370142815870a90ea3e7790c7a9465fb3e7aaa"
    assert manifest["fixture_only"] is True
    assert {item["path"] for item in manifest["files"]} == {str(path.relative_to(root)) for path in root.rglob("*.tf")}
    for item in manifest["files"]:
        raw = (root / item["path"]).read_bytes()
        assert len(raw) == item["size"]
        assert hashlib.sha256(raw).hexdigest() == item["sha256"]


@pytest.mark.parametrize("purpose,count", [("bootstrap", 9), ("phase-a", 7)])
def test_complete_ratified_inventory_source_precheck(purpose, count):
    plan, sources, inputs, _, policies = inventory(purpose)
    resolver = SourceResolver(plan, sources, {"generated_inputs": inputs, "account_id": ACCOUNT,
        "region": REGION, "purpose": purpose})
    assert len(policies) == count
    for address in policies:
        resolver.precheck(address)


@pytest.mark.parametrize("purpose", ["bootstrap", "phase-a"])
@pytest.mark.parametrize("mutation", [None, "state", "api", "role", "name", "omitted-api"])
def test_all_documents_state_and_real_readback_path_match_fixed_oracles(purpose, mutation):
    plan, sources, inputs, values, policies = inventory(purpose)
    resolver = SourceResolver(plan, sources, {"generated_inputs": inputs, "account_id": ACCOUNT,
        "region": REGION, "purpose": purpose})
    for address in policies:
        resolver.precheck(address)
    oracles = ORACLES[purpose]
    observed = identities(values)
    reports, documents = [], {}
    for address, oracle in oracles.items():
        observed[address].update(name=oracle["name"], role=oracle["role"], policy=json.dumps(oracle["policy"]))
        parameters = {"RoleName": oracle["role"], "PolicyName": oracle["name"]}
        documents[oracle["name"]] = parameters | {"PolicyDocument": copy.deepcopy(oracle["policy"])}
        reports.append({"service": "iam", "operation": "get_role_policy", "parameters": parameters, "expected_sha256": "0" * 64})
    first = next(iter(oracles))
    if mutation == "state":
        observed[first]["policy"] = '{"Statement":[],"Version":"2012-10-17"}'
    if mutation == "api":
        documents[oracles[first]["name"]]["PolicyDocument"]["Statement"][0]["Resource"] = "*"
    if mutation in {"role", "name"}:
        observed[first][mutation] = "other"
    if mutation == "omitted-api":
        reports.pop()
    aws = SimpleNamespace(call=lambda _service, _operation, **parameters: copy.deepcopy(documents[parameters["PolicyName"]]))
    args = (aws, {"readbacks": reports}, SimpleNamespace(check=lambda: None), contract.canonical(symbolic_state(observed)), resolver)
    if mutation:
        with pytest.raises(ValueError):
            runtime._readbacks(*args)
    else:
        assert len(runtime._readbacks(*args)) == len(policies)
        for address, oracle in oracles.items():
            assert resolver.policy(address) == oracle["policy"]


@pytest.mark.parametrize("mutation", ["input", "account", "each", "source-cardinality", "configuration-cardinality"])
def test_source_and_governed_inputs_are_authority_before_binding(mutation):
    plan, sources, inputs, _, policies = inventory("bootstrap")
    if mutation == "input":
        plan["variables"]["image_digest"]["value"] = "sha256:" + "f" * 64
    if mutation == "account":
        plan["variables"]["shared_outputs"]["value"]["account_id"] = "999999999999"
    if mutation == "each":
        next(item for item in plan["resource_changes"] if item["address"].endswith('runtime["unit"]'))["address"] = 'module.runtime_iam.aws_iam_role_policy.runtime["other"]'
    if mutation == "source-cardinality":
        key = "infra/opentofu/modules/runtime-iam/task-roles.tf"
        sources[key] = sources[key].replace(b'toset(["unit", "recovery", "audit"])', b'toset(["unit", "recovery"])')
    if mutation == "configuration-cardinality":
        row = next(row for row in plan["configuration"]["root_module"]["module_calls"]["runtime_iam"]["module"]["resources"] if row["address"] == "aws_iam_role_policy.runtime")
        row["for_each_expression"] = {"references": ["var.other"]}
    with pytest.raises(ValueError):
        resolver = SourceResolver(plan, sources, {"generated_inputs": inputs, "account_id": ACCOUNT,
            "region": REGION, "purpose": "bootstrap"})
        for address in policies:
            resolver.precheck(address)


@pytest.mark.parametrize("purpose,address", [(purpose, address) for purpose, policies in ORACLES.items() for address in policies])
def test_every_policy_rejects_widened_grants_independently_of_state_api_fingerprints(purpose, address):
    plan, sources, inputs, values, _ = inventory(purpose)
    resolver = SourceResolver(plan, sources, {"generated_inputs": inputs, "account_id": ACCOUNT,
        "region": REGION, "purpose": purpose})
    resolver.precheck(address)
    resources = identities(values)
    for item, oracle in ORACLES[purpose].items():
        resources[item].update(name=oracle["name"], role=oracle["role"], policy=json.dumps(oracle["policy"]))
    resolver.bind(resources)
    resolver.verify(address, resources[address])
    widened = copy.deepcopy(resources[address])
    policy = json.loads(widened["policy"])
    policy["Statement"][0]["Action"] = "*"
    widened["policy"] = json.dumps(policy)
    with pytest.raises(ValueError, match="resolved_policy"):
        resolver.verify(address, widened)
