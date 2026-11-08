"""Resolve as sete policies Phase A somente de fontes e producers autenticados."""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass
from typing import Any

from tools.cnesdata_delivery.contract import require
from tools.cnesdata_delivery.contract import canonical as canonical_bytes, loads as decode_json
from tools.cnesdata_delivery.iam_expression import (
    Budget,
    Evaluator,
    Expr,
    Pending,
    attributes,
    parse,
    pending,
    reference_sets,
    source_blocks,
)

type Node = dict[str, Any]
ROOT = "infra/opentofu/env/prod"
POLICIES = {
    f"module.runtime_iam.aws_iam_role_policy.{name}[0]": name
    for name in (
        "canary_task",
        "canary_execution",
        "canary_seeder",
        "canary_verifier",
        "promotion_fence_operator",
    )
}
POLICIES |= {
    "module.processing.aws_iam_role_policy.step_functions_ecs[0]": "step_functions",
    "module.processing.aws_iam_role_policy.canary_verifier_run_task[0]": "canary_verifier",
}
BOOTSTRAP_POLICIES = {
    "module.runtime_iam.aws_iam_role_policy.execution": "module.runtime_iam.aws_iam_role.execution",
    **{f'module.runtime_iam.aws_iam_role_policy.runtime["{mode}"]': f'module.runtime_iam.aws_iam_role.task["{mode}"]' for mode in ("unit", "recovery", "audit")},
    "module.runtime_iam.aws_iam_role_policy.api[0]": None,
    "module.runtime_iam.aws_iam_role_policy.step_functions[0]": "module.runtime_iam.aws_iam_role.step_functions[0]",
    **{f'module.schedulers.aws_iam_role_policy.run["{mode}"]': f'module.schedulers.aws_iam_role.scheduler["{mode}"]' for mode in ("recovery", "audit")},
    "module.athena.aws_iam_role_policy.cutoff": "module.athena.aws_iam_role.cutoff",
}
TYPES = {
    "aws_iam_role": "name",
    "aws_ecs_task_definition": "family",
    "aws_ecs_cluster": "name",
    "aws_dynamodb_table": "name",
    "aws_s3_bucket": "bucket",
    "aws_ecr_repository": "name",
    "aws_cloudwatch_log_group": "name",
}


@dataclass(frozen=True)
class Identity:
    address: str
    kind: str
    fields: Node
    unknown: Node


class SourceResolver:
    def __init__(self, plan: Node, sources: dict[str, bytes], bindings: Node):
        require(
            all(type(data) is bytes and len(data) <= 256 * 1024 for data in sources.values()),
            "iam=source_size",
        )
        require(sum(map(len, sources.values())) <= 2 * 1024**2, "iam=source_total")
        require(
            re.fullmatch(r"[0-9]{12}", bindings["account_id"])
            and re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]", bindings["region"]),
            "iam=identity_scope",
        )
        self.plan, self.sources, self.bindings = plan, sources, bindings
        variables = plan.get("variables", {})
        for name, value in bindings["generated_inputs"].items():
            if name in variables:
                require(canonical_bytes(value) == canonical_bytes(variables[name]["value"]), "iam=approved_input_binding")
        require(variables.get("shared_outputs", {}).get("value", {}).get("account_id") == bindings["account_id"], "iam=account_binding")
        purpose = bindings.get("purpose", "phase-a")
        require(purpose in {"phase-a", "bootstrap", "acm-certificate"}, "iam=purpose")
        self.policies = (POLICIES if purpose == "phase-a" else BOOTSTRAP_POLICIES if purpose == "bootstrap" else {})
        self.budget = Budget()
        self.changes = {item["address"]: item for item in plan["resource_changes"]}
        require(len(self.changes) == len(plan["resource_changes"]), "iam=duplicate_resource")
        require(
            sum(item["type"] in TYPES for item in self.changes.values()) <= 128, "iam=resources"
        )
        self.cache: dict[tuple[str, ...], Expr] = {}
        self.blocks: Node = {}
        self.stack: list[tuple[str, tuple[Any, ...]]] = []
        self.readbacks: Node | None = None
        self.trace: set[str] = set()
        self.traces: dict[str, set[str]] = {}
        self.role_values: dict[str, str] = {}
        self.identity_fields: dict[str, set[str]] = {}

    def module(self, name: str) -> Node:
        root = self.plan["configuration"]["root_module"]
        return root if not name else root["module_calls"][name]["module"]

    def directory(self, module: str) -> str:
        if not module:
            return ROOT
        call = self.plan["configuration"]["root_module"]["module_calls"][module]
        source = self.attribute("", ("module", module, "source"))
        require(source[0] == "template" and source[1] == (call["source"],), "iam=module_source")
        path = posixpath.normpath(ROOT + "/" + call["source"])
        require(re.fullmatch(r"infra/opentofu/modules/[a-z0-9-]+", path), "iam=module_path")
        return path

    def resource_file(self, module: str, name: str) -> str:
        if module == "runtime_iam":
            base = name.rsplit(".", 1)[-1]
            require(
                base in set(POLICIES.values()) | {"task", "execution", "runtime", "api"}
                and name.startswith(("aws_iam_role.", "aws_iam_role_policy.")),
                "iam=resource_scope",
            )
            if base == "promotion_fence_operator":
                return "promotion.tf"
            if base in {"task", "execution", "runtime", "api"}:
                return "task-roles.tf"
            return "step-functions.tf" if base == "step_functions" else "canary.tf"
        profiles = {
            ("schedulers", "aws_iam_role.scheduler"): "iam.tf",
            ("schedulers", "aws_iam_role_policy.run"): "iam.tf",
            ("athena", "aws_iam_role.cutoff"): "main.tf",
            ("athena", "aws_iam_role_policy.cutoff"): "main.tf",
            ("data_buckets", "aws_s3_bucket.data"): "main.tf",
            ("data_buckets", "aws_s3_bucket.audit"): "main.tf",
            ("processing", "aws_ecs_task_definition.processor"): "ecs.tf",
            ("processing", "aws_ecs_cluster.processor"): "step_functions.tf",
            ("processing", "aws_iam_role_policy.step_functions_ecs"): "step_functions.tf",
            ("processing", "aws_iam_role_policy.canary_verifier_run_task"): "canary.tf",
            ("processing", "aws_dynamodb_table.canary"): "canary.tf",
            ("processing", "aws_s3_bucket.canary"): "canary.tf",
            ("processor_registry", "aws_ecr_repository.this"): "main.tf",
            ("control_plane", "aws_dynamodb_table.control_plane"): "main.tf",
            ("", "aws_cloudwatch_log_group.processor"): "main.tf",
        }
        require((module, name) in profiles, "iam=resource_scope")
        return profiles[(module, name)]

    def source_path(self, module: str, selector: tuple[str, str, str]) -> str:
        kind, name, field = selector
        directory = self.directory(module)
        if kind == "resource":
            file = self.resource_file(module, name)
        elif kind == "module":
            require(not module, "iam=nested_module_unsupported")
            file = "main.tf"
        elif kind == "locals":
            files = {"": "providers.tf", "runtime_iam": "canary.tf", "processing": "canary.tf", "schedulers": "main.tf", "athena": "main.tf", "data_buckets": "main.tf", "control_plane": "main.tf", "processor_registry": "main.tf"}
            require(module in files, "iam=local_scope")
            file = "ecs.tf" if module == "processing" and field == "commands" else "task-roles.tf" if module == "runtime_iam" and field in {"data_prefixes", "publish_prefixes", "runtime_shared_statements", "runtime_statements", "api_data_statements", "api_sfn_statements"} else (
                "step_functions.tf"
                if module == "processing" and field in {"run_task_enabled", "run_task_resources"}
                else files[module]
            )
        else:
            require(kind in {"output", "variable"}, "iam=source_kind")
            file = "outputs.tf" if kind == "output" else "variables.tf"
        return directory + "/" + file

    def attribute(self, module: str, selector: tuple[str, str, str]) -> Expr:
        key = (module, *selector)
        if key not in self.cache:
            kind, name, field = selector
            path = self.source_path(module, selector)
            require(path in self.sources, f"iam=source_file_missing path={path}")
            if path not in self.blocks:
                self.blocks[path] = [
                    (item_kind, item_name, attributes(body))
                    for item_kind, item_name, body in source_blocks(self.sources[path])
                ]
            found = [
                values[field]
                for item_kind, item_name, values in self.blocks[path]
                if item_kind == kind and item_name == name and field in values
            ]
            require(
                len(found) == 1,
                f"iam=source_missing_or_ambiguous module={module} selector={selector}",
            )
            node = parse(found[0], self.budget)
            self.check_configuration(module, selector, node)
            self.cache[key] = node
        return self.cache[key]

    def check_configuration(self, module: str, selector: tuple[str, str, str], node: Expr) -> None:
        kind, name, field = selector
        configured = None
        if kind == "module" and field != "source":
            configured = self.module(module)["module_calls"][name]["expressions"][field]
        elif kind == "output":
            configured = self.module(module)["outputs"][name]["expression"]
        elif kind == "resource":
            rows = [row for row in self.module(module)["resources"] if row["address"] == name]
            require(len(rows) == 1, f"iam=configured_resource module={module} name={name}")
            configured = rows[0].get(field + "_expression") if field in {"count", "for_each"} else rows[0]["expressions"][field]
            require(configured is not None, "iam=configuration_instance_expression")
        if configured is not None:
            expected, allowed = reference_sets(node)
            observed = set(configured.get("references", []))
            require(expected <= observed <= allowed, "iam=source_configuration_expression")
            if not expected:
                value = self.evaluate(module, node)
                require(configured.get("constant_value") == value, "iam=constant_binding")

    def evaluate(self, module: str, node: Expr, scope: Node | None = None) -> Any:
        return Evaluator(lambda path, values: self.lookup(module, path, values), self.budget).value(
            node, scope
        )

    def access(self, module: str, node: Expr, tail: tuple[Any, ...]) -> Any:
        self.budget.spend("steps")
        if tail == ("__null__",) and node[0] in {"object", "list", "template", "literal"}:
            return node == ("literal", None)
        if tail and node[0] == "object":
            values = dict(node[1])
            field = tail[0][1] if type(tail[0]) is tuple else tail[0]
            require(field in values, "iam=object_binding")
            return self.access(module, values[field], tail[1:])
        if node[0] == "ref":
            return self.lookup(module, node[1] + tail, {})
        if node[0] == "conditional":
            condition = self.evaluate(module, node[1])
            require(type(condition) is bool, "iam=conditional_binding")
            return self.access(module, node[2] if condition else node[3], tail)
        return self.select(self.evaluate(module, node), tail)

    def lookup(self, module: str, path: tuple[Any, ...], scope: Node) -> Any:
        self.budget.spend("steps")
        self.budget.reference(module + ":" + str(path))
        key = (module, path)
        require(key not in self.stack and len(self.stack) < 24, "iam=reference_cycle_or_depth")
        transitions = sum(
            first[0] != second[0] for first, second in zip(self.stack, self.stack[1:])
        )
        require(
            transitions + bool(self.stack and self.stack[-1][0] != module) <= 8, "iam=module_hops"
        )
        self.stack.append(key)
        try:
            return self.reference(module, path, scope)
        finally:
            self.stack.pop()

    def reference(self, module: str, path: tuple[Any, ...], scope: Node) -> Any:
        path = tuple(("key", self.lookup(module, part[1], scope)) if type(part) is tuple and part[0] == "dynamic" else part for part in path)
        if not path:
            raise ValueError("iam=reference_shape")
        root = path[0]
        if root in scope:
            return self.select(scope[root], path[1:])
        if len(path) < 2:
            raise ValueError("iam=reference_shape")
        if root == "var":
            return self.variable(module, path[1:])
        if root == "local":
            return self.access(module, self.attribute(module, ("locals", "", path[1])), path[2:])
        if root == "module":
            if module or len(path) < 3:
                raise ValueError("iam=module_reference")
            return self.access(
                path[1], self.attribute(path[1], ("output", path[2], "value")), path[3:]
            )
        require(root in TYPES, "iam=identity_type")
        return self.select(self.collection(module, path[:2]), path[2:])

    def variable(self, module: str, path: tuple[Any, ...]) -> Any:
        name, tail = path[0], path[1:]
        if module:
            return self.access("", self.attribute("", ("module", module, name)), tail)
        variables = self.plan["variables"]
        require(name in variables, "iam=root_variable")
        value = variables[name]["value"]
        inputs = self.bindings["generated_inputs"]
        if name in inputs:
            require(canonical_bytes(value) == canonical_bytes(inputs[name]), "iam=approved_input_binding")
        elif name == "shared_outputs" and tail == ("account_id",):
            require(value["account_id"] == self.bindings["account_id"], "iam=account_binding")
        else:
            default = self.attribute("", ("variable", name, "default"))
            require(canonical_bytes(value) == canonical_bytes(self.evaluate("", default)), "iam=default_binding")
        return self.select(value, tail)

    def collection(self, module: str, path: tuple[Any, ...]) -> Any:
        prefix = ("module." + module + "." if module else "") + ".".join(path)
        matches = []
        for address, item in self.changes.items():
            match = re.fullmatch(
                re.escape(prefix) + r'(?:\[(0|"(?:unit|recovery|audit)")\])?', address
            )
            if match:
                require(
                    item["type"] == path[0] and item.get("mode") == "managed", "iam=producer_type"
                )
                change = item["change"]
                matches.append(
                    (
                        match[1],
                        Identity(
                            address, item["type"], change["after"], change.get("after_unknown", {})
                        ),
                    )
                )
        require(matches and len(matches) <= 64, "iam=identity_collection")
        if matches[0][0] is None:
            require(len(matches) == 1, "iam=identity_ambiguity")
            return matches[0][1]
        if matches[0][0] == "0":
            require(len(matches) == 1, "iam=count_identity")
            return [matches[0][1]]
        return {json.loads(index): identity for index, identity in matches}

    def select(self, value: Any, tail: tuple[Any, ...]) -> Any:
        self.budget.spend("steps")
        if tail == ("__null__",):
            require(not pending(value), "iam=null_comparison_unknown")
            return value is None
        if not tail:
            return value
        field, rest = tail[0], tail[1:]
        if field == "*":
            require(type(value) is list and len(value) <= 64, "iam=splat")
            return [self.select(item, rest) for item in value]
        if isinstance(value, Identity):
            return self.select(self.identity(value, field), rest)
        field = field[1] if type(field) is tuple else field
        require(type(value) in (dict, list), "iam=selector_type")
        require(
            (type(field) is int and type(value) is list and 0 <= field < len(value))
            or (type(value) is dict and field in value),
            "iam=selector",
        )
        return self.select(value[field], rest)

    def identity_name(self, identity: Identity) -> str:
        field = TYPES[identity.kind]
        require(not identity.unknown.get(field), "iam=identity_name_unknown")
        value = identity.fields.get(field)
        if type(value) is not str or not value:
            raise ValueError("iam=identity_name")
        module, local = (
            identity.address.removeprefix("module.").split(".", 1)
            if identity.address.startswith("module.")
            else ("", identity.address)
        )
        name = local.split("[", 1)[0]
        node = self.attribute(module, ("resource", name, field))
        scope = self.instance_scope(identity.address)
        require(self.evaluate(module, node, scope) == value, "iam=identity_source_name address=" + identity.address)
        return value

    def identity(self, identity: Identity, field: str) -> Any:
        require(field in {"arn", "id", TYPES[identity.kind]}, "iam=identity_attribute")
        name = self.identity_name(identity)
        self.trace.add(identity.address)
        self.identity_fields.setdefault(identity.address, set()).add(field)
        observed: Node = {}
        if self.readbacks is not None:
            require(identity.address in self.readbacks, "iam=identity_readback_missing")
            observed = self.readbacks[identity.address]
            require(observed.get(TYPES[identity.kind]) == name, "iam=identity_readback_name")
        if field == TYPES[identity.kind] or (field == "id" and identity.kind == "aws_iam_role"):
            result = name
        elif field in identity.fields and not identity.unknown.get(field):
            result = identity.fields[field]
        elif self.readbacks is None:
            return Pending(identity.address + "." + field)
        else:
            result = observed.get(field)
        if type(result) is not str:
            raise ValueError("iam=identity_value")
        if field == "arn":
            self.check_arn(identity.kind, name, result)
            require(
                self.readbacks is None or observed.get(field) == result, "iam=identity_readback_arn"
            )
        return result

    def check_arn(self, kind: str, name: str, value: str) -> None:
        account, region = self.bindings["account_id"], self.bindings["region"]
        prefixes = {
            "aws_iam_role": f"arn:aws:iam::{account}:role/",
            "aws_ecs_task_definition": f"arn:aws:ecs:{region}:{account}:task-definition/",
            "aws_ecs_cluster": f"arn:aws:ecs:{region}:{account}:cluster/",
            "aws_dynamodb_table": f"arn:aws:dynamodb:{region}:{account}:table/",
            "aws_s3_bucket": "arn:aws:s3:::",
            "aws_ecr_repository": f"arn:aws:ecr:{region}:{account}:repository/",
            "aws_cloudwatch_log_group": f"arn:aws:logs:{region}:{account}:log-group:",
        }
        expected = prefixes[kind] + name
        suffix = (
            r":[1-9][0-9]*"
            if kind == "aws_ecs_task_definition"
            else r"(?::\*)?"
            if kind == "aws_cloudwatch_log_group"
            else ""
        )
        require(bool(re.fullmatch(re.escape(expected) + suffix, value)), "iam=identity_arn")

    def policy(self, address: str) -> Node | Pending:
        """Returns: documento integral da fonte, ou placeholder somente antes do readback."""
        require(address in self.policies, "iam=policy_scope")
        module, local = address.removeprefix("module.").split(".", 1)
        node = self.attribute(module, ("resource", local.split("[", 1)[0], "policy"))
        require(
            node[0:2] == ("call", "jsonencode") and len(node[2]) == 1 and node[2][0][0] == "object",
            "iam=policy_jsonencode",
        )
        value = self.evaluate(module, node, self.instance_scope(address))
        if isinstance(value, Pending):
            require(self.readbacks is None, "iam=unresolved_policy")
            return value
        require(type(value) is str and len(value.encode()) <= 65536, "iam=policy_size")
        document = decode_json(value.encode(), limit=65536)
        require(type(document) is dict, "iam=policy_document")
        return document

    def instance_scope(self, address: str) -> Node:
        module, local = (address.removeprefix("module.").split(".", 1) if address.startswith("module.") else ("", address))
        name = local.split("[", 1)[0]
        path = self.source_path(module, ("resource", name, "name"))
        blocks = [(kind, block, attributes(body)) for kind, block, body in source_blocks(self.sources[path])]
        matches = [fields for kind, block, fields in blocks if kind == "resource" and block == name]
        require(len(matches) == 1, "iam=source_resource")
        fields = matches[0]
        prefix = ("module." + module + "." if module else "") + name
        actual = {item for item in self.changes if item == prefix or item.startswith(prefix + "[")}
        if "for_each" in fields:
            values = self.evaluate(module, self.attribute(module, ("resource", name, "for_each")))
            require(type(values) in (list, dict) and len(values) <= 64, "iam=instance_collection")
            values = {key: key for key in values} if type(values) is list else values
            require(all(type(key) is str for key in values), "iam=instance_key")
            expected = {prefix + "[" + json.dumps(key) + "]" for key in values}
            require(address in expected and (".aws_iam_role_policy." not in address or actual == expected), "iam=instance_inventory")
            key = json.loads(local[local.index("[") + 1:-1])
            return {"each": {"key": key, "value": values[key]}}
        if "count" in fields:
            count = self.evaluate(module, self.attribute(module, ("resource", name, "count")))
            require(type(count) is int and 0 <= count <= 1, "iam=instance_count")
            expected = {prefix + "[0]"} if count else set()
            require(address in expected and (".aws_iam_role_policy." not in address or actual == expected), "iam=instance_inventory")
        else:
            require(actual == {prefix} and address == prefix, "iam=instance_inventory")
        return {}

    def role_producer(self, address: str) -> str | None:
        """Returns: endereço canônico da role comprovada pela cadeia de fontes."""
        require(address in self.policies, "iam=policy_scope")
        module, local = address.removeprefix("module.").split(".", 1)
        previous, self.trace = self.trace, set()
        try:
            value = self.evaluate(
                module, self.attribute(module, ("resource", local.split("[", 1)[0], "role")), self.instance_scope(address)
            )
            expected = BOOTSTRAP_POLICIES[address] if address in BOOTSTRAP_POLICIES else "module.runtime_iam.aws_iam_role." + POLICIES[address] + "[0]"
            if expected is None:
                arn = self.variable(module, ("runtime_grants", "api_role_arn"))
                require(type(arn) is str and re.fullmatch(r"arn:aws:iam::" + self.bindings["account_id"] + r":role/(?:[A-Za-z0-9_+=,.@-]+/)*[A-Za-z0-9_+=,.@-]+", arn), "iam=external_role_arn")
                require(not self.trace and value == arn.rsplit("/", 1)[-1], "iam=external_role_name")
                self.role_values[address] = value
                return None
            require(self.trace == {expected} and type(value) is str, "iam=role_chain")
            self.role_values[address] = value
            return expected
        finally:
            self.trace |= previous

    def precheck(self, address: str) -> set[str]:
        """Returns: producers criados realmente necessários à policy e role."""
        if address in self.traces:
            return self.traces[address]
        self.trace = set()
        expected = self.policy(address)
        change = self.changes[address]["change"]
        if not pending(expected) and not change.get("after_unknown", {}).get("policy"):
            require(canonical_bytes(expected, 65536) == canonical_bytes(decode_json(change["after"]["policy"].encode(), limit=65536), 65536), "iam=known_source_policy")
        self.role_producer(address)
        created = {
            name for name in self.trace if "create" in self.changes[name]["change"]["actions"]
        }
        self.traces[address] = created
        return created

    def bind(self, resources: Node) -> None:
        """Raises: ValueError ao tentar substituir readbacks ou reiniciar a operação."""
        require(self.readbacks is None, "iam=duplicate_bind")
        self.readbacks = resources

    def verify(self, address: str, observed: Node) -> None:
        expected = self.policy(address)
        require(
            not pending(expected)
            and canonical_bytes(expected, 65536)
            == canonical_bytes(decode_json(observed["policy"].encode(), limit=65536), 65536),
            "iam=resolved_policy",
        )
        producer = self.role_producer(address)
        readbacks: Node = self.readbacks or {}
        require(
            observed["role"] == self.role_values[address]
            and (producer is None or producer in readbacks and observed["role"] == readbacks[producer]["name"]),
            "iam=role_readback",
        )

    def verify_state(self, state: Node) -> None:
        """Raises: ValueError se policy ou identidade do state divergir da fonte/API."""
        require(type(state.get("resources")) is list, "iam=state_resources")
        resources = {}
        for row in state["resources"]:
            if row.get("type") not in TYPES | {"aws_iam_role_policy": "policy"}:
                continue
            prefix = row.get("module", "")
            base = (prefix + "." if prefix else "") + row["type"] + "." + row["name"]
            for instance in row["instances"]:
                key = instance.get("index_key")
                address = (
                    base
                    if key is None
                    else base + "[" + canonical_bytes(key, 4096).decode().strip() + "]"
                )
                require(address not in resources and len(resources) < 128, "iam=state_identity")
                resources[address] = instance["attributes"]
        for address in self.traces:
            require(address in resources, "iam=state_policy_missing")
            self.verify(address, resources[address])
            producer = self.role_producer(address)
            require(
                producer is None or producer in resources and resources[producer]["name"] == self.role_values[address],
                "iam=state_role_binding",
            )

        for address, fields in self.identity_fields.items():
            require(address in resources, "iam=state_producer_missing")
            item = self.changes[address]
            change = item["change"]
            identity = Identity(
                address, item["type"], change["after"], change.get("after_unknown", {})
            )
            for field in fields:
                require(
                    resources[address].get(field) == self.identity(identity, field),
                    "iam=state_producer_identity",
                )
