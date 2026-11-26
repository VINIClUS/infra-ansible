"""Fontes do unit-start: cluster da máquina, ARN das tasks, DescribeTasks e outputs do RUNUNIT."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, Final, cast

from cnes_infra.aws.mode_canary_frames import refuse
from cnes_infra.control_plane.dynamodb_keys import item_key, unit_key

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence

DESCRIBE_TASKS_LIMIT: Final = 100
OUTPUT_FIELDS: Final = ("unit_id", "attempt", "dispatch_id", "state", "output_manifests")
MANIFEST_FIELDS: Final = ("manifest_id", "manifest_key")
_DISPATCH_ID: Final = re.compile(r"[0-9a-f]{16}")
_TASK_ID: Final = "/[0-9a-f]{32}"


def _strings(node: Any) -> Iterator[str]:
    if type(node) is str:
        yield node
    elif type(node) is dict:
        for value in cast("dict[str, Any]", node).values():
            yield from _strings(value)
    elif type(node) is list:
        for item in cast("list[Any]", node):
            yield from _strings(item)


def _clusters(node: Any) -> Iterator[Any]:
    if type(node) is dict:
        for key, value in cast("dict[str, Any]", node).items():
            if key == "Cluster":
                yield value
            yield from _clusters(value)
    elif type(node) is list:
        for item in cast("list[Any]", node):
            yield from _clusters(item)


def _parsed(text: Any) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def unit_cluster(definition: str) -> str | None:
    """Returns: Cluster único da definição da máquina; None sem um único ARN de cluster."""
    values = set(map(json.dumps, _clusters(_parsed(definition))))
    if len(values) != 1:
        return None
    cluster = json.loads(values.pop())
    return cluster if type(cluster) is str and ":cluster/" in cluster else None


def unit_execution_request(machine_arn: str, dispatch_id: str) -> dict[str, str]:
    """Returns: DescribeExecution da execução nomeada pelo dispatch, no ARN exato do probe.

    Raises: SyntheticContextRequired: unit_machine ou unit_dispatch_id.
    """
    prefix, marker, machine = machine_arn.rpartition(":stateMachine:")
    if not marker or not prefix or not machine or ":" in machine:
        raise refuse("unit_machine")
    if not _DISPATCH_ID.fullmatch(dispatch_id):
        raise refuse("unit_dispatch_id")
    return {"executionArn": f"{prefix}:execution:{machine}:{dispatch_id}"}


def unit_task_arns(execution: Mapping[str, Any], cluster_arn: str) -> tuple[str, ...]:
    """Returns: ARNs de task do cluster no output da execução SUCCEEDED, ordenados e únicos.

    Raises: SyntheticContextRequired: unit_cluster.
    """
    if ":cluster/" not in cluster_arn:
        raise refuse("unit_cluster")
    if execution.get("status") != "SUCCEEDED":
        return ()
    prefix = cluster_arn.replace(":cluster/", ":task/", 1)
    pattern = re.compile(re.escape(prefix) + _TASK_ID)
    return tuple(sorted({value for value in _strings(_parsed(execution.get("output")))
                         if pattern.fullmatch(value)}))


def describe_tasks_request(cluster_arn: str, task_arns: Sequence[str]) -> dict[str, Any]:
    """Returns: DescribeTasks do cluster com os ARNs dados.

    Raises: SyntheticContextRequired: unit_tasks (vazio, repetido ou acima de 100).
    """
    tasks = list(task_arns)
    if not tasks or len(tasks) > DESCRIBE_TASKS_LIMIT or len(set(tasks)) != len(tasks):
        raise refuse("unit_tasks")
    return {"cluster": cluster_arn, "tasks": tasks}


def unit_output_reads(table: str, tenant_id: str, run_id: str,
                      unit_ids: Sequence[str]) -> tuple[dict[str, Any], ...]:
    """Returns: GetItem forte do RUNUNIT de cada unit do dispatch, na ordem dos units."""
    return tuple({"TableName": table, "Key": item_key(*unit_key(tenant_id, run_id, unit_id)),
                  "ConsistentRead": True} for unit_id in unit_ids)


def _manifest(value: Any) -> dict[str, Any]:
    if type(value) is not dict or not set(MANIFEST_FIELDS) <= set(cast("dict[str, Any]", value)):
        raise refuse("unit_outputs")
    manifest = cast("dict[str, Any]", value)
    return {name: manifest[name] for name in MANIFEST_FIELDS}


def _output(item: Mapping[str, Any], key: tuple[str, str]) -> dict[str, Any]:
    try:
        keyed = (item["pk"]["S"], item["sk"]["S"]) == key and item["entity"]["S"] == "RUNUNIT"
        payload = json.loads(item["payload"]["S"])
    except (KeyError, TypeError, ValueError) as error:
        raise refuse("unit_outputs") from error
    if not keyed or type(payload) is not dict:
        raise refuse("unit_outputs")
    unit = cast("dict[str, Any]", payload)
    if not set(OUTPUT_FIELDS) <= set(unit) or type(unit["output_manifests"]) is not list:
        raise refuse("unit_outputs")
    manifests = [_manifest(value) for value in cast("list[Any]", unit["output_manifests"])]
    return {name: unit[name] for name in OUTPUT_FIELDS} | {"output_manifests": manifests}


def unit_outputs(tenant_id: str, run_id: str, unit_ids: Sequence[str],
                 unit_items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Returns: Projeção fechada do RUNUNIT de cada unit, na ordem dos units do dispatch.

    Raises: SyntheticContextRequired: unit_outputs (item fora do dispatch ou do formato).
    """
    if len(unit_items) != len(unit_ids):
        raise refuse("unit_outputs")
    return [_output(item, unit_key(tenant_id, run_id, unit_id))
            for item, unit_id in zip(unit_items, unit_ids, strict=True)]


__all__ = [
    "DESCRIBE_TASKS_LIMIT",
    "MANIFEST_FIELDS",
    "OUTPUT_FIELDS",
    "describe_tasks_request",
    "unit_cluster",
    "unit_execution_request",
    "unit_output_reads",
    "unit_outputs",
    "unit_task_arns",
]
