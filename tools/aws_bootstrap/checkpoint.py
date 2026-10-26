"""Validação pura de prefixos, origens e estados preservados no checkpoint."""

from collections.abc import Mapping
from typing import Any

from tools.aws_bootstrap.catalog import CATALOG, valid_scope
from tools.aws_bootstrap.contract import BootstrapSpec, Checkpoint, digest, plain
from tools.aws_bootstrap.validation import instant


STAGE_ORDER = ("foundation", "migrate_bootstrap", "budget_backend", "migrate_budget",
               "mark_backends_ready")
SNAPSHOT_FIELDS = ("exact_id", "owner", "tags", "attributes", "policy_documents")


def _check(condition: bool) -> None:
    if not condition:
        raise ValueError("checkpoint_history_invalid")


def remote_location(run: Mapping[str, Any], root: str) -> dict[str, Any]:
    """Returns: destino ativo literal do root recebido."""
    value = run["roots"][root]
    return {"account": run["account_id"], "region": run["region"], "owner": value["owner"],
            **value["backend"]}


def quarantine_location(run: Mapping[str, Any], root: str, state: Mapping[str, Any]) -> dict:
    """Returns: destino inerte de quarentena para o state recebido."""
    return {**remote_location(run, root), "key": "quarantine/" + digest(run) + "/" + root
            + "/" + state["state_sha256"] + ".tfstate"}


def state_identity(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    """Returns: preservação de identidade, IDs, série e bytes em série igual."""
    return all((
        before["owner"] == after["owner"], before["lineage"] == after["lineage"],
        before["resource_ids"] == after["resource_ids"], before["serial"] <= after["serial"],
        before["serial"] != after["serial"] or before["state_sha256"] == after["state_sha256"],
    ))


def _state(state: Mapping[str, Any], run: Mapping[str, Any], root: str) -> None:
    location = state["backend_location"]
    _check(state["owner"] == run["roots"][root]["owner"])
    _check(set(state["resource_ids"]) <= CATALOG[root])
    if location.get("kind") == "local":
        path = location["path"]
        _check(path.startswith("/") and "\x00" not in path)
        _check(all(part not in ("", ".", "..") for part in path.split("/")[1:]))
        _check(state["version_id"] is None)
    else:
        _check(location == remote_location(run, root) and state["version_id"] is not None)


def observation_matches(run: Mapping[str, Any], root: str, context: Mapping[str, Any]) -> bool:
    """Returns: convergência da observação com seu payload completo recebido."""
    address, value, pool = context["address"], context["observation"], context["evidence"]
    source_hash = value["source_evidence_sha256"]
    source = pool[source_hash]
    snapshot = {key: value[key] for key in SNAPSHOT_FIELDS}
    snapshot["status"] = value["observation_status"]
    return all((digest(source) == source_hash, source["kind"] == "resource_observation",
                source["run_sha256"] == digest(run), source["root_id"] == root,
                source["address"] == address, source["observed_at"] == value["observed_at"],
                source["observation"] == snapshot))


def resource_target(run: Mapping[str, Any], root: str, address: str) -> dict:
    """Returns: identidade declarada para recurso ainda ausente."""
    value = run["roots"][root]["resources"][address]
    exact_id = None if value["identity_kind"] == "provider_assigned" else (
        _configured_identifier(run, root, address))
    return {**value, "exact_id": exact_id}


def _configured_identifier(run: Mapping, root: str, address: str) -> str:
    name = run["roots"][root]["resources"][address]["configured_name"]
    kind, label = address.split(".")
    if kind.startswith("aws_s3_"):
        slot = "backend" if label == "state" else "logging"
        return run["roots"][root][slot]["bucket"]
    if kind == "aws_iam_policy":
        path = run["identities"]["boundary"]["path"]
        return "arn:aws:iam::" + run["account_id"] + ":policy" + path + name
    if kind == "aws_iam_user_policy":
        return run["identities"]["operator"]["name"] + ":" + name
    if kind == "aws_iam_role_policy":
        role = run["roots"][root]["resources"]["aws_iam_role." + label]["configured_name"]
        return role + ":" + name
    return name


def _manifest(payload: Mapping[str, Any], run: Mapping[str, Any], pool: Mapping) -> set[str]:
    _check(payload["run_sha256"] == digest(run))
    instant(payload["observed_at"])
    reached: set[str] = set()
    if "resources" not in payload:
        return reached
    root = payload["root_id"]
    _check(set(payload["resources"]) == CATALOG[root])
    for address, value in payload["resources"].items():
        _check(value["observed_at"] == payload["observed_at"])
        _check(observation_matches(run, root, {"address": address, "observation": value,
                                             "evidence": pool}))
        _observation_scope(value, run, root)
        reached.add(value["source_evidence_sha256"])
    return reached


def _observation_scope(value: Mapping, run: Mapping, root: str) -> None:
    if value["observation_status"] == "present":
        owner = run["roots"][root]["owner"]
        tags = {**run["tags"], "Owner": owner, "InitialRunId": run["initial_run_id"],
                "RunSpecSha256": digest(run)}
        _check(value["owner"] == owner and value["tags"] == tags and value["exact_id"] is not None)
    elif value["observation_status"] == "absent":
        _check(value["exact_id"] is None and value["owner"] is None)
        _check(not value["tags"] and not value["attributes"] and not value["policy_documents"])
    else:
        _check(False)


def _record(record: Mapping, run: Mapping, parents: Mapping) -> None:
    step, grant, initial = record["step"], record["stage_authorization"], record["authority"]
    _check(step["stage"] in STAGE_ORDER)
    _check(step["enabled"] and step["execution_mode"] == "initial_local")
    _check(step["execution_surface"] == "local")
    _check(record["spec_sha256"] == digest({"contract_version": 1, "run": run, "step": step}))
    _check(record["authority_sha256"] == digest(initial) == grant["authority_sha256"])
    _check(initial["run_sha256"] == grant["run_sha256"] == digest(run))
    _check(initial["roots"] == run["roots"] and valid_scope(run, initial))
    _check(all(initial[key] == run[key] for key in ("initial_run_id", "account_id", "region")))
    _check(grant["step_sha256"] == digest(step))
    parent = record["parent_checkpoint_sha256"]
    _check(grant["parent_checkpoint_sha256"] == parent and parent in parents)
    _check(step["expected_principal_arn"] == "arn:aws:iam::" + run["account_id"] + ":root")
    for key in ("binary_plan_sha256", "migration_config_sha256", "not_before", "expires_at"):
        _check(grant[key] == step[key])
    _check(instant(initial["not_before"]) <= instant(step["not_before"])
           < instant(step["expires_at"]) <= instant(initial["expires_at"]))


def _intent(intent: Mapping, record: Mapping, pool: Mapping, run: Mapping) -> None:
    step, grant = record["step"], record["stage_authorization"]
    _check(intent["run_sha256"] == digest(run) and intent["step_id"] == step["step_id"])
    _check(intent["spec_sha256"] == record["spec_sha256"])
    _check(intent["authorization_sha256"] == digest(grant))
    _check(intent["principal_arn"] == step["expected_principal_arn"])
    _check(intent["root_id"] == step["root_id"])
    for key in ("binary_plan_sha256", "migration_config_sha256", "before_manifest_sha256",
                "after_manifest_sha256", "parent_checkpoint_sha256", "not_before", "expires_at"):
        _check(intent[key] == grant[key])
    before = pool[intent["before_manifest_sha256"]]
    _check(before["root_id"] == intent["root_id"])
    _check(instant(intent["not_before"]) <= instant(before["observed_at"])
           < instant(intent["expires_at"]))
    if intent["target"]["kind"] == "resource_set":
        _resource_intent(intent, record, before, run)
    else:
        _check(intent["binary_plan_sha256"] is None
               and intent["migration_config_sha256"] is not None)
        _check(all(intent["target"][key] == before[key] for key in ("source", "destination")))
        _check("migrate" in record["authority"]["allowed_state_actions"][intent["root_id"]])


def _resource_intent(intent: Mapping, record: Mapping, before: Mapping, run: Mapping) -> None:
    root = intent["root_id"]
    resources = intent["target"]["resources"]
    _check(set(resources) == CATALOG[root])
    _check(intent["binary_plan_sha256"] is not None and intent["migration_config_sha256"] is None)
    for address, value in resources.items():
        configured = run["roots"][root]["resources"][address]
        _check(all(value["target"][key] == configured[key] for key in configured))
        _check(value["action"] in record["authority"]["allowed_resource_actions"][root][address])
        observed = before["resources"][address]
        expected = resource_target(run, root, address)
        if value["action"] == "noop":
            expected["exact_id"] = observed["exact_id"]
        _check(value["target"] == expected)
        if value["action"] == "noop":
            _check(observed["observation_status"] == "present")
            _check(value["target"]["exact_id"] == observed["exact_id"])
        else:
            _check(value["action"] == "create" and observed["observation_status"] == "absent")


def _receipt(receipt: Mapping, context: Mapping, run: Mapping, pool: Mapping) -> None:
    record = context["records"][receipt["origin_step_id"]]
    intent = context["intents"][receipt["intent_sha256"]]
    _check(receipt["run_sha256"] == digest(run) == intent["run_sha256"])
    _check(receipt["origin_step_id"] == intent["step_id"])
    _check(receipt["origin_spec_sha256"] == record["spec_sha256"] == intent["spec_sha256"])
    _check(receipt["origin_authorization_sha256"] == digest(record["stage_authorization"]))
    _check(receipt["root_id"] == intent["root_id"])
    _check(receipt["checkpoint_generation"] == context["generation"])
    observed = instant(receipt["observed_at"])
    _check(instant(pool[intent["before_manifest_sha256"]]["observed_at"]) <= observed)
    current = context["root_states"][receipt["root_id"]]
    _check(all(current[key] == receipt[key] for key in ("state_sha256", "lineage", "serial")))
    for grant in (record["authority"], record["stage_authorization"], record["step"]):
        _check(instant(grant["not_before"]) <= observed < instant(grant["expires_at"]))
    after = pool[receipt["observed_after_sha256"]]
    _check(after["observed_at"] == receipt["observed_at"])
    _check(after["root_id"] == receipt["root_id"] and after["run_sha256"] == digest(run))
    if receipt["target"]["kind"] == "resource":
        _resource_receipt(receipt, intent, after)
    else:
        _check(receipt["target"] == intent["target"] and receipt["exact_id"] is None)
        state = after["state"]
        _check(state_identity(intent["target"]["source"], state))
        _check(state["backend_location"] == intent["target"]["destination"])
        _check(all(state[key] == receipt[key] for key in ("state_sha256", "lineage", "serial")))


def _resource_receipt(receipt: Mapping, intent: Mapping, after: Mapping) -> None:
    target = receipt["target"]
    expected = intent["target"]["resources"][target["address"]]
    _check(target["action"] == expected["action"])
    _check(all(target[key] == expected["target"][key]
               for key in ("configured_name", "identity_kind")))
    _check(expected["target"]["exact_id"] in (None, receipt["exact_id"]))
    observation = after["resources"][target["address"]]
    _check(observation["observation_status"] == "present" and receipt["exact_id"] is not None)
    _check(observation["exact_id"] == receipt["exact_id"])
    _check(observation["observed_at"] == receipt["observed_at"])


def _append_records(old: Mapping, frame: Mapping, run: Mapping, parents: Mapping) -> dict:
    previous, records = old.get("stage_records", []), frame["stage_records"]
    _check(len(records) in (len(previous), len(previous) + 1))
    for index, record in enumerate(records):
        _record(record, run, parents)
        if index < len(previous):
            _check({k: v for k, v in record.items() if k != "receipt_sha256"}
                   == {k: v for k, v in previous[index].items() if k != "receipt_sha256"})
            _check(record["receipt_sha256"][:len(previous[index]["receipt_sha256"])]
                   == previous[index]["receipt_sha256"])
            if index != len(previous) - 1 or len(records) > len(previous):
                _check(record["receipt_sha256"] == previous[index]["receipt_sha256"])
        else:
            _check(record["parent_checkpoint_sha256"] == frame["previous_sha256"])
            if previous and record["step"]["stage"] == previous[-1]["step"]["stage"]:
                _check(record["step"]["binary_plan_sha256"]
                       != previous[-1]["step"]["binary_plan_sha256"])
    ids = [record["step"]["step_id"] for record in records]
    _check(len(ids) == len(set(ids)) and frame["current_step_id"] == ids[-1])
    _check(all(record["authority"] == records[0]["authority"] for record in records))
    return dict(zip(ids, records, strict=True))


def _states(old: Mapping, frame: Mapping, run: Mapping) -> None:
    states, previous = frame["root_states"], old.get("root_states", {})
    _check(set(previous) <= set(states) <= {"foundation", "budget-backend"})
    for root, state in states.items():
        _state(state, run, root)
        receipts = [r for r in frame["receipts"] if r["root_id"] == root]
        ids = {r["target"]["address"]: r["exact_id"] for r in receipts
               if r["target"]["kind"] == "resource"}
        _check(state["resource_ids"] == ids and bool(receipts))
        latest = receipts[-1]
        _check(all(state[key] == latest[key] for key in ("state_sha256", "lineage", "serial")))
        if root in previous:
            prior = previous[root]
            _check(all(state["resource_ids"].get(k) == v for k, v in prior["resource_ids"].items()))
            _check(state_identity({**prior, "resource_ids": state["resource_ids"]}, state))
            changed = prior["backend_location"] != state["backend_location"]
            _check(not changed or latest["target"]["kind"] == "root_state")
    local = [v["backend_location"] for v in states.values()
             if v["backend_location"].get("kind") == "local"]
    _check(len({v["machine_id"] for v in local}) <= 1)
    _check(len({v["path"] for v in local}) == len(local))


def _milestone(frame: Mapping, old: Mapping) -> None:
    stage, status = frame["stage"], frame["status"]
    origin = frame["stage_records"][-1]["step"]["stage"]
    count = {root: len(state["resource_ids"]) for root, state in frame["root_states"].items()}
    foundation, budget = count.get("foundation", 0), count.get("budget-backend", 0)
    table = {
        "foundation_pending": ("foundation", "pending", foundation == 0),
        "foundation_partial": ("foundation", "partial", 0 < foundation < 22),
        "foundation_verified": ("foundation", "complete", foundation == 22),
        "bootstrap_state_migrated": ("migrate_bootstrap", "complete", foundation == 22),
        "budget_backend_pending": ("budget_backend", "pending", budget == 0),
        "budget_backend_partial": ("budget_backend", "partial", 0 < budget < 12),
        "budget_backend_verified": ("budget_backend", "complete", budget == 12),
        "budget_state_migrated": ("migrate_budget", "complete", budget == 12),
        "backends_ready_initial_open": ("mark_backends_ready", "complete", budget == 12),
    }
    if stage == "migration_pending":
        _check(origin in ("migrate_bootstrap", "migrate_budget") and status == "pending")
    else:
        expected = table[stage]
        _check((origin, status) == expected[:2] and expected[2])
    _check((frame["intent"] is None) == (status == "complete"))
    if old:
        earlier = old["stage_records"][-1]["step"]["stage"]
        delta = STAGE_ORDER.index(origin) - STAGE_ORDER.index(earlier)
        _check(delta == 0 or delta == 1 and old["status"] == "complete")
    else:
        _check(stage == "foundation_pending" and not frame["receipts"] and not frame["root_states"])
    if origin in STAGE_ORDER[2:]:
        _check(foundation == 22
               and "kind" not in frame["root_states"]["foundation"]["backend_location"])
    remote_stages = ("bootstrap_state_migrated", "budget_state_migrated",
                     "backends_ready_initial_open")
    if stage in remote_stages:
        root = "foundation" if stage == "bootstrap_state_migrated" else "budget-backend"
        _check("kind" not in frame["root_states"][root]["backend_location"])


def _historical_migration(record: Mapping, pool: Mapping, parents: Mapping, run: Mapping) -> set:
    grant, step = record["stage_authorization"], record["step"]
    before = pool[grant["before_manifest_sha256"]]
    checkpoint = parents[record["parent_checkpoint_sha256"]]
    _check(before["source"] == checkpoint["root_states"][step["root_id"]])
    _check(before["source"]["backend_location"].get("kind") == "local")
    _check(before["destination"] == remote_location(run, step["root_id"]))
    destination = before["destination_state"]
    _check(before["destination_empty"] == (destination is None))
    if destination is not None:
        _state(destination, run, step["root_id"])
        _check(state_identity(before["source"], destination))
        _check(destination["backend_location"] == before["destination"])
    context = {**before, "checkpoint": checkpoint, "principal": step["expected_principal_arn"]}
    evidence = {key: value for key, value in pool.items() if "result" in value
                and value["result"]["step_sha256"] == digest(step)}
    migration_evidence(run, step, context, evidence)
    return set(evidence)


def migration_evidence(run: Mapping, step: Mapping, context: Mapping, evidence: Mapping) -> None:
    """Raises: ValueError para provas de migração internamente incoerentes."""
    source, destination, cp = context["source"], context["destination"], context["checkpoint"]
    root = step["root_id"]
    kinds = {value["kind"]: (key, value) for key, value in evidence.items()}
    _check(set(kinds) == {"freeze", "independent_backup", "remote_lock", "quarantine_restore"})
    _check(len(kinds) == len(evidence))
    for key, value in evidence.items():
        _check(digest(value) == key and value["root_id"] == root)
        _check(value["source"] == source and value["destination"] == destination)
        _check(value["observed_at"] == context["observed_at"])
        _check(instant(step["not_before"]) <= instant(value["observed_at"])
               < instant(step["expires_at"]))
        _check(value["result"]["run_sha256"] == digest(run))
        _check(value["result"]["step_sha256"] == digest(step))
    freeze = kinds["freeze"][1]["result"]
    lock = kinds["remote_lock"][1]["result"]
    _check(freeze["checkpoint_sha256"] == lock["checkpoint_sha256"] == digest(cp))
    _check(freeze["executor_principal_arn"] == lock["holder_principal_arn"] == context["principal"])
    _check(freeze["held_intent_sha256"] == (None if cp["intent"] is None else digest(cp["intent"])))
    _check(lock["lock_location"] == {**destination, "key": destination["key"] + ".tflock"})
    backup = kinds["independent_backup"][1]["result"]
    _check(backup["plaintext_state_sha256"] == source["state_sha256"])
    restore = kinds["quarantine_restore"][1]["result"]
    _check(restore["backup_evidence_sha256"] == kinds["independent_backup"][0])
    restored = restore["restored_state"]
    _check(state_identity(source, restored) and restored["serial"] == source["serial"])
    _check(restored["backend_location"] == quarantine_location(run, root, source))
    _check(restored["version_id"] is not None)


def _validate(value: Mapping, spec: BootstrapSpec) -> None:
    history, run = value["history"], spec.run
    _check(len(history) == value["generation"] and bool(history))
    _check({k: v for k, v in value.items() if k != "history"} == history[-1]["snapshot"])
    parents: dict[Any, Any] = {None: None}
    pool: dict[str, Any] = {}
    intents: dict[str, Any] = {}
    old: Mapping = {}
    local_machines: set[str] = set()
    for index, entry in enumerate(history, 1):
        frame = entry["snapshot"]
        _check(frame["generation"] == index and frame["contract_version"] == 1)
        _check(frame["initial_run_id"] == run["initial_run_id"]
               and frame["run_sha256"] == digest(run))
        _check(frame["initial_complete"] is False and frame["handoff_status"] == "pending")
        previous_hash = next(reversed(parents))
        _check(frame["previous_sha256"] == previous_hash)
        _check(instant(frame["updated_at"]) >= instant(old.get("updated_at", frame["updated_at"])))
        _check(not set(pool).intersection(entry["evidence"]))
        _check(all(key == digest(payload) for key, payload in entry["evidence"].items()))
        pool.update(entry["evidence"])
        records = _append_records(old, frame, run, parents)
        receipts, previous = frame["receipts"], old.get("receipts", [])
        _check(receipts[:len(previous)] == previous)
        _check(len({digest(r) for r in receipts}) == len(receipts))
        context = {"records": records, "intents": intents, "generation": index,
                   "root_states": frame["root_states"]}
        for receipt in receipts[len(previous):]:
            _receipt(receipt, context, run, pool)
            _check(instant(receipt["observed_at"]) <= instant(frame["updated_at"]))
        for step_id, record in records.items():
            _check(record["receipt_sha256"] == [digest(r) for r in receipts
                                                if r["origin_step_id"] == step_id])
        _unique_creations(receipts)
        _states(old, frame, run)
        _milestone(frame, old)
        _check_payloads(frame, run, pool, parents)
        if frame["intent"] is not None:
            intent = frame["intent"]
            _intent(intent, records[intent["step_id"]], pool, run)
            intents[digest(intent)] = intent
        local_machines.update(s["backend_location"]["machine_id"]
                              for s in frame["root_states"].values()
                              if s["backend_location"].get("kind") == "local")
        _check(len(local_machines) <= 1)
        cp = {**frame, "history": history[:index]}
        parents[digest(cp)] = cp
        old = frame


def _unique_creations(receipts: list) -> None:
    creations = [(r["root_id"], r["target"]["address"]) for r in receipts
                 if r["target"]["kind"] == "resource" and r["target"]["action"] == "create"]
    _check(len(creations) == len(set(creations)))


def _check_payloads(frame: Mapping, run: Mapping, pool: Mapping, parents: Mapping) -> None:
    reached: set[str] = set()
    for record in frame["stage_records"]:
        before = record["stage_authorization"]["before_manifest_sha256"]
        if before is not None:
            reached.add(before)
        if record["step"]["stage"] in ("migrate_bootstrap", "migrate_budget"):
            reached.update(_historical_migration(record, pool, parents, run))
    reached.update(r["observed_after_sha256"] for r in frame["receipts"])
    for key in tuple(reached):
        if "result" not in pool[key]:
            reached.update(_manifest(pool[key], run, pool))
    _check(set(pool) == reached)


def validate_checkpoint(checkpoint: Checkpoint | Mapping[str, Any], spec: BootstrapSpec) -> None:
    """Raises: ValueError com código fixo para história semântica inválida."""
    invalid = False
    try:
        value = (checkpoint if isinstance(checkpoint, Checkpoint)
                 else Checkpoint.from_mapping(checkpoint))
        _validate(plain(value), spec)
    except (ValueError, KeyError, TypeError, AttributeError, IndexError,
            RecursionError, OverflowError):
        invalid = True
    if invalid:
        raise ValueError("checkpoint_history_invalid")
