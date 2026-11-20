"""Acceptance replay: a second, production-shaped Phase A through the real plan and deploy gates."""
import shutil
import time

import pytest

from fixtures.cnesdata_phase_a_replay import FENCE, KEY, UPDATED_POLICIES, KNOWN_UPDATE, ReplayChain
from tools.cnesdata_delivery import contract as c, iam_boundary, runtime

FENCE_ROLE = f"module.runtime_iam.aws_iam_role.{FENCE}[0]"


def spy(monkeypatch, module, name, log):
    original = getattr(module, name)

    def wrapper(*args, **kwargs):
        result = original(*args, **kwargs)
        log.append((args, result))
        return result
    monkeypatch.setattr(module, name, wrapper)


def applies(chain):
    return [cmd for cmd in chain.commands if len(cmd) > 1 and cmd[1] == "apply"]


def admit(chain):
    runtime.execute("plan")
    reference = chain.planned()
    shutil.rmtree(chain.product / "infra/opentofu/env/prod/.terraform")
    chain.configure("deploy", 2, reference)
    return chain


def admitted_chain(monkeypatch, tmp_path):
    return admit(ReplayChain(monkeypatch, tmp_path))


def test_segunda_fase_a_com_forma_de_producao_passa_plan_e_deploy(monkeypatch, tmp_path):
    log = {name: [] for name in ("delta", "preflight", "drift", "prepare")}
    spy(monkeypatch, c, "validate_delta", log["delta"])
    spy(monkeypatch, c, "scheduler_preflight", log["preflight"])
    spy(monkeypatch, c, "drift_coverage", log["drift"])
    spy(monkeypatch, iam_boundary, "prepare", log["prepare"])
    chain = admitted_chain(monkeypatch, tmp_path)
    runtime.execute("deploy")
    assert len(applies(chain)) == 1
    changes = {item["address"]: item["change"]["actions"] for item in log["delta"][0][0][0]["resource_changes"]}
    assert changes[FENCE_ROLE] == ["update"]
    assert [a for a, v in changes.items() if v == ["delete", "create"]] == [
        f'module.processing.aws_ecs_task_definition.processor["{m}"]' for m in ("audit", "recovery", "unit")]
    assert {args[1] for args, _ in log["delta"]} == {"phase-a"}
    plan, state = log["preflight"][0][0]
    assert plan["variables"]["scheduler_recovery_task_definition_arn"] == {"value": None}
    assert {row["type"] for row in state["resources"] if row.get("module") == "module.schedulers"} == {
        "aws_iam_role", "aws_iam_role_policy"}
    stages = {args[5]: args[2] for args, _ in log["drift"]}
    assert set(stages) == {"before", "after"} and all(len(m["before"]) > 100 and len(m["after"]) > 100
                                                       for m in stages.values())
    resolvers = [result for _, result in log["prepare"]]
    assert resolvers and {tuple(sorted(r.traces)) for r in resolvers} == {tuple(sorted(
        (*UPDATED_POLICIES, *KNOWN_UPDATE)))}
    assert resolvers[-1].readbacks is not None


def published_predecessor(chain):
    from tools.cnesdata_delivery import contract as c
    from tools.cnesdata_delivery.aws_boundary import S3LeaseStore
    from tools.cnesdata_delivery.provenance import GitHub
    from tools.cnesdata_delivery.session_policy import predecessor_keys
    chain.gov["evidence_prefix"] = chain.gov["evidence_prefix"].rstrip("/") + "/"
    aws, original_api = runtime.AWS(chain.gov | {"role": "deploy"}), GitHub()
    store = S3LeaseStore(aws)
    previous, _ = store.get()
    chain.runs[c.REPOSITORY, 2].update(status="completed", conclusion="success")
    publication = next(value[0] for value in chain.artifacts.values() if value[1]["name"] == "cnesdata-applied-2-1")
    selector = {"protocol": "legacy-infra", "source_sha": "a" * 40, "run_id": 2, "run_attempt": 1,
                "status": "applied", "purpose": "phase-a"}
    reference = {"predecessor_version": 1, "protocol": "legacy-infra", "repository": c.REPOSITORY,
                 "source_sha": "a" * 40, "run_id": 2, "run_attempt": 1,
                 "owner_sha256": c.sha(previous["owner"].encode()), "generation": previous.get("generation"),
                 "session_sha256": previous["session_sha256"], "checkpoint_sha256": previous["checkpoint_sha256"],
                 "artifact_id": publication["artifact_id"], "artifact_digest": publication["artifact_digest"],
                 "producer_job_id": 91, "producer_name": "apply / execute", "objects": []}
    for key in predecessor_keys(chain.gov, selector):
        body, _ = aws.get(chain.gov["evidence_bucket"], key)
        reference["objects"].append({"name": key.rsplit("/", 1)[1], "sha256": c.sha(body), "size": len(body)})
    chain.gov.update(predecessor_read=selector, lifecycle_predecessor=reference)

    class API:
        def read(self, path, **kwargs):
            if path.endswith("/jobs/91"):
                return {"run_id": 2, "run_attempt": 1, "head_sha": "a" * 40, "name": "apply / execute",
                        "status": "completed", "conclusion": "success",
                        "started_at": c.utc(chain.now - 5), "completed_at": c.utc(chain.now + 5)}
            return original_api.read(path, **kwargs)

        def artifact(self, *args, **kwargs):
            return original_api.artifact(*args, **kwargs)
    return aws, API(), previous, reference


def test_predecessor_aplicado_pelos_gates_e_admitido_pela_aplicacao(monkeypatch, tmp_path):
    from tools.cnesdata_delivery.application_gate import authenticated_previous
    chain = admitted_chain(monkeypatch, tmp_path)
    runtime.execute("deploy")
    aws, api, previous, reference = published_predecessor(chain)
    result = authenticated_previous(aws, api, chain.gov, previous)
    assert result["predecessor_reference"] == reference
    assert result["phase_a_originals"]["origin"]["protocol"] == "legacy-infra"


def test_replay_recusa_entrada_de_scheduler_diferente_da_revisao_anterior(monkeypatch, tmp_path):
    chain = ReplayChain(monkeypatch, tmp_path)
    plan = c.loads(chain.plan_files["plan.json"], state=True)
    plan["variables"]["scheduler_audit_task_definition_arn"] = {"value": chain.replay.before[
        'module.processing.aws_ecs_task_definition.processor["audit"]']["arn"].replace(":3", ":2")}
    chain.plan_files["plan.json"] = c.canonical(plan)
    admit(chain)
    with pytest.raises(ValueError, match="scheduler input differs from prior applied revision"):
        runtime.execute("deploy")
    assert not applies(chain)


def test_replay_recusa_schedule_aplicado_com_entradas_nulas(monkeypatch, tmp_path):
    chain = ReplayChain(monkeypatch, tmp_path)
    schedule = {"mode": "managed", "module": "module.schedulers", "type": "aws_scheduler_schedule",
                "name": "mode", "instances": [{"index_key": "audit", "attributes": {}}]}
    chain.prior["resources"].append(schedule)
    chain.objects[chain.gov["state_bucket"], KEY] = c.canonical(chain.prior), "prior-etag"
    admit(chain)
    with pytest.raises(ValueError, match="scheduler input differs from prior applied revision"):
        runtime.execute("deploy")
    assert not applies(chain)


@pytest.mark.parametrize("stage", ["before", "after"])
def test_replay_recusa_matriz_de_drift_incompleta(monkeypatch, tmp_path, stage):
    chain = ReplayChain(monkeypatch, tmp_path)
    chain.gov["drift_matrix"][stage].pop()
    chain.configure("plan", 1)
    if stage == "before":
        with pytest.raises(ValueError, match="incomplete governed drift coverage"):
            runtime.execute("plan")
        return
    admit(chain)
    with pytest.raises(ValueError, match="incomplete governed drift coverage"):
        runtime.execute("deploy")


@pytest.mark.parametrize("mutation", ["matriz", "preflight"])
def test_leituras_before_e_preflight_falham_antes_do_acquire_no_deploy(monkeypatch, tmp_path, mutation):
    from tools.cnesdata_delivery import coordination_lease
    chain = ReplayChain(monkeypatch, tmp_path)
    runtime.execute("plan")
    reference = chain.planned()
    shutil.rmtree(chain.product / "infra/opentofu/env/prod/.terraform")
    if mutation == "matriz":
        chain.gov["drift_matrix"]["before"].pop()
    else:
        monkeypatch.setattr(c, "scheduler_preflight", lambda *args: c.require(False, "preflight probe"))
    chain.configure("deploy", 2, reference)
    acquired = []
    original = coordination_lease.Lease.acquire
    monkeypatch.setattr(coordination_lease.Lease, "acquire", lambda self: acquired.append(1) or original(self))
    with pytest.raises(ValueError, match="incomplete governed drift coverage|preflight probe"):
        runtime.execute("deploy")
    assert not acquired and not applies(chain)


def applied_release_sha256(chain):
    prefix = runtime._prefix(chain.gov, "a" * 40, 2, 1, "applied")
    envelope = c.loads(chain.objects[chain.gov["evidence_bucket"], prefix + "envelope.json"][0], canonical=True)
    return c.sha(c.canonical(envelope["plan"]["release"]))


def test_carrier_preserva_os_bytes_originais_publicados_pelo_deploy(monkeypatch, tmp_path):
    from tools.cnesdata_delivery.application_gate import authenticated_previous
    chain = admitted_chain(monkeypatch, tmp_path)
    runtime.execute("deploy")
    aws, api, previous, _ = published_predecessor(chain)
    prefix = runtime._prefix(chain.gov, "a" * 40, 2, 1, "applied")
    result = authenticated_previous(aws, api, chain.gov, previous)
    import base64
    carried = {entry["name"]: base64.b64decode(entry["bytes_base64"]) for entry in result["phase_a_originals"]["files"]}
    assert sorted(carried) == ["checkpoint.json", "drift.json", "envelope.json"]
    for name, raw in carried.items():
        assert raw == chain.objects[chain.gov["evidence_bucket"], prefix + name][0]
    outputs = c.loads(carried["checkpoint.json"], canonical=True)["outputs"]
    assert outputs["processor_task_definition_arns"] == chain.replay.output(chain.replay.after)


def test_preflight_publico_e_keeper_admitem_o_predecessor_real(monkeypatch, tmp_path):
    from test_cnesdata_application_gate import _current_caller
    from tools.cnesdata_delivery import lifecycle_runtime
    from tools.cnesdata_delivery.application_gate import Keeper, authenticated_previous
    from tools.cnesdata_delivery.aws_boundary import S3LeaseStore
    from tools.cnesdata_delivery.lifecycle_runtime import first_checkpoint
    chain = admitted_chain(monkeypatch, tmp_path)
    runtime.execute("deploy")
    aws, api, previous, reference = published_predecessor(chain)
    store = S3LeaseStore(aws)
    binding = {"repository": c.REPOSITORY, "source_sha": "b" * 40, "run_id": 44, "run_attempt": 1,
               "release_sha256": applied_release_sha256(chain), "session_sha256": "d" * 64, "lifecycle_version": 1}
    binding |= _current_caller(chain.gov, binding)
    chain.gov["application_purpose"] = "promotion"
    assert lifecycle_runtime.authenticate_application_predecessor(api, chain.gov, {"id": 44, "run_attempt": 1}) == reference
    keeper = Keeper(store, binding, lambda value: authenticated_previous(aws, api, chain.gov, value),
                    api=api, governance=chain.gov)
    owner = keeper.acquire(preparation_deadline=int(time.time()) + 900)
    current, _ = store.get()
    state, state_object = aws.get_state(absent=True)
    assert first_checkpoint(keeper.predecessor, current, owner, state, state_object) == keeper.predecessor["checkpoint"]
    assert keeper.predecessor["lease"] == previous
    assert current["lifecycle"]["predecessor_sha256"] == c.sha(c.canonical(reference))
