"""Production-shaped second Phase A over the executable Chain; synthetic values only.

Only the tofu/conftest processes, git, GitHub HTTP, AWS SDK and the artifact uploader are
faked. The plan, state, drift matrix, IAM sources and policy graph are generated here and
consumed by the real gate code.
"""
import copy
import json
import re
import time
import types
from pathlib import Path

from fixtures.cnesdata_iam_inventory import identities, inventory
from fixtures.cnesdata_iam_sources import ACCOUNT as SOURCE_ACCOUNT
from fixtures.cnesdata_session_chain import OwnerChain
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.iam_source import POLICIES

ACCOUNT = "111122223333"
KEY = "cnesdata/prod/opentofu.tfstate"
MODES = ("unit", "recovery", "audit")
ROOT = Path(__file__).parent / "cnesdata_delivery_sources"
ORACLES = json.loads((Path(__file__).parent / "cnesdata_iam_policy_oracles.json").read_text())["phase-a"]
CANARY_ROLES = ("canary_task", "canary_execution", "canary_seeder", "canary_verifier")
FENCE = "promotion_fence_operator"
UPDATED_POLICIES = (
    "module.processing.aws_iam_role_policy.step_functions_ecs[0]",
    "module.processing.aws_iam_role_policy.canary_verifier_run_task[0]",
)
OMITTED = ("aws_cloudwatch_log_group.processor", "module.processor_registry.aws_ecr_repository.this",
           "module.control_plane.aws_dynamodb_table.control_plane", "module.data_buckets.aws_s3_bucket.data",
           "module.data_buckets.aws_s3_bucket.audit", "module.athena.aws_iam_role.cutoff",
           "module.runtime_iam.aws_iam_role.execution")
KNOWN_UPDATE = ("module.runtime_iam.aws_iam_role_policy.canary_verifier[0]",)


def synthetic(value):
    return json.loads(json.dumps(value).replace(SOURCE_ACCOUNT, ACCOUNT))


def arn(family, revision):
    return f"arn:aws:ecs:us-east-2:{ACCOUNT}:task-definition/{family}:{revision}"


def oracle_policy(address, revision, canary_id):
    text = json.dumps(ORACLES[address]["policy"]).replace(SOURCE_ACCOUNT, ACCOUNT)
    text = text.replace("c" * 32, canary_id)
    return json.loads(re.sub(r"(processor-(?:unit|recovery|audit)):2\"", rf'\1:{revision}"', text))


def split(address):
    module, kind, local = address.rsplit(".", 2) if address.startswith("module.") else ("", *address.split(".", 1))
    name, _, key = local.partition("[")
    return module, kind, name, json.loads(key[:-1]) if key else None


def state_rows(resources):
    rows = {}
    for address, attributes in resources.items():
        module, kind, name, key = split(address)
        row = rows.setdefault((module, kind, name), {
            "module": module, "mode": "managed", "type": kind, "name": name,
            "provider": 'provider["registry.opentofu.org/hashicorp/aws"]', "instances": []})
        instance = {"schema_version": 0, "attributes": copy.deepcopy(attributes)}
        if key is not None:
            instance["index_key"] = key
        row["instances"].append(instance)
    return [{k: v for k, v in row.items() if v != ""} for row in rows.values()]


class Replay:
    """Prior state, saved plan, applied state and drift matrix of a second Phase A."""

    def __init__(self, gov, old_digest, new_digest):
        self.prefix = "cnesdata-prod"
        self.repository = f"{ACCOUNT}.dkr.ecr.us-east-2.amazonaws.com/{gov['ecr_repository']}"
        self.old_digest, self.new_digest = old_digest, new_digest
        self.canary_id = gov["phase_a_inputs"]["canary_release_id"]
        self.plan0, self.sources, _, values, _ = map(copy.deepcopy, inventory("phase-a"))
        self.values = synthetic(values)
        self.plan0 = synthetic(self.plan0)
        self.before, self.after = {}, {}
        self.build_resources()
        self.plan = self.build_plan(gov["phase_a_inputs"])

    def container(self, digest):
        return json.dumps([{"name": "processor", "image": f"{self.repository}@{digest}", "essential": True,
                            "environment": [{"name": "APP_MODE", "value": "worker"}]}], sort_keys=True)

    def taskdef(self, mode, revision, digest):
        family = f"{self.prefix}-processor-{mode}"
        known = {"family": family, "cpu": "256", "memory": "512", "network_mode": "awsvpc",
                 "requires_compatibilities": ["FARGATE"], "skip_destroy": True, "track_latest": False,
                 "execution_role_arn": f"arn:aws:iam::{ACCOUNT}:role/{self.prefix}-processor-execution",
                 "task_role_arn": f"arn:aws:iam::{ACCOUNT}:role/{self.prefix}-processor-{mode}",
                 "container_definitions": self.container(digest), "tags": {}}
        return known | {"arn": arn(family, revision), "id": arn(family, revision), "revision": revision,
                        "arn_without_revision": arn(family, revision).rsplit(":", 1)[0]}

    def build_resources(self):
        base = synthetic(identities(self.values))
        for address, attributes in base.items():
            kind = address.split(".")[-2]
            if kind == "aws_ecs_task_definition" or address in OMITTED or ".aws_iam_role.task[" in address:
                continue
            self.before[address] = copy.deepcopy(attributes)
        for mode in MODES:
            address = f'module.processing.aws_ecs_task_definition.processor["{mode}"]'
            self.before[address] = self.taskdef(mode, 3, self.old_digest)
            self.after[address] = self.taskdef(mode, 4, self.new_digest)
        for mode in ("recovery", "audit"):
            role = self.before[f'module.schedulers.aws_iam_role.scheduler["{mode}"]']
            self.before[f'module.schedulers.aws_iam_role_policy.run["{mode}"]'] = {
                "id": f"{role['name']}:run", "name": role["name"] + "-run", "role": role["name"],
                "policy": json.dumps({"Version": "2012-10-17", "Statement": []})}
        for name in CANARY_ROLES + (FENCE,):
            address = f"module.runtime_iam.aws_iam_role.{name}[0]"
            self.before[address] |= {"tags": {"ReleaseId": "0" * 32}, "tags_all": {"ReleaseId": "0" * 32},
                                     "assume_role_policy": self.trust("old-session")}
            self.after[address] = self.before[address] | {
                "tags": {"ReleaseId": self.canary_id}, "tags_all": {"ReleaseId": self.canary_id}}
        fence = f"module.runtime_iam.aws_iam_role.{FENCE}[0]"
        self.after[fence]["assume_role_policy"] = self.trust("new-session")
        self.build_policies()
        for address, attributes in self.before.items():
            self.after.setdefault(address, copy.deepcopy(attributes))

    def trust(self, session):
        return json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole",
            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/verifier"},
            "Condition": {"StringEquals": {"sts:RoleSessionName": session}}}]})

    def build_policies(self):
        for address in POLICIES:
            item = ORACLES[address]
            old = oracle_policy(address, 3, self.canary_id)
            new = oracle_policy(address, 4, self.canary_id)
            if address in KNOWN_UPDATE:
                old["Statement"] = old["Statement"][:-1]
            row = {"id": f"{item['role']}:{item['name']}", "name": item["name"], "role": item["role"]}
            self.before[address] = row | {"policy": json.dumps(old, sort_keys=True)}
            if address in UPDATED_POLICIES or address in KNOWN_UPDATE:
                self.after[address] = row | {"policy": json.dumps(new, sort_keys=True)}

    def change(self, address):
        before, after = self.before[address], self.after[address]
        kind = address.split(".")[-2]
        if before == after:
            return {"actions": ["no-op"], "before": before, "after": after, "after_unknown": {}}
        if kind == "aws_ecs_task_definition":
            known = {k: v for k, v in after.items() if k not in {"arn", "id", "revision", "arn_without_revision"}}
            return {"actions": ["delete", "create"], "before": before, "after": known,
                    "after_unknown": {k: True for k in ("arn", "id", "revision", "arn_without_revision")},
                    "replace_paths": [["container_definitions"]]}
        if address in UPDATED_POLICIES:
            hidden = {k: v for k, v in after.items() if k != "policy"}
            return {"actions": ["update"], "before": before, "after": hidden, "after_unknown": {"policy": True}}
        return {"actions": ["update"], "before": before, "after": after, "after_unknown": {}}

    def build_plan(self, phase):
        plan = copy.deepcopy(self.plan0)
        plan["variables"] = {key: {"value": value} for key, value in phase.items()} | {
            "shared_outputs": plan["variables"]["shared_outputs"],
            "scheduler_recovery_task_definition_arn": {"value": None},
            "scheduler_audit_task_definition_arn": {"value": None}}
        plan["resource_changes"] = [
            {"address": address, "mode": "managed", "type": address.split(".")[-2],
             "change": self.change(address)} for address in sorted(self.before)]
        plan["output_changes"] = {"processor_task_definition_arns": {
            "actions": ["update"], "before": self.output(self.before), "after": None, "after_unknown": True}}
        return plan

    def output(self, resources):
        return {mode: resources[f'module.processing.aws_ecs_task_definition.processor["{mode}"]']["arn"]
                for mode in MODES}

    def state(self, resources, serial):
        outputs = {"processor_task_definition_arns": {"value": self.output(resources), "type": ["map", "string"]},
                   "processor_container_name": {"value": "processor", "type": "string"}}
        return {"version": 4, "lineage": "original", "serial": serial, "outputs": outputs,
                "resources": state_rows(resources)}


def walk(module, prefix=""):
    for resource in module.get("resources", []):
        yield prefix + resource["address"], resource
    for name, call in module.get("module_calls", {}).items():
        yield from walk(call["module"], prefix + "module." + name + ".")


class ReplayChain(OwnerChain):
    """Real gates over a generated state/plan; only external boundaries are simulated."""

    OLD_DIGEST = "sha256:" + "9" * 64

    def __init__(self, monkeypatch, root):
        self.applied = False
        super().__init__(monkeypatch, root, purpose="phase-a")
        self.replay = Replay(self.gov, self.OLD_DIGEST, self.gov["release"]["image_digest"])
        for path, raw in self.replay.sources.items():
            target = self.product / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        self.plan_files["plan.json"] = c.canonical(self.replay.plan)
        self.prior = self.replay.state(self.replay.before, 21)
        self.final_state = self.replay.state(self.replay.after, 22)
        self.objects[self.gov["state_bucket"], KEY] = c.canonical(self.prior), "prior-etag"
        self.install_governance()
        self.configure("plan", 1)

    def policy_docs(self, resources):
        return {address: {"RoleName": resources[address]["role"], "PolicyName": resources[address]["name"],
                          "PolicyDocument": json.loads(resources[address]["policy"])}
                for address in POLICIES}

    def install_governance(self):
        replay = self.replay
        self.docs = {"before": self.policy_docs(replay.before), "after": self.policy_docs(replay.after)}
        self.order = sorted(replay.before)
        self.synthetic = {stage: [resources[address] for address in self.order]
                          for stage, resources in (("before", replay.before), ("after", replay.after))}
        specs = [{"service": "dynamodb", "operation": "describe_table", "parameters": {"TableName": "fixture"},
                  "expected_sha256": c.sha(c.canonical(self.synthetic))}]
        traced = (*UPDATED_POLICIES, *KNOWN_UPDATE)
        for address in (*traced, f"module.runtime_iam.aws_iam_role_policy.{FENCE}[0]"):
            doc = self.docs["before"][address]
            specs.append({"service": "iam", "operation": "get_role_policy",
                          "parameters": {"RoleName": doc["RoleName"], "PolicyName": doc["PolicyName"]},
                          "expected_sha256": c.sha(c.canonical(doc))})
        self.gov["readbacks"] = specs
        rows = {stage: [{"address": address, "attribute": name, "readback": 0, "path": [stage, index, name],
                         "encoding": "identity"} for index, address in enumerate(self.order)
                        for name in resources[address]]
                for stage, resources in (("before", replay.before), ("after", replay.after))}
        self.gov["drift_matrix"] = self.gov["drift_matrix"] | rows
        self.gov["baseline"]["phase_a_graph"] = self.graph()

    def graph(self):
        plan = self.replay.plan
        config = dict(walk(plan["configuration"]["root_module"]))
        witnesses = []
        for address, producers in sorted({
                UPDATED_POLICIES[0]: ['module.processing.aws_ecs_task_definition.processor["unit"]'],
                UPDATED_POLICIES[1]: ['module.processing.aws_ecs_task_definition.processor["audit"]']}.items()):
            local = re.sub(r"\[[^]]+\]", "", address)
            references = sorted(set(config[local]["expressions"]["policy"]["references"]))
            before = c.sha(c.canonical(json.loads(self.replay.before[address]["policy"])))
            witnesses.append({"address": address, "references": references, "producers": producers,
                              "before_policy_sha256": before})
        known = {address: c.sha(c.canonical(json.loads(self.replay.after[address]["policy"])))
                 for address in KNOWN_UPDATE}
        wanted = [path for path in sorted(self.replay.sources) if "/env/prod/" in path
                  or "/runtime-iam/" in path or "/processing/" in path]
        return {"source_files": [{"path": path, "sha256": c.sha(self.replay.sources[path])} for path in wanted],
                "configuration_sha256": c.sha(c.canonical(plan["configuration"])),
                "unknown_policies": witnesses, "known_policies": known}

    def sdk(self, service, operation, parameters):
        meta = {"ResponseMetadata": {"HTTPHeaders": {"date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())},
                                     "RequestId": "replay-readback"}}
        if service == "dynamodb":
            return copy.deepcopy(self.synthetic) | meta
        if service == "iam" and operation == "get_role_policy":
            stage = "after" if self.applied else "before"
            match = [doc for doc in self.docs[stage].values() if doc["PolicyName"] == parameters["PolicyName"]]
            return copy.deepcopy(match[0]) | meta
        return super().sdk(service, operation, parameters)

    def process_run(self, command, **kwargs):
        if command[0] == "git" and command[1] == "status":
            return types.SimpleNamespace(stdout=b"", returncode=0)
        if command[0] == "git" and command[1] == "ls-tree":
            names = "".join(name + "\0" for name in sorted(self.replay.sources))
            return types.SimpleNamespace(stdout=names.encode(), returncode=0)
        if command[0] == "git" and command[1] == "show":
            return types.SimpleNamespace(stdout=self.replay.sources[command[2].split(":", 1)[1]], returncode=0)
        return super().process_run(command, **kwargs)

    def process(self, command, **kwargs):
        if len(command) > 1 and command[1] == "apply":
            self.commands.append(list(command))
            time.sleep(1.1)
            self.objects[self.gov["state_bucket"], KEY] = c.canonical(self.final_state), "applied-etag"
            self.applied = True
            return types.SimpleNamespace(pid=1 << 30, returncode=0, poll=lambda: 0)
        return super().process(command, **kwargs)
