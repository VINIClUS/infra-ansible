"""Offline executable chain; fake HTTP/SDK/processes, real gates/CAS/publication."""
import base64
import copy
import io
import json
import os
import time
import types
import zipfile
from email.utils import formatdate
from pathlib import Path

from tools.cnesdata_delivery import contract as c, runtime
from tools.cnesdata_delivery.provenance import BASE_CHECKS, GitHub
from fixtures.cnesdata_plan import packet


class Chain:
    def __init__(self, monkeypatch, root, *, purpose="acm-certificate", compact_names=False):
        self.root, self.runs, self.artifacts, self.objects = root, {}, {}, {}
        self.monkeypatch = monkeypatch
        self.sequence = 1000
        self.commands = []
        self.now = int(time.time()) - 1
        self.purpose = purpose
        self.expires = c.utc(self.now + 3600)
        envelope, self.plan_files, baseline = packet()
        cost = envelope["plan"]["cost"]
        manifest = baseline["cost_manifest"]
        if purpose == "phase-a":
            from fixtures.cnesdata_cost import fixture
            cost, stage, measured, manifest = fixture(True)
            baseline.update(cost_context=stage, cost_evidence=measured, cost_manifest=manifest)
            cost["cloudfront"].update(observed_at=c.utc(self.now), expires_at=self.expires)
        manifest.update(calculated_at=c.utc(self.now), expires_at=self.expires)
        cost.update(calculated_at=c.utc(self.now), expires_at=self.expires, manifest_sha256=c.sha(c.canonical(manifest)))
        measured = baseline["cost_evidence"]
        measured["measurement"]["cost"] = {key: value for key, value in cost.items() if key != "evidence_sha256"}
        measured["measurement"]["manifest_sha256"] = cost["manifest_sha256"]
        cost["evidence_sha256"] = c.sha(c.canonical(measured))
        self.gov = {"authority": "infra-ansible#28/6715994616+6716076093+6716241666+6716490764+6716699477+6718141241+6718506538",
                    "activation_enabled": True, "region": "us-east-2", "account_id": "111122223333",
                    "roles": {"plan": "arn:aws:iam::111122223333:role/plan", "deploy": "arn:aws:iam::111122223333:role/deploy"},
                    "gate_shas": {"plan": "b" * 40, "deploy": "c" * 40}, "baseline": baseline, "cost": cost,
                    "dependencies": baseline["dependencies"], "required_checks": ["source-ci"],
                    "state_bucket": "synthetic-state", "state_kms_key_arn": baseline["backend"]["configuration"]["kms_key_id"],
                    "evidence_bucket": "synthetic-evidence", "evidence_kms_key_arn": "arn:aws:kms:us-east-2:111122223333:key/evidence",
                    "evidence_prefix": "cnesdata/prod/evidence", "product_inputs": {},
                    "contract_sha256": c.sha(b"immutable authority fixture"),
                    "drift_matrix": {"matrix_version": 1, "source_sha": "a" * 40, "purpose": purpose, "before": [], "after": []}}
        if compact_names:
            self.gov.update(evidence_bucket="evi", evidence_prefix="cnesdata/prod/e")
        self.gov["readbacks"] = [{"service": "dynamodb", "operation": "describe_table", "parameters": {"TableName": "fixture"},
                                  "expected_sha256": c.sha(c.canonical({"Table": {"Status": "ACTIVE"}}))}]
        self.gov["proof_producers"] = [{"repository": "VINIClUS/infra-ansible", "workflow_path": ".github/workflows/proof.yml", "workflow_sha": "e" * 40}]
        self.gov["caller_allowlist"] = [{"repository": c.REPOSITORY, "ref": "refs/heads/develop", "source_ref": "a" * 40,
                                        "workflow_ref": f"{c.REPOSITORY}/.github/workflows/infra-{role}.yml@" + "a" * 40}
                                       for role in ("plan", "apply")]
        self.gov["artifact_purposes"] = sorted({"backend", "policy", "cost", "drift", "shared-outputs", "toolchain"})
        self.gov["artifact_references"] = {purpose: self.add_artifact(200 + index, {"facts.json": b'{"facts":"measured"}\n'}, f".github/workflows/{purpose}.yml")
                                           for index, purpose in enumerate(self.gov["artifact_purposes"])}
        self.gov["baseline_artifacts"] = [{"purpose": purpose, "reference": self.gov["artifact_references"][purpose]}
                                          for purpose in self.gov["artifact_purposes"]]
        self.product = root / "product"
        module = self.product / "infra/opentofu/env/prod"
        module.mkdir(parents=True)
        if purpose == "phase-a":
            self.phase_setup(module, baseline)
        (module / ".terraform.lock.hcl").write_bytes(b"pinned lock")
        baseline["toolchain"]["lock_sha256"] = c.sha(b"pinned lock")
        policy = self.product / "policies/cnesdata.rego"
        policy.parent.mkdir()
        policy.write_bytes(b"independent policy fixture")
        self.gov["policy_sha256"] = c.sha(policy.read_bytes())
        binary = root / "bin"
        binary.mkdir()
        for name in ("tofu", "conftest"):
            (binary / name).write_bytes(("process-boundary-" + name).encode())
            (binary / name).chmod(0o700)
        baseline["toolchain"]["opentofu"]["binary_sha256"] = c.sha((binary / "tofu").read_bytes())
        self.gov["policy_evaluator_sha256"] = c.sha((binary / "conftest").read_bytes())
        bundle = root / ".delivery-uploader/dist/upload/index.js"
        bundle.parent.mkdir(parents=True)
        bundle.write_text("process boundary only")
        monkeypatch.chdir(root)
        monkeypatch.setenv("PATH", str(binary) + ":" + os.environ["PATH"])
        monkeypatch.setenv("HOME", str(root))
        monkeypatch.setenv("GITHUB_TOKEN", "offline-http-boundary")
        monkeypatch.setenv("GITHUB_REF", "refs/heads/develop")
        monkeypatch.setenv("GITHUB_REPOSITORY", c.REPOSITORY)
        monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
        monkeypatch.setenv("GITHUB_OUTPUT", str(root / "gate.outputs"))
        monkeypatch.setenv("EXPECTED_SOURCE_SHA", "a" * 40)
        monkeypatch.setenv("PURPOSE", purpose)
        monkeypatch.setenv("CONTRACT_REPOSITORY", c.REPOSITORY)
        monkeypatch.setenv("CONTRACT_SOURCE_SHA", c.CONTRACT_SHA)
        monkeypatch.setenv("CONTRACT_PATH", c.CONTRACT_PATH)
        monkeypatch.setenv("CONTRACT_SHA256", self.gov["contract_sha256"])
        for name in ("ACTIONS_RUNTIME_URL", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL",
                     "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
            monkeypatch.setenv(name, "offline-boundary")
        monkeypatch.setenv("AWS_CREDENTIAL_EXPIRATION", c.utc(self.now + 3600))
        monkeypatch.setenv("GITHUB_ENV", str(root / "credentials.env"))
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://fixture.actions.githubusercontent.com/token?request=fixture")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "offline-oidc-boundary")
        monkeypatch.setattr(GitHub, "_read", lambda client, path, **kwargs: self.http(path, **kwargs))
        monkeypatch.setattr(runtime.subprocess, "run", self.process_run)
        monkeypatch.setattr(runtime.subprocess, "Popen", self.process)
        chain = self
        class SDKClient:
            def __init__(self, service):
                self.service = service
            def __getattr__(self, operation):
                return lambda **kwargs: chain.sdk(self.service, operation, kwargs)
        session = types.SimpleNamespace(client=lambda service, **kwargs: SDKClient(service))
        monkeypatch.setitem(__import__("sys").modules, "boto3", types.SimpleNamespace(Session=lambda **kwargs: session, client=lambda service, **kwargs: SDKClient(service)))
        monkeypatch.setitem(__import__("sys").modules, "botocore", types.SimpleNamespace(UNSIGNED="unsigned"))
        monkeypatch.setitem(__import__("sys").modules, "botocore.config", types.SimpleNamespace(Config=lambda **kwargs: kwargs))
        monkeypatch.setattr(__import__("urllib.request", fromlist=["urlopen"]), "urlopen", self.oidc)
        saved = c.loads(self.plan_files["plan.json"], state=True)
        saved["variables"] = {f"scheduler_{mode}_task_definition_arn": {"value": None} for mode in ("recovery", "audit")}
        self.plan_files["plan.json"] = c.canonical(saved)
        self.configure("plan", 1)

    def run(self, repository, run_id, path, source="a" * 40, *, terminal=True, role=None):
        value = {"id": run_id, "run_attempt": 1, "repository": {"full_name": repository}, "head_sha": source, "path": path,
                 "status": "completed" if terminal else "in_progress", "conclusion": "success" if terminal else None,
                 # self.now is one second behind the clock; artifacts are strictly interior.
                 "event": "workflow_dispatch", "head_branch": "develop", "created_at": c.utc(self.now - 1),
                 "run_started_at": c.utc(self.now - 1), "updated_at": c.utc(self.now + 1)}
        if role:
            pin = self.gov["gate_shas"][role]
            value["referenced_workflows"] = [{"path": f"VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-{role}-gate.yml@{pin}", "sha": pin}]
        self.runs[repository, run_id] = value
        return value

    def add_artifact(self, run_id, members, path, *, repository=c.REPOSITORY, source="a" * 40, current=False, name="fixture"):
        if (repository, run_id) not in self.runs:
            self.run(repository, run_id, path, source)
        self.sequence += 1
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w") as archive:
            for key, value in sorted(members.items()):
                archive.writestr(key, value)
        raw = target.getvalue()
        reference = {"repository": repository, "run_id": run_id, "run_attempt": 1, "artifact_id": self.sequence,
                     "artifact_digest": "sha256:" + c.sha(raw), "workflow_path": path, "workflow_sha": source, "source_sha": source}
        metadata = {"id": self.sequence, "digest": reference["artifact_digest"], "expired": False,
                    "expires_at": self.expires, "created_at": c.utc(self.now), "name": name,
                    "workflow_run": {"id": run_id, "head_sha": source}}
        self.artifacts[repository, self.sequence] = (reference, metadata, members, raw)
        return reference

    def proof(self, role, binding=None):
        required = BASE_CHECKS | ({"exact-saved-plan-package", "planned-source-input-binding"} if role == "deploy" else set())
        if self.purpose == "phase-a":
            required |= {"promotion469-origin", "r2-candidate-a2-binding", "oci-promotion-byte-integrity"}
        checks, reports, members = [], [], {}
        for check_id in sorted(required):
            value = self.gov["baseline"]["cost_evidence"] if check_id == "cost-ledger-purpose-scope" else {
                "check_id": check_id, "source_sha": "a" * 40, "measurement": {"fact": check_id}}
            raw, name = c.canonical(value), check_id + ".json"
            measured = c.sha(c.canonical(value["measurement"]))
            checks.append({"check_id": check_id, "subject_sha256": "d" * 64, "expected_sha256": measured,
                           "observed_sha256": measured, "result": "pass", "observed_at": c.utc(self.now), "expires_at": self.expires})
            reports.append({"check_id": check_id, "name": name, "size": len(raw), "sha256": c.sha(raw)})
            members[name] = raw
        artifacts = []
        for purpose in self.gov["artifact_purposes"]:
            reference = self.gov["artifact_references"][purpose]
            content = self.artifacts[reference["repository"], reference["artifact_id"]][2]
            inventory = [{"name": name, "size": len(raw), "sha256": c.sha(raw)} for name, raw in sorted(content.items())]
            artifacts.append({"purpose": purpose, "reference": reference, "content_sha256": c.sha(c.canonical(inventory)), "expires_at": self.expires})
        producer_id = 100 if role == "plan" else 101
        producer = self.gov["proof_producers"][0] | {"run_id": producer_id, "run_attempt": 1}
        value = {"proof_version": 1, "source": {"repository": c.REPOSITORY, "ref": "refs/heads/develop", "source_sha": "a" * 40},
                 "producer": producer, "artifacts": artifacts, "reports": reports, "checks": checks,
                 "candidate_sha256": self.gov.get("release", {}).get("candidate_sha256"),
                 "promotion_evidence_sha256": self.gov.get("promotion_sha256"), "plan_binding_sha256": binding,
                 "observed_at": c.utc(self.now), "expires_at": self.expires}
        members["proof.json"] = c.canonical(value)
        reference = self.add_artifact(producer_id, members, producer["workflow_path"], repository=producer["repository"], source=producer["workflow_sha"])
        return reference

    def configure(self, role, run_id, planned=None):
        self.role = role
        if planned:
            self.gov["artifact_purposes"] = sorted(self.gov["artifact_purposes"] + ["planned"])
            self.gov["artifact_references"]["planned"] = planned
        binding = None if not planned else c.loads(self.artifacts[c.REPOSITORY, planned["artifact_id"]][2]["index.json"])["plan_binding_sha256"]
        self.gov["admission_reference"] = self.proof(role, binding)
        self.run(c.REPOSITORY, run_id, f".github/workflows/infra-{'plan' if role == 'plan' else 'apply'}.yml", terminal=False, role=role)
        descriptor = {"schema_version": 1, "repository": c.REPOSITORY, "source_sha": "a" * 40,
                      "producer_pins": self.gov["dependencies"], "baseline_artifacts": self.gov["baseline_artifacts"],
                      "payload_artifact": planned or (self.gov["artifact_references"].get("phase-inputs") if self.purpose == "phase-a" else None)}
        for key, value in {"CNESDATA_DELIVERY_GOVERNANCE": c.canonical(self.gov).decode(), "GITHUB_RUN_ID": str(run_id),
                           "REQUEST_DESCRIPTOR": c.canonical(descriptor).decode(),
                           "REQUEST_DESCRIPTOR_SHA256": c.sha(c.canonical(descriptor))}.items():
            self.monkeypatch.setenv(key, value)

    def http(self, path, *, raw=False, maximum=None):
        if "/contents/" in path:
            return {"content": base64.b64encode(b"immutable authority fixture").decode()}
        if "/compare/" in path:
            return {"status": "identical"}
        if "/check-runs" in path:
            return {"check_runs": [{"name": "source-ci", "head_sha": "a" * 40, "conclusion": "success"}]}
        parts = path.split("/")
        repository = "/".join(parts[1:3])
        if "/actions/workflows/" in path and "/runs?" in path:
            filename = parts[5]
            matches = [run for (repo, _), run in self.runs.items() if repo == repository
                       and run["path"] == ".github/workflows/" + filename and run["conclusion"] == "success"]
            return {"total_count": len(matches), "workflow_runs": sorted(matches, key=lambda run: run["id"], reverse=True)[:1]}
        if "/actions/runs/" in path and "/artifacts?" in path:
            matches = [record[1] for (repo, _), record in self.artifacts.items() if repo == repository
                       and record[0]["run_id"] == int(parts[5])]
            return {"total_count": len(matches), "artifacts": matches}
        if "/actions/runs/" in path and "/attempts/" in path:
            return copy.deepcopy(self.runs[repository, int(parts[5])])
        if "/actions/artifacts/" in path:
            record = self.artifacts[repository, int(parts[5])]
            return record[3] if raw else copy.deepcopy(record[1])
        raise AssertionError("unexpected GitHub HTTP boundary: " + path)

    def sdk(self, service, operation, parameters):
        if service == "sts" and operation == "assume_role_with_web_identity":
            from datetime import datetime, timezone
            self.sts_request = parameters
            if getattr(self, "sts_failure", None):
                raise self.sts_failure
            result = {"Credentials": {"AccessKeyId": "offline-access", "SecretAccessKey": "offline-secret", "SessionToken": "offline-session",
                                      "Expiration": datetime.fromtimestamp(time.time() + 3600, timezone.utc)},
                      "PackedPolicySize": getattr(self, "packed_size", 10)}
        elif service == "sts":
            result = {"Account": "111122223333", "Arn": f"arn:aws:sts::111122223333:assumed-role/{self.role}/fixture"}
        elif service == "dynamodb":
            result = {"Table": {"Status": "ACTIVE"}}
        elif service == "ecr":
            repository = "fixture"
            if operation == "describe_repositories":
                result = {"repositories": [{"registryId": "111122223333", "repositoryName": repository,
                    "repositoryArn": f"arn:aws:ecr:us-east-2:111122223333:repository/{repository}",
                    "repositoryUri": f"111122223333.dkr.ecr.us-east-2.amazonaws.com/{repository}", "imageTagMutability": "IMMUTABLE"}]}
            elif operation == "describe_images":
                result = {"imageDetails": [{"imageDigest": self.gov["release"]["image_digest"]}]}
            elif operation == "batch_get_image":
                result = {"images": [{"registryId": "111122223333", "repositoryName": repository,
                    "imageId": {"imageDigest": self.gov["release"]["image_digest"]}, "imageManifest": self.manifest.decode()}], "failures": []}
            elif operation == "get_download_url_for_layer":
                result = {"layerDigest": parameters["layerDigest"], "downloadUrl": "https://fixture.amazonaws.com/" + parameters["layerDigest"]}
            else:
                raise AssertionError(operation)
        elif operation == "get_object":
            key = parameters["Bucket"], parameters["Key"]
            if key not in self.objects:
                error = ValueError("not found")
                error.response = {"Error": {"Code": "NoSuchKey"}}
                raise error
            data, etag = self.objects[key]
            if getattr(self, "corrupt_ecr_readback", False) and parameters["Key"].endswith("/ecr-before.json"):
                data = b"x" + data[1:]
            result = {"Body": io.BytesIO(data), "ETag": etag, "ContentLength": len(data)}
            if parameters["Key"] == "cnesdata/prod/opentofu.tfstate":
                result["VersionId"] = "fixture-version-" + etag
        elif operation == "put_object":
            key = parameters["Bucket"], parameters["Key"]
            before = self.objects.get(key)
            assert (parameters.get("IfNoneMatch") == "*" and before is None) or (before and parameters.get("IfMatch") == before[1])
            etag = str(len(self.objects) + 1) + "-" + c.sha(parameters["Body"])[:16]
            self.objects[key] = parameters["Body"], etag
            result = {"ETag": etag}
        else:
            raise AssertionError((service, operation))
        result["ResponseMetadata"] = {"HTTPHeaders": {"date": formatdate(time.time(), usegmt=True)}, "RequestId": "offline-boundary"}
        return result

    def oidc(self, request, **kwargs):
        if isinstance(request, str):
            assert request.startswith("https://fixture.amazonaws.com/")
            return io.BytesIO(self.blobs[request.rsplit("/", 1)[-1]])
        assert request.full_url.startswith("https://fixture.actions.githubusercontent.com/token?")
        ref = f"VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-{self.role}-gate.yml@{self.gov['gate_shas'][self.role]}"
        claims = {"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com",
                  "sub": f"repo:{c.REPOSITORY}:environment:production:job_workflow_ref:{ref}",
                  "job_workflow_ref": ref, "repository": c.REPOSITORY, "ref": "refs/heads/develop"}
        token = "header." + base64.urlsafe_b64encode(c.canonical(claims)).decode().rstrip("=") + ".signature"
        return io.BytesIO(c.canonical({"value": token}))

    def phase_setup(self, module, baseline):
        config = c.canonical({"os": "linux", "architecture": "amd64"})
        layer = b"original promoted layer"
        self.blobs = {"sha256:" + c.sha(raw): raw for raw in (config, layer)}
        descriptors = [{"mediaType": media, "digest": "sha256:" + c.sha(raw), "size": len(raw)} for raw, media in [
            (config, "application/vnd.oci.image.config.v1+json"), (layer, "application/vnd.oci.image.layer.v1.tar+gzip")]]
        self.manifest = c.canonical({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                    "config": descriptors[0], "layers": [descriptors[1]]})
        candidate = c.canonical({"repository": c.REPOSITORY, "source_sha": "a" * 40, "release_id": "fixture-original"})
        binding = c.canary_binding(c.loads(candidate), c.sha(candidate))
        self.gov["release"] = {key: binding[key] for key in ("release_id", "source_sha", "candidate_sha256", "canary_id", "binding_sha256")}
        self.gov["release"]["image_digest"] = "sha256:" + c.sha(self.manifest)
        phase = {"image_digest": self.gov["release"]["image_digest"], "processor_active_unit_task_definition_arn": None,
            "processor_retained_unit_task_definition_arns": [], "canary_storage_enabled": True,
            "canary_release_id": binding["canary_id"], "canary_trusted_principal_arn": "arn:aws:iam::111122223333:role/verifier"}
        promotion = {"image_digest": self.gov["release"]["image_digest"], "manifest_sha256": c.sha(self.manifest),
            "config_digest": descriptors[0]["digest"], "blob_digests": [value["digest"] for value in descriptors]}
        self.gov.update(phase_a_inputs=phase, ecr_repository="fixture", promotion_sha256=c.sha(c.canonical(promotion)))
        files = {"phase-inputs.json": c.canonical(phase), "candidate.json": candidate, "promotion.json": c.canonical(promotion)}
        self.gov["phase_input_objects"] = {}
        for name, raw in files.items():
            key = self.gov["evidence_prefix"].rstrip("/") + "/i/" + {"phase-inputs.json": "p", "candidate.json": "c", "promotion.json": "m"}[name] + ".json"
            self.objects[self.gov["evidence_bucket"], key] = raw, "fixture-input"
            self.gov["phase_input_objects"][name] = {"key": key, "sha256": c.sha(raw)}
        reference = self.add_artifact(300, {"inputs-proof.json": b'{"measured":"inputs"}\n'}, ".github/workflows/phase-inputs.yml")
        self.gov["artifact_purposes"].append("phase-inputs")
        self.gov["artifact_purposes"].sort()
        self.gov["artifact_references"]["phase-inputs"] = reference
        source = b'locals { name_prefix = "cnesdata-prod" }\n'
        (module / "main.tf").write_bytes(source)
        configuration = {"root_module": {"resources": []}}
        self.plan_files["plan.json"] = c.canonical({"resource_changes": [], "configuration": configuration})
        baseline["phase_a_graph"] = {"source_files": [{"path": "infra/opentofu/env/prod/main.tf", "sha256": c.sha(source)}],
            "configuration_sha256": c.sha(c.canonical(configuration)), "unknown_policies": [], "known_policies": {}}

    def process_run(self, command, **kwargs):
        assert command[0] in {"git", "node"}
        value = "v24.11.1" if command[0] == "node" else runtime.UPLOAD_SHA if ".delivery-uploader" in str(kwargs.get("cwd")) else "a" * 40
        return types.SimpleNamespace(stdout=value + "\n", returncode=0)

    def process(self, command, **kwargs):
        self.commands.append(list(command))
        stdout = kwargs["stdout"]
        if command[0] == "node":
            env = kwargs["env"]
            files = {path.name: path.read_bytes() for path in Path(env["INPUT_PATH"]).iterdir()}
            run_id = int(env["GITHUB_RUN_ID"])
            reference = self.add_artifact(run_id, files, self.runs[c.REPOSITORY, run_id]["path"], current=True, name=env["INPUT_NAME"])
            Path(env["GITHUB_OUTPUT"]).write_text(f"artifact-id={reference['artifact_id']}\nartifact-digest={reference['artifact_digest']}\n")
        elif Path(command[0]).name == "conftest":
            stdout.write(b"[]\n")
        elif command[1] == "init":
            metadata = self.product / "infra/opentofu/env/prod/.terraform/terraform.tfstate"
            metadata.parent.mkdir()
            config = {key: value for key, value in self.gov["baseline"]["backend"]["configuration"].items() if key not in {"type", "workspace"}}
            metadata.write_bytes(c.canonical({"backend": {"type": "s3", "config": config}}))
        elif command[1] == "workspace":
            stdout.write(b"default\n")
        elif command[1] == "plan":
            Path(next(arg[5:] for arg in command if arg.startswith("-out="))).write_bytes(self.plan_files["plan.bin"])
        elif command[1] == "show":
            stdout.write(self.plan_files["plan.json"])
        else:
            raise AssertionError("unexpected process boundary " + repr(command))
        return types.SimpleNamespace(pid=1 << 30, returncode=0, poll=lambda: 0)

    def planned(self):
        matches = [value for value in self.artifacts.values() if value[1]["name"] == "cnesdata-planned-1-1"]
        assert len(matches) == 1
        self.runs[c.REPOSITORY, 1].update(status="completed", conclusion="success")
        return matches[0][0]
