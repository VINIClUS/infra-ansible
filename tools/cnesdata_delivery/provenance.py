"""Authenticated GitHub provenance and complete sanitized admission proof."""
import base64
import io
import os
import re
import stat
import time
import urllib.error
import urllib.request
import zipfile
from email.utils import parsedate_to_datetime

from tools.cnesdata_delivery.contract import (
    CONTRACT_PATH, CONTRACT_SHA, REPOSITORY, canonical, closed, digest, instant,
    integer, loads, require, sha,
    public_safe,
)

BASE_CHECKS = {"source-develop-checks", "artifact-origin-attempt-expiry", "dependency-pins",
               "toolchain-lock-selections", "backend-identity-workspace", "policy-evaluation",
               "cost-ledger-purpose-scope", "drift-baseline"}


def historical_plan_governance(governance, purpose):
    """The earlier input proof cannot contain the artifact it later produces."""
    current = set(governance["artifact_purposes"])
    require("planned" in current, "deploy planned inventory absent")
    historical = current - {"planned", "phase-inputs"}
    if purpose == "phase-a":
        historical.add("phase-inputs")
    references = governance["artifact_references"]
    require(historical <= set(references), "independently governed historical plan inputs missing")
    payload = references["planned"]
    for name in historical:
        reference = references[name]
        require((reference["repository"], reference["artifact_id"]) != (payload["repository"], payload["artifact_id"]),
                "circular historical plan artifact")
    return governance | {"artifact_purposes": sorted(historical),
                         "artifact_references": {name: references[name] for name in historical}}


def admit_source(actual, expected, credential_callback):
    require(actual == expected and actual["repository"] == REPOSITORY
            and actual["event"] == "workflow_dispatch" and actual["ref"] == "refs/heads/develop", "source admission")
    return credential_callback()


def producer_sha(run, role):
    require(role in {"plan", "deploy"}, "gate role")
    path = f"VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-{role}-gate.yml"
    entries = [entry for entry in run.get("referenced_workflows", []) if entry.get("path", "").startswith(path + "@")]
    require(len(entries) == 1, "ambiguous/missing reusable provenance")
    value = digest(entries[0]["sha"], 40)
    require(entries[0]["path"] == path + "@" + value and "ref" not in entries[0], "mutable reusable ref")
    return value


class GitHub:
    """Fixed-host HTTP; token never follows a cross-host download redirect."""
    def __init__(self, token=None):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        require(bool(self.token), "GitHub ephemeral token missing")
        self.sample = None
        self.expiries = {}

    def read(self, path, *, raw=False, maximum=192 * 1024**2):
        from tools.cnesdata_delivery.aws_boundary import bounded
        return bounded(lambda: self._read(path, raw=raw, maximum=maximum))

    def _read(self, path, *, raw, maximum):
        require(path.startswith("repos/") and not any(x in path for x in ("..", "\n", "\r", "://")), "GitHub API path")
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        request = urllib.request.Request("https://api.github.com/" + path, headers=headers)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None
        start = time.monotonic()
        try:
            response = urllib.request.build_opener(NoRedirect).open(request, timeout=20)
        except urllib.error.HTTPError as error:
            require(raw and error.code in {301, 302, 303, 307}, "GitHub HTTP failure")
            target = error.headers.get("Location", "")
            from urllib.parse import urlparse
            host = urlparse(target)
            require(host.scheme == "https" and host.hostname and
                    (host.hostname.endswith(".blob.core.windows.net") or host.hostname.endswith(".actions.githubusercontent.com")), "artifact redirect host")
            response = urllib.request.urlopen(target, timeout=20)  # no Authorization
        with response:
            date = response.headers.get("Date")
            require(bool(date), "authenticated Date missing")
            server = parsedate_to_datetime(date).timestamp()
            end = time.monotonic()
            require(end - start <= 20 and abs(time.time() - server) <= 31, "GitHub time uncertainty")
            self.sample = (start, end, server)
            data = response.read(maximum + 1)
            require(len(data) <= maximum, "GitHub response limit")
        return data if raw else loads(data)

    def run(self, reference, *, r2=False):
        run = self.read(f"repos/{reference['repository']}/actions/runs/{reference['run_id']}/attempts/{reference['run_attempt']}")
        head = reference["workflow_sha"] if r2 else reference["source_sha"]
        require(not r2 or reference["workflow_path"] == ".github/workflows/release-candidate.yml", "exclusive R2 creator carveout")
        require(run["id"] == reference["run_id"] and run["run_attempt"] == reference["run_attempt"]
                and run["repository"]["full_name"] == reference["repository"]
                and run["head_sha"] == head and run["path"].split("@")[0] == reference["workflow_path"]
                and run["status"] == "completed" and run["conclusion"] == "success", "artifact run/attempt/source")
        require(reference["workflow_sha"] == run["head_sha"], "actual caller workflow revision")
        return run

    def artifact(self, reference, now, *, r2=False):
        closed(reference, "repository run_id run_attempt artifact_id artifact_digest workflow_path workflow_sha source_sha")
        for key in ("run_id", "run_attempt", "artifact_id"):
            integer(reference[key])
        digest(reference["source_sha"], 40)
        digest(reference["workflow_sha"], 40)
        require(reference["artifact_digest"] == "sha256:" + digest(reference["artifact_digest"].removeprefix("sha256:")), "artifact digest")
        run = self.run(reference, r2=r2)
        prefix = f"repos/{reference['repository']}/actions/artifacts/{reference['artifact_id']}"
        metadata = self.read(prefix)
        require(metadata["id"] == reference["artifact_id"] and metadata.get("digest") == reference["artifact_digest"]
                and not metadata.get("expired", True) and instant(metadata["expires_at"]) > now
                and metadata["workflow_run"]["id"] == reference["run_id"]
                and metadata["workflow_run"]["head_sha"] == (reference["workflow_sha"] if r2 else reference["source_sha"]), "artifact metadata")
        # REST artifacts have no run_attempt. The attempt-specific run endpoint
        # retains its own start/completion times after reruns; the run ID/SHA alone
        # cannot distinguish artifacts from a failed earlier or later attempt.
        created = metadata.get("created_at")
        require(isinstance(created, str) and
                instant(run["run_started_at"]) <= instant(created) <= instant(run["updated_at"]),
                "artifact creation outside authenticated attempt")
        data = self.read(prefix + "/zip", raw=True)
        require("sha256:" + sha(data) == metadata["digest"], "external artifact byte digest")
        self.expiries[reference["repository"], reference["artifact_id"]] = instant(metadata["expires_at"])
        return unzip(data)


def unzip(data):
    result = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(len(archive.infolist()) <= 32, "artifact member count")
        for member in archive.infolist():
            name = member.filename
            mode = member.external_attr >> 16
            require(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) and name not in {".", ".."}
                    and name not in result and not member.is_dir() and stat.S_IFMT(mode) in {0, stat.S_IFREG}
                    and not member.external_attr & 16, "artifact unsafe member")
            total += member.file_size
            require(total <= 192 * 1024**2 and member.file_size <= 128 * 1024**2, "artifact expansion limit")
            result[name] = archive.read(member)
    return result


def validate_artifact_set(entries, governance, api, now, expires_at):
    expected = governance["artifact_purposes"]
    require(type(entries) is list and len(entries) <= 32 and [item["purpose"] for item in entries] == sorted(set(expected))
            and {"backend", "policy", "cost", "drift", "shared-outputs", "toolchain"} <= set(expected), "complete governed artifact purposes")
    for entry in entries:
        closed(entry, "purpose reference content_sha256 expires_at")
        require(instant(expires_at) <= instant(entry["expires_at"]) and instant(entry["expires_at"]) > now
                and entry["reference"] == governance["artifact_references"][entry["purpose"]], "input expiry/independent reference")
        members = api.artifact(entry["reference"], now, r2=entry["purpose"] == "r2-candidate")
        content = [{"name": name, "size": len(data), "sha256": sha(data)} for name, data in sorted(members.items())]
        require(sha(canonical(content)) == digest(entry["content_sha256"]), "all prior member bytes content binding")
        require(instant(entry["expires_at"]) <= api.expiries[entry["reference"]["repository"], entry["reference"]["artifact_id"]], "real artifact retention")


def validate_proof(proof, files, governance, api, now, source_sha, purpose, role):
    closed(proof, "proof_version source producer artifacts reports checks candidate_sha256 promotion_evidence_sha256 plan_binding_sha256 observed_at expires_at")
    require(proof["proof_version"] == 1 and type(proof["proof_version"]) is int, "proof version")
    closed(proof["source"], "repository ref source_sha")
    require(proof["source"] == {"repository": REPOSITORY, "ref": "refs/heads/develop", "source_sha": source_sha}, "proof source")
    require(instant(proof["observed_at"]) <= now < instant(proof["expires_at"]), "proof expiry")
    producer = closed(proof["producer"], "repository workflow_path workflow_sha run_id run_attempt")
    require({k: producer[k] for k in ("repository", "workflow_path", "workflow_sha")} in governance["proof_producers"], "unapproved producer code")
    run = api.read(f"repos/{producer['repository']}/actions/runs/{producer['run_id']}/attempts/{producer['run_attempt']}")
    require(run["conclusion"] == "success" and run["status"] == "completed" and
            run["path"].split("@")[0] == producer["workflow_path"] and run["head_sha"] == producer["workflow_sha"]
            and run["run_attempt"] == producer["run_attempt"], "proof producer live provenance")
    required = BASE_CHECKS | ({"promotion469-origin", "r2-candidate-a2-binding", "oci-promotion-byte-integrity"} if purpose == "phase-a" else set())
    if role == "deploy":
        required |= {"exact-saved-plan-package", "planned-source-input-binding"}
    checks = proof["checks"]
    require(type(checks) is list and len(checks) <= 64 and [x["check_id"] for x in checks] == sorted(required), "complete measured proof")
    reports = proof["reports"]
    require(type(reports) is list and [x["check_id"] for x in reports] == sorted(required), "complete reports")
    for check, report in zip(checks, reports):
        closed(check, "check_id subject_sha256 expected_sha256 observed_sha256 result observed_at expires_at")
        closed(report, "check_id name size sha256")
        require(check["result"] == "pass" and check["expected_sha256"] == check["observed_sha256"]
                and instant(check["observed_at"]) <= now < instant(check["expires_at"])
                and instant(proof["expires_at"]) <= instant(check["expires_at"]), "measurement equality/expiry")
        for field in ("subject_sha256", "expected_sha256", "observed_sha256"):
            digest(check[field])
        require(report["name"] not in {"index.json", "proof.json", "receipt.json", "redacted-plan.json"}
                and report["name"] in files and len(files[report["name"]]) == report["size"]
                and sha(files[report["name"]]) == digest(report["sha256"]), "report bytes")
        measured = loads(files[report["name"]], canonical=True, limit=262144)
        public_safe(measured)
        closed(measured, "check_id source_sha measurement")
        # Exact trusted evaluator pins own the report-specific facts, not caller input.
        require(type(measured) is dict and measured.get("check_id") == check["check_id"]
                and measured.get("source_sha") == source_sha and measured.get("measurement") not in (None, {}, []), "unexplained pass report")
        require(sha(canonical(measured["measurement"])) == check["observed_sha256"], "measured subject bytes")
    validate_artifact_set(proof["artifacts"], governance, api, now, proof["expires_at"])
    return proof


def preflight(descriptor, governance, api, role, now):
    closed(descriptor, "schema_version repository source_sha producer_pins baseline_artifacts payload_artifact")
    require(type(descriptor["schema_version"]) is int and descriptor["schema_version"] == 1 and descriptor["repository"] == REPOSITORY, "request version/repository")
    source = digest(descriptor["source_sha"], 40)
    baselines = descriptor["baseline_artifacts"]
    require(type(baselines) is list and [item["purpose"] for item in baselines] == sorted({"backend", "policy", "cost", "drift", "shared-outputs", "toolchain"}), "six baseline artifacts")
    for item in baselines:
        closed(item, "purpose reference")
        require(item["reference"] == governance["artifact_references"][item["purpose"]], "baseline independent producer reference")
    require(descriptor["producer_pins"] == governance["dependencies"], "dependency pins")
    current = api.read(f"repos/{REPOSITORY}/actions/runs/{os.environ['GITHUB_RUN_ID']}/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}")
    expected = {"repository": REPOSITORY, "ref": "refs/heads/develop", "event": "workflow_dispatch",
                "source_sha": source, "role": role,
                "workflow_path": f".github/workflows/infra-{'plan' if role == 'plan' else 'apply'}.yml"}
    actual = expected | {"repository": current["repository"]["full_name"], "source_sha": current["head_sha"],
                         "event": current["event"], "ref": os.environ["GITHUB_REF"], "workflow_path": current["path"].split("@")[0]}
    admit_source(actual, expected, lambda: None)
    caller = {"repository": REPOSITORY, "ref": actual["ref"], "source_ref": source,
              "workflow_ref": f"{REPOSITORY}/{actual['workflow_path']}@{current['head_sha']}"}
    require(caller in governance["caller_allowlist"], "reviewed caller/source catalog allowlist")
    require(producer_sha(current, role) == governance["gate_shas"][role], "reviewed reusable pin")
    compare = api.read(f"repos/{REPOSITORY}/compare/{source}...develop")
    require(compare["status"] in {"ahead", "identical"}, "source not contained in develop")
    checks = api.read(f"repos/{REPOSITORY}/commits/{source}/check-runs?per_page=100")["check_runs"]
    require(all(any(c["name"] == name and c["conclusion"] == "success" and c["head_sha"] == source for c in checks)
                for name in governance["required_checks"]), "required source checks")
    return current
