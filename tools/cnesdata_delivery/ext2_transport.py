"""Authenticate the physical EXT2 artifact carrier, never names or self-declared issuer."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
import io
import json
import re
import stat
from typing import Any, Callable, cast
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

from tools.cnesdata_delivery.evidence import date, require, sha

REPOSITORY = "VINIClUS/CnesData"
PRODUCER = "VINIClUS/infra-ansible"
WORKFLOW = ".github/workflows/reusable-cnesdata-signing-gate.yml"
HELPERS = tuple(
    "tools/cnesdata_delivery/" + name
    for name in (
        "evidence.py",
        "ext2_transport.py",
        "signing_gate.py",
        "ext2_inventory.py",
        "runtime-requirements.txt",
    )
)
COMMIT_STEP = "Commit EXT2 artifact reference"
MARKER = "EXT2_ARTIFACT_COMMIT_V1 "
REFERENCE_FIELDS = frozenset(
    "repository run_id run_attempt artifact_id artifact_digest publisher_job_id "
    "publisher_step_number source_sha caller_workflow_path reusable_workflow_sha".split()
)


def canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode()


def closed(value: Any, fields: set[str] | frozenset[str]) -> dict[str, Any]:
    require(type(value) is dict and set(value) == fields, "closed_object")
    return value


def loads(raw: bytes, maximum: int) -> Any:
    require(type(raw) is bytes and 0 < len(raw) <= maximum, "json_size")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def invalid(_: str) -> None:
        raise ValueError("ext2=json_constant")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid
        )
        require(canonical(value) == raw, "noncanonical_json")

        def bounded(item: Any, depth: int) -> int:
            require(depth <= 24, "json_depth")
            children = (
                item.values()
                if type(item) is dict
                else item
                if type(item) is list
                else []
            )
            count = 1 + sum(bounded(child, depth + 1) for child in children)
            require(count <= 4096, "json_nodes")
            return count

        bounded(value, 0)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError):
        raise ValueError("ext2=json_encoding") from None


def hex_digest(value: Any, length: int = 64) -> str:
    require(
        type(value) is str
        and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None,
        "digest",
    )
    return value


def positive_id(value: Any) -> str:
    require(
        type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None,
        "positive_id",
    )
    return value


def validate_reference(reference: Any) -> dict[str, Any]:
    value = closed(reference, REFERENCE_FIELDS)
    require(value["repository"] == REPOSITORY, "reference_repository")
    for name in ("run_id", "run_attempt", "artifact_id", "publisher_job_id"):
        positive_id(value[name])
    require(
        type(value["publisher_step_number"]) is int
        and 0 < value["publisher_step_number"] <= 128,
        "publisher_step",
    )
    hex_digest(value["source_sha"], 40)
    hex_digest(value["reusable_workflow_sha"], 40)
    require(
        type(value["artifact_digest"]) is str
        and value["artifact_digest"].startswith("sha256:"),
        "artifact_digest",
    )
    hex_digest(value["artifact_digest"][7:])
    require(
        re.fullmatch(
            r"\.github/workflows/[A-Za-z0-9_-]+\.yml", value["caller_workflow_path"]
        )
        is not None,
        "caller_workflow",
    )
    return value


def decode_member(raw: bytes) -> dict[str, Any]:
    value = closed(
        loads(raw, 4096), {"receipt_version_id", "receipt_sha256", "receipt_size"}
    )
    version = value["receipt_version_id"]
    require(
        type(version) is str
        and 0 < len(version) <= 1024
        and version != "null"
        and not any(ord(c) < 32 for c in version),
        "receipt_version",
    )
    hex_digest(value["receipt_sha256"])
    require(
        type(value["receipt_size"]) is int and 0 < value["receipt_size"] <= 65536,
        "receipt_size",
    )
    return value


def unpack_member(raw: bytes) -> bytes:
    require(type(raw) is bytes and 0 < len(raw) <= 1024**2, "archive_size")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
            members = bundle.infolist()
            require(len(members) == 1, "archive_members")
            item = members[0]
            kind = stat.S_IFMT(item.external_attr >> 16)
            require(
                item.filename == "receipt-ref.json"
                and not item.is_dir()
                and kind in {0, stat.S_IFREG}
                and not item.flag_bits & 1
                and 0 < item.file_size <= 4096,
                "archive_member",
            )
            member = bundle.read(item)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError):
        raise ValueError("ext2=archive_invalid") from None
    decode_member(member)
    return member


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


class GitHubClient:
    """Only API-origin authentication; one bounded download redirect, never forward bearer."""

    def __init__(self, token: str, *, opener: Callable[..., Any] | None = None):
        require(type(token) is str and bool(token), "github_token_absent")
        self.token = token
        self.open = opener or build_opener(_NoRedirect()).open

    def read(self, path: str, *, raw: bool = False, maximum: int = 8 * 1024**2) -> Any:
        require(
            path.startswith("repos/")
            and not urlsplit(path).scheme
            and not urlsplit(path).netloc
            and "\\" not in path
            and ".." not in path.split("/"),
            "api_path",
        )
        request = Request(
            "https://api.github.com/" + path,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
        try:
            try:
                response = self.open(request, timeout=20)
            except HTTPError as error:
                require(
                    raw
                    and error.code == 302
                    and (path.endswith("/zip") or path.endswith("/logs")),
                    "download_status",
                )
                location = error.headers.get("Location", "")
                parsed = urlsplit(location)
                host = parsed.hostname or ""
                require(
                    parsed.scheme == "https"
                    and parsed.username is None
                    and parsed.password is None
                    and parsed.port in {None, 443}
                    and not parsed.fragment
                    and (
                        host.endswith(".actions.githubusercontent.com")
                        or re.fullmatch(
                            r"productionresultssa[0-9]+\.blob\.core\.windows\.net", host
                        )
                        is not None
                    ),
                    "download_destination",
                )
                # A fresh request intentionally has no Authorization/API headers.
                response = self.open(Request(location), timeout=20)
            with response:
                result = response.read(maximum + 1)
            require(len(result) <= maximum, "api_response_size")
            if raw:
                return result
            return json.loads(result.decode("utf-8"))
        except Exception:
            raise ValueError("ext2=api_unavailable") from None


def _read(api: Any, path: str, *, raw: bool = False, maximum: int = 8 * 1024**2) -> Any:
    try:
        value = api.read(path, raw=raw, maximum=maximum)
    except Exception:
        raise ValueError("ext2=api_unavailable") from None
    require(
        (type(value) is bytes and len(value) <= maximum)
        if raw
        else type(value) is dict,
        "api_shape",
    )
    return value


def authenticate_closure(api: Any, profile: dict[str, Any]) -> None:
    entries = profile["closure"]
    require(type(entries) is list and 7 <= len(entries) <= 32, "source_closure")
    expected = {
        (PRODUCER, profile["workflow_sha"], path) for path in (WORKFLOW, *HELPERS)
    }
    expected.add((REPOSITORY, profile["source_sha"], profile["caller_workflow_path"]))
    entries = cast(list[dict[str, Any]], entries)
    seen: set[tuple[str, str, str]] = set()
    for entry in entries:
        closed(entry, {"repository", "revision", "path", "sha256"})
        identity = (entry["repository"], entry["revision"], entry["path"])
        require(
            identity in expected and identity not in seen, "source_closure_identity"
        )
        seen.add(identity)
        hex_digest(entry["sha256"])
        repo, revision, path = identity
        item = _read(
            api, f"repos/{repo}/contents/{path}?ref={revision}", maximum=2 * 1024**2
        )
        require(
            item.get("type") == "file"
            and item.get("encoding") == "base64"
            and item.get("path") == path
            and type(item.get("size")) is int
            and item["size"] <= 262144,
            "source_file",
        )
        try:
            content = base64.b64decode(item["content"].replace("\n", ""), validate=True)
        except Exception:
            raise ValueError("ext2=source_encoding") from None
        require(
            len(content) == item["size"] and sha(content) == entry["sha256"],
            "source_bytes",
        )
        blob = hashlib.sha1(
            b"blob " + str(len(content)).encode() + b"\0" + content
        ).hexdigest()
        require(item.get("sha") == blob, "source_blob")
    require(seen == expected, "source_closure_incomplete")


@dataclass(frozen=True)
class AuthenticatedReceiptReference:
    reference: dict[str, Any]
    receipt_reference: dict[str, Any]
    member_bytes: bytes


def authenticate_reference(
    reference: dict[str, Any],
    *,
    github: Any,
    governance: dict[str, Any],
    current_invocation: dict[str, Any] | None,
    now: datetime,
) -> AuthenticatedReceiptReference:
    ref = validate_reference(reference)
    profile = governance["provenance"]
    require(
        profile["repository_id"] == 1177879951
        and profile["owner_id"] == 124298687
        and ref["source_sha"] == profile["source_sha"]
        and ref["reusable_workflow_sha"] == profile["workflow_sha"]
        and ref["caller_workflow_path"] == profile["caller_workflow_path"],
        "governed_producer",
    )
    path = (
        f"repos/{REPOSITORY}/actions/runs/{ref['run_id']}/attempts/{ref['run_attempt']}"
    )
    run = _read(github, path)
    repo = run.get("repository", {})
    head_repo = run.get("head_repository", {})
    require(
        repo.get("id") == profile["repository_id"]
        and repo.get("full_name") == REPOSITORY
        and repo.get("owner", {}).get("id") == profile["owner_id"]
        and head_repo.get("id") == repo["id"]
        and head_repo.get("full_name") == REPOSITORY,
        "run_repository",
    )
    require(
        type(run.get("id")) is int
        and run["id"] == int(ref["run_id"])
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] == int(ref["run_attempt"])
        and run.get("head_sha") == profile["source_sha"]
        and run.get("head_branch") == "develop"
        and run.get("event") == "workflow_dispatch"
        and run.get("path", "").split("@")[0] == profile["caller_workflow_path"],
        "run_identity",
    )
    if current_invocation is None:
        require(
            run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and ref in profile["accepted_history"],
            "historical_acceptance",
        )
    else:
        require(
            current_invocation
            == {k: ref[k] for k in ("run_id", "run_attempt", "source_sha")},
            "current_invocation",
        )
        require(
            (run.get("status"), run.get("conclusion"))
            in {("in_progress", None), ("completed", "success")},
            "current_run_status",
        )
    prefix = PRODUCER + "/" + WORKFLOW + "@"
    refs = [
        item
        for item in run.get("referenced_workflows", [])
        if item.get("path", "").startswith(prefix)
    ]
    require(
        len(refs) == 1
        and refs[0].get("path") == prefix + profile["workflow_sha"]
        and refs[0].get("sha") == profile["workflow_sha"]
        and refs[0].get("ref") in {None, profile["workflow_sha"]},
        "reusable_pin",
    )
    authenticate_closure(github, profile)
    compare = _read(
        github, f"repos/{REPOSITORY}/compare/{profile['source_sha']}...develop"
    )
    require(compare.get("status") in {"identical", "ahead"}, "develop_containment")
    checks = _read(
        github,
        f"repos/{REPOSITORY}/commits/{profile['source_sha']}/check-runs?per_page=100",
    )
    required = profile["required_checks"]
    require(
        type(required) is list
        and 0 < len(required) <= 32
        and len(set(required)) == len(required),
        "required_checks",
    )
    require(
        type(checks.get("check_runs")) is list
        and checks.get("total_count") == len(checks["check_runs"])
        and len(checks["check_runs"]) <= 100,
        "checks_inventory",
    )
    require(
        all(
            any(
                item.get("name") == name
                and item.get("head_sha") == profile["source_sha"]
                and item.get("status") == "completed"
                and item.get("conclusion") == "success"
                for item in checks["check_runs"]
            )
            for name in required
        ),
        "source_checks",
    )
    jobs: list[dict[str, Any]] = []
    total: int | None = None
    for page in range(1, 5):
        part = _read(github, path + f"/jobs?per_page=100&page={page}")
        count = part.get("total_count")
        require(
            type(count) is int
            and 0 < count <= 256
            and (total is None or count == total),
            "jobs_count",
        )
        total = count
        items = part.get("jobs")
        require(type(items) is list and 0 < len(items) <= 100, "jobs_page")
        jobs.extend(items)
        require(
            len(jobs) <= count and len({x["id"] for x in jobs}) == len(jobs),
            "jobs_inventory",
        )
        if len(jobs) == count:
            break
    require(len(jobs) == total, "jobs_incomplete")
    selected = [item for item in jobs if item.get("id") == int(ref["publisher_job_id"])]
    require(
        len(selected) == 1
        and len(
            [item for item in jobs if item.get("name") == profile["publisher_job_name"]]
        )
        == 1,
        "publisher_job",
    )
    job = selected[0]
    require(
        job.get("run_id") == run["id"]
        and job.get("head_sha") == profile["source_sha"]
        and job.get("name") == profile["publisher_job_name"]
        and job.get("status") == "completed"
        and job.get("conclusion") == "success",
        "publisher_identity",
    )
    steps = job.get("steps", [])
    require(
        [x.get("name") for x in steps] == profile["publisher_steps"]
        and all(
            x.get("status") == "completed" and x.get("conclusion") == "success"
            for x in steps
        ),
        "publisher_source_steps",
    )
    step = [x for x in steps if x.get("name") == COMMIT_STEP]
    require(
        len(step) == 1 and step[0].get("number") == ref["publisher_step_number"],
        "publisher_step_identity",
    )
    log = _read(
        github,
        f"repos/{REPOSITORY}/actions/jobs/{ref['publisher_job_id']}/steps/{ref['publisher_step_number']}/logs",
        raw=True,
        maximum=65536,
    )
    try:
        lines = [
            re.sub(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z ", "", line)
            for line in log.decode("utf-8").splitlines()
        ]
    except UnicodeError:
        raise ValueError("ext2=publisher_log_encoding") from None
    records = [line[len(MARKER) :] for line in lines if line.startswith(MARKER)]
    require(len(records) == 1, "publisher_record")
    record = closed(
        loads((records[0] + "\n").encode(), 4096),
        {"artifact_id", "artifact_digest", "receipt_ref_sha256"},
    )
    require(
        record["artifact_id"] == ref["artifact_id"]
        and record["artifact_digest"] == ref["artifact_digest"],
        "publisher_artifact_binding",
    )
    artifact_path = f"repos/{REPOSITORY}/actions/artifacts/{ref['artifact_id']}"
    artifact = _read(github, artifact_path)
    produced = artifact.get("workflow_run", {})
    require(
        artifact.get("id") == int(ref["artifact_id"])
        and artifact.get("expired") is False
        and date(artifact.get("expires_at")) > now
        and artifact.get("digest") == ref["artifact_digest"]
        and produced.get("id") == run["id"]
        and produced.get("repository_id") == repo["id"]
        and produced.get("head_repository_id") == repo["id"]
        and produced.get("head_sha") == run["head_sha"],
        "artifact_metadata",
    )
    archive = _read(github, artifact_path + "/zip", raw=True, maximum=1024**2)
    require(
        sha(archive) == ref["artifact_digest"][7:]
        and type(artifact.get("size_in_bytes")) is int
        and artifact["size_in_bytes"] == len(archive),
        "artifact_archive_digest",
    )
    member = unpack_member(archive)
    require(sha(member) == record["receipt_ref_sha256"], "artifact_member_digest")
    return AuthenticatedReceiptReference(dict(ref), decode_member(member), member)
