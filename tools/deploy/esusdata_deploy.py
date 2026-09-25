#!/usr/bin/python3 -I
"""Deploy one published esusdata release through a fixed Ansible boundary."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Mapping, MutableMapping, NamedTuple, Sequence


TAG_RE = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PUBLIC_REPO_ROOT = "/srv/infra-ansible"
INVENTORY_REPO_ROOT = "/srv/infra-ansible-inventory"
FIXED_INVENTORY = "/srv/infra-ansible-inventory/inventories/prod/hosts.yml"
FIXED_PLAYBOOK = "playbooks/esusdata-service.yml"
FIXED_LIMIT = "esusdata-lxc"
FIXED_TAG = "esusdata_service"
VAULT_PASSWORD_FILE = "/etc/infra-ansible-deploy/vault-pass"
LOCK_PATH = "/run/infra-ansible/deploy.lock"
STATE_PATH = "/var/lib/esusdata-deploy/state.json"
SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
RELEASES_API = "https://api.github.com/repos/VINIClUS/esusdata/releases"
PACKAGE_NAME = "observatorio-aps"


class Release(NamedTuple):
    tag: str
    version: str


def _tag_argument(value: str) -> str:
    if not TAG_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("release tag must look like v1.2.3")
    return value


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Deploy the latest published esusdata release, or one exact "
            "published tag."
        )
    )
    parser.add_argument("tag", nargs="?", type=_tag_argument)
    return parser.parse_args(argv)


def _base_child_env(_base_env: Mapping[str, str]) -> dict[str, str]:
    return {
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
    }


def sanitize_root_environment(
    environment: MutableMapping[str, str],
) -> dict[str, str]:
    """Discard all caller-controlled process environment values."""

    sanitized = _base_child_env(environment)
    environment.clear()
    environment.update(sanitized)
    return dict(sanitized)


def build_github_opener():
    tls_context = ssl.create_default_context(cafile=SYSTEM_CA_BUNDLE)
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=tls_context),
    )


def release_from_payload(payload: object, requested_tag: str | None) -> Release:
    """Accept only a published, final release that carries the signed package."""

    if not isinstance(payload, dict):
        raise ValueError("GitHub release response was not an object")
    tag = payload.get("tag_name")
    if not isinstance(tag, str):
        raise ValueError("GitHub release response has no tag_name")
    match = TAG_RE.fullmatch(tag)
    if match is None:
        raise ValueError("GitHub release tag is not an exact vX.Y.Z version")
    if requested_tag is not None and tag != requested_tag:
        raise ValueError("GitHub returned a different release than requested")
    if payload.get("draft") is not False or payload.get("prerelease") is not False:
        raise ValueError("release is not published as a final release")
    version = match.group(1)
    assets = payload.get("assets")
    names = (
        {asset.get("name") for asset in assets if isinstance(asset, dict)}
        if isinstance(assets, list)
        else set()
    )
    required = {
        "SHA256SUMS",
        "SHA256SUMS.sig",
        f"{PACKAGE_NAME}_{version}_amd64.deb",
    }
    missing = sorted(required - names)
    if missing:
        raise ValueError("release is missing assets: " + ", ".join(missing))
    return Release(tag, version)


def fetch_release(
    requested_tag: str | None,
    open_url: Callable[..., object] | None = None,
) -> Release:
    if requested_tag is not None and not TAG_RE.fullmatch(requested_tag):
        raise ValueError("release tag must look like v1.2.3")
    url = (
        f"{RELEASES_API}/latest"
        if requested_tag is None
        else f"{RELEASES_API}/tags/{requested_tag}"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "esusdata-deploy/1",
        },
    )
    transport = build_github_opener().open if open_url is None else open_url
    with transport(request, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return release_from_payload(payload, requested_tag)


def _run_checked(
    run: Callable[..., subprocess.CompletedProcess[str]],
    command: list[str],
    env: Mapping[str, str],
    *,
    cwd: str | None = None,
) -> str:
    result = run(
        command,
        env=dict(env),
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _run_streamed(
    run: Callable[..., subprocess.CompletedProcess[str]],
    command: list[str],
    env: Mapping[str, str],
    *,
    cwd: str,
) -> None:
    """Let the playbook log reach the job; its secret tasks are all no_log."""

    run(command, env=dict(env), cwd=cwd, check=True)


def require_clean_checkouts(
    run: Callable[..., subprocess.CompletedProcess[str]],
    base_env: Mapping[str, str],
) -> tuple[str, str]:
    """Deploy only with the repositories the last infra deploy left in place."""

    env = _base_child_env(base_env)
    shas = []
    for root in (PUBLIC_REPO_ROOT, INVENTORY_REPO_ROOT):
        if _run_checked(run, ["git", "-C", root, "status", "--porcelain"], env):
            raise ValueError(f"{root} checkout is dirty")
        sha = _run_checked(run, ["git", "-C", root, "rev-parse", "HEAD"], env)
        if not SHA_RE.fullmatch(sha):
            raise ValueError(f"{root} did not resolve to an exact SHA")
        shas.append(sha)
    return shas[0], shas[1]


def build_playbook_invocation(
    release: Release,
    *,
    base_env: Mapping[str, str],
    vault_password_file: str = VAULT_PASSWORD_FILE,
) -> tuple[list[str], dict[str, str]]:
    if not TAG_RE.fullmatch(release.tag) or release.tag != f"v{release.version}":
        raise ValueError("release tag and version do not match")
    command = [
        "ansible-playbook",
        "--vault-password-file",
        vault_password_file,
        "-i",
        FIXED_INVENTORY,
        FIXED_PLAYBOOK,
        "--limit",
        FIXED_LIMIT,
        "--tags",
        FIXED_TAG,
        "--extra-vars",
        f"esusdata_service_version={release.version}",
    ]
    return command, _base_child_env(base_env)


def read_state(path: str = STATE_PATH) -> dict[str, str]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(payload, dict):
        raise ValueError("deployment state is not an object")
    return {key: value for key, value in payload.items() if isinstance(value, str)}


def write_state(state: Mapping[str, str], path: str = STATE_PATH) -> None:
    destination = Path(path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    file_descriptor, temporary_path = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}."
    )
    try:
        os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as state_file:
            state_file.write(json.dumps(dict(state), sort_keys=True) + "\n")
            state_file.flush()
            os.fsync(state_file.fileno())
        os.replace(temporary_path, destination)
    except BaseException:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def should_deploy(
    release: Release, state: Mapping[str, str], *, explicit: bool
) -> bool:
    """Scheduled runs skip the deployed release and a release that already failed."""

    if explicit:
        return True
    return release.version not in (state.get("version"), state.get("failed_version"))


def validate_lock_metadata(metadata, expected_uid: int = 0) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise PermissionError("deployment lock must be a regular file")
    if metadata.st_uid != expected_uid:
        raise PermissionError("deployment lock must be owned by root")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PermissionError("deployment lock must have mode 0600")


def _validate_runtime_directory(metadata, expected_uid: int) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise PermissionError("deployment runtime path must be a directory")
    if metadata.st_uid != expected_uid:
        raise PermissionError("deployment runtime directory must be owned by root")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise PermissionError("deployment runtime directory must have mode 0700")


@contextmanager
def deployment_lock(path: str = LOCK_PATH, *, expected_uid: int = 0):
    """Share infra-ansible-deploy's lock so the two boundaries never overlap."""

    runtime_path = os.path.dirname(path)
    lock_name = os.path.basename(path)
    try:
        os.mkdir(runtime_path, 0o700)
    except FileExistsError:
        pass
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    runtime_fd = os.open(runtime_path, directory_flags)
    lock_fd = None
    try:
        _validate_runtime_directory(os.fstat(runtime_fd), expected_uid)
        lock_flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        lock_fd = os.open(lock_name, lock_flags, 0o600, dir_fd=runtime_fd)
        validate_lock_metadata(os.fstat(lock_fd), expected_uid)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(runtime_fd)


def deploy_release(
    requested_tag: str | None,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    open_url: Callable[..., object] | None = None,
    base_env: MutableMapping[str, str] | None = None,
    state_path: str = STATE_PATH,
    lock: Callable[[], object] = deployment_lock,
) -> str:
    if requested_tag is not None and not TAG_RE.fullmatch(requested_tag):
        raise ValueError("release tag must look like v1.2.3")
    root_environment = os.environ if base_env is None else base_env
    environment = sanitize_root_environment(root_environment)
    with lock():
        release = fetch_release(requested_tag, open_url)
        state = read_state(state_path)
        if not should_deploy(release, state, explicit=requested_tag is not None):
            return f"esusdata {release.version} needs no deployment"
        infra_sha, inventory_sha = require_clean_checkouts(run, environment)
        command, child_env = build_playbook_invocation(
            release, base_env=environment
        )
        try:
            _run_streamed(run, command, child_env, cwd=PUBLIC_REPO_ROOT)
        except subprocess.CalledProcessError:
            write_state({**state, "failed_version": release.version}, state_path)
            raise
        write_state(
            {
                "version": release.version,
                "infra_sha": infra_sha,
                "inventory_sha": inventory_sha,
            },
            state_path,
        )
        return f"esusdata {release.version} deployed"


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    print(f"esusdata-deploy: {deploy_release(arguments.tag)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        json.JSONDecodeError,
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
        ValueError,
    ) as error:
        print(f"esusdata-deploy: {error}", file=sys.stderr)
        raise SystemExit(1)
