#!/usr/bin/python3 -I
"""Run the one fixed production deployment accepted from GitHub Actions."""

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

import yaml


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PUBLIC_REPO_ROOT = "/srv/infra-ansible"
INVENTORY_REPO_ROOT = "/srv/infra-ansible-inventory"
FIXED_INVENTORY = "/srv/infra-ansible-inventory/inventories/prod/hosts.yml"
INVENTORY_VALIDATOR = (
    "/srv/infra-ansible-inventory/tests/Validate-InventoryScaffold.ps1"
)
VAULT_PASSWORD_FILE = "/etc/infra-ansible-deploy/vault-pass"
HEALTH_VAULT_FILE = (
    "/srv/infra-ansible-inventory/inventories/prod/group_vars/"
    "local_validation/vault.yml"
)
RUNTIME_DIR = "/run/infra-ansible"
LOCK_PATH = "/run/infra-ansible/deploy.lock"
STATE_PATH = "/var/lib/infra-ansible-deploy/inventory-state.json"
SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
GITHUB_MAIN_URL = (
    "https://api.github.com/repos/VINIClUS/infra-ansible/git/ref/heads/main"
)
EXTERNAL_HEALTH_URL = "https://ansible.vinisantana.com/api/ping"


class RunSpec(NamedTuple):
    playbook: str
    limit: str
    tags: str


FIXED_RUNS = (
    RunSpec(
        "playbooks/deploy-ansible-controller.yml",
        "ansible",
        "semaphore_controller,monitoring_agent",
    ),
    RunSpec("playbooks/edge-proxy-route.yml", "nginx", "edge_proxy_route"),
    RunSpec(
        "playbooks/cloudflare-access.yml",
        "localhost",
        "cloudflare_access_application",
    ),
)
FIXED_ROLLBACK = RunSpec(
    "playbooks/rollback-ansible-controller.yml",
    "ansible",
    "semaphore_controller_rollback",
)

# The fixed set of playbook runs this boundary will ever execute. Ansible
# itself scopes which secrets each run can see (via inventory group
# membership); this allowlist only fixes *which playbook/limit/tags* may
# run, matching the narrow contract the sudoers rule grants the runner.
_ALLOWED_RUNS = frozenset((*FIXED_RUNS, FIXED_ROLLBACK))
_HEALTH_VAULT_KEYS = (
    "vault_cloudflare_access_client_id",
    "vault_cloudflare_access_client_secret",
)
_HEALTH_PROGRAM = """
import os
import sys
import urllib.request

request = urllib.request.Request(
    "https://ansible.vinisantana.com/api/ping",
    headers={
        "CF-Access-Client-Id": os.environ["CLOUDFLARE_ACCESS_CLIENT_ID"],
        "CF-Access-Client-Secret": os.environ["CLOUDFLARE_ACCESS_CLIENT_SECRET"],
        "User-Agent": "infra-ansible-deploy/1",
    },
)
with urllib.request.urlopen(request, timeout=15) as response:
    body = response.read().decode("utf-8").strip()
    if response.status != 200 or body != "pong":
        raise SystemExit("external Semaphore health check failed")
""".strip()


class RollbackFailed(RuntimeError):
    """The post-switch operation and the required rollback both failed."""


def _requested_sha_argument(value: str) -> str:
    if not SHA_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "requested SHA must be exactly 40 lowercase hex characters"
        )
    return value


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deploy exactly one validated infra-ansible main SHA."
    )
    parser.add_argument("requested_sha", type=_requested_sha_argument)
    return parser.parse_args(argv)


def validate_request(
    requested_sha: str,
    main_sha: str,
    checkout_sha: str,
    dirty: bool,
) -> None:
    """Reject everything except one clean checkout of the current main SHA."""

    if not SHA_RE.fullmatch(requested_sha):
        raise ValueError("requested SHA must be exactly 40 lowercase hex characters")
    if not SHA_RE.fullmatch(main_sha):
        raise ValueError("GitHub main did not resolve to an exact SHA")
    if not SHA_RE.fullmatch(checkout_sha):
        raise ValueError("public checkout did not resolve to an exact SHA")
    if requested_sha != main_sha:
        raise ValueError("requested SHA is not the current public main SHA")
    if requested_sha != checkout_sha:
        raise ValueError("public checkout does not match the requested SHA")
    if dirty:
        raise ValueError("public checkout is dirty")


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


def fetch_public_main_sha(
    open_url: Callable[..., object] | None = None,
) -> str:
    request = urllib.request.Request(
        GITHUB_MAIN_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "infra-ansible-deploy/1",
        },
    )
    transport = build_github_opener().open if open_url is None else open_url
    with transport(request, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))
    try:
        main_sha = payload["object"]["sha"]
    except (KeyError, TypeError) as error:
        raise ValueError("GitHub main response did not contain object.sha") from error
    if not isinstance(main_sha, str) or not SHA_RE.fullmatch(main_sha):
        raise ValueError("GitHub main response contained an invalid SHA")
    return main_sha


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


def prepare_public_checkout(
    requested_sha: str,
    run: Callable[..., subprocess.CompletedProcess[str]],
    base_env: Mapping[str, str],
) -> tuple[str, bool]:
    if not SHA_RE.fullmatch(requested_sha):
        raise ValueError("requested SHA must be exactly 40 lowercase hex characters")
    env = _base_child_env(base_env)
    preexisting_changes = _run_checked(
        run, ["git", "-C", PUBLIC_REPO_ROOT, "status", "--porcelain"], env
    )
    if preexisting_changes:
        raise ValueError("public checkout is dirty before update")
    _run_checked(
        run,
        ["git", "-C", PUBLIC_REPO_ROOT, "fetch", "--force", "--prune", "origin", "main"],
        env,
    )
    _run_checked(
        run,
        ["git", "-C", PUBLIC_REPO_ROOT, "checkout", "--detach", requested_sha],
        env,
    )
    checkout_sha = _run_checked(
        run, ["git", "-C", PUBLIC_REPO_ROOT, "rev-parse", "HEAD"], env
    )
    dirty = bool(
        _run_checked(
            run, ["git", "-C", PUBLIC_REPO_ROOT, "status", "--porcelain"], env
        )
    )
    return checkout_sha, dirty


def prepare_private_inventory(
    run: Callable[..., subprocess.CompletedProcess[str]],
    base_env: Mapping[str, str],
    *,
    vault_password_file: str = VAULT_PASSWORD_FILE,
) -> str:
    env = _base_child_env(base_env)
    env["GIT_SSH_COMMAND"] = (
        "ssh -i /etc/infra-ansible-deploy/inventory-deploy-key "
        "-o IdentitiesOnly=yes -o BatchMode=yes"
    )
    _run_checked(
        run,
        ["git", "-C", INVENTORY_REPO_ROOT, "fetch", "--force", "--prune", "origin", "main"],
        env,
    )
    _run_checked(
        run,
        ["git", "-C", INVENTORY_REPO_ROOT, "checkout", "--detach", "origin/main"],
        env,
    )
    inventory_sha = _run_checked(
        run, ["git", "-C", INVENTORY_REPO_ROOT, "rev-parse", "HEAD"], env
    )
    dirty = _run_checked(
        run, ["git", "-C", INVENTORY_REPO_ROOT, "status", "--porcelain"], env
    )
    if not SHA_RE.fullmatch(inventory_sha):
        raise ValueError("private inventory did not resolve to an exact SHA")
    if dirty:
        raise ValueError("private inventory checkout is dirty")
    # The validator shells out to ansible-inventory internally and resolves
    # the vault password through the inventory repo's own ansible.cfg
    # (tools/vault/get-vault-pass.sh); point it at the controller's password
    # file by path, never by value, to keep it out of this subprocess's env.
    validator_env = dict(env)
    validator_env["ANSIBLE_VAULT_PASSWORD_FILE"] = vault_password_file
    _run_checked(
        run,
        ["pwsh", "-NoProfile", "-File", INVENTORY_VALIDATOR],
        validator_env,
        cwd=INVENTORY_REPO_ROOT,
    )
    _run_checked(
        run,
        [
            "ansible-inventory",
            "-i",
            FIXED_INVENTORY,
            "--list",
            "--vault-password-file",
            vault_password_file,
        ],
        env,
        cwd=PUBLIC_REPO_ROOT,
    )
    return inventory_sha


def record_inventory_state(
    requested_sha: str, inventory_sha: str, path: str = STATE_PATH
) -> None:
    destination = Path(path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(
        {"infra_sha": requested_sha, "inventory_sha": inventory_sha},
        sort_keys=True,
    )
    file_descriptor, temporary_path = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}."
    )
    try:
        os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as state_file:
            state_file.write(payload + "\n")
            state_file.flush()
            os.fsync(state_file.fileno())
        os.replace(temporary_path, destination)
    except BaseException:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def build_playbook_invocation(
    run_spec: RunSpec,
    requested_sha: str,
    inventory_sha: str,
    *,
    base_env: Mapping[str, str],
    vault_password_file: str = VAULT_PASSWORD_FILE,
) -> tuple[list[str], dict[str, str]]:
    if run_spec not in _ALLOWED_RUNS:
        raise ValueError("run is not in the fixed deployment allowlist")
    validate_request(requested_sha, requested_sha, requested_sha, False)
    if not SHA_RE.fullmatch(inventory_sha):
        raise ValueError("inventory SHA must be exactly 40 lowercase hex characters")

    command = [
        "ansible-playbook",
        "--vault-password-file",
        vault_password_file,
        "-i",
        FIXED_INVENTORY,
        run_spec.playbook,
        "--limit",
        run_spec.limit,
        "--tags",
        run_spec.tags,
        "--extra-vars",
        f"infra_ansible_deploy_sha={requested_sha}",
        "--extra-vars",
        f"infra_ansible_inventory_sha={inventory_sha}",
    ]
    child_env = _base_child_env(base_env)
    return command, child_env


def run_external_health_check(
    run: Callable[..., subprocess.CompletedProcess[str]],
    base_env: Mapping[str, str],
    *,
    vault_password_file: str = VAULT_PASSWORD_FILE,
    health_vault_file: str = HEALTH_VAULT_FILE,
) -> None:
    read_env = _base_child_env(base_env)
    raw_decrypted = _run_checked(
        run,
        ["ansible-vault", "view", "--vault-password-file", vault_password_file,
         health_vault_file],
        read_env,
    )
    decrypted = yaml.safe_load(raw_decrypted)
    if not isinstance(decrypted, dict):
        raise RuntimeError("vault-decrypted health secrets were not a mapping")
    missing = [key for key in _HEALTH_VAULT_KEYS if not decrypted.get(key)]
    if missing:
        raise RuntimeError("missing external health keys: " + ", ".join(missing))

    health_env = _base_child_env(base_env)
    health_env.update(
        {
            "CLOUDFLARE_ACCESS_CLIENT_ID": str(
                decrypted["vault_cloudflare_access_client_id"]
            ),
            "CLOUDFLARE_ACCESS_CLIENT_SECRET": str(
                decrypted["vault_cloudflare_access_client_secret"]
            ),
        }
    )
    _run_checked(
        run,
        ["/usr/bin/python3", "-c", _HEALTH_PROGRAM],
        health_env,
        cwd=PUBLIC_REPO_ROOT,
    )


def execute_fixed_sequence(
    playbook_runner: Callable[[RunSpec], object],
    health_checker: Callable[[], object],
) -> None:
    playbook_runner(FIXED_RUNS[0])
    try:
        for run_spec in FIXED_RUNS[1:]:
            playbook_runner(run_spec)
        health_checker()
    except Exception as deployment_error:
        try:
            playbook_runner(FIXED_ROLLBACK)
        except Exception as rollback_error:
            raise RollbackFailed(
                "post-switch deployment failed and fixed rollback also failed"
            ) from rollback_error
        raise deployment_error


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


def deploy_requested_sha(
    requested_sha: str,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    open_url: Callable[..., object] | None = None,
    base_env: MutableMapping[str, str] | None = None,
) -> None:
    if not SHA_RE.fullmatch(requested_sha):
        raise ValueError("requested SHA must be exactly 40 lowercase hex characters")
    root_environment = os.environ if base_env is None else base_env
    environment = sanitize_root_environment(root_environment)
    with deployment_lock():
        main_sha = fetch_public_main_sha(open_url)
        checkout_sha, dirty = prepare_public_checkout(requested_sha, run, environment)
        validate_request(requested_sha, main_sha, checkout_sha, dirty)

        inventory_sha = prepare_private_inventory(
            run, environment, vault_password_file=VAULT_PASSWORD_FILE
        )
        record_inventory_state(requested_sha, inventory_sha)

        def playbook_runner(run_spec: RunSpec) -> None:
            command, child_env = build_playbook_invocation(
                run_spec,
                requested_sha,
                inventory_sha,
                base_env=environment,
            )
            _run_checked(run, command, child_env, cwd=PUBLIC_REPO_ROOT)

        execute_fixed_sequence(
            playbook_runner,
            lambda: run_external_health_check(run, environment),
        )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    deploy_requested_sha(arguments.requested_sha)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        json.JSONDecodeError,
        OSError,
        RollbackFailed,
        RuntimeError,
        subprocess.CalledProcessError,
        ValueError,
    ) as error:
        print(f"infra-ansible-deploy: {error}", file=sys.stderr)
        raise SystemExit(1)
