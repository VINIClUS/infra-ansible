#!/usr/bin/env python3
"""Create the Ansible controller's bootstrap secrets without disclosing them."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


SECRET_NAMES = (
    "ANSIBLE_BACKUP_AGE_IDENTITY",
    "CLOUDFLARE_ACCESS_CLIENT_ID",
    "CLOUDFLARE_ACCESS_CLIENT_SECRET",
    "INFRA_INVENTORY_DEPLOY_KEY",
    "SEMAPHORE_ACCESS_KEY_ENCRYPTION",
    "SEMAPHORE_ADMIN_PASSWORD",
    "SEMAPHORE_DB_PASSWORD",
)
INFISICAL_SECRET_PATH = "/ansible"
GITHUB_INVENTORY_REPOSITORY = "VINIClUS/infra-ansible-inventory"
GITHUB_DEPLOY_KEY_TITLE = "infra-ansible production inventory"
CLOUDFLARE_SERVICE_TOKEN_NAME = "Semaphore production health check"


class SeedError(RuntimeError):
    """An intentionally redacted provisioning error."""


class RemoteStateUncertain(SeedError):
    """A mutating remote request may have committed without a usable response."""


@dataclass(frozen=True)
class Config:
    infisical_url: str
    infisical_project_id: str
    infisical_environment: str
    infisical_client_id: str
    infisical_client_secret: str
    cloudflare_api_url: str
    cloudflare_account_id: str
    cloudflare_api_token: str
    inventory_root: Path

    @classmethod
    def from_environment(cls, inventory_root: Path) -> "Config":
        required = {
            "INFISICAL_PROJECT_ID": os.environ.get("INFISICAL_PROJECT_ID", ""),
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": os.environ.get(
                "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", ""
            ),
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": os.environ.get(
                "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", ""
            ),
            "CLOUDFLARE_ACCOUNT_ID": os.environ.get("CLOUDFLARE_ACCOUNT_ID", ""),
            "CLOUDFLARE_API_TOKEN": os.environ.get("CLOUDFLARE_API_TOKEN", ""),
        }
        missing = sorted(name for name, value in required.items() if not value)
        if missing:
            raise SeedError("missing required environment variables: " + ", ".join(missing))
        return cls(
            infisical_url=os.environ.get(
                "INFISICAL_API_URL", "https://infisical.vinisantana.com"
            ).rstrip("/"),
            infisical_project_id=required["INFISICAL_PROJECT_ID"],
            infisical_environment=os.environ.get("INFISICAL_ENVIRONMENT", "prod"),
            infisical_client_id=required["INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"],
            infisical_client_secret=required[
                "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"
            ],
            cloudflare_api_url=os.environ.get(
                "CLOUDFLARE_API_URL", "https://api.cloudflare.com/client/v4"
            ).rstrip("/"),
            cloudflare_account_id=required["CLOUDFLARE_ACCOUNT_ID"],
            cloudflare_api_token=required["CLOUDFLARE_API_TOKEN"],
            inventory_root=inventory_root,
        )


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class HttpResponse:
    status: int
    payload: Any


Transport = Callable[[HttpRequest], HttpResponse]


def _urllib_transport(request: HttpRequest) -> HttpResponse:
    raw_request = urllib.request.Request(
        request.url,
        data=request.body or None,
        headers=dict(request.headers),
        method=request.method,
    )
    try:
        with urllib.request.urlopen(raw_request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8") or "{}")
            return HttpResponse(response.status, payload)
    except urllib.error.HTTPError as error:
        raise SeedError(f"HTTP request failed with status {error.code}") from None
    except (urllib.error.URLError, TimeoutError, UnicodeError, json.JSONDecodeError):
        raise SeedError("HTTP request failed") from None


def request_json(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: Mapping[str, Any] | None = None,
    transport: Transport = _urllib_transport,
    operation: str = "API request",
) -> Any:
    request_headers = {"Accept": "application/json", **(headers or {})}
    encoded_body = b""
    if body is not None:
        request_headers["Content-Type"] = "application/json"
        encoded_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    try:
        response = transport(
            HttpRequest(
                method=method,
                url=url,
                headers=request_headers,
                body=encoded_body,
            )
        )
    except Exception:
        # The transport exception may echo a request body or header.
        raise SeedError(f"{operation} failed") from None
    if response.status < 200 or response.status >= 300:
        raise SeedError(f"{operation} failed with HTTP status {response.status}")
    return response.payload


class InfisicalClient:
    def __init__(self, config: Config, *, transport: Transport = _urllib_transport) -> None:
        self._config = config
        self._transport = transport
        self._access_token: str | None = None

    def _token(self) -> str:
        if self._access_token is None:
            response = request_json(
                "POST",
                f"{self._config.infisical_url}/api/v1/auth/universal-auth/login",
                body={
                    "clientId": self._config.infisical_client_id,
                    "clientSecret": self._config.infisical_client_secret,
                },
                transport=self._transport,
                operation="Infisical authentication",
            )
            token = response.get("accessToken", "") if isinstance(response, dict) else ""
            if not token:
                raise SeedError("Infisical authentication returned no access token")
            self._access_token = token
        return self._access_token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token()}"}

    def _query(self, *, view_secret_value: bool = False) -> str:
        return urllib.parse.urlencode(
            {
                "projectId": self._config.infisical_project_id,
                "environment": self._config.infisical_environment,
                "secretPath": INFISICAL_SECRET_PATH,
                "viewSecretValue": str(view_secret_value).lower(),
                "recursive": "false",
            }
        )

    def existing_secret_names(self) -> set[str]:
        payload = request_json(
            "GET",
            f"{self._config.infisical_url}/api/v4/secrets?{self._query()}",
            headers=self._headers(),
            transport=self._transport,
            operation="Infisical secret listing",
        )
        secrets_list = payload.get("secrets", []) if isinstance(payload, dict) else []
        if not isinstance(secrets_list, list):
            raise SeedError("Infisical secret listing returned an invalid response")
        return {
            item["secretKey"]
            for item in secrets_list
            if isinstance(item, dict) and isinstance(item.get("secretKey"), str)
        }

    def _secret_url(self, name: str) -> str:
        return (
            f"{self._config.infisical_url}/api/v4/secrets/"
            f"{urllib.parse.quote(name, safe='')}"
        )

    def _write_body(self, value: str) -> dict[str, Any]:
        return {
            "projectId": self._config.infisical_project_id,
            "environment": self._config.infisical_environment,
            "secretPath": INFISICAL_SECRET_PATH,
            "secretValue": value,
            "type": "shared",
        }

    def create_secret(self, name: str, value: str) -> None:
        request_json(
            "POST",
            self._secret_url(name),
            headers=self._headers(),
            body=self._write_body(value),
            transport=self._transport,
            operation=f"Infisical create for {name}",
        )

    def replace_secret(self, name: str, value: str) -> None:
        request_json(
            "PATCH",
            self._secret_url(name),
            headers=self._headers(),
            body=self._write_body(value),
            transport=self._transport,
            operation=f"Infisical rotation for {name}",
        )

    def read_secret_value(self, name: str) -> str:
        payload = request_json(
            "GET",
            f"{self._secret_url(name)}?{self._query(view_secret_value=True)}",
            headers=self._headers(),
            transport=self._transport,
            operation=f"Infisical rotation snapshot for {name}",
        )
        value = payload.get("secret", {}).get("secretValue") if isinstance(payload, dict) else None
        if not isinstance(value, str):
            raise SeedError(f"Infisical rotation snapshot for {name} returned no value")
        return value

    def delete_secret(self, name: str) -> None:
        request_json(
            "DELETE",
            self._secret_url(name),
            headers=self._headers(),
            body={
                "projectId": self._config.infisical_project_id,
                "environment": self._config.infisical_environment,
                "secretPath": INFISICAL_SECRET_PATH,
                "type": "shared",
            },
            transport=self._transport,
            operation=f"Infisical compensation for {name}",
        )


Command = Callable[..., subprocess.CompletedProcess[str]]


def _minimal_command_environment() -> dict[str, str]:
    return {
        "HOME": os.environ.get("HOME", ""),
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _run_command(argv: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        raise SeedError(f"{argv[0]} execution failed") from None
    if completed.returncode != 0:
        # stderr/stdout can contain key material. Never include either.
        raise SeedError(f"{argv[0]} execution failed")
    return completed


@dataclass(frozen=True)
class KeyMaterial:
    age_identity: str
    age_recipient: str
    deploy_private_key: str
    deploy_public_key: str
    deploy_public_key_path: Path
    workdir: Path


@contextmanager
def generated_key_material(
    *, command: Command = _run_command, temp_parent: Path | None = None
) -> Iterator[KeyMaterial]:
    workdir = Path(tempfile.mkdtemp(prefix="ansible-seed-", dir=temp_parent))
    os.chmod(workdir, 0o700)
    environment = _minimal_command_environment()
    age_path = workdir / "backup-age-identity"
    deploy_path = workdir / "inventory-deploy-key"
    try:
        command(["age-keygen", "-o", str(age_path)], env=environment)
        os.chmod(age_path, 0o600)
        age_recipient_result = command(
            ["age-keygen", "-y", str(age_path)], env=environment
        )
        command(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                GITHUB_DEPLOY_KEY_TITLE,
                "-f",
                str(deploy_path),
            ],
            env=environment,
        )
        public_path = deploy_path.with_suffix(".pub")
        os.chmod(deploy_path, 0o600)
        os.chmod(public_path, 0o600)
        yield KeyMaterial(
            age_identity=age_path.read_text(encoding="utf-8").rstrip("\n"),
            age_recipient=age_recipient_result.stdout.strip(),
            deploy_private_key=deploy_path.read_text(encoding="utf-8").rstrip("\n"),
            deploy_public_key=public_path.read_text(encoding="utf-8").strip(),
            deploy_public_key_path=public_path,
            workdir=workdir,
        )
    except SeedError:
        raise
    except (OSError, UnicodeError):
        raise SeedError("temporary key generation failed") from None
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def register_read_only_deploy_key(
    material: KeyMaterial, *, command: Command = _run_command
) -> int | None:
    environment = _minimal_command_environment()
    before = command(
        ["gh", "api", f"repos/{GITHUB_INVENTORY_REPOSITORY}/keys"],
        env=environment,
    )
    if _github_deploy_key_matches(before.stdout, title=GITHUB_DEPLOY_KEY_TITLE):
        raise SeedError("GitHub deploy key with the managed title already exists")
    try:
        command(
            [
                "gh",
                "repo",
                "deploy-key",
                "add",
                str(material.deploy_public_key_path),
                "--repo",
                GITHUB_INVENTORY_REPOSITORY,
                "--title",
                GITHUB_DEPLOY_KEY_TITLE,
            ],
            env=environment,
        )
    except Exception:
        raise RemoteStateUncertain(
            "GitHub deploy-key create response was ambiguous; manual recovery required"
        ) from None
    try:
        listing = command(
            ["gh", "api", f"repos/{GITHUB_INVENTORY_REPOSITORY}/keys"],
            env=environment,
        )
        matches = _github_deploy_key_matches(
            listing.stdout,
            title=GITHUB_DEPLOY_KEY_TITLE,
            public_key=material.deploy_public_key,
            require_read_only=True,
        )
    except Exception:
        raise RemoteStateUncertain(
            "GitHub deploy-key readback was ambiguous; manual recovery required"
        ) from None
    if len(matches) != 1 or not isinstance(matches[0].get("id"), int):
        raise RemoteStateUncertain(
            "GitHub deploy-key readback was not exact; manual recovery required"
        )
    return matches[0]["id"]


def _github_deploy_key_matches(
    output: str,
    *,
    title: str,
    public_key: str | None = None,
    require_read_only: bool = False,
) -> list[dict[str, Any]]:
    if not output.strip():
        return []
    try:
        parsed = json.loads(output)
        if not isinstance(parsed, list):
            raise TypeError
        return [
            item
            for item in parsed
            if isinstance(item, dict)
            and item.get("title") == title
            and (public_key is None or item.get("key", "").strip() == public_key)
            and (not require_read_only or item.get("read_only") is True)
        ]
    except (json.JSONDecodeError, TypeError, AttributeError):
        raise SeedError("GitHub deploy-key readback failed") from None


def delete_github_deploy_key(key_id: int | None, *, command: Command = _run_command) -> None:
    if key_id is None:
        return
    command(
        [
            "gh",
            "api",
            "--method",
            "DELETE",
            f"repos/{GITHUB_INVENTORY_REPOSITORY}/keys/{key_id}",
        ],
        env=_minimal_command_environment(),
    )


@dataclass(frozen=True)
class CloudflareServiceToken:
    resource_id: str
    client_id: str
    client_secret: str


def create_cloudflare_service_token(
    config: Config, *, transport: Transport = _urllib_transport
) -> CloudflareServiceToken:
    collection_url = (
        f"{config.cloudflare_api_url}/accounts/{config.cloudflare_account_id}"
        "/access/service_tokens"
    )
    headers = {"Authorization": f"Bearer {config.cloudflare_api_token}"}
    listing = request_json(
        "GET",
        f"{collection_url}?per_page=100",
        headers=headers,
        transport=transport,
        operation="Cloudflare Access service-token preflight",
    )
    listed_tokens = listing.get("result", []) if isinstance(listing, dict) else []
    if not isinstance(listed_tokens, list):
        raise SeedError("Cloudflare Access service-token preflight returned an invalid response")
    if any(
        isinstance(item, dict) and item.get("name") == CLOUDFLARE_SERVICE_TOKEN_NAME
        for item in listed_tokens
    ):
        raise SeedError("Cloudflare Access service token with the managed name already exists")
    try:
        payload = request_json(
            "POST",
            collection_url,
            headers=headers,
            body={"name": CLOUDFLARE_SERVICE_TOKEN_NAME, "duration": "8760h"},
            transport=transport,
            operation="Cloudflare Access service-token creation",
        )
    except Exception:
        raise RemoteStateUncertain(
            "Cloudflare service-token create response was ambiguous; "
            "manual recovery required"
        ) from None
    result = payload.get("result", {}) if isinstance(payload, dict) else {}
    values = (
        result.get("id") if isinstance(result, dict) else None,
        result.get("client_id") if isinstance(result, dict) else None,
        result.get("client_secret") if isinstance(result, dict) else None,
    )
    if not all(isinstance(value, str) and value for value in values):
        raise RemoteStateUncertain(
            "Cloudflare service-token create response was incomplete; "
            "manual recovery required"
        )
    return CloudflareServiceToken(*values)


def delete_cloudflare_service_token(
    config: Config, resource_id: str, *, transport: Transport = _urllib_transport
) -> None:
    request_json(
        "DELETE",
        (
            f"{config.cloudflare_api_url}/accounts/{config.cloudflare_account_id}"
            f"/access/service_tokens/{urllib.parse.quote(resource_id, safe='')}"
        ),
        headers={"Authorization": f"Bearer {config.cloudflare_api_token}"},
        transport=transport,
        operation="Cloudflare Access service-token compensation",
    )


@dataclass(frozen=True)
class GeneratedResources:
    values: Mapping[str, str]
    age_recipient: str
    cloudflare_service_token_id: str | None
    github_deploy_key_id: int | None


def generate_resources(
    config: Config,
    target_names: set[str],
    *,
    command: Command = _run_command,
    transport: Transport = _urllib_transport,
) -> GeneratedResources:
    values: dict[str, str] = {}
    cloudflare_token: CloudflareServiceToken | None = None
    deploy_key_id: int | None = None
    age_recipient = ""
    needs_keys = bool(
        target_names & {"ANSIBLE_BACKUP_AGE_IDENTITY", "INFRA_INVENTORY_DEPLOY_KEY"}
    )
    key_context = generated_key_material(command=command) if needs_keys else _empty_keys()
    try:
        with key_context as key_material:
            if "SEMAPHORE_DB_PASSWORD" in target_names:
                values["SEMAPHORE_DB_PASSWORD"] = secrets.token_urlsafe(48)
            if "SEMAPHORE_ADMIN_PASSWORD" in target_names:
                values["SEMAPHORE_ADMIN_PASSWORD"] = secrets.token_urlsafe(48)
            if "SEMAPHORE_ACCESS_KEY_ENCRYPTION" in target_names:
                values["SEMAPHORE_ACCESS_KEY_ENCRYPTION"] = base64.b64encode(
                    secrets.token_bytes(32)
                ).decode("ascii")
            if key_material is not None:
                age_recipient = key_material.age_recipient
                if "ANSIBLE_BACKUP_AGE_IDENTITY" in target_names:
                    values["ANSIBLE_BACKUP_AGE_IDENTITY"] = key_material.age_identity
                if "INFRA_INVENTORY_DEPLOY_KEY" in target_names:
                    deploy_key_id = register_read_only_deploy_key(
                        key_material, command=command
                    )
                    values["INFRA_INVENTORY_DEPLOY_KEY"] = key_material.deploy_private_key
            cloudflare_names = {
                "CLOUDFLARE_ACCESS_CLIENT_ID",
                "CLOUDFLARE_ACCESS_CLIENT_SECRET",
            }
            if target_names & cloudflare_names:
                if not cloudflare_names <= target_names:
                    raise SeedError("Cloudflare Access credentials must rotate together")
                cloudflare_token = create_cloudflare_service_token(
                    config, transport=transport
                )
                values["CLOUDFLARE_ACCESS_CLIENT_ID"] = cloudflare_token.client_id
                values["CLOUDFLARE_ACCESS_CLIENT_SECRET"] = cloudflare_token.client_secret
        if set(values) != target_names:
            raise SeedError("generated secret contract was incomplete")
    except Exception as error:
        compensation_ok = not isinstance(error, RemoteStateUncertain)
        if cloudflare_token is not None:
            compensation_ok &= _best_effort(
                lambda: delete_cloudflare_service_token(
                    config, cloudflare_token.resource_id, transport=transport
                )
            )
        if deploy_key_id is not None:
            compensation_ok &= _best_effort(
                lambda: delete_github_deploy_key(deploy_key_id, command=command)
            )
        state = "completed" if compensation_ok else "incomplete; manual recovery required"
        raise SeedError(f"resource generation failed; compensation {state}") from None
    return GeneratedResources(
        values=values,
        age_recipient=age_recipient,
        cloudflare_service_token_id=(
            cloudflare_token.resource_id if cloudflare_token else None
        ),
        github_deploy_key_id=deploy_key_id,
    )


@contextmanager
def _empty_keys() -> Iterator[None]:
    yield None


class InfisicalProvisioningClient(Protocol):
    def existing_secret_names(self) -> set[str]: ...

    def create_secret(self, name: str, value: str) -> None: ...

    def delete_secret(self, name: str) -> None: ...


Summary = dict[str, Any]


def _summary(
    *,
    cloudflare_service_token_id: str | None,
    created_names: set[str],
    existing_names: set[str],
    missing_names: set[str],
) -> Summary:
    return {
        "cloudflare_service_token_id": cloudflare_service_token_id,
        "created_names": sorted(created_names),
        "existing_names": sorted(existing_names),
        "missing_names": sorted(missing_names),
    }


def _best_effort(action: Callable[[], None]) -> bool:
    try:
        action()
        return True
    except Exception:
        return False


def provision(
    config: Config,
    *,
    infisical: InfisicalProvisioningClient | None = None,
    rotate: set[str] | None = None,
    generate_resources: Callable[[], GeneratedResources] | None = None,
    compensate_cloudflare: Callable[[str], None] | None = None,
    compensate_github: Callable[[int | None], None] | None = None,
) -> Summary:
    approved = set(SECRET_NAMES)
    rotate = set(rotate or set())
    infisical = infisical or InfisicalClient(config)
    existing = infisical.existing_secret_names() & approved

    if rotate - (approved & existing):
        raise SeedError("--rotate must name an approved existing secret")
    cloudflare_pair = {
        "CLOUDFLARE_ACCESS_CLIENT_ID",
        "CLOUDFLARE_ACCESS_CLIENT_SECRET",
    }
    if rotate & cloudflare_pair and not cloudflare_pair <= rotate:
        raise SeedError("Cloudflare Access credentials must rotate together")
    missing = approved - existing
    if existing and missing and not rotate:
        raise SeedError(
            "partial secret contract exists; use explicit --rotate after recovery review"
        )
    target_names = missing | rotate
    if not target_names:
        return _summary(
            cloudflare_service_token_id=None,
            created_names=set(),
            existing_names=existing,
            missing_names=set(),
        )

    resource_factory = generate_resources or (
        lambda: globals()["generate_resources"](config, target_names)
    )
    resources = resource_factory()
    if set(resources.values) != target_names:
        raise SeedError("generated values did not match the requested secret names")

    old_values: dict[str, str] = {}
    if rotate:
        if not hasattr(infisical, "read_secret_value") or not hasattr(
            infisical, "replace_secret"
        ):
            raise SeedError("rotation client cannot snapshot and restore existing secrets")
        old_values = {
            name: getattr(infisical, "read_secret_value")(name) for name in rotate
        }

    attempted_creates: list[str] = []
    attempted_rotations: list[str] = []
    inventory_rollback: Callable[[], None] = lambda: None
    compensate_cloudflare = compensate_cloudflare or (
        lambda resource_id: delete_cloudflare_service_token(config, resource_id)
    )
    compensate_github = compensate_github or delete_github_deploy_key
    try:
        for name in sorted(target_names):
            if name in rotate:
                attempted_rotations.append(name)
                getattr(infisical, "replace_secret")(name, resources.values[name])
            else:
                attempted_creates.append(name)
                infisical.create_secret(name, resources.values[name])
        if resources.cloudflare_service_token_id or resources.age_recipient:
            inventory_rollback = write_public_inventory_metadata(
                config.inventory_root,
                cloudflare_service_token_id=resources.cloudflare_service_token_id,
                age_recipient=resources.age_recipient or None,
            )
    except Exception:
        compensation_ok = _best_effort(inventory_rollback)
        for name in reversed(attempted_rotations):
            compensation_ok &= _best_effort(
                lambda name=name: getattr(infisical, "replace_secret")(
                    name, old_values[name]
                )
            )
        for name in reversed(attempted_creates):
            compensation_ok &= _best_effort(
                lambda name=name: infisical.delete_secret(name)
            )
        if resources.cloudflare_service_token_id:
            compensation_ok &= _best_effort(
                lambda: compensate_cloudflare(resources.cloudflare_service_token_id or "")
            )
        if resources.github_deploy_key_id is not None:
            compensation_ok &= _best_effort(
                lambda: compensate_github(resources.github_deploy_key_id)
            )
        state = "completed" if compensation_ok else "incomplete; manual recovery required"
        raise SeedError(f"provisioning failed; compensation {state}") from None

    return _summary(
        cloudflare_service_token_id=resources.cloudflare_service_token_id,
        created_names=target_names,
        existing_names=existing - rotate,
        missing_names=set(),
    )


def _replace_exact_setting(path: Path, name: str, value: str) -> str:
    original = path.read_text(encoding="utf-8")
    lines = original.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.startswith(f"{name}:")]
    if len(matches) != 1:
        raise SeedError(f"private inventory must contain exactly one {name} setting")
    newline = "\n" if lines[matches[0]].endswith("\n") else ""
    lines[matches[0]] = f'{name}: "{value}"{newline}'
    return "".join(lines)


def _atomic_write(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_public_inventory_metadata(
    inventory_root: Path,
    *,
    cloudflare_service_token_id: str | None,
    age_recipient: str | None,
) -> Callable[[], None]:
    updates: list[tuple[Path, str, str]] = []
    if cloudflare_service_token_id:
        updates.append(
            (
                inventory_root
                / "inventories/prod/group_vars/local_validation/cloudflare_access.yml",
                "cloudflare_access_service_token_id",
                cloudflare_service_token_id,
            )
        )
    if age_recipient:
        updates.append(
            (
                inventory_root
                / "inventories/prod/group_vars/ansible_controllers/semaphore.yml",
                "ansible_backup_age_recipient",
                age_recipient,
            )
        )
    originals: dict[Path, str] = {}
    try:
        rendered: dict[Path, str] = {}
        for path, name, value in updates:
            originals[path] = path.read_text(encoding="utf-8")
            rendered[path] = _replace_exact_setting(path, name, value)
        for path, content in rendered.items():
            _atomic_write(path, content)
    except (OSError, UnicodeError, SeedError):
        for path, original in originals.items():
            if path.exists():
                _best_effort(lambda path=path, original=original: _atomic_write(path, original))
        raise SeedError("private inventory metadata update failed") from None

    def rollback() -> None:
        for path, original in originals.items():
            _atomic_write(path, original)

    return rollback


def _default_inventory_root() -> Path:
    configured = os.environ.get("INFRA_ANSIBLE_INVENTORY_ROOT")
    if configured:
        return Path(configured)
    repository_root = Path(__file__).resolve().parents[2]
    if repository_root.parent.name == ".worktrees":
        repository_root = repository_root.parent.parent
    return repository_root.parent / "infra-ansible-inventory"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Seed the Ansible controller secret contract without disclosure."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list the approved secret names without credentials or network access",
    )
    parser.add_argument(
        "--rotate",
        action="append",
        default=[],
        metavar="NAME",
        help="explicitly rotate an existing approved secret (repeatable)",
    )
    parser.add_argument(
        "--inventory-root",
        type=Path,
        default=_default_inventory_root(),
        help="private inventory repository root for public metadata",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.dry_run:
        result = _summary(
            cloudflare_service_token_id=None,
            created_names=set(),
            existing_names=set(),
            missing_names=set(SECRET_NAMES),
        )
    else:
        config = Config.from_environment(args.inventory_root.resolve())
        result = provision(config, rotate=set(args.rotate))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SeedError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
