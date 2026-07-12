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
INVENTORY_JOURNAL_NAME = ".ansible-controller-metadata-transaction.json"
EXTERNAL_ROTATION_NAMES = frozenset(
    {
        "ANSIBLE_BACKUP_AGE_IDENTITY",
        "INFRA_INVENTORY_DEPLOY_KEY",
        "CLOUDFLARE_ACCESS_CLIENT_ID",
        "CLOUDFLARE_ACCESS_CLIENT_SECRET",
    }
)


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

    def __post_init__(self) -> None:
        _validate_https_url(self.infisical_url, "Infisical API URL")
        _validate_https_url(self.cloudflare_api_url, "Cloudflare API URL")

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


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject every redirect so credentials are never replayed to a new URL."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def _validate_https_url(url: str, label: str, *, allow_query: bool = False) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (parsed.query and not allow_query)
        or parsed.fragment
    ):
        raise SeedError(f"{label} must be a clean HTTPS URL")


def _urllib_transport(request: HttpRequest) -> HttpResponse:
    raw_request = urllib.request.Request(
        request.url,
        data=request.body or None,
        headers=dict(request.headers),
        method=request.method,
    )
    opener = urllib.request.build_opener(NoRedirectHandler())
    try:
        with opener.open(raw_request, timeout=30) as response:
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
    _validate_https_url(url, operation, allow_query=True)
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
        if not isinstance(payload, dict) or "secrets" not in payload:
            raise SeedError("Infisical secret listing semantics were invalid")
        secrets_list = payload["secrets"]
        if not isinstance(secrets_list, list):
            raise SeedError("Infisical secret listing semantics were invalid")
        names: list[str] = []
        for item in secrets_list:
            name = item.get("secretKey") if isinstance(item, dict) else None
            if not isinstance(name, str) or not name:
                raise SeedError("Infisical secret listing semantics were invalid")
            names.append(name)
        if len(names) != len(set(names)):
            raise SeedError("Infisical secret listing semantics were ambiguous")
        return set(names)

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

    @staticmethod
    def _require_committed_secret(payload: Any, name: str, operation: str) -> None:
        secret = payload.get("secret") if isinstance(payload, dict) else None
        if not isinstance(secret, dict) or secret.get("secretKey") != name:
            raise RemoteStateUncertain(
                f"{operation} returned no committed secret; manual recovery required"
            )

    def create_secret(self, name: str, value: str) -> None:
        payload = request_json(
            "POST",
            self._secret_url(name),
            headers=self._headers(),
            body=self._write_body(value),
            transport=self._transport,
            operation=f"Infisical create for {name}",
        )
        self._require_committed_secret(payload, name, f"Infisical create for {name}")
        if name not in self.existing_secret_names():
            raise RemoteStateUncertain(
                f"Infisical create readback for {name} found no committed secret; "
                "manual recovery required"
            )

    def replace_secret(self, name: str, value: str) -> None:
        payload = request_json(
            "PATCH",
            self._secret_url(name),
            headers=self._headers(),
            body=self._write_body(value),
            transport=self._transport,
            operation=f"Infisical rotation for {name}",
        )
        self._require_committed_secret(payload, name, f"Infisical rotation for {name}")
        if name not in self.existing_secret_names():
            raise RemoteStateUncertain(
                f"Infisical rotation readback for {name} found no committed secret; "
                "manual recovery required"
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
        key = payload.get("secret", {}).get("secretKey") if isinstance(payload, dict) else None
        if key != name or not isinstance(value, str):
            raise SeedError(f"Infisical rotation snapshot for {name} returned no value")
        return value

    def delete_secret(self, name: str) -> None:
        payload = request_json(
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
        self._require_committed_secret(payload, name, f"Infisical deletion for {name}")
        if name in self.existing_secret_names():
            raise RemoteStateUncertain(
                f"Infisical deletion readback for {name} still found the secret; "
                "manual recovery required"
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
        try:
            shutil.rmtree(workdir)
            if workdir.exists():
                raise OSError
        except OSError:
            raise RemoteStateUncertain(
                "secret temporary directory cleanup failed; manual cleanup required"
            ) from None


def register_read_only_deploy_key(
    material: KeyMaterial, *, command: Command = _run_command
) -> int | None:
    environment = _minimal_command_environment()
    before = list_github_deploy_keys(command=command)
    if _github_deploy_key_matches(before, title=GITHUB_DEPLOY_KEY_TITLE):
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
        listing = list_github_deploy_keys(command=command)
        matches = _github_deploy_key_matches(
            listing,
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
    keys: list[dict[str, Any]],
    *,
    title: str,
    public_key: str | None = None,
    require_read_only: bool = False,
) -> list[dict[str, Any]]:
    return [
        item
        for item in keys
        if item.get("title") == title
        and (public_key is None or item.get("key", "").strip() == public_key)
        and (not require_read_only or item.get("read_only") is True)
    ]


def list_github_deploy_keys(*, command: Command = _run_command) -> list[dict[str, Any]]:
    result = command(
        [
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{GITHUB_INVENTORY_REPOSITORY}/keys?per_page=100",
        ],
        env=_minimal_command_environment(),
    )
    try:
        pages = json.loads(result.stdout)
        if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
            raise TypeError
        keys = [item for page in pages for item in page]
        if any(not isinstance(item, dict) for item in keys):
            raise TypeError
        return keys
    except (json.JSONDecodeError, TypeError):
        raise SeedError("GitHub deploy-key paginated readback failed") from None


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
    if any(item.get("id") == key_id for item in list_github_deploy_keys(command=command)):
        raise SeedError("GitHub deploy-key deletion readback still found the resource")


@dataclass(frozen=True)
class CloudflareServiceToken:
    resource_id: str
    client_id: str
    client_secret: str


def _cloudflare_result(payload: Any, expected_type: type, operation: str) -> Any:
    if (
        not isinstance(payload, dict)
        or payload.get("success") is not True
        or not isinstance(payload.get("result"), expected_type)
    ):
        raise SeedError(f"{operation} failed Cloudflare success semantics")
    return payload["result"]


def list_cloudflare_service_tokens(
    config: Config, *, transport: Transport = _urllib_transport
) -> list[dict[str, Any]]:
    collection_url = (
        f"{config.cloudflare_api_url}/accounts/{config.cloudflare_account_id}"
        "/access/service_tokens"
    )
    headers = {"Authorization": f"Bearer {config.cloudflare_api_token}"}
    page = 1
    tokens: list[dict[str, Any]] = []
    while True:
        payload = request_json(
            "GET",
            f"{collection_url}?page={page}&per_page=100",
            headers=headers,
            transport=transport,
            operation="Cloudflare Access service-token listing",
        )
        result = _cloudflare_result(payload, list, "service-token listing")
        result_info = payload.get("result_info")
        if (
            not isinstance(result_info, dict)
            or result_info.get("page") != page
            or not isinstance(result_info.get("total_pages"), int)
            or result_info["total_pages"] < page
            or result_info["total_pages"] > 10000
            or any(not isinstance(item, dict) for item in result)
        ):
            raise SeedError("service-token listing failed Cloudflare success semantics")
        tokens.extend(result)
        if page == result_info["total_pages"]:
            return tokens
        page += 1


def create_cloudflare_service_token(
    config: Config, *, transport: Transport = _urllib_transport
) -> CloudflareServiceToken:
    collection_url = (
        f"{config.cloudflare_api_url}/accounts/{config.cloudflare_account_id}"
        "/access/service_tokens"
    )
    headers = {"Authorization": f"Bearer {config.cloudflare_api_token}"}
    listed_tokens = list_cloudflare_service_tokens(config, transport=transport)
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
    try:
        result = _cloudflare_result(payload, dict, "service-token creation")
    except SeedError:
        raise RemoteStateUncertain(
            "Cloudflare service-token create response was incomplete; "
            "manual recovery required"
        ) from None
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
    token = CloudflareServiceToken(*values)
    try:
        listed_after_create = list_cloudflare_service_tokens(
            config, transport=transport
        )
        managed_after_create = [
            item
            for item in listed_after_create
            if item.get("name") == CLOUDFLARE_SERVICE_TOKEN_NAME
        ]
        matches = [
            item
            for item in managed_after_create
            if item.get("id") == token.resource_id
            and item.get("client_id") == token.client_id
        ]
    except SeedError:
        raise RemoteStateUncertain(
            "Cloudflare service-token create readback failed; manual recovery required"
        ) from None
    if len(managed_after_create) != 1 or len(matches) != 1:
        raise RemoteStateUncertain(
            "Cloudflare service-token create readback was not exact; "
            "manual recovery required"
        )
    return token


def delete_cloudflare_service_token(
    config: Config, resource_id: str, *, transport: Transport = _urllib_transport
) -> None:
    payload = request_json(
        "DELETE",
        (
            f"{config.cloudflare_api_url}/accounts/{config.cloudflare_account_id}"
            f"/access/service_tokens/{urllib.parse.quote(resource_id, safe='')}"
        ),
        headers={"Authorization": f"Bearer {config.cloudflare_api_token}"},
        transport=transport,
        operation="Cloudflare Access service-token compensation",
    )
    result = _cloudflare_result(payload, dict, "service-token deletion")
    if result.get("id") != resource_id:
        raise SeedError("service-token deletion returned an unexpected resource ID")
    if any(
        item.get("id") == resource_id
        for item in list_cloudflare_service_tokens(config, transport=transport)
    ):
        raise SeedError("service-token deletion readback still found the resource")


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


def _read_inventory_setting(path: Path, name: str) -> str:
    try:
        matches = [
            line.split(":", 1)[1].strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith(f"{name}:")
        ]
    except (OSError, UnicodeError):
        raise SeedError(f"private inventory cannot read {name}") from None
    if len(matches) != 1 or len(matches[0]) < 2:
        raise SeedError(f"private inventory must contain exactly one {name}")
    encoded = matches[0]
    if not (encoded.startswith('"') and encoded.endswith('"')):
        raise SeedError(f"private inventory {name} must use a quoted scalar")
    value = encoded[1:-1]
    if not value or any(character in value for character in "\r\n\""):
        raise SeedError(f"private inventory {name} is empty or invalid")
    return value


@contextmanager
def _derived_public_material(
    deploy_private_key: str,
    age_identity: str,
    *,
    command: Command = _run_command,
) -> Iterator[tuple[str, str]]:
    workdir = Path(tempfile.mkdtemp(prefix="ansible-verify-"))
    os.chmod(workdir, 0o700)
    deploy_path = workdir / "inventory-deploy-key"
    age_path = workdir / "backup-age-identity"
    try:
        for path, value in (
            (deploy_path, deploy_private_key),
            (age_path, age_identity),
        ):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(value)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        environment = _minimal_command_environment()
        deploy_public = command(
            ["ssh-keygen", "-y", "-f", str(deploy_path)], env=environment
        ).stdout.strip()
        age_recipient = command(
            ["age-keygen", "-y", str(age_path)], env=environment
        ).stdout.strip()
        if not deploy_public or not age_recipient:
            raise SeedError("public-key derivation returned an invalid result")
        yield deploy_public, age_recipient
    finally:
        try:
            shutil.rmtree(workdir)
            if workdir.exists():
                raise OSError
        except OSError:
            raise RemoteStateUncertain(
                "secret verification directory cleanup failed; manual cleanup required"
            ) from None


def validate_complete_contract(
    config: Config,
    *,
    infisical: InfisicalProvisioningClient,
    command: Command = _run_command,
    transport: Transport = _urllib_transport,
) -> str:
    if not hasattr(infisical, "read_secret_value"):
        raise SeedError("complete contract validation cannot read selected secrets")
    read_value = getattr(infisical, "read_secret_value")
    deploy_private_key = read_value("INFRA_INVENTORY_DEPLOY_KEY")
    age_identity = read_value("ANSIBLE_BACKUP_AGE_IDENTITY")
    cloudflare_client_id = read_value("CLOUDFLARE_ACCESS_CLIENT_ID")
    with _derived_public_material(
        deploy_private_key, age_identity, command=command
    ) as (deploy_public_key, age_recipient):
        github_matches = _github_deploy_key_matches(
            list_github_deploy_keys(command=command),
            title=GITHUB_DEPLOY_KEY_TITLE,
        )
        if (
            len(github_matches) != 1
            or github_matches[0].get("read_only") is not True
            or github_matches[0].get("key", "").strip() != deploy_public_key
        ):
            raise SeedError("GitHub deploy-key external contract is incomplete")
        cloudflare_matches = [
            item
            for item in list_cloudflare_service_tokens(config, transport=transport)
            if item.get("name") == CLOUDFLARE_SERVICE_TOKEN_NAME
        ]
        if (
            len(cloudflare_matches) != 1
            or cloudflare_matches[0].get("client_id") != cloudflare_client_id
            or not isinstance(cloudflare_matches[0].get("id"), str)
        ):
            raise SeedError("Cloudflare service-token external contract is incomplete")
        resource_id = cloudflare_matches[0]["id"]
        inventory_resource_id = _read_inventory_setting(
            config.inventory_root
            / "inventories/prod/group_vars/local_validation/cloudflare_access.yml",
            "cloudflare_access_service_token_id",
        )
        inventory_age_recipient = _read_inventory_setting(
            config.inventory_root
            / "inventories/prod/group_vars/ansible_controllers/semaphore.yml",
            "ansible_backup_age_recipient",
        )
        if inventory_resource_id != resource_id or inventory_age_recipient != age_recipient:
            raise SeedError("private inventory external contract is incomplete")
        return resource_id


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
    validate_existing_contract: Callable[[], str] | None = None,
) -> Summary:
    recover_inventory_metadata_transaction(config.inventory_root)
    approved = set(SECRET_NAMES)
    rotate = set(rotate or set())
    infisical = infisical or InfisicalClient(config)
    existing = infisical.existing_secret_names() & approved

    if rotate - (approved & existing):
        raise SeedError("--rotate must name an approved existing secret")
    if rotate & EXTERNAL_ROTATION_NAMES:
        raise SeedError(
            "external credentials require a separate external-resource procedure"
        )
    missing = approved - existing
    if existing and missing and not rotate:
        raise SeedError(
            "partial secret contract exists; use explicit --rotate after recovery review"
        )
    target_names = missing | rotate
    if not target_names:
        validator = validate_existing_contract or (
            lambda: validate_complete_contract(config, infisical=infisical)
        )
        cloudflare_service_token_id = validator()
        return _summary(
            cloudflare_service_token_id=cloudflare_service_token_id,
            created_names=set(),
            existing_names=existing,
            missing_names=set(),
        )

    old_values: dict[str, str] = {}
    if rotate:
        if not hasattr(infisical, "read_secret_value") or not hasattr(
            infisical, "replace_secret"
        ):
            raise SeedError("rotation client cannot snapshot and restore existing secrets")
        old_values = {
            name: getattr(infisical, "read_secret_value")(name) for name in rotate
        }

    resource_factory = generate_resources or (
        lambda: globals()["generate_resources"](config, target_names)
    )
    resources = resource_factory()
    compensate_cloudflare = compensate_cloudflare or (
        lambda resource_id: delete_cloudflare_service_token(config, resource_id)
    )
    compensate_github = compensate_github or delete_github_deploy_key
    if set(resources.values) != target_names:
        compensation_ok = True
        if resources.cloudflare_service_token_id:
            compensation_ok &= _best_effort(
                lambda: compensate_cloudflare(resources.cloudflare_service_token_id or "")
            )
        if resources.github_deploy_key_id is not None:
            compensation_ok &= _best_effort(
                lambda: compensate_github(resources.github_deploy_key_id)
            )
        state = "completed" if compensation_ok else "incomplete; manual recovery required"
        raise SeedError(
            "generated values did not match the requested secret names; "
            f"compensation {state}"
        )

    attempted_creates: list[str] = []
    attempted_rotations: list[str] = []
    inventory_rollback: Callable[[], None] = lambda: None
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
    except Exception as error:
        compensation_ok = not isinstance(error, RemoteStateUncertain)
        compensation_ok &= _best_effort(inventory_rollback)
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
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _inventory_journal_path(inventory_root: Path) -> Path:
    return inventory_root / INVENTORY_JOURNAL_NAME


def _remove_inventory_journal(inventory_root: Path) -> None:
    journal = _inventory_journal_path(inventory_root)
    journal.unlink(missing_ok=True)
    _fsync_directory(inventory_root)


def recover_inventory_metadata_transaction(inventory_root: Path) -> None:
    journal = _inventory_journal_path(inventory_root)
    if not journal.exists():
        return
    try:
        payload = json.loads(journal.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError
        entries = payload.get("files")
        if payload.get("version") != 1 or not isinstance(entries, list):
            raise ValueError
        restores: dict[Path, str] = {}
        root = inventory_root.resolve()
        for entry in entries:
            relative = entry.get("path") if isinstance(entry, dict) else None
            original = entry.get("original") if isinstance(entry, dict) else None
            if not isinstance(relative, str) or not isinstance(original, str):
                raise ValueError
            target = (inventory_root / relative).resolve()
            if not target.is_relative_to(root):
                raise ValueError
            restores[target] = original
        for path, original in restores.items():
            _atomic_write(path, original)
        _remove_inventory_journal(inventory_root)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise RemoteStateUncertain(
            "private inventory transaction recovery failed; manual recovery required"
        ) from None


def _journaled_inventory_replace(
    inventory_root: Path, rendered: Mapping[Path, str]
) -> dict[Path, str]:
    recover_inventory_metadata_transaction(inventory_root)
    originals = {path: path.read_text(encoding="utf-8") for path in rendered}
    journal = {
        "version": 1,
        "files": [
            {
                "path": str(path.resolve().relative_to(inventory_root.resolve())),
                "original": originals[path],
            }
            for path in sorted(rendered)
        ],
    }
    _atomic_write(
        _inventory_journal_path(inventory_root),
        json.dumps(journal, sort_keys=True, separators=(",", ":")) + "\n",
    )
    for path in sorted(rendered):
        _atomic_write(path, rendered[path])
    _remove_inventory_journal(inventory_root)
    return originals


def write_public_inventory_metadata(
    inventory_root: Path,
    *,
    cloudflare_service_token_id: str | None,
    age_recipient: str | None,
) -> Callable[[], None]:
    recover_inventory_metadata_transaction(inventory_root)
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
    for _path, name, value in updates:
        if (
            not value
            or len(value) > 512
            or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for character in value)
        ):
            raise SeedError(f"public inventory metadata {name} is invalid")
    try:
        rendered: dict[Path, str] = {}
        for path, name, value in updates:
            rendered[path] = _replace_exact_setting(path, name, value)
        originals = _journaled_inventory_replace(inventory_root, rendered)
    except (OSError, UnicodeError, SeedError):
        recovery_ok = _best_effort(
            lambda: recover_inventory_metadata_transaction(inventory_root)
        )
        if not recovery_ok:
            raise RemoteStateUncertain(
                "private inventory metadata update failed; manual recovery required"
            ) from None
        raise SeedError("private inventory metadata update failed; recovered") from None

    def rollback() -> None:
        _journaled_inventory_replace(inventory_root, originals)

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
