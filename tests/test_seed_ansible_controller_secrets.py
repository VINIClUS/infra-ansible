from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from contextlib import nullcontext
from pathlib import Path

import pytest

from tools.bootstrap import seed_ansible_controller_secrets as seed


EXPECTED_NAMES = {
    "ANSIBLE_BACKUP_AGE_IDENTITY",
    "CLOUDFLARE_ACCESS_CLIENT_ID",
    "CLOUDFLARE_ACCESS_CLIENT_SECRET",
    "INFRA_INVENTORY_DEPLOY_KEY",
    "SEMAPHORE_ACCESS_KEY_ENCRYPTION",
    "SEMAPHORE_ADMIN_PASSWORD",
    "SEMAPHORE_DB_PASSWORD",
}


def config(tmp_path: Path) -> seed.Config:
    return seed.Config(
        infisical_url="https://infisical.example",
        infisical_project_id="project-id",
        infisical_environment="prod",
        infisical_client_id="ua-client-id",
        infisical_client_secret="ua-client-secret",
        cloudflare_api_url="https://api.cloudflare.com/client/v4",
        cloudflare_account_id="account-id",
        cloudflare_api_token="cloudflare-api-token",
        inventory_root=tmp_path / "inventory",
    )


def test_secret_contract_is_exact() -> None:
    assert set(seed.SECRET_NAMES) == EXPECTED_NAMES
    assert seed.INFISICAL_SECRET_PATH == "/ansible"


def test_dry_run_lists_names_only_without_reading_credentials(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.setattr(seed, "request_json", lambda *_args, **_kwargs: pytest.fail("HTTP called"))
    monkeypatch.setattr(seed.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("command called"))

    assert seed.main(["--dry-run"]) == 0

    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert output.err == ""
    assert summary == {
        "cloudflare_service_token_id": None,
        "created_names": [],
        "existing_names": [],
        "missing_names": sorted(EXPECTED_NAMES),
    }


def test_request_json_keeps_credentials_out_of_url_and_sanitizes_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[seed.HttpRequest] = []

    def fail_transport(request: seed.HttpRequest) -> seed.HttpResponse:
        captured.append(request)
        raise RuntimeError("server echoed cloudflare-api-token and ua-client-secret")

    with pytest.raises(seed.SeedError) as raised:
        seed.request_json(
            "POST",
            "https://api.example/resource",
            headers={"Authorization": "Bearer cloudflare-api-token"},
            body={"clientSecret": "ua-client-secret"},
            transport=fail_transport,
            operation="authenticate",
        )

    assert str(raised.value) == "authenticate failed"
    assert captured[0].url == "https://api.example/resource"
    assert "cloudflare-api-token" not in captured[0].url
    assert "ua-client-secret" not in captured[0].url
    assert json.loads(captured[0].body.decode()) == {"clientSecret": "ua-client-secret"}
    assert captured[0].headers["Authorization"] == "Bearer cloudflare-api-token"
    assert captured[0].headers["User-Agent"] == "infra-ansible-secret-bootstrap/1"

    def fail_with_seed_error(_request: seed.HttpRequest) -> seed.HttpResponse:
        raise seed.SeedError("server echoed ua-client-secret")

    with pytest.raises(seed.SeedError) as seed_raised:
        seed.request_json(
            "POST",
            "https://api.example/resource",
            body={"clientSecret": "ua-client-secret"},
            transport=fail_with_seed_error,
            operation="authenticate",
        )
    assert str(seed_raised.value) == "authenticate failed"


@pytest.mark.parametrize(
    "location",
    ["http://infisical.example/leak", "https://other-origin.example/leak"],
)
def test_http_transport_blocks_redirects_without_forwarding_authorization(
    monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    sentinel = "Bearer redirect-secret-sentinel"
    opened: list[urllib.request.Request] = []
    handlers: list[object] = []

    class FakeOpener:
        def open(self, request: urllib.request.Request, *, timeout: int) -> object:
            assert timeout == 30
            opened.append(request)
            raise urllib.error.HTTPError(
                request.full_url,
                302,
                "Found",
                {"Location": location},
                None,
            )

    def build_opener(*received_handlers: object) -> FakeOpener:
        handlers.extend(received_handlers)
        return FakeOpener()

    monkeypatch.setattr(seed.urllib.request, "build_opener", build_opener)
    monkeypatch.setattr(
        seed.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("default redirect-following opener used"),
    )

    with pytest.raises(seed.SeedError) as raised:
        seed.request_json(
            "GET",
            "https://infisical.example/api/v4/secrets",
            headers={"Authorization": sentinel},
            operation="redirect preflight",
        )

    assert len(opened) == 1
    assert any(isinstance(handler, seed.NoRedirectHandler) for handler in handlers)
    assert sentinel not in str(raised.value)


def test_infisical_list_hides_values_and_writes_values_only_in_http_body() -> None:
    requests: list[seed.HttpRequest] = []
    created = False

    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        nonlocal created
        requests.append(request)
        if request.url.endswith("/api/v1/auth/universal-auth/login"):
            return seed.HttpResponse(200, {"accessToken": "short-lived-token"})
        if request.method == "GET":
            names = ["SEMAPHORE_DB_PASSWORD"]
            if created:
                names.append("SEMAPHORE_ADMIN_PASSWORD")
            return seed.HttpResponse(200, {"secrets": [{"secretKey": name} for name in names]})
        created = True
        return seed.HttpResponse(200, {"secret": {"secretKey": "SEMAPHORE_ADMIN_PASSWORD"}})

    client = seed.InfisicalClient(config(Path("/tmp")), transport=transport)
    assert client.existing_secret_names() == {"SEMAPHORE_DB_PASSWORD"}
    client.create_secret("SEMAPHORE_ADMIN_PASSWORD", "body-only-secret")

    listing = next(request for request in requests if request.method == "GET")
    assert "viewSecretValue=false" in listing.url
    assert "secretPath=%2Fansible" in listing.url
    write = next(
        request
        for request in requests
        if request.method == "POST" and "/api/v4/secrets/" in request.url
    )
    assert write.method == "POST"
    assert "body-only-secret" not in write.url
    assert "body-only-secret" not in " ".join(write.headers.values())
    assert json.loads(write.body.decode())["secretValue"] == "body-only-secret"


def test_key_material_uses_0600_temp_files_and_only_public_key_reaches_gh(
    tmp_path: Path,
) -> None:
    calls: list[tuple[list[str], dict[str, str]]] = []
    public_key = "ssh-ed25519 AAAATEST controller\n"
    deploy_key_added = False

    def command(argv: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        nonlocal deploy_key_added
        calls.append((argv, env))
        if argv[0] == "age-keygen" and "-o" in argv:
            target = Path(argv[argv.index("-o") + 1])
            target.write_text("AGE-SECRET-KEY-TEST\n", encoding="utf-8")
            os.chmod(target, 0o600)
        elif argv[0] == "age-keygen" and "-y" in argv:
            return subprocess.CompletedProcess(argv, 0, "age1recipient\n", "")
        elif argv[0] == "ssh-keygen":
            target = Path(argv[argv.index("-f") + 1])
            target.write_text("OPENSSH-PRIVATE-TEST\n", encoding="utf-8")
            target.with_suffix(".pub").write_text(public_key, encoding="utf-8")
            os.chmod(target, 0o600)
            os.chmod(target.with_suffix(".pub"), 0o600)
        elif argv[:3] == ["gh", "repo", "deploy-key"]:
            key_path = Path(argv[4])
            assert key_path.read_text(encoding="utf-8") == public_key
            assert "--allow-write" not in argv
            assert "OPENSSH-PRIVATE-TEST" not in argv
            deploy_key_added = True
        elif argv[:2] == ["gh", "api"]:
            payload = []
            if deploy_key_added:
                payload = [
                    {
                        "id": 123,
                        "title": seed.GITHUB_DEPLOY_KEY_TITLE,
                        "key": public_key.strip(),
                        "read_only": True,
                    }
                ]
            return subprocess.CompletedProcess(argv, 0, json.dumps([payload]), "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    with seed.generated_key_material(command=command, temp_parent=tmp_path) as material:
        assert material.age_identity == "AGE-SECRET-KEY-TEST"
        assert material.age_recipient == "age1recipient"
        assert material.deploy_private_key == "OPENSSH-PRIVATE-TEST"
        assert seed.register_read_only_deploy_key(material, command=command) == 123
        workdir = material.workdir
        assert (workdir.stat().st_mode & 0o777) == 0o700
        assert all((path.stat().st_mode & 0o777) == 0o600 for path in workdir.iterdir())

    assert not workdir.exists()
    all_argv = json.dumps([argv for argv, _env in calls])
    assert "AGE-SECRET-KEY-TEST" not in all_argv
    assert "OPENSSH-PRIVATE-TEST" not in all_argv


def test_github_deploy_key_is_create_only(tmp_path: Path) -> None:
    public_path = tmp_path / "key.pub"
    public_key = "ssh-ed25519 AAAATEST controller"
    public_path.write_text(public_key + "\n", encoding="utf-8")
    material = seed.KeyMaterial(
        age_identity="unused",
        age_recipient="unused",
        deploy_private_key="OPENSSH-PRIVATE-TEST",
        deploy_public_key=public_key,
        deploy_public_key_path=public_path,
        workdir=tmp_path,
    )
    calls: list[list[str]] = []

    def command(argv: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        del env
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps(
                [
                    [
                    {
                        "id": 7,
                        "title": seed.GITHUB_DEPLOY_KEY_TITLE,
                        "key": public_key,
                        "read_only": True,
                    }
                    ]
                ]
            ),
            "",
        )

    with pytest.raises(seed.SeedError, match="already exists"):
        seed.register_read_only_deploy_key(material, command=command)
    assert not any(call[:4] == ["gh", "repo", "deploy-key", "add"] for call in calls)


def test_cloudflare_service_token_is_create_only_and_secret_safe(tmp_path: Path) -> None:
    requests: list[seed.HttpRequest] = []

    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        requests.append(request)
        return seed.HttpResponse(
            200,
            {
                "success": True,
                "result": [{"id": "existing-id", "name": seed.CLOUDFLARE_SERVICE_TOKEN_NAME}],
                "result_info": {"page": 1, "total_pages": 1},
            },
        )

    with pytest.raises(seed.SeedError, match="already exists") as raised:
        seed.create_cloudflare_service_token(config(tmp_path), transport=transport)
    assert "cloudflare-api-token" not in str(raised.value)
    assert [request.method for request in requests] == ["GET"]
    assert requests[0].headers["Authorization"] == "Bearer cloudflare-api-token"


def test_ambiguous_cloudflare_create_requires_manual_recovery(tmp_path: Path) -> None:
    calls = 0

    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        nonlocal calls
        calls += 1
        if request.method == "GET":
            return seed.HttpResponse(
                200,
                {
                    "success": True,
                    "result": [],
                    "result_info": {"page": 1, "total_pages": 1},
                },
            )
        raise RuntimeError("response lost after cloudflare-client-secret was accepted")

    with pytest.raises(seed.RemoteStateUncertain) as raised:
        seed.create_cloudflare_service_token(config(tmp_path), transport=transport)
    assert calls == 2
    assert "cloudflare-client-secret" not in str(raised.value)
    assert "manual recovery required" in str(raised.value)


def test_invalid_cloudflare_create_response_requires_manual_recovery(tmp_path: Path) -> None:
    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        if request.method == "GET":
            return seed.HttpResponse(
                200,
                {
                    "success": True,
                    "result": [],
                    "result_info": {"page": 1, "total_pages": 1},
                },
            )
        return seed.HttpResponse(200, {"success": True, "result": {"id": "created"}})

    with pytest.raises(seed.RemoteStateUncertain, match="manual recovery required"):
        seed.create_cloudflare_service_token(config(tmp_path), transport=transport)


def test_uncertain_external_state_is_never_reported_as_compensated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        seed,
        "create_cloudflare_service_token",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            seed.RemoteStateUncertain("Cloudflare state uncertain")
        ),
    )
    target = {
        "CLOUDFLARE_ACCESS_CLIENT_ID",
        "CLOUDFLARE_ACCESS_CLIENT_SECRET",
    }
    with pytest.raises(seed.SeedError, match="manual recovery required"):
        seed.generate_resources(config(tmp_path), target)


def test_resource_generation_compensates_deploy_key_if_cloudflare_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    public_path = tmp_path / "key.pub"
    public_path.write_text("ssh-ed25519 AAAATEST\n", encoding="utf-8")
    material = seed.KeyMaterial(
        age_identity="AGE-SECRET-KEY-TEST",
        age_recipient="age1recipient",
        deploy_private_key="OPENSSH-PRIVATE-TEST",
        deploy_public_key="ssh-ed25519 AAAATEST",
        deploy_public_key_path=public_path,
        workdir=tmp_path,
    )
    deleted: list[int | None] = []
    monkeypatch.setattr(seed, "generated_key_material", lambda **_kwargs: nullcontext(material))
    monkeypatch.setattr(seed, "register_read_only_deploy_key", lambda *_args, **_kwargs: 321)
    monkeypatch.setattr(
        seed,
        "create_cloudflare_service_token",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(seed.SeedError("Cloudflare failed")),
    )
    monkeypatch.setattr(
        seed, "delete_github_deploy_key", lambda key_id, **_kwargs: deleted.append(key_id)
    )

    with pytest.raises(seed.SeedError, match="resource generation failed; compensation completed"):
        seed.generate_resources(config(tmp_path), set(EXPECTED_NAMES))

    assert deleted == [321]


def test_generated_resource_contract_mismatch_is_compensated(tmp_path: Path) -> None:
    events: list[tuple[str, object]] = []

    class EmptyInfisical:
        def existing_secret_names(self) -> set[str]:
            return set()

    resources = seed.GeneratedResources(
        values={"SEMAPHORE_DB_PASSWORD": "value"},
        age_recipient="age1recipient",
        cloudflare_service_token_id="cf-id",
        github_deploy_key_id=987,
    )
    with pytest.raises(seed.SeedError, match="compensation completed"):
        seed.provision(
            config(tmp_path),
            infisical=EmptyInfisical(),
            generate_resources=lambda: resources,
            compensate_cloudflare=lambda token_id: events.append(("cloudflare", token_id)),
            compensate_github=lambda key_id: events.append(("github", key_id)),
        )
    assert events == [("cloudflare", "cf-id"), ("github", 987)]


def test_command_failure_never_includes_captured_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        seed.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["age-keygen"], 1, "OPENSSH-PRIVATE-TEST", "AGE-SECRET-KEY-TEST"
        ),
    )
    with pytest.raises(seed.SeedError) as raised:
        seed._run_command(["age-keygen"], env={})
    assert str(raised.value) == "age-keygen execution failed"


def test_create_only_is_compensated_on_partial_infisical_failure(tmp_path: Path) -> None:
    events: list[tuple[str, str]] = []
    values = {name: f"value-for-{name}" for name in EXPECTED_NAMES}

    class FakeInfisical:
        def existing_secret_names(self) -> set[str]:
            return set()

        def create_secret(self, name: str, value: str) -> None:
            assert value == values[name]
            events.append(("create", name))
            if name == "SEMAPHORE_ADMIN_PASSWORD":
                raise seed.SeedError("Infisical secret write failed")

        def delete_secret(self, name: str) -> None:
            events.append(("delete", name))

    resources = seed.GeneratedResources(
        values=values,
        age_recipient="age1recipient",
        cloudflare_service_token_id="cf-token-id",
        github_deploy_key_id=123,
    )
    compensations: list[tuple[str, object]] = []

    with pytest.raises(seed.SeedError, match="provisioning failed; compensation completed") as raised:
        seed.provision(
            config(tmp_path),
            infisical=FakeInfisical(),
            generate_resources=lambda: resources,
            compensate_cloudflare=lambda token_id: compensations.append(("cloudflare", token_id)),
            compensate_github=lambda key_id: compensations.append(("github", key_id)),
        )

    assert "value-for-" not in str(raised.value)
    created = [name for action, name in events if action == "create"]
    deleted = [name for action, name in events if action == "delete"]
    # The failed request may have committed server-side before its response was
    # lost, so compensation includes the attempted name as well.
    assert deleted == list(reversed(created))
    assert compensations == [("cloudflare", "cf-token-id"), ("github", 123)]


def test_malformed_infisical_delete_readback_prevents_compensation_success(
    tmp_path: Path,
) -> None:
    values = {name: f"value-for-{name}" for name in EXPECTED_NAMES}

    class MalformedDeleteReadback:
        def existing_secret_names(self) -> set[str]:
            return set()

        def create_secret(self, name: str, _value: str) -> None:
            if name == "SEMAPHORE_ADMIN_PASSWORD":
                raise seed.SeedError("create failed")

        def delete_secret(self, _name: str) -> None:
            raise seed.SeedError("Infisical secret listing semantics were invalid")

    with pytest.raises(seed.SeedError, match="manual recovery required") as raised:
        seed.provision(
            config(tmp_path),
            infisical=MalformedDeleteReadback(),
            generate_resources=lambda: seed.GeneratedResources(
                values=values,
                age_recipient="",
                cloudflare_service_token_id=None,
                github_deploy_key_id=None,
            ),
        )
    assert "compensation completed" not in str(raised.value)


def test_inventory_manual_recovery_state_cannot_be_reported_as_compensated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    values = {name: f"value-for-{name}" for name in EXPECTED_NAMES}

    class EmptyInfisical:
        def existing_secret_names(self) -> set[str]:
            return set()

        def create_secret(self, _name: str, _value: str) -> None:
            pass

        def delete_secret(self, _name: str) -> None:
            pass

    monkeypatch.setattr(
        seed,
        "write_public_inventory_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            seed.RemoteStateUncertain("inventory manual recovery required")
        ),
    )
    with pytest.raises(seed.SeedError, match="manual recovery required") as raised:
        seed.provision(
            config(tmp_path),
            infisical=EmptyInfisical(),
            generate_resources=lambda: seed.GeneratedResources(
                values=values,
                age_recipient="age1recipient",
                cloudflare_service_token_id="cf-id",
                github_deploy_key_id=123,
            ),
            compensate_cloudflare=lambda _token_id: None,
            compensate_github=lambda _key_id: None,
        )
    assert "compensation completed" not in str(raised.value)


def test_existing_contract_is_reported_without_generation(tmp_path: Path) -> None:
    class ExistingInfisical:
        def existing_secret_names(self) -> set[str]:
            return set(EXPECTED_NAMES)

    result = seed.provision(
        config(tmp_path),
        infisical=ExistingInfisical(),
        validate_existing_contract=lambda: "cf-existing-id",
        generate_resources=lambda: pytest.fail("generated on safe rerun"),
    )
    assert result == {
        "cloudflare_service_token_id": "cf-existing-id",
        "created_names": [],
        "existing_names": sorted(EXPECTED_NAMES),
        "missing_names": [],
    }


def test_success_summary_and_output_contract_never_include_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    values = {name: f"never-print-{name}" for name in EXPECTED_NAMES}

    class EmptyInfisical:
        def existing_secret_names(self) -> set[str]:
            return set()

        def create_secret(self, name: str, value: str) -> None:
            assert value == values[name]

        def delete_secret(self, name: str) -> None:
            pytest.fail(f"unexpected compensation for {name}")

    result = seed.provision(
        config(tmp_path),
        infisical=EmptyInfisical(),
        generate_resources=lambda: seed.GeneratedResources(
            values=values,
            age_recipient="",
            cloudflare_service_token_id=None,
            github_deploy_key_id=None,
        ),
    )
    output = json.dumps(result) + capsys.readouterr().out + capsys.readouterr().err
    assert set(result) == {
        "cloudflare_service_token_id",
        "created_names",
        "existing_names",
        "missing_names",
    }
    assert all(value not in output for value in values.values())


def test_partial_existing_contract_refuses_implicit_overwrite(tmp_path: Path) -> None:
    class PartialInfisical:
        def existing_secret_names(self) -> set[str]:
            return {"SEMAPHORE_DB_PASSWORD"}

    with pytest.raises(seed.SeedError, match="explicit --rotate"):
        seed.provision(
            config(tmp_path),
            infisical=PartialInfisical(),
            generate_resources=lambda: pytest.fail("generated before preflight"),
        )


def test_rotation_must_name_an_existing_approved_secret(tmp_path: Path) -> None:
    class ExistingInfisical:
        def existing_secret_names(self) -> set[str]:
            return set(EXPECTED_NAMES)

    with pytest.raises(seed.SeedError, match="approved existing secret"):
        seed.provision(
            config(tmp_path),
            infisical=ExistingInfisical(),
            rotate={"NOT_APPROVED"},
            generate_resources=lambda: pytest.fail("generated before validation"),
        )


def test_public_inventory_metadata_is_atomic_and_reversible(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory"
    access = inventory / "inventories/prod/group_vars/local_validation/cloudflare_access.yml"
    semaphore = inventory / "inventories/prod/group_vars/ansible_controllers/semaphore.yml"
    access.parent.mkdir(parents=True)
    semaphore.parent.mkdir(parents=True)
    access.write_text("cloudflare_access_service_token_id: \"\"\n", encoding="utf-8")
    semaphore.write_text("ansible_backup_age_recipient: \"\"\n", encoding="utf-8")

    rollback = seed.write_public_inventory_metadata(
        inventory,
        cloudflare_service_token_id="cf-public-id",
        age_recipient="age1publicrecipient",
    )
    assert "cf-public-id" in access.read_text(encoding="utf-8")
    assert "age1publicrecipient" in semaphore.read_text(encoding="utf-8")
    assert not list(inventory.rglob("*.tmp"))

    rollback()
    assert access.read_text(encoding="utf-8") == "cloudflare_access_service_token_id: \"\"\n"
    assert semaphore.read_text(encoding="utf-8") == "ansible_backup_age_recipient: \"\"\n"


def test_secret_transports_require_clean_https_urls(tmp_path: Path) -> None:
    base = config(tmp_path)
    for unsafe in (
        "http://infisical.example",
        "https://user:password@infisical.example",
        "https://infisical.example?redirect=evil",
        "https://infisical.example#fragment",
    ):
        with pytest.raises(seed.SeedError, match="HTTPS"):
            seed.Config(**{**base.__dict__, "infisical_url": unsafe})
    with pytest.raises(seed.SeedError, match="HTTPS"):
        seed.request_json("GET", "http://localhost:8080/test", transport=lambda _request: None)


def test_cleanup_failure_is_redacted_and_requires_manual_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sentinel = "AGE-SECRET-KEY-SENTINEL"

    def command(argv: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        del env
        if argv[0] == "age-keygen" and "-o" in argv:
            path = Path(argv[argv.index("-o") + 1])
            path.write_text(sentinel + "\n", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "age-keygen":
            return subprocess.CompletedProcess(argv, 0, "age1recipient\n", "")
        path = Path(argv[argv.index("-f") + 1])
        path.write_text("PRIVATE-SENTINEL\n", encoding="utf-8")
        path.with_suffix(".pub").write_text("ssh-ed25519 AAAATEST\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(seed.shutil, "rmtree", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(sentinel)))
    with pytest.raises(seed.RemoteStateUncertain, match="manual cleanup required") as raised:
        with seed.generated_key_material(command=command, temp_parent=tmp_path):
            pass
    assert sentinel not in str(raised.value)


def test_external_rotations_fail_closed_before_snapshot_or_generation(tmp_path: Path) -> None:
    events: list[str] = []

    class ExistingInfisical:
        def existing_secret_names(self) -> set[str]:
            return set(EXPECTED_NAMES)

        def read_secret_value(self, name: str) -> str:
            events.append(f"read:{name}")
            return "never"

    for names in (
        {"INFRA_INVENTORY_DEPLOY_KEY"},
        {"ANSIBLE_BACKUP_AGE_IDENTITY"},
        {"CLOUDFLARE_ACCESS_CLIENT_ID", "CLOUDFLARE_ACCESS_CLIENT_SECRET"},
    ):
        with pytest.raises(seed.SeedError, match="separate external-resource procedure"):
            seed.provision(
                config(tmp_path),
                infisical=ExistingInfisical(),
                rotate=names,
                generate_resources=lambda: events.append("generated"),
            )
    assert events == []


def test_simple_rotation_snapshots_before_generation_and_rolls_back(tmp_path: Path) -> None:
    events: list[str] = []
    name = "SEMAPHORE_ADMIN_PASSWORD"

    class ExistingInfisical:
        def existing_secret_names(self) -> set[str]:
            return set(EXPECTED_NAMES)

        def read_secret_value(self, read_name: str) -> str:
            events.append(f"snapshot:{read_name}")
            return "old-value"

        def replace_secret(self, write_name: str, value: str) -> None:
            events.append(f"write:{write_name}:{value}")
            if value == "new-value":
                raise seed.SeedError("write failed")

        def delete_secret(self, _name: str) -> None:
            pytest.fail("rotation must restore, not delete")

    def resources() -> seed.GeneratedResources:
        events.append("generated")
        return seed.GeneratedResources(
            values={name: "new-value"},
            age_recipient="",
            cloudflare_service_token_id=None,
            github_deploy_key_id=None,
        )

    with pytest.raises(seed.SeedError, match="compensation completed"):
        seed.provision(
            config(tmp_path),
            infisical=ExistingInfisical(),
            rotate={name},
            generate_resources=resources,
        )
    assert events == [
        f"snapshot:{name}",
        "generated",
        f"write:{name}:new-value",
        f"write:{name}:old-value",
    ]


def test_simple_rotation_succeeds_after_snapshot(tmp_path: Path) -> None:
    events: list[str] = []
    name = "SEMAPHORE_DB_PASSWORD"

    class ExistingInfisical:
        def existing_secret_names(self) -> set[str]:
            return set(EXPECTED_NAMES)

        def read_secret_value(self, read_name: str) -> str:
            events.append(f"snapshot:{read_name}")
            return "old-value"

        def replace_secret(self, write_name: str, value: str) -> None:
            events.append(f"write:{write_name}:{value}")

        def delete_secret(self, _name: str) -> None:
            pytest.fail("unexpected delete")

    def resources() -> seed.GeneratedResources:
        events.append("generated")
        return seed.GeneratedResources(
            values={name: "new-value"},
            age_recipient="",
            cloudflare_service_token_id=None,
            github_deploy_key_id=None,
        )

    result = seed.provision(
        config(tmp_path),
        infisical=ExistingInfisical(),
        rotate={name},
        generate_resources=resources,
    )
    assert events == [f"snapshot:{name}", "generated", f"write:{name}:new-value"]
    assert result["created_names"] == [name]


def test_snapshot_failure_precedes_all_resource_generation(tmp_path: Path) -> None:
    class ExistingInfisical:
        def existing_secret_names(self) -> set[str]:
            return set(EXPECTED_NAMES)

        def read_secret_value(self, _name: str) -> str:
            raise seed.SeedError("snapshot unavailable")

        def replace_secret(self, _name: str, _value: str) -> None:
            pytest.fail("write attempted after snapshot failure")

    with pytest.raises(seed.SeedError, match="snapshot unavailable"):
        seed.provision(
            config(tmp_path),
            infisical=ExistingInfisical(),
            rotate={"SEMAPHORE_ADMIN_PASSWORD"},
            generate_resources=lambda: pytest.fail("generated before snapshot"),
        )


def test_complete_names_require_external_contract_validation(tmp_path: Path) -> None:
    class ExistingInfisical:
        def existing_secret_names(self) -> set[str]:
            return set(EXPECTED_NAMES)

    with pytest.raises(seed.SeedError, match="external contract is incomplete"):
        seed.provision(
            config(tmp_path),
            infisical=ExistingInfisical(),
            validate_existing_contract=lambda: (_ for _ in ()).throw(
                seed.SeedError("external contract is incomplete")
            ),
            generate_resources=lambda: pytest.fail("generated on no-op validation"),
        )


def test_complete_contract_cross_checks_infisical_external_resources_and_inventory(
    tmp_path: Path,
) -> None:
    cfg = config(tmp_path)
    access = cfg.inventory_root / "inventories/prod/group_vars/local_validation/cloudflare_access.yml"
    semaphore = cfg.inventory_root / "inventories/prod/group_vars/ansible_controllers/semaphore.yml"
    access.parent.mkdir(parents=True)
    semaphore.parent.mkdir(parents=True)
    access.write_text('cloudflare_access_service_token_id: "cf-id"\n', encoding="utf-8")
    semaphore.write_text('ansible_backup_age_recipient: "age1recipient"\n', encoding="utf-8")
    secrets_by_name = {
        "INFRA_INVENTORY_DEPLOY_KEY": "OPENSSH-PRIVATE-SENTINEL",
        "ANSIBLE_BACKUP_AGE_IDENTITY": "AGE-SECRET-SENTINEL",
        "CLOUDFLARE_ACCESS_CLIENT_ID": "cf-client-id",
    }
    argv_seen: list[list[str]] = []

    class ExistingInfisical:
        def read_secret_value(self, name: str) -> str:
            return secrets_by_name[name]

    def command(argv: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        del env
        argv_seen.append(argv)
        if argv[0] == "ssh-keygen":
            return subprocess.CompletedProcess(argv, 0, "ssh-ed25519 AAAAPUBLIC\n", "")
        if argv[0] == "age-keygen":
            return subprocess.CompletedProcess(argv, 0, "age1recipient\n", "")
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps(
                [
                    [
                        {
                            "id": 42,
                            "title": seed.GITHUB_DEPLOY_KEY_TITLE,
                            "key": "ssh-ed25519 AAAAPUBLIC",
                            "read_only": True,
                        }
                    ]
                ]
            ),
            "",
        )

    def transport(_request: seed.HttpRequest) -> seed.HttpResponse:
        return seed.HttpResponse(
            200,
            {
                "success": True,
                "result": [
                    {
                        "id": "cf-id",
                        "name": seed.CLOUDFLARE_SERVICE_TOKEN_NAME,
                        "client_id": "cf-client-id",
                    }
                ],
                "result_info": {"page": 1, "total_pages": 1},
            },
        )

    assert seed.validate_complete_contract(
        cfg,
        infisical=ExistingInfisical(),
        command=command,
        transport=transport,
    ) == "cf-id"
    serialized_argv = json.dumps(argv_seen)
    assert all(value not in serialized_argv for value in secrets_by_name.values())

    access.write_text('cloudflare_access_service_token_id: "wrong-id"\n', encoding="utf-8")
    with pytest.raises(seed.SeedError, match="inventory external contract"):
        seed.validate_complete_contract(
            cfg,
            infisical=ExistingInfisical(),
            command=command,
            transport=transport,
        )


def test_github_listing_uses_all_pages() -> None:
    calls: list[list[str]] = []

    def command(argv: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        del env
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps([[{"id": 1, "title": "other"}], [{"id": 2, "title": seed.GITHUB_DEPLOY_KEY_TITLE}]]),
            "",
        )

    keys = seed.list_github_deploy_keys(command=command)
    assert [item["id"] for item in keys] == [1, 2]
    assert "--paginate" in calls[0]
    assert "--slurp" in calls[0]


def test_cloudflare_listing_follows_pages_and_requires_success(tmp_path: Path) -> None:
    requests: list[seed.HttpRequest] = []

    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        requests.append(request)
        page = int(urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query)["page"][0])
        return seed.HttpResponse(
            200,
            {
                "success": True,
                "result": [{"id": f"id-{page}", "name": f"name-{page}"}],
                "result_info": {"page": page, "total_pages": 2},
            },
        )

    assert [
        item["id"]
        for item in seed.list_cloudflare_service_tokens(config(tmp_path), transport=transport)
    ] == ["id-1", "id-2"]
    assert len(requests) == 2

    with pytest.raises(seed.SeedError, match="success semantics"):
        seed.list_cloudflare_service_tokens(
            config(tmp_path),
            transport=lambda _request: seed.HttpResponse(
                200,
                {
                    "success": False,
                    "result": [],
                    "result_info": {"page": 1, "total_pages": 1},
                },
            ),
        )


def test_cloudflare_create_requires_exact_paginated_readback(tmp_path: Path) -> None:
    calls = 0

    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        nonlocal calls
        calls += 1
        if request.method == "POST":
            return seed.HttpResponse(
                200,
                {
                    "success": True,
                    "result": {
                        "id": "cf-new-id",
                        "client_id": "cf-new-client",
                        "client_secret": "cf-new-secret",
                    },
                },
            )
        result = []
        if calls > 1:
            result = [
                {
                    "id": "cf-new-id",
                    "name": seed.CLOUDFLARE_SERVICE_TOKEN_NAME,
                    "client_id": "cf-new-client",
                }
            ]
        return seed.HttpResponse(
            200,
            {
                "success": True,
                "result": result,
                "result_info": {"page": 1, "total_pages": 1},
            },
        )

    token = seed.create_cloudflare_service_token(config(tmp_path), transport=transport)
    assert token.resource_id == "cf-new-id"
    assert calls == 3


def test_github_delete_requires_paginated_absence_readback() -> None:
    calls: list[list[str]] = []

    def command(argv: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        del env
        calls.append(argv)
        output = json.dumps([[]]) if "--paginate" in argv else ""
        return subprocess.CompletedProcess(argv, 0, output, "")

    seed.delete_github_deploy_key(123, command=command)
    assert calls[0][:4] == ["gh", "api", "--method", "DELETE"]
    assert "--paginate" in calls[1]


def test_infisical_mutation_rejects_pending_shape_and_requires_readback(tmp_path: Path) -> None:
    requests: list[seed.HttpRequest] = []

    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        requests.append(request)
        if request.url.endswith("/api/v1/auth/universal-auth/login"):
            return seed.HttpResponse(200, {"accessToken": "token"})
        if request.method == "POST":
            return seed.HttpResponse(200, {"approval": {"status": "pending"}})
        return seed.HttpResponse(200, {"secrets": []})

    client = seed.InfisicalClient(config(tmp_path), transport=transport)
    with pytest.raises(seed.RemoteStateUncertain, match="committed secret"):
        client.create_secret("SEMAPHORE_ADMIN_PASSWORD", "body-only")
    assert [request.method for request in requests].count("GET") == 0


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"secrets": {}},
        {"secrets": [{}]},
        {"secrets": [{"secretKey": ""}]},
        {
            "secrets": [
                {"secretKey": "SEMAPHORE_DB_PASSWORD"},
                {"secretKey": "SEMAPHORE_DB_PASSWORD"},
            ]
        },
    ],
)
def test_infisical_listing_rejects_malformed_or_ambiguous_envelopes(
    tmp_path: Path, payload: object
) -> None:
    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        if request.url.endswith("/api/v1/auth/universal-auth/login"):
            return seed.HttpResponse(200, {"accessToken": "token"})
        return seed.HttpResponse(200, payload)

    client = seed.InfisicalClient(config(tmp_path), transport=transport)
    with pytest.raises(seed.SeedError, match="listing semantics"):
        client.existing_secret_names()


def test_infisical_delete_malformed_absence_readback_fails_closed(tmp_path: Path) -> None:
    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        if request.url.endswith("/api/v1/auth/universal-auth/login"):
            return seed.HttpResponse(200, {"accessToken": "token"})
        if request.method == "DELETE":
            return seed.HttpResponse(
                200,
                {"secret": {"secretKey": "SEMAPHORE_ADMIN_PASSWORD"}},
            )
        return seed.HttpResponse(200, {})

    client = seed.InfisicalClient(config(tmp_path), transport=transport)
    with pytest.raises(seed.SeedError, match="listing semantics"):
        client.delete_secret("SEMAPHORE_ADMIN_PASSWORD")


def test_inventory_journal_recovers_interrupted_two_file_update(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    inventory = tmp_path / "inventory"
    access = inventory / "inventories/prod/group_vars/local_validation/cloudflare_access.yml"
    semaphore = inventory / "inventories/prod/group_vars/ansible_controllers/semaphore.yml"
    access.parent.mkdir(parents=True)
    semaphore.parent.mkdir(parents=True)
    access.write_text('cloudflare_access_service_token_id: ""\n', encoding="utf-8")
    semaphore.write_text('ansible_backup_age_recipient: ""\n', encoding="utf-8")
    original_atomic_write = seed._atomic_write
    writes = 0

    def interrupted_write(path: Path, content: str) -> None:
        nonlocal writes
        writes += 1
        if writes == 3:
            raise SystemExit("simulated crash")
        original_atomic_write(path, content)

    monkeypatch.setattr(seed, "_atomic_write", interrupted_write)
    with pytest.raises(SystemExit, match="simulated crash"):
        seed.write_public_inventory_metadata(
            inventory,
            cloudflare_service_token_id="cf-new-id",
            age_recipient="age1new",
        )
    journal = inventory / seed.INVENTORY_JOURNAL_NAME
    assert journal.exists()
    assert "age1new" in semaphore.read_text(encoding="utf-8")

    monkeypatch.setattr(seed, "_atomic_write", original_atomic_write)
    seed.recover_inventory_metadata_transaction(inventory)
    assert access.read_text(encoding="utf-8") == 'cloudflare_access_service_token_id: ""\n'
    assert semaphore.read_text(encoding="utf-8") == 'ansible_backup_age_recipient: ""\n'
    assert not journal.exists()
