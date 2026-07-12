from __future__ import annotations

import json
import os
import subprocess
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


def test_infisical_list_hides_values_and_writes_values_only_in_http_body() -> None:
    requests: list[seed.HttpRequest] = []

    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        requests.append(request)
        if request.url.endswith("/api/v1/auth/universal-auth/login"):
            return seed.HttpResponse(200, {"accessToken": "short-lived-token"})
        if request.method == "GET":
            return seed.HttpResponse(200, {"secrets": [{"secretKey": "SEMAPHORE_DB_PASSWORD"}]})
        return seed.HttpResponse(200, {})

    client = seed.InfisicalClient(config(Path("/tmp")), transport=transport)
    assert client.existing_secret_names() == {"SEMAPHORE_DB_PASSWORD"}
    client.create_secret("SEMAPHORE_ADMIN_PASSWORD", "body-only-secret")

    listing = next(request for request in requests if request.method == "GET")
    assert "viewSecretValue=false" in listing.url
    assert "secretPath=%2Fansible" in listing.url
    write = requests[-1]
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
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
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
                    {
                        "id": 7,
                        "title": seed.GITHUB_DEPLOY_KEY_TITLE,
                        "key": public_key,
                        "read_only": True,
                    }
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
            return seed.HttpResponse(200, {"success": True, "result": []})
        raise RuntimeError("response lost after cloudflare-client-secret was accepted")

    with pytest.raises(seed.RemoteStateUncertain) as raised:
        seed.create_cloudflare_service_token(config(tmp_path), transport=transport)
    assert calls == 2
    assert "cloudflare-client-secret" not in str(raised.value)
    assert "manual recovery required" in str(raised.value)


def test_invalid_cloudflare_create_response_requires_manual_recovery(tmp_path: Path) -> None:
    def transport(request: seed.HttpRequest) -> seed.HttpResponse:
        if request.method == "GET":
            return seed.HttpResponse(200, {"success": True, "result": []})
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


def test_existing_contract_is_reported_without_generation(tmp_path: Path) -> None:
    class ExistingInfisical:
        def existing_secret_names(self) -> set[str]:
            return set(EXPECTED_NAMES)

    result = seed.provision(
        config(tmp_path),
        infisical=ExistingInfisical(),
        generate_resources=lambda: pytest.fail("generated on safe rerun"),
    )
    assert result == {
        "cloudflare_service_token_id": None,
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
