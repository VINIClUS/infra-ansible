import json
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = "roles/cloudflare_access_application"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_yaml(path: str):
    return yaml.safe_load(read(path))


def uri_tasks(tasks: list[dict]) -> list[dict]:
    return [task for task in tasks if "ansible.builtin.uri" in task]


def run_playbook(
    playbook: Path, extra_vars: dict, tags: str | None = None
) -> subprocess.CompletedProcess:
    command = [
            "ansible-playbook",
            "-i",
            "localhost,",
            str(playbook),
            "--extra-vars",
            json.dumps(extra_vars),
        ]
    if tags:
        command.extend(["--tags", tags])
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def resolved_applications(service_token_id: str = "fixture-service-token-id") -> list[dict]:
    return [
        {
            "key": "human",
            "name": "Semaphore human OTP access",
            "domain": "ansible.vinisantana.com",
            "type": "self_hosted",
            "session_duration": "24h",
            "policy": {
                "name": "Allow exact Semaphore operator email",
                "decision": "allow",
                "include": [{"email": {"email": "me@vinisantana.com"}}],
                "exclude": [],
                "require": [],
                "precedence": 1,
            },
        },
        {
            "key": "health",
            "name": "Semaphore health service access",
            "domain": "ansible.vinisantana.com/api/ping",
            "type": "self_hosted",
            "session_duration": "24h",
            "policy": {
                "name": "Allow exact Semaphore health token",
                "decision": "non_identity",
                "include": [
                    {"service_token": {"token_id": service_token_id}}
                ],
                "exclude": [],
                "require": [],
                "precedence": 1,
            },
        },
    ]


def test_defaults_declare_exactly_two_path_scoped_self_hosted_applications():
    defaults = load_yaml(f"{ROLE}/defaults/main.yml")
    applications = defaults["cloudflare_access_applications"]

    assert defaults["cloudflare_access_human_domain"] == "ansible.vinisantana.com"
    assert defaults["cloudflare_access_health_domain"] == (
        "ansible.vinisantana.com/api/ping"
    )
    assert defaults["cloudflare_access_allowed_email"] == "me@vinisantana.com"
    assert len(applications) == 2
    assert [app["key"] for app in applications] == ["human", "health"]
    assert {app["type"] for app in applications} == {"self_hosted"}
    assert [app["domain"] for app in applications] == [
        "{{ cloudflare_access_human_domain }}",
        "{{ cloudflare_access_health_domain }}",
    ]


def test_human_policy_allows_only_the_exact_operator_email():
    applications = load_yaml(f"{ROLE}/defaults/main.yml")[
        "cloudflare_access_applications"
    ]
    human = applications[0]

    assert human["policy"]["decision"] == "allow"
    assert human["policy"]["include"] == [
        {"email": {"email": "{{ cloudflare_access_allowed_email }}"}}
    ]
    assert human["policy"]["exclude"] == []
    assert human["policy"]["require"] == []


def test_health_policy_is_non_identity_for_one_exact_service_token_resource_id():
    applications = load_yaml(f"{ROLE}/defaults/main.yml")[
        "cloudflare_access_applications"
    ]
    health = applications[1]

    assert health["policy"]["decision"] == "non_identity"
    assert health["policy"]["include"] == [
        {
            "service_token": {
                "token_id": "{{ cloudflare_access_service_token_id }}"
            }
        }
    ]
    assert health["policy"]["exclude"] == []
    assert health["policy"]["require"] == []
    assert "bypass" not in read(f"{ROLE}/defaults/main.yml").lower()
    assert "bypass" not in read(f"{ROLE}/tasks/main.yml").lower()


def test_api_reconciliation_lists_exact_domains_and_only_creates_or_updates():
    tasks = load_yaml(f"{ROLE}/tasks/main.yml")
    calls = uri_tasks(tasks)
    methods = [task["ansible.builtin.uri"].get("method", "GET") for task in calls]
    urls = [task["ansible.builtin.uri"]["url"] for task in calls]

    assert methods.count("GET") == 3
    assert methods.count("POST") == 2
    assert methods.count("PUT") == 2
    assert set(methods) == {"GET", "POST", "PUT"}
    assert any("?domain=" in url and "&exact=true" in url for url in urls)
    assert any(url.endswith("/access/identity_providers?per_page=100") for url in urls)
    assert any(url.endswith("/policies?per_page=100") for url in urls)
    assert any(url.endswith("/access/apps") for url in urls)
    assert any(url.endswith("/access/apps/{{ item.item.key }}") for url in urls) is False

    task_text = read(f"{ROLE}/tasks/main.yml")
    assert "selectattr('domain', 'equalto'" in task_text
    assert "selectattr('name', 'equalto'" in task_text
    assert "cloudflare_access_application_ids" in task_text
    assert "cloudflare_access_application_policy_ids" in task_text
    assert "method: DELETE" not in task_text
    assert "state: absent" not in task_text


def test_mutations_are_guarded_for_idempotency_and_unrelated_resources_are_untouched():
    tasks = load_yaml(f"{ROLE}/tasks/main.yml")
    calls = uri_tasks(tasks)
    creates = [task for task in calls if task["ansible.builtin.uri"].get("method") == "POST"]
    updates = [task for task in calls if task["ansible.builtin.uri"].get("method") == "PUT"]

    assert len(creates) == 2
    assert len(updates) == 2
    assert all("when" in task for task in creates + updates)
    assert all(task["ansible.builtin.uri"]["body_format"] == "json" for task in creates + updates)
    assert all(task["ansible.builtin.uri"]["status_code"] == 200 for task in creates + updates)


def test_every_token_bearing_api_task_is_no_log_and_discards_response_content():
    calls = uri_tasks(load_yaml(f"{ROLE}/tasks/main.yml"))

    assert calls
    for task in calls:
        request = task["ansible.builtin.uri"]
        assert task["no_log"] is True
        assert request["return_content"] is False
        assert request["headers"] == {
            "Authorization": "Bearer {{ cloudflare_access_api_token }}"
        }


def test_human_application_mutations_are_restricted_to_one_selected_otp_provider():
    tasks = load_yaml(f"{ROLE}/tasks/main.yml")
    mutations = [
        task
        for task in uri_tasks(tasks)
        if task["ansible.builtin.uri"].get("method") in {"POST", "PUT"}
        and "/policies" not in task["ansible.builtin.uri"]["url"]
    ]

    assert len(mutations) == 2
    for task in mutations:
        body = task["ansible.builtin.uri"]["body"]
        assert "cloudflare_access_application_otp_identity_provider_id" in body
        assert "allowed_idps" in body
        assert "auto_redirect_to_identity" in body

    task_text = read(f"{ROLE}/tasks/main.yml")
    assert "cloudflare_access_current_application.allowed_idps" in task_text
    assert "cloudflare_access_current_application.auto_redirect_to_identity" in task_text


def test_identity_provider_fixture_selects_only_onetimepin(tmp_path):
    playbook = tmp_path / "select-otp.yml"
    playbook.write_text(
        """---
- name: Select OTP fixture
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Run production identity-provider selection
      ansible.builtin.include_role:
        name: cloudflare_access_application
        tasks_from: identity_provider
      vars:
        cloudflare_access_identity_provider_candidates:
          - id: oidc-provider-id
            type: oidc
          - id: otp-provider-id
            type: onetimepin
    - name: Verify exact selected provider
      ansible.builtin.assert:
        that:
          - cloudflare_access_application_otp_identity_provider_id == 'otp-provider-id'
""",
        encoding="utf-8",
    )

    result = run_playbook(playbook, {})

    assert result.returncode == 0, result.stdout + result.stderr


def test_identity_provider_fixture_rejects_non_otp_provider(tmp_path):
    playbook = tmp_path / "reject-non-otp.yml"
    playbook.write_text(
        """---
- name: Reject non-OTP fixture
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Run production identity-provider selection
      ansible.builtin.include_role:
        name: cloudflare_access_application
        tasks_from: identity_provider
      vars:
        cloudflare_access_identity_provider_candidates:
          - id: oidc-provider-id
            type: oidc
""",
        encoding="utf-8",
    )

    result = run_playbook(playbook, {})

    assert result.returncode != 0


@pytest.mark.parametrize(
    ("application_index", "field", "value"),
    [
        (0, "name", "Arbitrary human app"),
        (0, "domain", "evil.example.com"),
        (0, "type", "saas"),
        (1, "domain", "ansible.vinisantana.com/admin"),
    ],
)
def test_validation_rejects_overridden_application_contract(
    application_index, field, value
):
    applications = resolved_applications()
    applications[application_index][field] = value
    result = run_playbook(
        ROOT / "playbooks/cloudflare-access.yml",
        {
            "cloudflare_access_account_id": "0" * 32,
            "cloudflare_access_zone_id": "",
            "cloudflare_access_api_token": "fixture-api-token",
            "cloudflare_access_service_token_id": "fixture-service-token-id",
            "cloudflare_access_applications": applications,
        },
        tags="cloudflare_access_application_validate",
    )

    assert result.returncode != 0


@pytest.mark.parametrize(
    ("application_index", "policy_field", "value"),
    [
        (0, "decision", "bypass"),
        (0, "include", [{"everyone": {}}]),
        (1, "decision", "allow"),
        (1, "include", [{"any_valid_service_token": {}}]),
    ],
)
def test_validation_rejects_overridden_policy_contract(
    application_index, policy_field, value
):
    applications = resolved_applications()
    applications[application_index]["policy"][policy_field] = value
    result = run_playbook(
        ROOT / "playbooks/cloudflare-access.yml",
        {
            "cloudflare_access_account_id": "0" * 32,
            "cloudflare_access_zone_id": "",
            "cloudflare_access_api_token": "fixture-api-token",
            "cloudflare_access_service_token_id": "fixture-service-token-id",
            "cloudflare_access_applications": applications,
        },
        tags="cloudflare_access_application_validate",
    )

    assert result.returncode != 0


def test_playbook_runs_only_the_access_role_on_localhost():
    playbook = load_yaml("playbooks/cloudflare-access.yml")

    assert playbook == [
        {
            "name": "Reconcile path-scoped Cloudflare Access",
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "roles": [
                {
                    "role": "cloudflare_access_application",
                    "tags": ["cloudflare_access_application"],
                }
            ],
        }
    ]
