from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = "roles/cloudflare_access_application"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_yaml(path: str):
    return yaml.safe_load(read(path))


def uri_tasks(tasks: list[dict]) -> list[dict]:
    return [task for task in tasks if "ansible.builtin.uri" in task]


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

    assert methods.count("GET") == 2
    assert methods.count("POST") == 2
    assert methods.count("PUT") == 2
    assert set(methods) == {"GET", "POST", "PUT"}
    assert any("?domain=" in url and "&exact=true" in url for url in urls)
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
