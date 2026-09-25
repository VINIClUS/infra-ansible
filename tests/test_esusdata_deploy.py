import json
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml

from tools.deploy import esusdata_deploy as deploy


ROOT = Path(__file__).resolve().parents[1]
SHA = "0123456789abcdef0123456789abcdef01234567"
INVENTORY_SHA = "e" * 40


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def release_payload(tag: str = "v0.1.2", **overrides) -> dict:
    version = tag[1:]
    payload = {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "assets": [
            {"name": "SHA256SUMS"},
            {"name": "SHA256SUMS.sig"},
            {"name": f"observatorio-aps_{version}_amd64.deb"},
            {"name": f"observatorio-aps-{version}.msi"},
        ],
    }
    payload.update(overrides)
    return payload


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


@contextmanager
def no_lock():
    yield


def git_runner(calls, *, dirty: str = "", playbook_error: bool = False):
    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[0] == "ansible-playbook":
            if playbook_error:
                raise subprocess.CalledProcessError(2, command)
            return subprocess.CompletedProcess(command, 0)
        if command[-1] == "--porcelain":
            return subprocess.CompletedProcess(command, 0, dirty, "")
        sha = SHA if command[2] == deploy.PUBLIC_REPO_ROOT else INVENTORY_SHA
        return subprocess.CompletedProcess(command, 0, sha + "\n", "")

    return run


@pytest.mark.parametrize(
    "arguments",
    [
        ["0.1.2"],
        ["v0.1"],
        ["v0.1.2-rc1"],
        ["latest"],
        ["v0.1.2", "extra"],
        ["v0.1.2", "--limit", "all"],
    ],
)
def test_cli_rejects_anything_but_an_optional_exact_tag(arguments):
    with pytest.raises(SystemExit):
        deploy.parse_args(arguments)


def test_cli_accepts_no_tag_or_one_exact_tag():
    assert deploy.parse_args([]).tag is None
    assert deploy.parse_args(["v0.1.2"]).tag == "v0.1.2"


def test_release_accepts_only_final_published_release_with_signed_package():
    assert deploy.release_from_payload(release_payload(), None) == deploy.Release(
        "v0.1.2", "0.1.2"
    )


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (release_payload(draft=True), "final release"),
        (release_payload(prerelease=True), "final release"),
        (release_payload(tag_name="v0.1.2-rc1"), "exact vX.Y.Z"),
        (release_payload(assets=[{"name": "SHA256SUMS"}]), "missing assets"),
        (["not", "an", "object"], "not an object"),
    ],
)
def test_release_rejects_untrusted_payloads(payload, message):
    with pytest.raises(ValueError, match=message):
        deploy.release_from_payload(payload, None)


def test_release_must_match_the_requested_tag():
    with pytest.raises(ValueError, match="different release"):
        deploy.release_from_payload(release_payload("v0.1.3"), "v0.1.2")


def test_fetch_asks_github_for_latest_or_the_exact_tag():
    requested = []

    def open_url(request, timeout):
        requested.append((request.full_url, timeout))
        return Response(release_payload())

    deploy.fetch_release(None, open_url)
    deploy.fetch_release("v0.1.2", open_url)

    assert requested == [
        ("https://api.github.com/repos/VINIClUS/esusdata/releases/latest", 15),
        ("https://api.github.com/repos/VINIClUS/esusdata/releases/tags/v0.1.2", 15),
    ]


def test_playbook_command_is_fixed_and_secret_free():
    command, env = deploy.build_playbook_invocation(
        deploy.Release("v0.1.2", "0.1.2"), base_env={"GITHUB_TOKEN": "leak"}
    )

    assert command == [
        "ansible-playbook",
        "--vault-password-file",
        "/etc/infra-ansible-deploy/vault-pass",
        "-i",
        "/srv/infra-ansible-inventory/inventories/prod/hosts.yml",
        "playbooks/esusdata-service.yml",
        "--limit",
        "esusdata-lxc",
        "--tags",
        "esusdata_service",
        "--extra-vars",
        "esusdata_service_version=0.1.2",
    ]
    assert env == {
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
    }


def test_playbook_command_rejects_mismatched_release():
    with pytest.raises(ValueError):
        deploy.build_playbook_invocation(
            deploy.Release("v0.1.2", "0.1.3"), base_env={}
        )


DEPLOYED = {"version": "0.1.2", "infra_sha": SHA, "inventory_sha": INVENTORY_SHA}
FAILED = {
    "failed_version": "0.1.2",
    "failed_infra_sha": SHA,
    "failed_inventory_sha": INVENTORY_SHA,
}


@pytest.mark.parametrize(
    ("state", "explicit", "expected"),
    [
        ({}, False, True),
        ({**DEPLOYED, "version": "0.1.1"}, False, True),
        (DEPLOYED, False, False),
        ({**DEPLOYED, "infra_sha": "a" * 40}, False, True),
        ({**DEPLOYED, "inventory_sha": "b" * 40}, False, True),
        ({**DEPLOYED, "version": "0.1.1", **FAILED}, False, False),
        ({**FAILED, "failed_inventory_sha": "b" * 40}, False, True),
        (DEPLOYED, True, True),
        (FAILED, True, True),
    ],
)
def test_scheduled_runs_skip_only_an_attempt_identical_to_the_last_outcome(
    state, explicit, expected
):
    release = deploy.Release("v0.1.2", "0.1.2")
    assert (
        deploy.should_deploy(
            release, state, (SHA, INVENTORY_SHA), explicit=explicit
        )
        is expected
    )


def test_successful_deploy_records_release_and_checkouts(tmp_path):
    calls = []
    state_path = tmp_path / "state.json"
    environment = {"GITHUB_TOKEN": "leak", "PATH": "/tmp/evil"}

    message = deploy.deploy_release(
        None,
        run=git_runner(calls),
        open_url=lambda *_args, **_kwargs: Response(release_payload()),
        base_env=environment,
        state_path=str(state_path),
        lock=no_lock,
    )

    assert message == "esusdata 0.1.2 deployed"
    assert "GITHUB_TOKEN" not in environment
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "infra_sha": SHA,
        "inventory_sha": INVENTORY_SHA,
        "version": "0.1.2",
    }
    playbook_calls = [call for call in calls if call[0][0] == "ansible-playbook"]
    assert len(playbook_calls) == 1
    assert playbook_calls[0][1]["cwd"] == "/srv/infra-ansible"
    assert "capture_output" not in playbook_calls[0][1]


def test_already_deployed_release_runs_nothing(tmp_path):
    calls = []
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(DEPLOYED), encoding="utf-8")

    message = deploy.deploy_release(
        None,
        run=git_runner(calls),
        open_url=lambda *_args, **_kwargs: Response(release_payload()),
        base_env={},
        state_path=str(state_path),
        lock=no_lock,
    )

    assert message == "esusdata 0.1.2 needs no deployment"
    assert not [call for call in calls if call[0][0] == "ansible-playbook"]


def test_failed_deploy_records_the_release_so_schedules_stop_retrying(tmp_path):
    calls = []
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps({**DEPLOYED, "version": "0.1.1"}), encoding="utf-8"
    )

    with pytest.raises(subprocess.CalledProcessError):
        deploy.deploy_release(
            None,
            run=git_runner(calls, playbook_error=True),
            open_url=lambda *_args, **_kwargs: Response(release_payload()),
            base_env={},
            state_path=str(state_path),
            lock=no_lock,
        )

    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        **DEPLOYED,
        "version": "0.1.1",
        **FAILED,
    }


def test_explicit_rollback_keeps_the_newer_failed_release_quarantined(tmp_path):
    calls = []
    state_path = tmp_path / "state.json"
    newer_failure = {**FAILED, "failed_version": "0.1.3"}
    state_path.write_text(
        json.dumps({**DEPLOYED, "version": "0.1.3", **newer_failure}), encoding="utf-8"
    )

    deploy.deploy_release(
        "v0.1.2",
        run=git_runner(calls),
        open_url=lambda *_args, **_kwargs: Response(release_payload()),
        base_env={},
        state_path=str(state_path),
        lock=no_lock,
    )

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state == {**DEPLOYED, **newer_failure}
    latest = deploy.Release("v0.1.3", "0.1.3")
    assert not deploy.should_deploy(latest, state, (SHA, INVENTORY_SHA), explicit=False)


def test_a_successful_retry_clears_its_own_failure(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(FAILED), encoding="utf-8")

    deploy.deploy_release(
        "v0.1.2",
        run=git_runner([]),
        open_url=lambda *_args, **_kwargs: Response(release_payload()),
        base_env={},
        state_path=str(state_path),
        lock=no_lock,
    )

    assert json.loads(state_path.read_text(encoding="utf-8")) == DEPLOYED


def test_dirty_checkout_blocks_the_playbook(tmp_path):
    calls = []

    with pytest.raises(ValueError, match="dirty"):
        deploy.deploy_release(
            None,
            run=git_runner(calls, dirty=" M hosts.yml"),
            open_url=lambda *_args, **_kwargs: Response(release_payload()),
            base_env={},
            state_path=str(tmp_path / "state.json"),
            lock=no_lock,
        )

    assert not [call for call in calls if call[0][0] == "ansible-playbook"]


def test_invalid_tag_is_rejected_before_lock_or_network():
    def forbidden(*_args, **_kwargs):
        raise AssertionError("must not be reached")

    with pytest.raises(ValueError, match="v1.2.3"):
        deploy.deploy_release("0.1.2", open_url=forbidden, base_env={}, lock=forbidden)


def test_boundary_shares_the_infra_deploy_lock():
    assert deploy.LOCK_PATH == "/run/infra-ansible/deploy.lock"


def test_sudoers_grants_only_the_no_argument_and_exact_tag_forms():
    sudoers = read("roles/infra_ansible_deployer/templates/infra-ansible-deploy.sudoers.j2")
    esusdata_lines = [line for line in sudoers.splitlines() if "esusdata-deploy" in line]

    assert esusdata_lines == [
        "Defaults!/usr/local/sbin/esusdata-deploy "
        "secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
        'github-runner ALL=(root) NOPASSWD:NOSETENV: /usr/local/sbin/esusdata-deploy ""',
        "github-runner ALL=(root) NOPASSWD:NOSETENV: /usr/local/sbin/esusdata-deploy "
        "^v[0-9]+[.][0-9]+[.][0-9]+$",
    ]


def test_deployer_installs_the_esusdata_boundary_and_vaulted_key():
    tasks = yaml.safe_load(read("roles/infra_ansible_deployer/tasks/main.yml"))
    by_name = {task["name"]: task for task in tasks}

    script = by_name["Install the root-owned esusdata release boundary"]
    assert script["ansible.builtin.copy"]["src"].endswith(
        "tools/deploy/esusdata_deploy.py"
    )
    assert script["ansible.builtin.copy"]["mode"] == "0755"
    key = by_name["Install the dedicated esusdata SSH private key"]
    assert key["no_log"] is True
    assert key["ansible.builtin.copy"]["mode"] == "0600"
    assert by_name["Validate the esusdata deploy key from the inventory vault"]["no_log"]


def test_workflow_deploys_on_schedule_or_dispatch_through_the_fixed_wrapper_only():
    workflow = yaml.safe_load(read(".github/workflows/esusdata-deploy.yml"))
    job = workflow["jobs"]["deploy"]

    assert set(workflow["on"]) == {"schedule", "workflow_dispatch"}
    assert workflow["permissions"] == {}
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "ansible-prod"]
    assert job["environment"] == "production"
    assert job["concurrency"] == {
        "group": "esusdata-production",
        "cancel-in-progress": False,
    }
    assert " ".join(job["if"].split()) == (
        "github.repository == 'VINIClUS/infra-ansible' && "
        "github.ref == 'refs/heads/main'"
    )
    assert all("uses" not in step for step in job["steps"])
    sudo_commands = sorted(
        line.strip()
        for step in job["steps"]
        for line in step["run"].splitlines()
        if line.strip().startswith("sudo ")
    )
    assert sudo_commands == [
        "sudo /usr/local/sbin/esusdata-deploy",
        'sudo /usr/local/sbin/esusdata-deploy "${TAG}"',
    ]
    assert job["steps"][0]["env"] == {"TAG": "${{ inputs.tag }}"}
