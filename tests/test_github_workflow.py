import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/pipeline.yml"

ACTION_PINS = {
    "actions/checkout": "df4cb1c069e1874edd31b4311f1884172cec0e10",
    "actions/setup-python": "ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
}


def read_workflow() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def load_workflow() -> dict:
    return yaml.safe_load(read_workflow())


def steps_using(job: dict, action: str) -> list[dict]:
    prefix = f"{action}@"
    return [step for step in job["steps"] if step.get("uses", "").startswith(prefix)]


def step_named(job: dict, name: str) -> dict:
    return next(step for step in job["steps"] if step.get("name") == name)


def test_workflow_has_only_pr_and_main_push_triggers():
    workflow = load_workflow()

    assert workflow["on"] == {
        "pull_request": {"branches": ["main"]},
        "push": {"branches": ["main"]},
    }
    assert "workflow_dispatch" not in read_workflow()
    assert "pull_request_target" not in read_workflow()


def test_workflow_uses_least_privilege_and_separates_runner_trust_boundaries():
    workflow = load_workflow()
    jobs = workflow["jobs"]

    assert workflow["permissions"] == {"contents": "read"}
    assert jobs["validate"]["runs-on"] == "ubuntu-latest"
    assert jobs["deploy"]["needs"] == "validate"
    assert jobs["deploy"]["runs-on"] == [
        "self-hosted",
        "linux",
        "x64",
        "ansible-prod",
    ]
    assert [job["runs-on"] for job in jobs.values()].count(
        ["self-hosted", "linux", "x64", "ansible-prod"]
    ) == 1


def test_deploy_requires_the_exact_trusted_main_context():
    deploy = load_workflow()["jobs"]["deploy"]
    condition = " ".join(deploy["if"].split())

    assert condition == (
        "github.event_name == 'push' && "
        "github.ref == 'refs/heads/main' && "
        "github.repository == 'VINIClUS/infra-ansible'"
    )
    assert deploy["environment"] == "production"
    assert deploy["concurrency"] == {
        "group": "ansible-production",
        "cancel-in-progress": False,
    }


def test_every_action_is_official_and_pinned_to_the_planned_full_sha():
    workflow = load_workflow()
    uses = [
        step["uses"]
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if "uses" in step
    ]

    assert set(uses) == {f"{action}@{sha}" for action, sha in ACTION_PINS.items()}
    assert all(re.fullmatch(r"actions/[^@]+@[0-9a-f]{40}", value) for value in uses)
    assert len(uses) == len(ACTION_PINS)


def test_validation_checks_out_without_persisting_credentials():
    validate = load_workflow()["jobs"]["validate"]
    checkout = steps_using(validate, "actions/checkout")

    assert len(checkout) == 1
    assert checkout[0]["with"]["persist-credentials"] is False


def test_validation_runs_the_complete_static_and_container_suite():
    validate = load_workflow()["jobs"]["validate"]
    commands = "\n".join(step["run"] for step in validate["steps"] if "run" in step)

    for command in (
        "python -m pytest -q",
        "pwsh -NoProfile -File tests/Validate-InfraAnsibleScaffold.ps1",
        "pwsh -NoProfile -File tests/Validate-AnsibleContainer.ps1",
        "pwsh -NoProfile -File tests/Validate-ProxmoxBackupStorageRole.ps1",
        "pwsh -NoProfile -File tests/Validate-GitHubRunnerMatrix.ps1",
        "ansible-inventory -i inventories/example/hosts.yml --list",
        "ansible-playbook -i inventories/example/hosts.yml \"${playbook}\" --syntax-check",
        "yamllint .",
        "ansible-lint .",
        "docker build --tag \"infra-ansible-tools:${GITHUB_SHA}\"",
        "docker run --rm \"infra-ansible-tools:${GITHUB_SHA}\" --version",
        "python tools/release/build_release_manifest.py \"${GITHUB_SHA}\" release-manifest.json",
    ):
        assert command in commands

    scaffolds = step_named(validate, "Validate repository scaffolds")
    assert scaffolds["shell"] == "bash"
    assert scaffolds["run"].startswith("set -euo pipefail\n")


def test_validation_uploads_only_the_release_manifest():
    validate = load_workflow()["jobs"]["validate"]
    uploads = steps_using(validate, "actions/upload-artifact")

    assert len(uploads) == 1
    assert uploads[0]["with"]["name"] == "release-manifest"
    assert uploads[0]["with"]["path"] == "release-manifest.json"
    assert uploads[0]["with"]["if-no-files-found"] == "error"


def test_deploy_verifies_same_workflow_manifest_then_invokes_only_fixed_wrapper():
    deploy = load_workflow()["jobs"]["deploy"]
    downloads = steps_using(deploy, "actions/download-artifact")
    run_steps = [step for step in deploy["steps"] if "run" in step]

    assert len(downloads) == 1
    assert downloads[0]["with"] == {"name": "release-manifest", "path": ".release"}
    assert not steps_using(deploy, "actions/checkout")
    assert "release-manifest.json" in run_steps[0]["run"]
    assert "GITHUB_SHA" in run_steps[0]["run"]
    sudo_commands = [
        line.strip()
        for step in run_steps
        for line in step["run"].splitlines()
        if line.strip().startswith("sudo ")
    ]
    assert sudo_commands == [
        'sudo /usr/local/sbin/infra-ansible-deploy "$GITHUB_SHA"'
    ]
