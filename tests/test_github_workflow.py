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


def test_workflow_has_pr_main_push_and_explicit_manual_triggers():
    workflow = load_workflow()

    assert workflow["on"] == {
        "pull_request": {"branches": ["main"]},
        "push": {"branches": ["main"]},
        "workflow_dispatch": {
            "inputs": {
                "deploy_production": {
                    "description": "Explicitly authorize production deployment after validation",
                    "type": "boolean",
                    "required": False,
                    "default": False,
                }
            }
        },
    }
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
        "github.event_name == 'workflow_dispatch' && "
        "github.ref == 'refs/heads/main' && "
        "github.repository == 'VINIClUS/infra-ansible' && "
        "inputs.deploy_production == true"
    )
    assert deploy["environment"] == "production"
    assert deploy["concurrency"] == {
        "group": "ansible-production",
        "cancel-in-progress": False,
    }


def test_todo_uses_e_oficial_e_fixado_por_sha():
    workflow = load_workflow()
    uses = {
        step["uses"]
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if "uses" in step
    }

    assert uses == {f"{action}@{sha}" for action, sha in ACTION_PINS.items()}
    assert all(re.fullmatch(r"actions/[^@]+@[0-9a-f]{40}", value) for value in uses)


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


def test_somente_validate_publica_release_manifest():
    jobs = load_workflow()["jobs"]
    manifest_uploads = [
        (name, step)
        for name, job in jobs.items()
        for step in steps_using(job, "actions/upload-artifact")
        if step["with"]["name"] == "release-manifest"
    ]

    assert [name for name, _ in manifest_uploads] == ["validate"]
    upload = manifest_uploads[0][1]
    assert upload["with"]["path"] == "release-manifest.json"
    assert upload["with"]["if-no-files-found"] == "error"


def test_outros_artefatos_tem_prefixo_ci_report():
    jobs = load_workflow()["jobs"]
    names = [
        step["with"]["name"]
        for job in jobs.values()
        for step in steps_using(job, "actions/upload-artifact")
        if step["with"]["name"] != "release-manifest"
    ]

    assert names and all(name.startswith("ci-report") for name in names)


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


def test_userns_permission_preparation_is_only_in_hosted_validation_before_native_tools():
    workflow = load_workflow()
    validate = workflow["jobs"]["validate"]
    assert validate["runs-on"] == "ubuntu-latest"
    commands = [(index, step.get("run", "")) for index, step in enumerate(validate["steps"])]
    permission = [(index, command) for index, command in commands if "prepare-hosted-userns.sh" in command]
    assert len(permission) == 1
    assert permission[0][1] == "bash tools/ci/prepare-hosted-userns.sh"
    native = [index for index, command in commands if "python -m tools.ci.native_bootstrap" in command]
    assert len(native) == 1 and permission[0][0] < native[0]
    assert all("prepare-hosted-userns.sh" not in step.get("run", "")
               for name, job in workflow["jobs"].items() if name != "validate"
               for step in job["steps"])


def test_um_unico_job_se_chama_validate():
    jobs = load_workflow()["jobs"]

    assert [name for name, job in jobs.items() if job.get("name") == "Validate"] == ["validate"]


def test_concorrencia_cancela_somente_em_pull_request():
    concurrency = load_workflow()["concurrency"]

    assert concurrency["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"
    assert "github.event.pull_request.number" in concurrency["group"]


def test_push_dispatch_e_schedule_usam_grupo_unico_por_execucao():
    group = " ".join(load_workflow()["concurrency"]["group"].split())

    assert "format('pipeline-run-{0}', github.run_id)" in group
    assert "format('pipeline-pr-{0}', github.event.pull_request.number)" in group
    assert group.startswith("${{ github.event_name == 'pull_request' &&")


def test_todo_job_exceto_deploy_tem_timeout():
    jobs = load_workflow()["jobs"]

    for name, job in jobs.items():
        if name == "deploy":
            assert "timeout-minutes" not in job
        else:
            assert isinstance(job["timeout-minutes"], int) and job["timeout-minutes"] > 0
    assert jobs["validate"]["timeout-minutes"] == 45


DEPLOY_LITERAL = {
    "name": "Deploy production",
    "needs": "validate",
    "if": (
        "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && "
        "github.repository == 'VINIClUS/infra-ansible' && inputs.deploy_production == true"
    ),
    "runs-on": ["self-hosted", "linux", "x64", "ansible-prod"],
    "environment": "production",
    "concurrency": {"group": "ansible-production", "cancel-in-progress": False},
    "steps": [
        {
            "name": "Download the validated release manifest",
            "uses": "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            "with": {"name": "release-manifest", "path": ".release"},
        },
        {
            "name": "Verify the release manifest targets this revision",
            "shell": "bash",
            "run": (
                "python3 - <<'PY'\n"
                "import json\n"
                "import os\n"
                "from pathlib import Path\n"
                "\n"
                'manifest_path = Path(".release/release-manifest.json")\n'
                'manifest = json.loads(manifest_path.read_text(encoding="utf-8"))\n'
                'if manifest.get("infra_sha") != os.environ["GITHUB_SHA"]:\n'
                '    raise SystemExit("release manifest SHA does not match GITHUB_SHA")\n'
                "PY\n"
            ),
        },
        {
            "name": "Deploy the validated revision",
            "shell": "bash",
            "run": 'sudo /usr/local/sbin/infra-ansible-deploy "$GITHUB_SHA"',
        },
    ],
}


def test_deploy_permanece_inalterado():
    deploy = load_workflow()["jobs"]["deploy"]
    deploy = {**deploy, "if": " ".join(deploy["if"].split())}

    assert deploy == DEPLOY_LITERAL


def test_workflow_nao_tem_retentativa_automatica():
    text = read_workflow()

    for forbidden in (
        "--reruns",
        "rerunfailures",
        "flaky",
        "--lf",
        "--last-failed",
        "--sw",
        "--stepwise",
    ):
        assert forbidden not in text


def _pytest_step(job):
    return next(step for step in job["steps"] if "python -m pytest -q" in step.get("run", ""))


def test_pytest_roda_com_xdist_loadgroup_e_plugin():
    validate = load_workflow()["jobs"]["validate"]
    command = " ".join(_pytest_step(validate)["run"].split())

    assert "-n 4 --dist loadgroup" in command
    assert "-p tools.ci.pytest_ci" in command
    assert '--ci-report-dir "${RUNNER_TEMP}/ci-report"' in command
    assert "--ci-quarantine exclude" in command
    assert '--junitxml "${RUNNER_TEMP}/ci-report/junit.xml"' in command
    assert _pytest_step(validate)["env"]["CNESDATA_NATIVE_CONTEXT"] == "public-ci"


def test_quarentena_roda_em_passo_que_nao_bloqueia():
    validate = load_workflow()["jobs"]["validate"]
    step = step_named(validate, "Run quarantined tests (non-blocking)")
    command = " ".join(step["run"].split())

    assert step["continue-on-error"] is True
    assert step["if"] == "always()"
    assert "--ci-quarantine only" in command
    assert '--ci-report-dir "${RUNNER_TEMP}/ci-quarantine"' in command
    assert "-eq 5" in command
    upload = step_named(validate, "Upload test reports")
    assert upload["if"] == "always()"
    assert upload["with"]["name"] == "ci-report-validate"
    assert upload["with"]["if-no-files-found"] == "warn"
    assert upload["with"]["overwrite"] is True
    assert "${{ runner.temp }}/ci-report" in upload["with"]["path"]
    assert "${{ runner.temp }}/ci-quarantine" in upload["with"]["path"]


def test_instalacao_de_ci_exige_hashes():
    validate = load_workflow()["jobs"]["validate"]
    install = step_named(validate, "Install validation dependencies")

    assert "--require-hashes -r tools/ci/requirements-ci.txt" in " ".join(install["run"].split())
    assert "ansible-galaxy collection install --requirements-file requirements.yml" in install["run"]
    assert "pip install" in install["run"] and "ansible-core \\" not in install["run"]
