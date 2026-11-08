"""Evaluate the real pipeline boundary without running a provider or a deployer."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "VINIClUS/infra-ansible"


@pytest.fixture(scope="module")
def pipeline():
    return yaml.safe_load((ROOT / ".github/workflows/pipeline.yml").read_text())


def _condition_allows(expression, context):
    """Interpret this gate's equality/conjunction subset, rejecting other syntax.

    GitHub compares strings case-insensitively. All boolean comparisons exercised
    here have boolean/missing operands; missing properties evaluate as empty strings.
    Unsupported syntax must fail the test instead of silently dropping a clause.
    """
    comparisons = []
    for clause in expression.split("&&"):
        match = re.fullmatch(
            r"\s*([a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)+)\s*==\s*"
            r"('(?:[^']|'')*'|true|false)\s*",
            clause,
        )
        assert match is not None, f"unsupported gate expression: {clause!r}"
        name, literal = match.groups()
        actual = context.get(name, "")
        if literal in {"true", "false"}:
            expected = literal == "true"
            # Empty string coerces to zero, so it cannot satisfy == true.
            comparisons.append(
                actual is expected
                if isinstance(actual, bool)
                else actual == "" and not expected
            )
        else:
            expected = literal[1:-1].replace("''", "'")
            assert isinstance(actual, str)
            comparisons.append(actual.casefold() == expected.casefold())
    return all(comparisons)


def test_pipeline_manual_input_is_explicit_boolean_default_false(pipeline):
    triggers = pipeline["on"]
    assert set(triggers) == {"pull_request", "push", "workflow_dispatch"}
    assert triggers["pull_request"] == {"branches": ["main"]}
    assert triggers["push"] == {"branches": ["main"]}
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"deploy_production"}
    assert inputs["deploy_production"]["type"] == "boolean"
    assert inputs["deploy_production"]["default"] is False
    assert inputs["deploy_production"]["required"] is False


@pytest.mark.parametrize(
    "event,ref,repository,opt_in,expected",
    [
        pytest.param(
            "pull_request",
            "refs/pull/37/merge",
            REPOSITORY,
            True,
            False,
            id="pr-even-with-opt-in",
        ),
        pytest.param(
            "pull_request",
            "refs/heads/main",
            "fork/infra-ansible",
            True,
            False,
            id="fork-pr",
        ),
        pytest.param(
            "pull_request_target",
            "refs/heads/main",
            REPOSITORY,
            True,
            False,
            id="pr-target",
        ),
        pytest.param(
            "push", "refs/heads/main", REPOSITORY, None, False, id="merge-push-main"
        ),
        pytest.param(
            "push",
            "refs/heads/main",
            REPOSITORY,
            True,
            False,
            id="push-main-even-with-opt-in",
        ),
        pytest.param(
            "workflow_dispatch",
            "refs/heads/main",
            REPOSITORY,
            None,
            False,
            id="manual-missing-opt-in",
        ),
        pytest.param(
            "workflow_dispatch",
            "refs/heads/main",
            REPOSITORY,
            False,
            False,
            id="manual-false",
        ),
        pytest.param(
            "workflow_dispatch",
            "refs/heads/develop",
            REPOSITORY,
            True,
            False,
            id="manual-wrong-branch",
        ),
        pytest.param(
            "workflow_dispatch",
            "refs/tags/main",
            REPOSITORY,
            True,
            False,
            id="manual-tag",
        ),
        pytest.param(
            "workflow_dispatch",
            "refs/heads/main",
            "fork/infra-ansible",
            True,
            False,
            id="manual-wrong-repository",
        ),
        pytest.param(
            "workflow_dispatch",
            "refs/heads/main",
            REPOSITORY,
            True,
            True,
            id="manual-main-explicit-true",
        ),
    ],
)
def test_real_deploy_condition_requires_manual_main_repository_opt_in(
    pipeline, event, ref, repository, opt_in, expected
):
    context = {
        "github.event_name": event,
        "github.ref": ref,
        "github.repository": repository,
    }
    if opt_in is not None:
        context["inputs.deploy_production"] = opt_in
    assert _condition_allows(pipeline["jobs"]["deploy"]["if"], context) is expected


def test_validation_stays_hosted_before_manual_production(pipeline):
    validate = pipeline["jobs"]["validate"]
    assert validate["runs-on"] == "ubuntu-latest"
    assert "if" not in validate
    deploy = pipeline["jobs"]["deploy"]
    assert deploy["needs"] == "validate"
    assert deploy["runs-on"] == ["self-hosted", "linux", "x64", "ansible-prod"]
    assert deploy["environment"] == "production"
    assert deploy["concurrency"] == {
        "group": "ansible-production",
        "cancel-in-progress": False,
    }
    assert deploy["steps"][-1]["run"] == (
        'sudo /usr/local/sbin/infra-ansible-deploy "$GITHUB_SHA"'
    )
