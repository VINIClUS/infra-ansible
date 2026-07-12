import json

import pytest

from tools.release.build_release_manifest import build_manifest


VALID_SHA = "0123456789abcdef0123456789abcdef01234567"
EXPECTED_MANIFEST = {
    "infra_sha": VALID_SHA,
    "runner_minimum": "2.335.1",
    "schema": 1,
    "semaphore_sha256": (
        "209cf89c23710ed74e4568be129690fb5f9599b66f3cdfb55ed6c1a437c94dc9"
    ),
    "semaphore_version": "2.18.25",
}


def test_manifest_is_canonical_and_exact(tmp_path):
    target = tmp_path / "release-manifest.json"

    build_manifest(VALID_SHA, target)

    assert json.loads(target.read_text(encoding="utf-8")) == EXPECTED_MANIFEST
    assert target.read_text(encoding="utf-8") == (
        json.dumps(EXPECTED_MANIFEST, indent=2, sort_keys=True) + "\n"
    )


@pytest.mark.parametrize(
    "invalid_sha",
    [
        "main",
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef012345678",
        "0123456789abcdef0123456789abcdef0123456g",
        "0123456789ABCDEF0123456789ABCDEF01234567",
    ],
)
def test_manifest_rejects_non_lowercase_40_character_sha(tmp_path, invalid_sha):
    with pytest.raises(ValueError, match="40 lowercase hexadecimal"):
        build_manifest(invalid_sha, tmp_path / "manifest.json")


def test_manifest_does_not_dump_environment_or_secrets(tmp_path, monkeypatch):
    secret = "must-not-appear-in-release-manifest"
    monkeypatch.setenv("OBJECT_STORAGE_SECRET_KEY", secret)
    monkeypatch.setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", secret)
    target = tmp_path / "release-manifest.json"

    build_manifest(VALID_SHA, target)

    rendered = target.read_text(encoding="utf-8")
    assert secret not in rendered
    assert "OBJECT_STORAGE_SECRET_KEY" not in rendered
    assert "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET" not in rendered
