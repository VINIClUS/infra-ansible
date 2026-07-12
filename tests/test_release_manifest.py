import json
import os
import stat

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


def test_manifest_preserves_existing_file_and_cleans_temporary_on_replace_error(
    tmp_path, monkeypatch
):
    target = tmp_path / "release-manifest.json"
    target.write_text("previous complete manifest\n", encoding="utf-8")

    def fail_replace(_source, _destination):
        raise OSError("injected replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError, match="injected replace failure"):
        build_manifest(VALID_SHA, target)

    assert target.read_text(encoding="utf-8") == "previous complete manifest\n"
    assert list(tmp_path.iterdir()) == [target]


def test_manifest_atomically_replaces_symlink_without_touching_its_target(tmp_path):
    protected = tmp_path / "protected"
    protected.write_text("do not overwrite\n", encoding="utf-8")
    target = tmp_path / "release-manifest.json"
    target.symlink_to(protected)

    build_manifest(VALID_SHA, target)

    assert protected.read_text(encoding="utf-8") == "do not overwrite\n"
    assert not target.is_symlink()
    assert json.loads(target.read_text(encoding="utf-8")) == EXPECTED_MANIFEST


def test_manifest_flushes_file_and_directory_and_is_owner_only(tmp_path, monkeypatch):
    fsync_calls = []
    real_fsync = os.fsync

    def record_fsync(file_descriptor):
        fsync_calls.append(file_descriptor)
        real_fsync(file_descriptor)

    monkeypatch.setattr(os, "fsync", record_fsync)
    target = tmp_path / "release-manifest.json"

    build_manifest(VALID_SHA, target)

    assert len(fsync_calls) >= 2
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
