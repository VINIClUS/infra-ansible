"""Boundary and supply-chain tests; no downloads, provider init or cloud calls."""
import io
import tarfile
import zipfile

import pytest

from fixtures import cnesdata_aws_bootstrap_native as native
from tools.ci import native_bootstrap as bootstrap


def test_operator_context_requires_real_budget_source(monkeypatch, tmp_path):
    monkeypatch.delenv("CNESDATA_NATIVE_CONTEXT", raising=False)
    monkeypatch.setenv("CNESDATA_TEST_BUDGET_SOURCE_DIR", str(tmp_path / "missing"))
    with pytest.raises(AssertionError, match="external_target_absent"):
        native.target_source("budget-backend")


def test_operator_context_copies_real_budget_source(monkeypatch, tmp_path):
    monkeypatch.delenv("CNESDATA_NATIVE_CONTEXT", raising=False)
    source = tmp_path / "private-source"
    source.mkdir()
    content = 'variable "account_id" { type = string }\n'
    (source / "main.tf").write_text(content)
    monkeypatch.setenv("CNESDATA_TEST_BUDGET_SOURCE_DIR", str(source))
    work = tmp_path / "work"
    work.mkdir()
    harness = object.__new__(native.NativeHarness)
    harness._copy_source(work, "budget-backend", {})
    assert (work / "main.tf").read_text() == content
    assert not (work / "empty.tf.json").exists()


def test_public_context_skips_only_external_target(monkeypatch):
    monkeypatch.setenv("CNESDATA_NATIVE_CONTEXT", "public-ci")
    with pytest.raises(pytest.skip.Exception, match="external_budget_target"):
        native.target_source("budget-backend")
    assert native.target_source("foundation") == native.REPO / "opentofu/cnesdata-bootstrap/foundation"


def test_unknown_context_fails_closed(monkeypatch):
    monkeypatch.setenv("CNESDATA_NATIVE_CONTEXT", "publci")
    with pytest.raises(AssertionError, match="native_context_invalid"):
        native.target_source("foundation")


def test_empty_target_does_not_turn_into_synthetic_config(monkeypatch, tmp_path):
    monkeypatch.setenv("CNESDATA_NATIVE_CONTEXT", "operator")
    monkeypatch.setenv("CNESDATA_TEST_BUDGET_SOURCE_DIR", str(tmp_path))
    with pytest.raises(AssertionError, match="external_target_absent"):
        native.target_source("budget-backend")


@pytest.mark.parametrize("name", ["terraform-provider-aws", "terraform-provider-aws_v6.54.0_x5"])
def test_provider_accepts_original_official_basename(tmp_path, name):
    binary = tmp_path / name
    binary.write_bytes(b"original provider bytes")
    binary.chmod(0o755)
    assert bootstrap.provider_binary(tmp_path) == binary
    assert binary.read_bytes() == b"original provider bytes"


def test_provider_rejects_ambiguity_and_wrong_version(tmp_path):
    for name in ("terraform-provider-aws", "terraform-provider-aws_v6.54.0_x5"):
        p = tmp_path / name
        p.touch(mode=0o755)
    with pytest.raises(AssertionError, match="cached_provider_ambiguous"):
        bootstrap.provider_binary(tmp_path)
    (tmp_path / "terraform-provider-aws").unlink()
    (tmp_path / "terraform-provider-aws_v6.54.0_x5").rename(tmp_path / "terraform-provider-aws_v6.53.0_x5")
    with pytest.raises(AssertionError, match="cached_provider_invalid"):
        bootstrap.provider_binary(tmp_path)


def test_provider_rejects_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.write_bytes(b"not an authenticated provider")
    outside.chmod(0o755)
    (tmp_path / "terraform-provider-aws").symlink_to(outside)
    with pytest.raises(AssertionError, match="cached_provider_invalid"):
        bootstrap.provider_binary(tmp_path)


def test_digest_mismatch_fails_before_extraction(tmp_path):
    archive = tmp_path / "download"
    archive.write_bytes(b"tampered")
    with pytest.raises(AssertionError, match="download_checksum_mismatch"):
        bootstrap.verify_sha256(archive, "0" * 64)


@pytest.mark.parametrize("kind", ["zip", "tar.gz"])
def test_extracts_only_single_regular_binary(tmp_path, kind):
    archive = tmp_path / ("archive." + kind)
    if kind == "zip":
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("../unwanted", b"do not extract")
            z.writestr("bin/tofu", b"verified binary")
    else:
        with tarfile.open(archive, "w:gz") as t:
            info = tarfile.TarInfo("bin/tofu")
            info.size = len(b"verified binary")
            t.addfile(info, io.BytesIO(b"verified binary"))
    destination = tmp_path / "installed"
    bootstrap.extract_binary(archive, "tofu", destination)
    assert destination.read_bytes() == b"verified binary"
    assert destination.stat().st_mode & 0o111
    assert not (tmp_path.parent / "unwanted").exists()


def test_archive_rejects_duplicate_binary(tmp_path):
    archive = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("a/tofu", b"one")
        z.writestr("b/tofu", b"two")
    with pytest.raises(AssertionError, match="archive_binary_ambiguous"):
        bootstrap.extract_binary(archive, "tofu", tmp_path / "installed")


def test_subprocess_environment_excludes_credentials_and_configuration(monkeypatch, tmp_path):
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "TF_CLI_ARGS_init", "TF_PLUGIN_CACHE_DIR", "GITHUB_TOKEN"):
        monkeypatch.setenv(name, "must not reach tofu")
    env = bootstrap.clean_environment(tmp_path)
    assert not set(env) & {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "TF_CLI_ARGS_init", "TF_PLUGIN_CACHE_DIR", "GITHUB_TOKEN"}
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"
    assert env["AWS_CONFIG_FILE"] == env["AWS_SHARED_CREDENTIALS_FILE"] == "/dev/null"


def test_bootstrap_refuses_accidental_local_download(monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(AssertionError, match="ci_only"):
        bootstrap.prepare(tmp_path)


def test_provider_seed_uses_locked_provider_without_runtime_configuration(tmp_path):
    seed = tmp_path / "seed"
    original = (bootstrap.FOUNDATION / ".terraform.lock.hcl").read_bytes()
    bootstrap.write_provider_seed(seed)
    import json
    config = json.loads((seed / "versions.tf.json").read_text())
    assert set(config) == {"terraform"}
    assert set(config["terraform"]) == {"required_version", "required_providers"}
    assert config["terraform"]["required_version"] == "=1.13.2"
    assert config["terraform"]["required_providers"] == {"aws": {"source": "hashicorp/aws", "version": "=6.54.0"}}
    assert (seed / ".terraform.lock.hcl").read_bytes() == original


@pytest.mark.parametrize("case", ["a", "b", "foreign", "budget-source-sink", "budget-foreign-prefix"])
def test_public_external_target_is_classified_before_work_or_native_calls(monkeypatch, case):
    monkeypatch.setenv("CNESDATA_NATIVE_CONTEXT", "public-ci")
    # No fixture initialization or tools: classification must precede all work.
    harness = object.__new__(native.NativeHarness)
    with pytest.raises(pytest.skip.Exception, match="external_budget_target"):
        harness.plan(case, "budget-backend", "target")


def test_prewarm_enforces_readonly_lock_and_rejects_installer_lock_mutation(monkeypatch, tmp_path):
    import json
    seen = []

    def installer(command, folder, env, label):
        seen.append(command)
        assert command == ["/verified/tofu", "init", "-backend=false", "-input=false", "-lockfile=readonly"]
        config = json.loads((folder / "versions.tf.json").read_text())
        assert set(config) == {"terraform"}
        (folder / ".terraform.lock.hcl").write_text("installer rewrote lock")
        return ""

    monkeypatch.setattr(bootstrap, "run", installer)
    with pytest.raises(AssertionError, match="provider_lock_changed"):
        bootstrap.prewarm_provider(tmp_path / "cache", "/verified/tofu", bootstrap.clean_environment(tmp_path))
    assert len(seen) == 1


def test_archive_rejects_tar_symlink(tmp_path):
    archive = tmp_path / "archive.tar.gz"
    with tarfile.open(archive, "w:gz") as t:
        member = tarfile.TarInfo("tofu")
        member.type = tarfile.SYMTYPE
        member.linkname = "/bin/sh"
        t.addfile(member)
    with pytest.raises(AssertionError, match="archive_binary_invalid"):
        bootstrap.extract_binary(archive, "tofu", tmp_path / "installed")


def test_namespace_preflight_never_retries_without_isolation(monkeypatch, tmp_path):
    seen = []

    def unavailable(command, folder, env, label):
        seen.append(command)
        assert label == "native_namespace_preflight_failed"
        raise AssertionError(label + ": Operation not permitted")

    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/unshare")
    monkeypatch.setattr(bootstrap, "run", unavailable)
    with pytest.raises(AssertionError, match="native_namespace_preflight_failed"):
        bootstrap.preflight("/verified/rtk", "/verified/tofu", tmp_path, {})
    assert seen == [["/verified/rtk", "proxy", "/usr/bin/unshare", "--user", "--map-root-user", "--net", "/verified/tofu", "version", "-json"]]


@pytest.mark.parametrize("override", [
    {"GITHUB_ACTIONS": "false"},
    {"RUNNER_ENVIRONMENT": "self-hosted"},
    {"RUNNER_OS": "Windows"},
    {"GITHUB_JOB": "deploy"},
    {"GITHUB_REPOSITORY": "other/repository"},
    {"ImageOS": "unreviewed-image"},
])
def test_userns_permission_preparation_refuses_other_contexts(tmp_path, override):
    import os
    import subprocess
    env = {
        "PATH": os.defpath,
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "GITHUB_JOB": "validate",
        "GITHUB_REPOSITORY": "VINIClUS/infra-ansible",
        "ImageOS": "ubuntu26",
        "RUNNER_TEMP": str(tmp_path),
        **override,
    }
    result = subprocess.run(
        ["bash", str(native.REPO / "tools/ci/prepare-hosted-userns.sh")],
        env=env, text=True, capture_output=True, timeout=5,
    )
    assert result.returncode != 0
    assert "hosted_userns_scope_refused" in result.stderr
    assert not list(tmp_path.iterdir())


def test_userns_permission_is_application_specific_without_global_policy_change():
    script = (native.REPO / "tools/ci/prepare-hosted-userns.sh").read_text()
    assert 'profile cnesdata-ci-unshare /usr/bin/unshare flags=(unconfined)' in script
    assert 'userns,' in script
    privileged = [line.strip() for line in script.splitlines() if line.strip().startswith("sudo ")]
    assert privileged == ['sudo -n /usr/sbin/apparmor_parser --add --skip-cache "$profile"']
    assert 'sysctl -w' not in script
    assert 'systemctl' not in script
    assert '/etc/apparmor.d/' not in script
    assert 'EUID' in script
