"""Prepare pinned native-test tools on an ephemeral GitHub Linux runner only.

Downloads and provider installation happen here, before tests enter network
namespaces. No backend, inventory, AWS credentials or private checkout is used.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import urllib.request
import zipfile
from pathlib import Path

TOFU_VERSION = "1.13.2"
AWS_VERSION = "6.54.0"
RTK_VERSION = "1.1.0"
# Official GitHub release asset SHA-256 digests, recorded 2026-11-07.
DOWNLOADS = {
    "tofu": (
        "https://github.com/opentofu/opentofu/releases/download/v1.13.2/tofu_1.13.2_linux_amd64.zip",
        "723bebb0df8411daff1e5fc3862e28ff5581fe5634087f4c29a9aa41d78208b5",
    ),
    "rtk": (
        "https://github.com/rtk-ai/rtk/releases/download/v1.1.0/rtk-x86_64-unknown-linux-musl.tar.gz",
        "9454ad1b9489daa57ab0a9f4ebe2faaf4dc82b8a0f26c9e5135151abd7c9378d",
    ),
}
REPO = Path(__file__).resolve().parents[2]
FOUNDATION = REPO / "opentofu/cnesdata-bootstrap/foundation"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def provider_binary(directory):
    """Use original package bytes/name; never rename or add a symlink alias."""
    candidates = list(directory.glob("terraform-provider-aws*"))
    require(len(candidates) <= 1, "cached_provider_ambiguous")
    require(len(candidates) == 1, "cached_provider_absent")
    binary = candidates[0]
    require(
        re.fullmatch(r"terraform-provider-aws(?:_v6\.54\.0(?:_x[0-9]+)?)?", binary.name)
        and binary.is_file() and not binary.is_symlink() and os.access(binary, os.X_OK),
        "cached_provider_invalid",
    )
    return binary


def verify_sha256(archive, expected):
    with archive.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    require(actual == expected, "download_checksum_mismatch: " + archive.name)


def extract_binary(archive, name, destination):
    """Read one regular member only; never extract archive paths to disk."""
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as bundle:
            members = [x for x in bundle.infolist() if Path(x.filename).name == name]
            require(len(members) == 1, "archive_binary_ambiguous: " + name)
            member = members[0]
            mode = member.external_attr >> 16
            require(not member.is_dir() and not stat.S_ISLNK(mode), "archive_binary_invalid")
            data = bundle.read(member)
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            members = [x for x in bundle.getmembers() if Path(x.name).name == name]
            require(len(members) == 1, "archive_binary_ambiguous: " + name)
            require(members[0].isfile(), "archive_binary_invalid")
            with bundle.extractfile(members[0]) as stream:
                data = stream.read()
    destination.write_bytes(data)
    destination.chmod(0o755)


def clean_environment(base):
    """Allowlist, rather than trying to enumerate every credential/config input."""
    home = base / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    return {
        "PATH": os.defpath,
        "HOME": str(home),
        "TMPDIR": str(base),
        "LANG": "C.UTF-8",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
        "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
    }


def run(command, folder, env, label):
    result = subprocess.run(command, cwd=folder, env=env, text=True,
                            capture_output=True, timeout=180, check=False)
    require(result.returncode == 0,
            f"{label}: exit={result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def write_provider_seed(seed):
    seed.mkdir()
    config = {"terraform": {
        "required_version": "=" + TOFU_VERSION,
        "required_providers": {"aws": {"source": "hashicorp/aws", "version": "=" + AWS_VERSION}},
    }}
    (seed / "versions.tf.json").write_text(json.dumps(config))
    (seed / ".terraform.lock.hcl").write_bytes((FOUNDATION / ".terraform.lock.hcl").read_bytes())


def prewarm_provider(seed, tofu, env):
    # This seed has no provider config/resources/data sources/backend.
    write_provider_seed(seed)
    lock = (seed / ".terraform.lock.hcl").read_bytes()
    run([tofu, "init", "-backend=false", "-input=false", "-lockfile=readonly"],
        seed, env, "native_provider_prewarm_failed")
    require((seed / ".terraform.lock.hcl").read_bytes() == lock, "provider_lock_changed")
    provider = seed / ".terraform/providers/registry.opentofu.org/hashicorp/aws" / AWS_VERSION / "linux_amd64"
    provider_binary(provider)
    require(seed in provider.resolve().parents, "provider_cache_escaped_seed")
    return provider


def preflight(rtk, tofu, base, env):
    unshare = shutil.which("unshare")
    require(unshare, "native_namespace_unavailable: unshare is required")
    # Exactly the fixture's user+network isolation. Never retry without it.
    version = run([rtk, "proxy", unshare, "--user", "--map-root-user", "--net", tofu,
                   "version", "-json"], base, env, "native_namespace_preflight_failed")
    require(json.loads(version)["terraform_version"] == TOFU_VERSION, "tofu_version_mismatch")


def prepare(base):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "ci_only: downloads require GitHub Actions")
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "ci_platform_unsupported")
    require(not base.exists(), "ci_destination_exists: use a fresh runner-temporary directory")
    base.mkdir(mode=0o700, parents=True)
    binaries = base / "bin"
    binaries.mkdir()
    for name, (url, checksum) in DOWNLOADS.items():
        archive = base / (name + ".download")
        with urllib.request.urlopen(url, timeout=60) as response, archive.open("xb") as output:
            shutil.copyfileobj(response, output)
        verify_sha256(archive, checksum)
        extract_binary(archive, name, binaries / name)
        archive.unlink()

    env = clean_environment(base)
    config = base / "tofu.rc"
    config.write_text('provider_installation { direct { include = ["registry.opentofu.org/hashicorp/aws"] } }\n')
    env["TF_CLI_CONFIG_FILE"] = str(config)
    tofu, rtk = str(binaries / "tofu"), str(binaries / "rtk")
    preflight(rtk, tofu, base, env)
    rtk_version = run([rtk, "--version"], base, env, "rtk_version_failed").strip()
    require(rtk_version == "rtk " + RTK_VERSION, "rtk_version_mismatch")

    provider = prewarm_provider(base / "provider-cache", tofu, env)
    print(f"Prepared OpenTofu {TOFU_VERSION}, RTK {RTK_VERSION}, AWS {AWS_VERSION}; namespace preflight passed")
    return binaries, provider


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--github-env", required=True, type=Path)
    parser.add_argument("--github-path", required=True, type=Path)
    args = parser.parse_args()
    binaries, provider = prepare(args.destination.resolve())
    with args.github_path.open("a") as output:
        output.write(str(binaries) + "\n")
    with args.github_env.open("a") as output:
        output.write("CNESDATA_TEST_AWS_PROVIDER_DIR=" + str(provider) + "\n")


if __name__ == "__main__":
    main()
