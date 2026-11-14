"""EXT-3 credential_process publication on the host, using local files only.

The production owner is root:10001; these tests inject the effective uid/gid,
which exercises the same fchown/fchmod/rename/readback sequence without root.
"""

import json
import os
import stat
import threading
import time

import pytest
from test_personal_platform_dispatcher import runtime

NOW = 1_900_000_000
KEY = "ASIA" + "FIXTURE" + "0" * 9


def owner():
    return (os.geteuid(), os.getegid())


def credentials(lifetime=3600, **changes):
    value = {
        "AccessKeyId": KEY,
        "SecretAccessKey": "secret-fixture",
        "SessionToken": "token-fixture",
        "Expiration": runtime().utc(NOW + lifetime),
    }
    value.update(changes)
    return value


def current(tmp_path):
    return runtime().private_directory(tmp_path / "cnesdata") / "current"


def test_publish_writes_canonical_v1_json_with_exact_owner_mode_and_directory(
    tmp_path,
):
    g = runtime()
    directory = current(tmp_path)
    expires = g.publish_container_credentials(
        directory, credentials(), now=NOW, owner=owner()
    )
    path = directory / "aws-credentials.json"
    info = os.lstat(path)
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o440
    assert (info.st_uid, info.st_gid) == owner() and info.st_nlink == 1
    folder = os.lstat(directory)
    assert stat.S_ISDIR(folder.st_mode) and stat.S_IMODE(folder.st_mode) == 0o710
    assert (folder.st_uid, folder.st_gid) == owner()
    assert path.read_bytes() == g.canonical({"Version": 1, **credentials()})
    assert json.loads(path.read_bytes())["Version"] == 1
    # Only the credential_process document is visible: no INI, expiration or temp.
    assert sorted(os.listdir(directory)) == ["aws-credentials.json"]
    assert expires == NOW + 3600


def test_owner_and_mode_are_applied_to_the_temp_before_rename(tmp_path, monkeypatch):
    g = runtime()
    directory = current(tmp_path)
    original = g.os.replace
    seen = []

    def spy(source, target, *args, **kwargs):
        info = os.lstat(source)
        seen.append(
            (
                os.path.dirname(source),
                os.path.basename(source),
                stat.S_IMODE(info.st_mode),
                (info.st_uid, info.st_gid),
                open(source, "rb").read(),
            )
        )
        return original(source, target, *args, **kwargs)

    monkeypatch.setattr(g.os, "replace", spy)
    g.publish_container_credentials(directory, credentials(), now=NOW, owner=owner())
    [(parent, name, mode, ids, data)] = seen
    assert parent == str(directory) and name.startswith(".write-")
    assert mode == 0o440 and ids == owner()
    assert data == g.canonical({"Version": 1, **credentials()})


@pytest.mark.parametrize("lifetime", [900, 1700, 3299, 3601, -1])
def test_publishable_lifetime_is_at_least_3300_and_at_most_3600(tmp_path, lifetime):
    g = runtime()
    with pytest.raises(ValueError, match="credential lifetime"):
        g.publish_container_credentials(
            current(tmp_path), credentials(lifetime), now=NOW, owner=owner()
        )
    assert not (current(tmp_path) / "aws-credentials.json").exists()


@pytest.mark.parametrize("lifetime", [3300, 3600])
def test_lifetime_window_bounds_are_inclusive(tmp_path, lifetime):
    g = runtime()
    expires = g.publish_container_credentials(
        current(tmp_path), credentials(lifetime), now=NOW, owner=owner()
    )
    assert expires == NOW + lifetime


@pytest.mark.parametrize(
    "changes",
    [
        {"AccessKeyId": "AKIA" + "FIXTURE" + "0" * 9},
        {"AccessKeyId": "ASIAfixture"},
        {"SessionToken": ""},
        {"SecretAccessKey": ""},
        {"SessionToken": 7},
        {"SessionToken": "token\nfixture"},
        {"SecretAccessKey": "secret\rfixture"},
        {"Expiration": "2030-01-01T00:00:00.5Z"},
        {"Version": 1},
        {"AccountId": "111122223333"},
    ],
)
def test_static_malformed_or_extended_documents_are_refused(tmp_path, changes):
    g = runtime()
    with pytest.raises(ValueError):
        g.publish_container_credentials(
            current(tmp_path), credentials(**changes), now=NOW, owner=owner()
        )
    assert not (current(tmp_path) / "aws-credentials.json").exists()


def test_failed_publication_never_alters_the_current_generation(tmp_path, monkeypatch):
    g = runtime()
    directory = current(tmp_path)
    g.publish_container_credentials(directory, credentials(), now=NOW, owner=owner())
    path = directory / "aws-credentials.json"
    before, inode = path.read_bytes(), os.lstat(path).st_ino
    newer = credentials(SecretAccessKey="secret-next", SessionToken="token-next")
    with pytest.raises(ValueError, match="credential lifetime"):
        g.publish_container_credentials(
            directory, credentials(900), now=NOW, owner=owner()
        )

    def fail(*_args, **_kwargs):
        raise OSError("rename interrupted")

    monkeypatch.setattr(g.os, "replace", fail)
    with pytest.raises(OSError, match="rename"):
        g.publish_container_credentials(directory, newer, now=NOW, owner=owner())
    assert path.read_bytes() == before and os.lstat(path).st_ino == inode
    assert sorted(os.listdir(directory)) == ["aws-credentials.json"]


def test_rename_replaces_the_inode_seen_by_a_directory_reader(tmp_path):
    g = runtime()
    directory = current(tmp_path)
    g.publish_container_credentials(directory, credentials(), now=NOW, owner=owner())
    first = os.lstat(directory / "aws-credentials.json").st_ino
    newer = credentials(AccessKeyId="ASIA" + "NEXT" + "0" * 12)
    g.publish_container_credentials(directory, newer, now=NOW, owner=owner())
    path = directory / "aws-credentials.json"
    assert os.lstat(path).st_ino != first
    assert json.loads(path.read_bytes())["AccessKeyId"] == newer["AccessKeyId"]


def test_shared_directory_is_created_0710_with_the_container_group(tmp_path):
    g = runtime()
    parent = g.private_directory(tmp_path / "cnesdata")
    path = g.shared_directory(parent / "current", owner=owner())
    info = os.lstat(path)
    assert stat.S_IMODE(info.st_mode) == 0o710 and (info.st_uid, info.st_gid) == owner()
    assert stat.S_IMODE(os.lstat(parent).st_mode) == 0o700


@pytest.mark.parametrize("mode", [0o700, 0o750, 0o711, 0o770, 0o2710])
def test_shared_directory_refuses_divergent_mode(tmp_path, mode):
    g = runtime()
    path = g.private_directory(tmp_path / "cnesdata") / "current"
    path.mkdir()
    os.chmod(path, mode)
    with pytest.raises(ValueError, match="shared directory"):
        g.shared_directory(path, owner=owner())


def test_shared_directory_refuses_divergent_group_and_symlink(tmp_path):
    g = runtime()
    parent = g.private_directory(tmp_path / "cnesdata")
    path = g.shared_directory(parent / "current", owner=owner())
    uid, gid = owner()
    with pytest.raises(ValueError, match="shared directory"):
        g.shared_directory(path, owner=(uid, gid + 12345))
    elsewhere = g.private_directory(tmp_path / "elsewhere")
    (parent / "linked").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        g.shared_directory(parent / "linked", owner=owner())


def test_shared_directory_requires_a_private_parent(tmp_path):
    g = runtime()
    parent = tmp_path / "cnesdata"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o750)
    with pytest.raises(ValueError, match="insecure directory"):
        g.shared_directory(parent / "current", owner=owner())
    assert not (parent / "current").exists()


def test_read_shared_requires_exact_regular_file_owner_mode_and_link(tmp_path):
    g = runtime()
    directory = current(tmp_path)
    g.publish_container_credentials(directory, credentials(), now=NOW, owner=owner())
    path = directory / "aws-credentials.json"
    assert g.read_shared(path, owner=owner()) == path.read_bytes()
    uid, gid = owner()
    with pytest.raises(ValueError, match="shared file"):
        g.read_shared(path, owner=(uid, gid + 12345))
    os.link(path, directory / "second-link")
    with pytest.raises(ValueError, match="shared file"):
        g.read_shared(path, owner=owner())
    os.unlink(directory / "second-link")
    os.chmod(path, 0o444)
    with pytest.raises(ValueError, match="shared file"):
        g.read_shared(path, owner=owner())
    os.chmod(path, 0o440)
    alias = directory / "alias.json"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        g.read_shared(alias, owner=owner())


def test_read_shared_refuses_a_fifo_without_blocking(tmp_path):
    g = runtime()
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo, 0o440)
    outcome = []

    def read():
        try:
            g.read_shared(fifo, owner=owner())
        except ValueError as error:
            outcome.append(str(error))

    start = time.monotonic()
    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    worker.join(2)
    assert not worker.is_alive() and time.monotonic() - start < 2
    assert outcome == ["shared file"]


def compose():
    image = "ghcr.io/viniclus/cnesdata@sha256:" + "a" * 64
    return image, {
        "services": {
            "api": {
                "image": image,
                "ports": [
                    {"host_ip": "127.0.0.1", "published": "18081", "target": 8000}
                ],
                "networks": {"cnesdata": {}},
                "read_only": True,
                "user": "10001:10001",
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "mem_limit": "512m",
                "cpus": "0.5",
                "pids_limit": 128,
                "logging": {
                    "driver": "json-file",
                    "options": {"max-size": "10m", "max-file": "3"},
                },
                "healthcheck": {"test": ["CMD", "true"]},
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/run/personal-platform/credentials/cnesdata/current",
                        "target": "/run/credentials",
                        "read_only": True,
                        "bind": {"create_host_path": False},
                    }
                ],
            }
        },
        "networks": {"cnesdata": {"name": "cnesdata"}},
    }


@pytest.mark.parametrize(
    "environment",
    [
        {"AWS_SHARED_CREDENTIALS_FILE": "/run/credentials/credentials"},
        {"AWS_SHARED_CREDENTIALS_FILE": "/dev/null"},
        {"AWS_CONFIG_FILE": "/run/credentials/aws-config"},
        {"AWS_ACCESS_KEY_ID": "ASIAFIXTURE"},
        {"AWS_PROFILE": "default"},
        {"AWS_EC2_METADATA_DISABLED": "true"},
        {"PYTHONPATH": "/run/credentials"},
    ],
)
def test_compose_refuses_every_aws_environment_override(environment):
    import copy

    g = runtime()
    image, base = compose()
    g.validate_compose(base, image, 18081)
    wrong = copy.deepcopy(base)
    wrong["services"]["api"]["environment"] = environment
    with pytest.raises(ValueError, match="runtime environment authority"):
        g.validate_compose(wrong, image, 18081)


def test_compose_keeps_only_the_read_only_directory_bind():
    import copy

    g = runtime()
    image, base = compose()
    neutral = copy.deepcopy(base)
    neutral["services"]["api"]["environment"] = {"TZ": "UTC"}
    g.validate_compose(neutral, image, 18081)
    for source, target, read_only in (
        (
            "/run/personal-platform/credentials/cnesdata/current/aws-credentials.json",
            "/run/credentials/aws-credentials.json",
            True,
        ),
        ("/run/personal-platform/credentials/cnesdata", "/run/credentials", True),
        ("/run/personal-platform/credentials/cnesdata/current", "/run/credentials", False),
    ):
        wrong = copy.deepcopy(base)
        wrong["services"]["api"]["volumes"][0].update(
            source=source, target=target, read_only=read_only
        )
        with pytest.raises(ValueError):
            g.validate_compose(wrong, image, 18081)


def test_container_owner_is_applied_by_fchown_before_the_rename(tmp_path, monkeypatch):
    g = runtime()
    assert g.CONTAINER_OWNER == (0, 10001)
    events = []
    fchown, replace = g.os.fchown, g.os.replace

    def spy_fchown(fd, uid, gid):
        events.append(("fchown", uid, gid))
        return fchown(fd, uid, gid)

    def spy_replace(source, target):
        events.append(("replace",))
        return replace(source, target)

    monkeypatch.setattr(g.os, "fchown", spy_fchown)
    monkeypatch.setattr(g.os, "replace", spy_replace)
    g.publish_container_credentials(
        current(tmp_path), credentials(), now=NOW, owner=owner()
    )
    assert events == [("fchown", *owner()), ("replace",)]


def test_document_never_exceeds_the_reader_8_kib_bound(tmp_path):
    g = runtime()
    with pytest.raises(ValueError, match="credential document bound"):
        g.publish_container_credentials(
            current(tmp_path),
            credentials(SessionToken="t" * 8200),
            now=NOW,
            owner=owner(),
        )
    assert not (current(tmp_path) / "aws-credentials.json").exists()
