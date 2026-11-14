"""H8: native Docker semantics of the EXT-3 credential directory bind.

The real publish_container_credentials runs as root in a writer container and a
long-lived reader runs as uid 10001 with the production hardening flags. Skips
only when no usable Docker daemon/image exists; it is not host evidence.
"""

import json
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
IMAGE = "python:3.12-alpine"
HARDENED = [
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--network",
    "none",
]
WRITER = """
import sys, time
from pathlib import Path
sys.path.insert(0, "/src")
from tools.cnesdata_delivery import host_gate as g
now = time.time()
root = g.private_directory(Path("/run/pp/credentials"))
cnesdata = g.private_directory(root / "cnesdata")
g.publish_container_credentials(
    cnesdata / "current",
    {
        "AccessKeyId": sys.argv[1],
        "SecretAccessKey": "secret-" + sys.argv[1],
        "SessionToken": "token-" + sys.argv[1],
        "Expiration": g.utc(now + 3600),
    },
    now=now,
    owner=(0, 10001),
)
"""
READER = """
import json, os, time
def key(path):
    try:
        with open(path, "rb") as file:
            return json.loads(file.read())["AccessKeyId"]
    except OSError as error:
        return type(error).__name__
print(f"start uid={os.getuid()} gid={os.getgid()}", flush=True)
try:
    open("/run/credentials/probe", "w")
    print("write=allowed", flush=True)
except OSError as error:
    print(f"write=errno{error.errno}", flush=True)
try:
    os.listdir("/run/credentials")
    print("listdir=allowed", flush=True)
except OSError as error:
    print(f"listdir={type(error).__name__}", flush=True)
last = None
while True:
    now = (key("/run/credentials/aws-credentials.json"), key("/run/filebind.json"))
    if now != last:
        print(f"dir_bind={now[0]} file_bind={now[1]}", flush=True)
        last = now
    time.sleep(0.1)
"""
PROBE = """
import os, sys
try:
    with open(sys.argv[1], "rb") as file:
        file.read()
    print("read=allowed")
except OSError as error:
    print(f"read={type(error).__name__}")
"""
KEY_A = "ASIA" + "NATIVEA" + "0" * 9
KEY_B = "ASIA" + "NATIVEB" + "0" * 9


def docker(*args, check=True, timeout=120):
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )
    if check and result.returncode != 0:
        raise AssertionError(f"docker {args[0]} failed: {result.stderr[-2000:]}")
    return result


@pytest.fixture
def native(tmp_path):
    if shutil.which("docker") is None:
        pytest.skip("native_docker_unavailable: docker CLI absent")
    if docker("info", check=False, timeout=30).returncode != 0:
        pytest.skip("native_docker_unavailable: daemon not reachable")
    if docker("image", "inspect", IMAGE, check=False).returncode != 0:
        if docker("pull", "-q", IMAGE, check=False, timeout=300).returncode != 0:
            pytest.skip("native_docker_unavailable: image " + IMAGE + " not pullable")
    state = tmp_path / "pp"
    state.mkdir()
    names = []
    yield state, names
    for name in names:
        docker("rm", "-f", name, check=False)
    docker(
        "run", "--rm", "--network", "none", "-v", f"{state}:/x", IMAGE,
        "sh", "-c", "rm -rf /x/credentials",
        check=False,
    )


def publish(state, key):
    docker(
        "run", "--rm", "--user", "0:0", *HARDENED[:1], "--network", "none",
        "-v", f"{REPO / 'tools'}:/src/tools:ro",
        "-v", f"{state}:/run/pp",
        IMAGE, "python3", "-I", "-c", WRITER, key,
    )


def probe(state, user, path, mount):
    return docker(
        "run", "--rm", "--user", user, *HARDENED, "-v", mount,
        IMAGE, "python3", "-I", "-c", PROBE, path,
    ).stdout.strip()


def wait_for(name, text, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        logs = docker("logs", name).stdout
        if text in logs:
            return logs
        time.sleep(0.2)
    raise AssertionError(f"{text!r} not observed; logs={logs!r}")


def test_directory_bind_sees_atomic_rename_without_restart(native):
    state, names = native
    current = state / "credentials" / "cnesdata" / "current"
    publish(state, KEY_A)
    reader = "cred55-h8-" + uuid.uuid4().hex[:12]
    names.append(reader)
    docker(
        "run", "-d", "--name", reader, "--user", "10001:10001", *HARDENED,
        "-v", f"{current}:/run/credentials:ro",
        "-v", f"{current / 'aws-credentials.json'}:/run/filebind.json:ro",
        IMAGE, "python3", "-I", "-u", "-c", READER,
    )
    logs = wait_for(reader, f"dir_bind={KEY_A} file_bind={KEY_A}")
    assert "start uid=10001 gid=10001" in logs
    assert "write=errno30" in logs  # EROFS: the container cannot alter the bind
    assert "listdir=PermissionError" in logs  # 0710: traverse, never enumerate
    before = json.loads(docker("inspect", reader).stdout)[0]
    publish(state, KEY_B)
    # The directory bind follows the rename; a single-file bind keeps the old
    # inode, which is why validate_compose only admits the directory pair.
    logs = wait_for(reader, f"dir_bind={KEY_B} file_bind={KEY_A}")
    after = json.loads(docker("inspect", reader).stdout)[0]
    assert after["RestartCount"] == before["RestartCount"] == 0
    assert after["State"]["StartedAt"] == before["State"]["StartedAt"]
    assert after["State"]["Pid"] == before["State"]["Pid"]
    assert after["State"]["Running"] is True


def test_only_the_container_group_reads_and_no_host_user_traverses(native):
    state, _ = native
    current = state / "credentials" / "cnesdata" / "current"
    publish(state, KEY_A)
    file = "/run/credentials/aws-credentials.json"
    mount = f"{current}:/run/credentials:ro"
    assert probe(state, "10001:10001", file, mount) == "read=allowed"
    assert probe(state, "10002:10002", file, mount) == "read=PermissionError"
    # Any non-root identity that sees the parents stops at the 0700 root levels.
    parents = f"{state / 'credentials'}:/mnt:ro"
    for user in ("10001:10001", "1000:1000"):
        assert (
            probe(state, user, "/mnt/cnesdata/current/aws-credentials.json", parents)
            == "read=PermissionError"
        )


def test_real_docker_cli_matches_the_adoption_observer(native):
    """ps filters, inspect fields, RFC3339Nano StartedAt and logs --since epoch."""
    import sys

    sys.path.insert(0, str(REPO))
    from tools.cnesdata_delivery import host_gate as g

    _, names = native
    project = "cnesdata-h8" + uuid.uuid4().hex[:8]
    name = "cred55-h8-" + uuid.uuid4().hex[:12]
    names.append(name)
    fingerprint = g.key_fingerprint(KEY_A)
    event = f"aws_credentials_refreshed key_fp={fingerprint} previous_fp=none pid=1"
    contract = json.dumps(
        {
            "timestamp": "2026-11-14T16:00:00.000001Z",
            "level": "INFO",
            "service": "central-api",
            "logger": "cnes_infra.aws.credentials",
            "event": event,
        }
    )
    script = (
        "import sys, time\n"
        f"print({contract!r}, flush=True)\n"
        f"print({contract!r}, file=sys.stderr, flush=True)\n"
        "time.sleep(600)\n"
    )
    since = int(time.time()) - 1
    docker(
        "run", "-d", "--name", name, "--user", "10001:10001", *HARDENED,
        "--label", "com.docker.compose.project=" + project,
        "--label", "com.docker.compose.service=api",
        IMAGE, "python3", "-I", "-u", "-c", script,
    )
    wait_for(name, event)

    def read(argv):
        return g.supervise(argv, lambda: None)

    client = g.credential_client(read, (project,))
    assert client["id"] == docker("inspect", "--format", "{{.Id}}", name).stdout.strip()
    assert client["restart_count"] == 0
    assert abs(g.started_at(client["started_at"]) - time.time()) < 120
    logs = read(["/usr/bin/docker", "logs", "--since", str(since), client["id"]])
    # Only the container stdout reaches the host parser (stderr is discarded).
    assert g.adoption_events(logs) == [(fingerprint, "none")]
    later = read(
        ["/usr/bin/docker", "logs", "--since", str(int(time.time()) + 5), client["id"]]
    )
    assert g.adoption_events(later) == []
