"""EXT-3 cnesdata renewal: JSON publication without restart, adoption one cycle behind.

Synthetic helper, Docker CLI, lease and clock boundaries. Nothing here is live
host evidence; the real proof is the operational acceptance on EXT-3.
"""

import copy
import hashlib
import json
import os
import signal
import stat
import sys
from pathlib import Path

import pytest
from test_personal_platform_dispatcher import H, closed_ready_fixture, runtime
from test_personal_platform_lease import Clock

DAY = 86400
START = 1_000_000
BLUE = "b" * 64
GREEN = "c" * 64
OTHER = "d" * 64
FORBIDDEN = {"restart", "stop", "kill", "rm", "compose", "up", "start", "exec"}


def key(n):
    return "ASIA" + f"{n:016d}"


def fp(n):
    return hashlib.sha256(key(n).encode()).hexdigest()[:12]


def refreshed(n, previous=None, pid=7):
    prior = fp(previous) if previous else "none"
    return f"aws_credentials_refreshed key_fp={fp(n)} previous_fp={prior} pid={pid}"


def line(event, **changes):
    value = {
        "timestamp": "2026-11-14T16:00:00.000001Z",
        "level": "INFO",
        "service": "central-api",
        "logger": "cnes_infra.aws.credentials",
        "event": event,
        "elapsed": 0.25,
    }
    value.update(changes)
    return json.dumps(value).encode()


class Docker:
    """Helper and Docker CLI fake; any mutation command fails the test."""

    def __init__(self, clock):
        self.clock = clock
        self.containers = {}
        self.calls = []
        self.issued = 0
        self.lifetime = 3600
        self.failure = None
        self.on_helper = None

    def run(self, ident, project="cnesdata-blue", running=True):
        self.containers[ident] = {
            "project": project,
            "running": running,
            "started": self.clock.t,
            "restart_count": 0,
            "logs": [],
        }

    def started_at(self, ident):
        return runtime().utc(self.containers[ident]["started"])[:-1] + ".123456789Z"

    def restarted(self, ident):
        """Docker restart policy (not the host): same Id, new StartedAt/count."""
        container = self.containers[ident]
        container.update(
            running=True,
            started=self.clock.t,
            restart_count=container["restart_count"] + 1,
        )

    def log(self, ident, data):
        self.containers[ident]["logs"].append((self.clock.t, data))

    def identity(self, ident):
        return {
            "id": ident,
            "started_at": self.started_at(ident),
            "restart_count": self.containers[ident]["restart_count"],
        }

    def __call__(self, argv, guard, **kwargs):
        guard()
        self.calls.append(list(argv))
        if argv[0] == "/usr/local/bin/aws_signing_helper":
            return self.helper(argv, guard)
        assert argv[0] == "/usr/bin/docker" and not FORBIDDEN & set(argv[1:2])
        if argv[1] == "ps":
            return self.ps(argv)
        if argv[1] == "inspect":
            container = self.containers[argv[2]]
            labels = {
                "com.docker.compose.project": container["project"],
                "com.docker.compose.service": "api",
            }
            return json.dumps(
                [
                    {
                        "Id": argv[2],
                        "Config": {"Labels": labels},
                        "State": {
                            "Running": container["running"],
                            "StartedAt": self.started_at(argv[2]),
                        },
                        "RestartCount": container["restart_count"],
                    }
                ]
            ).encode()
        if argv[1] == "logs":
            assert argv[2] == "--since" and len(argv) == 5
            since, entries = int(argv[3]), self.containers[argv[4]]["logs"]
            return b"".join(data + b"\n" for t, data in entries if t >= since)
        raise AssertionError("unexpected docker command")

    def helper(self, argv, guard):
        assert argv[argv.index("--session-duration") + 1] == "3600"
        assert argv[argv.index("--certificate") + 1].startswith(
            "/etc/personal-platform/ra/cnesdata/"
        )
        if self.on_helper:
            self.on_helper(guard)
        if self.failure:
            raise self.failure
        self.issued += 1
        return runtime().canonical(
            {
                "Version": 1,
                "AccessKeyId": key(self.issued),
                "SecretAccessKey": "secret-" + str(self.issued),
                "SessionToken": "token-" + str(self.issued),
                "Expiration": runtime().utc(self.clock.t + self.lifetime),
            }
        )

    def ps(self, argv):
        assert {"--no-trunc", "--quiet"} <= set(argv)
        filters = {argv[i + 1] for i, a in enumerate(argv) if a == "--filter"}
        assert {"status=running", "label=com.docker.compose.service=api"} <= filters
        [project] = [
            f.split("=", 2)[2]
            for f in filters
            if f.startswith("label=com.docker.compose.project=")
        ]
        return "".join(
            ident + "\n"
            for ident, c in self.containers.items()
            if c["running"] and c["project"] == project
        ).encode()


class API:
    def __init__(self, binding):
        self.binding = binding

    def read(self, path):
        return {
            "id": 12,
            "run_attempt": 1,
            "repository": {"full_name": "VINIClUS/CnesData"},
            "head_sha": self.binding["caller"]["source_sha"],
            "path": self.binding["caller"]["workflow_path"],
            "status": "completed",
            "conclusion": "success",
        }


def governance(g, clock):
    return {
        "credentials": {
            "application": "cnesdata",
            "certificate": "/etc/personal-platform/ra/cnesdata/certificate.pem",
            "private_key": "/etc/personal-platform/ra/cnesdata/private-key.pem",
            "trust_anchor_arn": "fixture",
            "profile_arn": "fixture",
            "role_arn": "fixture",
            "duration_seconds": 3600,
            "trust_deadline": g.utc(clock.t + 30 * DAY),
        }
    }


class Host:
    def __init__(self, tmp_path, monkeypatch):
        self.g = g = runtime()
        self.clock = Clock()
        self.clock.t = self.clock.m = START
        self.lease = g.HostLease(tmp_path / "authority", self.clock)
        self.docker = Docker(self.clock)
        self.root = tmp_path / "credentials"
        self.binding = closed_ready_fixture()[2]["binding"]
        self.invocation = 0
        self.deploys = 0
        self.governance = governance(g, self.clock)
        require, read = g.require, g.read_private
        monkeypatch.setattr(
            g,
            "require",
            lambda c, r: require(True if r == "root credential renewal" else c, r),
        )
        monkeypatch.setattr(
            g,
            "read_private",
            lambda p, *a, **kw: (
                b"certificate"
                if str(p).startswith("/etc/personal-platform/ra/")
                else read(p, *a, **kw)
            ),
        )
        monkeypatch.setattr(g, "Clock", lambda: self.clock)
        monkeypatch.setattr(g, "HostLease", lambda: self.lease)
        monkeypatch.setattr(g, "ROOT", self.lease.root)
        monkeypatch.setattr(g, "GitHub", lambda *_: API(self.binding))
        monkeypatch.setattr(g, "process_identity", self.identity)
        monkeypatch.setattr(g, "process_absent", lambda _: True)
        monkeypatch.setattr(g, "supervise", self.docker)
        monkeypatch.setattr(g, "CREDENTIAL_ROOT", self.root)
        monkeypatch.setattr(g, "CONTAINER_OWNER", (os.geteuid(), os.getegid()))

        def no_health(*_a, **_k):
            raise AssertionError("JSON renewal never reads a health endpoint")

        monkeypatch.setattr(g.urllib.request, "urlopen", no_health)

    def identity(self):
        return {
            "boot_id": "fixture-boot",
            "pid": 11,
            "start_ticks": 2,
            "invocation_id": "renew-" + str(self.invocation),
        }

    def renew(self):
        self.invocation += 1
        return self.g.renew_application_credentials(copy.deepcopy(self.governance))

    def deploy(self, container, *, previous=None, rolled_back=False):
        """Accepted deploy whose checkpoint names the new API container Id.

        rolled_back: the candidate started, then the exact nginx checkpoint was
        restored (restore_previous), so the previous release keeps serving.
        """
        g, b = self.g, self.binding
        b["previous_accepted_sha256"] = previous
        owner = {
            "class": "workflow",
            "process": {
                "boot_id": "fixture-boot",
                "pid": 99,
                "start_ticks": 1,
                "invocation_id": None,
            },
            "workflow": b["caller"],
            "human_session_commitment": None,
            "systemd_invocation": None,
        }
        self.deploys += 1
        operation = H if self.deploys == 1 else g.sha(b"deploy-%d" % self.deploys)
        token, first = self.lease.acquire(
            owner,
            operation,
            terminal_proof=lambda prior: g.prior_terminal(prior, b, API(b)),
        )
        b["lease_owner_sha256"] = g.sha(token)
        b["initial_generation"] = first["lease"]["generation"]
        op = g.Operation(self.lease, token, first, b, {"fixture": b"original"})
        for state in ("VERIFIED", "STAGED", "CANDIDATE_HEALTHY", "SWITCHED"):
            op.transition(state)
        if rolled_back:
            record = copy.deepcopy(op.record)
            record["effect_confirmed"] = True
            op.commit(record)
            op.transition("ROLLED_BACK")
        else:
            op.transition("ACCEPTED")
        g.durable(
            op.directory / "candidate-container.json",
            g.canonical(
                {
                    "version": 1,
                    "kind": "deploy-container",
                    "operation_id": op.record["operation_id"],
                    "project": self.docker.containers[container]["project"],
                    **self.docker.identity(container),
                }
            ),
            immutable=True,
        )
        accepted = op.snapshot["head"]["record_sha256"]
        self.lease.release(token, op.snapshot, accepted, lambda: True)
        return accepted

    def path(self):
        return self.root / "cnesdata" / "current" / "aws-credentials.json"

    def document(self):
        return json.loads(self.path().read_bytes())

    def state(self):
        return json.loads((self.root / "cnesdata" / "state.json").read_bytes())

    def record(self):
        name = self.state()["publication_sha256"] + ".json"
        return json.loads((self.root / "cnesdata" / "generations" / name).read_bytes())

    def checkpoint(self, digest=None):
        digest = digest or self.lease.snapshot()["lease"]["checkpoint_sha256"]
        raw = (self.lease.root / "checkpoints" / (digest + ".json")).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest
        return json.loads(raw)

    def advance(self, seconds):
        self.clock.advance(seconds)

    def released(self):
        return self.lease.snapshot()["lease"]["state"] == "RELEASED"


@pytest.fixture
def host(tmp_path, monkeypatch):
    return Host(tmp_path, monkeypatch)


def missing(generation, *suffix):
    return " ".join(
        [f"credential_adoption=missing generation={generation} key_fp={fp(generation)}"]
        + list(suffix)
    )


def test_first_publication_is_json_only_outside_records_and_never_restarts(host):
    g = host.g
    assert host.renew() == []
    document = host.document()
    assert document == {
        "Version": 1,
        "AccessKeyId": key(1),
        "SecretAccessKey": "secret-1",
        "SessionToken": "token-1",
        "Expiration": g.utc(START + 3600),
    }
    current = host.root / "cnesdata" / "current"
    assert sorted(os.listdir(current)) == ["aws-credentials.json"]
    assert stat.S_IMODE(os.lstat(current).st_mode) == 0o710
    for parent in (host.root, host.root / "cnesdata"):
        assert stat.S_IMODE(os.lstat(parent).st_mode) & 0o077 == 0
    state, record = host.state(), host.record()
    assert state["generation"] == 1 and state["adopted"] is False
    assert record["key_fp"] == fp(1) and record["container"] is None
    assert record["previous_expiration"] is None
    assert record["published_at"] == g.utc(START)
    assert record["adopt_by"] == g.utc(START + 120)
    for path in (host.root / "cnesdata").rglob("*"):
        if path.is_file() and path.parent != current:
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert b"secret-1" not in path.read_bytes()
            assert b"token-1" not in path.read_bytes()
    assert host.released()
    checkpoint = host.checkpoint()
    assert checkpoint["kind"] == "credential-publication"
    assert checkpoint["publication_sha256"] == state["publication_sha256"]
    assert checkpoint["adoption_sha256"] is None and checkpoint["quiescent"] is True
    assert [c[0] for c in host.docker.calls].count("/usr/local/bin/aws_signing_helper") == 1


def test_legacy_restart_governance_is_refused_before_any_effect(host):
    host.governance["credentials"].pop("trust_deadline")
    host.governance["credentials"].update(
        container_id="a" * 12,
        health_url="http://127.0.0.1:18081/api/v1/system/health",
        readiness_sha256=H,
    )
    with pytest.raises(ValueError):
        host.renew()
    assert host.docker.calls == [] and host.lease.snapshot()["lease"] is None


@pytest.mark.parametrize(
    "change",
    [
        {"duration_seconds": 900},
        {"duration_seconds": 3599},
        {"duration_seconds": 3601},
        {"duration_seconds": "3600"},
        {"duration_seconds": True},
        {"trust_deadline": "2026-12-13"},
        {"trust_deadline": None},
        {"container_id": "a" * 12},
        {"health_url": "http://127.0.0.1:18081/health/ready"},
        {"readiness_sha256": H},
        {"certificate": "/etc/personal-platform/ra/limnopulse/certificate.pem"},
        {"private_key": "/etc/personal-platform/ra/cnesdata/certificate.pem"},
    ],
)
def test_json_governance_is_closed_with_a_fixed_3600_second_session(host, change):
    host.governance["credentials"].update(change)
    with pytest.raises(ValueError):
        host.renew()
    assert host.docker.calls == [] and host.lease.snapshot()["lease"] is None


def test_json_governance_requires_the_trust_deadline(host):
    host.governance["credentials"].pop("trust_deadline")
    with pytest.raises(ValueError):
        host.renew()
    assert host.docker.calls == []


def test_renews_only_with_1800_seconds_or_less_remaining(host):
    assert host.renew() == []
    first, inode = host.document(), os.lstat(host.path()).st_ino
    host.advance(1799)
    assert host.renew() == []
    assert host.document() == first and os.lstat(host.path()).st_ino == inode
    assert host.docker.issued == 1 and host.released()
    host.advance(1)
    assert host.renew() == []
    assert host.docker.issued == 2 and host.document()["AccessKeyId"] == key(2)
    assert host.state()["generation"] == 2
    assert host.record()["previous_expiration"] == host.g.utc(START + 3600)
    # botocore adopts at previous - 900; the watcher logs within 60 s; 60 s slack.
    assert host.record()["adopt_by"] == host.g.utc(START + 3600 - 780)


@pytest.mark.parametrize("damage", ["missing", "mode", "foreign", "state"])
def test_missing_unreadable_or_foreign_current_is_republished(host, damage):
    g = host.g
    assert host.renew() == []
    path = host.path()
    if damage == "missing":
        path.unlink()
    elif damage == "mode":
        os.chmod(path, 0o444)
    elif damage == "foreign":
        path.unlink()
        g.publish_container_credentials(
            path.parent,
            {
                "AccessKeyId": key(99),
                "SecretAccessKey": "foreign",
                "SessionToken": "foreign",
                "Expiration": g.utc(START + 3600),
            },
            now=START,
            owner=(os.geteuid(), os.getegid()),
        )
    else:
        (host.root / "cnesdata" / "state.json").unlink()
    host.advance(300)
    assert host.renew() == []
    assert host.docker.issued == 2 and host.document()["AccessKeyId"] == key(2)


def test_two_rotations_are_adopted_in_the_same_container_without_restart(host):
    g = host.g
    host.docker.run(BLUE)
    host.deploy(BLUE)
    before = host.docker.identity(BLUE)
    assert host.renew() == []
    assert host.record()["container"] == before
    host.advance(60)
    host.docker.log(BLUE, line(refreshed(1)))
    host.advance(240)
    assert host.renew() == []
    state = host.state()
    assert state["adopted"] is True and state["baseline"] == before
    adoption = host.checkpoint(host.checkpoint()["adoption_sha256"])
    assert adoption["kind"] == "credential-adoption" and adoption["rebased"] is False
    assert adoption["container"] == before and adoption["key_fp"] == fp(1)
    host.advance(1500)
    assert host.renew() == []
    assert host.state()["generation"] == 2
    assert host.record()["adopt_by"] == g.utc(START + 3600 - 780)
    host.advance(300)
    assert host.renew() == [] and host.state()["adopted"] is False
    host.advance(660)
    host.docker.log(BLUE, line(refreshed(2, 1)))
    host.advance(60)
    assert host.renew() == []
    assert host.state()["adopted"] is True and host.state()["baseline"] == before
    assert host.docker.identity(BLUE) == before
    assert all(not FORBIDDEN & set(c[1:2]) for c in host.docker.calls)


def test_missing_adoption_fails_the_unit_but_never_withholds_publication(host):
    host.docker.run(BLUE)
    host.deploy(BLUE)
    assert host.renew() == []
    host.advance(300)
    assert host.renew() == [missing(1)]
    assert host.released() and host.state()["adopted"] is False
    assert host.checkpoint()["adoption_sha256"] is None
    host.advance(1500)
    assert host.renew() == [missing(1)]
    assert host.docker.issued == 2 and host.state()["generation"] == 2


@pytest.mark.parametrize(
    "data",
    [
        refreshed(1).encode(),
        line(refreshed(1), service="data-processor"),
        line(refreshed(1), logger="cnes_infra.aws"),
        line(refreshed(1), level="WARNING"),
        line(refreshed(1) + " extra=1"),
        line("x " + refreshed(1)),
        line(refreshed(1).replace(fp(1), fp(1)[:8])),
        line(refreshed(1).replace(fp(1), fp(1).upper())),
        line(refreshed(2, 1)),
        line(refreshed(1)).replace(b'"level": "INFO"', b'"level": "INFO", "level": "INFO"'),
        b"[" + line(refreshed(1)) + b"]",
    ],
)
def test_only_exact_contract_lines_of_the_same_container_prove_adoption(host, data):
    host.docker.run(BLUE)
    host.docker.run(OTHER, project="limnopulse-blue")
    host.deploy(BLUE)
    assert host.renew() == []
    host.advance(60)
    host.docker.log(BLUE, data)
    host.docker.log(OTHER, line(refreshed(1)))
    host.advance(240)
    assert host.renew() == [missing(1)]


def test_lines_before_the_publication_do_not_count(host):
    host.docker.run(BLUE)
    host.deploy(BLUE)
    host.docker.log(BLUE, line(refreshed(1)))
    host.advance(1)
    assert host.renew() == []
    host.advance(300)
    assert host.renew() == [missing(1)]


def test_new_container_without_a_deploy_checkpoint_is_container_replaced(host):
    host.docker.run(BLUE)
    host.deploy(BLUE)
    assert host.renew() == []
    host.docker.containers[BLUE]["running"] = False
    host.advance(30)
    host.docker.run(GREEN, project="cnesdata-green")
    host.docker.log(GREEN, line(refreshed(1)))
    host.advance(270)
    assert host.renew() == [
        f"credential_adoption=container_replaced generation=1 key_fp={fp(1)}"
    ]
    assert host.state()["adopted"] is False and host.released()


def test_first_generation_rebases_on_the_deployed_container_boot_line(host):
    host.docker.run(BLUE, running=False)
    host.deploy(BLUE)
    assert host.renew() == []
    assert host.record()["container"] is None
    host.advance(30)
    host.docker.restarted(BLUE)
    host.docker.log(BLUE, line(refreshed(1)))
    host.advance(270)
    assert host.renew() == []
    state = host.state()
    assert state["adopted"] is True and state["baseline"] == host.docker.identity(BLUE)
    adoption = host.checkpoint(host.checkpoint()["adoption_sha256"])
    assert adoption["rebased"] is True


def test_new_deployed_container_rebases_only_with_its_boot_line(host):
    host.docker.run(BLUE, running=False)
    host.deploy(BLUE)
    host.docker.run(GREEN, project="cnesdata-green")
    assert host.renew() == []
    assert host.record()["container"]["id"] == GREEN
    host.docker.containers[GREEN]["running"] = False
    host.advance(30)
    host.docker.restarted(BLUE)
    host.docker.log(BLUE, line(refreshed(1, 2)))
    host.advance(270)
    assert host.renew() == [missing(1)]
    host.docker.log(BLUE, line(refreshed(1)))
    host.advance(300)
    assert host.renew() == []
    assert host.state()["baseline"] == host.docker.identity(BLUE)


def test_restart_after_publication_is_reported_once_then_rebased(host):
    host.docker.run(BLUE)
    host.deploy(BLUE)
    assert host.renew() == []
    host.advance(60)
    host.docker.log(BLUE, line(refreshed(1)))
    host.advance(1740)
    assert host.renew() == []
    assert host.state()["generation"] == 2
    host.advance(700)
    host.docker.restarted(BLUE)
    host.docker.log(BLUE, line(refreshed(2)))
    host.advance(320)
    assert host.renew() == [
        f"credential_adoption=container_restarted generation=2 key_fp={fp(2)}"
    ]
    assert host.state()["restart_reported"] == host.docker.identity(BLUE)
    host.advance(300)
    assert host.renew() == []
    state = host.state()
    assert state["adopted"] is True and state["restart_reported"] is None
    assert state["baseline"] == host.docker.identity(BLUE)


def test_restart_before_publication_is_still_reported_against_the_baseline(host):
    host.docker.run(BLUE)
    host.deploy(BLUE)
    assert host.renew() == []
    host.advance(60)
    host.docker.log(BLUE, line(refreshed(1)))
    host.advance(240)
    assert host.renew() == []
    host.advance(1000)
    host.docker.restarted(BLUE)
    host.docker.log(BLUE, line(refreshed(1)))
    host.advance(500)
    assert host.renew() == []
    assert host.record()["container"] == host.docker.identity(BLUE)
    host.advance(960)
    host.docker.log(BLUE, line(refreshed(2, 1)))
    host.advance(60)
    assert host.renew() == [
        f"credential_adoption=container_restarted generation=2 key_fp={fp(2)}"
    ]
    host.advance(300)
    assert host.renew() == []
    assert host.state()["baseline"] == host.docker.identity(BLUE)


def test_no_deploy_and_no_container_has_nothing_to_adopt(host):
    assert host.renew() == []
    host.advance(300)
    assert host.renew() == []
    assert host.state()["adopted"] is False


def test_deployed_client_absent_or_ambiguous_is_missing_with_reason(host):
    host.docker.run(BLUE, running=False)
    host.deploy(BLUE)
    assert host.renew() == []
    host.advance(300)
    assert host.renew() == [missing(1, "client=absent")]
    host.docker.run(BLUE)
    host.docker.run(GREEN, project="cnesdata-green")
    host.advance(300)
    assert host.renew() == [missing(1, "client=unobservable")]
    assert host.released()


def test_docker_failure_during_proof_is_a_finding_and_releases_the_lease(
    host, monkeypatch
):
    host.docker.run(BLUE)
    host.deploy(BLUE)
    assert host.renew() == []
    original = host.docker.__call__

    def broken(argv, guard, **kwargs):
        if argv[:2] == ["/usr/bin/docker", "logs"]:
            raise ValueError("fixed process failed")
        return original(argv, guard, **kwargs)

    monkeypatch.setattr(host.g, "supervise", broken)
    host.advance(300)
    assert host.renew() == [missing(1, "client=unobservable")]
    assert host.released()


@pytest.mark.parametrize(
    "failure", [ValueError("fixed process failed"), OSError("exec"), "lifetime"]
)
def test_helper_failure_is_a_finding_and_releases_the_lease(host, failure):
    assert host.renew() == []
    before = host.path().read_bytes()
    host.advance(1800)
    if failure == "lifetime":
        host.docker.lifetime = 900
    else:
        host.docker.failure = failure
    assert host.renew() == ["credential_publication=failed generation=2"]
    assert host.path().read_bytes() == before and host.released()
    assert host.state()["generation"] == 1 and host.checkpoint()["publication_sha256"] is None
    host.docker.failure, host.docker.lifetime = None, 3600
    host.advance(300)
    assert host.renew() == []
    assert host.document()["AccessKeyId"] == key(host.docker.issued)


def test_lost_authority_is_never_converted_into_a_finding(host):
    def lose(guard):
        host.advance(400)
        guard()

    host.docker.on_helper = lose
    with pytest.raises(ValueError):
        host.renew()
    assert host.lease.snapshot()["lease"]["state"] == "HELD"
    assert not host.path().exists()


@pytest.mark.parametrize("days,code", [(6, "expiring"), (0, "expired")])
def test_crl_trust_deadline_alerts_seven_days_ahead(host, days, code):
    deadline = host.g.utc(START + days * DAY)
    host.governance["credentials"]["trust_deadline"] = deadline
    assert host.renew() == [f"credential_trust={code} trust_deadline={deadline}"]
    assert host.document()["AccessKeyId"] == key(1) and host.released()


def test_credential_checkpoint_chain_admits_the_next_deploy(host):
    g = host.g
    host.docker.run(BLUE)
    accepted = host.deploy(BLUE)
    assert host.renew() == []
    prior = host.lease.snapshot()["lease"]
    assert host.checkpoint()["accepted_record_sha256"] == accepted
    following = copy.deepcopy(host.binding)
    following["previous_accepted_sha256"] = accepted
    assert g.prior_terminal(prior, following, API(host.binding))
    following["previous_accepted_sha256"] = None
    with pytest.raises(ValueError, match="previous accepted"):
        g.prior_terminal(prior, following, API(host.binding))


def test_publication_checkpoint_is_closed_and_digest_bound(host):
    g = host.g
    assert host.renew() == []
    prior = host.lease.snapshot()["lease"]
    path = host.lease.root / "checkpoints" / (prior["checkpoint_sha256"] + ".json")
    raw = path.read_bytes()
    assert g.prior_owner_terminal(host.lease.root, prior, None) is None
    for change in (
        {"readiness_sha256": H},
        {"application": "limnopulse"},
        {"kind": "credential-adoption"},
        {"publication_sha256": "not-a-digest"},
        {"quiescent": False},
    ):
        value = json.loads(raw) | change
        tampered = g.canonical(value)
        name = hashlib.sha256(tampered).hexdigest()
        (path.parent / (name + ".json")).write_bytes(tampered)
        with pytest.raises(ValueError):
            g.prior_owner_terminal(
                host.lease.root, prior | {"checkpoint_sha256": name}, None
            )
    path.write_bytes(raw + b" ")
    with pytest.raises(ValueError, match="digest"):
        g.prior_owner_terminal(host.lease.root, prior, None)


def test_adoption_events_follow_the_frozen_contract_regex():
    g = runtime()
    good = line(refreshed(3, 2, pid=4242))
    assert g.adoption_events(good + b"\n" + b"not json\n" + line(refreshed(4))) == [
        (fp(3), fp(2)),
        (fp(4), "none"),
    ]
    assert g.ADOPTION_EVENT.pattern == (
        r"aws_credentials_refreshed key_fp=([0-9a-f]{12}) "
        r"previous_fp=([0-9a-f]{12}|none) pid=([0-9]+)"
    )


def test_findings_exit_2_with_key_value_lines_and_exceptions_stay_generic(
    monkeypatch, capsys
):
    g = runtime()
    saved = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGALRM)}
    monkeypatch.setattr(sys, "argv", ["host_gate.py", "--credential-reload"])
    monkeypatch.setattr(g, "load_credential_governance", lambda: {"credentials": {}})

    def deploy_loader():
        raise AssertionError("--credential-reload never reads the deploy binding")

    monkeypatch.setattr(g, "load_governance", deploy_loader)
    try:
        for result, code in (([missing(3)], 2), ([], 0), (None, 0)):
            monkeypatch.setattr(g, "renew_application_credentials", lambda _, r=result: r)
            assert g.main() == code
            assert capsys.readouterr().err == "".join(f + "\n" for f in result or [])

        def secret(_):
            raise ValueError("secret-bearing " + key(1))

        monkeypatch.setattr(g, "renew_application_credentials", secret)
        assert g.main() == 2
        err = capsys.readouterr().err
        assert key(1) not in err and "recovery_required" in err
    finally:
        for signum, handler in saved.items():
            signal.signal(signum, handler)


@pytest.mark.parametrize("damage", ["state", "directory", "record"])
def test_cnesdata_integrity_faults_fail_before_taking_the_host_lease(host, damage):
    assert host.renew() == []
    released = host.lease.snapshot()
    if damage == "state":
        (host.root / "cnesdata" / "state.json").write_bytes(b"{}")
    elif damage == "directory":
        os.chmod(host.root / "cnesdata" / "current", 0o750)
    else:
        record = host.root / "cnesdata" / "generations"
        [path] = list(record.iterdir())
        path.write_bytes(path.read_bytes() + b" ")
    host.advance(300)
    calls = len(host.docker.calls)
    with pytest.raises(ValueError):
        host.renew()
    # Deploys and LimnoPulse keep the released host-wide lease.
    assert host.lease.snapshot() == released and len(host.docker.calls) == calls


def test_container_recreated_outside_a_deploy_before_publication_is_replaced(host):
    host.docker.run(BLUE)
    host.deploy(BLUE)
    assert host.renew() == []
    host.advance(60)
    host.docker.log(BLUE, line(refreshed(1)))
    host.advance(240)
    assert host.renew() == [] and host.state()["baseline"]["id"] == BLUE
    host.advance(1000)
    host.docker.containers[BLUE]["running"] = False
    host.docker.run(GREEN, project="cnesdata-green")
    host.docker.log(GREEN, line(refreshed(1)))
    host.advance(500)
    assert host.renew() == []
    assert host.record()["container"]["id"] == GREEN
    host.advance(960)
    host.docker.log(GREEN, line(refreshed(2, 1)))
    host.advance(60)
    assert host.renew() == [
        f"credential_adoption=container_replaced generation=2 key_fp={fp(2)}"
    ]


def adopted_on(host, container):
    """First generation published and adopted on the given running container."""
    assert host.renew() == []
    host.advance(60)
    host.docker.log(container, line(refreshed(1)))
    host.advance(240)
    assert host.renew() == [] and host.state()["baseline"]["id"] == container


def test_deployed_container_seen_at_publication_keeps_the_normal_proof(host):
    host.docker.run(BLUE)
    first = host.deploy(BLUE)
    adopted_on(host, BLUE)
    host.advance(1000)
    host.docker.containers[BLUE]["running"] = False
    host.docker.run(GREEN, project="cnesdata-green")
    host.deploy(GREEN, previous=first)
    host.docker.log(GREEN, line(refreshed(1)))
    host.advance(500)
    assert host.renew() == [] and host.record()["container"]["id"] == GREEN
    host.advance(960)
    host.docker.log(GREEN, line(refreshed(2, 1)))
    host.advance(60)
    assert host.renew() == []
    assert host.state()["baseline"] == host.docker.identity(GREEN)


def test_undeployed_container_is_replaced_even_before_the_first_adoption(host):
    host.docker.run(BLUE, running=False)
    host.deploy(BLUE)
    host.docker.run(GREEN, project="cnesdata-green")
    assert host.renew() == [] and host.record()["container"]["id"] == GREEN
    host.advance(60)
    host.docker.log(GREEN, line(refreshed(1)))
    host.advance(240)
    assert host.renew() == [
        f"credential_adoption=container_replaced generation=1 key_fp={fp(1)}"
    ]
    assert host.state()["baseline"] is None


def test_rolled_back_deploy_keeps_the_serving_release_container(host):
    host.docker.run(BLUE)
    first = host.deploy(BLUE)
    adopted_on(host, BLUE)
    host.advance(1000)
    host.docker.containers[BLUE]["running"] = False
    host.docker.run(GREEN, project="cnesdata-green")
    second = host.deploy(GREEN, previous=first)
    host.docker.log(GREEN, line(refreshed(1)))
    host.advance(500)
    assert host.renew() == [] and host.record()["container"]["id"] == GREEN
    # A later deploy starts its candidate, fails and restores nginx: GREEN serves.
    host.docker.run(OTHER, project="cnesdata-blue", running=False)
    host.deploy(OTHER, previous=second, rolled_back=True)
    host.advance(960)
    host.docker.log(GREEN, line(refreshed(2, 1)))
    host.advance(60)
    assert host.renew() == []
    assert host.state()["baseline"] == host.docker.identity(GREEN)


def test_reboot_after_a_rollback_adopts_on_the_restored_release(host):
    host.docker.run(BLUE)
    first = host.deploy(BLUE)
    host.docker.run(OTHER, project="cnesdata-green", running=False)
    host.deploy(OTHER, previous=first, rolled_back=True)
    adopted_on(host, BLUE)


# --- D4a (#30): credentials-only governance for --credential-reload ---------
# The renewer reads only `credentials`; deploy (--host) and runner keep the
# complete binding. Synthetic values only; root and RA reads are bypassed by
# reason, exactly like the Host fixture above.


class _Instant:
    t = START


class _ReachedArtifact(Exception):
    pass


def credential_only_governance(g):
    return {
        "enabled": True,
        "runtime_sha256": g.sha(Path(g.__file__).read_bytes()),
        **governance(g, _Instant()),
    }


def full_governance(g):
    from test_personal_platform_dispatcher import closed_ready_fixture as fixture

    return {**credential_only_governance(g), **copy.deepcopy(fixture()[2])}


def private_file(tmp_path, value):
    path = tmp_path / "host-gate.json"
    path.write_bytes(json.dumps(value).encode())
    path.chmod(0o600)
    return path


@pytest.fixture
def root_loader(monkeypatch):
    g = runtime()
    require, read = g.require, g.read_private
    monkeypatch.setattr(
        g,
        "require",
        lambda c, r: require(True if r == "root boundary required" else c, r),
    )
    monkeypatch.setattr(
        g,
        "read_private",
        lambda p, *a, **kw: (
            b"certificate"
            if str(p).startswith("/etc/personal-platform/ra/")
            else read(p, *a, **kw)
        ),
    )
    return g


def test_credential_reload_loads_credentials_only_governance_without_binding(
    root_loader, tmp_path, monkeypatch
):
    g = root_loader
    value = credential_only_governance(g)

    def binding_read(_):
        raise AssertionError("credential governance never validates a binding")

    monkeypatch.setattr(g, "validate_binding", binding_read)
    loaded = g.load_credential_governance(private_file(tmp_path, value))
    # Only the closed credentials reach the renewer; nothing else is forwarded.
    assert loaded == {"credentials": value["credentials"]}


def test_deploy_and_runner_refuse_credentials_only_governance(root_loader, tmp_path):
    g = root_loader
    value = credential_only_governance(g)
    with pytest.raises(KeyError, match="binding"):
        g.load_governance(private_file(tmp_path, value))
    with pytest.raises(KeyError, match="binding"):
        g.runner_request(value, bytearray(b"synthetic-token"))


def test_complete_governance_is_still_accepted_by_reload_deploy_and_runner(
    root_loader, tmp_path, monkeypatch
):
    g = root_loader
    value = full_governance(g)
    path = private_file(tmp_path, value)
    assert g.load_credential_governance(path) == {
        "credentials": value["credentials"]
    }
    assert g.load_governance(path)["binding"] == value["binding"]

    class StopAtArtifact:
        def __init__(self, token):
            self.token = token

        def read(self, *_a, **_kw):
            raise _ReachedArtifact

    # The runner validated the binding and both pins before its first API read.
    monkeypatch.setattr(g, "GitHub", StopAtArtifact)
    approval = value["binding"]["approval"]["governance_sha256"]
    value["source_files"][0]["sha256"] = approval
    value["envelope"] = {"synthetic": "runner-only governance field"}
    with pytest.raises(_ReachedArtifact):
        g.runner_request(value, bytearray(b"synthetic-token"))


def _wrong_pin(v):
    v["runtime_sha256"] = "0" * 64


def _disabled(v):
    v["enabled"] = False


def _enabled_absent(v):
    del v["enabled"]


def _enabled_truthy(v):
    v["enabled"] = 1


def _pin_absent(v):
    del v["runtime_sha256"]


def _credentials_absent(v):
    del v["credentials"]


def _credentials_extra(v):
    v["credentials"]["container_id"] = "a" * 12


def _credentials_missing(v):
    del v["credentials"]["trust_deadline"]


def _legacy_application(v):
    v["credentials"]["application"] = "limnopulse"


def _foreign_identity(v):
    v["credentials"]["private_key"] = "/etc/personal-platform/ra/limnopulse/private-key.pem"


def _short_session(v):
    v["credentials"]["duration_seconds"] = 900


@pytest.mark.parametrize(
    ("mutation", "error", "reason"),
    [
        (_wrong_pin, ValueError, "installed runtime pin"),
        (_disabled, ValueError, "host delivery disabled"),
        (_enabled_absent, ValueError, "host delivery disabled"),
        (_enabled_truthy, ValueError, "host delivery disabled"),
        (_pin_absent, ValueError, "installed runtime pin"),
        (_credentials_absent, KeyError, "credentials"),
        (_credentials_extra, ValueError, "closed object fields"),
        (_credentials_missing, ValueError, "closed object fields"),
        (_legacy_application, ValueError, "RA application/lifetime"),
        (_foreign_identity, ValueError, "isolated RA identity"),
        (_short_session, ValueError, "RA application/lifetime"),
    ],
)
def test_credential_governance_refuses_pin_enablement_and_inexact_credentials(
    root_loader, tmp_path, mutation, error, reason
):
    g = root_loader
    value = credential_only_governance(g)
    mutation(value)
    with pytest.raises(error, match=reason):
        g.load_credential_governance(private_file(tmp_path, value))


@pytest.mark.skipif(os.geteuid() == 0, reason="the root refusal needs a non-root uid")
def test_credential_governance_requires_root(tmp_path):
    g = runtime()
    path = private_file(tmp_path, credential_only_governance(g))
    with pytest.raises(ValueError, match="root boundary required"):
        g.load_credential_governance(path)


def test_credential_governance_requires_a_private_file(root_loader, tmp_path):
    g = root_loader
    path = private_file(tmp_path, credential_only_governance(g))
    path.chmod(0o640)
    with pytest.raises(ValueError, match="insecure file"):
        g.load_credential_governance(path)
