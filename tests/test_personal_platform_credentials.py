"""Credential isolation and actual process-group supervision, no AWS access."""

import io
import json
import os
import sys
import time
import urllib.error

import pytest
from test_personal_platform_dispatcher import runtime


PROBE_PATH = "/run/personal-platform/probes/API.credentials"
PROBE_URL = "https://cnesdata-prod-probe.s3.us-east-2.amazonaws.com/cnesdata/probe/missing.json"


def test_runtime_probe_set_is_exactly_the_api_identity():
    g = runtime()
    assert g.RUNTIME_IDENTITIES == ("API",)
    assert g.runtime_probe_set({"API": {}}) == {"API": {}}
    for probes in ({"API": {}, "unit": {}}, {"API": {}, "recovery": {}}, {},
                   {"unit": {}, "recovery": {}, "API": {}}):
        with pytest.raises(ValueError, match="exactly the API runtime identity"):
            g.runtime_probe_set(probes)


def api_probe_case(monkeypatch, tmp_path, status, code):
    g = runtime()
    carrier = tmp_path / "API.credentials"
    carrier.write_text("[default]\naws_access_key_id = ASIAFIXTURE\n"
                       "aws_secret_access_key = secret\naws_session_token = token\n")
    carrier.chmod(0o600)
    read, calls = g.read_private, []
    monkeypatch.setattr(g, "read_private", lambda path, maximum=g.LIMIT: read(
        carrier if str(path) == PROBE_PATH else path, maximum))

    def supervise(argv, guard, *, timeout=20, env=None, stdin=None):
        calls.append((argv, env["AWS_SHARED_CREDENTIALS_FILE"]))
        return json.dumps({"Arn": "arn:aws:sts::111122223333:assumed-role/cnesdata-prod-api/api-session"})

    class Opener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            raise urllib.error.HTTPError(request.full_url, status, code, {},
                                         io.BytesIO(f"<Error><Code>{code}</Code></Error>".encode()))

    monkeypatch.setattr(g, "supervise", supervise)
    monkeypatch.setattr(g.urllib.request, "build_opener", lambda *_: Opener())
    probe = {"role_arn": "arn:aws:iam::111122223333:role/cnesdata-prod-api", "credential_path": PROBE_PATH,
             "expires_at": g.utc(time.time() + 3600), "bucket": "cnesdata-prod-probe",
             "key": "cnesdata/probe/missing.json"}
    return g, {"region": "us-east-2", "runtime_probes": {"API": probe}}, calls


def test_real_api_probe_uses_the_original_session_and_accepts_only_no_such_key(monkeypatch, tmp_path):
    g, governance, calls = api_probe_case(monkeypatch, tmp_path, 404, "NoSuchKey")
    g.verify_runtime_probes(governance, lambda: None)
    assert calls == [(["/usr/bin/aws", "sts", "get-caller-identity", "--output", "json"], PROBE_PATH), PROBE_URL]


def test_real_api_probe_refuses_access_denied_as_absence(monkeypatch, tmp_path):
    g, governance, calls = api_probe_case(monkeypatch, tmp_path, 403, "AccessDenied")
    with pytest.raises(ValueError, match="typed missing-object result"):
        g.verify_runtime_probes(governance, lambda: None)
    assert calls[-1] == PROBE_URL


def test_credentials_only_own_run_directory_and_erased_on_failure(tmp_path):
    g = runtime()
    with (
        pytest.raises(RuntimeError),
        g.credential_directory(tmp_path, "cnesdata") as path,
    ):
        g.write_credentials(
            path,
            {
                "AccessKeyId": "ASIAFIXTURE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": "2030-01-01T00:00:00Z",
            },
            now=1893453000,
        )
        assert (path / "credentials").stat().st_mode & 0o777 == 0o400
        assert "secret" in (path / "credentials").read_text()
        raise RuntimeError("fixture failure")
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(ValueError), g.credential_directory(tmp_path, "../limnopulse"):
        pass


def test_expired_or_static_credentials_are_refused(tmp_path):
    g = runtime()
    for key, expiry in [
        ("AKIASTATIC", "2030-01-01T00:00:00Z"),
        ("ASIAFIXTURE", "1970-01-01T00:01:00Z"),
    ]:
        with (
            g.credential_directory(tmp_path, "cnesdata") as path,
            pytest.raises(ValueError),
        ):
            g.write_credentials(
                path,
                {
                    "AccessKeyId": key,
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                    "Expiration": expiry,
                },
                now=1000,
            )


def test_process_group_is_dead_after_guard_failure(tmp_path):
    g = runtime()
    marker = tmp_path / "started"
    start = time.monotonic()

    def guard():
        if marker.exists():
            raise ValueError("fixture owner lost")

    with pytest.raises(ValueError, match="owner lost"):
        g.supervise(
            [
                sys.executable,
                "-c",
                "import time,pathlib; pathlib.Path("
                + repr(str(marker))
                + ").write_text('yes'); time.sleep(60)",
            ],
            guard,
            timeout=20,
            env={"PATH": os.environ["PATH"]},
        )
    assert time.monotonic() - start < 16


def test_no_renewal_future_credit_after_ambiguous_readback(tmp_path, monkeypatch):
    from test_personal_platform_deployer import operation

    g, clock, op = operation(tmp_path)
    window = g.Window(clock, close_confirmed_at=1000, fixed_seconds=1800, input_deadlines=[4600])
    watchdog = g.Watchdog(op, window)
    clock.advance(60)

    def ambiguous(*args):
        raise OSError("ambiguous renewal")

    monkeypatch.setattr(op.lease, "renew", ambiguous)
    with pytest.raises(OSError):
        watchdog.tick()
    with pytest.raises(ValueError, match="renewal"):
        watchdog.tick()
    assert op.snapshot["lease"]["expires_at"] == g.utc(1300)


def test_native_host_role_has_exact_read_only_capability():
    import json

    from fixtures.cnesdata_delivery_oidc_native import Native
    from test_cnesdata_delivery_oidc import render, variables

    native = Native()
    try:
        data = variables()
        data["host_gate"] = {
            "workflow_sha": "c" * 40,
            "objects": [
                {
                    "arn": "arn:aws:s3:::synthetic-evidence/cnesdata/platform.json",
                    "version": "exact-version",
                }
            ],
            "ssm_parameter_arns": [
                "arn:aws:ssm:us-east-2:111122223333:parameter/cnesdata/deploy/" + name
                for name in (
                    "ssh-key",
                    "cloudflare-client-id",
                    "cloudflare-client-secret",
                )
            ],
            "ssm_key_arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000003",
            "decrypt_keys": [
                {
                    "arn": "arn:aws:kms:us-east-2:111122223333:key/00000000-0000-4000-8000-000000000002",
                    "object_arns": [
                        "arn:aws:s3:::synthetic-evidence/cnesdata/platform.json"
                    ],
                }
            ],
        }
        resources, _ = render(native, data, "host-exact")
        role = resources["aws_iam_role.host_gate[0]"]
        trust = json.loads(role["assume_role_policy"])["Statement"][0]
        assert trust["Condition"]["StringEquals"] == {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
            "token.actions.githubusercontent.com:sub": "repo:VINIClUS/CnesData:ref:refs/heads/main",
            "token.actions.githubusercontent.com:job_workflow_ref": (
                "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-host-deploy-gate.yml@"
                + "c" * 40
            ),
        }
        statements = json.loads(
            resources["aws_iam_role_policy.host_gate[0]"]["policy"]
        )["Statement"]
        allows = [s for s in statements if s["Effect"] == "Allow"]
        assert {a for s in allows for a in s["Action"]} == {
            "s3:GetObjectVersion",
            "ssm:GetParameter",
            "kms:Decrypt",
        }
        obj = next(s for s in allows if s["Action"] == ["s3:GetObjectVersion"])
        assert obj["Condition"] == {"StringEquals": {"s3:VersionId": "exact-version"}}
        assert (
            obj["Resource"] == "arn:aws:s3:::synthetic-evidence/cnesdata/platform.json"
        )
        for change in ("cross-tenant", "wildcard-version", "mutable-pin"):
            import copy

            bad = copy.deepcopy(data)
            if change == "cross-tenant":
                bad["host_gate"]["ssm_parameter_arns"][0] = (
                    "arn:aws:ssm:us-east-2:111122223333:parameter/limnopulse/deploy/ssh-key"
                )
            elif change == "wildcard-version":
                bad["host_gate"]["objects"][0]["version"] = "*"
            else:
                bad["host_gate"]["workflow_sha"] = "main"
            code, _, _ = native.plan(bad, "host-" + change)
            assert code != 0
    finally:
        native.temp.cleanup()
