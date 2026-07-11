import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
ENTRYPOINT = REPO_ROOT / "tools" / "ansible" / "infisical_ansible.py"


class InfisicalAnsibleEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.bin_dir = pathlib.Path(self.tempdir.name)
        self.log_path = self.bin_dir / "calls.jsonl"
        self._write_executable(
            "infisical",
            """
            #!/usr/bin/env python3
            import json, os, sys
            with open(os.environ["MOCK_LOG"], "a", encoding="utf-8") as log:
                log.write(json.dumps({"argv": sys.argv[1:], "token": os.getenv("INFISICAL_TOKEN")}) + "\\n")
            if sys.argv[1] == "login":
                print("temporary-access-token")
            elif sys.argv[1] == "export":
                print(os.environ["MOCK_EXPORT"])
            """,
        )
        self._write_executable(
            "ansible-playbook",
            """
            #!/usr/bin/env python3
            import json, os, sys
            with open(os.environ["MOCK_LOG"], "a", encoding="utf-8") as log:
                log.write(json.dumps({"argv": sys.argv[1:], "selected": os.getenv("SELECTED"), "extra": os.getenv("EXTRA"), "client_secret": os.getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"), "token": os.getenv("INFISICAL_TOKEN"), "project_id": os.getenv("INFISICAL_PROJECT_ID")}) + "\\n")
            """,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _write_executable(self, name, content):
        path = self.bin_dir / name
        path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
        path.chmod(0o755)

    def _run(self, required_keys=("SELECTED",), export=None):
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin_dir}{os.pathsep}{env['PATH']}",
                "MOCK_LOG": str(self.log_path),
                "MOCK_EXPORT": json.dumps(export or {"SELECTED": "kept", "EXTRA": "discarded"}),
                "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "identity-id",
                "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "identity-secret",
            }
        )
        args = [
            sys.executable,
            str(ENTRYPOINT),
            "--domain", "https://infisical.example.test",
            "--project-id", "project-id",
            "--environment", "prod",
            "--path", "/infra/minio",
        ]
        for key in required_keys:
            args.extend(["--required-key", key])
        args.extend(["--", "site.yml", "--check"])
        return subprocess.run(args, env=env, capture_output=True, text=True)

    def test_injects_only_required_secrets_and_scrubs_auth(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        self.assertEqual(calls[-1]["selected"], "kept")
        self.assertIsNone(calls[-1]["extra"])
        self.assertIsNone(calls[-1]["client_secret"])
        self.assertIsNone(calls[-1]["token"])
        self.assertEqual(calls[-1]["project_id"], "project-id")
        self.assertEqual(calls[-1]["argv"], ["site.yml", "--check"])

    def test_fails_without_required_secret_and_does_not_run_ansible(self):
        result = self._run(required_keys=("MISSING",), export={"SELECTED": "value"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing required Infisical keys: MISSING", result.stderr)
        calls = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
