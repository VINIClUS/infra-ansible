#!/usr/bin/env python3
"""Authenticate with Infisical and exec Ansible with an allowlist of secrets."""

import argparse
import json
import os
import subprocess
import sys


AUTH_VARIABLES = (
    "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID",
    "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET",
)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--path", action="append", required=True, dest="paths")
    parser.add_argument("--required-key", action="append", required=True, dest="required_keys")
    parser.add_argument("ansible_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.ansible_args and args.ansible_args[0] == "--":
        args.ansible_args = args.ansible_args[1:]
    if not args.ansible_args:
        parser.error("an ansible-playbook command is required after --")
    return args


def run_checked(command, env):
    return subprocess.run(
        command,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main():
    args = parse_args()
    missing_auth = [name for name in AUTH_VARIABLES if not os.environ.get(name)]
    if missing_auth:
        raise RuntimeError(
            "Missing Universal Auth variables: " + ", ".join(missing_auth)
        )

    auth_env = os.environ.copy()
    token = run_checked(
        [
            "infisical",
            "login",
            "--method=universal-auth",
            "--silent",
            "--plain",
            "--domain",
            args.domain,
        ],
        auth_env,
    )
    if not token:
        raise RuntimeError("Infisical Universal Auth returned an empty access token")

    export_env = auth_env.copy()
    export_env["INFISICAL_TOKEN"] = token
    secrets = {}
    for secret_path in args.paths:
        raw = run_checked(
            [
                "infisical",
                "export",
                "--silent",
                "--domain",
                args.domain,
                "--projectId",
                args.project_id,
                "--env",
                args.environment,
                "--path",
                secret_path,
                "--format=json",
            ],
            export_env,
        )
        exported = json.loads(raw)
        if not isinstance(exported, dict):
            raise RuntimeError("Infisical export did not return a JSON object")
        for key, value in exported.items():
            if key in secrets and secrets[key] != value:
                raise RuntimeError(f"Conflicting Infisical value for key: {key}")
            secrets[key] = str(value)

    missing_keys = [key for key in args.required_keys if key not in secrets]
    if missing_keys:
        raise RuntimeError(
            "Missing required Infisical keys: " + ", ".join(missing_keys)
        )

    ansible_env = os.environ.copy()
    for name in (*AUTH_VARIABLES, "INFISICAL_TOKEN"):
        ansible_env.pop(name, None)
    ansible_env["INFISICAL_PROJECT_ID"] = args.project_id
    for key in args.required_keys:
        ansible_env[key] = secrets[key]

    os.execvpe("ansible-playbook", ["ansible-playbook", *args.ansible_args], ansible_env)


if __name__ == "__main__":
    try:
        main()
    except (json.JSONDecodeError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"infisical-ansible: {error}", file=sys.stderr)
        raise SystemExit(1)
