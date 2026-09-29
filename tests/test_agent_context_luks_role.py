import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles/agent_context_luks"
PLAYBOOKS = ("provision", "unlock")
KEY_VARS = ("agent_context_luks_data_key", "agent_context_luks_backup_key")
CONFIRM = "format-new-agent-context-containers"


def load(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def role_tasks() -> dict[str, list[dict]]:
    return {p.name: load(p) for p in sorted((ROLE / "tasks").glob("*.yml"))}


def walk(tasks):
    for task in tasks:
        nested = [key for key in ("block", "rescue", "always") if key in task]
        if not nested:
            yield task
        for key in nested:
            yield from walk(task[key])


def strip_text(node):
    if isinstance(node, dict):
        return {k: strip_text(v) for k, v in node.items() if k not in {"name", "fail_msg", "msg"}}
    if isinstance(node, list):
        return [strip_text(v) for v in node]
    return node


def uses_key(task) -> bool:
    """True when a task evaluates a key variable (error text is not evaluation)."""
    return any(key in yaml.safe_dump(strip_text(task)) for key in KEY_VARS)


def all_tasks():
    for name, tasks in role_tasks().items():
        for task in walk(tasks):
            yield name, task


def test_defaults_disabled_and_sizes_and_keys_have_no_default():
    defaults = load(ROLE / "defaults/main.yml")

    assert defaults["agent_context_luks_enabled"] is False
    assert defaults["agent_context_luks_confirm_provision"] == ""
    for name in (
        "agent_context_luks_data_size",
        "agent_context_luks_backup_size",
        *KEY_VARS,
    ):
        assert name not in defaults
    assert defaults["agent_context_luks_pbkdf_memory"] == 262144
    assert defaults["agent_context_luks_container_dir"] == "/var/lib/agent-context-luks"
    assert defaults["agent_context_luks_backup_mount_opts"] == "nodev,nosuid,noexec"
    assert "nodev,nosuid" == defaults["agent_context_luks_data_mount_opts"]
    assert defaults["agent_context_luks_data_mountpoint"] != defaults["agent_context_luks_backup_mountpoint"]


def test_every_task_touching_a_key_has_no_log_and_no_key_is_persisted():
    seen = 0
    for name, task in all_tasks():
        if uses_key(task):
            seen += 1
            assert task.get("no_log") is True, f"{name}: {task['name']}"
            assert not {"ansible.builtin.copy", "ansible.builtin.template", "ansible.builtin.lineinfile"} & set(task)
            assert "environment" not in task
    assert seen >= 3


def test_keys_travel_only_on_stdin_never_in_argv():
    formats = 0
    for name, task in all_tasks():
        command = task.get("ansible.builtin.command")
        if not command or not uses_key(command):
            continue
        formats += 1
        argv = command["argv"]
        assert "--key-file=-" in argv
        assert not any(key in str(part) for part in argv for key in KEY_VARS)
        assert all(key in command["stdin"] for key in KEY_VARS)
        assert command["stdin_add_newline"] is False
    assert formats == 3


def test_no_persistent_mount_crypttab_or_keyfile():
    text = "\n".join(p.read_text(encoding="utf-8") for p in ROLE.rglob("*.yml"))
    assert "crypttab" not in text
    assert "ansible.builtin.mount" not in text
    for name, task in all_tasks():
        mount = task.get("ansible.posix.mount")
        if mount:
            assert mount["state"] in {"ephemeral", "unmounted"}
        assert "ansible.builtin.lineinfile" not in task
        assert "fstab" not in yaml.safe_dump(task.get("ansible.posix.mount", {}))
    assert "--key-file=/" not in text and "--key-file=" + "{{" not in text
    assert not (ROLE / "templates").exists()


def test_provision_guard_and_never_reformat_logic():
    provision = load(ROLE / "tasks/provision.yml")
    volume = load(ROLE / "tasks/provision_volume.yml")
    text = (ROLE / "tasks/provision.yml").read_text(encoding="utf-8")

    guard = provision[0]["ansible.builtin.assert"]["that"]
    assert guard == f"agent_context_luks_confirm_provision == '{CONFIRM}'"
    assert text.index("confirmation") < text.index("ansible.builtin.package")
    failing = [t for t in provision if "ansible.builtin.fail" in t]
    assert any("stat.exists" in t["when"] for t in failing)
    header = next(t for t in walk(volume) if "isLuks" in yaml.safe_dump(t))
    assert header["failed_when"] == "agent_context_luks_header.rc == 0"
    # No override: nothing can skip the checks or force a format.
    role_text = "\n".join(p.read_text(encoding="utf-8") for p in ROLE.rglob("*.yml"))
    assert not re.search(r"force|overwrite|reformat_", role_text.replace("Never reformats", ""))
    assert (ROLE / "tasks/provision.yml").read_text(encoding="utf-8").count(CONFIRM) == 1


def test_luks2_argon2id_parameters_and_fallocate():
    volume = role_tasks()["provision_volume.yml"]
    fmt = next(t for t in walk(volume) if "luksFormat" in yaml.safe_dump(t))
    argv = fmt["ansible.builtin.command"]["argv"]
    for token in ("luks2", "argon2id", "--pbkdf-memory", "--batch-mode", "--type", "--pbkdf"):
        assert token in argv
    assert argv[argv.index("--type") + 1] == "luks2"
    assert argv[argv.index("--pbkdf") + 1] == "argon2id"
    alloc = next(t for t in walk(volume) if "fallocate" in yaml.safe_dump(t))
    assert alloc["ansible.builtin.command"]["argv"][0] == "fallocate"
    mkfs = next(t for t in walk(volume) if "mkfs.ext4" in yaml.safe_dump(t))
    assert "-L" in mkfs["ansible.builtin.command"]["argv"]
    assert "sparse" not in yaml.safe_dump(volume) and "truncate" not in yaml.safe_dump(volume)


def test_preflight_requires_long_distinct_keys_and_both_sizes():
    text = (ROLE / "tasks/preflight.yml").read_text(encoding="utf-8")
    assert ">= 32" in text and "distinct" in text
    assert "agent_context_luks_data_size is defined" in text
    assert "agent_context_luks_backup_size is defined" in text
    tasks = role_tasks()["preflight.yml"]
    check = next(t for t in tasks if "set_fact" in "".join(t) and "key_checks" in yaml.safe_dump(t))
    assert check["no_log"] is True
    others = [t for t in tasks if t is not check]
    assert not any(uses_key(t) for t in others)


@pytest.mark.parametrize("name", PLAYBOOKS)
def test_playbooks_target_only_the_agent_context_group(name):
    plays = load(ROOT / f"playbooks/agent-context-luks-{name}.yml")

    assert [play["hosts"] for play in plays] == ["agent_context_vps"]
    assert [r["role"] for r in plays[0]["roles"]] == ["agent_context_luks"]
    # Without pipelining Ansible writes module args (the key) to a remote temp file.
    assert plays[0]["vars"]["ansible_pipelining"] is True


def test_provision_playbook_cannot_be_switched_to_another_action():
    play = load(ROOT / "playbooks/agent-context-luks-provision.yml")[0]
    assert play["vars"]["agent_context_luks_action"] == "provision"
    unlock = load(ROOT / "playbooks/agent-context-luks-unlock.yml")[0]
    assert unlock["vars"]["agent_context_luks_action"] == "unlock"
    assert "'provision'" not in yaml.safe_dump(unlock["pre_tasks"])


def test_role_never_touches_docker_proxy_or_networking():
    text = "\n".join(p.read_text(encoding="utf-8") for p in ROLE.rglob("*.yml")).lower()
    for word in ("docker", "caddy", "nftables", "iptables", "systemd", "/etc/fstab", "ufw"):
        assert word not in text


def test_playbooks_are_not_deployable_by_push():
    deploy = (ROOT / "tools/deploy/infra_ansible_deploy.py").read_text(encoding="utf-8")
    assert "agent-context-luks" not in deploy
    assert "agent_context_luks" not in deploy
    for workflow in (ROOT / ".github").rglob("*.yml"):
        assert "agent-context-luks" not in workflow.read_text(encoding="utf-8")
    site = (ROOT / "playbooks/site.yml").read_text(encoding="utf-8")
    assert "agent_context_luks" not in site

    import importlib.util

    spec = importlib.util.spec_from_file_location("deploy", ROOT / "tools/deploy/infra_ansible_deploy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    allowed = {run.playbook for run in module._ALLOWED_RUNS}
    assert not any("agent-context-luks" in playbook for playbook in allowed)
    assert not any("agent-context-luks" in run.playbook for run in module.FIXED_RUNS)


def run_playbook(tmp_path, variables, action):
    playbook = tmp_path / "play.yml"
    playbook.write_text(
        f"""---
- hosts: all
  gather_facts: false
  vars:
    agent_context_luks_action: {action}
  tasks:
    - ansible.builtin.import_role:
        name: agent_context_luks
""",
        encoding="utf-8",
    )
    import json

    return subprocess.run(
        ["ansible-playbook", "-i", "vault-less,", "-c", "local", str(playbook), "-e", json.dumps(variables)],
        cwd=ROOT,
        env={**os.environ, "ANSIBLE_ROLES_PATH": str(ROOT / "roles")},
        capture_output=True,
        text=True,
        check=False,
    )


BASE = {
    "agent_context_luks_enabled": True,
    "agent_context_luks_data_size": "20G",
    "agent_context_luks_backup_size": "10G",
    "ansible_facts": {"os_family": "Debian"},
}


def test_disabled_role_changes_nothing(tmp_path):
    result = run_playbook(tmp_path, {"agent_context_luks_enabled": False}, "provision")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "cryptsetup" not in result.stdout


@pytest.mark.parametrize(
    "keys, message",
    [
        ({}, "must both be defined"),
        ({"agent_context_luks_data_key": "a" * 40}, "must both be defined"),
        ({"agent_context_luks_data_key": "short", "agent_context_luks_backup_key": "b" * 40}, "at least 32"),
        ({"agent_context_luks_data_key": "a" * 40, "agent_context_luks_backup_key": "a" * 40}, "differ"),
    ],
)
def test_bad_keys_fail_clearly_without_leaking_them(tmp_path, keys, message):
    result = run_playbook(tmp_path, {**BASE, **keys}, "unlock")
    out = result.stdout + result.stderr

    assert result.returncode != 0
    assert message in out
    assert not any(value in out for value in keys.values() if len(value) > 8)


def test_provision_without_confirmation_fails_before_any_change(tmp_path):
    keys = {"agent_context_luks_data_key": "a" * 40, "agent_context_luks_backup_key": "b" * 40}
    result = run_playbook(tmp_path, {**BASE, **keys}, "provision")

    assert result.returncode != 0
    assert "Refusing to provision" in result.stdout + result.stderr
    assert "Install the LUKS" not in result.stdout


@pytest.mark.skipif(
    os.environ.get("AGENT_CONTEXT_LUKS_DOCKER_TEST") != "1" or shutil.which("docker") is None,
    reason="set AGENT_CONTEXT_LUKS_DOCKER_TEST=1 to run the privileged cryptsetup round trip",
)
def test_cryptsetup_round_trip_in_a_throwaway_container():
    script = r"""
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq cryptsetup-bin e2fsprogs >/dev/null
f=/tmp/rt.luks; k=$(printf 'k%.0s' $(seq 1 40))
fallocate -l 64M "$f"
printf %s "$k" | cryptsetup luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 65536 --batch-mode --key-file=- "$f"
printf %s "$k" | cryptsetup open --type luks2 --key-file=- "$f" rt
mkfs.ext4 -q -L rt /dev/mapper/rt
mkdir -p /mnt/rt && mount -o nodev,nosuid,noexec /dev/mapper/rt /mnt/rt
umount /mnt/rt; cryptsetup close rt
cryptsetup isLuks "$f"
echo ROUNDTRIP_OK
"""
    result = subprocess.run(
        ["timeout", "120", "docker", "run", "--rm", "--privileged", "debian:stable-slim", "bash", "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "ROUNDTRIP_OK" in result.stdout, result.stdout + result.stderr
