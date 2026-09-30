import os
import json
import re
import sys
import shutil
import subprocess
import tempfile
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
            raise AssertionError("no module may write mount state")
        assert "ansible.builtin.lineinfile" not in task
        assert "fstab" not in yaml.safe_dump(task.get("ansible.posix.mount", {}))
    mount = next(t for _, t in all_tasks() if t["name"] == "Mount the volume without any persistent entry")
    assert mount["ansible.builtin.command"]["argv"][:4] == ["mount", "-t", "ext4", "-o"]
    assert "ansible.posix" not in text
    assert "--key-file=/" not in text and "--key-file=" + "{{" not in text
    assert not (ROLE / "templates").exists()


def test_provision_guard_and_never_reformat_logic():
    provision = load(ROLE / "tasks/provision.yml")
    volume = load(ROLE / "tasks/provision_volume.yml")
    text = (ROLE / "tasks/provision.yml").read_text(encoding="utf-8")

    guard = provision[0]["ansible.builtin.assert"]["that"]
    assert guard == f"agent_context_luks_confirm_provision == '{CONFIRM}'"
    assert text.index("confirmation") < text.index("ansible.builtin.package")
    refusal = next(t for t in load(ROLE / "tasks/preflight_volume.yml") if "ansible.builtin.assert" in t)
    assert "not agent_context_luks_existing_container.stat.exists" in refusal["ansible.builtin.assert"]["that"]
    assert "agent_context_luks_identity.luks_uuid == ''" in refusal["ansible.builtin.assert"]["that"]
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


def test_ownership_is_pinned_to_root_on_the_real_group():
    text = (ROLE / "tasks/preflight.yml").read_text(encoding="utf-8")
    guard = next(t for t in load(ROLE / "tasks/preflight.yml") if t["name"].startswith("Require root ownership"))

    assert guard["ansible.builtin.assert"]["that"] == [
        "agent_context_luks_owner == 'root'",
        "agent_context_luks_group == 'root'",
    ]
    assert guard["when"] == "'agent_context_vps' in group_names"
    assert "agent_context_luks_owner: root" in (ROLE / "defaults/main.yml").read_text(encoding="utf-8")
    assert text.count("agent_context_luks_owner") == 1


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


FAKE = r"""#!/usr/bin/env python3
import hashlib, json, os, sys

tool = os.path.basename(sys.argv[0])
args = sys.argv[1:]
state_path = os.environ["FAKE_STATE"]
state = json.load(open(state_path))
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps([tool, *args]) + "\n")
MAGIC = b"LUKS\xba\xbe"


def save():
    json.dump(state, open(state_path, "w"))


def is_luks(path):
    try:
        return open(path, "rb").read(6) == MAGIC
    except OSError:
        return False


def uuid_of(path):
    return "11111111-2222-3333-4444-" + hashlib.md5(path.encode()).hexdigest()[:12]


if tool == "cryptsetup":
    cmd = args[0]
    if cmd == "--version":
        print("cryptsetup 2.7.0")
    elif cmd == "status":
        if os.environ.get("FAKE_STATUS_RC"):
            sys.exit(int(os.environ["FAKE_STATUS_RC"]))
        m = state["mappers"].get(args[1])
        if not m:
            print("/dev/mapper/%s is inactive." % args[1])
            sys.exit(4)
        print("/dev/mapper/%s is active." % args[1])
        print("  type:    LUKS2\n  device:  %s\n  loop:    %s\n  mode:    read/write" % (m["loop"], m["file"]))
    elif cmd == "isLuks":
        if os.environ.get("FAKE_ISLUKS"):
            sys.exit(0)
        if os.environ.get("FAKE_SWAP"):
            os.rename(args[1], args[1] + ".original")
            open(args[1], "wb").write(b"someone else's data")
        sys.exit(0 if is_luks(args[1]) else 1)
    elif cmd in ("luksFormat", "open"):
        key = sys.stdin.read()
        if "--key-file=-" not in args or len(key) < 32:
            sys.exit(2)
        target = args[-1] if cmd == "luksFormat" else args[-2]
        if cmd == "luksFormat":
            if os.environ.get("FAKE_FAIL_FORMAT"):
                sys.exit(1)
            with open(target, "r+b") as f:
                f.write(MAGIC)
        else:
            if not is_luks(target):
                sys.exit(1)
            state["mappers"][args[-1]] = {"file": os.path.realpath(target), "loop": "/dev/loop%d" % (7 + len(state["mappers"]))}
            save()
    elif cmd == "close":
        if os.environ.get("FAKE_FAIL_CLOSE"):
            sys.exit(5)
        if args[1] not in state["mappers"]:
            sys.exit(4)
        del state["mappers"][args[1]]
        save()
elif tool == "losetup":
    target = os.path.realpath(args[1])
    for m in state["mappers"].values():
        if m["file"] == target:
            print("%s: [0042]:7 (%s)" % (m["loop"], target))
elif tool == "blkid":
    path = args[-1]
    if not is_luks(path):
        sys.exit(2)
    print("DEVNAME=" + path)
    print("UUID=" + uuid_of(path))
    print("TYPE=" + os.environ.get("FAKE_BLKID_TYPE", "crypto_LUKS"))
elif tool == "findmnt":
    m = state["mounts"].get(args[args.index("-M") + 1])
    if not m:
        sys.exit(1)
    entries = m if isinstance(m, list) else [m]
    if "-R" in args:  # only a recursive findmnt reports submounts and children
        flat = [{k: v for k, v in entries[0].items() if k != "submounts"}]
        print(json.dumps({"filesystems": flat + entries[1:] + entries[0].get("submounts", [])}))
    else:
        print(json.dumps({"filesystems": [{k: v for k, v in entries[0].items() if k not in ("submounts", "children")}]}))
elif tool == "mount":
    if os.environ.get("FAKE_FAIL_MOUNT"):
        sys.exit(32)
    opts, src, dst = args[args.index("-o") + 1], args[-2], args[-1]
    drop = os.environ.get("FAKE_MOUNT_DROP")
    if drop:
        opts = ",".join(o for o in opts.split(",") if o != drop)
    state["mounts"][dst] = {"source": src, "fstype": "ext4", "options": opts + ",rw,relatime"}
    save()
elif tool == "umount":
    if args[0] not in state["mounts"]:
        sys.exit(32)
    del state["mounts"][args[0]]
    save()
elif tool == "mkfs.ext4":
    if os.environ.get("FAKE_FAIL_MKFS"):
        sys.exit(1)
else:
    sys.exit(127)
"""

KEYS = {"agent_context_luks_data_key": "d" * 40, "agent_context_luks_backup_key": "b" * 40}
CONFIRMED = {"agent_context_luks_confirm_provision": CONFIRM}


class Lab:
    """A throwaway root: fake tools on PATH, temp paths, state kept in JSON."""

    def __init__(self, tmp_path: Path):
        self.root = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        fake = self.bin / "fake.py"
        fake.write_text(FAKE, encoding="utf-8")
        for tool in ("cryptsetup", "losetup", "blkid", "findmnt", "mount", "umount", "mkfs.ext4"):
            (self.bin / tool).symlink_to(fake)
        fake.chmod(0o755)
        self.state_path = tmp_path / "state.json"
        self.log = tmp_path / "calls.log"
        self.log.touch()
        self.state = {"mappers": {}, "mounts": {}}
        self.containers = tmp_path / "containers"
        self.srv = Path(tempfile.mkdtemp(dir="/var/tmp", prefix="acl-test-")) / "srv"
        self.data = self.srv / "agent-context"
        self.backup = self.srv / "backups" / "agent-context"
        self.extra_env = {}
        self.write_state()

    def write_state(self):
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")

    def read_state(self):
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def calls(self):
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def variables(self, **extra):
        import getpass
        import grp

        return {
            "agent_context_luks_enabled": True,
            "agent_context_luks_data_size": "1M",
            "agent_context_luks_backup_size": "1M",
            "agent_context_luks_free_space_margin": "1M",
            "agent_context_luks_pbkdf_memory": 65536,
            "agent_context_luks_owner": getpass.getuser(),
            "agent_context_luks_group": grp.getgrgid(os.getgid()).gr_name,
            "agent_context_luks_container_dir": str(self.containers),
            "agent_context_luks_mount_root": str(self.srv),
            "agent_context_luks_data_mountpoint": str(self.data),
            "agent_context_luks_backup_mountpoint": str(self.backup),
            "ansible_facts": {"os_family": "Debian"},
            "ansible_python_interpreter": sys.executable,
            **extra,
        }

    def run(self, action, check=False, **extra):
        self.write_state()
        playbook = self.root / "play.yml"
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
        command = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)]
        command += ["-e", json.dumps(self.variables(**extra))]
        if check:
            command.append("--check")
        env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "ANSIBLE_ROLES_PATH": str(ROOT / "roles"),
            "ANSIBLE_LOCAL_TEMP": str(self.root / "ans-local"),
            "ANSIBLE_REMOTE_TEMP": str(self.root / "ans-remote"),
            "ANSIBLE_PIPELINING": "1",
            "ANSIBLE_HOME": str(self.root / "ans-home"),
            "FAKE_STATE": str(self.state_path),
            "FAKE_LOG": str(self.log),
            **self.extra_env,
        }
        return subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, check=False)

    def provision(self, **extra):
        return self.run("provision", **{**KEYS, **CONFIRMED, **extra})

    def unlock(self, **extra):
        return self.run("unlock", **{**KEYS, **extra})

    def make_volume(self, name, mounted=True, opts="nodev,nosuid,rw,relatime"):
        """Bring a volume to the state a successful provision + unlock leaves."""
        file = self.containers / f"{name}.luks"
        file.parent.mkdir(exist_ok=True)
        file.write_bytes(b"LUKS\xba\xbe" + b"\0" * 1024)
        mapper = f"agent_context_{name}"
        self.state["mappers"][mapper] = {"file": os.path.realpath(file), "loop": "/dev/loop9"}
        mountpoint = self.data if name == "data" else self.backup
        mountpoint.mkdir(parents=True, exist_ok=True)
        if mounted:
            self.state["mounts"][str(mountpoint)] = {
                "source": f"/dev/mapper/{mapper}",
                "fstype": "ext4",
                "options": opts,
            }
        return file

    def tool_calls(self, tool, first=None):
        return [c for c in self.calls() if c[0] == tool and (first is None or c[1] == first)]


def out(result):
    return result.stdout + result.stderr


@pytest.fixture
def lab(tmp_path):
    lab = Lab(tmp_path)
    yield lab
    shutil.rmtree(lab.srv.parent, ignore_errors=True)


def test_disabled_role_changes_nothing(lab):
    result = lab.run("provision", agent_context_luks_enabled=False)

    assert result.returncode == 0, out(result)
    assert lab.calls() == []


@pytest.mark.parametrize(
    "keys, message",
    [
        ({}, "must both be defined"),
        ({"agent_context_luks_data_key": "a" * 40}, "must both be defined"),
        ({"agent_context_luks_data_key": "short", "agent_context_luks_backup_key": "b" * 40}, "at least 32"),
        ({"agent_context_luks_data_key": "a" * 40, "agent_context_luks_backup_key": "a" * 40}, "differ"),
        ({"agent_context_luks_data_key": 10**39, "agent_context_luks_backup_key": "1" + "0" * 39}, "be strings"),
        ({"agent_context_luks_data_key": 10**39, "agent_context_luks_backup_key": "b" * 40}, "be strings"),
        ({"agent_context_luks_data_key": "a" * 40, "agent_context_luks_backup_key": True}, "be strings"),
        ({"agent_context_luks_data_key": " " + "a" * 40, "agent_context_luks_backup_key": "b" * 40}, "whitespace"),
        ({"agent_context_luks_data_key": "a" * 40, "agent_context_luks_backup_key": "b" * 40 + "\n"}, "whitespace"),
    ],
)
def test_bad_keys_fail_clearly_without_leaking_them(lab, keys, message):
    result = lab.run("unlock", **keys)

    assert result.returncode != 0
    assert message in out(result)
    assert not any(value in out(result) for value in map(str, keys.values()) if len(value) > 8)
    assert lab.calls() == []


def test_provision_without_confirmation_fails_before_any_change(lab):
    result = lab.run("provision", **KEYS)

    assert result.returncode != 0
    assert "Refusing to provision" in out(result)
    assert lab.calls() == []
    assert not lab.containers.exists()


@pytest.mark.parametrize("action", ["provision", "unlock", "close"])
def test_check_mode_is_refused_accurately_for_every_action(lab, action):
    result = lab.run(action, check=True, **KEYS, **CONFIRMED)

    assert result.returncode != 0
    assert "does not support --check" in out(result)
    assert lab.calls() == []


def test_disabled_role_is_still_a_no_op_under_check_mode(lab):
    result = lab.run("provision", check=True, agent_context_luks_enabled=False)

    assert result.returncode == 0, out(result)


def test_provision_creates_both_volumes_with_stdin_keys_and_no_leaks(lab):
    result = lab.provision()

    assert result.returncode == 0, out(result)
    for name in ("data", "backup"):
        file = lab.containers / f"{name}.luks"
        assert file.stat().st_size == 1024 * 1024
        assert oct(file.stat().st_mode & 0o777) == "0o600"
    assert oct(lab.containers.stat().st_mode & 0o777) == "0o700"
    formats = lab.tool_calls("cryptsetup", "luksFormat")
    assert len(formats) == 2
    for call in formats:
        assert {"luks2", "argon2id", "--batch-mode", "--key-file=-"} <= set(call)
    assert not any("d" * 40 in line or "b" * 40 in line for line in lab.log.read_text().splitlines())
    assert "d" * 40 not in out(result)
    assert lab.read_state()["mappers"] == {}
    assert lab.read_state()["mounts"] == {}
    assert lab.data.parent.is_dir() and lab.backup.parent.is_dir()


def test_provision_refuses_an_existing_container_file(lab):
    lab.containers.mkdir()
    existing = lab.containers / "data.luks"
    existing.write_bytes(b"precious")

    result = lab.provision()

    assert result.returncode != 0
    assert "never reformats" in out(result)
    assert existing.read_bytes() == b"precious"
    assert lab.tool_calls("cryptsetup", "luksFormat") == []


def test_provision_refuses_an_existing_luks_header(lab):
    file = lab.make_volume("backup", mounted=False)
    lab.state["mappers"].clear()
    header_before = file.read_bytes()

    result = lab.provision()

    assert result.returncode != 0
    assert "never reformats" in out(result)
    assert file.read_bytes() == header_before
    assert lab.tool_calls("cryptsetup", "luksFormat") == []
    assert not (lab.containers / "data.luks").exists()


def test_exclusive_create_never_touches_a_file_that_appears_late(lab):
    """The shell create is O_EXCL: it fails on an existing file even if the preflight was raced."""
    lab.containers.mkdir()
    target = lab.containers / "x.luks"
    target.write_bytes(b"keep")
    task = next(t for _, t in all_tasks() if t["name"] == "Create the container file exclusively")
    argv = task["ansible.builtin.command"]["argv"]
    argv = [str(target) if part.startswith("{{") else part for part in argv]

    result = subprocess.run(argv, capture_output=True, text=True, check=False)

    assert result.returncode != 0
    assert target.read_bytes() == b"keep"


def test_rescue_removes_the_file_created_in_this_run(lab):
    lab.extra_env["FAKE_FAIL_FORMAT"] = "1"

    result = lab.provision()

    assert result.returncode != 0
    assert "failed" in out(result)
    assert not (lab.containers / "data.luks").exists()
    assert not (lab.containers / "backup.luks").exists()


def test_rescue_never_removes_a_file_that_is_not_the_one_created_in_this_run(lab):
    lab.extra_env["FAKE_SWAP"] = "1"

    result = lab.provision()

    assert result.returncode != 0
    assert "not the one created by this run" in out(result)
    assert (lab.containers / "data.luks").read_bytes() == b"someone else's data"
    assert (lab.containers / "data.luks.original").exists()
    assert lab.tool_calls("cryptsetup", "luksFormat") == []


def test_a_luks_header_that_appears_before_formatting_stops_the_run(lab):
    lab.extra_env["FAKE_ISLUKS"] = "1"

    result = lab.provision()

    assert result.returncode != 0
    assert "Refuse a container that already carries a LUKS header" in out(result)
    assert lab.tool_calls("cryptsetup", "luksFormat") == []
    assert not (lab.containers / "data.luks").exists()


def test_rescue_removes_the_file_once_the_mapping_is_confirmed_gone(lab):
    lab.extra_env["FAKE_FAIL_MKFS"] = "1"

    result = lab.provision()

    assert result.returncode != 0
    assert "was removed" in out(result)
    assert not (lab.containers / "data.luks").exists()
    assert ["cryptsetup", "close", "agent_context_data"] in lab.calls()


def test_a_failed_close_keeps_the_container_file(lab):
    lab.extra_env["FAKE_FAIL_MKFS"] = "1"
    lab.extra_env["FAKE_FAIL_CLOSE"] = "1"

    result = lab.provision()

    assert result.returncode != 0
    assert "left in place" in out(result) and "manual recovery" in out(result)
    assert (lab.containers / "data.luks").exists()
    assert "agent_context_data" in lab.read_state()["mappers"]
    assert "d" * 40 not in out(result)


def test_rescue_leaves_a_completed_sibling_volume_alone(lab):
    """The backup volume fails after data succeeded: only backup's new file goes."""
    original = (lab.bin / "fake.py").read_text(encoding="utf-8")
    patched = original.replace(
        'if os.environ.get("FAKE_FAIL_FORMAT"):',
        'if os.environ.get("FAKE_FAIL_FORMAT") or target.endswith("backup.luks"):',
    )
    (lab.bin / "fake.py").write_text(patched, encoding="utf-8")

    result = lab.provision()

    assert result.returncode != 0
    assert (lab.containers / "data.luks").exists()
    assert not (lab.containers / "backup.luks").exists()
    # data was closed after its own format; backup never opened, so nothing else was closed.
    assert lab.tool_calls("cryptsetup", "close") == [["cryptsetup", "close", "agent_context_data"]]


def test_unlock_opens_and_mounts_both_volumes_with_the_configured_options(lab):
    assert lab.provision().returncode == 0
    lab.state = lab.read_state()

    result = lab.unlock()

    assert result.returncode == 0, out(result)
    mounts = lab.read_state()["mounts"]
    assert mounts[str(lab.data)]["options"].startswith("nodev,nosuid,")
    assert "noexec" not in mounts[str(lab.data)]["options"].split(",")
    assert mounts[str(lab.backup)]["options"].startswith("nodev,nosuid,noexec,")
    assert all(m["source"].startswith("/dev/mapper/agent_context_") for m in mounts.values())


def test_unlock_is_idempotent(lab):
    lab.make_volume("data")
    lab.make_volume("backup", opts="nodev,nosuid,noexec,rw")

    result = lab.unlock()

    assert result.returncode == 0, out(result)
    assert "changed=0" in out(result)
    assert lab.tool_calls("mount") == [] and lab.tool_calls("cryptsetup", "open") == []


def test_unlock_refuses_a_foreign_mapper_under_our_name(lab):
    lab.make_volume("data", mounted=False)
    lab.make_volume("backup")
    lab.state["mappers"]["agent_context_data"]["file"] = "/somewhere/else.img"

    result = lab.unlock()

    assert result.returncode != 0
    assert "foreign" in out(result) and "not backed by the configured container" in out(result)
    assert lab.tool_calls("mount") == []
    assert lab.tool_calls("cryptsetup", "close") == []
    assert "agent_context_data" in lab.read_state()["mappers"]


def test_unlock_refuses_a_foreign_mount_at_the_target(lab):
    lab.make_volume("data", mounted=False)
    lab.state["mounts"][str(lab.data)] = {"source": "/dev/sdz1", "fstype": "ext4", "options": "rw"}
    lab.make_volume("backup")

    result = lab.unlock()

    assert result.returncode != 0
    assert "foreign" in out(result) and "/dev/sdz1" in out(result)
    assert lab.tool_calls("umount") == []
    assert lab.read_state()["mounts"][str(lab.data)]["source"] == "/dev/sdz1"


@pytest.mark.parametrize(
    "name, options",
    [
        ("data", "rw,relatime"),
        ("data", "nodev,rw"),
        ("backup", "nodev,nosuid,rw"),
    ],
)
def test_unlock_fails_on_mount_option_drift_instead_of_reporting_ok(lab, name, options):
    other = "backup" if name == "data" else "data"
    lab.make_volume(name, opts=options)
    lab.make_volume(other, opts="nodev,nosuid,noexec,rw")

    result = lab.unlock()

    assert result.returncode != 0
    assert "Close and unlock again, or remount it by hand" in out(result)
    assert lab.tool_calls("mount") == []


def test_unlock_fails_when_the_filesystem_type_drifted(lab):
    lab.make_volume("data")
    lab.make_volume("backup", opts="nodev,nosuid,noexec")
    lab.state["mounts"][str(lab.data)]["fstype"] = "xfs"

    result = lab.unlock()

    assert result.returncode != 0
    assert "not ext4" in out(result)


def test_unlock_refuses_a_missing_container_without_a_mapping(lab):
    result = lab.unlock()

    assert result.returncode != 0
    assert "run the provision playbook first" in out(result)


def test_close_unmounts_and_closes_only_our_volumes(lab):
    lab.make_volume("data")
    lab.make_volume("backup", opts="nodev,nosuid,noexec")

    result = lab.run("close")

    assert result.returncode == 0, out(result)
    assert lab.read_state() == {"mappers": {}, "mounts": {}}


def test_close_refuses_a_foreign_mount(lab):
    lab.make_volume("backup", opts="nodev,nosuid,noexec")
    lab.make_volume("data", mounted=False)
    lab.state["mounts"][str(lab.data)] = {"source": "/dev/sdz1", "fstype": "ext4", "options": "rw"}

    result = lab.run("close")

    assert result.returncode != 0
    assert "foreign" in out(result)
    assert lab.tool_calls("umount") == [] and lab.tool_calls("cryptsetup", "close") == []
    assert lab.read_state()["mounts"][str(lab.data)]["source"] == "/dev/sdz1"


def test_close_refuses_a_foreign_mapper_and_never_closes_it(lab):
    lab.make_volume("data")
    lab.make_volume("backup", opts="nodev,nosuid,noexec")
    lab.state["mappers"]["agent_context_backup"]["file"] = "/somewhere/else.img"

    result = lab.run("close")

    assert result.returncode != 0
    assert "agent_context_backup" in lab.read_state()["mappers"]
    assert lab.tool_calls("cryptsetup", "close") == []


def test_mountpoint_parent_symlink_is_refused(lab):
    real = lab.root / "elsewhere"
    real.mkdir()
    lab.srv.mkdir()
    (lab.srv / "backups").symlink_to(real)

    result = lab.provision()

    assert result.returncode != 0
    assert "must be a real directory" in out(result)
    assert not (real / "agent-context").exists()


def test_mountpoint_parents_are_created_explicitly_with_0755(lab):
    assert lab.provision().returncode == 0
    for path in (lab.srv, lab.backup.parent, lab.data, lab.backup):
        assert oct(path.stat().st_mode & 0o777) == "0o755"


def test_group_writable_mountpoint_parent_is_refused(lab):
    lab.srv.mkdir()
    lab.srv.chmod(0o775)

    result = lab.provision()

    assert result.returncode != 0
    assert "not group or world writable" in out(result)


OURS = {"source": "/dev/mapper/agent_context_data", "fstype": "ext4", "options": "nodev,nosuid,rw"}
TMPFS = {"source": "tmpfs", "fstype": "tmpfs", "options": "rw"}
STACKED = [OURS, TMPFS]
NESTED = [{**OURS, "children": [TMPFS]}]
SUBMOUNTED = [{**OURS, "submounts": [TMPFS]}]


@pytest.mark.parametrize("stack", [STACKED, NESTED, SUBMOUNTED], ids=["stacked", "children", "submounts"])
@pytest.mark.parametrize("action", ["unlock", "close"])
def test_stacked_or_nested_mounts_on_our_mapper_are_refused(lab, stack, action):
    lab.make_volume("backup", opts="nodev,nosuid,noexec")
    lab.make_volume("data", mounted=False)
    lab.state["mounts"][str(lab.data)] = stack

    result = lab.run(action, **KEYS)

    assert result.returncode != 0
    assert "stacked or nested mounts" in out(result)
    assert lab.tool_calls("umount") == [] and lab.tool_calls("mount") == []
    assert lab.tool_calls("cryptsetup", "close") == []
    assert lab.read_state()["mounts"][str(lab.data)] == stack


def test_findmnt_is_recursive_so_nested_mounts_can_be_seen():
    task = next(t for _, t in all_tasks() if t["name"] == "Read the filesystem mounted at the target")
    assert "-R" in task["ansible.builtin.command"]["argv"]


def test_close_fails_on_a_nested_mount_before_touching_either_volume(lab):
    lab.make_volume("backup", opts="nodev,nosuid,noexec")
    lab.make_volume("data", mounted=False)
    lab.state["mounts"][str(lab.data)] = SUBMOUNTED
    lab.log.write_text("")

    result = lab.run("close")

    assert result.returncode != 0
    assert [c[0] for c in lab.calls() if c[0] in ("umount", "mount") or c[:2] == ["cryptsetup", "close"]] == []
    assert "agent_context_backup" in lab.read_state()["mappers"]
    assert str(lab.backup) in lab.read_state()["mounts"]


def test_unexpected_mapping_status_is_an_error_not_absent(lab):
    lab.make_volume("data", mounted=False)
    lab.extra_env["FAKE_STATUS_RC"] = "1"

    result = lab.unlock()

    assert result.returncode != 0
    assert lab.tool_calls("cryptsetup", "open") == []


def test_inactive_mapping_status_4_still_means_absent(lab):
    assert lab.provision().returncode == 0
    lab.state = lab.read_state()

    assert lab.unlock().returncode == 0


def test_a_container_that_is_not_crypto_luks_is_refused(lab):
    assert lab.provision().returncode == 0
    lab.state = lab.read_state()
    lab.extra_env["FAKE_BLKID_TYPE"] = "ext4"
    lab.log.write_text("")

    result = lab.unlock()

    assert result.returncode != 0
    assert "not a LUKS container" in out(result)
    assert lab.tool_calls("cryptsetup", "open") == []


def test_failed_unlock_closes_only_the_mapping_opened_in_this_run(lab):
    assert lab.provision().returncode == 0
    lab.state = lab.read_state()
    lab.extra_env["FAKE_FAIL_MOUNT"] = "1"
    lab.log.write_text("")

    result = lab.unlock()

    assert result.returncode != 0
    assert "was closed" in out(result)
    assert lab.read_state()["mappers"] == {}
    assert ["cryptsetup", "close", "agent_context_data"] in lab.calls()


def test_failed_unlock_never_closes_a_mapping_it_did_not_open(lab):
    lab.make_volume("data", mounted=False)
    lab.make_volume("backup", opts="nodev,nosuid,noexec")
    lab.extra_env["FAKE_FAIL_MOUNT"] = "1"

    result = lab.unlock()

    assert result.returncode != 0
    assert "agent_context_data" in lab.read_state()["mappers"]
    assert lab.tool_calls("cryptsetup", "close") == []


@pytest.mark.parametrize(
    "variable, value",
    [
        ("agent_context_luks_data_mountpoint", "{srv}/../agent-context"),
        ("agent_context_luks_data_mountpoint", "{srv}//agent-context"),
        ("agent_context_luks_data_mountpoint", "{srv}/./agent-context"),
        ("agent_context_luks_data_mountpoint", "{srv}/agent-context/"),
        ("agent_context_luks_backup_mountpoint", "{srv}/backups/../../evil"),
        ("agent_context_luks_container_dir", "{root}/containers/../elsewhere"),
        ("agent_context_luks_container_dir", "relative/containers"),
        ("agent_context_luks_mount_root", "{srv}/."),
        ("agent_context_luks_mount_root", "/"),
        ("agent_context_luks_mount_root", "/tmp/acl"),
        ("agent_context_luks_mount_root", "/run/acl"),
        ("agent_context_luks_mount_root", "/proc"),
    ],
)
def test_unnormalized_or_unsafe_paths_are_refused_before_any_change(lab, variable, value):
    result = lab.provision(**{variable: value.format(srv=lab.srv, root=lab.root)})

    assert result.returncode != 0
    assert "absolute and normalized" in out(result) or "must be" in out(result)
    assert lab.calls() == []
    assert not lab.containers.exists()


def two_host_inventory(tmp_path, hosts):
    inventory = tmp_path / "inventory.ini"
    lines = ["[agent_context_vps]"] + [f"{h} ansible_connection=local" for h in hosts]
    inventory.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return inventory


@pytest.mark.parametrize("name", PLAYBOOKS)
def test_playbooks_refuse_more_than_one_host(tmp_path, name):
    inventory = two_host_inventory(tmp_path, ["one", "two"])

    result = subprocess.run(
        ["ansible-playbook", "-i", str(inventory), f"playbooks/agent-context-luks-{name}.yml",
         "-e", "ansible_become=false", "-e", f"ansible_python_interpreter={sys.executable}"],
        cwd=ROOT,
        env={**os.environ, "ANSIBLE_HOME": str(tmp_path / "home")},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "exactly one host" in out(result)
    assert "agent_context_luks :" not in result.stdout


@pytest.mark.parametrize("name", PLAYBOOKS)
def test_playbooks_accept_a_single_host_and_stay_inert_when_disabled(tmp_path, name):
    inventory = two_host_inventory(tmp_path, ["one"])

    result = subprocess.run(
        ["ansible-playbook", "-i", str(inventory), f"playbooks/agent-context-luks-{name}.yml",
         "-e", "ansible_become=false", "-e", f"ansible_python_interpreter={sys.executable}"],
        cwd=ROOT,
        env={**os.environ, "ANSIBLE_HOME": str(tmp_path / "home")},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, out(result)


@pytest.mark.parametrize(
    "variable, value",
    [
        ("agent_context_luks_data_mount_opts", "nodev,nosuid,dev"),
        ("agent_context_luks_data_mount_opts", "nodev,nosuid,suid"),
        ("agent_context_luks_data_mount_opts", "defaults,nodev,nosuid"),
        ("agent_context_luks_data_mount_opts", "nodev,nosuid,user"),
        ("agent_context_luks_data_mount_opts", "nodev,nosuid,users"),
        ("agent_context_luks_backup_mount_opts", "nodev,nosuid,noexec,dev"),
        ("agent_context_luks_backup_mount_opts", "nodev,nosuid,noexec,suid"),
        ("agent_context_luks_backup_mount_opts", "nodev,nosuid,noexec,exec"),
        ("agent_context_luks_backup_mount_opts", "defaults,nodev,nosuid,noexec"),
    ],
)
def test_conflicting_or_implying_mount_options_are_refused(lab, variable, value):
    result = lab.unlock(**{variable: value})

    assert result.returncode != 0
    assert "LUKS layout is invalid" in out(result)
    assert lab.calls() == []


@pytest.mark.parametrize("dropped", ["nodev", "nosuid"])
def test_a_mount_that_comes_up_without_a_required_flag_fails_and_is_undone(lab, dropped):
    assert lab.provision().returncode == 0
    lab.state = lab.read_state()
    lab.extra_env["FAKE_MOUNT_DROP"] = dropped
    lab.log.write_text("")

    result = lab.unlock()

    assert result.returncode != 0
    assert "Close and unlock again, or remount it by hand" in out(result)
    assert lab.read_state()["mounts"] == {}
    assert lab.read_state()["mappers"] == {}
    assert ["umount", str(lab.data)] in lab.calls()


def test_two_distinct_string_keys_pass_preflight(lab):
    result = lab.run("unlock", agent_context_luks_data_key="1" * 40, agent_context_luks_backup_key="2" * 40)

    assert "be strings" not in out(result)
