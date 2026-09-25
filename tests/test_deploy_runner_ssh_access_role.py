from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles/deploy_runner_ssh_access"


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_host_key_replacement_is_opt_in():
    defaults = load_yaml(ROLE / "defaults/main.yml")

    assert defaults["deploy_runner_ssh_access_template_host_key"] == ""


def test_baked_host_keys_are_replaced_before_any_ssh_access_is_granted():
    tasks = load_yaml(ROLE / "tasks/main.yml")
    names = [task["name"] for task in tasks]
    replace = tasks[names.index("Replace the SSH host keys baked into the clone template")]

    assert names.index(
        "Replace the SSH host keys baked into the clone template"
    ) < names.index("Install the admin public key inside the target LXC via pct exec")
    assert replace["when"] == "deploy_runner_ssh_access_template_host_key | length > 0"
    script = replace["ansible.builtin.command"]["argv"][-1]
    # Only a clone still presenting the template key is touched, so a rerun
    # never invalidates a host key already pinned.
    assert 'if [ "$current" = "$baked" ]' in script
    assert "ssh-keygen -A" in script
    # A failed restart must fail the task, not print a key sshd is not serving.
    assert "systemctl restart ssh || exit 1" in script
