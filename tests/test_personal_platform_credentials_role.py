"""personal_platform_credentials role: timer and tmpfiles for the EXT-3 JSON credential."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles" / "personal_platform_credentials"


def tasks():
    [block] = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    assert block["when"] == "personal_platform_credentials_enabled | bool"
    return block["block"]


def installed(dest):
    [task] = [
        t
        for t in tasks()
        if t.get("ansible.builtin.copy", {}).get("dest") == dest
    ]
    copy = task["ansible.builtin.copy"]
    assert (copy["owner"], copy["group"], copy["mode"]) == ("root", "root", "0644")
    return copy["content"]


def test_role_stays_disabled_and_never_enables_or_starts_units():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    assert defaults == {"personal_platform_credentials_enabled": False}
    modules = {name for task in tasks() for name in task if "." in name}
    assert modules <= {
        "ansible.builtin.assert",
        "ansible.builtin.file",
        "ansible.builtin.copy",
    }
    text = (ROLE / "tasks" / "main.yml").read_text()
    for word in ("systemctl", "enabled:", "state: started", "daemon_reload"):
        assert word not in text


def test_timer_runs_the_renewer_every_300_seconds_after_boot():
    timer = installed("/etc/systemd/system/personal-platform-credential-reload.timer")
    lines = [line for line in timer.splitlines() if line]
    assert lines == [
        "[Unit]",
        "Description=Personal platform credential_process publication and adoption",
        "[Timer]",
        "OnBootSec=30s",
        "OnUnitActiveSec=300s",
        "AccuracySec=10s",
        "Unit=personal-platform-credential-reload.service",
        "[Install]",
        "WantedBy=timers.target",
    ]


def test_service_stays_the_fixed_root_oneshot_within_the_180_second_budget():
    service = installed(
        "/etc/systemd/system/personal-platform-credential-reload.service"
    )
    assert "Type=oneshot" in service.splitlines()
    assert "TimeoutStartSec=180" in service.splitlines()
    assert (
        "ExecStart=/usr/bin/python3 -I /usr/local/lib/personal-platform/host_gate.py "
        "--credential-reload"
    ) in service.splitlines()
    assert "restart" not in service.lower()


def test_tmpfiles_recreates_private_parents_and_the_container_directory():
    config = installed("/etc/tmpfiles.d/personal-platform-credentials.conf")
    assert [line for line in config.splitlines() if line] == [
        "d /run/personal-platform 0700 root root -",
        "d /run/personal-platform/credentials 0700 root root -",
        "d /run/personal-platform/credentials/cnesdata 0700 root root -",
        "d /run/personal-platform/credentials/cnesdata/current 0710 root 10001 -",
    ]


def test_role_creates_the_same_directories_now_without_waiting_for_a_reboot():
    created = {}
    for task in tasks():
        spec = task.get("ansible.builtin.file")
        if spec and spec.get("state") == "directory":
            for path in task.get("loop", [spec["path"]]):
                created[path] = (spec["owner"], str(spec["group"]), spec["mode"])
    assert created["/run/personal-platform/credentials"] == ("root", "root", "0700")
    assert created["/run/personal-platform/credentials/cnesdata"] == (
        "root",
        "root",
        "0700",
    )
    assert created["/run/personal-platform/credentials/cnesdata/current"] == (
        "root",
        "10001",
        "0710",
    )


def test_no_host_user_can_traverse_to_the_container_directory():
    config = installed("/etc/tmpfiles.d/personal-platform-credentials.conf")
    modes = {line.split()[1]: line.split()[2] for line in config.splitlines() if line}
    for parent in (
        "/run/personal-platform",
        "/run/personal-platform/credentials",
        "/run/personal-platform/credentials/cnesdata",
    ):
        # No group/other execute bit on any ancestor: only root reaches current/.
        assert int(modes[parent], 8) & 0o011 == 0


def test_readme_documents_json_publication_timer_and_adoption():
    readme = (ROLE / "README.md").read_text()
    for phrase in (
        "credential_process",
        "aws-credentials.json",
        "root:10001 0440",
        "0710",
        "personal-platform-credential-reload.timer",
        "OnUnitActiveSec=300s",
        "tmpfiles.d",
        "not enabled",
        "aws_credentials_refreshed",
        "credential_adoption=missing",
        "LimnoPulse",
    ):
        assert phrase in readme, phrase
    assert "replace the client" not in readme
