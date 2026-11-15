"""personal_platform_signing_helper role: the pinned Roles Anywhere helper (#30, G4).

Static contract of the role and of the delivery playbook. The installed bytes
are proven on the host by the role's own readback (stat checksum + version).
"""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles" / "personal_platform_signing_helper"
PLAYBOOK = ROOT / "playbooks" / "personal-platform-delivery.yml"
HELPER = "/usr/local/bin/aws_signing_helper"
VERSION = "1.8.5"
SHA256 = "beec9ed1c492d93db809890f16713e3556353294b823c2184ad4e891f1b2b54d"
URL = (
    "https://rolesanywhere.amazonaws.com/releases/1.8.5/"
    "X86_64/Linux/Amzn2023/aws_signing_helper"
)
TAG = "personal_platform_signing_helper"


def tasks():
    [block] = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    assert block["when"] == "personal_platform_signing_helper_enabled | bool"
    return block["block"]


def module(task):
    [name] = [k for k in task if k.startswith("ansible.builtin.")]
    return name, task[name]


def asserted(task):
    name, spec = module(task)
    assert name == "ansible.builtin.assert"
    return [" ".join(str(c).split()) for c in spec["that"]]


def test_role_is_inert_by_default_and_pins_the_exact_release():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    assert defaults == {
        "personal_platform_signing_helper_enabled": False,
        "personal_platform_signing_helper_version": VERSION,
        "personal_platform_signing_helper_sha256": SHA256,
        "personal_platform_signing_helper_url": URL,
    }


def test_role_uses_only_bounded_modules_and_never_touches_services():
    names = [module(t)[0] for t in tasks()]
    assert set(names) <= {
        "ansible.builtin.assert",
        "ansible.builtin.command",
        "ansible.builtin.get_url",
        "ansible.builtin.stat",
    }
    assert names.count("ansible.builtin.get_url") == 1
    text = (ROLE / "tasks" / "main.yml").read_text()
    for word in ("systemctl", "shell:", "apt", "unarchive", "curl", "wget"):
        assert word not in text, word


def test_first_assert_requires_one_exact_host_and_the_official_url():
    first = asserted(tasks()[0])
    assert "ansible_limit | default('') == inventory_hostname" in first
    assert "ansible_play_hosts_all | length == 1" in first
    assert "personal_platform_delivery_enabled | default(false) | bool" in first
    assert (
        "personal_platform_signing_helper_sha256 is match('^[0-9a-f]{64}$')" in first
    )
    url_rule = [c for c in first if c.startswith("personal_platform_signing_helper_url ==")]
    assert url_rule == [
        "personal_platform_signing_helper_url == "
        "'https://rolesanywhere.amazonaws.com/releases/' "
        "~ personal_platform_signing_helper_version "
        "~ '/X86_64/Linux/Amzn2023/aws_signing_helper'"
    ]


def test_architecture_is_read_and_required_before_the_download():
    names = [module(t)[0] for t in tasks()]
    download = names.index("ansible.builtin.get_url")
    uname = [
        i
        for i, t in enumerate(tasks())
        if module(t)[0] == "ansible.builtin.command"
        and module(t)[1].get("argv") == ["/usr/bin/uname", "-m"]
    ]
    assert uname and uname[0] < download
    assert tasks()[uname[0]]["changed_when"] is False
    gate = [
        i
        for i, t in enumerate(tasks())
        if module(t)[0] == "ansible.builtin.assert"
        and any("stdout == 'x86_64'" in c for c in asserted(t))
    ]
    assert gate and uname[0] < gate[0] < download


def test_download_is_checksum_verified_into_the_fixed_root_path():
    [spec] = [
        module(t)[1] for t in tasks() if module(t)[0] == "ansible.builtin.get_url"
    ]
    assert spec == {
        "url": "{{ personal_platform_signing_helper_url }}",
        "dest": HELPER,
        "checksum": "sha256:{{ personal_platform_signing_helper_sha256 }}",
        "owner": "root",
        "group": "root",
        "mode": "0755",
        "timeout": 30,
    }


def test_installed_bytes_owner_mode_and_version_are_read_back_after_install():
    names = [module(t)[0] for t in tasks()]
    download = names.index("ansible.builtin.get_url")
    after = tasks()[download + 1 :]
    [stat] = [module(t)[1] for t in after if module(t)[0] == "ansible.builtin.stat"]
    assert stat == {
        "path": HELPER,
        "checksum_algorithm": "sha256",
        "get_mime": False,
    }
    [version] = [
        t
        for t in after
        if module(t)[0] == "ansible.builtin.command"
        and module(t)[1].get("argv") == [HELPER, "version"]
    ]
    assert version["changed_when"] is False
    final = asserted(after[-1])
    for rule in (
        "personal_platform_signing_helper_installed.stat.isreg",
        "not personal_platform_signing_helper_installed.stat.islnk",
        "personal_platform_signing_helper_installed.stat.checksum == "
        "personal_platform_signing_helper_sha256",
        "personal_platform_signing_helper_installed.stat.pw_name == 'root'",
        "personal_platform_signing_helper_installed.stat.gr_name == 'root'",
        "personal_platform_signing_helper_installed.stat.mode == '0755'",
        "personal_platform_signing_helper_reported.stdout | trim == "
        "personal_platform_signing_helper_version",
    ):
        assert rule in final, rule


def test_role_path_is_the_one_fixed_in_the_host_runtime():
    runtime = (ROOT / "tools" / "cnesdata_delivery" / "host_gate.py").read_text()
    assert f'"{HELPER}"' in runtime


def play():
    [value] = yaml.safe_load(PLAYBOOK.read_text())
    return value


def test_playbook_installs_the_helper_just_before_credentials_with_its_own_tag():
    roles = play()["roles"]
    names = [r["role"] for r in roles]
    assert names == [
        "personal_platform_dispatcher",
        "personal_platform_deployer",
        "personal_platform_nginx",
        "personal_platform_signing_helper",
        "personal_platform_credentials",
    ]
    [helper] = [r for r in roles if r["role"] == "personal_platform_signing_helper"]
    assert helper["tags"] == [TAG]


def test_every_pre_task_runs_under_any_tag_selection():
    pre = play()["pre_tasks"]
    assert pre and all("always" in t["tags"] for t in pre)
    [check] = pre
    rules = [" ".join(str(c).split()) for c in check["ansible.builtin.assert"]["that"]]
    assert "personal_platform_delivery_checkpoint_sha256 is match('^[0-9a-f]{64}$')" in rules
    assert (
        "personal_platform_limnopulse_smoke_evidence_sha256 is match('^[0-9a-f]{64}$')"
        in rules
    )


CHECKPOINT = "Require one exact inventory host and explicit installation authorization"
DOWNLOAD = "Download the exact helper bytes with checksum verification"
DISPATCHER = "Install the self-contained runtime from this exact checkout"
CREDENTIALS = "Install the fixed root-only credential renewer without starting it"


def listed(tmp_path, *selection):
    inventory = tmp_path / "hosts.yml"
    inventory.write_text(
        yaml.safe_dump(
            {"all": {"children": {"personal_platform": {"hosts": {"synthetic-ext3": {}}}}}}
        )
    )
    result = subprocess.run(
        ["ansible-playbook", "-i", str(inventory), str(PLAYBOOK), "--list-tasks", *selection],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible-core absent")
@pytest.mark.parametrize(
    ("selection", "present", "absent"),
    [
        (("--tags", TAG), [CHECKPOINT, DOWNLOAD], [DISPATCHER, CREDENTIALS]),
        (
            ("--tags", "personal_platform_delivery"),
            [CHECKPOINT, DISPATCHER, DOWNLOAD, CREDENTIALS],
            [],
        ),
        ((), [CHECKPOINT, DISPATCHER, DOWNLOAD, CREDENTIALS], []),
        (("--skip-tags", TAG), [CHECKPOINT, DISPATCHER, CREDENTIALS], [DOWNLOAD]),
    ],
)
def test_tag_selections_keep_the_checkpoint_assert_first(tmp_path, selection, present, absent):
    text = listed(tmp_path, *selection)
    for name in present:
        assert name in text, name
    for name in absent:
        assert name not in text, name
    positions = [text.index(name) for name in present]
    assert positions == sorted(positions) and positions[0] == text.index(CHECKPOINT)


def by_name(fragment):
    [task] = [t for t in tasks() if fragment in t["name"]]
    return task


def test_check_mode_reads_the_architecture_and_skips_only_the_post_install_readback():
    # uname is read-only, so it runs under --check and the x86_64 gate stays real.
    assert by_name("host architecture")["check_mode"] is False
    for fragment in ("x86_64", "Download", "installed helper bytes"):
        assert "check_mode" not in by_name(fragment) and "when" not in by_name(fragment)
    # Under --check get_url does not download, so there is nothing to execute.
    for fragment in ("helper version", "Require the exact installed bytes"):
        assert by_name(fragment)["when"] == "not ansible_check_mode"


def test_readme_documents_pin_path_inertness_and_isolated_run():
    readme = (ROLE / "README.md").read_text()
    for phrase in (
        VERSION,
        SHA256,
        URL,
        HELPER,
        "root 0755",
        "Disabled by default",
        f"--tags {TAG}",
        "x86_64",
        "credential_process",
        "--check",
    ):
        assert phrase in readme, phrase
