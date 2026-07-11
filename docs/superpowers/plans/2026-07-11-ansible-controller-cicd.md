# Ansible Controller LXC and CI/CD Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provision an unprivileged Debian LXC named `ansible`, run native Semaphore UI/API and an independently managed GitHub Actions runner on it, publish it through Cloudflare Access at `ansible.vinisantana.com`, and automatically deploy the validated `infra-ansible/main` SHA.

**Architecture:** A one-time trusted bootstrap creates the LXC and installs reusable roles. Steady-state CI validates on a GitHub-hosted runner, then a repository-scoped self-hosted runner invokes a root-owned fixed deployer that retrieves an allowlisted secret set from Infisical, reconciles Semaphore, verifies the CT 110 route, and rolls back from an encrypted PostgreSQL backup on failure.

**Tech Stack:** Ansible Core, `community.proxmox`, Python 3.12, PowerShell 7, Proxmox VE 9.1.1, Debian 13, Semaphore UI 2.18.25, PostgreSQL, GitHub Actions Runner 2.335.1, GitHub Actions/CLI/MCP, Infisical Universal Auth, MinIO S3, age, Nginx, Cloudflare Access.

## Global Constraints

- The LXC is unprivileged, has no nesting, and does not run Docker.
- The initial guest contract is 2 vCPU, 4096 MiB RAM, 32 GiB `local-lvm`, `vmbr0`, DHCP reservation, firewall enabled, and `onboot: true`.
- `proxmox_lxc_guest` has no absent, delete, or automatic replacement path.
- Semaphore starts at exact version `2.18.25`; its amd64 `.deb` SHA-256 is `209cf89c23710ed74e4568be129690fb5f9599b66f3cdfb55ed6c1a437c94dc9`.
- GitHub Actions Runner starts at exact version `2.335.1`; its linux-x64 archive SHA-256 is `4ef2f25285f0ae4477f1fe1e346db76d2f3ebf03824e2ddd1973a2819bf6c8cf`.
- Runtime secrets come only from Infisical folders `/ansible`, `/minio`, and `/edge-proxy` and never appear as command-line values, logs, artifacts, or unencrypted objects.
- Pull-request jobs use GitHub-hosted runners only; the `ansible-prod` runner is reachable only from the trusted push-to-main deployment job in the committed workflow.
- Production rollout is automatic after successful validation of a merge to `main`; it has no approval gate and never cancels an in-progress deployment.
- `https://ansible.vinisantana.com` is published only through Cloudflare Access and CT 110.
- The path-specific Cloudflare service token can reach only `/api/ping`; the catch-all UI requires OTP for `me@vinisantana.com`.
- Full-guest `vzdump` remains disabled; this plan implements encrypted PostgreSQL/configuration backups only.

---

## File and Interface Map

### `infra-ansible`

- `requirements.yml`: add the current Proxmox collection.
- `tools/ansible/Dockerfile`: install `proxmoxer`, `requests`, and `age` for bootstrap/deploy execution.
- `roles/proxmox_lxc_guest/`: one-time, create-only LXC lifecycle.
- `roles/github_actions_runner/`: reusable Debian/Ubuntu runner lifecycle.
- `roles/infra_ansible_deployer/`: root-owned fixed production boundary on an executor node.
- `roles/semaphore_controller/`: PostgreSQL, native Semaphore releases, service, backup, migration, rollback, and health.
- `roles/edge_proxy_route/`: atomic Nginx route management on CT 110.
- `roles/cloudflare_access_application/`: path-scoped Access applications and policies from localhost.
- `playbooks/provision-ansible-controller.yml`: create-only Proxmox bootstrap.
- `playbooks/bootstrap-ansible-controller.yml`: baseline, runner, deployer, Semaphore, edge, Access.
- `playbooks/deploy-ansible-controller.yml`: steady-state Semaphore and monitoring reconciliation only.
- `playbooks/rollback-ansible-controller.yml`: fixed rollback entrypoint used only by the deployer after post-switch failure.
- `tools/release/build_release_manifest.py`: deterministic manifest generator.
- `tools/deploy/infra_ansible_deploy.py`: fixed privileged deploy entrypoint.
- `tools/github/Configure-GitHubActions.ps1`: idempotent repository settings.
- `.github/workflows/pipeline.yml`: hosted validation plus trusted main deploy.

### `infra-ansible-inventory`

- `inventories/prod/hosts.yml`: add bootstrap, controller, runner, and edge groups.
- `inventories/prod/group_vars/ansible_controller_bootstrap/ansible_controller_lxc.yml`: desired LXC contract.
- `inventories/prod/group_vars/ansible_controllers/semaphore.yml`: Semaphore and backup contract.
- `inventories/prod/group_vars/github_actions_runners/github_actions_runner.yml`: runner contract.
- `inventories/prod/group_vars/edge_proxy_hosts/ansible_route.yml`: CT 110 route.
- `inventories/prod/group_vars/local_validation/cloudflare_access.yml`: Cloudflare Access contract.
- `inventories/prod/group_vars/infisical.yml`: add `/ansible` and required key names.
- `inventories/prod/group_vars/minio.yml`: add Semaphore backup/evidence prefixes.
- `tests/Validate-InventoryScaffold.ps1`: validate fail-closed and activated states.

### Stable interfaces

- `proxmox_lxc_guest` consumes an explicit VMID, template VMID `9400`, node, storage, bridge, and API environment variables; it produces a started LXC and redacted `proxmox_lxc_guest_summary`.
- `github_actions_runner` consumes `GITHUB_ACTIONS_RUNNER_REGISTRATION_TOKEN` from the controller environment during bootstrap; it produces the systemd unit derived by the official service installer for the configured runner name.
- `infra_ansible_deploy.py` accepts exactly one positional 40-character SHA and obtains all playbooks, limits, tags, and target values from root-owned configuration.
- `build_release_manifest.py` writes schema `1` JSON with `infra_sha`, `semaphore_version`, `semaphore_sha256`, and `runner_minimum`.
- `semaphore_controller` produces local health `http://127.0.0.1:3000/api/ping == pong` and redacted `/var/lib/infra-ansible/deployments/{{ infra_release_sha }}.json`.

---

## Milestone 1: Provisioning and Executor Foundation

### Task 1: Extend the validated Ansible toolchain

**Files:**
- Modify: `requirements.yml`
- Modify: `tools/ansible/Dockerfile`
- Modify: `tests/Validate-AnsibleContainer.ps1`
- Modify: `tests/Validate-InfraAnsibleScaffold.ps1`

**Interfaces:**
- Consumes: existing `tools/ansible/Dockerfile` build contract.
- Produces: image containing `community.proxmox`, `community.postgresql`, `proxmoxer>=2.3`, `psycopg`, `requests`, and `age`.

- [ ] **Step 1: Add failing scaffold assertions**

Add these assertions to both PowerShell validators where their existing collection/package checks live:

```powershell
Assert-FileContains -RelativePath "requirements.yml" -Pattern "community\.proxmox"
Assert-FileContains -RelativePath "requirements.yml" -Pattern "community\.postgresql"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern 'proxmoxer>=2\.3'
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "psycopg"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "requests"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "age"
```

- [ ] **Step 2: Verify the new assertions fail**

Run:

```bash
rtk pwsh -NoProfile -File tests/Validate-AnsibleContainer.ps1
rtk pwsh -NoProfile -File tests/Validate-InfraAnsibleScaffold.ps1
```

Expected: both fail because `community.proxmox`, `proxmoxer`, and `age` are absent.

- [ ] **Step 3: Add the collection and runtime packages**

Change `requirements.yml` to include:

```yaml
collections:
  - name: ansible.posix
  - name: community.general
  - name: community.proxmox
  - name: community.postgresql
  - name: community.docker
  - name: amazon.aws
```

Add `age` to the `apk add` list and add these pip requirements beside boto3:

```dockerfile
        "proxmoxer>=2.3.0" \
        "psycopg[binary]>=3.2.0" \
        "requests>=2.32.0" \
```

- [ ] **Step 4: Verify the container and syntax contracts**

Run:

```bash
rtk pwsh -NoProfile -File tests/Validate-AnsibleContainer.ps1
rtk pwsh -NoProfile -File tests/Validate-InfraAnsibleScaffold.ps1
rtk docker build -t infra-ansible-tools:test -f tools/ansible/Dockerfile .
rtk docker run --rm --entrypoint ansible-galaxy infra-ansible-tools:test collection list community.proxmox
```

Expected: validators pass, image builds, and the collection list contains `community.proxmox`.

- [ ] **Step 5: Commit**

```bash
rtk git add requirements.yml tools/ansible/Dockerfile tests/Validate-AnsibleContainer.ps1 tests/Validate-InfraAnsibleScaffold.ps1
rtk git commit -m "build: add Proxmox controller dependencies"
```

### Task 2: Implement create-only Proxmox LXC provisioning

**Files:**
- Create: `roles/proxmox_lxc_guest/defaults/main.yml`
- Create: `roles/proxmox_lxc_guest/tasks/main.yml`
- Create: `roles/proxmox_lxc_guest/README.md`
- Create: `playbooks/provision-ansible-controller.yml`
- Create: `tests/test_proxmox_lxc_guest_role.py`
- Modify: `tests/Validate-InfraAnsibleScaffold.ps1`

**Interfaces:**
- Consumes: `PVE_HOST`, `PVE_TOKEN_ID`, `PVE_TOKEN_SECRET`, and explicit inventory contract.
- Produces: `proxmox_lxc_guest_summary` with `vmid`, `hostname`, `node`, and `state`, never credentials.

- [ ] **Step 1: Write failing safety tests**

Create `tests/test_proxmox_lxc_guest_role.py`:

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_lxc_role_is_disabled_and_create_only():
    defaults = read("roles/proxmox_lxc_guest/defaults/main.yml")
    tasks = read("roles/proxmox_lxc_guest/tasks/main.yml")
    assert "proxmox_lxc_guest_enabled: false" in defaults
    assert "state: absent" not in tasks
    assert "delete" not in tasks.lower()
    assert "ansible_limit" in tasks
    assert "proxmox_lxc_guest" in tasks


def test_lxc_role_requires_approved_template_contract():
    tasks = read("roles/proxmox_lxc_guest/tasks/main.yml")
    for token in ("template", "unprivileged", "ostype", "rootfs", "vmbr0", "ip=dhcp"):
        assert token in tasks
    assert "community.proxmox.proxmox" in tasks


def test_lxc_playbook_runs_only_on_bootstrap_host():
    playbook = read("playbooks/provision-ansible-controller.yml")
    assert "hosts: ansible_controller_bootstrap" in playbook
    assert "connection: local" in playbook
    assert "role: proxmox_lxc_guest" in playbook
```

- [ ] **Step 2: Verify the role test fails**

Run: `rtk python3 -m pytest tests/test_proxmox_lxc_guest_role.py -q`

Expected: FAIL because the role and playbook do not exist.

- [ ] **Step 3: Create fail-closed defaults**

Create `roles/proxmox_lxc_guest/defaults/main.yml` with these exact public defaults:

```yaml
---
proxmox_lxc_guest_enabled: false
proxmox_lxc_guest_api_host: "{{ lookup('ansible.builtin.env', 'PVE_HOST') }}"
proxmox_lxc_guest_api_user: "{{ lookup('ansible.builtin.env', 'PVE_TOKEN_ID').split('!')[0] }}"
proxmox_lxc_guest_api_token_id: "{{ lookup('ansible.builtin.env', 'PVE_TOKEN_ID').split('!')[-1] }}"
proxmox_lxc_guest_api_token_secret: "{{ lookup('ansible.builtin.env', 'PVE_TOKEN_SECRET') }}"
proxmox_lxc_guest_validate_certs: true
proxmox_lxc_guest_node: pve-01
proxmox_lxc_guest_template_vmid: 9400
proxmox_lxc_guest_template_name: tlp-ct-debian-13
proxmox_lxc_guest_vmid: 0
proxmox_lxc_guest_hostname: ansible
proxmox_lxc_guest_storage: local-lvm
proxmox_lxc_guest_bridge: vmbr0
proxmox_lxc_guest_cores: 2
proxmox_lxc_guest_memory_mb: 4096
proxmox_lxc_guest_disk_gb: 32
proxmox_lxc_guest_onboot: true
```

- [ ] **Step 4: Implement validation, preflight, clone, and postflight**

In `tasks/main.yml`, implement this sequence with `no_log: true` on every module call containing token fields:

```yaml
---
- name: Validate LXC enable flag
  ansible.builtin.assert:
    that: [proxmox_lxc_guest_enabled is boolean]

- name: Stop the create-only role when disabled
  ansible.builtin.meta: end_role
  when: not proxmox_lxc_guest_enabled | bool

- name: Validate narrow create-only contract
  ansible.builtin.assert:
    that:
      - ansible_limit is defined
      - ansible_limit | trim == inventory_hostname
      - ansible_play_hosts_all == [inventory_hostname]
      - ansible_run_tags | list | sort == ['proxmox_lxc_guest']
      - proxmox_lxc_guest_vmid | int >= 100
      - proxmox_lxc_guest_template_vmid | int == 9400
      - proxmox_lxc_guest_storage == 'local-lvm'
      - proxmox_lxc_guest_bridge == 'vmbr0'
      - proxmox_lxc_guest_disk_gb | int == 32

- name: Read source template configuration
  ansible.builtin.uri:
    url: "https://{{ proxmox_lxc_guest_api_host }}/api2/json/nodes/{{ proxmox_lxc_guest_node }}/lxc/{{ proxmox_lxc_guest_template_vmid }}/config"
    headers:
      Authorization: "PVEAPIToken={{ lookup('ansible.builtin.env', 'PVE_TOKEN_ID') }}={{ proxmox_lxc_guest_api_token_secret }}"
    validate_certs: "{{ proxmox_lxc_guest_validate_certs }}"
    return_content: true
  register: proxmox_lxc_guest_template
  changed_when: false
  no_log: true

- name: Prove source template safety
  ansible.builtin.assert:
    that:
      - proxmox_lxc_guest_template.json.data.template | int == 1
      - proxmox_lxc_guest_template.json.data.unprivileged | int == 1
      - proxmox_lxc_guest_template.json.data.ostype == 'debian'
      - proxmox_lxc_guest_template.json.data.rootfs is search('size=32G')
      - proxmox_lxc_guest_template.json.data.net0 is search('bridge=vmbr0')
      - proxmox_lxc_guest_template.json.data.net0 is search('ip=dhcp')

- name: Read existing target VMID
  community.proxmox.proxmox_vm_info:
    api_host: "{{ proxmox_lxc_guest_api_host }}"
    api_user: "{{ proxmox_lxc_guest_api_user }}"
    api_token_id: "{{ proxmox_lxc_guest_api_token_id }}"
    api_token_secret: "{{ proxmox_lxc_guest_api_token_secret }}"
    validate_certs: true
    vmid: "{{ proxmox_lxc_guest_vmid }}"
    config: current
  register: proxmox_lxc_guest_existing
  changed_when: false
  no_log: true

- name: Clone absent approved template
  community.proxmox.proxmox:
    api_host: "{{ proxmox_lxc_guest_api_host }}"
    api_user: "{{ proxmox_lxc_guest_api_user }}"
    api_token_id: "{{ proxmox_lxc_guest_api_token_id }}"
    api_token_secret: "{{ proxmox_lxc_guest_api_token_secret }}"
    validate_certs: true
    clone: "{{ proxmox_lxc_guest_template_vmid }}"
    vmid: "{{ proxmox_lxc_guest_vmid }}"
    hostname: "{{ proxmox_lxc_guest_hostname }}"
    node: "{{ proxmox_lxc_guest_node }}"
    storage: "{{ proxmox_lxc_guest_storage }}"
  when: proxmox_lxc_guest_existing.proxmox_vms | length == 0
  no_log: true

- name: Reconcile non-destructive target configuration
  community.proxmox.proxmox:
    api_host: "{{ proxmox_lxc_guest_api_host }}"
    api_user: "{{ proxmox_lxc_guest_api_user }}"
    api_token_id: "{{ proxmox_lxc_guest_api_token_id }}"
    api_token_secret: "{{ proxmox_lxc_guest_api_token_secret }}"
    validate_certs: true
    vmid: "{{ proxmox_lxc_guest_vmid }}"
    hostname: "{{ proxmox_lxc_guest_hostname }}"
    node: "{{ proxmox_lxc_guest_node }}"
    cores: "{{ proxmox_lxc_guest_cores }}"
    memory: "{{ proxmox_lxc_guest_memory_mb }}"
    onboot: "{{ proxmox_lxc_guest_onboot }}"
    update: true
    state: started
  no_log: true
```

After creation, query `config: current`, assert hostname/node/type/unprivileged/rootfs/net0, and set the redacted summary. If a target already exists, assert exact agreement before reporting success.

- [ ] **Step 5: Add the bootstrap playbook and documentation**

Create `playbooks/provision-ansible-controller.yml`:

```yaml
---
- name: Provision the create-only Ansible controller LXC
  hosts: ansible_controller_bootstrap
  connection: local
  gather_facts: false
  serial: 1
  roles:
    - role: proxmox_lxc_guest
      tags: [proxmox_lxc_guest]
```

Document the exact tag/limit command, read-only preflight, and absence of deletion in the role README.

- [ ] **Step 6: Verify and commit**

Run:

```bash
rtk python3 -m pytest tests/test_proxmox_lxc_guest_role.py -q
rtk ansible-playbook -i inventories/example/hosts.yml playbooks/provision-ansible-controller.yml --syntax-check
rtk yamllint roles/proxmox_lxc_guest playbooks/provision-ansible-controller.yml
```

Expected: PASS without contacting Proxmox.

```bash
rtk git add roles/proxmox_lxc_guest playbooks/provision-ansible-controller.yml tests/test_proxmox_lxc_guest_role.py tests/Validate-InfraAnsibleScaffold.ps1
rtk git commit -m "feat: add create-only Ansible LXC role"
```

### Task 3: Implement the reusable GitHub Actions runner role

**Files:**
- Create: `roles/github_actions_runner/defaults/main.yml`
- Create: `roles/github_actions_runner/tasks/main.yml`
- Create: `roles/github_actions_runner/handlers/main.yml`
- Create: `roles/github_actions_runner/README.md`
- Create: `tests/test_github_actions_runner_role.py`
- Create: `tests/Validate-GitHubRunnerMatrix.ps1`
- Create: `tests/fixtures/github-runner/Dockerfile.debian13`
- Create: `tests/fixtures/github-runner/Dockerfile.ubuntu2404`
- Create: `tests/fixtures/github-runner/fake-runner/config.sh`
- Create: `tests/fixtures/github-runner/fake-runner/run.sh`

**Interfaces:**
- Consumes: `GITHUB_ACTIONS_RUNNER_REGISTRATION_TOKEN` only during bootstrap.
- Produces: repo-scoped runner named `ansible-prod-{{ ansible_controller_vmid }}` in production inventory, with labels `ansible-prod,linux,x64` and a systemd unit.

- [ ] **Step 1: Write failing role contract tests**

Test exact version/checksum, Debian/Ubuntu assertions, no broad sudoers, `no_log`, systemd installation, and absence of Semaphore paths:

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_runner_role_is_reusable_and_secret_safe():
    defaults = read("roles/github_actions_runner/defaults/main.yml")
    tasks = read("roles/github_actions_runner/tasks/main.yml")
    assert "github_actions_runner_version: 2.335.1" in defaults
    assert "4ef2f25285f0ae4477f1fe1e346db76" in defaults
    assert "GITHUB_ACTIONS_RUNNER_REGISTRATION_TOKEN" in tasks
    assert "no_log: true" in tasks
    assert "ansible_service_mgr == 'systemd'" in tasks
    assert "semaphore" not in tasks.lower()
    assert "NOPASSWD: ALL" not in tasks
```

- [ ] **Step 2: Verify red**

Run: `rtk python3 -m pytest tests/test_github_actions_runner_role.py -q`

Expected: FAIL because the role is absent.

- [ ] **Step 3: Implement defaults and platform validation**

Defaults must include:

```yaml
github_actions_runner_version: 2.335.1
github_actions_runner_sha256_x64: 4ef2f25285f0ae4477f1fe1e346db76d2f3ebf03824e2ddd1973a2819bf6c8cf
github_actions_runner_repository_url: https://github.com/VINIClUS/infra-ansible
github_actions_runner_name: "{{ inventory_hostname }}"
github_actions_runner_labels: [ansible-prod, linux, x64]
github_actions_runner_user: github-runner
github_actions_runner_group: github-runner
github_actions_runner_home: /opt/github-actions-runner
github_actions_runner_work: /var/lib/github-actions-runner
```

Assert `ansible_os_family == 'Debian'`, distribution is Debian or Ubuntu,
systemd is active, architecture maps to `x64` or `arm64`, and the registration
token is present only when `.runner` is absent.

- [ ] **Step 4: Implement verified install and registration**

Create the system user, download the exact official archive with `checksum:
sha256:{{ github_actions_runner_archive_sha256 }}`, extract it into the versioned directory, install
documented native dependencies, and execute `config.sh` as the runner user:

```yaml
- name: Register repository runner once
  ansible.builtin.command:
    argv:
      - ./config.sh
      - --unattended
      - --url
      - "{{ github_actions_runner_repository_url }}"
      - --token
      - "{{ lookup('ansible.builtin.env', 'GITHUB_ACTIONS_RUNNER_REGISTRATION_TOKEN') }}"
      - --name
      - "{{ github_actions_runner_name }}"
      - --labels
      - "{{ github_actions_runner_labels | join(',') }}"
      - --work
      - "{{ github_actions_runner_work }}"
      - --replace
  args:
    chdir: "{{ github_actions_runner_home }}"
    creates: "{{ github_actions_runner_home }}/.runner"
  become: true
  become_user: "{{ github_actions_runner_user }}"
  no_log: true
```

Install/start the runner through its generated `svc.sh`, allow official
self-update, and record only name, labels, service state, and effective version.

- [ ] **Step 5: Exercise the Debian/Ubuntu systemd matrix**

Build fixture images from `debian:13` and `ubuntu:24.04` that install systemd,
Python, sudo, and the role's native dependencies. Package the fake runner so
`config.sh` writes `.runner`, `run.sh` stays active, and neither contacts
GitHub. `Validate-GitHubRunnerMatrix.ps1` must start each image with a writable
cgroup, apply the role twice using the fake archive/checksum, assert the second
run has `changed=0`, verify the generated systemd unit is active, and remove
both containers in `finally`.

Run:

```bash
rtk pwsh -NoProfile -File tests/Validate-GitHubRunnerMatrix.ps1
```

Expected: Debian 13 and Ubuntu 24.04 both report first-run success,
second-run idempotency, and active fake runner service.

- [ ] **Step 6: Verify idempotency contract and commit**

Run:

```bash
rtk python3 -m pytest tests/test_github_actions_runner_role.py -q
rtk pwsh -NoProfile -File tests/Validate-GitHubRunnerMatrix.ps1
rtk yamllint roles/github_actions_runner
rtk ansible-playbook -i inventories/example/hosts.yml playbooks/site.yml --syntax-check
```

Expected: PASS.

```bash
rtk git add roles/github_actions_runner tests/test_github_actions_runner_role.py tests/Validate-GitHubRunnerMatrix.ps1 tests/fixtures/github-runner
rtk git commit -m "feat: add reusable GitHub runner role"
```

### Task 4: Build the fixed privileged deployment boundary

**Files:**
- Create: `tools/deploy/infra_ansible_deploy.py`
- Create: `tests/test_infra_ansible_deploy.py`
- Create: `roles/infra_ansible_deployer/defaults/main.yml`
- Create: `roles/infra_ansible_deployer/tasks/main.yml`
- Create: `roles/infra_ansible_deployer/templates/infra-ansible-deploy.env.j2`
- Create: `roles/infra_ansible_deployer/templates/infra-ansible-deploy.sudoers.j2`
- Create: `roles/infra_ansible_deployer/README.md`

**Interfaces:**
- Consumes: one SHA argument and root-only configuration.
- Produces: a fixed controller deployment, edge reconciliation, Access reconciliation, and external health sequence; any post-switch failure invokes the fixed rollback playbook.

- [ ] **Step 1: Write failing Python boundary tests**

Create tests for this pure function:

```python
validate_request(
    requested_sha: str,
    main_sha: str,
    checkout_sha: str,
    dirty: bool,
) -> None
```

Cover valid equal SHAs and rejection of malformed SHA, non-main SHA, dirty
checkout, alternate inventory, alternate limit, alternate tags, and unexpected
arguments. Mock subprocess and assert no secret is present in argv.

```python
import pytest

from tools.deploy.infra_ansible_deploy import validate_request

SHA = "0123456789abcdef0123456789abcdef01234567"


def test_accepts_only_clean_current_main_sha():
    validate_request(SHA, SHA, SHA, False)


@pytest.mark.parametrize(
    ("requested", "main", "checkout", "dirty"),
    [
        ("main", SHA, SHA, False),
        (SHA, "f" * 40, SHA, False),
        (SHA, SHA, "e" * 40, False),
        (SHA, SHA, SHA, True),
    ],
)
def test_rejects_untrusted_request(requested, main, checkout, dirty):
    with pytest.raises(ValueError):
        validate_request(requested, main, checkout, dirty)
```

- [ ] **Step 2: Verify red**

Run: `rtk python3 -m pytest tests/test_infra_ansible_deploy.py -q`

Expected: FAIL because the module is absent.

- [ ] **Step 3: Implement validation and fixed execution**

The script must:

```python
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FIXED_INVENTORY = "/srv/infra-ansible-inventory/inventories/prod/hosts.yml"
FIXED_RUNS = (
    ("playbooks/deploy-ansible-controller.yml", "ansible", "semaphore_controller,monitoring_agent"),
    ("playbooks/edge-proxy-route.yml", "nginx", "edge_proxy_route"),
    ("playbooks/cloudflare-access.yml", "localhost", "cloudflare_access_application"),
)
FIXED_ROLLBACK = ("playbooks/rollback-ansible-controller.yml", "ansible", "semaphore_controller_rollback")
```

Read the public main SHA from
`https://api.github.com/repos/VINIClUS/infra-ansible/git/ref/heads/main`, compare
it to the requested and checked-out SHA, reject a dirty worktree, take
`flock(/run/lock/infra-ansible-deploy.lock)`, and then `execve` the existing
`tools/ansible/infisical_ansible.py` for each fixed run with fixed paths and
required secret names. After the three runs, perform the service-token external
health check. If edge, Access, or external health fails after Semaphore switched,
execute `FIXED_ROLLBACK` before returning failure. Secrets enter only through
the child environment.

Before invoking the production playbook, update the private inventory clone to
its remote `main`, resolve and record its exact commit as `inventory_sha`, run
`Validate-InventoryScaffold.ps1`, and run `ansible-inventory --list`. Abort
before backup or migration if either private-inventory validation fails.

- [ ] **Step 4: Install the root-owned boundary**

The role must install the script mode `0755`, config mode `0600`, clone/update
both repositories into `/srv` by exact SHA, and install this only sudo rule:

```sudoers
github-runner ALL=(root) NOPASSWD: /usr/local/sbin/infra-ansible-deploy [0-9a-f]*
```

The Python script remains the enforcement boundary; the sudoers glob is not
treated as validation. Assert `NOPASSWD: ALL` never appears.

- [ ] **Step 5: Verify and commit**

Run:

```bash
rtk python3 -m pytest tests/test_infra_ansible_deploy.py -q
rtk yamllint roles/infra_ansible_deployer
rtk python3 -m py_compile tools/deploy/infra_ansible_deploy.py
```

```bash
rtk git add tools/deploy roles/infra_ansible_deployer tests/test_infra_ansible_deploy.py
rtk git commit -m "feat: add fixed production deploy boundary"
```

---

## Milestone 2: Semaphore, Backups, and Public Route

### Task 5: Implement native Semaphore and PostgreSQL releases

**Files:**
- Create: `roles/semaphore_controller/defaults/main.yml`
- Create: `roles/semaphore_controller/tasks/main.yml`
- Create: `roles/semaphore_controller/tasks/install.yml`
- Create: `roles/semaphore_controller/tasks/configure.yml`
- Create: `roles/semaphore_controller/handlers/main.yml`
- Create: `roles/semaphore_controller/templates/config.json.j2`
- Create: `roles/semaphore_controller/templates/semaphore.service.j2`
- Create: `roles/semaphore_controller/README.md`
- Create: `tests/test_semaphore_controller_role.py`

**Interfaces:**
- Consumes: exact version/checksum plus DB/admin/encryption environment names.
- Produces: systemd service and `GET http://127.0.0.1:3000/api/ping == pong`.

- [ ] **Step 1: Write failing role tests**

Assert exact version/checksum, release/current separation, PostgreSQL package,
three required secret names, loopback health endpoint, `no_log`, and no Docker.

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_native_semaphore_contract():
    defaults = read("roles/semaphore_controller/defaults/main.yml")
    tasks = read("roles/semaphore_controller/tasks/main.yml")
    assert "semaphore_controller_version: 2.18.25" in defaults
    assert "209cf89c23710ed74e4568be129690fb5" in defaults
    assert "/opt/semaphore/releases" in defaults
    assert "/opt/semaphore/current" in defaults
    assert "postgresql" in tasks
    assert "http://127.0.0.1:3000/api/ping" in tasks
    assert "no_log: true" in tasks
    assert "docker" not in tasks.lower()
```

- [ ] **Step 2: Verify red**

Run: `rtk python3 -m pytest tests/test_semaphore_controller_role.py -q`

- [ ] **Step 3: Implement fail-closed defaults**

Use:

```yaml
semaphore_controller_enabled: false
semaphore_controller_version: 2.18.25
semaphore_controller_sha256: 209cf89c23710ed74e4568be129690fb5f9599b66f3cdfb55ed6c1a437c94dc9
semaphore_controller_release_root: /opt/semaphore/releases
semaphore_controller_current_path: /opt/semaphore/current
semaphore_controller_config_dir: /etc/semaphore
semaphore_controller_port: 3000
semaphore_controller_required_env:
  - SEMAPHORE_DB_PASSWORD
  - SEMAPHORE_ACCESS_KEY_ENCRYPTION
  - SEMAPHORE_ADMIN_PASSWORD
```

Require Debian 13 for the controller instance, an exact one-host limit, and the
`semaphore_controller` tag.

- [ ] **Step 4: Implement native release extraction and configuration**

Install `postgresql`, `postgresql-client`, `ca-certificates`, `curl`, `git`,
`openssh-client`, `rsync`, `age`, `python3`, `python3-venv`, `python3-pexpect`,
and `python3-psycopg`. Download the
official `.deb`, verify SHA-256, extract with:

```yaml
- name: Extract immutable Semaphore release
  ansible.builtin.command:
    argv:
      - dpkg-deb
      - --extract
      - "{{ semaphore_controller_download_path }}"
      - "{{ semaphore_controller_release_path }}"
  args:
    creates: "{{ semaphore_controller_release_path }}/usr/bin/semaphore"
```

Create database/user with `community.postgresql`, render config mode `0640`,
and use `ansible.builtin.expect` with `no_log: true` for the first-run
`semaphore setup` prompts so DB/admin passwords travel over stdin and never
appear in argv. The role then creates a systemd unit pointing to
`current/usr/bin/semaphore`, switches the symlink atomically, starts the
service, and polls `/api/ping` until it returns `pong`.

- [ ] **Step 5: Verify and commit**

Run pytest, yamllint, and syntax-check. Expected: PASS.

```bash
rtk git add roles/semaphore_controller tests/test_semaphore_controller_role.py
rtk git commit -m "feat: deploy native Semaphore controller"
```

### Task 6: Add encrypted backup, migration, and rollback transaction

**Files:**
- Create: `roles/semaphore_controller/tasks/backup.yml`
- Create: `roles/semaphore_controller/tasks/deploy.yml`
- Create: `roles/semaphore_controller/tasks/rollback.yml`
- Create: `roles/semaphore_controller/templates/semaphore-backup.service.j2`
- Create: `roles/semaphore_controller/templates/semaphore-backup.timer.j2`
- Create: `roles/semaphore_controller/templates/semaphore-backup.sh.j2`
- Create: `tests/test_semaphore_controller_transaction.py`

**Interfaces:**
- Consumes: `ANSIBLE_BACKUP_AGE_IDENTITY`, public age recipient, and existing MinIO variables.
- Produces: encrypted pre-change backup, daily timer, rollback result, and redacted deployment record.

- [ ] **Step 1: Write failing transaction tests**

Test a Python/static fixture state machine with states:

```text
PREFLIGHT -> BACKED_UP -> MIGRATED -> SWITCHED -> HEALTHY
                              \-> ROLLED_BACK
```

Assert migration never runs before successful encrypted MinIO upload, rollback
restores DB/config/symlink, and final evidence failure does not roll back a
healthy service.

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_transaction_order_is_fail_closed():
    deploy = read("roles/semaphore_controller/tasks/deploy.yml")
    assert deploy.index("include_tasks: backup.yml") < deploy.index("migrate")
    assert deploy.index("migrate") < deploy.index("state: link")
    assert "include_tasks: rollback.yml" in deploy
    assert "always:" in deploy


def test_backup_is_encrypted_before_upload():
    backup = read("roles/semaphore_controller/tasks/backup.yml")
    assert backup.index("pg_dump") < backup.index("age")
    assert backup.index("age") < backup.index("amazon.aws.s3_object")
    assert "no_log: true" in backup
```

- [ ] **Step 2: Verify red**

Run: `rtk python3 -m pytest tests/test_semaphore_controller_transaction.py -q`

- [ ] **Step 3: Implement the Ansible block/rescue transaction**

`deploy.yml` must use:

```yaml
- name: Deploy Semaphore transactionally
  block:
    - ansible.builtin.include_tasks: backup.yml
    - ansible.builtin.command:
        argv:
          - "{{ semaphore_controller_target_binary }}"
          - migrate
          - --apply-to
          - "{{ semaphore_controller_version }}"
    - ansible.builtin.file:
        src: "{{ semaphore_controller_release_path }}"
        dest: "{{ semaphore_controller_current_path }}"
        state: link
        force: true
    - ansible.builtin.systemd_service:
        name: semaphore
        state: restarted
    - ansible.builtin.uri:
        url: http://127.0.0.1:3000/api/ping
        return_content: true
      register: semaphore_controller_health
      failed_when: semaphore_controller_health.status != 200 or semaphore_controller_health.content | trim != 'pong'
  rescue:
    - ansible.builtin.include_tasks: rollback.yml
    - ansible.builtin.fail:
        msg: Semaphore rollout failed and the previous release was restored.
```

Use `pg_dump --format=custom`, `tar`, `age -r {{ ansible_backup_age_recipient }}`, and
`amazon.aws.s3_object` with `no_log: true`. Delete plaintext staging in an
`always` block.

Add `semaphore_controller_rollback_mode: false` to defaults. When true, the
role skips install/deploy, requires an exact backup ID from the root-owned
deployment state, includes `rollback.yml`, verifies internal health, and clears
the one-shot rollback marker.

- [ ] **Step 4: Install and validate the daily timer**

Install `semaphore-backup.service` and `.timer`, run `systemd-analyze verify`,
start the timer, and assert the next trigger exists. The script uses the same
encryption and S3 prefix but never performs migrations.

- [ ] **Step 5: Verify and commit**

Run transaction tests, full pytest, yamllint, and syntax-check.

```bash
rtk git add roles/semaphore_controller tests/test_semaphore_controller_transaction.py
rtk git commit -m "feat: add Semaphore backup and rollback"
```

### Task 7: Manage the CT 110 route atomically

**Files:**
- Create: `roles/edge_proxy_route/defaults/main.yml`
- Create: `roles/edge_proxy_route/tasks/main.yml`
- Create: `roles/edge_proxy_route/handlers/main.yml`
- Create: `roles/edge_proxy_route/templates/nginx-route.conf.j2`
- Create: `roles/edge_proxy_route/README.md`
- Create: `tests/test_edge_proxy_route_role.py`
- Create: `playbooks/edge-proxy-route.yml`

**Interfaces:**
- Consumes: `ansible.vinisantana.com`, stable controller IP, port 3000, CT host.
- Produces: known-host 200/pong routing and unchanged unknown-host 404 behavior.

- [ ] **Step 1: Write failing route tests**

Assert the template contains both HTTP/HTTPS listeners used by CT 110,
WebSocket headers, `proxy_read_timeout 3600s`, explicit server name, exact
upstream, no default server, and handler validation before reload.

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_route_is_explicit_and_websocket_safe():
    template = read("roles/edge_proxy_route/templates/nginx-route.conf.j2")
    tasks = read("roles/edge_proxy_route/tasks/main.yml")
    for expected in (
        "server_name {{ edge_proxy_route_domain }}",
        "proxy_set_header Upgrade $http_upgrade",
        "proxy_read_timeout 3600s",
        "proxy_pass {{ edge_proxy_route_upstream }}",
    ):
        assert expected in template
    assert "default_server" not in template
    assert tasks.index("nginx -t") < tasks.index("state: reloaded")
```

- [ ] **Step 2: Verify red**

Run: `rtk python3 -m pytest tests/test_edge_proxy_route_role.py -q`

- [ ] **Step 3: Implement atomic route deployment**

Render to a temporary file, copy the old managed file to a timestamped backup,
move the candidate into place, run `nginx -t`, reload only on success, and use a
rescue block to restore the old file and re-run `nginx -t`.

The location must include:

```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_read_timeout 3600s;
proxy_pass http://ANSIBLE_CONTROLLER_PRIVATE_ADDRESS:3000;
```

- [ ] **Step 4: Add probes and commit**

Probe CT 110 with the public Host header and `/api/ping`; separately probe an
unknown Host and require 404. Run tests, syntax-check, yamllint, then commit.

```bash
rtk git add roles/edge_proxy_route playbooks/edge-proxy-route.yml tests/test_edge_proxy_route_role.py
rtk git commit -m "feat: publish Semaphore through edge proxy"
```

### Task 8: Manage path-scoped Cloudflare Access

**Files:**
- Create: `roles/cloudflare_access_application/defaults/main.yml`
- Create: `roles/cloudflare_access_application/tasks/main.yml`
- Create: `roles/cloudflare_access_application/README.md`
- Create: `tests/test_cloudflare_access_role.py`
- Create: `playbooks/cloudflare-access.yml`

**Interfaces:**
- Consumes: account/zone/API token, allowed email, Access service-token ID.
- Produces: catch-all OTP app and more-specific `/api/ping` service-token app.

- [ ] **Step 1: Write failing policy tests**

Assert there are exactly two applications, `/api/ping` is more specific,
human policy allows only `me@vinisantana.com`, service policy is
`non_identity`, API token tasks are `no_log`, and no bypass policy exists.

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_access_contract_has_no_bypass():
    defaults = read("roles/cloudflare_access_application/defaults/main.yml")
    tasks = read("roles/cloudflare_access_application/tasks/main.yml")
    assert "ansible.vinisantana.com/api/ping" in defaults
    assert "me@vinisantana.com" in defaults
    assert "non_identity" in tasks
    assert "bypass" not in tasks.lower()
    assert "no_log: true" in tasks
```

- [ ] **Step 2: Verify red**

Run: `rtk python3 -m pytest tests/test_cloudflare_access_role.py -q`

- [ ] **Step 3: Implement idempotent API reconciliation**

Use `ansible.builtin.uri` against Cloudflare API v4 to list by exact domain,
create/update the two applications, list their policies, and create/update by
exact policy name. Never delete unrelated applications or policies. Store IDs
only in facts and suppress response bodies on secret-bearing calls.

Required domains:

```yaml
cloudflare_access_human_domain: ansible.vinisantana.com
cloudflare_access_health_domain: ansible.vinisantana.com/api/ping
cloudflare_access_allowed_email: me@vinisantana.com
```

- [ ] **Step 4: Verify and commit**

Run pytest, yamllint, and syntax-check without live Cloudflare calls.

```bash
rtk git add roles/cloudflare_access_application playbooks/cloudflare-access.yml tests/test_cloudflare_access_role.py
rtk git commit -m "feat: protect Semaphore with Cloudflare Access"
```

### Task 9: Add private inventory contracts and orchestration

**Files:**
- Modify in inventory repo: paths listed in the File and Interface Map.
- Modify: `playbooks/bootstrap-ansible-controller.yml`
- Create: `playbooks/deploy-ansible-controller.yml`
- Create: `playbooks/rollback-ansible-controller.yml`
- Modify: `tests/Validate-InventoryScaffold.ps1`
- Create: `tests/test_ansible_controller_playbooks.py`

**Interfaces:**
- Consumes: all roles from Tasks 2-8.
- Produces: fail-closed catalog first, then an activated one-host production inventory after live discovery.

- [ ] **Step 1: Write failing inventory and playbook assertions**

Require groups `ansible_controller_bootstrap`, `ansible_controllers`,
`github_actions_runners`, and `edge_proxy_hosts`; require disabled LXC until
VMID is discovered; require exact Semaphore/runner versions and no secret-like
values; require deploy playbook `serial: 1`, exact roles, and tags.

```powershell
foreach ($group in @(
        "ansible_controller_bootstrap",
        "ansible_controllers",
        "github_actions_runners",
        "edge_proxy_hosts"
    )) {
    Assert-FileContains -RelativePath "inventories\prod\hosts.yml" -Pattern "$group`:"
}
Assert-FileContains -RelativePath "inventories\prod\group_vars\ansible_controller_bootstrap\ansible_controller_lxc.yml" -Pattern "proxmox_lxc_guest_enabled:\s*false"
Assert-FileContains -RelativePath "inventories\prod\group_vars\ansible_controllers\semaphore.yml" -Pattern "semaphore_controller_version:\s*2\.18\.25"
Assert-FileContains -RelativePath "inventories\prod\group_vars\github_actions_runners\github_actions_runner.yml" -Pattern "github_actions_runner_version:\s*2\.335\.1"
```

- [ ] **Step 2: Verify red in both repositories**

Run:

```bash
rtk pwsh -NoProfile -File tests/Validate-InventoryScaffold.ps1
rtk python3 -m pytest tests/test_ansible_controller_playbooks.py -q
```

Expected: FAIL for missing contracts.

- [ ] **Step 3: Add fail-closed private inventory**

Before live discovery, use the role's exact public variables:

```yaml
proxmox_lxc_guest_enabled: false
proxmox_lxc_guest_vmid: 0
ansible_controller_vmid: 0
ansible_controller_management_address: ""
proxmox_lxc_guest_template_vmid: 9400
proxmox_lxc_guest_template_name: tlp-ct-debian-13
proxmox_lxc_guest_node: pve-01
proxmox_lxc_guest_storage: local-lvm
proxmox_lxc_guest_bridge: vmbr0
semaphore_controller_version: 2.18.25
github_actions_runner_version: 2.335.1
github_actions_runner_name: "ansible-prod-{{ ansible_controller_vmid }}"
```

Add `/ansible` to `infisical_secret_paths`; add all seven approved secret names
to `infisical_required_keys`; add MinIO prefixes
`ansible/semaphore-backups` and `ansible/deployments`.

- [ ] **Step 4: Add orchestration playbooks**

`bootstrap-ansible-controller.yml` applies `common_base`, `ssh_hardening`,
`github_actions_runner`, `infra_ansible_deployer`, `semaphore_controller`, and
`monitoring_agent` to `ansible_controllers`, then applies `edge_proxy_route` to
`edge_proxy_hosts`, then `cloudflare_access_application` on localhost.

`deploy-ansible-controller.yml` applies only `semaphore_controller` and
monitoring reconciliation to `ansible_controllers`.
`edge-proxy-route.yml` and `cloudflare-access.yml` remain separate so every
privileged run has an exact one-host limit. `rollback-ansible-controller.yml`
applies `semaphore_controller` with
`semaphore_controller_rollback_mode: true`, tag
`semaphore_controller_rollback`, and the backup ID written by the immediately
preceding deployment. None
of these playbooks includes `proxmox_lxc_guest` or `github_actions_runner`.

- [ ] **Step 5: Verify and commit each repository separately**

Run scaffold, `ansible-inventory --list` for staging/prod, syntax-check for all
new playbooks, pytest, and yamllint. Commit inventory changes in the inventory
repo and playbook tests in `infra-ansible` with separate commits.

---

## Milestone 3: Release Pipeline and Controlled Activation

### Task 10: Generate and verify immutable release manifests

**Files:**
- Create: `tools/release/build_release_manifest.py`
- Create: `tests/test_release_manifest.py`

**Interfaces:**
- Consumes: exact infra SHA and pinned versions/checksum.
- Produces: deterministic schema-1 JSON consumed by the deploy job.

- [ ] **Step 1: Write failing tests**

Test canonical sorted JSON, rejection of non-40-character SHA, exact values,
and no environment/secret dumping.

```python
import json

import pytest

from tools.release.build_release_manifest import build_manifest


def test_manifest_is_canonical_and_exact(tmp_path):
    target = tmp_path / "release-manifest.json"
    build_manifest("0123456789abcdef0123456789abcdef01234567", target)
    parsed = json.loads(target.read_text())
    assert parsed["schema"] == 1
    assert parsed["semaphore_version"] == "2.18.25"
    assert parsed["runner_minimum"] == "2.335.1"
    assert target.read_text().endswith("\n")


def test_manifest_rejects_non_sha(tmp_path):
    with pytest.raises(ValueError, match="40 lowercase hexadecimal"):
        build_manifest("main", tmp_path / "manifest.json")
```

- [ ] **Step 2: Verify red**

Run: `rtk python3 -m pytest tests/test_release_manifest.py -q`

- [ ] **Step 3: Implement the generator**

The generated object is exactly:

```json
{
  "infra_sha": "0123456789abcdef0123456789abcdef01234567",
  "runner_minimum": "2.335.1",
  "schema": 1,
  "semaphore_sha256": "209cf89c23710ed74e4568be129690fb5f9599b66f3cdfb55ed6c1a437c94dc9",
  "semaphore_version": "2.18.25"
}
```

Write with `sort_keys=True`, two-space indentation, and trailing newline.

- [ ] **Step 4: Verify and commit**

Run pytest and `py_compile`, then commit.

### Task 11: Add the hosted-validation and automatic-deploy workflow

**Files:**
- Create: `.github/workflows/pipeline.yml`
- Create: `tests/test_github_workflow.py`

**Interfaces:**
- Consumes: release manifest generator and self-hosted runner label.
- Produces: required `validate` check and automatic `deploy` job for main.

- [ ] **Step 1: Write failing workflow tests**

Parse the workflow as YAML and assert:

- PR and main push triggers;
- `validate` uses only `ubuntu-latest`;
- `deploy` needs `validate` and uses all four self-hosted labels;
- the exact push/ref/repository condition exists;
- no `workflow_dispatch` or `pull_request_target`;
- `contents: read`, environment `production`, concurrency
  `ansible-production`, `cancel-in-progress: false`;
- every `uses:` value ends with a 40-character SHA.

```python
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_workflow_separates_untrusted_and_production_jobs():
    workflow = read(".github/workflows/pipeline.yml")
    assert "pull_request:" in workflow
    assert "branches: [main]" in workflow
    assert "runs-on: ubuntu-latest" in workflow
    assert "runs-on: [self-hosted, linux, x64, ansible-prod]" in workflow
    assert "github.event_name == 'push'" in workflow
    assert "github.repository == 'VINIClUS/infra-ansible'" in workflow
    assert "workflow_dispatch" not in workflow
    assert "pull_request_target" not in workflow
    for ref in re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow):
        assert re.fullmatch(r"[0-9a-f]{40}", ref)
```

- [ ] **Step 2: Verify red**

Run: `rtk python3 -m pytest tests/test_github_workflow.py -q`

- [ ] **Step 3: Implement `validate` with pinned official actions**

Use these exact pins:

```yaml
- uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
- uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
- uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
- uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8
```

Run the full existing test suite, scaffold validators, syntax checks, yamllint,
ansible-lint, Docker build/smoke, generate the manifest from `${GITHUB_SHA}`,
and upload only the manifest.

- [ ] **Step 4: Implement trusted deploy**

Use:

```yaml
if: >-
  github.event_name == 'push' &&
  github.ref == 'refs/heads/main' &&
  github.repository == 'VINIClUS/infra-ansible'
runs-on: [self-hosted, linux, x64, ansible-prod]
environment: production
```

Download the manifest, verify its SHA equals `${GITHUB_SHA}`, then execute only:

```bash
sudo /usr/local/sbin/infra-ansible-deploy "$GITHUB_SHA"
```

- [ ] **Step 5: Verify and commit**

Run workflow tests, yamllint, all tests, and `git diff --check`, then commit.

### Task 12: Automate GitHub repository configuration with `gh`

**Files:**
- Create: `tools/github/Configure-GitHubActions.ps1`
- Create: `tests/Validate-GitHubActionsConfiguration.ps1`
- Create: `tools/github/README.md`

**Interfaces:**
- Consumes: authenticated `gh` session with `repo` and `workflow` scopes.
- Produces: environment, SHA policy, fork approval policy, and branch protection.

- [ ] **Step 1: Write a mock-`gh` failing test**

Capture argv and assert the script performs GET readback before/after writes,
sets `allowed_actions=selected`, `github_owned_allowed=true`,
`sha_pinning_required=true`, approval policy `all_external_contributors`,
creates `production`, and protects `main` with required check `validate`, PR,
linear history, no force push, and no deletion.

```powershell
$calls = Get-Content -LiteralPath $mockLog
foreach ($required in @(
        "repos/VINIClUS/infra-ansible/actions/permissions",
        "repos/VINIClUS/infra-ansible/environments/production",
        "repos/VINIClUS/infra-ansible/branches/main/protection"
    )) {
    if (-not ($calls -match [regex]::Escape($required))) {
        throw "Missing gh API call: $required"
    }
}
foreach ($requiredBody in @(
        '"allowed_actions":"selected"',
        '"sha_pinning_required":true',
        '"required_approving_review_count":0',
        '"allow_force_pushes":false',
        '"allow_deletions":false'
    )) {
    if (-not ($calls -match [regex]::Escape($requiredBody))) {
        throw "Missing desired setting: $requiredBody"
    }
}
```

- [ ] **Step 2: Verify red**

Run: `rtk pwsh -NoProfile -File tests/Validate-GitHubActionsConfiguration.ps1`

- [ ] **Step 3: Implement idempotent CLI writes**

The script must use `gh api` JSON bodies rather than shell interpolation, stop
on any non-2xx result, and print only setting names/states. It must not request
or print runner registration tokens. Runner registration remains in bootstrap.

- [ ] **Step 4: Verify mock calls and commit**

Run the mock test twice and assert identical intended state, then commit.

### Task 13: Seed controller secrets without disclosure

**Files:**
- Create: `tools/bootstrap/seed_ansible_controller_secrets.py`
- Create: `tests/test_seed_ansible_controller_secrets.py`
- Modify: `docs/safety.md`

**Interfaces:**
- Consumes: local Universal Auth credentials, Cloudflare API token/account, and authenticated `gh`.
- Produces: seven `/ansible` secrets, path-scoped Access service token, and a read-only inventory deploy key.

- [ ] **Step 1: Write mocked no-disclosure tests**

Mock `secrets`, subprocess, and HTTP. Assert generated values never appear in
stdout/stderr, argv, exception strings, or JSON summary. Assert rerun reports
existing names and refuses overwrite unless an explicit rotation such as
`--rotate SEMAPHORE_DB_PASSWORD` is requested.

```python
import json

import pytest

from tools.bootstrap import seed_ansible_controller_secrets as seed


def test_create_only_summary_contains_names_not_values(monkeypatch, capsys):
    monkeypatch.setattr(seed, "generate_secret_values", lambda: {"SEMAPHORE_DB_PASSWORD": "never-print-me"})
    monkeypatch.setattr(seed, "existing_secret_names", lambda: set())
    monkeypatch.setattr(seed, "write_secret", lambda name, value: None)
    result = seed.run_create_only()
    output = json.dumps(result) + capsys.readouterr().out + capsys.readouterr().err
    assert "SEMAPHORE_DB_PASSWORD" in output
    assert "never-print-me" not in output


def test_existing_secret_is_not_overwritten(monkeypatch):
    monkeypatch.setattr(seed, "existing_secret_names", lambda: {"SEMAPHORE_DB_PASSWORD"})
    with pytest.raises(RuntimeError, match="already exists"):
        seed.run_create_only()
```

- [ ] **Step 2: Verify red**

Run: `rtk python3 -m pytest tests/test_seed_ansible_controller_secrets.py -q`

- [ ] **Step 3: Implement create-only provisioning**

Generate DB/admin passwords with `secrets.token_urlsafe(48)`, encryption key
with 32 random bytes encoded as base64, age identity with `age-keygen`, and an
Ed25519 deploy key with `ssh-keygen`. Register only the public deploy key using
`gh repo deploy-key add --read-only` against `infra-ansible-inventory`. Create
the Cloudflare service token through API, and write all secret values directly
to Infisical through authenticated HTTP request bodies. Return only:

```json
{
  "cloudflare_service_token_id": "non-secret Cloudflare resource ID",
  "created_names": ["secret names only"],
  "existing_names": ["secret names only"],
  "missing_names": []
}
```

Record `cloudflare_service_token_id` as
`cloudflare_access_service_token_id` in the private inventory; unlike the
client ID and client secret, this policy resource ID is not authentication
material.

- [ ] **Step 4: Verify, document, and commit**

Run mocked tests and a dry-run that lists names only. Document rotation and
recovery without values. Commit.

### Task 14: Perform the one-time bootstrap and activate the inventory

**Files:**
- Modify with discovered values: private inventory LXC and host files.
- No secret values are written to Git.

**Interfaces:**
- Consumes: implemented roles, live read-only Proxmox inventory, seeded secrets.
- Produces: running LXC, stable DHCP lease, trusted SSH host key, online runner, healthy internal Semaphore.

- [ ] **Step 1: Run all offline verification**

Run full pytest, all PowerShell validators, syntax-check for every playbook,
yamllint, ansible-lint, Docker build/smoke, and both inventory parses. Stop on
any failure.

- [ ] **Step 2: Run read-only Proxmox preflight**

Load `.env` in memory with CRLF normalization, force `ALLOW_PVE_WRITE=false`,
run ProxmoxMCP inventory, query `/cluster/nextid`, and dry-run the exact LXC
plan. Verify template VMID 9400 remains unprivileged Debian DHCP on `vmbr0` with
32 GiB rootfs.

- [ ] **Step 3: Record the free VMID and enable only bootstrap**

Set the returned free integer in both `ansible_controller_vmid` and
`proxmox_lxc_guest_vmid`, set `proxmox_lxc_guest_enabled: true`, keep controller management address
empty, validate the inventory, and commit the non-secret contract.

- [ ] **Step 4: Create the LXC with exact tag and limit**

Use `Invoke-InfisicalAnsible.ps1` with secret path `/proxmox`, required token
keys, playbook `playbooks/provision-ansible-controller.yml`, limit
`ansible-controller-bootstrap`, and tag `proxmox_lxc_guest`. Capture only the
redacted summary.

- [ ] **Step 5: Establish stable network and SSH trust**

Read the guest MAC/IP from Proxmox, create/confirm the DHCP reservation through
the DHCP server that issued the lease, reboot once, prove the address is
stable, collect the SSH host key out-of-band, compare it on first connection,
and commit the management address and `known_hosts` fingerprint contract to
private inventory. If the DHCP server has no authenticated API/CLI already
available in the workspace, stop after reporting only the MAC and leased
address and require the operator to confirm the reservation; do not guess
router credentials or replace the approved DHCP contract with a static IP.

- [ ] **Step 6: Bootstrap services and runner**

Generate a short-lived runner registration token with `gh api` into an
environment variable, run `bootstrap-ansible-controller.yml` with exact limit
and tags, unset the token immediately, and verify local Semaphore health and
runner systemd state. Do not configure the public route until these pass.

- [ ] **Step 7: Commit only non-secret activation data**

Run secret-pattern scans, inventory validation, and `git diff --check`, then
commit activated host, VMID, address, fingerprint, and version metadata in the
private inventory repository.

### Task 15: Publish, configure GitHub, and prove automatic rollout

**Files:**
- Modify: `docs/architecture.md`
- Modify: `docs/safety.md`
- Create: `docs/runbook-ansible-controller.md`

**Interfaces:**
- Consumes: bootstrapped runner and committed pipeline.
- Produces: protected main, automatic deployment, public Access route, tested rollback, and operational runbook.

- [ ] **Step 1: Publish the reviewed local history without force**

Fetch origin, prove local `main` is a descendant of `origin/main`, run the full
suite, and use a normal push. Abort if a force push would be required.

- [ ] **Step 2: Run hosted CI before branch protection**

Use `gh run watch` to observe the first `validate` job. Confirm the self-hosted
deploy job is skipped on the feature branch and that the manifest contains the
tested SHA only.

- [ ] **Step 3: Apply and read back GitHub settings**

Run `Configure-GitHubActions.ps1`, then verify workflow, `production`
environment, runner labels/status, SHA pinning, fork approval policy, and branch
protection with both `gh api` and GitHub MCP. Resolve any disagreement before
merging.

- [ ] **Step 4: Configure edge and Cloudflare Access**

Apply the route and Access roles with exact tags. Verify direct port 3000 is
blocked from a non-CT110 source, CT 110 Host-header `/api/ping` returns `pong`,
unknown Host returns 404, browser access prompts OTP, and the service token is
accepted only on `/api/ping`.

- [ ] **Step 5: Merge a no-op version marker and observe automatic deploy**

Merge a reviewed change to `main`, watch `validate` then `deploy`, and verify
the deployed SHA equals the merge SHA, the runner remains online, and a second
reconciliation has zero material changes.

- [ ] **Step 6: Exercise controlled rollback**

Use the test-only failure injection variable restricted to the staging/check
path to fail after migration. Prove DB/config/symlink restoration and healthy
old `/api/ping`; then remove the injection and run the production path normally.

- [ ] **Step 7: Verify encrypted backup and evidence**

List MinIO object names only. Confirm a pre-change encrypted backup and redacted
deployment report exist under their declared prefixes; download to a protected
temporary directory, verify age decryption and `pg_restore --list`, then delete
the plaintext temporary files.

- [ ] **Step 8: Complete documentation and final verification**

Document bootstrap, upgrades, runner maintenance, secret rotation, Access,
backup restore, rollback, and emergency runner disable. Run the full suite one
last time and commit documentation/evidence references without secret values or
raw infrastructure API responses.

---

## Final Verification Commands

Run from `infra-ansible`:

```bash
rtk python3 -m pytest tests -q
rtk pwsh -NoProfile -File tests/Validate-InfraAnsibleScaffold.ps1
rtk pwsh -NoProfile -File tests/Validate-AnsibleContainer.ps1
rtk pwsh -NoProfile -File tests/Validate-ProxmoxBackupStorageRole.ps1
rtk pwsh -NoProfile -File tests/Validate-GitHubActionsConfiguration.ps1
rtk ansible-playbook -i inventories/example/hosts.yml playbooks/provision-ansible-controller.yml --syntax-check
rtk ansible-playbook -i inventories/example/hosts.yml playbooks/bootstrap-ansible-controller.yml --syntax-check
rtk ansible-playbook -i inventories/example/hosts.yml playbooks/deploy-ansible-controller.yml --syntax-check
rtk ansible-playbook -i inventories/example/hosts.yml playbooks/rollback-ansible-controller.yml --syntax-check
rtk ansible-playbook -i inventories/example/hosts.yml playbooks/edge-proxy-route.yml --syntax-check
rtk ansible-playbook -i inventories/example/hosts.yml playbooks/cloudflare-access.yml --syntax-check
rtk yamllint .
rtk ansible-lint
rtk docker build -t infra-ansible-tools:verify -f tools/ansible/Dockerfile .
```

Run from `infra-ansible-inventory`:

```bash
rtk pwsh -NoProfile -File tests/Validate-InventoryScaffold.ps1
rtk ansible-inventory -i inventories/staging/hosts.yml --list >/dev/null
rtk ansible-inventory -i inventories/prod/hosts.yml --list >/dev/null
rtk yamllint inventories
```

Live acceptance is complete only when internal/external health, runner API
readback, branch protection, automatic deployment, idempotent rerun, induced
rollback, and encrypted backup restore verification all pass.
