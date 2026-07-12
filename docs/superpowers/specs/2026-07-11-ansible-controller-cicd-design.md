# Ansible Controller LXC and CI/CD Design

**Date:** 2026-07-11

**Status:** Approved design

## Purpose

Deploy a production Ansible controller named `ansible` as an unprivileged
Debian LXC on Proxmox VE, expose Semaphore UI/API at
`https://ansible.vinisantana.com`, and roll out the validated infrastructure
release automatically after every merge to `VINIClUS/infra-ansible` `main`.

The GitHub Actions runner is a reusable executor node. Its role must work on
Debian or Ubuntu, whether the host is an LXC or a VM, and must not be coupled to
the Semaphore process or release layout.

## Current State

- `infra-ansible` is public, has no workflows or self-hosted runners, and its
  remote `main` is not yet protected.
- `infra-ansible-inventory` is private and owns production topology and
  non-secret runtime contracts.
- `tools/ansible/Dockerfile` provides the existing CI/local Ansible tool image.
- Infisical is the secret source, MinIO is the artifact and backup target, and
  CT 110 (`nginx`) is the established edge proxy.
- Proxmox VE 9.1.1 has one online node, `pve-01`, bridge `vmbr0`, sufficient
  capacity on `local-lvm`, and an unprivileged Debian 13 LXC template named
  `tlp-ct-debian-13`.
- Semaphore UI 2.18.25 and GitHub Actions Runner 2.335.1 are the stable versions
  selected at design time.
- ProxmoxMCP supports read-only inventory and LXC dry-run planning but
  deliberately does not implement real LXC execution.

## Repository Boundaries

### `infra-ansible`

Owns reusable roles, playbooks, workflow definitions, tests, documentation,
the privileged deployment wrapper, and GitHub configuration automation.

### `infra-ansible-inventory`

Owns the selected VMID, DHCP-reserved management address, Proxmox node,
template, bridge, storage, sizing, Semaphore version, edge route, allowed
Cloudflare Access identity, secret names, MinIO prefixes, and host/group
membership. It never stores secret values.

### Infisical

Owns Universal Auth bootstrap credentials and all runtime secret values. The
controller identity is restricted to `/ansible`, `/minio`, and `/edge-proxy`.
Proxmox write credentials are used only from the trusted bootstrap station and
are not retained on the controller.

### ProxmoxMCP

Provides read-only inventory and LXC plan validation before bootstrap. The
initial write uses the reviewed `community.proxmox.proxmox` Ansible role because
real LXC execution remains blocked in ProxmoxMCP. Ongoing `main` deployments do
not manage LXC lifecycle.

## Architecture

Public traffic follows this path:

```text
Browser or health client
  -> Cloudflare Access
  -> Cloudflare proxied DNS
  -> CT 110 Nginx
  -> ansible LXC private address:3000
  -> Semaphore
```

Deployment follows this path:

```text
merge to infra-ansible/main
  -> GitHub-hosted validation job
  -> immutable release manifest for the tested SHA
  -> repo-scoped self-hosted runner on ansible LXC
  -> root-owned fixed deployment wrapper
  -> Infisical allowlisted secret injection
  -> Ansible reconciliation using private inventory
  -> backup, migrate, switch release, health checks, evidence
```

The first bootstrap is deliberately separate because the target runner does
not exist yet. A trusted workstation performs read-only preflight, creates the
LXC, applies the baseline, installs the runner, installs Semaphore, configures
the edge route, and verifies the public service. After bootstrap, Semaphore
rollouts are automatic.

## LXC Contract

The `proxmox_lxc_guest` role creates the guest once and has no absent, delete,
or automatic recreation path.

- template: `tlp-ct-debian-13`
- node: `pve-01`
- container mode: unprivileged, required
- CPU: 2 vCPU
- memory: 4096 MiB
- root disk: 32 GiB on `local-lvm`
- bridge: `vmbr0`, guest firewall enabled
- network: DHCP with a stable reservation
- startup: `onboot: true`
- nesting: disabled
- Docker: not installed or required

The bootstrap reads `/cluster/nextid`, verifies that the candidate is unused,
and records the chosen VMID in the private inventory before creation. It then
confirms that the stable DHCP lease and SSH host key are recorded before the
host joins the `ansible_controllers` group or is published through CT 110.

If an existing VMID differs in hostname, template provenance, unprivileged
mode, disk, bridge, or node, the role fails without mutation. Creation requires
an exact one-host limit and the `proxmox_lxc_guest` tag.

## Reusable Roles

### `proxmox_lxc_guest`

Runs on localhost during bootstrap. It validates the live Proxmox inventory,
the template contract, the explicit VMID, and absence of conflicts, then
creates and starts the LXC idempotently. It does not run during steady-state
deployments.

### `github_actions_runner`

Supports Debian 12/13 and Ubuntu 22.04/24.04 or newer supported releases on an
LXC or VM. It creates a dedicated unprivileged user, verifies the official
runner archive, registers with a short-lived token, installs systemd, applies
labels, and verifies the runner through the GitHub API. The initial selected
version is 2.335.1. Official self-update remains enabled so the runner does not
expire; the role records and reports the effective version.

The role is lifecycle-independent from Semaphore. It is applied during
bootstrap or maintenance, not from a deployment job currently running on that
same runner.

### `semaphore_controller`

Installs PostgreSQL from the supported Debian packages and Semaphore 2.18.25
from the official amd64 `.deb`. The package checksum is pinned. The package is
extracted into `/opt/semaphore/releases/<version>` without global installation,
and `/opt/semaphore/current` selects the active release.

Persistent state remains outside releases:

- `/etc/semaphore` for root-readable configuration;
- `/var/lib/postgresql` for the database;
- `/var/lib/semaphore` for controller state;
- `/var/backups/semaphore` for short-lived encrypted staging;
- `/var/lib/infra-ansible/deployments` for redacted deployment manifests.

Semaphore and the GitHub runner use separate Unix users. Semaphore listens on
port 3000. The guest firewall accepts that port only from localhost and CT 110.

### `edge_proxy_route`

Owns one Nginx vhost for `ansible.vinisantana.com`, including forwarded
headers, WebSocket upgrade, long task timeouts, upstream health validation, and
atomic rollback. It runs `nginx -t` before reload and checks the route by Host
header afterward. Unknown hosts continue to return 404 from the existing
default server.

## GitHub Actions Security Boundary

The runner is registered to the public `VINIClUS/infra-ansible` repository as
requested. This has more risk than a private repository or restricted
organization runner group. The following controls are mandatory:

- PR validation uses only GitHub-hosted runners.
- The `ansible-prod` label appears only in the main deployment job.
- The deployment job requires a `push` event, `refs/heads/main`, the exact
  repository name, and a successful validation job from the same workflow.
- `workflow_dispatch` and `pull_request_target` cannot target the production
  runner.
- Fork workflows require approval for all outside contributors.
- Actions are GitHub-owned and pinned to full commit SHAs.
- Repository settings require action SHA pinning.
- The runner user has no general sudo access and cannot read deployment
  secrets.
- The privileged wrapper independently queries the public GitHub API and
  accepts only the current 40-character `main` SHA, a clean checkout, and fixed
  playbook, inventory, host, and tag values.
- `main` requires PRs, the validation check, linear history, and blocks force
  pushes and deletion.

Arbitrary untrusted code on a persistent self-hosted runner remains a residual
risk for a public repository. Moving the repository to an organization runner
group restricted to a selected workflow is the future hardening path; it is
not required for the first release.

## Pipeline

`.github/workflows/pipeline.yml` handles both pull requests and pushes to
`main`.

### `validate` job

Runs on `ubuntu-latest` and performs:

- Python tests;
- PowerShell scaffold and role validators;
- `yamllint`, `ansible-lint`, and Ansible syntax checks;
- inventory parsing with secret values absent;
- build and smoke test of `tools/ansible/Dockerfile`;
- workflow static validation;
- creation of `release-manifest.json` containing the Git SHA, Semaphore
  version, runner minimum, source artifact checksum, and schema version.

### `deploy` job

Needs `validate`, runs only for a push to `main`, targets
`[self-hosted, linux, x64, ansible-prod]`, and records a deployment in the
`production` environment without a manual approval. A GitHub concurrency group
named `ansible-production` never cancels an in-progress production rollout.
A second host-local `flock` protects against duplicate execution.

The workflow has `contents: read` permission. Runtime secrets do not live in
GitHub Actions. The deployment wrapper obtains them from Infisical on the host.

Every successful merge reconciles the exact SHA of `infra-ansible`. Semaphore
changes only when the pin in private inventory changes. Idempotent merges still
produce a deployment record and health evidence without reinstalling the
binary.

## GitHub Configuration Procedure

Configuration uses `gh` for writes and both `gh` and GitHub MCP for readback:

1. Commit and push the workflow.
2. Run the first hosted validation successfully.
3. Create the `production` environment.
4. Generate a short-lived repository runner registration token without
   logging it, install the runner, and discard the token.
5. Confirm runner name, status, labels, and scope through CLI and MCP.
6. Restrict Actions policy and require full SHA pinning.
7. Configure branch protection with the exact validation check name.
8. Read back workflows, environment, runner, permissions, fork approval
   policy, and branch protection through CLI and MCP.

The current remote branch trails the reviewed local `main`; implementation
must verify and publish that non-force history before GitHub settings can refer
to the new workflow.

## Cloudflare Access and Edge

`ansible.vinisantana.com` remains a proxied Cloudflare hostname routed through
CT 110. Cloudflare Access uses two path-scoped applications so the automation
credential cannot open the interactive UI:

- a catch-all application for human access through One-Time PIN restricted to
  `me@vinisantana.com`;
- a more-specific `/api/ping` application with a `non_identity` service-token
  policy used only by automated health checks.

Semaphore retains its own local authentication and project RBAC as a second
layer. The initial administrator password is a bootstrap secret and must be
rotated after first login. The external check sends the Access service-token
headers to the path-scoped application and requires `GET /api/ping` to return
HTTP 200 with `pong`; the same token is denied by the catch-all application.

## Secret Contract

The `/ansible` folder contains:

- `SEMAPHORE_DB_PASSWORD`
- `SEMAPHORE_ACCESS_KEY_ENCRYPTION`
- `SEMAPHORE_ADMIN_PASSWORD`
- `ANSIBLE_EDGE_SSH_PRIVATE_KEY`
- `INFRA_INVENTORY_DEPLOY_KEY`
- `ANSIBLE_BACKUP_AGE_IDENTITY`
- `CLOUDFLARE_ACCESS_CLIENT_ID`
- `CLOUDFLARE_ACCESS_CLIENT_SECRET`

Existing `/minio` object-storage credentials and `/edge-proxy` Cloudflare
credentials are reused under their existing allowlisted names. The age
recipient is public and stored in inventory; the private identity remains only
in Infisical.

The root-owned Universal Auth bootstrap file is mode 0600. The runner user
cannot read it. The wrapper obtains a short-lived token, fetches only required
names, removes bootstrap variables, and invokes Ansible with `no_log` on all
secret-bearing tasks. Secrets are never command-line values, GitHub artifacts,
workflow outputs, or unencrypted MinIO objects.

The dedicated edge key is provisioned separately from the seven generated
controller bootstrap secrets. The deployer validates its OpenSSH private-key
envelope and installs it as root-only mode 0600 at
`/etc/infra-ansible-deploy/edge-ssh-key`; inventory contains only that public
path.

## Rollout and Rollback

The deployment transaction is:

1. Validate Infisical access, MinIO access, free disk, PostgreSQL health,
   current release, inventory SHA, and GitHub main SHA.
2. Create a PostgreSQL custom-format dump and configuration archive.
3. Encrypt both with age and require successful MinIO upload.
4. Download the pinned Semaphore release and verify its checksum.
5. Extract the immutable release.
6. Stop Semaphore and apply the target database migration with the new binary.
7. Atomically switch `current` and start Semaphore.
8. Require systemd active state, database access, and local `/api/ping` =
   `200 pong`.
9. Require CT 110 Host-header routing and external Cloudflare Access health.
10. Write a redacted deployment record locally, to MinIO, and to the GitHub job
    summary.

Any failure after migration enters a rescue block that stops Semaphore,
restores the database and configuration from the just-created local encrypted
backup, restores the previous symlink, restarts the prior binary, and repeats
internal health checks. A failed final evidence upload marks the workflow
failed but does not roll back an already healthy application.

Daily PostgreSQL backups run from a separate systemd timer and use the same
encryption and MinIO path. Full-guest `vzdump` backup remains separate and
disabled until the persistent `infra-backups` Proxmox storage contract is
activated.

## Testing Strategy

### Static and unit tests

- Validate role defaults, assertions, tags, and forbidden destructive states.
- Validate secret allowlists and ensure rendered logs/config fixtures redact
  secret values.
- Validate the privileged wrapper rejects non-main SHAs, malformed SHAs,
  altered checkout state, alternate inventory, alternate host, and alternate
  tags.
- Validate release manifest schema and SHA/checksum consistency.

### Role integration matrix

Exercise `github_actions_runner` on Debian 13 and Ubuntu 24.04 systemd test
guests. Cover clean install, idempotent rerun, labels, effective version,
service restart, and safe unregister. Assert that virtualization detection does
not branch into LXC-only or VM-only behavior.

Exercise `semaphore_controller` through clean install, unchanged rerun,
version upgrade, migration failure, missing secret, failed backup upload, local
health failure, external health failure, and successful rollback.

Exercise `edge_proxy_route` with configuration syntax failure, upstream
failure, atomic restore, WebSocket headers, known Host routing, and unknown Host
404 behavior.

### Proxmox validation

Run ProxmoxMCP read-only inventory and LXC dry-run before bootstrap. Test free
VMID selection, occupied VMID refusal, template mismatch, privileged template
refusal, wrong bridge, and check-mode. The role has no test or production path
that deletes an LXC.

## Observability

- Separate journald units for Semaphore, runner, deploy, and backup.
- Existing `monitoring_agent` role on the controller.
- Systemd, disk, and PostgreSQL health monitoring.
- Internal and external `/api/ping` probes.
- GitHub API check that the runner remains online.
- Version report containing the deployed infra SHA, Semaphore version, and
  effective runner version.
- Daily read-only drift report.
- Redacted evidence under the existing `ansible/reports` MinIO prefix.

## Acceptance Criteria

- The guest is demonstrably unprivileged, uses no nesting, and has no Docker
  dependency.
- Direct port 3000 access is blocked except from localhost and CT 110.
- `ansible.vinisantana.com` requires Cloudflare Access.
- `me@vinisantana.com` can authenticate and then use Semaphore authentication.
- The service token reaches the health endpoint but grants no interactive user
  session.
- A merge to `main` automatically deploys the exact validated SHA.
- A second deployment produces no material infrastructure or service change.
- An induced post-migration failure restores the prior binary, database, and
  healthy internal endpoint.
- The runner stays online while Semaphore rolls out.
- The runner role passes its Debian and Ubuntu integration matrix.
- No secret appears in Git, logs, GitHub artifacts, workflow outputs, or
  unencrypted MinIO objects.
- `gh` and GitHub MCP readback agree on workflow, environment, runner, Actions
  policy, and branch protection state.

## Non-Goals

- High-availability Semaphore or PostgreSQL.
- Automatic LXC deletion, replacement, or scaling.
- Running Docker inside the LXC.
- Exposing Semaphore directly to the Internet or bypassing CT 110.
- Triggering arbitrary production playbooks from GitHub workflow inputs.
- Enabling the currently disabled Proxmox full-guest backup storage.
- Moving the runner to an organization runner group in the first release.
