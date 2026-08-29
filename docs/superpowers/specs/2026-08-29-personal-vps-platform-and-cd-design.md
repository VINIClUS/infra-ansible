# Personal VPS Platform and GitHub-hosted CD Design

**Date:** 2026-08-29  
**Status:** Draft for repository review; architecture approved in design discussion  
**Repository:** `VINIClUS/infra-ansible`  
**Integration base:** `main`

## 1. Purpose

Extend `infra-ansible` with reusable, disabled-by-default automation for a
personal Hostinger VPS platform that hosts the CnesData and LimnoPulse APIs and
workers. Static web bundles remain outside the VPS and are delivered by private
S3 origins through CloudFront.

The design must:

- harden SSH without creating a lockout path;
- expose APIs and SSH only through Cloudflare Tunnel;
- run application containers without granting deployment users general Docker
  access;
- replace the municipal Infisical dependency with AWS Systems Manager
  Parameter Store, AWS KMS and IAM Roles Anywhere;
- support GitHub-hosted validation and manually approved production delivery on
  GitHub Free;
- preserve the existing municipal Ansible controller pipeline unchanged;
- keep additional monthly infrastructure spend within the approved aggregate
  ceiling of USD 20, with USD 15 as the operational ceiling.

## 2. Existing repository boundary

`infra-ansible` is public and owns reusable roles, playbooks, tests and examples.
It must not contain real inventory, account IDs, VPS IP addresses, secret values,
private certificates, Cloudflare identifiers or production state.

The existing `infra-ansible-inventory` repository remains the private inventory
for the municipal/Proxmox environment. Its Protocolos, Semaphore, Infisical,
MinIO, internal-address and self-hosted-runner contracts must not be imported by
the personal platform.

The current `infra-ansible` workflow may continue reconciling the municipal
controller after a merge to `main`. Every role introduced by this design is
therefore inert unless an inventory sets an explicit enable flag. A normal
municipal deployment after the merge must produce no personal-platform action
and no change to an existing municipal host.

Environment-specific composition belongs to a new private repository named
`personal-infra-live`, defined by the companion design. That repository pins an
exact `infra-ansible` commit and performs personal production delivery from
GitHub-hosted runners.

## 3. Scope

### 3.1 Included reusable capabilities

- Debian host preflight and immutable evidence report;
- staged administrative-user creation and SSH hardening;
- host firewall policy and Hostinger-firewall verification contract;
- Docker Engine/Compose installation without deploy-user group membership;
- root-owned application directories and systemd/Compose units;
- one Cloudflare Tunnel service with API and SSH ingress contracts;
- host Nginx API gateway, real-client-IP restoration and rate limiting;
- restricted application deployment command and rollback ledger;
- IAM Roles Anywhere credential renewal outside application containers;
- native Grafana Alloy service and bounded journald retention;
- consistent InfluxDB backup to private S3;
- preflight, health, rollback and disaster-recovery validation.

### 3.2 Explicit non-goals

- storing personal production inventory in this public repository;
- changing the existing `ansible-prod` self-hosted runner or Infisical flow;
- using the municipal controller, MinIO, Infisical, Proxmox or network as a
  dependency of personal services;
- hosting frontend assets on Nginx or the VPS;
- exposing Docker, InfluxDB, Mosquitto, Alloy, application ports or Nginx
  directly to the Internet;
- installing Kubernetes, a service mesh or a self-hosted Grafana stack;
- automatically changing Hostinger firewall rules from a generic role;
- executing destructive cleanup, filesystem replacement or server recreation.

## 4. Target host contract

The live inventory identifies one Hostinger KVM VPS by a non-secret alias. The
public example uses `personal_vps_example`; it does not contain the real
hostname or address.

Before any mutation, `personal-vps-preflight.yml` must collect and fail closed
on:

- unsupported operating system or release;
- less than the deployment's declared CPU, RAM or free-disk minimum;
- active package-manager transactions;
- unhealthy filesystem, failed systemd units or unresolved boot failure;
- unknown SSH host key;
- absence of a recent Hostinger backup or an operator-confirmed snapshot for a
  high-risk phase;
- ports already owned by an undeclared process;
- Docker data root located on an unexpected filesystem;
- existing users, sudo rules, Nginx config, firewall state or application
  directories that conflict with the declared contract;
- a public listener on an application, database, MQTT or observability port.

The preflight produces a redacted JSON report and changes nothing. Hostinger
backup, snapshot and provider-firewall state are read and confirmed through a
Hostinger read-only preflight or hPanel evidence before the apply gate. Their
unknown state is a blocker, never an assumed success.

## 5. Staged SSH and firewall hardening

SSH hardening is a two-apply transaction with a mandatory human checkpoint.

### 5.1 Stage A — establish alternate access

Stage A:

1. creates a named non-root human administrator;
2. installs only declared Ed25519 public keys;
3. creates separate `cnesdata-deploy`, `limnopulse-deploy` and
   `platform-deploy` automation users;
4. installs forced-command entries for automation keys;
5. installs narrow sudoers fragments validated with `visudo -cf`;
6. installs and starts `cloudflared` with SSH ingress;
7. validates a new human session through `ssh.vinisantana.com` and a separate
   automation session through Cloudflare Access;
8. leaves root login and the existing public SSH path unchanged.

The operator must keep the original root session open while the two alternate
sessions are tested. Stage B cannot run in the same Ansible invocation.

### 5.2 Stage B — close legacy access

Stage B requires an explicit inventory acknowledgement containing the Stage A
evidence digest. It then:

- sets `PermitRootLogin no`;
- sets `PasswordAuthentication no`, `KbdInteractiveAuthentication no` and
  `AuthenticationMethods publickey`;
- rejects empty passwords and disables forwarding features not required by the
  forced commands;
- applies connection/startup limits and a bounded authentication retry count;
- reloads SSH only after `sshd -t` succeeds;
- applies a default-deny host firewall with loopback and established traffic
  allowed;
- verifies that Hostinger's provider firewall has no public allow rule for TCP
  22, 80 or 443;
- reruns human and automation access checks after both layers are active.

The host firewall allows outbound DNS, NTP, HTTPS and Cloudflare Tunnel traffic.
It does not require inbound ports for the applications, API gateway or SSH.
Provider-firewall edits remain a separately approved Hostinger operation because
an incorrect rule can lock out the server.

### 5.3 Recovery

If a post-reload access probe fails, the open Stage A session restores the
previous SSH and host-firewall files from the transaction directory and reloads
the prior configuration. Provider-firewall closure happens only after OS-level
rollback has been tested. Recovery mode or snapshot restoration is never
automatically invoked.

## 6. Container and filesystem boundary

The existing `container_runtime` role is extended without changing its current
defaults. The personal profile selects a mode that installs Docker and Compose
but adds no human or deployment user to the `docker` group.

Root owns:

```text
/etc/personal-platform/
/etc/personal-platform/apps/<app>/
/opt/personal-platform/releases/<app>/<release-id>/
/srv/<app>/
/var/lib/<app>/
/var/log/<app>/
/var/lib/personal-platform/deployments/
/run/personal-platform/<app>/
```

Application containers must use:

- a non-root UID/GID;
- `read_only: true` where supported;
- explicit writable tmpfs and named-volume mounts;
- `no-new-privileges:true`;
- `cap_drop: [ALL]`, with a reviewed capability added only when unavoidable;
- explicit memory, CPU, PID and log-size limits;
- loopback-only published ports;
- health checks, bounded stop grace periods and restart policies;
- one internal network per application and no shared default network;
- immutable OCI digests rather than mutable deployment tags.

InfluxDB is the only persistent application database on the VPS. It receives a
dedicated volume and is never replaced during an API release transaction.

## 7. Restricted deployment boundary

Each automation user is forced to one root-owned dispatcher. The SSH command
line never selects an arbitrary executable, playbook, Compose file, path, image
registry or service.

The dispatcher accepts a length-prefixed standard-input protocol. Its first
frame is a non-secret, versioned JSON release manifest with:

```json
{
  "schema_version": 1,
  "project": "cnesdata",
  "source_repository": "VINIClUS/CnesData",
  "source_sha": "40-character-sha",
  "images": {"api": "registry/repository@sha256:digest"},
  "static_release": "optional-release-id",
  "compose_sha256": "sha256",
  "requested_action": "deploy"
}
```

For a private registry pull, an optional second frame carries the workflow's
ephemeral bearer credential. The dispatcher accepts that frame only for the
manifest's allowlisted repository and registry, enforces a strict size limit,
never places it in an argument, environment variable, log or evidence file,
and consumes it directly into the temporary Docker configuration. Public-image
deployments omit the frame.

Validation rejects:

- unknown projects, repositories, services or manifest versions;
- non-digest image references;
- paths, shell metacharacters or additional arguments;
- a source SHA without a successful, recorded CI gate;
- compose/config checksums that do not match the release artifact;
- concurrent deployment of the same application;
- rollout while a host safety or cost-freeze marker is active.

The privileged helper can only pull, validate, start a candidate, switch the
Nginx upstream, stop the prior candidate after health succeeds, or restore the
immediately preceding manifest. It cannot prune images globally, delete
volumes, execute a shell, change another application or alter the base host.

Private GHCR pulls use the workflow's ephemeral, `packages:read`-only
`GITHUB_TOKEN` through a temporary mode-0700 Docker configuration under
`/run`. The package is explicitly linked to its source repository. The
configuration is removed on every exit path and is never reused as a host
credential.

## 8. Cloudflare Tunnel and Nginx

One named Cloudflare Tunnel serves:

- `ssh.vinisantana.com` to the local SSH service through an Access policy;
- `api.cnesdata.vinisantana.com` to the CnesData Nginx virtual host;
- `api.limnopulse.com` to the LimnoPulse Nginx virtual host.

The tunnel config is root-owned and validated before service reload. Nginx
listens only on loopback. Because direct inbound HTTP is blocked, Nginx may
trust `CF-Connecting-IP` only from the local tunnel transport; client-supplied
forwarding headers from any other source are discarded.

Initial rate-limit profiles are deployment variables with safe defaults:

| Zone | Default | Example scope |
|---|---:|---|
| `api_general` | 10 requests/second, burst 20 | ordinary authenticated reads |
| `auth_sensitive` | 5 requests/minute, burst 5 | login/token-adjacent endpoints |
| `expensive_mutation` | 2 requests/minute, burst 2 | jobs, exports and expensive actions |

Nginx returns `429` with a request ID and no implementation details. The
application retains tenant/user/API-key quotas because an IP limit cannot
enforce business-level fairness. Cloudflare Free supplies the outer rule for
the most sensitive public endpoint only; the design does not assume paid WAF
or unlimited edge rules.

Nginx also enforces bounded request bodies, header sizes, upstream timeouts and
connection counts. Health endpoints receive a separate low-cost limit and must
not reveal dependencies or secret configuration.

## 9. Runtime secrets and temporary AWS credentials

Infisical is not part of the personal profile. The public role exposes a
backend-neutral contract, while `personal-infra-live` selects:

- SSM Parameter Store Standard parameters in `us-east-2`;
- one customer-managed KMS key with annual rotation;
- GitHub OIDC for workflow sessions;
- IAM Roles Anywhere for VPS sessions;
- an externally managed offline root CA, with no AWS Private CA.

Each application has a distinct Roles Anywhere certificate, private key,
profile and IAM role. The root CA private key never reaches the VPS.

A root-only systemd credential renewer:

1. invokes `aws_signing_helper` with the application's certificate/key;
2. obtains a short-lived role session;
3. writes the shared-credentials file atomically beneath
   `/run/personal-platform/<app>/aws/`;
4. assigns the application UID and mode 0400;
5. refreshes before half the remaining session lifetime or immediately after a
   failed credential health check;
6. leaves the last still-valid file in place if refresh is transiently
   unavailable;
7. marks the application unhealthy before expiry rather than falling back to a
   static access key.

Containers bind-mount only their application-specific temporary credential
directory and public AWS config read-only. Mounting the directory, rather than
one file inode, makes the host's atomic file replacement visible inside the
container. They cannot read the X.509 private key, root CA material or another
application's session. Runtime secret rendering follows the same tmpfs and
atomic-file pattern and never creates a persistent `.env` file.

## 10. Observability

Grafana Alloy runs as a native, unprivileged systemd service. It does not mount
the Docker socket and does not run as a privileged container.

It collects:

- host CPU, memory, disk and filesystem metrics;
- explicitly exposed loopback application metrics;
- selected systemd/journald units;
- Nginx, cloudflared, deploy and backup outcomes;
- bounded traces only when an application explicitly exports OTLP locally.

Local journald retention is capped at seven days and 512 MiB. Remote Grafana
Cloud Free budgets are below 5,000 active series, 5 GB logs and 2 GB traces per
month. Labels containing tenant IDs, users, emails, tokens, object keys or
unbounded request IDs are forbidden.

CloudWatch remains authoritative for AWS service alarms. Container Insights is
not enabled. Fargate logs retain seven days.

## 11. InfluxDB backup

The reusable backup role performs a consistent daily InfluxDB 2 backup into a
root-only staging directory, verifies the generated manifest, uploads to a
private versioned S3 bucket in `us-east-2`, verifies object size/checksum and
removes staging data.

Retention is:

- seven daily copies;
- four weekly copies;
- three monthly copies.

The uploader's Roles Anywhere role may write the backup prefix but cannot
delete objects, change retention or bypass Object Lock Governance. A separate
lifecycle policy performs expiration. Backup failure is alerted and never
silently replaced by a filesystem-only success.

Quarterly restore drills use an isolated temporary InfluxDB instance and never
overwrite the production volume.

## 12. CI and delivery model

The public repository keeps its current hosted validation and municipal deploy
job. New tests prove that personal roles remain disabled in the example and
municipal inventories unless explicitly selected.

Personal production delivery runs only from `personal-infra-live`:

1. a GitHub-hosted job checks out exact pinned revisions;
2. validation runs syntax, lint, unit/contract tests and check mode;
3. AWS OIDC obtains a short-lived plan/deploy session;
4. SSM supplies the Cloudflare Access service token and dedicated SSH key only
   to the in-memory job;
5. a plan artifact is bound to repository, commit, inventory digest, host-key
   fingerprint and expiration;
6. a separate `workflow_dispatch` verifies and applies that exact artifact;
7. logs and artifacts contain names and hashes, never secret values;
8. the paid GitHub Actions spending limit remains USD 0.

No protected private Environment feature is assumed. The hard gate is the
separate manual workflow plus cryptographic binding to the prior plan. A plan
expires after 24 hours and cannot be applied after inventory, dependency or
target-host drift.

## 13. Failure handling and rollback

Every modifying role uses preflight, staged files, native validation and a
rescue path. The transaction directory records only redacted prior-state hashes
and restorable configuration copies.

- Invalid `sshd`, Nginx, cloudflared, Alloy or systemd configuration is never
  installed or reloaded.
- Candidate application failure leaves the current upstream unchanged.
- Failure after an upstream switch restores the previous upstream and image
  digest.
- A failed credential refresh does not overwrite a valid session file.
- A failed backup upload retains staging data only within a bounded retry
  window and alerts.
- Firewall closure never occurs before independent alternate-access evidence.
- No rollback deletes an S3 object, DynamoDB item, Docker volume or InfluxDB
  dataset.

## 14. Testing strategy

### 14.1 Repository tests

- `yamllint`, `ansible-lint` and syntax check for every new playbook;
- Molecule or containerized systemd-capable tests where supported;
- idempotence tests for every reusable role;
- negative tests for missing enable flags, unsupported OS, conflicting users,
  open listeners and invalid configuration;
- forced-command parser fuzz/property tests;
- sudoers, SSH, Nginx, cloudflared, systemd and nftables/ufw validation;
- secret-redaction and no-persistent-credential tests;
- a regression proving current municipal inventory executes no personal role.

### 14.2 Deployment acceptance tests

- maintain two simultaneous SSH sessions through the Stage A/B cutover;
- confirm TCP 22, 80 and 443 are closed from an external probe;
- confirm the SSH hostname works only with Cloudflare Access plus an SSH key;
- confirm each API hostname routes only to its declared loopback service;
- induce rate limits and verify `429` behavior;
- deploy and rollback a harmless fixture service by digest;
- expire a temporary AWS session and observe successful renewal;
- deny renewal and prove fail-closed behavior without a static key;
- perform one isolated InfluxDB restore;
- verify logs and evidence contain no secret material.

## 15. Rollout order

1. Add disabled roles, public examples and tests to `infra-ansible`.
2. Merge only after the existing municipal pipeline is green and its deploy
   phase reports no personal-platform target.
3. Bootstrap `personal-infra-live` and its AWS/Cloudflare identities.
4. Run read-only VPS and Hostinger preflight.
5. Take or verify the required restore point.
6. Execute SSH Stage A and receive human approval.
7. Install base runtime, Tunnel, Nginx, Alloy and credential broker.
8. Validate a fixture application and rollback.
9. Execute SSH/firewall Stage B and external closure tests.
10. Hand off to the LimnoPulse production deployment specification.

## 16. Acceptance criteria

- Existing municipal roles, pipeline and inventories retain their current
  behavior and validations.
- The public repository contains no real personal or municipal secret/topology
  data.
- Personal production uses GitHub-hosted runners and no municipal service.
- No deployment or application user belongs to the Docker group.
- No persistent AWS access key or GHCR credential exists on the VPS.
- Root and password SSH are disabled only after alternate access evidence.
- Public inbound TCP 22, 80 and 443 are closed at both host and provider layers.
- APIs and SSH remain available through Cloudflare Tunnel.
- Configuration deployment and application rollback are deterministic and
  independently testable.
- Observability and backups remain within their approved free/low-cost budgets.
- All modifying paths require explicit enable flags, exact host limits and
  narrow tags.

## 17. References

- Companion composition design:
  `2026-08-29-personal-infra-live-composition-design.md`
- CnesData production deployment design in `VINIClUS/CnesData`
- LimnoPulse production deployment design in `VINIClUS/limnopulse`
- AWS IAM Roles Anywhere user guide:
  <https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html>
- Cloudflare Tunnel SSH documentation:
  <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/use-cases/ssh/>
- Grafana Alloy documentation: <https://grafana.com/docs/alloy/latest/>
