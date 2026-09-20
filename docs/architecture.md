# infra-ansible Architecture

`infra-ansible` owns reusable Ansible code only. It does not own production
inventory, secret values, Packer template builds, or domain bootstrap logic.

## Repository Boundaries

- `packer-proxmox-templates` builds and validates immutable Proxmox templates.
- `infra-ansible` validates, clones, configures, and orchestrates infrastructure
  from those templates.
- `infra-ansible-inventory` stores private inventory, environment metadata, and
  encrypted or runtime secret references.
- `esus-pec-bootstrap` remains the source for e-SUS PEC operational automation.
- `sus-siha-bootstrap` remains the source for DATASUS/SIHA operational
  automation.

## Runtime profiles

The existing integration model below is the municipal/Proxmox profile.
`infra-ansible-inventory`, its ansible-vault, and MinIO are contracts of that
profile, not global dependencies of every consumer of this reusable
repository.

The separate personal profile is composed by the private
`personal-infra-live` repository. It uses SSM Parameter Store, KMS and IAM
Roles Anywhere for secrets and temporary identity, and S3 for OpenTofu state,
deployment evidence and the approved personal backup contracts. The municipal
and personal profiles share no inventory, identity, secret, artifact or state.

## Municipal/Proxmox Integration Model

Ansible consumes stable contracts from sibling repositories:

- template names, VMIDs, storage pools, and bridges from Packer outputs;
- bootstrap repository path and pinned ref for e-SUS PEC and SIHA operations;
- `infra-ansible-inventory` ansible-vault variables for runtime secrets;
- MinIO buckets for artifacts, backups, and validation evidence.

## Municipal shared infrastructure and project ownership

This section applies to the municipal/Proxmox profile. This repository provides
reusable automation. The private
`infra-ansible-inventory` repository owns only shared platform topology:
Proxmox, edge networking, Cloudflare, MinIO, and operational infrastructure.
Application hosts, variables, and secret paths belong to their project
repositories.

Each domain uses its own MinIO service account. A project's ansible-vault
variables must not read the shared infrastructure group's secrets or another
project's, and projects must not share infrastructure bucket credentials.

## Municipal runtime secret flow

Roles read secrets as ordinary inventory variables (e.g. `pve_token_secret`,
`cloudflare_api_token`), each defined in `infra-ansible-inventory` as a
`{{ vault_* }}` indirection in a plaintext `group_vars/*/vars.yml`, resolving
to an encrypted `group_vars/*/vault.yml`. `ansible-playbook` decrypts them at
run time via `--vault-password-file`, itself resolved by
`tools/vault/get-vault-pass.sh` from `ANSIBLE_VAULT_PASSWORD` or
`vault/.vault-pass`. No launcher process, no ephemeral network token, no
separate bootstrap-credential exchange step.

The public contract is the inventory group a role's tasks run against and the
variable names it reads — the same contract as any other inventory variable.
A role gains access to a secret only if its tasks execute against a host that
belongs to the group hosting that secret's `vault.yml`.

The first implementation layer is intentionally read-only by default. Playbooks
that can change real infrastructure must require explicit inventory variables,
`--limit`, and a narrow tag.

## Municipal persistent Proxmox backup storage

The `proxmox_backup_storage` role owns the host-side persistence boundary for
full VM backups. It mounts the private inventory's verified source outside any
application release directory and registers an absent Proxmox `dir` storage
through `pvesm`. Proxmox receives `content backup`, `is_mountpoint=1`, and
`prune-backups keep-last=2`.

`infra-ansible-inventory` owns the source, filesystem type, options, node list,
and protected credential-file reference. `ProxmoxMCP` owns only read-only
contract verification and its existing approval-gated recovery execution. The
broker never mounts filesystems or changes Proxmox storage configuration.
