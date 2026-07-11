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

## Integration Model

Ansible consumes stable contracts from sibling repositories:

- template names, VMIDs, storage pools, and bridges from Packer outputs;
- bootstrap repository path and pinned ref for e-SUS PEC and SIHA operations;
- Infisical paths for runtime secrets;
- MinIO buckets for artifacts, backups, and validation evidence.

## Shared infrastructure and project ownership

This repository provides reusable automation. The private
`infra-ansible-inventory` repository owns only shared platform topology:
Proxmox, edge networking, Cloudflare, MinIO, and operational infrastructure.
Application hosts, variables, and secret paths belong to their project
repositories.

Each domain uses its own Infisical Machine Identity and MinIO service account.
A project identity must not read the shared infrastructure project or another
project's paths, and projects must not share infrastructure bucket credentials.

## Runtime secret flow

`Invoke-InfisicalAnsible.ps1` passes Universal Auth bootstrap variables to the
tools container by environment-variable name, never by value on the command
line. The container exchanges them for an ephemeral token, exports only the
requested project, environment, and paths, allowlists required keys, removes
the bootstrap credentials, and then replaces itself with `ansible-playbook`.

The public contract is project ID, environment, secret paths, and required key
names. Static `INFISICAL_TOKEN`, project slugs, and implicit access to all
project secrets are unsupported.

The first implementation layer is intentionally read-only by default. Playbooks
that can change real infrastructure must require explicit inventory variables,
`--limit`, and a narrow tag.

## Persistent Proxmox backup storage

The `proxmox_backup_storage` role owns the host-side persistence boundary for
full VM backups. It mounts the private inventory's verified source outside any
application release directory and registers an absent Proxmox `dir` storage
through `pvesm`. Proxmox receives `content backup`, `is_mountpoint=1`, and
`prune-backups keep-last=2`.

`infra-ansible-inventory` owns the source, filesystem type, options, node list,
and protected credential-file reference. `ProxmoxMCP` owns only read-only
contract verification and its existing approval-gated recovery execution. The
broker never mounts filesystems or changes Proxmox storage configuration.
