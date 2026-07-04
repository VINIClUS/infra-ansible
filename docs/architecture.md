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

The first implementation layer is intentionally read-only by default. Playbooks
that can change real infrastructure must require explicit inventory variables,
`--limit`, and a narrow tag.
