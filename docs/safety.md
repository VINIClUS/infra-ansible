# Safety Policy

## No secrets in Git

No secrets in Git. Do not commit passwords, tokens, private keys, database
credentials, certificates, `.env` files, vault passwords, backup payloads, or
health data exports.

## Infisical

Infisical is the primary secret source. This repository stores only:

- expected secret paths;
- expected key names;
- environment names;
- validation logic that redacts sensitive values.

Runtime tokens must come from the operator environment or a secure runner. Tasks
that inspect token presence must use `no_log: true`.

## MinIO

MinIO is the object storage target for artifacts, backups, and validation
reports. This repository stores only bucket names, prefixes, and retention
intent. Access keys are read at runtime and must never be printed.

## Production

Production is not a default target. Production playbooks require an explicit
inventory, `--limit`, and operator approval for any action that changes network,
firewall, reverse proxy, backups, restore, LXC/VM state, or service state.

## Proxmox backup mount

The persistent backup role must be invoked with a private inventory, an exact
one-node `--limit`, and `--tags proxmox_backup_storage`. It validates `findmnt`
before any storage registration and refuses an existing storage with a
different backend, path, content, retention, mountpoint guard, or node scope.

Proxmox `is_mountpoint=1` is mandatory: a missing external mount must make the
storage unavailable instead of allowing backup payloads to fall through to the
root filesystem. The role has no remove, unmount, manual prune, or direct
`storage.cfg` edit path. After host-side validation, hand off to the broker's
GET-only `recovery-preflight`; backup and restore approvals remain separate.
