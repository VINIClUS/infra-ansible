# Safety Policy

## No secrets in Git

No secrets in Git. Do not commit passwords, tokens, private keys, database
credentials, certificates, `.env` files, vault passwords, backup payloads, or
health data exports.

## Runtime profile boundary

ansible-vault, MinIO and `infra-ansible-inventory` are contracts of the
existing municipal/Proxmox profile. The separate personal profile is composed
in the private `personal-infra-live` repository and uses SSM Parameter Store,
KMS and IAM Roles Anywhere for secrets and temporary identity, plus S3 for
OpenTofu state, evidence and approved backups. No inventory, identity, secret,
artifact or state crosses between these profiles.

## Secrets (ansible-vault)

For the municipal/Proxmox profile, `infra-ansible-inventory`'s ansible-vault
is the primary and only secret source. Infisical, which previously held this
role, was decommissioned (September 2026); it is no longer reachable and its
values were migrated. This repository stores only:

- variable names, in `group_vars/*/vars.yml` (or role-equivalent contract
  files), each pointing at a `{{ vault_* }}` indirection;
- validation logic that redacts sensitive values.

The encrypted values live in sibling `group_vars/*/vault.yml` files in
`infra-ansible-inventory`, committed to git as whole-file
`ansible-vault encrypt` blobs (never inline `!vault` tags). Automation
authenticates by resolving a vault password through
`tools/vault/get-vault-pass.sh` (the inventory's `ansible.cfg`
`vault_password_file`): the `ANSIBLE_VAULT_PASSWORD` environment variable if
set, else `vault/.vault-pass` on disk. Do not pass the vault password as a
command-line argument or echo it to a log.

`ANSIBLE_EDGE_SSH_PRIVATE_KEY` is a separately provisioned secret, supplied
out-of-band at controller bootstrap — never stored in the inventory vault
(see `INFRA_INVENTORY_DEPLOY_KEY` in
`docs/runbook-secret-rotation.md` for why: the inventory can't hold the key
used to clone the inventory). It is transported only as a child-process
environment value, validated without disclosure, and installed by
`infra_ansible_deployer` as the root-owned mode-0600 file
`/etc/infra-ansible-deploy/edge-ssh-key`. Never place its value in inventory,
command arguments, logs, or incident output.

Grant each vault-backed secret's consumers access only through the inventory
group that hosts it. Rotate secrets by editing the encrypted `vault.yml`
directly (`ansible-vault edit`); see `docs/runbook-secret-rotation.md` for the
per-secret procedure, including the four secrets with an external
counterpart (GitHub deploy key, Cloudflare service token, age backup
identity) that require coordinated rotation on both sides.

## MinIO

For the municipal/Proxmox profile, MinIO is the object storage target for
artifacts, backups, and validation reports. This repository stores only bucket
names, prefixes, and retention intent. Access keys are read at runtime and must
never be printed.

Use a distinct MinIO service account and buckets for shared infrastructure and
for every project. `https://s3.vinisantana.com` is the S3 API endpoint;
`https://minio.vinisantana.com` and local port `9001` are administrative
consoles and must not be configured as S3 endpoints.

MinIO is decommissioned with no return date (as of September 2026; both
endpoints return HTTP 502). Its access-key pair was migrated to the vault and
the role configuration was deliberately left active rather than disabled, so
it resumes working immediately if the service returns. Until then,
`minio_artifacts` publish steps fail closed — `minio_validate_access: false`
in both environments keeps this from failing the surrounding playbook, so
check publish results explicitly rather than assuming a green run means
artifacts landed.

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
