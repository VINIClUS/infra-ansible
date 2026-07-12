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

Automation authenticates with an Infisical Machine Identity through Universal
Auth. Only the client ID and client secret are bootstrap inputs. The launcher
creates a short-lived token inside the tools container and removes it and the
bootstrap credentials before starting Ansible. Do not accept static
`INFISICAL_TOKEN` values or pass credentials as command-line arguments.

`ANSIBLE_EDGE_SSH_PRIVATE_KEY` is a separately provisioned `/ansible` secret,
not generated or rotated by the controller bootstrap seeder. It is transported
only as a child-process environment value, validated without disclosure, and
installed by `infra_ansible_deployer` as the root-owned mode-0600 file
`/etc/infra-ansible-deploy/edge-ssh-key`. Never place its value in inventory,
command arguments, logs, or incident output.

Grant each identity read access only to its project, environments, and secret
paths. Rotate identities independently through the untracked `.env` or secure
runner; no inventory change is required.

### Ansible controller bootstrap

`tools/bootstrap/seed_ansible_controller_secrets.py` is the only supported
bootstrap path for the seven approved names under `/ansible`. Start with
`--dry-run`; it needs no credentials or network access and prints names only.
The live mode authenticates with Universal Auth, lists existing keys with
`viewSecretValue=false`, sends values only in HTTPS request bodies, and emits a
JSON summary containing names and non-secret resource IDs only.

The bootstrap is create-only. A partial existing contract stops before
generating material. A complete seven-name set becomes a no-op only after the
bootstrap cross-checks the selected Infisical values against the one exact
read-only GitHub deploy key, the one exact Cloudflare service token, its ID in
inventory, and the age recipient in inventory. Both remote listings consume
every page. Missing, duplicate, or inconsistent state fails closed with a
redacted recovery message.

Never delete or overwrite an existing key merely to make a rerun pass. Local
Infisical rotation requires one explicit `--rotate NAME`, snapshots the prior
value before generating replacement material, and restores it on transaction
failure. `INFRA_INVENTORY_DEPLOY_KEY`, both Cloudflare Access credential names,
and `ANSIBLE_BACKUP_AGE_IDENTITY` are deliberately rejected by `--rotate`:
they require a separate change procedure that coordinates the old and new
GitHub/Cloudflare resource or backup-recipient handoff. Review the dependent
service recovery procedure and take an encrypted backup before any supported
local rotation.

Age and SSH private keys exist only in a temporary mode-0700 directory with
mode-0600 files. Removal is verified on every exit path; failure stops the run
with `manual cleanup required`. Only the public Ed25519 key is passed to
`gh repo deploy-key add`; read-only is the GitHub CLI default, so the bootstrap
never supplies `--allow-write`. API base URLs must be clean HTTPS URLs without
userinfo, query, or fragment. The HTTP client refuses every redirect so an
Authorization header can never be replayed to another origin or plaintext URL.
A 2xx response alone is insufficient: Infisical listings require an explicit,
unambiguous `secrets` list with valid key names, and mutations must return the
committed resource shape and pass a fresh paginated readback.

The age recipient and Cloudflare service-token resource ID are public metadata.
Their two-file inventory transaction uses a mode-0600 write-ahead journal,
atomic replacements, file and directory sync, and automatic rollback recovery
on the next invocation. The journal is removed only after both files are
durable. The corresponding private identity, client ID, and client secret
remain only in Infisical.

If a remote step fails, the bootstrap attempts to remove newly created
Infisical secrets, the new Cloudflare service token, and the new GitHub deploy
key, and restores public inventory files. A message ending in `compensation
completed` means that automated cleanup succeeded; `manual recovery required`
means an operator must inspect resources by their fixed names and IDs. Do not
copy API response bodies, subprocess output, temporary files, or secret values
into an incident ticket or terminal transcript during recovery.

## MinIO

MinIO is the object storage target for artifacts, backups, and validation
reports. This repository stores only bucket names, prefixes, and retention
intent. Access keys are read at runtime and must never be printed.

Use a distinct MinIO service account and buckets for shared infrastructure and
for every project. `https://s3.vinisantana.com` is the S3 API endpoint;
`https://minio.vinisantana.com` and local port `9001` are administrative
consoles and must not be configured as S3 endpoints.

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
