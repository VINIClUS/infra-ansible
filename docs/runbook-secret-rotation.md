# Runbook: rotating ansible-controller secrets

Infisical, and the automated bootstrap seeder that provisioned secrets
through it (`tools/bootstrap/seed_ansible_controller_secrets.py`), were
retired in September 2026. This is a manual runbook replacing what that
script did automatically: create/rotate/delete with compensation on
partial failure, paginated readback verification, and a coordinated
write into the inventory repository. Secrets now live encrypted in
`infra-ansible-inventory`, in `ansible-vault`-encrypted `group_vars/*/vault.yml`
files. There is no API to call — rotation is: generate, edit the vault
file, redeploy, then invalidate the old value everywhere else it's held.

General procedure for any secret below:

```bash
cd /path/to/infra-ansible-inventory
ansible-vault edit --vault-password-file vault/.vault-pass \
  inventories/prod/group_vars/<group>/vault.yml
# replace the vault_<name> value, save, exit
git add inventories/prod/group_vars/<group>/vault.yml
git commit -m "chore(vault): rotate <name>"
git push
# trigger a normal deploy (sudo infra-ansible-deploy <sha> on the controller,
# or let CI do it on the next push to infra-ansible main)
```

`ansible-vault edit` decrypts to a temp file, opens `$EDITOR`, and
re-encrypts on save — the plaintext never touches a shell history or a
committed file.

## Locally-generated secrets (no external service involved)

These were previously produced by `generate_resources()` in the seed
script. Generate a replacement value yourself and paste it into the vault
file at the path shown.

| Secret | Vault key / file | How the old script generated it | How to regenerate |
|---|---|---|---|
| `SEMAPHORE_DB_PASSWORD` | `vault_semaphore_db_password` in `group_vars/ansible_controllers/vault.yml` | `secrets.token_urlsafe(48)` | `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `SEMAPHORE_ADMIN_PASSWORD` | `vault_semaphore_admin_password`, same file | `secrets.token_urlsafe(48)` | same command as above |
| `SEMAPHORE_ACCESS_KEY_ENCRYPTION` | `vault_semaphore_access_key_encryption`, same file | 32 random bytes, base64-encoded (AES-256 key) | `python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"` |

After rotating any of the three: Semaphore's config references these at
setup time only (`roles/semaphore_controller/tasks/configure.yml`, the
`ansible.builtin.expect` first-run setup). Rotating `SEMAPHORE_DB_PASSWORD`
or `SEMAPHORE_ADMIN_PASSWORD` **after** initial setup requires updating them
inside Semaphore itself too (its Postgres role password and admin account
password respectively) — the role does not currently re-run setup on an
existing installation. `SEMAPHORE_ACCESS_KEY_ENCRYPTION` decrypts
Semaphore's stored credentials; rotating it without re-encrypting existing
data will make Semaphore unable to read its own stored secrets. Treat this
one as effectively non-rotatable without a Semaphore-side data migration —
only regenerate it as part of standing up a fresh Semaphore instance.

## Secrets with an external counterpart

These need the same value changed in two places: the vault file, and the
external system the value authenticates against. Order matters — create
the new external credential, put it in the vault, verify a deploy
succeeds, *then* revoke the old external credential. Doing it in the
other order causes an outage.

### `ANSIBLE_BACKUP_AGE_IDENTITY`

- **Vault**: `vault_ansible_backup_age_identity` in
  `group_vars/ansible_controllers/vault.yml`.
- **External counterpart**: the matching **public** recipient is
  committed in plaintext at `inventories/prod/group_vars/ansible_controllers/semaphore.yml`
  as `ansible_backup_age_recipient` (this is intentional — age public
  recipients are not secret). It must match the new identity's recipient
  exactly, or Semaphore's backup encryption task
  (`semaphore_controller_backup_age_recipient is match('^age1[0-9a-z]+$')`)
  and later restores will silently use the wrong keypair.
- **Regenerate**:
  ```bash
  age-keygen -o new-backup-identity
  age-keygen -y new-backup-identity   # prints the new public recipient
  ```
  Put the private output into the vault key, and the printed recipient
  into `ansible_backup_age_recipient` in the same commit.
- **Old backups** encrypted under the previous identity become
  unreadable once the old identity is discarded. Keep the old identity
  in a separate offline location (not in this repo) until you no longer
  need to restore anything encrypted before the rotation.

### `INFRA_INVENTORY_DEPLOY_KEY`

- **Vault**: this key is deliberately **not** stored in the inventory
  vault. It is the SSH key the controller uses to clone the inventory
  repository itself, so storing the key inside the thing it clones is
  circular — a compromised or corrupted vault could withhold the very
  key needed to fetch a fix. It lives only in the controller's bootstrap
  environment, alongside `ANSIBLE_EDGE_SSH_PRIVATE_KEY` and
  `ANSIBLE_VAULT_PASSWORD` — these three values are supplied out-of-band
  at bootstrap, never through the inventory (see
  `roles/infra_ansible_deployer`).
- **External counterpart**: a **read-only** GitHub deploy key on
  `VINIClUS/infra-ansible-inventory`, titled
  `infra-ansible production inventory` (the exact title the old script
  used to detect duplicates — reuse it, or update anything that greps
  for it).
- **Regenerate**:
  ```bash
  ssh-keygen -t ed25519 -N "" -C "infra-ansible production inventory" \
    -f new-inventory-deploy-key
  gh repo deploy-key add new-inventory-deploy-key.pub \
    --repo VINIClUS/infra-ansible-inventory \
    --title "infra-ansible production inventory"
  ```
  Install `new-inventory-deploy-key` (the private half) as
  `/etc/infra-ansible-deploy/inventory-deploy-key` on the controller
  (0600, root:root — this is what `infra_ansible_deployer` does at
  bootstrap; for a rotation, do it by hand or re-run that role with the
  new key supplied as `INFRA_INVENTORY_DEPLOY_KEY` in the bootstrap
  environment). Verify a deploy succeeds, then delete the old deploy key
  from GitHub (`gh repo deploy-key delete <id> --repo ...`).

### `CLOUDFLARE_ACCESS_CLIENT_ID` / `CLOUDFLARE_ACCESS_CLIENT_SECRET`

- **Vault**: `vault_cloudflare_access_client_id` /
  `vault_cloudflare_access_client_secret` in
  `group_vars/local_validation/vault.yml`.
- **External counterpart**: a Cloudflare Access **service token**
  (`POST /accounts/{account_id}/access/service_tokens`), named
  `Semaphore production health check`. The **token ID** (not the
  secret) is also committed in plaintext at
  `inventories/prod/group_vars/local_validation/cloudflare_access.yml`
  as `cloudflare_access_service_token_id` — this must be kept in sync
  with the vault's client ID or the health-check policy
  (`roles/cloudflare_access_application`, the `health` application's
  `service_token.token_id` policy include) will reference a token that
  no longer exists.
- **Regenerate** (via `cloudflare_api_token`, itself in
  `group_vars/local_validation/vault.yml`):
  ```bash
  curl -s -X POST \
    "https://api.cloudflare.com/client/v4/accounts/<account_id>/access/service_tokens" \
    -H "Authorization: Bearer <cloudflare_api_token>" \
    -H "Content-Type: application/json" \
    -d '{"name": "Semaphore production health check", "duration": "8760h"}'
  ```
  Response contains `id`, `client_id`, `client_secret`. Put `client_id`/
  `client_secret` in the vault, `id` in `cloudflare_access_service_token_id`
  (plaintext, same commit), redeploy `cloudflare_access_application`,
  confirm the health check passes, then delete the old service token
  (`DELETE .../access/service_tokens/<old_id>`).

### `OBJECT_STORAGE_ACCESS_KEY` / `OBJECT_STORAGE_SECRET_KEY` (MinIO)

- **Vault**: `vault_object_storage_access_key` /
  `vault_object_storage_secret_key` in `group_vars/minio/vault.yml`.
- **External counterpart**: an access key pair on the MinIO instance
  (`s3.vinisantana.com`). This was never managed by the seed script —
  it was always provisioned directly on MinIO and only *read* from
  Infisical. **MinIO is decommissioned with no return date as of this
  writing** (`https://s3.vinisantana.com` / `https://minio.vinisantana.com`
  return HTTP 502); there is currently no live service to rotate a key
  against. If MinIO is restored, generate a new key pair on the MinIO
  admin console or `mc admin user svcacct add`, put it in the vault,
  and revoke the old key pair the same way.

### `CLOUDFLARE_API_TOKEN`

- **Vault**: `vault_cloudflare_api_token` in
  `group_vars/local_validation/vault.yml`.
- **External counterpart**: a Cloudflare API token in the Cloudflare
  dashboard (My Profile → API Tokens). This token is what the
  `CLOUDFLARE_ACCESS_CLIENT_ID/SECRET` rotation above uses to call the
  Cloudflare API, and is also used directly by `edge_proxy_route` /
  `cloudflare_access_application` for DNS and Access application
  management — check both roles' required token scopes before creating
  the replacement, then revoke the old token from the dashboard once the
  new one is verified.

### `PVE_HOST` / `PVE_TOKEN_ID` / `PVE_TOKEN_SECRET`

Two **separate** credential pairs exist for two separate Proxmox API
tokens — do not confuse them:

- **`group_vars/proxmox_provisioners/vault.yml`** — used by
  `roles/proxmox_lxc_guest` to create the ansible-controller and
  deploy-runner LXCs. Rotate by creating a new API token on the Proxmox
  node for the same user/role, updating the vault, and revoking the old
  token in the Proxmox UI (Datacenter → Permissions → API Tokens) once a
  provisioning run succeeds with the new one.
- **`group_vars/proxmox_mcp_service_hosts/vault.yml`** — a distinct
  token used by the ProxmoxMCP broker service itself (separate Infisical
  project/identity historically; now just a separate vault file). Same
  rotation procedure, different token, different consumer
  (`roles/proxmox_mcp_service`).

## Secrets this runbook deliberately does not cover

- **The ansible-vault password itself**
  (`/etc/infra-ansible-deploy/vault-pass` on the controller,
  `vault/.vault-pass` locally, `ANSIBLE_VAULT_PASSWORD` in CI). Rotating
  it means re-encrypting every `vault.yml` in the inventory
  (`ansible-vault rekey`) and redistributing the new password to every
  place listed above simultaneously — plan this as its own change, not
  a per-secret rotation.
- **`ANSIBLE_EDGE_SSH_PRIVATE_KEY`** — provisioned directly on the edge
  host out of band; was never in Infisical (`docs/safety.md` predates
  this runbook and already documented this).
