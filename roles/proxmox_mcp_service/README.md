# proxmox_mcp_service

Deploys an exact `ProxmoxMCP` Git commit on one approved, unprivileged Debian
LXC guest. The role is
disabled by default and requires an exact `--limit` plus the
`proxmox_mcp_service` tag. Runtime values come from an allowlisted controller
environment, normally populated by the Infisical Machine Identity launcher.

The application release is replaceable under `/opt/proxmox-mcp/releases`; the
SQLite database and audit log remain in the fixed Docker volume
`proxmox_mcp_data`. Only a public SSH key is copied. The private key remains on
the controller.

`proxmox_mcp_service_release_source` defaults to `git`. A controlled local
deployment may select `controller_archive`; the role then runs `git archive`
for the exact 40-character commit and transfers only committed files. Local
`.env`, `.broker`, `.git`, and other untracked files cannot enter the archive.

The repository default binds port 3100 to loopback. Public/LAN binding is not
implemented by this role until an explicit Nginx source and host firewall
contract are available.

The deployed HTTP service receives only variables consumed by its runtime.
Operator-only recovery inputs, OpenAI placeholders, lifecycle metadata, and
Infisical bootstrap credentials are not copied into the service environment.
Backup and restore remain local CLI operations and stay disabled while the
persistent Proxmox storage contract is incomplete.

The LXC template may carry an inherited `mp1`, but this role does not mount or
bind `/mnt/infra-backups/proxmox` into Compose. That volume is not treated as
the host Proxmox backup storage.

```bash
ansible-playbook \
  -i <private-inventory> \
  playbooks/proxmox-mcp-service.yml \
  --limit <exact-host> \
  --tags proxmox_mcp_service
```
