# proxmox_mcp_service

Deploys an exact `ProxmoxMCP` Git commit on one Debian guest. The role is
disabled by default and requires an exact `--limit` plus the
`proxmox_mcp_service` tag. Runtime values come from an allowlisted controller
environment, normally populated by the Infisical Machine Identity launcher.

The application release is replaceable under `/opt/proxmox-mcp/releases`; the
SQLite database and audit log remain in the fixed Docker volume
`proxmox_mcp_data`. Only a public SSH key is copied. The private key remains on
the controller.

The repository default binds port 3100 to loopback. Public/LAN binding is not
implemented by this role until an explicit Nginx source and host firewall
contract are available.

```bash
ansible-playbook \
  -i <private-inventory> \
  playbooks/proxmox-mcp-service.yml \
  --limit <exact-host> \
  --tags proxmox_mcp_service
```
