# Protocolos edge route

This disabled-by-default role manages only the public edge route for VM 104,
`SistemaDeProtocolos`. When enabled by private inventory, it accepts only the
pinned domain, upstream, Let's Encrypt certificate paths, and Nginx site paths.
It consumes and validates the private inventory's `protocolos_service_*`
identity contract directly: VMID 104 on `pve-01`, name `SistemaDeProtocolos`,
private address `192.168.1.199`, MAC `BC:24:11:D1:92:1B`, and `onboot: true`.

Mutation also defaults to denied. Keep `protocolos_edge_route_apply` out of
private inventory and approve only the individual run. The role requires the
literal Ansible limit `nginx`; a missing or different limit fails before any
preflight or Nginx mutation. The exact targeted rollout command is:

```bash
ansible-playbook -i /path/to/private/inventories/prod/hosts.yml playbooks/edge-proxy-route.yml --limit nginx --tags protocolos_edge_route -e protocolos_edge_route_apply=true
```

The role never invokes certificate issuance or renewal. It requires the
existing certificate's sole DNS SAN to be `protocolos.portosoftware.com.br`
and requires `certbot.timer` to be enabled before any Nginx change.

The installed site returns an exact HTTP 301 redirect to HTTPS and proxies all
TLS paths to `http://192.168.1.199:80`. The transaction keeps a timestamped
backup, restores the prior vhost and `sites-enabled` symlink state on any
failure, then revalidates and reloads Nginx before reporting that failure.
The HTTPS acceptance probes refuse redirects so a redirect cannot satisfy the
required root, CSRF, or health response status.
