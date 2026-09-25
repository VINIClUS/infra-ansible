# esusdata edge route

This disabled-by-default role manages only the public edge route for LXC 170,
`esusdata-lxc`, which runs the esusdata (Observatorio APS) service deployed by
`roles/esusdata_service`. When enabled by private inventory, it accepts only
the pinned domain, upstream, Let's Encrypt certificate paths, and Nginx site
paths. It consumes and validates the private inventory's `esusdata_lxc_*`
identity contract directly: VMID 170 on `pve-01`, name `esusdata-lxc`,
private address `192.168.1.145`, MAC `BC:24:11:7C:73:49`, and `onboot: true`.

Mutation also defaults to denied. Keep `esusdata_edge_route_apply` out of
private inventory and approve only the individual run. The role requires the
literal Ansible limit `nginx`; a missing or different limit fails before any
preflight or Nginx mutation. The exact targeted rollout command is:

```bash
ansible-playbook -i /path/to/private/inventories/prod/hosts.yml playbooks/edge-proxy-route.yml --limit nginx --tags esusdata_edge_route --extra-vars '{"esusdata_edge_route_apply": true}'
```

The role never invokes certificate issuance or renewal. Issue the certificate
once on the edge host with `certbot certonly --nginx -d pe.esusdata.com`; the
role then requires the existing certificate's sole DNS SAN to be
`pe.esusdata.com` and requires `certbot.timer` to be enabled before any Nginx
change.

The installed site returns an exact HTTP 301 redirect to HTTPS and proxies all
TLS paths to `http://192.168.1.145:8080`, forwarding `Host`,
`X-Forwarded-For`, and `X-Forwarded-Proto`. The service trusts those headers
only from the edge address, so its session cookie is `Secure` behind TLS.
The transaction keeps a timestamped backup, restores the prior vhost and
`sites-enabled` symlink state on any failure, then revalidates and reloads
Nginx before reporting that failure. The HTTPS acceptance probes refuse
redirects so a redirect cannot satisfy the required root or readiness status.
