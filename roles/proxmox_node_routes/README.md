# proxmox_node_routes

Routes the private VNet range from every Proxmox node through the zone router.
The role is disabled by default and needs every target node named in
`--limit` and `--tags proxmox_node_routes`.

- Routes are installed as an ifupdown2 `if-up.d` hook
  (`proxmox_node_routes_hook_path`) that acts only when
  `proxmox_node_routes_interface` comes up and always exits 0, so it survives
  reboots and network reloads without editing `/etc/network/interfaces` or
  adding a second interface stanza. The role first confirms
  `addon_scripts_support=1`.
- Every next hop must be directly connected through that interface.
- Live routes are applied by running the hook exactly as ifupdown2 would
  (`IFACE`, `MODE=start`, `ip route replace`); the network is never reloaded,
  and `ifquery --check -a` must still pass afterwards.
- Routes removed from the inventory are dropped from the hook but must be
  deleted live by hand (`ip route del <cidr>`).

```bash
ansible-playbook -i <private-inventory> playbooks/proxmox-node-routes.yml \
  --limit node-a,node-b,node-c --tags proxmox_node_routes
```
