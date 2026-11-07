# proxmox_guest_routes

Gives one LAN guest its own route to the private VNet range through the zone
router, the way `proxmox_node_routes` does for the nodes. The LAN gateway's
static route is not a dependable path into the VNets (see
`proxmox_guest_network`), so a LAN guest that serves or administers the VNets
(for example a VPN router) needs this. The role is disabled by default and
needs the node that hosts the guest as the only `--limit` entry,
`--tags proxmox_guest_routes` and `-e proxmox_guest_routes_vmid=<id>`.

- The guest must be the declared, running guest; ifupdown2 inside it must have
  `addon_scripts_support=1`, and every next hop must be directly connected
  through the declared interface.
- The route lives in an ifupdown2 `if-up.d` hook inside the guest
  (`proxmox_guest_routes_hook_path`, written through `pct exec`) that acts only
  when the declared interface comes up and always exits 0. PVE rewrites the
  guest's `/etc/network/interfaces` on every start, so the route is never put
  there.
- Missing routes are applied by running the hook exactly as ifupdown2 would
  (`IFACE`, `MODE=start`, `ip route replace`); the guest network is never
  reloaded or restarted.
- A route removed from the inventory leaves the hook as written; delete the
  hook line and the live route by hand.

```bash
ansible-playbook -i <private-inventory> playbooks/proxmox-guest-routes.yml \
  --limit node-a --tags proxmox_guest_routes -e proxmox_guest_routes_vmid=100 --check
```
