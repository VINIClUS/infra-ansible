# proxmox_guest_network

Moves one LXC guest between bridges (typically from the LAN `vmbr0` to a
private SDN VNet) and back. The role is disabled by default and needs the node
that hosts the guest as the only `--limit` entry, `--tags proxmox_guest_network`
and `-e proxmox_guest_network_vmid=<id>` of a guest declared in
`proxmox_guest_network_guests`.

- Every run reads the guest first and refuses anything it does not expect: a
  different hostname, a second NIC, no fixed MAC, `firewall=1` missing, IPv6 on
  net0, pending changes, a stopped guest, an HA state other than `started`,
  missing probe tools or a `.pve-ignore.*` file inside the guest.
- A guest at its declared source is moved; a guest already at its target is
  only verified (no change). `-e '{"proxmox_guest_network_rollback": true}'`
  puts back the net0, nameserver and searchdomain recorded in
  `<backup_root>/<vmid>-original.json` before the first move.
- The new net0 is the live net0 with only `bridge`, `ip`, `gw` and `mtu`
  changed: the MAC and `firewall=1` are kept, so a rollback to `ip=dhcp` gets
  the same LAN reservation back. The read-back must match and keep the MAC.
- Before a move the target address must be unused: no other guest config in
  the cluster declares it and the zone router (`proxmox_guest_network_router_host`)
  gets no ARP answer for it after flushing its neighbour entry.
- The change is cold: the guest is stopped (through `ha-manager set --state`
  for HA guests, so HA does not undo it), snapshotted (`netiso-<timestamp>`,
  drop it once the move is accepted), set, and started once with the final
  settings; PVE rewrites its network files and `resolv.conf` on that boot. A
  busy guest (`busy_pattern` matches) is never restarted.
- PVE sets `mtu=` only on the host side of the veth and ifupdown2 in the guest
  resets an `eth0` without `mtu` to 1500, which silently drops full-size frames
  inside a VNet. `files/guest-mtu.sh` writes `mtu <value>` into the guest's
  eth0 stanza before the stop (PVE keeps that attribute in static stanzas) and
  aligns the live link after the start.
- Verification runs inside the guest (`files/guest-probe.sh`: one address, no
  global IPv6, MTU, MAC, default route, gateway ping with a full-size DF frame,
  resolver, DNS, HTTPS, systemd units) and from the node (TCP 22). The probe
  prints only yes/no checks, never addresses.
- Any failure after the stop puts back the settings read before the run,
  starts the guest, verifies it there and fails the play.

LAN hosts reach a moved guest dependably only with their own route to the
private range through the zone router (as the nodes have). Through the LAN
gateway's static route the flow is asymmetric (the zone router answers
on-link): the gateway's connection tracking drops bulk traffic from the LAN
into the VNet after about 64 KB, and guests on the zone router's own node lose
the flow in both directions (it crosses that node's bridge twice).

```bash
ansible-playbook -i <private-inventory> playbooks/proxmox-guest-network.yml \
  --limit node-a --tags proxmox_guest_network -e proxmox_guest_network_vmid=150 --check
ansible-playbook -i <private-inventory> playbooks/proxmox-guest-network.yml \
  --limit node-a --tags proxmox_guest_network -e proxmox_guest_network_vmid=150
```
