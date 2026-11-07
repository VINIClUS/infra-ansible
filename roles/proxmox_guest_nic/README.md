# proxmox_guest_nic

Hot-plugs a secondary NIC into one running LXC guest, for example a second leg
of an edge proxy on a private SDN VNet, and hot-removes it again. The role is
disabled by default and needs the node that hosts the guest as the only
`--limit` entry, `--tags proxmox_guest_nic` and
`-e proxmox_guest_nic_vmid=<id>` of a guest declared in
`proxmox_guest_nic_guests`.

- The NIC never carries a gateway: the default route stays on `net0`. A
  declaration with `gw` is refused, and the probe fails if the guest ends up
  with more than one default route or with the default route on the new NIC.
- The guest is never stopped or restarted (HA plays no part). It must be the
  declared running Debian guest with no pending changes, and no other NIC may
  already use the interface name.
- A NIC already present with exactly the declared settings is only verified.
  Any other NIC under that key is refused and left untouched.
- Before an add, no other guest config in the cluster may declare the address,
  and the zone router (`proxmox_guest_nic_router_host`) must get no ARP answer
  for it after flushing its neighbour entry.
- PVE gives the hot-plugged veth the bridge MTU and writes the guest stanza,
  but without `mtu`, so ifupdown2 would put the interface back to 1500 on the
  next boot. The role writes `mtu <proxmox_guest_nic_mtu>` into the static
  stanza with the shared `proxmox_guest_network` script `files/guest-mtu.sh`.
- Verification runs inside the guest (`files/guest-nic-probe.sh`: interface
  present, the one declared address, MTU, a single default route elsewhere, a
  full-size DF ping to `probe`) and on the node (host-side veth MTU). The probe
  prints only yes/no checks, never addresses.
- `-e '{"proxmox_guest_nic_remove": true}'` hot-removes the NIC. PVE leaves the
  interface's stanza in the guest, so `files/guest-nic-forget.sh` drops it.
- A failed add removes the NIC and its stanza again before the play fails.

```bash
ansible-playbook -i <private-inventory> playbooks/proxmox-guest-nic.yml \
  --limit node-a --tags proxmox_guest_nic -e proxmox_guest_nic_vmid=110 --check
ansible-playbook -i <private-inventory> playbooks/proxmox-guest-nic.yml \
  --limit node-a --tags proxmox_guest_nic -e proxmox_guest_nic_vmid=110
```
