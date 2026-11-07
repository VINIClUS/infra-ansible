# proxmox_router_vm

Creates the network isolation router as one full clone of the approved
cloud-init VM template, then adds storage replication and HA. The role is
disabled by default and create-only: it never replaces, recreates or removes a
guest. An existing VMID must match the router contract (name, not a template,
every `netN` bridge with `firewall=0` and every `ipconfigN`) or the run stops.

- Exact one-node `--limit` equal to `proxmox_router_vm_node`, `--tags
  proxmox_router_vm`.
- Every bridge must exist on the node, and every non-`vmbr` bridge must be an
  applied SDN VNet.
- The first NIC is the uplink and the only one with a gateway. VNet NICs use
  `mtu=1` so the guest inherits the VNet MTU through virtio. The PVE firewall is
  off on every router NIC (`ipfilter` and `policy_in` would drop routed
  traffic); the guest filters with nftables (`network_router`).
- The clone lands on `proxmox_router_vm_storage` (ZFS) so it can be replicated
  to `proxmox_router_vm_replication_target`.
- The HA resource is pinned by a strict node-affinity rule
  (`proxmox_router_vm_ha_nodes`, for example `node-a:1,node-b:1`). Equal
  priorities avoid automatic failback, which depends on replication working
  from the failover node as well.
- The cloud-init public key is staged in a root-only file and removed after
  `qm set`.

```bash
ansible-playbook -i <private-inventory> playbooks/proxmox-router-vm.yml \
  --limit <exact-proxmox-node> --tags proxmox_router_vm
```
