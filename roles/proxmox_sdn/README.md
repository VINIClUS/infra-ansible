# proxmox_sdn

Reconciles Proxmox SDN VXLAN zones and VNets declared in the private inventory
and, in an approved run, applies them to every node. The role is disabled by
default. It only creates or updates declared objects: it never deletes zones or
VNets, never moves a VNet to another zone and never re-tags one (that would
disconnect its guests).

## Safety model

- Exact one-node `--limit`, `--tags proxmox_sdn`, one play host. SDN
  configuration lives in pmxcfs, so one node writes and applies for the cluster.
- `proxmox_sdn_nodes` must equal the live, quorate cluster membership; every
  zone uses exactly those addresses as VXLAN peers and an explicit
  `vxlan-port` (`proxmox_sdn_vxlan_port`, default 4789).
- Before any change every node must pass `files/sdn-node-check.sh pre`:
  `/etc/network/interfaces` sources `/etc/network/interfaces.d/*`, there is no
  pending `/etc/network/interfaces.new`, `ifquery --check -a` reports no drift,
  the node address is present, and the host firewall is `enabled/running` with
  the IPset-restricted VXLAN guard rule for the same UDP port. VXLAN is
  unauthenticated, so the guard must exist before any VXLAN device does.
- VXLAN zones are layer 2: no subnet, gateway or IPAM is created; address
  plans live in the inventory.
- `proxmox_sdn_apply: false` (default) only edits the pending configuration
  and reports it. Apply also refuses pending changes that the inventory does
  not own, because `pvesh set /cluster/sdn` pushes every pending change.
- A live apply backs up `/etc/pve/sdn` and the node network files, releases HA
  watchdogs through `proxmox_change_guard` (`ha-states-sdn.json`), and arms a
  dead-man timer on every node that restores the previous
  `/etc/network/interfaces.d/sdn` (or removes it) and runs `ifreload -a`.
- The apply reload is asynchronous. The role polls `sdn-node-check.sh post`
  on every node until each VNet appears in `/etc/network/interfaces.d/sdn`, its
  bridge and `vxlan_<vnet>` device exist with the zone MTU, the VXLAN id and
  `dstport`; the default route must be unchanged, new SSH and 8006 connections
  from the controller must succeed, and quorum must be intact. Only then is the
  dead-man disarmed and HA restored.
- On failure the previous node file is restored and `ifreload -a` runs on every
  reachable node; HA stays disarmed and the cluster running configuration still
  holds the declared objects for a manual decision.

## Usage

```bash
ansible-playbook -i inventories/example/hosts.yml playbooks/proxmox-sdn.yml --syntax-check

# 1. Stage the pending configuration only.
ansible-playbook -i <private-inventory> playbooks/proxmox-sdn.yml \
  --limit <exact-proxmox-node> --tags proxmox_sdn

# 2. Apply under the HA guard and the dead-man timer.
ansible-playbook -i <private-inventory> playbooks/proxmox-sdn.yml \
  --limit <exact-proxmox-node> --tags proxmox_sdn -e '{"proxmox_sdn_apply": true}'
```
