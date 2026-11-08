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

## Optional bridge hashmax persistence

`proxmox_sdn_bridge_hashmax: {}` is empty by default. An explicitly declared
VNet may opt into the fixed string value, for example:

```yaml
proxmox_sdn_bridge_hashmax:
  vnold: "4096"
```

The role inspects every declared node before pending reconciliation. Only
`proxmox_sdn_apply: true` outside check mode installs the dedicated root-owned
0644 `/etc/network/ifupdown2/policy.d/90-sdn-existing-bridge-hashmax.json`.
Installation does not depend on pending SDN changes: with no pending changes it
only writes and verifies this policy file, without backup, HA, dead-man or
reload tasks. Staging and check mode inspect only; disabling the role skips it.
An empty map neither installs nor removes a policy.

The streamed Python helper checks the audited installed loader/addon hashes,
policy metadata, existing policy JSON and fingerprints before writing. It stops
for any other user `bridge.iface_defaults` subtree, including disjoint names:
the installed loader merges module dictionaries shallowly in unsorted order.
It never replaces an unmanaged destination or merges another file. An exact
already-managed file is unchanged. Publication uses an exclusive temporary and
an atomic no-replace rename; a competing arrival stops the write. Failures stop
before the next node and before the guarded network apply path. A published
file remains in place on a later fsync/readback failure, reported as changed
with an error; earlier successful nodes are not automatically rolled back.

Getter verification executes only the hash-verified standalone PolicyManager.
It requires target values to be string `4096`, preserves non-target/global
fallbacks, other files and generated network file hashes, and imports no bridge
addon. This proves loader acceptance of a persistent file. It does not prove a
future reload or live multicast state; those require separately reviewed
runtime evidence and authorization.

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
