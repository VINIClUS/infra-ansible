# proxmox_lxc_guest

Creates the Ansible controller as one full LXC clone of the approved Proxmox
template. The role is disabled by default and is deliberately create-only: it
has no removal or recreation path. If the destination VMID already exists, its
identity must agree with the approved LXC contract before the role can continue.

The private inventory must define exactly one host in the
`ansible_controller_bootstrap` group. That inventory hostname is a local
bootstrap target, must be selected by an exact `--limit`, and supplies any
approved overrides such as the destination VMID. Export `PVE_HOST`,
`PVE_TOKEN_ID`, and `PVE_TOKEN_SECRET` only in the runtime environment; never
store their values in inventory or Git.

Run only the dedicated tag against the exact bootstrap inventory host:

```bash
ansible-playbook -i <private-inventory> \
  playbooks/provision-ansible-controller.yml \
  --limit <exact-bootstrap-host> \
  --tags proxmox_lxc_guest \
  -e proxmox_lxc_guest_enabled=true \
  -e proxmox_lxc_guest_vmid=<approved-vmid>
```

Before cloning, the role performs read-only checks of source VMID `9400` and
the destination VMID. It proves the source is a Debian, unprivileged template
with a 32 GiB `local-lvm` root filesystem and DHCP on `vmbr0`. An absent target
is cloned, configured, started, read back, and exposed only as the redacted
`proxmox_lxc_guest_summary` fact (`vmid`, `hostname`, `node`, and `state`).

There is no deletion path: the role never removes an LXC, replaces an existing
VMID, or recreates a target. A mismatched existing target stops the run for
manual investigation.
