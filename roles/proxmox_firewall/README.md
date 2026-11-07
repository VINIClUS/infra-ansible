# proxmox_firewall

Reconciles the Proxmox VE datacenter firewall (`/etc/pve/firewall/cluster.fw`),
each node's `host.fw`, and the `<vmid>.fw` files of the guests declared in the
private inventory. The role is disabled by default and is the first step of the
cluster network isolation plan: it enforces host and guest policy on the
existing `vmbr0` before any SDN VXLAN zone exists.

All rule data (IPsets, aliases, security groups, host rules, guest options and
rules) lives in the private inventory. Undeclared guest `.fw` files are never
modified or removed.

## Safety model

- Exact one-node `--limit`, `--tags proxmox_firewall`, one play host. The file
  system is shared through pmxcfs, so a single node writes for the whole
  cluster.
- `proxmox_firewall_nodes` must equal the live, quorate cluster membership.
- The VXLAN guard rule (`IN ACCEPT udp 4789` only from the
  `proxmox_firewall_vxlan_guard_ipset`) is always rendered first, and that
  IPset must contain exactly the node addresses. VXLAN is unauthenticated; with
  `policy_in: DROP` this blocks frame injection from the rest of the LAN.
- `/etc/pve/firewall` is created if absent, then a root-only tarball of the
  existing paths among `/etc/pve/firewall`, `/etc/pve/nodes`, `/etc/pve/sdn`
  (private keys excluded) and `/etc/network/interfaces` is written to
  `proxmox_firewall_backup_root` before any change.
- Guests whose `options.enable` is true are refused while the datacenter
  firewall is still disabled: activate the datacenter and host layer first,
  then enable guests in a later run.
- Before a live change, HA watchdogs are released cluster-wide with
  `ha-manager crm-command disarm-ha freeze` (or, on releases without it, every
  HA resource is set to `ignored` until no LRM is active). HA self-fencing
  resets a node about 60 s after quorum loss, faster than any dead-man timer.
  Previous states are saved to `ha-states.json` next to the backup, and HA is
  restored only after verification passes.
- Whenever the resulting datacenter firewall is enabled, a transient systemd
  dead-man timer is armed on every node first, through the cluster's own root
  SSH trust. When it fires it runs `proxmox_firewall_revert_command`
  (`pvesh set /cluster/firewall/options --enable 0`, then
  `/usr/sbin/pve-firewall stop`), so a later reboot cannot re-apply a broken
  ruleset. It is disarmed only after `pve-firewall compile` shows no parser
  warnings, new SSH and 8006 connections from the controller succeed, every
  node reports `enabled/running`, and quorum is intact. A failed verification
  runs the same revert on every reachable node and leaves HA disarmed for a
  manual decision.
- A failure before the first pmxcfs write (staging or the offline validation)
  reverts nothing: the live firewall is unchanged, so the role disarms the
  dead-man timer, restores HA and says so. Reverting there would switch the
  datacenter firewall off because of a typo in the inventory.
- `proxmox_firewall_activate: false` (default) renders `enable: 0` and only
  compiles. An already enabled datacenter firewall is never disabled by the
  role.
- pmxcfs (`/etc/pve`) accepts writes but rejects `chmod`/`chown`. Every file
  is first rendered into a root-only staging tree
  (`proxmox_firewall_staging_root`, seeded with the live content so
  `--check --diff` shows the real change).
- **Offline validation gate before any pmxcfs write:** `files/fw-candidate-check.pl`
  copies the staged candidates into a test directory (with `enable: 1` forced),
  reports every per-rule parse error (unknown IPset/alias, invalid port, bad
  rule type) and compiles the ruleset in PVE's `testdir` mode; the VXLAN guard
  rule and `PVEFW-HOST-IN` must be present. Declared containers on the node
  that runs the check compile with their live config, so a guest that sets
  `enable` must produce its per-NIC chains (`veth<vmid>i<n>-IN/OUT`).
  `pve-firewall compile` alone is
  not a gate: it returns an empty ruleset while the datacenter is disabled, and
  invalid rule lines are dropped silently by the parser.
- Rules cannot reference the automatic `local_network` alias or `management`
  IPset (they only exist at compile time); declare an explicit alias or IPset.
- Staged files are then streamed into pmxcfs with `cat` and compared again;
  host and guest files are written before `cluster.fw`, which holds `enable`.
- `--check` reads HA and stages and validates every file, but never disarms HA,
  arms the dead-man timer or writes to pmxcfs, so it does not wait for the LRMs.
- A failed or timed-out HA disarm restores the saved HA states and stops
  before any firewall file is written. The LRM releases its watchdog only after
  about ten minutes without a configured service (60 rounds of ~10 s), so a
  live run keeps HA resources `ignored` for at least that long.
- The role does not switch to the nftables backend and does not touch SDN.

## Usage

```bash
ansible-playbook -i inventories/example/hosts.yml \
  playbooks/proxmox-firewall.yml --syntax-check

# 1. Render and compile with the datacenter firewall still disabled.
ansible-playbook -i <private-inventory> playbooks/proxmox-firewall.yml \
  --limit <exact-proxmox-node> --tags proxmox_firewall

# 2. Activate under the dead-man timer.
ansible-playbook -i <private-inventory> playbooks/proxmox-firewall.yml \
  --limit <exact-proxmox-node> --tags proxmox_firewall \
  -e '{"proxmox_firewall_activate": true}'
```

## Manual recovery

If the dead-man fired or the role failed after writing to pmxcfs, the
datacenter firewall is already
set to `enable: 0`. Check quorum (`pvecm status`), then re-arm HA with
`ha-manager crm-command arm-ha` (or restore the states from `ha-states.json`
with `ha-manager set <sid> --state <state>`). To retry, restore only the firewall files from
the latest tarball in `proxmox_firewall_backup_root` (pmxcfs rejects owner and
mode changes), confirm `pve-firewall compile`, then run `pve-firewall start` on
each node:

```bash
tar -xzf <file> -C / --no-same-owner --no-same-permissions \
  --wildcards 'etc/pve/firewall/*' 'etc/pve/nodes/*/host.fw'
```
