# proxmox_change_guard

Shared guard for live Proxmox network changes. It has no default entry point:
a role that owns a change includes it with `include_role` and `tasks_from`.

- `ha.yml` (`proxmox_change_guard_action: disarm|rearm`): saves every
  non-ignored HA resource state to `proxmox_change_guard_state_file`, sets each
  resource to `ignored` and waits until no LRM is `active` (the LRM releases its
  watchdog after about ten minutes without a configured service); `rearm`
  restores the saved states. HA self-fencing resets a node about 60 s after
  quorum loss, faster than any dead-man timer, so watchdogs are released first.
  Only the per-resource mode is used: the cluster-wide `disarm-ha` command is
  avoided while ha-manager versions differ between nodes.
- `deadman.yml` (`proxmox_change_guard_action: arm|disarm`): on every node in
  `proxmox_change_guard_nodes` (local shell or the cluster's root SSH trust with
  the PVE 9 per-node `ssh_known_hosts`), runs the optional
  `proxmox_change_guard_prepare_command`, then arms a transient
  `systemd-run --on-active` timer that runs
  `proxmox_change_guard_revert_command` locally. Neither command may contain a
  double quote.

The caller decides when a change is verified, disarms the dead-man timer and
re-arms HA. On a failed verification the caller reverts and leaves HA disarmed
for a manual decision.
