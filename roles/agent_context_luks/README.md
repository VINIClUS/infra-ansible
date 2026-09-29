# agent_context_luks

Gives the Agent Context stack on a single-disk VPS two encrypted filesystems
backed by LUKS2 container files (loop devices) on the existing ext4 root:

| Volume | Container file (default) | Mountpoint (default) | Options |
| --- | --- | --- | --- |
| data | `/var/lib/agent-context-luks/data.luks` | `/srv/agent-context` | `nodev,nosuid` |
| backup | `/var/lib/agent-context-luks/backup.luks` | `/srv/infra-backups/agent-context` | `nodev,nosuid,noexec` |

Data stays exec-capable because Neo4j loads plugins and native libraries from
its data tree; tighten it once that is measured. The backup volume is a
separate filesystem and never executes anything.

Disabled by default (`agent_context_luks_enabled: false`). Every play targets
`agent_context_vps`, which the private inventory defines; always run with an
exact `--limit <host>`; each playbook asserts that exactly one host is in the
play. Every configured path must be absolute and normalized, and the mount root
must not be `/` or inside `/proc`, `/sys`, `/dev`, `/run` or `/tmp`. These playbooks are deliberately not in the deploy
boundary's allowlist or any workflow: a push to `main` never runs them, and an
operator runs them by hand. Nothing here touches Docker, containers, Caddy,
networking or other mounts.

## Inventory (private vault)

- `agent_context_luks_data_size`, `agent_context_luks_backup_size`: required,
  `<integer>G` or `<integer>M`.
- `agent_context_luks_data_key`, `agent_context_luks_backup_key`: required, at
  least 32 characters, different from each other.

Keys are passed to `cryptsetup` only on stdin (`--key-file=-`). They are never
written to disk, argv, environment, facts or logs; every task that sees one has
`no_log: true`. There is no keyfile, crypttab or auto-unlock: after each boot
the volumes stay closed until the unlock playbook runs. The playbooks set
`ansible_pipelining: true` because otherwise Ansible copies each module, with
its arguments and so the key, to a temporary file on the remote disk.

## Provision (one-shot)

```sh
ansible-playbook playbooks/agent-context-luks-provision.yml --limit <host> \
  -e agent_context_luks_confirm_provision=format-new-agent-context-containers
```

Allocates each file with `fallocate` (not sparse, `0600` in a `0700` root
directory), formats LUKS2 with `argon2id` (memory bounded by
`agent_context_luks_pbkdf_memory`, default 256 MiB), creates a labelled ext4,
and closes it again. Preflight requires free space for both files plus
`agent_context_luks_free_space_margin`, and mountpoints that are root-owned,
not symlinks, and absent or empty. It never reformats: an existing container
file, LUKS header, active mapping or mounted target fails the run, and there is
no override variable. If one volume fails, only its own new file is removed; a
rerun then refuses because the other new container file exists, and the operator
must delete that leftover file by hand first.

No action supports `--check` (the probes are real and the changes cannot be
simulated), so the enabled role fails clearly under it. Owner and group are
asserted to be root on `agent_context_vps` hosts (the variables exist only so
the execution tests can run unprivileged). The container file is
created with an exclusive open, so an existing file fails instead of being
reused; the file is checked again (same inode, not LUKS) right before
`luksFormat`, and a failed run removes only a file it created itself.

If cleanup after a failed volume cannot be confirmed safe (the mapping is still
active or a loop device still references the file), the file is kept and the
run fails saying so. Recover by hand: check `cryptsetup status <mapper>` and
`losetup -j <container>`, close the mapping (`cryptsetup close <mapper>`) and
detach the loop device (`losetup -d <device>`), then delete the leftover
container file yourself and rerun.

## Identity checks

Unlock, close and the provision preflight all identify each volume first
(`cryptsetup status`, `losetup -j`, `blkid`, `findmnt -J`), for both volumes
before any change:

- An active mapping under our name whose backing file is not exactly the
  configured container is foreign: the run fails and never reuses or closes it.
- A mount at our mountpoint whose source is not our mapping is foreign: the run
  fails and never unmounts it.
- A stacked mount (another filesystem over ours) or a mount with children at
  our mountpoint is ambiguous and fails; exactly one plain mount is accepted.
- Unexpected tool exit codes are errors, never "absent" (`cryptsetup status`
  4 means inactive, `blkid` must report `crypto_LUKS` for a container).
- A mapping opened by a failed unlock is closed again, only if this run opened
  it and only after identifying it once more.
- A mount of our mapping that is not ext4 or lacks a configured option
  (`nodev`, `nosuid`, plus `noexec` on backup) also fails, never a silent ok.
  Close and unlock again, or remount by hand; the role does not remount live
  filesystems.
- Mountpoint parents (`agent_context_luks_mount_root`, default `/srv`, and every
  directory below it) must be real directories owned by root and not
  group/world-writable; missing ones are created explicitly with `0755`.

## Unlock and close

```sh
ansible-playbook playbooks/agent-context-luks-unlock.yml --limit <host>
ansible-playbook playbooks/agent-context-luks-unlock.yml --limit <host> -e agent_context_luks_action=close
```

Unlock opens both volumes and mounts them with a plain
`mount -t ext4 -o <options>` command, so no `/etc/fstab` entry can block boot; an already open and mounted volume reports
ok. Close is for maintenance: stop the stack first, since a busy mount fails.
