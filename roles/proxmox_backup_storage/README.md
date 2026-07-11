# proxmox_backup_storage

Provisions one externally managed persistent mount and registers it as a
Proxmox `dir` storage for full `vzdump` backups. The role is disabled by
default, retains exactly the last two backups, and refuses to overwrite a
storage with a different type, path, content, retention, mountpoint guard, or
node scope.

The exact source, filesystem type, mount options, nodes, and any protected CIFS
credentials-file path belong in the private inventory. Never place usernames,
passwords, tokens, or inline credential values in mount options.

Install dependencies and validate syntax before use:

```bash
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i inventories/example/hosts.yml \
  playbooks/proxmox-backup-storage.yml --syntax-check
```

Real operation requires a private inventory, one explicit Proxmox host limit,
and the narrow tag:

```bash
ansible-playbook -i <private-inventory> \
  playbooks/proxmox-backup-storage.yml \
  --limit <exact-proxmox-node> \
  --tags proxmox_backup_storage
```

Run the same command a second time and require zero changes. During a separately
approved maintenance window, reboot and confirm the mount returns. An isolated
unmount test must prove Proxmox marks the storage offline and never writes to
the empty mountpoint on the root filesystem. This role never removes storage,
unmounts a filesystem, prunes backups manually, or edits
`/etc/pve/storage.cfg`.
