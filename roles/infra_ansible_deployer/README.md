# infra_ansible_deployer

Installs the root-owned boundary used by the unprivileged production GitHub
Actions runner. The runner can pass one candidate SHA to
`/usr/local/sbin/infra-ansible-deploy`; it cannot choose an inventory,
playbook, host limit, tag, secret path, required secret, or rollback action.
The command-scoped sudo policy forbids caller environment preservation, sets a
fixed secure path, and uses a full-string SHA regular expression. Sudo dispatch
is still not treated as validation. The Python boundary accepts exactly one
lowercase 40-character SHA and independently requires it to equal both the
public GitHub `main` ref and a clean root-owned checkout.

PowerShell 7.6.3 is installed from its exact upstream release archive with a
pinned SHA-256 checksum. This keeps the role installable on stock Debian
without a vendor APT repository or an unpinned `latest` channel. It is
extracted into an immutable version directory and activated through a
root-owned link in `/usr/local/bin`.

Set `infra_ansible_deployer_public_sha` and
`infra_ansible_deployer_inventory_sha` to exact commits during bootstrap. The
role checks out both repositories under `/srv`, owned by root. Bootstrap also
requires `ANSIBLE_EDGE_SSH_PRIVATE_KEY`, `INFRA_INVENTORY_DEPLOY_KEY`, and
`ANSIBLE_VAULT_PASSWORD` in the Ansible controller environment. The dedicated
edge key is validated as an OpenSSH private key and installed at
`/etc/infra-ansible-deploy/edge-ssh-key`; the vault password is installed at
`/etc/infra-ansible-deploy/vault-pass`. Their values are installed only in
mode-0600 root files, and all secret-bearing tasks use `no_log`.

At deployment time the boundary locks the mode-0600 regular file
`/run/infra-ansible/deploy.lock` inside a root-only mode-0700 runtime
directory, validates public `main`, updates private
inventory `main`, runs both private inventory validators, records its exact
commit, and then runs only the fixed controller, edge, and Cloudflare Access
sequence. Every run decrypts the inventory's ansible-vault group_vars through
`--vault-password-file`; secret values never appear as command-line
arguments. A failure after the controller switch invokes the fixed rollback
playbook before the original failure is returned.

The same role installs a second, narrower boundary for esusdata:
`/usr/local/sbin/esusdata-deploy` (`tools/deploy/esusdata_deploy.py`). The
runner may call it with no argument, which deploys the latest published
esusdata release when it differs from the recorded state, or with one exact
`vX.Y.Z` tag. The script resolves the release through the public GitHub API,
accepts only a final release that carries the signed package, takes the same
deployment lock, requires both `/srv` checkouts to be clean, and runs only
`playbooks/esusdata-service.yml --limit esusdata-lxc --tags esusdata_service`.
Its SSH key comes from the inventory vault
(`infra_ansible_deployer_esusdata_ssh_private_key`) and is installed at
`/etc/infra-ansible-deploy/esusdata-ssh-key`. The last successful and the last
failed attempt (release plus both checkout SHAs) are recorded in
`/var/lib/esusdata-deploy/state.json`: a scheduled run skips an attempt
identical to either, so a failed release is not retried until the release or
the infra/inventory checkout changes, and an infra or inventory change
reapplies the current release. An explicit tag always deploys.
