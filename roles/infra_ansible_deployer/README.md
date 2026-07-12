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

Infisical CLI 0.43.84 and PowerShell 7.6.3 are installed from their exact
upstream release archives with pinned SHA-256 checksums. This keeps the role
installable on stock Debian without a vendor APT repository or an unpinned
`latest` channel. Both tools are extracted into immutable version directories
and activated through root-owned links in `/usr/local/bin`.

Set `infra_ansible_deployer_public_sha` and
`infra_ansible_deployer_inventory_sha` to exact commits during bootstrap. The
role checks out both repositories under `/srv`, owned by root. Bootstrap also
requires `ANSIBLE_EDGE_SSH_PRIVATE_KEY`, `INFRA_INVENTORY_DEPLOY_KEY`,
`INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`, and
`INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` in the Ansible controller
environment. The dedicated edge key is validated as an OpenSSH private key and
installed at `/etc/infra-ansible-deploy/edge-ssh-key`. Their values are
installed only in mode-0600 root files, and all secret-bearing tasks use
`no_log`.

At deployment time the boundary locks the mode-0600 regular file
`/run/infra-ansible/deploy.lock` inside a root-only mode-0700 runtime
directory, validates public `main`, updates private
inventory `main`, runs both private inventory validators, records its exact
commit, and then runs only the fixed controller, edge, and Cloudflare Access
sequence. It obtains only each run's fixed Infisical allowlist. Secret values
are child environment values and never command-line arguments. A failure after
the controller switch invokes the fixed rollback playbook before the original
failure is returned.
