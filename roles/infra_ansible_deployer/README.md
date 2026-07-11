# infra_ansible_deployer

Installs the root-owned boundary used by the unprivileged production GitHub
Actions runner. The runner can pass one candidate SHA to
`/usr/local/sbin/infra-ansible-deploy`; it cannot choose an inventory,
playbook, host limit, tag, secret path, required secret, or rollback action.
The sudoers glob narrows command dispatch but is not validation. The Python
boundary accepts exactly one lowercase 40-character SHA and independently
requires it to equal both the public GitHub `main` ref and a clean root-owned
checkout.

Set `infra_ansible_deployer_public_sha` and
`infra_ansible_deployer_inventory_sha` to exact commits during bootstrap. The
role checks out both repositories under `/srv`, owned by root. Bootstrap also
requires `INFRA_INVENTORY_DEPLOY_KEY`,
`INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`, and
`INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` in the Ansible controller
environment. Their values are installed only in mode-0600 root files, and all
secret-bearing tasks use `no_log`.

At deployment time the boundary locks
`/run/lock/infra-ansible-deploy.lock`, validates public `main`, updates private
inventory `main`, runs both private inventory validators, records its exact
commit, and then runs only the fixed controller, edge, and Cloudflare Access
sequence. It obtains only each run's fixed Infisical allowlist. Secret values
are child environment values and never command-line arguments. A failure after
the controller switch invokes the fixed rollback playbook before the original
failure is returned.
