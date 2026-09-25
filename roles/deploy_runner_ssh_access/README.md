# deploy_runner_ssh_access

Installs the operator's SSH admin key onto a freshly cloned deploy-runner LXC.
Template `9400` ships with no baked-in SSH key, and Proxmox's `ssh-public-keys`
LXC parameter is create-time-only (its `/config` PUT endpoint rejects it after
the clone), so `bootstrap-deploy-runner.yml` has nothing to authenticate with
until this role runs.

Generates (idempotently, via `creates`) a dedicated ed25519 keypair at
`deploy_runner_ssh_access_key_path` shared by both `runner-cnes-dev` and
`runner-cnes-prod`, then appends the public half to the target VMID's
`/root/.ssh/authorized_keys` from inside the container by SSHing into the
Proxmox node itself and running `pct exec` (idempotent — skips if the key line
is already present).

Template `9400` does ship baked SSH *host* keys, so every clone would share one
SSH identity. With `deploy_runner_ssh_access_template_host_key` set to the
template's `ssh-ed25519` host key, the role first replaces
`/etc/ssh/ssh_host_*` (`ssh-keygen -A`) in a clone that still presents it and
prints the new key to pin in `known_hosts`; a clone that already has its own
keys is left alone. Empty (the default) skips the step. Requires operator SSH access to
`deploy_runner_ssh_access_pve_ssh_host` with
`deploy_runner_ssh_access_pve_ssh_key`.

Run against the exact bootstrap host, after `proxmox_lxc_guest` has already
created and started the target (a separate invocation, since
`proxmox_lxc_guest` asserts it is the only tag in the run):

```bash
ansible-playbook playbooks/provision-deploy-runner.yml \
  --limit <exact-bootstrap-host> \
  --tags deploy_runner_ssh_access
```
