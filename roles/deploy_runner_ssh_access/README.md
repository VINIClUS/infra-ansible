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
is already present). Requires operator SSH access to
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
