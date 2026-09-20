# Ansible Docker Tools

This directory defines a lightweight local Ansible tool image based on
`python:3.12-alpine`.

It installs:

- `ansible-core`
- `ansible-lint`
- `yamllint`
- collections declared in `requirements.yml`

Build:

```powershell
rtk docker build -t infra-ansible-tools:local -f tools\ansible\Dockerfile .
```

Run Ansible through the wrapper:

```powershell
rtk powershell -NoProfile -ExecutionPolicy Bypass -File tools\ansible\Invoke-AnsibleContainer.ps1 -Arguments @("--version")
```

Run ad-hoc commands directly:

```powershell
rtk docker run --rm -e ANSIBLE_CONFIG=/work/ansible.cfg -v ${PWD}:/work -w /work --entrypoint ansible-inventory infra-ansible-tools:local -i inventories/example/hosts.yml --graph
```

Do not pass secrets as command-line arguments.

## Running against the private inventory

Real secrets live in `infra-ansible-inventory`'s ansible-vault
(`group_vars/*/vault.yml`), not in this repository. To run a playbook against
that inventory from the container, mount both repositories and set the vault
password as an environment variable rather than a file the container can read
by accident:

```powershell
rtk docker run --rm `
  -e ANSIBLE_VAULT_PASSWORD `
  -v ${PWD}:/work/infra-ansible `
  -v ${PWD}\..\infra-ansible-inventory:/work/infra-ansible-inventory `
  -w /work/infra-ansible-inventory `
  infra-ansible-tools:local `
  -i inventories/prod/hosts.yml ../infra-ansible/playbooks/site.yml --limit localhost
```

`infra-ansible-inventory/ansible.cfg` sets `vault_password_file` to
`tools/vault/get-vault-pass.sh`, which reads `ANSIBLE_VAULT_PASSWORD` from the
environment. See `docs/safety.md` and
`docs/runbook-secret-rotation.md` in this repository for the full secret
model and rotation procedures.
