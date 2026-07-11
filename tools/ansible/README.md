# Ansible Docker Tools

This directory defines a lightweight local Ansible tool image based on
`python:3.12-alpine`.

It installs:

- `ansible-core`
- `ansible-lint`
- `yamllint`
- collections declared in `requirements.yml`
- Infisical CLI `0.43.84`

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

Do not pass secrets as command-line arguments. Use runtime environment variables
or Infisical integration when live validation is intentionally enabled.

## Machine Identity launcher

Put `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` and
`INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` in the untracked `.env`, then run:

```powershell
rtk pwsh -NoProfile -File tools/ansible/Invoke-InfisicalAnsible.ps1 `
  -ProjectId $env:INFISICAL_PROJECT_ID `
  -Environment prod `
  -SecretPath @('/prod/proxmox', '/prod/minio') `
  -RequiredKey @('PROXMOX_API_TOKEN_SECRET', 'OBJECT_STORAGE_ACCESS_KEY', 'OBJECT_STORAGE_SECRET_KEY') `
  -Playbook playbooks/site.yml `
  -InventoryRoot ../infra-ansible-inventory `
  -Inventory inventories/prod/hosts.yml `
  -Limit localhost
```

The launcher obtains an ephemeral token inside the container, injects only
`RequiredKey` values, and scrubs Infisical credentials before Ansible starts.
