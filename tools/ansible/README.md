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

Do not pass secrets as command-line arguments. Use runtime environment variables
or Infisical integration when live validation is intentionally enabled.
