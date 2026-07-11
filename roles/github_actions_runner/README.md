# github_actions_runner

Installs an exact, checksum-verified GitHub Actions runner release on a Debian
or Ubuntu systemd host. The role supports x86_64 and aarch64 LXC guests and VMs,
uses a dedicated system account, and installs the service through the runner's
generated `svc.sh` helper.

The default runner is repository-scoped to
`https://github.com/VINIClUS/infra-ansible`, is named after the inventory host,
and carries the labels `ansible-prod`, `linux`, and `x64`. Production inventory
can set `github_actions_runner_name` to
`ansible-prod-{{ ansible_controller_vmid }}`.

Initial bootstrap requires `GITHUB_ACTIONS_RUNNER_REGISTRATION_TOKEN` in the
Ansible controller environment. The role reads it only while `.runner` is
absent, marks both validation and registration as `no_log`, and never persists
the token in Ansible-managed files. Subsequent runs do not require the token.

Runner files are extracted into a versioned release directory and activated at
`/opt/github-actions-runner`. The generated systemd unit is enabled and started.
The official runner's built-in self-update remains enabled; the role reports
only its effective version, name, labels, and service state.

The role does not add sudoers entries. Workflows needing privileged operations
must receive narrowly scoped authorization separately.
