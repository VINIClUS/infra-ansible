# infisical_runtime

Validates the runtime secret contract for Infisical without storing or printing
secret values. Authentication happens before Ansible starts through
`tools/ansible/Invoke-InfisicalAnsible.ps1`, using a Machine Identity with
Universal Auth.

The role validates the project ID, environment, explicit secret paths, and
required key names. It rejects the legacy static-token/project-slug contract.
Secret values are allowlisted and injected by the launcher; the role never
fetches, persists, or prints them.
