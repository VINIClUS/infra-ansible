# GitHub repository configuration

`Configure-GitHubActions.ps1` reconciles the production safety settings for
`VINIClUS/infra-ansible` through the GitHub REST API. It configures:

- GitHub Actions enabled with `allowed_actions=selected`;
- only GitHub-owned actions and reusable workflows;
- full commit SHA pinning for actions;
- approval of workflows from every external fork contributor;
- the `production` deployment environment;
- `main` protection with the `validate` check, pull requests, linear history,
  and force pushes and deletion disabled.

## Authentication and execution

Authenticate `gh` as a repository administrator with the `repo` and `workflow`
scopes, verify the target repository, and run:

```powershell
gh auth status
pwsh -NoProfile -File tools/github/Configure-GitHubActions.ps1
```

The optional `-Repository owner/name` parameter is restricted to safe GitHub
name characters. Every REST request declares its HTTP method and API version.
Mutating requests serialize canonical PowerShell objects into temporary JSON
files and pass them with `gh api --input`; response bodies are never forwarded
to standard output.

The operation is idempotent: each run discovers optional resources from their
parent collection or branch, reads the exact environment and protection
resource when it already exists, sends the same complete desired state with
`PUT`, and reads back every managed field. Its successful output contains only
setting names and the state `verified`. Any `gh` failure or post-write drift
stops the operation without printing the API response.

Runner registration is intentionally outside this tool. This script never
requests, accepts, stores, or prints a runner registration token.

## Offline contract test

The validator uses a stateful mock `gh`; it does not contact GitHub:

```powershell
pwsh -NoProfile -File tests/Validate-GitHubActionsConfiguration.ps1
```
