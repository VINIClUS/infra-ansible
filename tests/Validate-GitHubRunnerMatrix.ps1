$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
$FixtureRoot = Join-Path $PSScriptRoot "fixtures/github-runner"
$RunId = [Guid]::NewGuid().ToString("N").Substring(0, 10)
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) "github-runner-matrix-$RunId"
$ArchivePath = Join-Path $TempRoot "fake-runner.tar.gz"
$PlaybookPath = Join-Path $TempRoot "playbook.yml"
$Containers = [System.Collections.Generic.List[string]]::new()

$Cases = @(
    @{
        Name = "Debian 13"
        Dockerfile = Join-Path $FixtureRoot "Dockerfile.debian13"
        Image = "infra-ansible-github-runner-debian13:$RunId"
        Container = "github-runner-debian13-$RunId"
    },
    @{
        Name = "Ubuntu 24.04"
        Dockerfile = Join-Path $FixtureRoot "Dockerfile.ubuntu2404"
        Image = "infra-ansible-github-runner-ubuntu2404:$RunId"
        Container = "github-runner-ubuntu2404-$RunId"
    }
)

function Invoke-Docker {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    $output = & docker @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') failed:`n$($output -join [Environment]::NewLine)"
    }
    return $output
}

function Wait-Systemd {
    param([string]$Container)

    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & docker exec $Container bash -lc "systemctl is-system-running 2>/dev/null | grep -Eq '^(running|degraded)$'" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return
        }
        Start-Sleep -Seconds 1
    }
    throw "systemd did not become ready in $Container"
}

New-Item -ItemType Directory -Path $TempRoot | Out-Null

try {
    & tar -C (Join-Path $FixtureRoot "fake-runner") -czf $ArchivePath .
    if ($LASTEXITCODE -ne 0) {
        throw "failed to package the offline fake runner"
    }
    $ArchiveSha256 = (Get-FileHash -Algorithm SHA256 $ArchivePath).Hash.ToLowerInvariant()

    @"
---
- name: Validate offline GitHub Actions runner role
  hosts: localhost
  connection: local
  gather_facts: true
  roles:
    - role: github_actions_runner
  vars:
    github_actions_runner_archive_url: file:///opt/ansible-test/fake-runner.tar.gz
    github_actions_runner_archive_sha256: $ArchiveSha256
    github_actions_runner_name: matrix-runner
"@ | Set-Content -Path $PlaybookPath -Encoding utf8NoBOM

    foreach ($Case in $Cases) {
        Write-Host "Building $($Case.Name) systemd fixture"
        Invoke-Docker -Arguments @(
            "build", "--file", $Case.Dockerfile, "--tag", $Case.Image, $Root
        ) | Out-Host

        $RunArguments = @(
            "run",
            "--detach",
            "--name", $Case.Container,
            "--privileged",
            "--cgroupns", "host",
            "--volume", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            $Case.Image
        )
        $Containers.Add($Case.Container)
        Invoke-Docker -Arguments $RunArguments | Out-Null
        Wait-Systemd -Container $Case.Container

        Invoke-Docker -Arguments @(
            "exec", $Case.Container, "mkdir", "-p", "/opt/ansible-test/roles"
        ) | Out-Null
        Invoke-Docker -Arguments @(
            "cp",
            (Join-Path $Root "roles/github_actions_runner"),
            "$($Case.Container):/opt/ansible-test/roles/"
        ) | Out-Null
        Invoke-Docker -Arguments @(
            "cp", $ArchivePath, "$($Case.Container):/opt/ansible-test/fake-runner.tar.gz"
        ) | Out-Null
        Invoke-Docker -Arguments @(
            "cp", $PlaybookPath, "$($Case.Container):/opt/ansible-test/playbook.yml"
        ) | Out-Null

        Write-Host "Applying the role to $($Case.Name)"
        $FirstRun = Invoke-Docker -Arguments @(
            "exec",
            "--env", "GITHUB_ACTIONS_RUNNER_REGISTRATION_TOKEN=offline-fixture-token",
            $Case.Container,
            "ansible-playbook", "-i", "localhost,", "/opt/ansible-test/playbook.yml"
        )
        $FirstRun | Out-Host
        if (($FirstRun -join "`n") -notmatch "failed=0") {
            throw "$($Case.Name) first run did not report success"
        }

        $RunnerMetadataJson = Invoke-Docker -Arguments @(
            "exec", $Case.Container, "cat", "/opt/github-actions-runner/.runner"
        )
        $RunnerMetadata = (($RunnerMetadataJson -join "`n") | ConvertFrom-Json)
        $ContainerArchitecture = ((Invoke-Docker -Arguments @(
            "exec", $Case.Container, "dpkg", "--print-architecture"
        )) -join "`n").Trim()
        $ExpectedRunnerArchitecture = switch ($ContainerArchitecture) {
            "amd64" { "x64" }
            "arm64" { "arm64" }
            default { throw "$($Case.Name) reported unsupported architecture $ContainerArchitecture" }
        }
        $ExpectedRunnerLabels = "ansible-prod,linux,$ExpectedRunnerArchitecture"
        if ($RunnerMetadata.name -ne "matrix-runner") {
            throw "$($Case.Name) registered an unexpected runner name"
        }
        if ($RunnerMetadata.labels -ne $ExpectedRunnerLabels) {
            throw "$($Case.Name) registered unexpected runner labels"
        }
        if ($RunnerMetadata.work -ne "/var/lib/github-actions-runner") {
            throw "$($Case.Name) registered an unexpected runner work directory"
        }

        Write-Host "Proving idempotency on $($Case.Name) without a registration token"
        $SecondRun = Invoke-Docker -Arguments @(
            "exec",
            $Case.Container,
            "ansible-playbook", "-i", "localhost,", "/opt/ansible-test/playbook.yml"
        )
        $SecondRun | Out-Host
        if (($SecondRun -join "`n") -notmatch "changed=0") {
            throw "$($Case.Name) second run was not idempotent"
        }

        $ActiveState = Invoke-Docker -Arguments @(
            "exec",
            $Case.Container,
            "bash", "-lc", 'systemctl is-active "$(cat /opt/github-actions-runner/.service)"'
        )
        if (($ActiveState -join "`n").Trim() -ne "active") {
            throw "$($Case.Name) fake runner service is not active"
        }

        Write-Host "$($Case.Name): first run succeeded, second run changed=0, service active"
    }
}
finally {
    foreach ($Container in $Containers) {
        & docker rm --force $Container 2>$null | Out-Null
    }
    Remove-Item -Recurse -Force $TempRoot -ErrorAction SilentlyContinue
}
