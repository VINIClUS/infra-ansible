[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Assert-PathExists {
    param([string] $RelativePath)

    $path = Join-Path $RepoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing required path: $RelativePath"
    }
}

function Assert-FileContains {
    param(
        [string] $RelativePath,
        [string] $Pattern
    )

    $path = Join-Path $RepoRoot $RelativePath
    Assert-PathExists -RelativePath $RelativePath
    $content = Get-Content -Raw -LiteralPath $path
    if ($content -notmatch $Pattern) {
        throw "File $RelativePath does not contain expected pattern: $Pattern"
    }
}

Assert-PathExists -RelativePath "tools\ansible\Dockerfile"
Assert-PathExists -RelativePath "tools\ansible\Invoke-AnsibleContainer.ps1"
Assert-PathExists -RelativePath "tools\ansible\Invoke-InfisicalAnsible.ps1"
Assert-PathExists -RelativePath "tools\ansible\README.md"
Assert-PathExists -RelativePath ".dockerignore"

Assert-FileContains -RelativePath ".dockerignore" -Pattern "\.env"
Assert-FileContains -RelativePath ".dockerignore" -Pattern "\.git"
Assert-FileContains -RelativePath ".dockerignore" -Pattern "vault"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "python:3\.12-alpine"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "COPY requirements\.yml"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "ansible-galaxy collection install"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "ansible-core"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "ansible-lint"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "yamllint"
Assert-FileContains -RelativePath "requirements.yml" -Pattern "community\.proxmox"
Assert-FileContains -RelativePath "requirements.yml" -Pattern "community\.postgresql"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern 'proxmoxer>=2\.3'
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "psycopg"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "requests"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "age"
Assert-FileContains -RelativePath "tools\ansible\Invoke-AnsibleContainer.ps1" -Pattern "Invoke-Docker"
Assert-FileContains -RelativePath "tools\ansible\Invoke-AnsibleContainer.ps1" -Pattern "ANSIBLE_CONFIG=/work/ansible.cfg"
Assert-FileContains -RelativePath "tools\ansible\Invoke-AnsibleContainer.ps1" -Pattern "infra-ansible-tools:local"

$mockRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString("N"))
$mockLog = Join-Path $mockRoot "rtk-args.log"
$mockRtk = Join-Path $mockRoot $(if ($IsWindows) { "rtk.cmd" } else { "rtk" })
New-Item -ItemType Directory -Path $mockRoot | Out-Null
try {
    if ($IsWindows) {
        @"
@echo off
echo %*>>"%RTK_MOCK_LOG%"
"@ | Set-Content -LiteralPath $mockRtk -Encoding ASCII
    }
    else {
        @'
#!/bin/sh
printf '%s\n' "$*" >> "$RTK_MOCK_LOG"
'@ | Set-Content -LiteralPath $mockRtk -Encoding utf8NoBOM
        & chmod +x $mockRtk
    }

    $previousPath = $env:PATH
    $previousLog = $env:RTK_MOCK_LOG
    $env:PATH = "$mockRoot$([System.IO.Path]::PathSeparator)$previousPath"
    $env:RTK_MOCK_LOG = $mockLog

    & (Join-Path $RepoRoot "tools\ansible\Invoke-AnsibleContainer.ps1") -Arguments @("--version")
    if ($LASTEXITCODE -ne 0) {
        throw "Mocked wrapper execution failed with exit code $LASTEXITCODE"
    }

    $mockedInvocation = Get-Content -Raw -LiteralPath $mockLog
    foreach ($expected in @(
            "docker run",
            "--rm",
            "ANSIBLE_CONFIG=/work/ansible.cfg",
            "/work",
            "infra-ansible-tools:local",
            "--version"
        )) {
        if ($mockedInvocation -notmatch [regex]::Escape($expected)) {
            throw "Mocked wrapper invocation did not include: $expected"
        }
    }

    Clear-Content -LiteralPath $mockLog
    $env:INFISICAL_UNIVERSAL_AUTH_CLIENT_ID = "test-client-id"
    $env:INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET = "test-client-secret"
    & (Join-Path $RepoRoot "tools\ansible\Invoke-InfisicalAnsible.ps1") `
        -ProjectId "test-project" `
        -Environment "prod" `
        -SecretPath @("/infra/minio") `
        -RequiredKey @("OBJECT_STORAGE_ACCESS_KEY", "OBJECT_STORAGE_SECRET_KEY") `
        -Playbook "playbooks/site.yml" `
        -InventoryRoot $RepoRoot `
        -Inventory "inventories/example/hosts.yml" `
        -Limit "localhost" `
        -Tags "validation"
    if ($LASTEXITCODE -ne 0) {
        throw "Mocked Infisical wrapper execution failed with exit code $LASTEXITCODE"
    }

    $infisicalInvocation = Get-Content -Raw -LiteralPath $mockLog
    foreach ($expected in @(
            "docker run",
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID",
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET",
            "tools/ansible/infisical_ansible.py",
            "--project-id test-project",
            "--environment prod",
            "--path /infra/minio",
            "--required-key OBJECT_STORAGE_ACCESS_KEY",
            "--required-key OBJECT_STORAGE_SECRET_KEY",
            "playbooks/site.yml",
            ":/inventory:ro",
            "-i /inventory/inventories/example/hosts.yml",
            "--limit localhost",
            "--tags validation"
        )) {
        if ($infisicalInvocation -notmatch [regex]::Escape($expected)) {
            throw "Mocked Infisical invocation did not include: $expected"
        }
    }
    if ($infisicalInvocation -match "test-client-secret") {
        throw "Infisical client secret was exposed in Docker arguments"
    }
}
finally {
    $env:PATH = $previousPath
    $env:RTK_MOCK_LOG = $previousLog
    Remove-Item Env:INFISICAL_UNIVERSAL_AUTH_CLIENT_ID -ErrorAction SilentlyContinue
    Remove-Item Env:INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $mockRoot) {
        Remove-Item -LiteralPath $mockRoot -Recurse -Force
    }
}

Write-Output "ansible container scaffold validation passed"
