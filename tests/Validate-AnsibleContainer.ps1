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
Assert-FileContains -RelativePath "tools\ansible\Invoke-AnsibleContainer.ps1" -Pattern "Invoke-Docker"
Assert-FileContains -RelativePath "tools\ansible\Invoke-AnsibleContainer.ps1" -Pattern "ANSIBLE_CONFIG=/work/ansible.cfg"
Assert-FileContains -RelativePath "tools\ansible\Invoke-AnsibleContainer.ps1" -Pattern "infra-ansible-tools:local"

$mockRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString("N"))
$mockLog = Join-Path $mockRoot "rtk-args.log"
$mockRtk = Join-Path $mockRoot "rtk.cmd"
New-Item -ItemType Directory -Path $mockRoot | Out-Null
try {
    @"
@echo off
echo %*>>"%RTK_MOCK_LOG%"
"@ | Set-Content -LiteralPath $mockRtk -Encoding ASCII

    $previousPath = $env:PATH
    $previousLog = $env:RTK_MOCK_LOG
    $env:PATH = "$mockRoot;$previousPath"
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
}
finally {
    $env:PATH = $previousPath
    $env:RTK_MOCK_LOG = $previousLog
    if (Test-Path -LiteralPath $mockRoot) {
        Remove-Item -LiteralPath $mockRoot -Recurse -Force
    }
}

Write-Output "ansible container scaffold validation passed"
