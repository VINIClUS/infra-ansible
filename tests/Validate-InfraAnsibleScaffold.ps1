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

$requiredPaths = @(
    "ansible.cfg",
    "requirements.yml",
    "docs\architecture.md",
    "docs\safety.md",
    "inventories\example\hosts.yml",
    "inventories\example\group_vars\all.yml",
    "playbooks\site.yml",
    "playbooks\validate-infisical-access.yml",
    "playbooks\validate-minio-access.yml",
    "playbooks\proxmox-template-preflight.yml",
    "playbooks\proxmox-backup-storage.yml",
    "playbooks\publish-validation-report.yml",
    "playbooks\bootstrap-esus-pec.yml",
    "playbooks\bootstrap-sus-siha.yml",
    "playbooks\linux-baseline.yml",
    "playbooks\monitoring-agent.yml",
    "roles\bootstrap_bridge\tasks\main.yml",
    "roles\common_base\tasks\main.yml",
    "roles\ssh_hardening\tasks\main.yml",
    "roles\firewall_base\tasks\main.yml",
    "roles\cloudinit_guest\tasks\main.yml",
    "roles\infisical_runtime\tasks\main.yml",
    "roles\minio_artifacts\tasks\main.yml",
    "roles\monitoring_agent\tasks\main.yml",
    "roles\backup_client\tasks\main.yml",
    "roles\proxmox_readonly\tasks\main.yml",
    "roles\proxmox_backup_storage\defaults\main.yml",
    "roles\proxmox_backup_storage\tasks\main.yml",
    "roles\proxmox_backup_storage\handlers\main.yml",
    "roles\proxmox_backup_storage\README.md"
)

foreach ($relativePath in $requiredPaths) {
    Assert-PathExists -RelativePath $relativePath
}

Assert-FileContains -RelativePath "docs\safety.md" -Pattern "Infisical"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "MinIO"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "No secrets in Git"
Assert-FileContains -RelativePath "inventories\example\group_vars\all.yml" -Pattern "infisical_secret_paths"
Assert-FileContains -RelativePath "inventories\example\group_vars\all.yml" -Pattern "minio_buckets"
Assert-FileContains -RelativePath "roles\bootstrap_bridge\tasks\main.yml" -Pattern "bootstrap_bridge_repo_ref"

Write-Output "infra-ansible scaffold validation passed"
