[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Read-RequiredFile {
    param([string] $RelativePath)

    $path = Join-Path $RepoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing required path: $RelativePath"
    }
    return Get-Content -Raw -LiteralPath $path
}

function Assert-Contains {
    param(
        [string] $Content,
        [string] $Pattern,
        [string] $Message
    )

    if ($Content -notmatch $Pattern) {
        throw $Message
    }
}

$defaults = Read-RequiredFile "roles\proxmox_backup_storage\defaults\main.yml"
$tasks = Read-RequiredFile "roles\proxmox_backup_storage\tasks\main.yml"
$playbook = Read-RequiredFile "playbooks\proxmox-backup-storage.yml"
$readme = Read-RequiredFile "roles\proxmox_backup_storage\README.md"
$combined = "$defaults`n$tasks`n$playbook`n$readme"

Assert-Contains $defaults 'proxmox_backup_storage_enabled:\s*false' "Role must be disabled by default."
Assert-Contains $defaults 'proxmox_backup_prune_keep_last:\s*2' "Retention must default to two backups."
Assert-Contains $defaults 'proxmox_backup_is_mountpoint:\s*true' "Mountpoint guard must default to true."
Assert-Contains $tasks 'ansible_limit' "Role must require an explicit Ansible limit."
Assert-Contains $tasks 'ansible\.posix\.mount' "Role must persist the mount with ansible.posix.mount."
Assert-Contains $tasks 'findmnt' "Role must verify the live mount with findmnt."
Assert-Contains $tasks 'pvesm' "Role must use the supported pvesm interface."
Assert-Contains $tasks 'config' "Role must read existing storage configuration."
Assert-Contains $tasks 'add' "Role must support adding an absent directory storage."
Assert-Contains $tasks 'is_mountpoint' "Role must enable the Proxmox mountpoint guard."
Assert-Contains $tasks 'keep-last=2' "Role must configure exact keep-last retention."
Assert-Contains $tasks 'no_log:' "Sensitive mount data must be protected from task output."
Assert-Contains $playbook 'proxmox_backup_storage' "Playbook must use the narrow storage role/tag."
Assert-Contains $readme '--limit' "Runbook must require an explicit host limit."

if ($tasks -match 'pvesm\s+remove|storage\.cfg') {
    throw "Role must not remove storage or edit storage.cfg directly."
}

Write-Output "proxmox backup storage role validation passed"
