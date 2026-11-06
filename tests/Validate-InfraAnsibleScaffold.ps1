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
    ".env.example",
    ".yamllint",
    "ansible.cfg",
    "requirements.yml",
    "docs\architecture.md",
    "docs\safety.md",
    "inventories\example\hosts.yml",
    "inventories\example\group_vars\all.yml",
    "playbooks\site.yml",
    "playbooks\validate-minio-access.yml",
    "playbooks\proxmox-template-preflight.yml",
    "playbooks\proxmox-backup-storage.yml",
    "playbooks\proxmox-firewall.yml",
    "playbooks\provision-ansible-controller.yml",
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
    "roles\minio_artifacts\tasks\main.yml",
    "roles\monitoring_agent\tasks\main.yml",
    "roles\backup_client\tasks\main.yml",
    "roles\proxmox_readonly\tasks\main.yml",
    "roles\proxmox_backup_storage\defaults\main.yml",
    "roles\proxmox_backup_storage\tasks\main.yml",
    "roles\proxmox_backup_storage\handlers\main.yml",
    "roles\proxmox_backup_storage\README.md",
    "roles\proxmox_firewall\defaults\main.yml",
    "roles\proxmox_firewall\tasks\main.yml",
    "roles\proxmox_firewall\tasks\deadman.yml",
    "roles\proxmox_firewall\README.md",
    "playbooks\proxmox-sdn.yml",
    "playbooks\proxmox-router-vm.yml",
    "playbooks\network-router.yml",
    "playbooks\proxmox-node-routes.yml",
    "roles\proxmox_change_guard\tasks\ha.yml",
    "roles\proxmox_change_guard\tasks\deadman.yml",
    "roles\proxmox_change_guard\README.md",
    "roles\proxmox_sdn\defaults\main.yml",
    "roles\proxmox_sdn\tasks\main.yml",
    "roles\proxmox_sdn\files\sdn-node-check.sh",
    "roles\proxmox_sdn\README.md",
    "roles\proxmox_router_vm\defaults\main.yml",
    "roles\proxmox_router_vm\tasks\main.yml",
    "roles\proxmox_router_vm\README.md",
    "roles\network_router\defaults\main.yml",
    "roles\network_router\tasks\main.yml",
    "roles\network_router\templates\nftables.conf.j2",
    "roles\network_router\README.md",
    "roles\proxmox_node_routes\defaults\main.yml",
    "roles\proxmox_node_routes\tasks\main.yml",
    "roles\proxmox_node_routes\README.md",
    "roles\proxmox_guest_network\defaults\main.yml",
    "roles\proxmox_guest_network\tasks\main.yml",
    "roles\proxmox_guest_network\files\guest-probe.sh",
    "roles\proxmox_guest_network\files\guest-mtu.sh",
    "roles\proxmox_guest_network\README.md",
    "playbooks\proxmox-guest-network.yml",
    "roles\proxmox_guest_routes\defaults\main.yml",
    "roles\proxmox_guest_routes\tasks\main.yml",
    "roles\proxmox_guest_routes\README.md",
    "playbooks\proxmox-guest-routes.yml",
    "roles\proxmox_lxc_guest\defaults\main.yml",
    "roles\proxmox_lxc_guest\tasks\main.yml",
    "roles\proxmox_lxc_guest\README.md",
    "docs\runbook-secret-rotation.md"
)

foreach ($relativePath in $requiredPaths) {
    Assert-PathExists -RelativePath $relativePath
}

Assert-FileContains -RelativePath "docs\safety.md" -Pattern "Infisical"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "MinIO"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "No secrets in Git"
Assert-FileContains -RelativePath "docs\architecture.md" -Pattern "ansible-vault"
Assert-FileContains -RelativePath "docs\architecture.md" -Pattern "project\s+repositories"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "vault_password_file"
$envExample = Get-Content -Raw -LiteralPath (Join-Path $RepoRoot ".env.example")
foreach ($requiredVariable in @(
        "ANSIBLE_VAULT_PASSWORD=",
        "OBJECT_STORAGE_ACCESS_KEY=",
        "OBJECT_STORAGE_SECRET_KEY="
    )) {
    if ($envExample -notmatch [regex]::Escape($requiredVariable)) {
        throw ".env.example does not declare $requiredVariable"
    }
}
foreach ($legacyVariable in @(
        "INFISICAL_TOKEN=",
        "INFISICAL_PROJECT_SLUG=",
        "INVENTORY_INFISICAL_",
        "MINIO_ACCESS_KEY=",
        "MINIO_SECRET_KEY="
    )) {
    if ($envExample -match [regex]::Escape($legacyVariable)) {
        throw ".env.example still declares legacy variable $legacyVariable"
    }
}
if ($envExample -match "(?m)^INFISICAL_SECRET_PATH=") {
    throw "INFISICAL_SECRET_PATH must be derived instead of configured"
}
Assert-FileContains -RelativePath "docs\architecture.md" -Pattern "proxmox_backup_storage"
Assert-FileContains -RelativePath "docs\architecture.md" -Pattern "proxmox_firewall"
Assert-FileContains -RelativePath "roles\proxmox_firewall\defaults\main.yml" -Pattern "proxmox_firewall_enabled:\s+false"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "dead-man"
foreach ($disabledRole in @("proxmox_sdn", "proxmox_router_vm", "network_router", "proxmox_node_routes", "proxmox_guest_network", "proxmox_guest_routes")) {
    Assert-FileContains -RelativePath "roles\$disabledRole\defaults\main.yml" -Pattern "$($disabledRole)_enabled:\s+false"
}
Assert-FileContains -RelativePath "docs\architecture.md" -Pattern "proxmox_change_guard"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "nft --check"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "ha-manager set --state"
Assert-FileContains -RelativePath "docs\architecture.md" -Pattern "keep-last=2"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "is_mountpoint"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "--limit"
Assert-FileContains -RelativePath "docs\safety.md" -Pattern "recovery-preflight"
Assert-FileContains -RelativePath "inventories\example\group_vars\all.yml" -Pattern "minio_buckets"
Assert-FileContains -RelativePath "inventories\example\group_vars\all.yml" -Pattern "pve_token_secret"
Assert-FileContains -RelativePath "inventories\example\group_vars\all.yml" -Pattern "OBJECT_STORAGE_ACCESS_KEY"
Assert-FileContains -RelativePath "inventories\example\group_vars\all.yml" -Pattern "OBJECT_STORAGE_SECRET_KEY"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "boto3>=1\.35\.0"
Assert-FileContains -RelativePath "requirements.yml" -Pattern "community\.proxmox"
Assert-FileContains -RelativePath "roles\proxmox_lxc_guest\defaults\main.yml" -Pattern "proxmox_lxc_guest_enabled:\s+false"
Assert-FileContains -RelativePath "roles\proxmox_lxc_guest\tasks\main.yml" -Pattern "community\.proxmox\.proxmox"
Assert-FileContains -RelativePath "playbooks\provision-ansible-controller.yml" -Pattern "ansible_controller_bootstrap"
Assert-FileContains -RelativePath "requirements.yml" -Pattern "community\.postgresql"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern 'proxmoxer>=2\.3'
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "psycopg"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "requests"
Assert-FileContains -RelativePath "tools\ansible\Dockerfile" -Pattern "age"
Assert-FileContains -RelativePath "roles\minio_artifacts\tasks\main.yml" -Pattern "amazon\.aws\.s3_bucket_info"
$exampleHosts = Get-Content -Raw -LiteralPath (Join-Path $RepoRoot "inventories\example\hosts.yml")
foreach ($projectGroup in @("esus_pec:", "sus_siha:")) {
    if ($exampleHosts -match [regex]::Escape($projectGroup)) {
        throw "Shared example inventory still declares project group $projectGroup"
    }
}
Assert-FileContains -RelativePath "roles\bootstrap_bridge\tasks\main.yml" -Pattern "bootstrap_bridge_repo_ref"

Write-Output "infra-ansible scaffold validation passed"
