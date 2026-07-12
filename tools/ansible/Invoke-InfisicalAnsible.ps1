[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProjectId,
    [Parameter(Mandatory)] [string] $Environment,
    [Parameter(Mandatory)] [string[]] $SecretPath,
    [Parameter(Mandatory)] [string[]] $RequiredKey,
    [Parameter(Mandatory)] [string] $Playbook,
    [string] $Domain = "https://infisical.vinisantana.com",
    [string] $Inventory = "inventories/example/hosts.yml",
    [string] $InventoryRoot,
    [string] $Limit,
    [string] $Tags,
    [string[]] $AdditionalArguments = @(),
    [string] $Image = "infra-ansible-tools:local",
    [string] $EnvFile,
    [switch] $Build
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ContainerWrapper = Join-Path $PSScriptRoot "Invoke-AnsibleContainer.ps1"
$loadedVariables = @()

function Import-DotEnv {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*(?:#|$)') { continue }
        if ($line -notmatch '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            throw "Invalid .env line in $Path"
        }
        $name = $Matches[1]
        $value = $Matches[2].TrimEnd("`r")
        if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
            $script:loadedVariables += $name
        }
    }
}

if (-not $EnvFile) { $EnvFile = Join-Path $RepoRoot ".env" }
try {
    Import-DotEnv -Path $EnvFile
    foreach ($name in @(
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID",
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"
        )) {
        if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
            throw "Required environment variable is missing: $name"
        }
    }

    if ($Build) {
        & $ContainerWrapper -Build -Image $Image -Arguments @("--version")
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    $dockerArgs = @(
        "run", "--rm",
        "-e", "ANSIBLE_CONFIG=/work/ansible.cfg",
        "-e", "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID",
        "-e", "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET",
        "-v", "${RepoRoot}:/work",
        "-w", "/work",
        "--entrypoint", "python3",
        $Image,
        "/work/tools/ansible/infisical_ansible.py",
        "--domain", $Domain,
        "--project-id", $ProjectId,
        "--environment", $Environment
    )
    $containerInventory = $Inventory.Replace('\', '/')
    if ($InventoryRoot) {
        $resolvedInventoryRoot = (Resolve-Path -LiteralPath $InventoryRoot).Path
        $dockerArgs = $dockerArgs[0..9] + @(
            "-v", "${resolvedInventoryRoot}:/inventory:ro"
        ) + $dockerArgs[10..($dockerArgs.Length - 1)]
        $containerInventory = "/inventory/$($containerInventory.TrimStart('/'))"
    }
    foreach ($path in $SecretPath) { $dockerArgs += @("--path", $path) }
    foreach ($key in $RequiredKey) { $dockerArgs += @("--required-key", $key) }
    $dockerArgs += @("--", $Playbook, "-i", $containerInventory)
    if ($Limit) { $dockerArgs += @("--limit", $Limit) }
    if ($Tags) { $dockerArgs += @("--tags", $Tags) }
    $dockerArgs += $AdditionalArguments

    if (Get-Command rtk -ErrorAction SilentlyContinue) {
        & rtk docker @dockerArgs
    }
    else {
        & docker @dockerArgs
    }
}
finally {
    foreach ($name in $loadedVariables) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
}
