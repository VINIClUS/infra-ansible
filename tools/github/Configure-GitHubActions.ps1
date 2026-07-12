[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string] $Repository = "VINIClUS/infra-ansible"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

$ApiVersion = "2026-03-10"
$RepositoryParts = $Repository.Split('/', 2)
$Owner = [Uri]::EscapeDataString($RepositoryParts[0])
$Name = [Uri]::EscapeDataString($RepositoryParts[1])
$RepositoryEndpoint = "repos/$Owner/$Name"

function Invoke-GitHubApi {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("GET", "PUT")]
        [string] $Method,

        [Parameter(Mandatory)]
        [string] $Endpoint,

        [Parameter()]
        [object] $Body,

        [Parameter()]
        [switch] $WithBody
    )

    $arguments = @(
        "api",
        $Endpoint,
        "--method", $Method,
        "--header", "Accept: application/vnd.github+json",
        "--header", "X-GitHub-Api-Version: $ApiVersion"
    )
    $bodyPath = $null

    try {
        if ($WithBody) {
            $bodyPath = [IO.Path]::GetTempFileName()
            $json = $Body | ConvertTo-Json -Compress -Depth 20
            [IO.File]::WriteAllText($bodyPath, $json, [Text.UTF8Encoding]::new($false))
            $arguments += @("--input", $bodyPath)
        }

        try {
            $responseLines = @(& gh @arguments 2>&1)
            $exitCode = $LASTEXITCODE
        }
        catch {
            throw "gh api $Method $Endpoint could not be executed"
        }

        if ($exitCode -ne 0) {
            throw "gh api $Method $Endpoint failed with exit code $exitCode"
        }

        $responseText = ($responseLines -join [Environment]::NewLine).Trim()
        if ($responseText.Length -eq 0) {
            return $null
        }

        try {
            return $responseText | ConvertFrom-Json -Depth 20
        }
        catch {
            throw "gh api $Method $Endpoint returned invalid JSON"
        }
    }
    finally {
        if ($null -ne $bodyPath) {
            Remove-Item -Force -LiteralPath $bodyPath -ErrorAction SilentlyContinue
        }
    }
}

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory)]
        [object] $InputObject,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $Setting
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "$Setting verification did not return $Name"
    }
    return $property.Value
}

$actionsEndpoint = "$RepositoryEndpoint/actions/permissions"
$selectedActionsEndpoint = "$actionsEndpoint/selected-actions"
$forkApprovalEndpoint = "$actionsEndpoint/fork-pr-contributor-approval"
$environmentsEndpoint = "$RepositoryEndpoint/environments"
$environmentEndpoint = "$environmentsEndpoint/production"
$branchEndpoint = "$RepositoryEndpoint/branches/main"
$protectionEndpoint = "$branchEndpoint/protection"

$actionsBody = [ordered]@{
    enabled = $true
    allowed_actions = "selected"
    sha_pinning_required = $true
}
$selectedActionsBody = [ordered]@{
    github_owned_allowed = $true
    verified_allowed = $false
    patterns_allowed = @()
}
$forkApprovalBody = [ordered]@{
    approval_policy = "all_external_contributors"
}
$environmentBody = [ordered]@{}
$protectionBody = [ordered]@{
    required_status_checks = [ordered]@{
        strict = $true
        contexts = @("validate")
    }
    enforce_admins = $true
    required_pull_request_reviews = [ordered]@{
        dismiss_stale_reviews = $false
        require_code_owner_reviews = $false
        required_approving_review_count = 0
        require_last_push_approval = $false
    }
    restrictions = $null
    required_linear_history = $true
    allow_force_pushes = $false
    allow_deletions = $false
}

# Read all existing settings through endpoints that remain successful before the
# environment and branch protection are created.
$null = Invoke-GitHubApi -Method GET -Endpoint $actionsEndpoint
$null = Invoke-GitHubApi -Method GET -Endpoint $selectedActionsEndpoint
$null = Invoke-GitHubApi -Method GET -Endpoint $forkApprovalEndpoint
$null = Invoke-GitHubApi -Method GET -Endpoint $environmentsEndpoint
$branch = Invoke-GitHubApi -Method GET -Endpoint $branchEndpoint
if ((Get-RequiredProperty -InputObject $branch -Name "name" -Setting "main branch") -cne "main") {
    throw "main branch verification returned an unexpected branch"
}

# PUT is idempotent for these REST resources. Supplying complete canonical JSON
# on every run also removes drift that a previous partial update could retain.
$null = Invoke-GitHubApi -Method PUT -Endpoint $actionsEndpoint -Body $actionsBody -WithBody
$null = Invoke-GitHubApi -Method PUT -Endpoint $selectedActionsEndpoint -Body $selectedActionsBody -WithBody
$null = Invoke-GitHubApi -Method PUT -Endpoint $forkApprovalEndpoint -Body $forkApprovalBody -WithBody
$null = Invoke-GitHubApi -Method PUT -Endpoint $environmentEndpoint -Body $environmentBody -WithBody
$null = Invoke-GitHubApi -Method PUT -Endpoint $protectionEndpoint -Body $protectionBody -WithBody

$actions = Invoke-GitHubApi -Method GET -Endpoint $actionsEndpoint
if (
    -not [bool] (Get-RequiredProperty -InputObject $actions -Name "enabled" -Setting "actions permissions") -or
    (Get-RequiredProperty -InputObject $actions -Name "allowed_actions" -Setting "actions permissions") -cne "selected" -or
    -not [bool] (Get-RequiredProperty -InputObject $actions -Name "sha_pinning_required" -Setting "actions permissions")
) {
    throw "actions permissions verification failed"
}

$selectedActions = Invoke-GitHubApi -Method GET -Endpoint $selectedActionsEndpoint
$patternsAllowed = @(Get-RequiredProperty -InputObject $selectedActions -Name "patterns_allowed" -Setting "selected actions")
if (
    -not [bool] (Get-RequiredProperty -InputObject $selectedActions -Name "github_owned_allowed" -Setting "selected actions") -or
    [bool] (Get-RequiredProperty -InputObject $selectedActions -Name "verified_allowed" -Setting "selected actions") -or
    $patternsAllowed.Count -ne 0
) {
    throw "selected actions verification failed"
}

$forkApproval = Invoke-GitHubApi -Method GET -Endpoint $forkApprovalEndpoint
if ((Get-RequiredProperty -InputObject $forkApproval -Name "approval_policy" -Setting "fork approval") -cne "all_external_contributors") {
    throw "fork approval verification failed"
}

$environment = Invoke-GitHubApi -Method GET -Endpoint $environmentEndpoint
if ((Get-RequiredProperty -InputObject $environment -Name "name" -Setting "production environment") -cne "production") {
    throw "production environment verification failed"
}

$protection = Invoke-GitHubApi -Method GET -Endpoint $protectionEndpoint
$statusChecks = Get-RequiredProperty -InputObject $protection -Name "required_status_checks" -Setting "main branch protection"
$contexts = @(Get-RequiredProperty -InputObject $statusChecks -Name "contexts" -Setting "main branch protection")
$pullRequests = Get-RequiredProperty -InputObject $protection -Name "required_pull_request_reviews" -Setting "main branch protection"
$linearHistory = Get-RequiredProperty -InputObject $protection -Name "required_linear_history" -Setting "main branch protection"
$forcePushes = Get-RequiredProperty -InputObject $protection -Name "allow_force_pushes" -Setting "main branch protection"
$deletions = Get-RequiredProperty -InputObject $protection -Name "allow_deletions" -Setting "main branch protection"
if (
    -not [bool] (Get-RequiredProperty -InputObject $statusChecks -Name "strict" -Setting "main branch protection") -or
    $contexts.Count -ne 1 -or $contexts[0] -cne "validate" -or
    [int] (Get-RequiredProperty -InputObject $pullRequests -Name "required_approving_review_count" -Setting "main branch protection") -ne 0 -or
    -not [bool] (Get-RequiredProperty -InputObject $linearHistory -Name "enabled" -Setting "main branch protection") -or
    [bool] (Get-RequiredProperty -InputObject $forcePushes -Name "enabled" -Setting "main branch protection") -or
    [bool] (Get-RequiredProperty -InputObject $deletions -Name "enabled" -Setting "main branch protection")
) {
    throw "main branch protection verification failed"
}

Write-Output "actions-permissions: verified"
Write-Output "selected-actions: verified"
Write-Output "fork-approval: verified"
Write-Output "production-environment: verified"
Write-Output "main-branch-protection: verified"
