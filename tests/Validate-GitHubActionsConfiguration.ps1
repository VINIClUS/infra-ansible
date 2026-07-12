[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ScriptPath = Join-Path $RepoRoot "tools/github/Configure-GitHubActions.ps1"
$RunId = [Guid]::NewGuid().ToString("N")
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) "infra-ansible-gh-$RunId"
$MockPath = Join-Path $TempRoot "gh"
$MockLog = Join-Path $TempRoot "calls.jsonl"
$MockState = Join-Path $TempRoot "state"
$OriginalPath = $env:PATH

function Read-MockCalls {
    if (-not (Test-Path -LiteralPath $MockLog)) {
        return @()
    }

    return @(
        Get-Content -LiteralPath $MockLog |
            Where-Object { $_.Length -gt 0 } |
            ForEach-Object { $_ | ConvertFrom-Json -Depth 20 }
    )
}

function Assert-CallContract {
    param(
        [object[]] $Calls,
        [bool] $ExpectExistingResources
    )

    if ($Calls.Count -eq 0) {
        throw "Configure-GitHubActions.ps1 made no gh calls"
    }

    foreach ($call in $Calls) {
        if ($call.argv[0] -ne "api") {
            throw "Every gh invocation must use the api subcommand"
        }
        if (-not ($call.argv -contains "--method")) {
            throw "Every gh api invocation must declare an explicit method"
        }
        if (-not ($call.argv -contains "Accept: application/vnd.github+json")) {
            throw "Every gh api invocation must declare the GitHub JSON media type"
        }
        if (-not ($call.argv -contains "X-GitHub-Api-Version: 2026-03-10")) {
            throw "Every gh api invocation must pin the REST API version"
        }
        if ($call.method -ne "GET" -and -not ($call.argv -contains "--input")) {
            throw "Every mutating gh api invocation must supply JSON through --input"
        }
        if ($call.argv -contains "-f" -or $call.argv -contains "-F" -or $call.argv -contains "--raw-field" -or $call.argv -contains "--field") {
            throw "gh api bodies must not use interpolated field flags"
        }
        if ($call.endpoint -match "registration-token|remove-token|runner") {
            throw "Repository configuration must not request or manage runner tokens"
        }
    }

    $expectedWrites = [ordered]@{
        "repos/VINIClUS/infra-ansible/actions/permissions" = [ordered]@{
            enabled = $true
            allowed_actions = "selected"
            sha_pinning_required = $true
        }
        "repos/VINIClUS/infra-ansible/actions/permissions/selected-actions" = [ordered]@{
            github_owned_allowed = $true
            verified_allowed = $false
            patterns_allowed = @()
        }
        "repos/VINIClUS/infra-ansible/actions/permissions/fork-pr-contributor-approval" = [ordered]@{
            approval_policy = "all_external_contributors"
        }
        "repos/VINIClUS/infra-ansible/environments/production" = [ordered]@{}
        "repos/VINIClUS/infra-ansible/branches/main/protection" = [ordered]@{
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
    }

    foreach ($entry in $expectedWrites.GetEnumerator()) {
        $matchingWrites = @($Calls | Where-Object { $_.method -eq "PUT" -and $_.endpoint -eq $entry.Key })
        if ($matchingWrites.Count -ne 1) {
            throw "Expected exactly one PUT for $($entry.Key), got $($matchingWrites.Count)"
        }
        $actualBody = $matchingWrites[0].body | ConvertTo-Json -Compress -Depth 20
        $expectedBody = $entry.Value | ConvertTo-Json -Compress -Depth 20
        if ($actualBody -cne $expectedBody) {
            throw "Unexpected desired JSON for $($entry.Key)"
        }
    }

    foreach ($endpoint in @(
            "repos/VINIClUS/infra-ansible/actions/permissions",
            "repos/VINIClUS/infra-ansible/actions/permissions/selected-actions",
            "repos/VINIClUS/infra-ansible/actions/permissions/fork-pr-contributor-approval"
        )) {
        $indexes = for ($index = 0; $index -lt $Calls.Count; $index++) {
            if ($Calls[$index].endpoint -eq $endpoint) {
                $index
            }
        }
        $methods = @($indexes | ForEach-Object { $Calls[$_].method })
        if (($methods -join ",") -ne "GET,PUT,GET") {
            throw "$endpoint must be read before and after its PUT"
        }
    }

    $environmentCollectionIndex = [Array]::FindIndex([object[]] $Calls, [Predicate[object]] { param($call) $call.method -eq "GET" -and $call.endpoint -eq "repos/VINIClUS/infra-ansible/environments" })
    $environmentIndexes = for ($index = 0; $index -lt $Calls.Count; $index++) {
        if ($Calls[$index].endpoint -eq "repos/VINIClUS/infra-ansible/environments/production") {
            $index
        }
    }
    $environmentMethods = @($environmentIndexes | ForEach-Object { $Calls[$_].method })
    $expectedEnvironmentMethods = if ($ExpectExistingResources) { "GET,PUT,GET" } else { "PUT,GET" }
    if (
        $environmentCollectionIndex -lt 0 -or
        $environmentIndexes.Count -eq 0 -or
        $environmentCollectionIndex -ge $environmentIndexes[0] -or
        ($environmentMethods -join ",") -ne $expectedEnvironmentMethods
    ) {
        throw "The production environment must be discovered, read when present, updated, and read back"
    }

    $branchReadIndex = [Array]::FindIndex([object[]] $Calls, [Predicate[object]] { param($call) $call.method -eq "GET" -and $call.endpoint -eq "repos/VINIClUS/infra-ansible/branches/main" })
    $protectionIndexes = for ($index = 0; $index -lt $Calls.Count; $index++) {
        if ($Calls[$index].endpoint -eq "repos/VINIClUS/infra-ansible/branches/main/protection") {
            $index
        }
    }
    $protectionMethods = @($protectionIndexes | ForEach-Object { $Calls[$_].method })
    $expectedProtectionMethods = if ($ExpectExistingResources) { "GET,PUT,GET" } else { "PUT,GET" }
    if (
        $branchReadIndex -lt 0 -or
        $protectionIndexes.Count -eq 0 -or
        $branchReadIndex -ge $protectionIndexes[0] -or
        ($protectionMethods -join ",") -ne $expectedProtectionMethods
    ) {
        throw "The main branch must be discovered, its protection read when present, updated, and read back"
    }
}

function Get-IntendedState {
    param([object[]] $Calls)

    return @(
        $Calls |
            Where-Object { $_.method -eq "PUT" } |
            ForEach-Object {
                [ordered]@{
                    endpoint = $_.endpoint
                    body = $_.body
                } | ConvertTo-Json -Compress -Depth 20
            }
    ) -join "`n"
}

New-Item -ItemType Directory -Path $MockState -Force | Out-Null

try {
    @'
#!/usr/bin/env pwsh
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$argv = @($args)
if ($argv.Count -lt 2 -or $argv[0] -ne "api") {
    [Console]::Error.WriteLine("unsupported mock invocation")
    exit 64
}

$endpoint = $argv[1]
$methodIndex = [Array]::IndexOf($argv, "--method")
$method = if ($methodIndex -ge 0) { $argv[$methodIndex + 1] } else { "" }
$inputIndex = [Array]::IndexOf($argv, "--input")
$bodyText = if ($inputIndex -ge 0) { [IO.File]::ReadAllText($argv[$inputIndex + 1]) } else { "" }
$body = if ($bodyText.Length -gt 0) { $bodyText | ConvertFrom-Json -Depth 20 } else { $null }

[ordered]@{
    argv = $argv
    method = $method
    endpoint = $endpoint
    body = $body
} | ConvertTo-Json -Compress -Depth 20 | Add-Content -LiteralPath $env:GH_MOCK_LOG -Encoding utf8NoBOM

if ($env:GH_MOCK_FAIL_ENDPOINT -and $endpoint -eq $env:GH_MOCK_FAIL_ENDPOINT) {
    [Console]::Error.WriteLine("simulated GitHub API failure")
    exit 22
}

function Resolve-MockStatePath {
    param([string] $ApiEndpoint)

    $stateName = ($ApiEndpoint -replace "[^A-Za-z0-9_.-]", "_") + ".json"
    return Join-Path $env:GH_MOCK_STATE_DIR $stateName
}

$statePath = Resolve-MockStatePath -ApiEndpoint $endpoint
if ($method -eq "PUT") {
    [IO.File]::WriteAllText($statePath, $bodyText, [Text.UTF8Encoding]::new($false))
    if ($endpoint -match "/environments/production$") {
        Write-Output '{"name":"production"}'
    }
    else {
        Write-Output $bodyText
    }
    exit 0
}

if ($method -ne "GET") {
    [Console]::Error.WriteLine("unsupported mock method")
    exit 64
}

if ($endpoint -match "/environments$") {
    $environmentState = Resolve-MockStatePath -ApiEndpoint "$endpoint/production"
    if (Test-Path -LiteralPath $environmentState) {
        Write-Output '{"total_count":1,"environments":[{"name":"production"}]}'
    }
    else {
        Write-Output '{"total_count":0,"environments":[]}'
    }
}
elseif ($endpoint -match "/environments/production$") {
    if (-not (Test-Path -LiteralPath $statePath)) {
        [Console]::Error.WriteLine("environment missing")
        exit 22
    }
    Write-Output '{"name":"production"}'
}
elseif ($endpoint -match "/branches/main$") {
    $protectionState = Resolve-MockStatePath -ApiEndpoint "$endpoint/protection"
    $protected = Test-Path -LiteralPath $protectionState
    [ordered]@{
        name = "main"
        protected = $protected
    } | ConvertTo-Json -Compress
}
elseif ($endpoint -match "/branches/main/protection$") {
    if (-not (Test-Path -LiteralPath $statePath)) {
        [Console]::Error.WriteLine("protection missing")
        exit 22
    }
    $desired = [IO.File]::ReadAllText($statePath) | ConvertFrom-Json -Depth 20
    $protectionResponse = [ordered]@{
        required_status_checks = $desired.required_status_checks
        enforce_admins = @{ enabled = [bool] $desired.enforce_admins }
        required_pull_request_reviews = $desired.required_pull_request_reviews
        restrictions = $desired.restrictions
        required_linear_history = @{ enabled = [bool] $desired.required_linear_history }
        allow_force_pushes = @{ enabled = [bool] $desired.allow_force_pushes }
        allow_deletions = @{ enabled = [bool] $desired.allow_deletions }
    }
    switch ($env:GH_MOCK_DRIFT_FIELD) {
        "status-strict" { $protectionResponse.required_status_checks.strict = $false }
        "status-context" { $protectionResponse.required_status_checks.contexts = @("unexpected") }
        "enforce-admins" { $protectionResponse.enforce_admins.enabled = $false }
        "dismiss-stale-reviews" { $protectionResponse.required_pull_request_reviews.dismiss_stale_reviews = $true }
        "require-code-owner-reviews" { $protectionResponse.required_pull_request_reviews.require_code_owner_reviews = $true }
        "approving-review-count" { $protectionResponse.required_pull_request_reviews.required_approving_review_count = 1 }
        "require-last-push-approval" { $protectionResponse.required_pull_request_reviews.require_last_push_approval = $true }
        "linear-history" { $protectionResponse.required_linear_history.enabled = $false }
        "force-pushes" { $protectionResponse.allow_force_pushes.enabled = $true }
        "deletions" { $protectionResponse.allow_deletions.enabled = $true }
    }
    $protectionResponse | ConvertTo-Json -Compress -Depth 20
}
elseif (Test-Path -LiteralPath $statePath) {
    Get-Content -Raw -LiteralPath $statePath
}
elseif ($endpoint -match "/selected-actions$") {
    Write-Output '{"github_owned_allowed":false,"verified_allowed":true,"patterns_allowed":["*"]}'
}
elseif ($endpoint -match "/fork-pr-contributor-approval$") {
    Write-Output '{"approval_policy":"first_time_contributors"}'
}
elseif ($endpoint -match "/actions/permissions$") {
    Write-Output '{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}'
}
else {
    Write-Output '{}'
}
'@ | Set-Content -LiteralPath $MockPath -Encoding utf8NoBOM

    & chmod 0700 $MockPath
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to make the mock gh executable"
    }

    $env:GH_MOCK_LOG = $MockLog
    $env:GH_MOCK_STATE_DIR = $MockState
    $env:PATH = "$TempRoot$([IO.Path]::PathSeparator)$OriginalPath"

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        throw "Missing required script: tools/github/Configure-GitHubActions.ps1"
    }

    $FirstOutput = @(& $ScriptPath)
    $FirstCalls = Read-MockCalls
    Assert-CallContract -Calls $FirstCalls -ExpectExistingResources $false
    $FirstState = Get-IntendedState -Calls $FirstCalls

    Remove-Item -LiteralPath $MockLog
    $SecondOutput = @(& $ScriptPath)
    $SecondCalls = Read-MockCalls
    Assert-CallContract -Calls $SecondCalls -ExpectExistingResources $true
    $SecondState = Get-IntendedState -Calls $SecondCalls

    if ($FirstState -cne $SecondState) {
        throw "Repeated configuration runs did not produce identical intended state"
    }
    if (($FirstOutput -join "`n") -cne ($SecondOutput -join "`n")) {
        throw "Repeated configuration runs did not produce identical summaries"
    }

    $expectedSummary = @(
        "actions-permissions: verified",
        "selected-actions: verified",
        "fork-approval: verified",
        "production-environment: verified",
        "main-branch-protection: verified"
    )
    if (($FirstOutput -join "`n") -cne ($expectedSummary -join "`n")) {
        throw "The script must emit only the five non-sensitive verified states"
    }

    foreach ($driftField in @(
            "status-strict",
            "status-context",
            "enforce-admins",
            "dismiss-stale-reviews",
            "require-code-owner-reviews",
            "approving-review-count",
            "require-last-push-approval",
            "linear-history",
            "force-pushes",
            "deletions"
        )) {
        Remove-Item -LiteralPath $MockLog
        $env:GH_MOCK_DRIFT_FIELD = $driftField
        $driftFailed = $false
        $driftOutput = @()
        try {
            $driftOutput = @(& $ScriptPath)
        }
        catch {
            $driftFailed = $true
            if ($_.Exception.Message -match "\{|required_status_checks|required_pull_request_reviews") {
                throw "Drift failure disclosed the API response for $driftField"
            }
        }
        finally {
            Remove-Item Env:GH_MOCK_DRIFT_FIELD -ErrorAction SilentlyContinue
        }
        if (-not $driftFailed) {
            throw "The script accepted branch protection drift in $driftField"
        }
        if ($driftOutput.Count -ne 0) {
            throw "The script printed a verified state before rejecting $driftField drift"
        }
    }

    Remove-Item -LiteralPath $MockLog
    $env:GH_MOCK_FAIL_ENDPOINT = "repos/VINIClUS/infra-ansible/actions/permissions"
    $failed = $false
    try {
        & $ScriptPath | Out-Null
    }
    catch {
        $failed = $true
        if ($_.Exception.Message -match "simulated|\{|allowed_actions|sha_pinning") {
            throw "Failure handling disclosed the API response"
        }
    }
    finally {
        Remove-Item Env:GH_MOCK_FAIL_ENDPOINT -ErrorAction SilentlyContinue
    }
    if (-not $failed) {
        throw "The script did not stop on a gh API failure"
    }
    if ((Read-MockCalls).Count -ne 1) {
        throw "The script continued after the first gh API failure"
    }

    Write-Output "GitHub Actions repository configuration validation passed"
}
finally {
    $env:PATH = $OriginalPath
    Remove-Item Env:GH_MOCK_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:GH_MOCK_STATE_DIR -ErrorAction SilentlyContinue
    Remove-Item Env:GH_MOCK_FAIL_ENDPOINT -ErrorAction SilentlyContinue
    Remove-Item Env:GH_MOCK_DRIFT_FIELD -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $TempRoot -ErrorAction SilentlyContinue
}
