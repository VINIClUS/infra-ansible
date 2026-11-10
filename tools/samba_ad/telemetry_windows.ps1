#Requires -Version 7.4
<#! Source-only Windows pilot entry point. No asset acquisition, joins or policy changes. !#>
[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Install', 'Probe')][string]$Action = 'Validate',
    [string]$ConfigPath = 'C:\ProgramData\SambaADObservability\config.json',
    [switch]$Enabled, [switch]$Apply, [switch]$Activate,
    [string]$Limit = '', [string]$Tag = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = 'C:\ProgramData\SambaADObservability'
$Channels = @('Security', 'System', 'Application', 'Microsoft-Windows-GroupPolicy/Operational')

function Assert-S7([bool]$Condition) {
    if (-not $Condition) { throw 'S7 Windows precondition failed; values suppressed' }
}
function Write-Atomic([string]$Path, [string]$Text) {
    $temporary = $Path + '.new'
    [IO.File]::WriteAllText($temporary, $Text, [Text.UTF8Encoding]::new($false))
    $stream = [IO.File]::Open($temporary, 'Open', 'ReadWrite', 'None')
    try { $stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::Move($temporary, $Path, $true)
}
function Assert-PrivateFile([string]$Path) {
    Assert-S7 (-not ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint))
    $acl = Get-Acl -LiteralPath $Path
    foreach ($entry in $acl.Access) {
        $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        Assert-S7 ($sid -in @('S-1-5-18', 'S-1-5-32-544'))
    }
}
function Probe-S7($Config) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $lines = [Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $Channels.Count; $index++) {
        $up = 0
        try {
            $log = Get-WinEvent -ListLog $Channels[$index]
            if ($log.IsEnabled -and $null -ne $log.RecordCount) { $up = 1 }
        } catch { $up = 0 }
        $lines.Add('samba_ad_source_up{source="windows_channel_' + $index + '"} ' + $up)
    }
    $taskUp = 0
    try {
        $task = Get-ScheduledTask -TaskName $Config.rotation_task -TaskPath '\SambaAD\'
        $info = $task | Get-ScheduledTaskInfo
        $age = ([DateTime]::Now - $info.LastRunTime).TotalSeconds
        if ($task.State -ne 'Disabled' -and $info.LastTaskResult -eq 0 -and $age -ge 0 -and $age -le 2400) {
            $taskUp = 1
        }
    } catch { $taskUp = 0 }
    $lines.Add('samba_ad_source_up{source="windows_rotation_task"} ' + $taskUp)
    $certUp = 0
    $cert = $null
    try {
        $references = Get-Content -Raw -LiteralPath $Config.pki_active | ConvertFrom-Json -AsHashtable
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText($references.cert_file))
        $expiry = [DateTimeOffset]::new($cert.NotAfter.ToUniversalTime()).ToUnixTimeSeconds()
        $issued = [DateTimeOffset]::new($cert.NotBefore.ToUniversalTime()).ToUnixTimeSeconds()
        $eku = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
        $san = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' })
        Assert-S7 ($eku.Count -eq 1 -and @($eku[0].EnhancedKeyUsages).Count -eq 1)
        Assert-S7 ($eku[0].EnhancedKeyUsages[0].Value -eq '1.3.6.1.5.5.7.3.2' -and $san.Count -eq 1)
        $names = @([Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]::new(
            $san[0].RawData, $san[0].Critical).EnumerateDnsNames())
        Assert-S7 ($names.Count -eq 1 -and $names[0] -ceq $Config.fqdn)
        Assert-S7 ($issued -le $now -and $expiry -gt $now -and $expiry - $issued -le 604800)
        $lines.Add('samba_ad_expires_seconds{source="windows_certificate"} ' + $expiry)
        $lines.Add('samba_ad_rotate_by_seconds{source="windows_certificate"} ' + [long]($issued + ($expiry - $issued) * 0.66))
        $certUp = 1
    } catch { $certUp = 0 } finally { if ($null -ne $cert) { $cert.Dispose() } }
    $lines.Add('samba_ad_source_up{source="windows_certificate"} ' + $certUp)
    $pkiUp = 0
    try {
        $pki = Get-Content -Raw -LiteralPath 'C:\ProgramData\SambaADPKI\telemetry_windows_pilot\status.json' | ConvertFrom-Json -AsHashtable
        $age = $now - $pki.last_check
        if ($pki.success -eq $true -and $age -ge 0 -and $age -le 2400) { $pkiUp = 1 }
    } catch { $pkiUp = 0 }
    $lines.Add('samba_ad_source_up{source="windows_pki"} ' + $pkiUp)
    $spoolUp = 0
    try {
        $spool = (& $Config.python_binary "$Root\telemetry_spool.py" --metrics "$Root\spool" 2>$null) | ConvertFrom-Json -AsHashtable
        if ($LASTEXITCODE -eq 0 -and $now - $spool.heartbeat -ge 0 -and $now - $spool.heartbeat -le 120) { $spoolUp = 1 }
        foreach ($pair in @(@('bytes','queue_bytes'), @('rejected','queue_rejected_total'), @('delivered','queue_delivered_total'), @('oldest_age','queue_oldest_age_seconds'))) {
            Assert-S7 ($spool[$pair[0]] -ge 0)
            $lines.Add('samba_ad_' + $pair[1] + '{source="spool"} ' + $spool[$pair[0]])
        }
    } catch { $spoolUp = 0 }
    $lines.Add('samba_ad_source_up{source="spool"} ' + $spoolUp)
    $lines.Add('samba_ad_exporter_last_run_seconds ' + $now)
    Write-Atomic "$Root\textfile\ad.prom" (($lines -join "`n") + "`n")
    [IO.File]::AppendAllText("$Root\canary.log", (@{kind='samba_ad_canary'; at=$now} | ConvertTo-Json -Compress) + "`n")
}

try {
    if (-not $Enabled) { Write-Output '{"state":"disabled"}'; exit 0 }
    Assert-PrivateFile $ConfigPath
    $config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json -AsHashtable
    Assert-S7 ($config.schema -eq 'samba-ad-observability-windows/v1')
    $machine = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $edition = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' EditionID
    $guid = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Cryptography' MachineGuid
    Assert-S7 ($os.BuildNumber -eq '26100' -and $os.ProductType -eq 3)
    Assert-S7 ($edition -in @('ServerStandard', 'ServerDatacenter', 'ServerStandardEval', 'ServerDatacenterEval'))
    Assert-S7 ($machine.PartOfDomain -and $machine.Domain -ieq $config.domain -and $guid -ceq $config.machine_guid)
    Assert-S7 ($config.fqdn -ceq ($env:COMPUTERNAME.ToLowerInvariant() + '.' + $machine.Domain.ToLowerInvariant()))
    $endpoint = [Uri]$config.endpoint
    Assert-S7 ($endpoint.Scheme -ceq 'https' -and $endpoint.Port -eq 443 -and $endpoint.Host -ceq $config.server_name)
    Assert-S7 ($endpoint.AbsolutePath -ceq '/' -and -not $endpoint.UserInfo -and -not $endpoint.Query -and -not $endpoint.Fragment)
    Assert-S7 ($config.rotation_task -ceq 'TelemetryRotate')
    Assert-S7 ($config.pki_active -ceq 'C:\ProgramData\SambaADPKI\telemetry_windows_pilot\active.json')
    Assert-S7 ($config.transition_file -ceq 'C:\ProgramData\SambaADPKI\telemetry_windows_pilot\transition.json')
    Assert-S7 ($config.token_file -ceq "$Root\token")
    Assert-S7 ($config.alloy_sha256 -match '^[a-f0-9]{64}$' -and $config.pwsh_sha256 -match '^[a-f0-9]{64}$')
    Assert-S7 ((Get-FileHash -Algorithm SHA256 -LiteralPath $config.alloy_binary).Hash.ToLowerInvariant() -ceq $config.alloy_sha256)
    Assert-S7 ((Get-FileHash -Algorithm SHA256 -LiteralPath $config.pwsh_binary).Hash.ToLowerInvariant() -ceq $config.pwsh_sha256)
    Assert-S7 ($config.python_sha256 -match '^[a-f0-9]{64}$')
    Assert-S7 ((Get-FileHash -Algorithm SHA256 -LiteralPath $config.python_binary).Hash.ToLowerInvariant() -ceq $config.python_sha256)
    Assert-S7 ((& $config.python_binary --version 2>&1 | Out-String) -match '^Python 3\.13\.')
    Assert-PrivateFile $config.python_binary
    Assert-S7 ((& $config.alloy_binary --version 2>&1 | Out-String) -match 'v1\.18\.1')
    if ($Action -eq 'Probe') { Probe-S7 $config; exit 0 }
    Assert-S7 ($Limit -ceq $env:COMPUTERNAME -and $Tag -ceq 'samba_ad_observability')
    & $config.alloy_binary validate --stability.level=experimental $config.alloy_config 2>$null | Out-Null
    Assert-S7 ($LASTEXITCODE -eq 0)
    foreach ($channel in $Channels) { Assert-S7 ((Get-WinEvent -ListLog $channel).IsEnabled) }
    # The concrete companion producer validates its host-bound CA/JWK references before any task is installed.
    & (Join-Path $PSScriptRoot 'telemetry_windows_pki.ps1') -Enabled -Action Validate -ConfigPath $config.pki_config | Out-Null
    Assert-S7 ($LASTEXITCODE -eq 0)
    Assert-PrivateFile $config.alloy_config
    if ($Action -eq 'Validate' -or -not $Apply) { Write-Output '{"state":"validated"}'; exit 0 }
    foreach ($name in @('TelemetryTransport', 'TelemetryProbe', 'TelemetryForwarder', 'TelemetryRotate')) {
        Assert-S7 (-not (Get-ScheduledTask -TaskName $name -TaskPath '\SambaAD\' -ErrorAction SilentlyContinue))
    }
    Assert-S7 (-not (Test-Path -LiteralPath $Root))
    New-Item -ItemType Directory -Path "$Root\textfile" -Force | Out-Null
    & icacls.exe $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>$null | Out-Null
    Assert-S7 ($LASTEXITCODE -eq 0)
    Copy-Item -LiteralPath $PSCommandPath -Destination "$Root\telemetry.ps1"
    Copy-Item -LiteralPath $ConfigPath -Destination "$Root\config.json"
    Copy-Item -LiteralPath $config.alloy_config -Destination "$Root\agent.alloy"
    Copy-Item -LiteralPath $config.pki_config -Destination "$Root\pki.json"
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'telemetry_windows_pki.ps1') -Destination "$Root\pki.ps1"
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'telemetry_spool.py') -Destination "$Root\telemetry_spool.py"
    [IO.File]::WriteAllText("$Root\token", [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant())
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 100 -RestartInterval (New-TimeSpan -Minutes 1)
    $args = 'run --stability.level=experimental --server.http.listen-addr=127.0.0.1:19102 --storage.path="' + $Root + '\alloy" "' + $Root + '\agent.alloy"'
    $transport = New-ScheduledTaskAction -Execute $config.alloy_binary -Argument $args
    $probe = New-ScheduledTaskAction -Execute $config.pwsh_binary -Argument ('-NoProfile -NonInteractive -File "' + $Root + '\telemetry.ps1" -Enabled -Action Probe')
    $forwarder = New-ScheduledTaskAction -Execute $config.python_binary -Argument ('"' + $Root + '\telemetry_spool.py" "' + $Root + '\config.json"')
    $rotation = New-ScheduledTaskAction -Execute $config.pwsh_binary -Argument ('-NoProfile -NonInteractive -File "' + $Root + '\pki.ps1" -Enabled -Apply -Action Rotate')
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskPath '\SambaAD\' -TaskName TelemetryProbe -Action $probe -Trigger $trigger -Principal $principal | Out-Null
    Register-ScheduledTask -TaskPath '\SambaAD\' -TaskName TelemetryTransport -Action $transport -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $principal -Settings $settings | Out-Null
    Register-ScheduledTask -TaskPath '\SambaAD\' -TaskName TelemetryForwarder -Action $forwarder -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $principal -Settings $settings | Out-Null
    $rotateTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(30) -RepetitionInterval (New-TimeSpan -Minutes 30)
    $rotateSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskPath '\SambaAD\' -TaskName TelemetryRotate -Action $rotation -Trigger $rotateTrigger -Principal $principal -Settings $rotateSettings | Out-Null
    foreach ($task in @('TelemetryTransport', 'TelemetryProbe', 'TelemetryForwarder', 'TelemetryRotate')) {
        Disable-ScheduledTask -TaskPath '\SambaAD\' -TaskName $task | Out-Null
    }
    if ($Activate) {
        & "$Root\pki.ps1" -Enabled -Apply -Action Issue -Limit $Limit -Tag $Tag | Out-Null
        Assert-S7 ($LASTEXITCODE -eq 0)
    }
    Write-Output '{"state":"installed"}'
} catch {
    Write-Error 'S7 Windows operation refused; values suppressed' -ErrorAction Continue
    exit 1
}
