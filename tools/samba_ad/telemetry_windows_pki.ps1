#Requires -Version 7.4
[CmdletBinding()]
param(
    [ValidateSet('Validate', 'AuthPrepare', 'Issue', 'Rotate')][string]$Action = 'Validate',
    [string]$ConfigPath = 'C:\ProgramData\SambaADObservability\pki.json',
    [switch]$Enabled, [switch]$Apply, [string]$Limit = '', [string]$Tag = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = 'C:\ProgramData\SambaADPKI\telemetry_windows_pilot'
$Runtime = 'C:\ProgramData\SambaADObservability'
$published = $false; $candidate = $null; $previous = $null; $lock = $null; $key = $null; $owned = $false

function Require([bool]$Value) { if (-not $Value) { throw 'Windows PKI refused; values suppressed' } }
function Hex([byte[]]$Bytes) { return [Convert]::ToHexString($Bytes).ToLowerInvariant() }
function Digest([byte[]]$Bytes) { return Hex ([Security.Cryptography.SHA256]::HashData($Bytes)) }
function B64([byte[]]$Bytes) { return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
function UnB64([string]$Value) {
    return [Convert]::FromBase64String($Value.Replace('-', '+').Replace('_', '/') + ('=' * ((4 - $Value.Length % 4) % 4)))
}
function Private([string]$Path) {
    Require (-not ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint))
    foreach ($entry in (Get-Acl -LiteralPath $Path).Access) {
        Require ($entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -in @('S-1-5-18', 'S-1-5-32-544'))
    }
}
function Atomic([string]$Path, [string]$Text) {
    $temporary = $Path + '.new'
    Require (-not (Test-Path -LiteralPath $temporary))
    [IO.File]::WriteAllText($temporary, $Text, [Text.UTF8Encoding]::new($false))
    $stream = [IO.File]::Open($temporary, 'Open', 'ReadWrite', 'None')
    try { $stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::Move($temporary, $Path, $true)
}
function Sign-Token($Config, $Claims) {
    $info = [Diagnostics.ProcessStartInfo]::new($Config.step_binary)
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    foreach ($argument in @('crypto', 'jwt', 'sign', '-', '--subtle', '--alg', 'ES256', '--key', $Config.auth_jwe, '--password-file', $Config.passphrase_ref)) {
        $info.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($info)
    try {
        $errorRead = $process.StandardError.ReadToEndAsync()
        $outputRead = $process.StandardOutput.ReadToEndAsync()
        $process.StandardInput.Write(($Claims | ConvertTo-Json -Depth 8 -Compress)); $process.StandardInput.Close()
        if (-not $process.WaitForExit(30000)) { $process.Kill($true); throw 'Signing timed out' }
        Require ($process.ExitCode -eq 0)
        $token = $outputRead.GetAwaiter().GetResult().Trim()
        Require ($token.Length -le 8192)
        $parts = $token.Split('.'); Require ($parts.Count -eq 3)
        $header = [Text.Encoding]::UTF8.GetString((UnB64 $parts[0])) | ConvertFrom-Json -AsHashtable
        $payload = [Text.Encoding]::UTF8.GetString((UnB64 $parts[1])) | ConvertFrom-Json -AsHashtable
        Require (($header.Keys | Sort-Object) -join ',' -ceq 'alg,kid,typ')
        Require ($header.alg -ceq 'ES256' -and $header.typ -ceq 'JWT' -and $header.kid -ceq $Config.public_jwk.kid)
        Require (($payload.Keys | Sort-Object) -join ',' -ceq 'aud,cnf,exp,iat,iss,jti,nbf,sans,sub')
        foreach ($field in @('iss', 'sub', 'iat', 'nbf', 'exp', 'jti')) { Require ($payload[$field] -ceq $Claims[$field]) }
        foreach ($field in @('sans', 'aud')) { Require ($payload[$field].Count -eq 1 -and $payload[$field][0] -ceq $Claims[$field][0]) }
        Require ($payload.cnf.Count -eq 1 -and $payload.cnf['x5rt#S256'] -ceq $Claims.cnf['x5rt#S256'])
        $point = [Security.Cryptography.ECPoint]::new()
        $point.X = UnB64 $Config.public_jwk.x; $point.Y = UnB64 $Config.public_jwk.y
        $parameters = [Security.Cryptography.ECParameters]::new()
        $parameters.Curve = [Security.Cryptography.ECCurve]::NamedCurves.nistP256; $parameters.Q = $point
        $public = [Security.Cryptography.ECDsa]::Create($parameters)
        try {
            Require ($public.VerifyData([Text.Encoding]::ASCII.GetBytes($parts[0] + '.' + $parts[1]), (UnB64 $parts[2]),
                [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
        } finally { $public.Dispose() }
        return $token
    } finally { $process.Dispose() }
}

Add-Type -TypeDefinition @'
using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
public static class S7Tls {
  public static HttpClientHandler Handler(string rootPath, string issuerPath, string hostname) {
    var root = X509Certificate2.CreateFromPem(System.IO.File.ReadAllText(rootPath));
    var issuer = X509Certificate2.CreateFromPem(System.IO.File.ReadAllText(issuerPath));
    var h = new HttpClientHandler { AllowAutoRedirect = false };
    h.ServerCertificateCustomValidationCallback = (req, cert, ignored, errors) => {
      if (req.RequestUri.Host != hostname || cert == null ||
          (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
      using (var chain = new X509Chain()) {
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.ExtraStore.Add(issuer);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        return chain.Build(cert);
      }
    };
    return h;
  }
}
'@

function Verify-Leaf($Config, [string]$CertFile, $ExpectedKey, [string]$PreviousSPKI = '') {
    $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText($CertFile))
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        [void]$chain.ChainPolicy.CustomTrustStore.Add($script:rootCert)
        [void]$chain.ChainPolicy.ExtraStore.Add($script:issuerCert)
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.2'))
        Require ($chain.Build($cert) -and $chain.ChainElements.Count -eq 3)
        Require ((Digest $chain.ChainElements[1].Certificate.RawData) -ceq $Config.issuer_sha256)
        $san = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' })
        $eku = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
        Require ($san.Count -eq 1 -and $eku.Count -eq 1)
        $decoded = [Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]::new($san[0].RawData, $san[0].Critical)
        $names = @($decoded.EnumerateDnsNames())
        Require ($names.Count -eq 1 -and $names[0] -ceq $Config.fqdn -and @($decoded.EnumerateIPAddresses()).Count -eq 0)
        $reader = [System.Formats.Asn1.AsnReader]::new([ReadOnlyMemory[byte]]::new($san[0].RawData), [System.Formats.Asn1.AsnEncodingRules]::DER)
        $sequence = $reader.ReadSequence()
        Require ($sequence.PeekTag().TagClass -eq [System.Formats.Asn1.TagClass]::ContextSpecific -and $sequence.PeekTag().TagValue -eq 2)
        [void]$sequence.ReadEncodedValue()
        Require (-not $sequence.HasData -and -not $reader.HasData)
        Require ($eku[0].EnhancedKeyUsages.Count -eq 1 -and $eku[0].EnhancedKeyUsages[0].Value -eq '1.3.6.1.5.5.7.3.2')
        $constraints = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
        $usage = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
        Require ($constraints.Count -eq 1 -and -not $constraints[0].CertificateAuthority -and $usage.Count -eq 1)
        Require ($usage[0].KeyUsages -eq ([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment))
        $before = [DateTimeOffset]::new($cert.NotBefore.ToUniversalTime()).ToUnixTimeSeconds()
        $after = [DateTimeOffset]::new($cert.NotAfter.ToUniversalTime()).ToUnixTimeSeconds()
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        Require ($before -le $now -and $after -gt $now -and $after - $before -eq 604800)
        $public = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
        try {
            $parameters = $public.ExportParameters($false)
            Require ($parameters.Modulus.Length -in @(384, 512) -and $parameters.Modulus[0] -ge 128)
            Require ((Hex $parameters.Exponent) -ceq '010001')
            $spki = Digest $public.ExportSubjectPublicKeyInfo()
        } finally { $public.Dispose() }
        Require ($spki -ceq (Digest $ExpectedKey.ExportSubjectPublicKeyInfo()) -and $spki -cne $PreviousSPKI)
        return @{fingerprint=(Digest $cert.RawData); spki=$spki; expires=$after; rotate_by=[long]($before + 604800 * 0.66)}
    } finally { $chain.Dispose(); $cert.Dispose() }
}

function Readback($Config, [string]$Fingerprint, [string]$CertFile, [string]$KeyFile) {
    $uri = [Uri]$Config.collector_url
    $handler = [S7Tls]::Handler($Config.root_file, $Config.issuer_file, $uri.Host)
    $clientCert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($CertFile, $KeyFile)
    [void]$handler.ClientCertificates.Add($clientCert)
    $client = [Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds(5)
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(95)
        do {
            try {
                $body = [Net.Http.StringContent]::new('{}', [Text.Encoding]::UTF8, 'application/json')
                $response = $client.PostAsync(($Config.collector_url + '/identity'), $body).GetAwaiter().GetResult()
                try {
                    if ($response.StatusCode -eq 200) {
                        $value = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json -AsHashtable
                        if ($value.certificate_sha256 -ceq $Fingerprint) { return }
                    }
                } finally { $response.Dispose(); $body.Dispose() }
            } catch { }
            Start-Sleep -Seconds 2
        } while ([DateTime]::UtcNow -lt $deadline)
        throw 'Client certificate was not observed on both write paths'
    } finally { $client.Dispose(); $handler.Dispose(); $clientCert.Dispose() }
}

try {
    if (-not $Enabled) { Write-Output '{"state":"disabled"}'; exit 0 }
    Private $ConfigPath
    $c = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json -AsHashtable
    Require ($c.schema -ceq 'samba-ad-windows-pki/v1' -and $c.profile -ceq 'telemetry_windows_pilot')
    Require ($c.fqdn -match '^[a-z0-9.-]+$' -and $c.fqdn.EndsWith('.' + $c.domain))
    Require ((Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Cryptography' MachineGuid) -ceq $c.machine_guid)
    $os = Get-CimInstance Win32_OperatingSystem; $machine = Get-CimInstance Win32_ComputerSystem
    Require ($os.BuildNumber -eq '26100' -and $os.ProductType -eq 3 -and $machine.PartOfDomain -and $machine.Domain -ieq $c.domain)
    Require ((Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' EditionID) -in @('ServerStandard', 'ServerDatacenter', 'ServerStandardEval', 'ServerDatacenterEval'))
    Require ($c.fqdn -ceq ($env:COMPUTERNAME.ToLowerInvariant() + '.' + $machine.Domain.ToLowerInvariant()))
    foreach ($field in @('issuer_url', 'collector_url')) {
        $uri = [Uri]$c[$field]
        Require ($uri.Scheme -ceq 'https' -and $uri.Port -eq 443 -and -not $uri.UserInfo -and -not $uri.Query -and -not $uri.Fragment)
    }
    Require (([Uri]$c.issuer_url).AbsolutePath -ceq '/1.0/sign' -and ([Uri]$c.collector_url).AbsolutePath -ceq '/')
    Require (-not $c.collector_url.EndsWith('/'))
    Require ($c.auth_jwe -ceq "$Root\auth.jwe")
    Require ($c.passphrase_ref -ceq 'C:\ProgramData\SambaADPKICredentials\telemetry_windows_pilot\passphrase')
    foreach ($field in @('passphrase_ref', 'step_binary')) { Private $c[$field] }
    Require ((Get-FileHash -LiteralPath $c.step_binary -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $c.step_sha256)
    Require ((& $c.step_binary version 2>&1 | Out-String) -match '0\.31\.0')
    if ($Action -ne 'AuthPrepare') {
        Private $c.auth_jwe
        Require ($c.public_jwk.kty -ceq 'EC' -and $c.public_jwk.crv -ceq 'P-256' -and -not $c.public_jwk.ContainsKey('d'))
    }
    $script:rootCert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText($c.root_file))
    $script:issuerCert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText($c.issuer_file))
    Require ((Digest $rootCert.RawData) -ceq $c.root_sha256 -and (Digest $issuerCert.RawData) -ceq $c.issuer_sha256)
    if ($Action -eq 'AuthPrepare') {
        Require ($Limit -ceq $env:COMPUTERNAME -and $Tag -ceq 'samba_ad_observability')
        if (-not $Apply) { Write-Output '{"state":"planned"}'; exit 0 }
        Require (-not (Test-Path -LiteralPath $Root))
        New-Item -ItemType Directory -Path "$Root\generations" -Force | Out-Null
        & icacls.exe $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>$null | Out-Null
        Require ($LASTEXITCODE -eq 0); Private $Root
        $processInfo = [Diagnostics.ProcessStartInfo]::new($c.step_binary)
        $processInfo.UseShellExecute = $false; $processInfo.RedirectStandardOutput = $true; $processInfo.RedirectStandardError = $true
        foreach ($arg in @('crypto', 'jwk', 'create', "$Root\auth.public.json", $c.auth_jwe,
            '--kty', 'EC', '--alg', 'ES256', '--use', 'sig', '--password-file', $c.passphrase_ref)) { $processInfo.ArgumentList.Add($arg) }
        $process = [Diagnostics.Process]::Start($processInfo)
        try {
            $outRead = $process.StandardOutput.ReadToEndAsync(); $errRead = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(30000)) { $process.Kill($true); throw 'Authorization key creation timed out' }
            Require ($process.ExitCode -eq 0)
        } finally { $process.Dispose() }
        Private $c.auth_jwe
        Atomic "$Root\owner.json" (@{machine_guid=$c.machine_guid; fqdn=$c.fqdn; profile=$c.profile} | ConvertTo-Json -Compress)
        Write-Output '{"state":"auth_prepared","public_keys":1}'; exit 0
    }
    if ($Action -eq 'Validate' -or -not $Apply) { Write-Output '{"state":"validated"}'; exit 0 }
    if ($Action -eq 'Issue') { Require ($Limit -ceq $env:COMPUTERNAME -and $Tag -ceq 'samba_ad_observability') }
    Require ($ConfigPath -ieq "$Runtime\pki.json")
    Private $Root; Private $Runtime
    $owner = [IO.File]::ReadAllText("$Root\owner.json") | ConvertFrom-Json -AsHashtable
    Require ($owner.machine_guid -ceq $c.machine_guid -and $owner.fqdn -ceq $c.fqdn -and $owner.profile -ceq $c.profile)
    $owned = $true
    Require (-not (Test-Path -LiteralPath "$Root\transition.json") -and -not (Test-Path -LiteralPath "$Root\blocked.json"))
    $lock = [IO.File]::Open("$Root\rotation.lock", 'OpenOrCreate', 'ReadWrite', 'None')
    $active = "$Root\active.json"
    if (Test-Path -LiteralPath $active) {
        $previous = [IO.File]::ReadAllText($active)
        $old = $previous | ConvertFrom-Json -AsHashtable
        Require ($old.cert_file.StartsWith("$Root\generations\") -and $old.key_file -ceq ($old.cert_file.Replace('fullchain.pem', 'key.pem')))
        Private $old.cert_file; Private $old.key_file
        $oldCert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText($old.cert_file))
        $oldPublic = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($oldCert)
        $oldSPKI = Digest $oldPublic.ExportSubjectPublicKeyInfo(); $oldPublic.Dispose()
        $due = $oldCert.NotBefore.ToUniversalTime().AddSeconds(604800 * 0.66); $oldCert.Dispose()
        Require ($Action -ceq 'Rotate')
        if ([DateTime]::UtcNow -lt $due) {
            $oldKey = [Security.Cryptography.RSA]::Create()
            try {
                $oldKey.ImportFromPem([IO.File]::ReadAllText($old.key_file))
                $current = Verify-Leaf $c $old.cert_file $oldKey
                Readback $c $current.fingerprint $old.cert_file $old.key_file
            } finally { $oldKey.Dispose() }
            Atomic "$Root\status.json" (@{state='current'; last_check=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); success=$true; expires=$current.expires; rotate_by=$current.rotate_by} | ConvertTo-Json -Compress)
            Write-Output '{"state":"current"}'; exit 0
        }
    } else { Require ($Action -ceq 'Issue'); $oldSPKI = '' }
    $candidate = "$Root\generations\" + [Guid]::NewGuid().ToString('N')
    New-Item -ItemType Directory -Path $candidate | Out-Null
    $key = [Security.Cryptography.RSA]::Create(3072)
    $csr = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=' + $c.fqdn, $key, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new(); $san.AddDnsName($c.fqdn)
    $csr.CertificateExtensions.Add($san.Build())
    $der = $csr.CreateSigningRequest(); $csrPem = [Security.Cryptography.PemEncoding]::WriteString('CERTIFICATE REQUEST', $der)
    Atomic "$candidate\key.pem" $key.ExportPkcs8PrivateKeyPem()
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $claims = @{iss='s3-' + $c.profile; sub=$c.fqdn; sans=@($c.fqdn); aud=@($c.issuer_url); iat=$now; nbf=$now; exp=$now+300; jti=(Hex ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))); cnf=@{'x5rt#S256'=(B64 ([Security.Cryptography.SHA256]::HashData($der)))}}
    $token = Sign-Token $c $claims
    $handler = [S7Tls]::Handler($c.root_file, $c.issuer_file, ([Uri]$c.issuer_url).Host)
    $client = [Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds(15)
    try {
        $body = [Net.Http.StringContent]::new((@{csr=$csrPem; ott=$token} | ConvertTo-Json -Compress), [Text.Encoding]::UTF8, 'application/json')
        $response = $client.PostAsync($c.issuer_url, $body).GetAwaiter().GetResult()
        try {
            Require ($response.StatusCode -eq 201)
            $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult(); Require ($text.Length -le 32768)
            $issued = $text | ConvertFrom-Json -AsHashtable
            Require ($issued.certChain.Count -eq 2 -and $issued.crt -ceq $issued.certChain[0])
            Atomic "$candidate\cert.pem" $issued.crt
            $returnedIssuer = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($issued.certChain[1])
            try { Require ((Digest $returnedIssuer.RawData) -ceq $c.issuer_sha256) } finally { $returnedIssuer.Dispose() }
            Atomic "$candidate\fullchain.pem" ($issued.crt + [IO.File]::ReadAllText($c.issuer_file))
        } finally { $response.Dispose(); $body.Dispose() }
    } finally { $client.Dispose(); $handler.Dispose(); $token = $null }
    $info = Verify-Leaf $c "$candidate\cert.pem" $key $oldSPKI
    Atomic "$Root\transition.json" (@{expires=([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+240)} | ConvertTo-Json -Compress)
    Atomic $active (@{cert_file="$candidate\fullchain.pem"; key_file="$candidate\key.pem"; ca_file=$c.root_file} | ConvertTo-Json -Compress)
    $published = $true
    foreach ($task in @('TelemetryProbe', 'TelemetryTransport', 'TelemetryForwarder')) {
        Enable-ScheduledTask -TaskPath '\SambaAD\' -TaskName $task | Out-Null
        if ($task -eq 'TelemetryForwarder') { Stop-ScheduledTask -TaskPath '\SambaAD\' -TaskName $task }
        Start-ScheduledTask -TaskPath '\SambaAD\' -TaskName $task
    }
    Readback $c $info.fingerprint "$candidate\fullchain.pem" "$candidate\key.pem"
    Atomic "$Root\status.json" (@{state='active'; last_check=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); success=$true; expires=$info.expires; rotate_by=$info.rotate_by} | ConvertTo-Json -Compress)
    Remove-Item -LiteralPath "$Root\transition.json"
    Enable-ScheduledTask -TaskPath '\SambaAD\' -TaskName TelemetryRotate | Out-Null
    $published = $false # Commit: retain prior generation for directed cleanup, never reuse its key.
    Write-Output '{"state":"active"}'
} catch {
    if ($published) {
        try {
            Stop-ScheduledTask -TaskPath '\SambaAD\' -TaskName TelemetryForwarder
            if ($null -ne $previous) {
                Atomic "$Root\active.json" $previous
                Start-ScheduledTask -TaskPath '\SambaAD\' -TaskName TelemetryForwarder
                $old = $previous | ConvertFrom-Json -AsHashtable
                $restored = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText($old.cert_file))
                try { Readback $c (Digest $restored.RawData) $old.cert_file $old.key_file } finally { $restored.Dispose() }
            } else {
                Remove-Item -LiteralPath "$Root\active.json"
                Disable-ScheduledTask -TaskPath '\SambaAD\' -TaskName TelemetryForwarder | Out-Null
            }
            Remove-Item -LiteralPath "$Root\transition.json" -ErrorAction SilentlyContinue
        } catch {
            Stop-ScheduledTask -TaskPath '\SambaAD\' -TaskName TelemetryForwarder -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskPath '\SambaAD\' -TaskName TelemetryForwarder -ErrorAction SilentlyContinue | Out-Null
            try { Atomic "$Root\blocked.json" '{"state":"rollback_unproven"}' } catch { }
        }
    }
    if ($owned -and $Apply) {
        try { Atomic "$Root\status.json" (@{state='failed'; last_check=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); success=$false} | ConvertTo-Json -Compress) } catch { }
    }
    Write-Error 'S7 Windows PKI failed; values suppressed' -ErrorAction Continue
    exit 1
} finally {
    if ($null -ne $key) { $key.Dispose() }
    if ($null -ne $lock) { $lock.Dispose() }
}
