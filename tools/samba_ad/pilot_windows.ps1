# Public, fixed QGA program. Private values are read once from Console.In.
# Do not launch with -EncodedCommand or interpolate a credential into this script.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

function Assert-S6($Condition) { if (-not $Condition) { throw 'S6 precondition failed (values suppressed)' } }
function Hash-Bytes([byte[]]$Bytes) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $h.Dispose() }
}
function Public-Cert($Pem) {
    $base64 = $Pem.Replace('-----BEGIN CERTIFICATE-----','').Replace('-----END CERTIFICATE-----','') -replace '\s',''
    return [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($base64))
}
function File-Hash($Path) {
    Assert-S6 (-not ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint))
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Write-State($State) {
    $directory = 'C:\ProgramData\SambaADPilot'
    if (-not (Test-Path $directory)) { New-Item -ItemType Directory -Path $directory | Out-Null }
    Assert-S6 (-not ((Get-Item $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint))
    # LocalSystem and built-in Administrators only, expressed as locale-neutral SIDs.
    & icacls.exe $directory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    Assert-S6 ($LASTEXITCODE -eq 0)
    $State | ConvertTo-Json -Depth 20 -Compress | Set-Content -LiteralPath ($directory + '\state.json') -Encoding UTF8
}
function Read-LicenseObservation([string]$Edition) {
    # Raw native facts only: activation and purchased entitlement are not pilot
    # gates. Never collect keys, activate, rearm or convert the installed image.
    $products=@(Get-CimInstance SoftwareLicensingProduct -Property ID,LicenseStatus,GracePeriodRemaining -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND LicenseIsAddon=False" |
        ForEach-Object { @{id=$_.ID; license_status=$_.LicenseStatus;
            grace_period_minutes=$_.GracePeriodRemaining} })
    return @{source='SoftwareLicensingProduct'; edition=$Edition;
        evaluation=$Edition.EndsWith('Eval'); products=$products; entitlement='not_attested'}
}
function Inspect-Pilot($R) {
    $computer = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $product = Get-CimInstance Win32_ComputerSystemProduct
    $edition = (Get-WindowsEdition -Online).Edition
    Assert-S6 ($edition -ceq $R.windows.edition)
    Assert-S6 ($os.BuildNumber -ceq $R.windows.build -and $os.OSArchitecture -eq '64-bit')
    Assert-S6 ($os.ProductType -eq 3 -and $computer.DomainRole -in @(2,3))
    Assert-S6 ([DateTime]::UtcNow -lt [DateTime]::ParseExact($R.windows.support_until, 'yyyy-MM-dd', $null))
    $licensing = Read-LicenseObservation $edition
    $machine = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid.ToLowerInvariant()
    $localSids = @(Get-LocalUser | ForEach-Object { $_.SID.AccountDomainSid.Value } | Select-Object -Unique)
    Assert-S6 ($localSids.Count -eq 1 -and $localSids[0] -ceq $R.identity.local_sid)
    Assert-S6 ($product.UUID.ToLowerInvariant() -ceq $R.identity.uuid -and $machine -ceq $R.identity.machine_id)
    Assert-S6 ($os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') -ceq $R.identity.boot_id)
    Assert-S6 ($computer.Name.ToLowerInvariant() -ceq $R.substrate.resource.name.Split('.')[0])
    $nic = Get-NetAdapter -Name $R.identity.interface
    Assert-S6 ($nic.MacAddress.Replace('-',':') -ceq $R.substrate.resource.mac)
    $addresses = @(Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress)
    Assert-S6 ($addresses.Count -eq 1 -and $addresses[0] -ceq $R.substrate.resource.address.Split('/')[0])
    Assert-S6 ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State').ImageState -eq 'IMAGE_STATE_COMPLETE')
    $state = $null
    if (Test-Path 'C:\ProgramData\SambaADPilot\state.json') {
        $null = File-Hash 'C:\ProgramData\SambaADPilot\state.json'
        $state = Get-Content 'C:\ProgramData\SambaADPilot\state.json' -Raw | ConvertFrom-Json
        Assert-S6 ($state.owner -ceq $R.substrate.compatibility.data.target_sha256)
        Assert-S6 ($state.uuid -ceq $R.identity.uuid -and $state.machine_id -ceq $machine)
    }
    if ($computer.PartOfDomain) {
        Assert-S6 ($null -ne $state -and $state.member -eq $true -and $state.sid -ceq $R.sid)
        Assert-S6 ($computer.Domain.ToUpperInvariant() -ceq $script:M.domain.realm)
    } else {
        Assert-S6 ($null -eq $state -or $state.member -eq $false)
    }
    return @{ member=[bool]$computer.PartOfDomain; state=$state; nic=$nic; licensing=$licensing }
}
function Check-Assets($R) {
    $source = $R.windows.rsat_source
    Assert-S6 ((Get-Item $source).PSIsContainer -and -not ((Get-Item $source).Attributes -band [IO.FileAttributes]::ReparsePoint))
    $files = @(Get-ChildItem $source -File)
    Assert-S6 ($files.Count -eq @($R.windows.rsat_files.PSObject.Properties).Count)
    foreach ($file in $files) {
        $pin = $R.windows.rsat_files.PSObject.Properties[$file.Name]
        Assert-S6 ($null -ne $pin -and (File-Hash $file.FullName) -ceq $pin.Value)
        $signature = Get-AuthenticodeSignature -FilePath $file.FullName
        Assert-S6 ($signature.Status -eq 'Valid' -and $signature.SignerCertificate.Subject -match 'O=Microsoft Corporation')
    }
    Assert-S6 ((File-Hash $R.windows.baseline.archive) -ceq $R.windows.baseline.sha256)
}
function Prepare-Pilot($R, $Observed) {
    Check-Assets $R
    if (-not $R.apply) { return }
    Assert-S6 (-not $Observed.member)
    foreach ($key in @('root','issuer')) {
        $pem = $R.trust.($key + '_pem')
        Assert-S6 ((Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($pem))) -ceq $R.trust.($key + '_sha256'))
        $cert = Public-Cert $pem
        Assert-S6 ($cert.NotBefore.ToUniversalTime() -lt [DateTime]::UtcNow -and $cert.NotAfter.ToUniversalTime() -gt [DateTime]::UtcNow)
        $constraint = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
        Assert-S6 ($constraint.Count -eq 1 -and $constraint[0].CertificateAuthority)
        $storeName = if ($key -eq 'root') { 'Root' } else { 'CA' }
        $store = [Security.Cryptography.X509Certificates.X509Store]::new($storeName, 'LocalMachine')
        try { $store.Open('ReadWrite'); $store.Add($cert) } finally { $store.Close() }
    }
    $dns = @($R.dcs.dc01.address, $R.dcs.dc02.address)
    Set-DnsClientServerAddress -InterfaceIndex $Observed.nic.ifIndex -ServerAddresses $dns
    & w32tm.exe /config ("/manualpeerlist:" + ($script:M.network.time_sources -join ' ')) /syncfromflags:manual /update | Out-Null
    Assert-S6 ($LASTEXITCODE -eq 0)
    Start-Service W32Time
    & w32tm.exe /resync | Out-Null; Assert-S6 ($LASTEXITCODE -eq 0)
    # Server 2025 uses server features. Client RSAT capabilities are not inferred.
    $features = @('GPMC','RSAT-AD-PowerShell')
    $facts = @(Get-WindowsFeature -Name $features)
    Assert-S6 ($facts.Count -eq 2)
    $missing = @($facts | Where-Object { -not $_.Installed } | Select-Object -ExpandProperty Name)
    if ($missing.Count -gt 0) {
        # DISM -LimitAccess is mandatory: never fall back to Windows Update.
        foreach ($name in $missing) {
            $feature = if ($name -eq 'GPMC') { 'GroupPolicyManagement' } else { 'RSAT-AD-PowerShell' }
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -Source $R.windows.rsat_source -LimitAccess -NoRestart
            Assert-S6 (-not $result.RestartNeeded)
        }
        Assert-S6 (@(Get-WindowsFeature -Name $features | Where-Object { -not $_.Installed }).Count -eq 0)
    }
    # Prevent this credential-bearing process being captured in local crash dumps.
    New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Force | Out-Null
    New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name Disabled -Value 1 -PropertyType DWord -Force | Out-Null
    Write-State @{owner=$R.substrate.compatibility.data.target_sha256; uuid=$R.identity.uuid;
        machine_id=$R.identity.machine_id; sid=$R.sid; member=$false; licensing=$Observed.licensing}
}
function Check-Endpoints($R, $Observed) {
    $dns = @((Get-DnsClientServerAddress -InterfaceIndex $Observed.nic.ifIndex -AddressFamily IPv4).ServerAddresses)
    Assert-S6 (($dns -join ',') -ceq (@($R.dcs.dc01.address,$R.dcs.dc02.address) -join ','))
    foreach ($dc in @($R.dcs.dc01,$R.dcs.dc02)) {
        foreach ($resolver in @($R.dcs.dc01.address,$R.dcs.dc02.address)) {
            $addresses = @(Resolve-DnsName -Name $dc.fqdn -Type A -Server $resolver -DnsOnly |
                          Where-Object { $_.Type -eq 'A' } | Select-Object -ExpandProperty IPAddress -Unique)
            Assert-S6 ($addresses.Count -eq 1 -and $addresses[0] -ceq $dc.address)
        }
        $tcp = [Net.Sockets.TcpClient]::new()
        try {
            $task = $tcp.ConnectAsync($dc.address,636); Assert-S6 ($task.Wait(10000)); $task.GetAwaiter().GetResult()
            $stream = [Net.Security.SslStream]::new($tcp.GetStream(),$false)
            try {
                $stream.ReadTimeout=10000; $stream.WriteTimeout=10000
                $stream.AuthenticateAsClient($dc.fqdn,$null,[Security.Authentication.SslProtocols]::Tls12,$false)
                Assert-S6 ((Hash-Bytes $stream.RemoteCertificate.GetRawCertData()) -ceq $dc.certificate_sha256)
            } finally { $stream.Dispose() }
        } finally { $tcp.Dispose() }
    }
    Assert-S6 ((Get-Service W32Time).Status -eq 'Running')
    # Native numeric stratum and age, independent of localized w32tm text.
    $time = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    Assert-S6 ($time.Type -eq 'NTP')
    foreach ($peer in $script:M.network.time_sources) {
        $sample = (& w32tm.exe /stripchart ("/computer:" + $peer) /samples:1 /dataonly 2>$null) -join "`n"
        Assert-S6 ($LASTEXITCODE -eq 0 -and $sample -match '([+-][0-9]+\.[0-9]+)s')
        Assert-S6 ([Math]::Abs([double]::Parse($Matches[1],[Globalization.CultureInfo]::InvariantCulture)) -le 1.0)
    }
}
function Open-Directory($DC, $Credential) {
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $id = [DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($DC.fqdn,636,$true,$false)
    $ldap = [DirectoryServices.Protocols.LdapConnection]::new($id,$Credential.GetNetworkCredential(),[DirectoryServices.Protocols.AuthType]::Basic)
    $ldap.Timeout = [TimeSpan]::FromSeconds(15)
    $ldap.SessionOptions.ProtocolVersion = 3
    $ldap.SessionOptions.SecureSocketLayer = $true
    $ldap.SessionOptions.ReferralChasing = [DirectoryServices.Protocols.ReferralChasingOptions]::None
    $pin = $DC.certificate_sha256
    $ldap.SessionOptions.VerifyServerCertificate = { param($connection,$certificate)
        return (Hash-Bytes $certificate.GetRawCertData()) -ceq $pin
    }.GetNewClosure()
    $ldap.Bind()
    return $ldap
}
function Search-Directory($LDAP, $Base, $Filter, $Attributes, $Scope='Subtree') {
    $request = [DirectoryServices.Protocols.SearchRequest]::new($Base,$Filter,
        [DirectoryServices.Protocols.SearchScope]::$Scope,[string[]]$Attributes)
    return $LDAP.SendRequest($request)
}
function Assert-Domain($LDAP,$R) {
    $base = ($script:M.domain.dns_domain.Split('.') | ForEach-Object { 'DC=' + $_ }) -join ','
    $result = Search-Directory $LDAP $base '(objectClass=*)' @('objectSid') 'Base'
    Assert-S6 ($result.Entries.Count -eq 1)
    $sid = [Security.Principal.SecurityIdentifier]::new([byte[]]$result.Entries[0].Attributes['objectSid'][0],0)
    Assert-S6 ($sid.Value -ceq $R.sid)
}
function Verify-Membership($R,$Credential) {
    foreach ($dc in @($R.dcs.dc01,$R.dcs.dc02)) {
        Assert-S6 (Test-ComputerSecureChannel -Server $dc.fqdn -Credential $Credential)
        $ldap = Open-Directory $dc $Credential
        try { Assert-Domain $ldap $R } finally { $ldap.Dispose() }
        # Explicit server UNC and credentials in PSCredential memory, never net use argv.
        $drive = New-PSDrive -Name S6SYSVOL -PSProvider FileSystem -Root ('\\' + $dc.fqdn + '\SYSVOL') -Credential $Credential
        try {
            $policies = @(Get-ChildItem ('S6SYSVOL:\' + $script:M.domain.dns_domain + '\Policies') -Filter GPT.INI -Recurse)
            Assert-S6 ($policies.Count -gt 0)
            foreach ($p in $policies) { Assert-S6 ((Get-Content $p.FullName -Raw) -match '(?im)^Version=\d+') }
        } finally { Remove-PSDrive S6SYSVOL }
    }
}
function Read-Pol($Path) {
    $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($Path),[Text.Encoding]::Unicode)
    try {
        Assert-S6 ($reader.ReadUInt32() -eq 0x67655250 -and $reader.ReadUInt32() -eq 1)
        $entries = @()
        while ($reader.BaseStream.Position -lt $reader.BaseStream.Length) {
            Assert-S6 ($reader.ReadUInt16() -eq 91)
            $key=''; do { $c=$reader.ReadUInt16(); if ($c -ne 0) { $key += [char]$c } } while ($c -ne 0)
            Assert-S6 ($reader.ReadUInt16() -eq 59)
            $name=''; do { $c=$reader.ReadUInt16(); if ($c -ne 0) { $name += [char]$c } } while ($c -ne 0)
            Assert-S6 ($reader.ReadUInt16() -eq 59)
            $type=$reader.ReadUInt32(); Assert-S6 ($reader.ReadUInt16() -eq 59)
            $size=$reader.ReadUInt32(); Assert-S6 ($size -le 1048576 -and $reader.ReadUInt16() -eq 59)
            $data=$reader.ReadBytes($size); Assert-S6 ($data.Length -eq $size -and $reader.ReadUInt16() -eq 93)
            $value = if ($type -eq 4 -and $size -eq 4) { [BitConverter]::ToUInt32($data,0) } else { $null }
            $entries += @{key=('HKLM\' + $key); name=$name; value=$value; type=$type}
        }
        return $entries
    } finally { $reader.Dispose() }
}

try {
    $wire=[Console]::In.ReadToEnd() | ConvertFrom-Json
    $R=$wire.request; $script:M=$wire.manifest; $script:BaselineCatalog=$wire.baseline_catalog
    $observed=Inspect-Pilot $R
    if ($wire.mode -eq 'probe') {
        Check-Assets $R
        if ($R.action -eq 'policy') { Assert-RsopSamples $R }
        if ($R.action -ne 'prepare') {
            Assert-S6 ($null -ne $observed.state)
            Check-Endpoints $R $observed # before PVE opens its credential reference
        }
        @{nonce=$wire.nonce; identity=$R.identity; member=$observed.member; licensing=$observed.licensing} | ConvertTo-Json -Depth 20 -Compress
        exit 0
    }
    $changed=$false; $state='checked'
    if ($R.action -eq 'prepare') {
        Assert-S6 ($null -eq $wire.credentials)
        Prepare-Pilot $R $observed
        if ($R.apply) { $state='prepared'; $changed=$true }
    } else {
        Assert-S6 ($null -ne $observed.state)
        Assert-S6 ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting').Disabled -eq 1)
        Check-Endpoints $R $observed
        $secure=ConvertTo-SecureString $wire.credentials.password -AsPlainText -Force
        $credential=[PSCredential]::new(($wire.credentials.username + '@' + $script:M.domain.realm),$secure)
        $ldap=Open-Directory $R.dcs.dc01 $credential
        try {
            Assert-Domain $ldap $R
            $short=$R.substrate.resource.name.Split('.')[0].ToUpperInvariant()
            $accounts=Search-Directory $ldap $R.ou ('(sAMAccountName=' + $short + '$)') @('description','objectGUID')
            if (-not $observed.member) {
                Assert-S6 ($R.action -eq 'join' -and $wire.directory.action -eq 'join')
                if ($R.apply) {
                    Assert-S6 ($accounts.Entries.Count -eq 1)
                    Assert-S6 ([string]$accounts.Entries[0].Attributes['description'][0] -ceq $wire.directory.owner)
                    $guid=([BitConverter]::ToString([byte[]]$accounts.Entries[0].Attributes['objectGUID'][0])).Replace('-','').ToLowerInvariant()
                    Assert-S6 ($guid -ceq $wire.directory.computer_guid -and $accounts.Entries[0].DistinguishedName -ieq $wire.directory.computer_dn)
                    $result=Add-Computer -DomainName $script:M.domain.dns_domain -Server $R.dcs.dc01.fqdn -OUPath $R.ou -Credential $credential -PassThru -Force
                    Assert-S6 ($result.HasSucceeded)
                    $after=Search-Directory $ldap $wire.directory.computer_dn '(objectClass=computer)' @('description','objectGUID') 'Base'
                    Assert-S6 ($after.Entries.Count -eq 1 -and [string]$after.Entries[0].Attributes['description'][0] -ceq $wire.directory.owner)
                    $afterGuid=([BitConverter]::ToString([byte[]]$after.Entries[0].Attributes['objectGUID'][0])).Replace('-','').ToLowerInvariant()
                    Assert-S6 ($afterGuid -ceq $guid)
                    Write-State @{owner=$R.substrate.compatibility.data.target_sha256; uuid=$R.identity.uuid;
                        machine_id=$R.identity.machine_id; sid=$R.sid; member=$true; computer_guid=$guid; licensing=$observed.licensing}
                    $state='joined_reboot_required'; $changed=$true
                } else { Assert-S6 ($accounts.Entries.Count -eq 0) }
            } else {
                Assert-S6 ($wire.directory.action -eq 'verify' -and $accounts.Entries.Count -eq 1)
                Assert-S6 ([string]$accounts.Entries[0].Attributes['description'][0] -ceq $wire.directory.owner)
                $guid=([BitConverter]::ToString([byte[]]$accounts.Entries[0].Attributes['objectGUID'][0])).Replace('-','').ToLowerInvariant()
                Assert-S6 ($guid -ceq $observed.state.computer_guid -and $guid -ceq $wire.directory.computer_guid)
                Verify-Membership $R $credential
                if ($R.action -eq 'policy') { Apply-Policy $R $credential $wire.directory; $changed=$script:PolicyChanged }
                if ($R.apply) {
                    if ($R.action -eq 'policy') { Verify-PolicyBothDCs $R $credential; $state='verified' }
                    else { $state='membership_verified' }
                }
            }
        } finally { $ldap.Dispose(); $secure.Dispose(); $wire.credentials.password=$null }
    }
    @{nonce=$wire.nonce; state=$state; changed=$changed; licensing=$observed.licensing} | ConvertTo-Json -Depth 20 -Compress
} catch {
    [Console]::Error.WriteLine('S6 Windows precondition failed (values suppressed)')
    exit 2
}
