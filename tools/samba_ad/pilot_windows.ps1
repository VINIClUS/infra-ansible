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
function Inspect-Pilot($R) {
    $computer = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $product = Get-CimInstance Win32_ComputerSystemProduct
    $edition = (Get-WindowsEdition -Online).Edition
    Assert-S6 ($edition -ceq $R.windows.edition)
    Assert-S6 ($os.BuildNumber -ceq $R.windows.build -and $os.OSArchitecture -eq '64-bit')
    Assert-S6 ([DateTime]::UtcNow -lt [DateTime]::ParseExact($R.windows.support_until, 'yyyy-MM-dd', $null))
    $licenses = @(Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" |
        Where-Object { $_.PartialProductKey -and $_.LicenseStatus -eq 1 })
    Assert-S6 ($licenses.Count -eq 1) # observed activation, not proof of legal ownership
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
    return @{ member=[bool]$computer.PartOfDomain; state=$state; nic=$nic }
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
                  machine_id=$R.identity.machine_id; sid=$R.sid; member=$false}
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
function Apply-Policy($R,$Credential,$Directory) {
    Check-Assets $R
    Import-Module GroupPolicy
    $baseline=$R.windows.baseline
    $temporary=Join-Path 'C:\ProgramData\SambaADPilot' ([Guid]::NewGuid().ToString())
    New-Item -ItemType Directory $temporary | Out-Null
    try {
        # Validate entry paths before extraction; never run any downloaded code.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive=[IO.Compression.ZipFile]::OpenRead($baseline.archive)
        try {
            $entries=@($archive.Entries | Where-Object { $_.Name -ne '' })
            Assert-S6 ($entries.Count -eq @($baseline.files.PSObject.Properties).Count)
            foreach ($entry in $entries) {
                $name=$entry.FullName.Replace('\','/')
                Assert-S6 (-not $name.Contains('..') -and -not $name.StartsWith('/') -and -not $name.Contains(':'))
                Assert-S6 ($null -ne $baseline.files.PSObject.Properties[$name])
            }
        } finally { $archive.Dispose() }
        [IO.Compression.ZipFile]::ExtractToDirectory($baseline.archive,$temporary)
        foreach ($file in $baseline.files.PSObject.Properties) {
            Assert-S6 ((File-Hash (Join-Path $temporary $file.Name)) -ceq $file.Value)
        }
        foreach ($setting in $baseline.settings) {
            $entries=@(Read-Pol (Join-Path $temporary $setting.baseline_file))
            Assert-S6 (@($entries | Where-Object { $_.key -ceq $setting.key -and $_.name -ceq $setting.name -and $_.value -eq $setting.value }).Count -eq 1)
        }
        # GPMC uses the impersonated domain network token. No password in CLI,
        # scheduled tasks, script files, environment variables or process command line.
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class S6Logon {
 [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
 public static extern bool LogonUser(string u,string d,string p,int type,int provider,out IntPtr token);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr token);
}
'@
        $token=[IntPtr]::Zero; $context=$null
        try {
            $nc=$Credential.GetNetworkCredential()
            Assert-S6 ([S6Logon]::LogonUser($nc.UserName,$nc.Domain,$nc.Password,9,3,[ref]$token))
            $identity=[Security.Principal.WindowsIdentity]::new($token)
            $context=$identity.Impersonate()
            $dc=$R.dcs.dc01.fqdn; $domain=$script:M.domain.dns_domain
            $all=@(Get-GPO -All -Domain $domain -Server $dc)
            $found=@($all | Where-Object { $_.DisplayName -ceq $baseline.gpo_name })
            Assert-S6 ($found.Count -le 1)
            if ($found.Count -eq 1) {
                Assert-S6 ($found[0].Description -ceq $Directory.owner)
                $gpo=$found[0]
            } else {
                Assert-S6 ($R.apply)
                $gpo=New-GPO -Name $baseline.gpo_name -Comment $Directory.owner -Domain $domain -Server $dc
            }
            $policyPath='\\' + $dc + '\SYSVOL\' + $domain + '\Policies\{' + $gpo.Id.ToString().ToUpperInvariant() + '}'
            $existing=@(Get-ChildItem $policyPath -File -Recurse)
            foreach ($file in $existing) {
                $relative=$file.FullName.Substring($policyPath.Length + 1)
                Assert-S6 ($relative -in @('GPT.INI','Machine\Registry.pol'))
            }
            if (Test-Path ($policyPath + '\Machine\Registry.pol')) {
                foreach ($entry in @(Read-Pol ($policyPath + '\Machine\Registry.pol'))) {
                    Assert-S6 ($entry.type -eq 4 -and @($baseline.settings | Where-Object {
                        $_.key -ceq $entry.key -and $_.name -ceq $entry.name -and $_.value -eq $entry.value }).Count -eq 1)
                }
            }
            $inheritance=Get-GPInheritance -Target $R.ou -Domain $domain -Server $dc
            Assert-S6 (@($inheritance.GpoLinks | Where-Object { $_.GpoId -ne $gpo.Id }).Count -eq 0)
            if ($R.apply) {
                foreach ($setting in $baseline.settings) {
                    Set-GPRegistryValue -Guid $gpo.Id -Key $setting.key -ValueName $setting.name -Type DWord -Value $setting.value -Domain $domain -Server $dc | Out-Null
                }
                if (@($inheritance.GpoLinks).Count -eq 0) {
                    New-GPLink -Guid $gpo.Id -Target $R.ou -Domain $domain -Server $dc -LinkEnabled Yes -Enforced No | Out-Null
                }
            }
            foreach ($setting in $baseline.settings) {
                $value=Get-GPRegistryValue -Guid $gpo.Id -Key $setting.key -ValueName $setting.name -Domain $domain -Server $dc
                Assert-S6 ($value.Type -eq 'DWord' -and $value.Value -eq $setting.value)
            }
            $script:PolicyId=$gpo.Id.ToString()
        } finally {
            if ($null -ne $context) { $context.Undo(); $context.Dispose() }
            if ($token -ne [IntPtr]::Zero) { [void][S6Logon]::CloseHandle($token) }
        }
    } finally { Remove-Item $temporary -Recurse -Force }
}
function Verify-PolicyBothDCs($R) {
    $digests=@()
    foreach ($dc in @($R.dcs.dc01,$R.dcs.dc02)) {
        $root='\\' + $dc.fqdn + '\SYSVOL\' + $script:M.domain.dns_domain + '\Policies\{' + $script:PolicyId.ToUpperInvariant() + '}'
        $digests += ((File-Hash ($root + '\GPT.INI')) + (File-Hash ($root + '\Machine\Registry.pol')))
        # Native refresh must demonstrably use each named DC. If DC Locator
        # selects a different DC, fail pending runtime routing diagnosis.
        & nltest.exe ("/sc_reset:" + $script:M.domain.dns_domain + '\' + $dc.fqdn) | Out-Null
        Assert-S6 ($LASTEXITCODE -eq 0)
        & gpupdate.exe /target:computer /force /wait:120 | Out-Null; Assert-S6 ($LASTEXITCODE -eq 0)
        $report='C:\ProgramData\SambaADPilot\gpresult-' + $dc.fqdn.Split('.')[0] + '.xml'
        & gpresult.exe /scope computer /x $report /f | Out-Null; Assert-S6 ($LASTEXITCODE -eq 0)
        [xml]$result=Get-Content $report -Raw
        Assert-S6 ($result.DocumentElement.LocalName -eq 'Rsop')
        Assert-S6 ($result.OuterXml.ToLowerInvariant().Contains($script:PolicyId.ToLowerInvariant()))
        $controllers=@($result.SelectNodes("//*[local-name()='DCName']") | ForEach-Object { $_.InnerText.TrimStart('\').ToLowerInvariant() })
        Assert-S6 ($controllers -contains $dc.fqdn)
        foreach ($setting in $R.windows.baseline.settings) {
            $path=$setting.key.Replace('HKLM\','HKLM:\')
            Assert-S6 ((Get-ItemPropertyValue -LiteralPath $path -Name $setting.name) -eq $setting.value)
        }
    }
    Assert-S6 ($digests.Count -eq 2 -and $digests[0] -ceq $digests[1])
}
try {
    $wire=[Console]::In.ReadToEnd() | ConvertFrom-Json
    $R=$wire.request; $script:M=$wire.manifest
    $observed=Inspect-Pilot $R
    if ($wire.mode -eq 'probe') {
        @{nonce=$wire.nonce; identity=$R.identity; member=$observed.member} | ConvertTo-Json -Depth 20 -Compress
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
                                  machine_id=$R.identity.machine_id; sid=$R.sid; member=$true; computer_guid=$guid}
                    $state='joined_reboot_required'; $changed=$true
                } else { Assert-S6 ($accounts.Entries.Count -eq 0) }
            } else {
                Assert-S6 ($wire.directory.action -eq 'verify' -and $accounts.Entries.Count -eq 1)
                Assert-S6 ([string]$accounts.Entries[0].Attributes['description'][0] -ceq $wire.directory.owner)
                $guid=([BitConverter]::ToString([byte[]]$accounts.Entries[0].Attributes['objectGUID'][0])).Replace('-','').ToLowerInvariant()
                Assert-S6 ($guid -ceq $observed.state.computer_guid -and $guid -ceq $wire.directory.computer_guid)
                Verify-Membership $R $credential
                if ($R.action -eq 'policy') { Apply-Policy $R $credential $wire.directory; $changed=$R.apply }
                if ($R.apply) {
                    & gpupdate.exe /target:computer /force /wait:120 | Out-Null; Assert-S6 ($LASTEXITCODE -eq 0)
                    $report='C:\ProgramData\SambaADPilot\gpresult.xml'
                    & gpresult.exe /scope computer /x $report /f | Out-Null; Assert-S6 ($LASTEXITCODE -eq 0)
                    [xml]$result=Get-Content $report -Raw
                    Assert-S6 ($result.DocumentElement.LocalName -eq 'Rsop')
                    if ($R.action -eq 'policy') {
                        Assert-S6 ($result.OuterXml.ToLowerInvariant().Contains($script:PolicyId.ToLowerInvariant()))
                        Verify-PolicyBothDCs $R
                    }
                    $state='verified'
                }
            }
        } finally { $ldap.Dispose(); $secure.Dispose(); $wire.credentials.password=$null }
    }
    @{nonce=$wire.nonce; state=$state; changed=$changed} | ConvertTo-Json -Compress
} catch {
    [Console]::Error.WriteLine('S6 Windows precondition failed (values suppressed)')
    exit 2
}
