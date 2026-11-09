# Fixed native adapters for the complete pinned Microsoft member-server baseline.
function Read-SecurityInf([string]$Path) {
    $sections=@{};$section=$null
    foreach($line0 in [IO.File]::ReadAllLines($Path,[Text.Encoding]::Unicode)) {
        $line=$line0.Trim();if(-not $line -or $line.StartsWith(';')){continue}
        if($line -match '^\[([^\]]+)\]$') {
            $section=$Matches[1];Assert-S6 (-not $sections.ContainsKey($section));$sections[$section]=@{};continue
        }
        Assert-S6 ($null -ne $section -and $line.Contains('='))
        $pair=$line.Split('=',2);$key=$pair[0].Trim()
        Assert-S6 (-not $sections[$section].ContainsKey($key));$sections[$section][$key]=$pair[1].Trim()
    }
    return $sections
}
function Assert-RegistryPolicy($Rows,[string]$Scope) {
    foreach($row in $Rows) {
        if($row.scope -ne $Scope){continue}
        $root=if($Scope -eq 'User'){'HKCU:\'}else{'HKLM:\'}
        $path=$root+$row.key
        Assert-S6 (Test-Path -LiteralPath $path)
        $key=Get-Item -LiteralPath $path
        if($row.type -eq 0){Assert-S6 ($row.name -ceq '' -and $row.data -ceq '');continue}
        if($row.name.StartsWith('**del.')) {
            Assert-S6 ($row.name.Substring(6) -notin $key.GetValueNames());continue
        }
        Assert-S6 ($row.name -in $key.GetValueNames())
        $value=$key.GetValue($row.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind=$key.GetValueKind($row.name).ToString()
        $bytes=if($row.type -eq 4){Assert-S6 ($kind -eq 'DWord');[BitConverter]::GetBytes([uint32]$value)}else{
            Assert-S6 ($row.type -eq 1 -and $kind -eq 'String');[Text.Encoding]::Unicode.GetBytes([string]$value+[char]0)
        }
        Assert-S6 (([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant() -ceq $row.data)
    }
}
function Assert-SecurityState($Catalog,[string]$Directory) {
    $path=Join-Path $Directory 'effective-security.inf'
    & secedit.exe /export /mergedpolicy /cfg $path /quiet | Out-Null;Assert-S6 ($LASTEXITCODE -eq 0)
    $actual=Read-SecurityInf $path
    foreach($component in $Catalog.components.PSObject.Properties.Value) {
        foreach($section in $component.security.PSObject.Properties) {
            if($section.Name -in @('Unicode','Version')){continue}
            foreach($setting in $section.Value.PSObject.Properties) {
                Assert-S6 ($actual.ContainsKey($section.Name) -and $actual[$section.Name].ContainsKey($setting.Name))
                $value=$actual[$section.Name][$setting.Name]
                if($section.Name -eq 'Privilege Rights') {
                    $normalize={param($v)(@($v.Split(',') | ForEach-Object {$_.Trim()} | Where-Object {$_} | Sort-Object) -join ',')}
                    Assert-S6 ((& $normalize $value) -ceq (& $normalize $setting.Value))
                }else{Assert-S6 ($value -ceq $setting.Value)}
            }
        }
    }
    $audit=Join-Path $Directory 'effective-audit.csv'
    & auditpol.exe /backup ("/file:"+$audit) | Out-Null;Assert-S6 ($LASTEXITCODE -eq 0)
    $rows=@(Import-Csv -LiteralPath $audit)
    foreach($component in $Catalog.components.PSObject.Properties.Value) {
        foreach($expected in $component.audit) {
            $match=@($rows | Where-Object {$_.'Subcategory GUID' -ieq $expected.'Subcategory GUID'})
            Assert-S6 ($match.Count -eq 1 -and $match[0].'Setting Value' -ceq $expected.'Setting Value')
        }
    }
    $guard=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
    Assert-S6 ($guard.VirtualizationBasedSecurityStatus -eq 2 -and 1 -in $guard.SecurityServicesRunning -and 2 -in $guard.SecurityServicesRunning)
}
function Assert-PolicyFiles([string]$Path,$Expected) {
    $files=@(Get-ChildItem -LiteralPath $Path -File -Recurse)
    $seen=@()
    foreach($file in $files) {
        $relative=$file.FullName.Substring($Path.Length+1).Replace('\','/')
        if($relative -ieq 'GPT.INI'){continue}
        $pin=$Expected.PSObject.Properties[$relative]
        Assert-S6 ($null -ne $pin -and (File-Hash $file.FullName) -ceq $pin.Value)
        $seen+=$relative.ToLowerInvariant()
    }
    Assert-S6 ($seen.Count -eq @($Expected.PSObject.Properties).Count)
    foreach($file in $Expected.PSObject.Properties){Assert-S6 ($file.Name.ToLowerInvariant() -in $seen)}
}
function Prepare-BaselineArchive($R,[string]$Destination) {
    $catalog=$script:BaselineCatalog
    Assert-S6 ((File-Hash $R.windows.baseline.archive) -ceq $catalog.sha256)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive=[IO.Compression.ZipFile]::OpenRead($R.windows.baseline.archive)
    try {
        $entries=@($archive.Entries | Where-Object {$_.Name -ne ''})
        Assert-S6 ($entries.Count -eq @($catalog.files.PSObject.Properties).Count)
        $seen=@{}
        foreach($entry in $entries) {
            $name=$entry.FullName.Replace('\','/')
            Assert-S6 (-not $name.Contains('..') -and -not $name.StartsWith('/') -and -not $name.Contains(':') -and -not $seen.ContainsKey($name))
            Assert-S6 ($null -ne $catalog.files.PSObject.Properties[$name]);$seen[$name]=$true
        }
    }finally{$archive.Dispose()}
    [IO.Compression.ZipFile]::ExtractToDirectory($R.windows.baseline.archive,$Destination)
    foreach($file in $catalog.files.PSObject.Properties){Assert-S6 ((File-Hash (Join-Path $Destination $file.Name)) -ceq $file.Value)}
    # Only two exact approved S4 conflicts differ from the vendor backup.
    $domain=$catalog.components.'domain-security'
    $inf=Join-Path $Destination ($catalog.root+'/GPOs/{'+$domain.backup_id+'}/DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf')
    $content=[IO.File]::ReadAllText($inf,[Text.Encoding]::Unicode)
    foreach($replacement in $catalog.replacements.PSObject.Properties) {
        $before=$replacement.Name+' = '+$replacement.Value.vendor
        Assert-S6 ([regex]::Matches($content,'(?m)^'+[regex]::Escape($before)+'\r?$').Count -eq 1)
        $content=$content.Replace($before,$replacement.Name+' = '+$replacement.Value.required)
    }
    [IO.File]::WriteAllText($inf,$content,[Text.Encoding]::Unicode)
    # Complete policy-bearing file coverage, including security/audit/user data.
    foreach($component in $catalog.components.PSObject.Properties.Value) {
        $path=Join-Path $Destination ($catalog.root+'/GPOs/{'+$component.backup_id+'}/DomainSysvol/GPO')
        Assert-PolicyFiles $path $component.files
    }
    return (Join-Path $Destination ($catalog.root+'/GPOs'))
}
function Gpo-Record($LDAP,$GPO,$Component,[string]$Base) {
    $dn='CN={'+$GPO.Id.ToString()+'},CN=Policies,CN=System,'+$Base
    $result=Search-Directory $LDAP $dn '(objectClass=groupPolicyContainer)' @('versionNumber','gPCMachineExtensionNames','gPCUserExtensionNames') 'Base'
    Assert-S6 ($result.Entries.Count -eq 1)
    $entry=$result.Entries[0]
    foreach($scope in @('Machine','User')) {
        $name='gPC'+$scope+'ExtensionNames'
        $raw=if($entry.Attributes.Contains($name)){[string]$entry.Attributes[$name][0]}else{''}
        $actual=@([regex]::Matches($raw,'\[\{([a-f0-9-]{36})\}','IgnoreCase') | ForEach-Object {$_.Groups[1].Value.ToUpperInvariant()})
        $expected=@($Component.extensions.$scope | ForEach-Object {$_.ToUpperInvariant()})
        Assert-S6 ((@($actual | Sort-Object) -join ',') -ceq (@($expected | Sort-Object) -join ','))
    }
    return @{id=$GPO.Id.ToString();version=[uint32][string]$entry.Attributes['versionNumber'][0];
             Machine=@($Component.extensions.Machine);User=@($Component.extensions.User);files=$Component.files}
}
function Apply-Policy($R,$Credential,$Directory) {
    Check-Assets $R;Assert-RsopSamples $R;Import-Module GroupPolicy
    $script:PolicyChanged=$false
    $temporary=Join-Path 'C:\ProgramData\SambaADPilot' ([Guid]::NewGuid().ToString())
    New-Item -ItemType Directory $temporary | Out-Null
    $token=[IntPtr]::Zero;$context=$null;$ldap=$null
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class S6Logon {
 [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
 public static extern bool LogonUser(string u,string d,string p,int type,int provider,out IntPtr token);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr token);
}
'@
    try {
        $backups=Prepare-BaselineArchive $R (Join-Path $temporary 'source')
        $nc=$Credential.GetNetworkCredential()
        Assert-S6 ([S6Logon]::LogonUser($nc.UserName,$null,$nc.Password,9,3,[ref]$token))
        $identity=[Security.Principal.WindowsIdentity]::new($token);$context=$identity.Impersonate()
        $ldap=Open-Directory $R.dcs.dc01 $Credential
        $dc=$R.dcs.dc01.fqdn;$domain=$script:M.domain.dns_domain
        $base=($domain.Split('.') | ForEach-Object {'DC='+$_}) -join ','
        $script:Policies=@();$expectedNames=@()
        $names=@($script:BaselineCatalog.components.PSObject.Properties.Name | ForEach-Object {$R.windows.baseline.gpo_name+'-'+$_})
        $names+=($R.windows.baseline.gpo_name+'-loopback')
        $existing=@(Get-GPO -All -Domain $domain -Server $dc | Where-Object {$_.DisplayName -cin $names})
        Assert-S6 (@($existing | ForEach-Object {$_.DisplayName} | Select-Object -Unique).Count -eq $existing.Count)
        foreach($prior in $existing){
            Assert-S6 ($prior.Description -ceq $Directory.owner)
            Assert-GpoScope $ldap $prior.Id $R.ou $false
        }
        foreach($link in @((Get-GPInheritance -Target $R.ou -Domain $domain -Server $dc).GpoLinks)){
            Assert-S6 ($link.GpoId -in @($existing | ForEach-Object {$_.Id}) -and $link.Enabled -eq $true)
        }
        foreach($property in $script:BaselineCatalog.components.PSObject.Properties) {
            $component=$property.Value;$name=$R.windows.baseline.gpo_name+'-'+$property.Name;$expectedNames+=$name
            $found=@(Get-GPO -All -Domain $domain -Server $dc | Where-Object {$_.DisplayName -ceq $name})
            Assert-S6 ($found.Count -le 1);$new=$found.Count -eq 0
            if($new){
                Assert-S6 $R.apply
                $gpo=New-GPO -Name $name -Comment $Directory.owner -Domain $domain -Server $dc
                $script:PolicyChanged=$true
            }else{$gpo=$found[0];Assert-S6 ($gpo.Description -ceq $Directory.owner)}
            Assert-GpoScope $ldap $gpo.Id $R.ou $new
            $path='\\'+$dc+'\SYSVOL\'+$domain+'\Policies\{'+$gpo.Id.ToString().ToUpperInvariant()+'}'
            if($new){
                # Validated complete backup, exact source catalog and exceptions;
                # never run downloaded scripts or import an arbitrary backup.
                Assert-GpoScope $ldap $gpo.Id $R.ou $true
                Import-GPO -BackupId $component.backup_id -Path $backups -TargetGuid $gpo.Id -Domain $domain -Server $dc | Out-Null
                Assert-S6 ((Get-GPO -Guid $gpo.Id -Domain $domain -Server $dc).Description -ceq $Directory.owner)
                Assert-PolicyFiles $path $component.files
                Assert-GpoScope $ldap $gpo.Id $R.ou $true
                New-GPLink -Guid $gpo.Id -Target $R.ou -Domain $domain -Server $dc -LinkEnabled Yes -Enforced No | Out-Null
            }else{Assert-PolicyFiles $path $component.files}
            Assert-GpoScope $ldap $gpo.Id $R.ou $false
            $script:Policies+=Gpo-Record $ldap $gpo $component $base
        }
        # User baseline applies only on this computer OU, via explicit loopback.
        $name=$R.windows.baseline.gpo_name+'-loopback';$expectedNames+=$name
        $found=@(Get-GPO -All -Domain $domain -Server $dc | Where-Object {$_.DisplayName -ceq $name})
        Assert-S6 ($found.Count -le 1);$new=$found.Count -eq 0
        if($new){Assert-S6 $R.apply;$gpo=New-GPO -Name $name -Comment $Directory.owner -Domain $domain -Server $dc;$script:PolicyChanged=$true}
        else{$gpo=$found[0];Assert-S6 ($gpo.Description -ceq $Directory.owner)}
        Assert-GpoScope $ldap $gpo.Id $R.ou $new
        if($new){
            Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\Software\Policies\Microsoft\Windows\System' -ValueName UserPolicyMode -Type DWord -Value 1 -Domain $domain -Server $dc | Out-Null
            Assert-GpoScope $ldap $gpo.Id $R.ou $true
            New-GPLink -Guid $gpo.Id -Target $R.ou -Domain $domain -Server $dc -LinkEnabled Yes -Enforced No | Out-Null
        }
        $loop=Get-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\Software\Policies\Microsoft\Windows\System' -ValueName UserPolicyMode -Domain $domain -Server $dc
        Assert-S6 ($loop.Type -eq 'DWord' -and $loop.Value -eq 1)
        $loopPath='\\'+$dc+'\SYSVOL\'+$domain+'\Policies\{'+$gpo.Id.ToString().ToUpperInvariant()+'}'
        Assert-LoopbackPolicy $loopPath
        $component=[pscustomobject]@{extensions=[pscustomobject]@{Machine=@('35378EAC-683F-11D2-A89A-00C04FBBCFA2');User=@()};files=[pscustomobject]@{}}
        $script:Policies+=Gpo-Record $ldap $gpo $component $base
        $links=@((Get-GPInheritance -Target $R.ou -Domain $domain -Server $dc).GpoLinks)
        Assert-S6 ($links.Count -eq $expectedNames.Count)
        foreach($link in $links){Assert-S6 ($link.DisplayName -cin $expectedNames -and $link.Enabled -eq $true)}
    }finally{
        if($null -ne $ldap){$ldap.Dispose()}
        if($null -ne $context){$context.Undo();$context.Dispose()}
        if($token -ne [IntPtr]::Zero){[void][S6Logon]::CloseHandle($token)}
        Remove-Item $temporary -Recurse -Force
    }
}
function Assert-LoopbackPolicy([string]$Path) {
    foreach($file in @(Get-ChildItem $Path -File -Recurse)){
        $relative=$file.FullName.Substring($Path.Length+1)
        Assert-S6 ($relative -iin @('GPT.INI','Machine\Registry.pol'))
    }
    $rows=@(Read-Pol (Join-Path $Path 'Machine\Registry.pol'))
    Assert-S6 ($rows.Count -eq 1 -and $rows[0].type -eq 4 -and $rows[0].value -eq 1 -and
               $rows[0].key -ieq 'HKLM\Software\Policies\Microsoft\Windows\System' -and $rows[0].name -ceq 'UserPolicyMode')
}
function Verify-UserPolicy($R,$Credential,$DC,[string]$Work) {
    $ldap=Open-Directory $R.dcs.dc01 $Credential
    try{
        $base=($script:M.domain.dns_domain.Split('.') | ForEach-Object {'DC='+$_}) -join ','
        $result=Search-Directory $ldap $base ('(&(objectClass=user)(sAMAccountName='+$Credential.UserName.Split('@')[0]+'))') @('objectSid')
        Assert-S6 ($result.Entries.Count -eq 1)
        $sid=[Security.Principal.SecurityIdentifier]::new([byte[]]$result.Entries[0].Attributes['objectSid'][0],0)
        Assert-S6 ($sid.AccountDomainSid.Value -ceq $R.sid)
    }finally{$ldap.Dispose()}
    $directory=Join-Path $Work ('user-'+[Guid]::NewGuid().ToString());New-Item -ItemType Directory $directory | Out-Null
    & icacls.exe $directory /grant ('*'+$sid.Value+':(OI)(CI)M') | Out-Null;Assert-S6 ($LASTEXITCODE -eq 0)
    $inputFile=Join-Path $directory 'public.json';$scriptFile=Join-Path $directory 'worker.ps1'
    $rows=@($script:BaselineCatalog.components.PSObject.Properties.Value | ForEach-Object {$_.policies} | Where-Object {$_.scope -eq 'User'})
    @{sid=$sid.Value;dc=$DC.fqdn;policies=@(Scope-Policies $script:Policies 'User');rows=$rows;directory=$directory} |
        ConvertTo-Json -Depth 40 -Compress | Set-Content $inputFile -Encoding UTF8
    $source="param([string]`$InputFile)`n`$ErrorActionPreference='Stop';Set-StrictMode -Version Latest`n"
    foreach($name in @('Assert-S6','Rsop-Child','Rsop-ID','Rsop-Guid','Assert-RsopGPO','Assert-RsopApplied','Read-RsopXML','Assert-RegistryPolicy')){
        $source+='function '+$name+' {'+(Get-Command $name).Definition+"}`n"
    }
    $source+=@'
try {
 $inputData=Get-Content -LiteralPath $InputFile -Raw | ConvertFrom-Json
 Assert-S6 ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ceq $inputData.sid)
 $started=[DateTime]::UtcNow
 & gpupdate.exe /target:user /force /wait:120 | Out-Null;Assert-S6 ($LASTEXITCODE -eq 0)
 $finished=[DateTime]::UtcNow;$report=Join-Path $inputData.directory 'user.xml'
 & gpresult.exe /scope user /x $report /f | Out-Null;Assert-S6 ($LASTEXITCODE -eq 0)
 $namespace='root\RSOP\User\'+$inputData.sid.Replace('-','_')
 $gpos=@(Get-CimInstance -Namespace $namespace -ClassName RSOP_GPO)
 $extensions=@(Get-CimInstance -Namespace $namespace -ClassName RSOP_ExtensionStatus)
 Assert-RsopApplied (Read-RsopXML (Get-Content $report -Raw)) 'User' $inputData.policies $inputData.dc $started $finished $gpos $extensions
 Assert-RegistryPolicy $inputData.rows 'User'
 exit 0
} catch { [Console]::Error.WriteLine('S6 user policy validation failed (values suppressed)');exit 2 }
'@
    [IO.File]::WriteAllText($scriptFile,$source,[Text.Encoding]::UTF8)
    # The password is passed through PSCredential to the native logon API,
    # never in worker arguments, input JSON, script content or environment.
    $process=Start-Process -FilePath 'powershell.exe' -Credential $Credential -LoadUserProfile -PassThru -ArgumentList @(
        '-NoLogo','-NoProfile','-NonInteractive','-File',$scriptFile,'-InputFile',$inputFile)
    Assert-S6 ($process.WaitForExit(180000));$process.Refresh();Assert-S6 ($process.ExitCode -eq 0)
}
function Scope-Policies($Policies,[string]$Scope) {
    return @($Policies | Where-Object {@($_.$Scope).Count -gt 0} | ForEach-Object {
        @{id=$_.id;version=$_.version;extensions=@($_.$Scope)}
    })
}
function Verify-PolicyBothDCs($R,$Credential) {
    $digests=@();$work=Join-Path 'C:\ProgramData\SambaADPilot' ('acceptance-'+[Guid]::NewGuid().ToString())
    New-Item -ItemType Directory $work | Out-Null
    try {
        foreach($dc in @($R.dcs.dc01,$R.dcs.dc02)) {
            $hashes=@()
            foreach($policy in $script:Policies) {
                $root='\\'+$dc.fqdn+'\SYSVOL\'+$script:M.domain.dns_domain+'\Policies\{'+$policy.id.ToUpperInvariant()+'}'
                if(@($policy.files.PSObject.Properties).Count -gt 0){Assert-PolicyFiles $root $policy.files}else{Assert-LoopbackPolicy $root}
                foreach($file in @(Get-ChildItem $root -File -Recurse | Sort-Object FullName)){$hashes+=File-Hash $file.FullName}
            }
            $digests+=($hashes -join ',')
            & nltest.exe ("/sc_reset:"+$script:M.domain.dns_domain+'\'+$dc.fqdn) | Out-Null;Assert-S6 ($LASTEXITCODE -eq 0)
            $started=[DateTime]::UtcNow
            & gpupdate.exe /target:computer /force /wait:120 | Out-Null;Assert-S6 ($LASTEXITCODE -eq 0)
            $finished=[DateTime]::UtcNow;$report=Join-Path $work ('computer-'+$dc.fqdn+'.xml')
            & gpresult.exe /scope computer /x $report /f | Out-Null;Assert-S6 ($LASTEXITCODE -eq 0)
            $native=@(Get-CimInstance -Namespace 'root\RSOP\Computer' -ClassName RSOP_GPO)
            $extensions=@(Get-CimInstance -Namespace 'root\RSOP\Computer' -ClassName RSOP_ExtensionStatus)
            Assert-RsopApplied (Read-RsopXML (Get-Content $report -Raw)) 'Computer' (Scope-Policies $script:Policies 'Machine') $dc.fqdn $started $finished $native $extensions
            foreach($component in $script:BaselineCatalog.components.PSObject.Properties.Value){Assert-RegistryPolicy $component.policies 'Machine'}
            Assert-SecurityState $script:BaselineCatalog $work
            Verify-UserPolicy $R $Credential $dc $work
        }
        Assert-S6 ($digests.Count -eq 2 -and $digests[0] -ceq $digests[1])
    }finally{Remove-Item $work -Recurse -Force}
}
