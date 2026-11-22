# Pure guards and bounded LDAP reads. No top-level execution or credentials.
function Assert-GpoLinkSet($Links, [string]$OU, [bool]$AllowUnlinked) {
    if ($AllowUnlinked -and @($Links).Count -eq 0) { return }
    Assert-S6 (@($Links).Count -eq 1)
    foreach ($link in $Links) {
        Assert-S6 ($link.dn -ieq $OU -and [int]$link.options -eq 0)
    }
}
function Assert-GpoScope($LDAP, [Guid]$ID, [string]$OU, [bool]$AllowUnlinked) {
    $base=($script:M.domain.dns_domain.Split('.') | ForEach-Object {'DC='+$_}) -join ','
    $links=@()
    # Domain/subtree includes domain and every OU. Sites live in Configuration.
    foreach ($searchBase in @($base,('CN=Sites,CN=Configuration,'+$base))) {
        $result=Search-Directory $LDAP $searchBase '(gPLink=*)' @('gPLink')
        foreach ($entry in $result.Entries) {
            foreach ($value in $entry.Attributes['gPLink']) {
                $raw=[string]$value
                $matches=[regex]::Matches($raw,'\[LDAP://(?<dn>[^;\[\]]+);(?<options>[0-3])\]', 'IgnoreCase')
                Assert-S6 (($matches | ForEach-Object {$_.Value}) -join '' -ceq $raw)
                foreach ($match in $matches) {
                    $target=$match.Groups['dn'].Value
                    if ($target -imatch '^CN=\{([a-f0-9-]{36})\},CN=Policies,CN=System,') {
                        if ([Guid]$Matches[1] -eq $ID) {
                            Assert-S6 ($target -ieq ('CN={'+$ID.ToString()+'},CN=Policies,CN=System,'+$base))
                            $links+=@{dn=$entry.DistinguishedName;options=[int]$match.Groups['options'].Value}
                        }
                    } else { Assert-S6 $false }
                }
            }
        }
    }
    Assert-GpoLinkSet $links $OU $AllowUnlinked
}
function Rsop-Child($Node,[string]$Name) {
    $nodes=@($Node.SelectNodes("./*[local-name()='$Name' and namespace-uri()='http://www.microsoft.com/GroupPolicy/Rsop']"))
    Assert-S6 ($nodes.Count -eq 1)
    return $nodes[0]
}
function Rsop-ID($Node) {
    $ids=@($Node.SelectNodes("./*[local-name()='Identifier']"))
    Assert-S6 ($ids.Count -eq 1)
    $inner=@($ids[0].SelectNodes("./*[local-name()='Identifier']"))
    if ($inner.Count -eq 1) { return Rsop-Guid $inner[0].InnerText }
    Assert-S6 ($inner.Count -eq 0 -and $ids[0].ChildNodes.Count -eq 1)
    return Rsop-Guid $ids[0].InnerText
}
function Rsop-Guid([string]$Value) {
    # The native local-policy record is not an AD GPO. It must never satisfy
    # a required baseline GUID, but it may coexist with real domain entries.
    if ($Value -ceq 'LocalGPO') { return $null }
    return [Guid]$Value
}
function Assert-RsopGPO($GPO) {
    foreach ($name in @('Enabled','IsValid','FilterAllowed')) {
        Assert-S6 ((Rsop-Child $GPO $name).InnerText -ceq 'true')
    }
    Assert-S6 ((Rsop-Child $GPO 'AccessDenied').InnerText -ceq 'false')
    # An unexpected error representation cannot silently become acceptance.
    Assert-S6 (@($GPO.SelectNodes(".//*[contains(local-name(),'Error') or contains(local-name(),'Denied')][not(local-name()='AccessDenied')]" )).Count -eq 0)
}
function Assert-RsopApplied($XML,[string]$Scope,$Policies,[string]$DC,[DateTime]$Started,[DateTime]$Finished,$NativeGpos,$Extensions) {
    Assert-S6 ($Scope -in @('Computer','User'))
    Assert-S6 (@($Policies).Count -gt 0 -and @($Policies | ForEach-Object {$_.id} | Select-Object -Unique).Count -eq @($Policies).Count)
    Assert-S6 ($XML.DocumentElement.LocalName -ceq 'Rsop' -and $XML.DocumentElement.NamespaceURI -ceq 'http://www.microsoft.com/GroupPolicy/Rsop')
    $result=Rsop-Child $XML.DocumentElement ($Scope+'Results')
    Assert-S6 ((Rsop-Child $result 'DCName').InnerText.TrimStart('\') -ieq $DC)
    $gpos=@($result.SelectNodes("./*[local-name()='GPO' and namespace-uri()='http://www.microsoft.com/GroupPolicy/Rsop']"))
    foreach ($policy in $Policies) {
        $matched=@($gpos | Where-Object {(Rsop-ID $_) -eq [Guid]$policy.id})
        Assert-S6 ($matched.Count -eq 1); Assert-RsopGPO $matched[0]
        $native=@($NativeGpos | Where-Object {(Rsop-Guid $_.guidName) -eq [Guid]$policy.id})
        Assert-S6 ($native.Count -eq 1 -and $native[0].enabled -eq $true -and $native[0].accessDenied -eq $false -and
                   $native[0].filterAllowed -eq $true -and [uint32]$native[0].version -eq [uint32]$policy.version)
        Assert-S6 (@($policy.extensions).Count -gt 0)
        foreach ($id in $policy.extensions) {
            Assert-S6 (@($native[0].extensionIds | Where-Object {[Guid]$_ -eq [Guid]$id}).Count -eq 1)
            $extension=@($Extensions | Where-Object {[Guid]$_.extensionGuid -eq [Guid]$id})
            Assert-S6 ($extension.Count -eq 1 -and [int]$extension[0].error -eq 0 -and [int]$extension[0].loggingStatus -eq 1)
            $begin=([DateTime]$extension[0].beginTime).ToUniversalTime()
            $end=([DateTime]$extension[0].endTime).ToUniversalTime()
            Assert-S6 ($begin -ge $Started.ToUniversalTime().AddSeconds(-2) -and $end -ge $begin -and $end -le $Finished.ToUniversalTime().AddSeconds(2))
        }
    }
}
function Read-RsopXML([string]$Text) {
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Text),$settings)
    try{$document=[Xml.XmlDocument]::new();$document.XmlResolver=$null;$document.Load($reader);return $document}
    finally{$reader.Dispose()}
}
function Assert-RsopSamples($R) {
    # A real, separately reviewed corpus from the qualified OS image is required.
    # No public/synthetic positive sample is shipped as an operational receipt.
    foreach ($scope in @('Computer','User')) {
        $path='C:\SambaADAssets\rsop-'+$scope.ToLowerInvariant()+'.xml'
        Assert-S6 ((File-Hash $path) -ceq $R.windows.rsop.samples.$scope)
        $sample=Read-RsopXML (Get-Content -LiteralPath $path -Raw)
        Assert-S6 ($sample.DocumentElement.LocalName -ceq 'Rsop' -and $sample.DocumentElement.NamespaceURI -ceq 'http://www.microsoft.com/GroupPolicy/Rsop')
        $result=Rsop-Child $sample.DocumentElement ($scope+'Results')
        Assert-S6 ((Rsop-Child $result 'DCName').InnerText.Length -gt 0)
        $gpos=@($result.SelectNodes("./*[local-name()='GPO' and namespace-uri()='http://www.microsoft.com/GroupPolicy/Rsop']"))
        Assert-S6 ($gpos.Count -gt 0)
        foreach($gpo in $gpos) { $null=Rsop-ID $gpo }
        $positive=@($gpos | Where-Object {try{Assert-RsopGPO $_;$true}catch{$false}})
        Assert-S6 ($positive.Count -gt 0)
    }
}
