"""Pure PowerShell boundaries; synthetic XML is never a qualified OS receipt."""
from pathlib import Path
import json
import shutil
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]


def powershell(body):
    if not shutil.which('pwsh'): pytest.skip('PowerShell parser unavailable')
    helper=ROOT/'tools/samba_ad/pilot_policy.ps1'
    assert helper.exists(), 'policy guard helper missing'
    result=subprocess.run(['pwsh','-NoLogo','-NoProfile','-NonInteractive','-Command',
        "$ErrorActionPreference='Stop';Set-StrictMode -Version Latest;"+
        "function Assert-S6($c){if(-not $c){throw 'rejected'}};. '"+str(helper)+"';"+body],
        capture_output=True,text=True,timeout=20)
    return result


@pytest.mark.parametrize('links,accepted', [
    ([{'dn':'OU=pilot,DC=ad,DC=test','options':0}],True),
    ([{'dn':'OU=pilot,DC=ad,DC=test','options':1}],False),
    ([{'dn':'OU=pilot,DC=ad,DC=test','options':0},{'dn':'OU=foreign,DC=ad,DC=test','options':0}],False),
    ([{'dn':'DC=ad,DC=test','options':0}],False),
    ([{'dn':'CN=site,CN=Sites,CN=Configuration,DC=ad,DC=test','options':0}],False),
    ([],False),
])
def test_inverse_gpo_link_scope(links,accepted):
    body="$links=ConvertFrom-Json '"+json.dumps(links)+"';Assert-GpoLinkSet @($links) 'OU=pilot,DC=ad,DC=test' $false"
    result=powershell(body)
    assert (result.returncode==0)==accepted,result.stdout+result.stderr


def test_denied_filtered_stale_wrong_scope_or_dc_rsop_is_rejected():
    body=r'''
$id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';$ext='35378eac-683f-11d2-a89a-00c04fbbcfa2'
$start=[DateTime]::UtcNow.AddSeconds(-5);$finish=[DateTime]::UtcNow
$p=@(@{id=$id;version=2;extensions=@($ext)})
$native=@(@{guidName=$id;version=2;enabled=$true;accessDenied=$false;filterAllowed=$true;extensionIds=@($ext)})
$extensions=@(@{extensionGuid=$ext;error=0;loggingStatus=1;beginTime=$start;endTime=$finish})
$good='<Rsop xmlns="http://www.microsoft.com/GroupPolicy/Rsop"><ComputerResults><DCName>dc01.ad.test</DCName><GPO><Identifier>'+ $id +'</Identifier><Enabled>true</Enabled><IsValid>true</IsValid><AccessDenied>false</AccessDenied><FilterAllowed>true</FilterAllowed></GPO></ComputerResults></Rsop>'
Assert-RsopApplied ([xml]$good) 'Computer' $p 'dc01.ad.test' $start $finish $native $extensions
$bad=@($good.Replace('<AccessDenied>false','<AccessDenied>true'),$good.Replace('<FilterAllowed>true','<FilterAllowed>false'),$good.Replace('<IsValid>true','<IsValid>false'),$good.Replace('ComputerResults','UserResults'),$good.Replace('dc01.ad.test','dc02.ad.test'),$good.Replace('/Rsop"','/Unknown"'))
foreach($xml in $bad){$caught=$false;try{Assert-RsopApplied ([xml]$xml) 'Computer' $p 'dc01.ad.test' $start $finish $native $extensions}catch{$caught=$true};Assert-S6 $caught}
$extensions[0].error=5;$caught=$false;try{Assert-RsopApplied ([xml]$good) 'Computer' $p 'dc01.ad.test' $start $finish $native $extensions}catch{$caught=$true};Assert-S6 $caught
$extensions[0].error=0;$extensions[0].beginTime=$start.AddDays(-1);$caught=$false;try{Assert-RsopApplied ([xml]$good) 'Computer' $p 'dc01.ad.test' $start $finish $native $extensions}catch{$caught=$true};Assert-S6 $caught
'''
    result=powershell(body)
    assert result.returncode==0,result.stdout+result.stderr


def test_real_inverse_ldap_guard_visits_domain_and_sites_and_precedes_write():
    result=powershell(r'''
$script:M=@{domain=@{dns_domain='ad.test'}};$id=[Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
$script:foreign=$false;$script:disabled=$false
function Search-Directory($LDAP,$Base,$Filter,$Attributes){
 $script:bases+=@($Base)
 $entry=[pscustomobject]@{DistinguishedName='OU=pilot,DC=ad,DC=test';Attributes=@{gPLink=@('[LDAP://CN={AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE},CN=Policies,CN=System,DC=ad,DC=test;0]')}}
 if($script:disabled){$entry.Attributes.gPLink=@($entry.Attributes.gPLink[0].Replace(';0]',';1]'))}
 if($Base.StartsWith('CN=Sites')){
  if($script:foreign){$entry.DistinguishedName='CN=other,CN=Sites,CN=Configuration,DC=ad,DC=test';return @{Entries=@($entry)}}
  return @{Entries=@()}
 }
 return @{Entries=@($entry)}
}
$script:bases=@();Assert-GpoScope $null $id 'OU=pilot,DC=ad,DC=test' $false
Assert-S6 ($script:bases.Count -eq 2 -and $script:bases -contains 'CN=Sites,CN=Configuration,DC=ad,DC=test')
foreach($case in @('foreign','disabled')){
 $script:foreign=$case -eq 'foreign';$script:disabled=$case -eq 'disabled';$written=$false;$caught=$false
 try{Assert-GpoScope $null $id 'OU=pilot,DC=ad,DC=test' $false;$written=$true}catch{$caught=$true}
 Assert-S6 ($caught -and -not $written)
}
''')
    assert result.returncode==0,result.stdout+result.stderr


def test_rsop_reader_rejects_dtd_without_external_lookup():
    result=powershell(r'''$caught=$false;try{$null=Read-RsopXML '<!DOCTYPE x SYSTEM "https://outside.invalid/test"><x/>'}catch{$caught=$true};Assert-S6 $caught''')
    assert result.returncode==0,result.stdout+result.stderr
