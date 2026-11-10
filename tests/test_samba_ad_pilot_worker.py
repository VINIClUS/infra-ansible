"""Actual worker orchestration with mocked Win32 boundaries, no Windows logon."""
from test_samba_ad_pilot_policy import powershell, ROOT
import pytest


def run(body):
    return powershell(". '"+str(ROOT/'tools/samba_ad/pilot_user_worker.ps1')+"';"+body)


@pytest.mark.parametrize("failure",["none","logon","profile","environment","job","create","assign","resume","wait","timeout","exit","nonzero"])
def test_system_worker_bounds_wait_and_releases_resources(failure):
    result=run(r'''
$script:calls=[Collections.Generic.List[string]]::new();$script:fail='FAIL'
function Get-WorkerIdentity {return 'S-1-5-18'}
function Initialize-UserNative {}
function Invoke-UserNative($Operation,$State) {
 $script:calls.Add($Operation)
 if($Operation -eq $script:fail){throw 'native failure'}
 switch($Operation){
 'privileges' {return [IntPtr]10}
 'logon' {return [IntPtr]11}
 'profile' {return [IntPtr]12}
 'environment' {return [IntPtr]13}
 'job' {return [IntPtr]14}
 'create' {return @{Process=[IntPtr]15;Thread=[IntPtr]16}}
 'wait' {Assert-S6 ($State.timeout -eq 180000);return ($script:fail -ne 'timeout')}
 'exit' {if($script:fail -eq 'nonzero'){return 2};return 0}
 }
}
$c=[PSCredential]::new('user@ad.test',(ConvertTo-SecureString 'SENTINEL' -AsPlainText -Force))
$caught=$false
try {Invoke-UserWorker $c 'C:\owned\worker.ps1' 'C:\owned\public.json'}catch{$caught=$true}
Assert-S6 ($caught -eq ($script:fail -ne 'none'))
Assert-S6 ($script:calls[0] -eq 'privileges' -and $script:calls[1] -eq 'logon')
if($script:fail -ne 'logon'){Assert-S6 ($script:calls -contains 'close-token')}
if($script:fail -notin @('logon','profile')){Assert-S6 ($script:calls -contains 'unload-profile')}
if($script:fail -notin @('logon','profile','environment')){Assert-S6 ($script:calls -contains 'destroy-environment')}
if($script:fail -notin @('logon','profile','environment','job')){Assert-S6 ($script:calls -contains 'close-job')}
if($script:fail -in @('none','assign','resume','wait','timeout','exit','nonzero')){
 Assert-S6 ($script:calls -contains 'close-process' -and $script:calls -contains 'close-thread')
}
if($script:fail -in @('assign','resume','wait','timeout')){Assert-S6 ($script:calls -contains 'terminate')}
if($script:fail -eq 'none'){Assert-S6 ($script:calls.IndexOf('assign') -lt $script:calls.IndexOf('resume'))}
'''.replace('FAIL',failure))
    assert result.returncode==0,result.stdout+result.stderr


def test_non_system_context_is_rejected_before_logon():
    result=run(r'''
function Get-WorkerIdentity {return 'S-1-5-21-1-2-3-1000'}
$script:initialized=$false
function Initialize-UserNative {$script:initialized=$true;throw 'must not initialize'}
$caught=$false
try {Invoke-UserWorker $null 'C:\owned\worker.ps1' 'C:\owned\public.json'}catch{$caught=$true}
Assert-S6 ($caught -and -not $script:initialized)
''')
    assert result.returncode==0,result.stdout+result.stderr


def test_native_worker_interop_compiles_without_executing_logon():
    result=run("Initialize-UserNative;Assert-S6 ($null -ne ('S6WorkerNative' -as [type]))")
    assert result.returncode==0,result.stdout+result.stderr


@pytest.mark.parametrize('operation',['terminate','close-thread','close-process','close-job','destroy-environment','unload-profile','close-token'])
def test_cleanup_failure_does_not_skip_remaining_resources(operation):
    result=run(r'''
$script:calls=[Collections.Generic.List[string]]::new()
function Get-WorkerIdentity {return 'S-1-5-18'}
function Initialize-UserNative {}
function Invoke-UserNative($Operation,$State) {
 $script:calls.Add($Operation)
 if($Operation -eq 'FAIL'){throw 'cleanup failed'}
 switch($Operation){
  'privileges' {return [IntPtr]10}
  'logon' {return [IntPtr]11}
  'profile' {return [IntPtr]12}
  'environment' {return [IntPtr]13}
  'job' {return [IntPtr]14}
  'create' {return @{Process=[IntPtr]15;Thread=[IntPtr]16}}
  'wait' {return $false}
 }
}
$c=[PSCredential]::new('user@ad.test',(ConvertTo-SecureString 'SENTINEL' -AsPlainText -Force))
$caught=$false;try{Invoke-UserWorker $c 'C:\owned\worker.ps1' 'C:\owned\public.json'}catch{$caught=$true}
Assert-S6 $caught
foreach($op in @('terminate','close-thread','close-process','close-job','destroy-environment','unload-profile','close-token','restore-privileges')){Assert-S6 ($script:calls -contains $op)}
'''.replace('FAIL',operation))
    assert result.returncode==0,result.stdout+result.stderr
