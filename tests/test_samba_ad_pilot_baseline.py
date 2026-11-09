"""Complete source-artifact coverage and strict parsers, not OS acceptance."""
from pathlib import Path
import hashlib
import json
import struct
import pytest
from tools.samba_ad import pilot_baseline as baseline
from tools.samba_ad.pilot_baseline_catalog import CATALOG
from test_samba_ad_pilots import pilot_request, mod
from test_samba_ad_pilot_policy import powershell, ROOT


def test_single_logging_setting_or_missing_component_cannot_replace_full_baseline():
    r,m=pilot_request(True)
    r['windows']['baseline']['settings']=[{'key':'HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging',
                                         'name':'EnableScriptBlockLogging','value':1}]
    with pytest.raises(ValueError): mod().validate(r,m)
    assert set(CATALOG['components'])==set(baseline.COMPONENTS)
    assert sum(len(c['policies']) for c in CATALOG['components'].values())==274
    assert sum(len(c['audit']) for c in CATALOG['components'].values())==24
    assert CATALOG['components']['domain-security']['security']['System Access']['PasswordHistorySize']=='30'
    assert CATALOG['components']['domain-security']['security']['System Access']['LockoutBadCount']=='10'
    # Runtime input cannot omit, replace or add exclusions to this source catalog.
    for field in ['components','exclusions','files']:
        r,m=pilot_request(True);r['windows']['baseline'][field]={}
        with pytest.raises(ValueError):mod().validate(r,m)


def pol_entry(key='Software\\Policies\\test', name='value',kind=4,data=struct.pack('<I',1)):
    text=lambda s:(s+'\0').encode('utf-16le')
    return b'[\0'+text(key)+b';\0'+text(name)+b';\0'+struct.pack('<I',kind)+b';\0'+struct.pack('<I',len(data))+b';\0'+data+b']\0'


def test_registry_pol_covers_all_entries_and_rejects_unknown_or_duplicate():
    header=b'PReg\x01\0\0\0';row=pol_entry()
    assert baseline.pol(header+row)==[{'key':'Software\\Policies\\test','name':'value','type':4,'data':'01000000'}]
    for data in [header+row+row,header+pol_entry(kind=7),header+row[:-2],header+row+b'extra']:
        with pytest.raises(ValueError):baseline.pol(data)


def test_security_inf_refuses_unsupported_sections_or_duplicate_settings():
    fixture='[Unicode]\nUnicode=yes\n[Version]\nsignature="$CHICAGO$"\nRevision=1\n[System Access]\nMinimumPasswordLength = 14\n'
    assert baseline.inf(fixture.encode('utf-16'))['System Access']['MinimumPasswordLength']=='14'
    for extra in ['MinimumPasswordLength = 0\n','[Registry Keys]\nunsafe=1\n','[System Access]\n']:
        with pytest.raises(ValueError):baseline.inf((fixture+extra).encode('utf-16'))


def test_public_reference_archive_rebuilds_exact_catalog_and_native_transform(tmp_path):
    archive=Path('/tmp/s6-server2025-baseline.zip')
    if not archive.exists():pytest.skip('Public pinned Microsoft archive not staged on this test host')
    assert baseline.catalog(archive.read_bytes())==CATALOG
    catalog=tmp_path/'catalog.json';catalog.write_text(json.dumps(CATALOG))
    destination=tmp_path/'extracted'
    body=". '"+str(ROOT/'tools/samba_ad/pilot_baseline_windows.ps1')+"';"+r'''
function File-Hash($p){return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
'''+"$script:BaselineCatalog=Get-Content '"+str(catalog)+"' -Raw | ConvertFrom-Json;"+\
        "$r=@{windows=@{baseline=@{archive='"+str(archive)+"'}}};"+\
        "$null=Prepare-BaselineArchive $r '"+str(destination)+"'"
    result=powershell(body)
    assert result.returncode==0,result.stdout+result.stderr


def test_windows_source_helpers_parse_without_execution():
    body=r'''
$tokens=$null;$errors=$null
'''
    for filename in ['pilot_policy.ps1','pilot_baseline_windows.ps1','pilot_windows.ps1']:
        body+="[void][System.Management.Automation.Language.Parser]::ParseFile('"+str(ROOT/'tools/samba_ad'/filename)+"',[ref]$tokens,[ref]$errors);Assert-S6 ($errors.Count -eq 0);"
    result=powershell(body)
    assert result.returncode==0,result.stdout+result.stderr
