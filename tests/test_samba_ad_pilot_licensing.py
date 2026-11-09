"""License observations are synthetic here, never native pilot receipts."""
import json

import pytest

from test_samba_ad_pilot_policy import ROOT, powershell
from test_samba_ad_pilots import pilot_request
from tools.samba_ad import pilots
from tools.samba_ad.compatibility import sha


@pytest.mark.parametrize("edition", ["ServerStandard", "ServerDatacenter", "ServerStandardEval", "ServerDatacenterEval"])
def test_server_2025_edition_is_bound_to_observed_image(edition):
    request, manifest = pilot_request(True)
    request["windows"]["edition"] = edition
    bundle = request["substrate"]["compatibility"]
    bundle["data"]["report"]["template_observation"]["edition"] = edition
    bundle["sha256"] = sha(bundle["data"])
    assert pilots.validate(request, manifest)["state"] == "validated"
    request["windows"]["edition"] = "ServerDatacenter" if edition != "ServerDatacenter" else "ServerStandard"
    with pytest.raises(ValueError):
        pilots.validate(request, manifest)


@pytest.mark.parametrize("edition,rows", [
    ("ServerStandard", []),
    ("ServerStandard", [{"ID": "synthetic-product", "LicenseStatus": 0, "GracePeriodRemaining": 0}]),
    ("ServerStandardEval", [{"ID": "synthetic-product", "LicenseStatus": 2, "GracePeriodRemaining": 1000}]),
    ("ServerDatacenterEval", [{"ID": "synthetic-product", "LicenseStatus": 5, "GracePeriodRemaining": 0}]),
    ("ServerDatacenter", [{"ID": "synthetic-product", "LicenseStatus": 1, "GracePeriodRemaining": 0}]),
    ("ServerStandard", [{"ID": "synthetic-product", "LicenseStatus": None, "GracePeriodRemaining": None}]),
])
def test_unactivated_evaluation_and_absent_license_rows_remain_factual(edition, rows):
    path = ROOT / "tools/samba_ad/pilot_windows.ps1"
    result = powershell(r'''
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('PATH',[ref]$tokens,[ref]$errors)
Assert-S6 ($errors.Count -eq 0)
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Read-LicenseObservation'},$true)
Invoke-Expression $function.Extent.Text
$script:rows=ConvertFrom-Json 'ROWS'
function Get-CimInstance($ClassName,$Filter,$Property) {
 Assert-S6 ($ClassName -eq 'SoftwareLicensingProduct' -and $Filter -match 'LicenseIsAddon=False')
 Assert-S6 (($Property -join ',') -ceq 'ID,LicenseStatus,GracePeriodRemaining')
 return $script:rows
}
Read-LicenseObservation 'EDITION' | ConvertTo-Json -Depth 10 -Compress
'''.replace("PATH", str(path)).replace("ROWS", json.dumps(rows)).replace("EDITION", edition))
    assert result.returncode == 0, result.stdout + result.stderr
    observation = json.loads(result.stdout)
    assert observation["edition"] == edition
    assert observation["evaluation"] == edition.endswith("Eval")
    assert observation["entitlement"] == "not_attested"
    assert observation["products"] == [
        {"id": row["ID"], "license_status": row["LicenseStatus"], "grace_period_minutes": row["GracePeriodRemaining"]}
        for row in rows
    ]
