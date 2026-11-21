"""Native PowerShell cryptography on synthetic certificates; not a Windows receipt."""
import datetime as dt
import json
from pathlib import Path
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SOURCE = Path(__file__).resolve().parents[1] / 'tools/samba_ad/telemetry_windows_pki.ps1'


@pytest.mark.skipif(not shutil.which('pwsh'), reason='Native PowerShell required')
def test_windows_native_leaf_validation_and_fresh_rotation_key(tmp_path):
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(minutes=1)
    key = lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072)
    root_key, issuer_key, leaf_key = key(), key(), key()
    name = lambda value: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])
    root_name, issuer_name = name('S7 synthetic root'), name('S7 synthetic issuer')
    def base(subject, issuer, public, hours):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public)
                .serial_number(x509.random_serial_number()).not_valid_before(now)
                .not_valid_after(now + dt.timedelta(hours=hours)))
    root = (base(root_name, root_name, root_key.public_key(), 1000)
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
            .sign(root_key, hashes.SHA256()))
    issuer = (base(issuer_name, root_name, issuer_key.public_key(), 900)
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
              .sign(root_key, hashes.SHA256()))
    certs = {'root': root, 'issuer': issuer}
    for case, san, eku, hours, public in [
        ('good', 'pilot.example.test', ExtendedKeyUsageOID.CLIENT_AUTH, 168, leaf_key.public_key()),
        ('san', 'foreign.example.test', ExtendedKeyUsageOID.CLIENT_AUTH, 168, leaf_key.public_key()),
        ('eku', 'pilot.example.test', ExtendedKeyUsageOID.SERVER_AUTH, 168, leaf_key.public_key()),
        ('ttl', 'pilot.example.test', ExtendedKeyUsageOID.CLIENT_AUTH, 169, leaf_key.public_key()),
        ('key', 'pilot.example.test', ExtendedKeyUsageOID.CLIENT_AUTH, 168, key().public_key()),
    ]:
        certs[case] = (base(name(san), issuer_name, public, hours)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), False)
            .add_extension(x509.ExtendedKeyUsage([eku]), False).sign(issuer_key, hashes.SHA256()))
    for filename, cert in certs.items():
        (tmp_path / (filename + '.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / 'key.pem').write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tmp_path / 'config.json').write_text(json.dumps({'fqdn': 'pilot.example.test',
        'issuer_sha256': issuer.fingerprint(hashes.SHA256()).hex()}))
    harness = tmp_path / 'native.ps1'
    harness.write_text(r'''
param($Source, $Fixture)
$ErrorActionPreference = 'Stop'
$errors = $null; $tokens = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Source, [ref]$tokens, [ref]$errors)
if ($errors) { throw 'Source parse failed' }
$sourceText = [IO.File]::ReadAllText($Source)
$interop = [regex]::Match($sourceText, "(?s)Add-Type -TypeDefinition @'.*?'@")
if (-not $interop.Success) { throw 'TLS interop missing' }
Invoke-Expression $interop.Value
foreach ($function in $ast.FindAll({param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst]}, $false)) {
    if ($function.Name -in @('Require','Hex','Digest','Verify-Leaf')) { Invoke-Expression $function.Extent.Text }
}
$script:rootCert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText("$Fixture/root.pem"))
$script:issuerCert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText("$Fixture/issuer.pem"))
$handler = [S7Tls]::Handler("$Fixture/root.pem", "$Fixture/issuer.pem", 'localhost')
$handler.Dispose()
$config = Get-Content -Raw "$Fixture/config.json" | ConvertFrom-Json -AsHashtable
$key = [Security.Cryptography.RSA]::Create()
try {
    $key.ImportFromPem([IO.File]::ReadAllText("$Fixture/key.pem"))
    $good = Verify-Leaf $config "$Fixture/good.pem" $key
    Require ($good.expires -gt $good.rotate_by)
    foreach ($case in @('san','eku','ttl','key','reused')) {
        $rejected = $false
        try {
            if ($case -eq 'reused') { Verify-Leaf $config "$Fixture/good.pem" $key $good.spki | Out-Null }
            else { Verify-Leaf $config "$Fixture/$case.pem" $key | Out-Null }
        } catch { $rejected = $true }
        Require $rejected
    }
    Write-Output 'native Windows verifier: valid leaf accepted; SAN/EKU/TTL/key/reused-key rejected'
} finally { $key.Dispose(); $rootCert.Dispose(); $issuerCert.Dispose() }
''')
    result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-File', str(harness),
                             str(SOURCE), str(tmp_path)], capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'reused-key rejected' in result.stdout
