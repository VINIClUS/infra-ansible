"""Behavioral tests; synthetic inputs are never runtime acceptance receipts."""
import json
from pathlib import Path
import tempfile
import unittest

from tools.samba_ad import telemetry


class Signals(unittest.TestCase):
    def test_sysvol_requires_identity_freshness_and_complete_producer(self):
        good = dict(state="ok", failures=0, last_success=1000, last_attempt=1000,
                    sid="S-1-5-21-1-2-3", baseline={"example.test": {}},
                    retention=dict(count=1, limit=8, saturated=False))
        self.assertEqual(telemetry.sysvol(good, 1100, good["sid"])["healthy"], 1)
        for change in [dict(last_success=1), dict(last_success=1200), dict(failures=1),
                       dict(sid="other"), dict(state="failed_or_conflict")]:
            self.assertEqual(telemetry.sysvol(good | change, 1100, good["sid"])["healthy"], 0)
        for field in good:
            broken = good.copy(); del broken[field]
            with self.assertRaises(ValueError):
                telemetry.sysvol(broken, 1100, good["sid"])

    def test_pki_missing_expiry_or_stale_never_returns_success(self):
        lines = '\n'.join(f'samba_ad_pki_{key}{{profile="telemetry_dc01"}} {value}' for key, value in {
            'last_check_seconds': 1000, 'last_attempt_success': 1,
            'certificate_not_after_seconds': 100000, 'rotation_deadline_seconds': 2000}.items())
        self.assertEqual(telemetry.pki(lines, "telemetry_dc01", 1100)["healthy"], 1)
        self.assertEqual(telemetry.pki(lines, "telemetry_dc01", 4000)["healthy"], 0)
        with self.assertRaises(ValueError):
            telemetry.pki(lines.replace('certificate_not_after_seconds', 'unknown'), "telemetry_dc01", 1100)
        with self.assertRaises(ValueError):
            telemetry.pki(lines.replace('100000', 'NaN'), "telemetry_dc01", 1100)

    def test_failed_collection_emits_up_zero_and_no_fabricated_values(self):
        def fail():
            raise PermissionError("SECRET")
        result = telemetry.measure("pki", fail, 1000)
        self.assertIn('samba_ad_source_up{source="pki"} 0', result)
        self.assertNotIn("SECRET", result)
        self.assertNotIn("healthy", result)

    def test_drs_missing_partition_or_failure_never_healthy(self):
        row = {'NC dn': 'DC=example,DC=test', 'NTDS DN': 'CN=peer', 'is deleted': False,
               'consecutive failures': 0, 'last attempt message': 'WERR_OK',
               'last success': 'Thu Jan  1 00:16:40 1970 UTC'}
        expected = [{'nc': row['NC dn'], 'peer': row['NTDS DN']}]
        self.assertEqual(telemetry.drs({'repsFrom': [row]}, expected, 1100)['healthy'], 1)
        self.assertEqual(telemetry.drs({'repsFrom': []}, expected, 1100)['healthy'], 0)
        self.assertEqual(telemetry.drs({'repsFrom': [row | {'consecutive failures': 1}]}, expected, 1100)['healthy'], 0)


class Gateway(unittest.TestCase):
    def test_exact_san_authorization_and_no_subject_fallback(self):
        from tools.samba_ad.telemetry_gateway import authorize
        allowed = ['dc01.example.test']
        self.assertTrue(authorize({'subjectAltName': [('DNS', allowed[0])]}, allowed))
        for cert in [{}, {'subjectAltName': [('DNS', '*.example.test')]},
                     {'subjectAltName': [('DNS', 'dc01.example.test.evil')]},
                     {'subjectAltName': [('DNS', allowed[0]), ('DNS', 'other.example.test')]}]:
            self.assertFalse(authorize(cert, allowed))

    def test_fixed_routes_and_host_scoped_tenant(self):
        from tools.samba_ad.telemetry_gateway import route
        self.assertEqual(route('/loki/api/v1/push'), ('loki', '/loki/api/v1/push'))
        self.assertEqual(route('/api/v1/write'), ('prometheus', '/api/v1/write'))
        for path in ['/metrics', '//evil', '/loki/api/v1/push?x=1', '/api/v1/admin/tsdb/delete_series']:
            with self.assertRaises(ValueError): route(path)


if __name__ == '__main__':
    unittest.main()
