"""Pruebas del núcleo de protección y monitoreo del CFCC."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cfcc_lab.core import (
    database, list_cases, get_case, preview, classify, write_event,
    read_events, verify_log, suspicious_signal
)

BASE = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)


class CoreTests(unittest.TestCase):
    def test_01_sql_vulnerable_all_rows(self):
        with database() as db:
            self.assertEqual(len(list_cases(db, "' OR '1'='1", 'vulnerable', 'supervisor')), 4)

    def test_02_sql_secure_zero_rows(self):
        with database() as db:
            self.assertEqual(len(list_cases(db, "' OR '1'='1", 'secure', 'supervisor')), 0)

    def test_03_sql_legitimate_secure(self):
        with database() as db:
            self.assertEqual(len(list_cases(db, 'alta', 'secure', 'analista1')), 2)

    def test_04_sql_secure_min_privilege(self):
        with database() as db:
            self.assertEqual(list_cases(db, 'media', 'secure', 'analista1'), [])

    def test_05_xss_vulnerable_raw(self):
        self.assertIn('<img', preview('<img src=x onerror=alert(1)>', 'vulnerable'))

    def test_06_xss_secure_escaped(self):
        self.assertNotIn('<img', preview('<img src=x onerror=alert(1)>', 'secure'))

    def test_07_xss_secure_visible_as_text(self):
        self.assertIn('&lt;img', preview('<img src=x onerror=alert(1)>', 'secure'))

    def test_08_idor_vulnerable_foreign(self):
        with database() as db:
            self.assertEqual(get_case(db, 2, 'vulnerable', 'analista1')[1], 200)

    def test_09_idor_secure_hidden(self):
        with database() as db:
            self.assertEqual(get_case(db, 2, 'secure', 'analista1')[1], 404)

    def test_10_idor_secure_own(self):
        with database() as db:
            self.assertEqual(get_case(db, 1, 'secure', 'analista1')[1], 200)

    def test_11_idor_secure_missing(self):
        with database() as db:
            self.assertEqual(get_case(db, 99, 'secure', 'analista1')[1], 404)

    def test_12_monitoring_three_denials(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'e.jsonl'
            for i in range(3):
                write_event(p, 'authorization', 'analista1', 'denied', '/api/cases/:id', 404,
                            resource_id=2, at=BASE + timedelta(minutes=i))
            alerts = classify(read_events(p))
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]['count_in_window'], 3)
            self.assertNotIn('password', p.read_text())

    def test_13_enumeration_same_public_code(self):
        with database() as db:
            self.assertEqual(get_case(db, 2, 'secure', 'analista1')[1],
                             get_case(db, 99, 'secure', 'analista1')[1])
            self.assertEqual(get_case(db, 2, 'secure', 'analista1', explain=True)[2], 'not_owner')

    def test_14_list_scope_is_enforced_in_query(self):
        with database() as db:
            self.assertEqual(len(list_cases(db, 'media', 'vulnerable', 'analista1')), 1)
            self.assertEqual(len(list_cases(db, 'media', 'secure', 'analista1')), 0)

    def test_15_union_on_real_core_query(self):
        payload = "zzz' UNION SELECT 99,'x','x','x','x' -- "
        with database() as db:
            self.assertEqual(list_cases(db, payload, 'vulnerable', 'analista1')[0]['id'], 99)
            self.assertEqual(list_cases(db, payload, 'secure', 'analista1'), [])

    def test_16_suspicious_heuristics(self):
        self.assertEqual(suspicious_signal("' OR '1'='1", 'sql'), 'sql_pattern')
        self.assertEqual(suspicious_signal('<img src=x>', 'html'), 'html_markup')
        self.assertIsNone(suspicious_signal('alta', 'sql'))

    def test_17_exact_boundary_included(self):
        events = self.events([0, 5, 10])
        self.assertEqual(classify(events)[0]['count_in_window'], 3)

    def test_18_over_boundary_excluded(self):
        events = self.events([0, 5, 10 + 1/60])
        self.assertEqual(classify(events), [])

    def test_19_auth_failure_threshold(self):
        events = [{'timestamp_utc': (BASE+timedelta(minutes=i)).isoformat(),
                   'event': 'authentication', 'username': 'analista1',
                   'outcome': 'denied', 'endpoint': '/login', 'status': 401}
                  for i in range(5)]
        self.assertEqual(classify(events)[0]['rule'], 'R1_REPEAT_AUTH_FAIL')
        self.assertEqual(classify(events[:4]), [])

    def test_20_alert_dates_and_severity(self):
        events = self.events([0, 1, 2], user='supervisor')
        alert = classify(events)[0]
        self.assertEqual(alert['severity'], 'alta')
        self.assertEqual(alert['total_denials'], 3)
        self.assertIn('first_ts', alert)
        self.assertIn('last_ts', alert)

    def test_21_origin_mixed_accounts(self):
        events = self.events([0, 1, 2], user='analista1', origin='127.0.0.1')[:2]
        events += self.events([3], user='analista2', origin='127.0.0.1')
        alert = classify(events)[0]
        self.assertEqual(alert['rule'], 'R6_REPEAT_DENIAL_BY_ORIGIN')

    def test_22_log_chain_detects_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'e.jsonl'
            for _ in range(3):
                write_event(p, 'authorization', 'analista1', 'denied', '/api/cases/:id', 404)
            self.assertEqual(verify_log(p), (True, None))
            lines = p.read_text().splitlines()
            lines[1] = lines[1].replace('analista1', 'analista2')
            p.write_text('\n'.join(lines) + '\n')
            self.assertEqual(verify_log(p), (False, 2))

    @staticmethod
    def events(minutes, user='analista1', origin=None):
        return [{'timestamp_utc': (BASE + timedelta(minutes=m)).isoformat(),
                 'event': 'authorization', 'username': user, 'outcome': 'denied',
                 'endpoint': '/api/cases/:id', 'status': 404, 'origin_ip': origin}
                for m in minutes]


if __name__ == '__main__':
    unittest.main()
