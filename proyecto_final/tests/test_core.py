import json
import tempfile
import unittest
from pathlib import Path
from cfcc_lab.core import database, list_cases, get_case, preview, classify,write_event,read_events
class CoreTests(unittest.TestCase):
    def test_01_sql_vulnerable_all_rows(self):
        with database() as db:self.assertEqual(len(list_cases(db,"' OR '1'='1",'vulnerable','supervisor')),4)
    def test_02_sql_secure_zero_rows(self):
        with database() as db:self.assertEqual(len(list_cases(db,"' OR '1'='1",'secure','supervisor')),0)
    def test_03_sql_legitimate_secure(self):
        with database() as db:self.assertEqual(len(list_cases(db,'alta','secure','analista1')),2)
    def test_04_sql_secure_min_privilege(self):
        with database() as db:self.assertEqual(len(list_cases(db,'media','secure','analista1')),0)
    def test_05_xss_vulnerable_raw(self):
        self.assertIn('<img',preview('<img src=x onerror=alert(1)>','vulnerable'))
    def test_06_xss_secure_escaped(self):
        self.assertNotIn('<img',preview('<img src=x onerror=alert(1)>','secure'))
    def test_07_xss_secure_visible_as_text(self):
        self.assertIn('&lt;img',preview('<img src=x onerror=alert(1)>','secure'))
    def test_08_idor_vulnerable_foreign(self):
        with database() as db:self.assertEqual(get_case(db,2,'vulnerable','analista1')[1],200)
    def test_09_idor_secure_denied(self):
        with database() as db:self.assertEqual(get_case(db,2,'secure','analista1')[1],403)
    def test_10_idor_secure_own(self):
        with database() as db:self.assertEqual(get_case(db,1,'secure','analista1')[1],200)
    def test_11_idor_secure_missing(self):
        with database() as db:self.assertEqual(get_case(db,99,'secure','analista1')[1],404)
    def test_12_monitoring_three_denials(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'events.jsonl'
            for _ in range(3):write_event(f,'authorization','analista1','denied','/api/cases/:id',403)
            events=read_events(f)
            self.assertEqual(len(classify(events)),1)
            self.assertNotIn('password',f.read_text())
if __name__=='__main__':unittest.main()
