"""Pruebas HTTP reales contra el cliente local de Flask (sin tráfico externo)."""
import tempfile
import unittest
from pathlib import Path

try:
    from app import make_app
    from cfcc_lab.core import classify, read_events, verify_log
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


@unittest.skipUnless(FLASK_AVAILABLE, 'Flask no instalado; instalar requirements.txt para pruebas HTTP')
class FlaskEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.vlog = Path(self.tmp.name) / 'v.jsonl'
        self.slog = Path(self.tmp.name) / 's.jsonl'
        self.v = make_app('vulnerable', log_path=self.vlog).test_client()
        self.s = make_app('secure', log_path=self.slog).test_client()

    def auth(self, client, username='analista1'):
        response = client.post('/login', data={'username': username, 'password': 'demo1234'})
        self.assertEqual(response.status_code, 302)

    def test_health(self):
        self.assertEqual(self.s.get('/api/health').get_json()['mode'], 'secure')

    def test_authentication_required(self):
        self.assertEqual(self.s.get('/api/cases').status_code, 401)

    def test_sql_before_after(self):
        self.auth(self.v, 'supervisor')
        self.auth(self.s, 'supervisor')
        path = '/api/cases?severity=%27%20OR%20%271%27%3D%271'
        self.assertEqual(self.v.get(path).get_json()['count'], 4)
        self.assertEqual(self.s.get(path).get_json()['count'], 0)

    def test_xss_before_after(self):
        self.auth(self.v)
        self.auth(self.s)
        path = '/preview?message=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'
        self.assertIn(b'<img src=x onerror=alert(1)>', self.v.get(path).data)
        self.assertIn(b'&lt;img src=x onerror=alert(1)&gt;', self.s.get(path).data)

    def test_idor_before_after(self):
        self.auth(self.v)
        self.auth(self.s)
        self.assertEqual(self.v.get('/api/cases/2').status_code, 200)
        self.assertEqual(self.s.get('/api/cases/2').status_code, 404)
        self.assertEqual(self.s.get('/api/cases/1').status_code, 200)

    def test_idor_404_body_identical(self):
        self.auth(self.s)
        wrong = self.s.get('/api/cases/2')
        absent = self.s.get('/api/cases/99')
        self.assertEqual(wrong.status_code, absent.status_code)
        self.assertEqual(wrong.get_json(), absent.get_json())
        logs = read_events(self.slog)
        self.assertEqual(logs[-2]['reason'], 'not_owner')
        self.assertEqual(logs[-1]['reason'], 'not_found')

    def test_long_severity_returns_400(self):
        self.auth(self.s)
        self.assertEqual(self.s.get('/api/cases?severity=' + 'a' * 100).status_code, 400)
        self.assertEqual(read_events(self.slog)[-1]['reason'], 'severity_too_long')

    def test_sql_and_xss_flag_without_raw_data(self):
        self.auth(self.s)
        self.s.get('/api/cases?severity=%27%20OR%20%271%27%3D%271')
        self.s.get('/preview?message=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E')
        logs = read_events(self.slog)
        signals = [e.get('signal') for e in logs]
        self.assertIn('sql_pattern', signals)
        self.assertIn('html_markup', signals)
        self.assertNotIn('onerror=alert', self.slog.read_text())

    def test_unknown_username_is_pseudonymized(self):
        self.s.post('/login', data={'username': 'MiClave123', 'password': 'invalida'})
        self.assertNotIn('MiClave123', self.slog.read_text())
        self.assertTrue(read_events(self.slog)[0]['username'].startswith('desconocido-'))

    def test_r6_end_to_end_via_http(self):
        self.auth(self.s)
        for _ in range(3):
            self.assertEqual(self.s.get('/api/cases/2').status_code, 404)
        alerts = classify(read_events(self.slog))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['count_in_window'], 3)
        self.assertEqual(verify_log(self.slog), (True, None))

    def test_r1_end_to_end_via_http(self):
        for _ in range(5):
            self.s.post('/login', data={'username': 'analista1', 'password': 'incorrecta'})
        self.assertEqual(classify(read_events(self.slog))[0]['rule'], 'R1_REPEAT_AUTH_FAIL')

    def test_events_supervisor_has_alert(self):
        for _ in range(5):
            self.s.post('/login', data={'username': 'analista1', 'password': 'incorrecta'})
        self.auth(self.s, 'supervisor')
        r = self.s.get('/events')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'R1_REPEAT_AUTH_FAIL', r.data)

    def test_shared_secure_headers(self):
        self.assertEqual(self.v.get('/api/health').headers['X-Frame-Options'], 'DENY')
        self.assertEqual(self.s.get('/api/health').headers['X-Frame-Options'], 'DENY')
        self.assertNotIn('Content-Security-Policy', self.v.get('/api/health').headers)
        self.assertIn('Content-Security-Policy', self.s.get('/api/health').headers)
