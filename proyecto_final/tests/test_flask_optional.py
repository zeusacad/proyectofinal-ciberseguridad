"""Cinco verificaciones HTTP vía cliente de prueba cuando Flask está instalado."""
import tempfile
import unittest
from pathlib import Path
try:
    from app import make_app
    FLASK_AVAILABLE=True
except ImportError:
    FLASK_AVAILABLE=False

@unittest.skipUnless(FLASK_AVAILABLE,'Flask no instalado; instalar requirements.txt para pruebas HTTP')
class FlaskEndpointTests(unittest.TestCase):
    def setUp(self):
        # Bitácoras temporales: las pruebas no deben contaminar logs/ (evidencia de la regla R6)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.app_v=make_app('vulnerable',log_path=Path(self.tmp.name)/'v.jsonl')
        self.app_s=make_app('secure',log_path=Path(self.tmp.name)/'s.jsonl')
        self.v=self.app_v.test_client();self.s=self.app_s.test_client()
    def auth(self, client, username='analista1'):
        r=client.post('/login',data={'username':username,'password':'demo1234'})
        self.assertEqual(r.status_code,302)
    def test_health(self):
        self.assertEqual(self.s.get('/api/health').status_code,200)
    def test_authentication_required(self):
        self.assertEqual(self.s.get('/api/cases').status_code,401)
    def test_sql_before_after(self):
        self.auth(self.v,'supervisor'); self.auth(self.s,'supervisor')
        path='/api/cases?severity=%27%20OR%20%271%27%3D%271'
        self.assertEqual(self.v.get(path).get_json()['count'],4)
        self.assertEqual(self.s.get(path).get_json()['count'],0)
    def test_xss_before_after(self):
        self.auth(self.v);self.auth(self.s)
        path='/preview?message=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'
        self.assertIn(b'<img src=x onerror=alert(1)>',self.v.get(path).data)
        self.assertIn(b'&lt;img src=x onerror=alert(1)&gt;',self.s.get(path).data)
    def test_idor_before_after(self):
        self.auth(self.v);self.auth(self.s)
        self.assertEqual(self.v.get('/api/cases/2').status_code,200)
        self.assertEqual(self.s.get('/api/cases/2').status_code,403)
        self.assertEqual(self.s.get('/api/cases/1').status_code,200)
