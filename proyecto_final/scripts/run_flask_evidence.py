"""Comparación automática de endpoints Flask mediante cliente de prueba local.

Se ejecuta después de instalar requirements.txt. No envía tráfico a Internet
ni inicia servidores públicos; la aplicación utiliza datos ficticios.
"""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import make_app


def login(client, username):
    response = client.post('/login', data={'username': username, 'password': 'demo1234'})
    assert response.status_code == 302, f'falló login {username}: {response.status_code}'


def main():
    with tempfile.TemporaryDirectory() as tmp:
        v = make_app('vulnerable', log_path=Path(tmp)/'v.jsonl').test_client()
        s = make_app('secure', log_path=Path(tmp)/'s.jsonl').test_client()
        login(v, 'supervisor')
        login(s, 'supervisor')
        path = '/api/cases?severity=%27%20OR%20%271%27%3D%271'
        vl = v.get(path)
        sl = s.get(path)
        assert vl.status_code == sl.status_code == 200
        assert vl.get_json()['count'] == 4
        assert sl.get_json()['count'] == 0

        xs = '/preview?message=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'
        vx = v.get(xs)
        sx = s.get(xs)
        assert b'<img src=x onerror=alert(1)>' in vx.data
        assert b'&lt;img src=x onerror=alert(1)&gt;' in sx.data

        v.get('/logout')
        s.get('/logout')
        login(v, 'analista1')
        login(s, 'analista1')
        vid = v.get('/api/cases/2')
        sid = s.get('/api/cases/2')
        own = s.get('/api/cases/1')
        assert (vid.status_code, sid.status_code, own.status_code) == (200,403,200)

        result = {
            'entorno': 'cliente de pruebas Flask sin tráfico externo',
            'resultado': 'correcto',
            'sql_injection': {'vulnerable_count':vl.get_json()['count'],'secure_count':sl.get_json()['count']},
            'xss': {'vulnerable_html_sin_escapar':True,'secure_texto_escapado':True},
            'idor': {'vulnerable_http':vid.status_code,'secure_http':sid.status_code,'acceso_propio_http':own.status_code},
            'endpoints_comparados': ['/api/cases','/preview','/api/cases/2','/api/cases/1']
        }
    target=ROOT/'evidencias'/'pruebas_flask.json'
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
    print(json.dumps(result,indent=2,ensure_ascii=False))

if __name__=='__main__':main()
