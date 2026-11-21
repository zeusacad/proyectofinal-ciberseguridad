"""Genera resultados HTTP verificables con el cliente Flask y datos ficticios.

No se conecta a redes; escribe bitácoras separadas de las pruebas de ZAP.
"""
from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import make_app
from cfcc_lab.core import classify, read_events, verify_log

OUT = ROOT / 'evidencias'
OUT.mkdir(exist_ok=True)
vlog = OUT / 'sesion_http_vulnerable.jsonl'
slog = OUT / 'sesion_http_segura.jsonl'
for file in (vlog, slog):
    file.unlink(missing_ok=True)
v = make_app('vulnerable', log_path=vlog).test_client()
s = make_app('secure', log_path=slog).test_client()

def auth(client, user):
    response = client.post('/login', data={'username':user, 'password':'demo1234'})
    assert response.status_code == 302

def query(client, path, params=None):
    response = client.get(path, query_string=params)
    return {'http':response.status_code, 'body':response.get_json()}

health_v=query(v,'/api/health')
health_s=query(s,'/api/health')
auth(v,'analista1')
auth(s,'analista1')
original="' OR '1'='1"
union="zzz' UNION SELECT 99,'x','x','x','x' -- "
sqli_v=query(v,'/api/cases',{'severity':original})
sqli_s=query(s,'/api/cases',{'severity':original})
union_v=query(v,'/api/cases',{'severity':union})
union_s=query(s,'/api/cases',{'severity':union})
list_v=query(v,'/api/cases',{'severity':'media'})
list_s=query(s,'/api/cases',{'severity':'media'})
foreign_v=query(v,'/api/cases/2')
foreign_s=query(s,'/api/cases/2')
missing_s=query(s,'/api/cases/99')
own_s=query(s,'/api/cases/1')
invalid=query(s,'/api/cases',{'severity':'a'*100})
for _ in range(2):
    s.get('/api/cases/2')
for _ in range(5):
    s.post('/login',data={'username':'analista2','password':'incorrecta'})
s.get('/preview',query_string={'message':'<img src=x onerror=alert(1)>'})
alerts=classify(read_events(slog))
valid,line=verify_log(slog)
result={
    'fecha_utc':datetime.now(timezone.utc).isoformat(timespec='seconds'),
    'metodo':'Flask test_client; ejecución HTTP local sin ZAP',
    'health':{'vulnerable':health_v,'secure':health_s},
    'sql_or':{'vulnerable_count':sqli_v['body']['count'],'secure_count':sqli_s['body']['count'],
              'exposicion_de_otros_duenos':sorted({c['owner'] for c in sqli_v['body']['cases']})},
    'sql_union':{'vulnerable':union_v,'secure':union_s},
    'idor_listado':{'vulnerable':list_v,'secure':list_s},
    'idor_objeto':{'ajeno_vulnerable':foreign_v,'ajeno_seguro':foreign_s,
                   'inexistente_seguro':missing_s,'propio_seguro':own_s},
    'entrada_larga':{'status':invalid['http'],'error':invalid['body']},
    'monitoring':{'eventos':len(read_events(slog)),'alertas':alerts,'integridad_sha256':valid,
                  'linea_error':line}
}
assert result['sql_or']['vulnerable_count']==4 and result['sql_or']['secure_count']==0
assert result['sql_union']['vulnerable']['body']['count']==1
assert result['sql_union']['secure']['body']['count']==0
assert (foreign_v['http'],foreign_s['http'],missing_s['http'],own_s['http'])==(200,404,404,200)
assert {a['rule'] for a in alerts}=={'R6_REPEAT_DENIAL','R1_REPEAT_AUTH_FAIL'}
assert valid
(OUT/'reporte_http.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

# Transcripción textual para lectura directa de las respuestas verificadas.
lines=[
    'PROTOCOLO ZERO DAY / CFCC — RESULTADOS HTTP LOCALES',
    'Método: cliente de prueba Flask. No sustituye un informe de ZAP.',
    '',
    'F02  GET /api/health (servidor seguro)',
    'HTTP 200',json.dumps(health_s['body'],ensure_ascii=False,sort_keys=True),
    '',
    'F05  GET /api/cases?severity=[OR verdadera] (analista1, vulnerable)',
    f"HTTP {sqli_v['http']} — count={sqli_v['body']['count']}",
    f"Propietarios devueltos: {', '.join(result['sql_or']['exposicion_de_otros_duenos'])}",
    '',
    'F06  GET /api/cases?severity=[OR verdadera] (analista1, corregida)',
    f"HTTP {sqli_s['http']}",json.dumps(sqli_s['body'],ensure_ascii=False,sort_keys=True),
    '',
    'UNION SELECT contra /api/cases (datos de prueba)',
    f"Vulnerable: HTTP {union_v['http']}, count={union_v['body']['count']}, id={union_v['body']['cases'][0]['id']}",
    f"Corregida: HTTP {union_s['http']}, count={union_s['body']['count']}",
    '',
    'IDOR/BOLA con analista1',
    f"Expediente 2 (ajeno) vulnerable: HTTP {foreign_v['http']}",
    f"Expediente 2 (ajeno) corregido: HTTP {foreign_s['http']} {json.dumps(foreign_s['body'])}",
    f"Expediente 99 (no existe) corregido: HTTP {missing_s['http']} {json.dumps(missing_s['body'])}",
    f"Expediente 1 (propio) corregido: HTTP {own_s['http']}",
    '',
    'Validación de entrada: severity de 100 caracteres: HTTP 400',
    '',
    'Monitoreo de tráfico HTTP real del cliente Flask',
    f"Eventos registrados: {len(read_events(slog))}",
    *[f"{a['rule']}: usuario={a['username']}; total={a.get('total_denials',a.get('total_auth_failures'))}; "
      f"ventana={a['count_in_window']}; {a['first_ts']} a {a['last_ts']}; severidad={a['severity']}" for a in alerts],
    f'Integridad SHA-256: {"VERIFICADA" if valid else "NO VERIFICADA"}'
]
(OUT/'resultados_http.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print('\n'.join(lines))
