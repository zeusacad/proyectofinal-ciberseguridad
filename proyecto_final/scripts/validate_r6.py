"""Verifica ventanas exactas, correlación y reglas R6/R1 con datos locales."""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cfcc_lab.core import classify

BASE = datetime(2026, 11, 21, 9, 0, tzinfo=timezone.utc)


def event(minutes, kind='authorization', who='analista1', origin=None):
    e = {'timestamp_utc': (BASE + timedelta(minutes=minutes)).isoformat(timespec='seconds'),
         'event': kind, 'username': who, 'outcome': 'denied',
         'endpoint': '/login' if kind == 'authentication' else '/api/cases/:id',
         'status': 401 if kind == 'authentication' else 404}
    if origin:
        e['origin_ip'] = origin
    return e


def entries(minutes, **kwargs):
    return [event(m, **kwargs) for m in minutes]


cases = [
    ('C1 R6 positivo: 3 denegaciones', entries([0, 1, 2]), 1),
    ('C2 R6 negativo: 2 denegaciones', entries([0, 1]), 0),
    ('C3 R6 fuera de ventana (15 min)', entries([0, 15, 30]), 0),
    ('C4 R6 multiusuario 3 + 2', entries([0, 1, 2]) + entries([0, 1], who='analista2'), 1),
    ('C5 R6 multiusuario 3 + 4', entries([0, 1, 2]) + entries([0, 1, 2, 3], who='analista2'), 2),
    ('C6 R6 sin denegaciones', [], 0),
    ('C7 ventana exacta de 10:00', entries([0, 5, 10]), 1),
    ('C8 ventana 10:01: sin alerta', [event(0), event(5), event(10 + 1/60)], 0),
    ('C9 R1: 5 fallos en 10 minutos', entries([0, 1, 2, 3, 4], kind='authentication'), 1),
    ('C10 R1: 4 fallos no alertan', entries([0, 1, 2, 3], kind='authentication'), 0),
    ('C11 R1: 5 fallos dispersos', entries([0, 11, 22, 33, 44], kind='authentication'), 0),
    ('C12 R6 por origen con usuarios distintos', entries([0, 1], origin='127.0.0.1') + entries([2], who='analista2', origin='127.0.0.1'), 1),
]

rows = []
for name, records, expected in cases:
    alerts = classify(records)
    good = len(alerts) == expected
    rows.append({'caso': name, 'eventos': len(records), 'alertas': len(alerts),
                 'esperado': expected, 'ok': good})
    print(f'{name:49} {len(records):>4} eventos | {len(alerts)} alertas | {"OK" if good else "FALLO"}')

ok = sum(row['ok'] for row in rows)
print(f'\nValidación R6 / R1: {ok}/{len(rows)} casos correctos')
out = ROOT/'evidencias'/'validacion_r6.json'
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps({'correctos': ok, 'total': len(rows), 'casos': rows}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
raise SystemExit(0 if ok == len(rows) else 1)
