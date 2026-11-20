"""Funciones aisladas y verificables del laboratorio CFCC.

La variante vulnerable es deliberada y solo es apropiada para pruebas en localhost.
"""
from __future__ import annotations
import html
import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROWS = [
    (1, 'analista1', 'alta', 'Alerta de coordinación', 'Expediente inventado de continuidad.'),
    (2, 'analista2', 'media', 'Solicitud interinstitucional', 'Ejemplo ficticio de seguimiento.'),
    (3, 'analista1', 'alta', 'Servicio documental', 'Prueba de prioridad operativa.'),
    (4, 'analista2', 'baja', 'Actualización de estado', 'No contiene información real.'),
]
ACCOUNTS = {'analista1':'demo1234', 'analista2':'demo1234', 'supervisor':'demo1234'}

def database():
    db=sqlite3.connect(':memory:')
    db.row_factory=sqlite3.Row
    db.execute('CREATE TABLE cases (id INTEGER PRIMARY KEY, owner TEXT, severity TEXT, title TEXT, notes TEXT)')
    db.executemany('INSERT INTO cases VALUES (?, ?, ?, ?, ?)', ROWS)
    db.commit()
    return db

def list_cases(db, severity, mode, username):
    if mode == 'vulnerable':
        # Caso didáctico: concatenación incorrecta. No ejecutar fuera del laboratorio.
        statement = "SELECT * FROM cases WHERE severity = '" + severity + "' ORDER BY id"
        rows = db.execute(statement).fetchall()
    else:
        if len(severity) > 60:
            return []
        statement='SELECT * FROM cases WHERE severity = ? ORDER BY id'
        rows=db.execute(statement,(severity,)).fetchall()
        if username != 'supervisor':
            rows=[r for r in rows if r['owner'] == username]
    return [dict(r) for r in rows]

def get_case(db, case_id, mode, username):
    row=db.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
    if row is None:
        return None, 404
    if mode == 'secure' and username != 'supervisor' and row['owner'] != username:
        return None, 403
    return dict(row), 200

def preview(message, mode):
    if mode=='vulnerable':
        return '<div class="preview">'+message+'</div>'
    return '<div class="preview">'+html.escape(message, quote=True)+'</div>'

def classify(events, threshold=3):
    """Señal de tres denegaciones para un mismo actor en una ventana local de análisis."""
    counter=Counter(e.get('username','desconocido') for e in events if e.get('event')=='authorization' and e.get('outcome')=='denied')
    alerts=[]
    for username, count in sorted(counter.items()):
        if count>=threshold:
            alerts.append({'rule':'R6_REPEAT_DENIAL','username':username,'count':count,'severity':'media',
                           'summary':'Denegaciones repetidas de acceso en el laboratorio'})
    return alerts

def write_event(path, event, username, outcome, endpoint, status):
    """Sin contraseñas, tokens, parámetros de consulta ni cuerpos de solicitud."""
    record={'timestamp_utc':datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'event':event,'username':username,'outcome':outcome,'endpoint':endpoint,'status':status}
    target=Path(path);target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('a',encoding='utf-8') as f:
        f.write(json.dumps(record,ensure_ascii=False)+'\n')
    return record

def read_events(path):
    f=Path(path)
    return [json.loads(x) for x in f.read_text(encoding='utf-8').splitlines() if x.strip()] if f.exists() else []
