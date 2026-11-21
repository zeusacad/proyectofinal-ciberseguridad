"""Reglas verificables del laboratorio CFCC; ejecución exclusiva en localhost.

El modo vulnerable reproduce intencionalmente fallas sobre datos ficticios.
"""
from __future__ import annotations

import hashlib
import html
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROWS = [
    (1, 'analista1', 'alta', 'Alerta de coordinación', 'Expediente inventado de continuidad.'),
    (2, 'analista2', 'media', 'Solicitud interinstitucional', 'Ejemplo ficticio de seguimiento.'),
    (3, 'analista1', 'alta', 'Servicio documental', 'Prueba de prioridad operativa.'),
    (4, 'analista2', 'baja', 'Actualización de estado', 'No contiene información real.'),
]
ACCOUNTS = {'analista1': 'demo1234', 'analista2': 'demo1234', 'supervisor': 'demo1234'}
ZERO_HASH = '0' * 64


class _Conn(sqlite3.Connection):
    """Cierra la conexión al salir de with, incluso cuando ocurre una excepción."""
    def __exit__(self, *exc):
        try:
            return super().__exit__(*exc)
        finally:
            self.close()


def database():
    db = sqlite3.connect(':memory:', factory=_Conn)
    db.row_factory = sqlite3.Row
    db.execute('CREATE TABLE cases (id INTEGER PRIMARY KEY, owner TEXT, severity TEXT, title TEXT, notes TEXT)')
    db.executemany('INSERT INTO cases VALUES (?, ?, ?, ?, ?)', ROWS)
    db.commit()
    return db


def list_cases(db, severity, mode, username):
    if mode == 'vulnerable':
        # Vulnerabilidad intencional y acotada al laboratorio: concatenación de SQL.
        statement = "SELECT * FROM cases WHERE severity = '" + severity + "' ORDER BY id"
        rows = db.execute(statement).fetchall()
    else:
        # El motor de BD aplica desde el principio el alcance autorizado de cada identidad.
        statement = ("SELECT * FROM cases WHERE severity = ? "
                     "AND (owner = ? OR ? = 'supervisor') ORDER BY id")
        rows = db.execute(statement, (severity, username, username)).fetchall()
    return [dict(r) for r in rows]


def get_case(db, case_id, mode, username, explain=False):
    """En modo seguro, no distingue públicamente un ID ajeno de uno inexistente."""
    row = db.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
    if row is None:
        result = (None, 404, 'not_found')
    elif mode == 'secure' and username != 'supervisor' and row['owner'] != username:
        result = (None, 404, 'not_owner')
    else:
        result = (dict(row), 200, 'allowed')
    return result if explain else result[:2]


def preview(message, mode):
    if mode == 'vulnerable':
        return '<div class="preview">' + message + '</div>'
    return '<div class="preview">' + html.escape(message, quote=True) + '</div>'


def suspicious_signal(value, context):
    """Heurística didáctica, no detector exhaustivo ni bloqueo de solicitudes."""
    if context == 'sql' and ("'" in value or '--' in value or '/*' in value):
        return 'sql_pattern'
    if context == 'html' and ('<' in value or '>' in value):
        return 'html_markup'
    return None


def _timestamp(event):
    try:
        t = datetime.fromisoformat(event['timestamp_utc'])
        return t if t.tzinfo is not None else t.replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError):
        return None


def _best_window(items, minutes):
    """Devuelve eventos de la mayor ráfaga, admitiendo el límite exacto inclusivo."""
    points = sorted(((t, e) for e in items if (t := _timestamp(e)) is not None), key=lambda x: x[0])
    best = []
    left = 0
    duration = timedelta(minutes=minutes)
    for right, (moment, _) in enumerate(points):
        while moment - points[left][0] > duration:
            left += 1
        if right - left + 1 > len(best):
            best = points[left:right + 1]
    return best


def _build_alert(events, user, rule, threshold, window_min, summary, origin=None):
    best = _best_window(events, window_min)
    if len(best) < threshold:
        return None
    first, last = best[0][0], best[-1][0]
    ids = {str(e['resource_id']) for _, e in best if e.get('resource_id') is not None}
    severity = 'alta' if len(best) >= 10 or user == 'supervisor' or len(ids) >= 3 else 'media'
    alert = {
        'rule': rule,
        'username': user,
        'total_denials' if rule.startswith('R6') else 'total_auth_failures': len(events),
        'count_in_window': len(best),
        'first_ts': first.isoformat(timespec='seconds'),
        'last_ts': last.isoformat(timespec='seconds'),
        'window_min': window_min,
        'severity': severity,
        'summary': summary,
    }
    if origin:
        alert['origin_ip'] = origin
    if ids:
        alert['distinct_case_ids_in_window'] = len(ids)
    return alert


def classify(events, threshold=3, window_min=10, auth_threshold=5):
    """Clasifica denegaciones R6 y autenticaciones fallidas R1 por actor y origen.

    Las reglas por origen se usan si hay varios usuarios implicados; las señales no
    equivalen a detectar ransomware ni tienen una tasa real de falsos positivos medida.
    """
    if threshold < 1 or auth_threshold < 1 or window_min <= 0:
        raise ValueError('umbrales y ventana deben ser positivos')
    groups = {'R6': {}, 'R1': {}}
    by_ip = {'R6': {}, 'R1': {}}
    for event in events:
        if _timestamp(event) is None or event.get('outcome') != 'denied':
            continue
        typ = 'R6' if event.get('event') == 'authorization' else ('R1' if event.get('event') == 'authentication' else None)
        if not typ:
            continue
        user = event.get('username', 'desconocido')
        groups[typ].setdefault(user, []).append(event)
        ip = event.get('origin_ip')
        if ip:
            by_ip[typ].setdefault(ip, []).append(event)
    alerts = []
    for typ, limit, rule, summary in (
        ('R6', threshold, 'R6_REPEAT_DENIAL', 'Denegaciones repetidas de acceso en el laboratorio'),
        ('R1', auth_threshold, 'R1_REPEAT_AUTH_FAIL', 'Intentos repetidos de autenticación fallida en el laboratorio'),
    ):
        for username, items in sorted(groups[typ].items()):
            a = _build_alert(items, username, rule, limit, window_min, summary)
            if a:
                alerts.append(a)
        for ip, items in sorted(by_ip[typ].items()):
            # IP compartida solo se considera cuando alcanza varias identidades;
            # no duplicamos alertas de una identidad que ya superó el umbral.
            best = _best_window(items, window_min)
            usernames = {e.get('username') for _, e in best}
            has_user_alert = any(
                a['rule'] == rule and a['username'] in usernames for a in alerts
            )
            if len(usernames) >= 2 and not has_user_alert:
                a = _build_alert(items, 'multiples_usuarios',
                                 rule + '_BY_ORIGIN', limit, window_min, summary, origin=ip)
                if a:
                    alerts.append(a)
    return alerts


def _digest(prev_hash, record):
    encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(prev_hash.encode('ascii') + encoded).hexdigest()


def write_event(path, event, username, outcome, endpoint, status, *,
                origin_ip=None, reason=None, resource_id=None, signal=None,
                input_length=None, at=None):
    """Añade un evento JSONL sin datos crudos de entrada ni secretos.

    Se encadenan sumas SHA-256: es una comprobación de integridad básica, no un
    registro inmutable o prueba criptográfica contra reescritura de toda la cadena.
    """
    timestamp = at or datetime.now(timezone.utc)
    record = {'timestamp_utc': timestamp.isoformat(timespec='seconds'), 'event': event,
              'username': username, 'outcome': outcome, 'endpoint': endpoint, 'status': status}
    for key, value in (('origin_ip', origin_ip), ('reason', reason),
                       ('resource_id', resource_id), ('signal', signal), ('input_length', input_length)):
        if value is not None:
            record[key] = value
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = ZERO_HASH
    if target.exists():
        for line in reversed(target.read_text(encoding='utf-8').splitlines()):
            if line.strip():
                prev_hash = json.loads(line).get('entry_hash', ZERO_HASH)
                break
    record['prev_hash'] = prev_hash
    record['entry_hash'] = _digest(prev_hash, record)
    with target.open('a', encoding='utf-8') as f:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')
    return record


def read_events(path):
    target = Path(path)
    return ([json.loads(line) for line in target.read_text(encoding='utf-8').splitlines() if line.strip()]
            if target.exists() else [])


def verify_log(path):
    previous = ZERO_HASH
    for n, event in enumerate(read_events(path), 1):
        supplied = event.get('entry_hash')
        predecessor = event.get('prev_hash')
        content = {key: value for key, value in event.items() if key != 'entry_hash'}
        if predecessor != previous or supplied != _digest(previous, content):
            return False, n
        previous = supplied
    return True, None
