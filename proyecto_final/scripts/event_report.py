"""Analiza bitácoras JSONL y emite alertas R6/R1 con ventanas fechadas."""
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cfcc_lab.core import read_events, classify, write_event, verify_log

p = argparse.ArgumentParser()
p.add_argument('--log', type=Path, default=ROOT/'logs'/'secure_events.jsonl')
p.add_argument('--output', type=Path, default=ROOT/'evidencias'/'alertas_seguridad.json')
p.add_argument('--window', type=int, default=10, help='Ventana deslizante en minutos')
p.add_argument('--demo', action='store_true', help='Crea una sesión sintética independiente y reproducible')
a = p.parse_args()

if a.demo:
    a.log = ROOT/'evidencias'/'eventos_demo.jsonl'
    a.log.parent.mkdir(parents=True, exist_ok=True)
    a.log.unlink(missing_ok=True)
    base = datetime(2026, 11, 21, 9, 0, tzinfo=timezone.utc)
    for i in range(3):
        write_event(a.log, 'authorization', 'analista1', 'denied', '/api/cases/:id', 404,
                    origin_ip='127.0.0.1', reason='not_owner', resource_id=2,
                    at=base + timedelta(minutes=i))
    for i in range(5):
        write_event(a.log, 'authentication', 'analista2', 'denied', '/login', 401,
                    origin_ip='127.0.0.1', reason='invalid_credentials',
                    at=base + timedelta(minutes=i+3))
    write_event(a.log, 'validation', 'analista1', 'flagged', '/api/cases', 200,
                origin_ip='127.0.0.1', signal='sql_pattern', input_length=11,
                at=base + timedelta(minutes=8))

records = read_events(a.log)
alerts = classify(records, window_min=a.window)
valid, line = verify_log(a.log)
result = {'fuente': str(a.log.relative_to(ROOT)) if a.log.is_relative_to(ROOT) else str(a.log),
          'muestra': 'sintética y local' if a.demo else 'registro de ejecución local',
          'eventos_analizados': len(records), 'alertas_generadas': len(alerts),
          'integridad_cadena_sha256': 'verificada' if valid else f'alteración_o_formato_antiguo_en_línea_{line}',
          'alertas': alerts, 'ventana_min': a.window,
          'criterio': 'R6 >=3 denegaciones y R1 >=5 autenticaciones fallidas en diez minutos'}
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=False, indent=2))
