#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m unittest discover -s tests -v
python3 scripts/run_evidence.py
python3 scripts/run_flask_evidence.py
python3 scripts/event_report.py --log logs/secure_events.jsonl --output evidencias/alertas_seguridad.json
printf '\nLaboratorio verificado. Para comparar la interfaz con OWASP ZAP, iniciar en dos terminales:\n'
printf '  python3 app.py --mode vulnerable --port 5000\n'
printf '  python3 app.py --mode secure --port 5001\n'
