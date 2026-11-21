#!/usr/bin/env bash
# Flujo local de comparación de variantes, pruebas y evidencias independientes.
set -euo pipefail
cd "$(dirname "$0")/.."
python -W error::ResourceWarning -m unittest discover -s tests -v
python scripts/run_evidence.py
python scripts/run_flask_evidence.py
python scripts/validate_r6.py
python scripts/complete_lab_evidence.py
python scripts/event_report.py --demo
python scripts/verify_log.py evidencias/sesion_http_segura.jsonl
printf '\nVerificación local completa. ZAP Desktop se ejecuta y exporta por separado.\n'
