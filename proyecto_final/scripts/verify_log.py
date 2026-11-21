"""Comprueba el encadenamiento SHA-256 de una bitácora JSONL del CFCC."""
import argparse
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cfcc_lab.core import verify_log

p = argparse.ArgumentParser()
p.add_argument('path', type=Path, help='Archivo de eventos JSONL')
a = p.parse_args()
try:
    verified, line = verify_log(a.path)
except (ValueError, OSError) as exc:
    print('No fue posible verificar la bitácora:', exc)
    raise SystemExit(1)
if verified:
    print('Integridad de la cadena SHA-256: verificada')
else:
    print(f'Integridad no validada: línea {line}')
raise SystemExit(0 if verified else 1)
