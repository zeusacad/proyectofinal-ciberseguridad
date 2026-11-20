"""Ejecuta las 12 pruebas básicas y guarda resultados realmente obtenidos."""
import json
import sys
import unittest
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_core.py',top_level_dir=str(ROOT))
with (ROOT/'evidencias'/'pruebas_motor.txt').open('w',encoding='utf-8') as report:
    result=unittest.TextTestRunner(stream=report,verbosity=2).run(suite)
summary={'fecha_utc':datetime.now(timezone.utc).isoformat(timespec='seconds'),
         'entorno':'motor Python stdlib, sin requerir Flask',
         'total':result.testsRun,'correctas':result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped),
         'fallos':len(result.failures),'errores':len(result.errors),'omitidas':len(result.skipped),
         'notas':'Los ensayos HTTP/OWASP ZAP son independientes de las pruebas del motor.'}
(ROOT/'evidencias'/'pruebas_motor.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(summary,ensure_ascii=False,indent=2))
raise SystemExit(0 if result.wasSuccessful() else 1)
