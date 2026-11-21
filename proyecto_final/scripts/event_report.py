"""Analiza registros JSONL del laboratorio y emite alertas R6 reproducibles."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from cfcc_lab.core import read_events,classify,write_event
p=argparse.ArgumentParser()
p.add_argument('--log',type=Path,default=ROOT/'logs'/'secure_events.jsonl')
p.add_argument('--output',type=Path,default=ROOT/'evidencias'/'alertas_seguridad.json')
p.add_argument('--window',type=int,default=10,help='Ventana deslizante en minutos')
p.add_argument('--demo',action='store_true',help='Genera tres denegaciones de ejemplo antes de analizar')
a=p.parse_args()
if a.demo:
    for _ in range(3):write_event(a.log,'authorization','analista1','denied','/api/cases/:id',403)
records=read_events(a.log); alerts=classify(records,window_min=a.window)
result={'eventos_analizados':len(records),'alertas_generadas':len(alerts),'alertas':alerts,
        'ventana_min':a.window,
        'criterio':f'Regla didáctica: >=3 denegaciones por usuario dentro de una ventana de {a.window} minutos'}
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False,indent=2))
