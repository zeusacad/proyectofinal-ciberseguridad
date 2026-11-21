"""Valida la regla R6_REPEAT_DENIAL: caso positivo, negativos, ventana y varios usuarios.

Genera eventos con write_event (archivos temporales) y los analiza con classify.
"""
import json,sys,tempfile
from datetime import datetime,timedelta,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from cfcc_lab.core import classify,write_event,read_events

def real(denials):
    """denials = {usuario: n}; añade además un acceso permitido por usuario."""
    with tempfile.TemporaryDirectory() as tmp:
        f=Path(tmp)/'e.jsonl'
        for u,n in denials.items():
            write_event(f,'authorization',u,'allowed','/api/cases/:id',200)
            for _ in range(n):write_event(f,'authorization',u,'denied','/api/cases/:id',403)
        ev=read_events(f)
    return classify(ev),len(ev)

def spaced(minutes,n=3):
    base=datetime(2026,11,20,9,0,tzinfo=timezone.utc)
    ev=[{'timestamp_utc':(base+timedelta(minutes=minutes*i)).isoformat(timespec='seconds'),'event':'authorization',
         'username':'analista1','outcome':'denied','endpoint':'/api/cases/:id','status':403} for i in range(n)]
    return classify(ev),len(ev)

cases=[('C1 positivo: analista1 con 3 denegaciones',real({'analista1':3}),1),
 ('C2 negativo: analista1 con 2 denegaciones',real({'analista1':2}),0),
 ('C3 negativo: 3 denegaciones separadas 15 min',spaced(15),0),
 ('C4 multiusuario: analista1=3, analista2=2',real({'analista1':3,'analista2':2}),1),
 ('C5 multiusuario: analista1=3, analista2=4',real({'analista1':3,'analista2':4}),2),
 ('C6 supervisor sin denegaciones',real({'supervisor':0}),0)]
rows=[];ok=0
print(f"{'Caso':48} {'eventos':>7} {'alertas':>7} {'esperado':>8}  resultado")
for name,(alerts,total),exp in cases:
    good=len(alerts)==exp;ok+=good
    users=','.join(a['username'] for a in alerts) or '-'
    print(f"{name:48} {total:>7} {len(alerts):>7} {exp:>8}  {'OK' if good else 'FALLO'}  [{users}]")
    rows.append({'caso':name,'eventos':total,'alertas':len(alerts),'esperado':exp,'ok':good})
print(f'\nValidación R6: {ok}/{len(cases)} casos correctos (umbral=3, ventana=10 min)')
out=ROOT/'evidencias'/'validacion_r6.json'
out.write_text(json.dumps({'correctos':ok,'total':len(cases),'casos':rows},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
raise SystemExit(0 if ok==len(cases) else 1)
