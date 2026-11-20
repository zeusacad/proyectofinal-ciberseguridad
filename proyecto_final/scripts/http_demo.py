"""Pruebas HTTP con sesión; SOLO contra localhost y una aplicación iniciada manualmente."""
import argparse,json,urllib.parse,urllib.request,urllib.error,http.cookiejar
p=argparse.ArgumentParser();p.add_argument('--base',default='http://127.0.0.1:5001');p.add_argument('--user',default='analista1');a=p.parse_args()
if not (a.base.startswith('http://127.0.0.1:') or a.base.startswith('http://localhost:')):
    raise SystemExit('Por seguridad este programa solo acepta direcciones localhost')
cookies=http.cookiejar.CookieJar();o=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
login=urllib.parse.urlencode({'username':a.user,'password':'demo1234'}).encode()
o.open(a.base+'/login',data=login,timeout=5).read()
requests={'salud':'/api/health','consulta_valida':'/api/cases?severity=alta','sql_lab':'/api/cases?severity=%27%20OR%20%271%27%3D%271','idor_ajeno':'/api/cases/2','idor_propio':'/api/cases/1','xss_lab':'/preview?message=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'}
for label,path in requests.items():
    try:
        with o.open(a.base+path,timeout=5) as r:status=r.status;body=r.read().decode('utf-8')
    except urllib.error.HTTPError as e:status=e.code;body=e.read().decode('utf-8')
    print(json.dumps({'prueba':label,'url':a.base+path,'status':status,'fragmento_respuesta':body[:160]},ensure_ascii=False))
