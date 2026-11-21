"""Aplicación Flask CFCC: SOLO laboratorio propio, localhost (127.0.0.1).

Iniciar modo vulnerable: python app.py --mode vulnerable --port 5000
Iniciar modo corregido: python app.py --mode secure --port 5001
La variante vulnerable reproduce fallas para su corrección; jamás desplegar públicamente.
"""
from __future__ import annotations
import argparse
import hmac
import hashlib
import os
from pathlib import Path
from flask import Flask, Response, jsonify, redirect, render_template_string, request, session, url_for
from cfcc_lab.core import ACCOUNTS, database, get_case, list_cases, preview, write_event, read_events, classify, suspicious_signal

ROOT=Path(__file__).resolve().parent
# CSS local incluido en la plantilla para conservar sin cambios la política CSP original.
CSS_FILE=ROOT/'static'/'cfcc.css'
CSS=CSS_FILE.read_text(encoding='utf-8') if CSS_FILE.exists() else ''
PAGE='''<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>CFCC | Portal de continuidad · Laboratorio</title>
  <link rel="icon" type="image/png" href="{{ url_for('static',filename='assets/cfcc-escudo.png') }}">
  <style>{{ css_contents|safe }}</style>
</head>
<body class="cfcc-app {% if user %}session-open{% else %}session-closed{% endif %} {% if mode_is_secure %}is-secure{% else %}is-vulnerable{% endif %}">
  <div class="gov-stripe" aria-hidden="true"></div>
  <div class="topline">
    <div class="shell topline-inner">
      <span><span class="topline-dot" aria-hidden="true"></span> PROTOCOLO ZERO DAY <span class="topline-separator">/</span> ENTORNO ACADÉMICO</span>
      <span class="topline-right">SIMULACIÓN · DATOS FICTICIOS · 127.0.0.1</span>
    </div>
  </div>
  <header class="masthead">
    <div class="shell masthead-inner">
      <a class="brand" href="{{url_for('index')}}" aria-label="Ir al inicio del laboratorio CFCC">
        <img class="brand-seal" src="{{url_for('static',filename='assets/cfcc-escudo.png')}}" alt="Escudo ficticio del CFCC">
        <span class="brand-copy">
          <span class="brand-overline">CENTRO FEDERAL DE COORDINACIÓN</span>
          <span class="brand-name">DE CONTINUIDAD <span class="brand-monogram">CFCC</span></span>
          <span class="brand-under">Dirección de Seguridad y Resiliencia Digital</span>
        </span>
      </a>
      <div class="masthead-meta">
        <span class="masthead-classification"><span class="class-line"></span> PROYECTO ACADÉMICO</span>
        <span class="masthead-ref">CFCC / LABORATORIO / 2026</span>
      </div>
    </div>
  </header>
  <div class="environment-bar">
    <div class="shell environment-inner">
      <div class="environment-info">
        <span class="environment-indicator" aria-hidden="true"></span>
        <span class="environment-text">ESTADO DEL ENTORNO</span>
        <strong>{{ mode_label }}</strong>
      </div>
      <span class="environment-note">EJECUCIÓN LOCAL Y AUTORIZADA <span class="environment-divider">·</span> SIN DATOS REALES</span>
    </div>
  </div>

  <main class="shell main-area">
    {% if user %}
    <div class="session-bar">
      <div class="session-identity">
        <span class="identity-avatar" aria-hidden="true">{{user[0]|upper}}</span>
        <span class="identity-copy"><small>SESIÓN AUTENTICADA</small><strong>{{user}}</strong></span>
        <span class="session-active"><span class="session-active-dot"></span> ACTIVA</span>
      </div>
      <nav class="session-nav" aria-label="Navegación del laboratorio">
        <a href="{{url_for('dashboard')}}">Panel principal</a>
        <a href="{{url_for('events')}}">Bitácora</a>
        <a class="session-logout" href="{{url_for('logout')}}">Cerrar sesión <span aria-hidden="true">↗</span></a>
      </nav>
    </div>
    <div class="workspace">
      <div class="main-panel">{{ contents|safe }}</div>
      <aside class="lab-aside" aria-label="Información del laboratorio">
        <div class="aside-title-row"><span class="aside-rule"></span><span>PORTAL DE OPERACIONES</span></div>
        <div class="aside-brand">
          <img src="{{url_for('static',filename='assets/cfcc-escudo.png')}}" alt="" aria-hidden="true">
          <div><strong>CFCC</strong><small>CENTRO DE CONTINUIDAD</small></div>
        </div>
        <div class="aside-divider"></div>
        <span class="aside-label">ACCESO RÁPIDO</span>
        <nav class="aside-links" aria-label="Accesos de prueba">
          <a href="{{url_for('dashboard')}}"><span class="aside-index">01</span> Panel de control <span class="aside-chevron">↗</span></a>
          <a href="/api/cases?severity=alta"><span class="aside-index">02</span> API de expedientes <span class="aside-chevron">↗</span></a>
          <a href="/api/cases/1"><span class="aside-index">03</span> Consultar expediente <span class="aside-chevron">↗</span></a>
          <a href="{{url_for('events')}}"><span class="aside-index">04</span> Registro de eventos <span class="aside-chevron">↗</span></a>
          <a href="{{url_for('health')}}"><span class="aside-index">05</span> Estado del servicio <span class="aside-chevron">↗</span></a>
        </nav>
        <div class="aside-divider"></div>
        <span class="aside-label">PROTOCOLO ZERO DAY</span>
        <div class="aside-status"><span class="aside-live"></span> Servicios de prueba en localhost</div>
        <p class="aside-help">Sistema demostrativo. Las cuentas y los expedientes no pertenecen a ninguna institución real.</p>
        <div class="aside-footer">SEGURIDAD DE APLICACIONES<br>PRÁCTICA CONTROLADA / CFCC</div>
      </aside>
    </div>
    {% else %}
    <div class="login-grid">
      <section class="login-intro" aria-labelledby="welcome-title">
        <div class="login-intro-kicker"><span class="section-dash"></span> PORTAL INSTITUCIONAL · DEMOSTRACIÓN</div>
        <img class="login-large-seal" src="{{url_for('static',filename='assets/cfcc-escudo.png')}}" alt="Escudo del CFCC ficticio">
        <h1 id="welcome-title">Continuidad.<br><em>Confianza.</em><br>Seguridad.</h1>
        <p>Entorno de evaluación de accesos, expedientes y controles de seguridad de aplicaciones.</p>
        <div class="intro-divider"></div>
        <div class="intro-stats">
          <div><strong>03</strong><span>ESCENARIOS</span></div>
          <div><strong>02</strong><span>VARIANTES</span></div>
          <div><strong>LOCAL</strong><span>ENTORNO SEGURO</span></div>
        </div>
      </section>
      <section class="login-card" aria-label="Acceso al sistema">
        <div class="login-card-top"><span class="secure-key">ACCESO CONTROLADO</span><span class="login-edition">CFCC / LAB</span></div>
        {{ contents|safe }}
        <div class="login-disclaimer"><span class="info-mark">i</span><p>Esta interfaz es una simulación para un proyecto académico de ciberseguridad. Nunca introduzcas credenciales reales.</p></div>
      </section>
    </div>
    {% endif %}
  </main>
  <footer class="footer">
    <div class="shell footer-inner">
      <span>© 2026 · CENTRO FEDERAL DE COORDINACIÓN DE CONTINUIDAD — SIMULACIÓN ACADÉMICA</span>
      <span>PROTOCOLO ZERO DAY <span class="footer-sep">/</span> USO EXCLUSIVO EN LOCALHOST</span>
    </div>
  </footer>
</body>
</html>'''

def make_app(mode='secure',log_path=None):
    assert mode in ('vulnerable','secure')
    app=Flask(__name__)
    # Clave efímera por proceso: no almacena secretos permanentes en el código.
    app.secret_key=os.urandom(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=False,MAX_CONTENT_LENGTH=4096,TESTING=False)
    logfile=Path(log_path) if log_path else ROOT/'logs'/f'{mode}_events.jsonl'

    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['X-Frame-Options']='DENY'
        if mode=='secure':
            response.headers['Content-Security-Policy']="default-src 'self'; script-src 'none'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'"
        return response

    def page(contents):
        return render_template_string(PAGE,contents=contents,user=session.get('username'),mode_label='VARIANTE VULNERABLE' if mode=='vulnerable' else 'VARIANTE CORREGIDA',mode_is_secure=(mode=='secure'),css_contents=CSS)
    def audit(event,outcome,endpoint,status,**fields):
        write_event(logfile,event,session.get('username','anonimo'),outcome,endpoint,status,
                    origin_ip=request.remote_addr,**fields)
    def logged_in():return session.get('username') in ACCOUNTS

    @app.get('/')
    def index():return redirect(url_for('dashboard')) if logged_in() else redirect(url_for('login'))
    @app.route('/login',methods=['GET','POST'])
    def login():
        if request.method=='POST':
            username=request.form.get('username','')
            password=request.form.get('password','')
            if username in ACCOUNTS and hmac.compare_digest(ACCOUNTS[username],password):
                session.clear();session['username']=username
                audit('authentication','allowed','/login',302)
                return redirect(url_for('dashboard'))
            uid = username if username in ACCOUNTS else (
                'desconocido-' + hashlib.sha256(username.encode('utf-8')).hexdigest()[:8])
            write_event(logfile,'authentication',uid,'denied','/login',401,
                        origin_ip=request.remote_addr, reason='invalid_credentials')
            return page('<p class="login-error" role="alert"><b>Acceso incorrecto.</b> Verifica las credenciales de prueba.</p>'+login_form()),401
        return page(login_form())
    def login_form():
        return '''<div class="login-content">
          <div class="login-heading-kicker">IDENTIFICACIÓN DE USUARIO</div>
          <h2>Acceso al sistema</h2>
          <p class="login-lead">Ingresa con una cuenta de demostración para acceder al entorno de evaluación.</p>
          <form method="post" class="login-form">
            <label for="lab-username">USUARIO INSTITUCIONAL</label>
            <input id="lab-username" name="username" placeholder="Ej. supervisor" autocomplete="username" required>
            <label for="lab-password">CONTRASEÑA DE ACCESO</label>
            <input id="lab-password" type="password" name="password" placeholder="Contraseña de prueba" autocomplete="current-password" required>
            <button type="submit" class="btn-login">Ingresar al portal <span aria-hidden="true">→</span></button>
          </form>
          <div class="test-identities"><div class="test-identities-title">CREDENCIALES DE DEMOSTRACIÓN</div><p>Usuarios: <code>analista1</code>, <code>analista2</code>, <code>supervisor</code></p><p>Contraseña ficticia: <code>demo1234</code></p></div>
        </div>'''

    @app.get('/logout')
    def logout():session.clear();return redirect(url_for('login'))
    @app.get('/api/health')
    def health():return jsonify(status='ok',mode=mode,service='CFCC laboratorio')
    @app.get('/dashboard')
    def dashboard():
        if not logged_in():return redirect(url_for('login'))
        import html
        uname=html.escape(session['username'])
        body='''<div class="dashboard-head">
          <div><p class="eyebrow"><span class="section-dash"></span> CENTRO DE OPERACIONES DIGITALES <span class="muted-dot">/</span> ENTORNO DE PRUEBAS</p>
          <h1>Panel de control<span class="dot-accent">.</span></h1>
          <p class="dashboard-subtitle">Supervisión y validación de controles de seguridad para expedientes ficticios del CFCC.</p></div>
          <div class="dashboard-stamp"><span>CFCC</span><strong>LAB / 26</strong><small>UNIDAD DE PRUEBAS</small></div>
        </div>
        <section class="mission-panel">
          <div class="mission-copy"><span class="mission-label">MISIÓN DE SEGURIDAD · PROTOCOLO ZERO DAY</span>
            <h2>Verificar. Corregir.<br><em>Evidenciar.</em></h2>
            <p>Analizamos controles de acceso, procesamiento de entradas y registros de seguridad en un entorno autorizado.</p>
          </div>
          <div class="mission-metrics"><div><strong>03</strong><span>PRUEBAS DE APLICACIÓN</span></div><div><strong>02</strong><span>ENTORNOS LOCALES</span></div></div>
        </section>
        <div class="module-heading"><div><p class="eyebrow">EVALUACIÓN DE SEGURIDAD</p><h2>Módulos de prueba</h2></div><span>03 MÓDULOS / HTTP</span></div>
        <div class="module-grid">
          <article class="module-card card-sql"><div class="module-top"><span class="module-number">01 / BASE DE DATOS</span><span class="module-symbol">DB</span></div>
            <h3>Consultas SQL</h3><span class="module-technical">SQL INJECTION</span><p>Revisa cómo se interpretan los parámetros de búsqueda y compara las consultas de los expedientes.</p>
            <div class="module-action"><a href="/api/cases?severity=alta">Consultar expedientes <span aria-hidden="true">↗</span></a></div>
          </article>
          <article class="module-card card-idor"><div class="module-top"><span class="module-number">02 / AUTORIZACIÓN</span><span class="module-symbol">ID</span></div>
            <h3>Control de acceso</h3><span class="module-technical">IDOR / BOLA</span><p>Comprueba los permisos por recurso utilizando expedientes asociados a distintos analistas.</p>
            <div class="module-action dual-links"><a href="/api/cases/1">Caso 01 <span aria-hidden="true">↗</span></a><a href="/api/cases/2">Caso 02 <span aria-hidden="true">↗</span></a></div>
          </article>
          <article class="module-card card-xss"><div class="module-top"><span class="module-number">03 / VISTA PREVIA</span><span class="module-symbol">UI</span></div>
            <h3>Revisión de notas</h3><span class="module-technical">CROSS-SITE SCRIPTING</span><p>Inspecciona cómo se muestra el contenido suministrado por el usuario en el navegador.</p>
            <form class="note-form" action="/preview" method="get">
              <label for="note-message">CONTENIDO DE PRUEBA</label>
              <input id="note-message" name="message" value="Nota de prueba" aria-label="Nota de prueba">
              <button type="submit">Ver nota <span aria-hidden="true">↗</span></button>
            </form>
          </article>
        </div>
        <section class="info-band"><div class="info-icon">i</div><p><strong>Laboratorio autorizado.</strong> Todos los datos son ficticios. Para documentar hallazgos, captura las solicitudes y respuestas de las rutas anteriores con el navegador o OWASP ZAP.</p></section>'''
        return page(body)
    @app.get('/api/cases')
    def cases():
        if not logged_in():return jsonify(error='authentication_required'),401
        severity=request.args.get('severity','alta')
        if mode == 'secure' and len(severity) > 60:
            audit('validation','denied','/api/cases',400,reason='severity_too_long',input_length=len(severity))
            return jsonify(error='invalid_severity'),400
        signal=suspicious_signal(severity,'sql')
        if signal:
            audit('validation','flagged','/api/cases',200,signal=signal,input_length=len(severity))
        try:
            with database() as db:result=list_cases(db,severity,mode,session['username'])
        except Exception:
            audit('validation','denied','/api/cases',400)
            return jsonify(error='invalid_query'),400
        audit('query','allowed','/api/cases',200)
        return jsonify(count=len(result),cases=result,mode=mode)
    @app.get('/api/cases/<int:case_id>')
    def case_detail(case_id):
        if not logged_in():return jsonify(error='authentication_required'),401
        with database() as db:data,status,reason=get_case(db,case_id,mode,session['username'],explain=True)
        audit('authorization','allowed' if status==200 else 'denied','/api/cases/:id',
              status,reason=reason,resource_id=case_id)
        return (jsonify(data),status) if status==200 else (jsonify(error='not_found'),status)
    @app.get('/preview')
    def render_preview():
        if not logged_in():return redirect(url_for('login'))
        message=request.args.get('message','Nota de prueba')
        if len(message)>500:
            audit('validation','denied','/preview',400,reason='message_too_long',input_length=len(message))
            return page('<p>Entrada demasiado larga.</p>'),400
        signal=suspicious_signal(message,'html')
        if signal:
            audit('validation','flagged','/preview',200,signal=signal,input_length=len(message))
        audit('preview','allowed','/preview',200)
        # En modo vulnerable preview devuelve HTML sin escapado; solo en localhost.
        return page('<div class="page-heading"><p class="eyebrow">MÓDULO 03 / VALIDACIÓN DE CONTENIDO</p><h1>Vista previa de nota</h1><p>Representación del texto ingresado en el formulario de prueba.</p></div><div class="preview-wrapper"><p class="preview-label">CONTENIDO DEL MENSAJE</p>'+preview(message,mode)+'</div><a class="return-link" href="/dashboard">← Volver al panel</a>')
    @app.get('/events')
    def events():
        if not logged_in():return redirect(url_for('login'))
        if session['username']!='supervisor':
            audit('authorization','denied','/events',403)
            return page('<p>Acceso denegado.</p>'),403
        import html
        raw=read_events(logfile)[-30:]
        report=classify(read_events(logfile))
        body='<div class="page-heading"><p class="eyebrow">CONTROL Y AUDITORÍA / EVENTOS LOCALES</p><h1>Bitácora de seguridad</h1><p>Actividad reciente del servicio y señales detectadas.</p></div><div class="log-stats"><div><strong>'+str(len(raw))+'</strong><small>EVENTOS MOSTRADOS</small></div><div><strong>'+str(len(report))+'</strong><small>ALERTAS R6 / R1</small></div></div><div class="log-frame"><span>ALERTAS DETECTADAS / CONSULTA LOCAL</span><pre>'+html.escape('\n'.join(f"{a['rule']} | {a['username']} | {a['severity']} | {a['count_in_window']} en {a['window_min']} min" for a in report) or 'Sin alertas para la ventana configurada')+'</pre><span>REGISTRO DE ACTIVIDAD / MÁXIMO 30 EVENTOS</span><pre>'+html.escape('\n'.join(f"{e['event']} | {e['username']} | {e['outcome']} | {e['status']}" for e in raw))+'</pre></div>'
        return page(body)
    return app

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['vulnerable','secure'],default='secure');p.add_argument('--port',type=int,default=5001)
    a=p.parse_args()
    make_app(a.mode).run(host='127.0.0.1',port=a.port,debug=False)
