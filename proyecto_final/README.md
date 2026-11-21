# PROTOCOLO ZERO DAY | CFCC — Proyecto final

Laboratorio académico de ciberseguridad, **exclusivamente en un equipo propio**.
Se mantiene la organización ficticia CFCC del avance y se amplía el trabajo hacia la
seguridad de aplicaciones Flask. La variante vulnerable es intencional y **nunca**
debe publicarse en Internet o desplegarse en redes de terceros.

## Requisitos
- Python 3.10+; Windows, macOS o Linux.
- Flask 3.1.2 (la app y las pruebas de endpoints lo necesitan).
- OWASP ZAP Desktop, para inspección manual de tráfico HTTP local.

## Ejecutar
Desde `proyecto_final/`:

```bash
python3 -m venv .venv
source .venv/bin/activate                 # macOS / Linux
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/run_evidence.py
python scripts/event_report.py --demo
```

Iniciamos **dos terminales**, siempre en directorio `proyecto_final`:

```bash
python app.py --mode vulnerable --port 5000
python app.py --mode secure --port 5001
```

Abrimos `http://127.0.0.1:5000/` y `http://127.0.0.1:5001/`.
Usuarios ficticios: `analista1`, `analista2`, `supervisor`.
Clave exclusiva de demostración: `demo1234`. **No utilizarla para cuentas reales.**

## Comparación reproducible

| Caso | Variante vulnerable (5000) | Variante corregida (5001) |
|---|---|---|
| SQLi | supervisor + `severity=' OR '1'='1` devuelve 4 registros ficticios | Mismo valor devuelve 0 |
| XSS | `message=<img src=x onerror=alert(1)>` se inserta como HTML | Se muestra como texto escapado |
| IDOR | `analista1` consulta `/api/cases/2`, recibe 200 | Recibe 403; `/api/cases/1` devuelve 200 |

Pruebas de captura HTTP:

```bash
python scripts/http_demo.py --base http://127.0.0.1:5000
python scripts/http_demo.py --base http://127.0.0.1:5001
```

Para probar SQLi con los cuatro registros, iniciar sesión como `supervisor`.
La muestra inicial tiene 4 expedientes y no almacena datos auténticos.

## Evidencia automática de Flask

Con Flask instalado, el script `python scripts/run_flask_evidence.py` ejecuta
peticiones HTTP con el cliente de pruebas del propio framework, contrasta los
códigos de respuesta y guarda `evidencias/pruebas_flask.json`. También puede
utilizarse `bash scripts/run_full_demo.sh` en macOS/Linux para reunir las pruebas.
La comprobación de Flask y la inspección con OWASP ZAP son capas complementarias.

## OWASP ZAP
1. Iniciar ZAP Desktop. Usar Quick Start o navegador con proxy local.
2. Limitar el objetivo a `http://127.0.0.1:5000` y registrar las peticiones.
3. Iniciar sesión; recorrer los endpoints con cuentas didácticas, sin escanear dominios externos.
4. Repetir en `http://127.0.0.1:5001` con sesiones separadas.
5. Exportar resultados/alertas y distinguir hallazgos de ZAP de pruebas manuales.

## Mejora de monitoreo (Parte B, riesgo R6)
`logs/*_events.jsonl` almacena hora UTC, tipo de evento, usuario ficticio, resultado,
endpoint **sin parámetros** y estado HTTP. No registra contraseñas ni cookies.
Ejecutar `python scripts/event_report.py --demo` reproduce 3 denegaciones y una
alerta `R6_REPEAT_DENIAL`. El método es un detector didáctico local, no un SIEM.

## Evidencias
`evidencias/pruebas_motor.json` y `.txt`: ejecución del motor; el script genera un
archivo nuevo con resultados auténticos. `evidencias/alertas_seguridad.json`: regla R6.
Las capturas F01-F18 del informe se toman en el Mac durante la práctica.
Ver `PLAN_DE_CAPTURAS.md` para qué pantallas y resultados debe mostrar cada una.

## Seguridad y limitaciones
- No subir archivos `.env`, claves privadas, bases de datos de herramientas, sesiones de ZAP ni archivos binarios de GoPhish.
- No se envían correos reales ni se accede a redes ajenas.
- El cifrado de macOS, GoPhish y el tráfico previo están documentados en `../practicas_avance/` y son una etapa independiente.
- `SESSION_COOKIE_SECURE=False` permite la demostración por HTTP local, no producción; en Internet serían necesarios HTTPS, CSRF, autenticación corporativa, rotación de claves y un repositorio central protegido.
- El modo vulnerable siempre está limitado a `127.0.0.1`; jamás convertirlo en servicio público.

## Credenciales de demostración

`analista1`, `analista2` y `supervisor` usan la clave `demo1234`: es **ficticia**, exclusiva de este laboratorio
(127.0.0.1), no pertenece a ninguna cuenta real y no debe reutilizarse en ningún otro sistema.

## Regla R6 con ventana y su validación

La regla `R6_REPEAT_DENIAL` alerta si un usuario acumula 3 denegaciones de autorización dentro de una ventana
deslizante de 10 minutos (`classify(events, threshold=3, window_min=10)`).

```bash
python scripts/validate_r6.py                      # 6 casos: positivo, negativos, ventana y multiusuario
python scripts/event_report.py --window 10         # analiza logs/secure_events.jsonl
python -W error::ResourceWarning -m unittest discover -s tests -v   # 17 pruebas, sin avisos
```
