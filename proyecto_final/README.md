# PROTOCOLO ZERO DAY | CFCC — Proyecto final

Laboratorio académico de seguridad de aplicaciones desarrollado por nuestro equipo para el **Centro Federal de Coordinación de Continuidad (CFCC)**, organización completamente ficticia. Las variantes vulnerable y segura se ejecutan **solo en `127.0.0.1`**, con cuatro expedientes inventados y tres cuentas de demostración. La versión vulnerable contiene fallas deliberadas y jamás debe publicarse en Internet o redes de terceros.

## Requisitos e instalación

- Python 3.10 o superior; Windows, macOS o Linux.
- Flask 3.1.2 (incluido en `requirements.txt`).
- OWASP ZAP Desktop únicamente para la inspección manual local y su reporte independiente.

Desde `proyecto_final/`:

```bash
python3 -m venv .venv
source .venv/bin/activate          # macOS y Linux
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Ejecutamos primero las pruebas y la generación de evidencia. Estos comandos no dependen de servidores externos:

```bash
python -W error::ResourceWarning -m unittest discover -s tests -v
python scripts/run_evidence.py
python scripts/run_flask_evidence.py
python scripts/validate_r6.py
python scripts/complete_lab_evidence.py
python scripts/event_report.py --demo
python scripts/verify_log.py evidencias/sesion_http_segura.jsonl
```

La suite contempla **35 pruebas** (22 de núcleo y 13 de endpoints Flask) y el validador **12 escenarios** de las reglas R6 y R1. También se puede utilizar `bash scripts/run_full_demo.sh` en macOS o Linux. Los archivos generados en `evidencias/` se obtienen de ejecuciones locales y deben conservarse sin alterar sus valores.

## Servidores locales

En dos terminales distintas, ubicadas en `proyecto_final/` y con el entorno activado:

```bash
python app.py --mode vulnerable --port 5000
```

```bash
python app.py --mode secure --port 5001
```

Abrimos las aplicaciones desde `http://127.0.0.1:5000/` y `http://127.0.0.1:5001/`. Para verificar el servicio usamos `/api/health` y comprobamos la clave `mode` en cada respuesta (`vulnerable` o `secure`).

**Puerto 5000 en macOS.** En macOS 12 y posterior, el Receptor de AirPlay puede ocupar el puerto TCP 5000 y producir respuestas de otro servicio, incluso HTTP 403. Como equipo elegimos utilizar el puerto **5002** cuando esto ocurre:

```bash
lsof -nP -iTCP:5000 -sTCP:LISTEN
python app.py --mode vulnerable --port 5002
```

La alternativa es desactivar temporalmente Receptor de AirPlay en Configuración del Sistema → General → AirDrop y Handoff / AirDrop y Continuidad (el nombre varía según macOS). Si se utiliza `5002`, las consultas y pruebas HTTP de la variante vulnerable deben cambiar a ese puerto; en `verificar.sh` se permite usar `V_PORT=5002 bash verificar.sh`.

Las cuentas **`analista1`**, **`analista2`** y **`supervisor`** utilizan la contraseña ficticia **`demo1234`** únicamente dentro de localhost. Nunca debe emplearse en un sistema real.

## Comparación de controles

| Prueba | Variante vulnerable | Variante segura |
|---|---|---|
| SQLi por condición OR verdadera (analista1) | Cuatro expedientes; se observan dos propietarios | Cero expedientes; SQL parametrizado y filtrado por propietario |
| SQLi con UNION SELECT de cinco columnas | Una fila sintética id 99 | Cero filas |
| Listado de severidad `media` (analista1) | Expone el expediente ajeno 2 sin inyección | No devuelve expedientes ajenos |
| XSS por `message=<img src=x onerror=alert(1)>` | Inserción HTML no escapada | Salida escapada como texto y CSP complementaria |
| IDOR de `/api/cases/2` con analista1 | HTTP 200 | HTTP 404 con `not_found` |
| Objeto inexistente `/api/cases/99` | HTTP 404 | HTTP 404 con la misma respuesta pública |
| Objeto propio `/api/cases/1` | HTTP 200 | HTTP 200 |
| `severity` de 100 caracteres | No aplica la validación de longitud del modo seguro | HTTP 400 y evento `validation denied` |

La autorización segura ocurre dentro de la consulta SQL mediante el criterio `owner = ? OR ? = 'supervisor'`. En la consulta por ID, la aplicación no distingue públicamente los objetos ajenos de los inexistentes, pero conserva la razón interna de la denegación en el registro.

Para comparar las variantes con servidores abiertos, utilizamos:

```bash
bash verificar.sh                 # puertos 5000 y 5001
V_PORT=5002 bash verificar.sh     # macOS con AirPlay en 5000
```

El script `scripts/complete_lab_evidence.py` reproduce las comparaciones con el cliente local de Flask, guarda `evidencias/reporte_http.json`, `evidencias/resultados_http.txt` y dos bitácoras independientes. Ese resultado **no** se presenta como un informe de OWASP ZAP.

## Monitoreo y registros

Como equipo implementamos dos reglas de ventana deslizante de diez minutos:

- `R6_REPEAT_DENIAL`: al menos tres denegaciones de autorización de un usuario.
- `R1_REPEAT_AUTH_FAIL`: al menos cinco autenticaciones fallidas de un usuario.

Las alertas incluyen `first_ts`, `last_ts`, `count_in_window`, un total acumulado separado y severidad. Puede elevarse a alta con diez eventos en la ventana, un usuario supervisor o tres expedientes distintos. Los eventos incluyen el origen local para identificar patrones entre cuentas. El panel `/events` es accesible únicamente por `supervisor` y muestra el registro reciente y las alertas R6/R1.

Los logs no guardan contraseñas, cookies ni el contenido de los parámetros. Los nombres de usuario desconocidos durante un login fallido se pseudonimizan y las entradas con patrones SQL/HTML producen una señal `validation flagged` que conserva solamente la categoría y longitud; **es una heurística didáctica, no un detector exhaustivo de inyecciones**. Los registros nuevos incorporan un encadenamiento SHA-256 verificable con `scripts/verify_log.py`; permite detectar alteraciones simples, pero no ofrece almacenamiento inmutable ni protección contra quien pueda rehacer toda la cadena.

La muestra reproducible generada con `scripts/complete_lab_evidence.py` utiliza 19 eventos HTTP y demuestra una alerta R6 y otra R1. `scripts/event_report.py --demo` crea por separado una muestra **sintética** de nueve eventos, para no confundirla con la secuencia HTTP. Las pruebas de umbral de `validate_r6.py` son también sintéticas, mientras que las pruebas Flask incluyen verificaciones de extremo a extremo.

## OWASP ZAP Desktop

La inspección en ZAP es complementaria y **requiere ejecutarse y exportarse realmente** en el equipo donde se encuentra instalada la herramienta; no debe sustituirse por capturas recreadas o por JSON del cliente Flask.

1. Iniciamos ZAP Desktop y Quick Start → Manual Explore, con navegador configurado mediante el proxy de la herramienta.
2. Limitamos el alcance a `http://127.0.0.1:5000` o `http://127.0.0.1:5002`, sin destinos externos y sin incluir el puerto seguro en el escaneo activo.
3. Autenticamos una sesión local con `analista1` y recorremos `/api/health`, `/api/cases`, `/preview` y `/api/cases/2`.
4. Conservamos en History las solicitudes SQLi y XSS y examinamos la pestaña Alerts. Si realizamos Active Scan, lo hacemos solo contra el servidor vulnerable y con su bitácora aislada de las muestras R6/R1.
5. Repetimos la comparación manual en el puerto `5001` con una sesión separada. Documentamos URL, parámetro, riesgo, evidencia y confirmación manual de cada alerta (incluidas las alertas no confirmadas).
6. Exportamos desde ZAP el reporte real en HTML o JSON a `evidencias/` y añadimos la interpretación al informe académico **separado del ZIP**. Si una regla no encuentra una vulnerabilidad conocida, consignamos explícitamente la diferencia entre detección automática y prueba manual.

No se deben inventar alertas o contabilizar hallazgos que no aparezcan en la salida original de la herramienta.

## Archivos de evidencia y alcance

- `pruebas_motor.json` y `.txt`: resultados reales del núcleo.
- `pruebas_flask.json`: comparación reproducible de los tres endpoints principales.
- `validacion_r6.json`: doce escenarios R6/R1.
- `reporte_http.json` y `resultados_http.txt`: resultados y resumen del cliente Flask.
- `sesion_http_segura.jsonl` y `sesion_http_vulnerable.jsonl`: bitácoras locales independientes de los ensayos HTTP.
- `alertas_seguridad.json` y `eventos_demo.jsonl`: demostración sintética independiente del informe HTTP.

Mantenemos los resultados del avance en la documentación de las prácticas anteriores, sin considerarlos pruebas de sistemas de una institución real. El modo seguro tampoco constituye un despliegue de producción: el laboratorio emplea HTTP sin TLS, `SESSION_COOKIE_SECURE=False`, sesiones Flask firmadas en cliente, credenciales ficticias y SQLite en memoria. Para un sistema real se necesitarían HTTPS, cookies seguras, protección CSRF, manejo de contraseñas y sesiones revocables, infraestructura de monitorización y políticas de retención protegida.

**Uso exclusivo académico, local y autorizado.**
