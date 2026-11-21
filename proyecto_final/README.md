# PROTOCOLO ZERO DAY | CFCC — Proyecto Final

Laboratorio académico de ciberseguridad desarrollado para el **Centro Federal de Coordinación de Continuidad (CFCC)**, una organización completamente ficticia creada con fines educativos.

El proyecto amplía las prácticas del avance hacia el análisis, identificación y mitigación de vulnerabilidades en aplicaciones web desarrolladas con Flask.

Incluye dos variantes de una misma aplicación:

- **Modo vulnerable:** contiene vulnerabilidades intencionales para su análisis controlado.
- **Modo seguro:** implementa medidas correctivas para demostrar la mitigación de dichas vulnerabilidades.

**ADVERTENCIA DE SEGURIDAD:** Todas las pruebas deben realizarse exclusivamente en un equipo propio, utilizando `127.0.0.1` (localhost). La aplicación vulnerable nunca debe publicarse en Internet ni desplegarse en redes de terceros.

---

## 1. Requisitos

Para ejecutar correctamente el proyecto se necesita:

- Python 3.10 o superior.
- Windows, macOS o Linux.
- Flask 3.1.2.
- Dependencias incluidas en `requirements.txt`.
- OWASP ZAP Desktop para inspeccionar manualmente el tráfico HTTP local.
- Una terminal con acceso a Python y permisos para ejecutar scripts.

No se requieren servidores externos, credenciales institucionales ni conexiones a servicios de terceros.

## 2. Instalación y preparación del entorno

Desde el directorio raíz `proyecto_final/`, crear un entorno virtual:

```bash
python3 -m venv .venv
```

Activar el entorno virtual.

**macOS / Linux:**

```bash
source .venv/bin/activate
```

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

Instalar las dependencias:

```bash
python -m pip install -r requirements.txt
```

Ejecutar las pruebas unitarias y generar las evidencias iniciales:

```bash
python -m unittest discover -s tests -v
python scripts/run_evidence.py
python scripts/event_report.py --demo
```

Estos comandos permiten comprobar el funcionamiento inicial del proyecto y generar los archivos de evidencia correspondientes.

## 3. Ejecución de las aplicaciones Flask

El proyecto utiliza dos servidores Flask independientes.

Abrir **dos terminales diferentes**, ambas ubicadas en `proyecto_final/`, con el entorno virtual activado.

### Terminal 1 — Variante vulnerable

```bash
python app.py --mode vulnerable --port 5000
```

Dirección:

http://127.0.0.1:5000/

### Terminal 2 — Variante segura

```bash
python app.py --mode secure --port 5001
```

Dirección:

http://127.0.0.1:5001/

Ambas aplicaciones deben permanecer ejecutándose mientras se realizan las pruebas HTTP.

### 3.1. Nota importante para usuarios de macOS: conflicto con el puerto 5000

En macOS 12 (Monterey) y versiones posteriores, el puerto TCP `5000` puede estar ocupado por el **Receptor de AirPlay**, un servicio asociado al Centro de Control del sistema operativo.

Este conflicto puede impedir que Flask utilice el puerto indicado o provocar respuestas HTTP `403 Forbidden` procedentes del servicio de macOS, en lugar de la aplicación del proyecto.

**Este comportamiento no representa una vulnerabilidad ni un error de Flask.**

Para comprobar si el puerto está ocupado:

```bash
lsof -nP -iTCP:5000 -sTCP:LISTEN
```

Si aparece un proceso como `ControlCe` o `ControlCenter`, se recomienda utilizar una de las siguientes alternativas.

**Opción A — Utilizar el puerto 5002 (recomendada)**

Ejecutar la variante vulnerable mediante:

```bash
python app.py --mode vulnerable --port 5002
```

Acceder desde:

http://127.0.0.1:5002/

La variante segura continúa funcionando en el puerto `5001`.

**Opción B — Desactivar temporalmente el Receptor de AirPlay**

En macOS, acceder a:

**Configuración del Sistema → General → AirDrop y Handoff (o AirDrop y Continuidad) → Receptor de AirPlay.**

Desactivar temporalmente el receptor y volver a ejecutar la aplicación en el puerto `5000`.

La ubicación y el nombre exacto de esta opción pueden variar dependiendo de la versión de macOS.

**Importante:** Si se utiliza el puerto alternativo `5002`, todas las pruebas manuales, direcciones del navegador y comandos HTTP de la variante vulnerable deben utilizar dicho puerto.

Los scripts automatizados que tengan puertos configurados internamente deben revisarse antes de ejecutarlos.

### 3.2. Verificación de los endpoints

Para comprobar que la aplicación segura responde correctamente:

```bash
curl -i http://127.0.0.1:5001/api/health
```

También puede abrirse directamente:

http://127.0.0.1:5001/api/health

La respuesta debe permitir identificar que está funcionando la variante segura, incluyendo el indicador `"mode": "secure"`.

Para comprobar la variante vulnerable en macOS utilizando el puerto alternativo:

```bash
curl -i http://127.0.0.1:5002/api/health
```

El indicador de modo esperado será `"mode": "vulnerable"`.

Se debe confirmar que las respuestas proceden de Flask y no de otro servicio local.

## 4. Usuarios y credenciales de demostración

La aplicación contiene tres usuarios ficticios:

| Usuario | Perfil |
|---|---|
| `analista1` | Analista de seguridad |
| `analista2` | Analista de seguridad |
| `supervisor` | Supervisor de expedientes |

Todos utilizan la siguiente contraseña de demostración:

```text
demo1234
```

Esta contraseña es ficticia, se utiliza únicamente para el laboratorio local y **no debe reutilizarse en cuentas reales ni sistemas productivos**.

La base de datos inicial contiene cuatro expedientes ficticios y no almacena información auténtica de personas u organizaciones.

## 5. Comparación reproducible de vulnerabilidades

El laboratorio permite analizar las diferencias entre una aplicación intencionalmente vulnerable y su versión corregida.

| Caso | Variante vulnerable | Variante segura |
|---|---|---|
| SQL Injection (SQLi) | El usuario `supervisor`, utilizando el filtro `severity=' OR '1'='1`, obtiene cuatro registros ficticios. | La misma entrada devuelve cero registros debido al tratamiento seguro de las consultas. |
| Cross-Site Scripting (XSS) | La entrada `message=<img src=x onerror=alert(1)>` se incorpora como HTML. | La entrada se muestra como texto escapado, evitando su interpretación como HTML ejecutable. |
| Insecure Direct Object Reference (IDOR) | `analista1` consulta `/api/cases/2` y recibe HTTP 200. | La misma consulta devuelve HTTP 403. La consulta autorizada a `/api/cases/1` devuelve HTTP 200. |

Estas pruebas se realizan exclusivamente sobre los datos ficticios incluidos en el proyecto.

### 5.1. Pruebas HTTP reproducibles

Con los dos servidores en ejecución, abrir una tercera terminal.

**Configuración original:**

```bash
python scripts/http_demo.py --base http://127.0.0.1:5000
python scripts/http_demo.py --base http://127.0.0.1:5001
```

**Configuración alternativa para macOS:**

```bash
python scripts/http_demo.py --base http://127.0.0.1:5002
python scripts/http_demo.py --base http://127.0.0.1:5001
```

Para comprobar la inyección SQL con los cuatro registros ficticios, iniciar sesión como `supervisor`.

Los resultados deben contrastarse entre ambas variantes para identificar las diferencias de comportamiento y los controles implementados.

## 6. Evidencia automática con Flask

El proyecto incluye un script de comprobación que utiliza el cliente de pruebas integrado de Flask.

Ejecutar:

```bash
python scripts/run_flask_evidence.py
```

El procedimiento realiza solicitudes HTTP internas, compara códigos de respuesta y guarda los resultados en:

```text
evidencias/pruebas_flask.json
```

En macOS y Linux también puede ejecutarse:

```bash
bash scripts/run_full_demo.sh
```

Este script reúne las pruebas previstas en el flujo completo de demostración.

**Nota:** Antes de ejecutar scripts que inicien servidores o utilicen direcciones HTTP fijas, verificar su configuración de puertos, especialmente si en macOS se cambió el puerto vulnerable a `5002`.

Las pruebas automáticas de Flask y la inspección mediante OWASP ZAP son mecanismos complementarios de validación.

## 7. Análisis mediante OWASP ZAP

OWASP ZAP se utiliza para observar las solicitudes y respuestas HTTP de la aplicación dentro del entorno local autorizado.

Procedimiento:

1. Abrir OWASP ZAP Desktop.
2. Iniciar una sesión de inspección mediante Quick Start o un navegador configurado con el proxy local.
3. Limitar el alcance exclusivamente a `http://127.0.0.1:5000` o `http://127.0.0.1:5002`, según la configuración utilizada.
4. Iniciar sesión con las cuentas ficticias del laboratorio.
5. Recorrer los endpoints y registrar las solicitudes y respuestas observadas.
6. Repetir las comprobaciones sobre `http://127.0.0.1:5001`, utilizando una sesión independiente.
7. Exportar los resultados pertinentes y documentar las diferencias entre ambas variantes.

Los hallazgos automáticos de ZAP deben distinguirse de las pruebas manuales y de los resultados obtenidos con los scripts de Flask.

No se deben escanear dominios externos, redes ajenas ni servicios distintos de los establecidos para este laboratorio.

## 8. Mejora de monitoreo — Parte B, riesgo R6

El proyecto incorpora un mecanismo didáctico de monitoreo para identificar intentos repetidos de acceso no autorizado.

Las bitácoras se almacenan en archivos con el siguiente patrón:

```text
logs/*_events.jsonl
```

Cada evento registra:

- Fecha y hora en UTC.
- Tipo de evento.
- Usuario ficticio asociado.
- Resultado de la operación.
- Endpoint solicitado, sin parámetros de consulta.
- Código de estado HTTP.

Por seguridad, las bitácoras no almacenan contraseñas ni cookies de sesión.

Para reproducir los eventos de demostración:

```bash
python scripts/event_report.py --demo
```

La ejecución genera tres denegaciones de autorización y permite comprobar la activación de la alerta:

```text
R6_REPEAT_DENIAL
```

Este mecanismo es un detector local con fines académicos y no constituye una plataforma SIEM empresarial.

## 9. Regla R6: ventana temporal y validación

La regla `R6_REPEAT_DENIAL` detecta cuando un mismo usuario acumula tres denegaciones de autorización dentro de una ventana temporal deslizante de diez minutos.

La configuración utilizada es:

```python
classify(events, threshold=3, window_min=10)
```

Para verificar su funcionamiento:

```bash
python scripts/validate_r6.py
```

El script comprueba seis escenarios, incluyendo casos positivos, negativos, comportamiento de la ventana temporal y separación de eventos entre múltiples usuarios.

Para analizar los registros de la variante segura:

```bash
python scripts/event_report.py --window 10
```

Para ejecutar las pruebas unitarias con advertencias `ResourceWarning` tratadas como errores:

```bash
python -W error::ResourceWarning -m unittest discover -s tests -v
```

La suite contempla 17 pruebas unitarias orientadas a verificar el comportamiento del proyecto.

La ejecución debe finalizar satisfactoriamente antes de dar por validada la entrega.

## 10. Evidencias y documentación

El proyecto genera y conserva evidencias de las pruebas realizadas.

| Archivo | Descripción |
|---|---|
| `evidencias/pruebas_motor.json` | Resultados estructurados de la ejecución del motor. |
| `evidencias/pruebas_motor.txt` | Resultados de ejecución en formato legible. |
| `evidencias/pruebas_flask.json` | Resultados de las comprobaciones realizadas con Flask. |
| `evidencias/alertas_seguridad.json` | Evidencia de la regla de monitoreo R6. |
| `PLAN_DE_CAPTURAS.md` | Guía de las capturas y evidencias visuales F01–F18. |

Los archivos de ejecución deben reflejar resultados reales obtenidos al correr los scripts, sin modificar manualmente sus valores para simular pruebas exitosas.

### 10.1. Capturas del informe F01–F18

Las capturas se realizan durante la práctica en macOS y deben mostrar de forma clara los comandos, respuestas y resultados correspondientes.

Cada evidencia debe permitir identificar:

- La acción realizada.
- El servidor o variante utilizada.
- El resultado observable.
- La relación entre la prueba y la vulnerabilidad o control evaluado.

### 10.2. Evidencia F02 — Verificación del endpoint seguro

La captura F02 debe mostrar claramente la respuesta del endpoint:

```text
http://127.0.0.1:5001/api/health
```

La respuesta debe ser visible y contener el indicador:

```json
"mode": "secure"
```

Antes de tomar la captura, comprobar que el navegador terminó de cargar la respuesta y que el texto es legible.

No deben incorporarse capturas de ventanas negras, páginas sin cargar o imágenes que no permitan verificar el resultado.

Como comprobación complementaria puede utilizarse:

```bash
curl -i http://127.0.0.1:5001/api/health
```

La evidencia visual debe corresponder a una ejecución real de la aplicación.

## 11. Limpieza del repositorio y control de versiones

Para mantener el repositorio limpio y evitar la publicación de archivos temporales, se recomienda utilizar Git junto con un archivo `.gitignore`.

Este archivo debe encontrarse en la raíz del proyecto e incluir, como mínimo:

```gitignore
# Entornos virtuales
.venv/
venv/

# Archivos de Python
__pycache__/
*.py[cod]
.pytest_cache/

# Archivos generados por macOS
.DS_Store
__MACOSX/

# Archivos temporales
*.tmp
*.log

# Variables y secretos locales
.env
.env.*

# Bitácoras locales de ejecución
logs/*.jsonl

# Archivos de editores
.vscode/
.idea/
```

Las evidencias académicas requeridas para la evaluación deben conservarse y versionarse únicamente cuando formen parte de los entregables autorizados.

### 11.1. Verificación previa a la entrega

Antes de realizar un commit o generar el archivo ZIP:

1. Confirmar que `.venv/` no esté incluido en el repositorio.
2. Eliminar archivos `.DS_Store` y directorios `__MACOSX/` del paquete de entrega.
3. Excluir directorios `__pycache__/` y otros archivos temporales.
4. Verificar que no existan contraseñas reales, archivos `.env` o credenciales privadas.
5. Conservar los archivos fuente, documentación, pruebas y evidencias solicitadas.

Para revisar los cambios pendientes de Git:

```bash
git status --short
```

Para comprobar los archivos que Git tiene registrados:

```bash
git ls-files
```

**Importante:** `.gitignore` evita incorporar nuevos archivos coincidentes, pero no elimina automáticamente archivos que ya fueron versionados.

Si un directorio no deseado ya está registrado en Git, debe retirarse del índice sin eliminar necesariamente su copia local. Por ejemplo, si `.venv/` está versionado:

```bash
git rm -r --cached .venv
```

Después se deben revisar los cambios y confirmar la limpieza mediante un commit.

También debe revisarse el contenido del ZIP final, ya que `.gitignore` no impide por sí solo que una herramienta de compresión incluya archivos ignorados.

## 12. Seguridad y limitaciones

Este proyecto está diseñado únicamente para demostrar vulnerabilidades y controles de seguridad en un entorno académico controlado.

Se establecen las siguientes restricciones:

- No publicar archivos `.env`, claves privadas, tokens, sesiones, bases de datos de herramientas ni información confidencial.
- No incluir en el repositorio bases de datos de OWASP ZAP ni archivos binarios de GoPhish.
- No enviar correos electrónicos reales durante las pruebas.
- No ejecutar pruebas contra redes, dominios o servicios de terceros.
- No utilizar cuentas ni datos personales auténticos.
- Ejecutar la variante vulnerable exclusivamente en la interfaz local `127.0.0.1`.
- No considerar la variante segura como una aplicación preparada para producción sin controles adicionales.

La configuración:

```python
SESSION_COOKIE_SECURE = False
```

se utiliza únicamente para permitir la demostración mediante HTTP local.

En un entorno productivo sería necesario implementar, entre otras medidas:

- HTTPS obligatorio y cookies de sesión seguras.
- Protección contra Cross-Site Request Forgery (CSRF).
- Gestión robusta de autenticación y autorización.
- Administración y rotación segura de secretos.
- Políticas de control de acceso.
- Monitoreo y almacenamiento centralizado de registros.
- Validación continua de la seguridad de la aplicación.

Las prácticas anteriores relacionadas con cifrado de macOS, GoPhish y análisis de tráfico están documentadas en:

```text
../practicas_avance/
```

Estas actividades corresponden a una etapa independiente del proyecto.


---

## 13. Consideraciones finales

**PROTOCOLO ZERO DAY | CFCC** es un laboratorio educativo que permite comparar comportamientos vulnerables y seguros, analizar solicitudes HTTP y aplicar mecanismos básicos de monitoreo.

Su finalidad es fortalecer la comprensión práctica de la seguridad de aplicaciones web mediante ejercicios reproducibles en un entorno completamente controlado.

Todos los usuarios, expedientes, credenciales y escenarios utilizados son ficticios.

**Uso exclusivo académico. No desplegar la aplicación vulnerable fuera de localhost.**