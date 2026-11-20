# PROTOCOLO ZERO DAY

**Laboratorio de ciberseguridad | Centro Federal de Coordinación de Continuidad (CFCC)**

**Proyecto académico integral de evaluación, corrección y verificación de controles de seguridad.**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1.2-111827?logo=flask&logoColor=white)
![OWASP ZAP](https://img.shields.io/badge/An%C3%A1lisis-OWASP%20ZAP-164E63)
![Entorno](https://img.shields.io/badge/Entorno-Localhost-1D4ED8)
![Estado](https://img.shields.io/badge/Proyecto-Finalizado-15803D)

---

## Presentación

**PROTOCOLO ZERO DAY** es un proyecto académico de ciberseguridad desarrollado en equipo para estudiar la protección de sistemas, la gestión de accesos, el análisis de tráfico y la seguridad de aplicaciones web.

El caso de estudio se desarrolla alrededor del **Centro Federal de Coordinación de Continuidad (CFCC)**, una **organización completamente ficticia** utilizada como contexto institucional. El proyecto reúne prácticas de seguridad defensiva y un laboratorio funcional en Python y Flask que permite observar una vulnerabilidad, aplicar su corrección y comprobar el resultado mediante pruebas reproducibles.

El sistema utiliza exclusivamente **cuentas, expedientes y eventos de demostración**. No representa una infraestructura gubernamental real ni requiere conexiones a servicios externos.

## Objetivo

Evaluar riesgos y controles de seguridad mediante un proceso verificable de **identificación, análisis, comprobación, mitigación y monitoreo**, integrando ejercicios técnicos, evidencia de ejecución y una aplicación web con dos implementaciones comparables.

## Trabajo desarrollado

El proyecto se organizó en dos etapas complementarias:

### 01 · Evaluación de controles y seguridad operativa

En la primera etapa, el equipo realizó prácticas locales de:

- **Respaldos y restauración:** comprobación de recuperación de archivos de muestra.
- **Control de acceso basado en roles (RBAC):** verificación de operaciones permitidas y denegadas con perfiles ficticios.
- **Protección de información e integridad:** revisión de cifrado y comprobaciones mediante SHA-256.
- **Reconocimiento de red:** identificación de puertos y servicios locales con Nmap.
- **Análisis de tráfico:** captura e interpretación de comunicaciones de laboratorio con Wireshark.
- **Concientización ante phishing:** simulación controlada con GoPhish y Mailpit, empleando únicamente destinatarios ficticios y sin recopilar contraseñas.

Los scripts y registros de esta etapa se encuentran en **practicas_avance/**.

### 02 · Seguridad de aplicaciones y monitoreo

En la segunda etapa, el equipo implementó un portal web institucional de demostración con **dos variantes ejecutadas en paralelo**:

| Entorno | Dirección local | Propósito |
| --- | --- | --- |
| Vulnerable | http://127.0.0.1:5000 | Reproducir fallas deliberadas de seguridad |
| Corregido | http://127.0.0.1:5001 | Verificar los controles que mitigan esas fallas |

Se analizaron tres escenarios:

| Escenario | Comportamiento vulnerable | Control implementado |
| --- | --- | --- |
| **SQL Injection** | Construcción de consultas SQL mediante concatenación | Consultas parametrizadas y filtrado por usuario |
| **Cross-Site Scripting (XSS)** | Inserción de contenido de entrada como HTML | Escape de salida HTML y política Content Security Policy |
| **IDOR / BOLA** | Acceso a expedientes ajenos mediante su identificador | Validación de autorización por recurso y rol |

También se desarrolló una **bitácora estructurada de eventos** y la regla didáctica **R6_REPEAT_DENIAL**, que emite una alerta de severidad media al encontrar **tres o más denegaciones de autorización asociadas a un mismo usuario** dentro del conjunto de registros analizado.

## Arquitectura del laboratorio

La solución se ejecuta íntegramente en la computadora del participante:

- **Interfaz:** portal web CFCC con estilo institucional Navy Blue.
- **Servidor:** Python y Flask, con sesiones independientes para cada variante.
- **Lógica de negocio y seguridad:** módulo reutilizable en **cfcc_lab/core.py**.
- **Datos:** SQLite en memoria, con cuatro expedientes ficticios regenerados en cada conexión.
- **Auditoría:** registros JSON Lines (**JSONL**) con fecha UTC, usuario de prueba, evento, resultado y código HTTP.
- **Análisis HTTP:** OWASP ZAP como proxy local para observar solicitudes y respuestas.
- **Validación:** pruebas unitarias y pruebas de endpoints mediante el cliente de pruebas de Flask.

Las aplicaciones escuchan exclusivamente en **127.0.0.1**. La versión deliberadamente vulnerable se utiliza únicamente dentro de este entorno autorizado.

## Estructura del repositorio

~~~text
.
├── practicas_avance/
│   ├── datos/                  # Archivos ficticios de trabajo
│   ├── respaldo/               # Copia de seguridad de muestra
│   ├── restaurado/             # Comprobación de restauración
│   ├── rbac/                   # Pruebas de permisos
│   ├── evidencias/             # Registros de prácticas locales
│   └── captura_local.py        # Herramienta auxiliar de captura
│
├── proyecto_final/
│   ├── app.py                  # Portal Flask y endpoints HTTP
│   ├── cfcc_lab/core.py        # Motor de datos, controles y auditoría
│   ├── static/                 # Identidad gráfica CFCC
│   ├── scripts/                # Automatización, reportes y demostraciones
│   ├── tests/                  # Pruebas unitarias y de integración HTTP
│   ├── evidencias/             # Resultados generados por los scripts
│   ├── logs/                   # Registros locales de ejecución
│   ├── requirements.txt        # Dependencias Python
│   └── README.md               # Documentación técnica del laboratorio
│
└── README.md
~~~

## Requisitos

- **Python 3.10 o superior**.
- **Git**, para obtener el repositorio.
- **Flask 3.1.2**, instalado mediante el archivo de dependencias.
- **macOS, Windows o Linux**.
- **OWASP ZAP Desktop** (opcional, para inspeccionar el tráfico HTTP).

No se requiere una base de datos externa, un servidor remoto ni una cuenta institucional.

## Instalación

Clonar el repositorio e ingresar al directorio de la aplicación:

~~~bash
git clone https://github.com/zeusacad/proyectofinal-ciberseguridad.git
cd proyectofinal-ciberseguridad/proyecto_final
python3 -m venv .venv
~~~

**Activar el entorno virtual:**

macOS / Linux:

~~~bash
source .venv/bin/activate
~~~

Windows (PowerShell):

~~~powershell
.venv\Scripts\Activate.ps1
~~~

Instalar dependencias:

~~~bash
python -m pip install -r requirements.txt
~~~

## Ejecución

Desde **proyecto_final/**, abrir **dos terminales independientes** con el entorno virtual activo.

**Terminal 1 — Variante vulnerable:**

~~~bash
python app.py --mode vulnerable --port 5000
~~~

**Terminal 2 — Variante corregida:**

~~~bash
python app.py --mode secure --port 5001
~~~

Abrir los siguientes enlaces en el navegador:

- **Variante vulnerable:** http://127.0.0.1:5000
- **Variante corregida:** http://127.0.0.1:5001

### Credenciales de demostración

| Usuario | Perfil |
| --- | --- |
| analista1 | Analista de expedientes |
| analista2 | Analista de expedientes |
| supervisor | Supervisor de expedientes |

**Contraseña compartida, únicamente para el laboratorio:** **demo1234**.

Estas identidades son ficticias y no deben reutilizarse en sistemas reales.

## Resultados de las pruebas de seguridad

Las comprobaciones del laboratorio contrastan exactamente la misma entrada en ambas variantes:

| Prueba | Variante vulnerable | Variante corregida |
| --- | --- | --- |
| **SQL Injection**, como supervisor | **4** registros devueltos | **0** registros devueltos |
| **XSS**, vista previa de nota | Contenido interpretado como HTML | Contenido mostrado como texto escapado |
| **IDOR/BOLA**, analista1 solicita el expediente 2 | **HTTP 200** | **HTTP 403** |
| **Acceso legítimo**, analista1 solicita el expediente 1 | — | **HTTP 200** |

Los cuatro expedientes están definidos expresamente para la simulación; ninguna respuesta contiene datos institucionales reales.

## Pruebas automatizadas

Con las dependencias instaladas, desde **proyecto_final/**:

**Ejecutar la suite completa (17 pruebas):**

~~~bash
python -m unittest discover -s tests -v
~~~

La suite incluye **12 pruebas del motor de seguridad** y **5 pruebas HTTP de Flask**.

**Generar el reporte del motor:**

~~~bash
python scripts/run_evidence.py
~~~

**Generar la comparación automática de endpoints:**

~~~bash
python scripts/run_flask_evidence.py
~~~

Los resultados se escriben en **evidencias/pruebas_motor.json**, **evidencias/pruebas_motor.txt** y **evidencias/pruebas_flask.json**, respectivamente.

En macOS/Linux también puede ejecutarse la comprobación agrupada:

~~~bash
bash scripts/run_full_demo.sh
~~~

## Monitoreo y alertas

Cada aplicación registra eventos de autenticación, consultas, autorizaciones y acceso a las funciones de demostración. Las bitácoras se almacenan localmente en formato **JSONL**.

Para procesar los eventos de la variante corregida:

~~~bash
python scripts/event_report.py --log logs/secure_events.jsonl
~~~

Para generar una demostración reproducible de la regla R6 con tres denegaciones ficticias:

~~~bash
python scripts/event_report.py --demo
~~~

El reporte se guarda en **evidencias/alertas_seguridad.json** e identifica el usuario de prueba, el número de denegaciones, la regla activada y su severidad.

**R6_REPEAT_DENIAL es una regla local de detección con fines académicos; no constituye un sistema SIEM de producción.**

## Análisis de tráfico con OWASP ZAP

Con Flask y ZAP iniciados, es posible enviar tráfico al proxy local sin modificar el proxy general de macOS. Si ZAP está escuchando en **127.0.0.1:8080**, ejecutar:

~~~bash
curl --noproxy "" --proxy http://127.0.0.1:8080 http://127.0.0.1:5000/api/health
~~~

Repetir para la variante corregida:

~~~bash
curl --noproxy "" --proxy http://127.0.0.1:8080 http://127.0.0.1:5001/api/health
~~~

Las solicitudes pueden inspeccionarse en **History / Historial** de ZAP, donde se revisan rutas, encabezados, parámetros y códigos de respuesta. Las comprobaciones de SQL Injection, XSS e IDOR/BOLA se documentaron mediante pruebas controladas; **no se atribuyen a una detección automática de ZAP**.

## Metodología y trabajo en equipo

El desarrollo integró actividades complementarias de **análisis de riesgos, diseño del entorno de simulación, programación, ejecución de pruebas, validación de correcciones y documentación de evidencias**.

El procedimiento adoptado por el equipo fue:

1. **Identificar** activos, amenazas y controles relevantes para el caso ficticio CFCC.
2. **Reproducir** escenarios de seguridad en un entorno local y controlado.
3. **Implementar** medidas correctivas sobre la lógica de la aplicación.
4. **Comparar** los resultados antes y después de aplicar cada control.
5. **Registrar y analizar** eventos para demostrar la detección de patrones de acceso no autorizado.
6. **Verificar** los resultados mediante pruebas automatizadas y análisis de solicitudes HTTP.

De esta forma, el proyecto conecta la evaluación técnica de los controles con la implementación, la comprobación reproducible y la interpretación de evidencias.

## Tecnologías utilizadas

**Python · Flask · SQLite · unittest · HTML/CSS · Git · GitHub · OWASP ZAP · curl · Nmap · Wireshark · GoPhish · Mailpit**

## Uso responsable

> **Proyecto académico con vulnerabilidades intencionales.** El CFCC es una organización ficticia y el portal es un sistema de demostración. El modo vulnerable solo debe ejecutarse en **localhost**, con las cuentas y los datos suministrados para este laboratorio. No debe exponerse públicamente ni utilizarse contra sistemas de terceros.

La variante corregida demuestra mitigaciones concretas dentro del alcance de las prácticas; **no debe confundirse con una aplicación certificada o preparada para producción**.

---

**PROTOCOLO ZERO DAY · CFCC · 2026**  
*Identificar. Corregir. Verificar. Evidenciar.*
