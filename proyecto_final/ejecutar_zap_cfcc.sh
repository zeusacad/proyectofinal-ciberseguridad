#!/usr/bin/env bash
# CFCC — escaneo real de OWASP ZAP con Automation Framework (macOS, ejecución local)
# Uso desde la carpeta proyecto_final: bash ejecutar_zap_cfcc.sh vulnerable|secure
set -euo pipefail

MODE="${1:-}"
case "$MODE" in
  vulnerable) PORT=5002 ;;
  secure) PORT=5001 ;;
  *) echo 'Uso: bash ejecutar_zap_cfcc.sh vulnerable|secure'; exit 2 ;;
esac

BASE="http://127.0.0.1:${PORT}"
if [[ -n "${ZAP_SCRIPT:-}" && -f "$ZAP_SCRIPT" ]]; then
  ZAP="$ZAP_SCRIPT"
elif [[ -f /Applications/ZAP.app/Contents/Java/zap.sh ]]; then
  ZAP=/Applications/ZAP.app/Contents/Java/zap.sh
elif [[ -f '/Applications/OWASP ZAP.app/Contents/Java/zap.sh' ]]; then
  ZAP='/Applications/OWASP ZAP.app/Contents/Java/zap.sh'
elif command -v zap.sh >/dev/null 2>&1; then
  ZAP="$(command -v zap.sh)"
else
  echo 'No encuentro OWASP ZAP. Instala ZAP Desktop para macOS o define ZAP_SCRIPT=/ruta/a/zap.sh'
  exit 1
fi

if ! curl --noproxy '*' -fsS "${BASE}/api/health" | grep -q '"mode":"'"$MODE"'"'; then
  echo "El servidor ${MODE} no responde correctamente en ${BASE}. Inicia Flask primero."
  exit 1
fi

OUT="$(pwd)/evidencias/zap_${MODE}"
mkdir -p "$OUT"
PLAN="$OUT/plan_zap_${MODE}.yaml"
cat > "$PLAN" <<YAML
env:
  contexts:
    - name: CFCC_${MODE}
      urls:
        - "${BASE}/"
      includePaths:
        - 'http://127[.]0[.]0[.]1:${PORT}/.*'
      excludePaths:
        - 'http://127[.]0[.]0[.]1:${PORT}/logout.*'
      authentication:
        method: form
        parameters:
          loginPageUrl: "${BASE}/login"
          loginRequestUrl: "${BASE}/login"
          loginRequestBody: 'username={%username%}&password={%password%}'
        verification:
          method: poll
          pollUrl: "${BASE}/dashboard"
          pollFrequency: 2
          pollUnits: requests
          loggedInRegex: 'SESIÓN AUTENTICADA'
          loggedOutRegex: 'IDENTIFICACIÓN DE USUARIO'
      sessionManagement:
        method: cookie
      users:
        - name: analista1
          credentials:
            username: analista1
            password: demo1234
  parameters:
    failOnError: true
    failOnWarning: false
    progressToStdout: true
jobs:
  - type: requestor
    parameters:
      user: analista1
    requests:
      - {url: "${BASE}/dashboard", name: "panel autenticado", method: GET, responseCode: 200}
      - {url: "${BASE}/api/cases?severity=alta", name: "SQLi campo severity", method: GET, responseCode: 200}
      - {url: "${BASE}/api/cases?severity=media", name: "listado y propiedad", method: GET, responseCode: 200}
      - {url: "${BASE}/api/cases/1", name: "expediente propio", method: GET, responseCode: 200}
      - {url: "${BASE}/preview?message=Nota%20de%20prueba", name: "XSS campo message", method: GET, responseCode: 200}
      - {url: "${BASE}/api/cases?severity=%27%20OR%20%271%27%3D%271", name: "SQLi manual verificado por ZAP", method: GET, responseCode: 200}
      - {url: "${BASE}/preview?message=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E", name: "XSS manual verificado por ZAP", method: GET, responseCode: 200}
  - type: spider
    parameters:
      context: CFCC_${MODE}
      user: analista1
      url: "${BASE}/dashboard"
      maxDuration: 2
  - type: passiveScan-wait
    parameters:
      maxDuration: 2
  - type: activeScan
    parameters:
      context: CFCC_${MODE}
      user: analista1
      maxScanDurationInMins: 5
      maxRuleDurationInMins: 1
      defaultStrength: Medium
      defaultThreshold: Medium
  - type: passiveScan-wait
    parameters:
      maxDuration: 2
  - type: report
    parameters:
      template: traditional-html
      reportDir: "$OUT"
      reportFile: "reporte_zap_${MODE}.html"
      reportTitle: "CFCC - OWASP ZAP - ${MODE}"
      displayReport: false
  - type: report
    parameters:
      template: traditional-json
      reportDir: "$OUT"
      reportFile: "reporte_zap_${MODE}.json"
      reportTitle: "CFCC - OWASP ZAP - ${MODE}"
      displayReport: false
YAML

printf '\nCFCC: análisis %s en %s\n' "$MODE" "$BASE"
printf 'ZAP: %s\nPlan: %s\n\n' "$ZAP" "$PLAN"
set +e
"$ZAP" -cmd -autorun "$PLAN" 2>&1 | tee "$OUT/ejecucion_zap_${MODE}.log"
STATUS=${PIPESTATUS[0]}
set -e
printf '\nEstado de salida ZAP: %s\n' "$STATUS"
for f in "$OUT/reporte_zap_${MODE}.html" "$OUT/reporte_zap_${MODE}.json"; do
  if [[ -s "$f" ]]; then echo "GENERADO: $f"; else echo "NO GENERADO: $f"; fi
done
if [[ "$STATUS" -ne 0 && "$STATUS" -ne 2 ]]; then
  echo 'ZAP notificó un error: revisa la bitácora y la autenticación; NO presentes el escaneo como completado.'
  exit "$STATUS"
fi
if [[ ! -s "$OUT/reporte_zap_${MODE}.json" ]]; then
  echo 'No se generó el reporte JSON: el análisis no se considera cerrado.'
  exit 1
fi
printf '\nRevisa el log y los hallazgos; valida que las rutas autenticadas se hayan explorado.\n'
