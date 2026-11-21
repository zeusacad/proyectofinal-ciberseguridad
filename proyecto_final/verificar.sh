#!/usr/bin/env bash
# verificar.sh - Verificación del laboratorio CFCC (SQLi, XSS, IDOR/BOLA)
# USO: solo contra el laboratorio local (127.0.0.1) con datos ficticios.
#
#   1) Levanta las dos variantes (5000 vulnerable, 5001 secure) según el README.
#   2) Ejecuta desde la raíz del proyecto:  bash verificar.sh
#
# Opciones:
#   --zap        Ejecuta ZAP baseline (pasivo) contra el puerto 5000 con Docker
#   --log-test   Genera un login fallido con un "username" sospechoso y revisa si
#                la bitácora lo guarda crudo. OJO: agrega eventos a logs/ y
#                cambia el conteo de 23 eventos. Respalda la bitácora antes.
#
# Rutas, parámetros y credenciales salen del informe de los alumnos;
# ajusta las variables de abajo si el repositorio difiere.

HOST="127.0.0.1"; V=5000; S=5001
USER1="analista1"; SUP="supervisor"; PASS="demo1234"
LOGFILE="logs/secure_events.jsonl"
DO_ZAP=0; DO_LOG=0
for a in "$@"; do
  [ "$a" = "--zap" ] && DO_ZAP=1
  [ "$a" = "--log-test" ] && DO_LOG=1
done

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
REPORT="reporte_verificacion_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee "$REPORT") 2>&1

G="\033[32m"; R="\033[31m"; Y="\033[33m"; B="\033[1m"; N="\033[0m"
PASSN=0; FAILN=0; INFON=0
ok()   { echo -e "  ${G}[PASA]${N}  $1"; PASSN=$((PASSN+1)); }
fail() { echo -e "  ${R}[FALLA]${N} $1"; FAILN=$((FAILN+1)); }
info() { echo -e "  ${Y}[INFO]${N}  $1"; INFON=$((INFON+1)); }
title(){ echo -e "\n${B}== $1 ==${N}"; }

url()    { echo "http://$HOST:$1$2"; }
code()   { curl -s -o /dev/null -w "%{http_code}" "$@"; }
count()  { python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("count","?"))
except Exception: print("?")'; }
login()  { # puerto usuario archivo_cookie
  curl -s -c "$3" -d "username=$2" -d "password=$PASS" -o /dev/null -w "%{http_code}" "$(url "$1" /login)"; }

echo -e "${B}Verificación laboratorio CFCC${N}  $(date '+%Y-%m-%d %H:%M:%S')"
echo "Objetivos: vulnerable=$HOST:$V  secure=$HOST:$S"

# ---------------------------------------------------------------- 0. Estado
title "0. Estado de las variantes"
hv=$(curl -s "$(url $V /api/health)"); hs=$(curl -s "$(url $S /api/health)")
echo "  5000 -> $hv"; echo "  5001 -> $hs"
echo "$hv" | grep -q '"vulnerable"' && ok "5000 responde mode=vulnerable" || fail "5000 no responde como vulnerable (¿está levantada?)"
echo "$hs" | grep -q '"secure"'     && ok "5001 responde mode=secure"     || fail "5001 no responde como secure (¿está levantada?)"

for p in $V $S; do
  c=$(login $p $USER1 "$TMP/a$p.txt"); [ "$c" = "302" ] && ok "login $USER1 en $p (302)" || fail "login $USER1 en $p devolvió $c"
  c=$(login $p $SUP   "$TMP/s$p.txt"); [ "$c" = "302" ] && ok "login $SUP en $p (302)"   || fail "login $SUP en $p devolvió $c"
done

# ---------------------------------------------------------------- 1. SQLi
title "1. SQL Injection  (GET /api/cases?severity=)"
P="' OR '1'='1"
cv=$(curl -s -b "$TMP/s$V.txt" -G --data-urlencode "severity=$P" "$(url $V /api/cases)" | count)
cs=$(curl -s -b "$TMP/s$S.txt" -G --data-urlencode "severity=$P" "$(url $S /api/cases)" | count)
[ "$cv" = "4" ] && ok "vulnerable: payload OR devuelve count=4" || fail "vulnerable: esperado 4, obtenido $cv"
[ "$cs" = "0" ] && ok "corregida:  payload OR devuelve count=0" || fail "corregida: esperado 0, obtenido $cs"

cl=$(curl -s -b "$TMP/a$S.txt" "$(url $S '/api/cases?severity=alta')" | count)
[ "$cl" = "2" ] && ok "regresión: severity=alta (analista1) conserva 2 registros" || fail "regresión: esperado 2, obtenido $cl"

# UNION contra el endpoint real (el informe lo probó fuera de la app)
U="zzz' UNION SELECT 99,'x','x','x','x' -- "
uv=$(curl -s -b "$TMP/s$V.txt" -G --data-urlencode "severity=$U" "$(url $V /api/cases)" | count)
us=$(curl -s -b "$TMP/s$S.txt" -G --data-urlencode "severity=$U" "$(url $S /api/cases)" | count)
if [ "$uv" != "?" ] && [ "$uv" -ge 1 ] 2>/dev/null; then ok "vulnerable: UNION SELECT inyecta filas (count=$uv)"
else info "vulnerable: UNION no devolvió filas (count=$uv); puede que el orden/nº de columnas difiera"; fi
[ "$us" = "0" ] && ok "corregida:  UNION SELECT devuelve 0" || fail "corregida: UNION devolvió $us"

long=$(python3 -c 'print("A"*100)')
cl2=$(code -b "$TMP/s$S.txt" "$(url $S /api/cases?severity=$long)")
info "corregida: severity de 100 caracteres -> HTTP $cl2 (el código corta a 60)"

# ---------------------------------------------------------------- 2. XSS
title "2. XSS reflejado  (GET /preview?message=)"
X='<img src=x onerror=alert(1)>'
bv=$(curl -s -b "$TMP/a$V.txt" -G --data-urlencode "message=$X" "$(url $V /preview)")
bs=$(curl -s -b "$TMP/a$S.txt" -G --data-urlencode "message=$X" "$(url $S /preview)")
echo "$bv" | grep -qF "$X"                          && ok "vulnerable: la etiqueta llega SIN escapar" || fail "vulnerable: no se encontró la etiqueta cruda"
echo "$bs" | grep -qF '&lt;img src=x onerror=alert(1)&gt;' && ok "corregida: la etiqueta llega escapada (&lt; &gt;)" || fail "corregida: no se encontró salida escapada"
echo "$bs" | grep -qF "$X"                          && fail "corregida: aparece la etiqueta cruda" || ok "corregida: no hay etiqueta cruda en el cuerpo"
info "Para ver la ejecución real abre en el navegador: $(url $V '/preview?message=%3Cimg%20src=x%20onerror=alert(1)%3E')"

# ---------------------------------------------------------------- 3. IDOR
title "3. IDOR/BOLA  (GET /api/cases/<id> con analista1)"
c=$(code -b "$TMP/a$V.txt" "$(url $V /api/cases/2)"); [ "$c" = "200" ] && ok "vulnerable: expediente ajeno 2 -> 200" || fail "vulnerable: esperado 200, obtenido $c"
c=$(code -b "$TMP/a$S.txt" "$(url $S /api/cases/2)"); [ "$c" = "403" ] && ok "corregida:  expediente ajeno 2 -> 403" || fail "corregida: esperado 403, obtenido $c"
c=$(code -b "$TMP/a$S.txt" "$(url $S /api/cases/1)"); [ "$c" = "200" ] && ok "regresión: expediente propio 1 -> 200"    || fail "regresión: esperado 200, obtenido $c"
c=$(code -b "$TMP/a$S.txt" "$(url $S /api/cases/99)"); [ "$c" = "404" ] && ok "corregida:  inexistente 99 -> 404"        || fail "corregida: esperado 404, obtenido $c"
c=$(code -b "$TMP/s$S.txt" "$(url $S /api/cases/2)"); [ "$c" = "200" ] && ok "regresión: supervisor lee expediente 2 -> 200" || fail "regresión: supervisor esperado 200, obtenido $c"
c=$(code "$(url $S /api/cases/1)");                   info "corregida: sin sesión, /api/cases/1 -> HTTP $c (debería ser 401/302/403, no 200)"
[ "$c" = "200" ] && fail "corregida: se entregó un expediente SIN autenticación"

echo "  Enumeración de IDs en 5001 (403 vs 404 revela si el objeto existe):"
for i in 1 2 3 4 99; do
  printf "    id=%-3s -> HTTP %s\n" "$i" "$(code -b "$TMP/a$S.txt" "$(url $S /api/cases/$i)")"
done
info "Hallazgo documentado por el equipo: 403 vs 404 permite enumerar IDs; recomiendan normalizar a 404"

# ---------------------------------------------------------------- 4. Cabeceras y cookies
title "4. Cabeceras de seguridad y cookies"
for p in $V $S; do
  h=$(curl -sI -b "$TMP/a$p.txt" -G --data-urlencode "message=test" "$(url $p /preview)")
  echo "  Puerto $p:"
  for hd in "Content-Security-Policy" "X-Content-Type-Options" "X-Frame-Options"; do
    echo "$h" | grep -qi "^$hd" && echo "    - $hd: presente" || echo "    - $hd: AUSENTE"
  done
done
curl -sI -b "$TMP/a$V.txt" "$(url $V /preview?message=t)" | grep -qi "^Content-Security-Policy" \
  && info "5000 (vulnerable) también envía CSP" || ok "CSP solo en la variante segura (5001)"
curl -sI -b "$TMP/a$V.txt" "$(url $V /preview?message=t)" | grep -qi "^X-Content-Type-Options" \
  && info "5000 envía nosniff: el informe presenta estas cabeceras como exclusivas del modo seguro (inconsistencia)"

for p in $V $S; do
  sc=$(curl -si -d "username=$USER1" -d "password=$PASS" "$(url $p /login)" | grep -i "^Set-Cookie")
  echo "  Cookie de sesión en $p: ${sc:-<no encontrada>}"
  echo "$sc" | grep -qi "HttpOnly" && echo "    HttpOnly: sí" || echo "    HttpOnly: no"
  echo "$sc" | grep -qi "SameSite" && echo "    SameSite: sí" || echo "    SameSite: no"
  echo "$sc" | grep -qi "Secure"   && echo "    Secure:   sí" || echo "    Secure:   no (esperable sin HTTPS; es lo que ZAP marcó como Medio)"
done

# ---------------------------------------------------------------- 5. Bitácora
title "5. Bitácora y regla R6"
if [ -f "$LOGFILE" ]; then
  echo "  Eventos en $LOGFILE: $(wc -l < "$LOGFILE")"
  den=$(grep -c '"outcome": "denied"' "$LOGFILE"); echo "  Denegaciones registradas: $den"
else
  info "No se encontró $LOGFILE (ejecuta desde la raíz del proyecto)"
fi
if [ $DO_LOG -eq 1 ]; then
  marcador="PRUEBA_PASSWORD_$(date +%s)"
  curl -s -d "username=$marcador" -d "password=incorrecta" -o /dev/null "$(url $S /login)"
  sleep 1
  grep -q "$marcador" "$LOGFILE" 2>/dev/null \
    && fail "la bitácora guarda el username fallido CRUDO ($marcador): riesgo de filtrar contraseñas tecleadas en ese campo" \
    || ok "la bitácora NO guarda el username fallido crudo"
else
  info "Omitida prueba de username crudo en logs (usa --log-test; modifica la bitácora)"
fi

# ---------------------------------------------------------------- 6. Pruebas del repositorio
title "6. Pruebas automatizadas del repositorio"
PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
if [ -d tests ]; then
  out=$($PY -W error::ResourceWarning -m unittest discover -s tests -v 2>&1); rc=$?
  echo "$out" | tail -n 4 | sed 's/^/  /'
  [ $rc -eq 0 ] && ok "unittest con -W error::ResourceWarning: OK" || fail "unittest con modo estricto falló"
else
  info "No hay carpeta tests/ aquí"
fi
if [ -f scripts/validate_r6.py ]; then
  out=$($PY scripts/validate_r6.py 2>&1); echo "$out" | tail -n 3 | sed 's/^/  /'
  echo "$out" | grep -q "6/6" && ok "validate_r6.py: 6/6 casos correctos" || fail "validate_r6.py no reporta 6/6"
fi
[ -f scripts/event_report.py ] && [ -f "$LOGFILE" ] && {
  echo "  event_report.py:"; $PY scripts/event_report.py --log "$LOGFILE" 2>&1 | sed 's/^/    /'; }

# ---------------------------------------------------------------- 7. ZAP opcional
title "7. OWASP ZAP (opcional)"
if [ $DO_ZAP -eq 1 ]; then
  if command -v docker >/dev/null; then
    docker run --rm --network host -v "$(pwd)":/zap/wrk:rw -t zaproxy/zap-stable \
      zap-baseline.py -t "http://$HOST:$V" -r reporte_zap_5000.html || true
    [ -f reporte_zap_5000.html ] && ok "reporte generado: reporte_zap_5000.html" || info "ZAP no generó reporte"
    info "Baseline es PASIVO. Para Active Scan usa zap-full-scan.py solo sobre el 5000, en sesión aislada"
  else
    info "Docker no está instalado; usa la app de ZAP con Active Scan sobre http://$HOST:$V"
  fi
else
  info "Omitido (usa --zap)"
fi

# ---------------------------------------------------------------- Resumen
title "RESUMEN"
echo -e "  ${G}Pasan: $PASSN${N}   ${R}Fallan: $FAILN${N}   ${Y}Info: $INFON${N}"
echo "  Reporte guardado en: $REPORT"
[ $FAILN -eq 0 ] && echo -e "  ${G}Resultado: el comportamiento coincide con lo documentado en el informe${N}" \
                 || echo -e "  ${R}Resultado: hay diferencias con lo documentado; revisa los [FALLA]${N}"
