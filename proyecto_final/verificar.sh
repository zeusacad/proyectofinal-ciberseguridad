#!/usr/bin/env bash
# Verificación HTTP reproducible del laboratorio CFCC. Solo 127.0.0.1.
set -euo pipefail
cd "$(dirname "$0")"
HOST="127.0.0.1"
V="${V_PORT:-5000}"
S="${S_PORT:-5001}"
PASS="demo1234"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASSN=0; FAILN=0
ok(){ echo "[OK] $1"; PASSN=$((PASSN+1)); }
bad(){ echo "[FALLO] $1"; FAILN=$((FAILN+1)); }
url(){ printf 'http://%s:%s%s' "$HOST" "$1" "$2"; }
code(){ curl -sS -o /dev/null -w '%{http_code}' "$@"; }
assert_status(){ local expected="$1" actual="$2" label="$3"; if [ "$expected" = "$actual" ]; then ok "$label: HTTP $actual"; else bad "$label: esperaba $expected, recibió $actual"; fi; }
login(){ local p="$1" u="$2" f="$3"; curl -sS -c "$f" -d "username=$u" -d "password=$PASS" -o /dev/null -w '%{http_code}' "$(url "$p" /login)"; }
count(){ python -c 'import json,sys;print(json.load(sys.stdin)["count"])'; }

echo "PROTOCOLO ZERO DAY / CFCC - Verificación HTTP local"
echo "Variante vulnerable: $(url "$V" /api/health)"
echo "Variante segura:     $(url "$S" /api/health)"
for port in "$V" "$S"; do
  curl -fsS "$(url "$port" /api/health)" >"$TMP/h$port.json"
done
python - "$TMP/h$V.json" "$TMP/h$S.json" <<'PY'
import json,sys
v,s=[json.load(open(x)) for x in sys.argv[1:]]
assert v['mode']=='vulnerable' and s['mode']=='secure',(v,s)
print('[OK] Health y modo de ambas variantes')
PY

for port in "$V" "$S"; do
  assert_status 302 "$(login "$port" analista1 "$TMP/a$port.txt")" "Login de analista1 en $port"
  assert_status 302 "$(login "$port" supervisor "$TMP/s$port.txt")" "Login de supervisor en $port"
done

PAYLOAD="' OR '1'='1"
vcount=$(curl -fsS -b "$TMP/a$V.txt" -G --data-urlencode "severity=$PAYLOAD" "$(url "$V" /api/cases)" | count)
scount=$(curl -fsS -b "$TMP/a$S.txt" -G --data-urlencode "severity=$PAYLOAD" "$(url "$S" /api/cases)" | count)
[ "$vcount" = 4 ] && ok "SQLi vulnerable: cuatro expedientes" || bad "SQLi vulnerable count=$vcount"
[ "$scount" = 0 ] && ok "SQLi segura: cero expedientes" || bad "SQLi segura count=$scount"
UNION="zzz' UNION SELECT 99,'x','x','x','x' -- "
uv=$(curl -fsS -b "$TMP/a$V.txt" -G --data-urlencode "severity=$UNION" "$(url "$V" /api/cases)" | count)
us=$(curl -fsS -b "$TMP/a$S.txt" -G --data-urlencode "severity=$UNION" "$(url "$S" /api/cases)" | count)
[ "$uv" = 1 ] && ok "UNION vulnerable: fila ficticia" || bad "UNION vulnerable count=$uv"
[ "$us" = 0 ] && ok "UNION segura: cero expedientes" || bad "UNION segura count=$us"

assert_status 200 "$(code -b "$TMP/a$V.txt" "$(url "$V" /api/cases/2)")" 'IDOR vulnerable: expediente ajeno'
assert_status 404 "$(code -b "$TMP/a$S.txt" "$(url "$S" /api/cases/2)")" 'IDOR seguro: expediente ajeno'
assert_status 404 "$(code -b "$TMP/a$S.txt" "$(url "$S" /api/cases/99)")" 'IDOR seguro: expediente inexistente'
assert_status 200 "$(code -b "$TMP/a$S.txt" "$(url "$S" /api/cases/1)")" 'IDOR seguro: expediente propio'
assert_status 200 "$(code -b "$TMP/s$S.txt" "$(url "$S" /api/cases/2)")" 'Supervisor: expediente ajeno al analista'
assert_status 400 "$(code -b "$TMP/a$S.txt" "$(url "$S" "/api/cases?severity=$(printf 'A%.0s' {1..100})")")" 'Validación de longitud'

X='<img src=x onerror=alert(1)>'
vbody=$(curl -fsS -b "$TMP/a$V.txt" -G --data-urlencode "message=$X" "$(url "$V" /preview)")
sbody=$(curl -fsS -b "$TMP/a$S.txt" -G --data-urlencode "message=$X" "$(url "$S" /preview)")
if [[ "$vbody" == *"$X"* ]]; then ok 'XSS vulnerable: marcado bruto';else bad 'XSS vulnerable: falta marcado';fi
if [[ "$sbody" == *'&lt;img src=x onerror=alert(1)&gt;'* ]]; then ok 'XSS seguro: HTML escapado';else bad 'XSS seguro: escape ausente';fi

if [ "$FAILN" = 0 ]; then echo "Verificación HTTP: correcta ($PASSN comprobaciones)";else echo "Verificación HTTP: $FAILN fallos de $((FAILN+PASSN)) comprobaciones";fi
if [ "${1:-}" = '--zap' ]; then
  echo 'OWASP ZAP se ejecuta desde Desktop con el alcance local y autenticación documentados en README.md.'
  echo 'Esta opción no sustituye un reporte real exportado desde OWASP ZAP.'
fi
exit "$FAILN"
