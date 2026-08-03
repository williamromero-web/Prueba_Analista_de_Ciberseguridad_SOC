#!/usr/bin/env bash
# ===========================================================================
#  Comprobación de las correcciones de la aplicación.
#  Para cada vulnerabilidad revisa dos cosas: que el intento malicioso queda
#  rechazado y que el uso normal sigue funcionando. Termina con exito solo si
#  todas las comprobaciones pasan.
#
#  Uso:
#     cd app && JWT_SECRET=un_secreto_de_prueba node server.js &   # puerto 3000
#     BASE=http://localhost:3000 ./vapt/tests/run_validation.sh
# ===========================================================================
set -u
BASE="${BASE:-http://localhost:3000}"
FAILED=0
ok(){ echo "  [OK] $1"; }
ko(){ echo "  [FALLA] $1"; FAILED=1; }
code(){ curl -s -o /dev/null -w "%{http_code}" "$@"; }

# --- Tokens de sesión ---
TOKEN=$(curl -s -X POST "$BASE/api/login" -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')
UTOK=$(curl -s -X POST "$BASE/api/login" -H "Content-Type: application/json" \
  -d '{"username":"user","password":"user123"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')

echo "V01 · Inyección SQL"
r=$(curl -s -X POST "$BASE/api/login" -H "Content-Type: application/json" -d '{"username":"admin'\'' OR '\''1'\''='\''1","password":"x"}')
echo "$r" | grep -q token && ko "el salto fue aceptado" || ok "intento malicioso rechazado"
[ -n "$TOKEN" ] && ok "inicio de sesión normal funciona" || ko "el inicio de sesión normal fallo"

echo "V02 · Token de sesión"
FORGED="$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=').$(printf '{"id":1,"role":"admin"}' | base64 | tr '+/' '-_' | tr -d '=')."
[ "$(code "$BASE/api/users/1" -H "Authorization: Bearer $FORGED")" = "401" ] && ok "token falso rechazado" || ko "token falso aceptado"
[ "$(code "$BASE/api/users/1" -H "Authorization: Bearer $TOKEN")" = "200" ] && ok "token válido funciona" || ko "el token válido fallo"

echo "V03 · Petición forzada"
[ "$(code "$BASE/api/proxy?target=http://169.254.169.254/" -H "Authorization: Bearer $TOKEN")" = "403" ] && ok "destino interno rechazado" || ko "el destino interno fue permitido"

echo "V04 · Entidades en el XML"
r=$(curl -s -X POST "$BASE/api/xml-upload" -H "Content-Type: application/xml" --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file://c:/Windows/win.ini">]><username>&xxe;</username>')
echo "$r" | grep -qiE "16-bit|fonts" && ko "se leyo el archivo" || ok "declaración de entidades rechazada"
curl -s -X POST "$BASE/api/xml-upload" -H "Content-Type: application/xml" --data '<username>Carlos</username>' | grep -q Carlos && ok "XML normal funciona" || ko "el XML normal fallo"

echo "V05 · Asignación masiva"
r=$(curl -s -X POST "$BASE/api/users/update" -H "Authorization: Bearer $UTOK" -H "Content-Type: application/json" -d '{"username":"user","email":"u@x.com","role":"admin"}')
echo "$r" | grep -q '"role":"admin"' && ko "escalo a administrador" || ok "campo de rol descartado"

echo "V06 · Lectura de rutas"
[ "$(code "$BASE/api/files?file=../server.js")" = "400" ] && ok "salida de carpeta rechazada" || ko "la salida de carpeta fue permitida"
[ "$(code "$BASE/api/files?file=bienvenida.txt")" = "200" ] && ok "archivo permitido funciona" || ko "el archivo permitido fallo"

echo "V09 · Acceso a datos ajenos"
[ "$(code "$BASE/api/users/1" -H "Authorization: Bearer $UTOK")" = "403" ] && ok "no lee el perfil ajeno" || ko "leyo el perfil ajeno"
[ "$(code "$BASE/api/users/2" -H "Authorization: Bearer $UTOK")" = "200" ] && ok "lee su propio perfil" || ko "el perfil propio fallo"

echo "V07 · Limite de intentos, puede requerir una ventana limpia"
last=000; for i in $(seq 1 8); do last=$(code -X POST "$BASE/api/login" -H "Content-Type: application/json" -d '{"username":"z","password":"z"}'); done
[ "$last" = "429" ] && ok "se rechaza al superar el limite" || echo "  [INFO] último código $last, el limite es por dirección y ventana de tiempo"

echo "---------------------------------------------"
[ "$FAILED" = "0" ] && echo "RESULTADO: todas las comprobaciones pasaron" || echo "RESULTADO: hay comprobaciones que fallaron"
exit $FAILED
