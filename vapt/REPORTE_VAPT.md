# Reporte de análisis de vulnerabilidades - FleetSec S.A.S.

Aplicación evaluada: FleetSec API en Node.js y Express
Entorno: pruebas locales
Tipo de trabajo: análisis de vulnerabilidades y pruebas de penetración con
conocimiento parcial del sistema.

---

## 1. Resumen ejecutivo

El análisis ofensivo sobre la API de FleetSec dejó el riesgo global inicial en
nivel crítico. Un atacante sin credenciales válidas podía tomar control total
de la base de datos, hacerse pasar por cualquier usuario, incluidos los
administradores, y extraer sin restricción la información personal de la flota,
protegida por la Ley 1581 de 2012. Se encontraron y explotaron 10
vulnerabilidades. Las 10 quedaron corregidas y comprobadas con pruebas que
verifican tanto que el ataque queda bloqueado como que el uso normal sigue
funcionando.

Los tres hallazgos más graves:

| # | Hallazgo | Puntaje | Consecuencia si no se corrige |
|---|----------|:-------:|-------------------------------|
| 1 | Inyección SQL en el inicio de sesión | 9.8 | Se salta la autenticación por completo y se extrae toda la base de datos. |
| 2 | Falsificación del token de sesión | 9.1 | Suplantación de cualquier usuario o administrador sin conocer su contraseña. |
| 3 | Credenciales de la nube escritas en el código | 9.0 | Acceso directo a la infraestructura. |

Acción inmediata recomendada: cambiar de inmediato las credenciales de nube
expuestas, desplegar la versión corregida de la API y mantener activo el
pipeline de seguridad como control permanente. Riesgo que queda después de la
corrección: bajo.

---

## 2. Detalle por hallazgo

Cada prueba se ejecutó sobre el entorno propio. Los scripts reproducibles están
en `vapt/poc/` y las pruebas que comprueban la corrección en `vapt/tests/`. El
código vulnerable original se conserva en `_vulnerable_baseline/` y el corregido
está en `app/`.

### V01 · Inyección SQL

- Puntaje: 9.8, nivel crítico. Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Clasificación: A03:2021 Injection · CWE-89
- Dónde: `POST /api/login` y `GET /api/users/:id`
- Prueba:
  ```bash
  curl -X POST http://localhost:3000/api/login -H "Content-Type: application/json" \
       -d '{"username":"admin'\'' OR '\''1'\''='\''1","password":"x"}'
  # Devuelve un token de administrador sin conocer la contraseña
  ```
- Impacto: pérdida total de confidencialidad por el volcado de datos, pérdida de
  integridad porque se pueden modificar registros y afectación de la
  disponibilidad. En términos de Ley 1581 supone la exposición masiva de datos
  personales de los conductores.
- Corrección: las consultas usan marcadores de posición y los valores viajan
  aparte como parámetros, de modo que lo que escribe el usuario nunca forma
  parte de la sentencia.

### V02 · Sesión rota por token sin verificar

- Puntaje: 9.1, nivel crítico. Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
- Clasificación: A07:2021 Identification and Authentication Failures · CWE-345
- Dónde: todos los endpoints protegidos
- Prueba: se arma un token con el algoritmo declarado como none y sin firma, con
  el contenido de un administrador. El servidor lo aceptaba porque solo
  decodificaba el token en lugar de verificarlo. Ver `vapt/poc/run_all_pocs.sh`.
- Impacto: confidencialidad e integridad comprometidas por suplantación total.
  Acceso no autorizado a datos de los titulares.
- Corrección: se verifica la firma del token y se acepta un único algoritmo, con
  lo que los tokens falsificados quedan rechazados.

### V03 · Peticiones forzadas desde el servidor

- Puntaje: 8.8, nivel alto. Vector `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- Clasificación: A10:2021 Server-Side Request Forgery · CWE-918
- Dónde: `GET /api/proxy?url=`
- Prueba:
  ```bash
  curl "http://localhost:3000/api/proxy?url=http://169.254.169.254/latest/meta-data/" \
       -H "Authorization: Bearer <token>"
  # El servidor consultaba recursos internos de la nube
  ```
- Impacto: confidencialidad alta por el robo de credenciales temporales de la
  nube y posibilidad de moverse hacia la red interna.
- Corrección: el usuario ya no envía una dirección sino que elige una opción de
  una lista cerrada. La dirección consultada es siempre una constante del
  servidor, así que la entrada del usuario nunca llega a la petición de salida.

### V04 · Entidades externas en el procesamiento de XML

- Puntaje: 8.6, nivel alto. Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
- Clasificación: A05:2021 Security Misconfiguration · CWE-611
- Dónde: `POST /api/xml-upload`
- Prueba:
  ```bash
  curl -X POST http://localhost:3000/api/xml-upload -H "Content-Type: application/xml" \
    --data '<?xml versión="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file://c:/Windows/win.ini">]><username>&xxe;</username>'
  # La respuesta incluía el contenido de un archivo del servidor
  ```
- Impacto: confidencialidad alta por la lectura de archivos locales.
- Corrección: se rechaza cualquier declaración de entidades y no se resuelven
  referencias externas. El XML normal se sigue procesando igual.

### V05 · Asignación masiva de campos

- Puntaje: 8.1, nivel alto. Vector `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- Clasificación: A08:2021 Software and Data Integrity Failures · CWE-915
- Dónde: `POST /api/users/update`
- Prueba: un usuario normal enviaba el campo de rol con valor de administrador y
  quedaba con esos permisos, porque el servidor mezclaba todo el contenido
  recibido con su registro. Ver `vapt/poc/run_all_pocs.sh`.
- Impacto: integridad alta por escalada de privilegios.
- Corrección: se acepta únicamente una lista cerrada de campos, que son el
  nombre de usuario y el correo. El campo de rol enviado por el usuario se
  descarta por completo.

### V06 · Lectura de archivos fuera de la carpeta permitida

- Puntaje: 7.5, nivel alto. Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- Clasificación: A01:2021 Broken Access Control · CWE-22
- Dónde: `GET /api/files?file=`
- Prueba:
  ```bash
  curl "http://localhost:3000/api/files?file=../server.js"
  ```
- Impacto: confidencialidad alta por la lectura de cualquier archivo del
  servidor.
- Corrección: la ruta se resuelve por completo y se comprueba que siga dentro de
  la carpeta de documentos antes de abrir el archivo.

### V07 · Inicio de sesión sin límite de intentos

- Puntaje: 7.5, nivel alto. Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- Clasificación: A07:2021 Identification and Authentication Failures · CWE-307
- Dónde: `POST /api/login`
- Prueba: se lanzaron intentos repetidos de forma continua y ninguno fue
  frenado. Ver `vapt/poc/run_all_pocs.sh`.
- Impacto: permite probar contraseñas de forma masiva y afecta la disponibilidad
  del servicio de autenticación.
- Corrección: se aplica un límite de 5 intentos por dirección cada 5 minutos. El
  sexto intento recibe un rechazo por exceso de peticiones.

### V08 · Datos personales escritos en los registros

- Puntaje: 7.5, nivel alto. Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- Clasificación: A09:2021 Security Logging and Monitoring Failures · CWE-359
- Evidencia del registro en la versión vulnerable:
  ```
  [INFO] Login - Usuario: admin, Email: admin@fleetsec.com, Cédula: 123456789
  ```
- Impacto: confidencialidad alta. En términos de Ley 1581 supone un tratamiento
  indebido de datos personales dentro de los registros del sistema.
- Corrección: se agrega una función central de enmascarado por la que pasan
  todos los registros de la aplicación. Evidencia después de la corrección:
  `{"userId":1,"email":"ad****om","cc":"12****89"}`.

### V09 · Acceso a datos de otro usuario

- Puntaje: 6.5, nivel medio. Vector `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- Clasificación: A01:2021 Broken Access Control · CWE-639
- Dónde: `GET /api/users/:id`
- Prueba: un usuario con identificador 2 podía leer el perfil del identificador
  1, que es el administrador, con solo cambiar el número en la dirección.
- Impacto: confidencialidad alta por acceso a datos de otros titulares.
- Corrección: se comprueba a quién pertenece el dato. Solo el propio usuario o un
  administrador pueden verlo, y en cualquier otro caso se rechaza la petición.

### V10 · Credenciales escritas en el código

- Puntaje: 9.0, nivel crítico. Vector `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H`
- Clasificación: A05:2021 Security Misconfiguration · CWE-798
- Evidencia: la clave de acceso a la nube, el secreto de sesión y la contraseña
  de la base de datos estaban escritos dentro de `server.js`. El detector de
  secretos del pipeline los encontró.
- Uso malicioso: con la clave de nube un atacante se autentica contra la
  infraestructura y con el secreto de sesión puede firmar tokens válidos para
  cualquier usuario.
- Impacto: confidencialidad e integridad comprometidas a nivel de
  infraestructura.
- Corrección: el secreto de sesión se toma únicamente de una variable de
  entorno, que en producción entrega el gestor de secretos. No se movió a otro
  archivo del repositorio. El detector de secretos, que corre tanto antes del
  commit como dentro del pipeline, evita que la situación se repita.

---

## 3. Mapa de la superficie expuesta

| Endpoint | Autenticación | Hallazgos antes | Estado actual |
|----------|:-------------:|-----------------|:-------------:|
| `POST /api/login` | Ninguna | V01, V07, V08 | Seguro |
| `GET /api/proxy` | Token de sesión | V03 | Seguro |
| `GET /api/users/:id` | Token de sesión | V01, V09 | Seguro |
| `POST /api/xml-upload` | Ninguna | V04 | Seguro |
| `POST /api/users/update` | Token de sesión | V05, V01 | Seguro |
| `GET /api/files` | Ninguna | V06 | Seguro |
| Repositorio de código | No aplica | V10 | Seguro |

---

## 4. Comprobación de las correcciones

Las 10 vulnerabilidades quedaron corregidas en `app/server.js` y en
`app/Dockerfile`. Para cada una se comprueban dos cosas: que el intento
malicioso queda rechazado y que el uso normal sigue funcionando. Las pruebas se
ejecutan con `vapt/tests/run_validation.sh` y su resultado esperado está
documentado en la misma carpeta.

| ID | Intento malicioso | Uso normal |
|----|-------------------|------------|
| V01 | `admin' OR '1'='1` devuelve 401 | inicio de sesión válido devuelve 200 y token |
| V02 | token sin firma devuelve 401 | token válido devuelve 200 |
| V03 | destino interno devuelve 403 | destino permitido devuelve 200 |
| V04 | declaración de entidades devuelve 400 | XML normal devuelve 200 |
| V05 | campo de rol enviado se descarta | actualizar nombre y correo devuelve 200 |
| V06 | intento de subir de carpeta devuelve 400 | archivo permitido devuelve 200 |
| V07 | el sexto intento devuelve 429 | dentro del límite responde normal |
| V08 | no aplica | el registro muestra el correo y la cédula enmascarados |
| V09 | leer el perfil ajeno devuelve 403 | leer el perfil propio devuelve 200 |
| V10 | un secreto en el código detiene el pipeline | el secreto por variable de entorno funciona |
