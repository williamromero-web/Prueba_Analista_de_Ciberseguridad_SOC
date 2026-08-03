# Versión vulnerable de referencia

Esta carpeta guarda a propósito los archivos originales, con las fallas de
seguridad intactas, tal como estaban antes de la corrección. Sirve como
evidencia de lo que realmente se analizó y permite volver a reproducir las
pruebas de explotación cuando haga falta.

El pipeline ignora esta carpeta. Los escáneres apuntan a las carpetas app e
infrastructure, y el detector de secretos la tiene excluida en su
configuración. Nada de lo que hay aquí se despliega ni se analiza.

## Contenido

| Archivo | Qué es | Versión corregida |
|---|---|---|
| `app/server.js` | API con las 10 fallas del análisis | `app/server.js` |
| `app/Dockerfile` | Imagen sin versión fija y ejecutada como root | `app/Dockerfile` |

## Cómo reproducir las pruebas

```bash
# 1. Copiar el servidor vulnerable a un entorno aislado
cp _vulnerable_baseline/app/server.js /tmp/lab/server.js
cd /tmp/lab && npm init -y && npm i express sqlite3 jsonwebtoken axios xmldom xpath
JWT_SECRET=irrelevante node server.js

# 2. Ejecutar los scripts de prueba del directorio vapt/poc/
```

Las correcciones y su comprobación, tanto del ataque bloqueado como del uso
normal que sigue funcionando, están documentadas en `vapt/REPORTE_VAPT.md` y
automatizadas en `vapt/tests/`.
