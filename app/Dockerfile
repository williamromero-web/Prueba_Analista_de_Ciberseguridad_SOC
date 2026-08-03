# ===========================================================================
#  Dockerfile - versión endurecida
# ===========================================================================
#  Cambios aplicados:
#    - Versión de la imagen base fijada, ya no se usa la última disponible
#    - Instalación reproducible a partir del archivo de bloqueo
#    - Se quita npm de la imagen final para reducir la superficie de ataque
#    - El contenedor deja de correr como root y pasa al usuario node
#    - Se agrega una comprobación de estado para el orquestador
# ===========================================================================

# Versión fija de la imagen base. Se usa la variante de Debian porque trae
# binarios ya compilados para la base de datos y evita instalar compiladores.
FROM node:20.18.1-bookworm-slim

WORKDIR /usr/src/app

# Copia de los manifiestos e instalación de las dependencias de producción.
COPY --chown=node:node package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

# Código de la aplicación.
COPY --chown=node:node server.js ./
COPY --chown=node:node docs ./docs

# Ejecución sin privilegios. El usuario node ya viene en la imagen oficial.
USER node

EXPOSE 3000

# Comprobación de estado contra la raíz de la API.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD [ "node", "server.js" ]
