# ===========================================================================
#  Dockerfile - versión endurecida
# ===========================================================================
#  Cambios aplicados:
#    - Versión de la imagen base fijada, ya no se usa la última disponible. Se
#      elige una base más nueva para que el binario preparado de la base de
#      datos cargue sin necesidad de compilarlo
#    - Instalación reproducible a partir del archivo de bloqueo
#    - Se quita npm de la imagen final para reducir la superficie de ataque
#    - El contenedor deja de correr como root y pasa al usuario node
#    - Se aplican los parches del sistema base y se agrega una comprobación de estado
# ===========================================================================
FROM node:20-trixie-slim

# Parches de seguridad del sistema base.
# hadolint ignore=DL3005
RUN apt-get update && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY --chown=node:node package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

COPY --chown=node:node server.js ./
COPY --chown=node:node docs ./docs

USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD [ "node", "server.js" ]
