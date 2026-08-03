# ===========================================================================
#  Dockerfile - versión endurecida, construcción en dos fases
# ===========================================================================
#  Cambios aplicados:
#    - Versión de la imagen base fijada, ya no se usa la última disponible
#    - El módulo nativo de la base de datos se compila en una fase aparte, para
#      que quede enlazado con la versión del sistema del contenedor final
#    - La imagen final no lleva compiladores ni npm, para reducir el ataque
#    - El contenedor deja de correr como root y pasa al usuario node
#    - Se aplican los parches del sistema base y se agrega una comprobación de estado
# ===========================================================================

# ---- Fase 1: construcción, con las herramientas para compilar el módulo ----
FROM node:20.18.1-bookworm-slim AS builder

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY package*.json ./

# Se fuerza la compilación desde el código, en lugar de bajar un binario
# preparado, para que quede enlazado con la versión del sistema de esta imagen
# y cargue bien en la fase final.
ENV npm_config_build_from_source=true
RUN npm ci --omit=dev --no-audit --no-fund

# ---- Fase 2: imagen final, mínima, sin herramientas y sin privilegios ------
FROM node:20.18.1-bookworm-slim

# Parches de seguridad del sistema base.
# hadolint ignore=DL3005
RUN apt-get update && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Se copian las dependencias ya compiladas y el código.
COPY --from=builder --chown=node:node /usr/src/app/node_modules ./node_modules
COPY --chown=node:node package*.json ./
COPY --chown=node:node server.js ./
COPY --chown=node:node docs ./docs

# Ejecución sin privilegios. El usuario node ya viene en la imagen oficial.
USER node

EXPOSE 3000

# Comprobación de estado contra la raíz de la API.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD [ "node", "server.js" ]
