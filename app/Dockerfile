# ===========================================================================
#  Dockerfile - versión vulnerable para el laboratorio
# ===========================================================================
#  Malas prácticas puestas a propósito para que el escaneo de contenedor las
#  encuentre:
#    - Imagen base sin versión fija, lo que equivale a usar la última
#    - El contenedor corre como root
#    - Se deja npm y todas las herramientas de instalación en la imagen final
#
#  La versión endurecida queda después en app/Dockerfile. Esta se conserva en
#  la carpeta _vulnerable_baseline.
# ===========================================================================
FROM node:alpine

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY server.js .

EXPOSE 3000
CMD [ "node", "server.js" ]
