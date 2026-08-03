# Guía de respuesta al incidente

Incidente: fuga masiva de datos, 45.7 gigabytes, desde el depósito
`fleetpay-prod-drivers` y ejecución de una imagen maliciosa en producción.
Detección: a las dos horas de iniciado, cuando el ataque ya llevaba ese tiempo
activo.

---

## 1. Pasos de contención con sus comandos y su reversión

> Orden recomendado: primero cortar el acceso y después tocar los recursos.
> Cada paso trae su reversión para volver a la normalidad tras el peritaje.

Paso 1. Anular las credenciales de la cuenta comprometida.
- Contención:
  ```bash
  aws iam list-access-keys --user-name svc-monitoring
  aws iam update-access-key --user-name svc-monitoring --access-key-id <ID_DE_CLAVE> --status Inactive
  aws iam delete-access-key --user-name svc-monitoring --access-key-id <ID_DE_CLAVE>
  ```
- Reversión: `aws iam create-access-key --user-name svc-monitoring`

Paso 2. Quitarle el acceso por consola a la cuenta.
- Contención: `aws iam delete-login-profile --user-name svc-monitoring`
- Reversión: `aws iam create-login-profile --user-name svc-monitoring --password <NUEVA> --password-reset-required`

Paso 3. Cerrar las sesiones activas para invalidar los accesos temporales.
- Contención:
  ```bash
  aws iam put-user-policy --user-name svc-monitoring --policy-name RevokeAllSessions \
    --policy-document '{"Versión":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"2026-08-01T02:00:00Z"}}}]}'
  ```
- Reversión: `aws iam delete-user-policy --user-name svc-monitoring --policy-name RevokeAllSessions`

Paso 4. Aislar el servidor afectado sin apagarlo, para conservar la memoria.
- Contención: `aws ec2 modify-instance-attribute --instance-id i-0abc1234def56789 --groups <GRUPO_DE_CUARENTENA>`
- Reversión: `aws ec2 modify-instance-attribute --instance-id i-0abc1234def56789 --groups <GRUPO_ORIGINAL>`

Paso 5. Preservar la evidencia con una copia del disco y de los registros.
- Contención:
  ```bash
  VOL=$(aws ec2 describe-instances --instance-id i-0abc1234def56789 \
        --query 'Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId' --output text)
  aws ec2 create-snapshot --volume-id $VOL --description "Evidencia del incidente - i-0abc1234def56789"
  # Copia de los registros relevantes a un depósito que no admite cambios
  aws s3 cp s3://cloudtrail-logs/ s3://fleetsec-forensics-writeonce/incidente-2026-08-01/ --recursive
  ```
- Reversión: `aws ec2 delete-snapshot --snapshot-id <ID_DE_COPIA>`, solo tras cerrar el caso.

---

## 2. Correspondencia con las técnicas conocidas de ataque

| # | Técnica | Cómo apareció en el incidente | Cómo mitigarla |
|---|---------|-------------------------------|----------------|
| 1 | T1078.004 Uso de cuentas válidas en la nube | Inicio de sesión con credenciales robadas desde una red de anonimato. | Segundo factor obligatorio y detección de acceso desde redes de anonimato. |
| 2 | T1136.001 Creación de una cuenta | Se creó acceso por consola a la cuenta de servicio para mantener la entrada. | Alertar la creación de acceso en cuentas de servicio y aplicar políticas restrictivas. |
| 3 | T1098.003 Otorgar roles adicionales en la nube | Se le dio la política de administrador a la cuenta de servicio. | Límites de permisos, la regla de detección número 1 y prohibir la asignación amplia de políticas. |
| 4 | T1530 Lectura de datos del almacenamiento | 387 descargas en 8 minutos, 45.7 gigabytes. | Puntos de acceso privados con política de origen y la regla de detección número 4. |
| 5 | T1204.003 Ejecución de una imagen maliciosa | Registro de una tarea con una imagen de atacante. | Permitir solo imágenes del repositorio privado y escanearlas. |
| 6 | T1562.008 Alterar los registros de la nube | Intento de borrar el registro de actividad, bloqueado por las políticas. | Política de protección del registro, que funcionó, y la regla de detección número 2. |
| 7 | T1567.002 Fuga de datos por un servicio web | Cerca de 49 gigabytes hacia la dirección atacante. | Filtrado de salida y bloqueo de direcciones de baja reputación con la lista de amenazas. |
| 8 | T1048 Fuga de datos por un canal alternativo | Aviso de fuga de datos a través del servicio de nombres. | Inspección y limitación del tráfico de nombres de salida y la detección de amenazas. |

---

## 3. Análisis de causa raíz

- Punto de entrada, con hipótesis justificada: robo o filtración de una
  credencial de larga duración de un perfil con permisos, sin segundo factor. El
  atacante la usó para entrar por consola desde la red de anonimato. La
  hipótesis se apoya en que el primer inicio de sesión fue exitoso sin intentos
  previos de fuerza bruta y en la ausencia de segundo factor.
- Recorrido completo del ataque:
  1. Inicio de sesión por consola desde la red de anonimato.
  2. Creación de acceso a la cuenta de servicio para mantener la entrada.
  3. Asignación de permisos de administrador.
  4. Descifrado repetido sobre los datos de producción.
  5. Descarga masiva desde el depósito de producción.
  6. Salida de cerca de 49 gigabytes hacia la dirección atacante.
  7. Registro de una tarea con una imagen maliciosa.
  8. Intento de borrar el registro de actividad, que quedó bloqueado.
- Por qué fallaron los controles que había:
  1. Sin segundo factor: dejó usar la credencial robada sin una barrera extra.
  2. Permisos excesivos: la cuenta inicial podía asignar la política de administrador.
  3. Sin filtrado de salida: la red permitía salir sin restricción, lo que facilitó la fuga.
  4. Detección tardía: faltaban alarmas de volumen y velocidad, que hoy cubren las reglas de detección.

---

## 4. Resumen para la dirección

Asunto: incidente crítico de ciberseguridad con exposición de datos de conductores.

Qué pasó. Un atacante externo, usando las credenciales de un usuario con altos
permisos y conectándose desde una red anónima, entró a la plataforma de
madrugada, extrajo información de producción y ejecutó un programa malicioso.
Los controles de auditoría impidieron que borrara sus huellas, lo que permitió
conservar la evidencia.

Datos expuestos y su marco legal. Se extrajeron 45.7 gigabytes del
almacenamiento de producción, que incluye datos personales de los conductores,
como su identificación y la ubicación de la flota. Al ser una vulneración de
datos personales, existe la obligación de notificar a la Superintendencia de
Industria y Comercio dentro de los 15 días hábiles.

Tres acciones inmediatas.
1. Anular las credenciales comprometidas, expulsar al atacante y aislar los recursos afectados.
2. Preservar la evidencia con copias del disco y de los registros para la investigación legal y técnica.
3. Activar al equipo legal para notificar a la autoridad y comunicar a los conductores afectados.

---

## 5. Plan de mejora después del incidente

| Prioridad | Acción | Esfuerzo | Responsable |
|:---------:|--------|:--------:|-------------|
| Alta | Segundo factor obligatorio para todos los usuarios y retiro de las credenciales de larga duración. | Bajo, una semana | Ciberseguridad y operaciones |
| Alta | Cargar la lista de direcciones maliciosas en el detector de amenazas y bloquear la salida hacia direcciones de baja reputación. | Bajo, una semana | Ciberseguridad |
| Media | Filtrado de salida en la red y admisión solo de imágenes del repositorio privado. | Medio, un mes | Arquitectura de nube |
| Media | Desplegar las reglas de detección en el sistema de monitoreo con sus alertas. | Medio, dos semanas | Centro de operaciones de seguridad |
| Baja | Revisar los permisos para quitar los comodines y aplicar límites, y automatizar la búsqueda de credenciales. | Alto, tres meses | Equipo de seguridad en el desarrollo |
