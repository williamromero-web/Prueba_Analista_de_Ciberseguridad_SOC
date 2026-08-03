# Indicadores del ataque e inteligencia de amenazas - Incidente FleetSec

## 1. Indicadores del ataque

| Tipo | Indicador | Contexto en la línea de tiempo |
|------|-----------|--------------------------------|
| Dirección IP | `185.220.101.22` | Inicio de sesión inicial en el minuto cero y destino de la fuga de datos a la hora y 10 minutos. Nodo de salida de una red de anonimato. |
| Usuario | `svc-monitoring` | Cuenta de servicio a la que se le creó acceso a los 15 minutos y se le dieron permisos de administrador a los 22 minutos. |
| Usuario | cuenta inicial sin identificar | Origen del primer inicio de sesión desde la red de anonimato. La hipótesis es una credencial de larga duración robada. |
| Imagen de contenedor | `docker.io/attacker/exfil:latest` | Tarea maliciosa registrada en producción a la hora y 40 minutos. |
| Depósito de almacenamiento | `fleetpay-prod-drivers` | 387 descargas en 8 minutos, 45.7 gigabytes extraídos a los 35 minutos. |
| Clave de cifrado | `prod-data-key` | 12 operaciones de descifrado sobre datos de producción a los 58 minutos. |
| Instancia de servidor | `i-0abc1234def56789` | Puente para sacar cerca de 49 gigabytes y aviso de fuga de datos por dns a la hora y 50 minutos. |

### Patrones de comportamiento

- Volumen fuera de lo normal: 387 descargas en 8 minutos, muy por encima de lo habitual.
- Velocidad: paso de conseguir el acceso a extraer los datos en menos de 35 minutos.
- Horario: actividad concentrada de madrugada, fuera del horario de trabajo.
- Borrado de huellas: intento de eliminar el registro de actividad a la hora y 45 minutos, que quedó bloqueado.
- Anonimato: origen en una red de anonimato conocida.

## 2. Enriquecimiento de la dirección `185.220.101.22`

| Campo | Valor |
|-------|-------|
| Ubicación | Alemania, dentro de los nodos de salida europeos de la red de anonimato. |
| Operador de red | Infraestructura asociada a la red de anonimato. |
| Reputación | Puntaje de abuso máximo, catalogada como nodo de salida de la red de anonimato. |
| Análisis de reputación | Marcada como maliciosa por varios motores, asociada a escaneo y fuerza bruta. |
| Exposición de servicios | Puertos del servicio de anonimato visibles, con la firma propia de un nodo de salida. |
| Fuentes de inteligencia | Presente en varias listas de nodos de anonimato y de escaneo. |

> Nota sobre el método: el enriquecimiento se documenta con el proceso y las
> fuentes consultadas. Al tratarse de un nodo de salida conocido de una red de
> anonimato, la recomendación es bloquear la dirección y, además, vigilar de
> forma general el acceso desde ese tipo de redes, no solo esta dirección
> puntual.

## 3. Carga de la lista de direcciones maliciosas

El archivo `threat_intel.txt`, con una dirección por línea, contiene los
indicadores de red maliciosos.

### Opción A, por línea de comandos

```bash
# 1. Subir la lista a un depósito de seguridad con acceso restringido
aws s3 cp threat_intel.txt s3://fleetsec-security-intel/threat_intel.txt

# 2. Crear la lista en el servicio de detección de amenazas y activarla
aws guardduty create-threat-intel-set \
  --detector-id <ID_DEL_DETECTOR> \
  --name FleetSec-Malicious-IPs \
  --format TXT \
  --location s3://fleetsec-security-intel/threat_intel.txt \
  --activate
```

### Opción B, como código de infraestructura

Ver el archivo `incident_response/threatintelset.tf`, que registra y activa la
lista en el servicio de detección de amenazas.
