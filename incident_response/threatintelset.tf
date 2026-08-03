# ===========================================================================
#  Carga de direcciones maliciosas en el servicio de detección de amenazas.
#  Sube la lista threat_intel.txt a un depósito de seguridad y la registra
#  activa para que se avise del trafico relacionado.
#
#  Este archivo es un artefacto de referencia. Se despliega junto al detector
#  del módulo de línea base de seguridad, al que se le pasa su identificador.
# ===========================================================================

variable "detector_id" {
  type        = string
  description = "Identificador del detector donde se registra la lista."
}

variable "intel_bucket" {
  type        = string
  description = "Depósito de seguridad donde se guarda la lista de direcciones."
}

# Sube la lista de direcciones maliciosas al depósito de inteligencia.
resource "aws_s3_object" "threat_intel" {
  bucket = var.intel_bucket
  key    = "threat_intel.txt"
  source = "${path.module}/threat_intel.txt"
  etag   = filemd5("${path.module}/threat_intel.txt")
}

# Registra y activa la lista en el servicio de detección de amenazas.
resource "aws_guardduty_threatintelset" "malicious_ips" {
  detector_id = var.detector_id
  name        = "FleetSec-Malicious-IPs"
  format      = "TXT"
  location    = "s3://${var.intel_bucket}/${aws_s3_object.threat_intel.key}"
  activate    = true
}
