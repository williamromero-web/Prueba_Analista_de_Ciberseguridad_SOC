# ===========================================================================
#  Variables de entrada del módulo de línea base de seguridad.
# ===========================================================================
variable "environment" {
  type        = string
  default     = "production"
  description = "Entorno donde se despliega, por ejemplo production o staging."
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Región principal de AWS."
}

variable "company_name" {
  type        = string
  default     = "fleetsec"
  description = "Prefijo que se antepone al nombre de los recursos."
}
