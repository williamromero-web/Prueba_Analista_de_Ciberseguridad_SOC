# ===========================================================================
#  Punto de entrada de la infraestructura. Llama al módulo con la línea base
#  de seguridad de FleetSec.
#  No hace falta una cuenta de AWS real: el objetivo es que la validación y el
#  análisis de seguridad de la infraestructura pasen sin errores.
# ===========================================================================
provider "aws" {
  region = var.region
  # Credenciales de relleno para poder validar sin una cuenta real.
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Región principal. Se usa us-east-1 porque es la única desde donde se crea el firewall de la red de distribución."
}

module "security_baseline" {
  source       = "./modules/security-baseline"
  region       = var.region
  environment  = "production"
  company_name = "fleetsec"
}
