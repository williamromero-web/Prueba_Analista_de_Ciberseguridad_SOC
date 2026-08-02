# ===========================================================================
#  Módulo de línea base de seguridad. Versiones de los proveedores y datos de
#  la cuenta activa.
# ===========================================================================
terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# Identidad de la cuenta y región en uso. Se usan al armar políticas y nombres.
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
