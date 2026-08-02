# ===========================================================================
#  Base de datos. Replicada en dos zonas, cifrada con clave propia, sin acceso
#  desde internet, con copias de seguridad de 7 días, conexiones obligadas a
#  viajar cifradas y la credencial guardada en el gestor de secretos con
#  cambio automático cada 30 días.
# ===========================================================================

# Identificador de la función que AWS pública para cambiar la credencial de
# forma automática. En un despliegue real apunta al recurso oficial. Aquí se
# deja como variable para poder validar el código sin desplegar nada.
variable "rotation_lambda_arn" {
  type        = string
  default     = "arn:aws:lambda:us-east-1:123456789012:function:SecretsManagerRDSPostgreSQLRotationSingleUser"
  description = "Identificador de la función que cambia la credencial de la base de datos."
}

# --- Credencial guardada en el gestor de secretos -------------------------
resource "random_password" "db" {
  length           = 24
  special          = true
  override_special = "!#$%&*()-_=+[]{}"
}

resource "aws_secretsmanager_secret" "rds" {
  name        = "${var.company_name}/${var.environment}/rds-credentials"
  description = "Credencial de la base de datos de FleetSec"
  kms_key_id  = aws_kms_key.ecs.arn
}

resource "aws_secretsmanager_secret_version" "rds" {
  secret_id = aws_secretsmanager_secret.rds.id
  secret_string = jsonencode({
    username = "dbadmin"
    password = random_password.db.result
  })
}

# Cambio automático de la credencial cada 30 días.
resource "aws_secretsmanager_secret_rotation" "rds" {
  secret_id           = aws_secretsmanager_secret.rds.id
  rotation_lambda_arn = var.rotation_lambda_arn
  rotation_rules {
    automatically_after_days = 30
  }
}

# --- Subredes donde vive la base de datos, repartidas en dos zonas --------
resource "aws_db_subnet_group" "data" {
  name       = "${var.company_name}-data-subnets"
  subnet_ids = [aws_subnet.data_az1.id, aws_subnet.data_az2.id]
}

# --- Ajustes del motor: obliga el cifrado y registra las conexiones -------
resource "aws_db_parameter_group" "secure" {
  name   = "${var.company_name}-secure-pg"
  family = "postgres14"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
}

# --- Instancia de base de datos -------------------------------------------
resource "aws_db_instance" "main" {
  #checkov:skip=CKV_AWS_118:"El monitoreo ampliado necesita un rol adicional que queda fuera del alcance del laboratorio."
  #checkov:skip=CKV_AWS_353:"El análisis de rendimiento queda fuera del alcance del laboratorio."
  identifier     = "${var.company_name}-db"
  engine         = "postgres"
  engine_version = "14"
  instance_class = "db.t3.micro"
  allocated_storage = 20

  db_name  = "fleetsec"
  username = "dbadmin"
  password = random_password.db.result

  multi_az                            = true
  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.rds.arn
  db_subnet_group_name                = aws_db_subnet_group.data.name
  vpc_security_group_ids              = [aws_security_group.data.id]
  parameter_group_name                = aws_db_parameter_group.secure.name
  backup_retention_period             = 7
  auto_minor_version_upgrade          = true
  deletion_protection                 = true
  iam_database_authentication_enabled = true
  copy_tags_to_snapshot               = true
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  skip_final_snapshot                 = true
}
