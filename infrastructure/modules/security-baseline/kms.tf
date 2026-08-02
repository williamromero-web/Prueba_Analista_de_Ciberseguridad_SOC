# ===========================================================================
#  Claves de cifrado. Una clave propia y dedicada para cada servicio: uno para
#  el almacenamiento, otro para la base de datos y otro para los contenedores.
#  Todas rotan una vez al año y ninguna política deja el acceso abierto.
# ===========================================================================

# Política reutilizable: solo la propia cuenta administra la clave.
# En ningún caso se deja el acceso abierto a cualquier origen.
data "aws_iam_policy_document" "kms_account_admin" {
  #checkov:skip=CKV_AWS_109:"Es una política de clave, no de identidad. El asterisco se refiere a la clave misma y el acceso queda limitado a la cuenta. Es el patron estándar de AWS. Revisado por W.Romero el 2026-08-01."
  #checkov:skip=CKV_AWS_111:"Política de clave con permisos amplios solo sobre esa clave y limitada a la cuenta propietaria. Revisado por W.Romero el 2026-08-01."
  #checkov:skip=CKV_AWS_356:"El asterisco identifica la propia clave, no es una política de identidad. Revisado por W.Romero el 2026-08-01."
  statement {
    sid     = "EnableIAMUserPermissions"
    effect  = "Allow"
    actions = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

# Clave para cifrar el almacenamiento de objetos
resource "aws_kms_key" "s3" {
  description             = "Clave para cifrar el almacenamiento de FleetSec"
  deletion_window_in_days = 30
  enable_key_rotation     = true # rotación automática cada año
  policy                  = data.aws_iam_policy_document.kms_account_admin.json
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${var.company_name}-s3"
  target_key_id = aws_kms_key.s3.key_id
}

# Clave para cifrar la base de datos
resource "aws_kms_key" "rds" {
  description             = "Clave para cifrar la base de datos de FleetSec"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_account_admin.json
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.company_name}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# Clave para los contenedores y el gestor de secretos de la aplicación
resource "aws_kms_key" "ecs" {
  description             = "Clave para los contenedores y el gestor de secretos de FleetSec"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_account_admin.json
}

resource "aws_kms_alias" "ecs" {
  name          = "alias/${var.company_name}-ecs"
  target_key_id = aws_kms_key.ecs.key_id
}
