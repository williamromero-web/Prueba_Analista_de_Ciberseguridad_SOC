# ===========================================================================
#  Identidades y permisos. Política de contraseñas de la cuenta y roles para
#  los contenedores con los permisos mínimos que necesitan.
#  No hay claves de la cuenta raíz en el código. Su uso se vigila con alarmas.
# ===========================================================================

# --- Política de contraseñas de la cuenta -------------------------------
# Mínimo 14 caracteres, cambio cada 90 días y sin repetir las últimas 24.
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# --- Rol de arranque de los contenedores --------------------------------
# Permite descargar la imagen y escribir los registros de ejecución.
resource "aws_iam_role" "ecs_execution" {
  name = "${var.company_name}-${var.environment}-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

# Política gestionada por AWS para el arranque de tareas. No se otorga acceso
# de administrador en ningún momento.
resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- Rol de la aplicación en ejecución -----------------------------------
# Permiso mínimo: solo leer la credencial de la base de datos y descifrarla.
resource "aws_iam_role" "ecs_task" {
  name = "${var.company_name}-${var.environment}-ecs-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

# Política limitada a recursos concretos, sin comodines en las acciones.
data "aws_iam_policy_document" "ecs_task_least_privilege" {
  statement {
    sid       = "LeerSecretoRDS"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.rds.arn]
  }
  statement {
    sid       = "DescifrarConCMKecs"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.ecs.arn]
  }
}

resource "aws_iam_role_policy" "ecs_task_least_privilege" {
  name   = "${var.company_name}-ecs-task-least-privilege"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.ecs_task_least_privilege.json
}
