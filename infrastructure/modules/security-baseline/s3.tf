# ===========================================================================
#  Almacenamiento. Bloqueo de acceso público en toda la cuenta y un depósito
#  de auditoría que no se puede alterar.
# ===========================================================================

# --- Bloqueo de acceso público para toda la cuenta ------------------------
# Se aplica a cualquier depósito existente o futuro.
resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy      = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Depósito de registros de auditoría -----------------------------------
# Queda en modo de cumplimiento, lo que significa que una vez escrito el
# registro no se puede modificar ni borrar durante el plazo definido.
resource "aws_s3_bucket" "audit_logs" {
  #checkov:skip=CKV_AWS_18:"El depósito de registros no se audita a si mismo para evitar un ciclo infinito de escritura."
  #checkov:skip=CKV_AWS_144:"La replica entre regiones queda fuera del alcance de este laboratorio."
  #checkov:skip=CKV2_AWS_62:"Este depósito de auditoría no necesita enviar notificaciones de eventos."
  bucket              = "${var.company_name}-${var.environment}-audit-logs-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = true
}

# El versionado es obligatorio para poder bloquear la modificación de objetos
resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Retención inmutable durante un año. Ni siquiera la cuenta raíz puede borrar
# los registros antes de que se cumpla el plazo.
resource "aws_s3_bucket_object_lock_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}

# Cifrado en reposo con la clave dedicada del almacenamiento
resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Bloqueo público también a nivel del propio depósito, como segunda barrera
resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy      = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Ciclo de vida: pasar los registros a almacenamiento frio a los 180 días y
# limpiar las cargas que quedaron a medias.
resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    id     = "archivar-glacier-180d"
    status = "Enabled"
    filter {}
    transition {
      days          = 180
      storage_class = "GLACIER"
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Permisos del depósito: deja escribir al registro de actividad de la cuenta y
# al servicio de inventario de configuración.
data "aws_iam_policy_document" "audit_logs" {
  statement {
    sid       = "CloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit_logs.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "CloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  # Servicio de inventario de configuración: verificación de permisos y
  # entrega de las fotografias del estado de los recursos.
  statement {
    sid       = "ConfigAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit_logs.arn]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
  statement {
    sid       = "ConfigWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  # Obliga a que todo acceso al depósito viaje cifrado
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit_logs.arn, "${aws_s3_bucket.audit_logs.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  policy = data.aws_iam_policy_document.audit_logs.json
}
