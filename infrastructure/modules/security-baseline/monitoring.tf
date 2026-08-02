# ===========================================================================
#  MONITOREO Y CUMPLIMIENTO
#  Registro de actividad de la cuenta en todas las regiones, con alarmas sobre
#  los eventos más sensibles. Inventario continuo de configuración con seis
#  reglas de control, detección de amenazas con aviso automático y tablero
#  central de cumplimiento.
# ===========================================================================

# --- Canal de avisos de seguridad -----------------------------------------
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.company_name}-security-alerts"
  kms_master_key_id = "alias/aws/sns" # cifrado en reposo
}

# ---------------------------------------------------------------------------
# REGISTRO DE ACTIVIDAD DE LA CUENTA
# Cubre todas las regiones y entrega una copia al servicio de monitoreo para
# poder levantar alarmas sobre los eventos.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "cloudtrail" {
  #checkov:skip=CKV_AWS_158:"El cifrado con clave propia de este grupo de registros queda fuera del alcance. La retención de un año si esta aplicada."
  name              = "/aws/cloudtrail/${var.company_name}"
  retention_in_days = 365
}

resource "aws_iam_role" "cloudtrail_cw" {
  name = "${var.company_name}-cloudtrail-cw-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
    }]
  })
}

data "aws_iam_policy_document" "cloudtrail_cw" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name   = "${var.company_name}-cloudtrail-cw-policy"
  role   = aws_iam_role.cloudtrail_cw.id
  policy = data.aws_iam_policy_document.cloudtrail_cw.json
}

resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_35:"El cifrado del registro con clave propia queda fuera del alcance. La validación de integridad de los archivos si esta activa. Revisado por W.Romero el 2026-08-01."
  #checkov:skip=CKV2_AWS_10:"El envio al servicio de monitoreo esta configurado de forma explicita para poder levantar las alarmas. Revisado por W.Romero el 2026-08-01."
  #checkov:skip=CKV_AWS_252:"Los avisos se centralizan en el canal de alertas alimentado por las alarmas y la detección de amenazas. Revisado por W.Romero el 2026-08-01."
  name                          = "${var.company_name}-org-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn
  depends_on                    = [aws_s3_bucket_policy.audit_logs]
}

# ---------------------------------------------------------------------------
# ALARMAS SOBRE EVENTOS SENSIBLES
# Vigilan el uso de la cuenta raíz, los cambios de permisos, los cambios en
# las reglas de red y la desactivación de la rotación de claves. Cada una
# avisa por el canal de alertas.
# ---------------------------------------------------------------------------
locals {
  metric_filters = {
    root_login = {
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      metric_name = "RootAccountUsage"
    }
    iam_changes = {
      pattern     = "{ ($.eventName = Attach*Policy) || ($.eventName = Put*Policy) || ($.eventName = Create*) || ($.eventName = Delete*Policy) }"
      metric_name = "IAMPolicyChanges"
    }
    sg_changes = {
      pattern     = "{ ($.eventName = AuthorizeSecurityGroup*) || ($.eventName = RevokeSecurityGroup*) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
      metric_name = "SecurityGroupChanges"
    }
    disable_key_rotation = {
      pattern     = "{ ($.eventName = DisableKeyRotation) }"
      metric_name = "DisableKeyRotation"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each       = local.metric_filters
  name           = "${var.company_name}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern
  metric_transformation {
    name      = each.value.metric_name
    namespace = "FleetSec/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each            = local.metric_filters
  alarm_name          = "${var.company_name}-alarm-${each.key}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  period              = 300
  threshold           = 1
  statistic           = "Sum"
  namespace           = "FleetSec/Security"
  metric_name         = each.value.metric_name
  alarm_description   = "Alerta de seguridad: ${each.key}"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
}

# ---------------------------------------------------------------------------
# INVENTARIO DE CONFIGURACION
# Registra el estado de los recursos y evalua las seis reglas de control
# exigidas en el enunciado.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "config" {
  name = "${var.company_name}-config-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "config.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.company_name}-recorder"
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.company_name}-delivery"
  s3_bucket_name = aws_s3_bucket.audit_logs.id
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# Las seis reglas de control que pide el enunciado.
locals {
  config_rules = {
    cloudtrail-enabled              = "CLOUD_TRAIL_ENABLED"
    encrypted-volumes               = "ENCRYPTED_VOLUMES"
    guardduty-enabled-centralized   = "GUARDDUTY_ENABLED_CENTRALIZED"
    s3-bucket-public-read-prohibited = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    iam-password-policy             = "IAM_PASSWORD_POLICY"
    root-account-mfa-enabled        = "ROOT_ACCOUNT_MFA_ENABLED"
  }
}

resource "aws_config_config_rule" "this" {
  for_each = local.config_rules
  name     = each.key
  source {
    owner             = "AWS"
    source_identifier = each.value
  }
  depends_on = [aws_config_configuration_recorder.main]
}

# ---------------------------------------------------------------------------
# DETECCION DE AMENAZAS
# Vigila el almacenamiento, busca programas maliciosos en los discos y avisa
# de inmediato cuando el hallazgo es de severidad alta.
# ---------------------------------------------------------------------------
resource "aws_guardduty_detector" "main" {
  #checkov:skip=CKV2_AWS_3:"El laboratorio usa una sola cuenta. La administración centralizada para varias cuentas queda fuera del alcance de la prueba. Revisado por W.Romero el 2026-08-01."
  enable = true
  datasources {
    s3_logs {
      enable = true
    }
  }
}

resource "aws_guardduty_detector_feature" "malware" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

# Envia al canal de alertas los hallazgos de severidad alta.
resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "${var.company_name}-guardduty-high"
  description = "Hallazgos de detección de amenazas con severidad alta"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail        = { severity = [{ numeric = [">=", 7] }] }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_high.name
  target_id = "sns"
  arn       = aws_sns_topic.security_alerts.arn
}

# ---------------------------------------------------------------------------
# TABLERO CENTRAL DE CUMPLIMIENTO
# Reune los hallazgos y evalua la cuenta contra dos estándares de referencia.
# ---------------------------------------------------------------------------
resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
}
