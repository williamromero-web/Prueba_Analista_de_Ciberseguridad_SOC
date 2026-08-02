# ===========================================================================
#  Datos que expone el módulo para poder integrarlo con otros componentes.
# ===========================================================================
output "vpc_id" {
  value       = aws_vpc.main.id
  description = "Identificador de la red principal."
}

output "audit_bucket" {
  value       = aws_s3_bucket.audit_logs.id
  description = "Depósito de registros de auditoría con retención inmutable."
}

output "security_alerts_topic_arn" {
  value       = aws_sns_topic.security_alerts.arn
  description = "Identificador del canal de alertas de seguridad."
}

output "waf_alb_acl_arn" {
  value       = aws_wafv2_web_acl.alb.arn
  description = "Identificador del firewall de aplicaciones del balanceador."
}

output "rds_secret_arn" {
  value       = aws_secretsmanager_secret.rds.arn
  description = "Identificador de la credencial de la base de datos en el gestor de secretos."
}
