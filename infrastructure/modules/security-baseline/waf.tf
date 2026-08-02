# ===========================================================================
#  Firewall de aplicaciones web. Se configura uno para el balanceador y otro
#  para la red de distribución de contenido.
#  Reglas: se bloquean los intentos de inyección SQL y las entradas maliciosas
#  conocidas. El conjunto generico queda en modo observación para medir cuantas
#  peticiones legitimas afectaria antes de activarlo. Además se limita el ritmo
#  de peticiones al inicio de sesión y se restringe el acceso por pais.
# ===========================================================================

# Paises desde los que se permite el acceso.
locals {
  waf_geo_countries = ["CO", "PE", "US"]
}

# --- Firewall del balanceador ---------------------------------------------
resource "aws_wafv2_web_acl" "alb" {
  #checkov:skip=CKV2_AWS_31:"El envio de los registros del firewall a un servicio de streaming queda fuera del alcance. Se usan las métricas del servicio de monitoreo."
  name        = "${var.company_name}-alb-acl"
  description = "Firewall de aplicaciones del balanceador de FleetSec"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.company_name}-alb-acl"
    sampled_requests_enabled   = true
  }

  # 1. Inyección SQL, se bloquea
  rule {
    name     = "AWS-SQLi"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sqli"
      sampled_requests_enabled   = true
    }
  }

  # 2. Entradas maliciosas conocidas, se bloquean
  rule {
    name     = "AWS-KnownBadInputs"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # 3. Conjunto generico en modo observación, para medir falsos positivos
  rule {
    name     = "AWS-Common-COUNT"
    priority = 3
    override_action {
      count {} # primero se mide el impacto sobre el trafico legítimo
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common-count"
      sampled_requests_enabled   = true
    }
  }

  # 4. Limite de mil peticiones cada cinco minutos por dirección, aplicado
  #    solo sobre el inicio de sesión.
  rule {
    name     = "RateLimitAuth"
    priority = 4
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
        scope_down_statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/login"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit-auth"
      sampled_requests_enabled   = true
    }
  }

  # 5. Restricción por pais: se bloquea todo origen fuera de la lista.
  rule {
    name     = "GeoRestriction"
    priority = 5
    action {
      block {}
    }
    statement {
      not_statement {
        statement {
          geo_match_statement {
            country_codes = local.waf_geo_countries
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "geo-restriction"
      sampled_requests_enabled   = true
    }
  }
}

# --- Firewall del borde de la red de distribución -------------------------
# Este alcance solo se puede crear desde la región us-east-1.
resource "aws_wafv2_web_acl" "cloudfront" {
  #checkov:skip=CKV2_AWS_31:"El envio de los registros del firewall a un servicio de streaming queda fuera del alcance. Se usan las métricas del servicio de monitoreo."
  name        = "${var.company_name}-cloudfront-acl"
  description = "Firewall del borde de la red de distribución de FleetSec"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.company_name}-cloudfront-acl"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "AWS-SQLi"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "cf-sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWS-KnownBadInputs"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "cf-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "GeoRestriction"
    priority = 3
    action {
      block {}
    }
    statement {
      not_statement {
        statement {
          geo_match_statement {
            country_codes = local.waf_geo_countries
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "cf-geo-restriction"
      sampled_requests_enabled   = true
    }
  }
}
