# ===========================================================================
#  Red privada dividida en tres capas: pública, aplicación y datos. Cada capa
#  se reparte en dos zonas de disponibilidad. La capa de datos tiene reglas de
#  red restrictivas, se registra todo el trafico y ningún grupo de seguridad
#  queda abierto a internet salvo los puertos web del balanceador.
# ===========================================================================

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.company_name}-vpc" }
}

# --- Cierra por completo el grupo de seguridad que viene por defecto ------
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  # Sin reglas de entrada ni de salida, queda totalmente cerrado.
}

# --- Capa pública, donde vive el balanceador ------------------------------
resource "aws_subnet" "public_az1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.region}a"
  tags              = { Name = "${var.company_name}-public-az1", Tier = "public" }
}
resource "aws_subnet" "public_az2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.region}b"
  tags              = { Name = "${var.company_name}-public-az2", Tier = "public" }
}

# --- Capa de aplicación, donde corren los contenedores --------------------
resource "aws_subnet" "app_az1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "${var.region}a"
  tags              = { Name = "${var.company_name}-app-az1", Tier = "app" }
}
resource "aws_subnet" "app_az2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.12.0/24"
  availability_zone = "${var.region}b"
  tags              = { Name = "${var.company_name}-app-az2", Tier = "app" }
}

# --- Capa de datos, donde vive la base de datos ---------------------------
resource "aws_subnet" "data_az1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.21.0/24"
  availability_zone = "${var.region}a"
  tags              = { Name = "${var.company_name}-data-az1", Tier = "data" }
}
resource "aws_subnet" "data_az2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.22.0/24"
  availability_zone = "${var.region}b"
  tags              = { Name = "${var.company_name}-data-az2", Tier = "data" }
}

# --- Reglas de red de la capa de datos ------------------------------------
# Solo se permite el puerto de la base de datos desde la capa de aplicación y
# el retorno de esa misma conversación. Todo lo demas queda denegado.
resource "aws_network_acl" "data" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.data_az1.id, aws_subnet.data_az2.id]
  tags       = { Name = "${var.company_name}-data-nacl" }

  # Entrada: puerto de base de datos desde la capa de aplicación
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.0.11.0/24"
    from_port  = 5432
    to_port    = 5432
  }
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.0.12.0/24"
    from_port  = 5432
    to_port    = 5432
  }
  # Salida: puertos de respuesta hacia la capa de aplicación
  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 1024
    to_port    = 65535
  }
}

# --- Registro del trafico de red hacia el servicio de monitoreo -----------
resource "aws_cloudwatch_log_group" "flow_logs" {
  #checkov:skip=CKV_AWS_158:"El cifrado con clave propia de este grupo de registros queda fuera del alcance del laboratorio. La retención de un año si esta aplicada."
  name              = "/aws/vpc/${var.company_name}-flow-logs"
  retention_in_days = 365
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.company_name}-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

data "aws_iam_policy_document" "flow_logs" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "${var.company_name}-flow-logs-policy"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}

resource "aws_flow_log" "cloudwatch" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}

# --- Copia del registro de trafico al depósito de auditoría inmutable -----
resource "aws_flow_log" "s3" {
  log_destination      = aws_s3_bucket.audit_logs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.main.id
}

# ===========================================================================
#  GRUPOS DE SEGURIDAD
# ===========================================================================

# Balanceador: es el único que admite trafico público y solo en los puertos web.
resource "aws_security_group" "alb" {
  #checkov:skip=CKV_AWS_260:"Excepción prevista en el enunciado: se admite trafico desde cualquier origen únicamente en los puertos web del balanceador."
  #checkov:skip=CKV2_AWS_5:"En este laboratorio solo se válida el código, no se despliega el balanceador al que se asociaria el grupo."
  name        = "${var.company_name}-alb-sg"
  description = "Trafico web publico hacia el balanceador"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP publico"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS publico"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Salida hacia la capa de aplicacion"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["10.0.11.0/24", "10.0.12.0/24"]
  }
}

# Aplicación: solo acepta trafico que venga del balanceador.
resource "aws_security_group" "app" {
  #checkov:skip=CKV2_AWS_5:"En este laboratorio solo se válida el código, no se despliega el servicio de contenedores al que se asociaria el grupo."
  name        = "${var.company_name}-app-sg"
  description = "Trafico solo desde el balanceador"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Aplicacion desde el balanceador"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    description     = "Salida hacia la base de datos"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.data.id]
  }
}

# Datos: solo acepta conexiones de base de datos desde la capa de aplicación.
resource "aws_security_group" "data" {
  #checkov:skip=CKV2_AWS_5:"En este laboratorio solo se válida el código, no se despliega la base de datos a la que se asociaria el grupo."
  name        = "${var.company_name}-data-sg"
  description = "Base de datos accesible solo desde la capa de aplicacion"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Base de datos desde la capa de aplicacion"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.11.0/24", "10.0.12.0/24"]
  }
}
