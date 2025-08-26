# AWS Security Groups for EKS Pods
# Terraform configuration for creating security groups used with Security Groups for Pods

# Data sources for VPC and cluster information
data "aws_vpc" "eks_vpc" {
  tags = {
    Name = var.vpc_name
  }
}

data "aws_eks_cluster" "cluster" {
  name = var.cluster_name
}

# Common egress security group - allows outbound HTTPS and DNS
resource "aws_security_group" "common_egress" {
  name_prefix = "${var.cluster_name}-common-egress-"
  description = "Common egress rules for all pods"
  vpc_id      = data.aws_vpc.eks_vpc.id

  # Allow HTTPS egress
  egress {
    description = "HTTPS egress"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow DNS egress
  egress {
    description = "DNS egress"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow NTP egress
  egress {
    description = "NTP egress"
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-common-egress"
    Environment = var.environment
    Purpose     = "EKS-SGP-Common"
  }
}

# Frontend web security group
resource "aws_security_group" "frontend_web" {
  name_prefix = "${var.cluster_name}-frontend-web-"
  description = "Security group for frontend web pods"
  vpc_id      = data.aws_vpc.eks_vpc.id

  # Allow ingress from ALB security group
  ingress {
    description     = "HTTP from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Allow ingress from other frontend pods (for health checks)
  ingress {
    description = "Health checks from other frontend pods"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    self        = true
  }

  # Allow egress to backend API
  egress {
    description     = "To backend API"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.backend_api.id]
  }

  tags = {
    Name        = "${var.cluster_name}-frontend-web"
    Environment = var.environment
    Purpose     = "EKS-SGP-Frontend"
  }
}

# Backend API security group
resource "aws_security_group" "backend_api" {
  name_prefix = "${var.cluster_name}-backend-api-"
  description = "Security group for backend API pods"
  vpc_id      = data.aws_vpc.eks_vpc.id

  # Allow ingress from frontend
  ingress {
    description     = "From frontend"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend_web.id]
  }

  # Allow ingress from other backend services
  ingress {
    description = "From other backend services"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    self        = true
  }

  # Allow egress to database
  egress {
    description     = "To database"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.database.id]
  }

  # Allow egress to Redis
  egress {
    description     = "To Redis cache"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.redis.id]
  }

  tags = {
    Name        = "${var.cluster_name}-backend-api"
    Environment = var.environment
    Purpose     = "EKS-SGP-Backend"
  }
}

# Database security group
resource "aws_security_group" "database" {
  name_prefix = "${var.cluster_name}-database-"
  description = "Security group for database pods"
  vpc_id      = data.aws_vpc.eks_vpc.id

  # Allow ingress from backend API only
  ingress {
    description     = "PostgreSQL from backend"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.backend_api.id]
  }

  # Allow ingress from other database pods (replication)
  ingress {
    description = "Database replication"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    self        = true
  }

  # No egress rules - inherits from common_egress

  tags = {
    Name        = "${var.cluster_name}-database"
    Environment = var.environment
    Purpose     = "EKS-SGP-Database"
  }
}

# Payment service security group (PCI compliant)
resource "aws_security_group" "payment_service" {
  name_prefix = "${var.cluster_name}-payment-service-"
  description = "Highly restricted security group for payment service"
  vpc_id      = data.aws_vpc.eks_vpc.id

  # Allow ingress only from order service
  ingress {
    description     = "From order service only"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.order_service.id]
  }

  # Allow egress to payment database
  egress {
    description     = "To payment database"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.payment_database.id]
  }

  # Allow egress to external payment processors (specific IPs)
  egress {
    description = "To Stripe API"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["54.187.174.169/32", "54.187.205.235/32"] # Stripe IPs
  }

  tags = {
    Name        = "${var.cluster_name}-payment-service"
    Environment = var.environment
    Purpose     = "EKS-SGP-Payment"
    Compliance  = "PCI-DSS"
  }
}

# ALB security group
resource "aws_security_group" "alb" {
  name_prefix = "${var.cluster_name}-alb-"
  description = "Security group for Application Load Balancer"
  vpc_id      = data.aws_vpc.eks_vpc.id

  # Allow HTTP ingress from internet
  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTPS ingress from internet
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow egress to frontend pods
  egress {
    description     = "To frontend pods"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend_web.id]
  }

  tags = {
    Name        = "${var.cluster_name}-alb"
    Environment = var.environment
    Purpose     = "EKS-ALB"
  }
}

# Monitoring security group
resource "aws_security_group" "monitoring" {
  name_prefix = "${var.cluster_name}-monitoring-"
  description = "Security group for monitoring pods"
  vpc_id      = data.aws_vpc.eks_vpc.id

  # Allow ingress from Grafana
  ingress {
    description     = "From Grafana"
    from_port       = 9090
    to_port         = 9090
    protocol        = "tcp"
    security_groups = [aws_security_group.grafana.id]
  }

  # Allow egress to scrape metrics from all application pods
  egress {
    description = "Metrics scraping"
    from_port   = 8080
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.eks_vpc.cidr_block]
  }

  tags = {
    Name        = "${var.cluster_name}-monitoring"
    Environment = var.environment
    Purpose     = "EKS-SGP-Monitoring"
  }
}

# Output security group IDs for use in SecurityGroupPolicy
output "security_group_ids" {
  description = "Security group IDs for use in SecurityGroupPolicy resources"
  value = {
    common_egress    = aws_security_group.common_egress.id
    frontend_web     = aws_security_group.frontend_web.id
    backend_api      = aws_security_group.backend_api.id
    database         = aws_security_group.database.id
    payment_service  = aws_security_group.payment_service.id
    monitoring       = aws_security_group.monitoring.id
    alb              = aws_security_group.alb.id
  }
}