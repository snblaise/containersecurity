# CloudWatch Log Groups for Container Security Monitoring
# This configuration creates log groups for EKS cluster components and application logs

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# EKS Control Plane Log Group
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name        = "${var.cluster_name}-eks-logs"
    Component   = "EKS Control Plane"
    SecurityLevel = "High"
  })
}

# Container Application Log Group
resource "aws_cloudwatch_log_group" "container_apps" {
  name              = "/aws/containerinsights/${var.cluster_name}/application"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name        = "${var.cluster_name}-app-logs"
    Component   = "Container Applications"
    SecurityLevel = "High"
  })
}

# Security Events Log Group
resource "aws_cloudwatch_log_group" "security_events" {
  name              = "/aws/eks/${var.cluster_name}/security-events"
  retention_in_days = var.security_log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name        = "${var.cluster_name}-security-logs"
    Component   = "Security Events"
    SecurityLevel = "Critical"
  })
}

# Audit Log Group for API Server
resource "aws_cloudwatch_log_group" "audit_logs" {
  name              = "/aws/eks/${var.cluster_name}/audit"
  retention_in_days = var.audit_log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name        = "${var.cluster_name}-audit-logs"
    Component   = "API Server Audit"
    SecurityLevel = "Critical"
  })
}

# Container Insights Performance Log Group
resource "aws_cloudwatch_log_group" "performance" {
  name              = "/aws/containerinsights/${var.cluster_name}/performance"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name        = "${var.cluster_name}-performance-logs"
    Component   = "Container Insights"
    SecurityLevel = "Medium"
  })
}

# Log Stream for Pod Security Admission Events
resource "aws_cloudwatch_log_stream" "psa_events" {
  name           = "pod-security-admission"
  log_group_name = aws_cloudwatch_log_group.security_events.name
}

# Log Stream for Network Policy Violations
resource "aws_cloudwatch_log_stream" "network_policy_violations" {
  name           = "network-policy-violations"
  log_group_name = aws_cloudwatch_log_group.security_events.name
}

# Log Stream for Image Security Events
resource "aws_cloudwatch_log_stream" "image_security" {
  name           = "image-security-events"
  log_group_name = aws_cloudwatch_log_group.security_events.name
}