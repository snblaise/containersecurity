# GuardDuty Configuration for EKS Threat Detection
# This configuration enables GuardDuty with EKS protection and malware scanning

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Enable GuardDuty Detector
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = merge(var.common_tags, {
    Name      = "${var.cluster_name}-guardduty"
    Component = "Threat Detection"
  })
}

# GuardDuty EKS Protection
resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

# GuardDuty EKS Runtime Monitoring
resource "aws_guardduty_detector_feature" "eks_runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EKS_RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }
}

# GuardDuty Malware Protection
resource "aws_guardduty_detector_feature" "malware_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "MALWARE_PROTECTION"
  status      = "ENABLED"

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# Custom Threat Intelligence Set for Container Security
resource "aws_guardduty_threatintelset" "container_threats" {
  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.threat_intel.bucket}/container-threats.txt"
  name        = "${var.cluster_name}-container-threats"

  depends_on = [aws_s3_object.threat_intel_file]

  tags = var.common_tags
}

# S3 Bucket for Threat Intelligence
resource "aws_s3_bucket" "threat_intel" {
  bucket        = "${var.cluster_name}-guardduty-threat-intel-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = merge(var.common_tags, {
    Name      = "${var.cluster_name}-threat-intel"
    Component = "Threat Intelligence"
  })
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# S3 Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "threat_intel" {
  bucket = aws_s3_bucket.threat_intel.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "threat_intel" {
  bucket = aws_s3_bucket.threat_intel.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Threat Intelligence File
resource "aws_s3_object" "threat_intel_file" {
  bucket  = aws_s3_bucket.threat_intel.bucket
  key     = "container-threats.txt"
  content = file("${path.module}/threat-intel/container-threats.txt")
  etag    = filemd5("${path.module}/threat-intel/container-threats.txt")

  server_side_encryption = "aws:kms"
  kms_key_id            = var.kms_key_arn

  tags = var.common_tags
}

# EventBridge Rule for GuardDuty Findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.cluster_name}-guardduty-findings"
  description = "Capture GuardDuty findings for EKS security events"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      service = {
        serviceName = ["eks"]
      }
      severity = [7.0, 8.0, 8.9]  # HIGH and CRITICAL findings only
    }
  })

  tags = var.common_tags
}

# EventBridge Target for Security Alerts
resource "aws_cloudwatch_event_target" "security_alerts" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SecurityAlertsTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn
}

# SNS Topic for GuardDuty Alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "${var.cluster_name}-guardduty-alerts"
  kms_master_key_id = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name      = "${var.cluster_name}-guardduty-alerts"
    Component = "Threat Detection"
  })
}

# SNS Topic Policy for EventBridge
resource "aws_sns_topic_policy" "guardduty_alerts" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.guardduty_alerts.arn
      }
    ]
  })
}