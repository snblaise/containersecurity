# CloudWatch Alarms for Container Security Events
# This configuration creates alarms for critical security events and policy violations

# Alarm for Pod Security Admission Violations
resource "aws_cloudwatch_metric_alarm" "psa_violations" {
  alarm_name          = "${var.cluster_name}-psa-violations"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "PodSecurityAdmissionViolations"
  namespace           = "EKS/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors Pod Security Admission policy violations"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    ClusterName = var.cluster_name
  }

  tags = var.common_tags
}

# Alarm for Failed Container Image Pulls
resource "aws_cloudwatch_metric_alarm" "image_pull_failures" {
  alarm_name          = "${var.cluster_name}-image-pull-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ImagePullBackOff"
  namespace           = "ContainerInsights"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors container image pull failures"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    ClusterName = var.cluster_name
  }

  tags = var.common_tags
}

# Alarm for High Privilege Container Starts
resource "aws_cloudwatch_metric_alarm" "privileged_containers" {
  alarm_name          = "${var.cluster_name}-privileged-containers"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "PrivilegedContainerStarts"
  namespace           = "EKS/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors privileged container starts"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    ClusterName = var.cluster_name
  }

  tags = var.common_tags
}

# Alarm for Network Policy Violations
resource "aws_cloudwatch_metric_alarm" "network_policy_violations" {
  alarm_name          = "${var.cluster_name}-network-policy-violations"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "NetworkPolicyViolations"
  namespace           = "EKS/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors network policy violations"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    ClusterName = var.cluster_name
  }

  tags = var.common_tags
}

# SNS Topic for Security Alerts
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.cluster_name}-security-alerts"
  kms_master_key_id = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name      = "${var.cluster_name}-security-alerts"
    Component = "Security Monitoring"
  })
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

data "aws_caller_identity" "current" {}