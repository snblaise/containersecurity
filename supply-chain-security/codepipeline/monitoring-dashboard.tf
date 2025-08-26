# CloudWatch dashboard for monitoring supply chain security gates

resource "aws_cloudwatch_dashboard" "security_gates_dashboard" {
  dashboard_name = "${var.project_name}-security-gates-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/CodeBuild", "Builds", "ProjectName", aws_codebuild_project.security_gates.name],
            [".", "SucceededBuilds", ".", "."],
            [".", "FailedBuilds", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Security Gates Build Status"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/CodeBuild", "Duration", "ProjectName", aws_codebuild_project.security_gates.name],
            [".", ".", ".", aws_codebuild_project.image_build.name]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Build Duration"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/CodePipeline", "PipelineExecutionSuccess", "PipelineName", aws_codepipeline.secure_container_pipeline.name],
            [".", "PipelineExecutionFailure", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Pipeline Execution Status"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 6
        width  = 12
        height = 6

        properties = {
          query   = "SOURCE '/aws/codebuild/security-gates'\n| fields @timestamp, @message\n| filter @message like /SECURITY GATE FAILURE/\n| sort @timestamp desc\n| limit 20"
          region  = var.aws_region
          title   = "Security Gate Failures"
          view    = "table"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["SupplyChainSecurity", "CriticalVulnerabilities", "ProjectName", var.project_name],
            [".", "HighVulnerabilities", ".", "."],
            [".", "MediumVulnerabilities", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Vulnerability Trends"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 12
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["SupplyChainSecurity", "SASTIssues", "ProjectName", var.project_name],
            [".", "SCAIssues", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "SAST/SCA Issues"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 12
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["SupplyChainSecurity", "BuildsBlocked", "ProjectName", var.project_name],
            [".", "ImagesScanned", ".", "."],
            [".", "ImagesSigned", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Security Metrics"
          period  = 300
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Purpose     = "SecurityGatesMonitoring"
  }
}

# CloudWatch alarms for security gate failures
resource "aws_cloudwatch_metric_alarm" "security_gate_failures" {
  alarm_name          = "${var.project_name}-security-gate-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "FailedBuilds"
  namespace           = "AWS/CodeBuild"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors security gate build failures"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    ProjectName = aws_codebuild_project.security_gates.name
  }

  tags = {
    Environment = var.environment
    Purpose     = "SecurityGateMonitoring"
  }
}

resource "aws_cloudwatch_metric_alarm" "critical_vulnerabilities" {
  alarm_name          = "${var.project_name}-critical-vulnerabilities"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CriticalVulnerabilities"
  namespace           = "SupplyChainSecurity"
  period              = "300"
  statistic           = "Maximum"
  threshold           = "0"
  alarm_description   = "This metric monitors critical vulnerabilities detected"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    ProjectName = var.project_name
  }

  tags = {
    Environment = var.environment
    Purpose     = "VulnerabilityMonitoring"
  }
}

# SNS topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name = "${var.project_name}-security-alerts"

  tags = {
    Environment = var.environment
    Purpose     = "SecurityAlerts"
  }
}

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
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}