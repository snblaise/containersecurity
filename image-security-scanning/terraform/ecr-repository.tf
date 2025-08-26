# ECR Repository with Security Configurations
resource "aws_ecr_repository" "secure_app_repo" {
  name                 = var.repository_name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr_key.arn
  }

  tags = {
    Name        = var.repository_name
    Environment = var.environment
    Security    = "high"
    Compliance  = "required"
  }
}

# KMS Key for ECR encryption
resource "aws_kms_key" "ecr_key" {
  description             = "KMS key for ECR repository encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow ECR Service"
        Effect = "Allow"
        Principal = {
          Service = "ecr.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.repository_name}-ecr-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "ecr_key_alias" {
  name          = "alias/${var.repository_name}-ecr"
  target_key_id = aws_kms_key.ecr_key.key_id
}

# ECR Repository Policy
resource "aws_ecr_repository_policy" "secure_app_policy" {
  repository = aws_ecr_repository.secure_app_repo.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPushPull"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.codebuild_role_name}",
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.eks_node_role_name}",
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.eks_fargate_role_name}"
          ]
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeRepositories",
          "ecr:GetRepositoryPolicy",
          "ecr:ListImages",
          "ecr:DescribeImages",
          "ecr:BatchDeleteImage",
          "ecr:GetLifecyclePolicy",
          "ecr:GetLifecyclePolicyPreview",
          "ecr:ListTagsForResource",
          "ecr:DescribeImageScanFindings"
        ]
      },
      {
        Sid    = "AllowImageSigning"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.codebuild_role_name}"
        }
        Action = [
          "ecr:PutImageTagMutability",
          "ecr:StartImageScan",
          "ecr:DescribeImageScanFindings",
          "ecr:GetAuthorizationToken"
        ]
      },
      {
        Sid    = "DenyDeleteOfSignedImages"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "ecr:BatchDeleteImage",
          "ecr:PutImage"
        ]
        Condition = {
          StringLike = {
            "ecr:ImageTag" = [
              "prod-*",
              "release-*"
            ]
          }
        }
      },
      {
        Sid    = "RequireSSL"
        Effect = "Deny"
        Principal = "*"
        Action = "*"
        Resource = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ECR Lifecycle Policy
resource "aws_ecr_lifecycle_policy" "secure_app_lifecycle" {
  repository = aws_ecr_repository.secure_app_repo.name

  policy = file("${path.module}/../ecr-policies/lifecycle-policy.json")
}

# CloudWatch Log Group for ECR events
resource "aws_cloudwatch_log_group" "ecr_scan_logs" {
  name              = "/aws/ecr/${var.repository_name}/scan-results"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.ecr_key.arn

  tags = {
    Name        = "${var.repository_name}-scan-logs"
    Environment = var.environment
  }
}

# EventBridge rule for ECR scan completion
resource "aws_cloudwatch_event_rule" "ecr_scan_complete" {
  name        = "${var.repository_name}-scan-complete"
  description = "Capture ECR image scan completion events"

  event_pattern = jsonencode({
    source      = ["aws.ecr"]
    detail-type = ["ECR Image Scan"]
    detail = {
      repository-name = [aws_ecr_repository.secure_app_repo.name]
      scan-status     = ["COMPLETE"]
    }
  })

  tags = {
    Name        = "${var.repository_name}-scan-complete"
    Environment = var.environment
  }
}

# Lambda function for processing scan results
resource "aws_lambda_function" "process_scan_results" {
  filename         = "process_scan_results.zip"
  function_name    = "${var.repository_name}-process-scan-results"
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 60

  environment {
    variables = {
      REPOSITORY_NAME      = aws_ecr_repository.secure_app_repo.name
      CRITICAL_THRESHOLD   = var.critical_threshold
      HIGH_THRESHOLD       = var.high_threshold
      SNS_TOPIC_ARN       = aws_sns_topic.security_alerts.arn
    }
  }

  tags = {
    Name        = "${var.repository_name}-process-scan-results"
    Environment = var.environment
  }
}

# EventBridge target for Lambda
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.ecr_scan_complete.name
  target_id = "ProcessScanResultsTarget"
  arn       = aws_lambda_function.process_scan_results.arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.process_scan_results.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ecr_scan_complete.arn
}

# SNS Topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.repository_name}-security-alerts"
  kms_master_key_id = aws_kms_key.ecr_key.arn

  tags = {
    Name        = "${var.repository_name}-security-alerts"
    Environment = var.environment
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}