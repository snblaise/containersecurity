# AWS Signer Configuration for Container Image Signing

# Signing Profile for Container Images
resource "aws_signer_signing_profile" "container_signing" {
  platform_id = "AWSLambda-SHA256-ECDSA"
  name        = var.signing_profile_name

  signature_validity_period {
    value = var.signature_validity_days
    type  = "DAYS"
  }

  tags = {
    Name        = var.signing_profile_name
    Environment = var.environment
    Purpose     = "container-image-signing"
  }
}

# S3 Bucket for Signing Artifacts
resource "aws_s3_bucket" "signing_artifacts" {
  bucket = "${var.project_name}-signing-artifacts-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "${var.project_name}-signing-artifacts"
    Environment = var.environment
    Purpose     = "container-signing-artifacts"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "signing_artifacts_versioning" {
  bucket = aws_s3_bucket.signing_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "signing_artifacts_encryption" {
  bucket = aws_s3_bucket.signing_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.signing_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "signing_artifacts_pab" {
  bucket = aws_s3_bucket.signing_artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS Key for Signing Artifacts
resource "aws_kms_key" "signing_key" {
  description             = "KMS key for container signing artifacts"
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
        Sid    = "Allow Signer Service"
        Effect = "Allow"
        Principal = {
          Service = "signer.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CodeBuild"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.codebuild_role_name}"
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
    Name        = "${var.project_name}-signing-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "signing_key_alias" {
  name          = "alias/${var.project_name}-signing"
  target_key_id = aws_kms_key.signing_key.key_id
}

# IAM Role for Signing Operations
resource "aws_iam_role" "signing_role" {
  name = "${var.project_name}-signing-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.codebuild_role_name}"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-signing-role"
    Environment = var.environment
  }
}

# IAM Policy for Signing Operations
resource "aws_iam_role_policy" "signing_policy" {
  name = "${var.project_name}-signing-policy"
  role = aws_iam_role.signing_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "signer:StartSigningJob",
          "signer:DescribeSigningJob",
          "signer:GetSigningProfile",
          "signer:ListSigningJobs"
        ]
        Resource = [
          aws_signer_signing_profile.container_signing.arn,
          "arn:aws:signer:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:signing-job/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.signing_artifacts.arn,
          "${aws_s3_bucket.signing_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant"
        ]
        Resource = aws_kms_key.signing_key.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:DescribeImages",
          "ecr:DescribeRepositories"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Log Group for Signing Operations
resource "aws_cloudwatch_log_group" "signing_logs" {
  name              = "/aws/signer/${var.project_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.signing_key.arn

  tags = {
    Name        = "${var.project_name}-signing-logs"
    Environment = var.environment
  }
}

# EventBridge Rule for Signing Job Events
resource "aws_cloudwatch_event_rule" "signing_job_events" {
  name        = "${var.project_name}-signing-job-events"
  description = "Capture AWS Signer job completion events"

  event_pattern = jsonencode({
    source      = ["aws.signer"]
    detail-type = ["Signer Job State Change"]
    detail = {
      profileName = [aws_signer_signing_profile.container_signing.name]
      status      = ["Succeeded", "Failed"]
    }
  })

  tags = {
    Name        = "${var.project_name}-signing-job-events"
    Environment = var.environment
  }
}

# Lambda Function for Processing Signing Events
resource "aws_lambda_function" "process_signing_events" {
  filename         = "process_signing_events.zip"
  function_name    = "${var.project_name}-process-signing-events"
  role            = aws_iam_role.signing_lambda_role.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 60

  environment {
    variables = {
      SIGNING_PROFILE_NAME = aws_signer_signing_profile.container_signing.name
      S3_BUCKET           = aws_s3_bucket.signing_artifacts.bucket
      SNS_TOPIC_ARN       = aws_sns_topic.signing_notifications.arn
    }
  }

  tags = {
    Name        = "${var.project_name}-process-signing-events"
    Environment = var.environment
  }
}

# IAM Role for Signing Lambda
resource "aws_iam_role" "signing_lambda_role" {
  name = "${var.project_name}-signing-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-signing-lambda-role"
    Environment = var.environment
  }
}

# IAM Policy for Signing Lambda
resource "aws_iam_role_policy" "signing_lambda_policy" {
  name = "${var.project_name}-signing-lambda-policy"
  role = aws_iam_role.signing_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "signer:DescribeSigningJob",
          "signer:GetSigningProfile"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.signing_artifacts.arn,
          "${aws_s3_bucket.signing_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.signing_notifications.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.signing_key.arn
      }
    ]
  })
}

# EventBridge Target for Lambda
resource "aws_cloudwatch_event_target" "signing_lambda_target" {
  rule      = aws_cloudwatch_event_rule.signing_job_events.name
  target_id = "ProcessSigningEventsTarget"
  arn       = aws_lambda_function.process_signing_events.arn
}

# Lambda Permission for EventBridge
resource "aws_lambda_permission" "allow_signing_eventbridge" {
  statement_id  = "AllowExecutionFromSigningEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.process_signing_events.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.signing_job_events.arn
}

# SNS Topic for Signing Notifications
resource "aws_sns_topic" "signing_notifications" {
  name              = "${var.project_name}-signing-notifications"
  kms_master_key_id = aws_kms_key.signing_key.arn

  tags = {
    Name        = "${var.project_name}-signing-notifications"
    Environment = var.environment
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}