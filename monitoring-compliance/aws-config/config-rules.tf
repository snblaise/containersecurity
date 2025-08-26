# AWS Config Rules for Container Security Compliance Monitoring
# This configuration creates Config rules for continuous compliance monitoring
# Requirements: 4.2, 4.5

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# AWS Config Configuration Recorder
resource "aws_config_configuration_recorder" "container_security" {
  name     = "${var.cluster_name}-container-security-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = true
    
    resource_types = [
      "AWS::EKS::Cluster",
      "AWS::ECR::Repository",
      "AWS::IAM::Role",
      "AWS::IAM::Policy",
      "AWS::KMS::Key",
      "AWS::S3::Bucket",
      "AWS::SecretsManager::Secret",
      "AWS::EC2::SecurityGroup",
      "AWS::EC2::VPC",
      "AWS::CloudTrail::Trail",
      "AWS::GuardDuty::Detector"
    ]
  }

  depends_on = [aws_config_delivery_channel.container_security]
}

# AWS Config Delivery Channel
resource "aws_config_delivery_channel" "container_security" {
  name           = "${var.cluster_name}-container-security-delivery"
  s3_bucket_name = aws_s3_bucket.config_bucket.bucket
  s3_key_prefix  = "config"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
}

# S3 Bucket for Config
resource "aws_s3_bucket" "config_bucket" {
  bucket        = "${var.cluster_name}-config-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = merge(var.common_tags, {
    Name      = "${var.cluster_name}-config-bucket"
    Component = "Compliance Monitoring"
  })
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# S3 Bucket Policy for Config
resource "aws_s3_bucket_policy" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config_bucket.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.config_bucket.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# S3 Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM Role for Config
resource "aws_iam_role" "config_role" {
  name = "${var.cluster_name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = var.common_tags
}

# IAM Role Policy Attachment for Config
resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# Config Rule: EKS Cluster Endpoint Access
resource "aws_config_config_rule" "eks_endpoint_access" {
  name = "${var.cluster_name}-eks-endpoint-access"

  source {
    owner             = "AWS"
    source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.container_security]

  tags = var.common_tags
}

# Config Rule: EKS Cluster Logging Enabled
resource "aws_config_config_rule" "eks_logging_enabled" {
  name = "${var.cluster_name}-eks-logging-enabled"

  source {
    owner             = "AWS"
    source_identifier = "EKS_CLUSTER_LOGGING_ENABLED"
  }

  input_parameters = jsonencode({
    requiredLogTypes = "api,audit,authenticator,controllerManager,scheduler"
  })

  depends_on = [aws_config_configuration_recorder.container_security]

  tags = var.common_tags
}

# Config Rule: ECR Repository Scan on Push
resource "aws_config_config_rule" "ecr_scan_on_push" {
  name = "${var.cluster_name}-ecr-scan-on-push"

  source {
    owner             = "AWS"
    source_identifier = "ECR_PRIVATE_IMAGE_SCANNING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.container_security]

  tags = var.common_tags
}

# Config Rule: ECR Repository Lifecycle Policy
resource "aws_config_config_rule" "ecr_lifecycle_policy" {
  name = "${var.cluster_name}-ecr-lifecycle-policy"

  source {
    owner             = "AWS"
    source_identifier = "ECR_PRIVATE_LIFECYCLE_POLICY_CONFIGURED"
  }

  depends_on = [aws_config_configuration_recorder.container_security]

  tags = var.common_tags
}

# Config Rule: IAM Root User Access Key Check
resource "aws_config_config_rule" "iam_root_access_key" {
  name = "${var.cluster_name}-iam-root-access-key"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.container_security]

  tags = var.common_tags
}

# Config Rule: S3 Bucket Public Access Prohibited
resource "aws_config_config_rule" "s3_bucket_public_access" {
  name = "${var.cluster_name}-s3-bucket-public-access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_ACCESS_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.container_security]

  tags = var.common_tags
}

# Config Rule: CloudTrail Enabled
resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "${var.cluster_name}-cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.container_security]

  tags = var.common_tags
}

# Config Rule: GuardDuty Enabled
resource "aws_config_config_rule" "guardduty_enabled" {
  name = "${var.cluster_name}-guardduty-enabled"

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  depends_on = [aws_config_configuration_recorder.container_security]

  tags = var.common_tags
}

# Config Rule: KMS Key Rotation Enabled
resource "aws_config_config_rule" "kms_key_rotation" {
  name = "${var.cluster_name}-kms-key-rotation"

  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.container_security]

  tags = var.common_tags
}

# Custom Config Rule: EKS Security Groups
resource "aws_config_config_rule" "eks_security_groups" {
  name = "${var.cluster_name}-eks-security-groups"

  source {
    owner                = "AWS"
    source_identifier    = "INCOMING_SSH_DISABLED"
  }

  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }

  depends_on = [aws_config_configuration_recorder.container_security]

  tags = var.common_tags
}

# Config Remediation Configuration for EKS Endpoint Access
resource "aws_config_remediation_configuration" "eks_endpoint_remediation" {
  config_rule_name = aws_config_config_rule.eks_endpoint_access.name

  resource_type    = "AWS::EKS::Cluster"
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWSConfigRemediation-RemovePublicAccessFromEKSCluster"
  target_version   = "1"

  parameter {
    name           = "AutomationAssumeRole"
    static_value   = aws_iam_role.remediation_role.arn
  }

  parameter {
    name                = "ClusterName"
    resource_value      = "RESOURCE_ID"
  }

  automatic                = false
  maximum_automatic_attempts = 1

  tags = var.common_tags
}

# IAM Role for Config Remediation
resource "aws_iam_role" "remediation_role" {
  name = "${var.cluster_name}-config-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      }
    ]
  })

  tags = var.common_tags
}

# IAM Policy for Config Remediation
resource "aws_iam_role_policy" "remediation_policy" {
  name = "${var.cluster_name}-config-remediation-policy"
  role = aws_iam_role.remediation_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "eks:UpdateClusterConfig",
          "eks:DescribeCluster",
          "config:GetComplianceDetailsByConfigRule",
          "config:GetResourceConfigHistory"
        ]
        Resource = "*"
      }
    ]
  })
}

# EventBridge Rule for Config Compliance Changes
resource "aws_cloudwatch_event_rule" "config_compliance" {
  name        = "${var.cluster_name}-config-compliance"
  description = "Capture Config compliance state changes"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = [
        aws_config_config_rule.eks_endpoint_access.name,
        aws_config_config_rule.eks_logging_enabled.name,
        aws_config_config_rule.ecr_scan_on_push.name,
        aws_config_config_rule.guardduty_enabled.name
      ]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = var.common_tags
}

# EventBridge Target for Config Compliance
resource "aws_cloudwatch_event_target" "config_compliance_sns" {
  rule      = aws_cloudwatch_event_rule.config_compliance.name
  target_id = "ConfigComplianceTarget"
  arn       = aws_sns_topic.config_alerts.arn
}

# SNS Topic for Config Alerts
resource "aws_sns_topic" "config_alerts" {
  name              = "${var.cluster_name}-config-alerts"
  kms_master_key_id = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name      = "${var.cluster_name}-config-alerts"
    Component = "Compliance Monitoring"
  })
}

# SNS Topic Policy for EventBridge
resource "aws_sns_topic_policy" "config_alerts" {
  arn = aws_sns_topic.config_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.config_alerts.arn
      }
    ]
  })
}

# Data sources
data "aws_caller_identity" "current" {}