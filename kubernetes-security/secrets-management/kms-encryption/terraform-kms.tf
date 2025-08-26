# Terraform configuration for KMS keys used in EKS secrets management
# This creates customer-managed KMS keys for envelope encryption

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Local values for key configuration
locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  
  # KMS key configurations
  kms_keys = {
    database = {
      description = "EKS Secrets Manager - Database Secrets"
      alias       = "eks-secrets-database"
    }
    application = {
      description = "EKS Secrets Manager - Application Secrets"
      alias       = "eks-secrets-application"
    }
    api = {
      description = "EKS Secrets Manager - API Secrets"
      alias       = "eks-secrets-api"
    }
    monitoring = {
      description = "EKS Secrets Manager - Monitoring Secrets"
      alias       = "eks-secrets-monitoring"
    }
    tls = {
      description = "EKS Secrets Manager - TLS Certificates"
      alias       = "eks-secrets-tls"
    }
  }
}

# KMS key policy template
data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    
    actions   = ["kms:*"]
    resources = ["*"]
  }
  
  statement {
    sid    = "Allow Secrets Manager Service"
    effect = "Allow"
    
    principals {
      type        = "Service"
      identifiers = ["secretsmanager.amazonaws.com"]
    }
    
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*"
    ]
    
    resources = ["*"]
    
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
  
  statement {
    sid    = "Allow EKS Service Accounts"
    effect = "Allow"
    
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${local.account_id}:role/EKSSecretsManagerRole",
        "arn:aws:iam::${local.account_id}:role/EKSApplicationRole",
        "arn:aws:iam::${local.account_id}:role/EKSMonitoringRole"
      ]
    }
    
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    
    resources = ["*"]
    
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
  
  statement {
    sid    = "Allow CloudTrail Logging"
    effect = "Allow"
    
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    
    actions = [
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    
    resources = ["*"]
    
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }
  
  statement {
    sid    = "Deny Direct Access"
    effect = "Deny"
    
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*"
    ]
    
    resources = ["*"]
    
    condition {
      test     = "StringNotEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
    
    condition {
      test     = "Bool"
      variable = "aws:PrincipalIsAWSService"
      values   = ["false"]
    }
  }
}

# Create KMS keys for each secret category
resource "aws_kms_key" "secrets_keys" {
  for_each = local.kms_keys
  
  description              = each.value.description
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  policy                  = data.aws_iam_policy_document.kms_key_policy.json
  enable_key_rotation     = true
  deletion_window_in_days = 7
  
  tags = {
    Name        = each.value.description
    Environment = "production"
    Purpose     = "secrets-management"
    ManagedBy   = "terraform"
  }
}

# Create aliases for the KMS keys
resource "aws_kms_alias" "secrets_key_aliases" {
  for_each = local.kms_keys
  
  name          = "alias/${each.value.alias}"
  target_key_id = aws_kms_key.secrets_keys[each.key].key_id
}

# Outputs
output "kms_key_ids" {
  description = "Map of KMS key IDs"
  value = {
    for k, v in aws_kms_key.secrets_keys : k => v.key_id
  }
}

output "kms_key_arns" {
  description = "Map of KMS key ARNs"
  value = {
    for k, v in aws_kms_key.secrets_keys : k => v.arn
  }
}

output "kms_key_aliases" {
  description = "Map of KMS key aliases"
  value = {
    for k, v in aws_kms_alias.secrets_key_aliases : k => v.name
  }
}

# Output for use in other Terraform configurations
output "secrets_kms_keys" {
  description = "Complete KMS key information for secrets management"
  value = {
    for k, v in local.kms_keys : k => {
      key_id = aws_kms_key.secrets_keys[k].key_id
      arn    = aws_kms_key.secrets_keys[k].arn
      alias  = aws_kms_alias.secrets_key_aliases[k].name
    }
  }
}