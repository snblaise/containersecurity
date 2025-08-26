# CodePipeline with integrated security gates for supply chain security
# Implements SAST, SCA scanning with build failure logic and provenance recording

resource "aws_codepipeline" "secure_container_pipeline" {
  name     = "secure-container-pipeline"
  role_arn = aws_iam_role.codepipeline_role.arn

  artifact_store {
    location = aws_s3_bucket.pipeline_artifacts.bucket
    type     = "S3"

    encryption_key {
      id   = aws_kms_key.pipeline_key.arn
      type = "KMS"
    }
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeCommit"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = {
        RepositoryName = var.repository_name
        BranchName     = var.branch_name
      }
    }
  }

  stage {
    name = "SecurityGates"

    action {
      name             = "SAST_SCA_Scanning"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["source_output"]
      output_artifacts = ["security_scan_output"]
      version          = "1"

      configuration = {
        ProjectName = aws_codebuild_project.security_gates.name
      }
    }
  }

  stage {
    name = "ImageBuild"

    action {
      name             = "BuildAndScan"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["security_scan_output"]
      output_artifacts = ["build_output"]
      version          = "1"

      configuration = {
        ProjectName = aws_codebuild_project.image_build.name
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "EKS"
      input_artifacts = ["build_output"]
      version         = "1"

      configuration = {
        ClusterName = var.eks_cluster_name
        ServiceName = var.service_name
      }
    }
  }
}

# CodeBuild project for security gates (SAST/SCA)
resource "aws_codebuild_project" "security_gates" {
  name          = "security-gates-project"
  description   = "Security gates with SAST and SCA scanning"
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_MEDIUM"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:4.0"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode            = true

    environment_variable {
      name  = "AWS_DEFAULT_REGION"
      value = var.aws_region
    }

    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = var.aws_account_id
    }

    environment_variable {
      name  = "IMAGE_REPO_NAME"
      value = var.ecr_repository_name
    }

    # Security thresholds
    environment_variable {
      name  = "MAX_CRITICAL_VULNERABILITIES"
      value = "0"
    }

    environment_variable {
      name  = "MAX_HIGH_VULNERABILITIES"
      value = "5"
    }

    environment_variable {
      name  = "MAX_MEDIUM_VULNERABILITIES"
      value = "20"
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "supply-chain-security/codepipeline/buildspec-security-gates.yml"
  }

  logs_config {
    cloudwatch_logs {
      group_name  = "/aws/codebuild/security-gates"
      stream_name = "build-logs"
    }
  }

  tags = {
    Environment = var.environment
    Purpose     = "SupplyChainSecurity"
  }
}

# CodeBuild project for image building (separate from security gates)
resource "aws_codebuild_project" "image_build" {
  name          = "image-build-project"
  description   = "Container image build and push to ECR"
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_MEDIUM"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:4.0"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode            = true

    environment_variable {
      name  = "AWS_DEFAULT_REGION"
      value = var.aws_region
    }

    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = var.aws_account_id
    }

    environment_variable {
      name  = "IMAGE_REPO_NAME"
      value = var.ecr_repository_name
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "supply-chain-security/codepipeline/buildspec-image-build.yml"
  }

  logs_config {
    cloudwatch_logs {
      group_name  = "/aws/codebuild/image-build"
      stream_name = "build-logs"
    }
  }

  tags = {
    Environment = var.environment
    Purpose     = "ImageBuild"
  }
}

# S3 bucket for pipeline artifacts
resource "aws_s3_bucket" "pipeline_artifacts" {
  bucket        = "${var.project_name}-pipeline-artifacts-${random_string.bucket_suffix.result}"
  force_destroy = true

  tags = {
    Environment = var.environment
    Purpose     = "PipelineArtifacts"
  }
}

resource "aws_s3_bucket_versioning" "pipeline_artifacts" {
  bucket = aws_s3_bucket.pipeline_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "pipeline_artifacts" {
  bucket = aws_s3_bucket.pipeline_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.pipeline_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "pipeline_artifacts" {
  bucket = aws_s3_bucket.pipeline_artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS key for pipeline encryption
resource "aws_kms_key" "pipeline_key" {
  description             = "KMS key for CodePipeline encryption"
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.aws_account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CodePipeline to use the key"
        Effect = "Allow"
        Principal = {
          Service = [
            "codepipeline.amazonaws.com",
            "codebuild.amazonaws.com"
          ]
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
    Environment = var.environment
    Purpose     = "PipelineEncryption"
  }
}

resource "aws_kms_alias" "pipeline_key" {
  name          = "alias/${var.project_name}-pipeline-key"
  target_key_id = aws_kms_key.pipeline_key.key_id
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# CloudWatch Log Groups for build logs
resource "aws_cloudwatch_log_group" "security_gates_logs" {
  name              = "/aws/codebuild/security-gates"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    Purpose     = "SecurityGatesLogs"
  }
}

resource "aws_cloudwatch_log_group" "image_build_logs" {
  name              = "/aws/codebuild/image-build"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    Purpose     = "ImageBuildLogs"
  }
}