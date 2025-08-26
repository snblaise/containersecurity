# Variables for CodePipeline with security gates

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "secure-container"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "repository_name" {
  description = "CodeCommit repository name"
  type        = string
}

variable "branch_name" {
  description = "Git branch name to build from"
  type        = string
  default     = "main"
}

variable "ecr_repository_name" {
  description = "ECR repository name for container images"
  type        = string
}

variable "eks_cluster_name" {
  description = "EKS cluster name for deployment"
  type        = string
}

variable "service_name" {
  description = "Kubernetes service name for deployment"
  type        = string
  default     = "app-service"
}

# Security gate thresholds
variable "max_critical_vulnerabilities" {
  description = "Maximum number of critical vulnerabilities allowed"
  type        = number
  default     = 0
}

variable "max_high_vulnerabilities" {
  description = "Maximum number of high vulnerabilities allowed"
  type        = number
  default     = 5
}

variable "max_medium_vulnerabilities" {
  description = "Maximum number of medium vulnerabilities allowed"
  type        = number
  default     = 20
}

# Tool versions
variable "semgrep_version" {
  description = "Semgrep version for SAST scanning"
  type        = string
  default     = "1.45.0"
}

variable "trivy_version" {
  description = "Trivy version for SCA and container scanning"
  type        = string
  default     = "0.48.0"
}

variable "syft_version" {
  description = "Syft version for SBOM generation"
  type        = string
  default     = "0.95.0"
}

variable "cosign_version" {
  description = "Cosign version for image signing"
  type        = string
  default     = "2.2.1"
}