variable "repository_name" {
  description = "Name of the ECR repository"
  type        = string
  default     = "secure-app"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "codebuild_role_name" {
  description = "Name of the CodeBuild service role"
  type        = string
  default     = "CodeBuildServiceRole"
}

variable "eks_node_role_name" {
  description = "Name of the EKS node group role"
  type        = string
  default     = "EKSNodeInstanceRole"
}

variable "eks_fargate_role_name" {
  description = "Name of the EKS Fargate execution role"
  type        = string
  default     = "EKSFargateExecutionRole"
}

variable "critical_threshold" {
  description = "Maximum number of critical vulnerabilities allowed"
  type        = number
  default     = 0
}

variable "high_threshold" {
  description = "Maximum number of high vulnerabilities allowed"
  type        = number
  default     = 5
}

variable "medium_threshold" {
  description = "Maximum number of medium vulnerabilities allowed"
  type        = number
  default     = 20
}

variable "enable_image_signing" {
  description = "Enable image signing requirements"
  type        = bool
  default     = true
}

variable "allowed_principals" {
  description = "List of AWS principals allowed to access the repository"
  type        = list(string)
  default     = []
}

variable "scan_on_push" {
  description = "Enable automatic scanning when images are pushed"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email address for security notifications"
  type        = string
  default     = ""
}