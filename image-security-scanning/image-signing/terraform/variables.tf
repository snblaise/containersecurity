variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "container-security"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "signing_profile_name" {
  description = "Name of the AWS Signer signing profile"
  type        = string
  default     = "container-signing-profile"
}

variable "signature_validity_days" {
  description = "Number of days the signature is valid"
  type        = number
  default     = 365
}

variable "codebuild_role_name" {
  description = "Name of the CodeBuild service role"
  type        = string
  default     = "CodeBuildServiceRole"
}

variable "enable_signing_notifications" {
  description = "Enable SNS notifications for signing events"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email address for signing notifications"
  type        = string
  default     = ""
}

variable "signing_artifacts_retention_days" {
  description = "Number of days to retain signing artifacts"
  type        = number
  default     = 90
}