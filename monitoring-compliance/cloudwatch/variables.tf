variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "log_retention_days" {
  description = "Number of days to retain standard logs"
  type        = number
  default     = 30
}

variable "security_log_retention_days" {
  description = "Number of days to retain security logs"
  type        = number
  default     = 90
}

variable "audit_log_retention_days" {
  description = "Number of days to retain audit logs"
  type        = number
  default     = 365
}

variable "kms_key_arn" {
  description = "ARN of KMS key for log encryption"
  type        = string
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "container-security"
    ManagedBy   = "terraform"
  }
}

variable "enable_container_insights" {
  description = "Enable Container Insights for the cluster"
  type        = bool
  default     = true
}

variable "enable_security_monitoring" {
  description = "Enable enhanced security monitoring"
  type        = bool
  default     = true
}